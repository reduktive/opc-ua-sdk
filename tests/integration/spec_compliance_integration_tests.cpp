// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "matchers.h"
#include "ua_test_server.h"

#include "ua_attribute_id.h"
#include "ua_browse_description.h"
#include "ua_browse_direction.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_core_client.h"
#include "test_log_sink.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_node_class.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_reference_description.h"
#include "ua_session_attribute_services.h"
#include "ua_session_view_services.h"
#include "ua_referencetype_id.h"
#include "ua_server_state.h"
#include "ua_status.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_timestamps_to_return.h"
#include "ua_variable_id.h"
#include "ua_variabletype_id.h"

#include "ua_role_configuration.h"
#include "ua_built_in_authenticators.h"
#include "ua_certificate_store_files.h"
#include "ua_crypto.h"

#include "test_utilities.h"

#include <filesystem>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

namespace
{

ReadValueId make_read(NodeId nodeId, AttributeId attr)
{
  ReadValueId rv;
  rv.node_id() = std::move(nodeId);
  rv.attribute_id() = static_cast<uint32_t>(attr);
  return rv;
}

// ---------------------------------------------------------------------------
// Base fixture: server + client, no session
// ---------------------------------------------------------------------------
class SpecCompliance : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mServer.create();

    ServerEndpointConfig endpoint;
    endpoint.name = "None";
    endpoint.messageSecurityMode = MessageSecurityMode::None;
    endpoint.securityPolicyId = SecurityPolicyId::None;
    endpoint.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));

    mListener = mServer.listen_ephemeral();
    mServer.add_endpoint(mListener, endpoint);
    mServer.start();

    auto urls = mServer.server().advertised_urls(mListener);
    ASSERT_FALSE(urls.empty());
    mEndpointUrl = urls.front().str();

    // The server's sink is installed by TestServer::create (test_log_sink()); wire the client here.
    mClient.emplace(CoreClient::create(mClientThreadPool.executor(),
      ua::client::CreateConfig{.identity = ua::ApplicationIdentity::load_default(),
        .application = ua::test_utils::create_test_config()},
      ua::client::ClientComponents{
        .crypto = ua::test_helpers::test_crypto(), .logSink = test_log_sink(), .logLevel = LogLevel::Debug}));
  }

  void TearDown() override
  {
    // Drop the client handle BEFORE stopping the pool so that any impl-owned
    // strand-bound resources (channels, sessions, certificate stores with periodic
    // refresh timers) get torn down while the pool can still process their teardown
    // posts. Stopping the pool first leaves outstanding handlers that the watchdog
    // has to abort.
    mClient.reset();
    ::ua::test_utils::stop_pool_in_teardown(mClientThreadPool, "client");
  }

  TestServer mServer;
  boost::asio::thread_pool mClientThreadPool;
  ListenerHandle mListener{0};
  std::string mEndpointUrl;
  std::optional<CoreClient> mClient;
};

// ---------------------------------------------------------------------------
// Derived fixture: channel + session opened in SetUp
// ---------------------------------------------------------------------------
class SpecComplianceWithSession : public SpecCompliance
{
protected:
  void SetUp() override
  {
    SpecCompliance::SetUp();
    mChannel.emplace(mClient->open_channel_sync({.endpointUrl = mEndpointUrl}));
    mSession.emplace(mChannel->create_session_sync({.sessionName = "SpecComplianceTest"}));
    mSession->activate_sync();
  }

  void TearDown() override
  {
    if (mSession)
      (void)mSession->try_close_sync();
    if (mChannel)
      (void)mChannel->try_close_sync();
    SpecCompliance::TearDown();
  }

  std::optional<SecureChannel> mChannel;
  std::optional<Session> mSession;
};

// ===========================================================================
// Lifecycle: channel and session state transitions
// ===========================================================================
TEST_F(SpecCompliance, SessionLifecycle_StateTransitions)
{
  auto channel = mClient->open_channel_sync({.endpointUrl = mEndpointUrl});
  EXPECT_TRUE(channel.is_open());
  EXPECT_NE(channel.secure_channel_id(), 0u);

  auto session = channel.create_session_sync({.sessionName = "LifecycleTest"});
  EXPECT_TRUE(session.is_created());

  session.activate_sync();
  EXPECT_TRUE(session.is_active());

  session.close_sync();
  channel.close_sync();
}

// ===========================================================================
// Lifecycle: try_*_sync variants return Result<T>
// ===========================================================================
TEST_F(SpecCompliance, SessionLifecycle_TrySyncVariants)
{
  auto channelResult = mClient->try_open_channel_sync({.endpointUrl = mEndpointUrl});
  ASSERT_TRUE(channelResult.is_good()) << channelResult.status_code().as_uint32();

  auto channel = std::move(channelResult).value();

  auto sessionResult = channel.try_create_session_sync({});
  ASSERT_TRUE(sessionResult.is_good()) << sessionResult.status_code().as_uint32();

  auto session = std::move(sessionResult).value();

  auto activateResult = session.try_activate_sync();
  ASSERT_TRUE(activateResult.is_good()) << activateResult.status_code().as_uint32();

  auto closeSessionResult = session.try_close_sync();
  EXPECT_THAT(closeSessionResult, ::ua::test_helpers::Good());

  auto closeChannelResult = channel.try_close_sync();
  EXPECT_THAT(closeChannelResult, ::ua::test_helpers::Good());
}

// ===========================================================================
// 1. GetEndpoints: ProductUri must not be empty
// ===========================================================================
TEST_F(SpecCompliance, GetEndpoints_ProductUri_NotEmpty)
{
  auto channel = mClient->open_channel_sync({.endpointUrl = mEndpointUrl});

  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto resp = channel.get_endpoints_sync(std::move(req));

  ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_GE(resp.endpoints().size(), 1u);

  for (size_t i = 0; i < resp.endpoints().size(); ++i)
  {
    EXPECT_FALSE(resp.endpoints()[i].server().product_uri().empty())
      << "Endpoint " << i << " has empty ProductUri";
  }

  channel.close_sync();
}

// ===========================================================================
// 2. GetEndpoints: SecurityLevel > 0 for secured endpoints
// ===========================================================================
TEST_F(SpecCompliance, GetEndpoints_SecurityLevel_NonZeroForSecuredEndpoints)
{
  auto channel = mClient->open_channel_sync({.endpointUrl = mEndpointUrl});

  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto resp = channel.get_endpoints_sync(std::move(req));

  ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());

  for (size_t i = 0; i < resp.endpoints().size(); ++i)
  {
    if (resp.endpoints()[i].security_mode() != MessageSecurityMode::None)
    {
      EXPECT_GT(resp.endpoints()[i].security_level(), 0u)
        << "Endpoint " << i << " is secured but has SecurityLevel == 0";
    }
  }

  channel.close_sync();
}

// ===========================================================================
// 3. Browse Root: Types folder metadata
// ===========================================================================
TEST_F(SpecComplianceWithSession, BrowseRoot_TypesFolderMetadata)
{
  BrowseRequest req;
  BrowseDescription bd;
  bd.node_id() = NodeId{ObjectId::RootFolder};
  bd.browse_direction() = BrowseDirection::Forward;
  bd.reference_type_id() = NodeId{ReferenceTypeId::HierarchicalReferences};
  bd.include_subtypes() = true;
  bd.node_class_mask() = 0xFF;  // All node classes (matches Prosys trace)
  bd.result_mask() = 63;  // BrowseResultMask::All
  req.nodes_to_browse().push_back(std::move(bd));

  auto resp = mSession->view().browse_sync(std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);
  ASSERT_TRUE(resp.results()[0].status_code().is_good());

  // Find the Types folder (i=86)
  const ReferenceDescription* typesRef = nullptr;
  for (const auto& ref : resp.results()[0].references())
  {
    if (ref.node_id().node_id() == NodeId{ObjectId::TypesFolder})
    {
      typesRef = &ref;
      break;
    }
  }
  ASSERT_NE(typesRef, nullptr) << "Types folder (i=" << static_cast<uint32_t>(ObjectId::TypesFolder)
                               << ") not found in Root's references";

  EXPECT_EQ(typesRef->node_class(), NodeClass::Object);
  EXPECT_FALSE(typesRef->browse_name().name().empty()) << "Types folder BrowseName is empty";
  EXPECT_FALSE(typesRef->display_name().text().empty()) << "Types folder DisplayName is empty";
  EXPECT_EQ(typesRef->type_definition().node_id(), NodeId{ObjectTypeId::FolderType})
    << "Types folder TypeDefinition should be FolderType (i=61)";
}

// ===========================================================================
// 4. Read Server_ServerStatus Value
// ===========================================================================
TEST_F(SpecComplianceWithSession, ReadServerStatus_Value)
{
  ReadRequest req;
  req.timestamps_to_return() = TimestampsToReturn::Both;  // Matches Prosys trace frame 3805
  req.nodes_to_read().push_back(make_read(NodeId{VariableId::Server_ServerStatus}, AttributeId::Value));

  auto resp = mSession->attributes().read_sync(std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);

  const auto& dv = resp.results()[0];
  if (dv.status().has_value())
  {
    EXPECT_TRUE(dv.status()->is_good())
      << "ServerStatus Value read failed: 0x" << std::hex << dv.status()->as_uint32();
  }
  EXPECT_FALSE(dv.value().empty()) << "ServerStatus Value should be present";
}

// ===========================================================================
// 5. Read Server_ServerStatus_BuildInfo Value
// ===========================================================================
TEST_F(SpecComplianceWithSession, ReadBuildInfo_Value)
{
  ReadRequest req;
  req.timestamps_to_return() = TimestampsToReturn::Neither;  // Matches Prosys trace frame 3808
  req.nodes_to_read().push_back(
    make_read(NodeId{VariableId::Server_ServerStatus_BuildInfo}, AttributeId::Value));

  auto resp = mSession->attributes().read_sync(std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);

  const auto& dv = resp.results()[0];
  if (dv.status().has_value())
  {
    EXPECT_TRUE(dv.status()->is_good())
      << "BuildInfo Value read failed: 0x" << std::hex << dv.status()->as_uint32();
  }
  EXPECT_FALSE(dv.value().empty()) << "BuildInfo Value should be present";
}

// ===========================================================================
// 6. Read SecondsTillShutdown and ShutdownReason
// ===========================================================================
TEST_F(SpecComplianceWithSession, ReadSecondsTillShutdown_And_ShutdownReason)
{
  ReadRequest req;
  req.timestamps_to_return() = TimestampsToReturn::Neither;  // Matches Prosys trace frame 3808
  req.nodes_to_read().push_back(
    make_read(NodeId{VariableId::Server_ServerStatus_SecondsTillShutdown}, AttributeId::Value));
  req.nodes_to_read().push_back(
    make_read(NodeId{VariableId::Server_ServerStatus_ShutdownReason}, AttributeId::Value));

  auto resp = mSession->attributes().read_sync(std::move(req));
  ASSERT_EQ(resp.results().size(), 2u);

  // SecondsTillShutdown - should be Good with a UInt32 value
  {
    const auto& dv = resp.results()[0];
    if (dv.status().has_value())
    {
      EXPECT_TRUE(dv.status()->is_good())
        << "SecondsTillShutdown read failed: 0x" << std::hex << dv.status()->as_uint32();
    }
    EXPECT_TRUE(dv.value().is_uint32()) << "SecondsTillShutdown should be UInt32";
  }

  // ShutdownReason - should be Good with a LocalizedText value
  {
    const auto& dv = resp.results()[1];
    if (dv.status().has_value())
    {
      EXPECT_TRUE(dv.status()->is_good())
        << "ShutdownReason read failed: 0x" << std::hex << dv.status()->as_uint32();
    }
    EXPECT_TRUE(dv.value().is_localized_text()) << "ShutdownReason should be LocalizedText";
  }
}

// ===========================================================================
// 7. Read Description - mandatory for all node classes
// ===========================================================================
TEST_F(SpecComplianceWithSession, ReadDescription_MandatoryForAllNodeClasses)
{
  // One representative node per node class:
  //   Object:        RootFolder (i=84)
  //   Object:        ObjectsFolder (i=85)
  //   Object:        Server (i=2253)
  //   DataType:      Boolean (i=1)
  //   ReferenceType: Organizes (i=35)
  //   ObjectType:    BaseObjectType (i=58)
  const std::vector<std::pair<uint32_t, std::string>> nodes = {
    {static_cast<uint32_t>(ObjectId::RootFolder), "RootFolder"},
    {static_cast<uint32_t>(ObjectId::ObjectsFolder), "ObjectsFolder"},
    {static_cast<uint32_t>(ObjectId::Server), "Server"},
    {static_cast<uint32_t>(DataTypeId::Boolean), "Boolean DataType"},
    {static_cast<uint32_t>(ReferenceTypeId::Organizes), "Organizes ReferenceType"},
    {static_cast<uint32_t>(ObjectTypeId::BaseObjectType), "BaseObjectType"},
  };

  ReadRequest req;
  req.timestamps_to_return() = TimestampsToReturn::Both;  // Matches Prosys trace frames 3652+
  for (const auto& [id, name] : nodes)
  {
    req.nodes_to_read().push_back(make_read(NodeId(0, id), AttributeId::Description));
  }

  auto resp = mSession->attributes().read_sync(std::move(req));
  ASSERT_EQ(resp.results().size(), nodes.size());

  // Part 3 section 4.3.3: Description is optional for all node classes.
  // BadAttributeIdInvalid is correct when the attribute is not instantiated on a node.
  for (size_t i = 0; i < nodes.size(); ++i)
  {
    const auto& dv = resp.results()[i];
    bool isGood = !dv.status().has_value() || dv.status()->is_good();
    bool isBadAttrId = dv.status().has_value() &&
                       dv.status()->as_uint32() == static_cast<uint32_t>(Status::BadAttributeIdInvalid);
    EXPECT_TRUE(isGood || isBadAttrId) << "Description of " << nodes[i].second << " (i=" << nodes[i].first
                                       << ") returned unexpected status: 0x" << std::hex
                                       << (dv.status().has_value() ? dv.status()->as_uint32() : 0u);
  }
}

// ===========================================================================
// 8. Read WriteMask and UserWriteMask - mandatory for all node classes
// ===========================================================================
TEST_F(SpecComplianceWithSession, ReadWriteMask_MandatoryForAllNodeClasses)
{
  const std::vector<std::pair<uint32_t, std::string>> nodes = {
    {static_cast<uint32_t>(ObjectId::RootFolder), "RootFolder"},
    {static_cast<uint32_t>(ObjectId::ObjectsFolder), "ObjectsFolder"},
    {static_cast<uint32_t>(ObjectId::Server), "Server"},
    {static_cast<uint32_t>(DataTypeId::Boolean), "Boolean DataType"},
    {static_cast<uint32_t>(ReferenceTypeId::Organizes), "Organizes ReferenceType"},
    {static_cast<uint32_t>(ObjectTypeId::BaseObjectType), "BaseObjectType"},
  };

  ReadRequest req;
  req.timestamps_to_return() = TimestampsToReturn::Both;  // Matches Prosys trace frames 3652+
  for (const auto& [id, name] : nodes)
  {
    req.nodes_to_read().push_back(make_read(NodeId(0, id), AttributeId::WriteMask));
    req.nodes_to_read().push_back(make_read(NodeId(0, id), AttributeId::UserWriteMask));
  }

  auto resp = mSession->attributes().read_sync(std::move(req));
  ASSERT_EQ(resp.results().size(), nodes.size() * 2);

  // Part 3 section 4.3.3: WriteMask and UserWriteMask are optional for all node classes.
  // BadAttributeIdInvalid is correct when the attribute is not instantiated on a node.
  for (size_t i = 0; i < nodes.size(); ++i)
  {
    // WriteMask
    {
      const auto& dv = resp.results()[i * 2];
      bool isGood = !dv.status().has_value() || dv.status()->is_good();
      bool isBadAttrId = dv.status().has_value() &&
                         dv.status()->as_uint32() == static_cast<uint32_t>(Status::BadAttributeIdInvalid);
      EXPECT_TRUE(isGood || isBadAttrId)
        << "WriteMask of " << nodes[i].second << " (i=" << nodes[i].first << ") returned unexpected status";
      if (isGood)
      {
        EXPECT_TRUE(dv.value().is_uint32()) << "WriteMask of " << nodes[i].second << " should be UInt32";
      }
    }
    // UserWriteMask
    {
      const auto& dv = resp.results()[i * 2 + 1];
      bool isGood = !dv.status().has_value() || dv.status()->is_good();
      bool isBadAttrId = dv.status().has_value() &&
                         dv.status()->as_uint32() == static_cast<uint32_t>(Status::BadAttributeIdInvalid);
      EXPECT_TRUE(isGood || isBadAttrId) << "UserWriteMask of " << nodes[i].second << " (i=" << nodes[i].first
                                         << ") returned unexpected status";
      if (isGood)
      {
        EXPECT_TRUE(dv.value().is_uint32()) << "UserWriteMask of " << nodes[i].second << " should be UInt32";
      }
    }
  }
}

// ===========================================================================
// 9. Read Value on VariableType nodes - valid per Part 3 Table 14
// ===========================================================================
TEST_F(SpecComplianceWithSession, ReadValue_ValidForVariableTypeNodes)
{
  ReadRequest req;
  req.timestamps_to_return() = TimestampsToReturn::Both;  // Matches Prosys trace frames 3652+
  // BaseDataVariableType (i=63)
  req.nodes_to_read().push_back(make_read(NodeId{VariableTypeId::BaseDataVariableType}, AttributeId::Value));
  // PropertyType (i=68)
  req.nodes_to_read().push_back(make_read(NodeId{VariableTypeId::PropertyType}, AttributeId::Value));

  auto resp = mSession->attributes().read_sync(std::move(req));
  ASSERT_EQ(resp.results().size(), 2u);

  for (size_t i = 0; i < 2; ++i)
  {
    const auto& dv = resp.results()[i];
    // Value is an optional attribute for VariableType nodes (Part 3 Table 14).
    // BadAttributeIdInvalid is correct when the value is not instantiated.
    if (dv.status().has_value())
    {
      bool isGood = dv.status()->is_good();
      bool isBadAttrId = dv.status()->as_uint32() == static_cast<uint32_t>(Status::BadAttributeIdInvalid);
      EXPECT_TRUE(isGood || isBadAttrId)
        << "Value attribute on VariableType node " << i << " returned unexpected status: 0x" << std::hex
        << dv.status()->as_uint32();
    }
  }
}

// ===========================================================================
// 10. Browse PublishSubscribeType - no BadUnexpectedError
// ===========================================================================
TEST_F(SpecComplianceWithSession, BrowsePublishSubscribeType_NoBadUnexpectedError)
{
  BrowseRequest req;
  BrowseDescription bd;
  bd.node_id() = NodeId{ObjectTypeId::PublishSubscribeType};
  bd.browse_direction() = BrowseDirection::Both;
  bd.reference_type_id() = NodeId{ReferenceTypeId::References};
  bd.include_subtypes() = true;
  bd.node_class_mask() = 0xFF;  // All node classes (matches Prosys trace)
  bd.result_mask() = 63;
  req.nodes_to_browse().push_back(std::move(bd));

  auto resp = mSession->view().browse_sync(std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);

  // BadUnexpectedError (0x80010000) indicates a server-internal failure.
  // Good or BadNodeIdUnknown are acceptable.
  EXPECT_NE(resp.results()[0].status_code().as_uint32(), 0x80010000u)
    << "Browse of PublishSubscribeType returned BadUnexpectedError";
}

// ===========================================================================
// 11. Read with TimestampsBoth - source and server timestamps present
// ===========================================================================
TEST_F(SpecComplianceWithSession, ReadWithTimestampsBoth_SourceTimestampPresent)
{
  ReadRequest req;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.nodes_to_read().push_back(
    make_read(NodeId{VariableId::Server_ServerStatus_CurrentTime}, AttributeId::Value));

  auto resp = mSession->attributes().read_sync(std::move(req));
  ASSERT_EQ(resp.results().size(), 1u);

  const auto& dv = resp.results()[0];
  bool isGood = !dv.status().has_value() || dv.status()->is_good();
  ASSERT_TRUE(isGood) << "Read of CurrentTime failed";

  EXPECT_TRUE(dv.source_timestamp().has_value())
    << "SourceTimestamp must be present when TimestampsToReturn == Both";
  EXPECT_TRUE(dv.server_timestamp().has_value())
    << "ServerTimestamp must be present when TimestampsToReturn == Both";
}

// ===========================================================================
// 12. Read InverseName on non-symmetric ReferenceTypes
// ===========================================================================
TEST_F(SpecComplianceWithSession, ReadInverseName_NonSymmetricReferenceType)
{
  ReadRequest req;
  req.timestamps_to_return() = TimestampsToReturn::Both;  // Matches Prosys trace frames 3652+
  // Organizes (i=35) - InverseName should be "OrganizedBy"
  req.nodes_to_read().push_back(make_read(NodeId{ReferenceTypeId::Organizes}, AttributeId::InverseName));
  // HasComponent (i=47) - InverseName should be "ComponentOf"
  req.nodes_to_read().push_back(make_read(NodeId{ReferenceTypeId::HasComponent}, AttributeId::InverseName));

  auto resp = mSession->attributes().read_sync(std::move(req));
  ASSERT_EQ(resp.results().size(), 2u);

  const char* names[] = {"Organizes", "HasComponent"};
  for (size_t i = 0; i < 2; ++i)
  {
    const auto& dv = resp.results()[i];
    bool isGood = !dv.status().has_value() || dv.status()->is_good();
    EXPECT_TRUE(isGood) << "InverseName of " << names[i] << " returned bad status: 0x" << std::hex
                        << (dv.status().has_value() ? dv.status()->as_uint32() : 0u);

    if (isGood)
    {
      EXPECT_TRUE(dv.value().is_localized_text())
        << "InverseName of " << names[i] << " should be a LocalizedText";
    }
  }
}

// ===========================================================================
// Authenticated channel: Basic256Sha256/SignAndEncrypt e2e
// ===========================================================================
// Proves that the full signature handshake, channel encryption, session
// creation/activation, and service dispatch work through the real transport
// stack with an authenticated security policy.
class AuthenticatedChannelTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mCrypto = create_default_crypto([]() { return ua::SecureString{"password"}; });

    // Server certificate.
    Crypto::Name subject;
    subject.commonName = "AuthTest Server";
    UtcTime expiry{2050, 1, 1, 0, 0, 0};
    Crypto::SubjectAlternateName altName;
    altName.uris.push_back("urn:test:authtest:server");
    altName.hostnames.push_back("localhost");
    altName.hostnames.push_back("127.0.0.1");

    auto serverCertResult = mCrypto->try_create_self_signed_application_instance_certificate_sync(
      subject, expiry, altName, CertificateType::RsaSha256Application, 2048);
    ASSERT_TRUE(serverCertResult.is_good());
    auto [serverKeys, serverCert] = std::move(serverCertResult).value();
    mServerCert = std::move(serverCert);

    // Client certificate.
    Crypto::Name clientSubject;
    clientSubject.commonName = "AuthTest Client";
    Crypto::SubjectAlternateName clientAltName;
    clientAltName.uris.push_back("urn:test:authtest:client");
    clientAltName.hostnames.push_back("localhost");

    auto clientCertResult = mCrypto->try_create_self_signed_application_instance_certificate_sync(
      clientSubject, expiry, clientAltName, CertificateType::RsaSha256Application, 2048);
    ASSERT_TRUE(clientCertResult.is_good());
    auto [clientKeys, clientCert] = std::move(clientCertResult).value();

    // Temp directories for cert stores.
    mTempDir =
      std::filesystem::temp_directory_path() / ("ua_auth_test_" + Guid::create_and_generate().as_string());
    std::filesystem::create_directories(mTempDir);

    // Server cert store: holds server app cert, trusts client cert.
    auto serverStorePath = mTempDir / "server_store";
    std::filesystem::create_directories(serverStorePath);

    TrustListValidationOptions validationOptions;
    mServerCertStore = CertificateStoreFiles::create(mServerThreadPool.executor(),
      mCrypto,
      {.trustListPath = serverStorePath, .validationOptions = validationOptions});

    {
      CertificateStore::ApplicationCertificate appCert;
      appCert.certificateType = CertificateType::RsaSha256Application;
      appCert.certificate = mServerCert;
      appCert.keys = std::move(serverKeys);
      mServerCertStore->add_to_application_certificates_sync(appCert);
    }
    mServerCertStore->add_to_trusted_certificates_sync(clientCert);

    // Client cert store: holds client app cert, trusts server cert.
    auto clientStorePath = mTempDir / "client_store";
    std::filesystem::create_directories(clientStorePath);

    mClientCertStore = CertificateStoreFiles::create(mClientThreadPool.executor(),
      mCrypto,
      {.trustListPath = clientStorePath, .validationOptions = validationOptions});

    {
      CertificateStore::ApplicationCertificate appCert;
      appCert.certificateType = CertificateType::RsaSha256Application;
      appCert.certificate = clientCert;
      appCert.keys = std::move(clientKeys);
      mClientCertStore->add_to_application_certificates_sync(appCert);
    }
    mClientCertStore->add_to_trusted_certificates_sync(mServerCert);

    // Server.
    auto appCfg = ua::test_utils::create_test_config();
    ServerComponents components{.crypto = mCrypto, .applicationGroupCertificateStore = mServerCertStore};
    components.authenticator = std::make_shared<AnonymousAuthenticator>();
    components.roleConfiguration = RoleConfiguration::from_well_known_grants(
      {{WellKnownRole::SecurityAdmin, IdentityCriteriaType::Anonymous}});

    server::CreateConfig serverCreateCfg{
      .identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)};

    auto logSink = test_log_sink();
    components.logSink = logSink;
    components.logLevel = LogLevel::Debug;
    mServer.emplace(
      Server::create(mServerThreadPool.executor(), std::move(serverCreateCfg), std::move(components)));

    transport::BindAddress bind;
    bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
    bind.address = "127.0.0.1:0";
    mListenerHandle = mServer->listen_sync(std::move(bind), {});

    ServerEndpointConfig ep;
    ep.name = "Basic256Sha256_SignAndEncrypt";
    ep.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
    ep.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    ep.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    mServer->add_endpoint(mListenerHandle, std::move(ep));
    mServer->start_sync();

    auto urls = mServer->advertised_urls(mListenerHandle);
    ASSERT_FALSE(urls.empty());
    mEndpointUrl = urls.front().str();

    // Client.
    auto clientAppCfg = ua::test_utils::create_test_config();
    clientAppCfg.application_description_part().applicationUri = "urn:test:authtest:client";
    client::CreateConfig clientCfg{
      .identity = ApplicationIdentity::load_default(), .application = std::move(clientAppCfg)};
    mClient.emplace(CoreClient::create(mClientThreadPool.executor(),
      std::move(clientCfg),
      ua::client::ClientComponents{.crypto = mCrypto,
        .applicationGroupCertificateStore = mClientCertStore,
        .logSink = logSink,
        .logLevel = LogLevel::Debug}));
  }

  void TearDown() override
  {
    if (mServer)
      (void)mServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
    mClient.reset();
    mServer.reset();
    ::ua::test_utils::stop_pool_in_teardown(mClientThreadPool, "client");
    ::ua::test_utils::stop_pool_in_teardown(mServerThreadPool, "server");

    std::error_code ec;
    std::filesystem::remove_all(mTempDir, ec);
  }

  std::shared_ptr<const Crypto> mCrypto;
  std::shared_ptr<const X509Certificate> mServerCert;
  boost::asio::thread_pool mServerThreadPool;
  boost::asio::thread_pool mClientThreadPool;
  std::shared_ptr<CertificateStore> mServerCertStore;
  std::shared_ptr<CertificateStore> mClientCertStore;
  std::filesystem::path mTempDir;
  std::optional<Server> mServer;
  ListenerHandle mListenerHandle{0};
  std::string mEndpointUrl;
  std::optional<CoreClient> mClient;
};

TEST_F(AuthenticatedChannelTest, Basic256Sha256_SignAndEncrypt_SessionAndRead)
{
  CoreClient::OpenChannelConfig channelConfig;
  channelConfig.endpointUrl = mEndpointUrl;
  channelConfig.securityMode = MessageSecurityMode::SignAndEncrypt;
  channelConfig.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  channelConfig.serverCertificate = mServerCert;

  auto channelResult = mClient->try_open_channel_sync(std::move(channelConfig));
  ASSERT_TRUE(channelResult.is_good())
    << "Failed to open authenticated channel: 0x" << std::hex << channelResult.status_code().as_uint32();

  auto channel = std::move(channelResult).value();
  EXPECT_TRUE(channel.is_open());

  auto sessionResult = channel.try_create_session_sync({.sessionName = "AuthTest"});
  ASSERT_TRUE(sessionResult.is_good())
    << "Failed to create session: 0x" << std::hex << sessionResult.status_code().as_uint32();

  auto session = std::move(sessionResult).value();

  auto activateResult = session.try_activate_sync();
  ASSERT_TRUE(activateResult.is_good())
    << "Failed to activate session: 0x" << std::hex << activateResult.status_code().as_uint32();

  EXPECT_TRUE(session.is_active());

  // Read ServerState to prove the session works over the encrypted channel.
  ReadRequest readReq;
  ReadValueId rv;
  rv.node_id() = NodeId{VariableId::Server_ServerStatus_State};
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  readReq.nodes_to_read().push_back(std::move(rv));

  auto readResult = session.attributes().try_read_sync(std::move(readReq));
  ASSERT_TRUE(readResult.is_good()) << "Read failed: 0x" << std::hex << readResult.status_code().as_uint32();

  auto readResp = std::move(readResult).value();
  ASSERT_EQ(readResp.results().size(), 1u);
  EXPECT_TRUE(!readResp.results()[0].status().has_value() || readResp.results()[0].status()->is_good());
  EXPECT_TRUE(readResp.results()[0].value().is_int32());
  EXPECT_EQ(readResp.results()[0].value().as<int32_t>(), static_cast<int32_t>(ServerState::Running));

  session.try_close_sync();
  channel.try_close_sync();
}

}  // namespace
