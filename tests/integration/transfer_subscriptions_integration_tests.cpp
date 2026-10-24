// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// TransferSubscriptions Integration Tests
///
/// Tests covering OPC UA Part 4 TransferSubscriptions service requirements.
/// Two fixtures:
///   - TransferSubscriptionsSecure: Basic256Sha256 / SignAndEncrypt + Anonymous auth
///   - TransferSubscriptionsNone: None / None + Anonymous auth (for SVR-XFER-003 negative test)
///
/// Each test uses two independent client sessions (A and B) to exercise subscription
/// transfer between sessions.

#include <gtest/gtest.h>

#include "access_control_test_support.h"
#include "matchers.h"
#include "requests.h"
#include "subscription.h"

#include "ua_role_configuration.h"
#include "ua_built_in_authenticators.h"
#include "ua_certificate_store_files.h"
#include "ua_core_client.h"
#include "test_log_sink.h"
#include "ua_crypto.h"
#include "ua_server.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_security_policy.h"

#include "ua_transfer_subscriptions_request.h"
#include "ua_transfer_subscriptions_response.h"
#include "ua_transfer_result.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_result_mask.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_subscription_diagnostics_data_type.h"
#include "ua_attribute_id.h"
#include "ua_variable_id.h"
#include "ua_session_attribute_services.h"
#include "ua_session_view_services.h"
#include "ua_publish_request.h"
#include "ua_publish_response.h"
#include "ua_notification_message.h"
#include "ua_data_change_notification.h"
#include "ua_monitored_item_notification.h"
#include "ua_status_change_notification.h"
#include "ua_to_string.h"
#include "ua_session_subscription_services.h"
#include "ua_republish_request.h"
#include "ua_republish_response.h"
#include "ua_set_monitoring_mode_request.h"
#include "ua_set_monitoring_mode_response.h"
#include "ua_create_monitored_items_response.h"
#include "ua_monitored_item_create_result.h"
#include "ua_user_token_policy.h"
#include "ua_user_identity.h"

#include "ua_default_namespace.h"
#include "ua_default_variable_node.h"
#include "ua_access_level_type.h"
#include "ua_datatype_id.h"
#include "ua_object_id.h"
#include "ua_referencetype_id.h"
#include "ua_server_configuration.h"
#include "ua_address_space.h"
#include "ua_node_accessor.h"

#include "ua_test_server.h"
#include "test_utilities.h"

#include <chrono>
#include <filesystem>
#include <future>
#include <set>
#include <string>
#include <algorithm>
#include <thread>
#include <vector>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

// ===========================================================================
// Key material helper (same as security_integration_tests.cpp)
// ===========================================================================

namespace
{

struct KeyMaterial
{
  std::shared_ptr<const AsymmetricKeyPair> keys;
  std::shared_ptr<const X509Certificate> cert;
};

KeyMaterial create_self_signed_cert(const std::shared_ptr<const Crypto>& crypto, CertificateType certType,
  const std::string& commonName, const std::string& uri, size_t keyBits = 2048)
{
  Crypto::Name subject;
  subject.commonName = commonName;
  UtcTime expiry{2050, 1, 1, 0, 0, 0};
  Crypto::SubjectAlternateName altName;
  altName.uris.push_back(uri);
  altName.hostnames.push_back("localhost");
  altName.hostnames.push_back("127.0.0.1");

  auto result = crypto->try_create_self_signed_application_instance_certificate_sync(
    subject, expiry, altName, certType, keyBits);
  if (result.is_bad())
    throw std::runtime_error("Failed to create certificate: " + commonName);

  auto [keys, cert] = std::move(result).value();
  return {std::move(keys), std::move(cert)};
}

// Browse Server.ServerDiagnostics.SubscriptionDiagnosticsArray for the HasComponent child whose
// BrowseName is the subscription id; return that node (its Value is the full
// SubscriptionDiagnosticsDataType struct, OPC 10000-5 6.3.7). The array is server-global, so any
// authenticated session can browse it.
std::optional<NodeId> find_subscription_diag_node(Session& session, uint32_t subId)
{
  BrowseRequest req;
  BrowseDescription desc;
  desc.node_id() = NodeId{VariableId::Server_ServerDiagnostics_SubscriptionDiagnosticsArray};
  desc.browse_direction() = BrowseDirection::Forward;
  desc.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
  desc.include_subtypes() = true;
  desc.result_mask() = static_cast<uint32_t>(BrowseResultMask::All);
  req.nodes_to_browse().push_back(std::move(desc));

  auto resp = session.view().browse_sync(std::move(req));
  if (resp.results().empty())
    return std::nullopt;
  const std::string target = std::to_string(subId);
  for (const auto& ref : resp.results()[0].references())
  {
    if (std::string{ref.browse_name().name()} == target)
      return ref.node_id().node_id();
  }
  return std::nullopt;
}

// Poll find_subscription_diag_node until the node exists (its creation is async), within a short
// budget.
std::optional<NodeId> wait_for_subscription_diag_node(
  Session& session, uint32_t subId, const std::optional<NodeId>& replacedNode = std::nullopt)
{
  for (int attempt = 0; attempt < 50; ++attempt)
  {
    if (auto node = find_subscription_diag_node(session, subId);
        node && (!replacedNode || *node != *replacedNode))
      return node;
    std::this_thread::sleep_for(40ms);
  }
  auto node = find_subscription_diag_node(session, subId);
  return node && (!replacedNode || *node != *replacedNode) ? node : std::nullopt;
}

// Read the subscription's diagnostics struct, retrying until `predicate` holds (the diagnostic update
// posts on the subscription strand after the transfer completes). Returns the last-read struct.
SubscriptionDiagnosticsDataType wait_for_transfer_diagnostics(Session& session, const NodeId& diagNode,
  const std::function<bool(const SubscriptionDiagnosticsDataType&)>& predicate)
{
  SubscriptionDiagnosticsDataType last;
  for (int attempt = 0; attempt < 50; ++attempt)
  {
    ReadRequest req;
    ReadValueId rv;
    rv.node_id() = diagNode;
    rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    req.nodes_to_read().push_back(std::move(rv));
    req.timestamps_to_return() = TimestampsToReturn::Both;
    auto resp = session.attributes().read_sync(std::move(req));
    if (!resp.results().empty())
    {
      if (const auto* decoded = resp.results()[0].value().try_as<SubscriptionDiagnosticsDataType>())
      {
        last = *decoded;
        if (predicate(last))
          return last;
      }
    }
    std::this_thread::sleep_for(40ms);
  }
  return last;
}

}  // namespace

// ===========================================================================
// Fixture 1: TransferSubscriptionsSecure
// Basic256Sha256 / SignAndEncrypt + Anonymous auth, with a writable Int32 variable.
// Two client sessions (A, B) per test.
// ===========================================================================

class TransferSubscriptionsSecure : public ::testing::Test
{
protected:
  // Expensive one-time setup: crypto, certs, server, thread pools.
  static void SetUpTestSuite()
  {
    sLogSink = test_log_sink();

    // Crypto provider.
    sCrypto = create_default_crypto([]() { return ua::SecureString{"password"}; });

    // Self-signed certs (RSA SHA256, 2048-bit) for server and client.
    sServerCert = create_self_signed_cert(
      sCrypto, CertificateType::RsaSha256Application, "TestServer", "urn:test:transfer:server");
    sClientCertA = create_self_signed_cert(
      sCrypto, CertificateType::RsaSha256Application, "TestClientA", "urn:test:transfer:client:a");
    sClientCertB = create_self_signed_cert(
      sCrypto, CertificateType::RsaSha256Application, "TestClientB", "urn:test:transfer:client:b");

    // Server infrastructure.
    sServerThreadPool = std::make_unique<boost::asio::thread_pool>();
    auto serverExecutor = sServerThreadPool->executor();

    sTempDir =
      std::filesystem::temp_directory_path() / ("ua_xfer_test_" + Guid::create_and_generate().as_string());
    std::filesystem::create_directories(sTempDir);

    // Server cert store: add server cert, trust client cert.
    auto appStorePath = sTempDir / "app_group";
    std::filesystem::create_directories(appStorePath);
    TrustListValidationOptions appValidationOptions;
    sAppCertStore = CertificateStoreFiles::create(
      serverExecutor, sCrypto, {.trustListPath = appStorePath, .validationOptions = appValidationOptions});

    {
      CertificateStore::ApplicationCertificate appCert;
      appCert.certificateType = CertificateType::RsaSha256Application;
      appCert.certificate = sServerCert.cert;
      appCert.keys = sServerCert.keys;
      sAppCertStore->add_to_application_certificates_sync(appCert);
    }
    sAppCertStore->add_to_trusted_certificates_sync(sClientCertA.cert);
    sAppCertStore->add_to_trusted_certificates_sync(sClientCertB.cert);

    // Server security hooks: anonymous authentication + broad demonstration Role mapping.
    ServerComponents components{.crypto = sCrypto,
      .applicationGroupCertificateStore = sAppCertStore,
      .logSink = sLogSink,
      .logLevel = LogLevel::Debug};
    components.authenticator = std::make_shared<AnonymousAuthenticator>();
    components.roleConfiguration = RoleConfiguration::from_well_known_grants(
      {{WellKnownRole::SecurityAdmin, IdentityCriteriaType::Anonymous}});

    // Create server.
    auto appCfg = ua::test_utils::create_test_config();
    appCfg.allowInsecureEndpoints = false;

    ServerConfig serverCfg;
    serverCfg.connectionThrottling.enabled = false;

    server::CreateConfig serverCreateCfg{.identity = ApplicationIdentity::load_default(),
      .application = std::move(appCfg),
      .server = std::move(serverCfg)};

    sServer.emplace(Server::create(serverExecutor, std::move(serverCreateCfg), std::move(components)));

    // Listen on ephemeral port.
    transport::BindAddress bind;
    bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
    bind.address = "127.0.0.1:0";
    sListenerHandle = sServer->listen_sync(std::move(bind), {});

    // Add Basic256Sha256 / SignAndEncrypt endpoint with anonymous auth.
    ServerEndpointConfig endpoint;
    endpoint.name = "B256S256_SaE";
    endpoint.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
    endpoint.securityPolicyId = SecurityPolicyId::Basic256Sha256;

    UserTokenPolicy anonPolicy;
    anonPolicy.policy_id() = "anon";
    anonPolicy.token_type() = UserTokenType::Anonymous;
    endpoint.userIdentityTokens.push_back(std::move(anonPolicy));

    sServer->add_endpoint(sListenerHandle, endpoint);

    // Create writable variable node.
    auto addressSpace = sServer->address_space();
    auto testNamespace = default_ns::Namespace::create("urn:test:transfer", serverExecutor);
    sTestNamespaceIndex = addressSpace.add_namespace_sync(testNamespace);
    // A namespace that declares no RolePermissions publishes an ENGAGED, EMPTY default and hides
    // every undecorated node it owns, so an ordinary client is refused BadUserAccessDenied on
    // reads, browses and monitored items. This fixture derives from ::testing::Test rather than
    // ComplianceBase, so grant_fixture_namespace_permissions never runs for it; the per-namespace
    // form has to be called here. The subject of these tests is subscription transfer, not a
    // denial, so granting is not granting away the thing under test.
    ua::test_helpers::grant_namespace_to_test_client(addressSpace, sTestNamespaceIndex);

    sWritableVariableId = NodeId{sTestNamespaceIndex, uint32_t{1000}};
    auto varNode = addressSpace.create_node_sync(sWritableVariableId, NodeClass::Variable);
    auto variable = varNode.as<VariableAccessor>();
    variable->set_browse_name(QualifiedName{sTestNamespaceIndex, "WritableInt32"});
    variable->set_display_name(LocalizedText{"", "WritableInt32"});
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->write_value_sync(int32_t{42});
    variable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});

    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, sWritableVariableId);

    sServer->start_sync();

    auto urls = sServer->advertised_urls(sListenerHandle);
    sEndpointUrl = urls.front().str();

    // Client infrastructure.
    sClientThreadPool = std::make_unique<boost::asio::thread_pool>();

    auto clientStorePathA = sTempDir / "client_store_a";
    auto clientStorePathB = sTempDir / "client_store_b";
    std::filesystem::create_directories(clientStorePathA);
    std::filesystem::create_directories(clientStorePathB);
    TrustListValidationOptions clientValidationOptions;
    sClientCertStoreA = CertificateStoreFiles::create(sClientThreadPool->executor(),
      sCrypto,
      {.trustListPath = clientStorePathA, .validationOptions = clientValidationOptions});
    sClientCertStoreB = CertificateStoreFiles::create(sClientThreadPool->executor(),
      sCrypto,
      {.trustListPath = clientStorePathB, .validationOptions = clientValidationOptions});

    {
      CertificateStore::ApplicationCertificate cert;
      cert.certificateType = CertificateType::RsaSha256Application;
      cert.certificate = sClientCertA.cert;
      cert.keys = sClientCertA.keys;
      sClientCertStoreA->add_to_application_certificates_sync(cert);
    }
    {
      CertificateStore::ApplicationCertificate cert;
      cert.certificateType = CertificateType::RsaSha256Application;
      cert.certificate = sClientCertB.cert;
      cert.keys = sClientCertB.keys;
      sClientCertStoreB->add_to_application_certificates_sync(cert);
    }
    sClientCertStoreA->add_to_trusted_certificates_sync(sServerCert.cert);
    sClientCertStoreB->add_to_trusted_certificates_sync(sServerCert.cert);
  }

  static void TearDownTestSuite()
  {
    // Tear down in dependency order: gracefully shut the server down and destroy the consumers
    // (CertificateStoreFiles holds a boost::asio::strand<boost::asio::any_io_executor> bound to a pool's
    // io_context, so it MUST be destroyed before the owning boost::asio::thread_pool - otherwise the strand
    // outlives the io_context and its destructor accesses freed memory: SEH 0xc0000005 on Windows). Then
    // drain the pools.
    if (sServer)
      (void)sServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
    sServer.reset();
    sAppCertStore.reset();
    sClientCertStoreA.reset();
    sClientCertStoreB.reset();

    if (sServerThreadPool)
      sServerThreadPool->join();
    if (sClientThreadPool)
      sClientThreadPool->join();

    sServerThreadPool.reset();
    sClientThreadPool.reset();

    sCrypto.reset();
    sLogSink.reset();
    if (!sTempDir.empty())
      std::filesystem::remove_all(sTempDir);
  }

  // Per-test: open two channels + sessions.
  void SetUp() override
  {
    auto clientConfigA = ua::test_utils::create_test_config();
    clientConfigA.application_description_part().applicationUri = "urn:test:transfer:client:a";
    mClientA.emplace(CoreClient::create(sClientThreadPool->executor(),
      client::CreateConfig{
        .identity = ApplicationIdentity::load_default(), .application = std::move(clientConfigA)},
      ua::client::ClientComponents{.crypto = sCrypto,
        .applicationGroupCertificateStore = sClientCertStoreA,
        .logSink = sLogSink,
        .logLevel = LogLevel::Debug}));

    mChannelA.emplace(mClientA->open_channel_sync({.endpointUrl = sEndpointUrl,
      .securityMode = MessageSecurityMode::SignAndEncrypt,
      .securityPolicyId = SecurityPolicyId::Basic256Sha256,
      .serverCertificate = sServerCert.cert}));
    mSessionA.emplace(mChannelA->create_session_sync({.sessionName = "SessionA"}));
    mSessionA->activate_sync();

    auto clientConfigB = ua::test_utils::create_test_config();
    clientConfigB.application_description_part().applicationUri = "urn:test:transfer:client:b";
    mClientB.emplace(CoreClient::create(sClientThreadPool->executor(),
      client::CreateConfig{
        .identity = ApplicationIdentity::load_default(), .application = std::move(clientConfigB)},
      ua::client::ClientComponents{.crypto = sCrypto,
        .applicationGroupCertificateStore = sClientCertStoreB,
        .logSink = sLogSink,
        .logLevel = LogLevel::Debug}));

    mChannelB.emplace(mClientB->open_channel_sync({.endpointUrl = sEndpointUrl,
      .securityMode = MessageSecurityMode::SignAndEncrypt,
      .securityPolicyId = SecurityPolicyId::Basic256Sha256,
      .serverCertificate = sServerCert.cert}));
    mSessionB.emplace(mChannelB->create_session_sync({.sessionName = "SessionB"}));
    mSessionB->activate_sync();
  }

  void TearDown() override
  {
    if (mSessionB)
      (void)mSessionB->try_close_sync();
    if (mChannelB)
      (void)mChannelB->try_close_sync();
    mClientB.reset();

    if (mSessionA)
      (void)mSessionA->try_close_sync();
    if (mChannelA)
      (void)mChannelA->try_close_sync();
    mClientA.reset();
  }

  // Open a second channel of client A, so that a Session created on it shares mSessionA's
  // ApplicationUri.
  //
  // Part 4 section 5.13.7.1: "If the Client uses an ANONYMOUS user token, the Server shall validate if the
  // ApplicationUri is the same for the old and the new Session and the MessageSecurityMode is SIGN or
  // SIGNANDENCRYPT." Every Session in this fixture is anonymous, and mClientA / mClientB deliberately
  // advertise different ApplicationUris (that difference is what the alt-client diagnostics test is
  // about). A transfer from mSessionA to mSessionB is therefore refused with Bad_UserAccessDenied
  // before any transfer mechanics run - correctly so. Tests whose obligation is about the mechanics
  // (the items, the sendInitialValues flag, the retransmission queue) must take their target Session
  // from client A instead. The caller creates and activates the Session on the returned channel and
  // must keep that channel alive for the Session's lifetime.
  SecureChannel open_same_client_channel()
  {
    return mClientA->open_channel_sync({.endpointUrl = sEndpointUrl,
      .securityMode = MessageSecurityMode::SignAndEncrypt,
      .securityPolicyId = SecurityPolicyId::Basic256Sha256,
      .serverCertificate = sServerCert.cert});
  }

  // Suite-level state.
  static inline std::shared_ptr<LogSink> sLogSink;
  static inline std::shared_ptr<const Crypto> sCrypto;
  static inline KeyMaterial sServerCert;
  static inline KeyMaterial sClientCertA;
  static inline KeyMaterial sClientCertB;
  static inline std::unique_ptr<boost::asio::thread_pool> sServerThreadPool;
  static inline std::unique_ptr<boost::asio::thread_pool> sClientThreadPool;
  static inline std::filesystem::path sTempDir;
  static inline std::shared_ptr<CertificateStore> sAppCertStore;
  static inline std::shared_ptr<CertificateStore> sClientCertStoreA;
  static inline std::shared_ptr<CertificateStore> sClientCertStoreB;
  static inline std::optional<Server> sServer;
  static inline ListenerHandle sListenerHandle{0};
  static inline std::string sEndpointUrl;
  static inline uint16_t sTestNamespaceIndex{0};
  static inline NodeId sWritableVariableId;

  // Per-test state.
  std::optional<CoreClient> mClientA;
  std::optional<SecureChannel> mChannelA;
  std::optional<Session> mSessionA;

  std::optional<CoreClient> mClientB;
  std::optional<SecureChannel> mChannelB;
  std::optional<Session> mSessionB;
};

// ===========================================================================
// Fixture 2: TransferSubscriptionsNone
// None / None + Anonymous auth. For SVR-XFER-003 negative test.
// ===========================================================================

class TransferSubscriptionsNone : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mServer.create();

    ServerEndpointConfig endpoint;
    endpoint.name = "None";
    endpoint.messageSecurityMode = MessageSecurityMode::None;
    endpoint.securityPolicyId = SecurityPolicyId::None;

    UserTokenPolicy anonPolicy;
    anonPolicy.policy_id() = "anon";
    anonPolicy.token_type() = UserTokenType::Anonymous;
    endpoint.userIdentityTokens.push_back(std::move(anonPolicy));

    mListener = mServer.listen_ephemeral();
    mServer.add_endpoint(mListener, endpoint);
    mServer.start();

    auto urls = mServer.server().advertised_urls(mListener);
    ASSERT_FALSE(urls.empty());
    mEndpointUrl = urls.front().str();

    // The server's sink is installed by TestServer::create (test_log_sink()); wire the clients here.
    auto logSink = test_log_sink();

    // Client A.
    mClientA.emplace(CoreClient::create(mClientThreadPool.executor(),
      ua::test_utils::create_test_client_config(),
      ua::client::ClientComponents{
        .crypto = ua::test_helpers::test_crypto(), .logSink = logSink, .logLevel = LogLevel::Debug}));
    mChannelA.emplace(mClientA->open_channel_sync({.endpointUrl = mEndpointUrl}));
    mSessionA.emplace(mChannelA->create_session_sync({.sessionName = "SessionA_None"}));
    mSessionA->activate_sync();

    // Client B.
    mClientB.emplace(CoreClient::create(mClientThreadPool.executor(),
      ua::test_utils::create_test_client_config(),
      ua::client::ClientComponents{
        .crypto = ua::test_helpers::test_crypto(), .logSink = logSink, .logLevel = LogLevel::Debug}));
    mChannelB.emplace(mClientB->open_channel_sync({.endpointUrl = mEndpointUrl}));
    mSessionB.emplace(mChannelB->create_session_sync({.sessionName = "SessionB_None"}));
    mSessionB->activate_sync();
  }

  void TearDown() override
  {
    if (mSessionB)
      (void)mSessionB->try_close_sync();
    if (mChannelB)
      (void)mChannelB->try_close_sync();
    mClientB.reset();

    if (mSessionA)
      (void)mSessionA->try_close_sync();
    if (mChannelA)
      (void)mChannelA->try_close_sync();
    mClientA.reset();

    ::ua::test_utils::stop_pool_in_teardown(mClientThreadPool, "client");
  }

  TestServer mServer;
  boost::asio::thread_pool mClientThreadPool;
  ListenerHandle mListener{0};
  std::string mEndpointUrl;

  std::optional<CoreClient> mClientA;
  std::optional<SecureChannel> mChannelA;
  std::optional<Session> mSessionA;

  std::optional<CoreClient> mClientB;
  std::optional<SecureChannel> mChannelB;
  std::optional<Session> mSessionB;
};

// ===========================================================================
// Service-level error tests (TransferSubscriptionsSecure)
// ===========================================================================

/// SVR-XFER-SVC-001: Empty subscription_ids list returns BadNothingToDo.
// @relation(SVR-XFER-OP-002, SVR-XFER-SVC-001, scope=function)
TEST_F(TransferSubscriptionsSecure, TransferSub_EmptyList_BadNothingToDo)
{
  TransferSubscriptionsRequest req;
  // subscription_ids is empty.
  req.send_initial_values() = false;

  auto result = mSessionB->subscriptions().try_transfer_subscriptions_sync(std::move(req));
  if (result.is_good())
  {
    auto& resp = result.value();
    EXPECT_EQ(resp.response_header().service_result(), StatusCode{Status::BadNothingToDo})
      << "Expected service-level BadNothingToDo for empty subscription list, got: "
      << to_string(resp.response_header().service_result());
  }
  else
  {
    // Transport-level or decode error carrying BadNothingToDo is also acceptable.
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadNothingToDo})
      << "Expected BadNothingToDo, got: " << to_string(result.status_code());
  }
}

/// SVR-XFER-SM-022: Self-transfer (transferring a subscription to the session that already owns it).
/// State machine transition #22: SessionChanged()==FALSE -> ReturnNegativeResponse().
/// The spec does not mandate a specific StatusCode for this case; it just says "negative response".
/// The per-result status must be bad (not Good).
// @relation(SVR-XFER-OP-002, SVR-XFER-SM-022, scope=function)
TEST_F(TransferSubscriptionsSecure, TransferSub_SelfTransfer_NegativeResponse)
{
  auto subId = create_subscription(*mSessionA);

  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  req.send_initial_values() = false;

  // Transfer from A to A (self-transfer).
  auto result = mSessionA->subscriptions().try_transfer_subscriptions_sync(std::move(req));
  ASSERT_TRUE(result.is_good()) << "Request failed: " << to_string(result.status_code());
  auto& resp = result.value();

  if (resp.response_header().service_result().is_good())
  {
    // Service succeeded - check per-result is a negative (bad) status.
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_TRUE(resp.results()[0].status_code().is_bad())
      << "Self-transfer must return a negative per-result status (transition #22), got: "
      << to_string(resp.results()[0].status_code());
  }
  else
  {
    // Service-level bad status is also a valid negative response.
    EXPECT_TRUE(resp.response_header().service_result().is_bad())
      << "Self-transfer must return a negative response (transition #22), got: "
      << to_string(resp.response_header().service_result());
  }
}

/// SVR-XFER-OP-001: Transferring a non-existent subscription ID returns per-result
/// BadSubscriptionIdInvalid.
// @relation(SVR-XFER-OP-001, SVR-XFER-OP-002, scope=function)
TEST_F(TransferSubscriptionsSecure, TransferSub_InvalidId_BadSubscriptionIdInvalid)
{
  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(99999);
  req.send_initial_values() = false;

  auto result = mSessionB->subscriptions().try_transfer_subscriptions_sync(std::move(req));
  ASSERT_TRUE(result.is_good()) << "Request failed: " << to_string(result.status_code());
  auto& resp = result.value();
  ASSERT_TRUE(resp.response_header().service_result().is_good())
    << "Service-level error: " << to_string(resp.response_header().service_result());

  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_EQ(resp.results()[0].status_code(), StatusCode{Status::BadSubscriptionIdInvalid})
    << "Expected BadSubscriptionIdInvalid, got: " << to_string(resp.results()[0].status_code());
}

/// SVR-XFER-OP-001: Multiple non-existent subscription IDs all return BadSubscriptionIdInvalid.
// @relation(SVR-XFER-OP-001, scope=function)
TEST_F(TransferSubscriptionsSecure, TransferSub_MultipleInvalidIds)
{
  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(99999);
  req.subscription_ids().push_back(88888);
  req.subscription_ids().push_back(77777);
  req.send_initial_values() = false;

  auto result = mSessionB->subscriptions().try_transfer_subscriptions_sync(std::move(req));
  ASSERT_TRUE(result.is_good()) << "Request failed: " << to_string(result.status_code());
  auto& resp = result.value();
  ASSERT_TRUE(resp.response_header().service_result().is_good())
    << "Service-level error: " << to_string(resp.response_header().service_result());

  ASSERT_EQ(resp.results().size(), 3u);
  for (size_t i = 0; i < 3; ++i)
  {
    EXPECT_EQ(resp.results()[i].status_code(), StatusCode{Status::BadSubscriptionIdInvalid})
      << "Result[" << i
      << "] expected BadSubscriptionIdInvalid, got: " << to_string(resp.results()[i].status_code());
  }
}

// ===========================================================================
// Successful transfer tests (TransferSubscriptionsSecure)
// ===========================================================================

/// SVR-XFER-001, SVR-XFER-SM-023: Basic successful transfer of a subscription from session A to B.
// @relation(SVR-XFER-OP-002, scope=function)
TEST_F(TransferSubscriptionsSecure, TransferSub_BasicSuccess)
{
  // Part 4 section 5.13.7.1 forbids an anonymous transfer across ApplicationUris; this test's subject is
  // the transfer mechanics, so the target Session comes from client A.
  auto basicSuccessChannel = open_same_client_channel();
  auto target = basicSuccessChannel.create_session_sync({.sessionName = "TransferSub_BasicSuccess_target"});
  target.activate_sync();

  auto subId = create_subscription(*mSessionA);

  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  req.send_initial_values() = false;

  auto result = target.subscriptions().try_transfer_subscriptions_sync(std::move(req));
  ASSERT_TRUE(result.is_good()) << "Request failed: " << to_string(result.status_code());
  auto& resp = result.value();
  ASSERT_TRUE(resp.response_header().service_result().is_good())
    << "Service-level error: " << to_string(resp.response_header().service_result());

  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_TRUE(resp.results()[0].status_code().is_good())
    << "Expected Good per-result, got: " << to_string(resp.results()[0].status_code());
}

/// XFER-DIAG (same client): a transfer between two sessions of the SAME Client (identical
/// ApplicationUri) records exactly one transfer to the SAME client. Second session is opened on
/// mClientA so both sessions share one ClientDescription.ApplicationUri.
TEST_F(TransferSubscriptionsSecure, TransferSub_SameClientTransferDiagnostics)
{
  auto channelA2 = mClientA->open_channel_sync({.endpointUrl = sEndpointUrl,
    .securityMode = MessageSecurityMode::SignAndEncrypt,
    .securityPolicyId = SecurityPolicyId::Basic256Sha256,
    .serverCertificate = sServerCert.cert});
  auto sessionA2 = channelA2.create_session_sync({.sessionName = "SessionA2_same"});
  sessionA2.activate_sync();

  auto subId = create_subscription(*mSessionA);
  auto sourceDiagNode = wait_for_subscription_diag_node(*mSessionA, subId);
  ASSERT_TRUE(sourceDiagNode.has_value());

  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  req.send_initial_values() = false;
  auto result = sessionA2.subscriptions().try_transfer_subscriptions_sync(std::move(req));
  ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
  ASSERT_EQ(result.value().results().size(), 1u);
  ASSERT_TRUE(result.value().results()[0].status_code().is_good())
    << to_string(result.value().results()[0].status_code());

  auto diagNode = wait_for_subscription_diag_node(sessionA2, subId, sourceDiagNode);
  ASSERT_TRUE(diagNode.has_value()) << "No SubscriptionDiagnostics node for transferred sub " << subId;

  auto diag = wait_for_transfer_diagnostics(sessionA2,
    *diagNode,
    [](const SubscriptionDiagnosticsDataType& d) { return d.transfer_request_count() >= 1; });
  EXPECT_EQ(diag.transfer_request_count(), 1u);
  EXPECT_EQ(diag.transferred_to_same_client_count(), 1u) << "both sessions belong to mClientA";
  EXPECT_EQ(diag.transferred_to_alt_client_count(), 0u);

  (void)sessionA2.try_close_sync();
  (void)channelA2.try_close_sync();
}

/// SVR-XFER-001, SVR-XFER-OP-001: Mixed results when transferring one valid and one invalid subscription ID.
// @relation(SVR-XFER-OP-001, scope=function)
TEST_F(TransferSubscriptionsSecure, TransferSub_MixedResults)
{
  // Part 4 section 5.13.7.1 forbids an anonymous transfer across ApplicationUris; this test's subject is
  // the transfer mechanics, so the target Session comes from client A.
  auto mixedResultsChannel = open_same_client_channel();
  auto target = mixedResultsChannel.create_session_sync({.sessionName = "TransferSub_MixedResults_target"});
  target.activate_sync();

  auto subId = create_subscription(*mSessionA);

  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  req.subscription_ids().push_back(99999);  // Invalid ID.
  req.send_initial_values() = false;

  auto result = target.subscriptions().try_transfer_subscriptions_sync(std::move(req));
  ASSERT_TRUE(result.is_good()) << "Request failed: " << to_string(result.status_code());
  auto& resp = result.value();
  ASSERT_TRUE(resp.response_header().service_result().is_good())
    << "Service-level error: " << to_string(resp.response_header().service_result());

  ASSERT_EQ(resp.results().size(), 2u);
  EXPECT_TRUE(resp.results()[0].status_code().is_good())
    << "First result expected Good, got: " << to_string(resp.results()[0].status_code());
  EXPECT_EQ(resp.results()[1].status_code(), StatusCode{Status::BadSubscriptionIdInvalid})
    << "Second result expected BadSubscriptionIdInvalid, got: " << to_string(resp.results()[1].status_code());
}

/// SVR-XFER-001: After transfer, the new session receives data change notifications.
// @relation(SVR-XFER-OP-002, SVR-XFER-SM-023, scope=function)
TEST_F(TransferSubscriptionsSecure, TransferSub_SubscriptionContinuesOnNewSession)
{
  // Part 4 section 5.13.7.1 forbids an anonymous transfer across ApplicationUris; this test's subject is
  // the transfer mechanics, so the target Session comes from client A.
  auto continuesChannel = open_same_client_channel();
  auto target = continuesChannel.create_session_sync(
    {.sessionName = "TransferSub_SubscriptionContinuesOnNewSession_target"});
  target.activate_sync();

  auto [subId, miId] = create_subscription_with_monitored_item(*mSessionA, sWritableVariableId);

  drain_initial_publish(*mSessionA, subId);

  // Transfer to session B (sendInitialValues=false).
  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  req.send_initial_values() = false;

  auto xferResult = target.subscriptions().try_transfer_subscriptions_sync(std::move(req));
  ASSERT_TRUE(xferResult.is_good()) << "Transfer failed: " << to_string(xferResult.status_code());
  auto& xferResp = xferResult.value();
  ASSERT_TRUE(xferResp.response_header().service_result().is_good())
    << "Transfer service error: " << to_string(xferResp.response_header().service_result());
  ASSERT_EQ(xferResp.results().size(), 1u);
  ASSERT_TRUE(xferResp.results()[0].status_code().is_good())
    << "Transfer per-result error: " << to_string(xferResp.results()[0].status_code());

  // Write a new value to trigger a data change.
  write_value_async(target, sWritableVariableId, Variant{int32_t{123}});

  // Publish on session B - expect to receive the data change.
  auto notif = wait_for_data_change(target, subId);
  ASSERT_TRUE(notif) << "Expected DataChangeNotification on session B after transfer";
  ASSERT_FALSE(notif->monitored_items().empty());
  EXPECT_THAT(*notif, ContainsDataChangeFor(1u, good_value_of<int32_t>(123)));
}

/// SVR-XFER-001: After transfer, the old session no longer receives data for that subscription.
/// The subscription has been moved to session B, so session A must not get DataChangeNotifications.
// @relation(SVR-XFER-SM-023, scope=function)
TEST_F(TransferSubscriptionsSecure, TransferSub_OldSessionNoLongerReceives)
{
  // Part 4 section 5.13.7.1 forbids an anonymous transfer across ApplicationUris; this test's subject is
  // the transfer mechanics, so the target Session comes from client A.
  auto oldSessionSilentChannel = open_same_client_channel();
  auto target = oldSessionSilentChannel.create_session_sync(
    {.sessionName = "TransferSub_OldSessionNoLongerReceives_target"});
  target.activate_sync();

  auto [subId, miId] = create_subscription_with_monitored_item(*mSessionA, sWritableVariableId);

  drain_initial_publish(*mSessionA, subId);

  // Transfer to session B.
  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  req.send_initial_values() = false;

  auto xferResult = target.subscriptions().try_transfer_subscriptions_sync(std::move(req));
  ASSERT_TRUE(xferResult.is_good()) << to_string(xferResult.status_code());
  ASSERT_TRUE(xferResult.value().response_header().service_result().is_good());
  ASSERT_EQ(xferResult.value().results().size(), 1u);
  ASSERT_TRUE(xferResult.value().results()[0].status_code().is_good());

  // Write a new value - this should only be visible to session B, not A.
  write_value_async(target, sWritableVariableId, Variant{int32_t{999}});

  // Session A must NOT receive a DataChangeNotification for the transferred sub.
  // Use ~1.5s - long enough to cover several full publish cycles at the 100ms
  // publishingInterval default so a regression that leaks a DCN through to
  // session A has time to surface. A bad service result internally
  // (e.g. BadNoSubscription) is skipped by wait_for_publish, which also
  // produces nullopt - that is correct per the spec.
  auto notif = wait_for_data_change(*mSessionA, subId, 1500ms);
  EXPECT_FALSE(notif)
    << "Session A must not receive DataChangeNotifications after subscription was transferred";
}

/// SVR-XFER-001: Transfer multiple subscriptions in one request.
// @relation(SVR-XFER-SM-023, scope=function)
TEST_F(TransferSubscriptionsSecure, TransferSub_MultipleSubscriptionsTransfer)
{
  // Part 4 section 5.13.7.1 forbids an anonymous transfer across ApplicationUris; this test's subject is
  // the transfer mechanics, so the target Session comes from client A.
  auto multipleSubsChannel = open_same_client_channel();
  auto target = multipleSubsChannel.create_session_sync(
    {.sessionName = "TransferSub_MultipleSubscriptionsTransfer_target"});
  target.activate_sync();

  auto subId1 = create_subscription(*mSessionA);
  auto subId2 = create_subscription(*mSessionA);

  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId1);
  req.subscription_ids().push_back(subId2);
  req.send_initial_values() = false;

  auto result = target.subscriptions().try_transfer_subscriptions_sync(std::move(req));
  ASSERT_TRUE(result.is_good()) << "Request failed: " << to_string(result.status_code());
  auto& resp = result.value();
  ASSERT_TRUE(resp.response_header().service_result().is_good())
    << "Service-level error: " << to_string(resp.response_header().service_result());

  ASSERT_EQ(resp.results().size(), 2u);
  EXPECT_TRUE(resp.results()[0].status_code().is_good())
    << "First subscription transfer failed: " << to_string(resp.results()[0].status_code());
  EXPECT_TRUE(resp.results()[1].status_code().is_good())
    << "Second subscription transfer failed: " << to_string(resp.results()[1].status_code());
}

// ===========================================================================
// StatusChangeNotification test (TransferSubscriptionsSecure)
// ===========================================================================

/// SVR-XFER-004: After transfer, the old session receives a StatusChangeNotification
/// with Good_SubscriptionTransferred.
///
/// Part 4, section 5.13.7.1: "If the Server transfers the Subscription to the new Session,
/// the Server shall issue a StatusChangeNotification notificationMessage with the
/// status code Good_SubscriptionTransferred to the old Session."
///
/// The SCN is dispatched to a pending publish on session A during detach. We must
/// have a publish request queued on A before the transfer to receive it. We use
/// publish_async to queue the request, then transfer, then collect the result.
/// SVR-SUB-GEN-101: Good_SubscriptionTransferred is used in StatusChangeNotification
/// if the Subscription was transferred to another Session.
// @relation(SVR-XFER-OP-002, scope=function)
TEST_F(TransferSubscriptionsSecure, TransferSub_StatusChangeNotification)
{
  // Part 4 section 5.13.7.1 forbids an anonymous transfer across ApplicationUris; this test's subject is
  // the transfer mechanics, so the target Session comes from client A.
  auto statusChangeChannel = open_same_client_channel();
  auto target =
    statusChangeChannel.create_session_sync({.sessionName = "TransferSub_StatusChangeNotification_target"});
  target.activate_sync();

  auto subId = create_subscription(*mSessionA);

  // Drain initial notifications on A.
  (void)wait_for_publish(
    *mSessionA, [subId](const PublishResponse& r) { return r.subscription_id() == subId; }, 500ms);

  // Queue an async publish on session A so it's pending when the transfer happens.
  //
  // The promise is shared with the callback rather than captured by reference. A pending Publish
  // outlives this scope on every failing path: an ASSERT below returns from the test body, teardown
  // closes session A, and the session completes its outstanding request with an error. A
  // stack promise captured by reference would be gone by then and set_value would write into a
  // destroyed frame.
  auto publishPromise = std::make_shared<std::promise<SessionSubscriptionServices::PublishResponseResult>>();
  auto publishFuture = publishPromise->get_future();
  mSessionA->subscriptions().publish_async(PublishRequest{},
    [publishPromise](SessionSubscriptionServices::PublishResponseResult result)
    { publishPromise->set_value(std::move(result)); });

  // Give the publish request time to reach the server.
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  // Transfer to B.
  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  req.send_initial_values() = false;

  auto xferResult = target.subscriptions().try_transfer_subscriptions_sync(std::move(req));
  ASSERT_TRUE(xferResult.is_good()) << to_string(xferResult.status_code());
  ASSERT_TRUE(xferResult.value().response_header().service_result().is_good());
  ASSERT_EQ(xferResult.value().results().size(), 1u);
  ASSERT_TRUE(xferResult.value().results()[0].status_code().is_good());

  // Collect the async publish result from session A.
  auto futureStatus = publishFuture.wait_for(std::chrono::seconds(5));
  ASSERT_EQ(futureStatus, std::future_status::ready) << "Async publish on session A timed out";

  auto pubResult = publishFuture.get();
  ASSERT_TRUE(pubResult.is_good()) << "Publish on session A failed: " << to_string(pubResult.status_code());
  auto& pubResp = pubResult.value();

  const auto* scn = as_status_change(pubResp);
  ASSERT_NE(scn, nullptr)
    << "Old session must receive StatusChangeNotification after transfer (SVR-XFER-004)";
  EXPECT_EQ(scn->status(), StatusCode{Status::GoodSubscriptionTransferred})
    << "StatusChangeNotification status must be GoodSubscriptionTransferred, got: "
    << to_string(scn->status());
}

// ===========================================================================
// sendInitialValues tests (TransferSubscriptionsSecure)
// ===========================================================================

/// SVR-XFER-005: With sendInitialValues=true, the new session receives the current value
/// of all monitored items immediately after transfer.
///
/// The target Session is opened on mClientA rather than mClientB. Both Sessions here are anonymous,
/// and Part 4 section 5.13.7.1 permits an anonymous transfer only between Sessions of the same Client
/// - mClientA and mClientB advertise different ApplicationUris on purpose, for the alt-client
/// diagnostics rows. Transferring across them is refused by the Server, correctly, before this test's
/// own subject is reached.
// @relation(SVR-XFER-OP-002, scope=function)
// @verifies AC-SVR-XFER-005-SENDINITIALVALUES-TRUE
TEST_F(TransferSubscriptionsSecure, TransferSub_SendInitialValues_True)
{
  auto channelA2 = mClientA->open_channel_sync({.endpointUrl = sEndpointUrl,
    .securityMode = MessageSecurityMode::SignAndEncrypt,
    .securityPolicyId = SecurityPolicyId::Basic256Sha256,
    .serverCertificate = sServerCert.cert});
  auto target = channelA2.create_session_sync({.sessionName = "SessionA2_initialValues"});
  target.activate_sync();

  // Ensure variable has value 42.
  write_value_async(*mSessionA, sWritableVariableId, Variant{int32_t{42}});

  auto [subId, miId] = create_subscription_with_monitored_item(*mSessionA, sWritableVariableId);

  drain_initial_publish(*mSessionA, subId);

  // Transfer with sendInitialValues=true.
  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  req.send_initial_values() = true;

  auto xferResult = target.subscriptions().try_transfer_subscriptions_sync(std::move(req));
  ASSERT_TRUE(xferResult.is_good()) << to_string(xferResult.status_code());
  ASSERT_TRUE(xferResult.value().response_header().service_result().is_good());
  ASSERT_EQ(xferResult.value().results().size(), 1u);
  ASSERT_TRUE(xferResult.value().results()[0].status_code().is_good());

  // Publish on the target - should receive the current value (42) as an initial notification.
  auto notif = wait_for_data_change(target, subId);
  ASSERT_TRUE(notif) << "Expected DataChangeNotification with initial values on the target session";
  ASSERT_FALSE(notif->monitored_items().empty());
  EXPECT_THAT(*notif, ContainsDataChangeFor(1u, good_value_of<int32_t>(42)));
}

/// SVR-XFER-006: With sendInitialValues=false, the new session does NOT receive initial values
/// (only a keep-alive or nothing until the next actual data change).
// @relation(SVR-XFER-OP-002, scope=function)
TEST_F(TransferSubscriptionsSecure, TransferSub_SendInitialValues_False)
{
  // Part 4 section 5.13.7.1 forbids an anonymous transfer across ApplicationUris; this test's subject is
  // the transfer mechanics, so the target Session comes from client A.
  auto initialValuesFalseChannel = open_same_client_channel();
  auto target = initialValuesFalseChannel.create_session_sync(
    {.sessionName = "TransferSub_SendInitialValues_False_target"});
  target.activate_sync();

  // Ensure variable has value 42.
  write_value_async(*mSessionA, sWritableVariableId, Variant{int32_t{42}});

  auto [subId, miId] = create_subscription_with_monitored_item(*mSessionA, sWritableVariableId);

  drain_initial_publish(*mSessionA, subId);

  // Transfer to B with sendInitialValues=false.
  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  req.send_initial_values() = false;

  auto xferResult = target.subscriptions().try_transfer_subscriptions_sync(std::move(req));
  ASSERT_TRUE(xferResult.is_good()) << to_string(xferResult.status_code());
  ASSERT_TRUE(xferResult.value().response_header().service_result().is_good());
  ASSERT_EQ(xferResult.value().results().size(), 1u);
  ASSERT_TRUE(xferResult.value().results()[0].status_code().is_good());

  // Publish on B - per spec, "shall contain only the value changes since the last Publish
  // response was sent." Since we haven't changed the value since the last publish on A,
  // there should be no DataChangeNotification carrying the current value.
  //
  // The pre-migration assertion accepted both "no DCN" AND "DCN with empty monitored_items"
  // - a legal keep-alive-like emission. Match that permissiveness by predicating on
  // non-empty monitored_items: the test fails only when a DCN actually carries a value
  // for our MI. Timeout bumped to 1.5s so the poll covers a full publish cadence at
  // the default keep-alive interval (10 x 100ms).
  auto carriesAnyValue = [](const DataChangeNotification& dc)
  {
    return !dc.monitored_items().empty();
  };
  auto notif = wait_for_data_change(target, subId, carriesAnyValue, 1500ms);
  EXPECT_FALSE(notif) << "With sendInitialValues=false and no value change, must not receive initial "
                         "DataChangeNotification (Part 4, Table 100, l.5865-5867)";
}

/// Part 4 section 5.13.7.1: a Subscription whose Session has closed without deleting it keeps sampling its
/// MonitoredItems, and a Session that transfers it receives what was queued while nobody owned it - the
/// recovery a durable Subscription exists for (the CTT's Subscription Durable 004). With sendInitialValues
/// false the first Publish carries exactly those queued changes.
TEST_F(TransferSubscriptionsSecure, TransferSub_OrphanedSubscriptionDeliversTheValuesQueuedWhileOrphaned)
{
  write_value_async(*mSessionA, sWritableVariableId, Variant{int32_t{100}});

  auto ownerChannel = open_same_client_channel();
  auto owner = ownerChannel.create_session_sync({.sessionName = "OrphanedQueueOwner"});
  owner.activate_sync();
  auto [subId, miId] = create_subscription_with_monitored_item(
    owner, sWritableVariableId, {.lifetimeCount = 600}, {.samplingInterval = 50.0, .queueSize = 100});
  drain_initial_publish(owner, subId);

  auto parked = owner.try_close_sync(ua::client::Session::CloseOptions{.deleteSubscriptions = false});
  ASSERT_THAT(parked, ::ua::test_helpers::Good()) << "the owner must close without deleting its Subscription";
  (void)ownerChannel.try_close_sync();

  // Changes made while the Subscription has no Session. Each is held for several sampling intervals so
  // every one is sampled.
  for (int32_t value = 101; value <= 103; ++value)
  {
    write_value_async(*mSessionA, sWritableVariableId, Variant{value});
    std::this_thread::sleep_for(300ms);
  }

  auto recoveryChannel = open_same_client_channel();
  auto recovery = recoveryChannel.create_session_sync({.sessionName = "OrphanedQueueRecovery"});
  recovery.activate_sync();
  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  req.send_initial_values() = false;
  auto transferred = recovery.subscriptions().try_transfer_subscriptions_sync(std::move(req));
  ASSERT_TRUE(transferred.is_good()) << to_string(transferred.status_code());
  ASSERT_EQ(transferred.value().results().size(), 1u);
  ASSERT_TRUE(transferred.value().results()[0].status_code().is_good())
    << to_string(transferred.value().results()[0].status_code());

  std::vector<int32_t> delivered;
  const auto collect = [&delivered](const DataChangeNotification& dc)
  {
    for (const auto& item : dc.monitored_items())
    {
      if (const auto* value = item.value().value().try_as<int32_t>())
        delivered.push_back(*value);
    }
    return std::find(delivered.begin(), delivered.end(), 103) != delivered.end();
  };
  EXPECT_TRUE(wait_for_data_change(recovery, subId, collect, 3000ms))
    << "the transferred Subscription must deliver the changes it sampled while orphaned";
  EXPECT_EQ(delivered, (std::vector<int32_t>{101, 102, 103}))
    << "every change queued while orphaned, in order, and nothing sent before the orphaning again";

  (void)recovery.try_close_sync();
  (void)recoveryChannel.try_close_sync();
}

/// The throwing close with options (API-4.4) passes deleteSubscriptions to CloseSession (Part 4 section
/// 5.6.4): with false the Subscription survives the Session and another Session can transfer it; with the
/// default options it is deleted, and the transfer finds no such Subscription.
TEST_F(TransferSubscriptionsSecure, TransferSub_CloseSyncWithOptionsKeepsOrDeletesTheSubscription)
{
  for (const bool deleteSubscriptions : {false, true})
  {
    auto ownerChannel = open_same_client_channel();
    auto owner = ownerChannel.create_session_sync({.sessionName = "CloseSyncOptionsOwner"});
    owner.activate_sync();
    auto [subId, miId] =
      create_subscription_with_monitored_item(owner, sWritableVariableId, {.lifetimeCount = 600});
    ua::client::Session::CloseOptions options;  // the default deletes
    if (!deleteSubscriptions)
      options.deleteSubscriptions = false;
    owner.close_sync(options);
    (void)ownerChannel.try_close_sync();

    auto recoveryChannel = open_same_client_channel();
    auto recovery = recoveryChannel.create_session_sync({.sessionName = "CloseSyncOptionsRecovery"});
    recovery.activate_sync();
    TransferSubscriptionsRequest req;
    req.subscription_ids().push_back(subId);
    auto transferred = recovery.subscriptions().try_transfer_subscriptions_sync(std::move(req));
    ASSERT_TRUE(transferred.is_good()) << to_string(transferred.status_code());
    ASSERT_EQ(transferred.value().results().size(), 1u);
    const auto status = transferred.value().results()[0].status_code();
    if (deleteSubscriptions)
    {
      EXPECT_EQ(status, StatusCode{Status::BadSubscriptionIdInvalid})
        << "the default options delete the Subscription, got " << to_string(status);
    }
    else
    {
      EXPECT_TRUE(status.is_good())
        << "deleteSubscriptions=false must leave the Subscription to transfer, got " << to_string(status);
    }

    (void)recovery.try_close_sync();
    (void)recoveryChannel.try_close_sync();
  }
}

// ===========================================================================
// Retransmission test (TransferSubscriptionsSecure)
// ===========================================================================

/// SVR-XFER-008: After transfer, the TransferResult should contain available_sequence_numbers
/// for any unacknowledged notifications.
///
/// The target Session is opened on mClientA for the reason given on TransferSub_SendInitialValues_True:
/// an anonymous transfer between two different Clients is refused by Part 4 section 5.13.7.1, and
/// mClientB advertises a different ApplicationUri on purpose.
// Covers SVR-XFER-016 (coverage-audit retag).
// @relation(SVR-XFER-OP-002, scope=function)
// @verifies AC-SVR-XFER-016-AVAILABLE-SEQUENCE-NUMBERS
TEST_F(TransferSubscriptionsSecure, TransferSub_AvailableSequenceNumbers)
{
  auto channelA2 = mClientA->open_channel_sync({.endpointUrl = sEndpointUrl,
    .securityMode = MessageSecurityMode::SignAndEncrypt,
    .securityPolicyId = SecurityPolicyId::Basic256Sha256,
    .serverCertificate = sServerCert.cert});
  auto target = channelA2.create_session_sync({.sessionName = "SessionA2_availableSeq"});
  target.activate_sync();

  auto [subId, miId] = create_subscription_with_monitored_item(*mSessionA, sWritableVariableId);

  // Get a publish response (initial data change). Do NOT acknowledge it.
  // Use wait_for_publish primitive to retain access to the full PublishResponse - the
  // DCN extraction in wait_for_data_change discards the surrounding sequence_number().
  auto pubResp = wait_for_publish(
    *mSessionA,
    [subId](const PublishResponse& r)
    { return r.subscription_id() == subId && as_data_change(r) != nullptr; },
    2s);
  ASSERT_TRUE(pubResp.has_value()) << "Expected initial publish response on session A";

  uint32_t seqNum = pubResp->notification_message().sequence_number();
  ASSERT_GT(seqNum, 0u) << "Expected a valid sequence number";

  // Transfer. The unacknowledged notification should appear in available_sequence_numbers.
  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  req.send_initial_values() = false;

  auto xferResult = target.subscriptions().try_transfer_subscriptions_sync(std::move(req));
  ASSERT_TRUE(xferResult.is_good()) << to_string(xferResult.status_code());
  ASSERT_TRUE(xferResult.value().response_header().service_result().is_good());
  ASSERT_EQ(xferResult.value().results().size(), 1u);
  ASSERT_TRUE(xferResult.value().results()[0].status_code().is_good());

  auto& transferResult = xferResult.value().results()[0];
  EXPECT_FALSE(transferResult.available_sequence_numbers().empty())
    << "Expected non-empty available_sequence_numbers after transfer with unacknowledged notification";

  // The unacknowledged sequence number should be in the list.
  bool found = false;
  for (const auto& sn : transferResult.available_sequence_numbers())
  {
    if (sn == seqNum)
    {
      found = true;
      break;
    }
  }
  EXPECT_TRUE(found) << "Expected sequence number " << seqNum << " in available_sequence_numbers";
}

// ===========================================================================
// Anonymous + None negative test (TransferSubscriptionsNone)
// ===========================================================================

/// SVR-XFER-003: TransferSubscriptions on an unsecured (None/None) anonymous channel
/// must be rejected. Part 4 section 5.13.7.1: "If the Client uses an ANONYMOUS user token,
/// the Server shall validate ... the MessageSecurityMode is SIGN or SIGNANDENCRYPT."
/// The expected operation-level status is BadUserAccessDenied (Table 102).
// @relation(SVR-XFER-OP-002, SVR-XFER-SM-024, scope=function)
TEST_F(TransferSubscriptionsNone, TransferSub_AnonymousNone_Rejected)
{
  auto subId = create_subscription(*mSessionA);

  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  req.send_initial_values() = false;

  auto result = mSessionB->subscriptions().try_transfer_subscriptions_sync(std::move(req));
  ASSERT_TRUE(result.is_good()) << "Request failed: " << to_string(result.status_code());
  auto& resp = result.value();

  if (resp.response_header().service_result().is_good())
  {
    // Per-result level rejection - the normative path.
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_EQ(resp.results()[0].status_code(), StatusCode{Status::BadUserAccessDenied})
      << "Anonymous + None channel must be rejected with BadUserAccessDenied per Table 102, got: "
      << to_string(resp.results()[0].status_code());
  }
  else
  {
    // Service-level rejection with BadUserAccessDenied is also acceptable.
    EXPECT_EQ(resp.response_header().service_result(), StatusCode{Status::BadUserAccessDenied})
      << "Anonymous + None channel must be rejected with BadUserAccessDenied, got: "
      << to_string(resp.response_header().service_result());
  }
}

// ===========================================================================
// Identity-and-configuration transfer obligations
// ===========================================================================

namespace
{

// Publish on `session` until every client handle in `handles` has appeared in a DataChangeNotification
// for `subscriptionId`, or the attempt budget runs out. Returns true only when every handle was seen,
// so a caller cannot mistake "nothing was ever delivered" for "the queue is drained" - the
// distinction matters for the sendInitialValues=FALSE obligation, whose whole premise is that the old
// Session already received these values.
bool drain_initial_values(
  ua::client::Session& session, uint32_t subscriptionId, const std::vector<uint32_t>& handles)
{
  std::set<uint32_t> pending(handles.begin(), handles.end());
  for (int attempt = 0; attempt < 8 && !pending.empty(); ++attempt)
  {
    auto notif = wait_for_data_change(session, subscriptionId, 500ms);
    if (!notif)
      continue;
    for (const auto& mi : notif->monitored_items())
      pending.erase(mi.client_handle());
  }
  return pending.empty();
}

// True when `notification` carries an entry for `clientHandle` (whatever its value).
bool carries_handle(const DataChangeNotification& notification, uint32_t clientHandle)
{
  for (const auto& mi : notification.monitored_items())
  {
    if (mi.client_handle() == clientHandle)
      return true;
  }
  return false;
}

}  // namespace

/// Part 4 section 5.13.7: TransferSubscriptions moves the Subscription *and its MonitoredItems* to the
/// target Session. An implementation that moves only the Subscription object - or that re-registers the
/// items under fresh identifiers on the new Session - satisfies "the transfer returned Good" while
/// forcing the client to recreate everything, which is precisely the cost the service exists to avoid.
/// Two items with distinct client handles are used so the assertion is about the item set, not a single
/// item: both must keep reporting under their original handles, and both must still be addressable by
/// their original MonitoredItemIds on the new Session.
///
/// The target Session is a second Session of client A: these Sessions are anonymous, and Part 4
/// section 5.13.7.1 permits an anonymous transfer only between Sessions of the same ApplicationUri (see
/// open_same_client_channel). The criterion says nothing about Clients, so the identity precondition
/// is satisfied rather than tested here.
// @verifies AC-SVR-XFER-001-TRANSFER-CARRIES-ITEMS
TEST_F(TransferSubscriptionsSecure, TransferSub_TransferredSubscriptionKeepsItsMonitoredItems)
{
  constexpr uint32_t handleOne = 11;
  constexpr uint32_t handleTwo = 22;

  auto targetChannel = open_same_client_channel();
  auto targetSession = targetChannel.create_session_sync({.sessionName = "SessionA2_KeepsItems"});
  targetSession.activate_sync();

  auto [subId, miIdOne] = create_subscription_with_monitored_item(
    *mSessionA, sWritableVariableId, {}, MonitoringOptions{.clientHandle = handleOne});

  auto miResp = mSessionA->monitored_items().create_monitored_items_sync(
    build_create_mi_request(subId, sWritableVariableId, MonitoringOptions{.clientHandle = handleTwo}));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good())
    << "Second monitored item was not created: " << to_string(miResp.results()[0].status_code());
  const uint32_t miIdTwo = miResp.results()[0].monitored_item_id();
  ASSERT_NE(miIdTwo, 0u);

  // Both items must be reporting on session A before the transfer, otherwise "they continue reporting"
  // is not an observation about the transfer.
  ASSERT_TRUE(drain_initial_values(*mSessionA, subId, {handleOne, handleTwo}))
    << "Both monitored items must report on the owning session before the transfer";

  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  req.send_initial_values() = false;

  auto xferResult = targetSession.subscriptions().try_transfer_subscriptions_sync(std::move(req));
  ASSERT_TRUE(xferResult.is_good()) << to_string(xferResult.status_code());
  ASSERT_TRUE(xferResult.value().response_header().service_result().is_good());
  ASSERT_EQ(xferResult.value().results().size(), 1u);
  ASSERT_TRUE(xferResult.value().results()[0].status_code().is_good())
    << "Transfer failed: " << to_string(xferResult.value().results()[0].status_code());

  // A single stimulus after the transfer must move BOTH items, each under the client handle it was
  // created with.
  write_value_async(targetSession, sWritableVariableId, Variant{int32_t{4711}});

  bool reportedHandleOne = false;
  bool reportedHandleTwo = false;
  for (int attempt = 0; attempt < 8 && !(reportedHandleOne && reportedHandleTwo); ++attempt)
  {
    auto notif = wait_for_data_change(targetSession, subId, 500ms);
    if (!notif)
      continue;
    for (const auto& mi : notif->monitored_items())
    {
      const auto* value = mi.value().value().try_as<int32_t>();
      if (value == nullptr || *value != 4711)
        continue;
      if (mi.client_handle() == handleOne)
        reportedHandleOne = true;
      if (mi.client_handle() == handleTwo)
        reportedHandleTwo = true;
    }
  }
  EXPECT_TRUE(reportedHandleOne) << "Item with client handle " << handleOne
                                 << " must keep reporting on the new session";
  EXPECT_TRUE(reportedHandleTwo) << "Item with client handle " << handleTwo
                                 << " must keep reporting on the new session";

  // Configuration intact also means the new Session knows the items by their original
  // MonitoredItemIds: SetMonitoringMode addresses them by id and would answer
  // BadMonitoredItemIdInvalid for items that had been recreated or dropped.
  SetMonitoringModeRequest modeReq;
  modeReq.subscription_id() = subId;
  modeReq.monitoring_mode() = MonitoringMode::Reporting;
  modeReq.monitored_item_ids().push_back(miIdOne);
  modeReq.monitored_item_ids().push_back(miIdTwo);
  auto modeResp = targetSession.monitored_items().set_monitoring_mode_sync(std::move(modeReq));
  ASSERT_TRUE(modeResp.response_header().service_result().is_good())
    << to_string(modeResp.response_header().service_result());
  ASSERT_EQ(modeResp.results().size(), 2u);
  EXPECT_TRUE(modeResp.results()[0].is_good())
    << "MonitoredItemId " << miIdOne
    << " is not known to the new session: " << to_string(modeResp.results()[0]);
  EXPECT_TRUE(modeResp.results()[1].is_good())
    << "MonitoredItemId " << miIdTwo
    << " is not known to the new session: " << to_string(modeResp.results()[1]);

  (void)targetSession.try_close_sync();
  (void)targetChannel.try_close_sync();
}

/// Part 4 section 5.13.7 / Table 100: with sendInitialValues FALSE the first Publish after the transfer
/// "shall contain only the value changes since the last Publish response was sent". A server that
/// ignores the flag and re-queues every reporting item's last value still delivers the changed item, so
/// a test that only looks for the change passes against the broken implementation. The unchanged item
/// is the discriminator: it must be absent from that first notification.
///
/// The target Session is a second Session of client A: these Sessions are anonymous, and Part 4
/// section 5.13.7.1 permits an anonymous transfer only between Sessions of the same ApplicationUri (see
/// open_same_client_channel). The criterion says nothing about Clients, so the identity precondition
/// is satisfied rather than tested here.
// @verifies AC-SVR-XFER-006-SENDINITIALVALUES-FALSE
TEST_F(TransferSubscriptionsSecure, TransferSub_SendInitialValuesFalseSendsOnlyChangedItems)
{
  constexpr uint32_t changingHandle = 31;
  constexpr uint32_t unchangedHandle = 32;

  auto targetChannel = open_same_client_channel();
  auto targetSession = targetChannel.create_session_sync({.sessionName = "SessionA2_InitialValues"});
  targetSession.activate_sync();

  auto [subId, miIdChanging] = create_subscription_with_monitored_item(
    *mSessionA, sWritableVariableId, {}, MonitoringOptions{.clientHandle = changingHandle});

  // Server_ServerArray is a static NS0 variable: once its initial value has been reported it never
  // changes again, so any later appearance can only come from a re-queue of last-sent values.
  auto miResp = mSessionA->monitored_items().create_monitored_items_sync(build_create_mi_request(
    subId, NodeId{VariableId::Server_ServerArray}, MonitoringOptions{.clientHandle = unchangedHandle}));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good())
    << "Static monitored item was not created: " << to_string(miResp.results()[0].status_code());

  // Both initial values must have been published on the OLD session; "changes since the last Publish"
  // is measured from there.
  ASSERT_TRUE(drain_initial_values(*mSessionA, subId, {changingHandle, unchangedHandle}))
    << "Both monitored items must report their initial value on the owning session before the transfer";

  // Quiescence guard for the discriminator: if the static item reported on its own, its appearance
  // after the transfer would prove nothing about sendInitialValues.
  auto strayStaticReport = wait_for_data_change(
    *mSessionA,
    subId,
    [unchangedHandle](const DataChangeNotification& dc) { return carries_handle(dc, unchangedHandle); },
    700ms);
  ASSERT_FALSE(strayStaticReport)
    << "The static item reported a change of its own; it cannot serve as the unchanged item here";

  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  req.send_initial_values() = false;

  auto xferResult = targetSession.subscriptions().try_transfer_subscriptions_sync(std::move(req));
  ASSERT_TRUE(xferResult.is_good()) << to_string(xferResult.status_code());
  ASSERT_TRUE(xferResult.value().response_header().service_result().is_good());
  ASSERT_EQ(xferResult.value().results().size(), 1u);
  ASSERT_TRUE(xferResult.value().results()[0].status_code().is_good())
    << "Transfer failed: " << to_string(xferResult.value().results()[0].status_code());

  // Exactly one item changes after the transfer.
  write_value_async(targetSession, sWritableVariableId, Variant{int32_t{5150}});

  auto carriesAnyValue = [](const DataChangeNotification& dc)
  {
    return !dc.monitored_items().empty();
  };
  auto notif = wait_for_data_change(targetSession, subId, carriesAnyValue, 2000ms);
  ASSERT_TRUE(notif) << "Expected the changed value to be delivered on the new session";
  ASSERT_FALSE(notif->monitored_items().empty());
  EXPECT_THAT(*notif, ContainsDataChangeFor(changingHandle, good_value_of<int32_t>(5150)));
  EXPECT_FALSE(carries_handle(*notif, unchangedHandle))
    << "With sendInitialValues=FALSE the first Publish must not carry the unchanged item's last value "
       "(Part 4, Table 100)";

  (void)targetSession.try_close_sync();
  (void)targetChannel.try_close_sync();
}

/// Part 4 section 5.13.8: "If a Subscription is transferred to another Session, the queued
/// NotificationMessages for this Subscription are moved from the old to the new Session." Moved, not
/// copied - a server that leaves the entries behind lets a client that never learned of the transfer
/// keep republishing messages the new owner has already consumed. Both halves are asserted: the new
/// Session can Republish each accumulated sequence number, and the old Session cannot.
///
/// The target Session is a second Session of client A: these Sessions are anonymous, and Part 4
/// section 5.13.7.1 permits an anonymous transfer only between Sessions of the same ApplicationUri (see
/// open_same_client_channel). The criterion says nothing about Clients, so the identity precondition
/// is satisfied rather than tested here.
// @verifies AC-SVR-XFER-008-QUEUE-MOVES
TEST_F(TransferSubscriptionsSecure, TransferSub_RetransmissionQueueMovesToNewSession)
{
  auto targetChannel = open_same_client_channel();
  auto targetSession = targetChannel.create_session_sync({.sessionName = "SessionA2_Retransmission"});
  targetSession.activate_sync();

  auto [subId, miId] = create_subscription_with_monitored_item(*mSessionA, sWritableVariableId);

  // Accumulate two unacknowledged NotificationMessages on session A. Nothing is ever acknowledged, so
  // both stay in the retransmission queue and remain observable at the point of assertion.
  auto first = wait_for_publish(
    *mSessionA,
    [subId](const PublishResponse& r)
    { return r.subscription_id() == subId && as_data_change(r) != nullptr; },
    2s);
  ASSERT_TRUE(first.has_value()) << "Expected an initial notification on session A";
  const uint32_t seqOne = first->notification_message().sequence_number();
  ASSERT_GT(seqOne, 0u);

  write_value_async(*mSessionA, sWritableVariableId, Variant{int32_t{31337}});
  auto second = wait_for_publish(
    *mSessionA,
    [subId, seqOne](const PublishResponse& r)
    {
      return r.subscription_id() == subId && as_data_change(r) != nullptr &&
             r.notification_message().sequence_number() != seqOne;
    },
    2s);
  ASSERT_TRUE(second.has_value()) << "Expected a second notification on session A";
  const uint32_t seqTwo = second->notification_message().sequence_number();
  ASSERT_NE(seqOne, seqTwo);

  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  req.send_initial_values() = false;

  auto xferResult = targetSession.subscriptions().try_transfer_subscriptions_sync(std::move(req));
  ASSERT_TRUE(xferResult.is_good()) << to_string(xferResult.status_code());
  ASSERT_TRUE(xferResult.value().response_header().service_result().is_good());
  ASSERT_EQ(xferResult.value().results().size(), 1u);
  ASSERT_TRUE(xferResult.value().results()[0].status_code().is_good())
    << "Transfer failed: " << to_string(xferResult.value().results()[0].status_code());

  // The new Session can Republish both accumulated messages.
  for (uint32_t seqNum : {seqOne, seqTwo})
  {
    RepublishRequest newReq;
    newReq.subscription_id() = subId;
    newReq.retransmit_sequence_number() = seqNum;
    auto newResult = targetSession.subscriptions().try_republish_sync(std::move(newReq));
    ASSERT_TRUE(newResult.is_good()) << "Republish of sequence number " << seqNum
                                     << " on the new session failed: " << to_string(newResult.status_code());
    EXPECT_TRUE(newResult.value().response_header().service_result().is_good())
      << "Republish of sequence number " << seqNum << " on the new session returned "
      << to_string(newResult.value().response_header().service_result());
    EXPECT_EQ(newResult.value().notification_message().sequence_number(), seqNum);
  }

  // The old Session cannot: the queue moved with the Subscription rather than being copied.
  RepublishRequest oldReq;
  oldReq.subscription_id() = subId;
  oldReq.retransmit_sequence_number() = seqOne;
  auto oldResult = mSessionA->subscriptions().try_republish_sync(std::move(oldReq));
  if (oldResult.is_good())
  {
    EXPECT_EQ(
      oldResult.value().response_header().service_result(), StatusCode{Status::BadSubscriptionIdInvalid})
      << "The old session must no longer serve Republish for a transferred subscription, got: "
      << to_string(oldResult.value().response_header().service_result());
    EXPECT_NE(oldResult.value().notification_message().sequence_number(), seqOne)
      << "The old session returned the retransmitted message it should have handed over";
  }
  else
  {
    EXPECT_EQ(oldResult.status_code(), StatusCode{Status::BadSubscriptionIdInvalid})
      << "The old session must no longer serve Republish for a transferred subscription, got: "
      << to_string(oldResult.status_code());
  }

  (void)targetSession.try_close_sync();
  (void)targetChannel.try_close_sync();
}

// ===========================================================================
// Fixture 3: TransferSubscriptionsIdentity
//
// One server exposing two endpoints on the same listener:
//   - Basic256Sha256 / SignAndEncrypt, advertising Anonymous AND UserName token policies
//   - None / None, advertising Anonymous
// with a username/password authenticator behind them. That combination is what makes the
// TransferSubscriptions identity rules drivable from one place: a Session authenticated as a
// different user, an anonymous Session presenting a different ApplicationUri, and an anonymous
// Session on an unsecured channel. Two clients (X and Y) supply the two ApplicationUris; sessions
// that must share an ApplicationUri are opened on the same client.
// ===========================================================================

class TransferSubscriptionsIdentity : public ::testing::Test
{
protected:
  static constexpr const char* sClientUriX = "urn:test:transfer:identity:x";
  static constexpr const char* sClientUriY = "urn:test:transfer:identity:y";
  static constexpr const char* sUserPolicyId = "user-rsa";
  static constexpr const char* sAliceUser = "alice";
  static constexpr const char* sAlicePassword = "alice-pw";
  static constexpr const char* sBobUser = "bob";
  static constexpr const char* sBobPassword = "bob-pw";

  static void SetUpTestSuite()
  {
    sLogSink = test_log_sink();

    sCrypto = create_default_crypto([]() { return ua::SecureString{"password"}; });

    sServerCert = create_self_signed_cert(
      sCrypto, CertificateType::RsaSha256Application, "TestIdServer", "urn:test:transfer:identity:server");
    sClientCertX =
      create_self_signed_cert(sCrypto, CertificateType::RsaSha256Application, "TestIdClientX", sClientUriX);
    sClientCertY =
      create_self_signed_cert(sCrypto, CertificateType::RsaSha256Application, "TestIdClientY", sClientUriY);

    sServerThreadPool = std::make_unique<boost::asio::thread_pool>();
    auto serverExecutor = sServerThreadPool->executor();

    sTempDir =
      std::filesystem::temp_directory_path() / ("ua_xfer_id_test_" + Guid::create_and_generate().as_string());
    std::filesystem::create_directories(sTempDir);

    auto appStorePath = sTempDir / "app_group";
    std::filesystem::create_directories(appStorePath);
    TrustListValidationOptions appValidationOptions;
    sAppCertStore = CertificateStoreFiles::create(
      serverExecutor, sCrypto, {.trustListPath = appStorePath, .validationOptions = appValidationOptions});

    {
      CertificateStore::ApplicationCertificate appCert;
      appCert.certificateType = CertificateType::RsaSha256Application;
      appCert.certificate = sServerCert.cert;
      appCert.keys = sServerCert.keys;
      sAppCertStore->add_to_application_certificates_sync(appCert);
    }
    sAppCertStore->add_to_trusted_certificates_sync(sClientCertX.cert);
    sAppCertStore->add_to_trusted_certificates_sync(sClientCertY.cert);

    // Anonymous plus a real username/password authenticator, so two Sessions can differ by user alone.
    ServerComponents components{.crypto = sCrypto,
      .applicationGroupCertificateStore = sAppCertStore,
      .logSink = sLogSink,
      .logLevel = LogLevel::Debug};
    auto composite = std::make_shared<CompositeAuthenticator>();
    composite->add(UserTokenKind::Anonymous, std::make_shared<AnonymousAuthenticator>());
    composite->add(UserTokenKind::UserName,
      std::make_shared<SimpleUserPasswordAuthenticator>(
        [](std::string_view username, const ua::SecureString& password)
        {
          const std::string_view secret{password.c_str()};
          return (username == sAliceUser && secret == sAlicePassword) ||
                 (username == sBobUser && secret == sBobPassword);
        }));
    components.authenticator = std::move(composite);
    components.roleConfiguration = RoleConfiguration::from_well_known_grants(
      {{WellKnownRole::SecurityAdmin, IdentityCriteriaType::AuthenticatedUser}});

    // create_test_config() already opts in to insecure endpoints, which the None endpoint needs.
    auto appCfg = ua::test_utils::create_test_config();

    ServerConfig serverCfg;
    serverCfg.connectionThrottling.enabled = false;

    server::CreateConfig serverCreateCfg{.identity = ApplicationIdentity::load_default(),
      .application = std::move(appCfg),
      .server = std::move(serverCfg)};

    sServer.emplace(Server::create(serverExecutor, std::move(serverCreateCfg), std::move(components)));

    transport::BindAddress bind;
    bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
    bind.address = "127.0.0.1:0";
    sListenerHandle = sServer->listen_sync(std::move(bind), {});

    {
      ServerEndpointConfig endpoint;
      endpoint.name = "B256S256_SaE_Identity";
      endpoint.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
      endpoint.securityPolicyId = SecurityPolicyId::Basic256Sha256;

      UserTokenPolicy anonPolicy;
      anonPolicy.policy_id() = "anon";
      anonPolicy.token_type() = UserTokenType::Anonymous;
      endpoint.userIdentityTokens.push_back(std::move(anonPolicy));

      UserTokenPolicy userPolicy;
      userPolicy.policy_id() = std::string{sUserPolicyId};
      userPolicy.token_type() = UserTokenType::UserName;
      userPolicy.security_policy_uri() =
        std::string{SecurityPolicy::create(SecurityPolicyId::Basic256Sha256)->uri()};
      endpoint.userIdentityTokens.push_back(std::move(userPolicy));

      sServer->add_endpoint(sListenerHandle, endpoint);
    }

    {
      ServerEndpointConfig endpoint;
      endpoint.name = "None_Identity";
      endpoint.messageSecurityMode = MessageSecurityMode::None;
      endpoint.securityPolicyId = SecurityPolicyId::None;

      UserTokenPolicy anonPolicy;
      anonPolicy.policy_id() = "anon";
      anonPolicy.token_type() = UserTokenType::Anonymous;
      endpoint.userIdentityTokens.push_back(std::move(anonPolicy));

      sServer->add_endpoint(sListenerHandle, endpoint);
    }

    auto addressSpace = sServer->address_space();
    auto testNamespace = default_ns::Namespace::create("urn:test:transfer:identity", serverExecutor);
    sTestNamespaceIndex = addressSpace.add_namespace_sync(testNamespace);
    // A namespace that declares no RolePermissions publishes an ENGAGED, EMPTY default and hides
    // every undecorated node it owns, so an ordinary client is refused BadUserAccessDenied on
    // reads, browses and monitored items. This fixture derives from ::testing::Test rather than
    // ComplianceBase, so grant_fixture_namespace_permissions never runs for it; the per-namespace
    // form has to be called here. The subject of these tests is subscription transfer, not a
    // denial, so granting is not granting away the thing under test.
    ua::test_helpers::grant_namespace_to_test_client(addressSpace, sTestNamespaceIndex);

    sWritableVariableId = NodeId{sTestNamespaceIndex, uint32_t{1000}};
    auto varNode = addressSpace.create_node_sync(sWritableVariableId, NodeClass::Variable);
    auto variable = varNode.as<VariableAccessor>();
    variable->set_browse_name(QualifiedName{sTestNamespaceIndex, "WritableInt32"});
    variable->set_display_name(LocalizedText{"", "WritableInt32"});
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->write_value_sync(int32_t{42});
    variable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});

    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, sWritableVariableId);

    sServer->start_sync();

    auto urls = sServer->advertised_urls(sListenerHandle);
    sEndpointUrl = urls.front().str();

    sClientThreadPool = std::make_unique<boost::asio::thread_pool>();

    auto clientStorePathX = sTempDir / "client_store_x";
    auto clientStorePathY = sTempDir / "client_store_y";
    std::filesystem::create_directories(clientStorePathX);
    std::filesystem::create_directories(clientStorePathY);
    TrustListValidationOptions clientValidationOptions;
    sClientCertStoreX = CertificateStoreFiles::create(sClientThreadPool->executor(),
      sCrypto,
      {.trustListPath = clientStorePathX, .validationOptions = clientValidationOptions});
    sClientCertStoreY = CertificateStoreFiles::create(sClientThreadPool->executor(),
      sCrypto,
      {.trustListPath = clientStorePathY, .validationOptions = clientValidationOptions});

    {
      CertificateStore::ApplicationCertificate cert;
      cert.certificateType = CertificateType::RsaSha256Application;
      cert.certificate = sClientCertX.cert;
      cert.keys = sClientCertX.keys;
      sClientCertStoreX->add_to_application_certificates_sync(cert);
    }
    {
      CertificateStore::ApplicationCertificate cert;
      cert.certificateType = CertificateType::RsaSha256Application;
      cert.certificate = sClientCertY.cert;
      cert.keys = sClientCertY.keys;
      sClientCertStoreY->add_to_application_certificates_sync(cert);
    }
    sClientCertStoreX->add_to_trusted_certificates_sync(sServerCert.cert);
    sClientCertStoreY->add_to_trusted_certificates_sync(sServerCert.cert);

    auto clientConfigX = ua::test_utils::create_test_config();
    clientConfigX.application_description_part().applicationUri = sClientUriX;
    sClientX.emplace(CoreClient::create(sClientThreadPool->executor(),
      client::CreateConfig{
        .identity = ApplicationIdentity::load_default(), .application = std::move(clientConfigX)},
      ua::client::ClientComponents{.crypto = sCrypto,
        .applicationGroupCertificateStore = sClientCertStoreX,
        .logSink = sLogSink,
        .logLevel = LogLevel::Debug}));

    auto clientConfigY = ua::test_utils::create_test_config();
    clientConfigY.application_description_part().applicationUri = sClientUriY;
    sClientY.emplace(CoreClient::create(sClientThreadPool->executor(),
      client::CreateConfig{
        .identity = ApplicationIdentity::load_default(), .application = std::move(clientConfigY)},
      ua::client::ClientComponents{.crypto = sCrypto,
        .applicationGroupCertificateStore = sClientCertStoreY,
        .logSink = sLogSink,
        .logLevel = LogLevel::Debug}));
  }

  static void TearDownTestSuite()
  {
    // Same dependency order as TransferSubscriptionsSecure: clients, then server, then the
    // certificate stores (they hold strands bound to the pools), then the pools themselves.
    sClientX.reset();
    sClientY.reset();

    if (sServer)
      (void)sServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
    sServer.reset();
    sAppCertStore.reset();
    sClientCertStoreX.reset();
    sClientCertStoreY.reset();

    if (sServerThreadPool)
      sServerThreadPool->join();
    if (sClientThreadPool)
      sClientThreadPool->join();

    sServerThreadPool.reset();
    sClientThreadPool.reset();

    sCrypto.reset();
    sLogSink.reset();
    if (!sTempDir.empty())
      std::filesystem::remove_all(sTempDir);
  }

  // Opens a Basic256Sha256 / SignAndEncrypt channel - the secured channel the anonymous transfer rule
  // demands, and the channel the UserName token policy is bound to.
  static SecureChannel open_secure_channel(CoreClient& client)
  {
    return client.open_channel_sync({.endpointUrl = sEndpointUrl,
      .securityMode = MessageSecurityMode::SignAndEncrypt,
      .securityPolicyId = SecurityPolicyId::Basic256Sha256,
      .serverCertificate = sServerCert.cert});
  }

  static ua::client::Session::ActivateConfig user_identity(const char* username, const char* password)
  {
    ua::client::Session::ActivateConfig config;
    config.policyId = std::string{sUserPolicyId};
    config.identity =
      UsernamePasswordIdentity{.username = std::string{username}, .password = std::string{password}};
    return config;
  }

  // Issues a single-subscription TransferSubscriptions from `session` and reduces the answer to the
  // status that decides the operation: the per-result code when the service itself succeeded, the
  // service-level code otherwise.
  static StatusCode transfer_status(ua::client::Session& session, uint32_t subscriptionId)
  {
    TransferSubscriptionsRequest req;
    req.subscription_ids().push_back(subscriptionId);
    req.send_initial_values() = false;

    auto result = session.subscriptions().try_transfer_subscriptions_sync(std::move(req));
    if (result.is_bad())
      return result.status_code();
    auto& resp = result.value();
    if (resp.response_header().service_result().is_bad())
      return resp.response_header().service_result();
    if (resp.results().size() != 1u)
    {
      ADD_FAILURE() << "Expected exactly one TransferResult, got " << resp.results().size();
      return StatusCode{Status::BadInternalError};
    }
    return resp.results()[0].status_code();
  }

  static inline std::shared_ptr<LogSink> sLogSink;
  static inline std::shared_ptr<const Crypto> sCrypto;
  static inline KeyMaterial sServerCert;
  static inline KeyMaterial sClientCertX;
  static inline KeyMaterial sClientCertY;
  static inline std::unique_ptr<boost::asio::thread_pool> sServerThreadPool;
  static inline std::unique_ptr<boost::asio::thread_pool> sClientThreadPool;
  static inline std::filesystem::path sTempDir;
  static inline std::shared_ptr<CertificateStore> sAppCertStore;
  static inline std::shared_ptr<CertificateStore> sClientCertStoreX;
  static inline std::shared_ptr<CertificateStore> sClientCertStoreY;
  static inline std::optional<Server> sServer;
  static inline ListenerHandle sListenerHandle{0};
  static inline std::string sEndpointUrl;
  static inline uint16_t sTestNamespaceIndex{0};
  static inline NodeId sWritableVariableId;
  static inline std::optional<CoreClient> sClientX;
  static inline std::optional<CoreClient> sClientY;
};

/// XFER-DIAG (alt client): a transfer between two distinct Clients records exactly one transfer to a
/// DIFFERENT client, driving SubscriptionDiagnostics TransferRequestCount, TransferredToAltClientCount
/// and TransferredToSameClientCount.
///
/// It runs on this fixture rather than TransferSubscriptionsSecure because a cross-Client transfer is
/// only legitimate for an authenticated user: Part 4 section 5.13.7.1 requires an ANONYMOUS transfer to
/// carry the same ApplicationUri at both ends, so an anonymous cross-Client transfer is refused with
/// Bad_UserAccessDenied and never reaches the diagnostic counters at all. Both Sessions here are alice,
/// and clients X and Y supply the two ApplicationUris, so "different Client, same user" - the case the
/// alt-client counter exists to count - is the only thing being varied.
TEST_F(TransferSubscriptionsIdentity, TransferSub_AltClientTransferDiagnostics)
{
  auto ownerChannel = open_secure_channel(*sClientX);
  auto ownerSession = ownerChannel.create_session_sync({.sessionName = "AliceOnClientX"});
  ownerSession.activate_sync(user_identity(sAliceUser, sAlicePassword));

  auto claimantChannel = open_secure_channel(*sClientY);
  auto claimantSession = claimantChannel.create_session_sync({.sessionName = "AliceOnClientY"});
  claimantSession.activate_sync(user_identity(sAliceUser, sAlicePassword));

  auto subId = create_subscription(ownerSession);
  auto sourceDiagNode = wait_for_subscription_diag_node(ownerSession, subId);
  ASSERT_TRUE(sourceDiagNode.has_value());

  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  req.send_initial_values() = false;
  auto result = claimantSession.subscriptions().try_transfer_subscriptions_sync(std::move(req));
  ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
  ASSERT_EQ(result.value().results().size(), 1u);
  ASSERT_TRUE(result.value().results()[0].status_code().is_good())
    << to_string(result.value().results()[0].status_code());

  auto diagNode = wait_for_subscription_diag_node(claimantSession, subId, sourceDiagNode);
  ASSERT_TRUE(diagNode.has_value()) << "No SubscriptionDiagnostics node for transferred sub " << subId;

  auto diag = wait_for_transfer_diagnostics(claimantSession,
    *diagNode,
    [](const SubscriptionDiagnosticsDataType& d) { return d.transfer_request_count() >= 1; });
  EXPECT_EQ(diag.transfer_request_count(), 1u);
  EXPECT_EQ(diag.transferred_to_alt_client_count(), 1u)
    << "clients X and Y advertise distinct ApplicationUris, so this is a transfer to another Client";
  EXPECT_EQ(diag.transferred_to_same_client_count(), 0u);

  (void)claimantSession.try_close_sync();
  (void)claimantChannel.try_close_sync();
  (void)ownerSession.try_close_sync();
  (void)ownerChannel.try_close_sync();
}

/// Part 4 section 5.13.7: the server must compare the requesting Session's authenticated user against
/// the user of the Session that owns the Subscription. Without it, TransferSubscriptions is a
/// data-theft primitive - a successful transfer redirects a live Subscription's notifications to the
/// caller, and subscription ids are server-unique integers anyone can name. Both Sessions here run on
/// the same client (same ApplicationUri) over the same secured channel type, so the user is the only
/// thing that differs. The refusal alone is not enough: the Subscription must also still be serving
/// its original Session afterwards, which is what a "refuse but detach anyway" implementation breaks.
// @verifies AC-SVR-XFER-002-SAME-USER
TEST_F(TransferSubscriptionsIdentity, TransferSub_DifferentUserIsRefusedAndSubscriptionStays)
{
  auto aliceChannel = open_secure_channel(*sClientX);
  auto aliceSession = aliceChannel.create_session_sync({.sessionName = "AliceOwner"});
  aliceSession.activate_sync(user_identity(sAliceUser, sAlicePassword));

  auto bobChannel = open_secure_channel(*sClientX);
  auto bobSession = bobChannel.create_session_sync({.sessionName = "BobClaimant"});
  bobSession.activate_sync(user_identity(sBobUser, sBobPassword));

  auto [subId, miId] = create_subscription_with_monitored_item(aliceSession, sWritableVariableId);
  ASSERT_TRUE(drain_initial_values(aliceSession, subId, {1u}))
    << "The subscription must be reporting to its owner before the claim attempt";

  EXPECT_EQ(transfer_status(bobSession, subId), StatusCode{Status::BadUserAccessDenied})
    << "A Session acting for a different user must not be able to claim the Subscription";

  // The Subscription stayed with alice: her Session still receives its notifications.
  write_value_async(aliceSession, sWritableVariableId, Variant{int32_t{2468}});
  auto notif = wait_for_data_change(aliceSession, subId, 2000ms);
  ASSERT_TRUE(notif) << "The refused transfer must leave the Subscription with its original Session";
  ASSERT_FALSE(notif->monitored_items().empty());
  EXPECT_THAT(*notif, ContainsDataChangeFor(1u, good_value_of<int32_t>(2468)));

  (void)bobSession.try_close_sync();
  (void)bobChannel.try_close_sync();
  (void)aliceSession.try_close_sync();
  (void)aliceChannel.try_close_sync();
}

/// Part 4 section 5.13.7.1: "If the Client uses an ANONYMOUS user token, the Server shall validate if
/// the ApplicationUri is the same for the old and the new Session and the MessageSecurityMode is SIGN
/// or SIGNANDENCRYPT." Anonymous Sessions have no user to compare, so these two conditions are the
/// whole of the check - and a plausible implementation that only verifies "both ends are anonymous"
/// leaves every anonymous Subscription claimable by anyone. Each condition is violated in isolation
/// here: one requester differs only by ApplicationUri, the other only by channel security mode.
// @verifies AC-SVR-XFER-003-ANONYMOUS-EXTRA-CHECKS
// @relation(AC-SVR-XFER-003-ORPHAN-CONTEXT, scope=function)
TEST_F(TransferSubscriptionsIdentity, TransferSub_AnonymousRequiresSameApplicationUriAndSecuredChannel)
{
  // Owner: client X, anonymous, SignAndEncrypt.
  auto ownerChannel = open_secure_channel(*sClientX);
  auto ownerSession = ownerChannel.create_session_sync({.sessionName = "AnonOwner"});
  ownerSession.activate_sync();

  // Requester 1: anonymous and secured exactly like the owner, but a DIFFERENT ApplicationUri.
  auto altUriChannel = open_secure_channel(*sClientY);
  auto altUriSession = altUriChannel.create_session_sync({.sessionName = "AnonAltUri"});
  altUriSession.activate_sync();

  // Requester 2: anonymous with the SAME ApplicationUri as the owner, but on an unsecured channel.
  auto noneChannel = sClientX->open_channel_sync({.endpointUrl = sEndpointUrl});
  auto noneSession = noneChannel.create_session_sync({.sessionName = "AnonNoneMode"});
  noneSession.activate_sync();

  const auto subForAltUri = create_subscription(ownerSession);
  const auto subForNoneMode = create_subscription(ownerSession);
  ASSERT_NE(subForAltUri, subForNoneMode);

  EXPECT_EQ(transfer_status(altUriSession, subForAltUri), StatusCode{Status::BadUserAccessDenied})
    << "An anonymous transfer from a Session with a different ApplicationUri must be refused";

  EXPECT_EQ(transfer_status(noneSession, subForNoneMode), StatusCode{Status::BadUserAccessDenied})
    << "An anonymous transfer requested over a MessageSecurityMode=None channel must be refused";

  (void)noneSession.try_close_sync();
  (void)noneChannel.try_close_sync();
  (void)altUriSession.try_close_sync();
  (void)altUriChannel.try_close_sync();
  (void)ownerSession.try_close_sync();
  (void)ownerChannel.try_close_sync();
}

/// The CTT's Subscription Durable 004 exactly: the same user on both Sessions, and ONE Publish straight after
/// the transfer. The values sampled while the Subscription had no Session belong to it, and the new Session
/// of the same user is authorized for them - so that first Publish carries them. A server that authorizes
/// the parked values only on its periodic recheck answers that Publish with a keep-alive, because the
/// Subscription went Late while nobody could publish.
TEST_F(
  TransferSubscriptionsIdentity, TransferSub_TheFirstPublishAfterRecoveringAnOrphanCarriesItsQueuedValues)
{
  const auto writeServerSide = [](int32_t value)
  {
    auto node = sServer->address_space().find_node_sync(sWritableVariableId);
    auto variable = node.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->write_value_sync(Variant{value});
  };
  writeServerSide(200);

  auto ownerChannel = open_secure_channel(*sClientX);
  auto owner = ownerChannel.create_session_sync({.sessionName = "UserOrphanOwner"});
  owner.activate_sync(user_identity(sAliceUser, sAlicePassword));
  auto [subId, miId] = create_subscription_with_monitored_item(owner,
    sWritableVariableId,
    {.publishingInterval = 250.0, .lifetimeCount = 600, .keepAliveCount = 3},
    {.samplingInterval = 50.0, .queueSize = 100});
  drain_initial_publish(owner, subId);

  auto parked = owner.try_close_sync(ua::client::Session::CloseOptions{.deleteSubscriptions = false});
  ASSERT_THAT(parked, ::ua::test_helpers::Good()) << "the owner must close without deleting its Subscription";
  (void)ownerChannel.try_close_sync();

  for (int32_t value = 201; value <= 203; ++value)
  {
    writeServerSide(value);
    std::this_thread::sleep_for(300ms);
  }
  // Long enough past the keep-alive count for the unowned Subscription to be Late.
  std::this_thread::sleep_for(1s);

  auto recoveryChannel = open_secure_channel(*sClientX);
  auto recovery = recoveryChannel.create_session_sync({.sessionName = "UserOrphanRecovery"});
  recovery.activate_sync(user_identity(sAliceUser, sAlicePassword));
  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  req.send_initial_values() = false;
  auto transferred = recovery.subscriptions().try_transfer_subscriptions_sync(std::move(req));
  ASSERT_TRUE(transferred.is_good()) << to_string(transferred.status_code());
  ASSERT_EQ(transferred.value().results().size(), 1u);
  ASSERT_TRUE(transferred.value().results()[0].status_code().is_good())
    << to_string(transferred.value().results()[0].status_code());

  auto first = try_publish_once(recovery);
  ASSERT_TRUE(first.has_value()) << "the recovering Session's Publish must be answered";
  const auto* dataChange = as_data_change(*first);
  ASSERT_NE(dataChange, nullptr)
    << "the first Publish after the transfer must carry the queued values, not a "
       "keep-alive";
  std::vector<int32_t> delivered;
  for (const auto& item : dataChange->monitored_items())
  {
    if (const auto* value = item.value().value().try_as<int32_t>())
      delivered.push_back(*value);
  }
  EXPECT_EQ(delivered, (std::vector<int32_t>{201, 202, 203}));

  (void)recovery.try_close_sync();
  (void)recoveryChannel.try_close_sync();
}

/// Part 4 section 5.13.7.1 applies the same ApplicationUri and signed-target conditions after the old
/// Session has gone. The two denied attempts precede the valid recovery deliberately: success at the end
/// proves that neither denial consumed the orphaned Subscription or discarded its source security facts.
// @relation(AC-SVR-XFER-003-ORPHAN-CONTEXT, scope=function)
TEST_F(
  TransferSubscriptionsIdentity, TransferSub_OrphanedAnonymousRequiresSameApplicationUriAndSecuredChannel)
{
  auto ownerChannel = open_secure_channel(*sClientX);
  auto ownerSession = ownerChannel.create_session_sync({.sessionName = "AnonOrphanOwner"});
  ownerSession.activate_sync();
  const auto subscriptionId = create_subscription(ownerSession, {.lifetimeCount = 600});

  auto parked = ownerSession.try_close_sync(ua::client::Session::CloseOptions{.deleteSubscriptions = false});
  ASSERT_THAT(parked, ::ua::test_helpers::Good())
    << "the source Session must close without deleting its Subscription so the orphan path is exercised";
  (void)ownerChannel.try_close_sync();

  auto altUriChannel = open_secure_channel(*sClientY);
  auto altUriSession = altUriChannel.create_session_sync({.sessionName = "AnonOrphanAltUri"});
  altUriSession.activate_sync();
  EXPECT_EQ(transfer_status(altUriSession, subscriptionId), StatusCode{Status::BadUserAccessDenied})
    << "a secured anonymous Session from another verified ApplicationUri must not claim the orphan";
  (void)altUriSession.try_close_sync();
  (void)altUriChannel.try_close_sync();

  auto noneChannel = sClientX->open_channel_sync({.endpointUrl = sEndpointUrl});
  auto noneSession = noneChannel.create_session_sync({.sessionName = "AnonOrphanNoneMode"});
  noneSession.activate_sync();
  EXPECT_EQ(transfer_status(noneSession, subscriptionId), StatusCode{Status::BadUserAccessDenied})
    << "the same claimed ApplicationUri over an unsecured channel is unverified and must not claim the "
       "orphan";
  (void)noneSession.try_close_sync();
  (void)noneChannel.try_close_sync();

  auto recoveryChannel = open_secure_channel(*sClientX);
  auto recoverySession = recoveryChannel.create_session_sync({.sessionName = "AnonOrphanRecovery"});
  recoverySession.activate_sync();
  EXPECT_EQ(transfer_status(recoverySession, subscriptionId), StatusCode{Status::Good})
    << "the original verified application on a signed channel must still recover the orphan after both "
       "denials";

  (void)recoverySession.try_close_sync();
  (void)recoveryChannel.try_close_sync();
}

/// Part 4 section 5.13.7.4: when identity validation fails for one subscriptionId, that id's own slot
/// carries Bad_UserAccessDenied and the other ids in the request are processed independently. A server
/// that fails the whole batch - or that lets one denial abort the walk - turns a partially permitted
/// recovery into a total one, which is how a reconnecting client loses subscriptions it does own.
/// The requesting Session is a second Session of the same user as the permitted Subscription's owner,
/// so the permitted slot is decided by the real identity check and not by the caller owning it already.
// @verifies AC-SVR-XFER-OP-002-DENIED
TEST_F(TransferSubscriptionsIdentity, TransferSub_DeniedSubscriptionFailsInItsOwnSlot)
{
  auto aliceOwnerChannel = open_secure_channel(*sClientX);
  auto aliceOwnerSession = aliceOwnerChannel.create_session_sync({.sessionName = "AliceOwnerSlot"});
  aliceOwnerSession.activate_sync(user_identity(sAliceUser, sAlicePassword));

  auto aliceRequesterChannel = open_secure_channel(*sClientX);
  auto aliceRequesterSession =
    aliceRequesterChannel.create_session_sync({.sessionName = "AliceRequesterSlot"});
  aliceRequesterSession.activate_sync(user_identity(sAliceUser, sAlicePassword));

  auto bobChannel = open_secure_channel(*sClientX);
  auto bobSession = bobChannel.create_session_sync({.sessionName = "BobOwnerSlot"});
  bobSession.activate_sync(user_identity(sBobUser, sBobPassword));

  const auto subOwnedByAlice = create_subscription(aliceOwnerSession);
  const auto subOwnedByBob = create_subscription(bobSession);
  ASSERT_NE(subOwnedByAlice, subOwnedByBob);

  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subOwnedByAlice);
  req.subscription_ids().push_back(subOwnedByBob);
  req.send_initial_values() = false;

  auto result = aliceRequesterSession.subscriptions().try_transfer_subscriptions_sync(std::move(req));
  ASSERT_TRUE(result.is_good()) << "Request failed: " << to_string(result.status_code());
  auto& resp = result.value();
  ASSERT_TRUE(resp.response_header().service_result().is_good())
    << "A denied operation must not fail the whole service call, got: "
    << to_string(resp.response_header().service_result());

  ASSERT_EQ(resp.results().size(), 2u);
  EXPECT_TRUE(resp.results()[0].status_code().is_good())
    << "The permitted subscription must still transfer, got: " << to_string(resp.results()[0].status_code());
  EXPECT_EQ(resp.results()[1].status_code(), StatusCode{Status::BadUserAccessDenied})
    << "Another user's subscription must be denied in its own slot, got: "
    << to_string(resp.results()[1].status_code());

  (void)bobSession.try_close_sync();
  (void)bobChannel.try_close_sync();
  (void)aliceRequesterSession.try_close_sync();
  (void)aliceRequesterChannel.try_close_sync();
  (void)aliceOwnerSession.try_close_sync();
  (void)aliceOwnerChannel.try_close_sync();
}

// ===========================================================================
// Table 85 transfer transitions 22 / 23 / 24
//
// All three assert on the Subscription's lifetime counter, which is only reachable from a client
// through SubscriptionDiagnostics.CurrentLifetimeCount. Two properties of that reading shape the
// tests below:
//
//   * the counter decrements once per publishing cycle only while no Publish request is queued, so
//     the decay window must contain no Publish on the owning Session at all; and
//   * every Subscription service resets it, so the decayed reading cannot be taken with one. An
//     ordinary attribute Write is used instead: it is not a Subscription service, but the sample it
//     produces makes the server refresh the diagnostics snapshot.
// ===========================================================================

/// Part 4 section 5.13.1.2, Table 85 transition 22: TransferSubscriptions with SessionChanged()==FALSE must
/// perform ResetLifetimeCounter() *and* ReturnNegativeResponse(). The reset is the half a plausible
/// implementation drops - the natural shape is to notice "the caller already owns this one", write a
/// bad status into that slot and continue, which skips the reset entirely. It matters because the
/// caller has just proved it is alive, so its Subscription must not be left closer to expiry for
/// having asked; the refusal is about the request being meaningless, not about the Subscription being
/// in doubt.
///
// @verifies AC-SVR-XFER-SM-022-SAME-SESSION-REFUSED
TEST_F(TransferSubscriptionsSecure, TransferSub_SelfTransferIsRefusedAndStillResetsTheLifetimeCounter)
{
  auto [subId, miId] = create_subscription_with_monitored_item(*mSessionA,
    sWritableVariableId,
    SubscriptionOptions{.publishingInterval = 1000.0, .lifetimeCount = 100, .keepAliveCount = 10});

  auto diagNode = wait_for_subscription_diag_node(*mSessionA, subId);
  ASSERT_TRUE(diagNode.has_value()) << "No SubscriptionDiagnostics node for subscription " << subId;

  // No Publish on session A during this window, so the publishing timer decrements the counter.
  std::this_thread::sleep_for(1500ms);
  write_value_async(*mSessionA, sWritableVariableId, Variant{int32_t{7001}});

  auto before = wait_for_transfer_diagnostics(*mSessionA,
    *diagNode,
    [](const SubscriptionDiagnosticsDataType& d)
    { return d.max_lifetime_count() > 0u && d.current_lifetime_count() < d.max_lifetime_count(); });
  ASSERT_GT(before.max_lifetime_count(), 0u) << "SubscriptionDiagnostics for " << subId << " never read";
  ASSERT_LT(before.current_lifetime_count(), before.max_lifetime_count())
    << "The lifetime counter never decayed, so a reset would not be observable here";
  const uint32_t decayed = before.current_lifetime_count();

  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  req.send_initial_values() = false;

  auto result = mSessionA->subscriptions().try_transfer_subscriptions_sync(std::move(req));
  ASSERT_TRUE(result.is_good()) << "Request failed: " << to_string(result.status_code());
  auto& resp = result.value();

  if (resp.response_header().service_result().is_good())
  {
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_TRUE(resp.results()[0].status_code().is_bad())
      << "Transition 22 requires a negative response for a self-transfer, got: "
      << to_string(resp.results()[0].status_code());
  }
  else
  {
    EXPECT_TRUE(resp.response_header().service_result().is_bad())
      << "Transition 22 requires a negative response for a self-transfer, got: "
      << to_string(resp.response_header().service_result());
  }

  // Refresh the diagnostics snapshot exactly as the pre-call reading was taken. A Write is not a
  // Subscription service, so it cannot itself reset the lifetime counter; it only makes the server
  // republish an up-to-date snapshot, so that a failure below is the missing reset and not a stale read.
  write_value_async(*mSessionA, sWritableVariableId, Variant{int32_t{7002}});

  auto after = wait_for_transfer_diagnostics(*mSessionA,
    *diagNode,
    [decayed](const SubscriptionDiagnosticsDataType& d)
    { return d.max_lifetime_count() > 0u && d.current_lifetime_count() > decayed; });
  ASSERT_GT(after.max_lifetime_count(), 0u) << "SubscriptionDiagnostics for " << subId << " never read";
  EXPECT_GT(after.current_lifetime_count(), decayed)
    << "Transition 22 requires ResetLifetimeCounter() even though the operation is refused; the counter "
       "only ever falls without one";
  EXPECT_EQ(after.current_lifetime_count(), after.max_lifetime_count())
    << "ResetLifetimeCounter() must restore the full revised lifetime count";
}

/// Part 4 section 5.13.1.2, Table 85 transition 23: a validated transfer to a different Session must do all
/// four of SetSession(), ResetLifetimeCounter(), ReturnResponse() and IssueStatusChangeNotification().
/// A server that reports Good and re-homes the notifications passes every "did the transfer work"
/// test while having dropped the reset, and the Subscription then carries the old Session's spent
/// counter into the new one and can expire almost immediately - a successful transfer that yields a
/// dead Subscription. The old Session's Good_SubscriptionTransferred notification is the other easily
/// dropped action: without it the previous owner keeps publishing against a Subscription that is no
/// longer its own.
///
/// The target Session is a second Session of client A: these Sessions are anonymous, and Part 4
/// section 5.13.7.1 permits an anonymous transfer only between Sessions of the same ApplicationUri (see
/// open_same_client_channel). That is what makes this the *validated* branch of the transition.
// @verifies AC-SVR-XFER-SM-023-TRANSFER-SUCCESS
TEST_F(TransferSubscriptionsSecure, TransferSub_ValidatedTransferRehomesResetsLifetimeAndNotifiesOldSession)
{
  auto targetChannel = open_same_client_channel();
  auto targetSession = targetChannel.create_session_sync({.sessionName = "SessionA2_Transition23"});
  targetSession.activate_sync();
  ASSERT_FALSE(targetSession.session_id().is_null());
  ASSERT_FALSE(targetSession.session_id() == mSessionA->session_id())
    << "The two Sessions must be distinguishable for SetSession() to be observable";

  auto [subId, miId] = create_subscription_with_monitored_item(*mSessionA,
    sWritableVariableId,
    SubscriptionOptions{.publishingInterval = 1000.0, .lifetimeCount = 100, .keepAliveCount = 10});

  auto sourceDiagNode = wait_for_subscription_diag_node(*mSessionA, subId);
  ASSERT_TRUE(sourceDiagNode.has_value()) << "No SubscriptionDiagnostics node for subscription " << subId;

  // No Publish on session A during this window, so the publishing timer decrements the counter. This
  // also leaves the old Session without a queued Publish at transfer time, which is why the
  // Good_SubscriptionTransferred notification below has to survive as a parked notification rather
  // than being delivered into a waiting request.
  std::this_thread::sleep_for(1500ms);
  write_value_async(*mSessionA, sWritableVariableId, Variant{int32_t{8002}});

  auto before = wait_for_transfer_diagnostics(*mSessionA,
    *sourceDiagNode,
    [](const SubscriptionDiagnosticsDataType& d)
    { return d.max_lifetime_count() > 0u && d.current_lifetime_count() < d.max_lifetime_count(); });
  ASSERT_GT(before.max_lifetime_count(), 0u) << "SubscriptionDiagnostics for " << subId << " never read";
  ASSERT_LT(before.current_lifetime_count(), before.max_lifetime_count())
    << "The lifetime counter never decayed, so a reset would not be observable here";
  const uint32_t decayed = before.current_lifetime_count();

  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  req.send_initial_values() = false;

  // (3) ReturnResponse.
  auto xferResult = targetSession.subscriptions().try_transfer_subscriptions_sync(std::move(req));
  ASSERT_TRUE(xferResult.is_good()) << to_string(xferResult.status_code());
  ASSERT_TRUE(xferResult.value().response_header().service_result().is_good())
    << to_string(xferResult.value().response_header().service_result());
  ASSERT_EQ(xferResult.value().results().size(), 1u);
  EXPECT_TRUE(xferResult.value().results()[0].status_code().is_good())
    << "A validated transfer to a different Session must succeed, got: "
    << to_string(xferResult.value().results()[0].status_code());

  auto targetDiagNode = wait_for_subscription_diag_node(targetSession, subId, sourceDiagNode);
  ASSERT_TRUE(targetDiagNode.has_value())
    << "No SubscriptionDiagnostics node for transferred subscription " << subId;

  auto after = wait_for_transfer_diagnostics(targetSession,
    *targetDiagNode,
    [decayed](const SubscriptionDiagnosticsDataType& d)
    { return d.max_lifetime_count() > 0u && d.current_lifetime_count() > decayed; });
  ASSERT_GT(after.max_lifetime_count(), 0u) << "SubscriptionDiagnostics for " << subId << " never read";

  // (1) SetSession: the Subscription's owning Session is the requesting one.
  EXPECT_TRUE(after.session_id() == targetSession.session_id())
    << "The transferred Subscription must be owned by the requesting Session; SessionId reads "
    << to_string(after.session_id()) << ", expected " << to_string(targetSession.session_id());

  // (2) ResetLifetimeCounter.
  EXPECT_GT(after.current_lifetime_count(), decayed)
    << "The transferred Subscription must not carry the old Session's spent lifetime counter; the "
       "counter only ever falls without a reset";
  EXPECT_EQ(after.current_lifetime_count(), after.max_lifetime_count())
    << "ResetLifetimeCounter() must restore the full revised lifetime count";

  // (4) IssueStatusChangeNotification on the old Session.
  auto scn = wait_for_status_change(*mSessionA, subId, 3000ms);
  ASSERT_TRUE(scn.has_value())
    << "The old Session must be told its Subscription moved (Part 4 section 5.13.7.1)";
  EXPECT_EQ(scn->status(), StatusCode{Status::GoodSubscriptionTransferred})
    << "StatusChangeNotification status must be GoodSubscriptionTransferred, got: "
    << to_string(scn->status());

  (void)targetSession.try_close_sync();
  (void)targetChannel.try_close_sync();
}

/// Part 4 section 5.13.1.2, Table 85 transition 24: when the Session changed but the client did not validate,
/// the only action is ReturnNegativeResponse - no SetSession, and in particular no
/// IssueStatusChangeNotification. The notification is the dangerous half: a server that builds and
/// enqueues Good_SubscriptionTransferred before running the identity check tells the legitimate owner
/// its Subscription has moved when it has not, and the correct client reaction to that notification is
/// to stop using the Subscription - so a refused theft attempt still costs the victim its data.
///
/// Both Sessions run on the same client over the same secured channel type and differ only by
/// authenticated user, so the refusal is decided by the identity comparison and nothing else. The
/// absence of a notification is asserted before anything else consumes a Publish response: a wrongly
/// issued StatusChangeNotification is parked until the next Publish, and any drain would swallow it.
// @verifies AC-SVR-XFER-SM-024-UNVALIDATED-REFUSED
TEST_F(TransferSubscriptionsIdentity, TransferSub_UnvalidatedTransferIsRefusedWithoutMovingOrNotifying)
{
  auto ownerChannel = open_secure_channel(*sClientX);
  auto ownerSession = ownerChannel.create_session_sync({.sessionName = "AliceOwnerTransition24"});
  ownerSession.activate_sync(user_identity(sAliceUser, sAlicePassword));

  auto claimantChannel = open_secure_channel(*sClientX);
  auto claimantSession = claimantChannel.create_session_sync({.sessionName = "BobClaimantTransition24"});
  claimantSession.activate_sync(user_identity(sBobUser, sBobPassword));

  auto [subId, miId] = create_subscription_with_monitored_item(ownerSession, sWritableVariableId);
  ASSERT_TRUE(drain_initial_values(ownerSession, subId, {1u}))
    << "The Subscription must be reporting to its owner before the unvalidated claim";

  // (1) A negative response.
  EXPECT_EQ(transfer_status(claimantSession, subId), StatusCode{Status::BadUserAccessDenied})
    << "A Session acting for a different user is not a validated client (transition 24)";

  // (2) No StatusChangeNotification to the owning Session. Asserted first, while a wrongly enqueued
  // notification is still parked and therefore still observable.
  auto scn = wait_for_status_change(ownerSession, subId, 1500ms);
  EXPECT_FALSE(scn.has_value()) << "A refused transfer must not tell the owner its Subscription moved; got a "
                                   "StatusChangeNotification with status "
                                << (scn.has_value() ? to_string(scn->status()) : std::string{"<none>"});

  // (3) The Subscription stayed with its original Session.
  write_value_async(ownerSession, sWritableVariableId, Variant{int32_t{9003}});
  auto notif = wait_for_data_change(ownerSession, subId, 2000ms);
  ASSERT_TRUE(notif) << "The refused transfer must leave the Subscription with its original Session";
  ASSERT_FALSE(notif->monitored_items().empty());
  EXPECT_THAT(*notif, ContainsDataChangeFor(1u, good_value_of<int32_t>(9003)));

  (void)claimantSession.try_close_sync();
  (void)claimantChannel.try_close_sync();
  (void)ownerSession.try_close_sync();
  (void)ownerChannel.try_close_sync();
}

/// Part 4 section 5.13.7.3, Table 101 lists Bad_TooManyOperations among the service results of
/// TransferSubscriptions, but Table 182 defines it as the batch exceeding "the limit set by the
/// Server": the refusal binds only where the Server sets a per-call ceiling on subscriptionIds[].
/// Part 5 section 6.3.11 Table 19 enumerates every advertisable operation limit and none scopes that array
/// - MaxMonitoredItemsPerCall, the only limit governing a per-Subscription array, is scoped to
/// itemsToCreate, itemsToModify, monitoredItemIds and linksToAdd/linksToRemove. So an over-limit
/// batch is not constructible against a Server that configures no such ceiling, and no service-level
/// refusal is obliged for one that is merely long.
///
/// What Table 101 does fix is the closed set of service-level refusals this Service may return. The
/// request below carries 1024 ids, so Bad_NothingToDo cannot apply, and it comes from a second
/// Session of the same client (see open_same_client_channel), so Bad_InsufficientClientProfile
/// cannot either. An oversized batch must therefore either be refused with Bad_TooManyOperations or
/// be answered at the service level and settled per operation - one results[] entry per requested id,
/// Part 4 section 5.13.7.2 - and never with some other service fault or a results[] shorter than the
/// request. The one real Subscription is listed FIRST so that whichever branch the Server takes, the
/// batch it walks begins with a genuinely transferable id.
// @verifies AC-SVR-XFER-SVC-002-TOOMANYOPERATIONS
TEST_F(TransferSubscriptionsSecure, TransferSub_RequestOverTheOperationLimitIsRejectedAndTransfersNothing)
{
  constexpr size_t oversizedOperationCount = 1024;

  auto targetChannel = open_same_client_channel();
  auto targetSession = targetChannel.create_session_sync({.sessionName = "SessionA2_TooManyOperations"});
  targetSession.activate_sync();

  auto [subId, miId] = create_subscription_with_monitored_item(*mSessionA, sWritableVariableId);

  // The Subscription must be live and reporting before the oversized request, otherwise the first id
  // in the batch is not a transferable one.
  ASSERT_TRUE(drain_initial_values(*mSessionA, subId, {1u}))
    << "The subscription must be reporting to its owner before the oversized transfer request";

  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  for (size_t i = 1; i < oversizedOperationCount; ++i)
    req.subscription_ids().push_back(static_cast<uint32_t>(1000000 + i));
  ASSERT_EQ(req.subscription_ids().size(), oversizedOperationCount);
  req.send_initial_values() = false;

  auto result = targetSession.subscriptions().try_transfer_subscriptions_sync(std::move(req));
  const StatusCode serviceStatus =
    result.is_bad() ? result.status_code() : StatusCode{result.value().response_header().service_result()};
  EXPECT_TRUE(serviceStatus.is_good() || serviceStatus == StatusCode{Status::BadTooManyOperations})
    << "Table 101 admits only Bad_NothingToDo, Bad_TooManyOperations and Bad_InsufficientClientProfile "
       "as service results, and the other two cannot apply to a 1024-id request from a Session of the "
       "owning client, got: "
    << to_string(serviceStatus);

  if (result.is_good() && serviceStatus.is_good())
  {
    EXPECT_EQ(result.value().results().size(), oversizedOperationCount)
      << "A batch accepted at the service level is settled per operation, one results[] entry per "
         "requested id, got "
      << result.value().results().size();
  }

  (void)targetSession.try_close_sync();
  (void)targetChannel.try_close_sync();
}

/// Part 4 section 5.13.1.2, Table 85 row 27: when the lifetime counter reaches one the Subscription
/// deletes its MonitoredItems, issues a StatusChangeNotification and reaches CLOSED, and Part 4 section
/// 5.13.1.1 fixes that notification's status code as Bad_Timeout. The transfer-area statement of the same
/// obligation adds the part that only a transfer can break: the notification goes to the Subscription's
/// CURRENT Session, which after a transfer is not the one that created it. A Server that re-homes the
/// Subscription for publishing but leaves the expiry path pointing at the Session recorded at creation
/// sends the death notice to a Session that no longer owns anything - the new owner is left holding a
/// SubscriptionId that has silently stopped existing, which is exactly the state a client recovering a
/// Subscription cannot detect any other way. The lifetime counter is also the reason no Publish may be
/// sent during the window below: it only decrements while no Publish request is queued, and every
/// Publish resets it, so a polling wait would keep the Subscription alive forever.
// @verifies AC-SVR-XFER-014-LIFETIME-EXPIRY-NOTIFICATION
TEST_F(TransferSubscriptionsSecure, TransferSub_LifetimeExpiryAfterTransferClosesItAndTellsTheNewOwner)
{
  constexpr uint32_t handle = 41;

  // The target Session is a second Session of client A: these Sessions are anonymous, and Part 4
  // section 5.13.7.1 permits an anonymous transfer only between Sessions of the same ApplicationUri (see
  // open_same_client_channel). The criterion is about what happens after the transfer, so the identity
  // precondition is satisfied rather than tested here.
  auto targetChannel = open_same_client_channel();
  auto targetSession = targetChannel.create_session_sync({.sessionName = "SessionA2_LifetimeExpiry"});
  targetSession.activate_sync();
  ASSERT_FALSE(targetSession.session_id() == mSessionA->session_id())
    << "the two Sessions must be distinguishable, or 'the current Session' names nothing";

  // A short lifetime so the counter can run out inside a test: 15 cycles of 200ms is three seconds.
  // The interval scales under a sanitizer and the expiry below is derived from the revised value, so
  // the counter still has to run out - just with room for an instrumented build to get there.
  auto createResp = mSessionA->subscriptions().create_subscription_sync(build_subscription_request(
    {.publishingInterval = ua::test_utils::scaled_ms(200.0), .lifetimeCount = 15, .keepAliveCount = 3}));
  ASSERT_TRUE(createResp.response_header().service_result().is_good())
    << to_string(createResp.response_header().service_result());
  const auto subId = createResp.subscription_id();
  ASSERT_NE(subId, 0u);
  const auto expiryMs =
    static_cast<int64_t>(createResp.revised_lifetime_count() * createResp.revised_publishing_interval());
  ASSERT_GT(expiryMs, 0);

  auto miResp = mSessionA->monitored_items().create_monitored_items_sync(build_create_mi_request(
    subId, sWritableVariableId, MonitoringOptions{.clientHandle = handle, .samplingInterval = 50.0}));
  ASSERT_EQ(miResp.results().size(), 1u);
  ASSERT_TRUE(miResp.results()[0].status_code().is_good())
    << "Monitored item was not created: " << to_string(miResp.results()[0].status_code());

  ASSERT_TRUE(drain_initial_values(*mSessionA, subId, {handle}))
    << "The Subscription must be reporting to its creating Session before it is transferred";

  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  req.send_initial_values() = false;

  auto xferResult = targetSession.subscriptions().try_transfer_subscriptions_sync(std::move(req));
  ASSERT_TRUE(xferResult.is_good()) << to_string(xferResult.status_code());
  ASSERT_TRUE(xferResult.value().response_header().service_result().is_good())
    << to_string(xferResult.value().response_header().service_result());
  ASSERT_EQ(xferResult.value().results().size(), 1u);
  ASSERT_TRUE(xferResult.value().results()[0].status_code().is_good())
    << "Transfer failed: " << to_string(xferResult.value().results()[0].status_code());

  // Antecedent: the transferred Subscription is serving its new Session. Without this, its silence
  // after the window below would be the silence of a Subscription that never worked there.
  write_value_async(targetSession, sWritableVariableId, Variant{int32_t{1401}});
  auto served = wait_for_data_change(
    targetSession,
    subId,
    [](const DataChangeNotification& dcn) { return !dcn.monitored_items().empty(); },
    3000ms);
  ASSERT_TRUE(served) << "The transferred Subscription never delivered on its new Session";

  // No Publish on either Session for the whole window - see the note above on the lifetime counter.
  std::this_thread::sleep_for(std::chrono::milliseconds{expiryMs + 1500});

  // The notification is issued on the Subscription's current Session.
  auto scn = wait_for_status_change(targetSession, subId, 3000ms);
  ASSERT_TRUE(scn.has_value()) << "No StatusChangeNotification reached the Session that owns subscription "
                               << subId << " after its lifetime counter ran out over " << expiryMs << "ms";
  EXPECT_EQ(scn->status(), StatusCode{Status::BadTimeout})
    << "A Subscription deleted by lifetime expiry issues Bad_Timeout, got: " << to_string(scn->status());

  // And it really was deleted: Republish naming it can no longer find the Subscription at all.
  {
    RepublishRequest repReq;
    repReq.subscription_id() = subId;
    repReq.retransmit_sequence_number() = 1;
    auto repResult = targetSession.subscriptions().try_republish_sync(std::move(repReq));
    const StatusCode repStatus = repResult.is_good()
                                   ? StatusCode{repResult.value().response_header().service_result()}
                                   : repResult.status_code();
    EXPECT_EQ(repStatus, StatusCode{Status::BadSubscriptionIdInvalid})
      << "The expired Subscription must reach CLOSED, but the Server still knows subscription " << subId
      << ": " << to_string(repStatus);
  }

  // The old Session is not the one told. It is entitled to the Good_SubscriptionTransferred notification
  // it was issued at the transfer, so only a Bad_Timeout for this Subscription counts as a violation.
  auto oldOwnerScn = wait_for_status_change(
    *mSessionA,
    subId,
    [](const StatusChangeNotification& notification)
    { return notification.status() == StatusCode{Status::BadTimeout}; },
    1500ms);
  EXPECT_FALSE(oldOwnerScn.has_value())
    << "The Bad_Timeout was issued on the Session that created subscription " << subId
    << ", not on the Session that owned it when it expired";

  (void)targetSession.try_close_sync();
  (void)targetChannel.try_close_sync();
}
