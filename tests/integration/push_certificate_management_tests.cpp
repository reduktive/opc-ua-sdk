// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Push Certificate Management - Integration Tests
///
/// End-to-end integration tests exercising the full push certificate management lifecycle
/// through the real OPC UA stack: Client -> TCP transport -> SecureChannel -> Session ->
/// Call service -> method handler -> component -> CertificateStoreFiles -> filesystem.

#include "compliance_helpers.h"

#include <boost/asio/ip/address.hpp>

#include "ua_error_chain.h"
#include "ua_error_detail.h"

#include "ua_session_attribute_services.h"
#include "ua_session_method_services.h"
#include "ua_session_monitored_item_services.h"
#include "ua_session_subscription_services.h"

#include "ua_access_level_type.h"
#include "ua_attribute_id.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_data_value.h"
#include "ua_method_id.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_server.h"
#include "ua_create_monitored_items_request.h"
#include "ua_create_monitored_items_response.h"
#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_event_filter.h"
#include "ua_event_field_list.h"
#include "ua_event_notification_list.h"
#include "ua_monitored_item_create_request.h"
#include "ua_monitoring_mode.h"
#include "ua_monitoring_parameters.h"
#include "ua_notification_message.h"
#include "ua_publish_request.h"
#include "ua_publish_response.h"
#include "ua_simple_attribute_operand.h"
#include "ua_timestamps_to_return.h"
#include "ua_trust_list_data_type.h"
#include "ua_variable_id.h"
#include "ua_write_request.h"
#include "ua_write_response.h"

#include "ua_session_view_services.h"

#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_result.h"
#include "ua_node_class.h"
#include "ua_reference_description.h"
#include "ua_server_state.h"

#include "requests.h"

#include "ua_binary_codec.h"
#include "ua_codec_namespace_context.h"
#include "ua_encoding_limits.h"
#include "ua_memory_stream.h"
#include "ua_structure_factory.h"

#include "test_pki_helpers.h"

#include "role_based_security_fixture.h"

#include "ua_discovery_registration.h"
#include "ua_lds_registrar.h"
#include "ua_mdns_discovery_configuration.h"
#include "ua_registered_server.h"

#include "fmt/format.h"
#include "fmt/ranges.h"

#include "ua_byte_format.h"

#include <algorithm>
#include <chrono>
#include <future>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace ua;
using namespace ua::client;
using namespace ua::server;

// ===========================================================================
// Helpers
// ===========================================================================

static CallRequest make_single_call(
  const NodeId& objectId, const NodeId& methodId, Array<Variant> inputArgs = {})
{
  CallMethodRequest req;
  req.object_id() = objectId;
  req.method_id() = methodId;
  req.input_arguments() = std::move(inputArgs);

  CallRequest callReq;
  callReq.methods_to_call().push_back(std::move(req));
  return callReq;
}

static const NodeId serverConfigObjectId{ObjectId::ServerConfiguration};
static const NodeId trustListObjectId{
  ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList};

// ===========================================================================
// Fixture: PushCertificateManagementTest
// ===========================================================================

class PushCertificateManagementTest : public ComplianceSecured
{
protected:
  void configure_server_create_config(server::CreateConfig& cfg) override
  {
    cfg.server.auditingEnabled = true;
  }

  // The server's ApplicationUri is the one its certificates name: UpdateCertificate validates a new
  // certificate against it (Part 12 7.10.4, Part 6 6.2.2), and every certificate this fixture pushes
  // carries this URI in its SubjectAltName, as the fixture's own server certificate does.
  void configure_secured_server(ApplicationConfig& appCfg) override
  {
    appCfg.application_description_part().applicationUri = "urn:test:compliance:server";
  }

  void SetUp() override
  {
    ComplianceSecured::SetUp();

    // Open SignAndEncrypt channel + session
    CoreClient::OpenChannelConfig channelCfg;
    channelCfg.endpointUrl = mEndpointUrl;
    channelCfg.securityMode = MessageSecurityMode::SignAndEncrypt;
    channelCfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    channelCfg.serverCertificate = mServerCert;
    mChannel.emplace(mClient->core().open_channel_sync(std::move(channelCfg)));
    mSession.emplace(mChannel->create_session_sync({.sessionName = "PushCertMgmtTest"}));
    mSession->activate_sync();

    // Set up CA for CSR signing
    mPki.emplace(mCrypto);
    auto caKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    mCaKeys = std::move(caKeys);
    mCaCert = mPki->create_root_ca(mCaKeys);

    // Add CA cert to trusted + issuer stores so UpdateCertificate validation succeeds
    mServerCertStore->add_to_trusted_certificates_sync(mCaCert);
    mServerCertStore->add_to_issuer_certificates_sync(mCaCert);
  }

  void TearDown() override
  {
    if (mSession)
      (void)mSession->try_close_sync();
    if (mChannel)
      (void)mChannel->try_close_sync();
    ComplianceSecured::TearDown();
  }

  /// Create a leaf app cert signed by the CA with proper key usages for OPC UA application certificates.
  std::shared_ptr<const X509Certificate> create_app_cert(std::shared_ptr<const AsymmetricKeyPair> subjectKeys,
    std::vector<std::string> uris = {"urn:test:compliance:server"},
    std::vector<std::string> hostnames = {"localhost"}, const std::string& name = "TestAppCert")
  {
    Crypto::CreateCertificateConfig p;
    p.subjectKeys = subjectKeys;
    p.issuerKeys = mCaKeys;
    p.subject.commonName = name;
    p.serialNumber = std::to_string(DateTime::now().value().time_since_epoch().count());
    p.keyUsage.digitalSignature = true;
    p.keyUsage.nonRepudiation = true;
    p.keyUsage.keyEncipherment = true;
    p.keyUsage.dataEncipherment = true;
    p.keyUsage.serverAuth = true;
    p.keyUsage.clientAuth = true;
    p.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
    p.from = DateTime::now();
    p.to = DateTime{p.from.value() + std::chrono::days{365}};
    p.issuer = mCaCert;
    p.subjectAlternateName.uris = std::move(uris);
    p.subjectAlternateName.hostnames = std::move(hostnames);
    // The host clients dial, as the certificate this one replaces names it.
    p.subjectAlternateName.ipAddresses.push_back(boost::asio::ip::make_address("127.0.0.1"));
    return mPki->create_cert(p);
  }

  // --- Call helpers ---

  /// Call a method on ServerConfiguration and return the operation-level result.
  CallMethodResult call_server_config_method(const NodeId& methodId, Array<Variant> inputArgs = {})
  {
    auto req = make_single_call(serverConfigObjectId, methodId, std::move(inputArgs));
    auto respResult = mSession->methods().try_call_sync(std::move(req));
    if (respResult.is_bad())
    {
      CallMethodResult bad;
      bad.status_code() = respResult.status_code();
      return bad;
    }
    auto& resp = respResult.value();
    if (resp.results().empty())
    {
      CallMethodResult bad;
      bad.status_code() = StatusCode{Status::BadUnexpectedError};
      return bad;
    }
    return std::move(resp.results()[0]);
  }

  /// Call a method on the TrustList object and return the operation-level result.
  CallMethodResult call_trust_list_method(const NodeId& methodId, Array<Variant> inputArgs = {})
  {
    auto req = make_single_call(trustListObjectId, methodId, std::move(inputArgs));
    auto respResult = mSession->methods().try_call_sync(std::move(req));
    if (respResult.is_bad())
    {
      CallMethodResult bad;
      bad.status_code() = respResult.status_code();
      return bad;
    }
    auto& resp = respResult.value();
    if (resp.results().empty())
    {
      CallMethodResult bad;
      bad.status_code() = StatusCode{Status::BadUnexpectedError};
      return bad;
    }
    return std::move(resp.results()[0]);
  }

  /// Call a method and return the operation-level result, on a custom session.
  CallMethodResult call_method_on_session(
    Session& session, const NodeId& objectId, const NodeId& methodId, Array<Variant> inputArgs = {})
  {
    auto req = make_single_call(objectId, methodId, std::move(inputArgs));
    auto respResult = session.methods().try_call_sync(std::move(req));
    if (respResult.is_bad())
    {
      CallMethodResult bad;
      bad.status_code() = respResult.status_code();
      return bad;
    }
    auto& resp = respResult.value();
    if (resp.results().empty())
    {
      CallMethodResult bad;
      bad.status_code() = StatusCode{Status::BadUnexpectedError};
      return bad;
    }
    return std::move(resp.results()[0]);
  }

  // --- Typed push management helpers ---

  Result<ByteString> call_create_signing_request(
    NodeId groupId, NodeId typeId, String subject, bool regenerateKey, ByteString nonce)
  {
    Array<Variant> args;
    args.resize(5);
    args[0] = Variant{std::move(groupId)};
    args[1] = Variant{std::move(typeId)};
    args[2] = Variant{std::move(subject)};
    args[3] = Variant{regenerateKey};
    args[4] = Variant{std::move(nonce)};

    auto result =
      call_server_config_method(NodeId{MethodId::ServerConfiguration_CreateSigningRequest}, std::move(args));

    if (result.status_code().is_bad())
      return result.status_code();
    if (result.output_arguments().empty())
      return StatusCode{Status::BadUnexpectedError};
    return result.output_arguments()[0].as<ByteString>();
  }

  Result<bool> call_update_certificate(NodeId groupId, NodeId typeId, ByteString cert,
    std::vector<ByteString> issuers = {}, String keyFormat = {}, ByteString privateKey = {})
  {
    Array<Variant> args;
    args.resize(6);
    args[0] = Variant{std::move(groupId)};
    args[1] = Variant{std::move(typeId)};
    args[2] = Variant{std::move(cert)};
    // issuerCertificates is an array of ByteString
    Array<ByteString> issuerArray;
    for (auto& i : issuers)
      issuerArray.push_back(std::move(i));
    args[3] = Variant{std::move(issuerArray)};
    args[4] = Variant{std::move(keyFormat)};
    args[5] = Variant{std::move(privateKey)};

    auto result =
      call_server_config_method(NodeId{MethodId::ServerConfiguration_UpdateCertificate}, std::move(args));

    if (result.status_code().is_bad())
      return result.status_code();
    if (result.output_arguments().empty())
      return StatusCode{Status::BadUnexpectedError};
    return result.output_arguments()[0].as<bool>();
  }

  VoidResult call_apply_changes()
  {
    auto result = call_server_config_method(NodeId{MethodId::ServerConfiguration_ApplyChanges});
    if (result.status_code().is_bad())
      return result.status_code();
    return VoidResult{};
  }

  VoidResult call_cancel_changes()
  {
    auto result = call_server_config_method(NodeId{MethodId::ServerConfiguration_CancelChanges});
    if (result.status_code().is_bad())
      return result.status_code();
    return VoidResult{};
  }

  Result<std::vector<ByteString>> call_get_rejected_list()
  {
    auto result = call_server_config_method(NodeId{MethodId::ServerConfiguration_GetRejectedList});
    if (result.status_code().is_bad())
      return result.status_code();
    if (result.output_arguments().empty())
      return StatusCode{Status::BadUnexpectedError};
    auto arr = result.output_arguments()[0].as<Array<ByteString>>();
    std::vector<ByteString> vec;
    for (auto& bs : arr)
      vec.push_back(std::move(bs));
    return vec;
  }

  // --- TrustList FileType helpers ---

  Result<uint32_t> call_open(uint8_t mode)
  {
    Array<Variant> args;
    args.resize(1);
    args[0] = Variant{mode};
    auto result = call_trust_list_method(
      NodeId{MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_Open},
      std::move(args));
    if (result.status_code().is_bad())
      return result.status_code();
    if (result.output_arguments().empty())
      return StatusCode{Status::BadUnexpectedError};
    return result.output_arguments()[0].as<uint32_t>();
  }

  VoidResult call_close(uint32_t handle)
  {
    Array<Variant> args;
    args.resize(1);
    args[0] = Variant{handle};
    auto result = call_trust_list_method(
      NodeId{MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_Close},
      std::move(args));
    if (result.status_code().is_bad())
      return result.status_code();
    return VoidResult{};
  }

  Result<ByteString> call_read_file(uint32_t handle, int32_t length)
  {
    Array<Variant> args;
    args.resize(2);
    args[0] = Variant{handle};
    args[1] = Variant{length};
    auto result = call_trust_list_method(
      NodeId{MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_Read},
      std::move(args));
    if (result.status_code().is_bad())
      return result.status_code();
    if (result.output_arguments().empty())
      return StatusCode{Status::BadUnexpectedError};
    return result.output_arguments()[0].as<ByteString>();
  }

  VoidResult call_write_file(uint32_t handle, ByteString data)
  {
    Array<Variant> args;
    args.resize(2);
    args[0] = Variant{handle};
    args[1] = Variant{std::move(data)};
    auto result = call_trust_list_method(
      NodeId{MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_Write},
      std::move(args));
    if (result.status_code().is_bad())
      return result.status_code();
    return VoidResult{};
  }

  Result<uint32_t> call_open_with_masks(uint32_t masks)
  {
    Array<Variant> args;
    args.resize(1);
    args[0] = Variant{masks};
    auto result = call_trust_list_method(
      NodeId{MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_OpenWithMasks},
      std::move(args));
    if (result.status_code().is_bad())
      return result.status_code();
    if (result.output_arguments().empty())
      return StatusCode{Status::BadUnexpectedError};
    return result.output_arguments()[0].as<uint32_t>();
  }

  Result<bool> call_close_and_update(uint32_t handle)
  {
    Array<Variant> args;
    args.resize(1);
    args[0] = Variant{handle};
    auto result = call_trust_list_method(
      NodeId{
        MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_CloseAndUpdate},
      std::move(args));
    if (result.status_code().is_bad())
      return result.status_code();
    if (result.output_arguments().empty())
      return StatusCode{Status::BadUnexpectedError};
    return result.output_arguments()[0].as<bool>();
  }

  VoidResult call_add_certificate(ByteString cert, bool isTrusted)
  {
    Array<Variant> args;
    args.resize(2);
    args[0] = Variant{std::move(cert)};
    args[1] = Variant{isTrusted};
    auto result = call_trust_list_method(
      NodeId{
        MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_AddCertificate},
      std::move(args));
    if (result.status_code().is_bad())
      return result.status_code();
    return VoidResult{};
  }

  VoidResult call_remove_certificate(String thumbprint, bool isTrusted)
  {
    Array<Variant> args;
    args.resize(2);
    args[0] = Variant{std::move(thumbprint)};
    args[1] = Variant{isTrusted};
    auto result = call_trust_list_method(
      NodeId{
        MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_RemoveCertificate},
      std::move(args));
    if (result.status_code().is_bad())
      return result.status_code();
    return VoidResult{};
  }

  // --- Property read helpers ---

  DataValue read_property(VariableId variableId)
  {
    ReadRequest req;
    ReadValueId rv;
    rv.node_id() = NodeId{variableId};
    rv.attribute_id() = static_cast<IntegerId>(AttributeId::Value);
    req.nodes_to_read().push_back(std::move(rv));

    auto resp = mSession->attributes().read_sync(std::move(req));
    EXPECT_EQ(resp.results().size(), 1u);
    return std::move(resp.results()[0]);
  }

  // --- Second session helpers ---

  struct SecondSession
  {
    SecureChannel channel;
    Session session;
  };

  SecondSession open_second_session()
  {
    CoreClient::OpenChannelConfig channelCfg;
    channelCfg.endpointUrl = mEndpointUrl;
    channelCfg.securityMode = MessageSecurityMode::SignAndEncrypt;
    channelCfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    channelCfg.serverCertificate = mServerCert;
    auto channel = mClient->core().open_channel_sync(std::move(channelCfg));
    auto session = channel.create_session_sync({.sessionName = "PushCertMgmtTest2"});
    session.activate_sync();
    return {std::move(channel), std::move(session)};
  }

  // --- Event subscription helpers ---

  /// Create an event subscription on the Server node, returning the subscription ID.
  uint32_t setup_event_subscription()
  {
    CreateSubscriptionRequest subReq;
    subReq.requested_publishing_interval() = 50.0;
    subReq.requested_lifetime_count() = 30;
    subReq.requested_max_keep_alive_count() = 10;
    subReq.max_notifications_per_publish() = 0;
    subReq.publishing_enabled() = true;
    auto subResp = mSession->subscriptions().create_subscription_sync(std::move(subReq));
    uint32_t subId = subResp.subscription_id();

    // EventFilter selecting EventId (index 0) and EventType (index 1)
    EventFilter filter;
    SimpleAttributeOperand eventIdOp;
    eventIdOp.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
    eventIdOp.browse_path().push_back(QualifiedName{0, "EventId"});
    eventIdOp.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    SimpleAttributeOperand eventTypeOp;
    eventTypeOp.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
    eventTypeOp.browse_path().push_back(QualifiedName{0, "EventType"});
    eventTypeOp.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    filter.select_clauses().push_back(std::move(eventIdOp));
    filter.select_clauses().push_back(std::move(eventTypeOp));

    ReadValueId rv;
    rv.node_id() = NodeId{ObjectId::Server};
    rv.attribute_id() = static_cast<uint32_t>(AttributeId::EventNotifier);

    MonitoringParameters params;
    params.client_handle() = 1;
    params.sampling_interval() = 0;
    params.queue_size() = 50;
    params.discard_oldest() = true;
    params.filter() = std::make_unique<EventFilter>(std::move(filter));

    MonitoredItemCreateRequest miCreateReq;
    miCreateReq.item_to_monitor() = std::move(rv);
    miCreateReq.monitoring_mode() = MonitoringMode::Reporting;
    miCreateReq.requested_parameters() = std::move(params);

    CreateMonitoredItemsRequest miReq;
    miReq.subscription_id() = subId;
    miReq.timestamps_to_return() = TimestampsToReturn::Both;
    miReq.items_to_create().push_back(std::move(miCreateReq));
    auto miResp = mSession->monitored_items().create_monitored_items_sync(std::move(miReq));
    EXPECT_EQ(miResp.results().size(), 1u);
    EXPECT_TRUE(!miResp.results()[0].status_code().is_bad())
      << "Monitored item creation failed: " << miResp.results()[0].status_code().as_uint32();

    return subId;
  }

  /// Collect event type NodeIds from publish responses. Publishes up to maxAttempts times.
  std::vector<NodeId> collect_event_types(int maxAttempts = 10)
  {
    std::vector<NodeId> eventTypes;
    for (int i = 0; i < maxAttempts; ++i)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      PublishRequest pubReq;
      auto pubResult = mSession->subscriptions().try_publish_sync(std::move(pubReq));
      if (pubResult.is_bad())
        continue;
      auto& resp = pubResult.value();
      if (resp.response_header().service_result().is_bad())
        continue;
      for (const auto& nd : resp.notification_message().notification_data())
      {
        auto* eventNotif = dynamic_cast<const EventNotificationList*>(nd.get());
        if (eventNotif == nullptr)
          continue;
        for (const auto& efl : eventNotif->events())
        {
          // EventType is at select clause index 1
          if (efl.event_fields().size() > 1 && efl.event_fields()[1].is_scalar())
          {
            try
            {
              eventTypes.push_back(efl.event_fields()[1].as<NodeId>());
            }
            catch (...)
            {}
          }
        }
      }
    }
    return eventTypes;
  }

  // --- Decode helpers ---

  TrustListDataType decode_trust_list(const ByteString& data)
  {
    memory_stream_device::ExternalReadOnly readDevice(data);
    MemoryStream<memory_stream_device::ExternalReadOnly> readStream(readDevice);
    UaBinaryDecoder decoder(StructureResolver{}, readStream, EncodingLimits{});
    TrustListDataType trustList;
    decoder.decode(EncodingLimits{}.stack_depth(), trustList);
    return trustList;
  }

  TrustListDataType read_trust_list(uint32_t masks = 0x0F)
  {
    auto handleResult = call_open_with_masks(masks);
    EXPECT_TRUE(handleResult.is_good()) << handleResult.status_code().as_uint32();
    auto handle = handleResult.value();

    auto dataResult = call_read_file(handle, 65535);
    EXPECT_TRUE(dataResult.is_good()) << dataResult.status_code().as_uint32();

    auto closeResult = call_close(handle);
    EXPECT_TRUE(closeResult.is_good()) << closeResult.status_code().as_uint32();

    return decode_trust_list(dataResult.value());
  }

  /// Open(Write|EraseExisting) -> Write(@p trustList) -> CloseAndUpdate on the application TrustList. Inside
  /// a transaction the change is staged until ApplyChanges (OPC 10000-12 7.8.2.3).
  Result<bool> close_and_update_trust_list(const TrustListDataType& trustList)
  {
    memory_stream_device::Dynamic encDevice(65535, /*reserve=*/true);
    MemoryStream<memory_stream_device::Dynamic> encStream(encDevice);
    UaBinaryEncoder encoder(CodecNamespaceContext{}, encStream);
    encoder.encode(EncodingLimits{}.stack_depth(), trustList);
    auto handle = call_open(0x06);
    if (handle.is_bad())
      return handle.status_code();
    auto written = call_write_file(handle.value(), ByteString{encDevice.get_data()});
    if (written.is_bad())
      return written.status_code();
    return call_close_and_update(handle.value());
  }

  /// A transaction opened the way 7.10.1 describes: an UpdateCertificate (AddCertificate and
  /// RemoveCertificate are not part of a transaction, 7.8.2.4 / 7.8.2.5). Cancel or apply it afterwards.
  void open_transaction_with_update_certificate()
  {
    auto keys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    auto cert = create_app_cert(keys);
    auto updated = call_update_certificate(
      NodeId{}, rsa_cert_type_id(), cert->der_encoding(), {}, String{"PEM"}, keys->private_key_pem());
    ASSERT_TRUE(updated.is_good()) << ua::format(updated.status_code());
  }

  /// A TrustList without the CA (all four lists empty): the change that makes a certificate the transaction
  /// staged earlier inconsistent at ApplyChanges.
  static TrustListDataType trust_list_without_the_ca()
  {
    TrustListDataType trustList;
    trustList.specified_lists() = 0x0F;
    return trustList;
  }

  // --- Convenience: RSA type NodeId ---

  static NodeId rsa_cert_type_id()
  {
    return NodeId{ObjectTypeId::RsaSha256ApplicationCertificateType};
  }

  // --- Members ---

  std::optional<SecureChannel> mChannel;
  std::optional<Session> mSession;
  std::optional<TestPki> mPki;
  std::shared_ptr<const AsymmetricKeyPair> mCaKeys;
  std::shared_ptr<const X509Certificate> mCaCert;
};

// ===========================================================================
// 3.1 Static property verification
// ===========================================================================

// @relation(SVR-PULLCRT-001, scope=function)
TEST_F(PushCertificateManagementTest, StaticProperties_SupportedPrivateKeyFormats)
{
  auto dv = read_property(VariableId::ServerConfiguration_SupportedPrivateKeyFormats);
  ASSERT_TRUE(!dv.status().has_value() || dv.status()->is_good());
  auto arr = dv.value().as<Array<String>>();
  bool hasPem = false;
  for (const auto& s : arr)
  {
    if (string_view{s} == "PEM")
      hasPem = true;
  }
  EXPECT_TRUE(hasPem) << "SupportedPrivateKeyFormats should contain 'PEM'";
}

TEST_F(PushCertificateManagementTest, StaticProperties_MaxTrustListSize)
{
  auto dv = read_property(VariableId::ServerConfiguration_MaxTrustListSize);
  ASSERT_TRUE(!dv.status().has_value() || dv.status()->is_good());
  auto value = dv.value().as<uint32_t>();
  EXPECT_GT(value, 0u);
}

TEST_F(PushCertificateManagementTest, StaticProperties_MulticastDnsEnabled)
{
  auto dv = read_property(VariableId::ServerConfiguration_MulticastDnsEnabled);
  ASSERT_TRUE(!dv.status().has_value() || dv.status()->is_good());
  EXPECT_FALSE(dv.value().as<bool>());
}

TEST_F(PushCertificateManagementTest, StaticProperties_HasSecureElement)
{
  auto dv = read_property(VariableId::ServerConfiguration_HasSecureElement);
  ASSERT_TRUE(!dv.status().has_value() || dv.status()->is_good());
  EXPECT_FALSE(dv.value().as<bool>());
}

// @relation(SVR-ECC-010, SVR-PULLCRT-003, scope=function)
TEST_F(PushCertificateManagementTest, StaticProperties_CertificateTypes)
{
  auto dv =
    read_property(VariableId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateTypes);
  ASSERT_TRUE(!dv.status().has_value() || dv.status()->is_good());
  // The property should be an array of NodeId containing the supported certificate types.
  // The server derives types from the cert store at runtime, so it must always be populated.
  ASSERT_TRUE(dv.value().is_array()) << "CertificateTypes should be an array";
  auto& arr = dv.value().as<Array<NodeId>>();
  ASSERT_FALSE(arr.empty()) << "CertificateTypes array should not be empty";
  bool hasRsa = false;
  for (const auto& nid : arr)
  {
    if (nid == rsa_cert_type_id())
      hasRsa = true;
  }
  EXPECT_TRUE(hasRsa) << "CertificateTypes should contain RsaSha256ApplicationCertificateType";
}

// ===========================================================================
// 3.1b Transaction diagnostics (Part 12 section 7.10.11, UA-1.05.06)
// ===========================================================================

// SupportsTransactions advertises that the SDK implements the push transaction
// model (queues changes, ApplyChanges required).
TEST_F(PushCertificateManagementTest, SupportsTransactions_ReadsTrue)
{
  auto dv = read_property(VariableId::ServerConfiguration_SupportsTransactions);
  ASSERT_TRUE(!dv.status().has_value() || dv.status()->is_good());
  EXPECT_TRUE(dv.value().as<bool>()) << "SupportsTransactions should advertise true";
}

// Before any transaction, the TransactionDiagnostics Result Variable has status
// Bad_OutOfService (Part 12 section 7.10.11). Read over an encrypted admin session.
// @relation(SVR-ECC-010, SVR-PULLCRT-031, scope=function)
TEST_F(PushCertificateManagementTest, TransactionDiagnostics_InitialStateOutOfService)
{
  auto dv = read_property(VariableId::ServerConfiguration_TransactionDiagnostics_Result);
  ASSERT_TRUE(dv.status().has_value()) << "Result should carry a value status";
  EXPECT_EQ(*dv.status(), StatusCode{Status::BadOutOfService});
}

// After a CancelChanges the TransactionDiagnostics Object reflects the cancelled
// transaction: Result value Bad_RequestCancelledByClient (Part 12 section 7.10.11) and
// the affected certificate group recorded. CancelChanges (unlike a successful
// ApplyChanges) does not renegotiate channels, so the same session can read back.
TEST_F(PushCertificateManagementTest, TransactionDiagnostics_PopulatedAfterCancelChanges)
{
  // Stage a certificate update so the transaction has an affected group.
  auto newKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto newCert = create_app_cert(newKeys, {"urn:test:compliance:server"}, {"localhost"}, "DiagServer");
  std::vector<ByteString> issuers;
  issuers.push_back(mCaCert->der_encoding());
  auto updateResult = call_update_certificate(NodeId{},
    rsa_cert_type_id(),
    newCert->der_encoding(),
    std::move(issuers),
    String{"PEM"},
    newKeys->private_key_pem());
  ASSERT_TRUE(updateResult.is_good())
    << ua::format(updateResult.status_code())
    << (updateResult.shared_detail() ? "\n" + ua::to_string(*updateResult.shared_detail()) : std::string{});

  auto cancelResult = call_cancel_changes();
  ASSERT_TRUE(cancelResult.is_good()) << cancelResult.status_code().as_uint32();

  // Result value reflects the cancellation.
  auto resultDv = read_property(VariableId::ServerConfiguration_TransactionDiagnostics_Result);
  EXPECT_EQ(resultDv.value().as<StatusCode>(), StatusCode{Status::BadRequestCancelledByClient});

  // AffectedCertificateGroups contains the DefaultApplicationGroup.
  auto groupsDv =
    read_property(VariableId::ServerConfiguration_TransactionDiagnostics_AffectedCertificateGroups);
  ASSERT_TRUE(groupsDv.value().is_array());
  const auto& groups = groupsDv.value().as<Array<NodeId>>();
  bool hasDefaultGroup = false;
  for (const auto& id : groups)
  {
    if (id == NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup})
      hasDefaultGroup = true;
  }
  EXPECT_TRUE(hasDefaultGroup) << "AffectedCertificateGroups should contain DefaultApplicationGroup";
}

// ===========================================================================
// 3.2 TrustList FileType protocol
// ===========================================================================

TEST_F(PushCertificateManagementTest, TrustList_OpenRead_ReturnsHandle)
{
  auto handleResult = call_open(0x01);  // Read mode
  ASSERT_TRUE(handleResult.is_good()) << handleResult.status_code().as_uint32();
  EXPECT_GT(handleResult.value(), 0u);
  call_close(handleResult.value());
}

TEST_F(PushCertificateManagementTest, TrustList_OpenWrite_ReturnsHandle)
{
  auto handleResult = call_open(0x06);  // Write|EraseExisting
  ASSERT_TRUE(handleResult.is_good()) << handleResult.status_code().as_uint32();
  EXPECT_GT(handleResult.value(), 0u);
  call_close(handleResult.value());
}

TEST_F(PushCertificateManagementTest, TrustList_OpenInvalidMode_Fails)
{
  auto handleResult = call_open(0x02);  // Write-only (invalid per Part 12)
  EXPECT_TRUE(handleResult.is_bad());
}

TEST_F(PushCertificateManagementTest, TrustList_ReadAfterOpen_ReturnsTrustListData)
{
  auto handleResult = call_open(0x01);
  ASSERT_TRUE(handleResult.is_good()) << handleResult.status_code().as_uint32();
  auto handle = handleResult.value();

  auto dataResult = call_read_file(handle, 65535);
  ASSERT_TRUE(dataResult.is_good()) << dataResult.status_code().as_uint32();
  ASSERT_FALSE(dataResult.value().empty());

  call_close(handle);

  // Decode and verify the data contains at least one trusted certificate
  auto trustList = decode_trust_list(dataResult.value());
  EXPECT_FALSE(trustList.trusted_certificates().empty())
    << "Trust list should contain at least one trusted certificate";
}

TEST_F(PushCertificateManagementTest, TrustList_DoubleOpen_Fails)
{
  auto handle1 = call_open(0x01);
  ASSERT_TRUE(handle1.is_good()) << handle1.status_code().as_uint32();

  // Second open should fail
  auto handle2 = call_open(0x01);
  EXPECT_TRUE(handle2.is_bad());

  call_close(handle1.value());
}

TEST_F(PushCertificateManagementTest, TrustList_WriteAndCloseAndUpdate_ReplacesTrustList)
{
  // Read the current trust list to preserve existing trusted certs
  auto currentTrustList = read_trust_list(0x01);

  // Create a new leaf certificate to add
  auto leafKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leafCert = mPki->create_leaf_cert(leafKeys,
    mCaKeys,
    mCaCert,
    DateTime::now(),
    DateTime{DateTime::now().value() + std::chrono::days{365}},
    {"urn:test:write:replace"},
    {"localhost"},
    "WriteReplaceLeaf");

  // Build a TrustListDataType with existing certs plus the new one
  TrustListDataType newTrustList;
  newTrustList.specified_lists() = 0x01;  // TrustedCertificates only
  for (const auto& cert : currentTrustList.trusted_certificates())
    newTrustList.trusted_certificates().push_back(cert);
  newTrustList.trusted_certificates().push_back(leafCert->der_encoding());

  // Encode the TrustListDataType to UA Binary
  memory_stream_device::Dynamic encDevice(65535, /*reserve=*/true);
  MemoryStream<memory_stream_device::Dynamic> encStream(encDevice);
  UaBinaryEncoder encoder(CodecNamespaceContext{}, encStream);
  encoder.encode(EncodingLimits{}.stack_depth(), newTrustList);
  auto encoded = encDevice.get_data();

  // Open for write (mode 0x06 = Write|EraseExisting)
  auto handleResult = call_open(0x06);
  ASSERT_TRUE(handleResult.is_good()) << handleResult.status_code().as_uint32();
  auto handle = handleResult.value();

  // Write the encoded trust list
  auto writeResult = call_write_file(handle, std::move(encoded));
  ASSERT_TRUE(writeResult.is_good()) << writeResult.status_code().as_uint32();

  auto closeResult = call_close_and_update(handle);
  ASSERT_TRUE(closeResult.is_good()) << closeResult.status_code().as_uint32();
  EXPECT_TRUE(closeResult.value());

  // RATIFIED (owner report 2026-10-03, BR-13): the TrustList changes at ApplyChanges (OPC 10000-12 7.8.2.3:
  // "the Server does not update the TrustList until ApplyChanges ... Any Clients that read the TrustList
  // before ApplyChanges is called will receive the existing TrustList"); the test asserted the change at
  // once.
  {
    const auto before = read_trust_list(0x01);
    const auto leafDer = leafCert->der_encoding();
    EXPECT_TRUE(
      std::ranges::none_of(before.trusted_certificates(), [&](const auto& c) { return c == leafDer; }))
      << "read before ApplyChanges returns the TrustList before the transaction";
  }
  auto applied = call_apply_changes();
  ASSERT_TRUE(applied.is_good()) << ua::format(applied.status_code());

  // Read back and verify the new cert is present
  auto updatedTrustList = read_trust_list(0x01);
  auto leafDer = leafCert->der_encoding();
  bool found = false;
  for (const auto& cert : updatedTrustList.trusted_certificates())
  {
    if (cert == leafDer)
    {
      found = true;
      break;
    }
  }
  EXPECT_TRUE(found) << "Written leaf cert should be present after CloseAndUpdate";

  // Cancel to clean up the pending transaction
  call_cancel_changes();
}

// ===========================================================================
// 3.3 OpenWithMasks
// ===========================================================================

// Covers SVR-SECADMIN-009 (coverage-audit retag).
TEST_F(PushCertificateManagementTest, OpenWithMasks_TrustedOnly)
{
  auto trustList = read_trust_list(0x01);
  EXPECT_FALSE(trustList.trusted_certificates().empty()) << "Trusted certificates should not be empty";
  EXPECT_TRUE(trustList.issuer_certificates().empty()) << "Issuer certificates should be empty for mask 0x01";
  EXPECT_TRUE(trustList.issuer_crls().empty()) << "Issuer CRLs should be empty for mask 0x01";
}

TEST_F(PushCertificateManagementTest, OpenWithMasks_AllMasks)
{
  auto trustList = read_trust_list(0x0F);
  EXPECT_EQ(trustList.specified_lists(), 0x0Fu) << "specified_lists should be 0x0F for all masks";
}

TEST_F(PushCertificateManagementTest, OpenWithMasks_ZeroFetchesAll)
{
  auto trustList = read_trust_list(0);
  // Zero means fetch all - specified_lists should cover all lists
  EXPECT_EQ(trustList.specified_lists(), 0x0Fu) << "specified_lists should cover all lists when mask is zero";
}

// ===========================================================================
// 3.4 AddCertificate / RemoveCertificate
// ===========================================================================

TEST_F(PushCertificateManagementTest, AddCertificate_TrustedAddsToStore)
{
  // Create a leaf certificate to add
  auto leafKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leafCert = mPki->create_leaf_cert(leafKeys,
    mCaKeys,
    mCaCert,
    DateTime::now(),
    DateTime{DateTime::now().value() + std::chrono::days{365}},
    {"urn:test:extra:leaf"},
    {"localhost"},
    "ExtraLeaf");

  auto addResult = call_add_certificate(leafCert->der_encoding(), true);
  ASSERT_TRUE(addResult.is_good()) << addResult.status_code().as_uint32();

  // Verify the specific cert is present in the trust list
  auto trustList = read_trust_list(0x01);
  auto leafDer = leafCert->der_encoding();
  bool found = false;
  for (const auto& cert : trustList.trusted_certificates())
  {
    if (cert == leafDer)
    {
      found = true;
      break;
    }
  }
  EXPECT_TRUE(found) << "Added leaf cert DER should be present in trusted certificates";
}

// RATIFIED EXPECTATION CHANGE (group J, B3-4): OPC 10000-12 1.05.02 7.8.2.4 (errata 6794) - "If FALSE
// Bad_CertificateInvalid is returned." AddCertificate with isTrustedCertificate FALSE no longer adds the
// certificate to the issuer list.
// @verifies AC-SVR-SECADMIN-009-ADDCERTIFICATE-VALIDATES-AND-REFUSES-WHAT-THE-SPEC-REFUSES
TEST_F(PushCertificateManagementTest, AddCertificate_IsTrustedFalseIsRefusedAndAddsNothing)
{
  // A CA in neither list, so an add to either would show (the fixture's CA is already an issuer).
  auto freshCaKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto freshCa = mPki->create_root_ca(freshCaKeys);
  const auto freshDer = freshCa->der_encoding();

  auto addResult = call_add_certificate(freshDer, false);
  EXPECT_EQ(addResult.status_code().as_status(), Status::BadCertificateInvalid);

  const auto lists = read_trust_list(0x05);  // trusted and issuer certificates
  EXPECT_EQ(std::ranges::count(lists.issuer_certificates(), freshDer), 0) << "not added as an issuer";
  EXPECT_EQ(std::ranges::count(lists.trusted_certificates(), freshDer), 0) << "not added as trusted";
}

TEST_F(PushCertificateManagementTest, RemoveCertificate_RemovesFromStore)
{
  // First add a cert
  auto leafKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leafCert = mPki->create_leaf_cert(leafKeys,
    mCaKeys,
    mCaCert,
    DateTime::now(),
    DateTime{DateTime::now().value() + std::chrono::days{365}},
    {"urn:test:remove:leaf"},
    {"localhost"},
    "RemoveLeaf");

  auto addResult = call_add_certificate(leafCert->der_encoding(), true);
  ASSERT_TRUE(addResult.is_good()) << addResult.status_code().as_uint32();

  // Now remove it by thumbprint
  auto thumbprint = fmt::format("{:02X}", fmt::join(leafCert->thumbprint(), ""));
  auto removeResult = call_remove_certificate(String{thumbprint}, true);
  ASSERT_TRUE(removeResult.is_good()) << removeResult.status_code().as_uint32();

  // Verify the removed cert is no longer in the trust list
  auto trustList = read_trust_list(0x01);
  auto leafDer = leafCert->der_encoding();
  bool found = false;
  for (const auto& cert : trustList.trusted_certificates())
  {
    if (cert == leafDer)
    {
      found = true;
      break;
    }
  }
  EXPECT_FALSE(found) << "Removed certificate should not be in the trust list";
}

// Part 12 Figure 22 (7.8.2.1): while Session A's transaction is in progress, Session B's Open with the write
// bit is refused with Bad_TransactionPending; B may still read, and A may open for write. Through the
// server's own wiring (the push service's transaction owner).
// @verifies AC-SVR-PULLCRT-039-OPEN-FOR-WRITE-IS-REFUSED-UNDER-ANOTHER-SESSIONS-TRANSACTION
TEST_F(PushCertificateManagementTest, OpenForWriteIsRefusedForAnotherSessionDuringATransaction)
{
  open_transaction_with_update_certificate();
  auto [channel2, session2] = open_second_session();
  const auto openOnSession2 = [&](uint8_t mode)
  {
    Array<Variant> args;
    args.resize(1);
    args[0] = Variant{mode};
    return call_method_on_session(session2,
      trustListObjectId,
      NodeId{MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_Open},
      std::move(args));
  };

  auto refused = openOnSession2(0x06);
  EXPECT_EQ(refused.status_code(), StatusCode{Status::BadTransactionPending})
    << "0x" << std::hex << refused.status_code().as_uint32();
  auto read = openOnSession2(0x01);
  ASSERT_TRUE(read.status_code().is_good()) << "reading is not refused";
  ASSERT_FALSE(read.output_arguments().empty());
  Array<Variant> closeArgs;
  closeArgs.resize(1);
  closeArgs[0] = read.output_arguments()[0];
  (void)call_method_on_session(session2,
    trustListObjectId,
    NodeId{MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_Close},
    std::move(closeArgs));
  auto owner = call_open(0x06);
  ASSERT_TRUE(owner.is_good()) << "the transaction's own Session may open for write";
  (void)call_close(owner.value());

  session2.close_sync();
  channel2.close_sync();
  call_cancel_changes();
}

// Part 12 Figure 22 end to end: Session A's Open with the write bit starts its transaction, which outlives
// the handle - closed here with nothing changed - so Session B's Open for write is refused with
// Bad_TransactionPending although no handle is open. ApplyChanges ends the empty transaction and B may open.
// Falsifiable: the former server started the transaction only at CloseAndUpdate.
// @verifies AC-SVR-PULLCRT-039-B-OPEN-FOR-WRITE-STARTS-THE-SESSIONS-TRANSACTION
TEST_F(PushCertificateManagementTest, OpenForWriteStartsATransactionThatOutlivesTheHandle)
{
  auto opened = call_open(0x06);
  ASSERT_TRUE(opened.is_good()) << ua::format(opened.status_code());
  ASSERT_TRUE(call_close(opened.value()).is_good());

  auto [channel2, session2] = open_second_session();
  const auto openOnSession2 = [&]()
  {
    Array<Variant> args;
    args.resize(1);
    args[0] = Variant{uint8_t{0x06}};
    return call_method_on_session(session2,
      trustListObjectId,
      NodeId{MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_Open},
      std::move(args));
  };
  auto refused = openOnSession2();
  EXPECT_EQ(refused.status_code(), StatusCode{Status::BadTransactionPending})
    << "0x" << std::hex << refused.status_code().as_uint32();

  auto applied = call_apply_changes();
  ASSERT_TRUE(applied.is_good()) << "the empty transaction applies: " << ua::format(applied.status_code());

  auto admitted = openOnSession2();
  ASSERT_TRUE(admitted.status_code().is_good()) << "0x" << std::hex << admitted.status_code().as_uint32();
  ASSERT_FALSE(admitted.output_arguments().empty());
  Array<Variant> closeArgs;
  closeArgs.resize(1);
  closeArgs[0] = admitted.output_arguments()[0];
  (void)call_method_on_session(session2,
    trustListObjectId,
    NodeId{MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_Close},
    std::move(closeArgs));
  session2.close_sync();
  channel2.close_sync();
}

// Decision 28: a thumbprint that is not 40 hexadecimal digits is Bad_InvalidArgument.
// @verifies AC-SVR-PULLCRT-038-A-UNKNOWN-THUMBPRINT-IS-INVALID-ARGUMENT
TEST_F(PushCertificateManagementTest, RemoveCertificate_MalformedThumbprint_ReturnsBadInvalidArgument)
{
  auto removeResult = call_remove_certificate(String{"DEADBEEF"}, true);
  EXPECT_EQ(removeResult.status_code(), StatusCode{Status::BadInvalidArgument})
    << "0x" << std::hex << removeResult.status_code().as_uint32();
}

// Part 12 7.8.2.5: "It returns Bad_InvalidArgument if the thumbprint does not match a Certificate in the
// Trust List" - a well-formed thumbprint of no listed certificate, through the public Method.
// @verifies AC-SVR-PULLCRT-038-A-UNKNOWN-THUMBPRINT-IS-INVALID-ARGUMENT
TEST_F(PushCertificateManagementTest, RemoveCertificate_UnknownThumbprint_ReturnsBadInvalidArgument)
{
  auto strangerKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto stranger = mPki->create_root_ca(strangerKeys, "Never Listed CA", "300");
  const auto thumbprint = fmt::format("{:02X}", fmt::join(stranger->thumbprint(), ""));

  auto removeResult = call_remove_certificate(String{thumbprint}, true);

  EXPECT_EQ(removeResult.status_code(), StatusCode{Status::BadInvalidArgument})
    << "0x" << std::hex << removeResult.status_code().as_uint32();
}

// Part 12 7.8.2.5: "If the Certificate is a CA Certificate that has CRLs then all CRLs for that CA are
// removed as well" (Mantis 6796: only that CA's), seen through GetTrustList after the public Method.
// @verifies AC-SVR-PULLCRT-038-B-A-CA-LEAVES-WITH-ITS-CRLS
TEST_F(PushCertificateManagementTest, RemoveCertificate_OfACaRemovesItsCrls)
{
  auto removedKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto removedCa = mPki->create_root_ca(removedKeys, "Removed Issuer CA", "301");
  auto removedCrl = mPki->create_crl(removedCa, removedKeys, {});
  auto keptCrl = mPki->create_crl(mCaCert, mCaKeys, {});
  mServerCertStore->add_to_issuer_certificates_sync(removedCa);
  mServerCertStore->add_to_issuer_crls_sync(removedCrl);
  mServerCertStore->add_to_issuer_crls_sync(keptCrl);

  const auto thumbprint = fmt::format("{:02X}", fmt::join(removedCa->thumbprint(), ""));
  auto removeResult = call_remove_certificate(String{thumbprint}, /*isTrusted=*/false);
  ASSERT_TRUE(removeResult.is_good()) << "0x" << std::hex << removeResult.status_code().as_uint32();

  const auto lists = read_trust_list(0x0C);  // issuer certificates and issuer CRLs
  EXPECT_EQ(std::ranges::count(lists.issuer_certificates(), removedCa->der_encoding()), 0);
  EXPECT_EQ(std::ranges::count(lists.issuer_crls(), removedCrl->der_encoding()), 0)
    << "the CA's CRL left with it";
  EXPECT_EQ(std::ranges::count(lists.issuer_crls(), keptCrl->der_encoding()), 1) << "another CA's CRL stays";
  EXPECT_EQ(std::ranges::count(lists.issuer_certificates(), mCaCert->der_encoding()), 1);
}

// ===========================================================================
// 3.5 Security checks - channel security mode
// ===========================================================================

class PushCertNoneChannelTest : public ComplianceSecured
{
protected:
  void configure_server_create_config(server::CreateConfig& cfg) override
  {
    cfg.server.auditingEnabled = true;
  }

  void SetUp() override
  {
    ComplianceSecured::SetUp();

    // Open None channel + session
    CoreClient::OpenChannelConfig channelCfg;
    channelCfg.endpointUrl = mEndpointUrl;
    channelCfg.securityMode = MessageSecurityMode::None;
    channelCfg.securityPolicyId = SecurityPolicyId::None;
    mChannel.emplace(mClient->core().open_channel_sync(std::move(channelCfg)));
    mSession.emplace(mChannel->create_session_sync({.sessionName = "PushCertNoneTest"}));
    mSession->activate_sync();
  }

  void TearDown() override
  {
    if (mSession)
      (void)mSession->try_close_sync();
    if (mChannel)
      (void)mChannel->try_close_sync();
    ComplianceSecured::TearDown();
  }

  CallMethodResult call_method(const NodeId& objectId, const NodeId& methodId, Array<Variant> inputArgs = {})
  {
    auto req = make_single_call(objectId, methodId, std::move(inputArgs));
    auto resp = mSession->methods().call_sync(std::move(req));
    EXPECT_EQ(resp.results().size(), 1u);
    return std::move(resp.results()[0]);
  }

  std::optional<SecureChannel> mChannel;
  std::optional<Session> mSession;
};

// @relation(SVR-ECC-010, SVR-PULLCRT-006, scope=function)
TEST_F(PushCertNoneChannelTest, UpdateCertificate_NoneChannel_Fails)
{
  Array<Variant> args;
  args.resize(6);
  args[0] = Variant{NodeId{}};
  args[1] = Variant{NodeId{ObjectTypeId::RsaSha256ApplicationCertificateType}};
  args[2] = Variant{ByteString{}};
  args[3] = Variant{Array<ByteString>{}};
  args[4] = Variant{String{}};
  args[5] = Variant{ByteString{}};

  auto result = call_method(
    serverConfigObjectId, NodeId{MethodId::ServerConfiguration_UpdateCertificate}, std::move(args));
  EXPECT_TRUE(result.status_code().is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadSecurityModeInsufficient});
}

// @relation(SVR-ECC-010, SVR-PULLCRT-010, scope=function)
TEST_F(PushCertNoneChannelTest, CreateSigningRequest_NoneChannel_Fails)
{
  Array<Variant> args;
  args.resize(5);
  args[0] = Variant{NodeId{}};
  args[1] = Variant{NodeId{ObjectTypeId::RsaSha256ApplicationCertificateType}};
  args[2] = Variant{String{}};
  args[3] = Variant{true};
  args[4] = Variant{ByteString(std::vector<byte>(32, byte{0xAB}))};

  auto result = call_method(
    serverConfigObjectId, NodeId{MethodId::ServerConfiguration_CreateSigningRequest}, std::move(args));
  EXPECT_TRUE(result.status_code().is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadSecurityModeInsufficient});
}

TEST_F(PushCertNoneChannelTest, AddCertificate_NoneChannel_Fails)
{
  Array<Variant> args;
  args.resize(2);
  args[0] = Variant{ByteString{}};
  args[1] = Variant{true};

  auto result = call_method(trustListObjectId,
    NodeId{MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_AddCertificate},
    std::move(args));
  EXPECT_TRUE(result.status_code().is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadSecurityModeInsufficient});
}

TEST_F(PushCertNoneChannelTest, CloseAndUpdate_NoneChannel_Fails)
{
  Array<Variant> args;
  args.resize(1);
  args[0] = Variant{uint32_t{0}};

  auto result = call_method(trustListObjectId,
    NodeId{MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_CloseAndUpdate},
    std::move(args));
  EXPECT_TRUE(result.status_code().is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadSecurityModeInsufficient});
}

// --- Sign channel tests ---

class PushCertSignChannelTest : public ComplianceSecured
{
protected:
  void configure_server_create_config(server::CreateConfig& cfg) override
  {
    cfg.server.auditingEnabled = true;
  }

  void SetUp() override
  {
    ComplianceSecured::SetUp();

    CoreClient::OpenChannelConfig channelCfg;
    channelCfg.endpointUrl = mEndpointUrl;
    channelCfg.securityMode = MessageSecurityMode::Sign;
    channelCfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    channelCfg.serverCertificate = mServerCert;
    mChannel.emplace(mClient->core().open_channel_sync(std::move(channelCfg)));
    mSession.emplace(mChannel->create_session_sync({.sessionName = "PushCertSignTest"}));
    mSession->activate_sync();
  }

  void TearDown() override
  {
    if (mSession)
      (void)mSession->try_close_sync();
    if (mChannel)
      (void)mChannel->try_close_sync();
    ComplianceSecured::TearDown();
  }

  CallMethodResult call_method(const NodeId& objectId, const NodeId& methodId, Array<Variant> inputArgs = {})
  {
    auto req = make_single_call(objectId, methodId, std::move(inputArgs));
    auto resp = mSession->methods().call_sync(std::move(req));
    EXPECT_EQ(resp.results().size(), 1u);
    return std::move(resp.results()[0]);
  }

  std::optional<SecureChannel> mChannel;
  std::optional<Session> mSession;
};

TEST_F(PushCertSignChannelTest, ApplyChanges_SignChannel_Succeeds)
{
  // ApplyChanges with no transaction should fail with BadNothingToDo, not BadSecurityModeInsufficient
  auto result = call_method(serverConfigObjectId, NodeId{MethodId::ServerConfiguration_ApplyChanges});
  // Should NOT be BadSecurityModeInsufficient - the security mode is sufficient
  EXPECT_NE(result.status_code(), StatusCode{Status::BadSecurityModeInsufficient});
}

// @relation(SVR-ECC-010, SVR-PULLCRT-021, scope=function)
TEST_F(PushCertSignChannelTest, GetRejectedList_SignChannel_Succeeds)
{
  auto result = call_method(serverConfigObjectId, NodeId{MethodId::ServerConfiguration_GetRejectedList});
  EXPECT_TRUE(result.status_code().is_good()) << result.status_code().as_uint32();
}

TEST_F(PushCertSignChannelTest, Open_SignChannel_Succeeds)
{
  Array<Variant> args;
  args.resize(1);
  args[0] = Variant{uint8_t{0x01}};  // Read mode
  auto result = call_method(trustListObjectId,
    NodeId{MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_Open},
    std::move(args));
  EXPECT_TRUE(result.status_code().is_good()) << result.status_code().as_uint32();

  // Close the handle
  if (result.status_code().is_good() && !result.output_arguments().empty())
  {
    auto handle = result.output_arguments()[0].as<uint32_t>();
    Array<Variant> closeArgs;
    closeArgs.resize(1);
    closeArgs[0] = Variant{handle};
    call_method(trustListObjectId,
      NodeId{MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_Close},
      std::move(closeArgs));
  }
}

// ===========================================================================
// 3.6 CreateSigningRequest
// ===========================================================================

// @relation(SVR-ECC-010, SVR-PULLCRT-013, scope=function)
TEST_F(PushCertificateManagementTest, CreateSigningRequest_ValidParams_ReturnsDerCsr)
{
  ByteString nonce(std::vector<byte>(32, byte{0xAB}));
  auto csrResult =
    call_create_signing_request(NodeId{}, rsa_cert_type_id(), String{}, true, std::move(nonce));
  ASSERT_TRUE(csrResult.is_good()) << csrResult.status_code().as_uint32();
  EXPECT_FALSE(csrResult.value().empty());
}

// @relation(SVR-ECC-010, SVR-PULLCRT-012, scope=function)
TEST_F(PushCertificateManagementTest, CreateSigningRequest_NonceTooShort_Fails)
{
  ByteString nonce(std::vector<byte>(16, byte{0xAB}));  // Too short (< 32)
  auto csrResult =
    call_create_signing_request(NodeId{}, rsa_cert_type_id(), String{}, true, std::move(nonce));
  EXPECT_TRUE(csrResult.is_bad());
}

TEST_F(PushCertificateManagementTest, CreateSigningRequest_InvalidCertType_Fails)
{
  ByteString nonce(std::vector<byte>(32, byte{0xAB}));
  auto csrResult =
    call_create_signing_request(NodeId{}, NodeId{0, uint32_t{99999}}, String{}, true, std::move(nonce));
  EXPECT_TRUE(csrResult.is_bad());
}

TEST_F(PushCertificateManagementTest, CreateSigningRequest_NullGroupDefaultsToApp)
{
  ByteString nonce(std::vector<byte>(32, byte{0xAB}));
  auto csrResult =
    call_create_signing_request(NodeId{}, rsa_cert_type_id(), String{}, true, std::move(nonce));
  ASSERT_TRUE(csrResult.is_good()) << csrResult.status_code().as_uint32();
  EXPECT_FALSE(csrResult.value().empty());
}

TEST_F(PushCertificateManagementTest, CreateSigningRequest_UseExistingKey)
{
  ByteString nonce(std::vector<byte>(32, byte{0xAB}));
  auto csrResult =
    call_create_signing_request(NodeId{}, rsa_cert_type_id(), String{}, false, std::move(nonce));
  ASSERT_TRUE(csrResult.is_good()) << csrResult.status_code().as_uint32();
  EXPECT_FALSE(csrResult.value().empty());
}

// @relation(SVR-ECC-010, SVR-PULLCRT-009, scope=function)
TEST_F(PushCertificateManagementTest, CreateSigningRequest_RepeatOverwritesPending)
{
  ByteString nonce1(std::vector<byte>(32, byte{0xAA}));
  auto csr1 = call_create_signing_request(NodeId{}, rsa_cert_type_id(), String{}, true, std::move(nonce1));
  ASSERT_TRUE(csr1.is_good()) << csr1.status_code().as_uint32();

  ByteString nonce2(std::vector<byte>(32, byte{0xBB}));
  auto csr2 = call_create_signing_request(NodeId{}, rsa_cert_type_id(), String{}, true, std::move(nonce2));
  ASSERT_TRUE(csr2.is_good()) << csr2.status_code().as_uint32();

  // Both should succeed; second overwrites first's pending key
  EXPECT_FALSE(csr2.value().empty());
}

// ===========================================================================
// 3.7 UpdateCertificate
// ===========================================================================

TEST_F(PushCertificateManagementTest, UpdateCertificate_WithExistingKey_Succeeds)
{
  // First, create a CSR to get a pending key pair
  ByteString nonce(std::vector<byte>(32, byte{0xAB}));
  auto csrResult =
    call_create_signing_request(NodeId{}, rsa_cert_type_id(), String{}, true, std::move(nonce));
  ASSERT_TRUE(csrResult.is_good()) << csrResult.status_code().as_uint32();

  // Sign the CSR with our CA
  Crypto::SubjectAlternateName san;
  san.uris.push_back("urn:test:compliance:server");
  san.hostnames.push_back("localhost");
  san.ipAddresses.push_back(boost::asio::ip::make_address("127.0.0.1"));  // the host clients dial
  auto signedCert = mPki->sign_csr(
    csrResult.value(), mCaKeys, mCaCert, CertificateSignatureAlgorithm::RsaPkcs15Sha2256, std::move(san));

  // UpdateCertificate with the signed cert (no private key - using pending key)
  std::vector<ByteString> issuers;
  issuers.push_back(mCaCert->der_encoding());
  auto updateResult =
    call_update_certificate(NodeId{}, rsa_cert_type_id(), signedCert->der_encoding(), std::move(issuers));
  ASSERT_TRUE(updateResult.is_good())
    << ua::format(updateResult.status_code())
    << (updateResult.shared_detail() ? "\n" + ua::to_string(*updateResult.shared_detail()) : std::string{});
  EXPECT_TRUE(updateResult.value());  // applyChangesRequired = true

  // Clean up - cancel so other tests aren't affected
  call_cancel_changes();
}

TEST_F(PushCertificateManagementTest, UpdateCertificate_WithPrivateKeyPEM_Succeeds)
{
  // Generate new key pair and certificate externally
  auto newKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto newCert = create_app_cert(newKeys, {"urn:test:compliance:server"}, {"localhost"}, "NewServer");

  std::vector<ByteString> issuers;
  issuers.push_back(mCaCert->der_encoding());
  auto updateResult = call_update_certificate(NodeId{},
    rsa_cert_type_id(),
    newCert->der_encoding(),
    std::move(issuers),
    String{"PEM"},
    newKeys->private_key_pem());
  ASSERT_TRUE(updateResult.is_good())
    << ua::format(updateResult.status_code())
    << (updateResult.shared_detail() ? "\n" + ua::to_string(*updateResult.shared_detail()) : std::string{});
  EXPECT_TRUE(updateResult.value());

  call_cancel_changes();
}

TEST_F(PushCertificateManagementTest, UpdateCertificate_InvalidCert_Fails)
{
  ByteString garbageDer(std::vector<byte>(100, byte{0xFF}));
  auto updateResult = call_update_certificate(NodeId{}, rsa_cert_type_id(), std::move(garbageDer));
  EXPECT_TRUE(updateResult.is_bad());
}

// @relation(SVR-ECC-010, SVR-PULLCRT-008, AC-SVR-PULLCRT-008-TYPE-IN-GROUP, scope=function)
TEST_F(PushCertificateManagementTest, UpdateCertificate_InvalidCertType_Fails)
{
  auto newKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto newCert = create_app_cert(newKeys);

  auto updateResult = call_update_certificate(NodeId{},
    NodeId{0, uint32_t{99999}},
    newCert->der_encoding(),
    {},
    String{"PEM"},
    newKeys->private_key_pem());
  EXPECT_TRUE(updateResult.is_bad());
}

// @relation(SVR-ECC-010, SVR-PULLCRT-005, scope=function)
TEST_F(PushCertificateManagementTest, UpdateCertificate_KeyMismatch_Fails)
{
  // Generate a cert signed with one key, but don't provide private key (and no pending CSR key)
  auto newKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto newCert = mPki->create_leaf_cert(newKeys,
    mCaKeys,
    mCaCert,
    DateTime::now(),
    DateTime{DateTime::now().value() + std::chrono::days{365}},
    {"urn:test:compliance:server"},
    {"localhost"});

  // No CSR was created, no private key provided -> key mismatch
  auto updateResult = call_update_certificate(NodeId{}, rsa_cert_type_id(), newCert->der_encoding());
  // The key check's status; the fixture's certificates name the server's ApplicationUri, so the
  // store validation that precedes it passes.
  EXPECT_EQ(updateResult.status_code().as_status(), Status::BadSecurityChecksFailed);
}

// @relation(SVR-ECC-010, SVR-PULLCRT-007, scope=function)
TEST_F(PushCertificateManagementTest, UpdateCertificate_NullGroupDefaultsToApp)
{
  auto newKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto newCert = create_app_cert(newKeys);

  auto updateResult = call_update_certificate(
    NodeId{}, rsa_cert_type_id(), newCert->der_encoding(), {}, String{"PEM"}, newKeys->private_key_pem());
  ASSERT_TRUE(updateResult.is_good())
    << ua::format(updateResult.status_code())
    << (updateResult.shared_detail() ? "\n" + ua::to_string(*updateResult.shared_detail()) : std::string{});

  call_cancel_changes();
}

// ===========================================================================
// 3.8 Full CSR workflow
// ===========================================================================

// @relation(SVR-ECC-010, SVR-PULLCRT-011, scope=function)
TEST_F(PushCertificateManagementTest, CsrWorkflow_FullLifecycle)
{
  // 1. CreateSigningRequest
  ByteString nonce(std::vector<byte>(32, byte{0xAB}));
  auto csrResult =
    call_create_signing_request(NodeId{}, rsa_cert_type_id(), String{}, true, std::move(nonce));
  ASSERT_TRUE(csrResult.is_good()) << csrResult.status_code().as_uint32();

  // 2. CA signs the CSR
  Crypto::SubjectAlternateName san;
  san.uris.push_back("urn:test:compliance:server");
  san.hostnames.push_back("localhost");
  san.ipAddresses.push_back(boost::asio::ip::make_address("127.0.0.1"));  // the host clients dial
  auto signedCert = mPki->sign_csr(
    csrResult.value(), mCaKeys, mCaCert, CertificateSignatureAlgorithm::RsaPkcs15Sha2256, std::move(san));

  // 3. UpdateCertificate with signed cert (no private key)
  std::vector<ByteString> issuers;
  issuers.push_back(mCaCert->der_encoding());
  auto updateResult =
    call_update_certificate(NodeId{}, rsa_cert_type_id(), signedCert->der_encoding(), std::move(issuers));
  ASSERT_TRUE(updateResult.is_good())
    << ua::format(updateResult.status_code())
    << (updateResult.shared_detail() ? "\n" + ua::to_string(*updateResult.shared_detail()) : std::string{});
  EXPECT_TRUE(updateResult.value());  // applyChangesRequired

  // 4. ApplyChanges - closes all channels
  try
  {
    call_apply_changes();
  }
  catch (...)
  {}
  mSession.reset();
  mChannel.reset();

  // 5. Verify the new cert is active in the store
  auto appCert = mServerCertStore->get_application_certificate_sync(CertificateType::RsaSha256Application);
  EXPECT_EQ(appCert.certificate->der_encoding(), signedCert->der_encoding())
    << "New certificate should be active in the store after ApplyChanges";
}

// @relation(SVR-ECC-010, SVR-PULLCRT-016, SVR-PULLCRT-017, scope=function)
TEST_F(PushCertificateManagementTest, CsrWorkflow_ApplyChangesClosesChannels)
{
  // Set up: CSR -> sign -> UpdateCertificate
  ByteString nonce(std::vector<byte>(32, byte{0xAB}));
  auto csrResult =
    call_create_signing_request(NodeId{}, rsa_cert_type_id(), String{}, true, std::move(nonce));
  ASSERT_TRUE(csrResult.is_good()) << csrResult.status_code().as_uint32();

  Crypto::SubjectAlternateName san;
  san.uris.push_back("urn:test:compliance:server");
  san.hostnames.push_back("localhost");
  san.ipAddresses.push_back(boost::asio::ip::make_address("127.0.0.1"));  // the host clients dial
  auto signedCert = mPki->sign_csr(
    csrResult.value(), mCaKeys, mCaCert, CertificateSignatureAlgorithm::RsaPkcs15Sha2256, std::move(san));

  std::vector<ByteString> issuers;
  issuers.push_back(mCaCert->der_encoding());
  auto updateResult =
    call_update_certificate(NodeId{}, rsa_cert_type_id(), signedCert->der_encoding(), std::move(issuers));
  ASSERT_TRUE(updateResult.is_good())
    << ua::format(updateResult.status_code())
    << (updateResult.shared_detail() ? "\n" + ua::to_string(*updateResult.shared_detail()) : std::string{});

  // ApplyChanges - after this, the channel should be disrupted
  try
  {
    auto applyResult = call_apply_changes();
  }
  catch (...)
  {
    // Transport error is expected
  }

  // Wait a bit for the server to close channels
  std::this_thread::sleep_for(std::chrono::milliseconds{200});

  // Attempt a subsequent operation - should fail
  bool channelDisrupted = false;
  try
  {
    read_property(VariableId::ServerConfiguration_MaxTrustListSize);
  }
  catch (...)
  {
    channelDisrupted = true;
  }
  EXPECT_TRUE(channelDisrupted) << "Channel should be disrupted after ApplyChanges";

  // Null out session/channel so TearDown doesn't try to close them
  mSession.reset();
  mChannel.reset();
}

// ===========================================================================
// 3.9 Full key-pair-push workflow
// ===========================================================================

TEST_F(PushCertificateManagementTest, KeyPushWorkflow_FullLifecycle)
{
  // Generate new cert+key externally
  auto newKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto newCert = create_app_cert(newKeys, {"urn:test:compliance:server"}, {"localhost"}, "NewServerCert");

  std::vector<ByteString> issuers;
  issuers.push_back(mCaCert->der_encoding());
  auto updateResult = call_update_certificate(NodeId{},
    rsa_cert_type_id(),
    newCert->der_encoding(),
    std::move(issuers),
    String{"PEM"},
    newKeys->private_key_pem());
  ASSERT_TRUE(updateResult.is_good())
    << ua::format(updateResult.status_code())
    << (updateResult.shared_detail() ? "\n" + ua::to_string(*updateResult.shared_detail()) : std::string{});

  // ApplyChanges will close channels
  try
  {
    call_apply_changes();
  }
  catch (...)
  {}
  mSession.reset();
  mChannel.reset();

  // Verify the new cert is active in the store
  auto appCert = mServerCertStore->get_application_certificate_sync(CertificateType::RsaSha256Application);
  EXPECT_EQ(appCert.certificate->der_encoding(), newCert->der_encoding())
    << "New certificate should be active in the store after ApplyChanges";
}

// ===========================================================================
// 3.10 Full trust list push workflow
// ===========================================================================

TEST_F(PushCertificateManagementTest, TrustListWorkflow_FullLifecycle)
{
  // Create a leaf cert to include in the new trust list
  auto leafKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leafCert = mPki->create_leaf_cert(leafKeys,
    mCaKeys,
    mCaCert,
    DateTime::now(),
    DateTime{DateTime::now().value() + std::chrono::days{365}},
    {"urn:test:trustlist:write"},
    {"localhost"},
    "TrustListWriteLeaf");

  // Build a TrustListDataType with the leaf cert in trusted certificates
  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;  // TrustedCertificates only
  trustList.trusted_certificates().push_back(leafCert->der_encoding());

  // Also include existing trusted certs (server cert + client cert + CA cert) so validation
  // continues to work for the existing channels.
  trustList.trusted_certificates().push_back(mServerCert->der_encoding());
  trustList.trusted_certificates().push_back(mCaCert->der_encoding());

  // Encode the TrustListDataType to UA Binary
  memory_stream_device::Dynamic encDevice(65535, /*reserve=*/true);
  MemoryStream<memory_stream_device::Dynamic> encStream(encDevice);
  UaBinaryEncoder encoder(CodecNamespaceContext{}, encStream);
  encoder.encode(EncodingLimits{}.stack_depth(), trustList);
  auto encoded = encDevice.get_data();

  // Open for write (mode 0x06 = Write|EraseExisting)
  auto handleResult = call_open(0x06);
  ASSERT_TRUE(handleResult.is_good()) << handleResult.status_code().as_uint32();
  auto handle = handleResult.value();

  // Write the encoded trust list
  auto writeResult = call_write_file(handle, std::move(encoded));
  ASSERT_TRUE(writeResult.is_good()) << writeResult.status_code().as_uint32();

  // CloseAndUpdate to commit the new trust list
  auto closeResult = call_close_and_update(handle);
  ASSERT_TRUE(closeResult.is_good()) << closeResult.status_code().as_uint32();
  EXPECT_TRUE(closeResult.value());  // applyChangesRequired = true

  // ApplyChanges - will close channels
  try
  {
    call_apply_changes();
  }
  catch (...)
  {
    // Expected - channel closed
  }

  mSession.reset();
  mChannel.reset();
}

TEST_F(PushCertificateManagementTest, TrustListWorkflow_AddCertThenApply)
{
  // Add a certificate
  auto leafKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leafCert = mPki->create_leaf_cert(leafKeys,
    mCaKeys,
    mCaCert,
    DateTime::now(),
    DateTime{DateTime::now().value() + std::chrono::days{365}},
    {"urn:test:trust:leaf"},
    {"localhost"},
    "TrustLeaf");

  auto addResult = call_add_certificate(leafCert->der_encoding(), true);
  ASSERT_TRUE(addResult.is_good()) << addResult.status_code().as_uint32();

  // ApplyChanges - trust list changes also close channels
  try
  {
    auto applyResult = call_apply_changes();
  }
  catch (...)
  {
    // Expected - channel closed
  }

  mSession.reset();
  mChannel.reset();
}

// ===========================================================================
// 3.11 ApplyChanges
// ===========================================================================

// @relation(SVR-ECC-010, SVR-PULLCRT-015, scope=function)
TEST_F(PushCertificateManagementTest, ApplyChanges_NoTransaction_Fails)
{
  auto result = call_apply_changes();
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadNothingToDo});
}

// @relation(SVR-ECC-010, SVR-PULLCRT-014, scope=function)
TEST_F(PushCertificateManagementTest, ApplyChanges_TrustListStillOpen_Fails)
{
  // Start a transaction. RATIFIED (owner report 2026-10-03, BR-13): with an UpdateCertificate - the
  // AddCertificate this used is not part of a transaction (OPC 10000-12 7.8.2.4), so it opened none.
  ASSERT_NO_FATAL_FAILURE(open_transaction_with_update_certificate());

  // Open trust list for write (leaves it open)
  auto handleResult = call_open(0x06);
  ASSERT_TRUE(handleResult.is_good()) << handleResult.status_code().as_uint32();

  // ApplyChanges while trust list is still open should fail
  auto applyResult = call_apply_changes();
  EXPECT_TRUE(applyResult.is_bad());
  EXPECT_EQ(applyResult.status_code(), StatusCode{Status::BadInvalidState});

  // Clean up
  call_close(handleResult.value());
  call_cancel_changes();
}

// @relation(SVR-ECC-010, SVR-PULLCRT-020, scope=function)
TEST_F(PushCertificateManagementTest, ApplyChanges_WrongSession_Fails)
{
  // Session A starts a transaction
  auto newKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto newCert = create_app_cert(newKeys);

  auto updateResult = call_update_certificate(
    NodeId{}, rsa_cert_type_id(), newCert->der_encoding(), {}, String{"PEM"}, newKeys->private_key_pem());
  ASSERT_TRUE(updateResult.is_good())
    << ua::format(updateResult.status_code())
    << (updateResult.shared_detail() ? "\n" + ua::to_string(*updateResult.shared_detail()) : std::string{});

  // Session B tries ApplyChanges
  auto [channel2, session2] = open_second_session();
  auto result = call_method_on_session(
    session2, serverConfigObjectId, NodeId{MethodId::ServerConfiguration_ApplyChanges});
  EXPECT_TRUE(result.status_code().is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadUserAccessDenied});

  session2.close_sync();
  channel2.close_sync();

  call_cancel_changes();
}

// ===========================================================================
// 3.12 CancelChanges
// ===========================================================================

// @relation(SVR-ECC-010, SVR-PULLCRT-023, scope=function)
TEST_F(PushCertificateManagementTest, CancelChanges_DiscardsTransaction)
{
  // Start a transaction
  auto newKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto newCert = create_app_cert(newKeys);

  auto updateResult = call_update_certificate(
    NodeId{}, rsa_cert_type_id(), newCert->der_encoding(), {}, String{"PEM"}, newKeys->private_key_pem());
  ASSERT_TRUE(updateResult.is_good())
    << ua::format(updateResult.status_code())
    << (updateResult.shared_detail() ? "\n" + ua::to_string(*updateResult.shared_detail()) : std::string{});

  // Cancel
  auto cancelResult = call_cancel_changes();
  EXPECT_TRUE(cancelResult.is_good()) << cancelResult.status_code().as_uint32();

  // Now ApplyChanges should fail with BadNothingToDo
  auto applyResult = call_apply_changes();
  EXPECT_TRUE(applyResult.is_bad());
  EXPECT_EQ(applyResult.status_code(), StatusCode{Status::BadNothingToDo});
}

// @relation(SVR-ECC-010, SVR-PULLCRT-024, scope=function)
TEST_F(PushCertificateManagementTest, CancelChanges_NoTransaction_Fails)
{
  auto result = call_cancel_changes();
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadNothingToDo});
}

// @relation(SVR-PULLCRT-023, scope=function)
TEST_F(PushCertificateManagementTest, CancelChanges_WrongSession_Fails)
{
  // Session A starts a transaction
  auto newKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto newCert = create_app_cert(newKeys);

  auto updateResult = call_update_certificate(
    NodeId{}, rsa_cert_type_id(), newCert->der_encoding(), {}, String{"PEM"}, newKeys->private_key_pem());
  ASSERT_TRUE(updateResult.is_good())
    << ua::format(updateResult.status_code())
    << (updateResult.shared_detail() ? "\n" + ua::to_string(*updateResult.shared_detail()) : std::string{});

  // Session B tries CancelChanges
  auto [channel2, session2] = open_second_session();
  auto result = call_method_on_session(
    session2, serverConfigObjectId, NodeId{MethodId::ServerConfiguration_CancelChanges});
  EXPECT_TRUE(result.status_code().is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadUserAccessDenied});

  session2.close_sync();
  channel2.close_sync();

  call_cancel_changes();
}

// ===========================================================================
// 3.13 Transaction model
// ===========================================================================

// Part 12 section 7.10.1 permits one active certificate-push transaction. Once Session A owns it,
// UpdateCertificate from Session B is rejected as a transaction conflict rather than as malformed
// service state. The deferred-prerequisite unit arm proves the earlier reservation point; this
// public control proves the same BadTransactionPending status after Session A has staged an update.
TEST_F(PushCertificateManagementTest, Transaction_SessionBLockedOut)
{
  // Session A starts a transaction via UpdateCertificate
  auto newKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto newCert = create_app_cert(newKeys);

  auto updateResult = call_update_certificate(
    NodeId{}, rsa_cert_type_id(), newCert->der_encoding(), {}, String{"PEM"}, newKeys->private_key_pem());
  ASSERT_TRUE(updateResult.is_good())
    << ua::format(updateResult.status_code())
    << (updateResult.shared_detail() ? "\n" + ua::to_string(*updateResult.shared_detail()) : std::string{});

  // Session B tries to UpdateCertificate - should fail
  auto [channel2, session2] = open_second_session();
  Array<Variant> args;
  args.resize(6);
  args[0] = Variant{NodeId{}};
  args[1] = Variant{PushCertificateManagementTest::rsa_cert_type_id()};
  args[2] = Variant{newCert->der_encoding()};
  args[3] = Variant{Array<ByteString>{}};
  args[4] = Variant{String{"PEM"}};
  args[5] = Variant{newKeys->private_key_pem()};

  auto result = call_method_on_session(
    session2, serverConfigObjectId, NodeId{MethodId::ServerConfiguration_UpdateCertificate}, std::move(args));
  EXPECT_TRUE(result.status_code().is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadTransactionPending});

  session2.close_sync();
  channel2.close_sync();

  call_cancel_changes();
}

TEST_F(PushCertificateManagementTest, Transaction_SessionCloseAutoCancel)
{
  // Open a second session and start a transaction on it
  auto [channel2, session2] = open_second_session();

  auto newKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto newCert = create_app_cert(newKeys);

  Array<Variant> args;
  args.resize(6);
  args[0] = Variant{NodeId{}};
  args[1] = Variant{rsa_cert_type_id()};
  args[2] = Variant{newCert->der_encoding()};
  args[3] = Variant{Array<ByteString>{}};
  args[4] = Variant{String{"PEM"}};
  args[5] = Variant{newKeys->private_key_pem()};

  auto updateResult = call_method_on_session(
    session2, serverConfigObjectId, NodeId{MethodId::ServerConfiguration_UpdateCertificate}, std::move(args));
  ASSERT_TRUE(updateResult.status_code().is_good()) << updateResult.status_code().as_uint32();

  // Close session 2 - should auto-cancel the transaction
  session2.close_sync();
  channel2.close_sync();

  // Wait a bit for the session close event to propagate
  std::this_thread::sleep_for(std::chrono::milliseconds{200});

  // Now from session 1, ApplyChanges should fail with BadNothingToDo
  auto applyResult = call_apply_changes();
  EXPECT_TRUE(applyResult.is_bad());
  EXPECT_EQ(applyResult.status_code(), StatusCode{Status::BadNothingToDo});
}

TEST_F(PushCertificateManagementTest, Transaction_ApplyChangesRequiredAlwaysTrue)
{
  auto newKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto newCert = create_app_cert(newKeys);

  auto updateResult = call_update_certificate(
    NodeId{}, rsa_cert_type_id(), newCert->der_encoding(), {}, String{"PEM"}, newKeys->private_key_pem());
  ASSERT_TRUE(updateResult.is_good())
    << ua::format(updateResult.status_code())
    << (updateResult.shared_detail() ? "\n" + ua::to_string(*updateResult.shared_detail()) : std::string{});
  EXPECT_TRUE(updateResult.value()) << "applyChangesRequired should be true for UpdateCertificate";

  call_cancel_changes();

  // Also verify CloseAndUpdate returns applyChangesRequired=true
  auto leafKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leafCert = mPki->create_leaf_cert(leafKeys,
    mCaKeys,
    mCaCert,
    DateTime::now(),
    DateTime{DateTime::now().value() + std::chrono::days{365}},
    {"urn:test:applyreq:leaf"},
    {"localhost"},
    "ApplyReqLeaf");

  // RATIFIED TEST ADAPTATION (group J, B3-4): the new list reaches CloseAndUpdate through the write
  // handle. AddCertificate while the TrustList is open for write is refused (Part 12 7.8.2.4:
  // Bad_InvalidState), so it no longer supplies the change; that refusal is asserted instead.
  TrustListDataType newTrustList;
  newTrustList.specified_lists() = 0x01;  // TrustedCertificates only
  // Held in a local: a range-for over a member of the temporary would read it after it is destroyed.
  const auto currentTrustList = read_trust_list(0x01);
  for (const auto& cert : currentTrustList.trusted_certificates())
    newTrustList.trusted_certificates().push_back(cert);
  newTrustList.trusted_certificates().push_back(leafCert->der_encoding());
  memory_stream_device::Dynamic encDevice(65535, /*reserve=*/true);
  MemoryStream<memory_stream_device::Dynamic> encStream(encDevice);
  UaBinaryEncoder encoder(CodecNamespaceContext{}, encStream);
  encoder.encode(EncodingLimits{}.stack_depth(), newTrustList);

  auto handleResult = call_open(0x06);
  ASSERT_TRUE(handleResult.is_good()) << handleResult.status_code().as_uint32();

  auto addResult = call_add_certificate(leafCert->der_encoding(), true);
  EXPECT_EQ(addResult.status_code().as_status(), Status::BadInvalidState)
    << "AddCertificate is refused while the TrustList is open for write";

  auto writeResult = call_write_file(handleResult.value(), encDevice.get_data());
  ASSERT_TRUE(writeResult.is_good()) << writeResult.status_code().as_uint32();

  auto closeAndUpdateResult = call_close_and_update(handleResult.value());
  ASSERT_TRUE(closeAndUpdateResult.is_good()) << closeAndUpdateResult.status_code().as_uint32();
  EXPECT_TRUE(closeAndUpdateResult.value()) << "applyChangesRequired should be true for CloseAndUpdate";

  call_cancel_changes();
}

// ===========================================================================
// 3.14 GetRejectedList
// ===========================================================================

TEST_F(PushCertificateManagementTest, GetRejectedList_ReturnsEmptyInitially)
{
  auto result = call_get_rejected_list();
  ASSERT_TRUE(result.is_good()) << result.status_code().as_uint32();
  EXPECT_TRUE(result.value().empty());
}

// ===========================================================================
// 3.15 Dynamic properties
// ===========================================================================

TEST_F(PushCertificateManagementTest, DynamicProperty_LastUpdateTimeUpdatedAfterAddCert)
{
  auto before = read_property(
    VariableId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_LastUpdateTime);
  ASSERT_TRUE(!before.status().has_value() || before.status()->is_good());

  // Add a certificate
  auto leafKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leafCert = mPki->create_leaf_cert(leafKeys,
    mCaKeys,
    mCaCert,
    DateTime::now(),
    DateTime{DateTime::now().value() + std::chrono::days{365}},
    {"urn:test:lastupdate:leaf"},
    {"localhost"},
    "LastUpdateLeaf");

  auto addResult = call_add_certificate(leafCert->der_encoding(), true);
  ASSERT_TRUE(addResult.is_good()) << addResult.status_code().as_uint32();

  auto after = read_property(
    VariableId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_LastUpdateTime);
  ASSERT_TRUE(!after.status().has_value() || after.status()->is_good());

  // After should be >= before (timestamp advanced or same if too fast)
  auto beforeTime = before.value().as<DateTime>();
  auto afterTime = after.value().as<DateTime>();
  EXPECT_GE(afterTime.value(), beforeTime.value());
}

TEST_F(PushCertificateManagementTest, DynamicProperty_OpenCountReflectsOpenState)
{
  auto countBefore = read_property(
    VariableId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_OpenCount);
  ASSERT_TRUE(!countBefore.status().has_value() || countBefore.status()->is_good());
  EXPECT_EQ(countBefore.value().as<uint16_t>(), 0u);

  auto handleResult = call_open(0x01);
  ASSERT_TRUE(handleResult.is_good());

  auto countDuring = read_property(
    VariableId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_OpenCount);
  ASSERT_TRUE(!countDuring.status().has_value() || countDuring.status()->is_good());
  EXPECT_EQ(countDuring.value().as<uint16_t>(), 1u);

  call_close(handleResult.value());

  auto countAfter = read_property(
    VariableId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_OpenCount);
  ASSERT_TRUE(!countAfter.status().has_value() || countAfter.status()->is_good());
  EXPECT_EQ(countAfter.value().as<uint16_t>(), 0u);
}

// ===========================================================================
// 3.16 Audit events
// ===========================================================================

TEST_F(PushCertificateManagementTest, AuditEvent_TrustListUpdateRequested_OnAddCert)
{
  // Set up event subscription before the operation so we capture the audit event.
  setup_event_subscription();

  // Perform AddCertificate - adds a CA-issued end-entity certificate as trusted. (A CA certificate is
  // refused by AddCertificate, Part 12 7.8.2.4: it cannot carry the CA's CRLs.)
  auto leafKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leafCert =
    create_app_cert(leafKeys, {"urn:test:audit:leaf"}, {"localhost"}, "AuditUpdateRequestedLeaf");
  auto addResult = call_add_certificate(leafCert->der_encoding(), true);
  ASSERT_TRUE(addResult.is_good()) << addResult.status_code().as_uint32();

  // Collect events and look for TrustListUpdateRequestedAuditEventType.
  auto eventTypes = collect_event_types();

  const NodeId expectedType{ObjectTypeId::TrustListUpdateRequestedAuditEventType};
  bool found = false;
  for (const auto& eventType : eventTypes)
  {
    if (eventType == expectedType)
    {
      found = true;
      break;
    }
  }
  EXPECT_TRUE(found) << "Expected TrustListUpdateRequestedAuditEventType event after AddCertificate. "
                     << "Received " << eventTypes.size() << " event(s).";
}

TEST_F(PushCertificateManagementTest, AuditEvent_TrustListUpdated_OnAddCert)
{
  // Set up event subscription before the operation so we capture the audit event.
  setup_event_subscription();

  // Perform AddCertificate - adds a CA-issued end-entity certificate as trusted. (A CA certificate is
  // refused by AddCertificate, Part 12 7.8.2.4: it cannot carry the CA's CRLs.)
  auto leafKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leafCert = create_app_cert(leafKeys, {"urn:test:audit:leaf"}, {"localhost"}, "AuditUpdatedLeaf");
  auto addResult = call_add_certificate(leafCert->der_encoding(), true);
  ASSERT_TRUE(addResult.is_good()) << addResult.status_code().as_uint32();

  // Collect events and look for TrustListUpdatedAuditEventType.
  auto eventTypes = collect_event_types();

  const NodeId expectedType{ObjectTypeId::TrustListUpdatedAuditEventType};
  bool found = false;
  for (const auto& eventType : eventTypes)
  {
    if (eventType == expectedType)
    {
      found = true;
      break;
    }
  }
  EXPECT_TRUE(found) << "Expected TrustListUpdatedAuditEventType event after AddCertificate. " << "Received "
                     << eventTypes.size() << " event(s).";
}

TEST_F(PushCertificateManagementTest, AuditEvent_CertUpdateRequested_OnUpdateCert)
{
  // Set up event subscription before the operation.
  setup_event_subscription();

  // Create a new app cert + PEM private key for UpdateCertificate.
  auto newKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto newCert = create_app_cert(newKeys);
  auto pemKey = newKeys->private_key_pem();

  auto updateResult =
    call_update_certificate(NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup},
      rsa_cert_type_id(),
      newCert->der_encoding(),
      {mCaCert->der_encoding()},
      String{"PEM"},
      ByteString{pemKey});
  ASSERT_TRUE(updateResult.is_good())
    << ua::format(updateResult.status_code())
    << (updateResult.shared_detail() ? "\n" + ua::to_string(*updateResult.shared_detail()) : std::string{});

  // Collect events and look for CertificateUpdateRequestedAuditEventType.
  auto eventTypes = collect_event_types();

  const NodeId expectedType{ObjectTypeId::CertificateUpdateRequestedAuditEventType};
  bool found = false;
  for (const auto& eventType : eventTypes)
  {
    if (eventType == expectedType)
    {
      found = true;
      break;
    }
  }
  EXPECT_TRUE(found) << "Expected CertificateUpdateRequestedAuditEventType event after UpdateCertificate. "
                     << "Received " << eventTypes.size() << " event(s).";
}

TEST_F(PushCertificateManagementTest, AuditEvent_CertUpdated_OnApplyChanges)
{
  // REQ-AUD-2: ApplyChanges emits CertificateUpdatedAuditEventType.
  //
  // Strategy: subscribe to events, call UpdateCertificate + ApplyChanges (which closes all
  // channels), then reconnect on a new channel and reactivate the session. Per Part 4 section 5.6.2,
  // the session MUST survive channel closure for its timeout duration. The subscription and its
  // queued event notifications survive with the session - Publish on the new channel delivers them.

  // Trust the CA cert on the client side so we can reconnect after the server cert changes.
  mClientCertStore->add_to_trusted_certificates_sync(mCaCert);

  // Set up event subscription before the operation.
  setup_event_subscription();

  // UpdateCertificate (ApplyChanges requires a pending update).
  auto newKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto newCert = create_app_cert(newKeys);

  auto updateResult = call_update_certificate(NodeId{},
    rsa_cert_type_id(),
    newCert->der_encoding(),
    {mCaCert->der_encoding()},
    String{"PEM"},
    newKeys->private_key_pem());
  ASSERT_TRUE(updateResult.is_good())
    << ua::format(updateResult.status_code())
    << (updateResult.shared_detail() ? "\n" + ua::to_string(*updateResult.shared_detail()) : std::string{});

  // ApplyChanges emits CertificateUpdatedAuditEventType, then closes all channels.
  try
  {
    call_apply_changes();
  }
  catch (...)
  {}

  // Reconnect on a new channel and reactivate the session (Part 4, section 5.6.2).
  // The session must survive the channel closure for its timeout duration.
  CoreClient::OpenChannelConfig reconnCfg;
  reconnCfg.endpointUrl = mEndpointUrl;
  reconnCfg.securityMode = MessageSecurityMode::SignAndEncrypt;
  reconnCfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  reconnCfg.serverCertificate = newCert;
  auto newChannel = mClient->core().open_channel_sync(std::move(reconnCfg));
  mSession->activate_sync(std::move(newChannel));

  // Publish to collect the queued audit event notification.
  auto eventTypes = collect_event_types(10);

  const NodeId expectedType{ObjectTypeId::CertificateUpdatedAuditEventType};
  bool found = false;
  for (const auto& eventType : eventTypes)
  {
    if (eventType == expectedType)
    {
      found = true;
      break;
    }
  }
  EXPECT_TRUE(found) << "Expected CertificateUpdatedAuditEventType event after ApplyChanges";

  mSession->close_sync();
  mSession.reset();
  mChannel.reset();
}

// ===========================================================================
// 3.17 ECC certificate types
// ===========================================================================

/// Fixture that seeds both RSA and ECC P-256 application certificates in the server's cert store.
/// The ECC cert must be added before the server starts so that wire_push_management can derive
/// the supported certificate type IDs from the cert store.
class PushCertEccTest : public PushCertificateManagementTest
{
protected:
  /// Called by ComplianceSecured::SetUp after cert store creation but before Server::create/start.
  void configure_secured_server(ApplicationConfig& appCfg) override
  {
    PushCertificateManagementTest::configure_secured_server(appCfg);
    // Create and seed the ECC P-256 app cert into the server's cert store.
    // mCrypto and mServerCertStore are already populated at this point.
    Crypto::Name eccSubject;
    eccSubject.commonName = "ECC P-256 Server";
    Crypto::SubjectAlternateName eccAltName;
    eccAltName.uris.push_back("urn:test:compliance:server");
    eccAltName.hostnames.push_back("localhost");

    auto eccCertResult = mCrypto->try_create_self_signed_application_instance_certificate_sync(eccSubject,
      UtcTime{2050, 1, 1, 0, 0, 0},
      eccAltName,
      CertificateType::EccNistP256Application,
      std::nullopt);
    ASSERT_TRUE(eccCertResult.is_good());
    auto [keys, cert] = std::move(eccCertResult).value();
    mEccKeys = std::move(keys);
    mEccCert = std::move(cert);

    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::EccNistP256Application;
    appCert.certificate = mEccCert;
    appCert.keys = mEccKeys;
    mServerCertStore->add_to_application_certificates_sync(appCert);
  }

  static NodeId ecc_p256_cert_type_id()
  {
    return NodeId{ObjectTypeId::EccNistP256ApplicationCertificateType};
  }

  /// Create an ECC P-256 leaf app cert signed by the CA.
  std::shared_ptr<const X509Certificate> create_ecc_app_cert(
    std::shared_ptr<const AsymmetricKeyPair> subjectKeys,
    std::vector<std::string> uris = {"urn:test:compliance:server"},
    std::vector<std::string> hostnames = {"localhost"}, const std::string& name = "EccTestAppCert")
  {
    Crypto::CreateCertificateConfig p;
    p.subjectKeys = subjectKeys;
    p.issuerKeys = mCaKeys;
    p.subject.commonName = name;
    p.serialNumber = std::to_string(DateTime::now().value().time_since_epoch().count());
    p.keyUsage.digitalSignature = true;
    p.keyUsage.nonRepudiation = true;
    p.keyUsage.keyAgreement = true;
    p.keyUsage.serverAuth = true;
    p.keyUsage.clientAuth = true;
    p.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::EcDsaSha2256;
    p.from = DateTime::now();
    p.to = DateTime{p.from.value() + std::chrono::days{365}};
    p.issuer = mCaCert;
    p.subjectAlternateName.uris = std::move(uris);
    p.subjectAlternateName.hostnames = std::move(hostnames);
    // The host clients dial, as the certificate this one replaces names it.
    p.subjectAlternateName.ipAddresses.push_back(boost::asio::ip::make_address("127.0.0.1"));
    return mPki->create_cert(p);
  }

  std::shared_ptr<const AsymmetricKeyPair> mEccKeys;
  std::shared_ptr<const X509Certificate> mEccCert;
};

TEST_F(PushCertEccTest, CreateSigningRequest_EccP256_ReturnsDerCsr)
{
  ByteString nonce(std::vector<byte>(32, byte{0xAB}));
  auto csrResult =
    call_create_signing_request(NodeId{}, ecc_p256_cert_type_id(), String{}, true, std::move(nonce));
  ASSERT_TRUE(csrResult.is_good()) << csrResult.status_code().as_uint32();
  EXPECT_FALSE(csrResult.value().empty());
}

TEST_F(PushCertEccTest, CsrWorkflow_EccNistP256_FullLifecycle)
{
  // 1. CreateSigningRequest with ECC P-256
  ByteString nonce(std::vector<byte>(32, byte{0xAB}));
  auto csrResult =
    call_create_signing_request(NodeId{}, ecc_p256_cert_type_id(), String{}, true, std::move(nonce));
  ASSERT_TRUE(csrResult.is_good()) << csrResult.status_code().as_uint32();

  // 2. CA signs the CSR (using ECC signature algorithm)
  Crypto::SubjectAlternateName san;
  san.uris.push_back("urn:test:compliance:server");
  san.hostnames.push_back("localhost");
  san.ipAddresses.push_back(boost::asio::ip::make_address("127.0.0.1"));  // the host clients dial
  auto signedCert = mPki->sign_csr(
    csrResult.value(), mCaKeys, mCaCert, CertificateSignatureAlgorithm::RsaPkcs15Sha2256, std::move(san));

  // 3. UpdateCertificate with the signed cert (no private key - using pending key)
  std::vector<ByteString> issuers;
  issuers.push_back(mCaCert->der_encoding());
  auto updateResult = call_update_certificate(
    NodeId{}, ecc_p256_cert_type_id(), signedCert->der_encoding(), std::move(issuers));
  ASSERT_TRUE(updateResult.is_good())
    << ua::format(updateResult.status_code())
    << (updateResult.shared_detail() ? "\n" + ua::to_string(*updateResult.shared_detail()) : std::string{});
  EXPECT_TRUE(updateResult.value());

  // 4. ApplyChanges
  try
  {
    call_apply_changes();
  }
  catch (...)
  {}

  mSession.reset();
  mChannel.reset();
}

TEST_F(PushCertEccTest, KeyPushWorkflow_EccNistP256_FullLifecycle)
{
  // Generate new ECC P-256 cert+key externally
  auto newKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::EccNistP256, std::nullopt);
  auto newCert = create_ecc_app_cert(newKeys);

  std::vector<ByteString> issuers;
  issuers.push_back(mCaCert->der_encoding());
  auto updateResult = call_update_certificate(NodeId{},
    ecc_p256_cert_type_id(),
    newCert->der_encoding(),
    std::move(issuers),
    String{"PEM"},
    newKeys->private_key_pem());
  ASSERT_TRUE(updateResult.is_good())
    << ua::format(updateResult.status_code())
    << (updateResult.shared_detail() ? "\n" + ua::to_string(*updateResult.shared_detail()) : std::string{});

  try
  {
    call_apply_changes();
  }
  catch (...)
  {}

  mSession.reset();
  mChannel.reset();
}

// SVR-PULLCRT-026 (Part 12 section 7.8.4.7): EccNistP256ApplicationCertificateType requires
// an ECC nistP256 key. Pushing an RSA-keyed cert under the ECC type (which IS in this
// fixture's group CertificateTypes) fails the key-shape algorithm-family check with
// Bad_InvalidArgument - isolating key-shape (026) from type-in-group (008).
TEST_F(PushCertEccTest, Mirror_UpdateCertificateRsaKeyUnderEccTypeFailsInvalidArgument)
{
  auto rsaKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto rsaCert = create_app_cert(rsaKeys, {"urn:test:compliance:server"}, {"localhost"}, "RsaUnderEcc");

  auto updateResult = call_update_certificate(NodeId{},
    ecc_p256_cert_type_id(),
    rsaCert->der_encoding(),
    {},
    String{"PEM"},
    rsaKeys->private_key_pem());
  ASSERT_TRUE(updateResult.is_bad());
  EXPECT_EQ(updateResult.status_code(), StatusCode{Status::BadInvalidArgument})
    << "RSA key under EccNistP256ApplicationCertificateType must yield Bad_InvalidArgument: "
    << updateResult.status_code().as_uint32();
}

// ===========================================================================
// SVR-PULLCRT CTT-mirror integration tests
//
// These mirror the CTT v1.05.06 Push-Model / Security-Certificate-Administration
// cases against the section 3.x catalog rows.
//
// Policy note: the ComplianceSecured fixture maps its Anonymous identity to
// SecurityAdmin, so there is no Role differentiation in this functional suite.
// The SecurityAdmin-Role gate for these
// Methods is enforced by NodeSet AccessRestrictions/RolePermissions via the
// generic Call service (covered at the unit level). What the in-handler gate
// enforces - and what these integration mirrors exercise - is the CHANNEL floor
// (encrypted vs authenticated SecureChannel), matching the catalog's
// "channel floor ... not a Role gate" disposition.
// ===========================================================================

namespace
{
/// True if a browse result lists a forward child with the given BrowseName.
bool browse_lists_child(const BrowseResult& result, std::string_view browseName)
{
  for (const auto& ref : result.references())
  {
    if (string_view{ref.browse_name().name()} == browseName)
      return true;
  }
  return false;
}
}  // namespace

// --- SVR-PULLCRT-001: ServerConfiguration node + mandatory children present ---

// @relation(SVR-ECC-010, SVR-PULLCRT-001, scope=function)
TEST_F(PushCertificateManagementTest, Mirror_ServerConfigurationNodePresentWithMandatoryChildren)
{
  auto resp = mSession->view().browse_sync(browse(serverConfigObjectId));
  ASSERT_EQ(resp.results().size(), 1u);
  ASSERT_FALSE(resp.results()[0].status_code().is_bad())
    << "Browse of ServerConfiguration (i=12637) failed: " << resp.results()[0].status_code().as_uint32();
  const auto& result = resp.results()[0];

  // Four mandatory Methods (Part 12 section 7.10.2 / Figure 21).
  for (std::string_view method :
    {"UpdateCertificate", "ApplyChanges", "CreateSigningRequest", "GetRejectedList"})
  {
    EXPECT_TRUE(browse_lists_child(result, method)) << "Missing mandatory Method child: " << method;
  }

  // Mandatory Properties + the CertificateGroups Object.
  for (std::string_view child : {"ServerCapabilities",
         "SupportedPrivateKeyFormats",
         "MaxTrustListSize",
         "MulticastDnsEnabled",
         "CertificateGroups"})
  {
    EXPECT_TRUE(browse_lists_child(result, child)) << "Missing mandatory child: " << child;
  }
}

// --- SVR-PULLCRT-003: DefaultApplicationGroup present at i=14156 with CertificateTypes ---

// @relation(SVR-ECC-010, SVR-PULLCRT-003, scope=function)
TEST_F(PushCertificateManagementTest, Mirror_DefaultApplicationGroupPresentWithCertificateTypes)
{
  // Browse CertificateGroups -> find DefaultApplicationGroup and confirm its reserved NodeId.
  auto groupsResp =
    mSession->view().browse_sync(browse(NodeId{ObjectId::ServerConfiguration_CertificateGroups}));
  ASSERT_EQ(groupsResp.results().size(), 1u);
  ASSERT_FALSE(groupsResp.results()[0].status_code().is_bad());

  NodeId defaultGroupId;
  for (const auto& ref : groupsResp.results()[0].references())
  {
    if (string_view{ref.browse_name().name()} == "DefaultApplicationGroup")
      defaultGroupId = ref.node_id().node_id();
  }
  ASSERT_FALSE(defaultGroupId.is_null()) << "DefaultApplicationGroup not found under CertificateGroups";
  EXPECT_EQ(defaultGroupId, NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup})
    << "DefaultApplicationGroup must be at reserved NodeId i=14156";

  // Browse the group: it must expose CertificateTypes + TrustList.
  auto groupResp = mSession->view().browse_sync(browse(defaultGroupId));
  ASSERT_EQ(groupResp.results().size(), 1u);
  EXPECT_TRUE(browse_lists_child(groupResp.results()[0], "CertificateTypes"));
  EXPECT_TRUE(browse_lists_child(groupResp.results()[0], "TrustList"));

  // CertificateTypes must be populated (server derives them from the cert store).
  auto dv =
    read_property(VariableId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateTypes);
  ASSERT_TRUE(dv.value().is_array());
  EXPECT_FALSE(dv.value().as<Array<NodeId>>().empty()) << "DefaultApplicationGroup.CertificateTypes is empty";
}

// --- SVR-PULLCRT-002: ServerConfiguration + immediate children browse-visible ---

// @relation(SVR-ECC-010, SVR-PULLCRT-002, scope=function)
TEST_F(PushCertificateManagementTest, Mirror_ServerConfigurationImmediateChildrenBrowsable)
{
  // The section 7.10.2 SHALL: ServerConfig and its immediate children are visible to a
  // user who can access the Server Object. (The inner CertificateGroups-children SHOULD
  // restriction to SecurityAdmin is unenforceable under AllowAllAuthorizer and is tracked
  // at the unit level - see SVR-PULLCRT-002 row note.)
  auto resp = mSession->view().browse_sync(browse(serverConfigObjectId));
  ASSERT_EQ(resp.results().size(), 1u);
  ASSERT_FALSE(resp.results()[0].status_code().is_bad());
  EXPECT_FALSE(resp.results()[0].references().empty()) << "ServerConfiguration children must be browsable";
  EXPECT_TRUE(browse_lists_child(resp.results()[0], "CertificateGroups"));

  // CertificateGroups itself is an immediate child and remains browsable.
  auto groupsResp =
    mSession->view().browse_sync(browse(NodeId{ObjectId::ServerConfiguration_CertificateGroups}));
  ASSERT_EQ(groupsResp.results().size(), 1u);
  EXPECT_FALSE(groupsResp.results()[0].status_code().is_bad());
}

// --- SVR-PULLCRT-004: UpdateCertificate runs full integrity checks -> Bad_SecurityChecksFailed ---

// @relation(SVR-ECC-010, SVR-PULLCRT-004, scope=function)
TEST_F(PushCertificateManagementTest, Mirror_UpdateCertificateUntrustedIssuerFailsSecurityChecks)
{
  // A well-formed cert signed by a CA the server does NOT trust must fail the Table 106
  // Trust-List / Build-Chain check with Bad_SecurityChecksFailed (not a decode error).
  auto untrustedCaKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto untrustedCa = mPki->create_root_ca(untrustedCaKeys, "Untrusted CA", "777");

  auto leafKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto untrustedLeaf = mPki->create_leaf_cert(leafKeys,
    untrustedCaKeys,
    untrustedCa,
    DateTime::now(),
    DateTime{DateTime::now().value() + std::chrono::days{365}},
    {"urn:test:compliance:server"},
    {"localhost"},
    "UntrustedServer");

  auto updateResult = call_update_certificate(NodeId{},
    rsa_cert_type_id(),
    untrustedLeaf->der_encoding(),
    {untrustedCa->der_encoding()},
    String{"PEM"},
    leafKeys->private_key_pem());
  ASSERT_TRUE(updateResult.is_bad());
  EXPECT_EQ(updateResult.status_code(), StatusCode{Status::BadSecurityChecksFailed})
    << "Untrusted issuer must fail integrity checks: " << updateResult.status_code().as_uint32();
}

// --- SVR-PULLCRT-005: UpdateCertificate public-key mismatch with no privateKey -> rejected ---

// @relation(SVR-ECC-010, SVR-PULLCRT-005, scope=function)
TEST_F(PushCertificateManagementTest, Mirror_UpdateCertificatePublicKeyMismatchFails)
{
  // Stage a pending key via CreateSigningRequest (key K1), then push a cert whose public
  // key (K2) matches neither K1 nor any provided privateKey (none supplied) -> rejected.
  ByteString nonce(std::vector<byte>(32, byte{0xAB}));
  auto csrResult =
    call_create_signing_request(NodeId{}, rsa_cert_type_id(), String{}, true, std::move(nonce));
  ASSERT_TRUE(csrResult.is_good()) << csrResult.status_code().as_uint32();

  // A different, CA-signed cert (key K2) - unrelated to the staged CSR key.
  auto mismatchedKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto mismatchedCert = create_app_cert(mismatchedKeys);

  auto updateResult =
    call_update_certificate(NodeId{}, rsa_cert_type_id(), mismatchedCert->der_encoding(), {});
  EXPECT_EQ(updateResult.status_code().as_status(), Status::BadSecurityChecksFailed)
    << "Cert whose key matches neither the pending CSR nor a provided privateKey must be rejected";

  call_cancel_changes();
}

// --- SVR-PULLCRT-007: UpdateCertificate null groupId routes to DefaultApplicationGroup ---

// @relation(SVR-ECC-010, SVR-PULLCRT-007, scope=function)
TEST_F(PushCertificateManagementTest, Mirror_UpdateCertificateNullGroupRoutesToDefaultGroup)
{
  auto newKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto newCert = create_app_cert(newKeys, {"urn:test:compliance:server"}, {"localhost"}, "NullGroupServer");

  auto updateResult = call_update_certificate(
    NodeId{}, rsa_cert_type_id(), newCert->der_encoding(), {}, String{"PEM"}, newKeys->private_key_pem());
  ASSERT_TRUE(updateResult.is_good())
    << ua::format(updateResult.status_code())
    << (updateResult.shared_detail() ? "\n" + ua::to_string(*updateResult.shared_detail()) : std::string{});

  // The transaction must record the DefaultApplicationGroup as affected - proving the
  // null groupId resolved to it (Part 12 section 7.10.4).
  auto cancelResult = call_cancel_changes();
  ASSERT_TRUE(cancelResult.is_good()) << cancelResult.status_code().as_uint32();

  auto groupsDv =
    read_property(VariableId::ServerConfiguration_TransactionDiagnostics_AffectedCertificateGroups);
  ASSERT_TRUE(groupsDv.value().is_array());
  bool hasDefaultGroup = false;
  for (const auto& id : groupsDv.value().as<Array<NodeId>>())
  {
    if (id == NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup})
      hasDefaultGroup = true;
  }
  EXPECT_TRUE(hasDefaultGroup) << "null groupId must resolve to DefaultApplicationGroup";
}

// --- SVR-PULLCRT-008: certificateTypeId not in group CertificateTypes -> Bad_InvalidArgument ---

// @relation(SVR-ECC-010, SVR-PULLCRT-008, scope=function)
TEST_F(PushCertificateManagementTest, Mirror_UpdateCertificateTypeNotInGroupFailsInvalidArgument)
{
  auto newKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto newCert = create_app_cert(newKeys);

  auto updateResult = call_update_certificate(NodeId{},
    NodeId{0, uint32_t{99999}},  // not a member of the group's CertificateTypes
    newCert->der_encoding(),
    {},
    String{"PEM"},
    newKeys->private_key_pem());
  ASSERT_TRUE(updateResult.is_bad());
  EXPECT_EQ(updateResult.status_code(), StatusCode{Status::BadInvalidArgument})
    << "typeId outside the group's CertificateTypes must yield Bad_InvalidArgument: "
    << updateResult.status_code().as_uint32();
}

// --- SVR-PULLCRT-026: certificate-type key-shape enforced at UpdateCertificate ---

// @relation(SVR-ECC-010, SVR-PULLCRT-026, scope=function)
TEST_F(PushCertificateManagementTest, Mirror_UpdateCertificateWrongKeySizeForTypeFailsInvalidArgument)
{
  // Part 12 section 7.8.4.5: RsaSha256ApplicationCertificateType requires an RSA key size of
  // 2048/3072/4096. A 1024-bit RSA cert under that type fails the key-shape gate with
  // Bad_InvalidArgument. Using a wrong *size* under the SAME type that is already in the
  // group's CertificateTypes isolates the key-shape check (026) from the type-in-group
  // check (008) - both surface Bad_InvalidArgument, so the size must be the only variable.
  auto weakKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 1024);
  auto weakCert = create_app_cert(weakKeys, {"urn:test:compliance:server"}, {"localhost"}, "WeakKeyServer");

  auto updateResult = call_update_certificate(
    NodeId{}, rsa_cert_type_id(), weakCert->der_encoding(), {}, String{"PEM"}, weakKeys->private_key_pem());
  ASSERT_TRUE(updateResult.is_bad());
  EXPECT_EQ(updateResult.status_code(), StatusCode{Status::BadInvalidArgument})
    << "RSA-1024 under RsaSha256ApplicationCertificateType must yield Bad_InvalidArgument (key-shape): "
    << updateResult.status_code().as_uint32();
}

// --- SVR-PULLCRT-009: repeated CreateSigningRequest stages only the second key ---

// @relation(SVR-ECC-010, SVR-PULLCRT-009, scope=function)
TEST_F(PushCertificateManagementTest, Mirror_CreateSigningRequestRepeatStagesSecondKey)
{
  ByteString nonce1(std::vector<byte>(32, byte{0x11}));
  auto csr1 = call_create_signing_request(NodeId{}, rsa_cert_type_id(), String{}, true, std::move(nonce1));
  ASSERT_TRUE(csr1.is_good()) << csr1.status_code().as_uint32();

  ByteString nonce2(std::vector<byte>(32, byte{0x22}));
  auto csr2 = call_create_signing_request(NodeId{}, rsa_cert_type_id(), String{}, true, std::move(nonce2));
  ASSERT_TRUE(csr2.is_good()) << csr2.status_code().as_uint32();

  // Both calls succeed and each returns a distinct CSR - the second regenerated key
  // overwrites the first's staged-but-not-yet-active key (one active + one new per
  // (group,type), Part 12 section 7.10.7).
  EXPECT_FALSE(csr2.value().empty());
  EXPECT_NE(csr1.value(), csr2.value());
}

// --- SVR-PULLCRT-011: regeneratePrivateKey=TRUE staged until matching UpdateCertificate ---

// @relation(SVR-ECC-010, SVR-PULLCRT-011, scope=function)
TEST_F(PushCertificateManagementTest, Mirror_CreateSigningRequestRegenerateKeyThenUpdateCompletes)
{
  // regeneratePrivateKey=TRUE -> server stores a new private key; a matching UpdateCertificate
  // (no privateKey supplied) completes against that staged key.
  ByteString nonce(std::vector<byte>(32, byte{0xAB}));
  auto csrResult =
    call_create_signing_request(NodeId{}, rsa_cert_type_id(), String{}, true, std::move(nonce));
  ASSERT_TRUE(csrResult.is_good()) << csrResult.status_code().as_uint32();

  Crypto::SubjectAlternateName san;
  san.uris.push_back("urn:test:compliance:server");
  san.hostnames.push_back("localhost");
  san.ipAddresses.push_back(boost::asio::ip::make_address("127.0.0.1"));  // the host clients dial
  auto signedCert = mPki->sign_csr(
    csrResult.value(), mCaKeys, mCaCert, CertificateSignatureAlgorithm::RsaPkcs15Sha2256, std::move(san));

  auto updateResult = call_update_certificate(
    NodeId{}, rsa_cert_type_id(), signedCert->der_encoding(), {mCaCert->der_encoding()});
  ASSERT_TRUE(updateResult.is_good())
    << "UpdateCertificate must complete against the staged regenerated key: "
    << updateResult.status_code().as_uint32();
  EXPECT_TRUE(updateResult.value());  // applyChangesRequired

  call_cancel_changes();
}

// --- SVR-PULLCRT-012: regeneratePrivateKey=TRUE + nonce<32 -> Bad_InvalidArgument ---

// @relation(SVR-ECC-010, SVR-PULLCRT-012, scope=function)
TEST_F(PushCertificateManagementTest, Mirror_CreateSigningRequestNonceTooShortFailsInvalidArgument)
{
  ByteString nonce(std::vector<byte>(16, byte{0xAB}));  // < 32 bytes
  auto csrResult =
    call_create_signing_request(NodeId{}, rsa_cert_type_id(), String{}, true, std::move(nonce));
  ASSERT_TRUE(csrResult.is_bad());
  EXPECT_EQ(csrResult.status_code(), StatusCode{Status::BadInvalidArgument})
    << "nonce < 32 bytes with regeneratePrivateKey=TRUE must yield Bad_InvalidArgument: "
    << csrResult.status_code().as_uint32();
}

// --- SVR-PULLCRT-013: CreateSigningRequest produces a signable ApplicationInstance CSR ---

// @relation(SVR-ECC-010, SVR-PULLCRT-013, scope=function)
TEST_F(PushCertificateManagementTest, Mirror_CreateSigningRequestProducesSignableApplicationCsr)
{
  // End-to-end: the generated CSR is a well-formed PKCS#10 that a CA can sign and the
  // server then accepts via UpdateCertificate (proving it carries the fields needed for an
  // ApplicationInstance certificate). Deep per-field SAN inspection of the CSR DER is the
  // planned unit test CreateSigningRequest_PopulatesSubjectAltNameWithAppUri.
  ByteString nonce(std::vector<byte>(32, byte{0xAB}));
  auto csrResult =
    call_create_signing_request(NodeId{}, rsa_cert_type_id(), String{}, true, std::move(nonce));
  ASSERT_TRUE(csrResult.is_good()) << csrResult.status_code().as_uint32();
  ASSERT_FALSE(csrResult.value().empty());

  Crypto::SubjectAlternateName san;
  san.uris.push_back("urn:test:compliance:server");
  san.hostnames.push_back("localhost");
  san.ipAddresses.push_back(boost::asio::ip::make_address("127.0.0.1"));  // the host clients dial
  auto signedCert = mPki->sign_csr(
    csrResult.value(), mCaKeys, mCaCert, CertificateSignatureAlgorithm::RsaPkcs15Sha2256, std::move(san));
  ASSERT_NE(signedCert, nullptr);

  // Server acceptance of the signed cert exercises the Table 106 URI/HostName checks
  // against the server's own ApplicationUri - proving the CSR produced an ApplicationInstance
  // certificate the server recognises as its own.
  auto updateResult = call_update_certificate(
    NodeId{}, rsa_cert_type_id(), signedCert->der_encoding(), {mCaCert->der_encoding()});
  ASSERT_TRUE(updateResult.is_good())
    << "server must accept the cert produced from its own CSR: " << updateResult.status_code().as_uint32();
  EXPECT_TRUE(updateResult.value());  // applyChangesRequired

  call_cancel_changes();
}

// --- SVR-PULLCRT-014: ApplyChanges with TrustList open for write -> Bad_InvalidState ---

// @relation(SVR-ECC-010, SVR-PULLCRT-014, scope=function)
TEST_F(PushCertificateManagementTest, Mirror_ApplyChangesTrustListOpenFailsInvalidState)
{
  // Start a transaction AND leave a TrustList write handle open, then ApplyChanges must refuse with
  // Bad_InvalidState; after closing it can proceed. RATIFIED (owner report 2026-10-03, BR-13): the
  // transaction is an UpdateCertificate's - the AddCertificate this used is not part of one (7.8.2.4).
  ASSERT_NO_FATAL_FAILURE(open_transaction_with_update_certificate());

  auto handleResult = call_open(0x06);  // Write|EraseExisting - leaves it open
  ASSERT_TRUE(handleResult.is_good()) << handleResult.status_code().as_uint32();

  auto applyResult = call_apply_changes();
  ASSERT_TRUE(applyResult.is_bad());
  EXPECT_EQ(applyResult.status_code(), StatusCode{Status::BadInvalidState})
    << "ApplyChanges with a TrustList open for write must yield Bad_InvalidState: "
    << applyResult.status_code().as_uint32();

  call_close(handleResult.value());
  call_cancel_changes();
}

// --- SVR-PULLCRT-015: ApplyChanges with no active transaction -> Bad_NothingToDo ---

// @relation(SVR-ECC-010, SVR-PULLCRT-015, scope=function)
TEST_F(PushCertificateManagementTest, Mirror_ApplyChangesNoTransactionFailsNothingToDo)
{
  auto applyResult = call_apply_changes();
  ASSERT_TRUE(applyResult.is_bad());
  EXPECT_EQ(applyResult.status_code(), StatusCode{Status::BadNothingToDo});

  // The failed no-op must leave the session usable.
  auto dv = read_property(VariableId::ServerConfiguration_MaxTrustListSize);
  EXPECT_TRUE(!dv.status().has_value() || dv.status()->is_good());
}

// --- SVR-PULLCRT-016: ApplyChanges closes the caller's channel; reconnect with new cert ---

// @relation(SVR-ECC-010, SVR-PULLCRT-016, scope=function)
TEST_F(PushCertificateManagementTest, Mirror_ApplyChangesClosesChannelThenReconnect)
{
  // Trust the CA so the client can validate the rotated server cert on reconnect.
  mClientCertStore->add_to_trusted_certificates_sync(mCaCert);

  ByteString nonce(std::vector<byte>(32, byte{0xAB}));
  auto csrResult =
    call_create_signing_request(NodeId{}, rsa_cert_type_id(), String{}, true, std::move(nonce));
  ASSERT_TRUE(csrResult.is_good()) << csrResult.status_code().as_uint32();

  Crypto::SubjectAlternateName san;
  san.uris.push_back("urn:test:compliance:server");
  san.hostnames.push_back("localhost");
  san.ipAddresses.push_back(boost::asio::ip::make_address("127.0.0.1"));  // the host clients dial
  auto signedCert = mPki->sign_csr(
    csrResult.value(), mCaKeys, mCaCert, CertificateSignatureAlgorithm::RsaPkcs15Sha2256, std::move(san));

  auto updateResult = call_update_certificate(
    NodeId{}, rsa_cert_type_id(), signedCert->der_encoding(), {mCaCert->der_encoding()});
  ASSERT_TRUE(updateResult.is_good())
    << ua::format(updateResult.status_code())
    << (updateResult.shared_detail() ? "\n" + ua::to_string(*updateResult.shared_detail()) : std::string{});

  try
  {
    call_apply_changes();
  }
  catch (...)
  {}

  // The original channel is torn down; a request on it must fail.
  std::this_thread::sleep_for(std::chrono::milliseconds{200});
  bool channelDisrupted = false;
  try
  {
    read_property(VariableId::ServerConfiguration_MaxTrustListSize);
  }
  catch (...)
  {
    channelDisrupted = true;
  }
  EXPECT_TRUE(channelDisrupted) << "Caller channel must be closed after ApplyChanges";

  // Reconnect with the new server cert and reactivate the surviving session.
  CoreClient::OpenChannelConfig reconnCfg;
  reconnCfg.endpointUrl = mEndpointUrl;
  reconnCfg.securityMode = MessageSecurityMode::SignAndEncrypt;
  reconnCfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  reconnCfg.serverCertificate = signedCert;
  auto newChannel = mClient->core().open_channel_sync(std::move(reconnCfg));
  mSession->activate_sync(std::move(newChannel));

  auto dv = read_property(VariableId::ServerConfiguration_MaxTrustListSize);
  EXPECT_TRUE(!dv.status().has_value() || dv.status()->is_good())
    << "Read on the reconnected session must succeed";

  mSession->close_sync();
  mSession.reset();
  mChannel.reset();
}

// --- SVR-PULLCRT-017: channel close does not destroy the Session / Subscription ---

// @relation(SVR-ECC-010, SVR-PULLCRT-017, scope=function)
TEST_F(PushCertificateManagementTest, Mirror_ApplyChangesSessionSurvivesSubscriptionContinues)
{
  mClientCertStore->add_to_trusted_certificates_sync(mCaCert);

  // Subscribe to Server events before the rotation.
  setup_event_subscription();

  auto newKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto newCert = create_app_cert(newKeys, {"urn:test:compliance:server"}, {"localhost"}, "SurviveServer");
  auto updateResult = call_update_certificate(NodeId{},
    rsa_cert_type_id(),
    newCert->der_encoding(),
    {mCaCert->der_encoding()},
    String{"PEM"},
    newKeys->private_key_pem());
  ASSERT_TRUE(updateResult.is_good())
    << ua::format(updateResult.status_code())
    << (updateResult.shared_detail() ? "\n" + ua::to_string(*updateResult.shared_detail()) : std::string{});

  try
  {
    call_apply_changes();
  }
  catch (...)
  {}

  // Reconnect on a new channel and reactivate the SAME session (Part 4 section 5.6.2).
  CoreClient::OpenChannelConfig reconnCfg;
  reconnCfg.endpointUrl = mEndpointUrl;
  reconnCfg.securityMode = MessageSecurityMode::SignAndEncrypt;
  reconnCfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  reconnCfg.serverCertificate = newCert;
  auto newChannel = mClient->core().open_channel_sync(std::move(reconnCfg));
  mSession->activate_sync(std::move(newChannel));

  // The subscription survived with the session: trigger a fresh audit event and collect it. (A trusted
  // add of an end-entity certificate: AddCertificate with isTrustedCertificate FALSE is refused, and so is
  // a CA certificate, Part 12 7.8.2.4.)
  auto leafKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leafCert = create_app_cert(leafKeys, {"urn:test:survive:leaf"}, {"localhost"}, "SurviveLeaf");
  auto addResult = call_add_certificate(leafCert->der_encoding(), true);
  ASSERT_TRUE(addResult.is_good()) << addResult.status_code().as_uint32();

  auto eventTypes = collect_event_types(10);
  EXPECT_FALSE(eventTypes.empty())
    << "Subscription must survive channel closure and continue delivering notifications";

  call_cancel_changes();
  mSession->close_sync();
  mSession.reset();
  mChannel.reset();
}

// --- SVR-PULLCRT-020: ApplyChanges requires the originating session + authenticated channel ---

// @relation(SVR-ECC-010, SVR-PULLCRT-020, scope=function)
TEST_F(PushCertificateManagementTest, Mirror_ApplyChangesNonOwningSessionDenied)
{
  // Session A opens a transaction.
  auto newKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto newCert = create_app_cert(newKeys);
  auto updateResult = call_update_certificate(
    NodeId{}, rsa_cert_type_id(), newCert->der_encoding(), {}, String{"PEM"}, newKeys->private_key_pem());
  ASSERT_TRUE(updateResult.is_good())
    << ua::format(updateResult.status_code())
    << (updateResult.shared_detail() ? "\n" + ua::to_string(*updateResult.shared_detail()) : std::string{});

  // Session B (a different session on its own channel) cannot ApplyChanges A's transaction.
  auto [channel2, session2] = open_second_session();
  auto foreignResult = call_method_on_session(
    session2, serverConfigObjectId, NodeId{MethodId::ServerConfiguration_ApplyChanges});
  ASSERT_TRUE(foreignResult.status_code().is_bad());
  EXPECT_EQ(foreignResult.status_code(), StatusCode{Status::BadUserAccessDenied})
    << "ApplyChanges from a non-owning session must be denied: " << foreignResult.status_code().as_uint32();

  session2.close_sync();
  channel2.close_sync();
  call_cancel_changes();
}

// --- SVR-PULLCRT-023: CancelChanges discards pending; foreign session denied ---

// @relation(SVR-ECC-010, SVR-PULLCRT-023, scope=function)
TEST_F(PushCertificateManagementTest, Mirror_CancelChangesDiscardsAndForeignSessionDenied)
{
  // Open a transaction on session A.
  auto newKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto newCert = create_app_cert(newKeys);
  auto updateResult = call_update_certificate(
    NodeId{}, rsa_cert_type_id(), newCert->der_encoding(), {}, String{"PEM"}, newKeys->private_key_pem());
  ASSERT_TRUE(updateResult.is_good())
    << ua::format(updateResult.status_code())
    << (updateResult.shared_detail() ? "\n" + ua::to_string(*updateResult.shared_detail()) : std::string{});

  // A foreign session cannot cancel A's transaction.
  auto [channel2, session2] = open_second_session();
  auto foreignResult = call_method_on_session(
    session2, serverConfigObjectId, NodeId{MethodId::ServerConfiguration_CancelChanges});
  ASSERT_TRUE(foreignResult.status_code().is_bad());
  EXPECT_EQ(foreignResult.status_code(), StatusCode{Status::BadUserAccessDenied});
  session2.close_sync();
  channel2.close_sync();

  // The owning session cancels - discarding the pending change.
  auto cancelResult = call_cancel_changes();
  ASSERT_TRUE(cancelResult.is_good()) << cancelResult.status_code().as_uint32();

  // Nothing remains to apply.
  auto applyResult = call_apply_changes();
  ASSERT_TRUE(applyResult.is_bad());
  EXPECT_EQ(applyResult.status_code(), StatusCode{Status::BadNothingToDo});
}

// --- SVR-PULLCRT-024: CancelChanges with no active transaction -> Bad_NothingToDo ---

// @relation(SVR-ECC-010, SVR-PULLCRT-024, scope=function)
TEST_F(PushCertificateManagementTest, Mirror_CancelChangesNoTransactionFailsNothingToDo)
{
  auto cancelResult = call_cancel_changes();
  ASSERT_TRUE(cancelResult.is_bad());
  EXPECT_EQ(cancelResult.status_code(), StatusCode{Status::BadNothingToDo});

  // Server remains usable after the no-op.
  auto dv = read_property(VariableId::ServerConfiguration_MaxTrustListSize);
  EXPECT_TRUE(!dv.status().has_value() || dv.status()->is_good());
}

// --- SVR-PULLCRT-025: GetCertificates over an admin encrypted channel returns active certs ---

// @relation(SVR-ECC-010, SVR-PULLCRT-025, scope=function)
TEST_F(PushCertificateManagementTest, Mirror_GetCertificatesOverAdminChannelReturnsActiveCerts)
{
  // GetCertificates is materialised at runtime (i=32333); call it via its MethodId on the
  // live server. Over the admin encrypted channel it returns (certificateTypeIds[],
  // certificates[]) for the named group.
  auto result = call_server_config_method(NodeId{MethodId::ServerConfiguration_GetCertificates},
    []
    {
      Array<Variant> args;
      args.resize(1);
      args[0] = Variant{NodeId{}};  // null groupId -> DefaultApplicationGroup
      return args;
    }());
  ASSERT_TRUE(result.status_code().is_good()) << result.status_code().as_uint32();
  ASSERT_EQ(result.output_arguments().size(), 2u) << "GetCertificates returns (typeIds[], certificates[])";

  auto typeIds = result.output_arguments()[0].as<Array<NodeId>>();
  auto certs = result.output_arguments()[1].as<Array<ByteString>>();
  EXPECT_FALSE(certs.empty()) << "server has an active application certificate to report";
  EXPECT_EQ(typeIds.size(), certs.size()) << "one certificateTypeId per returned certificate";
}

// --- SVR-PULLCRT-028: a failed Method inside an open transaction does not abort it ---

// @relation(SVR-ECC-010, SVR-PULLCRT-028, scope=function)
TEST_F(PushCertificateManagementTest, Mirror_FailedMethodInsideTransactionDoesNotAbortIt)
{
  // A successful UpdateCertificate opens a transaction. RATIFIED (owner report 2026-10-03, BR-13): the
  // transaction and the failing Method are an UpdateCertificate and a CloseAndUpdate - the AddCertificate
  // calls this used are not part of a transaction (OPC 10000-12 7.8.2.4).
  ASSERT_NO_FATAL_FAILURE(open_transaction_with_update_certificate());

  // A failing Method inside it (a TrustList holding a malformed certificate) must NOT abort it.
  TrustListDataType garbage;
  garbage.specified_lists() = 0x01;
  garbage.trusted_certificates().push_back(ByteString(std::vector<byte>(64, byte{0xFF})));
  auto badUpdate = close_and_update_trust_list(garbage);
  EXPECT_TRUE(badUpdate.is_bad()) << "a CloseAndUpdate with a malformed certificate should fail";

  // The transaction is still open: CancelChanges succeeds (it would be Bad_NothingToDo if
  // the failed Method had aborted/cleared it).
  auto cancelResult = call_cancel_changes();
  EXPECT_TRUE(cancelResult.is_good())
    << "transaction must remain open after a failed Method: " << cancelResult.status_code().as_uint32();
}

// --- SVR-PULLCRT-029: transaction queue preserves invocation order (add A, add B, remove A) ---

// @relation(SVR-ECC-010, SVR-PULLCRT-029, scope=function)
TEST_F(PushCertificateManagementTest, Mirror_TransactionPreservesOrderAddRemoveNetsToRemoved)
{
  auto makeLeaf = [&](std::string_view uri, const std::string& name)
  {
    auto keys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    return mPki->create_leaf_cert(keys,
      mCaKeys,
      mCaCert,
      DateTime::now(),
      DateTime{DateTime::now().value() + std::chrono::days{365}},
      {std::string{uri}},
      {"localhost"},
      name);
  };
  auto certA = makeLeaf("urn:test:order:a", "OrderLeafA");
  auto certB = makeLeaf("urn:test:order:b", "OrderLeafB");

  // Queue: Add(A) -> Add(B) -> Remove(A). Net working set must contain B but not A.
  ASSERT_TRUE(call_add_certificate(certA->der_encoding(), true).is_good());
  ASSERT_TRUE(call_add_certificate(certB->der_encoding(), true).is_good());
  auto thumbprintA = fmt::format("{:02X}", fmt::join(certA->thumbprint(), ""));
  ASSERT_TRUE(call_remove_certificate(String{thumbprintA}, true).is_good());

  auto trustList = read_trust_list(0x01);
  auto derA = certA->der_encoding();
  auto derB = certB->der_encoding();
  bool foundA = false;
  bool foundB = false;
  for (const auto& cert : trustList.trusted_certificates())
  {
    if (cert == derA)
      foundA = true;
    if (cert == derB)
      foundB = true;
  }
  EXPECT_TRUE(foundB) << "B (added, not removed) must be present";
  EXPECT_FALSE(foundA) << "A (added then removed in order) must be absent";

  call_cancel_changes();
}

// --- SVR-PULLCRT-030: ApplyChanges whole-batch verify failure discards all changes ---

// @relation(SVR-ECC-010, SVR-PULLCRT-030, scope=function)
TEST_F(PushCertificateManagementTest, Mirror_ApplyChangesInconsistentBatchDiscardsAll)
{
  // Stage a new server cert (passes per-Method validation: CA is trusted) AND, in the same
  // transaction, remove that CA from the trust list. ApplyChanges re-validates the staged
  // cert whole-batch; its issuer is now gone -> the entire batch is discarded.
  auto newKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto newCert = create_app_cert(newKeys, {"urn:test:compliance:server"}, {"localhost"}, "BatchServer");
  auto updateResult = call_update_certificate(
    NodeId{}, rsa_cert_type_id(), newCert->der_encoding(), {}, String{"PEM"}, newKeys->private_key_pem());
  ASSERT_TRUE(updateResult.is_good())
    << ua::format(updateResult.status_code())
    << (updateResult.shared_detail() ? "\n" + ua::to_string(*updateResult.shared_detail()) : std::string{});

  // Remove the issuing CA from the trust list within the same transaction. RATIFIED (owner report
  // 2026-10-03, BR-13): with a CloseAndUpdate, which joins the transaction (7.8.2.3) - the RemoveCertificate
  // this used is not part of one (7.8.2.5) and is refused while it is open.
  auto removeResult = close_and_update_trust_list(trust_list_without_the_ca());
  ASSERT_TRUE(removeResult.is_good())
    << "the CA removal is the inconsistency under test: " << removeResult.status_code().as_uint32();

  auto applyResult = call_apply_changes();
  EXPECT_TRUE(applyResult.is_bad()) << "inconsistent batch must fail whole-batch verification";

  // The original server cert must still be active - nothing was committed.
  auto appCert = mServerCertStore->get_application_certificate_sync(CertificateType::RsaSha256Application);
  EXPECT_EQ(appCert.certificate->der_encoding(), mServerCert->der_encoding())
    << "no change may be committed when the batch is inconsistent";

  try
  {
    call_cancel_changes();
  }
  catch (...)
  {}
}

// ===========================================================================
// Sign-only channel: encrypted-required Methods are rejected (channel floor)
// ===========================================================================

// @relation(SVR-PULLCRT-006, scope=function)
TEST_F(PushCertSignChannelTest, Mirror_UpdateCertificateOnSignChannelFailsSecurityModeInsufficient)
{
  Array<Variant> args;
  args.resize(6);
  args[0] = Variant{NodeId{}};
  args[1] = Variant{NodeId{ObjectTypeId::RsaSha256ApplicationCertificateType}};
  args[2] = Variant{ByteString{}};
  args[3] = Variant{Array<ByteString>{}};
  args[4] = Variant{String{}};
  args[5] = Variant{ByteString{}};

  auto result = call_method(
    serverConfigObjectId, NodeId{MethodId::ServerConfiguration_UpdateCertificate}, std::move(args));
  ASSERT_TRUE(result.status_code().is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadSecurityModeInsufficient})
    << "UpdateCertificate requires an encrypted channel; Sign-only must be rejected";
}

// @relation(SVR-ECC-010, SVR-PULLCRT-010, scope=function)
TEST_F(PushCertSignChannelTest, Mirror_CreateSigningRequestOnSignChannelFailsSecurityModeInsufficient)
{
  Array<Variant> args;
  args.resize(5);
  args[0] = Variant{NodeId{}};
  args[1] = Variant{NodeId{ObjectTypeId::RsaSha256ApplicationCertificateType}};
  args[2] = Variant{String{}};
  args[3] = Variant{true};
  args[4] = Variant{ByteString(std::vector<byte>(32, byte{0xAB}))};

  auto result = call_method(
    serverConfigObjectId, NodeId{MethodId::ServerConfiguration_CreateSigningRequest}, std::move(args));
  ASSERT_TRUE(result.status_code().is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadSecurityModeInsufficient})
    << "CreateSigningRequest requires an encrypted channel; Sign-only must be rejected";
}

// ===========================================================================
// None channel: authenticated-required Methods are rejected (channel floor)
// ===========================================================================

// @relation(SVR-ECC-010, SVR-PULLCRT-021, scope=function)
TEST_F(PushCertNoneChannelTest, Mirror_GetRejectedListOnNoneChannelFailsSecurityModeInsufficient)
{
  auto result = call_method(serverConfigObjectId, NodeId{MethodId::ServerConfiguration_GetRejectedList});
  ASSERT_TRUE(result.status_code().is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadSecurityModeInsufficient})
    << "GetRejectedList requires an authenticated channel; None must be rejected";
}

TEST_F(PushCertNoneChannelTest, Mirror_GetCertificatesOnNoneChannelFailsSecurityModeInsufficient)
{
  Array<Variant> args;
  args.resize(1);
  args[0] = Variant{NodeId{}};
  auto result =
    call_method(serverConfigObjectId, NodeId{MethodId::ServerConfiguration_GetCertificates}, std::move(args));
  ASSERT_TRUE(result.status_code().is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadSecurityModeInsufficient})
    << "GetCertificates requires an authenticated channel; None must be rejected";
}

// @relation(SVR-ECC-010, SVR-PULLCRT-033, scope=function)
TEST_F(PushCertNoneChannelTest, Mirror_ResetToServerDefaultsOnNoneChannelFailsSecurityModeInsufficient)
{
  auto result =
    call_method(serverConfigObjectId, NodeId{MethodId::ServerConfiguration_ResetToServerDefaults});
  ASSERT_TRUE(result.status_code().is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadSecurityModeInsufficient})
    << "ResetToServerDefaults requires an authenticated channel; None must be rejected";
}

// ===========================================================================
// SVR-PULLCRT-032 / 019: ResetToServerDefaults transitions the server to SHUTDOWN
//
// This shuts the per-test server down - it runs in its own fixture with a longer
// shutdown grace period so ServerStatus stays readable, and lets TearDown reap it.
// ===========================================================================

class PushCertResetTest : public PushCertificateManagementTest
{
protected:
  void configure_server_create_config(server::CreateConfig& cfg) override
  {
    PushCertificateManagementTest::configure_server_create_config(cfg);
    // Long grace so ServerStatus is still readable after the SHUTDOWN transition.
    cfg.server.defaultShutdownGracePeriodSeconds = 60;
  }
};

// @relation(SVR-ECC-010, SVR-PULLCRT-019, SVR-PULLCRT-032, scope=function)
TEST_F(PushCertResetTest, Mirror_ResetToServerDefaultsTransitionsServerToShutdown)
{
  auto result = call_server_config_method(NodeId{MethodId::ServerConfiguration_ResetToServerDefaults});
  ASSERT_TRUE(result.status_code().is_good()) << result.status_code().as_uint32();

  // ServerState -> SHUTDOWN with a localized ShutdownReason and a SecondsTillShutdown
  // advertisement (Part 12 section 7.10.10; SVR-PULLCRT-019 restart-announcement mechanism).
  auto stateDv = read_property(VariableId::Server_ServerStatus_State);
  ASSERT_TRUE(!stateDv.status().has_value() || stateDv.status()->is_good());
  EXPECT_EQ(stateDv.value().as<int32_t>(), static_cast<int32_t>(ServerState::Shutdown))
    << "ResetToServerDefaults must transition ServerState to SHUTDOWN";

  auto reasonDv = read_property(VariableId::Server_ServerStatus_ShutdownReason);
  ASSERT_TRUE(!reasonDv.status().has_value() || reasonDv.status()->is_good());
  EXPECT_FALSE(string_view{reasonDv.value().as<LocalizedText>().text()}.empty())
    << "ShutdownReason must carry a localized warning message";

  auto secondsDv = read_property(VariableId::Server_ServerStatus_SecondsTillShutdown);
  ASSERT_TRUE(!secondsDv.status().has_value() || secondsDv.status()->is_good());
  EXPECT_GT(secondsDv.value().as<uint32_t>(), 0u) << "SecondsTillShutdown must be advertised";

  // Let TearDown reap the shutting-down server; do not reuse the session.
}

// ===========================================================================
// UpdateCertificate key-matching, CSR contents and TransactionDiagnostics
// ===========================================================================

// Part 12 section 7.10.4: the Server shall report an error if the pushed Certificate's public key
// does not match the existing one and no privateKey was supplied; supplying the matching private
// key alongside makes the same Certificate acceptable. An implementation that only checks the
// chain accepts the first push and then holds a Certificate it cannot prove: every secured
// connection fails at the signature with nothing pointing at the cause. Both arms use the SAME
// Certificate so the private key is the only variable.
// @verifies AC-SVR-PULLCRT-005-PUBLICKEY-MUST-MATCH
TEST_F(PushCertificateManagementTest, UpdateCertificateNeedsMatchingKeyUnlessPrivateKeySupplied)
{
  // A CA-signed Certificate whose key pair the server has never seen: no CreateSigningRequest has
  // staged a key on this session, so the only way its key can arrive is in the privateKey argument.
  auto foreignKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto foreignCert =
    create_app_cert(foreignKeys, {"urn:test:compliance:server"}, {"localhost"}, "KeyPairingProbe");
  const auto foreignDer = foreignCert->der_encoding();

  // Arm 1 - public key does not match the active Certificate and no privateKey supplied.
  std::vector<ByteString> issuersWithoutKey;
  issuersWithoutKey.push_back(mCaCert->der_encoding());
  auto withoutKey =
    call_update_certificate(NodeId{}, rsa_cert_type_id(), foreignDer, std::move(issuersWithoutKey));
  EXPECT_EQ(withoutKey.status_code().as_status(), Status::BadSecurityChecksFailed)
    << "a Certificate whose public key matches neither the active key nor a supplied privateKey "
       "must be refused; got "
    << withoutKey.status_code().as_uint32();

  // Arm 2 - the very same Certificate, this time with its private key travelling alongside.
  std::vector<ByteString> issuersWithKey;
  issuersWithKey.push_back(mCaCert->der_encoding());
  auto withKey = call_update_certificate(NodeId{},
    rsa_cert_type_id(),
    foreignDer,
    std::move(issuersWithKey),
    String{"PEM"},
    foreignKeys->private_key_pem());
  ASSERT_TRUE(withKey.is_good()) << "the same Certificate pushed with its matching private key must be "
                                    "accepted; got "
                                 << withKey.status_code().as_uint32();
  EXPECT_TRUE(withKey.value()) << "acceptance must open a transaction (applyChangesRequired)";

  // The acceptance really staged a transaction - CancelChanges would be Bad_NothingToDo otherwise.
  auto cancelResult = call_cancel_changes();
  EXPECT_TRUE(cancelResult.is_good())
    << "the accepted push must leave a pending transaction: " << cancelResult.status_code().as_uint32();
}

// Part 12 section 7.10.7 with Part 6 section 6.2: a CSR for an ApplicationInstance Certificate must
// carry the application URI and the host names in subjectAltName. A plausible implementation builds
// the CSR from the subject name alone; the omission only surfaces after the CA has signed it, when
// the Server installs a Certificate every peer rejects. The subject is supplied explicitly here so
// the ApplicationUri cannot reach the CSR through the subject DN - if it appears, it came from
// subjectAltName.
// @verifies AC-SVR-PULLCRT-013-CSR-REQUIRED-FIELDS
TEST_F(PushCertificateManagementTest, CreateSigningRequestCarriesApplicationUriAndHostNameInSubjectAltName)
{
  // ServerArray[0] is the Server's own ApplicationUri - the same configuration value the CSR
  // builder reads, so this is the exact byte sequence subjectAltName must carry.
  auto serverArrayDv = read_property(VariableId::Server_ServerArray);
  ASSERT_TRUE(!serverArrayDv.status().has_value() || serverArrayDv.status()->is_good());
  ASSERT_TRUE(serverArrayDv.value().is_array()) << "ServerArray must be an array";
  const auto& serverUris = serverArrayDv.value().as<Array<String>>();
  ASSERT_FALSE(serverUris.empty()) << "ServerArray must publish the local Server URI";
  const std::string applicationUri{string_view{serverUris.payload().front()}};
  ASSERT_FALSE(applicationUri.empty()) << "the local Server URI must not be empty";

  ByteString nonce(std::vector<byte>(32, byte{0xC5}));
  auto csrResult = call_create_signing_request(
    NodeId{}, rsa_cert_type_id(), String{"CsrFieldProbe"}, true, std::move(nonce));
  ASSERT_TRUE(csrResult.is_good()) << csrResult.status_code().as_uint32();
  const auto& csrDer = csrResult.value();
  ASSERT_FALSE(csrDer.empty()) << "CreateSigningRequest must return a DER CSR";

  // GeneralName URI / dNSName entries are IA5String, i.e. literal ASCII inside the CSR DER.
  const std::string_view csrBytes{reinterpret_cast<const char*>(csrDer.data()), csrDer.size()};
  EXPECT_NE(csrBytes.find(applicationUri), std::string_view::npos)
    << "subjectAltName must carry the ApplicationUri '" << applicationUri << "'";
  EXPECT_NE(csrBytes.find("localhost"), std::string_view::npos)
    << "subjectAltName must carry the Server's host name";
}

// Part 12 section 7.10.11: TransactionDiagnostics is populated at the end of EVERY transaction,
// successful or not. The failure mode is staleness - an implementation that only publishes on
// success leaves the previous transaction's Result in place, so an administrator reading the Object
// after a failed ApplyChanges concludes the change applied. The errored transaction here runs
// second precisely so a stale Object would still read Good.
// @verifies AC-SVR-PULLCRT-031-TRANSACTIONDIAGNOSTICS
TEST_F(PushCertificateManagementTest, TransactionDiagnosticsRecordsBothSuccessfulAndErroredTransactions)
{
  // Trust the CA client-side so the client can validate the rotated Server Certificate.
  mClientCertStore->add_to_trusted_certificates_sync(mCaCert);

  // --- Transaction 1: a transaction that succeeds. ---
  auto goodKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto goodCert = create_app_cert(goodKeys, {"urn:test:compliance:server"}, {"localhost"}, "DiagOkServer");
  auto stageGood = call_update_certificate(NodeId{},
    rsa_cert_type_id(),
    goodCert->der_encoding(),
    {mCaCert->der_encoding()},
    String{"PEM"},
    goodKeys->private_key_pem());
  ASSERT_TRUE(stageGood.is_good()) << stageGood.status_code().as_uint32();

  try
  {
    call_apply_changes();
  }
  catch (...)
  {
    // ApplyChanges closes the caller's channel; the transport error is expected.
  }

  // Reconnect with the rotated Certificate and reactivate the surviving Session (Part 4 5.6.2).
  CoreClient::OpenChannelConfig reconnCfg;
  reconnCfg.endpointUrl = mEndpointUrl;
  reconnCfg.securityMode = MessageSecurityMode::SignAndEncrypt;
  reconnCfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  reconnCfg.serverCertificate = goodCert;
  auto newChannel = mClient->core().open_channel_sync(std::move(reconnCfg));
  mSession->activate_sync(std::move(newChannel));

  // The successful transaction is recorded: Good Result, no Errors, affected group named.
  auto goodResultDv = read_property(VariableId::ServerConfiguration_TransactionDiagnostics_Result);
  EXPECT_TRUE(goodResultDv.value().as<StatusCode>().is_good())
    << "a successful transaction must record a good Result: "
    << goodResultDv.value().as<StatusCode>().as_uint32();

  auto goodErrorsDv = read_property(VariableId::ServerConfiguration_TransactionDiagnostics_Errors);
  ASSERT_TRUE(goodErrorsDv.value().is_array()) << "Errors must be recorded as an array";
  EXPECT_TRUE(goodErrorsDv.value().as<Array<RefStructure<Structure>>>().empty())
    << "a successful transaction names no errors";

  auto goodGroupsDv =
    read_property(VariableId::ServerConfiguration_TransactionDiagnostics_AffectedCertificateGroups);
  ASSERT_TRUE(goodGroupsDv.value().is_array());
  const auto& goodGroups = goodGroupsDv.value().as<Array<NodeId>>();
  ASSERT_FALSE(goodGroups.empty()) << "the successful transaction must name its affected group";
  bool goodHasDefaultGroup = false;
  for (const auto& id : goodGroups)
  {
    if (id == NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup})
      goodHasDefaultGroup = true;
  }
  EXPECT_TRUE(goodHasDefaultGroup) << "AffectedCertificateGroups must name DefaultApplicationGroup";

  // --- Transaction 2: a transaction in which errors occur. ---
  // Stage a Certificate that passes per-Method validation, then remove its issuing CA from the
  // trust list in the same transaction: whole-batch verification at ApplyChanges then fails.
  auto batchKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto batchCert =
    create_app_cert(batchKeys, {"urn:test:compliance:server"}, {"localhost"}, "DiagFailServer");
  auto stageBatch = call_update_certificate(NodeId{},
    rsa_cert_type_id(),
    batchCert->der_encoding(),
    {mCaCert->der_encoding()},
    String{"PEM"},
    batchKeys->private_key_pem());
  ASSERT_TRUE(stageBatch.is_good()) << stageBatch.status_code().as_uint32();

  // RATIFIED (owner report 2026-10-03, BR-13): the CA leaves the TrustList through a CloseAndUpdate, which
  // joins the transaction (7.8.2.3); RemoveCertificate is not part of one (7.8.2.5).
  ASSERT_TRUE(close_and_update_trust_list(trust_list_without_the_ca()).is_good())
    << "removing the issuing CA within the transaction must be queued";

  auto failedApply = call_apply_changes();
  ASSERT_TRUE(failedApply.is_bad()) << "the inconsistent batch must fail whole-batch verification";

  // The errored transaction replaces the previous contents rather than leaving them stale.
  auto badResultDv = read_property(VariableId::ServerConfiguration_TransactionDiagnostics_Result);
  EXPECT_TRUE(badResultDv.value().as<StatusCode>().is_bad())
    << "the failed transaction must overwrite the previous Good Result; read "
    << badResultDv.value().as<StatusCode>().as_uint32();

  auto badErrorsDv = read_property(VariableId::ServerConfiguration_TransactionDiagnostics_Errors);
  ASSERT_TRUE(badErrorsDv.value().is_array()) << "Errors must be recorded as an array";
  EXPECT_FALSE(badErrorsDv.value().as<Array<RefStructure<Structure>>>().empty())
    << "the errored transaction must name its errors";

  try
  {
    call_cancel_changes();
  }
  catch (...)
  {}

  mSession->close_sync();
  mSession.reset();
  mChannel.reset();
}

// ===========================================================================
// Part-18 gated push surface: what a session WITHOUT SecurityAdmin may see
//
// The functional fixtures above pin the channel floor. These two mirrors add
// the ordinary Role control: the connecting Session resolves to the Anonymous
// Role only and never to SecurityAdmin, and the owning Namespace evaluates the
// push Method's RolePermissions before handler dispatch.
// ===========================================================================

namespace
{

/// Non-administrator Session: Part-18 RBAC wired, Anonymous authenticator, no admin grant.
class PushCertNonAdminRbacTest : public ComplianceRoleBasedSecurity
{};

/// Read one Attribute over the wire on an arbitrary Session and return the per-operation
/// StatusCode (the service result when the request itself failed).
StatusCode read_attribute_status_on(Session& session, const NodeId& node, AttributeId attribute)
{
  ReadRequest req;
  ReadValueId rv;
  rv.node_id() = node;
  rv.attribute_id() = static_cast<IntegerId>(attribute);
  req.nodes_to_read().push_back(std::move(rv));

  auto resp = session.attributes().read_sync(std::move(req));
  if (resp.response_header().service_result().is_bad())
    return resp.response_header().service_result();
  if (resp.results().empty())
    return StatusCode{Status::BadUnexpectedError};
  const auto& dv = resp.results()[0];
  return dv.status().has_value() ? *dv.status() : StatusCode{Status::Good};
}

}  // namespace

// Part 12 section 7.10.2 separates visibility from readability deliberately: any user who can reach
// the Server Object must be able to discover that push management exists (so they can ask an
// administrator to use it), while the contents of the CertificateGroups subtree stay with
// SecurityAdmin. Both halves fail plausibly and in opposite directions - gate the whole subtree and
// the feature becomes undiscoverable; gate nothing and the trust configuration is public.
// @verifies AC-SVR-PULLCRT-002-CONFIG-VISIBILITY
TEST_F(PushCertNonAdminRbacTest, NonAdminBrowsesServerConfigurationButIsRefusedCertificateGroupContents)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "PushCertVisibilityNonAdmin");

  // Visible: the Object and its immediate children.
  auto resp = session.view().browse_sync(browse(serverConfigObjectId));
  ASSERT_EQ(resp.results().size(), 1u);
  ASSERT_FALSE(resp.results()[0].status_code().is_bad())
    << "a non-administrator must be able to Browse ServerConfiguration: "
    << resp.results()[0].status_code().as_uint32();
  ASSERT_FALSE(resp.results()[0].references().empty())
    << "ServerConfiguration's immediate children must be visible to a non-administrator";
  EXPECT_TRUE(browse_lists_child(resp.results()[0], "CertificateGroups"))
    << "CertificateGroups is an immediate child and must remain visible";

  // Refused: the trust list and the group's certificate contents.
  EXPECT_EQ(read_attribute_status_on(session, trustListObjectId, AttributeId::DisplayName),
    StatusCode{Status::BadUserAccessDenied})
    << "the DefaultApplicationGroup TrustList must not be visible to a non-administrator";
  EXPECT_EQ(
    read_attribute_status_on(session,
      NodeId{VariableId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateTypes},
      AttributeId::Value),
    StatusCode{Status::BadUserAccessDenied})
    << "the group's certificate contents must not be readable by a non-administrator";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Part 12 section 7.10: GetCertificates carries the same gate as GetRejectedList - an authenticated
// SecureChannel AND the SecurityAdmin Role. It is an Optional Method the SDK materialises at
// runtime rather than inheriting from the NodeSet, so it is exactly the Method whose gate can be
// forgotten: it reports the Certificates currently active in a group, which is trust configuration.
// @verifies AC-SVR-PULLCRT-025-GETCERTIFICATES-GUARDS
TEST_F(PushCertNonAdminRbacTest, GetCertificatesRefusedOnUnauthenticatedChannelAndWithoutSecurityAdmin)
{
  // Arm 1 - an unauthenticated (None) SecureChannel.
  {
    auto [channel, session] = open_session(MessageSecurityMode::None, "PushCertGetCertsNoneChannel");
    Array<Variant> args;
    args.resize(1);
    args[0] = Variant{NodeId{}};  // null groupId -> DefaultApplicationGroup
    auto resp = session.methods().call_sync(make_single_call(
      serverConfigObjectId, NodeId{MethodId::ServerConfiguration_GetCertificates}, std::move(args)));
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_TRUE(resp.results()[0].status_code().is_bad())
      << "GetCertificates over an unauthenticated channel must be refused";
    EXPECT_TRUE(resp.results()[0].output_arguments().empty())
      << "a refused GetCertificates must return no certificates";
    (void)session.try_close_sync();
    (void)channel.try_close_sync();
  }

  // Arm 2 - an authenticated, encrypted SecureChannel whose Session lacks SecurityAdmin.
  {
    auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "PushCertGetCertsNonAdmin");
    Array<Variant> args;
    args.resize(1);
    args[0] = Variant{NodeId{}};
    auto resp = session.methods().call_sync(make_single_call(
      serverConfigObjectId, NodeId{MethodId::ServerConfiguration_GetCertificates}, std::move(args)));
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_EQ(resp.results()[0].status_code(), StatusCode{Status::BadUserAccessDenied})
      << "GetCertificates without the SecurityAdmin Role must be refused; got "
      << resp.results()[0].status_code().as_uint32();
    EXPECT_TRUE(resp.results()[0].output_arguments().empty())
      << "a refused GetCertificates must return no certificates";
    (void)session.try_close_sync();
    (void)channel.try_close_sync();
  }
}

// ===========================================================================
// The push copy of the capabilities list against the Discovery copy
// ===========================================================================

namespace
{

/// Observation point on the interface the discovery-registration driver uses to send one
/// register cycle. It records the `discoveryConfiguration` it is handed and completes the
/// cycle successfully so the driver stays on its steady cadence.
///
/// It produces nothing: the RegisterServer2 payload - including whether an
/// `MdnsDiscoveryConfiguration` is present at all and what `serverCapabilities` it carries -
/// is built entirely by `ua::app::DiscoveryRegistration`, the component under test here.
class CapturingLdsRegistrar : public ua::app::LdsRegistrar
{
public:
  void register_async(ua::app::DiscoveryTarget /*target*/, ua::RegisteredServer server,
    std::vector<std::shared_ptr<ua::Structure>> discoveryConfiguration, bool /*preferFallback*/,
    RegisterResultCallback callback) noexcept override
  {
    const bool isOnline = server.is_online();
    {
      std::lock_guard<std::mutex> lock(mMutex);
      if (isOnline)
      {
        mSawOnlineCycle = true;
        mDiscoveryConfiguration = discoveryConfiguration;
      }
    }

    if (callback)
      callback(ua::Result<RegisterOutcome>{RegisterOutcome{/*usedFallback=*/false}});
  }

  bool saw_online_cycle() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mSawOnlineCycle;
  }

  std::vector<std::shared_ptr<ua::Structure>> discovery_configuration() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mDiscoveryConfiguration;
  }

private:
  mutable std::mutex mMutex;
  bool mSawOnlineCycle{false};
  std::vector<std::shared_ptr<ua::Structure>> mDiscoveryConfiguration;
};

}  // namespace

// Part 12 section 7.10.3: the value of ServerConfiguration.ServerCapabilities "is the same as the
// value reported to the LocalDiscoveryServer when the Server calls the RegisterServer2 Service".
// One logical state published through two subsystems that never consult each other - Push
// Management writes the Property, Discovery builds the RegisterServer2 discoveryConfiguration - so
// the test reads one copy, captures the other off the register interface, and compares the contents
// order-insensitively.
// Either copy may legitimately report nothing: Part 12 section 4.2.2 lets RegisterServer2 carry
// "zero or more ServerCapability Identifiers", so a payload without an MdnsDiscoveryConfiguration
// carries the empty list rather than failing the capture, and a Property with no value publishes
// the empty list. Whether either list is non-empty and drawn from the normative capability CSV is a
// separate obligation (SVR-DISC-CAP-001 / -002); this test asserts only that the two agree.
// @verifies AC-SVR-PULLCRT-027-CAPABILITIES-AGREE
TEST_F(PushCertificateManagementTest, ServerCapabilitiesPropertyAgreesWithWhatRegisterServer2Reports)
{
  // --- The push copy: ServerConfig.ServerCapabilities, read over the admin session. ---
  auto pushDv = read_property(VariableId::ServerConfiguration_ServerCapabilities);
  ASSERT_TRUE(!pushDv.status().has_value() || pushDv.status()->is_good())
    << "ServerConfiguration.ServerCapabilities is a Mandatory Property and must read Good: "
    << (pushDv.status().has_value() ? pushDv.status()->as_uint32() : 0u);

  std::vector<std::string> pushCapabilities;
  if (pushDv.value().is_array())
  {
    for (const auto& capability : pushDv.value().as<Array<String>>())
      pushCapabilities.push_back(std::string{string_view{capability}});
  }

  // --- The Discovery copy: the serverCapabilities the Server hands to RegisterServer2. ---
  // The real outbound driver builds the RegisterServer2 payload; only the transport interface beneath it
  // is replaced, so the argument observed below is the one the Server would put on the wire.
  auto registrar = std::make_shared<CapturingLdsRegistrar>();

  ua::RegisteredServer identity;
  identity.server_uri() = String{"urn:test:compliance:server"};
  identity.product_uri() = String{"urn:test:compliance:product"};
  identity.server_type() = ua::ApplicationType::Server;
  identity.discovery_urls().payload().push_back(String{mEndpointUrl});
  identity.is_online() = true;

  ua::app::DiscoveryTarget target;
  target.discoveryUrl = mEndpointUrl;
  target.messageSecurityMode = MessageSecurityMode::None;

  ua::app::DiscoveryRegistrationConfig registrationConfig;
  registrationConfig.targets.push_back(target);
  registrationConfig.cadence = std::chrono::seconds{1};
  registrationConfig.backoffInitial = std::chrono::seconds{1};
  registrationConfig.backoffCap = std::chrono::seconds{2};
  registrationConfig.shutdownDeregisterTimeout = std::chrono::seconds{3};

  auto driver = ua::app::DiscoveryRegistration::create(
    mServerThreadPool.executor(), registrar, std::move(identity), std::move(registrationConfig));

  {
    std::promise<void> started;
    driver->start_async([&started](VoidResult) { started.set_value(); });
    (void)started.get_future().wait_for(std::chrono::seconds{5});
  }

  for (int attempt = 0; attempt < 100 && !registrar->saw_online_cycle(); ++attempt)
    std::this_thread::sleep_for(std::chrono::milliseconds{50});

  // Snapshot before teardown so the assertions below cannot abort with the driver still running.
  const bool sawOnlineCycle = registrar->saw_online_cycle();
  const auto discoveryConfiguration = registrar->discovery_configuration();

  {
    std::promise<void> stopped;
    driver->stop_async([&stopped](VoidResult) { stopped.set_value(); });
    (void)stopped.get_future().wait_for(std::chrono::seconds{8});
  }
  driver.reset();

  ASSERT_TRUE(sawOnlineCycle) << "the discovery-registration driver must run a registration cycle for "
                                 "the configured target before the Discovery copy can be observed";

  const ua::MdnsDiscoveryConfiguration* mdns = nullptr;
  for (const auto& entry : discoveryConfiguration)
  {
    const auto* candidate = dynamic_cast<const ua::MdnsDiscoveryConfiguration*>(entry.get());
    if (candidate != nullptr)
      mdns = candidate;
  }
  // MdnsDiscoveryConfiguration is the only carrier for serverCapabilities in the RegisterServer2
  // payload; no carrier means the Server reported no capabilities to the LocalDiscoveryServer.
  std::vector<std::string> discoveryCapabilities;
  if (mdns != nullptr)
  {
    for (const auto& capability : mdns->server_capabilities())
      discoveryCapabilities.push_back(std::string{string_view{capability}});
  }

  std::sort(pushCapabilities.begin(), pushCapabilities.end());
  std::sort(discoveryCapabilities.begin(), discoveryCapabilities.end());
  EXPECT_EQ(pushCapabilities, discoveryCapabilities)
    << "ServerConfiguration.ServerCapabilities and RegisterServer2.serverCapabilities are two copies "
       "of one logical state and must be identical";
}

// The same obligation read from the discovery side, which asks for one thing the test above does
// not: that the two copies do not merely agree at startup but *stay* agreed across a configuration
// change. Agreement between two constants is worth nothing if either can be moved afterwards.
//
// So the question is which surfaces can move a copy, and the answer is the branch this product took.
// The Discovery copy is built by `ua::app::DiscoveryRegistration`, which hands the registrar an
// empty `discoveryConfiguration` on every cycle (`ua_discovery_registration.cpp`), and the SDK
// exposes no Annex D capability list anywhere in `ServerConfig` - the `ServerCapabilities`
// struct there is the OPC 10000-5 6.3.2 limits Object, a different thing that shares a name. Part 12
// section 6.1 permits exactly this: RegisterServer2 "allows the Application to specify **zero or
// more** ServerCapability Identifiers". Reporting none is conforming, and no configuration can
// change it.
//
// That leaves the push copy, and one surface that could move it: a Client writing the Property. If
// that write landed, a Client could make the Server advertise `DA` in its AddressSpace while
// registering nothing with the LDS - the two copies driven apart by a Client, through the very
// Service the Property exists to mirror. This test pins the mechanism that prevents it: CurrentWrite
// is false and the write is refused, so the agreement above is a property of the Server rather than
// a snapshot taken before anyone touched it.
//
// It is deliberately falsifiable in the direction the product is likeliest to move. Wiring a
// capability list into the registration payload, or making the Property writable, without connecting
// the two breaks this test - which is the point, because Part 12 section 7.10.3 makes them one value.
// @verifies AC-SVR-DISC-DCM-001-CAPABILITIES-CONSISTENT
TEST_F(PushCertificateManagementTest, TheServerCapabilitiesPropertyCannotBeDrivenOutOfAgreementByAClient)
{
  ReadRequest accessRead;
  ReadValueId accessRv;
  accessRv.node_id() = NodeId{VariableId::ServerConfiguration_ServerCapabilities};
  accessRv.attribute_id() = static_cast<IntegerId>(AttributeId::AccessLevel);
  accessRead.nodes_to_read().push_back(std::move(accessRv));

  auto accessResp = mSession->attributes().read_sync(std::move(accessRead));
  ASSERT_EQ(accessResp.results().size(), 1u);
  const auto& accessDv = accessResp.results()[0];
  ASSERT_TRUE(!accessDv.status().has_value() || accessDv.status()->is_good())
    << "AccessLevel is a Mandatory Attribute of a Variable and must read Good";

  const auto* accessLevel = accessDv.value().try_as<uint8_t>();
  ASSERT_NE(accessLevel, nullptr) << "AccessLevel must be a Byte";
  EXPECT_FALSE(AccessLevelType{*accessLevel}.test(AccessLevelType::Bit::CurrentWrite))
    << "ServerConfiguration.ServerCapabilities advertises CurrentWrite. Part 12 section 7.10.3 "
       "defines its value as the value reported to the LocalDiscoveryServer over RegisterServer2, so "
       "a Client that can write it can make the AddressSpace claim a capability the Server never "
       "registered";

  // The advertisement and the enforcement are separate obligations: a Server may advertise
  // CurrentWrite false and still accept the write. Both are asked for here.
  Array<String> claimed;
  claimed.payload().push_back(String{"DA"});
  auto writeResp = mSession->attributes().write_sync(
    WriteRequestBuilder{}
      .write(NodeId{VariableId::ServerConfiguration_ServerCapabilities}, Variant{std::move(claimed)})
      .build());
  ASSERT_FALSE(writeResp.results().empty());
  EXPECT_TRUE(writeResp.results()[0].is_bad())
    << "a Client write of ServerConfiguration.ServerCapabilities was accepted with status "
    << writeResp.results()[0].as_uint32()
    << ". Nothing in the registration path consumes it, so the write moves the push copy alone and "
       "leaves the two copies of one logical state disagreeing";

  auto after = read_property(VariableId::ServerConfiguration_ServerCapabilities);
  std::vector<std::string> capabilitiesAfter;
  if (after.value().is_array())
  {
    for (const auto& capability : after.value().as<Array<String>>())
      capabilitiesAfter.push_back(std::string{string_view{capability}});
  }
  EXPECT_TRUE(std::find(capabilitiesAfter.begin(), capabilitiesAfter.end(), "DA") == capabilitiesAfter.end())
    << "the refused write still reached the Property: it now advertises DA, which no RegisterServer2 "
       "cycle reports";
}

// Part 12 Annex D asks that every advertised CapabilityIdentifier come from the CSV the Annex links,
// and is emphatic that the table printed beside the link is not that source: "Table 115 is a
// non-normative list of possible identifiers ... This CSV will be changed to meet the needs of
// companion specifications and will not trigger an update to this document. Application developers
// shall always use the linked CSV."
//
// This Server advertises no identifiers at all, so the obligation holds vacuously - and that is the
// whole of what can honestly be asserted here, so it is what is asserted. The alternative is worse
// than useless: validating a non-empty list against Table 115 transcribed into this file would be
// the exact inversion the Annex warns about, a test that certifies identifiers against the source
// the specification says is not the source, and it would pass while doing it.
//
// The value of the test is therefore in the day it fails. Advertising a capability - through the
// Property, through an `MdnsDiscoveryConfiguration` in the registration payload, or through a
// configuration surface that feeds either - turns this red, and the fix is not to relax it but to
// replace it with a check against the CSV. Recording that here is the point: the obligation is not
// discharged by the emptiness, it is deferred by it, and the deferral has a tripwire.
// @verifies AC-SVR-DISC-CAP-001-NORMATIVE-CAPABILITIES
TEST_F(PushCertificateManagementTest, NoCapabilityIdentifierIsAdvertisedFromAnyUnvalidatedSource)
{
  auto pushDv = read_property(VariableId::ServerConfiguration_ServerCapabilities);
  ASSERT_TRUE(!pushDv.status().has_value() || pushDv.status()->is_good())
    << "ServerConfiguration.ServerCapabilities is a Mandatory Property and must read Good";

  std::vector<std::string> advertised;
  if (pushDv.value().is_array())
  {
    for (const auto& capability : pushDv.value().as<Array<String>>())
      advertised.push_back(std::string{string_view{capability}});
  }

  EXPECT_TRUE(advertised.empty())
    << "the Server advertises " << advertised.size() << " CapabilityIdentifier(s), the first being '"
    << (advertised.empty() ? "" : advertised.front())
    << "'. Part 12 Annex D requires each to come from "
       "http://www.opcfoundation.org/UA/schemas/ServerCapabilities.csv, which this repository does "
       "not carry, so nothing here can confirm the identifier is valid. Replace this test with one "
       "that checks against the CSV - do not transcribe Table 115, which the Annex marks "
       "non-normative and expects to fall behind the CSV";
}

// ===========================================================================
// GDS push scenarios (OPC 10000-12 7.7, Figures 18, 19 and 22): the test client acts as the GDS. Each
// scenario asserts that the GDS RECEIVES the ApplyChanges response (7.10.6) and ends with what a third party
// observes on a new channel.
// ===========================================================================

namespace
{

/// A second OPC UA application with its own certificate and store, unknown to the server until a push
/// trusts it.
struct OtherApplication
{
  std::shared_ptr<CertificateStore> store;
  std::shared_ptr<const X509Certificate> certificate;
  std::optional<Client> client;
};

}  // namespace

class GdsPushScenarios : public PushCertificateManagementTest
{
protected:
  void TearDown() override
  {
    if (mOther.client)
      mOther.client.reset();
    PushCertificateManagementTest::TearDown();
  }

  /// Opens a SignAndEncrypt channel from @p client that expects the server to present @p serverCertificate.
  static CoreClient::SecureChannelResult try_open(
    Client& client, const std::string& endpointUrl, std::shared_ptr<const X509Certificate> serverCertificate)
  {
    CoreClient::OpenChannelConfig config;
    config.endpointUrl = endpointUrl;
    config.securityMode = MessageSecurityMode::SignAndEncrypt;
    config.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    config.serverCertificate = std::move(serverCertificate);
    return client.core().try_open_channel_sync(std::move(config));
  }

  /// A client application the server does not trust; it trusts the server's current certificate.
  void make_other_application()
  {
    Crypto::Name subject;
    subject.commonName = "GDS push other application";
    Crypto::SubjectAlternateName alternateName;
    alternateName.uris.push_back("urn:test:gds:push:other");
    alternateName.hostnames.push_back("localhost");
    auto identity = mCrypto->try_create_self_signed_application_instance_certificate_sync(
      subject, UtcTime{2050, 1, 1, 0, 0, 0}, alternateName, CertificateType::RsaSha256Application, 2048);
    ASSERT_TRUE(identity.is_good());
    auto [keys, certificate] = std::move(identity).value();
    mOther.certificate = certificate;
    const auto storePath = mTempDir / "other_client_store";
    std::filesystem::create_directories(storePath);
    mOther.store =
      CertificateStoreFiles::create(mClientThreadPool.executor(), mCrypto, {.trustListPath = storePath});
    CertificateStore::ApplicationCertificate own;
    own.certificateType = CertificateType::RsaSha256Application;
    own.certificate = certificate;
    own.keys = std::move(keys);
    mOther.store->add_to_application_certificates_sync(own);
    mOther.store->add_to_trusted_certificates_sync(mServerCert);
    auto configuration = ua::test_utils::create_test_config();
    configuration.application_description_part().applicationUri = "urn:test:gds:push:other";
    mOther.client.emplace(Client::create(mClientThreadPool.executor(),
      client::CreateConfig{
        .identity = ApplicationIdentity::load_default(), .application = std::move(configuration)},
      ua::client::ClientComponents{
        .crypto = mCrypto, .applicationGroupCertificateStore = mOther.store, .logSink = test_log_sink()}));
  }

  /// The CA-signed RSA certificate a GDS issues for this server: the server's ApplicationUri and the host the
  /// clients dial.
  Crypto::SubjectAlternateName server_names() const
  {
    Crypto::SubjectAlternateName names;
    names.uris.push_back("urn:test:compliance:server");
    names.hostnames.push_back("localhost");
    names.ipAddresses.push_back(boost::asio::ip::make_address("127.0.0.1"));
    return names;
  }

  OtherApplication mOther;
};

// PUSH-1 (Figures 18 and 19 left): the GDS asks the server for a signing request, its CA signs it, the GDS
// pushes the certificate and applies the change. The GDS receives the ApplyChanges response (7.10.6: the
// response is sent before the channels renegotiate) and every new channel is served with the new certificate:
// a client that expects it connects, and a client that still expects the old one is refused. Falsifiable: a
// server that closes the caller's channel before the response is written (BR-14) fails the first assertion.
// @relation(AC-SVR-PULLCRT-016-THE-APPLYCHANGES-CALLER-RECEIVES-THE-RESPONSE-BEFORE-ITS-CHANNEL-CLOSES, scope=function)
TEST_F(GdsPushScenarios, ACertificateRotationIsAnsweredAndPresentedOnEveryNewChannel)
{
  mClientCertStore->add_to_trusted_certificates_sync(mCaCert);
  auto csr = call_create_signing_request(
    NodeId{}, rsa_cert_type_id(), String{}, true, ByteString(std::vector<byte>(32, byte{0xAB})));
  ASSERT_TRUE(csr.is_good()) << ua::format(csr.status_code());
  const auto issued = mPki->sign_csr(
    csr.value(), mCaKeys, mCaCert, CertificateSignatureAlgorithm::RsaPkcs15Sha2256, server_names());
  auto updated =
    call_update_certificate(NodeId{}, rsa_cert_type_id(), issued->der_encoding(), {mCaCert->der_encoding()});
  ASSERT_TRUE(updated.is_good()) << ua::format(updated.status_code());

  const auto applied = call_apply_changes();
  EXPECT_TRUE(applied.is_good()) << "the GDS receives the ApplyChanges response: "
                                 << ua::format(applied.status_code());

  auto withNew = try_open(*mClient, mEndpointUrl, issued);
  EXPECT_TRUE(withNew.is_good()) << "a new channel is served with the pushed certificate: "
                                 << ua::format(withNew.status_code());
  auto withOld = try_open(*mClient, mEndpointUrl, mServerCert);
  EXPECT_TRUE(withOld.is_bad()) << "the replaced certificate is no longer presented";
  mSession.reset();
  mChannel.reset();
}

// PUSH-2 (Figure 19 right): the GDS generates the key pair and pushes it with the certificate (PEM). The
// server answers ApplyChanges and then serves channels with the new certificate, which it can only do while
// holding the pushed private key (a SignAndEncrypt OpenSecureChannel is signed with it).
// @relation(AC-SVR-PULLCRT-016-THE-APPLYCHANGES-CALLER-RECEIVES-THE-RESPONSE-BEFORE-ITS-CHANNEL-CLOSES, scope=function)
TEST_F(GdsPushScenarios, AGdsGeneratedKeyPairIsInUseAfterApplyChanges)
{
  mClientCertStore->add_to_trusted_certificates_sync(mCaCert);
  auto keys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  const auto issued = create_app_cert(keys, {"urn:test:compliance:server"}, {"localhost"}, "GdsKeyServer");
  auto updated = call_update_certificate(NodeId{},
    rsa_cert_type_id(),
    issued->der_encoding(),
    {mCaCert->der_encoding()},
    String{"PEM"},
    keys->private_key_pem());
  ASSERT_TRUE(updated.is_good()) << ua::format(updated.status_code());

  const auto applied = call_apply_changes();
  EXPECT_TRUE(applied.is_good()) << ua::format(applied.status_code());
  auto withNew = try_open(*mClient, mEndpointUrl, issued);
  EXPECT_TRUE(withNew.is_good()) << "the server signs with the pushed key: "
                                 << ua::format(withNew.status_code());
  mSession.reset();
  mChannel.reset();
}

// PUSH-4 (Figure 18 TrustList write, 7.8.2): a TrustList the GDS writes replaces the server's trust. The
// pushed list drops this client's certificate; after ApplyChanges (answered) a new channel from the client is
// refused, while the CA's certificate in the list keeps the server's own chain valid.
// @relation(AC-SVR-PULLCRT-016-THE-APPLYCHANGES-CALLER-RECEIVES-THE-RESPONSE-BEFORE-ITS-CHANNEL-CLOSES, scope=function)
TEST_F(GdsPushScenarios, AWithdrawnTrustTakesEffectForNewChannels)
{
  auto control = try_open(*mClient, mEndpointUrl, mServerCert);
  ASSERT_TRUE(control.is_good()) << "control: the client is trusted before the push";

  TrustListDataType trustList;
  trustList.specified_lists() = 0x01;  // TrustedCertificates
  trustList.trusted_certificates().push_back(mCaCert->der_encoding());
  memory_stream_device::Dynamic device(65535, /*reserve=*/true);
  MemoryStream<memory_stream_device::Dynamic> stream(device);
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);
  encoder.encode(EncodingLimits{}.stack_depth(), trustList);
  auto handle = call_open(0x06);  // Write | EraseExisting
  ASSERT_TRUE(handle.is_good()) << ua::format(handle.status_code());
  ASSERT_TRUE(call_write_file(handle.value(), device.get_data()).is_good());
  auto closed = call_close_and_update(handle.value());
  ASSERT_TRUE(closed.is_good()) << ua::format(closed.status_code());

  const auto applied = call_apply_changes();
  EXPECT_TRUE(applied.is_good()) << ua::format(applied.status_code());
  auto refused = try_open(*mClient, mEndpointUrl, mServerCert);
  EXPECT_TRUE(refused.is_bad()) << "the server no longer trusts the client the GDS withdrew";
  mSession.reset();
  mChannel.reset();
}

// PUSH-6 (7.10.9 GetRejectedList, 7.8.2.4 AddCertificate): an application the server does not trust is
// refused and recorded; the GDS reads the rejected list, trusts that certificate and applies the change; the
// application then connects.
// @relation(AC-SVR-PULLCRT-016-THE-APPLYCHANGES-CALLER-RECEIVES-THE-RESPONSE-BEFORE-ITS-CHANNEL-CLOSES, scope=function)
TEST_F(GdsPushScenarios, ARejectedApplicationIsAdmittedThroughTheRejectedList)
{
  make_other_application();
  auto refused = try_open(*mOther.client, mEndpointUrl, mServerCert);
  ASSERT_TRUE(refused.is_bad()) << "control: the server does not trust the other application";

  auto rejected = call_get_rejected_list();
  ASSERT_TRUE(rejected.is_good()) << ua::format(rejected.status_code());
  const auto found = std::ranges::find(rejected.value(), mOther.certificate->der_encoding());
  ASSERT_NE(found, rejected.value().end()) << "the refused certificate is in the rejected list";

  // OPC 10000-12 7.8.2.4: AddCertificate changes the TrustList at once - no transaction, so no ApplyChanges
  // (it would answer Bad_NothingToDo, 7.10.6). RATIFIED (owner report 2026-10-03, BR-13).
  auto added = call_add_certificate(*found, true);
  ASSERT_TRUE(added.is_good()) << ua::format(added.status_code());

  auto admitted = try_open(*mOther.client, mEndpointUrl, mServerCert);
  EXPECT_TRUE(admitted.is_good()) << "the GDS trusted the rejected application: "
                                  << ua::format(admitted.status_code());
  mSession.reset();
  mChannel.reset();
}

// ===========================================================================
// Push management turned off (owner decision Q3, 2026-10-04)
// ===========================================================================

class PushManagementOffTest : public PushCertificateManagementTest
{
protected:
  void configure_server_create_config(server::CreateConfig& cfg) override
  {
    PushCertificateManagementTest::configure_server_create_config(cfg);
    cfg.server.pushCertificateManagementEnabled = false;
  }
};

// A server provisioned by pull management turns push management off: it publishes no ServerConfiguration
// Object (the Server Object lists none, and a Call on its Methods finds no node), so nothing can change its
// certificates or trust lists through the server. Secured connections work as before (this fixture's
// SignAndEncrypt session). Falsifiable: the former server always published and wired the push model.
// @verifies AC-SVR-PULLCRT-042-PUSH-MANAGEMENT-OFF-PUBLISHES-NO-SERVER-CONFIGURATION
TEST_F(PushManagementOffTest, TheServerPublishesNoServerConfigurationModel)
{
  auto serverResp = mSession->view().browse_sync(browse(NodeId{ObjectId::Server}));
  ASSERT_EQ(serverResp.results().size(), 1u);
  ASSERT_TRUE(serverResp.results()[0].status_code().is_good());
  EXPECT_TRUE(browse_lists_child(serverResp.results()[0], "ServerStatus"))
    << "control: the Server Object browses";
  EXPECT_FALSE(browse_lists_child(serverResp.results()[0], "ServerConfiguration"));

  auto configResp = mSession->view().browse_sync(browse(serverConfigObjectId));
  ASSERT_EQ(configResp.results().size(), 1u);
  EXPECT_EQ(configResp.results()[0].status_code(), StatusCode{Status::BadNodeIdUnknown});

  // Part 4 Call: an unknown Object or Method, not a push service's refusal (Bad_UserAccessDenied,
  // Bad_InvalidState, Bad_NothingToDo).
  const auto unknown = [](const StatusCode& code)
  {
    return code == StatusCode{Status::BadNodeIdUnknown} || code == StatusCode{Status::BadMethodInvalid};
  };
  auto applied = call_server_config_method(NodeId{MethodId::ServerConfiguration_ApplyChanges});
  EXPECT_TRUE(unknown(applied.status_code())) << "0x" << std::hex << applied.status_code().as_uint32();
  Array<Variant> args;
  args.resize(1);
  args[0] = Variant{uint8_t{0x06}};
  auto opened = call_trust_list_method(
    NodeId{MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_Open},
    std::move(args));
  EXPECT_TRUE(unknown(opened.status_code())) << "0x" << std::hex << opened.status_code().as_uint32();
}
