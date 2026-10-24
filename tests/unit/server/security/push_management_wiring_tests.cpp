// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Unit tests for wire_push_management - verifying dynamic properties and audit events.

#include <gtest/gtest.h>

#include <cstring>
#include <chrono>
#include <thread>

#include "ua_push_management_wiring.h"
#include "fake_certificate_store.h"

#include "ua_application_configuration.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_certificate_store.h"
#include "ua_certificate_update_requested_audit_event_payload.h"
#include "ua_certificate_updated_audit_event_payload.h"
#include "ua_binary_codec.h"
#include "ua_codec_namespace_context.h"
#include "ua_data_type_registration.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_crypto.h"
#include "ua_encoding_limits.h"
#include "ua_sinks.h"
#include "ua_file_stream.h"
#include "ua_memory_stream.h"
#include "ua_method_id.h"
#include "ua_namespace_array.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_security_policy.h"
#include "ua_structure_factory.h"
#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>
#include "ua_trust_list_data_type.h"
#include "ua_trust_list_update_requested_audit_event_payload.h"
#include "ua_trust_list_updated_audit_event_payload.h"
#include "ua_variable_id.h"
#include "ua_nodeset_import_engine.h"
#include "ua_nodeset_parser.h"
#include "ua_value_source.h"
#include "posting_writes_namespace.h"
#include "test_pki_helpers.h"

#include "ua_fmt.h"
#include <fmt/format.h>
#include <fmt/ranges.h>

#include <atomic>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace ua;
using namespace std::chrono_literals;

// ADL-found by gtest for assertion messages (defined in trust_list_manager_tests.cpp,
// but not in a header - must be declared here for the compiler to find it).
namespace ua
{
extern std::ostream& operator<<(std::ostream& os, const StatusCode& sc);
}

namespace
{

using InMemoryFakeCertificateStore = ua::test_helpers::InMemoryFakeCertificateStore;

// ============================================================================
// FakeEventSink - records emitted audit events for verification
// ============================================================================

class FakeEventSink : public EventSink
{
public:
  void emit(BaseEvent& event) override
  {
    std::lock_guard lock{mMutex};
    mEmitted.push_back(event.clone());
  }

  size_t count() const
  {
    std::lock_guard lock{mMutex};
    return mEmitted.size();
  }

  BaseEvent* at(size_t index) const
  {
    std::lock_guard lock{mMutex};
    return mEmitted.at(index).get();
  }

  void clear()
  {
    std::lock_guard lock{mMutex};
    mEmitted.clear();
  }

  template<typename T>
  size_t count_of() const
  {
    std::lock_guard lock{mMutex};
    size_t n = 0;
    for (auto& e : mEmitted)
    {
      if (dynamic_cast<const T*>(e.get()))
        ++n;
    }
    return n;
  }

private:
  mutable std::mutex mMutex;
  std::vector<std::unique_ptr<BaseEvent>> mEmitted;
};

// ============================================================================
// Helper: load NS0 into an address space
// ============================================================================

void load_ns0(const EncodingLimits& limits, AddressSpace& addressSpace, StructureFactory& structureFactory)
{
  auto lookupFn = namespace_array_utils::get_index_lookup_function(addressSpace);
  const CodecNamespaceContext nsConfig{std::move(lookupFn), {}, {}, {}};
  register_ua_data_types_with_factory(nsConfig, &structureFactory, &structureFactory);

  FileStream inputStream{"NodeSet2.xml"};
  inputStream.open_for_read();
  auto nodeSets = xml::nodeset::Parser::parse(limits,
    inputStream,
    structureFactory,
    addressSpace.namespace_array(),
    addressSpace.server_array(),
    xml::nodeset::Parser::GetDependentModelCallback{});

  auto importer = xml::nodeset::ImportEngine::create(limits, addressSpace, nodeSets, {});
  importer->import_all_sync({}, {});
}

// ============================================================================
// Test fixture
// ============================================================================

class PushManagementWiringTest : public ::testing::Test
{
protected:
  /// One pool per suite run: a derived suite (PushManagementLateEndpointPolicies) runs this SetUpTestSuite
  /// again after the base suite's TearDownTestSuite joined its pool, and a joined pool runs nothing more.
  static std::optional<boost::asio::thread_pool> sPool;
  static std::optional<AddressSpace> sAddressSpace;
  static EncodingLimits sLimits;
  static StructureFactory sStructureFactory;
  static std::shared_ptr<const Crypto> sCrypto;
  static std::unique_ptr<TestPki> sPki;
  static std::shared_ptr<const AsymmetricKeyPair> sCaKeys;
  static std::shared_ptr<const X509Certificate> sCaCert;
  static std::shared_ptr<const AsymmetricKeyPair> sLeafKeys;
  static std::shared_ptr<const X509Certificate> sLeafCert;
  static std::shared_ptr<const X509Crl> sCrl;

  static void SetUpTestSuite()
  {
    const auto cfg = ApplicationConfig::load_default();
    sLimits = make_encoding_limits(cfg);

    sPool.emplace(2);
    sAddressSpace.emplace(AddressSpace::create("uri:test:push", sPool->executor()));
    load_ns0(sLimits, *sAddressSpace, sStructureFactory);

    sCrypto = create_default_crypto([]() { return ua::SecureString{"password"}; });
    sPki = std::make_unique<TestPki>(sCrypto);

    sCaKeys = sCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    sCaCert = sPki->create_root_ca(sCaKeys);

    sLeafKeys = sCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    auto now = DateTime::now();
    sLeafCert = sPki->create_leaf_cert(sLeafKeys,
      sCaKeys,
      sCaCert,
      now,
      DateTime{now.value() + std::chrono::days{30}},
      {"urn:test:server"},
      {"localhost"},
      "TestLeaf");

    sCrl = sPki->create_crl(sCaCert, sCaKeys, {});
  }

  static void TearDownTestSuite()
  {
    sPki.reset();
    sAddressSpace.reset();
    sPool->join();
    sPool.reset();
  }

  void SetUp() override
  {
    mFakeStore = std::make_shared<InMemoryFakeCertificateStore>();
    mFakeStore->trustedCerts.push_back(sLeafCert);
    mFakeStore->issuerCerts.push_back(sCaCert);
    mFakeStore->trustedCrls.push_back(sCrl);
  }

  void TearDown() override
  {
    if (mComponents.trustList)
      mComponents.trustList->shutdown();
    if (mComponents.certificatePushService)
      mComponents.certificatePushService->shutdown();
  }

  AddressSpace& as()
  {
    return mIsolatedAddressSpace ? *mIsolatedAddressSpace : *sAddressSpace;
  }

  std::mutex mReevaluationMutex;
  std::vector<std::pair<NodeId, server::MethodResponseCorrelation>> mReevaluations;

  std::vector<std::pair<NodeId, server::MethodResponseCorrelation>> reevaluations()
  {
    const std::lock_guard lock{mReevaluationMutex};
    return mReevaluations;
  }

  void wire(
    std::weak_ptr<EventSink> eventSink = {}, std::optional<boost::asio::any_io_executor> executor = {})
  {
    PushManagementWiringParams params{
      .addressSpace = as(),
      .certificateStore = mFakeStore,
      .crypto = sCrypto,
      .executor = executor.value_or(sPool->executor()),
      .logger = Logger{},
      .applicationUri = "urn:test:server",
      .hostnames = {"localhost"},
      .closeAllChannels =
        [](const NodeId&, server::MethodResponseCorrelation, std::function<void(VoidResult)> callback)
      { callback(VoidResult{}); },
      .reevaluateCertificates =
        [this](const NodeId& origin,
          server::MethodResponseCorrelation correlation,
          std::function<void(VoidResult)>
            callback)
      {
        {
          const std::lock_guard lock{mReevaluationMutex};
          mReevaluations.push_back({origin, correlation});
        }
        callback(VoidResult{});
      },
      .requestShutdown = [this] { mShutdownRequested = true; },
      .eventSink = eventSink,
      .serverId = "TestServer",
      .maxTrustListSize = 65535,
      .activityTimeout = 60000ms,
      .sessionExists = mSessionExists,
    };

    params.servedEndpointPolicies = mServedEndpointPolicies;
    params.userTokenCertificateStore = mUserTokenStore;
    mComponents = wire_push_management(std::move(params));
  }

  /// Read a dynamic variable value via the VariableAccessor.
  DataValue read_variable(VariableId variableId)
  {
    auto findResult = as().try_find_node_sync(NodeId{variableId});
    EXPECT_TRUE(findResult) << "Could not find variable node";
    if (!findResult)
      return {};

    auto accessor = findResult.value().as<VariableAccessor>();
    EXPECT_TRUE(accessor) << "Node is not a VariableAccessor";
    if (!accessor)
      return {};

    auto readResult = accessor->try_read_value_sync();
    EXPECT_TRUE(readResult) << "Read failed: " << readResult.status_code();
    return readResult.is_good() ? std::move(readResult).value() : DataValue{};
  }

  // --- Sync wrappers for TrustList methods ---

  Result<uint32_t> open_sync(const NodeId& sessionId, uint8_t mode)
  {
    std::promise<Result<uint32_t>> p;
    mComponents.trustList->open_async(
      sessionId, mode, [&p](Result<uint32_t> r) { p.set_value(std::move(r)); });
    return p.get_future().get();
  }

  VoidResult close_sync(const NodeId& sessionId, uint32_t handle)
  {
    std::promise<VoidResult> p;
    mComponents.trustList->close_async(sessionId, handle, [&p](VoidResult r) { p.set_value(std::move(r)); });
    return p.get_future().get();
  }

  VoidResult add_certificate_sync(const NodeId& sessionId, ByteString cert, bool isTrusted)
  {
    std::promise<VoidResult> p;
    mComponents.trustList->add_certificate_async(
      sessionId, std::move(cert), isTrusted, [&p](VoidResult r) { p.set_value(std::move(r)); });
    return p.get_future().get();
  }

  VoidResult write_sync(const NodeId& sessionId, uint32_t handle, const TrustListDataType& trustList)
  {
    memory_stream_device::Dynamic device(65535, true);
    MemoryStream<memory_stream_device::Dynamic> stream(device);
    UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);
    encoder.encode(EncodingLimits{}.stack_depth(), trustList);
    std::promise<VoidResult> p;
    mComponents.trustList->write_async(
      sessionId, handle, ByteString{device.get_data()}, [&p](VoidResult r) { p.set_value(std::move(r)); });
    return p.get_future().get();
  }

  std::optional<ua::detail::TrustListContent> staged_lists_sync()
  {
    std::promise<std::optional<ua::detail::TrustListContent>> p;
    mComponents.trustList->staged_lists_async(
      [&p](std::optional<ua::detail::TrustListContent> r) { p.set_value(std::move(r)); });
    return p.get_future().get();
  }

  /// The Object a wired Method is a component of: the source of the Method's inverse HasComponent Reference.
  static NodeId object_of(const NodeAccessor& method)
  {
    for (const Reference& reference : method.get_references_sync())
    {
      if (!reference.is_forward() && reference.type_id() == NodeId{ReferenceTypeId::HasComponent})
        return reference.target_id().node_id();
    }
    return NodeId{};
  }

  /// Call a wired method node through its MethodAccessor, on the Object it is a component of, returning the
  /// CallResult.
  CallResult call_method(MethodId methodId, CallMethodRequest request,
    MessageSecurityMode securityMode = MessageSecurityMode::SignAndEncrypt,
    optional<uint32_t> serverRequestId = 41)
  {
    auto findResult = as().try_find_node_sync(NodeId{methodId});
    if (!findResult)
      return CallResult{StatusCode{Status::BadNodeIdUnknown}};
    const auto method = findResult.value().as<MethodAccessor>();
    if (!method)
      return CallResult{StatusCode{Status::BadMethodInvalid}};
    request.method_id() = NodeId{methodId};
    request.object_id() = object_of(findResult.value());

    auto context = std::make_shared<MethodCallContext>();
    context->sessionId = mSessionA;
    if (serverRequestId)
      ua::detail::MethodCallContextInternalAccess::set_response_correlation(*context, {1, *serverRequestId});
    context->channelSecurityMode = securityMode;

    std::promise<CallResult> promise;
    method->call_async(
      request, context, [&promise](CallResult result) { promise.set_value(std::move(result)); });
    return promise.get_future().get();
  }

  /// Stage a certificate update via the wired UpdateCertificate handler using the
  /// PEM private-key path. Pushes the matching app cert into the fake store so
  /// type validation and the key-vs-cert public-key check pass.
  CallResult stage_certificate_update()
  {
    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::RsaSha256Application;
    appCert.certificate = sLeafCert;
    appCert.keys = sLeafKeys;
    mFakeStore->appCerts.push_back(appCert);

    CallMethodRequest request;
    request.input_arguments().resize(6);
    request.input_arguments()[0] =
      Variant{NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup}};
    request.input_arguments()[1] =
      Variant{NodeId{0, static_cast<uint32_t>(ObjectTypeId::RsaSha256ApplicationCertificateType)}};
    request.input_arguments()[2] = Variant{sLeafCert->der_encoding()};
    request.input_arguments()[3] = Variant{Array<ByteString>{}};
    request.input_arguments()[4] = Variant{String{"PEM"}};
    request.input_arguments()[5] = Variant{sLeafKeys->private_key_pem()};
    return call_method(MethodId::ServerConfiguration_UpdateCertificate, std::move(request));
  }

  /// SVR-PULLCRT-026 helper: invoke UpdateCertificate for `typeId` with the candidate
  /// `certDer` + its matching PEM `privateKey`. Pushes an app-cert tagged `storeType`
  /// into the fake store so the SVR-PULLCRT-008 type-in-group check passes and the
  /// key-shape gate (this row) is what the call actually exercises.
  CallResult call_update_certificate_for_type(
    ObjectTypeId typeId, CertificateType storeType, const ByteString& certDer, const ByteString& privateKey)
  {
    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = storeType;
    appCert.certificate = sLeafCert;  // only the type tag matters for type-in-group validation
    appCert.keys = sLeafKeys;
    mFakeStore->appCerts.push_back(appCert);

    CallMethodRequest request;
    request.input_arguments().resize(6);
    request.input_arguments()[0] =
      Variant{NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup}};
    request.input_arguments()[1] = Variant{NodeId{0, static_cast<uint32_t>(typeId)}};
    request.input_arguments()[2] = Variant{certDer};
    request.input_arguments()[3] = Variant{Array<ByteString>{}};
    request.input_arguments()[4] = Variant{String{"PEM"}};
    request.input_arguments()[5] = Variant{privateKey};
    return call_method(MethodId::ServerConfiguration_UpdateCertificate, std::move(request));
  }

  /// Create a CA-signed leaf certificate whose subject key pair is `subjectKeys`.
  std::shared_ptr<const X509Certificate> make_leaf(std::shared_ptr<const AsymmetricKeyPair> subjectKeys)
  {
    auto now = DateTime::now();
    return sPki->create_leaf_cert(std::move(subjectKeys),
      sCaKeys,
      sCaCert,
      now,
      DateTime{now.value() + std::chrono::days{30}},
      {"urn:test:server"},
      {"localhost"},
      "ShapeLeaf");
  }

  std::optional<AddressSpace> mIsolatedAddressSpace;
  std::shared_ptr<InMemoryFakeCertificateStore> mFakeStore;
  std::shared_ptr<InMemoryFakeCertificateStore> mUserTokenStore;  // wired as the user-token store when set
  PushManagementComponents mComponents;
  NodeId mSessionA{1, 100u};
  NodeId mSessionB{1, 200u};
  bool mShutdownRequested{false};
  // The server's Session lookup as the wiring receives it; null treats every Session as existing.
  std::function<bool(const NodeId&)> mSessionExists;
  // The served endpoints' SecurityPolicies as the wiring receives them; null means no policy check.
  std::function<std::vector<std::pair<std::string, std::shared_ptr<const SecurityPolicy>>>()>
    mServedEndpointPolicies;
};

// Static member definitions
std::optional<boost::asio::thread_pool> PushManagementWiringTest::sPool;
std::optional<AddressSpace> PushManagementWiringTest::sAddressSpace;
EncodingLimits PushManagementWiringTest::sLimits;
StructureFactory PushManagementWiringTest::sStructureFactory;
std::shared_ptr<const Crypto> PushManagementWiringTest::sCrypto;
std::unique_ptr<TestPki> PushManagementWiringTest::sPki;
std::shared_ptr<const AsymmetricKeyPair> PushManagementWiringTest::sCaKeys;
std::shared_ptr<const X509Certificate> PushManagementWiringTest::sCaCert;
std::shared_ptr<const AsymmetricKeyPair> PushManagementWiringTest::sLeafKeys;
std::shared_ptr<const X509Certificate> PushManagementWiringTest::sLeafCert;
std::shared_ptr<const X509Crl> PushManagementWiringTest::sCrl;

// ============================================================================
// Test: Dynamic property - LastUpdateTime
// ============================================================================

TEST_F(PushManagementWiringTest, LastUpdateTimeIsInitiallyZero)
{
  wire();

  auto dv = read_variable(
    VariableId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_LastUpdateTime);
  auto* timestamp = dv.value().try_as<DateTime>();
  ASSERT_NE(timestamp, nullptr);
  EXPECT_EQ(*timestamp, DateTime{});
}

TEST_F(PushManagementWiringTest, LastUpdateTimeUpdatedAfterAddCertificate)
{
  wire();

  auto before = DateTime::now();

  auto certDer = sLeafCert->der_encoding();
  auto addResult = add_certificate_sync(mSessionA, certDer, true);
  ASSERT_TRUE(addResult) << "AddCertificate failed: " << addResult.status_code();

  auto dv = read_variable(
    VariableId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_LastUpdateTime);
  auto* timestamp = dv.value().try_as<DateTime>();
  ASSERT_NE(timestamp, nullptr);
  EXPECT_NE(*timestamp, DateTime{});
  EXPECT_GE(timestamp->value(), before.value());
}

// ============================================================================
// Test: Dynamic property - OpenCount
// ============================================================================

TEST_F(PushManagementWiringTest, OpenCountIsInitiallyZero)
{
  wire();

  auto dv = read_variable(
    VariableId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_OpenCount);
  auto* count = dv.value().try_as<uint16_t>();
  ASSERT_NE(count, nullptr);
  EXPECT_EQ(*count, 0);
}

TEST_F(PushManagementWiringTest, OpenCountIncrementsOnOpenDecrementsOnClose)
{
  wire();

  // Open the trust list in read mode (mode = 1)
  auto openResult = open_sync(mSessionA, 1);
  ASSERT_TRUE(openResult) << "Open failed: " << openResult.status_code();
  auto fileHandle = openResult.value();

  auto dv = read_variable(
    VariableId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_OpenCount);
  auto* count = dv.value().try_as<uint16_t>();
  ASSERT_NE(count, nullptr);
  EXPECT_EQ(*count, 1);

  // Close the trust list
  auto closeResult = close_sync(mSessionA, fileHandle);
  ASSERT_TRUE(closeResult) << "Close failed: " << closeResult.status_code();

  dv = read_variable(
    VariableId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_OpenCount);
  count = dv.value().try_as<uint16_t>();
  ASSERT_NE(count, nullptr);
  EXPECT_EQ(*count, 0);
}

// ============================================================================
// Test: Audit events - TrustList audit events on AddCertificate via wired handler
// ============================================================================

TEST_F(PushManagementWiringTest, AddCertificateEmitsTrustListAuditEvents)
{
  auto sink = std::make_shared<FakeEventSink>();
  wire(sink);

  CallMethodRequest request;
  request.input_arguments().resize(2);
  request.input_arguments()[0] = Variant{sLeafCert->der_encoding()};
  request.input_arguments()[1] = Variant{true};

  auto callResult = call_method(
    MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_AddCertificate,
    std::move(request));
  ASSERT_TRUE(callResult) << "Wired AddCertificate call failed: " << callResult.status_code();
  EXPECT_TRUE(callResult.value().status_code().is_good())
    << "AddCertificate result status: " << callResult.value().status_code();

  EXPECT_GE(sink->count_of<TrustListUpdateRequestedAuditEventPayload>(), 1u)
    << "Expected TrustListUpdateRequestedAuditEventPayload";
  EXPECT_GE(sink->count_of<TrustListUpdatedAuditEventPayload>(), 1u)
    << "Expected TrustListUpdatedAuditEventPayload";
}

// OPC 10000-12 7.8.2.3: "When the TrustList changes the Server shall re-evaluate the Certificate associated
// with any open Sessions". AddCertificate and RemoveCertificate change it at once (7.8.2.4 / 7.8.2.5), so the
// wired Methods trigger the re-evaluation, naming the caller and its response correlation, before they
// answer. Falsifiable: a handler that completes directly re-evaluates nothing.
// @relation(AC-SVR-PULLCRT-016-A-TRUSTLIST-CHANGE-CLOSES-ONLY-WHAT-IT-INVALIDATES, scope=function)
TEST_F(PushManagementWiringTest, AddAndRemoveCertificateReevaluateBeforeTheyAnswer)
{
  wire();
  CallMethodRequest add;
  add.input_arguments().resize(2);
  add.input_arguments()[0] = Variant{sLeafCert->der_encoding()};
  add.input_arguments()[1] = Variant{true};
  auto added = call_method(
    MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_AddCertificate,
    std::move(add));
  ASSERT_TRUE(added);
  ASSERT_TRUE(added.value().status_code().is_good()) << added.value().status_code();
  auto seen = reevaluations();
  ASSERT_EQ(seen.size(), 1u) << "re-evaluated before the answer";
  EXPECT_EQ(seen[0].first, mSessionA);
  EXPECT_EQ(seen[0].second, (server::MethodResponseCorrelation{1, 41}));

  CallMethodRequest remove;
  remove.input_arguments().resize(2);
  remove.input_arguments()[0] =
    Variant{String{fmt::format("{:02X}", fmt::join(sLeafCert->thumbprint(), ""))}};
  remove.input_arguments()[1] = Variant{true};
  auto removed = call_method(
    MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_RemoveCertificate,
    std::move(remove));
  ASSERT_TRUE(removed);
  ASSERT_TRUE(removed.value().status_code().is_good()) << removed.value().status_code();
  EXPECT_EQ(reevaluations().size(), 2u);
}

// 7.8.2.4: AddCertificate "returns Bad_TransactionPending if a transaction is in progress" - here the
// caller's own, opened by an UpdateCertificate - changes nothing and re-evaluates nothing.
// @relation(AC-SVR-PULLCRT-036-ADD-AND-REMOVE-ARE-APPLIED-AT-ONCE-AND-REFUSED-DURING-A-TRANSACTION, scope=function)
TEST_F(PushManagementWiringTest, AddCertificateIsRefusedDuringTheCallersOwnTransaction)
{
  wire();
  auto staged = stage_certificate_update();
  ASSERT_TRUE(staged);
  ASSERT_TRUE(staged.value().status_code().is_good());
  const auto trustedBefore = mFakeStore->trustedCerts.size();

  CallMethodRequest add;
  add.input_arguments().resize(2);
  add.input_arguments()[0] = Variant{sLeafCert->der_encoding()};
  add.input_arguments()[1] = Variant{true};
  auto added = call_method(
    MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_AddCertificate,
    std::move(add));
  ASSERT_TRUE(added);
  EXPECT_EQ(added.value().status_code(), StatusCode{Status::BadTransactionPending});
  EXPECT_EQ(mFakeStore->trustedCerts.size(), trustedBefore);
  EXPECT_TRUE(reevaluations().empty());
}

// ============================================================================
// Test: Audit events - TrustListUpdated has correct trust_list_id
// ============================================================================

TEST_F(PushManagementWiringTest, TrustListUpdatedAuditEventHasTrustListId)
{
  auto sink = std::make_shared<FakeEventSink>();
  wire(sink);

  CallMethodRequest request;
  request.input_arguments().resize(2);
  request.input_arguments()[0] = Variant{sLeafCert->der_encoding()};
  request.input_arguments()[1] = Variant{true};

  auto callResult = call_method(
    MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_AddCertificate,
    std::move(request));
  ASSERT_TRUE(callResult);
  ASSERT_TRUE(callResult.value().status_code().is_good());

  bool foundUpdated = false;
  for (size_t i = 0; i < sink->count(); ++i)
  {
    auto* updated = dynamic_cast<const TrustListUpdatedAuditEventPayload*>(sink->at(i));
    if (updated)
    {
      foundUpdated = true;
      EXPECT_EQ(updated->trustListId,
        NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList});
      EXPECT_TRUE(updated->status);
      break;
    }
  }
  EXPECT_TRUE(foundUpdated) << "Did not find TrustListUpdatedAuditEventPayload";
}

// ============================================================================
// Test: Audit events - CertificateUpdateRequested on UpdateCertificate
// ============================================================================

TEST_F(PushManagementWiringTest, UpdateCertificateEmitsCertificateUpdateRequestedAuditEvent)
{
  auto sink = std::make_shared<FakeEventSink>();
  wire(sink);

  CertificateStore::ApplicationCertificate appCert;
  appCert.certificateType = CertificateType::RsaSha256Application;
  appCert.certificate = sLeafCert;
  appCert.keys = sLeafKeys;
  mFakeStore->appCerts.push_back(appCert);

  CallMethodRequest request;
  request.input_arguments().resize(6);
  request.input_arguments()[0] =
    Variant{NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup}};
  request.input_arguments()[1] =
    Variant{NodeId{0, static_cast<uint32_t>(ObjectTypeId::RsaSha256ApplicationCertificateType)}};
  request.input_arguments()[2] = Variant{sLeafCert->der_encoding()};
  request.input_arguments()[3] = Variant{Array<ByteString>{}};
  request.input_arguments()[4] = Variant{String{"PEM"}};
  request.input_arguments()[5] = Variant{ByteString{}};

  call_method(MethodId::ServerConfiguration_UpdateCertificate, std::move(request));

  // The audit event is emitted before the async operation, so it should always be present.
  EXPECT_GE(sink->count_of<CertificateUpdateRequestedAuditEventPayload>(), 1u)
    << "Expected CertificateUpdateRequestedAuditEventPayload";
}

// ============================================================================
// Test: Audit events disabled - no events when eventSink is null
// ============================================================================

TEST_F(PushManagementWiringTest, NoAuditEventsWhenEventSinkIsNull)
{
  wire({});

  CallMethodRequest request;
  request.input_arguments().resize(2);
  request.input_arguments()[0] = Variant{sLeafCert->der_encoding()};
  request.input_arguments()[1] = Variant{true};

  auto callResult = call_method(
    MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_AddCertificate,
    std::move(request));

  // No crash with null eventSink - null check in emit helpers prevents emission.
  EXPECT_TRUE(callResult) << "Call should not crash with null event sink";
}

// ============================================================================
// TransactionDiagnostics + SupportsTransactions (Part 12 section 7.10.11, UA-1.05.06)
// ============================================================================

namespace
{
constexpr VariableId diagStartTime = VariableId::ServerConfiguration_TransactionDiagnostics_StartTime;
constexpr VariableId diagEndTime = VariableId::ServerConfiguration_TransactionDiagnostics_EndTime;
constexpr VariableId diagResult = VariableId::ServerConfiguration_TransactionDiagnostics_Result;
constexpr VariableId diagAffectedTrustLists =
  VariableId::ServerConfiguration_TransactionDiagnostics_AffectedTrustLists;
constexpr VariableId diagAffectedGroups =
  VariableId::ServerConfiguration_TransactionDiagnostics_AffectedCertificateGroups;
constexpr VariableId diagErrors = VariableId::ServerConfiguration_TransactionDiagnostics_Errors;

const NodeId defaultAppGroupId{
  0, static_cast<uint32_t>(ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup)};
}  // namespace

// SupportsTransactions (Optional in the NodeSet, created at runtime) must read
// true: the SDK implements the push transaction model.
TEST_F(PushManagementWiringTest, SupportsTransactionsAdvertisesTrue)
{
  wire();

  auto dv = read_variable(VariableId::ServerConfiguration_SupportsTransactions);
  ASSERT_TRUE(!dv.status().has_value() || dv.status()->is_good());
  auto* flag = dv.value().try_as<bool>();
  ASSERT_NE(flag, nullptr) << "SupportsTransactions should be a Boolean";
  EXPECT_TRUE(*flag) << "SupportsTransactions must advertise true";
}

// SVR-PULLCRT-025 / Part 12 section 7.10.5: GetCertificates is an Optional member that
// the NodeSet does not pre-instantiate. The wiring materialises it from the type
// definition at the OPC-reserved id (32333) with its InputArguments(32334) /
// OutputArguments(32335) Argument metadata, and binds the handler so it is
// callable over an authenticated channel.
// @relation(SVR-PULLCRT-025, scope=function)
TEST_F(PushManagementWiringTest, GetCertificatesInstantiatedAtReservedIdAndCallable)
{
  wire();

  const NodeId getCertsId{0, 32333u};
  auto methodNode = as().try_find_node_sync(getCertsId);
  ASSERT_TRUE(methodNode.is_good()) << "GetCertificates Method should be materialised at reserved id 32333";
  EXPECT_EQ(methodNode.value().get_node_class(), NodeClass::Method);

  auto inputArgs = as().try_find_node_sync(NodeId{0, 32334u});
  ASSERT_TRUE(inputArgs.is_good()) << "GetCertificates InputArguments should exist at reserved id 32334";
  auto outputArgs = as().try_find_node_sync(NodeId{0, 32335u});
  ASSERT_TRUE(outputArgs.is_good()) << "GetCertificates OutputArguments should exist at reserved id 32335";
  // The Argument[] metadata Value was copied from the type declaration (async
  // value-copy step in the instantiation engine).
  if (auto var = inputArgs.value().as<VariableAccessor>())
  {
    auto argValue = var->try_read_value_sync();
    ASSERT_TRUE(argValue.is_good());
    EXPECT_FALSE(argValue.value().value().empty())
      << "InputArguments must carry the copied Argument[] metadata";
  }

  // Callable: returns the application certificates of the group.
  CertificateStore::ApplicationCertificate appCert;
  appCert.certificateType = CertificateType::RsaSha256Application;
  appCert.certificate = sLeafCert;
  appCert.keys = sLeafKeys;
  mFakeStore->appCerts.push_back(appCert);

  CallMethodRequest request;
  request.input_arguments().resize(1);
  request.input_arguments()[0] =
    Variant{NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup}};
  auto callResult = call_method(MethodId::ServerConfiguration_GetCertificates, std::move(request));
  ASSERT_TRUE(callResult) << callResult.status_code();
  EXPECT_TRUE(callResult.value().status_code().is_good())
    << "GetCertificates call: " << callResult.value().status_code();
  ASSERT_EQ(callResult.value().output_arguments().size(), 2u)
    << "GetCertificates returns (certificateTypeIds[], certificates[])";
}

// Part 12 Figure 22 through the server's wiring: Open with the write bit creates the Session's transaction.
// Another Session's AddCertificate is refused with Bad_TransactionPending while it is held - also after the
// handle is closed with nothing changed - and the empty transaction ends with ApplyChanges (Good).
// Falsifiable: the former wiring started the transaction only at CloseAndUpdate, so the AddCertificate after
// the Close went through.
// @verifies AC-SVR-PULLCRT-039-B-OPEN-FOR-WRITE-STARTS-THE-SESSIONS-TRANSACTION
TEST_F(PushManagementWiringTest, OpenForWriteStartsTheSessionsTransaction)
{
  wire();
  auto opened = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(opened.is_good());
  EXPECT_EQ(open_sync(mSessionB, 0x06).status_code(), StatusCode{Status::BadTransactionPending})
    << "Part 12 7.8.2.1, not the FileType Bad_NotWritable: A's open handle is its transaction";
  EXPECT_EQ(add_certificate_sync(mSessionB, sLeafCert->der_encoding(), true).status_code(),
    StatusCode{Status::BadInvalidState})
    << "7.8.2.4 Result Codes: Bad_InvalidState while the TrustList is open for write";

  ASSERT_TRUE(close_sync(mSessionA, opened.value()).is_good());
  EXPECT_EQ(add_certificate_sync(mSessionB, sLeafCert->der_encoding(), true).status_code(),
    StatusCode{Status::BadTransactionPending})
    << "the transaction outlives the handle";

  auto applied = call_method(MethodId::ServerConfiguration_ApplyChanges, CallMethodRequest{});
  ASSERT_TRUE(applied.is_good());
  EXPECT_TRUE(applied.value().status_code().is_good()) << "an empty transaction applies";
  EXPECT_EQ(mFakeStore->trustedCerts.size(), 1u) << "nothing changed";
  EXPECT_TRUE(add_certificate_sync(mSessionB, sLeafCert->der_encoding(), true).is_good()) << "ended";
}

// Part 12 7.10.8 through the server's wiring (owner decision Q2): CancelChanges is never refused, also while
// a CloseAndUpdate of the transaction is still merging (its store read parked here). The change it lands is
// dropped, no transaction carries it, and the Session's next transaction does not bring it back. Falsifiable:
// the former service opened a new transaction for the late change, so it could be applied after the cancel.
// @verifies AC-SVR-PULLCRT-041-A-CANCELLED-CHANGE-IS-NOT-CARRIED-INTO-A-NEW-TRANSACTION
TEST_F(PushManagementWiringTest, CancelChangesDuringAMergeDropsTheChangeForGood)
{
  wire();
  auto opened = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(opened.is_good());
  TrustListDataType noCrls;
  noCrls.specified_lists() = 0x02;  // TrustedCrls, now empty; the merge reads the trusted certificates
  ASSERT_TRUE(write_sync(mSessionA, opened.value(), noCrls).is_good());
  mFakeStore->parkTrustedRead = true;
  auto updated = std::make_shared<std::promise<Result<bool>>>();
  mComponents.trustList->close_and_update_async(
    mSessionA, opened.value(), [updated](Result<bool> r) { updated->set_value(std::move(r)); });
  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while (!mFakeStore->trustedReadIsParked.load() && std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(1ms);
  ASSERT_TRUE(mFakeStore->trustedReadIsParked.load()) << "the CloseAndUpdate is merging";

  auto cancelled = call_method(MethodId::ServerConfiguration_CancelChanges, CallMethodRequest{});
  ASSERT_TRUE(cancelled.is_good());
  EXPECT_TRUE(cancelled.value().status_code().is_good()) << "CancelChanges is not refused";

  mFakeStore->parkTrustedRead = false;  // the next merge reads the store at once
  mFakeStore->release_parked_trusted_read();
  auto updateFuture = updated->get_future();
  ASSERT_EQ(updateFuture.wait_for(5s), std::future_status::ready);
  (void)updateFuture.get();
  const auto dropped = std::chrono::steady_clock::now() + 5s;
  while (staged_lists_sync().has_value() && std::chrono::steady_clock::now() < dropped)
    std::this_thread::sleep_for(1ms);
  EXPECT_FALSE(staged_lists_sync().has_value()) << "the cancelled change is dropped";
  auto nothing = call_method(
    MethodId::ServerConfiguration_ApplyChanges, CallMethodRequest{}, MessageSecurityMode::SignAndEncrypt, 42);
  ASSERT_TRUE(nothing.is_good());
  EXPECT_EQ(nothing.value().status_code(), StatusCode{Status::BadNothingToDo}) << "no transaction carries it";

  // The Session's next transaction changes only the issuers: the CRL the cancelled change removed stays.
  auto reopened = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(reopened.is_good());
  TrustListDataType issuers;
  issuers.specified_lists() = 0x04;
  issuers.issuer_certificates().push_back(sCaCert->der_encoding());
  ASSERT_TRUE(write_sync(mSessionA, reopened.value(), issuers).is_good());
  std::promise<Result<bool>> second;
  mComponents.trustList->close_and_update_async(
    mSessionA, reopened.value(), [&second](Result<bool> r) { second.set_value(std::move(r)); });
  auto secondFuture = second.get_future();
  ASSERT_EQ(secondFuture.wait_for(5s), std::future_status::ready);
  ASSERT_TRUE(secondFuture.get().is_good());
  auto applied = call_method(
    MethodId::ServerConfiguration_ApplyChanges, CallMethodRequest{}, MessageSecurityMode::SignAndEncrypt, 43);
  ASSERT_TRUE(applied.is_good());
  ASSERT_TRUE(applied.value().status_code().is_good()) << applied.value().status_code();
  EXPECT_EQ(mFakeStore->trustedCrls.size(), 1u) << "the cancelled change did not come back";
}

// Owner decision Q2 through the server's wiring: CancelChanges ends the transaction the TrustList was opened
// in, so the upload on that handle is not carried into a new transaction: its CloseAndUpdate is refused
// (Bad_InvalidState) and nothing is staged or applied. Falsifiable: the former CloseAndUpdate opened a new
// transaction holding the cancelled upload.
// @verifies AC-SVR-PULLCRT-041-A-CANCELLED-CHANGE-IS-NOT-CARRIED-INTO-A-NEW-TRANSACTION
TEST_F(PushManagementWiringTest, AnUploadOnAHandleWhoseTransactionWasCancelledIsRefused)
{
  wire();
  auto opened = open_sync(mSessionA, 0x06);
  ASSERT_TRUE(opened.is_good());
  TrustListDataType noCrls;
  noCrls.specified_lists() = 0x02;
  ASSERT_TRUE(write_sync(mSessionA, opened.value(), noCrls).is_good());
  auto cancelled = call_method(MethodId::ServerConfiguration_CancelChanges, CallMethodRequest{});
  ASSERT_TRUE(cancelled.is_good());
  ASSERT_TRUE(cancelled.value().status_code().is_good());

  std::promise<Result<bool>> updated;
  mComponents.trustList->close_and_update_async(
    mSessionA, opened.value(), [&updated](Result<bool> r) { updated.set_value(std::move(r)); });
  EXPECT_EQ(updated.get_future().get().status_code(), StatusCode{Status::BadInvalidState});
  EXPECT_FALSE(staged_lists_sync().has_value());
  auto nothing = call_method(MethodId::ServerConfiguration_ApplyChanges, CallMethodRequest{});
  ASSERT_TRUE(nothing.is_good());
  EXPECT_EQ(nothing.value().status_code(), StatusCode{Status::BadNothingToDo});
  EXPECT_EQ(mFakeStore->trustedCrls.size(), 1u);
}

// SVR-PULLCRT-032 / Part 12 section 7.10.10: ResetToServerDefaults clears the TrustList
// and triggers the server shutdown transition (via the requestShutdown hook).
// @relation(SVR-ECC-010, SVR-PULLCRT-032, scope=function)
TEST_F(PushManagementWiringTest, ResetToServerDefaultsClearsTrustListAndRequestsShutdown)
{
  wire();

  // Precondition: the fixture seeds trusted + issuer certs.
  ASSERT_FALSE(mFakeStore->trustedCerts.empty());
  ASSERT_FALSE(mFakeStore->issuerCerts.empty());
  ASSERT_FALSE(mShutdownRequested);

  auto callResult = call_method(MethodId::ServerConfiguration_ResetToServerDefaults, CallMethodRequest{});
  ASSERT_TRUE(callResult) << callResult.status_code();
  EXPECT_TRUE(callResult.value().status_code().is_good())
    << "ResetToServerDefaults: " << callResult.value().status_code();

  EXPECT_TRUE(mFakeStore->trustedCerts.empty()) << "TrustList trusted certs must be cleared";
  EXPECT_TRUE(mFakeStore->issuerCerts.empty()) << "TrustList issuer certs must be cleared";
  EXPECT_TRUE(mShutdownRequested) << "ResetToServerDefaults must trigger the shutdown transition";
}

// Part 12 7.10.10: "All TrustLists are cleared" - the DefaultUserTokenGroup's too, not only the
// application's. Falsifiable: the former reset cleared the application TrustList alone.
// @verifies AC-SVR-PULLCRT-040-ONE-LIST-WRITE-AT-A-TIME
TEST_F(PushManagementWiringTest, ResetToServerDefaultsClearsTheUserTokenTrustListToo)
{
  mUserTokenStore = std::make_shared<InMemoryFakeCertificateStore>();
  mUserTokenStore->trustedCerts.push_back(sLeafCert);
  mUserTokenStore->issuerCerts.push_back(sCaCert);
  wire();

  auto callResult = call_method(MethodId::ServerConfiguration_ResetToServerDefaults, CallMethodRequest{});
  ASSERT_TRUE(callResult) << callResult.status_code();
  EXPECT_TRUE(callResult.value().status_code().is_good()) << callResult.value().status_code();

  EXPECT_TRUE(mFakeStore->trustedCerts.empty());
  EXPECT_TRUE(mUserTokenStore->trustedCerts.empty()) << "the user-token TrustList is cleared too";
  EXPECT_TRUE(mUserTokenStore->issuerCerts.empty());
  EXPECT_TRUE(mShutdownRequested);
}

// Part 12 section 7.10.10: ResetToServerDefaults requires an authenticated SecureChannel.
// @relation(SVR-ECC-010, SVR-PULLCRT-033, scope=function)
TEST_F(PushManagementWiringTest, ResetToServerDefaultsNoneChannelFails)
{
  wire();

  auto callResult = call_method(
    MethodId::ServerConfiguration_ResetToServerDefaults, CallMethodRequest{}, MessageSecurityMode::None);
  ASSERT_TRUE(callResult);
  EXPECT_EQ(callResult.value().status_code(), StatusCode{Status::BadSecurityModeInsufficient})
    << "ResetToServerDefaults over a None channel must be rejected";
  EXPECT_FALSE(mShutdownRequested) << "A rejected call must not trigger shutdown";
}

// Part 12 section 7.10.5: GetCertificates requires an authenticated SecureChannel.
// Covers SVR-PULLCRT-025 (coverage-audit retag).
// @relation(SVR-ECC-010, SVR-PULLCRT-025, scope=function)
TEST_F(PushManagementWiringTest, GetCertificatesNoneChannelFails)
{
  wire();

  CallMethodRequest request;
  request.input_arguments().resize(1);
  request.input_arguments()[0] =
    Variant{NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup}};
  auto callResult =
    call_method(MethodId::ServerConfiguration_GetCertificates, std::move(request), MessageSecurityMode::None);
  ASSERT_TRUE(callResult);
  EXPECT_EQ(callResult.value().status_code(), StatusCode{Status::BadSecurityModeInsufficient})
    << "GetCertificates over a None channel must be rejected (authenticated-channel floor)";
}

// Part 12 section 7.10.11: before any transaction, every TransactionDiagnostics
// Variable has status Bad_OutOfService.
// @relation(SVR-ECC-010, SVR-PULLCRT-031, scope=function)
TEST_F(PushManagementWiringTest, TransactionDiagnosticsInitiallyOutOfService)
{
  wire();

  for (auto variableId :
    {diagStartTime, diagEndTime, diagResult, diagAffectedTrustLists, diagAffectedGroups, diagErrors})
  {
    auto dv = read_variable(variableId);
    ASSERT_TRUE(dv.status().has_value())
      << "Variable " << static_cast<uint32_t>(variableId) << " should carry a status";
    EXPECT_EQ(*dv.status(), StatusCode{Status::BadOutOfService})
      << "Variable " << static_cast<uint32_t>(variableId) << " should be Bad_OutOfService initially";
  }
}

// @relation(AC-SVR-PULLCRT-018-TRUSTLIST-AFFECTS-USERS, scope=function)
TEST_F(PushManagementWiringTest, ApplyChangesWithoutWireResponseCorrelationFailsClosed)
{
  wire();

  auto callResult = call_method(MethodId::ServerConfiguration_ApplyChanges,
    CallMethodRequest{},
    MessageSecurityMode::SignAndEncrypt,
    std::nullopt);

  ASSERT_TRUE(callResult);
  EXPECT_EQ(callResult.value().status_code(), StatusCode{Status::BadInternalError});
  ASSERT_NE(callResult.value().status_code().shared_detail(), nullptr);
  EXPECT_EQ(callResult.value().status_code().shared_detail()->code, "MissingMethodResponseCorrelation");
}

// After a successful ApplyChanges the TransactionDiagnostics Object reflects the
// transaction: timestamps set, Result Good, the affected certificate group
// recorded, and no errors.
TEST_F(PushManagementWiringTest, TransactionDiagnosticsPopulatedAfterApplyChanges)
{
  wire();

  auto before = DateTime::now();

  auto updateResult = stage_certificate_update();
  ASSERT_TRUE(updateResult) << "UpdateCertificate call failed: " << updateResult.status_code();
  ASSERT_TRUE(updateResult.value().status_code().is_good())
    << "UpdateCertificate result: " << updateResult.value().status_code();

  auto applyResult = call_method(MethodId::ServerConfiguration_ApplyChanges, CallMethodRequest{});
  ASSERT_TRUE(applyResult) << "ApplyChanges call failed: " << applyResult.status_code();
  ASSERT_TRUE(applyResult.value().status_code().is_good())
    << "ApplyChanges result: " << applyResult.value().status_code();

  // Result - Good value, good node status.
  auto resultDv = read_variable(diagResult);
  ASSERT_TRUE(!resultDv.status().has_value() || resultDv.status()->is_good());
  EXPECT_TRUE(resultDv.value().as<StatusCode>().is_good())
    << "Result value: " << resultDv.value().as<StatusCode>();

  // StartTime / EndTime - populated and ordered after the test start.
  auto startDv = read_variable(diagStartTime);
  auto* startTime = startDv.value().try_as<DateTime>();
  ASSERT_NE(startTime, nullptr);
  EXPECT_GE(startTime->value(), before.value());
  auto endDv = read_variable(diagEndTime);
  auto* endTime = endDv.value().try_as<DateTime>();
  ASSERT_NE(endTime, nullptr);
  EXPECT_GE(endTime->value(), startTime->value());

  // AffectedCertificateGroups - contains DefaultApplicationGroup.
  auto groupsDv = read_variable(diagAffectedGroups);
  const auto& groups = groupsDv.value().as<Array<NodeId>>();
  bool hasDefaultGroup = false;
  for (const auto& id : groups)
  {
    if (id == defaultAppGroupId)
      hasDefaultGroup = true;
  }
  EXPECT_TRUE(hasDefaultGroup) << "AffectedCertificateGroups should contain DefaultApplicationGroup";

  // Errors - empty on success.
  auto errorsDv = read_variable(diagErrors);
  const auto& errors = errorsDv.value().as<Array<RefStructure<Structure>>>();
  EXPECT_EQ(errors.size(), 0u) << "Errors should be empty on a successful transaction";
}

// On a commit failure ApplyChanges records the per-target error: Result carries
// the failing status and Errors holds a TransactionErrorType for the group.
TEST_F(PushManagementWiringTest, TransactionDiagnosticsRecordsErrorsOnCommitFailure)
{
  wire();

  // Force the certificate-store commit to fail.
  mFakeStore->addToApplicationCertificatesStatus = StatusCode{Status::BadInternalError};

  auto updateResult = stage_certificate_update();
  ASSERT_TRUE(updateResult);
  ASSERT_TRUE(updateResult.value().status_code().is_good())
    << "UpdateCertificate stages even when the later commit will fail";

  auto applyResult = call_method(MethodId::ServerConfiguration_ApplyChanges, CallMethodRequest{});
  ASSERT_TRUE(applyResult);
  EXPECT_TRUE(applyResult.value().status_code().is_bad()) << "ApplyChanges should fail when commit fails";

  // Result - carries the failing status as its value.
  auto resultDv = read_variable(diagResult);
  EXPECT_EQ(resultDv.value().as<StatusCode>(), StatusCode{Status::BadInternalError});

  // Errors - one TransactionErrorType targeting the affected group.
  auto errorsDv = read_variable(diagErrors);
  const auto& errors = errorsDv.value().as<Array<RefStructure<Structure>>>();
  ASSERT_EQ(errors.size(), 1u) << "Expected one error for the failed commit";
  const auto* txnError = dynamic_cast<const TransactionErrorType*>(errors.payload()[0].get());
  ASSERT_NE(txnError, nullptr) << "Errors element should be a TransactionErrorType";
  EXPECT_EQ(txnError->target_id(), defaultAppGroupId);
  EXPECT_EQ(txnError->error(), StatusCode{Status::BadInternalError});
}

// SVR-PULLCRT-030 / Part 12 section 7.10.1: "When ApplyChanges is called the Server
// verifies that all the changes are consistent and can be applied without
// errors. If any errors are found then all changes are discarded." A certificate
// that validated at UpdateCertificate time but fails re-validation at
// ApplyChanges (e.g. a TrustList that changed in between) must cause the WHOLE
// batch to be discarded - nothing is committed to the application-certificate
// store. (Falsifiability: without the verify-before-commit pass the staged
// certificate is committed and appCerts grows.)
// @relation(SVR-ECC-010, SVR-PULLCRT-030, scope=function)
TEST_F(PushManagementWiringTest, ApplyChangesDiscardsAllWhenBatchVerificationFails)
{
  wire();

  auto updateResult = stage_certificate_update();
  ASSERT_TRUE(updateResult);
  ASSERT_TRUE(updateResult.value().status_code().is_good())
    << "UpdateCertificate stages (and validates) successfully";

  const size_t committedBefore = mFakeStore->appCerts.size();

  // The staged certificate no longer validates when ApplyChanges runs.
  mFakeStore->validateCertificateStatus = StatusCode{Status::BadCertificateUntrusted};

  auto applyResult = call_method(MethodId::ServerConfiguration_ApplyChanges, CallMethodRequest{});
  ASSERT_TRUE(applyResult);
  EXPECT_TRUE(applyResult.value().status_code().is_bad())
    << "ApplyChanges must fail when batch verification finds an error";

  // All-or-nothing: nothing was committed.
  EXPECT_EQ(mFakeStore->appCerts.size(), committedBefore)
    << "A failed verification must discard ALL changes (no partial commit)";

  // The transaction is discarded - a second ApplyChanges finds nothing to do.
  auto secondApply = call_method(MethodId::ServerConfiguration_ApplyChanges, CallMethodRequest{});
  ASSERT_TRUE(secondApply);
  EXPECT_EQ(secondApply.value().status_code(), StatusCode{Status::BadNothingToDo})
    << "The failed batch must have cleared the active transaction";

  // Diagnostics record the per-target verification error (section 7.10.11).
  auto resultDv = read_variable(diagResult);
  EXPECT_TRUE(resultDv.value().as<StatusCode>().is_bad());
  auto errorsDv = read_variable(diagErrors);
  const auto& errors = errorsDv.value().as<Array<RefStructure<Structure>>>();
  ASSERT_EQ(errors.size(), 1u) << "Expected one error for the failed verification";
  const auto* txnError = dynamic_cast<const TransactionErrorType*>(errors.payload()[0].get());
  ASSERT_NE(txnError, nullptr) << "Errors element should be a TransactionErrorType";
  EXPECT_EQ(txnError->target_id(), defaultAppGroupId);
}

// SVR-PULLCRT-028 / Part 12 section 7.10.1: "If a Method called within a transaction
// fails (e.g. a parameter was invalid) the transaction state shall not change and
// all previous changes are applied when ApplyChanges is called." A failing
// UpdateCertificate must NOT abort the open transaction.
// @relation(SVR-ECC-010, SVR-PULLCRT-028, scope=function)
TEST_F(PushManagementWiringTest, FailedMethodDoesNotAbortOpenTransaction)
{
  wire();

  auto staged = stage_certificate_update();  // creates the transaction + queues a change
  ASSERT_TRUE(staged);
  ASSERT_TRUE(staged.value().status_code().is_good());
  const size_t committedBefore = mFakeStore->appCerts.size();

  // A failing Method inside the open transaction (invalid certificate type).
  CallMethodRequest badRequest;
  badRequest.input_arguments().resize(6);
  badRequest.input_arguments()[0] =
    Variant{NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup}};
  badRequest.input_arguments()[1] = Variant{NodeId{0, 9999u}};  // not a certificate type
  badRequest.input_arguments()[2] = Variant{sLeafCert->der_encoding()};
  badRequest.input_arguments()[3] = Variant{Array<ByteString>{}};
  badRequest.input_arguments()[4] = Variant{String{"PEM"}};
  badRequest.input_arguments()[5] = Variant{sLeafKeys->private_key_pem()};
  auto badResult = call_method(MethodId::ServerConfiguration_UpdateCertificate, std::move(badRequest));
  ASSERT_TRUE(badResult);
  EXPECT_TRUE(badResult.value().status_code().is_bad()) << "Invalid certificate type must fail";

  // The transaction was NOT aborted: ApplyChanges still applies the earlier change.
  auto applyResult = call_method(MethodId::ServerConfiguration_ApplyChanges, CallMethodRequest{});
  ASSERT_TRUE(applyResult);
  EXPECT_TRUE(applyResult.value().status_code().is_good())
    << "ApplyChanges after a failed Method must still apply the queued change: "
    << applyResult.value().status_code();
  EXPECT_GT(mFakeStore->appCerts.size(), committedBefore)
    << "The change queued before the failed Method must still be committed";
}

// SVR-PULLCRT-029 / Part 12 section 7.10.1: "a Server shall queue the changes in the
// order that they were requested within the current Session." Multiple changes
// queued in one transaction are all applied by a single ApplyChanges (the queue
// is an ordered vector - emplace_back preserves request order).
// @relation(SVR-ECC-010, SVR-PULLCRT-029, scope=function)
TEST_F(PushManagementWiringTest, AllQueuedChangesApplyInOneTransaction)
{
  wire();

  ASSERT_TRUE(stage_certificate_update().value().status_code().is_good());
  ASSERT_TRUE(stage_certificate_update().value().status_code().is_good());
  const size_t committedBefore = mFakeStore->appCerts.size();

  auto applyResult = call_method(MethodId::ServerConfiguration_ApplyChanges, CallMethodRequest{});
  ASSERT_TRUE(applyResult);
  EXPECT_TRUE(applyResult.value().status_code().is_good()) << applyResult.value().status_code();

  // Both queued UpdateCertificate changes were committed by the single ApplyChanges.
  EXPECT_EQ(mFakeStore->appCerts.size(), committedBefore + 2u)
    << "Every change queued in the transaction must be applied";
}

// Part 12 section 7.10.11: CancelChanges sets the TransactionDiagnostics Result value to
// Bad_RequestCancelledByClient.
TEST_F(PushManagementWiringTest, TransactionDiagnosticsResultCancelledAfterCancelChanges)
{
  wire();

  auto updateResult = stage_certificate_update();
  ASSERT_TRUE(updateResult);
  ASSERT_TRUE(updateResult.value().status_code().is_good());

  auto cancelResult = call_method(MethodId::ServerConfiguration_CancelChanges, CallMethodRequest{});
  ASSERT_TRUE(cancelResult);
  ASSERT_TRUE(cancelResult.value().status_code().is_good())
    << "CancelChanges result: " << cancelResult.value().status_code();

  auto resultDv = read_variable(diagResult);
  EXPECT_EQ(resultDv.value().as<StatusCode>(), StatusCode{Status::BadRequestCancelledByClient});
}

// ============================================================================
// SVR-PULLCRT-026 - certificate-type key-shape enforcement at UpdateCertificate
// (Part 12 section 7.8.4.4-section 7.8.4.12). Key shape that does not match the certificateTypeId
// subtype is rejected with Bad_InvalidArgument; the matching shape is accepted.
// The key-shape gate runs before integrity validation, so the negatives exercise
// only the shape check (fake-store validate is a no-op pass).
// ============================================================================

// section 7.8.4.4 RsaMinApplicationCertificateType: RSA key size of 1024 or 2048 bits.
// 2048 is within the allowed set -> the full update succeeds.
// @relation(SVR-ECC-010, SVR-PULLCRT-026, scope=function)
TEST_F(PushManagementWiringTest, UpdateCertificate_RsaMin_2048BitAccepted)
{
  wire();
  auto keys = sCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leaf = make_leaf(keys);

  auto callResult = call_update_certificate_for_type(ObjectTypeId::RsaMinApplicationCertificateType,
    CertificateType::RsaMinApplication,
    leaf->der_encoding(),
    keys->private_key_pem());
  ASSERT_TRUE(callResult);
  EXPECT_TRUE(callResult.value().status_code().is_good())
    << "RSA-2048 is valid for RsaMin: " << callResult.value().status_code();
}

// section 7.8.4.4: 4096 bits is NOT in the RsaMin allowed set {1024, 2048} -> rejected.
TEST_F(PushManagementWiringTest, UpdateCertificate_RsaMin_4096BitRejected)
{
  wire();
  auto keys = sCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 4096);
  auto leaf = make_leaf(keys);

  auto callResult = call_update_certificate_for_type(ObjectTypeId::RsaMinApplicationCertificateType,
    CertificateType::RsaMinApplication,
    leaf->der_encoding(),
    keys->private_key_pem());
  ASSERT_TRUE(callResult);
  EXPECT_EQ(callResult.value().status_code(), StatusCode{Status::BadInvalidArgument})
    << "RSA-4096 must be rejected for RsaMin (allowed: 1024/2048): " << callResult.value().status_code();
}

// section 7.8.4.5 RsaSha256ApplicationCertificateType: RSA key size of 2048, 3072 or 4096 bits.
// 1024 is below the allowed minimum -> rejected.
// @relation(AC-SVR-PULLCRT-026-KEY-SHAPE-CONSTRAINTS, scope=function)
TEST_F(PushManagementWiringTest, UpdateCertificate_RsaSha256_1024BitRejected)
{
  wire();
  auto keys = sCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 1024);
  auto leaf = make_leaf(keys);

  auto callResult = call_update_certificate_for_type(ObjectTypeId::RsaSha256ApplicationCertificateType,
    CertificateType::RsaSha256Application,
    leaf->der_encoding(),
    keys->private_key_pem());
  ASSERT_TRUE(callResult);
  EXPECT_EQ(callResult.value().status_code(), StatusCode{Status::BadInvalidArgument})
    << "RSA-1024 must be rejected for RsaSha256 (allowed: 2048/3072/4096): "
    << callResult.value().status_code();
}

// section 7.8.4.7 EccNistP256ApplicationCertificateType: shall have an ECC nistP256 key.
// An RSA key under the ECC type fails the algorithm-family check -> rejected.
// @relation(AC-SVR-PULLCRT-026-KEY-SHAPE-CONSTRAINTS, scope=function)
TEST_F(PushManagementWiringTest, UpdateCertificate_EccNistP256_RsaKeyRejected)
{
  wire();
  auto keys = sCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto leaf = make_leaf(keys);

  auto callResult = call_update_certificate_for_type(ObjectTypeId::EccNistP256ApplicationCertificateType,
    CertificateType::EccNistP256Application,
    leaf->der_encoding(),
    keys->private_key_pem());
  ASSERT_TRUE(callResult);
  EXPECT_EQ(callResult.value().status_code(), StatusCode{Status::BadInvalidArgument})
    << "RSA key must be rejected for an ECC certificate type: " << callResult.value().status_code();
}

// section 7.8.4.7: a P-256 key under the EccNistP256 type matches the named curve -> accepted.
TEST_F(PushManagementWiringTest, UpdateCertificate_EccNistP256_CorrectCurveAccepted)
{
  wire();
  auto keys = sCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::EccNistP256, std::nullopt);
  auto leaf = make_leaf(keys);

  auto callResult = call_update_certificate_for_type(ObjectTypeId::EccNistP256ApplicationCertificateType,
    CertificateType::EccNistP256Application,
    leaf->der_encoding(),
    keys->private_key_pem());
  ASSERT_TRUE(callResult);
  EXPECT_TRUE(callResult.value().status_code().is_good())
    << "P-256 key is valid for EccNistP256: " << callResult.value().status_code();
}

// section 7.8.4.7 vs section 7.8.4.8: a P-384 key under the EccNistP256 type is the wrong named
// curve -> rejected (the ECC check is by curve identity, not bit length).
TEST_F(PushManagementWiringTest, UpdateCertificate_EccNistP256_WrongCurveRejected)
{
  wire();
  auto keys = sCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::EccNistP384, std::nullopt);
  auto leaf = make_leaf(keys);

  auto callResult = call_update_certificate_for_type(ObjectTypeId::EccNistP256ApplicationCertificateType,
    CertificateType::EccNistP256Application,
    leaf->der_encoding(),
    keys->private_key_pem());
  ASSERT_TRUE(callResult);
  EXPECT_EQ(callResult.value().status_code(), StatusCode{Status::BadInvalidArgument})
    << "P-384 key must be rejected for EccNistP256 (wrong curve): " << callResult.value().status_code();
}

}  // namespace

// UpdateCertificate validates the candidate against THIS server's ApplicationUri (Part 12 7.10.4 "all
// normal integrity checks"): a certificate naming another application would otherwise be installed
// and then refused by every client.
// @verifies AC-SVR-PULLCRT-004-UPDATECERTIFICATE-VALIDATES-THE-SERVERS-APPLICATION-URI
TEST_F(PushManagementWiringTest, UpdateCertificateValidatesTheCandidateAgainstTheServersApplicationUri)
{
  wire();
  auto callResult = stage_certificate_update();
  ASSERT_TRUE(callResult);
  ASSERT_TRUE(callResult.value().status_code().is_good()) << callResult.value().status_code();
  EXPECT_GE(mFakeStore->validateCertificateCallCount, 1u);
  ASSERT_TRUE(mFakeStore->lastValidatedApplicationUri.has_value())
    << "the validation must carry the server's ApplicationUri";
  EXPECT_EQ(*mFakeStore->lastValidatedApplicationUri, "urn:test:server");
}

// The gate is wired: through the production wiring, a modification by a session other than the
// push transaction's owner is refused by the TrustListManager before it is applied.
// @verifies AC-SVR-SECADMIN-009-TRUST-LIST-CHANGES-ARE-REFUSED-UNDER-ANOTHER-SESSIONS-TRANSACTION
TEST_F(PushManagementWiringTest, TheWiredTrustListRefusesAnotherSessionsChangeWhileATransactionIsOpen)
{
  wire();
  const NodeId owner{1, uint32_t{7001}};
  const NodeId other{1, uint32_t{7002}};
  mComponents.certificatePushService->on_trust_list_modified(owner, NodeId{0, uint32_t{12345}});
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{3};
  while (mComponents.certificatePushService->trust_list_modification_allowed(other).is_good() &&
         std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds{5});
  }

  std::promise<VoidResult> done;
  mComponents.trustList->add_certificate_async(
    other, sLeafCert->der_encoding(), true, [&](VoidResult result) { done.set_value(std::move(result)); });
  const auto result = done.get_future().get();
  EXPECT_EQ(result.status_code().as_status(), Status::BadTransactionPending)
    << "the wired gate refuses the other session's change before it is applied";
}

// Through the production wiring, the server's Session lookup reaches the push service: a trust-list
// change by a Session the server no longer holds is refused before it is applied, and another Session's
// change goes through.
// @verifies AC-SVR-SECADMIN-009-TRUST-LIST-CHANGES-ARE-REFUSED-UNDER-ANOTHER-SESSIONS-TRANSACTION
TEST_F(PushManagementWiringTest, TheWiredTrustListRefusesAChangeByASessionTheServerNoLongerHolds)
{
  const NodeId closed{1, uint32_t{7201}};
  const NodeId live{1, uint32_t{7202}};
  mSessionExists = [closed](const NodeId& sessionId)
  {
    return sessionId != closed;
  };
  wire();

  const auto add = [&](const NodeId& session)
  {
    std::promise<VoidResult> done;
    mComponents.trustList->add_certificate_async(session,
      sLeafCert->der_encoding(),
      true,
      [&](VoidResult result) { done.set_value(std::move(result)); });
    return done.get_future().get();
  };
  EXPECT_EQ(add(closed).status_code().as_status(), Status::BadSessionIdInvalid)
    << "the closed Session's change is refused through the wiring";
  EXPECT_TRUE(mComponents.certificatePushService->trust_list_modification_allowed(live).is_good())
    << "the refusal left no claim behind";
  EXPECT_TRUE(add(live).is_good()) << "a Session the server holds is unaffected";
}

// Through the production wiring: a modification that fails after its claim was granted (malformed DER)
// releases the claim, so another session's change is admitted at once.
// @verifies AC-SVR-SECADMIN-009-TRUST-LIST-CHANGES-ARE-REFUSED-UNDER-ANOTHER-SESSIONS-TRANSACTION
TEST_F(PushManagementWiringTest, AFailedModificationReleasesItsClaimThroughTheWiring)
{
  wire();
  const NodeId first{1, uint32_t{7101}};
  const NodeId second{1, uint32_t{7102}};
  const auto add = [&](const NodeId& session, ByteString der)
  {
    std::promise<VoidResult> done;
    mComponents.trustList->add_certificate_async(
      session, std::move(der), true, [&](VoidResult result) { done.set_value(std::move(result)); });
    return done.get_future().get();
  };
  EXPECT_FALSE(add(first, ByteString{0x30, 0x03, 0x01}).is_good()) << "malformed DER is refused";
  EXPECT_TRUE(mComponents.certificatePushService->trust_list_modification_allowed(second).is_good())
    << "the refused modification left no claim behind";
  EXPECT_TRUE(add(second, sLeafCert->der_encoding()).is_good()) << "another session's change is admitted";
}

// Completeness review C2 (decision 24): UpdateCertificate's issuerCertificates argument (OPC 10000-12 7.10.4)
// is stored with the new certificate as ApplicationCertificate::issuerCertificates, in order, when the
// change is applied - the chain every outgoing certificate field then sends (ServerSignatureTests
// CreateSessionServerCertificateIsTheLeafThenItsIssuers).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-82-OWN-CHAIN-LOAD, scope=function)
TEST_F(PushManagementWiringTest, UpdateCertificateIssuerCertificatesAreStoredWithTheCertificate)
{
  wire();
  CertificateStore::ApplicationCertificate current;
  current.certificateType = CertificateType::RsaSha256Application;
  current.certificate = sLeafCert;
  current.keys = sLeafKeys;
  mFakeStore->appCerts.push_back(current);

  CallMethodRequest request;
  request.input_arguments().resize(6);
  request.input_arguments()[0] =
    Variant{NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup}};
  request.input_arguments()[1] =
    Variant{NodeId{0, static_cast<uint32_t>(ObjectTypeId::RsaSha256ApplicationCertificateType)}};
  request.input_arguments()[2] = Variant{sLeafCert->der_encoding()};
  request.input_arguments()[3] = Variant{Array<ByteString>{sCaCert->der_encoding()}};
  request.input_arguments()[4] = Variant{String{"PEM"}};
  request.input_arguments()[5] = Variant{sLeafKeys->private_key_pem()};
  auto updateResult = call_method(MethodId::ServerConfiguration_UpdateCertificate, std::move(request));
  ASSERT_TRUE(updateResult) << updateResult.status_code();
  ASSERT_TRUE(updateResult.value().status_code().is_good()) << updateResult.value().status_code();

  auto applyResult = call_method(MethodId::ServerConfiguration_ApplyChanges, CallMethodRequest{});
  ASSERT_TRUE(applyResult) << applyResult.status_code();
  ASSERT_TRUE(applyResult.value().status_code().is_good()) << applyResult.value().status_code();

  ASSERT_FALSE(mFakeStore->appCerts.empty());
  const auto& stored = mFakeStore->appCerts.back();
  ASSERT_TRUE(stored.certificate);
  EXPECT_EQ(stored.certificate->thumbprint(), sLeafCert->thumbprint());
  ASSERT_EQ(stored.issuerCertificates.size(), 1u) << "the issuerCertificates argument is kept";
  EXPECT_EQ(stored.issuerCertificates.front()->thumbprint(), sCaCert->thumbprint());
}

// ============================================================================
// UpdateCertificate reads the served endpoint policies when it is called (OPC 10000-12 7.10.4), not
// when push management was wired. The server wires push management before it adds its endpoints, so a
// list captured at wiring time is empty and the policy check never refuses anything. Each test wires
// first, and only afterwards makes the provider report a Basic256Sha256 endpoint - the order the
// server's own startup produces. The two arms differ only in the candidate's signature algorithm.
// ============================================================================

namespace
{

/// A provider that serves no endpoint until @p served is set, then one Basic256Sha256 endpoint.
std::function<std::vector<std::pair<std::string, std::shared_ptr<const SecurityPolicy>>>()>
  late_basic256sha256(std::shared_ptr<std::atomic<bool>> served)
{
  return [served]()
  {
    std::vector<std::pair<std::string, std::shared_ptr<const SecurityPolicy>>> endpoints;
    if (served->load())
    {
      endpoints.emplace_back(
        "Basic256Sha256_SignAndEncrypt", SecurityPolicy::create(SecurityPolicyId::Basic256Sha256));
    }
    return endpoints;
  };
}

}  // namespace

class PushManagementLateEndpointPolicies : public PushManagementWiringTest
{
protected:
  /// A CA-signed RSA-2048 candidate whose certificate signature uses @p algorithm.
  std::shared_ptr<const X509Certificate> make_candidate(const std::shared_ptr<const AsymmetricKeyPair>& keys,
    CertificateSignatureAlgorithm algorithm, const std::string& serial)
  {
    Crypto::CreateCertificateConfig p;
    p.subjectKeys = keys;
    p.issuerKeys = sCaKeys;
    p.issuer = sCaCert;
    p.subject.commonName = "LatePolicyLeaf";
    p.serialNumber = serial;
    p.keyUsage.digitalSignature = true;
    p.keyUsage.nonRepudiation = true;
    p.keyUsage.keyEncipherment = true;
    p.keyUsage.dataEncipherment = true;
    p.keyUsage.serverAuth = true;
    p.keyUsage.clientAuth = true;
    p.certificateSignatureAlgorithm = algorithm;
    p.from = DateTime::now();
    p.to = DateTime{p.from.value() + std::chrono::days{30}};
    p.subjectAlternateName.uris = {"urn:test:server"};
    p.subjectAlternateName.hostnames = {"localhost"};
    return sPki->create_cert(p);
  }

  /// Wire with the late provider, THEN serve the endpoint, then call UpdateCertificate with @p candidate.
  CallResult update_after_the_endpoint_is_served(const std::shared_ptr<const X509Certificate>& candidate,
    const std::shared_ptr<const AsymmetricKeyPair>& keys)
  {
    auto served = std::make_shared<std::atomic<bool>>(false);
    mServedEndpointPolicies = late_basic256sha256(served);
    wire();
    served->store(true);  // the endpoint exists only after the service was created

    CertificateStore::ApplicationCertificate current;
    current.certificateType = CertificateType::RsaSha256Application;
    current.certificate = sLeafCert;
    current.keys = sLeafKeys;
    mFakeStore->appCerts.push_back(current);

    CallMethodRequest request;
    request.input_arguments().resize(6);
    request.input_arguments()[0] =
      Variant{NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup}};
    request.input_arguments()[1] =
      Variant{NodeId{0, static_cast<uint32_t>(ObjectTypeId::RsaSha256ApplicationCertificateType)}};
    request.input_arguments()[2] = Variant{candidate->der_encoding()};
    request.input_arguments()[3] = Variant{Array<ByteString>{sCaCert->der_encoding()}};
    request.input_arguments()[4] = Variant{String{"PEM"}};
    request.input_arguments()[5] = Variant{keys->private_key_pem()};
    return call_method(MethodId::ServerConfiguration_UpdateCertificate, std::move(request));
  }
};

// Negative arm: a SHA-1-signed candidate violates the Basic256Sha256 endpoint that was added after the
// service was created. Read at call time, the endpoint is seen and the update is refused with
// Bad_SecurityChecksFailed; a list captured when push management was wired would be empty and accept it.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-146-UPDATE-CERTIFICATE-READS-SERVED-POLICIES-AT-CALL-TIME, scope=function)
TEST_F(PushManagementLateEndpointPolicies, ASha1CandidateIsRefusedByAnEndpointServedAfterWiring)
{
  auto keys = sCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto candidate = make_candidate(keys, CertificateSignatureAlgorithm::RsaPkcs15Sha1, "9101");
  ASSERT_EQ(candidate->signature_algorithm(), CertificateSignatureAlgorithm::RsaPkcs15Sha1);

  auto callResult = update_after_the_endpoint_is_served(candidate, keys);
  ASSERT_TRUE(callResult) << callResult.status_code();
  EXPECT_EQ(callResult.value().status_code(), StatusCode{Status::BadSecurityChecksFailed})
    << "the endpoint served after wiring must be checked: " << callResult.value().status_code();
}

// Control arm: the same flow with a SHA-256-signed candidate complies with the endpoint and is staged.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-146-UPDATE-CERTIFICATE-READS-SERVED-POLICIES-AT-CALL-TIME, scope=function)
TEST_F(PushManagementLateEndpointPolicies, ASha256CandidateIsAcceptedByAnEndpointServedAfterWiring)
{
  auto keys = sCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto candidate = make_candidate(keys, CertificateSignatureAlgorithm::RsaPkcs15Sha2256, "9102");
  ASSERT_EQ(candidate->signature_algorithm(), CertificateSignatureAlgorithm::RsaPkcs15Sha2256);

  auto callResult = update_after_the_endpoint_is_served(candidate, keys);
  ASSERT_TRUE(callResult) << callResult.status_code();
  EXPECT_TRUE(callResult.value().status_code().is_good())
    << "a compliant candidate must be staged: " << callResult.value().status_code();
}

// An ECC certificate is checked only against the endpoints that present ECC certificates, as the startup
// check does: a server serving only a Basic256Sha256 (RSA) endpoint accepts a compliant ECC P-256 certificate
// into its ECC slot. Falsifiable: holding every pushed certificate to every served endpoint refuses it with
// Bad_SecurityChecksFailed, the RSA policy's verdict on an ECC key (found end to end by
// PushCertEccTest.KeyPushWorkflow_EccNistP256_FullLifecycle).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-146-UPDATE-CERTIFICATE-READS-SERVED-POLICIES-AT-CALL-TIME, scope=function)
TEST_F(PushManagementLateEndpointPolicies, AnEccCertificateIsNotHeldToAnRsaEndpointsPolicy)
{
  auto eccKeys = sCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::EccNistP256, std::nullopt);
  ASSERT_NE(eccKeys, nullptr);
  Crypto::CreateCertificateConfig p;
  p.subjectKeys = eccKeys;
  p.issuerKeys = sCaKeys;
  p.issuer = sCaCert;
  p.subject.commonName = "EccLeaf";
  p.serialNumber = "9103";
  p.keyUsage.digitalSignature = true;
  p.keyUsage.nonRepudiation = true;
  p.keyUsage.keyAgreement = true;
  p.keyUsage.serverAuth = true;
  p.keyUsage.clientAuth = true;
  p.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  p.from = DateTime::now();
  p.to = DateTime{p.from.value() + std::chrono::days{30}};
  p.subjectAlternateName.uris = {"urn:test:server"};
  p.subjectAlternateName.hostnames = {"localhost"};
  const auto candidate = sPki->create_cert(p);

  // The group offers the ECC type because the store holds an ECC certificate when push management is wired.
  CertificateStore::ApplicationCertificate rsa;
  rsa.certificateType = CertificateType::RsaSha256Application;
  rsa.certificate = sLeafCert;
  rsa.keys = sLeafKeys;
  mFakeStore->appCerts.push_back(rsa);
  CertificateStore::ApplicationCertificate ecc;
  ecc.certificateType = CertificateType::EccNistP256Application;
  ecc.certificate = candidate;
  ecc.keys = eccKeys;
  mFakeStore->appCerts.push_back(ecc);
  auto served = std::make_shared<std::atomic<bool>>(true);
  mServedEndpointPolicies = late_basic256sha256(served);  // an RSA endpoint only
  wire();

  CallMethodRequest request;
  request.input_arguments().resize(6);
  request.input_arguments()[0] =
    Variant{NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup}};
  request.input_arguments()[1] =
    Variant{NodeId{0, static_cast<uint32_t>(ObjectTypeId::EccNistP256ApplicationCertificateType)}};
  request.input_arguments()[2] = Variant{candidate->der_encoding()};
  request.input_arguments()[3] = Variant{Array<ByteString>{sCaCert->der_encoding()}};
  request.input_arguments()[4] = Variant{String{"PEM"}};
  request.input_arguments()[5] = Variant{eccKeys->private_key_pem()};
  auto callResult = call_method(MethodId::ServerConfiguration_UpdateCertificate, std::move(request));
  ASSERT_TRUE(callResult) << callResult.status_code();
  EXPECT_TRUE(callResult.value().status_code().is_good())
    << "the RSA endpoint presents the RSA certificate; it does not judge the ECC one: "
    << callResult.value().status_code();
}

// OPC 10000-12 7.10.4: an issuer certificate that will not parse fails the integrity checks on "all of the
// issuer Certificates" - Bad_SecurityChecksFailed; a new certificate that will not parse is the Certificate
// itself - Bad_CertificateInvalid. Falsifiable: the former code answered Bad_CertificateInvalid for both.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-128-UPDATE-CERTIFICATE-ISSUERS, scope=function)
TEST_F(PushManagementLateEndpointPolicies, AnUnparsableIssuerIsASecurityCheckFailure)
{
  auto keys = sCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto candidate = make_candidate(keys, CertificateSignatureAlgorithm::RsaPkcs15Sha2256, "9105");
  CertificateStore::ApplicationCertificate current;
  current.certificateType = CertificateType::RsaSha256Application;
  current.certificate = sLeafCert;
  current.keys = sLeafKeys;
  mFakeStore->appCerts.push_back(current);
  wire();

  const auto update = [&](ByteString certificate, ByteString issuer)
  {
    CallMethodRequest request;
    request.input_arguments().resize(6);
    request.input_arguments()[0] =
      Variant{NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup}};
    request.input_arguments()[1] =
      Variant{NodeId{0, static_cast<uint32_t>(ObjectTypeId::RsaSha256ApplicationCertificateType)}};
    request.input_arguments()[2] = Variant{std::move(certificate)};
    request.input_arguments()[3] = Variant{Array<ByteString>{std::move(issuer)}};
    request.input_arguments()[4] = Variant{String{"PEM"}};
    request.input_arguments()[5] = Variant{keys->private_key_pem()};
    return call_method(MethodId::ServerConfiguration_UpdateCertificate, std::move(request));
  };

  auto issuerBytes = sCaCert->der_encoding();
  std::vector<byte> trailing(issuerBytes.size());
  std::memcpy(trailing.data(), issuerBytes.data(), issuerBytes.size());
  trailing.push_back(byte{0x00});
  trailing.push_back(byte{0x00});
  auto badIssuer = update(candidate->der_encoding(), ByteString{std::move(trailing)});
  ASSERT_TRUE(badIssuer) << badIssuer.status_code();
  EXPECT_EQ(badIssuer.value().status_code(), StatusCode{Status::BadSecurityChecksFailed})
    << "an issuer that will not parse: " << badIssuer.value().status_code();

  auto badCertificate =
    update(ByteString{std::vector<byte>{byte{0x30}, byte{0x01}}}, sCaCert->der_encoding());
  ASSERT_TRUE(badCertificate) << badCertificate.status_code();
  EXPECT_EQ(badCertificate.value().status_code(), StatusCode{Status::BadCertificateInvalid})
    << "the new certificate that will not parse: " << badCertificate.value().status_code();
}

// Control for the filter above: an endpoint that presents ECC certificates still judges a pushed ECC
// certificate. The ECC policy requires an ECDSA signer, so a certificate signed by the RSA CA is refused by
// the endpoint policy itself. Falsifiable: a filter that dropped every endpoint accepts it.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-146-UPDATE-CERTIFICATE-READS-SERVED-POLICIES-AT-CALL-TIME, scope=function)
TEST_F(PushManagementLateEndpointPolicies, AnEccEndpointStillJudgesAnEccCertificate)
{
  auto eccKeys = sCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::EccNistP256, std::nullopt);
  ASSERT_NE(eccKeys, nullptr);
  Crypto::CreateCertificateConfig p;
  p.subjectKeys = eccKeys;
  p.issuerKeys = sCaKeys;
  p.issuer = sCaCert;
  p.subject.commonName = "EccLeaf";
  p.serialNumber = "9104";
  p.keyUsage.digitalSignature = true;
  p.keyUsage.nonRepudiation = true;
  p.keyUsage.keyAgreement = true;
  p.keyUsage.serverAuth = true;
  p.keyUsage.clientAuth = true;
  p.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha1;
  p.from = DateTime::now();
  p.to = DateTime{p.from.value() + std::chrono::days{30}};
  p.subjectAlternateName.uris = {"urn:test:server"};
  p.subjectAlternateName.hostnames = {"localhost"};
  const auto candidate = sPki->create_cert(p);

  // The group offers the ECC type because the store holds an ECC certificate when push management is wired.
  CertificateStore::ApplicationCertificate rsa;
  rsa.certificateType = CertificateType::RsaSha256Application;
  rsa.certificate = sLeafCert;
  rsa.keys = sLeafKeys;
  mFakeStore->appCerts.push_back(rsa);
  CertificateStore::ApplicationCertificate ecc;
  ecc.certificateType = CertificateType::EccNistP256Application;
  ecc.certificate = candidate;
  ecc.keys = eccKeys;
  mFakeStore->appCerts.push_back(ecc);
  mServedEndpointPolicies = []()
  {
    return std::vector<std::pair<std::string, std::shared_ptr<const SecurityPolicy>>>{
      {"EccNistP256_SignAndEncrypt", SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm)}};
  };
  wire();

  CallMethodRequest request;
  request.input_arguments().resize(6);
  request.input_arguments()[0] =
    Variant{NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup}};
  request.input_arguments()[1] =
    Variant{NodeId{0, static_cast<uint32_t>(ObjectTypeId::EccNistP256ApplicationCertificateType)}};
  request.input_arguments()[2] = Variant{candidate->der_encoding()};
  request.input_arguments()[3] = Variant{Array<ByteString>{sCaCert->der_encoding()}};
  request.input_arguments()[4] = Variant{String{"PEM"}};
  request.input_arguments()[5] = Variant{eccKeys->private_key_pem()};
  auto callResult = call_method(MethodId::ServerConfiguration_UpdateCertificate, std::move(request));
  ASSERT_TRUE(callResult) << callResult.status_code();
  EXPECT_EQ(callResult.value().status_code(), StatusCode{Status::BadSecurityChecksFailed})
    << "the ECC endpoint, which presents the ECC certificate, still judges it: "
    << callResult.value().status_code();
  const auto detail = callResult.value().status_code().shared_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "CertificateViolatesEndpointPolicy")
    << "refused by the endpoint policy, not elsewhere";
}

// The TransactionDiagnostics snapshot is written from the push service's strand when a transaction ends.
// Each Variable is written through whatever serves it, which may answer by posting to the executor that
// strand runs on. On a one-thread executor a blocking write waits there for an answer that can only run
// there, so ApplyChanges never returns; the asynchronous writes must let it return, and the Variable must
// still receive its value.
//
// Use a private address space: replacing StartTime's value source cannot be undone, and the other tests
// must not depend on an executor that this test has already stopped when their order is shuffled.
TEST_F(PushManagementWiringTest, TransactionDiagnosticsPublishCompletesWhenTheWriteIsAnsweredByPosting)
{
  mIsolatedAddressSpace.emplace(AddressSpace::create("uri:test:push", sPool->executor()));
  load_ns0(sLimits, *mIsolatedAddressSpace, sStructureFactory);

  ua::test::OneThreadExecutor executor;
  wire({}, executor.executor());

  auto startTime = as().try_find_node_sync(NodeId{diagStartTime});
  ASSERT_TRUE(startTime.is_good());
  auto* source = startTime.value()->external_value_source();
  ASSERT_NE(source, nullptr);
  auto written = std::make_shared<std::atomic<int>>(0);
  ASSERT_TRUE(source
                ->set_value_source(make_value_source([](const ValueSource::ReadContext&,
                                                       const Node&,
                                                       const ReadValueId&,
                                                       std::function<void(DataValueResult)>
                                                         complete) { complete(DataValue{}); },
                  [answerExecutor = executor.executor(), written](const ValueSource::WriteContext&,
                    const Node&,
                    const WriteValue&,
                    std::function<void(ValueSource::WriteResult)>
                      complete)
                  {
                    ++*written;
                    boost::asio::post(answerExecutor,
                      [complete = std::move(complete)]() mutable { complete(ValueSource::Written{}); });
                  }))
                .is_good());

  auto updateResult = stage_certificate_update();
  ASSERT_TRUE(updateResult) << "UpdateCertificate call failed: " << updateResult.status_code();
  ASSERT_TRUE(updateResult.value().status_code().is_good());

  auto applyChanges = as().try_find_node_sync(NodeId{MethodId::ServerConfiguration_ApplyChanges});
  ASSERT_TRUE(applyChanges.is_good());
  const auto applyChangesMethod = applyChanges.value().as<MethodAccessor>();
  ASSERT_TRUE(applyChangesMethod.has_value());
  CallMethodRequest applyChangesRequest;
  applyChangesRequest.object_id() = object_of(applyChanges.value());
  applyChangesRequest.method_id() = NodeId{MethodId::ServerConfiguration_ApplyChanges};
  auto context = std::make_shared<MethodCallContext>();
  context->sessionId = mSessionA;
  ua::detail::MethodCallContextInternalAccess::set_response_correlation(*context, {1, 42});
  context->channelSecurityMode = MessageSecurityMode::SignAndEncrypt;
  auto promise = std::make_shared<std::promise<CallResult>>();
  auto future = promise->get_future();
  applyChangesMethod->call_async(
    applyChangesRequest, context, [promise](CallResult result) { promise->set_value(std::move(result)); });
  ASSERT_EQ(future.wait_for(std::chrono::seconds{10}), std::future_status::ready)
    << "publishing TransactionDiagnostics blocked the thread its Variable's write answers on";
  auto applied = future.get();
  ASSERT_TRUE(applied.is_good());
  EXPECT_TRUE(applied.value().status_code().is_good()) << applied.value().status_code();
  EXPECT_EQ(written->load(), 1) << "StartTime was not written";

  // Shut the components down while their executor still runs; TearDown would do it after this test's
  // executor has been destroyed, and their shutdown waits on it.
  mComponents.trustList->shutdown();
  mComponents.certificatePushService->shutdown();
  mComponents = PushManagementComponents{};
}
