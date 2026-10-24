// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientWrite cluster of the client integration-test matrix (the 13 `ClientWrite.*` rows).
///
/// These are END-TO-END integration tests of the TIER-2 managed write accessor
/// (`ua::client::Connection` - `write_value_*`, `typed()`, `service_requests()`, section 7.2) against a real
/// in-tree server. The tier-2 `Connection` is built by wrapping a real `ConnectionImpl` over an
/// activated tier-0 Session (the same construction the ClientRead slice and the reconnect integration
/// test use). The Connection is built WITHOUT reconnect wiring, so it is single-shot and runs NO
/// keep-alive poll: there are no background writes to race the MisbehavingServer response mutators, and
/// the bootstrap runs against an un-mutated server (mutators are armed only AFTER `start`).
///
/// Fixture split (matches the ClientRead slice + the coordinator's direction):
///   - Round-trip / capture / local-validation rows derive the fixture from `ComplianceWithNodes` and
///     write against real, pre-`start` nodes. "What the client put on the wire" is captured with a
///     SERVER-SIDE write value handler on the target node (mirrors ClientRead's
///     `MaxAgeZeroAndInt32MaxPassThroughUnclamped`, which captured the wire MaxAge the same way).
///   - The response-shape rows stand up their own `MisbehavingServer` and drive the write facade
///     through injected WriteResponse mutations (wrong results-count, per-slot bad code, service-level
///     serviceResult) - exactly as ClientRead did with ReadResponse.
///
/// Falsifiability: every test encodes the matrix row's `[neg: ...]` falsifier. Local shape validation is
/// exercised through public tier-2 `Connection::write_value`; a server-side value handler is used only as
/// the no-Wire observation interface because the public client API intentionally exposes no frame counter.
/// AccessLevelEx pre-wire validation remains scoped independently by its owning requirement.

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"

#include "misbehaving_server.h"

#include "ua_connection.h"
#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_service_set.h"
#include "ua_typed_access.h"

#include "ua_access_level_ex_type.h"
#include "ua_access_level_type.h"
#include "ua_application_configuration.h"
#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_byte_string.h"
#include "ua_client.h"
#include "ua_client_secure_channel.h"
#include "ua_client_session.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_date_time.h"
#include "ua_default_variable_node.h"
#include "ua_localized_text.h"
#include "ua_logger.h"
#include "ua_node.h"
#include "ua_range.h"
#include "ua_read_value_id.h"
#include "ua_ref_structure.h"
#include "ua_referencetype_id.h"
#include "ua_relative_path.h"
#include "ua_relative_path_element.h"
#include "ua_translated_node_id.h"
#include "ua_status.h"
#include "ua_structure.h"
#include "ua_to_string.h"
#include "ua_numeric_range_parser.h"
#include "ua_value_rank.h"
#include "ua_value_source.h"
#include "ua_variabletype_id.h"
#include "ua_variable_id.h"
#include "ua_variant.h"
#include "ua_data_access_utils.h"
#include "ua_server_configuration.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_write_value.h"

#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

using ua::test_helpers::MisbehavingServer;

namespace
{

// ---------------------------------------------------------------------------------------------
// StartedConnection: wraps a `ConnectionImpl` (built over an activated Session, no reconnect wiring
// -> single-shot, no keep-alive) into the public tier-2 `Connection` handle, runs the bootstrap, and
// closes gracefully on destruction. Copied from the ClientRead slice - the same tier-2 write interface.
// ---------------------------------------------------------------------------------------------
class StartedConnection
{
public:
  StartedConnection(
    boost::asio::any_io_executor executor, Session session, ua::client::detail::ConnectionConfig config = {})
  {
    auto impl = ua::client::detail::ConnectionImpl::create(
      std::move(executor), std::move(session), std::move(config), Logger{});

    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    impl->start_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
    mStartStatus = future.get();

    mConnection.emplace(ua::client::detail::ConnectionHandleFactory::make_connection(std::move(impl)));
  }

  ~StartedConnection()
  {
    if (mConnection)
      (void)mConnection->try_close_sync();
  }

  StartedConnection(const StartedConnection&) = delete;
  StartedConnection& operator=(const StartedConnection&) = delete;

  const VoidResult& start_status() const
  {
    return mStartStatus;
  }

  Connection& operator*()
  {
    return *mConnection;
  }

  Connection* operator->()
  {
    return &*mConnection;
  }

private:
  VoidResult mStartStatus{};  // default-constructs to Good
  std::optional<Connection> mConnection;
};

// ---------------------------------------------------------------------------------------------
// MisbehavingWriteFixture: a real client bound to a MisbehavingServer's crypto + trusted certificate
// store, on its own thread pool, with an activated Session wrapped into a started tier-2 Connection.
// The bootstrap completes against the un-mutated server; the test arms the response mutators AFTER
// construction. Mirror of the ClientRead slice's MisbehavingReadFixture.
// ---------------------------------------------------------------------------------------------
class MisbehavingWriteFixture
{
public:
  explicit MisbehavingWriteFixture(MisbehavingServer& server)
  {
    auto appConfig = ua::test_utils::create_test_config();
    appConfig.application_description_part().applicationUri = "urn:test:misbehaving:client";
    ua::client::CreateConfig clientConfig{
      .identity = ApplicationIdentity::load_default(), .application = std::move(appConfig)};
    mClient.emplace(Client::create(mThreadPool.executor(),
      std::move(clientConfig),
      ua::client::ClientComponents{.crypto = server.crypto(),
        .applicationGroupCertificateStore = server.client_certificate_store(),
        .logLevel = LogLevel::Warning}));

    CoreClient::OpenChannelConfig openConfig;
    openConfig.endpointUrl = server.endpoint_url_none();
    openConfig.timeout = 5000ms;
    auto channel = mClient->core().open_channel_sync(openConfig);
    auto session = channel.create_session_sync({.sessionName = "ClientWriteMatrix"});
    session.activate_sync();
    mConnection.emplace(mThreadPool.executor(), std::move(session));
  }

  ~MisbehavingWriteFixture()
  {
    mConnection.reset();
    mClient.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  MisbehavingWriteFixture(const MisbehavingWriteFixture&) = delete;
  MisbehavingWriteFixture& operator=(const MisbehavingWriteFixture&) = delete;

  Connection& conn()
  {
    return **mConnection;
  }

  const VoidResult& start_status() const
  {
    return mConnection->start_status();
  }

private:
  boost::asio::thread_pool mThreadPool;
  std::optional<Client> mClient;
  std::optional<StartedConnection> mConnection;
};

// Records every WriteValue that reached a node's server-side value handler (what the client actually put
// on the wire, decoded by the server). Guarded because the handler runs on a server worker while the
// test thread reads the captured values.
struct WriteCapture
{
  mutable std::mutex mutex;
  std::vector<DataValue> values;
  std::vector<String> indexRanges;

  std::vector<DataValue> snapshot() const
  {
    std::lock_guard lock(mutex);
    return values;
  }
};

// A readable/writable NS0 node present on every server (an enum-backed Int32 value). Used as the
// arbitrary Write target for the MisbehavingServer response-shape rows (the response is replaced, so the
// node's real write verdict is irrelevant - only that the server emits a WriteResponse to be mutated).
NodeId server_state_node()
{
  return NodeId{VariableId::Server_ServerStatus_State};
}

// Extracts the raw bytes from a Variant holding either a ByteString or a Byte array, so a ByteString /
// Byte[] round-trip can be compared byte-for-byte regardless of which representation the server stored.
std::optional<std::vector<uint8_t>> extract_bytes(const Variant& variant)
{
  if (const auto* byteString = variant.try_as<ByteString>())
    return std::vector<uint8_t>(byteString->begin(), byteString->end());
  auto asVector = variant.to_vector<uint8_t>();
  if (asVector.is_good())
    return asVector.value();
  return std::nullopt;
}

}  // namespace

// =============================================================================================
// Fixture: one gtest suite `ClientWrite`. Derives from ComplianceWithNodes so the round-trip /
// capture / local-validation rows have a populated address space; the extra nodes those rows need are
// created here, BEFORE the server starts (no post-start node registration).
// =============================================================================================
class ClientWrite : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();

    auto addressSpace = mServer.server().address_space();
    const AccessLevelType readWrite{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite};

    // ComplianceWithNodes creates this Byte[] target before this fixture hook. Complete its mandatory
    // Variable shape metadata so the public tier-2 path can validate it rather than treating missing
    // ArrayDimensions as an array-metadata failure.
    {
      auto byteArrayVariable = addressSpace.find_node_sync(mByteArrayVariableId).as<VariableAccessor>();
      byteArrayVariable->set_value_rank(ValueRank{1});
      byteArrayVariable->set_array_dimensions(std::vector<std::uint32_t>{0});
    }

    auto createVariable = [&](uint32_t id,
                            DataTypeId dataType,
                            std::string_view name,
                            ValueRank valueRank = ValueRank{-1}) -> NodeId
    {
      NodeId nodeId{mTestNamespaceIndex, id};
      auto node = addressSpace.create_node_sync(nodeId, NodeClass::Variable);
      auto variable = node.as<VariableAccessor>();
      variable->set_browse_name(QualifiedName{mTestNamespaceIndex, std::string{name}});
      variable->set_display_name(LocalizedText{"", std::string{name}});
      variable->set_data_type(NodeId{dataType});
      variable->set_value_rank(valueRank);
      if (valueRank.as_int32() == -1)
        variable->set_array_dimensions(std::nullopt);
      variable->set_access_level(readWrite);
      return nodeId;
    };

    // ByteString-typed scalar Variable (ByteString <-> Byte[] interchange, Row 1 reverse direction).
    mByteStringId = createVariable(8000, DataTypeId::ByteString, "WritableByteString");

    // Full-access Int32 capture node (Value + Status + timestamps carriage, Rows 8/9): needs the
    // StatusWrite + TimestampWrite bits so a status/timestamp write clears the server's access gate and
    // reaches the capturing value handler.
    mCaptureInt32Id = NodeId{mTestNamespaceIndex, uint32_t{8010}};
    {
      auto node = addressSpace.create_node_sync(mCaptureInt32Id, NodeClass::Variable);
      auto variable = node.as<VariableAccessor>();
      variable->set_browse_name(QualifiedName{mTestNamespaceIndex, "CaptureInt32"});
      variable->set_display_name(LocalizedText{"", "CaptureInt32"});
      variable->set_data_type(NodeId{DataTypeId::Int32});
      variable->set_value_rank(ValueRank{-1});
      variable->set_array_dimensions(std::nullopt);
      variable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead,
        AccessLevelType::Bit::CurrentWrite,
        AccessLevelType::Bit::StatusWrite,
        AccessLevelType::Bit::TimestampWrite});
    }

    // LocalizedText-typed capture node (null-vs-empty semantics, Row 10).
    mCaptureLtId = createVariable(8011, DataTypeId::LocalizedText, "CaptureLocalizedText");

    // Full-array-only Int32 array (Row 3 case A + Row 12): AccessLevelEx.WriteFullArrayOnly set.
    mFullArrayOnlyId = NodeId{mTestNamespaceIndex, uint32_t{8020}};
    {
      auto node = addressSpace.create_node_sync(mFullArrayOnlyId, NodeClass::Variable);
      auto variable = node.as<VariableAccessor>();
      variable->set_browse_name(QualifiedName{mTestNamespaceIndex, "FullArrayOnly"});
      variable->set_display_name(LocalizedText{"", "FullArrayOnly"});
      variable->set_data_type(NodeId{DataTypeId::Int32});
      variable->set_value_rank(ValueRank{1});
      variable->set_array_dimensions(std::vector<std::uint32_t>{10});
      variable->set_access_level(readWrite);
      variable->set_access_level_ex(AccessLevelExType{AccessLevelExType::Bit::CurrentRead,
        AccessLevelExType::Bit::CurrentWrite,
        AccessLevelExType::Bit::WriteFullArrayOnly});
      Array<int32_t> initial;
      for (int32_t i = 0; i < 10; ++i)
        initial.push_back(i);
      variable->write_value_sync(initial);
    }

    // Plain Int32 array (Row 3 case B: a ranged write with the clear WriteFullArrayOnly bit). Ten
    // elements so an IndexRange '0:5' is in-bounds.
    mRangeArrayId = createVariable(8021, DataTypeId::Int32, "RangeArray", ValueRank{1});
    {
      auto variable = addressSpace.find_node_sync(mRangeArrayId).as<VariableAccessor>();
      variable->set_array_dimensions(std::vector<std::uint32_t>{10});
      Array<int32_t> initial;
      for (int32_t i = 0; i < 10; ++i)
        initial.push_back(i);
      variable->write_value_sync(initial);
    }

    // Rank-2 Variable (Row 11 rank-mismatch): ValueRank=2, ArrayDimensions=[3,4].
    mRank2Id = NodeId{mTestNamespaceIndex, uint32_t{8030}};
    {
      auto node = addressSpace.create_node_sync(mRank2Id, NodeClass::Variable);
      auto variable = node.as<VariableAccessor>();
      variable->set_browse_name(QualifiedName{mTestNamespaceIndex, "Rank2Double"});
      variable->set_display_name(LocalizedText{"", "Rank2Double"});
      variable->set_data_type(NodeId{DataTypeId::Double});
      variable->set_value_rank(ValueRank{2});
      variable->set_array_dimensions(std::vector<uint32_t>{3, 4});
      variable->set_access_level(readWrite);
    }

    // AnalogItem (Double) with EURange [0, 100] + the Data Access write check (Reject policy), so
    // an out-of-range write surfaces Bad_OutOfRange (Row 2).
    mAnalogId = NodeId{mTestNamespaceIndex, uint32_t{8040}};
    {
      auto node = addressSpace.create_node_sync(mAnalogId, NodeClass::Variable);
      auto variable = node.as<VariableAccessor>();
      variable->set_browse_name(QualifiedName{mTestNamespaceIndex, "AnalogValue"});
      variable->set_display_name(LocalizedText{"", "AnalogValue"});
      variable->set_data_type(NodeId{DataTypeId::Double});
      variable->set_value_rank(ValueRank{-1});
      variable->set_array_dimensions(std::nullopt);
      variable->set_access_level(readWrite);
      variable->write_value_sync(double{50.0});
      node.add_reference_sync(
        NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::AnalogItemType});
    }
    mEuRangeId = NodeId{mTestNamespaceIndex, uint32_t{8041}};
    {
      auto node = addressSpace.create_node_sync(mEuRangeId, NodeClass::Variable);
      auto variable = node.as<VariableAccessor>();
      variable->set_browse_name(QualifiedName{0, "EURange"});
      variable->set_data_type(NodeId{DataTypeId::Range});
      variable->set_value_rank(ValueRank{-1});
      variable->set_array_dimensions(std::nullopt);
      auto range = std::make_unique<Range>();
      range->low() = 0.0;
      range->high() = 100.0;
      variable->write_value_sync(DataValue{Variant{RefStructure<Structure>{std::move(range)}}});
      node.add_reference_sync(
        NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
      addressSpace.find_node_sync(mAnalogId).add_reference_sync(
        NodeId{ReferenceTypeId::HasProperty}, mEuRangeId);
    }
  }

  void configure_server_config(ServerConfig& cfg) override
  {
    ComplianceWithNodes::configure_server_config(cfg);
    cfg.dataAccessWritePolicy = DataAccessOutOfRangePolicy::Reject;
  }

  // Opens a fresh channel + activated session on the fixture's (normal) server, leaving mSession
  // untouched. The returned Session is consumed to build a managed tier-2 Connection.
  Session open_activated_session(std::string name)
  {
    auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
    auto session = channel.create_session_sync({.sessionName = std::move(name)});
    session.activate_sync();
    return session;
  }

  // Installs a server-side write value handler on @p nodeId that records every incoming WriteValue (the
  // decoded wire frame the client produced) and stores it so a read-back still works. Mirrors
  // ClientRead's value-source capture of the wire MaxAge.
  std::shared_ptr<WriteCapture> install_write_capture(const NodeId& nodeId)
  {
    auto capture = std::make_shared<WriteCapture>();
    auto node = std::dynamic_pointer_cast<default_ns::VariableNode>(mTestNamespace->find_node<Node>(nodeId));
    EXPECT_NE(node, nullptr) << "capture target must be a default-namespace Variable";
    EXPECT_TRUE(node->external_value_source()
                  ->set_value_source(make_value_source(
                    [capture](const ValueSource::ReadContext& /*context*/,
                      const Node& /*node*/,
                      const ReadValueId& read,
                      std::function<void(DataValueResult)>
                        callback)
                    {
                      DataValue last;
                      {
                        std::lock_guard lock(capture->mutex);
                        if (!capture->values.empty())
                          last = capture->values.back();
                      }
                      index_range_utils::apply_to_value(last, read.index_range());
                      callback(DataValueResult{std::move(last)});
                    },
                    [capture](const ValueSource::WriteContext& /*context*/,
                      const Node& /*node*/,
                      const WriteValue& write,
                      std::function<void(ValueSource::WriteResult)>
                        callback)
                    {
                      {
                        std::lock_guard lock(capture->mutex);
                        capture->values.push_back(write.value());
                        capture->indexRanges.push_back(write.index_range());
                      }
                      callback(ValueSource::Written{});
                    }))
                  .is_good());
    return capture;
  }

  NodeId mByteStringId;
  NodeId mCaptureInt32Id;
  NodeId mCaptureLtId;
  NodeId mFullArrayOnlyId;
  NodeId mRangeArrayId;
  NodeId mRank2Id;
  NodeId mAnalogId;
  NodeId mEuRangeId;
};

// =============================================================================================
// Row 1 - ByteStringByteArrayEquivalence  (ComplianceWithNodes)
// The tier-2 typed write must ACCEPT (never client-reject) both a ByteString Variant and a Byte[]
// Variant and forward each to the wire; the client must not fabricate a local type rejection.
// [neg: ByteString/Byte[] interchange]
//
// REPORTED tested-contract conflict: the matrix oracle expects BOTH directions to round-trip Good, but
// the in-tree server's Write type check (ua_attribute_service_set.cpp:1859) deliberately whitelists only
// ByteString -> Byte[] (the SVR-ATTR-WRITE-011 tested contract), NOT Byte[] -> ByteString, which it rejects
// with Bad_TypeMismatch. That is a SERVER-side asymmetry, not a client rejection; the falsifier is
// "either direction is CLIENT-rejected", so this test pins the client-observable guarantee: the client
// forwards both Variant shapes and its tier-2 verdict equals the raw tier-0 per-operation verdict (no
// local fabrication). The Byte[] -> ByteString direction is reported as blocked on the server type check
// (not changed here without approval).
// =============================================================================================
// @verifies CL-ATTR-020
// @relation(CL-ATTR-020, scope=function)
TEST_F(ClientWrite, ByteStringByteArrayEquivalence)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("W1")};
  ASSERT_TRUE(connection.start_status().is_good());

  const std::vector<uint8_t> payload{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x7F};

  // ByteString -> Byte[]-typed Variable: the server permits ByteString-as-Byte[], so this round-trips.
  ASSERT_TRUE(connection->try_write_value_sync(mByteArrayVariableId, Variant{ByteString{payload}}).is_good())
    << "a ByteString written to a Byte[] Variable must not be client-rejected";
  {
    auto readBack = connection->try_read_value_sync(mByteArrayVariableId);
    ASSERT_TRUE(readBack.is_good());
    auto bytes = extract_bytes(readBack.value().value());
    ASSERT_TRUE(bytes.has_value()) << "the read-back value must hold bytes";
    EXPECT_EQ(*bytes, payload) << "ByteString -> Byte[] must round-trip byte-for-byte";
  }

  // Byte[] -> ByteString-typed Variable: the client must FORWARD it (not reject locally). The in-tree
  // server rejects the reverse direction with Bad_TypeMismatch; the client-observable guarantee is that
  // tier-2 surfaces the server's exact per-operation verdict, identical to the raw tier-0 path.
  Array<uint8_t> byteArray;
  for (uint8_t byte : payload)
    byteArray.push_back(byte);

  auto tier2 = connection->try_write_value_sync(mByteStringId, Variant{byteArray});
  auto tier1 = connection->service_requests().try_write_sync(
    WriteRequestBuilder().write(mByteStringId, Variant{byteArray}));
  ASSERT_TRUE(tier1.is_good()) << "the Write service itself completes; any failure is per-operation";
  ASSERT_EQ(tier1.value().results().size(), 1u);
  const StatusCode rawPerOp = tier1.value().results()[0];
  const StatusCode tier2Status = tier2.is_bad() ? tier2.status_code() : StatusCode{Status::Good};
  EXPECT_EQ(tier2Status.value(), rawPerOp.value())
    << "tier-2 must surface the server's exact per-operation verdict for the Byte[] -> ByteString write, "
       "never fabricate a local rejection";
  EXPECT_EQ(rawPerOp.as_status(), Status::BadTypeMismatch)
    << "the in-tree server rejects Byte[] -> ByteString with Bad_TypeMismatch (server-side asymmetry)";
}

// =============================================================================================
// Row 2 - AnalogValueOutsideEuRangeStatusRoundTrips  (ComplianceWithNodes)
// For the known in-tree AnalogItem (InstrumentRange/EURange 0..100), out-of-range writes (-1, 101)
// must surface a Bad code and MUST NOT be Good; the tier-2 status must equal the raw tier-1
// per-operation StatusCode for the same op (tier-2 does not rewrite it).
// [neg: below-low and above-high writes]
// =============================================================================================
// @verifies CL-ADDRSP-005
// @relation(CL-ADDRSP-005, scope=function)
TEST_F(ClientWrite, AnalogValueOutsideEuRangeStatusRoundTrips)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("W2")};
  ASSERT_TRUE(connection.start_status().is_good());

  // Stimulus: resolve EURange via resolve_path (TranslateBrowsePaths) + Read and confirm the [0, 100] bounds.
  RelativePath toEuRange;
  {
    RelativePathElement step;
    step.reference_type_id() = NodeId{ReferenceTypeId::HasProperty};
    step.is_inverse() = false;
    step.include_subtypes() = true;
    step.target_name() = QualifiedName{0, "EURange"};
    toEuRange.elements().push_back(step);
  }
  auto translated = connection->typed().try_resolve_path_sync(mAnalogId, toEuRange);
  ASSERT_TRUE(translated.is_good()) << "EURange must resolve to one local node under the AnalogItem: "
                                    << to_string(translated.status_code());
  const NodeId resolvedEuRange = translated.value();
  EXPECT_EQ(resolvedEuRange, mEuRangeId);

  auto euRange = connection->try_read_value_sync(resolvedEuRange);
  ASSERT_TRUE(euRange.is_good());
  ASSERT_FALSE(euRange.value().value().empty()) << "the EURange Property must carry a value";
  // If the client decoded the ExtensionObject to a concrete Range, confirm the known [0, 100] bounds.
  if (const Range* range = euRange.value().value().try_as<Range>())
  {
    EXPECT_DOUBLE_EQ(range->low(), 0.0);
    EXPECT_DOUBLE_EQ(range->high(), 100.0);
  }

  // Out-of-range writes must be Bad, and the tier-2 verdict must equal the raw tier-1 per-op status.
  for (double outOfRange : {-1.0, 101.0})
  {
    auto tier2 = connection->try_write_value_sync(mAnalogId, Variant{outOfRange});
    EXPECT_TRUE(tier2.is_bad()) << "an out-of-range write (" << outOfRange << ") must not be Good";

    auto tier1 = connection->service_requests().try_write_sync(
      WriteRequestBuilder().write(mAnalogId, Variant{outOfRange}));
    ASSERT_TRUE(tier1.is_good()) << "the Write service itself succeeds; the failure is per-operation";
    ASSERT_EQ(tier1.value().results().size(), 1u);
    const StatusCode rawPerOp = tier1.value().results()[0];
    EXPECT_TRUE(rawPerOp.is_bad());
    EXPECT_EQ(tier2.status_code().value(), rawPerOp.value())
      << "tier-2 must surface the exact tier-1 per-operation StatusCode, not rewrite it; detail="
      << (tier2.shared_detail() ? to_string(*tier2.shared_detail()) : std::string{"<none>"});
  }
}

// =============================================================================================
// Row 3 - WriteFullArrayOnlyAllowsFullArrayAndClearBitAllowsRange  (ComplianceWithNodes)
// Case A: WriteFullArrayOnly=1, a full-array write (null IndexRange) must reach the wire and be Good.
// Case B: WriteFullArrayOnly=0, an IndexRange '0:5' write must reach the wire and be Good. The client
// must NOT over-block either legitimate write. [neg: must not over-block legitimate writes]
// =============================================================================================
// @verifies CL-ADDRSP-014
// @relation(CL-ADDRSP-014, scope=function)
TEST_F(ClientWrite, WriteFullArrayOnlyAllowsFullArrayAndClearBitAllowsRange)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("W3")};
  ASSERT_TRUE(connection.start_status().is_good());

  // Case A: full-array write to the WriteFullArrayOnly=1 node (null IndexRange, via write_value).
  Array<int32_t> fullArray;
  for (int32_t i = 100; i < 110; ++i)
    fullArray.push_back(i);
  auto caseA = connection->try_write_value_sync(mFullArrayOnlyId, Variant{fullArray});
  EXPECT_TRUE(caseA.is_good())
    << "a full-array write to a WriteFullArrayOnly Variable must not be over-blocked: "
    << to_string(caseA.status_code());

  // Case B: IndexRange '0:5' write to the WriteFullArrayOnly=0 node through public tier 2.
  Array<int32_t> rangeSlice;
  for (int32_t i = 0; i < 6; ++i)
    rangeSlice.push_back(500 + i);
  auto caseB = connection->typed().try_write_attribute_sync(
    mRangeArrayId, AttributeId::Value, String{"0:5"}, DataValue{Variant{rangeSlice}});
  EXPECT_TRUE(caseB.is_good())
    << "a ranged write with the clear WriteFullArrayOnly bit must not be over-blocked";
}

// =============================================================================================
// Row 4 - GoodCompletesAsynchronouslyTreatedAsGood  (MisbehavingServer)
// A per-operation Good_CompletesAsynchronously must NOT be treated as a failure: the tier-2 write
// reports success. The Good sub-code cannot be carried by a VoidResult (Result<void> requires a
// non-Good StatusCode), so its exact preservation is asserted on the raw tier-0 WriteResponse instead.
// [neg: Good sub-code not treated as failure]
// =============================================================================================
// @verifies CL-ATTR-018
// @relation(CL-ATTR-018, scope=function)
TEST_F(ClientWrite, GoodCompletesAsynchronouslyTreatedAsGood)
{
  MisbehavingServer server;
  MisbehavingWriteFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  server.set_response_mutator(
    [](Response& response)
    {
      if (auto* writeResponse = dynamic_cast<WriteResponse*>(response.second.get()))
      {
        if (!writeResponse->results().empty())
          writeResponse->results()[0] = StatusCode{Status::GoodCompletesAsynchronously};
      }
    });
  // tier-2: a Good sub-code is not a failure -> the write reports success.
  auto tier2 = fixture.conn().try_write_value_sync(server_state_node(), Variant{int32_t{7}});
  EXPECT_TRUE(tier2.is_good()) << "Good_CompletesAsynchronously must not be reclassified as a failure";
  fixture.conn().write_value_sync(server_state_node(), Variant{int32_t{7}});  // must not throw

  // tier-0: the exact Good sub-code is preserved verbatim on the raw WriteResponse.
  auto tier0 = fixture.conn().service_requests().try_write_sync(
    WriteRequestBuilder().write(server_state_node(), Variant{int32_t{7}}));
  ASSERT_TRUE(tier0.is_good());
  ASSERT_EQ(tier0.value().results().size(), 1u);
  EXPECT_EQ(tier0.value().results()[0].value(), StatusCode{Status::GoodCompletesAsynchronously}.value())
    << "the Good sub-code must survive verbatim on the raw tier-0 WriteResponse";
}

// =============================================================================================
// Row 5 - OperationAndServiceErrorsSurfacedPerCode  (MisbehavingServer)
// A stamped service-level serviceResult and a stamped per-operation bad StatusCode must each surface
// to the tier-2 caller with its exact code; neither may be swallowed into a Good result.
// [neg: write error-code catalogue]
// =============================================================================================
// @verifies CL-ATTR-017
// @verifies CL-ATTR-019
// @relation(CL-ATTR-017, CL-ATTR-019, scope=function)
TEST_F(ClientWrite, OperationAndServiceErrorsSurfacedPerCode)
{
  MisbehavingServer server;
  MisbehavingWriteFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto serviceResult = std::make_shared<std::atomic<uint32_t>>(0);  // 0 = leave untouched
  auto perOpResult = std::make_shared<std::atomic<uint32_t>>(0);  // 0 = leave untouched
  server.set_response_mutator(
    [serviceResult, perOpResult](Response& response)
    {
      auto* writeResponse = dynamic_cast<WriteResponse*>(response.second.get());
      if (!writeResponse)
        return;
      if (const uint32_t code = serviceResult->load(); code != 0)
        writeResponse->response_header().service_result() = StatusCode{code};
      if (const uint32_t code = perOpResult->load(); code != 0 && !writeResponse->results().empty())
        writeResponse->results()[0] = StatusCode{code};
    });

  // Service-level errors (Err-001 family): stamped on ResponseHeader.serviceResult.
  for (Status status : {Status::BadTooManyOperations, Status::BadServiceUnsupported, Status::BadOutOfRange})
  {
    serviceResult->store(StatusCode{status}.as_uint32());
    perOpResult->store(0);
    auto result = fixture.conn().try_write_value_sync(server_state_node(), Variant{int32_t{1}});
    EXPECT_TRUE(result.is_bad()) << "a service-level error must be surfaced, not swallowed";
    EXPECT_EQ(result.status_code().value(), StatusCode{status}.value())
      << "the exact service-level code must surface";
  }

  // Per-operation errors (Err-002/003 families): stamped on results[0].
  for (Status status : {Status::BadWriteNotSupported,
         Status::BadTypeMismatch,
         Status::BadOutOfRange,
         Status::BadNotWritable,
         Status::BadNodeIdInvalid})
  {
    serviceResult->store(0);
    perOpResult->store(StatusCode{status}.as_uint32());
    auto result = fixture.conn().try_write_value_sync(server_state_node(), Variant{int32_t{1}});
    EXPECT_TRUE(result.is_bad()) << "a per-operation error must be surfaced, not swallowed";
    EXPECT_EQ(result.status_code().value(), StatusCode{status}.value())
      << "the exact per-operation code must surface";
  }
}

// =============================================================================================
// Row 6 - PartialSuccessReportedPerSlotNoRollback  (MisbehavingServer)
// A 3-item bulk write whose server results are {Good, Bad_TypeMismatch, Good} must surface all three
// statuses positionally, and the SDK must emit NO compensating Write afterward (no client-side
// rollback). [neg: partial write, no client rollback]
// =============================================================================================
// @verifies CL-ATTR-019
// @relation(CL-ATTR-019, scope=function)
TEST_F(ClientWrite, PartialSuccessReportedPerSlotNoRollback)
{
  MisbehavingServer server;
  MisbehavingWriteFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto writeResponses = std::make_shared<std::atomic<uint64_t>>(0);
  server.set_response_mutator(
    [writeResponses](Response& response)
    {
      auto* writeResponse = dynamic_cast<WriteResponse*>(response.second.get());
      if (!writeResponse)
        return;
      writeResponses->fetch_add(1);
      if (writeResponse->results().size() != 3)
        return;
      writeResponse->results()[0] = StatusCode{Status::Good};
      writeResponse->results()[1] = StatusCode{Status::BadTypeMismatch};
      writeResponse->results()[2] = StatusCode{Status::Good};
    });

  std::vector<std::pair<NodeId, Variant>> pairs;
  pairs.emplace_back(server_state_node(), Variant{int32_t{1}});
  pairs.emplace_back(NodeId{VariableId::Server_ServerStatus_CurrentTime}, Variant{int32_t{2}});
  pairs.emplace_back(NodeId{VariableId::Server_ServerStatus_State}, Variant{int32_t{3}});

  const uint64_t writesBefore = writeResponses->load();
  auto result = fixture.conn().typed().try_write_values_sync(pairs);
  const uint64_t writesAfter = writeResponses->load();

  ASSERT_TRUE(result.is_good()) << "the bulk service itself succeeds; the failure is per-operation";
  ASSERT_EQ(result.value().size(), 3u) << "every slot status must be reported, in order";
  EXPECT_TRUE(result.value()[0].is_good());
  EXPECT_TRUE(result.value()[1].is_bad());
  EXPECT_EQ(result.value()[1].status_code().value(), StatusCode{Status::BadTypeMismatch}.value());
  EXPECT_TRUE(result.value()[2].is_good());

  EXPECT_EQ(writesAfter - writesBefore, 1u)
    << "exactly one Write round-trip must occur: the SDK must NOT emit a compensating rollback Write";
}

// =============================================================================================
// Row 7 - ResultsMirrorNodesToWriteLengthMismatchRejected  (MisbehavingServer)
// For a 2-item bulk write, a Results array of length 0, 1, or 3 must be rejected with
// Bad_UnexpectedError; statuses must never be mis-mapped to the wrong node. [neg: write results count
// mismatch]
//
// Slot-alignment guard ADDED at the bulk write facade (TypedAccess::write_values_async): the tier-0
// wire-op funnel returns the malformed response verbatim, so the facade validates
// results.size() == pairs.size() (mirrors the read_values facade + ua_server_diagnostics_access.cpp).
// =============================================================================================
// @verifies CL-ATTR-017
// @relation(CL-ATTR-017, scope=function)
TEST_F(ClientWrite, ResultsMirrorNodesToWriteLengthMismatchRejected)
{
  MisbehavingServer server;
  MisbehavingWriteFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto targetLength = std::make_shared<std::atomic<int>>(-1);  // -1 = leave untouched
  server.set_response_mutator(
    [targetLength](Response& response)
    {
      auto* writeResponse = dynamic_cast<WriteResponse*>(response.second.get());
      if (!writeResponse)
        return;
      const int length = targetLength->load();
      if (length < 0)
        return;
      Array<StatusCode> replacement;
      for (int i = 0; i < length; ++i)
        replacement.push_back(StatusCode{Status::Good});
      writeResponse->results() = std::move(replacement);
    });

  std::vector<std::pair<NodeId, Variant>> pairs;
  pairs.emplace_back(server_state_node(), Variant{int32_t{1}});
  pairs.emplace_back(NodeId{VariableId::Server_ServerStatus_CurrentTime}, Variant{int32_t{2}});

  for (int badLength : {0, 1, 3})
  {
    targetLength->store(badLength);
    auto result = fixture.conn().typed().try_write_values_sync(pairs);
    EXPECT_TRUE(result.is_bad()) << "a Results length of " << badLength
                                 << " for a 2-item bulk Write must be rejected, not returned as OK";
    if (result.is_bad())
      EXPECT_EQ(result.status_code().value(), StatusCode{Status::BadUnexpectedError}.value())
        << "a slot-alignment mismatch must be Bad_UnexpectedError";
  }
}

// =============================================================================================
// Row 8 - ValueStatusTimestampsCarriedEndToEnd  (ComplianceWithNodes, server-side capture)
// A full DataValue (Value + StatusCode + SourceTimestamp + ServerTimestamp), and a
// ServerTimestamp-only variant, must reach the wire with every supplied field intact - verified by a
// server-side value handler that captures the decoded WriteValue.
// =============================================================================================
// @verifies CL-ATTR-027
// @relation(CL-ATTR-027, scope=function)
TEST_F(ClientWrite, ValueStatusTimestampsCarriedEndToEnd)
{
  auto capture = install_write_capture(mCaptureInt32Id);

  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("W8")};
  ASSERT_TRUE(connection.start_status().is_good());

  // Case 001: a full DataValue - Value + StatusCode + SourceTimestamp + ServerTimestamp.
  const DateTime sourceTs = DateTime::now();
  const DateTime serverTs = DateTime::now();
  DataValue full{Variant{int32_t{123}}, StatusCode{Status::GoodClamped}};
  full.source_timestamp() = sourceTs;
  full.server_timestamp() = serverTs;
  ASSERT_TRUE(
    connection->typed().try_write_attribute_sync(mCaptureInt32Id, AttributeId::Value, full).is_good());

  // Case 002: a ServerTimestamp-only variant (no status, no source timestamp).
  DataValue serverOnly{Variant{int32_t{456}}};
  serverOnly.server_timestamp() = serverTs;
  ASSERT_TRUE(
    connection->typed().try_write_attribute_sync(mCaptureInt32Id, AttributeId::Value, serverOnly).is_good());

  auto captured = capture->snapshot();
  ASSERT_EQ(captured.size(), 2u) << "both writes must reach the server-side handler";

  const DataValue& fullSeen = captured[0];
  ASSERT_NE(fullSeen.value().try_as<int32_t>(), nullptr);
  EXPECT_EQ(*fullSeen.value().try_as<int32_t>(), 123);
  ASSERT_TRUE(fullSeen.status().has_value()) << "the client must carry the supplied StatusCode";
  EXPECT_EQ(fullSeen.status()->value(), StatusCode{Status::GoodClamped}.value());
  ASSERT_TRUE(fullSeen.source_timestamp().has_value()) << "SourceTimestamp must reach the wire";
  EXPECT_EQ(*fullSeen.source_timestamp(), sourceTs);
  ASSERT_TRUE(fullSeen.server_timestamp().has_value()) << "ServerTimestamp must reach the wire";
  EXPECT_EQ(*fullSeen.server_timestamp(), serverTs);

  const DataValue& serverOnlySeen = captured[1];
  ASSERT_NE(serverOnlySeen.value().try_as<int32_t>(), nullptr);
  EXPECT_EQ(*serverOnlySeen.value().try_as<int32_t>(), 456);
  EXPECT_FALSE(serverOnlySeen.status().has_value()) << "no StatusCode was supplied; none must be invented";
  EXPECT_FALSE(serverOnlySeen.source_timestamp().has_value())
    << "no SourceTimestamp was supplied; none must be invented";
  ASSERT_TRUE(serverOnlySeen.server_timestamp().has_value()) << "the ServerTimestamp-only field must carry";
  EXPECT_EQ(*serverOnlySeen.server_timestamp(), serverTs);
}

// =============================================================================================
// Row 9 - QualityOnlyAndVendorSubStatusExactBits  (ComplianceWithNodes, server-side capture)
// A Value+Status write must place the exact 32-bit StatusCode pattern on the wire, including a
// vendor-specific sub-status pattern that must not be canonicalised or masked.
// [neg: vendor sub-status bit fidelity]
// =============================================================================================
// @verifies CL-ATTR-028
// @relation(CL-ATTR-028, scope=function)
TEST_F(ClientWrite, QualityOnlyAndVendorSubStatusExactBits)
{
  auto capture = install_write_capture(mCaptureInt32Id);

  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("W9")};
  ASSERT_TRUE(connection.start_status().is_good());

  // Case 003: standard StatusCodes. Case 004: a vendor-specific 32-bit pattern with sub-status bits set
  // in the reserved/info region - the on-wire code must equal the supplied 32-bit value exactly.
  const std::vector<uint32_t> patterns{StatusCode{Status::Good}.as_uint32(),
    StatusCode{Status::GoodClamped}.as_uint32(),
    StatusCode{Status::BadDeviceFailure}.as_uint32(),
    StatusCode{Status::BadNotConnected}.as_uint32(),
    uint32_t{0x80AB'0400u}};

  for (uint32_t pattern : patterns)
  {
    DataValue value{Variant{int32_t{9}}, StatusCode{pattern}};
    ASSERT_TRUE(
      connection->typed().try_write_attribute_sync(mCaptureInt32Id, AttributeId::Value, value).is_good())
      << "writing quality 0x" << std::hex << pattern << " must succeed on a StatusWrite node";
  }

  auto captured = capture->snapshot();
  ASSERT_EQ(captured.size(), patterns.size());
  for (std::size_t i = 0; i < patterns.size(); ++i)
  {
    ASSERT_TRUE(captured[i].status().has_value()) << "the supplied StatusCode must reach the wire";
    EXPECT_EQ(captured[i].status()->as_uint32(), patterns[i])
      << "the on-wire StatusCode must equal the exact 32-bit pattern supplied (index " << i << ")";
  }
}

// =============================================================================================
// Row 9b - QualityTimestampUnsupportedAtomicRejection  (MisbehavingServer)
// When the server returns Bad_WriteNotSupported for a (Value, Status, Timestamp) write, the tier-2
// caller must see Bad_WriteNotSupported and assume NO partial commitment (an unsupported combination is
// an atomic no-write): the client must NOT report the value as written. [neg: unsupported combination =
// atomic no-write]
//
// The facade enriches the wire-only status at its final request-aware boundary, naming the attempted
// field tuple while preserving any downstream detail as its cause.
// =============================================================================================
// @verifies CL-ATTR-027
// @verifies CL-ATTR-028
// @relation(CL-ATTR-027, CL-ATTR-028, scope=function)
TEST_F(ClientWrite, QualityTimestampUnsupportedAtomicRejection)
{
  MisbehavingServer server;
  MisbehavingWriteFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  server.set_response_mutator(
    [](Response& response)
    {
      if (auto* writeResponse = dynamic_cast<WriteResponse*>(response.second.get()))
      {
        if (!writeResponse->results().empty())
          writeResponse->results()[0] = StatusCode{Status::BadWriteNotSupported};
      }
    });
  auto writeRequests = std::make_shared<std::atomic<std::uint64_t>>(0);
  server.set_request_observer(
    [writeRequests](const Structure& request)
    {
      if (dynamic_cast<const WriteRequest*>(&request))
        writeRequests->fetch_add(1, std::memory_order_relaxed);
    });

  // A full (Value, Status, SourceTimestamp, ServerTimestamp) write the server declares unsupported.
  DataValue full{Variant{int32_t{5}}, StatusCode{Status::Good}};
  full.source_timestamp() = DateTime::now();
  full.server_timestamp() = DateTime::now();

  const std::uint64_t writesBefore = writeRequests->load(std::memory_order_relaxed);
  auto result =
    fixture.conn().typed().try_write_attribute_sync(server_state_node(), AttributeId::Value, full);
  const std::uint64_t writesAfter = writeRequests->load(std::memory_order_relaxed);

  EXPECT_TRUE(result.is_bad()) << "an unsupported (value,status,timestamp) combination must fail, not be "
                                  "silently reported as written";
  EXPECT_EQ(result.status_code().value(), StatusCode{Status::BadWriteNotSupported}.value())
    << "the exact Bad_WriteNotSupported must surface to the caller";
  const auto* detail = result.error_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "WriteAttributeCombinationUnsupported");
  const auto attemptedTuple = std::find_if(
    detail->context.begin(), detail->context.end(), [](const auto& entry) { return entry.key == "value"; });
  ASSERT_NE(attemptedTuple, detail->context.end());
  EXPECT_NE(attemptedTuple->value.find("value=present"), std::string::npos);
  EXPECT_NE(attemptedTuple->value.find("status=present"), std::string::npos);
  EXPECT_NE(attemptedTuple->value.find("sourceTimestamp=present"), std::string::npos);
  EXPECT_NE(attemptedTuple->value.find("serverTimestamp=present"), std::string::npos);
  EXPECT_EQ(writesAfter - writesBefore, 1u)
    << "an atomic no-write must not trigger a partial-commit retry: exactly one Write round-trip occurs";
}

// =============================================================================================
// Row 10 - LocalizedTextNullStringSemanticsPreserved  (ComplianceWithNodes, server-side capture)
// A LocalizedText write must carry each field faithfully (no field dropped, swapped, or fabricated),
// plus an overwrite. [neg: null patterns must not be normalised]
//
// REPORTED tested-contract note: ua::String deliberately collapses the null and empty String into one
// value (documented: "the null String and the empty String share the same value ... is_null() and
// empty() are therefore equivalent"). The matrix row's deeper "null-text vs null-locale" distinction is
// therefore NOT representable at the ua::String type level - the representable-and-asserted property is
// faithful per-field carriage: the present field survives verbatim and the empty field stays empty
// (which drives the wire encoding mask). A field swap/drop/normalisation across fields still fails this.
// =============================================================================================
// @verifies AC-CL-ATTR-021-LOCALIZEDTEXT-NULLS
// @relation(AC-CL-ATTR-021-LOCALIZEDTEXT-NULLS, scope=function)
TEST_F(ClientWrite, LocalizedTextNullStringSemanticsPreserved)
{
  auto capture = install_write_capture(mCaptureLtId);

  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("W10")};
  ASSERT_TRUE(connection.start_status().is_good());

  // Three null patterns: (locale=en, text empty), (locale empty, text=abc), (both empty), plus an
  // overwrite that replaces the first pattern with a fully-populated value.
  const std::vector<LocalizedText> writes{LocalizedText{LocaleId{"en"}, String{}},
    LocalizedText{LocaleId{}, String{"abc"}},
    LocalizedText{LocaleId{}, String{}},
    LocalizedText{LocaleId{"de"}, String{"hallo"}}};

  for (const auto& localizedText : writes)
    ASSERT_TRUE(connection->try_write_value_sync(mCaptureLtId, Variant{localizedText}).is_good());

  auto captured = capture->snapshot();
  ASSERT_EQ(captured.size(), writes.size());
  for (std::size_t i = 0; i < writes.size(); ++i)
  {
    const LocalizedText* seen = captured[i].value().try_as<LocalizedText>();
    ASSERT_NE(seen, nullptr) << "the write must carry a LocalizedText (index " << i << ")";
    EXPECT_EQ(std::string{seen->locale()}, std::string{writes[i].locale()})
      << "the locale field must survive verbatim (index " << i << ")";
    EXPECT_EQ(std::string{seen->text()}, std::string{writes[i].text()})
      << "the text field must survive verbatim (index " << i << ")";
  }
}

// =============================================================================================
// Row 11 - Tier2RejectsRankMismatchNoWire  (ComplianceWithNodes)
// A 1-D Variant written to a ValueRank=2, ArrayDimensions=[3,4] Variable must not succeed as if the
// shape matched. [neg: rank mismatch rejected before wire]
// =============================================================================================
// @verifies CL-ADDRSP-005
// @relation(CL-ADDRSP-005, scope=function)
TEST_F(ClientWrite, Tier2RejectsRankMismatchNoWire)
{
  auto capture = install_write_capture(mRank2Id);
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("W11")};
  ASSERT_TRUE(connection.start_status().is_good());

  Array<double> oneDimensional{1.0, 2.0, 3.0};

  auto tier2 = connection->try_write_value_sync(mRank2Id, Variant{oneDimensional});
  ASSERT_TRUE(tier2.is_bad());
  EXPECT_EQ(tier2.status_code(), StatusCode{Status::BadTypeMismatch});
  ASSERT_NE(tier2.shared_detail(), nullptr);
  EXPECT_EQ(tier2.shared_detail()->code, "VariableValueRankMismatch");
  EXPECT_NE(to_string(*tier2.shared_detail()).find(to_string(mRank2Id)), std::string::npos)
    << "the rich local rejection must name the target Variable";
  EXPECT_TRUE(capture->snapshot().empty())
    << "public tier-2 must reject after metadata Read and before issuing any Write frame";
}

// =============================================================================================
// Row 12 - WriteFullArrayOnlyBlocksIndexRangeNoWire  (ComplianceWithNodes)
// A ranged write to a Variable advertising AccessLevelEx.WriteFullArrayOnly=1 must be blocked. [neg:
// bit set blocks ranged write locally]
//
// The test first reads AccessLevelEx through public tier 2, deterministically populating the enabled
// Connection cache, then performs the ranged write through the public tier-2 overload. The server-side
// value handler is observation only: it must see no Write frame.
// =============================================================================================
// @verifies CL-ATTR-024
// @verifies CL-ADDRSP-014
// @relation(CL-ADDRSP-014, CL-ATTR-024, scope=function)
TEST_F(ClientWrite, WriteFullArrayOnlyBlocksIndexRangeNoWire)
{
  auto capture = install_write_capture(mFullArrayOnlyId);
  ua::client::detail::ConnectionConfig config;
  config.addressSpaceCache.enabled = true;
  config.addressSpaceCache.useRegisterNodes = false;
  StartedConnection connection{
    mClientThreadPool.executor(), open_activated_session("W12"), std::move(config)};
  ASSERT_TRUE(connection.start_status().is_good());

  auto observed = connection->typed().try_read_attribute_sync(mFullArrayOnlyId, AttributeId::AccessLevelEx);
  ASSERT_TRUE(observed.is_good());
  const auto* accessLevelEx = observed.value().value().try_as<std::uint32_t>();
  ASSERT_NE(accessLevelEx, nullptr);
  EXPECT_TRUE(AccessLevelExType{*accessLevelEx}.test(AccessLevelExType::Bit::WriteFullArrayOnly));

  Array<int32_t> rangeSlice;
  for (int32_t i = 0; i < 6; ++i)
    rangeSlice.push_back(300 + i);
  auto ranged = connection->typed().try_write_attribute_sync(
    mFullArrayOnlyId, AttributeId::Value, String{"0:5"}, DataValue{Variant{rangeSlice}});

  ASSERT_TRUE(ranged.is_bad());
  EXPECT_EQ(ranged.status_code(), StatusCode{Status::BadWriteNotSupported});
  ASSERT_NE(ranged.shared_detail(), nullptr);
  EXPECT_EQ(ranged.shared_detail()->code, "WriteFullArrayOnlyIndexRangeRejected");
  EXPECT_TRUE(capture->snapshot().empty())
    << "the cached WriteFullArrayOnly bit must reject before any Write reaches the server";
}
