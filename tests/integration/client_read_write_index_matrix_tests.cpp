// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientReadIndex + ClientWriteIndex clusters of the client integration-test matrix (the
///        `ClientReadIndex.*` and `ClientWriteIndex.*` rows, IndexRange read/write builder section 7.2).
///
/// These are END-TO-END integration tests of the client's IndexRange read/write surfaces against a real
/// in-tree server. Tier-2 ranged reads enter through
/// `Connection::typed().try_read_attribute_sync(..., indexRange)` and validate CL-ADDRSP-006 syntax/rank
/// before the ranged Value Read. Raw tier-1 read/write cases enter through `Connection::service_requests()`
/// and retain their wire-shaped passthrough contract.
///
/// KEY CALIBRATION - tier-2 ranged reads validate syntax before any Read and use live ValueRank metadata to
/// reject partial fixed-rank ranges before the ranged Value request. Tier-1 `ServiceSet` deliberately
/// performs neither check, so its malformed ranges continue to reach the server unchanged. Write
/// size-checking and single-element auto-wrap remain separate tier-1 matrix concerns.
///
/// Falsifiability: malformed tier-2 syntax must leave the MisbehavingServer interceptor count unchanged;
/// a valid multi-dimensional range must return the selected cells; a partial fixed-rank range must fail as
/// an outer tier-2 Result. Tier-1 write tests separately assert their exact wire payloads and server
/// verdicts.

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"

#include "misbehaving_server.h"

#include "ua_connection.h"
#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_service_set.h"
#include "ua_typed_access.h"

#include "ua_access_level_type.h"
#include "ua_application_configuration.h"
#include "ua_array.h"
#include "ua_array_base.h"
#include "ua_attribute_id.h"
#include "ua_byte_string.h"
#include "ua_client.h"
#include "ua_client_secure_channel.h"
#include "ua_client_session.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_default_variable_node.h"
#include "ua_localized_text.h"
#include "ua_logger.h"
#include "ua_node.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_status.h"
#include "ua_numeric_range_parser.h"
#include "ua_string.h"
#include "ua_to_string.h"
#include "ua_value_rank.h"
#include "ua_value_source.h"
#include "ua_variable_id.h"
#include "ua_variant.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_write_value.h"

#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <mutex>
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
// closes gracefully on destruction. Copied from the ClientRead / ClientWrite slices - the same tier-2
// wire-op interface these IndexRange rows drive through `service_requests()`.
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
// MisbehavingIndexFixture: a real client bound to a MisbehavingServer's crypto + trusted certificate
// store, on its own thread pool, with an activated Session wrapped into a started tier-2 Connection. The
// bootstrap completes against the un-mutated server; the test arms response mutators / request observers
// AFTER construction. Mirror of the ClientRead slice's MisbehavingReadFixture - used here only to prove
// the "reached the wire" clause of the RejectedLocally / ArraySizeMustMatch / SingleElementWraps rows via
// the interceptor fire-count + request observer.
// ---------------------------------------------------------------------------------------------
class MisbehavingIndexFixture
{
public:
  explicit MisbehavingIndexFixture(
    MisbehavingServer& server, ua::client::detail::ConnectionConfig connectionConfig = {})
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
    auto session = channel.create_session_sync({.sessionName = "ClientIndexMatrix"});
    session.activate_sync();
    mConnection.emplace(mThreadPool.executor(), std::move(session), std::move(connectionConfig));
  }

  ~MisbehavingIndexFixture()
  {
    mConnection.reset();
    mClient.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  MisbehavingIndexFixture(const MisbehavingIndexFixture&) = delete;
  MisbehavingIndexFixture& operator=(const MisbehavingIndexFixture&) = delete;

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

// A readable/writable NS0 node present on every server (an enum-backed Int32 scalar). Used as the
// arbitrary IndexRange target for the MisbehavingServer wire-round-trip proofs (the range is malformed /
// mismatched, so the server produces a verdict without the value type ever mattering).
NodeId server_state_node()
{
  return NodeId{VariableId::Server_ServerStatus_State};
}

// Extracts the raw bytes of a Variant holding a scalar ByteString (for byte-exact substring checks).
std::optional<std::vector<uint8_t>> byte_string_bytes(const Variant& variant)
{
  if (const auto* byteString = variant.try_as<ByteString>())
    return std::vector<uint8_t>(byteString->begin(), byteString->end());
  return std::nullopt;
}

}  // namespace

// =============================================================================================
// Fixture base: creates the array / matrix / String / ByteString nodes both suites need, BEFORE the
// server starts. Derives from ComplianceWithNodes for the client + endpoint plumbing. Node ids use the
// 9100/9200 ranges to avoid colliding with the ComplianceWithNodes catalogue.
// =============================================================================================
class ReadWriteIndexBase : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();

    auto addressSpace = mServer.server().address_space();
    const AccessLevelType readWrite{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite};

    auto createNode = [&](uint32_t id, DataTypeId dataType, std::string_view name, ValueRank rank) -> NodeId
    {
      NodeId nodeId{mTestNamespaceIndex, id};
      auto node = addressSpace.create_node_sync(nodeId, NodeClass::Variable);
      auto variable = node.as<VariableAccessor>();
      variable->set_browse_name(QualifiedName{mTestNamespaceIndex, std::string{name}});
      variable->set_display_name(LocalizedText{"", std::string{name}});
      variable->set_data_type(NodeId{dataType});
      variable->set_value_rank(rank);
      variable->set_access_level(readWrite);
      return nodeId;
    };

    auto ten = [](auto zero)
    {
      using T = decltype(zero);
      Array<T> array;
      for (int i = 0; i < 10; ++i)
        array.push_back(static_cast<T>(i));
      return array;
    };

    // 1-D arrays of several scalar DataTypes, valued 0..9.
    mInt32ArrayId = createNode(9101, DataTypeId::Int32, "IdxInt32Array", ValueRank{1});
    addressSpace.find_node_sync(mInt32ArrayId).as<VariableAccessor>()->write_value_sync(ten(int32_t{}));
    mDoubleArrayId = createNode(9102, DataTypeId::Double, "IdxDoubleArray", ValueRank{1});
    addressSpace.find_node_sync(mDoubleArrayId).as<VariableAccessor>()->write_value_sync(ten(double{}));
    mUInt32ArrayId = createNode(9103, DataTypeId::UInt32, "IdxUInt32Array", ValueRank{1});
    addressSpace.find_node_sync(mUInt32ArrayId).as<VariableAccessor>()->write_value_sync(ten(uint32_t{}));

    // 2-D Int32 matrix [4,4], row-major 0..15.
    mMatrixId = createNode(9104, DataTypeId::Int32, "IdxMatrix", ValueRank{2});
    {
      auto variable = addressSpace.find_node_sync(mMatrixId).as<VariableAccessor>();
      variable->set_array_dimensions(std::vector<uint32_t>{4, 4});
      std::vector<int32_t> payload(16);
      for (int32_t i = 0; i < 16; ++i)
        payload[static_cast<std::size_t>(i)] = i;
      variable->write_value_sync(Array<int32_t>{Dimensions{4, 4}, payload});
    }

    // Scalar String / ByteString (substring reads/writes).
    mScalarStringId = createNode(9105, DataTypeId::String, "IdxScalarString", ValueRank{-1});
    addressSpace.find_node_sync(mScalarStringId)
      .as<VariableAccessor>()
      ->write_value_sync(String{"Hello, World!"});
    mScalarByteStringId = createNode(9106, DataTypeId::ByteString, "IdxScalarByteString", ValueRank{-1});
    addressSpace.find_node_sync(mScalarByteStringId)
      .as<VariableAccessor>()
      ->write_value_sync(ByteString{std::vector<uint8_t>{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}});

    // Array-of-String / array-of-ByteString (element+char/byte 2-D range). Element 2 is >= 8 chars/bytes.
    mStringArrayId = createNode(9107, DataTypeId::String, "IdxStringArray", ValueRank{1});
    addressSpace.find_node_sync(mStringArrayId)
      .as<VariableAccessor>()
      ->write_value_sync(Array<String>{String{"alpha"}, String{"bravo"}, String{"charlie123"}});
    mByteStringArrayId = createNode(9108, DataTypeId::ByteString, "IdxByteStringArray", ValueRank{1});
    addressSpace.find_node_sync(mByteStringArrayId)
      .as<VariableAccessor>()
      ->write_value_sync(Array<ByteString>{ByteString{std::vector<uint8_t>{100, 101}},
        ByteString{std::vector<uint8_t>{110, 111}},
        ByteString{std::vector<uint8_t>{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}}});

    // Write targets (fresh, writable), valued 0..9 / matrix / scalar String+ByteString.
    mWriteInt32ArrayId = createNode(9201, DataTypeId::Int32, "IdxWriteInt32Array", ValueRank{1});
    addressSpace.find_node_sync(mWriteInt32ArrayId).as<VariableAccessor>()->write_value_sync(ten(int32_t{}));
    mWriteInt32ArrayId2 = createNode(9202, DataTypeId::Int32, "IdxWriteInt32Array2", ValueRank{1});
    addressSpace.find_node_sync(mWriteInt32ArrayId2).as<VariableAccessor>()->write_value_sync(ten(int32_t{}));
    mWriteMatrixId = createNode(9203, DataTypeId::Int32, "IdxWriteMatrix", ValueRank{2});
    {
      auto variable = addressSpace.find_node_sync(mWriteMatrixId).as<VariableAccessor>();
      variable->set_array_dimensions(std::vector<uint32_t>{4, 4});
      std::vector<int32_t> payload(16);
      for (int32_t i = 0; i < 16; ++i)
        payload[static_cast<std::size_t>(i)] = i;
      variable->write_value_sync(Array<int32_t>{Dimensions{4, 4}, payload});
    }
    mWriteScalarStringId = createNode(9204, DataTypeId::String, "IdxWriteScalarString", ValueRank{-1});
    addressSpace.find_node_sync(mWriteScalarStringId)
      .as<VariableAccessor>()
      ->write_value_sync(String{"Hello, World!"});
    mWriteScalarByteStringId =
      createNode(9205, DataTypeId::ByteString, "IdxWriteScalarByteString", ValueRank{-1});
    addressSpace.find_node_sync(mWriteScalarByteStringId)
      .as<VariableAccessor>()
      ->write_value_sync(ByteString{std::vector<uint8_t>{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}});
  }

  // Opens a fresh channel + activated session on the fixture's (normal) server.
  Session open_activated_session(std::string name)
  {
    auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
    auto session = channel.create_session_sync({.sessionName = std::move(name)});
    session.activate_sync();
    return session;
  }

  // Reads one attribute Value of @p node with the given IndexRange through the wire-op funnel, returning
  // the per-operation DataValue Result (a service failure surfaces as a bad Result).
  Result<DataValue> read_index(Connection& connection, const NodeId& node, String range)
  {
    return connection.typed().try_read_attribute_sync(node, AttributeId::Value, std::move(range));
  }

  NodeId mInt32ArrayId;
  NodeId mDoubleArrayId;
  NodeId mUInt32ArrayId;
  NodeId mMatrixId;
  NodeId mScalarStringId;
  NodeId mScalarByteStringId;
  NodeId mStringArrayId;
  NodeId mByteStringArrayId;

  NodeId mWriteInt32ArrayId;
  NodeId mWriteInt32ArrayId2;
  NodeId mWriteMatrixId;
  NodeId mWriteScalarStringId;
  NodeId mWriteScalarByteStringId;
};

// Two trivial derived fixtures so the gtest suites are named exactly ClientReadIndex.* / ClientWriteIndex.*.
class ClientReadIndex : public ReadWriteIndexBase
{};

class ClientWriteIndex : public ReadWriteIndexBase
{};

// =============================================================================================
// ClientReadIndex - EqualOrDescendingBoundsRejectedLocallyNoWire (public tier 2)
// Equal-bound ('5:5'), descending-bound ('7:5'), and whitespace ('5 :7') ranges fail locally with
// Bad_IndexRangeInvalid. A server-side handler on the target Variable proves no Value Read reached the
// target; because syntax validation runs before metadata construction, the owning units separately pin
// that no ValueRank Read is issued either. [neg: equal/descending/whitespace invalid syntax]
// =============================================================================================
// @verifies CL-ATTR-008
// @verifies CL-ADDRSP-006
// @relation(CL-ADDRSP-006, CL-ATTR-008, scope=function)
// @relation(AC-CL-ADDRSP-006-NUMERICRANGE, scope=function)
TEST_F(ClientReadIndex, EqualOrDescendingBoundsRejectedLocallyNoWire)
{
  auto observedValueReads = std::make_shared<std::atomic<std::uint64_t>>(0);
  auto observedValueWrites = std::make_shared<std::atomic<std::uint64_t>>(0);
  auto node =
    std::dynamic_pointer_cast<default_ns::VariableNode>(mTestNamespace->find_node<Node>(mInt32ArrayId));
  ASSERT_NE(node, nullptr);
  ASSERT_TRUE(node->external_value_source()
                ->set_value_source(make_value_source(
                  [observedValueReads](const ValueSource::ReadContext&,
                    const Node&,
                    const ReadValueId& read,
                    std::function<void(DataValueResult)>
                      callback)
                  {
                    observedValueReads->fetch_add(1);
                    DataValue value{Variant{Array<std::int32_t>{0, 1, 2, 3}}};
                    index_range_utils::apply_to_value(value, read.index_range());
                    callback(DataValueResult{std::move(value)});
                  },
                  [observedValueWrites](const ValueSource::WriteContext&,
                    const Node&,
                    const WriteValue&,
                    std::function<void(ValueSource::WriteResult)>
                      callback)
                  {
                    observedValueWrites->fetch_add(1);
                    callback(ValueSource::Written{});
                  }))
                .is_good());

  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("RI-InvalidSyntax")};
  ASSERT_TRUE(connection.start_status().is_good());

  for (String range : {String{"5:5"}, String{"7:5"}, String{"5 :7"}})
  {
    const std::uint64_t readsBefore = observedValueReads->load();
    auto result = connection->typed().try_read_attribute_sync(mInt32ArrayId, AttributeId::Value, range);

    EXPECT_EQ(observedValueReads->load(), readsBefore)
      << "malformed tier-2 range '" << std::string_view{range} << "' must not reach the target Variable";
    ASSERT_TRUE(result.is_bad());
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadIndexRangeInvalid});
    ASSERT_NE(result.shared_detail(), nullptr);
    EXPECT_EQ(result.shared_detail()->code, "NumericRangeSyntaxInvalid");

    const std::uint64_t writesBefore = observedValueWrites->load();
    auto writeResult = connection->typed().try_write_attribute_sync(
      mInt32ArrayId, AttributeId::Value, range, DataValue{Variant{Array<std::int32_t>{99}}});
    EXPECT_EQ(observedValueWrites->load(), writesBefore)
      << "malformed tier-2 write range '" << std::string_view{range} << "' must not reach the Variable";
    ASSERT_TRUE(writeResult.is_bad());
    EXPECT_EQ(writeResult.status_code(), StatusCode{Status::BadIndexRangeInvalid});
    ASSERT_NE(writeResult.shared_detail(), nullptr);
    EXPECT_EQ(writeResult.shared_detail()->code, "NumericRangeSyntaxInvalid");
  }
}

// =============================================================================================
// ClientReadIndex - MultiDimAllDimsRequired  (normal server)
// Case A: a 2-D [4,4] array read with IndexRange='2:3,2:3' returns the 2x2 sub-block. Case B: a single-dim
// '1:2' on the rank-2 array is answered locally, after the live ValueRank metadata Read and without the
// ranged Value Read, as the server's Read answers it: a Good Result whose value has the status
// Bad_IndexRangeNoData, no value, and the client's ErrorDetail NumericRangeDimensionCountMismatch, which
// shows the answer was made locally. [neg: omitted dimension selects no data]
// =============================================================================================
// @verifies AC-CL-ADDRSP-006-NUMERICRANGE
// @relation(AC-CL-ADDRSP-006-NUMERICRANGE, scope=function)
TEST_F(ClientReadIndex, MultiDimAllDimsRequired)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("RI-MultiDim")};
  ASSERT_TRUE(connection.start_status().is_good());

  // Case A: '2:3,2:3' selects rows 2..3, cols 2..3 of the row-major 0..15 matrix -> {10,11,14,15}.
  auto caseA = read_index(*connection, mMatrixId, "2:3,2:3");
  ASSERT_TRUE(caseA.is_good()) << "the ranged Read must not fail at the service level";
  EXPECT_THAT(caseA.value(), Good()) << "a full-dimension multi-dim range must select the sub-block";
  auto block = caseA.value().value().to_vector<int32_t>();
  ASSERT_TRUE(block.is_good()) << "the sub-block must decode to Int32";
  EXPECT_EQ(block.value(), (std::vector<int32_t>{10, 11, 14, 15}))
    << "the 2x2 sub-block must carry the correct row-major cells (no dropped dimension)";

  // A single-dim range on a rank-2 array is answered at the tier-2 dimension-count boundary as the server's
  // Read answers it (DL-7 (b), DL-16): the Read succeeds and the value's status is Bad_IndexRangeNoData, with
  // the value null.
  auto singleDim = read_index(*connection, mMatrixId, "1:2");
  ASSERT_TRUE(singleDim.is_good()) << "the Read failed instead of answering the range's status in its value";
  EXPECT_THAT(singleDim.value(), HasStatusPresent(Status::BadIndexRangeNoData));
  ASSERT_TRUE(singleDim.value().status().has_value());
  ASSERT_NE(singleDim.value().status()->shared_detail(), nullptr)
    << "the value's status carries no ErrorDetail, so the answer may not have been made locally";
  EXPECT_EQ(singleDim.value().status()->shared_detail()->code, "NumericRangeDimensionCountMismatch");
  EXPECT_TRUE(singleDim.value().value().empty()) << "a value whose status is bad carries a value";
}

// =============================================================================================
// ClientReadIndex - SingleAndRangeIndexPerDataType  (normal server)
// For arrays of several scalar DataTypes, a single index '4' returns a 1-element array holding the element
// at index 4, and a range '3:5' returns the 3-element slice 3..5. If IndexRange were dropped, the whole
// array would be returned instead. [neg: IndexRange must not be dropped]
// =============================================================================================
// @verifies CL-ATTR-008
// @relation(CL-ATTR-008, scope=function)
TEST_F(ClientReadIndex, SingleAndRangeIndexPerDataType)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("RI-PerType")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto checkNumeric = [&](const NodeId& node, auto zero)
  {
    using T = decltype(zero);
    // Single '4' -> a 1-element array holding the value at index 4.
    auto single = read_index(*connection, node, "4");
    ASSERT_TRUE(single.is_good());
    ASSERT_THAT(single.value(), Good());
    auto singleVec = single.value().value().template to_vector<T>();
    ASSERT_TRUE(singleVec.is_good()) << "the single-index read must decode to the element type";
    ASSERT_EQ(singleVec.value().size(), 1u) << "a single-index read returns exactly one element";
    EXPECT_EQ(singleVec.value()[0], static_cast<T>(4)) << "the single index must select element 4";

    // Range '3:5' -> the 3-element slice {3,4,5}.
    auto range = read_index(*connection, node, "3:5");
    ASSERT_TRUE(range.is_good());
    ASSERT_THAT(range.value(), Good());
    auto rangeVec = range.value().value().template to_vector<T>();
    ASSERT_TRUE(rangeVec.is_good());
    EXPECT_EQ(rangeVec.value(), (std::vector<T>{static_cast<T>(3), static_cast<T>(4), static_cast<T>(5)}))
      << "the range read must return exactly the server's slice 3..5, not the whole array";
  };

  checkNumeric(mInt32ArrayId, int32_t{});
  checkNumeric(mDoubleArrayId, double{});
  checkNumeric(mUInt32ArrayId, uint32_t{});
}

// =============================================================================================
// ClientReadIndex - UpperOverflowPartialLowerOverflowNoData  (normal server)
// A 10-element array. Case A: IndexRange='3:100' (upper overflow) returns a 7-element array (3..9) with
// Good status - the server clips the high bound. Case B: IndexRange='20:30' (lower overflow) surfaces
// Bad_IndexRangeNoData. If the client pre-sized to (upper-lower+1) it would over-read/pad; if it treated
// case B as partial it would hide the error. [neg: upper clip vs lower NoData]
// =============================================================================================
// @verifies CL-ATTR-010
// @relation(CL-ATTR-010, scope=function)
TEST_F(ClientReadIndex, UpperOverflowPartialLowerOverflowNoData)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("RI-Overflow")};
  ASSERT_TRUE(connection.start_status().is_good());

  // Case A: upper overflow '3:100' -> the partial slice {3,4,5,6,7,8,9} (7 elements), Good.
  auto caseA = read_index(*connection, mInt32ArrayId, "3:100");
  ASSERT_TRUE(caseA.is_good());
  EXPECT_THAT(caseA.value(), Good()) << "an upper-overflow range is clipped, not an error";
  auto slice = caseA.value().value().to_vector<int32_t>();
  ASSERT_TRUE(slice.is_good());
  EXPECT_EQ(slice.value(), (std::vector<int32_t>{3, 4, 5, 6, 7, 8, 9}))
    << "the high bound must be clipped to the array end (7 elements), not padded to 98";

  // Case B: lower overflow '20:30' -> Bad_IndexRangeNoData.
  auto caseB = read_index(*connection, mInt32ArrayId, "20:30");
  ASSERT_TRUE(caseB.is_good()) << "the Read service itself completes; the failure is per-operation";
  EXPECT_THAT(caseB.value(), HasStatus(Status::BadIndexRangeNoData))
    << "a lower bound past the array end must surface Bad_IndexRangeNoData, not a partial slice";
}

// =============================================================================================
// ClientReadIndex - SubstringByteRangeForByteStringAndString  (normal server)
// Scalar ByteString/String read with '3:7' returns the 5-byte/char slice; an array-of-ByteString/String
// read with '2,3:7' returns the 5-byte slice of element 2; and '2' (whole element) returns the entire
// element. If the client stripped the trailing char range, '2,3:7' would return the whole element.
// [neg: final-index substring semantics]
// =============================================================================================
// @verifies CL-ATTR-011
// @relation(CL-ATTR-011, scope=function)
TEST_F(ClientReadIndex, SubstringByteRangeForByteStringAndString)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("RI-Substring")};
  ASSERT_TRUE(connection.start_status().is_good());

  // --- Scalar String '3:7' -> chars 3..7 of "Hello, World!" = "lo, W".
  {
    auto scalar = read_index(*connection, mScalarStringId, "3:7");
    ASSERT_TRUE(scalar.is_good());
    ASSERT_THAT(scalar.value(), Good());
    const String* value = scalar.value().value().try_as<String>();
    ASSERT_NE(value, nullptr) << "a scalar String substring must decode to a String";
    EXPECT_EQ(std::string_view{*value}, std::string_view{"lo, W"})
      << "chars 3..7 of \"Hello, World!\" must be the 5-char slice";
  }

  // --- Scalar ByteString '3:7' -> bytes {3,4,5,6,7}.
  {
    auto scalar = read_index(*connection, mScalarByteStringId, "3:7");
    ASSERT_TRUE(scalar.is_good());
    ASSERT_THAT(scalar.value(), Good());
    auto bytes = byte_string_bytes(scalar.value().value());
    ASSERT_TRUE(bytes.has_value()) << "a scalar ByteString substring must decode to a ByteString";
    EXPECT_EQ(*bytes, (std::vector<uint8_t>{3, 4, 5, 6, 7})) << "bytes 3..7 must be the 5-byte slice";
  }

  // --- Array-of-String '2,3:7' -> chars 3..7 of element 2 ("charlie123") = "rlie1"
  // ("charlie123"[3..7] == r,l,i,e,1).
  {
    auto sliced = read_index(*connection, mStringArrayId, "2,3:7");
    ASSERT_TRUE(sliced.is_good());
    ASSERT_THAT(sliced.value(), Good());
    auto elements = sliced.value().value().to_vector<String>();
    ASSERT_TRUE(elements.is_good());
    ASSERT_EQ(elements.value().size(), 1u) << "the array range selects exactly element 2";
    EXPECT_EQ(std::string_view{elements.value()[0]}, std::string_view{"rlie1"})
      << "the trailing char range 3:7 must slice element 2, not return the whole element";
  }

  // --- Array-of-ByteString '2,3:7' -> bytes 3..7 of element 2 ({0..9}) = {3,4,5,6,7}.
  {
    auto sliced = read_index(*connection, mByteStringArrayId, "2,3:7");
    ASSERT_TRUE(sliced.is_good());
    ASSERT_THAT(sliced.value(), Good());
    auto elements = sliced.value().value().to_vector<ByteString>();
    ASSERT_TRUE(elements.is_good());
    ASSERT_EQ(elements.value().size(), 1u);
    std::vector<uint8_t> bytes(elements.value()[0].begin(), elements.value()[0].end());
    EXPECT_EQ(bytes, (std::vector<uint8_t>{3, 4, 5, 6, 7}))
      << "the trailing byte range 3:7 must slice element 2's bytes";
  }

  // --- Whole-element '2' on the array-of-ByteString -> a 1-element array holding all of element 2.
  {
    auto whole = read_index(*connection, mByteStringArrayId, "2");
    ASSERT_TRUE(whole.is_good());
    ASSERT_THAT(whole.value(), Good());
    auto elements = whole.value().value().to_vector<ByteString>();
    ASSERT_TRUE(elements.is_good());
    ASSERT_EQ(elements.value().size(), 1u);
    std::vector<uint8_t> bytes(elements.value()[0].begin(), elements.value()[0].end());
    EXPECT_EQ(bytes, (std::vector<uint8_t>{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}))
      << "a whole-element index must return the entire element, not a substring";
  }
}

// =============================================================================================
// ClientWriteIndex - ArraySizeMustMatchRange  (MisbehavingServer)  [int+unit]
// Tier 2 size-checks an IndexRange write: case A ('3:6', 4-element array) reaches the wire; case B
// ('3:5', a 3-wide range, 4-element array) is rejected locally with BadTypeMismatch and no wire frame.
// Tier 1 remains wire-shaped and lets the server reject the mismatch. [neg: array size must equal range
// cardinality before tier-2 wire emission]
// =============================================================================================
// @verifies AC-CL-ATTR-023-INDEXRANGE-SIZE
// @relation(AC-CL-ATTR-023-INDEXRANGE-SIZE, scope=function)
TEST_F(ClientWriteIndex, ArraySizeMustMatchRange)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("WI-SizeMatch")};
  ASSERT_TRUE(connection.start_status().is_good());

  // Case A: '3:6' (width 4) with a 4-element array -> accepted; read-back shows elements 3..6 overwritten.
  Array<int32_t> four{700, 701, 702, 703};
  auto caseA = connection->typed().try_write_attribute_sync(
    mWriteInt32ArrayId, AttributeId::Value, String{"3:6"}, DataValue{Variant{four}});
  ASSERT_TRUE(caseA.is_good()) << "a matched-size tier-2 ranged write must reach the wire and be accepted";
  {
    auto readBack = connection->try_read_value_sync(mWriteInt32ArrayId);
    ASSERT_TRUE(readBack.is_good());
    auto vec = readBack.value().value().to_vector<int32_t>();
    ASSERT_TRUE(vec.is_good());
    ASSERT_EQ(vec.value().size(), 10u);
    EXPECT_EQ((std::vector<int32_t>(vec.value().begin() + 3, vec.value().begin() + 7)),
      (std::vector<int32_t>{700, 701, 702, 703}))
      << "elements 3..6 must carry the written 4-element slice";
  }

  // Case B: '3:5' (width 3) with a 4-element array. No local size check -> forwarded; server rejects the
  // mismatch. The exact server verdict is Bad_IndexRangeInvalid (write_array_1d size-extent check).
  auto caseB = connection->service_requests().try_write_sync(
    WriteRequestBuilder().write(mWriteInt32ArrayId, Variant{four}).index_range("3:5"));
  ASSERT_TRUE(caseB.is_good()) << "the Write service itself completes; the failure is per-operation";
  ASSERT_EQ(caseB.value().results().size(), 1u);
  EXPECT_THAT(caseB.value().results()[0], HasStatus(Status::BadIndexRangeInvalid))
    << "a range/array size mismatch must be rejected (by the server) - the client does not pre-validate";

  // Public tier 2 rejects the same mismatch before a Write frame reaches a MisbehavingServer.
  MisbehavingServer server;
  MisbehavingIndexFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto observedWrites = std::make_shared<std::atomic<std::uint64_t>>(0);
  server.set_request_observer(
    [observedWrites](const ua::Structure& request)
    {
      if (dynamic_cast<const ua::WriteRequest*>(&request))
        observedWrites->fetch_add(1, std::memory_order_acq_rel);
    });
  auto local = fixture.conn().typed().try_write_attribute_sync(
    server_state_node(), AttributeId::Value, String{"3:5"}, DataValue{Variant{four}});
  ASSERT_TRUE(local.is_bad());
  EXPECT_EQ(local.status_code(), StatusCode{Status::BadTypeMismatch});
  ASSERT_NE(local.shared_detail(), nullptr);
  EXPECT_EQ(local.shared_detail()->code, "NumericRangeWriteCardinalityMismatch");
  EXPECT_EQ(observedWrites->load(std::memory_order_acquire), 0u);
}

// =============================================================================================
// ClientWriteIndex - MultiDimBulkAndSubstringWrites  (normal server)
// Multi-dim IndexRange writes, multi-node bulk writes, and String/ByteString substring writes must each
// carry the correct values at the correct positions (the server round-trips Good and the read-back
// matches). [neg: 2-D + substring element writes]
// =============================================================================================
// @verifies CL-ATTR-022
// @verifies CL-ATTR-011
// @relation(CL-ATTR-011, CL-ATTR-022, scope=function)
TEST_F(ClientWriteIndex, MultiDimBulkAndSubstringWrites)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("WI-MultiDim")};
  ASSERT_TRUE(connection.start_status().is_good());

  // --- 2-D write '1:2,1:2' of {900,901,902,903} into the [4,4] matrix -> cells (1,1)(1,2)(2,1)(2,2).
  {
    Array<int32_t> block{900, 901, 902, 903};
    auto write = connection->service_requests().try_write_sync(
      WriteRequestBuilder().write(mWriteMatrixId, Variant{block}).index_range("1:2,1:2"));
    ASSERT_TRUE(write.is_good());
    ASSERT_EQ(write.value().results().size(), 1u);
    EXPECT_THAT(write.value().results()[0], Good()) << "a full-dimension 2-D ranged write must be accepted";

    auto readBack = connection->try_read_value_sync(mWriteMatrixId);
    ASSERT_TRUE(readBack.is_good());
    auto flat = readBack.value().value().to_vector<int32_t>();
    ASSERT_TRUE(flat.is_good());
    ASSERT_EQ(flat.value().size(), 16u);
    // Row-major [4,4]: (1,1)=5, (1,2)=6, (2,1)=9, (2,2)=10.
    EXPECT_EQ(flat.value()[5], 900);
    EXPECT_EQ(flat.value()[6], 901);
    EXPECT_EQ(flat.value()[9], 902);
    EXPECT_EQ(flat.value()[10], 903);
    EXPECT_EQ(flat.value()[0], 0) << "cells outside the 2-D sub-block must be untouched";
    EXPECT_EQ(flat.value()[15], 15) << "cells outside the 2-D sub-block must be untouched";
  }

  // --- Multi-node bulk write: one WriteRequest carrying a ranged write to two distinct array nodes.
  {
    Array<int32_t> sliceA{610, 611};
    Array<int32_t> sliceB{620, 621, 622};
    auto write = connection->service_requests().try_write_sync(WriteRequestBuilder()
                                                                 .write(mWriteInt32ArrayId, Variant{sliceA})
                                                                 .index_range("0:1")
                                                                 .write(mWriteInt32ArrayId2, Variant{sliceB})
                                                                 .index_range("5:7"));
    ASSERT_TRUE(write.is_good());
    ASSERT_EQ(write.value().results().size(), 2u);
    EXPECT_THAT(write.value().results()[0], Good()) << "bulk slot 0 must be accepted";
    EXPECT_THAT(write.value().results()[1], Good()) << "bulk slot 1 must be accepted";

    auto readA = connection->try_read_value_sync(mWriteInt32ArrayId);
    ASSERT_TRUE(readA.is_good());
    auto vecA = readA.value().value().to_vector<int32_t>();
    ASSERT_TRUE(vecA.is_good());
    EXPECT_EQ(vecA.value()[0], 610);
    EXPECT_EQ(vecA.value()[1], 611);

    auto readB = connection->try_read_value_sync(mWriteInt32ArrayId2);
    ASSERT_TRUE(readB.is_good());
    auto vecB = readB.value().value().to_vector<int32_t>();
    ASSERT_TRUE(vecB.is_good());
    EXPECT_EQ(vecB.value()[5], 620);
    EXPECT_EQ(vecB.value()[6], 621);
    EXPECT_EQ(vecB.value()[7], 622);
  }

  // --- Scalar String substring write '3:7' of "lo, W"-length replacement into "Hello, World!".
  {
    auto write = connection->service_requests().try_write_sync(
      WriteRequestBuilder().write(mWriteScalarStringId, Variant{String{"XYZ12"}}).index_range("3:7"));
    ASSERT_TRUE(write.is_good());
    ASSERT_EQ(write.value().results().size(), 1u);
    EXPECT_THAT(write.value().results()[0], Good()) << "a scalar String substring write must be accepted";

    auto readBack = connection->try_read_value_sync(mWriteScalarStringId);
    ASSERT_TRUE(readBack.is_good());
    const String* value = readBack.value().value().try_as<String>();
    ASSERT_NE(value, nullptr);
    EXPECT_EQ(std::string_view{*value}, std::string_view{"HelXYZ12orld!"})
      << "chars 3..7 must be replaced in place, the remainder preserved";
  }

  // --- Scalar ByteString substring write '3:7' of {30,31,32,33,34} into {0..9}.
  {
    auto write = connection->service_requests().try_write_sync(
      WriteRequestBuilder()
        .write(mWriteScalarByteStringId, Variant{ByteString{std::vector<uint8_t>{30, 31, 32, 33, 34}}})
        .index_range("3:7"));
    ASSERT_TRUE(write.is_good());
    ASSERT_EQ(write.value().results().size(), 1u);
    EXPECT_THAT(write.value().results()[0], Good()) << "a scalar ByteString substring write must be accepted";

    auto readBack = connection->try_read_value_sync(mWriteScalarByteStringId);
    ASSERT_TRUE(readBack.is_good());
    auto bytes = byte_string_bytes(readBack.value().value());
    ASSERT_TRUE(bytes.has_value());
    EXPECT_EQ(*bytes, (std::vector<uint8_t>{0, 1, 2, 30, 31, 32, 33, 34, 8, 9}))
      << "bytes 3..7 must be replaced in place, the remainder preserved";
  }
}

// @verifies CL-ATTR-009
// @relation(CL-ATTR-009, scope=function)
TEST_F(ClientWriteIndex, Tier2CachedRankAllowsCompleteMultidimensionalWrite)
{
  ua::client::detail::ConnectionConfig config;
  config.addressSpaceCache.enabled = true;
  config.addressSpaceCache.useRegisterNodes = false;
  StartedConnection connection{
    mClientThreadPool.executor(), open_activated_session("WI-Tier2MultiDim"), std::move(config)};
  ASSERT_TRUE(connection.start_status().is_good());

  auto observedRank = connection->typed().try_read_attribute_sync(mWriteMatrixId, AttributeId::ValueRank);
  ASSERT_TRUE(observedRank.is_good());
  ASSERT_EQ(observedRank.value().value().as<std::int32_t>(), 2);

  Array<int32_t> block{930, 931, 932, 933};
  auto write = connection->typed().try_write_attribute_sync(
    mWriteMatrixId, AttributeId::Value, String{"1:2,1:2"}, DataValue{Variant{block}});
  ASSERT_TRUE(write.is_good());

  auto readBack = connection->try_read_value_sync(mWriteMatrixId);
  ASSERT_TRUE(readBack.is_good());
  auto flat = readBack.value().value().to_vector<int32_t>();
  ASSERT_TRUE(flat.is_good());
  ASSERT_EQ(flat.value().size(), 16u);
  EXPECT_EQ(flat.value()[5], 930);
  EXPECT_EQ(flat.value()[6], 931);
  EXPECT_EQ(flat.value()[9], 932);
  EXPECT_EQ(flat.value()[10], 933);
}

// @verifies CL-ATTR-009
// @relation(CL-ATTR-009, scope=function)
// @relation(AC-CL-ADDRSP-006-NUMERICRANGE, scope=function)
TEST(ClientWriteIndexPublic, CachedValueRankRejectsMissingDimensionNoWire)
{
  MisbehavingServer server;
  auto mutateValueRank = std::make_shared<std::atomic<bool>>(false);
  server.set_response_mutator(
    [mutateValueRank](ua::Response& response)
    {
      if (!mutateValueRank->load(std::memory_order_acquire))
        return;
      auto* read = dynamic_cast<ua::ReadResponse*>(response.second.get());
      if (!read)
        return;
      read->results().clear();
      read->results().push_back(ua::DataValue{ua::Variant{std::int32_t{2}}});
    });

  ua::client::detail::ConnectionConfig config;
  config.addressSpaceCache.enabled = true;
  config.addressSpaceCache.useRegisterNodes = false;
  MisbehavingIndexFixture fixture{server, config};
  ASSERT_TRUE(fixture.start_status().is_good());

  mutateValueRank->store(true, std::memory_order_release);
  auto observedRank =
    fixture.conn().typed().try_read_attribute_sync(server_state_node(), AttributeId::ValueRank);
  ASSERT_TRUE(observedRank.is_good());
  ASSERT_EQ(observedRank.value().value().as<std::int32_t>(), 2);

  auto observedWrites = std::make_shared<std::atomic<std::uint64_t>>(0);
  server.set_request_observer(
    [observedWrites](const ua::Structure& request)
    {
      if (dynamic_cast<const ua::WriteRequest*>(&request))
        observedWrites->fetch_add(1, std::memory_order_acq_rel);
    });

  auto result = fixture.conn().typed().try_write_attribute_sync(
    server_state_node(), AttributeId::Value, String{"0:1"}, DataValue{Variant{Array<std::int32_t>{10, 11}}});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIndexRangeInvalid});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "NumericRangeDimensionCountMismatch");
  EXPECT_EQ(observedWrites->load(std::memory_order_acquire), 0u);
}

// =============================================================================================
// ClientWriteIndex - SingleElementWrapsAsArray  (MisbehavingServer)  [int+unit]
// Tier 2 wraps a scalar Variant written with IndexRange='4' into the one-element array required by
// Part 4 section 5.10.4.2. Tier 1 remains the raw wire-shaped explicit override: a caller-supplied array
// succeeds, while a scalar is forwarded verbatim and rejected by the server. [neg: single-element IndexRange
// write must not reach the wire as a scalar through tier 2]
// =============================================================================================
// @verifies AC-CL-ATTR-022-INDEXRANGE-ARRAY
// @relation(AC-CL-ATTR-022-INDEXRANGE-ARRAY, scope=function)
TEST_F(ClientWriteIndex, SingleElementWrapsAsArray)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("WI-SingleElem")};
  ASSERT_TRUE(connection.start_status().is_good());

  // Built path: a caller-supplied 1-element array with IndexRange='4' writes element 4.
  Array<int32_t> oneElement{808};
  auto wrapped = connection->service_requests().try_write_sync(
    WriteRequestBuilder().write(mWriteInt32ArrayId, Variant{oneElement}).index_range("4"));
  ASSERT_TRUE(wrapped.is_good());
  ASSERT_EQ(wrapped.value().results().size(), 1u);
  EXPECT_THAT(wrapped.value().results()[0], Good())
    << "a 1-element array with IndexRange='4' is the correct wire shape and must be accepted";
  {
    auto readBack = connection->try_read_value_sync(mWriteInt32ArrayId);
    ASSERT_TRUE(readBack.is_good());
    auto vec = readBack.value().value().to_vector<int32_t>();
    ASSERT_TRUE(vec.is_good());
    ASSERT_EQ(vec.value().size(), 10u);
    EXPECT_EQ(vec.value()[4], 808) << "element 4 must carry the single-element write";
  }

  // Public tier 2 accepts the ergonomic scalar and emits the required one-element array.
  auto tier2 = connection->typed().try_write_attribute_sync(
    mWriteInt32ArrayId, AttributeId::Value, String{"4"}, DataValue{Variant{int32_t{909}}});
  ASSERT_TRUE(tier2.is_good());
  {
    auto readBack = connection->try_read_value_sync(mWriteInt32ArrayId);
    ASSERT_TRUE(readBack.is_good());
    auto vec = readBack.value().value().to_vector<int32_t>();
    ASSERT_TRUE(vec.is_good());
    ASSERT_EQ(vec.value().size(), 10u);
    EXPECT_EQ(vec.value()[4], 909) << "tier-2 scalar normalization must update the selected element";
  }

  // Raw tier 1 forwards a scalar verbatim and the server rejects the invalid wire shape.
  auto scalar = connection->service_requests().try_write_sync(
    WriteRequestBuilder().write(mWriteInt32ArrayId, Variant{int32_t{910}}).index_range("4"));
  ASSERT_TRUE(scalar.is_good()) << "the Write service itself completes; the failure is per-operation";
  ASSERT_EQ(scalar.value().results().size(), 1u);
  EXPECT_THAT(scalar.value().results()[0], HasStatus(Status::BadTypeMismatch))
    << "the client does not auto-wrap a scalar as a 1-element array; the server rejects the scalar partial";

  // Prove the scalar reaches the wire UNWRAPPED: the request observer sees a scalar WriteValue.
  MisbehavingServer server;
  MisbehavingIndexFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto sawScalar = std::make_shared<std::atomic<int>>(-1);  // -1 = not observed, 0 = array, 1 = scalar
  server.set_request_observer(
    [sawScalar](const ua::Structure& request)
    {
      const auto* write = dynamic_cast<const ua::WriteRequest*>(&request);
      if (!write || write->nodes_to_write().empty())
        return;
      sawScalar->store(write->nodes_to_write()[0].value().value().is_array() ? 0 : 1);
    });
  (void)fixture.conn().service_requests().try_write_sync(
    WriteRequestBuilder().write(server_state_node(), Variant{int32_t{910}}).index_range("4"));
  EXPECT_EQ(sawScalar->load(), 1)
    << "the client must forward the scalar Variant verbatim (no 1-element-array wrap) onto the wire";
}

// =============================================================================================
// ValueSourceIndexRange - ASourceAppliesARangedWrite  (normal server)
// NR-11 rule 3 (NR-70 C3): a ranged Write reaches the Variable's ValueSource as the client sent it, the
// partial value with its IndexRange, and the source merges it into the Value it holds. A whole read
// afterwards returns the source's merged Value. [neg: the source saw the range, so the SDK did not merge it
// first]
// =============================================================================================
// @relation(AC-COMP-ADDRSP-VALUE-SOURCE-01-A-SOURCE-RECEIVES-EACH-ITEM-AS-GIVEN, scope=function)
using ValueSourceIndexRange = ClientWriteIndex;

TEST_F(ValueSourceIndexRange, ASourceAppliesARangedWrite)
{
  struct Held
  {
    std::mutex mutex;
    Variant value{Array<int32_t>{0, 1, 2, 3, 4}};
    std::vector<String> writtenRanges;
  };

  auto held = std::make_shared<Held>();
  auto node = mTestNamespace->find_node<Node>(mWriteInt32ArrayId);
  ASSERT_NE(node, nullptr);
  ASSERT_TRUE(node->external_value_source()
                ->set_value_source(make_value_source(
                  [held](const ValueSource::ReadContext&,
                    const Node&,
                    const ReadValueId& read,
                    std::function<void(DataValueResult)>
                      done)
                  {
                    DataValue value;
                    {
                      const std::lock_guard lock{held->mutex};
                      value.value() = held->value;
                    }
                    index_range_utils::apply_to_value(value, read.index_range());
                    done(DataValueResult{std::move(value)});
                  },
                  [held](const ValueSource::WriteContext&,
                    const Node&,
                    const WriteValue& write,
                    std::function<void(ValueSource::WriteResult)>
                      done)
                  {
                    const std::lock_guard lock{held->mutex};
                    held->writtenRanges.push_back(write.index_range());
                    if (write.index_range().empty())
                    {
                      held->value = write.value().value();
                      done(ValueSource::Written{});
                      return;
                    }
                    auto range = parse_numeric_range(write.index_range());
                    if (range.is_bad())
                    {
                      done(ValueSource::WriteResult{range.status_code(), range.shared_detail()});
                      return;
                    }
                    auto merged =
                      index_range_utils::apply_write(held->value, write.value().value(), range.value());
                    if (merged.is_bad())
                    {
                      done(ValueSource::WriteResult{merged.status_code(), merged.shared_detail()});
                      return;
                    }
                    held->value = std::move(merged).value();
                    done(ValueSource::Written{});
                  }))
                .is_good());

  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("VS-RangedWrite")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto written = connection->typed().try_write_attribute_sync(
    mWriteInt32ArrayId, AttributeId::Value, String{"1:2"}, DataValue{Variant{Array<int32_t>{70, 80}}});
  ASSERT_TRUE(written.is_good()) << to_string(written.status_code());

  {
    const std::lock_guard lock{held->mutex};
    EXPECT_EQ(held->writtenRanges, (std::vector<String>{String{"1:2"}}))
      << "the source did not receive the write's IndexRange";
  }
  auto readBack = connection->try_read_value_sync(mWriteInt32ArrayId);
  ASSERT_TRUE(readBack.is_good()) << to_string(readBack.status_code());
  auto values = readBack.value().value().to_vector<int32_t>();
  ASSERT_TRUE(values.is_good());
  EXPECT_EQ(values.value(), (std::vector<int32_t>{0, 70, 80, 3, 4}));
}
