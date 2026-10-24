// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientRead cluster of the client integration-test matrix (the 12 `ClientRead.*` rows).
///
/// These are END-TO-END integration tests of the TIER-2 managed read accessor
/// (`ua::client::Connection` - `read_value_*`, `typed()`, `service_requests()`, section 7.2) against a real
/// in-tree server. The tier-2 `Connection` is built by wrapping a real `ConnectionImpl` over an
/// activated tier-0 Session (the same construction the reconnect integration test uses). The
/// Connection is built WITHOUT reconnect wiring, so it is single-shot and runs NO keep-alive poll:
/// there are no background reads to race the MisbehavingServer response mutators, and the bootstrap
/// runs against an un-mutated server (mutators are armed only AFTER `start`).
///
/// Falsifiability: every test encodes the matrix row's `[neg: ...]` falsifier - it fails if the named
/// behaviour regresses. Rows whose tier-2 behaviour is not yet built are left as genuinely-failing RED
/// tests that assert the spec (no test skips itself); the header comment on each such test and the
/// authoring report record the gap.
///
/// Fixture note: all 12 tests share the single gtest suite name `ClientRead` (so they are named
/// exactly `ClientRead.<RowName>`). The fixture derives from `ComplianceWithNodes` to give the
/// normal-server rows a populated address space; the MisbehavingServer rows ignore the fixture server
/// and stand up their own adversarial server + client + managed Connection.

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
#include "ua_attribute_id.h"
#include "ua_core_client.h"
#include "ua_client_secure_channel.h"
#include "ua_client_session.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_default_variable_node.h"
#include "ua_logger.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_status.h"
#include "ua_value_source.h"
#include "ua_numeric_range_parser.h"
#include "ua_variant.h"
#include "ua_variable_id.h"

#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <limits>
#include <memory>
#include <optional>
#include <string>
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
// closes gracefully on destruction. This is the interface that exposes the section 7.2 tier-2 read accessor.
// ---------------------------------------------------------------------------------------------
class StartedConnection
{
public:
  StartedConnection(boost::asio::any_io_executor executor, Session session)
  {
    auto impl = ua::client::detail::ConnectionImpl::create(
      std::move(executor), std::move(session), ua::client::detail::ConnectionConfig{}, Logger{});

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
// MisbehavingReadFixture: a real client bound to a MisbehavingServer's crypto + trusted certificate
// store, on its own thread pool, with an activated Session wrapped into a started tier-2 Connection.
// The bootstrap completes against the un-mutated server; the test arms the response mutators AFTER
// construction (see start_status()). Teardown closes the connection, drops the client, then drains.
// ---------------------------------------------------------------------------------------------
class MisbehavingReadFixture
{
public:
  explicit MisbehavingReadFixture(MisbehavingServer& server)
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
    auto session = channel.create_session_sync({.sessionName = "ClientReadMatrix"});
    session.activate_sync();
    mConnection.emplace(mThreadPool.executor(), std::move(session));
  }

  ~MisbehavingReadFixture()
  {
    mConnection.reset();
    mClient.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  MisbehavingReadFixture(const MisbehavingReadFixture&) = delete;
  MisbehavingReadFixture& operator=(const MisbehavingReadFixture&) = delete;

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

// A readable NS0 node present on every server (an enum-backed Int32 value).
NodeId server_state_node()
{
  return NodeId{VariableId::Server_ServerStatus_State};
}

}  // namespace

// ---------------------------------------------------------------------------------------------
// Fixture: one gtest suite `ClientRead` for all 12 rows. Derives from ComplianceWithNodes so the
// normal-server rows have a populated address space; also creates the extra typed nodes the
// round-trip (Row 4) and AccessLevelEx (Row 10) rows need, before the client connects.
// ---------------------------------------------------------------------------------------------
class ClientRead : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();

    auto addressSpace = mServer.server().address_space();

    auto createScalar = [&](uint32_t id, DataTypeId dataType, std::string_view name) -> NodeId
    {
      NodeId nodeId{mTestNamespaceIndex, id};
      auto node = addressSpace.create_node_sync(nodeId, NodeClass::Variable);
      auto variable = node.as<VariableAccessor>();
      variable->set_browse_name(QualifiedName{mTestNamespaceIndex, std::string{name}});
      variable->set_display_name(LocalizedText{"", std::string{name}});
      variable->set_data_type(NodeId{dataType});
      variable->set_access_level(
        AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
      return nodeId;
    };

    mRoundTripInt64Id = createScalar(5001, DataTypeId::Int64, "RoundTripInt64");
    mRoundTripDoubleId = createScalar(5002, DataTypeId::Double, "RoundTripDouble");

    // AccessLevelEx: one Variable advertises NonatomicRead; one omits the AccessLevelEx attribute.
    mNonatomicReadId = createScalar(5100, DataTypeId::Int32, "NonatomicReadVar");
    {
      auto variable = addressSpace.find_node_sync(mNonatomicReadId).as<VariableAccessor>();
      variable->set_access_level_ex(
        AccessLevelExType{AccessLevelExType::Bit::CurrentRead, AccessLevelExType::Bit::NonatomicRead});
    }
    mNoAccessLevelExId = createScalar(5101, DataTypeId::Int32, "NoAccessLevelExVar");
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

  NodeId mRoundTripInt64Id;
  NodeId mRoundTripDoubleId;
  NodeId mNonatomicReadId;
  NodeId mNoAccessLevelExId;
};

// =============================================================================================
// Row 1 - GoodSubStatusPassesThrough  (MisbehavingServer)
// A Good severity with a non-zero sub-code must be delivered as a Good DataValue with the value
// intact - the tier-2 read must not treat "non-zero StatusCode" as "bad" and drop the value.
// [neg: Good severity with sub-code]
// =============================================================================================
// @verifies CL-ATTR-005
// @relation(CL-ATTR-005, scope=function)
TEST_F(ClientRead, GoodSubStatusPassesThrough)
{
  MisbehavingServer server;
  MisbehavingReadFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good()) << "bootstrap must succeed against the un-mutated server: "
                                                << to_string(fixture.start_status().status_code());

  // Arm AFTER bootstrap: stamp results[0] with a Good severity carrying the GoodOverload sub-code.
  server.set_response_mutator(
    [](Response& response)
    {
      if (auto* readResponse = dynamic_cast<ReadResponse*>(response.second.get()))
      {
        if (!readResponse->results().empty())
          readResponse->results()[0] = DataValue{Variant{int32_t{4242}}, StatusCode{Status::GoodOverload}};
      }
    });

  auto result = fixture.conn().try_read_value_sync(server_state_node());
  ASSERT_TRUE(result.is_good()) << "a Good-severity sub-code is not a service failure";

  const auto& dataValue = result.value();
  ASSERT_TRUE(dataValue.status().has_value());
  EXPECT_TRUE(dataValue.status()->is_good())
    << "a Good severity with a sub-code must remain Good, not be reclassified as bad";
  EXPECT_EQ(dataValue.status()->as_uint32(), StatusCode{Status::GoodOverload}.as_uint32())
    << "the exact sub-code must be preserved";
  ASSERT_FALSE(dataValue.value().empty()) << "the Good value must be delivered, not dropped";
  ASSERT_NE(dataValue.value().try_as<int32_t>(), nullptr);
  EXPECT_EQ(*dataValue.value().try_as<int32_t>(), 4242);
}

// =============================================================================================
// Row 2 - InvalidAttributeIdServerRejection  (normal server)
// A Read of an explicitly-cast invalid AttributeId(99) must surface the server's per-operation
// Bad_AttributeIdInvalid through the tier-2 callback; the client must not rewrite/drop the field.
// [neg: out-of-range AttributeId]
// =============================================================================================
// @verifies AC-CL-ATTR-007-VALID-ATTRIBUTEID
// @relation(AC-CL-ATTR-007-VALID-ATTRIBUTEID, scope=function)
TEST_F(ClientRead, InvalidAttributeIdServerRejection)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("R2")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto result =
    connection->typed().try_read_attribute_sync(mWritableVariableId, static_cast<AttributeId>(99));

  ASSERT_TRUE(result.is_good()) << "an invalid attribute is a per-operation status, not a service fault";
  EXPECT_THAT(result.value(), HasStatus(Status::BadAttributeIdInvalid))
    << "the server's Bad_AttributeIdInvalid must reach the caller intact";
}

// =============================================================================================
// Row 3 - MaxAgeZeroAndInt32MaxPassThroughUnclamped  (normal server)
// The client must put MaxAge on the wire as the caller gave it, at both boundaries Part 4 section
// 5.10.2.2 names: 0 ("shall attempt to read a new value from the data source") and Int32.max or greater
// ("shall attempt to get a cached value"). The Variable's single value handler carries the Read's maxAge,
// which the server hands it unchanged, so the value the handler observes is the value the client sent.
// read_value_sync's own default of 0 is checked as a third case. [neg: boundary maxAge values not clamped]
// =============================================================================================
// @verifies CL-ATTR-001
// @verifies CL-ATTR-002
// @relation(CL-ATTR-001, CL-ATTR-002, scope=function)
TEST_F(ClientRead, MaxAgeZeroAndInt32MaxPassThroughUnclamped)
{
  auto observedMaxAge = std::make_shared<std::atomic<double>>(-1.0);
  auto node =
    std::dynamic_pointer_cast<default_ns::VariableNode>(mTestNamespace->find_node<Node>(mMaxAgeVariableId));
  ASSERT_NE(node, nullptr);
  ASSERT_TRUE(node->external_value_source()
                ->set_value_source(make_value_source(
                  [observedMaxAge](const ValueSource::ReadContext& context,
                    const Node& /*node*/,
                    const ReadValueId& read,
                    std::function<void(DataValueResult)>
                      callback)
                  {
                    observedMaxAge->store(context.maxAge);
                    DataValue value{Variant{int32_t{5}}};
                    index_range_utils::apply_to_value(value, read.index_range());
                    callback(DataValueResult{std::move(value)});
                  }))
                .is_good());

  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("R3")};
  ASSERT_TRUE(connection.start_status().is_good());

  // read_value_sync (the tier-2 one-hop) defaults MaxAge to 0.
  observedMaxAge->store(-1.0);
  ASSERT_TRUE(connection->try_read_value_sync(mMaxAgeVariableId).is_good());
  EXPECT_DOUBLE_EQ(observedMaxAge->load(), 0.0) << "read_value_sync must default MaxAge to 0";

  // Explicit MaxAge = 0.
  observedMaxAge->store(-1.0);
  ASSERT_TRUE(
    connection->service_requests()
      .try_read_sync(ReadRequestBuilder().read(mMaxAgeVariableId).attribute(AttributeId::Value).max_age(0.0))
      .is_good());
  EXPECT_DOUBLE_EQ(observedMaxAge->load(), 0.0) << "explicit MaxAge=0 must reach the wire unclamped";

  // Explicit MaxAge = Int32.max.
  //
  // The server keeps no copy of a value a source produces (ua_node.h, ReadValueHandler): it cannot
  // know what the source considers current, whether the value differs per caller, or what holding it
  // costs. Its attempt to get a cached value is therefore to pass maxAge to the source, whose job it is to
  // answer from what it holds; a source that ignores maxAge and always reads freshly is conformant, since
  // Part 4 asks for an attempt. So the handler is consulted here too and must observe Int32.max.
  // (RATIFIED REVERT, 2026-10-01: an R18 rewrite asserted the handler must NOT run at Int32.max, which
  // turned this client test into a server requirement the SDK's documented design does not have; the
  // test then failed from 2026-08-29 until the first full integration run found it.)
  const double int32Max = static_cast<double>(std::numeric_limits<int32_t>::max());
  observedMaxAge->store(-1.0);
  ASSERT_TRUE(
    connection->service_requests()
      .try_read_sync(
        ReadRequestBuilder().read(mMaxAgeVariableId).attribute(AttributeId::Value).max_age(int32Max))
      .is_good());
  EXPECT_GE(observedMaxAge->load(), int32Max) << "Int32.max MaxAge must reach the wire unclamped";
}

// =============================================================================================
// Row 4 - MinMaxAndMaxArrayValuePerDataTypeRoundTrip  (normal server)
// Extreme values of several built-in DataTypes and a 1000-element array must round-trip
// byte-for-byte through the write -> wire -> read -> decode path.
// [neg: DataType matrix extremes + max array]
// =============================================================================================
// @verifies CL-ATTR-005
// @relation(CL-ATTR-005, scope=function)
TEST_F(ClientRead, MinMaxAndMaxArrayValuePerDataTypeRoundTrip)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("R4")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto roundTripScalar = [&connection](const NodeId& node, auto value)
  {
    using T = decltype(value);
    auto write = connection->try_write_value_sync(node, Variant{value});
    ASSERT_TRUE(write.is_good()) << "extreme value must be writable";
    auto read = connection->try_read_value_sync(node);
    ASSERT_TRUE(read.is_good());
    const T* held = read.value().value().template try_as<T>();
    ASSERT_NE(held, nullptr) << "read-back must decode to the written type";
    EXPECT_EQ(*held, value) << "extreme value must round-trip exactly";
  };

  roundTripScalar(mWritableVariableId, std::numeric_limits<int32_t>::min());
  roundTripScalar(mWritableVariableId, std::numeric_limits<int32_t>::max());
  roundTripScalar(mRoundTripInt64Id, std::numeric_limits<int64_t>::min());
  roundTripScalar(mRoundTripInt64Id, std::numeric_limits<int64_t>::max());
  roundTripScalar(mRoundTripDoubleId, std::numeric_limits<double>::lowest());
  roundTripScalar(mRoundTripDoubleId, std::numeric_limits<double>::max());

  // A 1000-element Int32 array: the full length must be consumed and every element preserved.
  Array<int32_t> bigArray;
  for (int32_t i = 0; i < 1000; ++i)
    bigArray.push_back(i);
  ASSERT_TRUE(connection->try_write_value_sync(mArrayVariableId, Variant{bigArray}).is_good());

  auto arrayRead = connection->try_read_value_sync(mArrayVariableId);
  ASSERT_TRUE(arrayRead.is_good());
  auto decoded = arrayRead.value().value().to_vector<int32_t>();
  ASSERT_TRUE(decoded.is_good()) << "the array Value must decode to a vector of Int32";
  ASSERT_EQ(decoded.value().size(), 1000u) << "the full 1000-element array must be consumed";
  EXPECT_EQ(decoded.value()[0], 0);
  EXPECT_EQ(decoded.value()[500], 500);
  EXPECT_EQ(decoded.value()[999], 999);
}

// =============================================================================================
// Row 5 - NegativeMaxAgeRejectedLocallyNoWire  (MisbehavingServer)
// A negative MaxAge must be rejected client-side (Bad_MaxAgeInvalid) BEFORE any Read reaches the
// wire. [neg: negative maxAge blocked before wire]
//
// Local validation ADDED at the managed read entry (ConnectionImpl::read_async): a negative MaxAge is
// rejected as request-input before dispatch. "No wire" is proven by the server interceptor fire-count
// NOT advancing across the call: with no keep-alive on this single-shot Connection and the bootstrap
// already complete, ANY server response (a ReadResponse OR a ServiceFault) would advance the count. A
// count that does not move proves the request never reached the server.
// =============================================================================================
// @verifies CL-ATTR-003
// @relation(CL-ATTR-003, scope=function)
TEST_F(ClientRead, NegativeMaxAgeRejectedLocallyNoWire)
{
  MisbehavingServer server;
  MisbehavingReadFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const uint64_t firesBefore = server.interceptor_fire_count();

  auto result = fixture.conn().service_requests().try_read_sync(
    ReadRequestBuilder().read(server_state_node()).attribute(AttributeId::Value).max_age(-1.0));

  const uint64_t firesAfter = server.interceptor_fire_count();

  EXPECT_EQ(firesBefore, firesAfter)
    << "a negative MaxAge must be rejected before any request reaches the wire (CL-ATTR-003): the "
       "server produced "
    << (firesAfter - firesBefore) << " response(s)";
  EXPECT_TRUE(result.is_bad()) << "a negative MaxAge must fail the call";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadMaxAgeInvalid})
    << "the rejection must carry Bad_MaxAgeInvalid";
}

// =============================================================================================
// Row 6 - PerOperationBadStatusSurfacedRemainingFlow  (MisbehavingServer)
// Case A: in a 2-item Read, an injected Results[0]=Bad_Timeout must surface with a null value while
// slot 1's Good value still flows. Case B: all-bad must surface on every slot with no slot value
// consumed as data. [neg: one-bad-one-good and all-bad]
// =============================================================================================
// @verifies AC-CL-ATTR-005-STATUS-BEFORE-VALUE
// @relation(AC-CL-ATTR-005-STATUS-BEFORE-VALUE, scope=function)
TEST_F(ClientRead, PerOperationBadStatusSurfacedRemainingFlow)
{
  MisbehavingServer server;
  MisbehavingReadFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto mode = std::make_shared<std::atomic<int>>(0);  // 0 = passthrough, 1 = slot-0 bad, 2 = all bad
  server.set_response_mutator(
    [mode](Response& response)
    {
      auto* readResponse = dynamic_cast<ReadResponse*>(response.second.get());
      if (!readResponse)
        return;
      auto& results = readResponse->results();
      const int current = mode->load();
      if (current == 1 && results.size() >= 1)
      {
        results[0] = DataValue{Variant{}, StatusCode{Status::BadTimeout}};
      }
      else if (current == 2)
      {
        for (std::size_t i = 0; i < results.size(); ++i)
          results[i] = DataValue{Variant{}, StatusCode{Status::BadTimeout}};
      }
    });

  auto twoNodeRead = []
  {
    return ReadRequestBuilder()
      .read(NodeId{VariableId::Server_ServerStatus_State})
      .attribute(AttributeId::Value)
      .read(NodeId{VariableId::Server_ServerStatus_CurrentTime})
      .attribute(AttributeId::Value)
      .build();
  };

  // Case A: one bad, one good.
  mode->store(1);
  auto caseA = fixture.conn().service_requests().try_read_sync(twoNodeRead());
  ASSERT_TRUE(caseA.is_good()) << "the service itself succeeds; the failure is per-operation";
  ASSERT_EQ(caseA.value().results().size(), 2u);
  EXPECT_THAT(caseA.value().results()[0], HasStatus(Status::BadTimeout))
    << "slot 0's Bad_Timeout must surface";
  EXPECT_TRUE(caseA.value().results()[0].value().empty()) << "a Bad slot must not hand a value to the caller";
  EXPECT_THAT(caseA.value().results()[1], Good()) << "slot 1's Good value must still flow through";
  EXPECT_FALSE(caseA.value().results()[1].value().empty());

  // Case B: all bad.
  mode->store(2);
  auto caseB = fixture.conn().service_requests().try_read_sync(twoNodeRead());
  ASSERT_TRUE(caseB.is_good());
  ASSERT_EQ(caseB.value().results().size(), 2u);
  for (std::size_t i = 0; i < 2; ++i)
  {
    EXPECT_THAT(caseB.value().results()[i], HasStatus(Status::BadTimeout))
      << "every slot must surface the error";
    EXPECT_TRUE(caseB.value().results()[i].value().empty()) << "no slot value may be consumed as data";
  }
}

// =============================================================================================
// Row 7 - ResultsLengthMismatchRejected  (MisbehavingServer)
// For a 2-node bulk Read, a Results array of length 0, 1, or 3 must be rejected with
// Bad_UnexpectedError; the caller must NOT be handed a synthetic OK value or a mis-aligned result.
// [neg: count mismatch (short/long/empty)]
//
// Slot-alignment guard ADDED at the bulk read facade (TypedAccess::read_values_async): the tier-0
// wire-op funnel returns the malformed response verbatim (raw contract), so the facade validates
// results.size() == nodes.size() (mirrors the ServerDiagnostics facade). This test drives the facade.
// =============================================================================================
// @verifies AC-CL-ATTR-004-READ-ALIGNMENT
// @relation(AC-CL-ATTR-004-READ-ALIGNMENT, scope=function)
TEST_F(ClientRead, ResultsLengthMismatchRejected)
{
  MisbehavingServer server;
  MisbehavingReadFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto targetLength = std::make_shared<std::atomic<int>>(-1);  // -1 = leave untouched
  server.set_response_mutator(
    [targetLength](Response& response)
    {
      auto* readResponse = dynamic_cast<ReadResponse*>(response.second.get());
      if (!readResponse)
        return;
      const int length = targetLength->load();
      if (length < 0)
        return;
      Array<DataValue> replacement;
      for (int i = 0; i < length; ++i)
        replacement.push_back(DataValue{Variant{int32_t{0}}, StatusCode{Status::Good}});
      readResponse->results() = std::move(replacement);
    });

  const std::vector<NodeId> twoNodes{
    NodeId{VariableId::Server_ServerStatus_State}, NodeId{VariableId::Server_ServerStatus_CurrentTime}};

  for (int badLength : {0, 1, 3})
  {
    targetLength->store(badLength);
    auto result = fixture.conn().typed().try_read_values_sync(twoNodes);
    EXPECT_TRUE(result.is_bad()) << "a Results length of " << badLength
                                 << " for a 2-node bulk Read must be rejected, not returned as OK";
    if (result.is_bad())
      EXPECT_EQ(result.status_code(), StatusCode{Status::BadUnexpectedError})
        << "a slot-alignment mismatch must be Bad_UnexpectedError";
  }
}

// =============================================================================================
// Row 8 - ServiceResultErrorSurfacedPerCode  (MisbehavingServer)
// A stamped service-level error must be surfaced to the caller as a bad Result carrying that code;
// it must not be swallowed into a Good response with empty results.
// [neg: service-result family]
//
// Driven through the value facade (read_value_sync), which now flattens a bad
// ResponseHeader.serviceResult the tier-0 wire-op funnel returns verbatim (facade flatten added,
// mirroring the Discovery facade). The "Bad_SessionId* additionally triggers the reconnect path"
// sub-claim needs reconnect wiring; this single-shot Connection has none, so it is out of scope here
// and is exercised by the reconnect cluster.
// =============================================================================================
// @verifies CL-ATTR-004
// @relation(CL-ATTR-004, scope=function)
TEST_F(ClientRead, ServiceResultErrorSurfacedPerCode)
{
  MisbehavingServer server;
  MisbehavingReadFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto serviceResult = std::make_shared<std::atomic<uint32_t>>(0);  // 0 = leave untouched
  server.set_response_mutator(
    [serviceResult](Response& response)
    {
      auto* readResponse = dynamic_cast<ReadResponse*>(response.second.get());
      if (!readResponse)
        return;
      const uint32_t code = serviceResult->load();
      if (code != 0)
        readResponse->response_header().service_result() = StatusCode{code};
    });

  for (Status status : {Status::BadTooManyOperations, Status::BadServiceUnsupported, Status::BadOutOfRange})
  {
    serviceResult->store(StatusCode{status}.as_uint32());
    auto result = fixture.conn().try_read_value_sync(server_state_node());

    EXPECT_TRUE(result.is_bad()) << "service error 0x" << std::hex << StatusCode{status}.as_uint32()
                                 << " must be surfaced, not swallowed";
    if (result.is_bad())
      EXPECT_EQ(result.status_code(), StatusCode{status}) << "the exact service code must surface";
  }
}

// =============================================================================================
// Row 9 - Tier2BadStatusReturnsBadResultNoValue  (MisbehavingServer)
// Case A: a Bad_NoData DataValue with a null Value. Case B: a Bad status with a stray non-null
// Variant (non-conformant). The tier-2 typed read must return a bad Result carrying the StatusCode
// WITHOUT inspecting the Variant (both cases); the DataValue form still returns the raw DataValue for
// inspection. [neg: Bad status carries null Value; stray value ignored]
//
// Asserted through three paths:
//   - The DataValue form (`try_read_value_sync`) faithfully surfaces the raw DataValue for inspection
//     in BOTH cases (Bad status + whatever Value) - the "tier-1 still returns the raw DataValue"
//     clause of the matrix oracle (the two-layer model, CL-DA-015/CL-SM-002).
//   - The SINGLE typed form (`try_read_value_sync<int32_t>`) short-circuits on a Bad-severity value
//     quality: it surfaces that StatusCode AS the Result WITHOUT decoding the Variant (CL-ATTR-005/006).
//     Case B (Bad + stray Variant{999}) yields a bad Result, NOT a bogus Good(999).
//   - The BULK typed form (`typed().try_read_values_sync<int32_t>`) short-circuits identically per element
//     (design section 7.2A). Single and bulk now AGREE - the earlier single-vs-bulk divergence was resolved
//     by CL-ATTR-005/006 (D2).
// =============================================================================================
// @verifies AC-CL-ATTR-005-STATUS-BEFORE-VALUE
// @verifies CL-ATTR-006
// @relation(AC-CL-ATTR-005-STATUS-BEFORE-VALUE, CL-ATTR-006, scope=function)
TEST_F(ClientRead, Tier2BadStatusReturnsBadResultNoValue)
{
  MisbehavingServer server;
  MisbehavingReadFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto mode = std::make_shared<std::atomic<int>>(0);  // 1 = bad + null, 2 = bad + stray value
  server.set_response_mutator(
    [mode](Response& response)
    {
      auto* readResponse = dynamic_cast<ReadResponse*>(response.second.get());
      if (!readResponse || readResponse->results().empty())
        return;
      const int current = mode->load();
      if (current == 1)
        readResponse->results()[0] = DataValue{Variant{}, StatusCode{Status::BadNoData}};
      else if (current == 2)
        readResponse->results()[0] = DataValue{Variant{int32_t{999}}, StatusCode{Status::BadNoData}};
    });

  const std::vector<NodeId> oneNode{server_state_node()};

  // Case A: Bad + null Value.
  mode->store(1);
  {
    // The DataValue form still surfaces the raw DataValue for inspection (two-layer).
    auto dataValueResult = fixture.conn().try_read_value_sync(server_state_node());
    ASSERT_TRUE(dataValueResult.is_good()) << "the DataValue form surfaces the raw value for inspection";
    EXPECT_THAT(dataValueResult.value(), HasStatus(Status::BadNoData));
    EXPECT_TRUE(dataValueResult.value().value().empty()) << "case A carries a null Value";

    // The SINGLE typed short-circuit (CL-ATTR-005/006): a Bad-severity value quality yields a bad Result
    // carrying that StatusCode, WITHOUT decoding the Variant.
    auto singleTyped = fixture.conn().try_read_value_sync<int32_t>(server_state_node());
    ASSERT_TRUE(singleTyped.is_bad()) << "case A: the single typed read flattens the Bad-severity quality";
    EXPECT_EQ(singleTyped.status_code(), StatusCode{Status::BadNoData})
      << "the single typed read must carry the value-quality StatusCode (CL-ATTR-006)";

    // The BULK typed short-circuit (CL-ATTR-005/006): identical per-element behaviour.
    auto typedResult = fixture.conn().typed().try_read_values_sync<int32_t>(oneNode);
    ASSERT_TRUE(typedResult.is_good()) << "the bulk service call itself succeeds";
    ASSERT_EQ(typedResult.value().size(), 1u);
    EXPECT_TRUE(typedResult.value()[0].is_bad()) << "case A: a Bad per-op status yields a bad typed element";
    EXPECT_EQ(typedResult.value()[0].status_code(), StatusCode{Status::BadNoData})
      << "the bad typed element must carry the per-op StatusCode (CL-ATTR-006)";
  }

  // Case B: Bad status with a stray non-null Variant - the falsifier for dereferencing the Variant.
  mode->store(2);
  {
    // The single typed read must NOT return a bogus Good(999) - the Bad-severity flatten short-circuits
    // BEFORE the Variant is decoded (CL-ATTR-005).
    auto singleTyped = fixture.conn().try_read_value_sync<int32_t>(server_state_node());
    ASSERT_TRUE(singleTyped.is_bad())
      << "case B: the single typed read must NOT decode the stray Variant of a Bad DataValue to Good(999)";
    EXPECT_EQ(singleTyped.status_code(), StatusCode{Status::BadNoData});

    auto typedResult = fixture.conn().typed().try_read_values_sync<int32_t>(oneNode);
    ASSERT_TRUE(typedResult.is_good());
    ASSERT_EQ(typedResult.value().size(), 1u);
    EXPECT_TRUE(typedResult.value()[0].is_bad())
      << "case B: the tier-2 typed read must NOT dereference the Variant of a Bad DataValue "
         "(CL-ATTR-005) and hand back a bogus value as success";
  }
}

// =============================================================================================
// Row 10 - AccessLevelExNonatomicFlagsSurfaced  (normal server)
// A Variable advertising AccessLevelEx.NonatomicRead must surface that flag; a Variable that omits
// AccessLevelEx must read as unknown (a Bad per-operation status), not be fabricated as "atomic".
// [neg: absent AccessLevelEx = unknown, not atomic]
//
// Scope: this drives the public tier-2 VariableMetadata accessor against a real server and proves
// decoded NonatomicRead. The absent-attribute wire response is pinned at the fake-transport unit
// interface because the in-tree server materializes a default AccessLevelEx for Variables.
// =============================================================================================
// @verifies AC-CL-ADDRSP-010-NONATOMIC-FLAGS
// @relation(AC-CL-ADDRSP-010-NONATOMIC-FLAGS, scope=function)
TEST_F(ClientRead, AccessLevelExNonatomicFlagsSurfaced)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("R10")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto nonatomic = connection->typed().try_read_variable_metadata_sync(mNonatomicReadId);
  ASSERT_TRUE(nonatomic.is_good());
  ASSERT_TRUE(nonatomic.value().accessLevelEx.has_value());
  EXPECT_TRUE(nonatomic.value().nonatomic_read());

  auto absent = connection->typed().try_read_variable_metadata_sync(mNoAccessLevelExId);
  ASSERT_TRUE(absent.is_good());
  ASSERT_TRUE(absent.value().accessLevelEx.has_value())
    << "the in-tree server materializes its default AccessLevelEx";
  EXPECT_FALSE(absent.value().nonatomic_read());
}

// =============================================================================================
// Row 11 - ExpandedNodeIdServerIndexRoutingOrReject  (normal server)
// The public tier-2 ExpandedNodeId overload must not silently strip a non-zero ServerIndex and read the
// same numeric NodeId from the local Server. This client has no cross-Server registry configured, so its
// documented default policy is a local Bad_NotImplemented rejection with rich diagnostic detail.
// [neg: non-zero serverIndex silently stripped]
// =============================================================================================
// @verifies CL-ATTR-029
// @relation(CL-ATTR-029, scope=function)
TEST_F(ClientRead, ExpandedNodeIdServerIndexRoutingOrReject)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("R11")};
  ASSERT_TRUE(connection.start_status().is_good());

  const ua::ExpandedNodeId remote{mWritableVariableId, {}, std::uint32_t{2}};
  auto result = connection->try_read_value_sync(remote);

  ASSERT_TRUE(result.is_bad()) << "a remote ExpandedNodeId must never be coerced into a local read";
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadNotImplemented});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "ServerIndexRoutingUnsupported");
  EXPECT_EQ(result.shared_detail()->source, "client.tier2.connection.resolve_expanded");
}

// =============================================================================================
// Row 12 - AbstractDataTypeResolvesToConcreteSubtype  (normal server)
// A Variable declaring an abstract DataType (Number) holding a concrete Int32 must be delivered to
// the caller without an "abstract type" complaint. [neg: unrelated concrete type rejected]
//
// Case 2 gap: the unrelated-type case (a String on a Number-declared Variable must be rejected as
// "not a subtype of the declared DataType") needs a client-side TypeResolver check in the read path,
// which is not wired in yet, and injecting a non-conformant value would need the MisbehavingServer.
// The report records case 2 as RED-because-unbuilt. This test pins case 1 (concrete subtype resolves).
// =============================================================================================
// @verifies CL-ADDRSP-009
// @relation(CL-ADDRSP-009, scope=function)
TEST_F(ClientRead, AbstractDataTypeResolvesToConcreteSubtype)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("R12")};
  ASSERT_TRUE(connection.start_status().is_good());

  // Int32 is a concrete subtype of the abstract Number DataType: writable and readable as Int32.
  ASSERT_TRUE(connection->try_write_value_sync(mNumberVariableId, Variant{int32_t{7}}).is_good())
    << "a concrete subtype value must be accepted for an abstract-DataType Variable";

  auto typedResult = connection->try_read_value_sync<int32_t>(mNumberVariableId);
  ASSERT_TRUE(typedResult.is_good())
    << "an abstract-DataType Variable holding a concrete Int32 must resolve without an abstract complaint";
  EXPECT_EQ(typedResult.value(), 7);
}

// =============================================================================================
// Part 5 section 5.3 Table 5 (AccessLevelEx) - "For all Variables specified in NamespaceIndex 0, the
// Attributes named in Table 5 shall be set as specified in Table 5", and the AccessLevelEx row reads:
// "If the AccessLevelEx Attribute is provided, it shall have the bits 8, 9, and 10 set to 0, meaning
// that read and write operations on an individual Variable are atomic, and arrays can be partly
// written." Bit 8 is NonatomicRead, bit 9 NonatomicWrite, bit 10 WriteFullArrayOnly.
//
// The obligation is about what this server publishes for the standard Nodes, and it is the opposite
// arm from Row 10 above: Row 10 proves the CLIENT surfaces the non-atomic flags when a server sets
// them, which says nothing about NS0's own values. A plausible implementation seeds AccessLevelEx for
// every Variable from one server-wide default - an easy way to reach that default is to copy the
// AccessLevel bits and then OR in whatever the data-source layer reports about its own read
// granularity - and a generic client reading a standard Node is then told that Server_ServerArray
// cannot be read atomically and must be written whole, which changes how it reads and writes every
// one of them.
//
// Population: a named sample of NS0 Variables rather than a browse of the whole model, because this
// suite's fixture opens one Session and a full hierarchical walk exhausts its request allowance
// (D-SERVER-SEQUENTIAL-REQUESTS-TOO-BUSY). The size of the sample that actually answered is logged and
// asserted non-zero, so a server that stops publishing AccessLevelEx fails here rather than passing
// over an empty set.
// =============================================================================================
// @verifies AC-SVR-BASE-039-ACCESSLEVELEX
TEST_F(ClientRead, EverySampledNamespaceZeroVariableLeavesTheNonAtomicAccessLevelExBitsClear)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("BASE039")};
  ASSERT_TRUE(connection.start_status().is_good());

  const std::vector<NodeId> subjects{NodeId{VariableId::Server_ServerArray},
    NodeId{VariableId::Server_NamespaceArray},
    NodeId{VariableId::Server_ServerStatus},
    NodeId{VariableId::Server_ServerStatus_StartTime},
    NodeId{VariableId::Server_ServerStatus_CurrentTime},
    NodeId{VariableId::Server_ServerStatus_State},
    NodeId{VariableId::Server_ServiceLevel},
    NodeId{VariableId::Server_Auditing},
    NodeId{VariableId::Server_ServerCapabilities_ServerProfileArray},
    NodeId{VariableId::Server_ServerCapabilities_LocaleIdArray},
    NodeId{VariableId::Server_ServerCapabilities_MinSupportedSampleRate},
    NodeId{VariableId::Server_ServerCapabilities_MaxBrowseContinuationPoints},
    NodeId{VariableId::Server_ServerCapabilities_MaxArrayLength},
    NodeId{VariableId::Server_ServerCapabilities_MaxStringLength},
    NodeId{VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerRead},
    NodeId{VariableId::Server_ServerDiagnostics_EnabledFlag}};

  ReadRequestBuilder builder;
  for (const auto& subject : subjects)
  {
    builder.read(subject).attribute(AttributeId::AccessLevelEx);
  }

  auto response = connection->service_requests().try_read_sync(builder.build());
  ASSERT_TRUE(response.is_good()) << "the batched AccessLevelEx read failed as a service: "
                                  << to_string(response.status_code());
  ASSERT_EQ(response.value().results().size(), subjects.size())
    << "Read results are positional and must match the request";

  std::size_t exposed = 0;
  std::vector<std::string> offenders;
  for (std::size_t i = 0; i < subjects.size(); ++i)
  {
    const auto& dataValue = response.value().results()[i];
    if (dataValue.status().has_value() && dataValue.status()->is_bad())
      continue;  // this Variable does not provide the Attribute; the rule is conditional on it
    const std::uint32_t* raw = dataValue.value().try_as<std::uint32_t>();
    if (raw == nullptr)
      continue;  // provided as nothing at all - again outside the population the rule quantifies over
    ++exposed;

    const AccessLevelExType bits{*raw};
    if (bits.test(AccessLevelExType::Bit::NonatomicRead) ||
        bits.test(AccessLevelExType::Bit::NonatomicWrite) ||
        bits.test(AccessLevelExType::Bit::WriteFullArrayOnly))
    {
      offenders.push_back(ua::to_string(subjects[i]) + " -> AccessLevelEx " + std::to_string(*raw));
    }
  }

  GTEST_LOG_(INFO) << "AccessLevelEx was provided by " << exposed << " of " << subjects.size()
                   << " sampled namespace-0 Variables";
  ASSERT_GT(exposed, 0u) << "not one sampled namespace-0 Variable provided AccessLevelEx, so this test "
                            "checked nothing";
  EXPECT_TRUE(offenders.empty()) << offenders.size()
                                 << " namespace-0 Variable(s) set one of the AccessLevelEx bits 8, 9 or 10 "
                                 << "that Part 5 Table 5 requires to be zero, first: "
                                 << (offenders.empty() ? std::string{} : offenders.front());
}
