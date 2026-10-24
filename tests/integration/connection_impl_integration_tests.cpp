// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Client tier-1 ConnectionImpl integration tests (slice 1: bootstrap + read + close, section 8.2A).
///
/// Drives the internal `ua::client::detail::ConnectionImpl` orchestrator against a real TestServer
/// over ephemeral TCP. Each test performs the tier-0 connect (open_channel / create_session /
/// activate) to obtain an activated session, hands it to a `ConnectionImpl`, and bridges the async
/// surface to the test thread with std::promise / std::future so assertions are deterministic.

#include "compliance_helpers.h"
#include "requests.h"

#include "ua_connection_impl.h"

#include "ua_attribute_id.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_browse_description.h"
#include "ua_browse_direction.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_result_mask.h"
#include "ua_data_value.h"
#include "ua_logger.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_server_state.h"
#include "ua_timestamps_to_return.h"
#include "ua_variable_id.h"
#include "ua_variant.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_write_value.h"

#include <cstdint>
#include <future>
#include <utility>

using namespace ua;
using namespace ua::client;
using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionState;

using ConnectionImplIntegration = ComplianceBase;
using ConnectionImplNodesIntegration = ComplianceWithNodes;

namespace
{

/// Builds a ReadRequest for one node's Value attribute.
ReadRequest make_value_read(const NodeId& node)
{
  ReadRequest request;
  ReadValueId nodeToRead;
  nodeToRead.node_id() = node;
  nodeToRead.attribute_id() = static_cast<std::uint32_t>(AttributeId::Value);
  request.nodes_to_read().push_back(std::move(nodeToRead));
  request.timestamps_to_return() = TimestampsToReturn::Both;
  return request;
}

/// Builds a WriteRequest setting one node's Value attribute to @p value.
WriteRequest make_int32_write(const NodeId& node, std::int32_t value)
{
  WriteRequest request;
  WriteValue writeValue;
  writeValue.node_id() = node;
  writeValue.attribute_id() = static_cast<std::uint32_t>(AttributeId::Value);
  writeValue.value() = DataValue{Variant{value}};
  request.nodes_to_write().push_back(std::move(writeValue));
  return request;
}

/// Builds a forward BrowseRequest for one node.
BrowseRequest make_forward_browse(const NodeId& node)
{
  BrowseRequest request;
  BrowseDescription description;
  description.node_id() = node;
  description.browse_direction() = BrowseDirection::Forward;
  description.include_subtypes() = true;
  description.result_mask() = static_cast<std::uint32_t>(BrowseResultMask::All);
  request.nodes_to_browse().push_back(std::move(description));
  return request;
}

/// Runs the bootstrap and blocks until it completes, returning the outcome.
VoidResult start_and_wait(ConnectionImpl& connection)
{
  std::promise<VoidResult> promise;
  auto future = promise.get_future();
  connection.start_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
  return future.get();
}

/// Issues a Read through the orchestrator and blocks until it completes.
Result<ReadResponse> read_and_wait(ConnectionImpl& connection, ReadRequest request)
{
  std::promise<Result<ReadResponse>> promise;
  auto future = promise.get_future();
  connection.read_async(
    std::move(request), [&promise](Result<ReadResponse> result) { promise.set_value(std::move(result)); });
  return future.get();
}

/// Closes the orchestrator and blocks until it completes.
VoidResult close_and_wait(ConnectionImpl& connection)
{
  std::promise<VoidResult> promise;
  auto future = promise.get_future();
  connection.close_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
  return future.get();
}

/// Issues a Write through the orchestrator and blocks until it completes.
Result<WriteResponse> write_and_wait(ConnectionImpl& connection, WriteRequest request)
{
  std::promise<Result<WriteResponse>> promise;
  auto future = promise.get_future();
  connection.write_async(
    std::move(request), [&promise](Result<WriteResponse> result) { promise.set_value(std::move(result)); });
  return future.get();
}

/// Issues a Browse through the orchestrator and blocks until it completes.
Result<BrowseResponse> browse_and_wait(ConnectionImpl& connection, BrowseRequest request)
{
  std::promise<Result<BrowseResponse>> promise;
  auto future = promise.get_future();
  connection.browse_async(
    std::move(request), [&promise](Result<BrowseResponse> result) { promise.set_value(std::move(result)); });
  return future.get();
}

/// Issues a Call through the orchestrator and blocks until it completes.
Result<CallResponse> call_and_wait(ConnectionImpl& connection, CallRequest request)
{
  std::promise<Result<CallResponse>> promise;
  auto future = promise.get_future();
  connection.call_async(
    std::move(request), [&promise](Result<CallResponse> result) { promise.set_value(std::move(result)); });
  return future.get();
}

}  // namespace

// ---------------------------------------------------------------------------
// Bootstrap reaches Active and reads the NamespaceArray (section 8.2A.3 / CL-SESS-028).
// ---------------------------------------------------------------------------
// @relation(CL-BASE-004, scope=function)
TEST_F(ConnectionImplIntegration, BootstrapReachesActiveAndReadsNamespaceArray)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "CONN_IMPL_BOOTSTRAP"});
  session.activate_sync();
  ASSERT_TRUE(session.is_active());

  auto connection = ConnectionImpl::create(
    mClientThreadPool.executor(), std::move(session), ua::client::detail::ConnectionConfig{}, Logger{});

  auto startResult = start_and_wait(*connection);
  ASSERT_TRUE(startResult.is_good()) << "bootstrap failed: 0x" << std::hex
                                     << startResult.status_code().as_uint32();

  auto info = connection->info();
  ASSERT_NE(info, nullptr);
  EXPECT_EQ(info->state, ConnectionState::Active);
  EXPECT_GE(info->namespaceCount, 1u);
  EXPECT_FALSE(info->sessionId.is_null());

  // CL-BASE-001: the bootstrap batches a Server.UrisVersion read alongside the NamespaceArray. This server
  // does not publish Server.UrisVersion, so its index-2 result is a per-item bad status - the client must
  // TOLERATE that (bootstrap still reaches Active above, namespaceCount >= 1) and leave the snapshot
  // version-untagged. A client that treated the per-item bad as fatal would fail the whole bootstrap; a
  // client that mis-populated it would carry a spurious version. @verifies CL-BASE-001
  EXPECT_FALSE(info->urisVersion.has_value()) << "a server without Server.UrisVersion must leave the cached "
                                                 "snapshot version-untagged, not fail bootstrap";

  // CL-BASE-003: the client must honour OperationLimits.MaxNodesPer* when batching, which starts with reading
  // + caching them at bootstrap. This server PUBLISHES the OperationLimits (MaxNodesPer* == 1000), so the
  // client caches the real server-published values end-to-end - proving the combined bootstrap read + the
  // index-3 parse alignment against a real server, not just the fake. A client that failed to read them would
  // leave 0; a mis-indexed parse a wrong value. The end-to-end CONSUMPTION of the cached limit (transparent
  // chunking of an over-limit batch) is the ChunkedReadBeyondMaxNodesPerRead test below.
  // @verifies CL-BASE-003
  EXPECT_EQ(info->operationLimits.maxNodesPerRead, 1000u)
    << "the client must cache the server-published Server...OperationLimits.MaxNodesPerRead";
  EXPECT_EQ(info->operationLimits.maxNodesPerBrowse, 1000u);
  EXPECT_GT(info->operationLimits.maxMonitoredItemsPerCall, 0u)
    << "the server publishes MaxMonitoredItemsPerCall; the client must read it";

  // @verifies CL-BASE-004
  // The same real bootstrap reads the three mandatory UInt16 ServerCapabilities continuation-point
  // ceilings. The focused unit controls above consume these cached values for deterministic admission and
  // release; this real-wire assertion prevents a fake-only parser/wiring implementation from passing.
  EXPECT_GT(info->continuationPointLimits.maxBrowse, 0u);
  EXPECT_GT(info->continuationPointLimits.maxQuery, 0u);
  EXPECT_GT(info->continuationPointLimits.maxHistory, 0u);

  EXPECT_TRUE(close_and_wait(*connection).is_good());
}

// ---------------------------------------------------------------------------
// CL-BASE-003 end-to-end: a Read batch LARGER than the server's MaxNodesPerRead must be transparently split
// into <= limit-sized chunks and reassembled. This is a falsifiable real-stack oracle: the reference server
// ENFORCES MaxNodesPerRead (== 1000) by faulting an over-limit single Read with BadTooManyOperations, so a
// client that did NOT chunk would fail the whole call; a client that chunks sends 2 Reads (1000 + 500) that
// both succeed, yielding all 1500 results in request order. @verifies CL-BASE-003
// ---------------------------------------------------------------------------
TEST_F(ConnectionImplIntegration, ChunkedReadBeyondMaxNodesPerRead)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "CONN_IMPL_CHUNK_READ"});
  session.activate_sync();

  auto connection = ConnectionImpl::create(
    mClientThreadPool.executor(), std::move(session), ua::client::detail::ConnectionConfig{}, Logger{});
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto info = connection->info();
  ASSERT_NE(info, nullptr);
  ASSERT_EQ(info->operationLimits.maxNodesPerRead, 1000u)
    << "precondition: server publishes MaxNodesPerRead=1000";

  // 1500 > 1000: a non-chunking client sends one over-limit Read and the server faults it
  // (BadTooManyOperations).
  constexpr std::size_t batch = 1500;
  ReadRequest request;
  for (std::size_t index = 0; index < batch; ++index)
  {
    ReadValueId nodeToRead;
    nodeToRead.node_id() = NodeId{VariableId::Server_ServerStatus_State};
    nodeToRead.attribute_id() = static_cast<std::uint32_t>(AttributeId::Value);
    request.nodes_to_read().push_back(std::move(nodeToRead));
  }
  request.timestamps_to_return() = TimestampsToReturn::Both;

  auto readResult = read_and_wait(*connection, std::move(request));
  ASSERT_TRUE(readResult.is_good())
    << "an over-limit batched Read must be chunked transparently, not faulted: 0x" << std::hex
    << readResult.status_code().as_uint32();

  const auto& response = readResult.value();
  ASSERT_EQ(response.results().size(), batch)
    << "the reassembled read must return one result per requested node";
  for (std::size_t index = 0; index < response.results().size(); ++index)
  {
    const auto& itemResult = response.results()[index];
    ASSERT_FALSE(itemResult.status().has_value() && itemResult.status()->is_bad())
      << "result " << index << " is bad - a chunk boundary must not corrupt per-item results";
    EXPECT_EQ(itemResult.value().as<int32_t>(), static_cast<int32_t>(ServerState::Running))
      << "every chunk must resolve Server_ServerStatus_State == Running";
  }

  EXPECT_TRUE(close_and_wait(*connection).is_good());
}

// ---------------------------------------------------------------------------
// A Read routed through the gate returns Server_ServerStatus_State == Running.
// ---------------------------------------------------------------------------
TEST_F(ConnectionImplIntegration, ReadThroughConnectionReturnsServerState)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "CONN_IMPL_READ"});
  session.activate_sync();

  auto connection = ConnectionImpl::create(
    mClientThreadPool.executor(), std::move(session), ua::client::detail::ConnectionConfig{}, Logger{});
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto readResult =
    read_and_wait(*connection, make_value_read(NodeId{VariableId::Server_ServerStatus_State}));
  ASSERT_TRUE(readResult.is_good()) << "read failed: 0x" << std::hex << readResult.status_code().as_uint32();

  const auto& response = readResult.value();
  ASSERT_EQ(response.results().size(), 1u);
  EXPECT_FALSE(response.results()[0].status().has_value() && response.results()[0].status()->is_bad());

  auto value = response.results()[0].value().as<int32_t>();
  EXPECT_EQ(value, static_cast<int32_t>(ServerState::Running));

  EXPECT_TRUE(close_and_wait(*connection).is_good());
}

// ---------------------------------------------------------------------------
// close_async transitions to Closed and the gate then fails further Reads.
// ---------------------------------------------------------------------------
TEST_F(ConnectionImplIntegration, CloseTransitionsToClosed)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "CONN_IMPL_CLOSE"});
  session.activate_sync();

  auto connection = ConnectionImpl::create(
    mClientThreadPool.executor(), std::move(session), ua::client::detail::ConnectionConfig{}, Logger{});
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  EXPECT_TRUE(close_and_wait(*connection).is_good());
  ASSERT_NE(connection->info(), nullptr);
  EXPECT_EQ(connection->info()->state, ConnectionState::Closed);

  // A Read after close is rejected with Bad_ConnectionClosed (section 8.2A.3: new calls after close fail).
  auto readResult =
    read_and_wait(*connection, make_value_read(NodeId{VariableId::Server_ServerStatus_State}));
  EXPECT_TRUE(readResult.is_bad());
}

// ---------------------------------------------------------------------------
// A Write routed through the gate updates a writable node; a follow-up Read
// (also through the gate) reads the new value back.
// ---------------------------------------------------------------------------
TEST_F(ConnectionImplNodesIntegration, WriteThenReadBackThroughConnection)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "CONN_IMPL_WRITE"});
  session.activate_sync();

  auto connection = ConnectionImpl::create(
    mClientThreadPool.executor(), std::move(session), ua::client::detail::ConnectionConfig{}, Logger{});
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  const std::int32_t newValue = 24680;
  auto writeResult = write_and_wait(*connection, make_int32_write(mWritableVariableId, newValue));
  ASSERT_TRUE(writeResult.is_good()) << "write failed: 0x" << std::hex
                                     << writeResult.status_code().as_uint32();
  ASSERT_EQ(writeResult.value().results().size(), 1u);
  EXPECT_TRUE(writeResult.value().results()[0].is_good())
    << "write op status: 0x" << std::hex << writeResult.value().results()[0].as_uint32();

  auto readResult = read_and_wait(*connection, make_value_read(mWritableVariableId));
  ASSERT_TRUE(readResult.is_good());
  ASSERT_EQ(readResult.value().results().size(), 1u);
  EXPECT_EQ(readResult.value().results()[0].value().as<std::int32_t>(), newValue);

  EXPECT_TRUE(close_and_wait(*connection).is_good());
}

// ---------------------------------------------------------------------------
// A Browse routed through the gate returns the child references of a node.
// ---------------------------------------------------------------------------
TEST_F(ConnectionImplNodesIntegration, BrowseThroughConnectionReturnsReferences)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "CONN_IMPL_BROWSE"});
  session.activate_sync();

  auto connection = ConnectionImpl::create(
    mClientThreadPool.executor(), std::move(session), ua::client::detail::ConnectionConfig{}, Logger{});
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  auto browseResult = browse_and_wait(*connection, make_forward_browse(mTestFolderId));
  ASSERT_TRUE(browseResult.is_good())
    << "browse failed: 0x" << std::hex << browseResult.status_code().as_uint32();
  ASSERT_EQ(browseResult.value().results().size(), 1u);
  EXPECT_TRUE(browseResult.value().results()[0].status_code().is_good());
  EXPECT_GE(browseResult.value().results()[0].references().size(), 1u)
    << "the test folder has at least one child reference";

  EXPECT_TRUE(close_and_wait(*connection).is_good());
}

// ---------------------------------------------------------------------------
// A Call routed through the gate invokes a server method and returns its output.
// ---------------------------------------------------------------------------
TEST_F(ConnectionImplNodesIntegration, CallThroughConnectionReturnsMethodOutput)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "CONN_IMPL_CALL"});
  session.activate_sync();

  auto connection = ConnectionImpl::create(
    mClientThreadPool.executor(), std::move(session), ua::client::detail::ConnectionConfig{}, Logger{});
  ASSERT_TRUE(start_and_wait(*connection).is_good());

  // mTestMethodId is an "Add" method (two Int32 args -> their sum).
  auto callResult = call_and_wait(*connection,
    ua::test_helpers::CallRequestBuilder()
      .call(mTestFolderId, mTestMethodId, {Variant{std::int32_t{5}}, Variant{std::int32_t{7}}})
      .build());
  ASSERT_TRUE(callResult.is_good()) << "call failed: 0x" << std::hex << callResult.status_code().as_uint32();
  ASSERT_EQ(callResult.value().results().size(), 1u);
  ASSERT_TRUE(callResult.value().results()[0].status_code().is_good());
  ASSERT_EQ(callResult.value().results()[0].output_arguments().size(), 1u);
  EXPECT_EQ(callResult.value().results()[0].output_arguments()[0].as<std::int32_t>(), 12);

  EXPECT_TRUE(close_and_wait(*connection).is_good());
}
