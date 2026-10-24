// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Falsifiable coverage for the P4 find_nodes adoption (interface refactor proposal section 5).
//
// The Read and Write services resolve every node in a request through ONE batched
// AddressSpace::find_nodes_async call rather than one find_node_async per item. Because the base
// Namespace::find_nodes default simply loops find_node, the resolved accessors - and therefore
// every service result - are byte-identical whether or not the service batches; the in-memory
// suite alone cannot tell the two apart. These tests make the difference observable: a namespace
// that counts its find_node vs find_nodes entry points proves the service drives find_nodes exactly
// once for a multi-item, single-namespace request. Before the adoption this count was zero (the
// service called find_node per item); after it, it is one. That is the falsifiable signal.

#include <gtest/gtest.h>

#include <atomic>
#include <future>
#include <span>
#include <vector>

#include "ua_access_level_type.h"
#include "ua_attribute_id.h"
#include "ua_attribute_service_set.h"
#include "ua_default_namespace.h"
#include "ua_node_accessor.h"
#include "ua_qualified_name.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_server.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include <boost/asio/thread_pool.hpp>

#include "stubs.h"
#include "test_log_sink.h"
#include "test_utilities.h"

#include "test_components.h"
using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

namespace
{

// Wraps the in-memory default namespace and counts how often the service layer resolves, and with
// how many ids at a time. find_nodes delegates to the in-memory base, so the resolved accessors (and
// hence service results) are unchanged - only the shape of the resolution is observable.
class ResolveCountingNamespace final : public default_ns::Namespace
{
public:
  ResolveCountingNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  void find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
    std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> callback) override
  {
    ++mFindNodesCalls;
    mLastBatchSize = nodeIds.size();
    default_ns::Namespace::find_nodes_async(request, nodeIds, maxAge, std::move(callback));
  }

  /// Declines the synchronous form, which is what a namespace fronting a remote store does - and
  /// what keeps find_nodes the only route, so counting it counts every resolution. The answering
  /// side is covered separately; see the two-sided coverage the interface asks for.
  std::optional<NodeResult> find_node(const NodeId& nodeId, std::optional<Duration> maxAge) override
  {
    (void)nodeId;
    (void)maxAge;
    return std::nullopt;
  }

  size_t find_nodes_calls() const
  {
    return mFindNodesCalls.load();
  }

  size_t last_batch_size() const
  {
    return mLastBatchSize.load();
  }

  /// Zeroes the counters so an assertion measures ONE operation rather than the whole fixture.
  ///
  /// Resolution is the only interface now, so server construction, namespace registration and node
  /// creation all pass through find_nodes too. Counting from here makes "one call" mean one call by
  /// the service under test - and means it now also catches a service that resolves item by item,
  /// which a counter watching only the batched entry point could never see.
  void reset_counts()
  {
    mFindNodesCalls.store(0);
    mLastBatchSize.store(0);
  }

private:
  std::atomic_size_t mFindNodesCalls{0};
  std::atomic_size_t mLastBatchSize{0};
};

ua::server::Server make_server(boost::asio::any_io_executor executor)
{
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};
  auto server = ua::server::Server::create(
    executor, std::move(cfg), ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  return server;
}

}  // namespace

TEST(BatchResolveTests, ReadResolvesAllItemsInOneFindNodesCall)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();

  auto server = make_server(executor);
  auto ns = make_shared<ResolveCountingNamespace>("uri://batch-resolve-read", executor);
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);

  constexpr size_t nodeCount = 5;
  std::vector<NodeId> ids;
  ids.reserve(nodeCount);
  for (size_t i = 0; i < nodeCount; ++i)
  {
    NodeId id{nsIndex, static_cast<uint32_t>(1000 + i)};
    ns->create_node(id, NodeClass::Object);
    ids.push_back(id);
  }

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), executor);

  // Read each node's own NodeId attribute: the expected value is DISTINCT per item, so the
  // per-item reassembly (batch.items[k] -> request slot) is ordering-sensitive - a permuted or
  // misindexed batch would surface as a value landing on the wrong node.
  ReadRequest readRequest;
  readRequest.timestamps_to_return() = TimestampsToReturn::Neither;
  readRequest.nodes_to_read().resize(nodeCount);
  for (size_t i = 0; i < nodeCount; ++i)
  {
    readRequest.nodes_to_read()[i].node_id() = ids[i];
    readRequest.nodes_to_read()[i].attribute_id() = utils::to_underlying(AttributeId::NodeId);
  }

  std::promise<void> done;
  ReadResponse result;
  std::vector<LocaleId> locales{"en"};
  ns->reset_counts();
  auto service = AttributeServiceSet::create(sessionInfo,
    locales,
    0,
    std::move(readRequest),
    executor,
    [&done, &result](Response response)
    {
      if (auto* readResponse = dynamic_cast<ReadResponse*>(response.second.get()))
        result = std::move(*readResponse);
      done.set_value();
    });

  ASSERT_EQ(done.get_future().wait_for(2s), std::future_status::ready);

  // The whole request resolved through exactly one batched find_nodes, carrying every node id.
  EXPECT_EQ(ns->find_nodes_calls(), 1u);
  EXPECT_EQ(ns->last_batch_size(), nodeCount);

  // ...and each result carries its OWN node's id, so batching preserved per-item order. The default
  // read path leaves status() empty on success (implicit Good); a present status must be good.
  ASSERT_EQ(result.results().size(), nodeCount);
  for (size_t i = 0; i < nodeCount; ++i)
  {
    const auto& dv = result.results()[i];
    if (dv.status().has_value())
      EXPECT_TRUE(dv.status()->is_good());
    EXPECT_EQ(dv.value().as<NodeId>(), ids[i]);
  }

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

TEST(BatchResolveTests, WriteResolvesAllItemsInOneFindNodesCall)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();

  auto server = make_server(executor);
  auto ns = make_shared<ResolveCountingNamespace>("uri://batch-resolve-write", executor);
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);

  auto addressSpace = server.address_space();
  constexpr size_t nodeCount = 4;
  std::vector<NodeId> ids;
  ids.reserve(nodeCount);
  for (size_t i = 0; i < nodeCount; ++i)
  {
    NodeId id{nsIndex, static_cast<uint32_t>(2000 + i)};
    auto varResult = addressSpace.try_create_sync<VariableAccessor>(id, NodeClass::Variable);
    ASSERT_TRUE(varResult.is_good());
    AccessLevelType accessLevel;
    accessLevel.set(AccessLevelType::Bit::CurrentRead);
    accessLevel.set(AccessLevelType::Bit::CurrentWrite);
    varResult.value().set_access_level(accessLevel);
    ids.push_back(id);
  }

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), executor);

  WriteRequest writeRequest;
  writeRequest.nodes_to_write().resize(nodeCount);
  for (size_t i = 0; i < nodeCount; ++i)
  {
    auto& wv = writeRequest.nodes_to_write()[i];
    wv.node_id() = ids[i];
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{static_cast<int32_t>(i)};
  }

  std::promise<void> done;
  WriteResponse result;
  ns->reset_counts();
  auto service = AttributeServiceSet::create(sessionInfo,
    1,
    std::move(writeRequest),
    executor,
    [&done, &result](Response response)
    {
      if (auto* writeResponse = dynamic_cast<WriteResponse*>(response.second.get()))
        result = std::move(*writeResponse);
      done.set_value();
    });

  ASSERT_EQ(done.get_future().wait_for(2s), std::future_status::ready);

  EXPECT_EQ(ns->find_nodes_calls(), 1u);
  EXPECT_EQ(ns->last_batch_size(), nodeCount);

  ASSERT_EQ(result.results().size(), nodeCount);
  for (const auto& status : result.results())
  {
    EXPECT_TRUE(status.is_good());
  }

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Exercises the genuinely new logic the adoption introduced: when only SOME items survive their
// pre-checks, the batch is a PROPER SUBSET of the request and on_read_nodes_resolved must scatter
// each batch result back to its ABSOLUTE request slot (indices[k]), not to k. Items 0 and 2 carry a
// dataEncoding on a non-Value attribute, which prepare_read_operation rejects up front
// (BadDataEncodingInvalid) so they never enter the batch; items 1 and 3 survive. A skip/remap bug
// (using k instead of indices[k]) would land the survivors in the wrong slots and is caught here.
TEST(BatchResolveTests, ReadBatchesOnlySurvivorsAfterEarlyReject)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();

  auto server = make_server(executor);
  auto ns = make_shared<ResolveCountingNamespace>("uri://batch-resolve-read-subset", executor);
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);

  constexpr size_t nodeCount = 4;
  std::vector<NodeId> ids;
  ids.reserve(nodeCount);
  for (size_t i = 0; i < nodeCount; ++i)
  {
    NodeId id{nsIndex, static_cast<uint32_t>(3000 + i)};
    ns->create_node(id, NodeClass::Object);
    ids.push_back(id);
  }

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), executor);

  ReadRequest readRequest;
  readRequest.timestamps_to_return() = TimestampsToReturn::Neither;
  readRequest.nodes_to_read().resize(nodeCount);
  for (size_t i = 0; i < nodeCount; ++i)
  {
    auto& rvid = readRequest.nodes_to_read()[i];
    rvid.node_id() = ids[i];
    rvid.attribute_id() = utils::to_underlying(AttributeId::NodeId);
    // Even indices: a dataEncoding on a non-Value attribute -> rejected in prepare, omitted from
    // the batch. Odd indices: clean reads that survive into the batch.
    if (i % 2 == 0)
      rvid.data_encoding() = QualifiedName{0, "Default Binary"};
  }

  std::promise<void> done;
  ReadResponse result;
  std::vector<LocaleId> locales{"en"};
  ns->reset_counts();
  auto service = AttributeServiceSet::create(sessionInfo,
    locales,
    0,
    std::move(readRequest),
    executor,
    [&done, &result](Response response)
    {
      if (auto* readResponse = dynamic_cast<ReadResponse*>(response.second.get()))
        result = std::move(*readResponse);
      done.set_value();
    });

  ASSERT_EQ(done.get_future().wait_for(2s), std::future_status::ready);

  // Exactly one batch, carrying ONLY the two survivors.
  EXPECT_EQ(ns->find_nodes_calls(), 1u);
  EXPECT_EQ(ns->last_batch_size(), 2u);

  ASSERT_EQ(result.results().size(), nodeCount);
  for (size_t i = 0; i < nodeCount; ++i)
  {
    const auto& dv = result.results()[i];
    if (i % 2 == 0)
    {
      // Rejected before resolution - the failure status is always present.
      ASSERT_TRUE(dv.status().has_value());
      EXPECT_EQ(*dv.status(), Status::BadDataEncodingInvalid);
    }
    else
    {
      // Survivor: scattered back to its own slot, carrying its own node id. The default read path
      // leaves status() empty on success (implicit Good); a present status must be good.
      if (dv.status().has_value())
        EXPECT_TRUE(dv.status()->is_good());
      EXPECT_EQ(dv.value().as<NodeId>(), ids[i]);
    }
  }

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Write has no per-item pre-check that rejects (prepare_write_operation only fails whole-request on
// a dead session / missing AccessIdentity), so the proper-subset case is produced instead by routing
// some items to an UNKNOWN namespace: start_write_request answers those with BadNodeIdUnknown up
// front and omits them from the dispatch set, leaving a non-contiguous survivor set that
// on_write_nodes_resolved must scatter back by absolute slot. A remap bug would let a survivor's
// Good status overwrite an unknown-namespace slot (or vice versa).
TEST(BatchResolveTests, WriteBatchesOnlySurvivorsAfterUnknownNamespaceItems)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();

  auto server = make_server(executor);
  auto ns = make_shared<ResolveCountingNamespace>("uri://batch-resolve-write-subset", executor);
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);
  // An index with no registered namespace -> BadNodeIdUnknown, handled before dispatch.
  const uint16_t unknownNsIndex = static_cast<uint16_t>(nsIndex + 7);

  auto addressSpace = server.address_space();
  constexpr size_t nodeCount = 4;
  std::vector<NodeId> ids;
  ids.reserve(nodeCount);
  for (size_t i = 0; i < nodeCount; ++i)
  {
    if (i % 2 == 0)
    {
      // Unknown-namespace item: never created, never resolved.
      ids.push_back(NodeId{unknownNsIndex, static_cast<uint32_t>(4000 + i)});
      continue;
    }
    NodeId id{nsIndex, static_cast<uint32_t>(4000 + i)};
    auto varResult = addressSpace.try_create_sync<VariableAccessor>(id, NodeClass::Variable);
    ASSERT_TRUE(varResult.is_good());
    AccessLevelType accessLevel;
    accessLevel.set(AccessLevelType::Bit::CurrentRead);
    accessLevel.set(AccessLevelType::Bit::CurrentWrite);
    varResult.value().set_access_level(accessLevel);
    ids.push_back(id);
  }

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), executor);

  WriteRequest writeRequest;
  writeRequest.nodes_to_write().resize(nodeCount);
  for (size_t i = 0; i < nodeCount; ++i)
  {
    auto& wv = writeRequest.nodes_to_write()[i];
    wv.node_id() = ids[i];
    wv.attribute_id() = utils::to_underlying(AttributeId::Value);
    wv.value().value() = Variant{static_cast<int32_t>(i)};
  }

  std::promise<void> done;
  WriteResponse result;
  ns->reset_counts();
  auto service = AttributeServiceSet::create(sessionInfo,
    1,
    std::move(writeRequest),
    executor,
    [&done, &result](Response response)
    {
      if (auto* writeResponse = dynamic_cast<WriteResponse*>(response.second.get()))
        result = std::move(*writeResponse);
      done.set_value();
    });

  ASSERT_EQ(done.get_future().wait_for(2s), std::future_status::ready);

  // Exactly one batch, carrying ONLY the two known-namespace survivors.
  EXPECT_EQ(ns->find_nodes_calls(), 1u);
  EXPECT_EQ(ns->last_batch_size(), 2u);

  ASSERT_EQ(result.results().size(), nodeCount);
  for (size_t i = 0; i < nodeCount; ++i)
  {
    if (i % 2 == 0)
      EXPECT_EQ(result.results()[i], Status::BadNodeIdUnknown);
    else
      EXPECT_TRUE(result.results()[i].is_good());
  }

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// =============================================================================================
// The other side of the interface: a namespace that CAN answer immediately
// =============================================================================================
//
// Every test above models a namespace fronting a remote store - it declines the synchronous form, so
// find_nodes is the only route and counting it counts everything. These two cover the other half of
// the interface's contract, which is the half nearly every real namespace in this SDK uses: an
// in-memory store answers on the caller's stack and is never asked through find_nodes at all.
//
// This is what the synchronous form is FOR. Measured on the same store, one resolution costs 231ns
// answered here against 2201ns through find_nodes (resolution_round_trip_tests.cpp, debug build) -
// and for a whole request it is paid once per node instead of once per node plus a suspension.

namespace
{

/// Answers every id from the local store, and counts what it was asked and by which route.
class AnsweringNamespace final : public default_ns::Namespace
{
public:
  AnsweringNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  std::optional<NodeResult> find_node(const NodeId& nodeId, std::optional<Duration> maxAge) override
  {
    ++mFindNodeCalls;
    return default_ns::Namespace::find_node(nodeId, maxAge);
  }

  void find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
    std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> callback) override
  {
    ++mFindNodesCalls;
    default_ns::Namespace::find_nodes_async(request, nodeIds, maxAge, std::move(callback));
  }

  size_t find_node_calls() const
  {
    return mFindNodeCalls.load();
  }

  size_t find_nodes_calls() const
  {
    return mFindNodesCalls.load();
  }

  void reset_counts()
  {
    mFindNodeCalls.store(0);
    mFindNodesCalls.store(0);
  }

private:
  std::atomic_size_t mFindNodeCalls{0};
  std::atomic_size_t mFindNodesCalls{0};
};

}  // namespace

TEST(BatchResolveTests, ANamespaceThatAnswersImmediatelyIsNeverAskedAsynchronously)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();

  auto server = make_server(executor);
  auto ns = make_shared<AnsweringNamespace>("uri://batch-resolve-fast", executor);
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);

  constexpr size_t nodeCount = 5;
  std::vector<NodeId> ids;
  ids.reserve(nodeCount);
  for (size_t i = 0; i < nodeCount; ++i)
  {
    NodeId id{nsIndex, static_cast<uint32_t>(4000 + i)};
    ns->create_node(id, NodeClass::Object);
    ids.push_back(id);
  }

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), executor);

  ReadRequest readRequest;
  readRequest.timestamps_to_return() = TimestampsToReturn::Neither;
  readRequest.nodes_to_read().resize(nodeCount);
  for (size_t i = 0; i < nodeCount; ++i)
  {
    readRequest.nodes_to_read()[i].node_id() = ids[i];
    readRequest.nodes_to_read()[i].attribute_id() = utils::to_underlying(AttributeId::NodeId);
  }

  std::promise<void> done;
  ReadResponse result;
  std::vector<LocaleId> locales{"en"};
  ns->reset_counts();
  auto service = AttributeServiceSet::create(sessionInfo,
    locales,
    0,
    std::move(readRequest),
    executor,
    [&done, &result](Response response)
    {
      if (auto* readResponse = dynamic_cast<ReadResponse*>(response.second.get()))
        result = std::move(*readResponse);
      done.set_value();
    });

  ASSERT_EQ(done.get_future().wait_for(2s), std::future_status::ready);

  EXPECT_EQ(ns->find_nodes_calls(), 0u)
    << "a namespace that answered every id has nothing left to be asked asynchronously about";
  EXPECT_GE(ns->find_node_calls(), nodeCount)
    << "and every id was put to it through the synchronous interface";

  // Identical answers to the declining case above: the fast lane is an optimisation, not a
  // behaviour. Each result carries its OWN node's id, so the reassembly is still ordering-correct.
  ASSERT_EQ(result.results().size(), nodeCount);
  for (size_t i = 0; i < nodeCount; ++i)
  {
    const auto& dv = result.results()[i];
    if (dv.status().has_value())
      EXPECT_TRUE(dv.status()->is_good());
    EXPECT_EQ(dv.value().as<NodeId>(), ids[i]);
  }

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

TEST(BatchResolveTests, ARequestSpanningBothKindsOfNamespaceSplitsAndReassemblesInOrder)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();

  auto server = make_server(executor);
  auto fast = make_shared<AnsweringNamespace>("uri://batch-resolve-mixed-fast", executor);
  auto slow = make_shared<ResolveCountingNamespace>("uri://batch-resolve-mixed-slow", executor);
  const uint16_t fastIndex = server.address_space().add_namespace_sync(fast);
  const uint16_t slowIndex = server.address_space().add_namespace_sync(slow);

  // Interleaved deliberately: the two namespaces are resolved by different routes and their results
  // have to land back in REQUEST order, not in route order.
  constexpr size_t nodeCount = 6;
  std::vector<NodeId> ids;
  ids.reserve(nodeCount);
  for (size_t i = 0; i < nodeCount; ++i)
  {
    const uint16_t nsIndex = (i % 2 == 0) ? fastIndex : slowIndex;
    NodeId id{nsIndex, static_cast<uint32_t>(5000 + i)};
    if (i % 2 == 0)
      fast->create_node(id, NodeClass::Object);
    else
      slow->create_node(id, NodeClass::Object);
    ids.push_back(id);
  }

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), executor);

  ReadRequest readRequest;
  readRequest.timestamps_to_return() = TimestampsToReturn::Neither;
  readRequest.nodes_to_read().resize(nodeCount);
  for (size_t i = 0; i < nodeCount; ++i)
  {
    readRequest.nodes_to_read()[i].node_id() = ids[i];
    readRequest.nodes_to_read()[i].attribute_id() = utils::to_underlying(AttributeId::NodeId);
  }

  std::promise<void> done;
  ReadResponse result;
  std::vector<LocaleId> locales{"en"};
  fast->reset_counts();
  slow->reset_counts();
  auto service = AttributeServiceSet::create(sessionInfo,
    locales,
    0,
    std::move(readRequest),
    executor,
    [&done, &result](Response response)
    {
      if (auto* readResponse = dynamic_cast<ReadResponse*>(response.second.get()))
        result = std::move(*readResponse);
      done.set_value();
    });

  ASSERT_EQ(done.get_future().wait_for(2s), std::future_status::ready);

  EXPECT_EQ(fast->find_nodes_calls(), 0u) << "the answering namespace was never asked asynchronously";
  EXPECT_EQ(slow->find_nodes_calls(), 1u) << "the declining one was asked exactly once, in a batch";
  EXPECT_EQ(slow->last_batch_size(), nodeCount / 2)
    << "and that batch carried only its own ids - not the ones already answered";

  ASSERT_EQ(result.results().size(), nodeCount);
  for (size_t i = 0; i < nodeCount; ++i)
  {
    const auto& dv = result.results()[i];
    if (dv.status().has_value())
      EXPECT_TRUE(dv.status()->is_good());
    EXPECT_EQ(dv.value().as<NodeId>(), ids[i]) << "result " << i << " landed on the wrong node";
  }

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}
