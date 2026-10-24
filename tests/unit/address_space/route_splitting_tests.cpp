// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The route splits a namespace's part of a lookup by the service operation limits
/// (COMP-ADDRSP-NAMESPACE-ROUTE-03).
///
/// The stub namespace declines the single-Node fast path, so every lookup takes the batched path, and it
/// records the size of each batched call it receives.

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

#include "test_components.h"
#include "test_utilities.h"
#include "ua_address_space.h"
#include "ua_default_namespace.h"
#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"
#include "ua_namespace.h"
#include "ua_namespace_context.h"
#include "ua_node_accessor.h"
#include "ua_server.h"
#include "ua_server_configuration.h"
#include "ua_service_operation_limits.h"
#include <boost/asio/thread_pool.hpp>

using namespace ua;
using namespace std::chrono_literals;

namespace
{

/// Forwards to a default namespace, records every batched lookup call, and holds each call until the
/// test releases it when asked to.
class SplitRecordingNamespace final : public Namespace
{
public:
  explicit SplitRecordingNamespace(std::shared_ptr<default_ns::Namespace> inner) : mInner(std::move(inner))
  {}

  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
  {
    callback(VoidResult{});
  }

  String uri() const override
  {
    return mInner->uri();
  }

  void create_nodes_async(const RequestInfo& request, std::span<const NodeCreation> nodes,
    std::function<void(BatchResult<NodeResult>)> complete) override
  {
    mInner->create_nodes_async(request, nodes, std::move(complete));
  }

  void read_references_async(const RequestInfo& request, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    mInner->read_references_async(request, queries, std::move(complete));
  }

  void read_values_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
    std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    mInner->read_values_async(request, caller, items, maxAge, setSourceTimestamp, std::move(complete));
  }

  // No synchronous find_node: every lookup takes the batched path.
  void find_nodes_async(const RequestInfo& /*request*/, std::span<const NodeId> nodeIds,
    std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> callback) override
  {
    std::vector<NodeId> ids(nodeIds.begin(), nodeIds.end());
    {
      const std::lock_guard lock(mMutex);
      if (mUnanswered != 0)
      {
        mStartedWhileUnanswered = true;
      }
      ++mUnanswered;
      mCalls.push_back(ids);
      if (hold)
      {
        mHeld.push_back(HeldCall{std::move(ids), maxAge, std::move(callback)});
      }
    }
    mChanged.notify_all();
    if (!hold)
    {
      answer(nodeIds, maxAge, std::move(callback));
    }
  }

  bool wait_for_held(std::chrono::milliseconds bound)
  {
    std::unique_lock lock(mMutex);
    return mChanged.wait_for(lock, bound, [this] { return !mHeld.empty(); });
  }

  /// Answers the oldest held call, outside the lock.
  void release_one()
  {
    std::optional<HeldCall> call;
    {
      const std::lock_guard lock(mMutex);
      if (mHeld.empty())
      {
        return;
      }
      call = std::move(mHeld.front());
      mHeld.erase(mHeld.begin());
    }
    answer(call->nodeIds, call->maxAge, std::move(call->callback));
  }

  std::vector<std::vector<NodeId>> calls() const
  {
    const std::lock_guard lock(mMutex);
    return mCalls;
  }

  std::vector<std::size_t> call_sizes() const
  {
    std::vector<std::size_t> sizes;
    for (const auto& call : calls())
    {
      sizes.push_back(call.size());
    }
    return sizes;
  }

  bool started_while_unanswered() const
  {
    const std::lock_guard lock(mMutex);
    return mStartedWhileUnanswered;
  }

  std::atomic<bool> hold{false};

private:
  struct HeldCall
  {
    std::vector<NodeId> nodeIds;
    std::optional<Duration> maxAge;
    std::function<void(BatchResult<NodeResult>)> callback;
  };

  // A namespace that forwards passes its context on (NR-39).
  VoidResult on_attached(const NamespaceContext& context) override
  {
    return mInner->attach(context);
  }

  void answer(std::span<const NodeId> nodeIds, std::optional<Duration> maxAge,
    std::function<void(BatchResult<NodeResult>)> callback)
  {
    mInner->find_nodes_async(RequestInfo{},
      nodeIds,
      maxAge,
      [this, callback = std::move(callback)](BatchResult<NodeResult> result) mutable
      {
        {
          const std::lock_guard lock(mMutex);
          --mUnanswered;
        }
        callback(std::move(result));
      });
  }

  std::shared_ptr<default_ns::Namespace> mInner;
  mutable std::mutex mMutex;
  std::condition_variable mChanged;
  std::vector<std::vector<NodeId>> mCalls;
  std::vector<HeldCall> mHeld;
  std::size_t mUnanswered{0};
  bool mStartedWhileUnanswered{false};
};

/// One lookup's completion: how often it ran, and what it answered first.
struct Completion
{
  std::atomic<int> calls{0};
  std::promise<BatchResult<NodeAccessorResult>> first;
  std::future<BatchResult<NodeAccessorResult>> answered{first.get_future()};
};

AddressSpace::FindNodesCompleteCallback record(const std::shared_ptr<Completion>& completion)
{
  return [completion](BatchResult<NodeAccessorResult> result)
  {
    if (completion->calls.fetch_add(1) == 0)
    {
      completion->first.set_value(std::move(result));
    }
  };
}

/// Registers a recording namespace with @p addressSpace and creates five Objects in it through the address
/// space; returns their NodeIds in creation order.
std::vector<NodeId> register_with_five_nodes(
  AddressSpace& addressSpace, const std::shared_ptr<SplitRecordingNamespace>& space)
{
  const auto index = addressSpace.add_namespace_sync(space);
  std::vector<NodeId> ids;
  for (uint32_t i = 1; i <= 5; ++i)
  {
    const NodeId id{index, i};
    EXPECT_TRUE(addressSpace.try_create_node_sync(id, NodeClass::Object, {}).is_good()) << "Node " << i;
    ids.push_back(id);
  }
  return ids;
}

void expect_every_node_in_order(
  const BatchResult<NodeAccessorResult>& result, const std::vector<NodeId>& asked)
{
  ASSERT_EQ(result.items.size(), asked.size());
  for (std::size_t i = 0; i < asked.size(); ++i)
  {
    ASSERT_TRUE(result.items[i].is_good()) << "item " << i;
    EXPECT_EQ(result.items[i].value().get_node_id(), asked[i]) << "item " << i;
  }
}

BatchResult<NodeAccessorResult> look_up(AddressSpace& addressSpace, const std::vector<NodeId>& ids)
{
  auto completion = std::make_shared<Completion>();
  addressSpace.find_nodes_async(ids, record(completion));
  EXPECT_EQ(completion->answered.wait_for(5s), std::future_status::ready);
  return completion->answered.get();
}

bool context_names_field(const StatusCode& status, std::string_view field)
{
  const auto detail = status.shared_detail();
  return detail != nullptr && std::any_of(detail->context.begin(),
                                detail->context.end(),
                                [field](const NamedValue& entry) {
                                  return entry.key == ContextKeys::fieldName.value() && entry.value == field;
                                });
}

}  // namespace

// @relation(AC-COMP-ADDRSP-NAMESPACE-ROUTE-03-A-BATCH-ABOVE-THE-LIMIT-IS-SENT-AS-CONSECUTIVE-CALLS, scope=function)
TEST(RouteSplitting, ABatchAboveTheLimitIsSentAsConsecutiveCalls)
{
  boost::asio::thread_pool pool{2};
  auto completion = std::make_shared<Completion>();
  std::vector<NodeId> ids;
  std::shared_ptr<SplitRecordingNamespace> space;
  {
    auto addressSpace = AddressSpace::create("urn:test:route-splitting", pool.get_executor());
    space = std::make_shared<SplitRecordingNamespace>(
      default_ns::Namespace::create("urn:test:route-splitting-ns", pool.get_executor()));
    ids = register_with_five_nodes(addressSpace, space);
    ServiceOperationLimits limits;
    limits.maxNodesPerRead = 2;
    addressSpace.set_operation_limits(limits);
    space->hold = true;

    addressSpace.find_nodes_async(ids, record(completion));
    for (int round = 0; round < 8 && completion->answered.wait_for(0s) != std::future_status::ready; ++round)
    {
      if (space->wait_for_held(500ms))
      {
        space->release_one();
      }
    }
    ASSERT_EQ(completion->answered.wait_for(5s), std::future_status::ready);
  }
  ::ua::test_utils::drain_with_timeout(pool);

  const auto calls = space->calls();
  EXPECT_EQ(space->call_sizes(), (std::vector<std::size_t>{2, 2, 1}));
  if (calls.size() == 3)
  {
    EXPECT_EQ(calls[0], (std::vector<NodeId>{ids[0], ids[1]}));
    EXPECT_EQ(calls[1], (std::vector<NodeId>{ids[2], ids[3]}));
    EXPECT_EQ(calls[2], (std::vector<NodeId>{ids[4]}));
  }
  EXPECT_FALSE(space->started_while_unanswered()) << "a call started while an earlier one was unanswered";
  EXPECT_EQ(completion->calls.load(), 1);
  expect_every_node_in_order(completion->answered.get(), ids);
}

// @relation(AC-COMP-ADDRSP-NAMESPACE-ROUTE-03-AN-UNSET-LIMIT-DOES-NOT-SPLIT, scope=function)
TEST(RouteSplitting, AnUnsetLimitDoesNotSplit)
{
  boost::asio::thread_pool pool{2};
  {
    auto addressSpace = AddressSpace::create("urn:test:route-unsplit", pool.get_executor());
    auto space = std::make_shared<SplitRecordingNamespace>(
      default_ns::Namespace::create("urn:test:route-unsplit-ns", pool.get_executor()));
    const auto ids = register_with_five_nodes(addressSpace, space);

    // Never set: an address space used without a server does not split.
    expect_every_node_in_order(look_up(addressSpace, ids), ids);
    EXPECT_EQ(space->call_sizes(), (std::vector<std::size_t>{5}));

    ServiceOperationLimits limits;
    limits.maxNodesPerRead = std::nullopt;
    addressSpace.set_operation_limits(limits);
    expect_every_node_in_order(look_up(addressSpace, ids), ids);
    EXPECT_EQ(space->call_sizes(), (std::vector<std::size_t>{5, 5}));
  }
  ::ua::test_utils::drain_with_timeout(pool);
}

// @relation(AC-COMP-ADDRSP-NAMESPACE-ROUTE-03-A-ZERO-LIMIT-IS-REFUSED, scope=function)
TEST(RouteSplitting, AZeroLimitIsRefused)
{
  boost::asio::thread_pool pool{2};
  std::shared_ptr<SplitRecordingNamespace> space;
  {
    auto addressSpace = AddressSpace::create("urn:test:route-zero-limit", pool.get_executor());
    space = std::make_shared<SplitRecordingNamespace>(
      default_ns::Namespace::create("urn:test:route-zero-limit-ns", pool.get_executor()));
    const auto ids = register_with_five_nodes(addressSpace, space);
    ServiceOperationLimits inForce;
    inForce.maxNodesPerRead = 2;
    addressSpace.set_operation_limits(inForce);

    ServiceOperationLimits zero;
    zero.maxMonitoredItemsPerCall = 0;
    std::optional<StatusCode> refusal;
    try
    {
      addressSpace.set_operation_limits(zero);
    }
    catch (const UaException& e)
    {
      refusal = e.status_code();
    }
    EXPECT_TRUE(refusal.has_value()) << "set_operation_limits accepted maxMonitoredItemsPerCall 0";
    if (refusal)
    {
      EXPECT_EQ(refusal->as_status(), Status::BadInvalidArgument);
      ASSERT_NE(refusal->shared_detail(), nullptr);
      EXPECT_EQ(refusal->shared_detail()->code, "OperationLimitZero");
      EXPECT_TRUE(context_names_field(*refusal, "maxMonitoredItemsPerCall"));
    }

    expect_every_node_in_order(look_up(addressSpace, ids), ids);
  }
  ::ua::test_utils::drain_with_timeout(pool);

  EXPECT_EQ(space->call_sizes(), (std::vector<std::size_t>{2, 2, 1}))
    << "the limits set first are not in force";
}

// @relation(AC-COMP-ADDRSP-NAMESPACE-ROUTE-03-THE-SERVER-PASSES-ITS-OPERATION-LIMITS, scope=function)
TEST(RouteSplitting, TheServerPassesItsOperationLimits)
{
  boost::asio::thread_pool pool{2};
  std::shared_ptr<SplitRecordingNamespace> space;
  {
    server::ServerConfig serverConfig;
    serverConfig.server_capabilities().operationLimits.maxNodesPerRead = 2;
    server::CreateConfig config{.identity = ApplicationIdentity::load_default(),
      .application = test_utils::create_test_config(),
      .server = std::move(serverConfig)};
    auto uaServer = server::Server::create(pool.get_executor(),
      std::move(config),
      server::ServerComponents{.crypto = ::ua::test_helpers::test_crypto()});
    auto addressSpace = uaServer.address_space();
    space = std::make_shared<SplitRecordingNamespace>(
      default_ns::Namespace::create("urn:test:route-server-limits-ns", pool.get_executor()));
    const auto ids = register_with_five_nodes(addressSpace, space);

    expect_every_node_in_order(look_up(addressSpace, ids), ids);
  }
  ::ua::test_utils::drain_with_timeout(pool);

  const auto sizes = space->call_sizes();
  std::size_t total = 0;
  for (const auto size : sizes)
  {
    EXPECT_LE(size, 2u) << "a call carried more Nodes than maxNodesPerRead";
    total += size;
  }
  EXPECT_EQ(total, 5u);
}

// @relation(AC-COMP-ADDRSP-NAMESPACE-ROUTE-03-THE-SERVER-CONFIGURATION-TYPE-IS-THE-CORE-TYPE, scope=function)
TEST(ServiceOperationLimitsType, TheServerConfigurationTypeIsTheCoreType)
{
  EXPECT_TRUE((std::is_same_v<server::ServerConfig::OperationLimits, ServiceOperationLimits>));

  const ServiceOperationLimits limits{};
  EXPECT_EQ(limits.maxNodesPerRead, std::optional<uint32_t>{1000});
  EXPECT_EQ(limits.maxNodesPerHistoryReadData, std::optional<uint32_t>{100});
  EXPECT_EQ(limits.maxNodesPerHistoryReadEvents, std::optional<uint32_t>{100});
  EXPECT_EQ(limits.maxNodesPerWrite, std::optional<uint32_t>{1000});
  EXPECT_EQ(limits.maxNodesPerHistoryUpdateData, std::optional<uint32_t>{100});
  EXPECT_EQ(limits.maxNodesPerHistoryUpdateEvents, std::optional<uint32_t>{100});
  EXPECT_EQ(limits.maxNodesPerMethodCall, std::optional<uint32_t>{100});
  EXPECT_EQ(limits.maxNodesPerBrowse, std::optional<uint32_t>{1000});
  EXPECT_EQ(limits.maxNodesPerRegisterNodes, std::optional<uint32_t>{1000});
  EXPECT_EQ(limits.maxNodesPerTranslateBrowsePathsToNodeIds, std::optional<uint32_t>{1000});
  EXPECT_EQ(limits.maxNodesPerNodeManagement, std::optional<uint32_t>{100});
  EXPECT_EQ(limits.maxMonitoredItemsPerCall, std::optional<uint32_t>{1000});
}
