// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// COMP-SVR-NAMESPACE-CALLS-17 rule 1: before a namespace that implements no monitoring is registered, the
// base Namespace's create_monitoring_async answers Bad_NotSupported per item and registers nothing (NR-47).

#include <gtest/gtest.h>

#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_described_nodes.h"
#include "ua_integer_id.h"
#include "ua_namespace.h"
#include "ua_namespace_items.h"
#include "ua_namespace_monitoring.h"
#include "ua_namespace_monitoring_support_access.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_node_description.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_request_info.h"
#include "ua_sinks.h"
#include "ua_status.h"
#include "ua_to_string.h"
#include "ua_variant.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <limits>
#include <memory>
#include <set>
#include <span>
#include <utility>
#include <vector>

using namespace ua;
using namespace std::chrono_literals;

namespace
{

/// A namespace that implements no monitoring: it answers lookups from a DescribedNodes store and the Values
/// of its Variables from a field, and overrides none of the monitoring members.
class FieldNamespace final : public Namespace
{
public:
  String uri() const override
  {
    return String{"urn:test:default-monitoring:unregistered"};
  }

  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
  {
    if (callback)
    {
      callback(VoidResult{});
    }
  }

  void find_nodes_async(const RequestInfo&, std::span<const NodeId> nodeIds, std::optional<Duration>,
    std::function<void(BatchResult<NodeResult>)> callback) override
  {
    resolve_each(nodeIds,
      std::move(callback),
      [this](const NodeId& nodeId, std::function<void(NodeResult)> one)
      { one(NodeResult{variable(nodeId)}); });
  }

  void read_references_async(const RequestInfo&, std::span<const ReferenceQuery>,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    complete(BatchResult<NodeReferencesResult>{VoidResult{StatusCode{Status::BadNotSupported}}, {}});
  }

  void read_values_async(const RequestInfo&, const CallerInfo*, std::span<const ValueReadItem> items,
    Duration, bool, std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    BatchResult<DataValueResult> answer;
    for (std::size_t i = 0; i < items.size(); ++i)
    {
      DataValue value;
      value.value() = Variant{mField.load()};
      value.status() = StatusCode{Status::Good};
      answer.items.emplace_back(std::move(value));
    }
    complete(std::move(answer));
  }

  /// The Node of the Variable @p nodeId, as this namespace's lookup answers it.
  shared_ptr<Node> variable(const NodeId& nodeId)
  {
    return mStore.node_for(NodeDescription::variable(
      nodeId, QualifiedName{nodeId.namespace_index(), "Field"}, NodeId{DataTypeId::Int32}));
  }

private:
  DescribedNodes mStore;
  std::atomic<int32_t> mField{1};
};

/// A subscription's sink as the monitoring members are given it; it records nothing, since a namespace that
/// registers an item keeps its sink (MonitoringCreateItem::sink).
class IdleSampleSink final : public SampleSink
{
public:
  void push(std::vector<std::pair<IntegerId, DataValue>>) override
  {}

  void invalidate(IntegerId, StatusCode) override
  {}

  void detach() override
  {}
};

}  // namespace

// The criterion's namespace is constructed and never registered; two Value items, each carrying the Node this
// namespace's lookup answers and the subscription's sink, as CreateMonitoredItems builds them. "Registered
// anywhere" is observed through the sink: a registration holds its sink for its lifetime, so after the call
// the sink is held by this test and the two items only.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-17-BEFORE-REGISTRATION-EACH-ITEM-IS-BAD-NOT-SUPPORTED, scope=function)
TEST(DefaultMonitoring, BeforeRegistrationEachItemIsBadNotSupported)
{
  auto nameSpace = std::make_shared<FieldNamespace>();
  auto sink = std::make_shared<IdleSampleSink>();
  std::vector<MonitoringCreateItem> items(2);
  for (uint32_t i = 0; i < items.size(); ++i)
  {
    items[i].nodeId = NodeId{2, i + 1};
    items[i].node = nameSpace->variable(items[i].nodeId);
    items[i].attributeId = AttributeId::Value;
    items[i].monitoredItemId = IntegerId{i + 1};
    items[i].samplingInterval = Duration{100};
    items[i].queueSize = 1;
    items[i].sink = sink;
  }
  const auto heldBefore = sink.use_count();

  std::promise<BatchResult<MonitoringCreateItemResult>> answered;
  auto answer = answered.get_future();
  nameSpace->create_monitoring_async(RequestInfo{},
    nullptr,
    std::span<const MonitoringCreateItem>{items},
    [promise = std::make_shared<std::promise<BatchResult<MonitoringCreateItemResult>>>(std::move(answered))](
      BatchResult<MonitoringCreateItemResult> result) { promise->set_value(std::move(result)); });
  ASSERT_EQ(answer.wait_for(5s), std::future_status::ready) << "create_monitoring_async never answered";
  const auto results = answer.get();

  ASSERT_TRUE(results.batchStatus.is_good()) << to_string(results.batchStatus.status_code());
  ASSERT_EQ(results.items.size(), 2u);
  for (const auto& result : results.items)
  {
    EXPECT_EQ(result.status_code().as_status(), Status::BadNotSupported) << to_string(result.status_code());
  }
  EXPECT_EQ(sink.use_count(), heldBefore) << "an item was registered: something still holds the sink";
}

// The in-memory namespace's monitoring helper issues its handles through issue_handle: a counter that wraps
// issues neither 0 nor the handle of a registration that still exists.
TEST(MonitoringHandleIssue, AWrappedCounterSkipsZeroAndEveryHandleInUse)
{
  const std::set<MonitoringHandle> inUse{1, 2};
  const auto held = [&inUse](MonitoringHandle candidate)
  {
    return inUse.contains(candidate);
  };
  MonitoringHandle next = std::numeric_limits<MonitoringHandle>::max();

  EXPECT_EQ(ua::detail::issue_handle(next, held), std::numeric_limits<MonitoringHandle>::max());
  EXPECT_EQ(next, 0u) << "the counter did not wrap";

  EXPECT_EQ(ua::detail::issue_handle(next, held), 3u) << "the wrapped counter issued 0 or a handle in use";
  EXPECT_EQ(next, 4u);
}

// The control: an unwrapped counter issues its next handle, or the first after it that is not in use.
TEST(MonitoringHandleIssue, ACounterIssuesItsNextHandleThatIsNotInUse)
{
  const std::set<MonitoringHandle> inUse{8};
  const auto held = [&inUse](MonitoringHandle candidate)
  {
    return inUse.contains(candidate);
  };
  MonitoringHandle next = 7;

  EXPECT_EQ(ua::detail::issue_handle(next, held), 7u);
  EXPECT_EQ(ua::detail::issue_handle(next, held), 9u);
  EXPECT_EQ(next, 10u);
}
