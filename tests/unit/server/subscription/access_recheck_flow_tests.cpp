// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// How a Subscription's access recheck calls the namespace that owns its items' Nodes (NR-23): the
// re-authorization an identity change starts, and the periodic recheck, each look every item's Node up with
// one call per namespace and authorize every item found with one permission call per namespace, whatever the
// number of items; and each item is then allowed or denied as before.
//
// The Subscription is driven as the pipeline drives it, through its asynchronous entries, on a Server's
// address space. Its items' Nodes are held by a recording in-memory namespace that, from the recheck on,
// declines its immediate lookups and permissions, so that every lookup and permission question of the recheck
// reaches the batched members, where it is counted.

#include <gtest/gtest.h>

#include "create_flow_fixture.h"

#include "ua_permission_type.h"

#include <chrono>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <vector>

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;
using namespace ua::test::create_flow;

namespace
{

class AccessRecheckFlow : public MonitoringFlow
{
protected:
  /// One item's access, read on its Subscription's strand.
  struct ItemAccess
  {
    bool held{false};
    bool denied{false};
    /// The status of the item's last queued value; `nullopt` when its queue is empty.
    std::optional<StatusCode> lastQueued;
  };

  /// Four readable Int32 Variables of the namespace @p index, and a Value item on each, created on @p target
  /// for the Session, each allowed. Returns the Variables; @p monitoredItemIds receives the items' ids in the
  /// same order.
  std::vector<NodeId> monitor_four(
    uint16_t index, Subscription& target, std::vector<IntegerId>& monitoredItemIds)
  {
    std::vector<NodeId> variables;
    std::vector<MonitoredItemCreateRequest> items;
    for (uint32_t i = 0; i < 4; ++i)
    {
      variables.push_back(
        create_variable(NodeId{index, 100 + i}, NodeId{DataTypeId::Int32}, DataValue{Variant{int32_t{0}}}));
      items.push_back(value_item(variables.back(), 1 + i));
    }
    const auto results = create(target, std::move(items), mSecurity);
    for (std::size_t i = 0; i < results.size(); ++i)
    {
      EXPECT_EQ(results[i].status_code().as_status(), Status::Good)
        << "row " << i + 1 << ": " << to_string(results[i].status_code());
      monitoredItemIds.push_back(results[i].monitored_item_id());
    }
    const auto access = access_of(target, monitoredItemIds);
    for (std::size_t i = 0; i < access.size(); ++i)
    {
      EXPECT_TRUE(access[i].held && !access[i].denied) << "item " << i + 1 << " was not created allowed";
    }
    return variables;
  }

  static std::vector<ItemAccess> access_of(
    Subscription& target, const std::vector<IntegerId>& monitoredItemIds)
  {
    return STA::on_strand(target,
      [&monitoredItemIds](auto& guard)
      {
        std::vector<ItemAccess> access;
        for (const IntegerId monitoredItemId : monitoredItemIds)
        {
          const auto* item = guard.find_monitored_item(monitoredItemId);
          if (item == nullptr)
          {
            access.push_back(ItemAccess{});
            continue;
          }
          std::optional<StatusCode> lastQueued;
          if (!item->queue.empty())
          {
            lastQueued = item->queue.back().status().value_or(StatusCode{Status::Good});
          }
          access.push_back(
            ItemAccess{.held = true, .denied = item->access_denied(), .lastQueued = lastQueued});
        }
        return access;
      });
  }

  /// Expects the item @p access describes to be held and allowed.
  static void expect_allowed(const ItemAccess& access, const std::string& item)
  {
    EXPECT_TRUE(access.held) << item << " is gone";
    EXPECT_FALSE(access.denied) << item << " was denied";
  }

  /// Expects the item @p access describes to be held, denied, and to have queued a value of status @p status.
  static void expect_denied(const ItemAccess& access, Status status, const std::string& item)
  {
    EXPECT_TRUE(access.held) << item << " is gone";
    EXPECT_TRUE(access.denied) << item << " was not denied";
    ASSERT_TRUE(access.lastQueued.has_value()) << item << " queued no value";
    EXPECT_EQ(access.lastQueued->as_status(), status) << item << ": " << to_string(*access.lastQueued);
  }
};

}  // namespace

// NR-23 rules 2 and 3 for the re-authorization an identity change starts
// (Subscription::reauthorize_all_async): four items on one namespace are looked up in one batched call naming
// all four and authorized in one effective_permissions_async naming all four, not one call of each per item.
// The control is the items' outcomes, which the batching must not change: the item whose Read permission the
// namespace no longer grants is denied with Bad_UserAccessDenied queued, the other three stay allowed, and
// the re-authorization answers Good.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-13-AN-ACCESS-RECHECK-ASKS-EACH-NAMESPACE-ONCE-PER-STEP, scope=function)
TEST_F(AccessRecheckFlow, AReauthorizationAsksTheNamespaceOncePerStepForAllItsItems)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  auto sub = subscription(1);
  std::vector<IntegerId> monitoredItemIds;
  const auto variables = monitor_four(index, *sub, monitoredItemIds);
  ASSERT_EQ(monitoredItemIds.size(), 4u);
  sub->configure_access_recheck(1h, mSecurity, mAddressSpace->weak(), {});
  strand_barrier(*sub);
  measure(n);
  n.grant(variables[2], PermissionType{PermissionType::Bit::Browse});

  auto answered = std::make_shared<std::promise<VoidResult>>();
  auto future = answered->get_future();
  sub->reauthorize_all_async([answered](VoidResult result) { answered->set_value(std::move(result)); });
  ASSERT_EQ(future.wait_for(5s), std::future_status::ready) << "the re-authorization did not answer";
  const auto result = future.get();
  EXPECT_TRUE(result.is_good()) << to_string(result.status_code());

  const auto calls = n.calls();
  const auto lookups = naming(calls, is_batched_lookup, variables);
  EXPECT_EQ(lookups.size(), 1u) << "batched lookup calls naming the four Variables" << describe(calls);
  if (lookups.size() == 1u)
  {
    EXPECT_EQ(sorted(lookups[0].nodeIds), sorted(variables)) << describe(calls);
  }
  const auto permissions = naming(calls, is_permission_call, variables);
  EXPECT_EQ(permissions.size(), 1u) << "effective_permissions_async calls naming the four Variables"
                                    << describe(calls);
  if (permissions.size() == 1u)
  {
    EXPECT_EQ(sorted(permissions[0].nodeIds), sorted(variables)) << describe(calls);
  }

  const auto access = access_of(*sub, monitoredItemIds);
  ASSERT_EQ(access.size(), 4u);
  expect_allowed(access[0], "item 1");
  expect_allowed(access[1], "item 2");
  expect_denied(access[2], Status::BadUserAccessDenied, "item 3, whose Read permission was withdrawn");
  expect_allowed(access[3], "item 4");
}

// NR-23 rules 2 and 3 for the periodic recheck (Subscription::run_access_recheck): four items on one
// namespace are looked up together, the three the immediate lookup does not answer in one batched call, and
// the three found are authorized in one effective_permissions_async naming those three, not one call of each
// per item. The control is the items' outcomes, which the batching must not change: the item whose lookup the
// namespace answers Bad_NodeIdUnknown is denied with that status queued and does not stop the cycle; the item
// whose Read permission is withdrawn is denied with Bad_UserAccessDenied queued; the other two stay allowed.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-13-AN-ACCESS-RECHECK-ASKS-EACH-NAMESPACE-ONCE-PER-STEP, scope=function)
TEST_F(AccessRecheckFlow, APeriodicRecheckAsksTheNamespaceOncePerStepForAllItsItems)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  auto sub = subscription(1);
  std::vector<IntegerId> monitoredItemIds;
  const auto variables = monitor_four(index, *sub, monitoredItemIds);
  ASSERT_EQ(monitoredItemIds.size(), 4u);
  sub->configure_access_recheck(1h, mSecurity, mAddressSpace->weak(), {});
  strand_barrier(*sub);
  measure(n);
  n.answer_lookup_of(variables[1], StatusCode{Status::BadNodeIdUnknown});
  n.grant(variables[2], PermissionType{PermissionType::Bit::Browse});

  auto finished = std::make_shared<std::promise<void>>();
  auto future = finished->get_future();
  STA::on_strand(
    *sub, [finished](auto& guard) { guard.run_access_recheck([finished] { finished->set_value(); }); });
  ASSERT_EQ(future.wait_for(5s), std::future_status::ready) << "the periodic recheck did not finish";

  // The scripted Bad_NodeIdUnknown is answered by the immediate lookup, so the batched one names the other
  // three.
  const auto calls = n.calls();
  const std::vector<NodeId> found{variables[0], variables[2], variables[3]};
  const auto lookups = naming(calls, is_batched_lookup, variables);
  EXPECT_EQ(lookups.size(), 1u) << "batched lookup calls naming the Variables" << describe(calls);
  if (lookups.size() == 1u)
  {
    EXPECT_EQ(sorted(lookups[0].nodeIds), sorted(found)) << describe(calls);
  }
  const auto permissions = naming(calls, is_permission_call, variables);
  EXPECT_EQ(permissions.size(), 1u) << "effective_permissions_async calls naming the Variables"
                                    << describe(calls);
  if (permissions.size() == 1u)
  {
    EXPECT_EQ(sorted(permissions[0].nodeIds), sorted(found)) << describe(calls);
  }

  const auto access = access_of(*sub, monitoredItemIds);
  ASSERT_EQ(access.size(), 4u);
  expect_allowed(access[0], "item 1");
  expect_denied(access[1], Status::BadNodeIdUnknown, "item 2, whose lookup was answered Bad_NodeIdUnknown");
  expect_denied(access[2], Status::BadUserAccessDenied, "item 3, whose Read permission was withdrawn");
  expect_allowed(access[3], "item 4");
}
