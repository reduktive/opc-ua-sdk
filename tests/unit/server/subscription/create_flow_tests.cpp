// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// How CreateMonitoredItems and ModifyMonitoredItems call the namespaces that own their Nodes
// (COMP-SVR-NAMESPACE-CALLS-13): one lookup, through the form that takes the request, and one permission
// call per namespace per request; a row whose lookup is not Good decides only that row; the DataTypes of
// AbsoluteDeadband items and the EURanges of PercentDeadband items are decided once per request; the initial
// Values are read in one call per namespace; a sample or a deletion notice pushed for an item before its
// create commits is delivered after its initial value; and a modify calls its namespaces at once.
//
// The Subscription is driven as the pipeline drives it, through its asynchronous entries, on a Server's
// address space (its namespace 0 is the standard model). Its items' Nodes are held by recording in-memory
// namespaces that decline their immediate lookups and permissions, so that every lookup and permission
// question reaches the batched members, where it is counted. Notifications are taken by fulfill_publish.

#include <gtest/gtest.h>

#include "create_flow_fixture.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;
using namespace ua::test::create_flow;

// COMP-SVR-NAMESPACE-CALLS-13 rule 1, NR-26: the items' Nodes are looked up once, through the form that takes
// the request, and authorized with one permission call.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-13-ONE-LOOKUP-AND-ONE-PERMISSION-CALL-PER-NAMESPACE, scope=function)
TEST_F(CreateFlow, OneLookupAndOnePermissionCallPerNamespacePerRequest)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  std::vector<NodeId> variables;
  std::vector<MonitoredItemCreateRequest> items;
  for (uint32_t i = 0; i < 5; ++i)
  {
    variables.push_back(
      create_variable(NodeId{index, 100 + i}, NodeId{DataTypeId::Int32}, DataValue{Variant{int32_t{0}}}));
    items.push_back(value_item(variables.back(), 1 + i));
  }
  measure(n);
  auto sub = subscription(1);

  const auto results = create(*sub, std::move(items), mSecurity);

  const auto calls = n.calls();
  const auto lookups = naming(calls, is_batched_lookup, variables);
  EXPECT_EQ(lookups.size(), 1u) << "batched lookup calls naming the five Variables" << describe(calls);
  if (lookups.size() == 1u)
  {
    EXPECT_TRUE(lookups[0].member == Member::BatchedLookup && lookups[0].hasRequest)
      << "the lookup was not made through the form that takes the request" << describe(calls);
    EXPECT_EQ(sorted(lookups[0].nodeIds), sorted(variables)) << describe(calls);
  }
  const auto permissions = naming(calls, is_permission_call, variables);
  EXPECT_EQ(permissions.size(), 1u) << "effective_permissions_async calls naming the five Variables"
                                    << describe(calls);
  if (permissions.size() == 1u)
  {
    EXPECT_EQ(sorted(permissions[0].nodeIds), sorted(variables)) << describe(calls);
  }
  ASSERT_EQ(results.size(), 5u);
  for (std::size_t i = 0; i < results.size(); ++i)
  {
    EXPECT_EQ(results[i].status_code().as_status(), Status::Good)
      << "row " << i + 1 << ": " << to_string(results[i].status_code());
  }
}

// COMP-SVR-NAMESPACE-CALLS-13 rule 1: the request's RequestInfo, with the deadline its timeoutHint gives,
// reaches the namespace's lookup and its create_monitoring_async. Hold the first lookup so later stages
// cannot begin until after the originating call has returned and its arrival interval is fixed.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-13-THE-REQUESTS-DEADLINE-REACHES-THE-NAMESPACES, scope=function)
TEST_F(CreateFlow, TheRequestsDeadlineReachesTheNamespaces)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  const NodeId variable =
    create_variable(NodeId{index, 100}, NodeId{DataTypeId::Int32}, DataValue{Variant{int32_t{0}}});
  measure(n);
  auto sub = subscription(1);

  n.hold_lookups_of({variable});
  auto pending = start_create(*sub, list_of(value_item(variable, 1)), mSecurity, 5000);
  const auto requestSubmittedBy = std::chrono::steady_clock::now();
  ASSERT_TRUE(n.wait_for_held_lookups(1, 3s));
  EXPECT_EQ(pending.wait_for(100ms), std::future_status::timeout);
  EXPECT_EQ(n.release_held_lookups(), 1u);
  finish_create(pending, 1);

  const auto calls = n.calls();
  const auto lookups = naming(calls, is_batched_lookup, {variable});
  const auto creates =
    naming(calls, [](const Call& call) { return is_member(call, Member::CreateMonitoring); }, {variable});
  ASSERT_FALSE(lookups.empty()) << "the Variable was not named by a batched lookup of N" << describe(calls);
  ASSERT_FALSE(creates.empty()) << "the item was not registered with N" << describe(calls);
  for (const auto& lookup : lookups)
  {
    EXPECT_TRUE(lookup.hasRequest) << "a lookup carried no RequestInfo" << describe(calls);
    EXPECT_LE(lookup.deadline, lookup.entered + 5000ms)
      << "a lookup's deadline is later than 5000 ms after the request arrived";
    EXPECT_LE(lookup.deadline, requestSubmittedBy + 5000ms)
      << "a lookup renewed the originating request's deadline";
  }
  for (const auto& registration : creates)
  {
    EXPECT_TRUE(registration.hasRequest)
      << "create_monitoring_async was not given the request" << describe(calls);
    EXPECT_LE(registration.deadline, registration.entered + 5000ms)
      << "create_monitoring_async's deadline is later than 5000 ms after the request arrived";
    EXPECT_LE(registration.deadline, requestSubmittedBy + 5000ms)
      << "create_monitoring_async renewed the originating request's deadline";
  }
}

// COMP-SVR-NAMESPACE-CALLS-13 rule 2, DL-69 (D2): an Uncertain lookup answer holds no Node, so its row is
// refused, and the other rows are answered as if it were absent.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-13-AN-UNCERTAIN-LOOKUP-ANSWER-REFUSES-ONLY-ITS-ROW, scope=function)
TEST_F(CreateFlow, AnUncertainLookupAnswerRefusesOnlyItsRow)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  std::vector<NodeId> variables;
  for (uint32_t i = 0; i < 3; ++i)
  {
    variables.push_back(
      create_variable(NodeId{index, 100 + i}, NodeId{DataTypeId::Int32}, DataValue{Variant{int32_t{0}}}));
  }
  measure(n);
  n.answer_lookup_of(variables[1], StatusCode{uncertainAnswer});
  auto sub = subscription(1);

  const auto results = create(*sub,
    list_of(value_item(variables[0], 1), value_item(variables[1], 2), value_item(variables[2], 3)),
    mSecurity);

  EXPECT_GE(times_named(n.calls(), is_lookup, variables[1]), 1u) << "the scripted answer was never used";
  ASSERT_EQ(results.size(), 3u);
  EXPECT_EQ(results[0].status_code().as_status(), Status::Good)
    << "row 1: " << to_string(results[0].status_code());
  expect_uncertain_lookup_refusal(results[1].status_code(), "row 2");
  EXPECT_EQ(results[2].status_code().as_status(), Status::Good)
    << "row 3: " << to_string(results[2].status_code());
  std::vector<uint32_t> answered{static_cast<uint32_t>(results[0].monitored_item_id()),
    static_cast<uint32_t>(results[2].monitored_item_id())};
  std::sort(answered.begin(), answered.end());
  EXPECT_EQ(items_held(*sub), answered) << "the subscription does not hold exactly rows 1 and 3's items";
}

// The same for a ModifyMonitoredItems of AbsoluteDeadband items, whose Variables' DataTypes are decided by a
// lookup.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-13-AN-UNCERTAIN-LOOKUP-ANSWER-REFUSES-ONLY-ITS-ROW, scope=function)
TEST_F(ModifyFlow, AnUncertainLookupAnswerRefusesOnlyItsRow)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  std::vector<NodeId> variables;
  std::vector<MonitoredItemCreateRequest> items;
  for (uint32_t i = 0; i < 3; ++i)
  {
    variables.push_back(
      create_variable(NodeId{index, 100 + i}, NodeId{DataTypeId::Double}, DataValue{Variant{0.0}}));
    items.push_back(value_item(variables.back(), 1 + i, 5, absolute_deadband(1.0)));
  }
  measure(n);
  auto sub = subscription(1);
  const auto created = create(*sub, std::move(items), mSecurity);
  ASSERT_EQ(created.size(), 3u);
  for (std::size_t i = 0; i < created.size(); ++i)
  {
    ASSERT_TRUE(created[i].status_code().is_good())
      << "item " << i + 1 << " was not created: " << to_string(created[i].status_code());
  }
  n.reset();
  n.answer_lookup_of(variables[1], StatusCode{uncertainAnswer});

  auto future = start_modify(*sub,
    list_of(modify_item(created[0].monitored_item_id(), 1, 5, absolute_deadband(1.0)),
      modify_item(created[1].monitored_item_id(), 2, 5, absolute_deadband(1.0)),
      modify_item(created[2].monitored_item_id(), 3, 5, absolute_deadband(1.0))));
  const auto results = finish_modify(future, 3);

  const auto calls = n.calls();
  EXPECT_GE(times_named(calls, is_lookup, variables[1]), 1u)
    << "the scripted answer was never used" << describe(calls);
  ASSERT_EQ(results.size(), 3u);
  EXPECT_EQ(results[0].status_code().as_status(), Status::Good)
    << "row 1: " << to_string(results[0].status_code());
  expect_uncertain_lookup_refusal(results[1].status_code(), "row 2");
  EXPECT_EQ(results[2].status_code().as_status(), Status::Good)
    << "row 3: " << to_string(results[2].status_code());
}

// COMP-SVR-NAMESPACE-CALLS-13 rule 2, Part 4 5.12.2.4 Table 71: a data item and an event item on NodeIds N
// does not hold are refused with the lookup's answer and never registered. N answers each lookup with an
// ErrorDetail of its own, so that the rows can be seen to carry it.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-13-AN-UNKNOWN-NODE-REFUSES-A-DATA-OR-EVENT-ITEM, scope=function)
TEST_F(CreateFlow, AnUnknownNodeRefusesADataOrEventItem)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  const NodeId unknownData{index, uint32_t{99999}};
  const NodeId unknownNotifier{index, uint32_t{99998}};
  const NodeId variable =
    create_variable(NodeId{index, 100}, NodeId{DataTypeId::Int32}, DataValue{Variant{int32_t{0}}});
  measure(n);
  n.answer_lookup_of(unknownData,
    StatusCode{Status::BadNodeIdUnknown,
      ErrorDetail::build("NoSuchDataNode", "N holds no Node with this NodeId", "CreateFlowTest")});
  n.answer_lookup_of(unknownNotifier,
    StatusCode{Status::BadNodeIdUnknown,
      ErrorDetail::build("NoSuchNotifierNode", "N holds no Node with this NodeId", "CreateFlowTest")});
  mEventBus = std::make_shared<EventBus>(*mAddressSpace);
  auto sub = subscription(1);

  const auto results = create(*sub,
    list_of(value_item(unknownData, 1), event_item(unknownNotifier, 2), value_item(variable, 3)),
    mSecurity,
    0,
    mEventBus);

  const auto calls = n.calls();
  EXPECT_GE(times_named(calls, is_lookup, unknownData), 1u) << "row 1's scripted answer was never used";
  EXPECT_GE(times_named(calls, is_lookup, unknownNotifier), 1u) << "row 2's scripted answer was never used";
  ASSERT_EQ(results.size(), 3u);
  EXPECT_EQ(results[0].status_code().as_status(), Status::BadNodeIdUnknown)
    << "row 1: " << to_string(results[0].status_code());
  EXPECT_EQ(detail_code(results[0].status_code()), "NoSuchDataNode")
    << "row 1 does not carry the lookup's ErrorDetail";
  EXPECT_EQ(results[1].status_code().as_status(), Status::BadNodeIdUnknown)
    << "row 2: " << to_string(results[1].status_code());
  EXPECT_EQ(detail_code(results[1].status_code()), "NoSuchNotifierNode")
    << "row 2 does not carry the lookup's ErrorDetail";
  EXPECT_EQ(results[2].status_code().as_status(), Status::Good)
    << "row 3: " << to_string(results[2].status_code());

  const auto creates = naming(calls,
    [](const Call& call) { return is_member(call, Member::CreateMonitoring); },
    {unknownData, unknownNotifier});
  EXPECT_TRUE(creates.empty()) << "N's create_monitoring_async named an item of row 1 or 2"
                               << describe(calls);

  auto registered = std::make_shared<std::promise<Result<bool>>>();
  auto answered = registered->get_future();
  mEventBus->has_event_items_async(
    sub->id(), [registered](Result<bool> result) { registered->set_value(std::move(result)); });
  ASSERT_EQ(answered.wait_for(5s), std::future_status::ready) << "the event bus did not answer";
  const auto hasEventItems = answered.get();
  ASSERT_TRUE(hasEventItems.is_good()) << to_string(hasEventItems.status_code());
  EXPECT_FALSE(hasEventItems.value()) << "an event item was registered with the event bus";
}

// COMP-SVR-NAMESPACE-CALLS-13 rule 2, Part 4 5.12.2.1: a lookup that fails for a reason other than an unknown
// Node refuses its row with the lookup's status and ErrorDetail, and the item is never registered; the other
// row is created.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-13-A-LOOKUP-FAILURE-OTHER-THAN-AN-UNKNOWN-NODE-REFUSES-ITS-ROW, scope=function)
TEST_F(CreateFlow, ALookupFailureOtherThanAnUnknownNodeRefusesItsRow)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  const NodeId unreachable =
    create_variable(NodeId{index, 100}, NodeId{DataTypeId::Int32}, DataValue{Variant{int32_t{7}}});
  const NodeId reachable =
    create_variable(NodeId{index, 101}, NodeId{DataTypeId::Int32}, DataValue{Variant{int32_t{8}}});
  measure(n);
  n.answer_lookup_of(unreachable,
    StatusCode{Status::BadCommunicationError,
      ErrorDetail::build("DeviceOffline", "The device holding the Node does not answer", "CreateFlowTest")});
  auto sub = subscription(1);

  const auto results = create(*sub, list_of(value_item(unreachable, 1), value_item(reachable, 2)), mSecurity);

  const auto calls = n.calls();
  EXPECT_GE(times_named(calls, is_lookup, unreachable), 1u) << "the scripted answer was never used";
  ASSERT_EQ(results.size(), 2u);
  EXPECT_EQ(results[0].status_code().as_status(), Status::BadCommunicationError)
    << "row 1: " << to_string(results[0].status_code());
  EXPECT_EQ(detail_code(results[0].status_code()), "DeviceOffline")
    << "row 1 does not carry the lookup's ErrorDetail";
  const auto creates =
    naming(calls, [](const Call& call) { return is_member(call, Member::CreateMonitoring); }, {unreachable});
  EXPECT_TRUE(creates.empty()) << "N's create_monitoring_async named row 1's item" << describe(calls);
  EXPECT_EQ(results[1].status_code().as_status(), Status::Good)
    << "row 2: " << to_string(results[1].status_code());
}

// COMP-SVR-SUBSCRIPTION-CREATE-MONITORED-ITEMS-01: a batch failure of the namespace's create_monitoring_async
// reaches every item it owns with its numeric status and the same ErrorDetail object, in one completion.
// @relation(AC-COMP-SVR-SUBSCRIPTION-CREATE-MONITORED-ITEMS-01-RICH-NAMESPACE-FAILURES, scope=function)
TEST_F(CreateFlow, ANamespacesBatchFailureReachesEveryItemUnchanged)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  const NodeId a =
    create_variable(NodeId{index, 100}, NodeId{DataTypeId::Int32}, DataValue{Variant{int32_t{1}}});
  const NodeId b =
    create_variable(NodeId{index, 101}, NodeId{DataTypeId::Int32}, DataValue{Variant{int32_t{2}}});
  const StatusCode sentinel{Status::BadCommunicationError,
    ErrorDetail::build(
      "CreateMonitoringBatchSentinel", "The namespace refused the monitoring batch", "CreateFlowTest")};
  const auto sentinelDetail = sentinel.shared_detail();
  ASSERT_NE(sentinelDetail, nullptr);
  measure(n);
  n.fail_create_monitoring(sentinel);
  auto sub = subscription(1);
  auto completions = std::make_shared<std::atomic_size_t>(0);

  auto future =
    start_create(*sub, list_of(value_item(a, 1), value_item(b, 2)), mSecurity, 0, {}, completions);
  const auto results = finish_create(future, 2);
  strand_barrier(*sub);

  const auto calls = n.calls();
  const auto creates =
    naming(calls, [](const Call& call) { return is_member(call, Member::CreateMonitoring); }, {a, b});
  ASSERT_EQ(creates.size(), 1u) << "N's create_monitoring_async was not asked about both items in one call"
                                << describe(calls);
  EXPECT_EQ(completions->load(), 1u) << "the create completed more than once";
  ASSERT_EQ(results.size(), 2u);
  for (std::size_t i = 0; i < results.size(); ++i)
  {
    EXPECT_EQ(results[i].status_code().as_status(), Status::BadCommunicationError)
      << "row " << i + 1 << ": " << to_string(results[i].status_code());
    EXPECT_EQ(results[i].status_code().shared_detail(), sentinelDetail)
      << "row " << i + 1 << " does not carry the namespace's ErrorDetail object";
  }
}

// COMP-SVR-SUBSCRIPTION-CREATE-MONITORED-ITEMS-01: an item failure of the namespace's create_monitoring_async
// reaches only its item, with its numeric status and the same ErrorDetail object; the neighbour is created.
// @relation(AC-COMP-SVR-SUBSCRIPTION-CREATE-MONITORED-ITEMS-01-RICH-NAMESPACE-FAILURES, scope=function)
TEST_F(CreateFlow, ANamespacesPerItemFailureReachesOnlyItsItem)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  const NodeId a =
    create_variable(NodeId{index, 100}, NodeId{DataTypeId::Int32}, DataValue{Variant{int32_t{1}}});
  const NodeId b =
    create_variable(NodeId{index, 101}, NodeId{DataTypeId::Int32}, DataValue{Variant{int32_t{2}}});
  const StatusCode sentinel{Status::BadCommunicationError,
    ErrorDetail::build(
      "CreateMonitoringItemSentinel", "The namespace refused one monitoring item", "CreateFlowTest")};
  const auto sentinelDetail = sentinel.shared_detail();
  ASSERT_NE(sentinelDetail, nullptr);
  measure(n);
  n.fail_create_monitoring_of(a, sentinel);
  auto sub = subscription(1);
  auto completions = std::make_shared<std::atomic_size_t>(0);

  auto future =
    start_create(*sub, list_of(value_item(a, 1), value_item(b, 2)), mSecurity, 0, {}, completions);
  const auto results = finish_create(future, 2);
  strand_barrier(*sub);

  const auto calls = n.calls();
  const auto creates =
    naming(calls, [](const Call& call) { return is_member(call, Member::CreateMonitoring); }, {a, b});
  ASSERT_EQ(creates.size(), 1u) << "N's create_monitoring_async was not asked about both items in one call"
                                << describe(calls);
  EXPECT_EQ(completions->load(), 1u) << "the create completed more than once";
  ASSERT_EQ(results.size(), 2u);
  EXPECT_EQ(results[0].status_code().as_status(), Status::BadCommunicationError)
    << "row 1: " << to_string(results[0].status_code());
  EXPECT_EQ(results[0].status_code().shared_detail(), sentinelDetail)
    << "row 1 does not carry the namespace's ErrorDetail object";
  EXPECT_EQ(results[1].status_code().as_status(), Status::Good)
    << "row 2: " << to_string(results[1].status_code());
  EXPECT_NE(results[1].monitored_item_id(), 0u) << "row 2 was given no monitored item id";
}

// COMP-REQUEST-OP-LIFECYCLE-06: while the namespace's permission answer for the request's items is
// outstanding, no item is registered; once it is given, they are.
// @relation(AC-COMP-REQUEST-OP-LIFECYCLE-06-AUTHORIZATION-COMPLETES-BEFORE-REGISTRATION, scope=function)
TEST_F(CreateFlow, AuthorizationCompletesForEveryItemBeforeAnyRegistration)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  std::vector<MonitoredItemCreateRequest> items;
  for (uint32_t i = 0; i < 5; ++i)
  {
    const NodeId variable =
      create_variable(NodeId{index, 100 + i}, NodeId{DataTypeId::Int32}, DataValue{Variant{int32_t{0}}});
    items.push_back(value_item(variable, 1 + i));
  }
  measure(n);
  n.hold_permission_answers();
  auto sub = subscription(1);

  auto future = start_create(*sub, std::move(items), mSecurity);
  ASSERT_TRUE(n.wait_for_held_permission_answers(1, 3s)) << "no permission answer was asked for and held";
  EXPECT_FALSE(n.wait_for_calls(Member::CreateMonitoring, 1, 500ms))
    << "an item was registered while its permission answer was outstanding" << describe(n.calls());
  EXPECT_EQ(future.wait_for(0s), std::future_status::timeout)
    << "the create answered while its permission answer was outstanding";

  n.release_held_permission_answers();
  EXPECT_TRUE(n.wait_for_calls(Member::CreateMonitoring, 1, 3s))
    << "no item was registered once the permission answer was given" << describe(n.calls());
  const auto results = finish_create(future, 5);
  for (std::size_t i = 0; i < results.size(); ++i)
  {
    EXPECT_EQ(results[i].status_code().as_status(), Status::Good)
      << "row " << i + 1 << ": " << to_string(results[i].status_code());
  }
}

// COMP-SVR-NAMESPACE-CALLS-13 rule 3, NR-24 rule 1: the DataType the four Variables share is looked up and
// its supertype read once for the request.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-13-DEADBAND-DATA-TYPES-ARE-DECIDED-ONCE-PER-REQUEST, scope=function)
TEST_F(CreateFlow, DeadbandDataTypesAreResolvedOncePerRequest)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  const auto model = create_deadband_model(index);
  measure(n);
  auto sub = subscription(1);

  const auto results = create(*sub, absolute_deadband_items(model.ofD), mSecurity);

  const auto calls = n.calls();
  EXPECT_EQ(times_named(calls, is_batched_lookup, model.d), 1u) << "batched lookups of D" << describe(calls);
  EXPECT_EQ(times_named(
              calls, [](const Call& call) { return is_member(call, Member::ReadReferences); }, model.d),
    1u)
    << "References reads of D" << describe(calls);
  ASSERT_EQ(results.size(), 4u);
  for (std::size_t i = 0; i < results.size(); ++i)
  {
    EXPECT_EQ(results[i].status_code().as_status(), Status::Good)
      << "row " << i + 1 << ": " << to_string(results[i].status_code());
  }
}

// COMP-SVR-NAMESPACE-CALLS-13 rule 3: a namespace-0 DataType with a numeric identifier from 1 to 28 is
// decided without a call. Namespace 0 cannot be replaced by a recording namespace, so the absence of a call
// is observed through its effect: namespace 0's Double is made a subtype of String here, so a walk that read
// Double's Node would reach BaseDataType without Number and refuse the rows Bad_FilterNotAllowed.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-13-DEADBAND-DATA-TYPES-ARE-DECIDED-ONCE-PER-REQUEST, scope=function)
TEST_F(CreateFlow, ABuiltInDeadbandDataTypeCostsNoCall)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  const auto model = create_deadband_model(index);
  auto doubleType = mAddressSpace->try_find_sync<DataTypeAccessor>(NodeId{DataTypeId::Double});
  ASSERT_TRUE(doubleType.is_good()) << to_string(doubleType.status_code());
  ASSERT_TRUE(
    doubleType.value()
      .try_remove_reference_sync(NodeId{ReferenceTypeId::HasSubtype}, NodeId{DataTypeId::Number}, false)
      .is_good())
    << "Double's supertype Number could not be removed";
  ASSERT_TRUE(
    doubleType.value()
      .try_add_reference_sync(NodeId{ReferenceTypeId::HasSubtype}, NodeId{DataTypeId::String}, false)
      .is_good())
    << "Double could not be made a subtype of String";
  measure(n);
  auto sub = subscription(1);

  const auto results = create(*sub, absolute_deadband_items(model.ofDouble), mSecurity);

  ASSERT_EQ(results.size(), 4u);
  for (std::size_t i = 0; i < results.size(); ++i)
  {
    EXPECT_EQ(results[i].status_code().as_status(), Status::Good)
      << "row " << i + 1 << ": " << to_string(results[i].status_code())
      << " (a refusal means Double's Node was read: it is a subtype of String in this test)";
  }
  const auto calls = n.calls();
  for (const auto& call : calls)
  {
    if (!is_lookup(call) && call.member != Member::ReadReferences)
    {
      continue;
    }
    for (const auto& nodeId : call.nodeIds)
    {
      EXPECT_NE(nodeId.namespace_index(), 0u)
        << member_name(call.member) << " named " << nodeId.as_definition();
    }
  }
}

// COMP-SVR-NAMESPACE-CALLS-13 rule 3: an AbsoluteDeadband on a String Variable is refused before
// registration.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-13-AN-ABSOLUTE-DEADBAND-REFUSAL-IS-NEVER-REGISTERED, scope=function)
TEST_F(CreateFlow, AnAbsoluteDeadbandRefusalIsNeverRegistered)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  const NodeId text =
    create_variable(NodeId{index, 300}, NodeId{DataTypeId::String}, DataValue{Variant{String{"text"}}});
  measure(n);
  auto sub = subscription(1);

  const auto results = create(*sub, list_of(value_item(text, 1, 5, absolute_deadband(1.0))), mSecurity);

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].status_code().as_status(), Status::BadFilterNotAllowed)
    << to_string(results[0].status_code());
  const bool deleted = n.wait_for_calls(Member::DeleteMonitoring, 1, 500ms);
  const auto calls = n.calls();
  const auto creates =
    naming(calls, [](const Call& call) { return is_member(call, Member::CreateMonitoring); }, {text});
  EXPECT_TRUE(creates.empty()) << "N's create_monitoring_async named the refused item" << describe(calls);
  EXPECT_FALSE(deleted) << "N received a delete_monitoring_async" << describe(calls);
}

// COMP-SVR-NAMESPACE-CALLS-13 rule 4: the EURange Properties of a request's PercentDeadband items are read
// with one References read, one lookup and one Value read per namespace, and each item applies its own range:
// of a change of half its deadband and then one of twice it, it reports only the second.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-13-EU-RANGES-ARE-READ-ONCE-PER-NAMESPACE, scope=function)
TEST_F(CreateFlow, EuRangesAreReadOncePerNamespace)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  std::vector<NodeId> variables;
  std::vector<NodeId> properties;
  std::vector<double> deadbands;
  std::vector<MonitoredItemCreateRequest> items;
  for (uint32_t i = 0; i < 4; ++i)
  {
    const double high = std::pow(10.0, static_cast<double>(i + 1));
    variables.emplace_back(index, 400 + i);
    properties.emplace_back(index, 500 + i);
    deadbands.push_back(high / 10.0);
    create_analog_item(variables.back(), properties.back(), 0.0, high);
    items.push_back(value_item(variables.back(), 1 + i, 10, percent_deadband(10.0)));
  }
  measure(n);
  auto sub = subscription(1);

  const auto results = create(*sub, std::move(items), mSecurity);

  const auto calls = n.calls();
  const auto references =
    naming(calls, [](const Call& call) { return is_member(call, Member::ReadReferences); }, variables);
  EXPECT_EQ(references.size(), 1u) << "read_references_async calls for the EURange Properties"
                                   << describe(calls);
  if (references.size() == 1u)
  {
    EXPECT_EQ(sorted(references[0].nodeIds), sorted(variables)) << describe(calls);
  }
  const auto lookups = naming(calls, is_batched_lookup, properties);
  EXPECT_EQ(lookups.size(), 1u) << "batched lookups of the EURange Properties" << describe(calls);
  if (lookups.size() == 1u)
  {
    EXPECT_EQ(sorted(lookups[0].nodeIds), sorted(properties)) << describe(calls);
  }
  const auto reads =
    naming(calls, [](const Call& call) { return is_member(call, Member::ReadValues); }, properties);
  EXPECT_EQ(reads.size(), 1u) << "read_values_async calls of the EURange Properties" << describe(calls);
  if (reads.size() == 1u)
  {
    EXPECT_EQ(sorted(reads[0].nodeIds), sorted(properties)) << describe(calls);
  }
  ASSERT_EQ(results.size(), 4u);
  for (std::size_t i = 0; i < results.size(); ++i)
  {
    ASSERT_EQ(results[i].status_code().as_status(), Status::Good)
      << "row " << i + 1 << ": " << to_string(results[i].status_code());
  }

  for (std::size_t i = 0; i < variables.size(); ++i)
  {
    auto variable = mVariables.at(variables[i]);
    variable.write_value_sync(DataValue{Variant{deadbands[i] / 2.0}});
    variable.write_value_sync(DataValue{Variant{deadbands[i] * 2.0}});
  }
  ASSERT_TRUE(publish_until(*sub,
    [&]
    {
      for (std::size_t i = 0; i < variables.size(); ++i)
      {
        if (!reported_double(static_cast<uint32_t>(1 + i), deadbands[i] * 2.0))
        {
          return false;
        }
      }
      return true;
    }))
    << "an item did not report a change of twice its own deadband";
  for (std::size_t i = 0; i < variables.size(); ++i)
  {
    const auto handle = static_cast<uint32_t>(1 + i);
    EXPECT_FALSE(reported_double(handle, deadbands[i] / 2.0))
      << "item " << handle << " reported a change of half its own deadband; " << reports_text(handle);
  }
}

// COMP-SVR-NAMESPACE-CALLS-13 rule 4, DL-50 (3), DL-53: when no target is the EURange and a candidate's
// lookup failed for a reason other than not existing, that failure is the answer. A guard.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-13-AN-EU-RANGE-CANDIDATE-THAT-FAILS-IS-THE-ANSWER, scope=function)
TEST_F(CreateFlow, AnEuRangeCandidateThatFailsIsTheAnswer)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  const NodeId variable{index, 600};
  const NodeId property{index, 601};
  create_analog_item(variable, property, 0.0, 100.0);
  measure(n);
  n.answer_lookup_of(property, StatusCode{Status::BadTimeout});
  auto sub = subscription(1);

  const auto results = create(*sub, list_of(value_item(variable, 1, 5, percent_deadband(10.0))), mSecurity);

  EXPECT_GE(times_named(n.calls(), is_lookup, property), 1u) << "the scripted answer was never used";
  ASSERT_EQ(results.size(), 1u);
  const auto& status = results[0].status_code();
  EXPECT_TRUE(status.is_bad()) << "the row was not refused: " << to_string(status);
  EXPECT_NE(status.as_status(), Status::BadNodeIdUnknown) << to_string(status);
  EXPECT_TRUE(status.as_status() == Status::BadTimeout ||
              detail_cause(status) == StatusCode{Status::BadTimeout}.value())
    << "neither the row's status nor its ErrorDetail's cause is Bad_Timeout: " << to_string(status);
}

// COMP-SVR-NAMESPACE-CALLS-13 rule 5: the initial Values of a request's Value items are read with one
// read_values_async per namespace, with the Session's caller and no IndexRange.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-13-INITIAL-VALUES-ARE-ONE-READ-PER-NAMESPACE, scope=function)
TEST_F(CreateFlow, InitialValuesAreOneReadPerNamespace)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  std::vector<NodeId> variables;
  std::vector<MonitoredItemCreateRequest> items;
  for (uint32_t i = 0; i < 5; ++i)
  {
    variables.push_back(create_variable(
      NodeId{index, 100 + i}, NodeId{DataTypeId::Int32}, DataValue{Variant{static_cast<int32_t>(100 + i)}}));
    items.push_back(value_item(variables.back(), 1 + i));
  }
  measure(n);
  auto sub = subscription(1);

  const auto results = create(*sub, std::move(items), mSecurity);

  const auto calls = n.calls();
  const auto reads =
    naming(calls, [](const Call& call) { return is_member(call, Member::ReadValues); }, variables);
  EXPECT_EQ(reads.size(), 1u) << "read_values_async calls for the initial Values" << describe(calls);
  if (reads.size() == 1u)
  {
    const auto& read = reads[0];
    EXPECT_EQ(sorted(read.nodeIds), sorted(variables)) << describe(calls);
    EXPECT_TRUE(
      std::none_of(read.itemRanged.begin(), read.itemRanged.end(), [](bool ranged) { return ranged; }))
      << "an initial read carried an IndexRange";
    EXPECT_TRUE(read.hasCaller && read.callerSessionId == sessionNodeId)
      << "the initial read was not made with the Session's caller";
  }
  ASSERT_EQ(results.size(), 5u);
  for (std::size_t i = 0; i < results.size(); ++i)
  {
    EXPECT_EQ(results[i].status_code().as_status(), Status::Good)
      << "row " << i + 1 << ": " << to_string(results[i].status_code());
  }
  ASSERT_TRUE(publish_until(*sub,
    [&]
    {
      for (uint32_t handle = 1; handle <= 5; ++handle)
      {
        if (reports_of(handle).empty())
        {
          return false;
        }
      }
      return true;
    }))
    << "an item reported nothing";
  for (uint32_t i = 0; i < 5; ++i)
  {
    const auto first = reports_of(1 + i).front();
    EXPECT_TRUE(first.status.is_good() && first.value.is_int32() &&
                first.value.as<int32_t>() == static_cast<int32_t>(100 + i))
      << "item " << i + 1 << "'s first notification is not its Variable's Value; " << reports_text(1 + i);
  }
}

// COMP-SVR-NAMESPACE-CALLS-15 rule 2 (NR-14 rule 1): whoever produces a value narrows it, so the initial read
// of a ranged Value item carries the item's IndexRange, and the item reports the slice the namespace
// answered.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-15-A-RANGED-INITIAL-VALUE-IS-READ-WITH-ITS-RANGE, scope=function)
TEST_F(CreateFlow, ARangedInitialValueIsReadWithItsRange)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  const NodeId v = create_array_variable(NodeId{index, 800}, Array<int32_t>{1, 2, 3, 4, 5});
  measure(n);
  auto sub = subscription(1);
  auto item = value_item(v, 1);
  item.item_to_monitor().index_range() = "2:3";

  const auto results = create(*sub, list_of(std::move(item)), mSecurity);

  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results[0].status_code().as_status(), Status::Good) << to_string(results[0].status_code());
  const auto calls = n.calls();
  const auto reads = naming(calls, [](const Call& call) { return is_member(call, Member::ReadValues); }, {v});
  ASSERT_EQ(reads.size(), 1u) << "read_values_async calls naming the Variable" << describe(calls);
  ASSERT_EQ(reads[0].itemRanges.size(), 1u) << describe(calls);
  EXPECT_EQ(std::string{std::string_view{reads[0].itemRanges[0]}}, "2:3")
    << "the initial read did not carry the item's IndexRange";
  ASSERT_TRUE(publish_until(*sub, [&] { return !reports_of(1).empty(); })) << "the item reported nothing";
  const auto first = reports_of(1).front();
  EXPECT_TRUE(first.status.is_good()) << reports_text(1);
  EXPECT_EQ(first.value, (Variant{Array<int32_t>{3, 4}})) << reports_text(1);
}

// COMP-SVR-NAMESPACE-CALLS-15 rules 2 and 3 (NR-10 rule 8): a namespace that ignores the IndexRange and
// answers the whole Value has broken its contract, so the item's first notification is that failure, not a
// Value the item narrowed.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-15-A-VALUE-LARGER-THAN-ITS-RANGE-FAILS-THE-INITIAL-VALUE, scope=function)
TEST_F(CreateFlow, AValueLargerThanItsRangeFailsTheInitialValue)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  const NodeId v = create_array_variable(NodeId{index, 801}, Array<int32_t>{1, 2, 3, 4, 5});
  measure(n);
  n.answer_whole_values();
  auto sub = subscription(1);
  auto item = value_item(v, 1);
  item.item_to_monitor().index_range() = "2:3";

  const auto results = create(*sub, list_of(std::move(item)), mSecurity);

  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results[0].status_code().as_status(), Status::Good) << to_string(results[0].status_code());
  ASSERT_TRUE(publish_until(*sub, [&] { return !reports_of(1).empty(); })) << "the item reported nothing";
  const auto first = reports_of(1).front();
  EXPECT_EQ(first.status.as_status(), Status::BadInternalError) << reports_text(1);
  EXPECT_EQ(detail_code(first.status), "NamespaceValueExceedsRange") << reports_text(1);
}

// COMP-SVR-NAMESPACE-CALLS-15 rule 2, a guard: the initial value of an item on a VariableType's Value is read
// from the Node's description, and the first notification is that value narrowed to the item's IndexRange,
// once.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-15-A-RANGED-INITIAL-VALUE-FROM-THE-DESCRIPTION-IS-NARROWED-ONCE, scope=function)
TEST_F(CreateFlow, ARangedInitialValueFromTheDescriptionIsNarrowedOnce)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  const NodeId typeId{index, 820};
  auto created = mAddressSpace->try_create_node_sync(typeId, NodeClass::VariableType, {});
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
  auto type = created.value().as<VariableTypeAccessor>();
  ASSERT_TRUE(type.has_value());
  type->set_data_type(NodeId{DataTypeId::Int32});
  type->set_value_rank(ValueRank{1});
  type->set_value(DataValue{Variant{Array<int32_t>{1, 2, 3, 4}}});
  measure(n);
  auto sub = subscription(1);
  auto item = value_item(typeId, 1);
  item.item_to_monitor().index_range() = "1:2";

  const auto results = create(*sub, list_of(std::move(item)), mSecurity);

  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results[0].status_code().as_status(), Status::Good) << to_string(results[0].status_code());
  ASSERT_TRUE(publish_until(*sub, [&] { return !reports_of(1).empty(); })) << "the item reported nothing";
  const auto first = reports_of(1).front();
  EXPECT_TRUE(first.status.is_good()) << reports_text(1);
  EXPECT_EQ(first.value, (Variant{Array<int32_t>{2, 3}})) << reports_text(1);
}

// COMP-SVR-NAMESPACE-CALLS-13 rule 6, DL-69 (D7): a change reported for B, the later item, while A's initial
// read is held is delivered after B's initial value.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-13-A-CHANGE-DURING-THE-CREATE-IS-DELIVERED-AFTER-THE-INITIAL-VALUE, scope=function)
TEST_F(CreateFlow, AChangeDuringTheCreateIsDeliveredAfterTheInitialValue)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  const NodeId a = create_variable(
    NodeId{index, 700}, NodeId{DataTypeId::Int32}, DataValue{Variant{int32_t{0}}, DateTime::now()});
  const NodeId b =
    create_variable(NodeId{index, 701}, NodeId{DataTypeId::Int32}, DataValue{Variant{int32_t{1}}});
  measure(n);
  n.observe_deliveries();
  n.hold_value_reads_of({a});
  auto sub = subscription(1);

  auto future = start_create(*sub, list_of(value_item(a, 1, 5), value_item(b, 2, 5)), mSecurity);
  ASSERT_TRUE(n.wait_for_held_value_reads(1, 3s)) << "A's initial read was not held";
  const IntegerId bId = monitored_item_id_of(n, b);
  ASSERT_NE(bId, 0u) << "B's item was not registered with N";
  n.report_change(b, AttributeId::Value, DataValue{Variant{int32_t{2}}});
  ASSERT_TRUE(n.wait_for_delivery(bId, false, 3s))
    << "B's change was not delivered to the subscription's sink";
  strand_barrier(*sub);
  n.release_held_value_reads();
  const auto results = finish_create(future, 2);

  ASSERT_EQ(results.size(), 2u);
  ASSERT_EQ(results[1].status_code().as_status(), Status::Good)
    << "B's row: " << to_string(results[1].status_code());
  publish_until(*sub, [&] { return reports_of(2).size() >= 2u; });
  std::vector<int32_t> values;
  for (const auto& reported : reports_of(2))
  {
    if (reported.status.is_good() && reported.value.is_int32())
    {
      values.push_back(reported.value.as<int32_t>());
    }
  }
  EXPECT_EQ(values, (std::vector<int32_t>{1, 2})) << reports_text(2);
}

// COMP-SVR-NAMESPACE-CALLS-13 rule 6, DL-69 (D7): a sample held during the create that is older than the
// initial value is dropped, so that the first notification is not an older value. A guard.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-13-A-HELD-SAMPLE-OLDER-THAN-THE-INITIAL-VALUE-IS-DROPPED, scope=function)
TEST_F(CreateFlow, AHeldSampleOlderThanTheInitialValueIsDropped)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  const DateTime current = DateTime::now();
  const NodeId a =
    create_variable(NodeId{index, 700}, NodeId{DataTypeId::Int32}, DataValue{Variant{int32_t{0}}, current});
  const NodeId b =
    create_variable(NodeId{index, 701}, NodeId{DataTypeId::Int32}, DataValue{Variant{int32_t{1}}, current});
  measure(n);
  n.observe_deliveries();
  n.hold_value_reads_of({a});
  auto sub = subscription(1);

  auto future = start_create(*sub, list_of(value_item(a, 1, 1), value_item(b, 2, 1)), mSecurity);
  ASSERT_TRUE(n.wait_for_held_value_reads(1, 3s)) << "A's initial read was not held";
  const IntegerId bId = monitored_item_id_of(n, b);
  ASSERT_NE(bId, 0u) << "B's item was not registered with N";
  n.report_change(b,
    AttributeId::Value,
    DataValue{Variant{int32_t{0}}, DateTime{current.value() - std::chrono::seconds{1}}});
  ASSERT_TRUE(n.wait_for_delivery(bId, false, 3s))
    << "B's older value was not delivered to the subscription's sink";
  strand_barrier(*sub);
  n.release_held_value_reads();
  const auto results = finish_create(future, 2);

  ASSERT_EQ(results.size(), 2u);
  ASSERT_EQ(results[1].status_code().as_status(), Status::Good)
    << "B's row: " << to_string(results[1].status_code());
  ASSERT_TRUE(publish_until(*sub, [&] { return !reports_of(2).empty(); })) << "B's item reported nothing";
  const auto first = reports_of(2).front();
  EXPECT_TRUE(first.status.is_good() && first.value.is_int32() && first.value.as<int32_t>() == 1)
    << "B's first notification is not B's current Value; " << reports_text(2);
}

// COMP-SVR-NAMESPACE-CALLS-13 rule 6, DL-69 (D7): a deletion of B, the later item, while A's initial read is
// held is reported after B's initial value, once.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-13-A-DELETION-DURING-THE-CREATE-IS-REPORTED, scope=function)
TEST_F(CreateFlow, ADeletionDuringTheCreateIsReported)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  const NodeId a =
    create_variable(NodeId{index, 700}, NodeId{DataTypeId::Int32}, DataValue{Variant{int32_t{0}}});
  const NodeId b =
    create_variable(NodeId{index, 701}, NodeId{DataTypeId::Int32}, DataValue{Variant{int32_t{1}}});
  n.observe_deliveries();
  n.hold_value_reads_of({a});
  auto sub = subscription(1);

  auto future = start_create(*sub, list_of(value_item(a, 1, 5), value_item(b, 2, 5)), mSecurity);
  ASSERT_TRUE(n.wait_for_held_value_reads(1, 3s)) << "A's initial read was not held";
  strand_barrier(*sub);
  ASSERT_EQ(future.wait_for(0ms), std::future_status::timeout);
  const IntegerId bId = monitored_item_id_of(n, b);
  ASSERT_NE(bId, 0u) << "B's item was not registered with N";
  const auto deleted = mAddressSpace->try_delete_node_sync(b, true);
  ASSERT_TRUE(deleted.is_good()) << "B's delete answered " << to_string(deleted.status_code());
  ASSERT_TRUE(n.wait_for_delivery(bId, true, 3s))
    << "B's item's tick did not report the deletion to the sink";
  strand_barrier(*sub);
  n.release_held_value_reads();
  const auto results = finish_create(future, 2);

  ASSERT_EQ(results.size(), 2u);
  EXPECT_EQ(results[1].status_code().as_status(), Status::Good)
    << "B's row: " << to_string(results[1].status_code());
  publish_for(*sub, 2000ms);
  std::vector<std::string> sequence;
  for (const auto& reported : reports_of(2))
  {
    if (reported.status.as_status() == Status::BadNodeIdUnknown)
    {
      sequence.emplace_back("Bad_NodeIdUnknown");
    }
    else if (reported.status.is_good() && reported.value.is_int32())
    {
      sequence.push_back(std::to_string(reported.value.as<int32_t>()));
    }
    else
    {
      sequence.push_back(to_string(reported.value) + " [" + to_string(reported.status) + "]");
    }
  }
  EXPECT_EQ(sequence, (std::vector<std::string>{"1", "Bad_NodeIdUnknown"})) << reports_text(2);
}

// COMP-SVR-NAMESPACE-CALLS-16 rule 3, DL-69 (E4): O1 is deleted after the create's lookup found it and before
// its item's EventNotifier is checked, so O1's description answers the item Bad_NodeIdUnknown with the
// ErrorDetail NodeDeleted naming O1; O2's item, in the same request, is created.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-16-AN-EVENT-ITEM-ON-A-NODE-DELETED-AFTER-ITS-LOOKUP-ANSWERS-ONLY-THAT-ITEM, scope=function)
TEST_F(CreateFlow, AnEventItemOnANodeDeletedAfterItsLookupAnswersOnlyThatItem)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  const NodeId o1 = create_notifier(NodeId{index, uint32_t{400}});
  const NodeId o2 = create_notifier(NodeId{index, uint32_t{401}});
  measure(n);
  n.hold_permission_answers();
  mEventBus = std::make_shared<EventBus>(*mAddressSpace);
  auto sub = subscription(1);

  auto future = start_create(*sub, list_of(event_item(o1, 1), event_item(o2, 2)), mSecurity, 0, mEventBus);
  ASSERT_TRUE(n.wait_for_held_permission_answers(1, 3s)) << "no permission answer was asked for and held";
  const auto deleted = mAddressSpace->try_delete_node_sync(o1, true);
  ASSERT_TRUE(deleted.is_good()) << "O1's delete answered " << to_string(deleted.status_code());
  n.release_held_permission_answers();
  const auto results = finish_create(future, 2);

  ASSERT_EQ(results.size(), 2u);
  const auto& o1Status = results[0].status_code();
  EXPECT_EQ(o1Status.as_status(), Status::BadNodeIdUnknown) << "O1's row: " << to_string(o1Status);
  EXPECT_EQ(detail_code(o1Status), "NodeDeleted") << "O1's row: " << to_string(o1Status);
  EXPECT_EQ(::ua::test_utils::error_context(o1Status.detail(), ContextKeys::nodeId.value()), to_string(o1))
    << "O1's row's ErrorDetail does not name O1: " << to_string(o1Status);
  EXPECT_EQ(results[1].status_code().as_status(), Status::Good)
    << "O2's row: " << to_string(results[1].status_code());
  EXPECT_NE(results[1].monitored_item_id(), 0u) << "O2's row was given no monitored item id";
}

// COMP-SVR-NAMESPACE-CALLS-13 rule 7, NR-26: a ModifyMonitoredItems calls its namespaces at once, not one
// after another.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-13-THE-NAMESPACES-ARE-MODIFIED-AT-ONCE, scope=function)
TEST_F(ModifyFlow, TheNamespacesAreModifiedConcurrently)
{
  const auto indexes = setup(2);
  auto& first = *mNamespaces.at(0);
  auto& second = *mNamespaces.at(1);
  const NodeId a =
    create_variable(NodeId{indexes.at(0), 100}, NodeId{DataTypeId::Int32}, DataValue{Variant{int32_t{0}}});
  const NodeId b =
    create_variable(NodeId{indexes.at(1), 100}, NodeId{DataTypeId::Int32}, DataValue{Variant{int32_t{0}}});
  auto sub = subscription(1);
  const auto created = create(*sub, list_of(value_item(a, 1), value_item(b, 2)), mSecurity);
  ASSERT_EQ(created.size(), 2u);
  ASSERT_TRUE(created[0].status_code().is_good()) << to_string(created[0].status_code());
  ASSERT_TRUE(created[1].status_code().is_good()) << to_string(created[1].status_code());
  first.hold_modify_answers();
  first.reset();
  second.reset();

  auto future = start_modify(*sub,
    list_of(modify_item(created[0].monitored_item_id(), 1, 10),
      modify_item(created[1].monitored_item_id(), 2, 10)));
  const bool firstHeld = first.wait_for_held_modify_answers(1, 3s);
  const bool secondCalledWhileHeld = second.wait_for_calls(Member::ModifyMonitoring, 1, 1s);
  first.release_held_modify_answers();
  const auto results = finish_modify(future, 2);

  ASSERT_TRUE(firstHeld) << "A's modify_monitoring_async was not called";
  EXPECT_TRUE(secondCalledWhileHeld)
    << "B's modify_monitoring_async was not called while A's answer was held";
  ASSERT_EQ(results.size(), 2u);
  EXPECT_EQ(results[0].status_code().as_status(), Status::Good) << to_string(results[0].status_code());
  EXPECT_EQ(results[1].status_code().as_status(), Status::Good) << to_string(results[1].status_code());
}
