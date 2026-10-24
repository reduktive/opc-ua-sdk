// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The monitoring helper the SDK owns, one per namespace registration, reached through the registration's
// context (COMP-SVR-NAMESPACE-MONITORING-HELPER, COMP-SVR-NAMESPACE-MONITORING-INVALIDATION-01 as restated by
// NR-70 B3).
//
// A namespace reaches its helper through `context().monitoring()`, which a namespace may call and a test may
// not, so the namespaces here expose it. The helper is given the resolved Node with each item, so the
// deletion and Value read the helper's tick observes are switched by a test Node of its own.

#include <gtest/gtest.h>

#include "monitoring_helper_fixture.h"

#include "ua_access_level_ex_type.h"

#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace ua;
using namespace std::chrono_literals;
using namespace ua::test::monitoring_helper;

// NR-47 rule 1: one helper per registration, the same for the context and every copy of it, and a report
// through one registration's helper reaches none of another's items.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-HELPER-01-EACH-REGISTRATION-HAS-ITS-OWN-HELPER, scope=function)
TEST_F(MonitoringHelperOwnership, EachRegistrationHasItsOwnHelper)
{
  auto a = registered_namespace("urn:test:monitoring-helper:a");
  auto b = registered_namespace("urn:test:monitoring-helper:b");

  Helper* const aFirst = &a->helper();
  Helper* const aSecond = &a->helper();
  const NamespaceContext aCopy = a->context_copy();
  Helper* const aThroughCopy = &aCopy.monitoring();
  Helper* const bFirst = &b->helper();
  Helper* const bSecond = &b->helper();
  EXPECT_EQ(aFirst, aSecond);
  EXPECT_EQ(aFirst, aThroughCopy);
  EXPECT_EQ(bFirst, bSecond);
  EXPECT_NE(aFirst, bFirst);

  // N's MinimumSamplingInterval is absent, so an item at interval 0 on its Value is Reported (rule 3).
  auto n = variable(*a, 1u, Variant{int32_t{1}});
  auto itemSink = sink();
  const std::vector<MonitoringCreateItem> items{{.nodeId = n->node_id(),
    .attributeId = AttributeId::Value,
    .monitoredItemId = 1,
    .samplingInterval = 0,
    .queueSize = 10,
    .sink = itemSink}};
  BatchResult<MonitoringCreateItemResult> created;
  a->create_monitoring_async(RequestInfo{},
    nullptr,
    items,
    [&created](BatchResult<MonitoringCreateItemResult> result) { created = result; });
  ASSERT_EQ(created.items.size(), 1u);
  ASSERT_TRUE(created.items[0].is_good()) << to_string(created.items[0].status_code());
  // The initial value is the Subscription's to read; a Reported registration is given nothing until a change.
  std::this_thread::sleep_for(50ms);
  const auto before = itemSink->samples();

  b->helper().attribute_changed(n->node_id(), AttributeId::Value, DataValue{Variant{int32_t{5}}});
  EXPECT_FALSE(itemSink->wait_for_samples(before + 1, 300ms))
    << "a report through B's helper reached A's item; " << itemSink->text();

  a->helper().attribute_changed(n->node_id(), AttributeId::Value, DataValue{Variant{int32_t{6}}});
  EXPECT_TRUE(itemSink->wait_for_samples(before + 1, 1s)) << itemSink->text();
  EXPECT_EQ(itemSink->samples_of(6), 1u) << itemSink->text();
  EXPECT_EQ(itemSink->samples_of(5), 0u) << itemSink->text();
}

// DL-68 (1): before attach, `monitoring()` answers a helper that refuses every create, modify and delete per
// item with Bad_NotSupported and NamespaceNotRegistered, whether or not the item carries a Node; after
// registration the same creates are Good.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-HELPER-01-BEFORE-ATTACH-EVERY-CREATE-IS-REFUSED, scope=function)
TEST_F(MonitoringHelperOwnership, BeforeAttachEveryCreateIsRefused)
{
  auto ns = ExposedNamespace::create("urn:test:monitoring-helper:unattached", mExecutor);
  auto first = default_ns::VariableNode::create(NodeId{2, 1u});
  auto second = default_ns::VariableNode::create(NodeId{2, 2u});
  write_value(first, Variant{int32_t{1}});
  write_value(second, Variant{int32_t{2}});
  auto firstSink = sink();
  auto secondSink = sink();
  auto thirdSink = sink();
  const std::vector<Helper::ResolvedMonitoringItem> items{
    resolved(first->node_id(), AttributeId::Value, 1, 100, firstSink, first, Helper::Delivery::Sampled),
    resolved(second->node_id(), AttributeId::Value, 2, 0, secondSink, second, Helper::Delivery::Reported),
    resolved(NodeId{2, 3u}, AttributeId::Value, 3, 100, thirdSink, nullptr, Helper::Delivery::Sampled),
  };

  const auto created = ns->helper().create_monitoring(items);
  ASSERT_EQ(created.size(), 3u);
  for (size_t index = 0; index < created.size(); ++index)
    EXPECT_TRUE(refused_as_unregistered(created[index].result.status_code())) << "create " << index;

  const std::vector<Helper::ResolvedMonitoringModifyItem> modifies{
    {MonitoringModifyItem{1, 250, 4}, Helper::Delivery::Sampled},
    {MonitoringModifyItem{2, 0, 4}, Helper::Delivery::Reported},
  };
  const auto modified = ns->helper().modify_monitoring(modifies);
  ASSERT_EQ(modified.size(), 2u);
  for (size_t index = 0; index < modified.size(); ++index)
    EXPECT_TRUE(refused_as_unregistered(modified[index].result.status_code())) << "modify " << index;

  const std::vector<MonitoringHandle> handles{1, 2};
  const auto deleted = ns->helper().delete_monitoring(handles);
  ASSERT_EQ(deleted.size(), 2u);
  for (size_t index = 0; index < deleted.size(); ++index)
    EXPECT_TRUE(refused_as_unregistered(deleted[index].status_code())) << "delete " << index;

  ns->helper().attribute_changed(first->node_id(), AttributeId::Value, DataValue{Variant{int32_t{5}}});
  std::this_thread::sleep_for(150ms);
  EXPECT_EQ(firstSink->events().size(), 0u) << firstSink->text();
  EXPECT_EQ(secondSink->events().size(), 0u) << secondSink->text();
  EXPECT_EQ(thirdSink->events().size(), 0u) << thirdSink->text();

  const auto added = mAddressSpace->try_add_namespace_sync(ns);
  ASSERT_TRUE(added.is_good()) << to_string(added.status_code());
  mNamespaces.push_back(ns);
  const std::vector<Helper::ResolvedMonitoringItem> again{items[0], items[1]};
  const auto createdAgain = ns->helper().create_monitoring(again);
  ASSERT_EQ(createdAgain.size(), 2u);
  std::vector<MonitoringHandle> issued;
  for (size_t index = 0; index < createdAgain.size(); ++index)
  {
    ASSERT_TRUE(createdAgain[index].result.is_good())
      << "create " << index << " after registration: " << to_string(createdAgain[index].result.status_code());
    issued.push_back(createdAgain[index].result.value().handle);
  }
  ns->helper().delete_monitoring(issued);
}

// NR-48 rule 1: a change stated by NodeId and attribute reaches every Reported registration on that attribute
// of that Node, once, and no registration on another attribute, another Node, or a Sampled one.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-HELPER-02-A-CHANGE-REACHES-EVERY-REPORTED-REGISTRATION-ON-THE-ATTRIBUTE, scope=function)
TEST_F(MonitoringHelperIndex, AChangeReachesEveryReportedRegistrationOnTheAttribute)
{
  auto ns = registered_namespace("urn:test:monitoring-helper:index");
  auto n = variable(*ns, 1u, Variant{int32_t{1}});
  auto m = variable(*ns, 2u, Variant{int32_t{1}});
  auto reportedOne = sink();
  auto reportedTwo = sink();
  auto displayName = sink();
  auto otherNode = sink();
  auto sampled = sink();
  const std::vector<Helper::ResolvedMonitoringItem> items{
    resolved(n->node_id(), AttributeId::Value, 1, 0, reportedOne, n, Helper::Delivery::Reported),
    resolved(n->node_id(), AttributeId::Value, 2, 0, reportedTwo, n, Helper::Delivery::Reported),
    resolved(n->node_id(), AttributeId::DisplayName, 3, 100, displayName, n, Helper::Delivery::Reported),
    resolved(m->node_id(), AttributeId::Value, 4, 0, otherNode, m, Helper::Delivery::Reported),
    resolved(n->node_id(), AttributeId::Value, 5, 100, sampled, n, Helper::Delivery::Sampled),
  };
  const auto created = ns->helper().create_monitoring(items);
  ASSERT_EQ(created.size(), items.size());
  for (size_t index = 0; index < created.size(); ++index)
    ASSERT_TRUE(created[index].result.is_good())
      << "create " << index << ": " << to_string(created[index].result.status_code());
  // The Sampled registration delivers its first read; a Reported one is given nothing until a change.
  ASSERT_TRUE(sampled->wait_for_samples(1, 2s)) << sampled->text();
  std::this_thread::sleep_for(150ms);

  ns->helper().attribute_changed(n->node_id(), AttributeId::Value, DataValue{Variant{int32_t{7}}});
  std::this_thread::sleep_for(200ms);

  EXPECT_EQ(reportedOne->samples_of(7), 1u) << reportedOne->text();
  EXPECT_EQ(reportedTwo->samples_of(7), 1u) << reportedTwo->text();
  EXPECT_EQ(displayName->events().size(), 0u) << displayName->text();
  EXPECT_EQ(otherNode->events().size(), 0u) << otherNode->text();
  EXPECT_EQ(sampled->samples_of(7), 0u) << sampled->text();
}

// DL-68 (6) and Part 4 5.12.1.6: a Sampled and a Reported registration whose Node reports deleted() each
// receive Bad_NodeIdUnknown once over three ticks, and a change reported after the switch is not delivered.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-INVALIDATION-01-TOMBSTONE-LIFECYCLE, scope=function)
TEST_F(MonitoringHelperIndex, ADeletedNodeDeliversBadNodeIdUnknownOnce)
{
  auto ns = registered_namespace("urn:test:monitoring-helper:deleted");
  const NodeId nodeId{ns->context_copy().index(), 10u};
  auto node = switchable(nodeId, Variant{int32_t{5}});
  auto sampledSink = sink();
  auto reportedSink = sink();
  const std::vector<Helper::ResolvedMonitoringItem> items{
    resolved(nodeId, AttributeId::Value, 1, 100, sampledSink, node, Helper::Delivery::Sampled),
    resolved(nodeId, AttributeId::Value, 2, 0, reportedSink, node, Helper::Delivery::Reported),
  };
  const auto created = ns->helper().create_monitoring(items);
  ASSERT_EQ(created.size(), 2u);
  ASSERT_TRUE(created[0].result.is_good()) << to_string(created[0].result.status_code());
  ASSERT_TRUE(created[1].result.is_good()) << to_string(created[1].result.status_code());
  ASSERT_TRUE(sampledSink->wait_for_samples(1, 2s)) << sampledSink->text();

  node->mark_deleted();
  ns->helper().attribute_changed(nodeId, AttributeId::Value, DataValue{Variant{int32_t{9}}});
  std::this_thread::sleep_for(400ms);

  const StatusCode nodeIdUnknown{Status::BadNodeIdUnknown};
  for (const auto& [target, id] :
    {std::pair{sampledSink, IntegerId{1}}, std::pair{reportedSink, IntegerId{2}}})
  {
    const auto events = target->events();
    size_t notices = 0;
    bool sampleAfterNotice = false;
    for (const auto& event : events)
    {
      if (event.notice)
      {
        EXPECT_EQ(event.status, nodeIdUnknown) << "item " << id;
        EXPECT_EQ(event.monitoredItemId, id);
        ++notices;
      }
      else if (notices > 0)
      {
        sampleAfterNotice = true;
      }
    }
    EXPECT_EQ(notices, 1u) << "item " << id << ": " << target->text();
    EXPECT_FALSE(sampleAfterNotice) << "item " << id << ": " << target->text();
  }
  EXPECT_EQ(reportedSink->samples_of(9), 0u) << reportedSink->text();
}

// DL-68 (6): a deletion that lands during the tick's read gives one notice in place of what was read, not a
// sample of the failed read and then a notice.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-INVALIDATION-01-A-DELETION-DURING-THE-READ-IS-ONE-NOTICE, scope=function)
TEST_F(MonitoringHelperIndex, ADeletionDuringTheReadIsOneNotice)
{
  auto ns = registered_namespace("urn:test:monitoring-helper:during-read");
  const NodeId nodeId{ns->context_copy().index(), 20u};
  auto node = switchable(nodeId, Variant{int32_t{5}});
  node->delete_on_read(2);
  auto target = sink();
  const std::vector<Helper::ResolvedMonitoringItem> items{
    resolved(nodeId, AttributeId::Value, 1, 50, target, node, Helper::Delivery::Sampled),
  };
  const auto created = ns->helper().create_monitoring(items);
  ASSERT_EQ(created.size(), 1u);
  ASSERT_TRUE(created[0].result.is_good()) << to_string(created[0].result.status_code());
  const Duration interval = std::max<Duration>(created[0].result.value().revisedSamplingInterval, 50);

  ASSERT_TRUE(node->wait_for_reads(2, 3s)) << "the second read was not made";
  std::this_thread::sleep_for(std::chrono::milliseconds(static_cast<int64_t>(interval * 3)) + 50ms);

  const auto events = target->events();
  ASSERT_FALSE(events.empty()) << target->text();
  EXPECT_FALSE(events.front().notice) << target->text();
  EXPECT_EQ(target->samples_of(5), 1u) << target->text();
  EXPECT_EQ(target->notices(), 1u) << target->text();
  for (const auto& event : events)
  {
    if (!event.notice)
      EXPECT_NE(event.value.status().value_or(StatusCode{Status::Good}), StatusCode{Status::BadNodeIdUnknown})
        << target->text();
  }
}

// Part 4 5.12.1.5: notifications for an item are returned in queue order, so a value sampled before the
// deletion reaches the sink before the deletion's notice, and no notice overtakes a push in progress.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-INVALIDATION-01-A-SAMPLE-READ-BEFORE-THE-DELETION-PRECEDES-THE-NOTICE, scope=function)
TEST_F(MonitoringHelperIndex, ASampleReadBeforeTheDeletionPrecedesTheNotice)
{
  auto ns = registered_namespace("urn:test:monitoring-helper:order");
  const NodeId nodeId{ns->context_copy().index(), 30u};
  auto node = switchable(nodeId, Variant{int32_t{5}});
  auto target = sink();
  target->block_pushes();
  const std::vector<Helper::ResolvedMonitoringItem> items{
    resolved(nodeId, AttributeId::Value, 1, 50, target, node, Helper::Delivery::Sampled),
  };
  const auto created = ns->helper().create_monitoring(items);
  ASSERT_EQ(created.size(), 1u);
  ASSERT_TRUE(created[0].result.is_good()) << to_string(created[0].result.status_code());
  const Duration interval = std::max<Duration>(created[0].result.value().revisedSamplingInterval, 50);

  ASSERT_TRUE(target->wait_for_push_entered(3s)) << "no push was made";
  node->mark_deleted();
  std::this_thread::sleep_for(std::chrono::milliseconds(static_cast<int64_t>(interval * 3)));
  EXPECT_EQ(target->notices(), 0u) << "a notice arrived while a push was blocked; " << target->text();

  target->release_pushes();
  ASSERT_TRUE(target->wait_for_notices(1, 1s)) << target->text();
  const auto events = target->events();
  ASSERT_GE(events.size(), 2u) << target->text();
  EXPECT_FALSE(events[0].notice) << target->text();
  EXPECT_EQ(target->samples_of(5), 1u) << target->text();
  EXPECT_TRUE(events.back().notice) << target->text();
  EXPECT_EQ(target->notices(), 1u) << target->text();
}

// NR-47 rule 7: the address space shuts every registration's helper down, awaiting its tick in flight, before
// it calls the namespaces' shutdown_async, and the tick in flight pushes nothing once shutdown has begun.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-HELPER-04-THE-ADDRESS-SPACE-SHUTS-THE-HELPER-BEFORE-THE-NAMESPACE, scope=function)
TEST_F(MonitoringHelperShutdown, TheAddressSpaceShutsTheHelperBeforeTheNamespace)
{
  auto ns = registered_namespace("urn:test:monitoring-helper:shutdown");
  const NodeId nodeId{ns->context_copy().index(), 40u};
  auto node = switchable(nodeId, Variant{int32_t{5}});
  node->hold_reads();
  std::atomic<bool> calledWhileReadHeld{false};
  ns->on_shutdown(
    [&calledWhileReadHeld, node] { calledWhileReadHeld = calledWhileReadHeld || node->is_read_held(); });
  auto target = sink();
  const std::vector<Helper::ResolvedMonitoringItem> items{
    resolved(nodeId, AttributeId::Value, 1, 50, target, node, Helper::Delivery::Sampled),
  };
  const auto created = ns->helper().create_monitoring(items);
  ASSERT_EQ(created.size(), 1u);
  ASSERT_TRUE(created[0].result.is_good()) << to_string(created[0].result.status_code());
  ASSERT_TRUE(node->wait_for_held_read(3s)) << "no tick read the Value";

  auto done = std::make_shared<std::promise<VoidResult>>();
  auto shutdown = done->get_future();
  mAddressSpace->shutdown_async([done](VoidResult result) { done->set_value(std::move(result)); });
  std::this_thread::sleep_for(200ms);
  EXPECT_EQ(ns->shutdown_calls(), 0) << "the namespace was shut down while the helper's read was held";
  EXPECT_NE(shutdown.wait_for(0ms), std::future_status::ready)
    << "the shutdown completed while a read was held";

  node->release_reads();
  ASSERT_EQ(shutdown.wait_for(5s), std::future_status::ready) << "the shutdown did not complete";
  EXPECT_TRUE(shutdown.get().is_good());
  EXPECT_EQ(ns->shutdown_calls(), 1);
  EXPECT_FALSE(calledWhileReadHeld.load());
  std::this_thread::sleep_for(100ms);
  EXPECT_EQ(target->samples(), 0u) << "the released read was pushed; " << target->text();
}

// Part 4 5.12.1.2: a Value item's interval is at least the MinimumSamplingInterval however the Server learns
// of a change, so a Reported Value registration at interval 0 on a Node whose minimum is 500 is revised to at
// least 500 and delivers the latest value at each tick, not every change.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-HELPER-02-A-REPORTED-VALUE-KEEPS-THE-MINIMUM-SAMPLING-INTERVAL, scope=function)
TEST_F(MonitoringHelperIndex, AReportedValueKeepsTheMinimumSamplingInterval)
{
  auto ns = registered_namespace("urn:test:monitoring-helper:reported-minimum");
  auto n = variable(*ns, 50u, Variant{int32_t{0}});
  mAddressSpace->find_node_sync(n->node_id())
    .write_attribute_sync(AttributeId::MinimumSamplingInterval, Variant{Duration{500}});
  auto target = sink();
  const std::vector<Helper::ResolvedMonitoringItem> items{
    resolved(n->node_id(), AttributeId::Value, 1, 0, target, n, Helper::Delivery::Reported),
  };
  const auto created = ns->helper().create_monitoring(items);
  ASSERT_EQ(created.size(), 1u);
  ASSERT_TRUE(created[0].result.is_good()) << to_string(created[0].result.status_code());
  EXPECT_GE(created[0].result.value().revisedSamplingInterval, 500);

  for (const int32_t value : {1, 2, 3})
  {
    ns->helper().attribute_changed(n->node_id(), AttributeId::Value, DataValue{Variant{value}});
    std::this_thread::sleep_for(20ms);
  }
  std::this_thread::sleep_for(1500ms);

  EXPECT_GE(target->samples_of(3), 1u) << target->text();
  const bool every = target->samples_of(1) > 0 && target->samples_of(2) > 0 && target->samples_of(3) > 0;
  EXPECT_FALSE(every) << "every change was delivered; " << target->text();
}

// COMP-SVR-NAMESPACE-MONITORING-HELPER-03 rule 3: values reported and not yet delivered when a modify changes
// a Reported registration's interval, from 0 to 1000 or from 1000 to 0, are delivered after it.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-HELPER-03-A-MODIFY-DELIVERS-THE-REPORTED-VALUES-STILL-PENDING, scope=function)
TEST_F(MonitoringHelperModifyReported, AModifyDeliversTheReportedValuesStillPending)
{
  auto ns = registered_namespace("urn:test:monitoring-helper:modify-pending");
  auto n = variable(*ns, 60u, Variant{int32_t{0}});
  auto m = variable(*ns, 61u, Variant{int32_t{0}});
  auto nSink = sink();
  auto mSink = sink();
  const std::vector<Helper::ResolvedMonitoringItem> items{
    resolved(n->node_id(), AttributeId::Value, 1, 0, nSink, n, Helper::Delivery::Reported),
    resolved(m->node_id(), AttributeId::Value, 2, 1000, mSink, m, Helper::Delivery::Reported),
  };
  const auto created = ns->helper().create_monitoring(items);
  ASSERT_EQ(created.size(), 2u);
  ASSERT_TRUE(created[0].result.is_good()) << to_string(created[0].result.status_code());
  ASSERT_TRUE(created[1].result.is_good()) << to_string(created[1].result.status_code());
  // A Reported registration is given nothing until a change; this lets anything the creates started settle.
  std::this_thread::sleep_for(100ms);

  ns->helper().attribute_changed(n->node_id(), AttributeId::Value, DataValue{Variant{int32_t{1}}});
  ns->helper().attribute_changed(n->node_id(), AttributeId::Value, DataValue{Variant{int32_t{2}}});
  const std::vector<Helper::ResolvedMonitoringModifyItem> modifyN{
    {MonitoringModifyItem{created[0].result.value().handle, 1000, 10}, Helper::Delivery::Reported},
  };
  const auto modifiedN = ns->helper().modify_monitoring(modifyN);
  ASSERT_EQ(modifiedN.size(), 1u);
  EXPECT_TRUE(modifiedN[0].result.is_good()) << to_string(modifiedN[0].result.status_code());

  ns->helper().attribute_changed(m->node_id(), AttributeId::Value, DataValue{Variant{int32_t{7}}});
  const std::vector<Helper::ResolvedMonitoringModifyItem> modifyM{
    {MonitoringModifyItem{created[1].result.value().handle, 0, 10}, Helper::Delivery::Reported},
  };
  const auto modifiedM = ns->helper().modify_monitoring(modifyM);
  ASSERT_EQ(modifiedM.size(), 1u);
  EXPECT_TRUE(modifiedM[0].result.is_good()) << to_string(modifiedM[0].result.status_code());

  std::this_thread::sleep_for(2500ms);

  EXPECT_GE(nSink->samples_of(2), 1u) << "N: " << nSink->text();
  EXPECT_GE(mSink->samples_of(7), 1u) << "M: " << mSink->text();
}

// NR-47 rule 7: each registration's helper is shut down before its own namespace's shutdown_async, so a
// namespace whose helper has no tick in flight is shut down while another registration's helper awaits a held
// read.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-HELPER-04-A-SLOW-HELPER-HOLDS-BACK-ONLY-ITS-OWN-NAMESPACE, scope=function)
TEST_F(MonitoringHelperShutdown, ASlowHelperHoldsBackOnlyItsOwnNamespace)
{
  auto slow = registered_namespace("urn:test:monitoring-helper:slow");
  auto prompt = registered_namespace("urn:test:monitoring-helper:prompt");
  const NodeId slowId{slow->context_copy().index(), 70u};
  const NodeId promptId{prompt->context_copy().index(), 71u};
  auto slowNode = switchable(slowId, Variant{int32_t{5}});
  auto promptNode = switchable(promptId, Variant{int32_t{6}});
  slowNode->hold_reads();
  const std::vector<Helper::ResolvedMonitoringItem> slowItems{
    resolved(slowId, AttributeId::Value, 1, 50, sink(), slowNode, Helper::Delivery::Sampled),
  };
  const std::vector<Helper::ResolvedMonitoringItem> promptItems{
    resolved(promptId, AttributeId::Value, 2, 50, sink(), promptNode, Helper::Delivery::Sampled),
  };
  const auto slowCreated = slow->helper().create_monitoring(slowItems);
  const auto promptCreated = prompt->helper().create_monitoring(promptItems);
  ASSERT_EQ(slowCreated.size(), 1u);
  ASSERT_EQ(promptCreated.size(), 1u);
  ASSERT_TRUE(slowCreated[0].result.is_good()) << to_string(slowCreated[0].result.status_code());
  ASSERT_TRUE(promptCreated[0].result.is_good()) << to_string(promptCreated[0].result.status_code());
  ASSERT_TRUE(slowNode->wait_for_held_read(3s)) << "no tick read the slow namespace's Value";

  auto done = std::make_shared<std::promise<VoidResult>>();
  auto shutdown = done->get_future();
  mAddressSpace->shutdown_async([done](VoidResult result) { done->set_value(std::move(result)); });
  std::this_thread::sleep_for(300ms);
  EXPECT_EQ(prompt->shutdown_calls(), 1) << "the namespace whose helper had no read held was not shut down";
  EXPECT_EQ(slow->shutdown_calls(), 0) << "the namespace was shut down while its helper's read was held";

  slowNode->release_reads();
  ASSERT_EQ(shutdown.wait_for(5s), std::future_status::ready) << "the shutdown did not complete";
  EXPECT_TRUE(shutdown.get().is_good());
  EXPECT_EQ(slow->shutdown_calls(), 1);
  EXPECT_EQ(prompt->shutdown_calls(), 1);
}

namespace
{

/// A Property Node in @p ns with the BrowseName @p browseName and, when @p semanticFlag, the SemanticChange
/// bit of AccessLevelEx.
std::shared_ptr<Node> property_node(
  ExposedNamespace& ns, uint32_t identifier, const QualifiedName& browseName, bool semanticFlag)
{
  const NodeId nodeId{ns.context_copy().index(), identifier};
  auto node = ns.create_node<default_ns::VariableNode>(nodeId);
  write_value(node, Variant{double{1.0}});
  auto written = std::make_shared<std::promise<VoidResult>>();
  auto done = written->get_future();
  node->write_attribute_async(AttributeId::BrowseName,
    Variant{browseName},
    [written](VoidResult result) { written->set_value(result); });
  EXPECT_EQ(done.wait_for(2s), std::future_status::ready);
  EXPECT_TRUE(done.get().is_good());
  if (semanticFlag)
  {
    const AccessLevelExType flagged{
      AccessLevelExType::Bit::CurrentRead, AccessLevelExType::Bit::SemanticChange};
    auto flagWritten = std::make_shared<std::promise<VoidResult>>();
    auto flagDone = flagWritten->get_future();
    node->write_attribute_async(AttributeId::AccessLevelEx,
      Variant{uint32_t{flagged.as_underlying_type()}},
      [flagWritten](VoidResult result) { flagWritten->set_value(result); });
    EXPECT_EQ(flagDone.wait_for(2s), std::future_status::ready);
    EXPECT_TRUE(flagDone.get().is_good());
  }
  return node;
}

/// Registers a Reported item on the Value of @p owner, whose changes reach @p recording.
void monitor_value(ExposedNamespace& ns, const std::shared_ptr<default_ns::VariableNode>& owner, IntegerId itemId,
  std::shared_ptr<RecordingSink> recording)
{
  const std::vector<Helper::ResolvedMonitoringItem> items{resolved(owner->node_id(),
    AttributeId::Value,
    itemId,
    0,
    std::move(recording),
    owner,
    Helper::Delivery::Reported)};
  const auto created = ns.helper().create_monitoring(items);
  ASSERT_EQ(created.size(), 1u);
  ASSERT_TRUE(created[0].result.is_good()) << to_string(created[0].result.status_code());
}

}  // namespace

// A Property that Part 8 names as semantic marks the Value registrations of its owner, and no
// SemanticChangeEvent is due while the flag is not set.
// @relation(AC-COMP-ADDRSP-SEMANTICS-03-THE-PROPERTY-DECIDES, scope=function)
TEST_F(NamespaceMonitoringSupportSemantics, ASemanticPropertyMarksTheOwnersValueItems)
{
  auto ns = registered_namespace("urn:test:monitoring-helper:semantics:mark");
  auto owner = variable(*ns, 1u, Variant{int32_t{1}});
  auto property = property_node(*ns, 2u, QualifiedName{0, "EURange"}, false);
  auto marked = sink();
  monitor_value(*ns, owner, 11, marked);

  const bool eventDue = ns->helper().property_value_changed(owner->node_id(), *property, false);

  EXPECT_FALSE(eventDue);
  EXPECT_EQ(marked->semantics_marks(), std::vector<IntegerId>{11});
}

// A Property that is neither flagged nor named by Part 8 marks nothing.
// @relation(AC-COMP-ADDRSP-SEMANTICS-03-THE-PROPERTY-DECIDES, scope=function)
TEST_F(NamespaceMonitoringSupportSemantics, AnotherPropertyMarksNothing)
{
  auto ns = registered_namespace("urn:test:monitoring-helper:semantics:other");
  auto owner = variable(*ns, 1u, Variant{int32_t{1}});
  auto property = property_node(*ns, 2u, QualifiedName{0, "Definition"}, false);
  auto unmarked = sink();
  monitor_value(*ns, owner, 11, unmarked);

  const bool eventDue = ns->helper().property_value_changed(owner->node_id(), *property, false);

  EXPECT_FALSE(eventDue);
  EXPECT_TRUE(unmarked->semantics_marks().empty());
}

// A SemanticChangeEvent is due for a flagged Property's change but not for the write that gave it its first
// Value; the owner's items are marked in both cases.
// @relation(AC-COMP-ADDRSP-SEMANTICS-03-THE-PROPERTY-DECIDES, scope=function)
TEST_F(NamespaceMonitoringSupportSemantics, AnEventIsDueOnlyForAFlaggedChange)
{
  auto ns = registered_namespace("urn:test:monitoring-helper:semantics:event");
  auto owner = variable(*ns, 1u, Variant{int32_t{1}});
  auto property = property_node(*ns, 2u, QualifiedName{2, "Flagged"}, true);
  auto marked = sink();
  monitor_value(*ns, owner, 11, marked);

  EXPECT_TRUE(ns->helper().property_value_changed(owner->node_id(), *property, false));
  EXPECT_FALSE(ns->helper().property_value_changed(owner->node_id(), *property, true));

  EXPECT_EQ(marked->semantics_marks(), (std::vector<IntegerId>{11, 11}));
}
