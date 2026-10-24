// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <boost/asio/thread_pool.hpp>
#include <gtest/gtest.h>

#include "counting_executor.h"
#include "every_node_in_view_namespace.h"
#include "ua_default_namespace.h"
#include "ua_history_namespace.h"
#include "ua_address_space.h"
#include "ua_base_event.h"
#include "ua_event_bus.h"
#include "ua_event_bus_test_access.h"
#include "ua_event_notifier_type.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"
#include "ua_log_entry.h"
#include "ua_log_level.h"
#include "ua_log_sink.h"
#include "ua_logger.h"
#include "ua_server.h"
#include "ua_status_code.h"
#include "ua_to_string.h"
#include "test_components.h"
#include "test_utilities.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

namespace
{

constexpr auto dispatchTimeout = 1s;

const NodeId serverObjectId{ObjectId::Server};
const NodeId areaNodeId{0, 10000u};
const NodeId deviceNodeId{0, 10001u};

/// Thread-safe delivery recorder. Owned via shared_ptr so the lambda the test
/// registers with EventBus (which lives in the registry and in any in-flight
/// DispatchEventFlow snapshot) keeps the tracker alive past the test body.
class DeliveryTracker
{
public:
  void on_event(IntegerId monitoredItemId, std::shared_ptr<const BaseEvent> event)
  {
    std::lock_guard lock(mMutex);
    mDeliveries.emplace_back(monitoredItemId, std::move(event));
    mCv.notify_all();
  }

  size_t delivery_count() const
  {
    std::lock_guard lock(mMutex);
    return mDeliveries.size();
  }

  std::vector<std::pair<IntegerId, std::shared_ptr<const BaseEvent>>> deliveries() const
  {
    std::lock_guard lock(mMutex);
    return mDeliveries;
  }

  /// Block until at least `expected` deliveries have been recorded, or until
  /// `timeout` elapses. Returns true if reached.
  bool wait_for_count(size_t expected, std::chrono::milliseconds timeout)
  {
    std::unique_lock lock(mMutex);
    return mCv.wait_for(lock, timeout, [&]() { return mDeliveries.size() >= expected; });
  }

private:
  mutable std::mutex mMutex;
  std::condition_variable mCv;
  std::vector<std::pair<IntegerId, std::shared_ptr<const BaseEvent>>> mDeliveries;
};

/// Test fixture that sets up an address space with:
///   Server (ns=0, i=2253) [SubscribeToEvents]
///     HasNotifier -> Area (ns=0, i=10000) [SubscribeToEvents]
///       HasNotifier -> Device (ns=0, i=10001) [SubscribeToEvents]
class EventBusTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mIdleCounter = std::make_shared<ua::test_helpers::ExecutorIdleCounter>();
    boost::asio::any_io_executor wrappedExecutor{
      ua::test_helpers::CountingExecutor{mThreadPool.get_executor(), mIdleCounter}};
    mAddressSpace = AddressSpace::create("uri:test", std::move(wrappedExecutor));

    // Create the Server Object in the test address space (NS0 nodeset is not loaded).
    auto serverResult = mAddressSpace->try_create_sync<ObjectAccessor>(serverObjectId, NodeClass::Object);
    ASSERT_TRUE(serverResult.is_good()) << "Failed to create Server Object";
    {
      EventNotifierType notifier{EventNotifierType::Bit::SubscribeToEvents};
      serverResult.value().set_event_notifier(notifier);
    }

    // Create Area node with SubscribeToEvents
    auto areaResult = mAddressSpace->try_create_sync<ObjectAccessor>(areaNodeId, NodeClass::Object);
    ASSERT_TRUE(areaResult.is_good());
    {
      auto& area = areaResult.value();
      EventNotifierType notifier{EventNotifierType::Bit::SubscribeToEvents};
      area.set_event_notifier(notifier);

      // Server HasNotifier -> Area (forward on Server, inverse on Area)
      auto serverNode = mAddressSpace->try_find_node_sync(serverObjectId);
      ASSERT_TRUE(serverNode.is_good());
      serverNode.value().add_reference_sync(NodeId{ReferenceTypeId::HasNotifier}, areaNodeId, true);
      area.add_reference_sync(NodeId{ReferenceTypeId::HasNotifier}, serverObjectId, false);
    }

    // Create Device node with SubscribeToEvents
    auto deviceResult = mAddressSpace->try_create_sync<ObjectAccessor>(deviceNodeId, NodeClass::Object);
    ASSERT_TRUE(deviceResult.is_good());
    {
      auto& device = deviceResult.value();
      EventNotifierType notifier{EventNotifierType::Bit::SubscribeToEvents};
      device.set_event_notifier(notifier);

      // Area HasNotifier -> Device (forward on Area, inverse on Device)
      auto areaNode = mAddressSpace->try_find_node_sync(areaNodeId);
      ASSERT_TRUE(areaNode.is_good());
      areaNode.value().add_reference_sync(NodeId{ReferenceTypeId::HasNotifier}, deviceNodeId, true);
      device.add_reference_sync(NodeId{ReferenceTypeId::HasNotifier}, areaNodeId, false);
    }

    mEventBus = std::make_shared<EventBus>(*mAddressSpace);
  }

  void TearDown() override
  {
    // Drain pending pool work so it doesn't reference fixture state during
    // teardown. EventBus posts via weak_from_this so late deliveries no-op
    // safely once the bus is reset, but draining first keeps lifetimes tidy.
    mIdleCounter->wait_for_idle(dispatchTimeout);
    mEventBus.reset();
    mAddressSpace.reset();
    mThreadPool.join();
  }

  BaseEvent make_event(NodeId sourceNode, uint16_t severity = 500)
  {
    BaseEvent event;
    event.eventType = NodeId{ObjectTypeId::BaseEventType};
    event.sourceNode = std::move(sourceNode);
    event.sourceName = String{"Test"};
    event.message = LocalizedText{LocaleId{}, String{"Test event"}};
    event.severity = severity;
    return event;
  }

  /// Block until the address-space pool reports no outstanding work. Use
  /// before asserting "no delivery" (negative assertions cannot wait on a
  /// count).
  void wait_idle()
  {
    ASSERT_TRUE(mIdleCounter->wait_for_idle(dispatchTimeout));
  }

  /// An Object with the SubscribeToEvents bit.
  void make_notifier(const NodeId& nodeId)
  {
    auto created = mAddressSpace->try_create_sync<ObjectAccessor>(nodeId, NodeClass::Object);
    ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
    created.value().set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
  }

  /// A Reference of @p referenceType from @p source to @p target, with its inverse on @p target. The address
  /// space adds the inverse half of a HasSubtype itself (NR-70 B8).
  void link(const NodeId& source, const NodeId& referenceType, const NodeId& target)
  {
    auto sourceNode = mAddressSpace->try_find_node_sync(source);
    ASSERT_TRUE(sourceNode.is_good()) << to_string(source);
    ASSERT_TRUE(
      sourceNode.value().try_add_reference_sync(referenceType, ExpandedNodeId{target}, true).is_good());
    auto targetNode = mAddressSpace->try_find_node_sync(target);
    ASSERT_TRUE(targetNode.is_good()) << to_string(target);
    if (referenceType == NodeId{ReferenceTypeId::HasSubtype} || referenceType == NodeId{ReferenceTypeId::HasEncoding})
    {
      return;
    }
    ASSERT_TRUE(
      targetNode.value().try_add_reference_sync(referenceType, ExpandedNodeId{source}, false).is_good());
  }

  /// A ReferenceType Node, created when absent; this fixture's namespace 0 holds no type Nodes.
  void ensure_reference_type(const NodeId& referenceTypeId)
  {
    if (mAddressSpace->try_find_node_sync(referenceTypeId).is_good())
      return;
    ASSERT_TRUE(
      mAddressSpace->try_create_sync<ReferenceTypeAccessor>(referenceTypeId, NodeClass::ReferenceType)
        .is_good());
  }

  /// HasEventSource (i=36) and its subtype HasNotifier (i=48), as the namespace-0 NodeSet provides them, so a
  /// supertype walk from an application subtype of HasNotifier can reach HasEventSource.
  void add_event_source_reference_types()
  {
    const NodeId hasEventSource{ReferenceTypeId::HasEventSource};
    const NodeId hasNotifier{ReferenceTypeId::HasNotifier};
    ensure_reference_type(hasEventSource);
    ensure_reference_type(hasNotifier);
    link(hasEventSource, NodeId{ReferenceTypeId::HasSubtype}, hasNotifier);
  }

  /// Registers an Event item on @p nodeId whose deliveries @p tracker records.
  void subscribe(
    const NodeId& nodeId, IntegerId monitoredItemId, const std::shared_ptr<DeliveryTracker>& tracker)
  {
    mEventBus->register_event_item(nodeId,
      monitoredItemId,
      0,
      [tracker](IntegerId id, std::shared_ptr<const BaseEvent> ev) { tracker->on_event(id, ev); });
  }

  /// The fixture's executor, counted by the idle counter.
  boost::asio::any_io_executor counting_executor()
  {
    return boost::asio::any_io_executor{
      ua::test_helpers::CountingExecutor{mThreadPool.get_executor(), mIdleCounter}};
  }

  /// Registers @p ns and creates in it a View Node with the SubscribeToEvents bit; returns its NodeId.
  NodeId make_subscribable_view(const std::shared_ptr<ua::test::EveryNodeInViewNamespace>& ns, uint32_t id)
  {
    const auto nsIndex = mAddressSpace->try_add_namespace_sync(ns);
    EXPECT_TRUE(nsIndex.is_good()) << to_string(nsIndex.status_code());
    const NodeId viewId{nsIndex.is_good() ? nsIndex.value() : uint16_t{0}, id};
    ns->create_node(viewId, NodeClass::View);
    auto view = mAddressSpace->try_find_node_sync(viewId);
    EXPECT_TRUE(view.is_good()) << to_string(view.status_code());
    if (view.is_good())
    {
      auto accessor = view.value().as<ViewAccessor>();
      EXPECT_TRUE(accessor.has_value());
      if (accessor)
        accessor->set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
    }
    return viewId;
  }

  boost::asio::thread_pool mThreadPool{1};
  std::shared_ptr<ua::test_helpers::ExecutorIdleCounter> mIdleCounter;
  optional<AddressSpace> mAddressSpace;
  std::shared_ptr<EventBus> mEventBus;
};

/// Records every entry's level, category and message.
class RecordingLogSink final : public LogSink
{
public:
  struct Entry
  {
    LogLevel level;
    std::string category;
    std::string message;
    std::string status;
  };

  void log(const LogEntry& entry) override
  {
    std::string status;
    for (const auto& field : entry.fields)
    {
      if (field.key == "status")
      {
        if (const auto* text = std::get_if<std::string_view>(&field.value))
          status = std::string{*text};
      }
    }
    const std::lock_guard lock{mMutex};
    mEntries.push_back(Entry{entry.level, std::string{entry.category}, entry.message, std::move(status)});
  }

  /// The entries of @p level in @p category whose structured `status` field is @p status.
  std::size_t count_with_status(LogLevel level, std::string_view category, std::string_view status) const
  {
    const std::lock_guard lock{mMutex};
    return static_cast<std::size_t>(std::count_if(mEntries.begin(),
      mEntries.end(),
      [&](const Entry& entry)
      { return entry.level == level && entry.category == category && entry.status == status; }));
  }

  std::size_t count(LogLevel level, std::string_view category, std::string_view message) const
  {
    const std::lock_guard lock{mMutex};
    return static_cast<std::size_t>(std::count_if(mEntries.begin(),
      mEntries.end(),
      [&](const Entry& entry)
      {
        return entry.level == level && entry.category == category &&
               entry.message.find(message) != std::string::npos;
      }));
  }

private:
  mutable std::mutex mMutex;
  std::vector<Entry> mEntries;
};

/// The membership answers of a test View, set by the test between Events and asked on the bus's threads.
class MembershipScript
{
public:
  void set(std::unordered_map<NodeId, BoolResult> answers)
  {
    const std::lock_guard lock{mMutex};
    mAnswers = std::move(answers);
  }

  /// The answer set for @p nodeId; false for a NodeId the test did not script.
  BoolResult answer(const NodeId& nodeId)
  {
    const std::lock_guard lock{mMutex};
    const auto found = mAnswers.find(nodeId);
    if (found == mAnswers.end())
      return BoolResult{false};
    if (found->second.status_code().is_uncertain())
      ++mUncertainGiven;
    return found->second;
  }

  std::size_t uncertain_answers_given() const
  {
    const std::lock_guard lock{mMutex};
    return mUncertainGiven;
  }

private:
  mutable std::mutex mMutex;
  std::unordered_map<NodeId, BoolResult> mAnswers;
  std::size_t mUncertainGiven{0};
};

}  // namespace

// ============================================================================
// Auto-fill
// ============================================================================

TEST_F(EventBusTest, AutoFillsEventId)
{
  // SVR-EVT-BET-003: unique EventId. auto_fill() runs synchronously inside emit()
  // before dispatch is posted, so no wait is needed for this assertion.
  auto tracker = std::make_shared<DeliveryTracker>();
  mEventBus->register_event_item(serverObjectId,
    1,
    0,
    [tracker](IntegerId id, std::shared_ptr<const BaseEvent> ev) { tracker->on_event(id, ev); });

  auto event = make_event(deviceNodeId);
  EXPECT_TRUE(event.eventId.empty());

  mEventBus->emit(event);

  EXPECT_FALSE(event.eventId.empty());
}

TEST_F(EventBusTest, AutoFillsReceiveTime)
{
  // SVR-EVT-BET-005: ReceiveTime always set
  auto event = make_event(deviceNodeId);
  EXPECT_TRUE(event.receiveTime.is_null());

  mEventBus->emit(event);

  EXPECT_FALSE(event.receiveTime.is_null());
}

TEST_F(EventBusTest, AutoFillsTimeIfNull)
{
  auto event = make_event(deviceNodeId);
  EXPECT_TRUE(event.time.is_null());

  mEventBus->emit(event);

  EXPECT_FALSE(event.time.is_null());
}

TEST_F(EventBusTest, PreservesTimeIfAlreadySet)
{
  // SVR-EVT-BET-004: don't overwrite Time if set
  auto event = make_event(deviceNodeId);
  auto originalTime = DateTime{2025, 1, 1, 12, 0, 0.0};
  event.time = originalTime;

  mEventBus->emit(event);

  EXPECT_EQ(event.time, originalTime);
}

TEST_F(EventBusTest, UniqueEventIds)
{
  // SVR-EVT-BET-003: each event gets a unique EventId
  auto event1 = make_event(deviceNodeId);
  auto event2 = make_event(deviceNodeId);

  mEventBus->emit(event1);
  mEventBus->emit(event2);

  EXPECT_NE(event1.eventId, event2.eventId);
}

// ============================================================================
// Routing: Server Object receives all events
// ============================================================================

TEST_F(EventBusTest, ServerObjectReceivesAllEvents)
{
  // SVR-EVT-SRV-002: all events reach Server Object subscriber
  auto tracker = std::make_shared<DeliveryTracker>();
  mEventBus->register_event_item(serverObjectId,
    1,
    0,
    [tracker](IntegerId id, std::shared_ptr<const BaseEvent> ev) { tracker->on_event(id, ev); });

  auto event = make_event(deviceNodeId, 500);
  mEventBus->emit(event);

  ASSERT_TRUE(tracker->wait_for_count(1, dispatchTimeout));
  EXPECT_EQ(tracker->delivery_count(), 1u);

  auto deliveries = tracker->deliveries();
  EXPECT_EQ(deliveries[0].first, 1u);
  EXPECT_EQ(deliveries[0].second->severity, 500);
}

TEST_F(EventBusTest, ServerObjectReceivesEventsFromMultipleSources)
{
  // SVR-EVT-SRV-002: events from different sources all arrive
  auto tracker = std::make_shared<DeliveryTracker>();
  mEventBus->register_event_item(serverObjectId,
    1,
    0,
    [tracker](IntegerId id, std::shared_ptr<const BaseEvent> ev) { tracker->on_event(id, ev); });

  auto event1 = make_event(deviceNodeId, 100);
  auto event2 = make_event(areaNodeId, 200);
  mEventBus->emit(event1);
  mEventBus->emit(event2);

  ASSERT_TRUE(tracker->wait_for_count(2, dispatchTimeout));
  EXPECT_EQ(tracker->delivery_count(), 2u);
}

TEST_F(EventBusTest, EventEmittedBeforeRegistrationIsNotDeliveredToNewItem)
{
  // OPC 10000-9 section 4.5: Event Notifications begin at subscription time - "the
  // currently existing state will not be reported." An Event emitted BEFORE a
  // MonitoredItem is created must NOT be delivered to it (prior state is
  // obtainable only via ConditionRefresh).
  //
  // Regression for the intermittent COND-1802 (Subscription_DisableEventHasRetain
  // False) failure: emit() snapshotted the registry AFTER the async EventType-
  // hierarchy resolution. On a cache miss that resolution reposts onto the
  // dispatch strand, so a register_event_item posted between emit() and the
  // resolution continuation could run first and pull the brand-new MI into the
  // snapshot, wrongly delivering the earlier event to it.
  //
  // This test makes the race deterministic: emit() and register_event_item() both
  // post to the dispatch strand from this thread (emit first), and BaseEventType
  // is absent from the test address space so its hierarchy resolution is a cache
  // miss that reposts - giving the registration a window to land before the
  // (pre-fix) late snapshot. With the snapshot taken in emit order, the later
  // registration is correctly excluded.
  auto tracker = std::make_shared<DeliveryTracker>();

  auto event = make_event(serverObjectId, 500);  // Server is always in the notifier set
  mEventBus->emit(event);

  mEventBus->register_event_item(serverObjectId,
    42,
    0,
    [tracker](IntegerId id, std::shared_ptr<const BaseEvent> ev) { tracker->on_event(id, ev); });

  wait_idle();

  EXPECT_EQ(tracker->delivery_count(), 0u)
    << "an event emitted before the MonitoredItem was registered must not be delivered to it";
}

// ============================================================================
// Routing: HasNotifier propagation
// ============================================================================

TEST_F(EventBusTest, EventPropagatesUpHasNotifierChain)
{
  // SVR-EVT-REF-008: event from Device reaches Area subscriber via HasNotifier
  auto tracker = std::make_shared<DeliveryTracker>();
  mEventBus->register_event_item(areaNodeId,
    10,
    0,
    [tracker](IntegerId id, std::shared_ptr<const BaseEvent> ev) { tracker->on_event(id, ev); });

  auto event = make_event(deviceNodeId, 700);
  mEventBus->emit(event);

  ASSERT_TRUE(tracker->wait_for_count(1, dispatchTimeout));
  auto deliveries = tracker->deliveries();
  EXPECT_EQ(deliveries[0].first, 10u);
  EXPECT_EQ(deliveries[0].second->severity, 700);
}

TEST_F(EventBusTest, EventDoesNotReachUnrelatedSubscriber)
{
  // Create an unrelated node with no HasNotifier path
  auto unrelatedId = NodeId{0, 20000u};
  auto result = mAddressSpace->try_create_sync<ObjectAccessor>(unrelatedId, NodeClass::Object);
  if (result.is_good())
  {
    EventNotifierType notifier{EventNotifierType::Bit::SubscribeToEvents};
    result.value().set_event_notifier(notifier);
  }

  auto serverTracker = std::make_shared<DeliveryTracker>();
  auto unrelatedTracker = std::make_shared<DeliveryTracker>();

  mEventBus->register_event_item(serverObjectId,
    1,
    0,
    [serverTracker](IntegerId id, std::shared_ptr<const BaseEvent> ev) { serverTracker->on_event(id, ev); });
  mEventBus->register_event_item(unrelatedId,
    2,
    0,
    [unrelatedTracker](IntegerId id, std::shared_ptr<const BaseEvent> ev)
    { unrelatedTracker->on_event(id, ev); });

  auto event = make_event(deviceNodeId, 500);
  mEventBus->emit(event);

  // Negative assertion requires draining the dispatch entirely.
  wait_idle();
  EXPECT_EQ(serverTracker->delivery_count(), 1u);
  EXPECT_EQ(unrelatedTracker->delivery_count(), 0u);
}

TEST_F(EventBusTest, EventReachesSourceNodeSubscriber)
{
  // Subscribing directly to the source node should receive the event
  auto tracker = std::make_shared<DeliveryTracker>();
  mEventBus->register_event_item(deviceNodeId,
    5,
    0,
    [tracker](IntegerId id, std::shared_ptr<const BaseEvent> ev) { tracker->on_event(id, ev); });

  auto event = make_event(deviceNodeId, 300);
  mEventBus->emit(event);

  ASSERT_TRUE(tracker->wait_for_count(1, dispatchTimeout));
  EXPECT_EQ(tracker->delivery_count(), 1u);
}

// Part 3 section 5.4: "the Server Object defined in OPC 10000-5 shall never be part of any View since it
// provides all Events of the Server". V's namespace answers that every Node is a member of V, the Server
// Object included, so only the bus's own rule keeps the Server Object's Event out of V. Device is a notifier
// and a member of V: its Event is the control that V delivers at all.
// @relation(AC-SVR-EVT-ATTR-007-SERVER-OBJECT-EVENTS-REACH-NO-VIEW, scope=function)
TEST_F(EventBusTest, TheServerObjectsEventsReachNoViewThatAnswersEveryNodeIsAMember)
{
  auto ns = ua::test::EveryNodeInViewNamespace::create("urn:test:every-node-in-view", counting_executor());
  const NodeId viewV = make_subscribable_view(ns, 23100u);
  auto atView = std::make_shared<DeliveryTracker>();
  auto atServer = std::make_shared<DeliveryTracker>();
  subscribe(viewV, 1, atView);
  subscribe(serverObjectId, 2, atServer);

  auto serverEvent = make_event(serverObjectId);
  mEventBus->emit(serverEvent);
  auto deviceEvent = make_event(deviceNodeId);
  mEventBus->emit(deviceEvent);
  ASSERT_TRUE(atServer->wait_for_count(2, dispatchTimeout))
    << "the Server Object's item did not receive both Events, so the stimulus never happened";
  wait_idle();

  std::size_t fromServerObject = 0;
  std::size_t fromDevice = 0;
  for (const auto& [id, event] : atView->deliveries())
  {
    fromServerObject += event->sourceNode == serverObjectId ? 1u : 0u;
    fromDevice += event->sourceNode == deviceNodeId ? 1u : 0u;
  }
  EXPECT_EQ(fromServerObject, 0u)
    << "the Event whose SourceNode is the Server Object was delivered through a View";
  EXPECT_EQ(fromDevice, 1u) << "the Event of Device, a notifier and a member of V, was not delivered once";
}

// Part 3 section 5.4 and section 7.18: Device's Events are provided in Area, and V provides the Events of the
// notifiers that are part of its content. An Uncertain membership answer does not say that a Node is a
// member: the bus logs it, and the other notifiers' answers still count. (1) and (2) give the Uncertain answer
// to each of the two notifiers in turn, the other being a member; (3) is the control that an Uncertain answer
// is not taken as membership.
// @relation(AC-SVR-EVT-ATTR-005-UNCERTAIN-MEMBERSHIP-SKIPS-ONLY-THAT-NOTIFIER, scope=function)
TEST_F(EventBusTest, AnUncertainMembershipAnswerSkipsOnlyThatNotifier)
{
  auto sink = std::make_shared<RecordingLogSink>();
  mAddressSpace->set_logger(Logger{sink, std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace), "test"});
  auto script = std::make_shared<MembershipScript>();
  auto ns = ua::test::EveryNodeInViewNamespace::create("urn:test:uncertain-view-membership",
    counting_executor(),
    [script](const NodeId& nodeId) { return script->answer(nodeId); });
  const NodeId viewV = make_subscribable_view(ns, 23000u);
  auto atView = std::make_shared<DeliveryTracker>();
  auto atServer = std::make_shared<DeliveryTracker>();
  subscribe(viewV, 1, atView);
  subscribe(serverObjectId, 2, atServer);
  const auto uncertain = []
  {
    return BoolResult{StatusCode{Status::Uncertain},
      ErrorDetail::build("ScriptedMembershipUncertain",
        "The test's View is not sure whether this Node is a member",
        "TestView")};
  };

  // (1) Device Uncertain, Area a member.
  script->set({{deviceNodeId, uncertain()}, {areaNodeId, BoolResult{true}}});
  auto first = make_event(deviceNodeId);
  mEventBus->emit(first);
  ASSERT_TRUE(atServer->wait_for_count(1, dispatchTimeout)) << "the first Event was not emitted";
  wait_idle();
  EXPECT_EQ(atView->delivery_count(), 1u)
    << "the first Event, whose notifier Area is a member of V, was not delivered once through V";

  // (2) Device a member, Area Uncertain.
  script->set({{deviceNodeId, BoolResult{true}}, {areaNodeId, uncertain()}});
  auto second = make_event(deviceNodeId);
  mEventBus->emit(second);
  ASSERT_TRUE(atServer->wait_for_count(2, dispatchTimeout)) << "the second Event was not emitted";
  wait_idle();
  EXPECT_EQ(atView->delivery_count(), 2u)
    << "the second Event, whose notifier Device is a member of V, was not delivered once through V";

  // (3) Device Uncertain, Area not a member.
  script->set({{deviceNodeId, uncertain()}, {areaNodeId, BoolResult{false}}});
  auto third = make_event(deviceNodeId);
  mEventBus->emit(third);
  ASSERT_TRUE(atServer->wait_for_count(3, dispatchTimeout)) << "the third Event was not emitted";
  wait_idle();
  EXPECT_EQ(atView->delivery_count(), 2u)
    << "the third Event was delivered: an Uncertain answer was taken as "
       "membership";

  // V is asked about every notifier in each Event, so the Uncertain notifier of each of (1) to (3) is asked.
  EXPECT_GE(script->uncertain_answers_given(), 2u) << "V was not asked about the Uncertain notifiers";
  EXPECT_EQ(sink->count_with_status(LogLevel::Warning, "events", to_string(StatusCode{Status::Uncertain})),
    script->uncertain_answers_given())
    << "not every Uncertain membership answer was logged as a warning in the category events naming its "
       "status";
}

// @relation(AC-SVR-EVT-ATTR-005-VIEW-AGGREGATES-EVENTS, scope=function)
TEST_F(EventBusTest, SubscribableViewReceivesAnEventSourcedByItself)
{
  const NodeId viewId{0, 21300u};
  auto view = mAddressSpace->try_create_sync<ViewAccessor>(viewId, NodeClass::View);
  ASSERT_TRUE(view.is_good());
  view.value().set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});

  auto tracker = std::make_shared<DeliveryTracker>();
  mEventBus->register_event_item(viewId,
    23,
    0,
    [tracker](IntegerId id, std::shared_ptr<const BaseEvent> event) { tracker->on_event(id, event); });

  auto event = make_event(viewId);
  mEventBus->emit(event);

  ASSERT_TRUE(tracker->wait_for_count(1, dispatchTimeout));
  EXPECT_EQ(tracker->delivery_count(), 1u);
}

// Part 3 section 5.4: a View that supports Events provides the Events "that occur in any Object used as
// EventNotifier that is part of the content of the View"; NR-28 delivers through a View the Events of those
// notifiers only. Part 5 section 6.4.31: a ModelChangeEvent for the whole AddressSpace has the Server Object
// as its SourceNode, and NR-56 generates model changes in that context only, so the bus has no case that
// delivers a model change through a View because of its type. C is a member of V and not an EventNotifier. An
// ordinary Event and a GeneralModelChangeEvent, both with SourceNode C, reach the Server Object's item (the
// control that each was emitted and delivered) and not V's. The ordinary Event's half is a guard; the
// model-change half fails while the bus asks the Views about a model change's SourceNode.
// @relation(AC-SVR-EVT-ATTR-006-VIEW-MODELCHANGE-EVENTS, scope=function)
// @relation(AC-SVR-EVT-ATTR-005-VIEW-AGGREGATES-EVENTS, scope=function)
TEST_F(EventBusTest, AViewReceivesNoEventSourcedAtContentThatIsNotANotifier)
{
  const NodeId viewId{0, 21500u};
  const NodeId contentId{0, 21501u};
  const NodeId organizes{ReferenceTypeId::Organizes};
  auto view = mAddressSpace->try_create_sync<ViewAccessor>(viewId, NodeClass::View);
  auto content = mAddressSpace->try_create_sync<ObjectAccessor>(contentId, NodeClass::Object);
  ASSERT_TRUE(view.is_good());
  ASSERT_TRUE(content.is_good());
  view.value().set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
  ASSERT_TRUE(view.value().try_add_reference_sync(organizes, ExpandedNodeId{contentId}, true).is_good());
  ASSERT_TRUE(content.value().try_add_reference_sync(organizes, ExpandedNodeId{viewId}, false).is_good());
  ASSERT_TRUE(view.value().try_add_node_to_view_sync(contentId).is_good());

  auto viewTracker = std::make_shared<DeliveryTracker>();
  mEventBus->register_event_item(viewId,
    25,
    0,
    [viewTracker](IntegerId id, std::shared_ptr<const BaseEvent> event)
    { viewTracker->on_event(id, event); });
  auto serverTracker = std::make_shared<DeliveryTracker>();
  mEventBus->register_event_item(serverObjectId,
    26,
    0,
    [serverTracker](IntegerId id, std::shared_ptr<const BaseEvent> event)
    { serverTracker->on_event(id, event); });

  auto ordinaryEvent = make_event(contentId);
  mEventBus->emit(ordinaryEvent);
  ASSERT_TRUE(serverTracker->wait_for_count(1, dispatchTimeout))
    << "the Server Object's item never received the ordinary Event, so the stimulus never happened";
  wait_idle();
  EXPECT_EQ(viewTracker->delivery_count(), 0u)
    << "an ordinary Event sourced at a member that is not an EventNotifier reached the View";

  auto modelChangeEvent = make_event(contentId);
  modelChangeEvent.eventType = NodeId{ObjectTypeId::GeneralModelChangeEventType};
  mEventBus->emit(modelChangeEvent);
  ASSERT_TRUE(serverTracker->wait_for_count(2, dispatchTimeout))
    << "the Server Object's item never received the GeneralModelChangeEvent, so the stimulus never happened";
  wait_idle();
  EXPECT_EQ(viewTracker->delivery_count(), 0u)
    << "a GeneralModelChangeEvent sourced at a member that is not an EventNotifier reached the View";
}

// ============================================================================
// Registration / Deregistration
// ============================================================================

TEST_F(EventBusTest, DeregisteredItemDoesNotReceiveEvents)
{
  auto tracker = std::make_shared<DeliveryTracker>();
  auto handle = mEventBus->register_event_item(serverObjectId,
    1,
    0,
    [tracker](IntegerId id, std::shared_ptr<const BaseEvent> ev) { tracker->on_event(id, ev); });

  mEventBus->deregister_event_item(handle);

  auto event = make_event(deviceNodeId, 500);
  mEventBus->emit(event);

  wait_idle();
  EXPECT_EQ(tracker->delivery_count(), 0u);
}

TEST_F(EventBusTest, MultipleRegistrationsOnSameNode)
{
  auto tracker1 = std::make_shared<DeliveryTracker>();
  auto tracker2 = std::make_shared<DeliveryTracker>();

  mEventBus->register_event_item(serverObjectId,
    1,
    0,
    [tracker1](IntegerId id, std::shared_ptr<const BaseEvent> ev) { tracker1->on_event(id, ev); });
  mEventBus->register_event_item(serverObjectId,
    2,
    0,
    [tracker2](IntegerId id, std::shared_ptr<const BaseEvent> ev) { tracker2->on_event(id, ev); });

  auto event = make_event(deviceNodeId, 500);
  mEventBus->emit(event);

  ASSERT_TRUE(tracker1->wait_for_count(1, dispatchTimeout));
  ASSERT_TRUE(tracker2->wait_for_count(1, dispatchTimeout));
  EXPECT_EQ(tracker1->delivery_count(), 1u);
  EXPECT_EQ(tracker2->delivery_count(), 1u);
}

// ============================================================================
// Event not delivered after deregistration
// ============================================================================

TEST_F(EventBusTest, EventNotDeliveredAfterDeletion)
{
  // SVR-EVT-SRV-002 (negative): event after MI deletion not received
  auto tracker = std::make_shared<DeliveryTracker>();
  auto handle = mEventBus->register_event_item(serverObjectId,
    1,
    0,
    [tracker](IntegerId id, std::shared_ptr<const BaseEvent> ev) { tracker->on_event(id, ev); });

  // First event should be delivered
  auto event1 = make_event(deviceNodeId, 100);
  mEventBus->emit(event1);
  ASSERT_TRUE(tracker->wait_for_count(1, dispatchTimeout));

  // Deregister
  mEventBus->deregister_event_item(handle);

  // Second event should NOT be delivered
  auto event2 = make_event(deviceNodeId, 200);
  mEventBus->emit(event2);

  wait_idle();
  EXPECT_EQ(tracker->delivery_count(), 1u);  // Only the first one
}

// ============================================================================
// TEST-BET-003-P2: 1000 unique EventIds
// ============================================================================

TEST_F(EventBusTest, ThousandUniqueEventIds)
{
  std::set<ByteString> ids;
  for (int i = 0; i < 1000; ++i)
  {
    auto event = make_event(deviceNodeId, 500);
    mEventBus->emit(event);
    ids.insert(event.eventId);
  }
  EXPECT_EQ(ids.size(), 1000u);
}

// ============================================================================
// TEST-BET-007: Severity clamping
// ============================================================================

TEST_F(EventBusTest, SeverityZeroClampedToOne)
{
  auto event = make_event(deviceNodeId, 0);
  mEventBus->emit(event);
  EXPECT_EQ(event.severity, 1);
}

TEST_F(EventBusTest, SeverityAboveMaxClampedTo1000)
{
  auto event = make_event(deviceNodeId, 1001);
  mEventBus->emit(event);
  EXPECT_EQ(event.severity, 1000);
}

TEST_F(EventBusTest, SeverityWithinRangePreserved)
{
  auto event = make_event(deviceNodeId, 500);
  mEventBus->emit(event);
  EXPECT_EQ(event.severity, 500);
}

TEST_F(EventBusTest, SeverityBoundariesPreserved)
{
  auto event1 = make_event(deviceNodeId, 1);
  mEventBus->emit(event1);
  EXPECT_EQ(event1.severity, 1);

  auto event2 = make_event(deviceNodeId, 1000);
  mEventBus->emit(event2);
  EXPECT_EQ(event2.severity, 1000);
}

// ============================================================================
// TEST-REF-008-P2: 3-level HasNotifier chain
// ============================================================================

TEST_F(EventBusTest, ThreeLevelNotifierChain)
{
  // Server -> Area -> Device
  // Subscribe on Server, emit on Device - should propagate through 3 levels
  auto serverTracker = std::make_shared<DeliveryTracker>();
  auto areaTracker = std::make_shared<DeliveryTracker>();
  auto deviceTracker = std::make_shared<DeliveryTracker>();

  mEventBus->register_event_item(serverObjectId,
    1,
    0,
    [serverTracker](IntegerId id, std::shared_ptr<const BaseEvent> ev) { serverTracker->on_event(id, ev); });
  mEventBus->register_event_item(areaNodeId,
    2,
    0,
    [areaTracker](IntegerId id, std::shared_ptr<const BaseEvent> ev) { areaTracker->on_event(id, ev); });
  mEventBus->register_event_item(deviceNodeId,
    3,
    0,
    [deviceTracker](IntegerId id, std::shared_ptr<const BaseEvent> ev) { deviceTracker->on_event(id, ev); });

  auto event = make_event(deviceNodeId, 500);
  mEventBus->emit(event);

  // All three levels should receive the event
  ASSERT_TRUE(serverTracker->wait_for_count(1, dispatchTimeout));
  ASSERT_TRUE(areaTracker->wait_for_count(1, dispatchTimeout));
  ASSERT_TRUE(deviceTracker->wait_for_count(1, dispatchTimeout));
  EXPECT_EQ(serverTracker->delivery_count(), 1u);
  EXPECT_EQ(areaTracker->delivery_count(), 1u);
  EXPECT_EQ(deviceTracker->delivery_count(), 1u);
}

// ============================================================================
// emit_to_subscription
// ============================================================================

TEST_F(EventBusTest, EmitToSubscription_DeliversToMatchingSubscription)
{
  auto sub1Tracker = std::make_shared<DeliveryTracker>();
  auto sub2Tracker = std::make_shared<DeliveryTracker>();

  // Two items on subscriptionId=1, one on subscriptionId=2
  mEventBus->register_event_item(serverObjectId,
    10,
    1,
    [sub1Tracker](IntegerId id, std::shared_ptr<const BaseEvent> ev) { sub1Tracker->on_event(id, ev); });
  mEventBus->register_event_item(serverObjectId,
    11,
    1,
    [sub1Tracker](IntegerId id, std::shared_ptr<const BaseEvent> ev) { sub1Tracker->on_event(id, ev); });
  mEventBus->register_event_item(serverObjectId,
    20,
    2,
    [sub2Tracker](IntegerId id, std::shared_ptr<const BaseEvent> ev) { sub2Tracker->on_event(id, ev); });

  auto event = make_event(deviceNodeId, 500);
  mEventBus->emit_to_subscription(1, event);

  ASSERT_TRUE(sub1Tracker->wait_for_count(2, dispatchTimeout));
  EXPECT_EQ(sub1Tracker->delivery_count(), 2u);
  EXPECT_EQ(sub2Tracker->delivery_count(), 0u);
}

TEST_F(EventBusTest, EmitToSubscription_AutoFillsEventId)
{
  auto tracker = std::make_shared<DeliveryTracker>();
  mEventBus->register_event_item(serverObjectId,
    1,
    1,
    [tracker](IntegerId id, std::shared_ptr<const BaseEvent> ev) { tracker->on_event(id, ev); });

  auto event = make_event(deviceNodeId);
  EXPECT_TRUE(event.eventId.empty());

  mEventBus->emit_to_subscription(1, event);

  EXPECT_FALSE(event.eventId.empty());
}

// A ConditionRefresh re-sends the last Event (OPC 10000-9 5.5.2), so a replay keeps the ReceiveTime that
// Event was given: a stale replay must not look newer to a client than a live transition that overtook it.
// A replay that carries none is still given one (SVR-EVT-BET-005).
TEST_F(EventBusTest, EmitToSubscription_KeepsTheReceiveTimeAReplayCarries)
{
  auto tracker = std::make_shared<DeliveryTracker>();
  mEventBus->register_event_item(serverObjectId,
    1,
    1,
    [tracker](IntegerId id, std::shared_ptr<const BaseEvent> ev) { tracker->on_event(id, ev); });

  const DateTime original{2026, 1, 2, 3, 4, 5.0};
  auto replay = make_event(deviceNodeId);
  replay.receiveTime = original;
  auto unstamped = make_event(deviceNodeId);

  mEventBus->emit_to_subscription(1, replay);
  mEventBus->emit_to_subscription(1, unstamped);

  ASSERT_TRUE(tracker->wait_for_count(2, dispatchTimeout));
  std::size_t replaysSeen = 0;
  for (const auto& [monitoredItemId, delivered] : tracker->deliveries())
  {
    static_cast<void>(monitoredItemId);
    if (delivered->eventId == replay.eventId)
    {
      ++replaysSeen;
      EXPECT_EQ(delivered->receiveTime, original) << "the replay arrives with its original ReceiveTime";
    }
    else
    {
      EXPECT_FALSE(delivered->receiveTime.is_null()) << "an event without one is still stamped";
    }
  }
  EXPECT_EQ(replaysSeen, 1u);
}

TEST_F(EventBusTest, EmitToSubscription_NoMatchingSubscription_NoDelivery)
{
  auto tracker = std::make_shared<DeliveryTracker>();
  mEventBus->register_event_item(serverObjectId,
    1,
    1,
    [tracker](IntegerId id, std::shared_ptr<const BaseEvent> ev) { tracker->on_event(id, ev); });

  auto event = make_event(deviceNodeId, 500);
  mEventBus->emit_to_subscription(99, event);

  wait_idle();
  EXPECT_EQ(tracker->delivery_count(), 0u);
}

TEST_F(EventBusTest, EmitToSubscription_BypassesNotifierResolution)
{
  // Create an unrelated node with no HasNotifier path to the event source
  auto unrelatedId = NodeId{0, 20000u};
  auto result = mAddressSpace->try_create_sync<ObjectAccessor>(unrelatedId, NodeClass::Object);
  ASSERT_TRUE(result.is_good());
  {
    EventNotifierType notifier{EventNotifierType::Bit::SubscribeToEvents};
    result.value().set_event_notifier(notifier);
  }

  auto tracker = std::make_shared<DeliveryTracker>();
  mEventBus->register_event_item(unrelatedId,
    1,
    5,
    [tracker](IntegerId id, std::shared_ptr<const BaseEvent> ev) { tracker->on_event(id, ev); });

  // Regular emit would NOT deliver to the unrelated node (no notifier path)
  auto event1 = make_event(deviceNodeId, 300);
  mEventBus->emit(event1);
  wait_idle();
  EXPECT_EQ(tracker->delivery_count(), 0u);

  // emit_to_subscription bypasses notifier resolution and delivers anyway
  auto event2 = make_event(deviceNodeId, 400);
  mEventBus->emit_to_subscription(5, event2);
  ASSERT_TRUE(tracker->wait_for_count(1, dispatchTimeout));
  EXPECT_EQ(tracker->delivery_count(), 1u);
}

// ============================================================================
// Per-MonitoredItem FIFO ordering (Part 4 section 5.12.1.5, section 7.25.1)
// ============================================================================

TEST_F(EventBusTest, SingleThreadEmitsPreserveFIFOPerMI)
{
  // 50 sequential emits on the same source must arrive at the MI in emit order.
  // Each event carries its sequence number in `severity` for cross-check.
  auto tracker = std::make_shared<DeliveryTracker>();
  mEventBus->register_event_item(serverObjectId,
    1,
    0,
    [tracker](IntegerId id, std::shared_ptr<const BaseEvent> ev) { tracker->on_event(id, ev); });

  constexpr size_t n = 50;
  for (size_t i = 0; i < n; ++i)
  {
    auto event = make_event(deviceNodeId, static_cast<uint16_t>(i + 1));
    mEventBus->emit(event);
  }

  ASSERT_TRUE(tracker->wait_for_count(n, dispatchTimeout));
  auto deliveries = tracker->deliveries();
  ASSERT_EQ(deliveries.size(), n);
  for (size_t i = 0; i < n; ++i)
  {
    EXPECT_EQ(deliveries[i].second->severity, static_cast<uint16_t>(i + 1))
      << "Out-of-order delivery at index " << i;
  }
}

TEST_F(EventBusTest, MultiThreadConcurrentEmitsPreservePerThreadSubsequence)
{
  // M threads each emit N tagged events; the MI's delivery sequence must
  // preserve each thread's per-thread subsequence in order. Cross-thread
  // global ordering is not claimed - only per-thread monotonicity.
  auto tracker = std::make_shared<DeliveryTracker>();
  mEventBus->register_event_item(serverObjectId,
    1,
    0,
    [tracker](IntegerId id, std::shared_ptr<const BaseEvent> ev) { tracker->on_event(id, ev); });

  constexpr size_t threads = 4;
  constexpr size_t perThread = 25;
  constexpr size_t total = threads * perThread;

  // Encode (threadId, seq) as severity = threadId * 1000 + seq (kept in [1,1000]
  // by spec-clamping - so we keep both small).
  auto emitBatch = [&](uint16_t threadTag)
  {
    for (size_t s = 0; s < perThread; ++s)
    {
      auto event = make_event(deviceNodeId, static_cast<uint16_t>(threadTag * 100 + s + 1));
      mEventBus->emit(event);
    }
  };

  std::vector<std::thread> emitters;
  emitters.reserve(threads);
  for (size_t t = 0; t < threads; ++t)
  {
    emitters.emplace_back(emitBatch, static_cast<uint16_t>(t + 1));
  }
  for (auto& th : emitters)
    th.join();

  ASSERT_TRUE(tracker->wait_for_count(total, dispatchTimeout));
  auto deliveries = tracker->deliveries();
  ASSERT_EQ(deliveries.size(), total);

  // For each thread tag, the per-thread sequence numbers must appear in order.
  std::vector<uint16_t> lastSeqByThread(threads + 1, 0);
  for (const auto& [miId, ev] : deliveries)
  {
    auto sev = ev->severity;
    auto threadTag = static_cast<uint16_t>(sev / 100);
    auto seq = static_cast<uint16_t>(sev % 100);
    ASSERT_GE(threadTag, 1u);
    ASSERT_LE(threadTag, threads);
    EXPECT_GT(seq, lastSeqByThread[threadTag]) << "Per-thread subsequence broken for thread " << threadTag;
    lastSeqByThread[threadTag] = seq;
  }
}

// ============================================================================
// Listener ordering relative to subscriber dispatch
// ============================================================================

TEST_F(EventBusTest, ListenerFiresBeforeSubscriberDispatch)
{
  // The local listener is invoked on the bus strand before subscriber fan-out.
  // We assert this by recording the order of events: listener entry vs. MI
  // delivery for the same event. Since both run on the same dispatch strand,
  // the listener entry MUST precede the MI delivery for any single emit.
  std::mutex orderMutex;
  std::vector<std::string> order;

  mEventBus->set_event_listener(
    [&](const BaseEvent& /*ev*/)
    {
      std::lock_guard lk(orderMutex);
      order.push_back("listener");
    });

  auto tracker = std::make_shared<DeliveryTracker>();
  mEventBus->register_event_item(serverObjectId,
    1,
    0,
    [&, tracker](IntegerId id, std::shared_ptr<const BaseEvent> ev)
    {
      {
        std::lock_guard lk(orderMutex);
        order.push_back("mi");
      }
      tracker->on_event(id, std::move(ev));
    });

  auto event = make_event(deviceNodeId, 500);
  mEventBus->emit(event);

  ASSERT_TRUE(tracker->wait_for_count(1, dispatchTimeout));

  std::lock_guard lk(orderMutex);
  ASSERT_EQ(order.size(), 2u);
  EXPECT_EQ(order[0], "listener");
  EXPECT_EQ(order[1], "mi");
}

TEST_F(EventBusTest, EmitToSubscriptionDoesNotInvokeListener)
{
  // ConditionRefresh path bypasses the local listener.
  std::atomic<int> listenerCalls{0};
  mEventBus->set_event_listener([&](const BaseEvent&) { ++listenerCalls; });

  auto tracker = std::make_shared<DeliveryTracker>();
  mEventBus->register_event_item(serverObjectId,
    1,
    7,
    [tracker](IntegerId id, std::shared_ptr<const BaseEvent> ev) { tracker->on_event(id, ev); });

  auto event = make_event(deviceNodeId, 500);
  mEventBus->emit_to_subscription(7, event);

  ASSERT_TRUE(tracker->wait_for_count(1, dispatchTimeout));
  EXPECT_EQ(listenerCalls.load(), 0);
}

// @relation(AC-COMP-SVR-EVENTBUS-DISPATCH-01-CALLBACK-CONTAINMENT, scope=function)
TEST_F(EventBusTest, ThrowingListenerDoesNotSkipRecipientsOrWedgeTheNextDispatch)
{
  std::atomic_uint32_t listenerCalls{0};
  mEventBus->set_event_listener(
    [&listenerCalls](const BaseEvent&)
    {
      if (listenerCalls.fetch_add(1) == 0)
        throw std::runtime_error{"sentinel listener failure"};
    });

  auto tracker = std::make_shared<DeliveryTracker>();
  mEventBus->register_event_item(serverObjectId,
    1,
    7,
    [tracker](IntegerId id, std::shared_ptr<const BaseEvent> event)
    { tracker->on_event(id, std::move(event)); });

  auto first = make_event(deviceNodeId, 100);
  auto second = make_event(deviceNodeId, 200);
  mEventBus->emit(first);
  mEventBus->emit(second);

  ASSERT_TRUE(tracker->wait_for_count(2, dispatchTimeout));
  EXPECT_EQ(listenerCalls.load(), 2u);
  EXPECT_EQ(tracker->delivery_count(), 2u);
}

// ============================================================================

// @relation(AC-COMP-SVR-EVENTDECL-01-RICH-FAILURE-RETRY, scope=function)
TEST_F(EventBusTest, FailedDeclarationResolutionRetainsRichDetailAndRetriesTheSameConcreteType)
{
  const StatusCode sentinel{Status::BadCommunicationError,
    ErrorDetail::build("SentinelDeclarationResolutionFailure",
      "The injected EventType declaration lookup failed",
      "EventBusTest")};

  struct Observation
  {
    uint32_t resolverCalls{0};
    std::vector<std::shared_ptr<const event_type_model::DeclarationsResult>> models;
    std::promise<void> complete;
  };

  auto observation = std::make_shared<Observation>();
  auto completed = observation->complete.get_future();
  EventBusTestAccess::on_strand(*mEventBus,
    [observation, sentinel](auto& guarded)
    {
      guarded.declaration_resolver() = [observation, sentinel](
                                         AddressSpace, NodeId, event_type_model::CollectCallback onComplete)
      {
        ++observation->resolverCalls;
        if (observation->resolverCalls == 1)
        {
          onComplete(event_type_model::DeclarationsResult{sentinel});
          return;
        }
        onComplete(event_type_model::DeclarationsResult{event_type_model::Declarations{}});
      };
    });

  mEventBus->register_event_item(serverObjectId,
    87,
    0,
    EventDeliveryCallback{[observation](IntegerId,
                            std::shared_ptr<const BaseEvent>,
                            std::shared_ptr<const event_type_model::DeclarationsResult>
                              model)
      {
        observation->models.push_back(std::move(model));
        if (observation->models.size() == 2)
          observation->complete.set_value();
      }},
    true);

  auto failed = make_event(deviceNodeId, 110);
  auto recovered = make_event(deviceNodeId, 220);
  mEventBus->emit(failed);
  mEventBus->emit(recovered);

  ASSERT_EQ(completed.wait_for(dispatchTimeout), std::future_status::ready);
  ASSERT_EQ(observation->models.size(), 2u);
  ASSERT_NE(observation->models[0], nullptr);
  ASSERT_TRUE(observation->models[0]->is_bad());
  EXPECT_EQ(observation->models[0]->status_code().as_status(), Status::BadCommunicationError);
  EXPECT_EQ(observation->models[0]->status_code().shared_detail(), sentinel.shared_detail());
  ASSERT_NE(observation->models[1], nullptr);
  EXPECT_TRUE(observation->models[1]->is_good());
  EXPECT_EQ(observation->resolverCalls, 2u)
    << "a failed declaration Result must not poison the concrete EventType cache";
}

// @relation(AC-COMP-SVR-EVENTDECL-02-SUCCESS-CACHED, scope=function)
TEST_F(EventBusTest, ReusesImmutableDeclarationModelForRepeatedConcreteEventType)
{
  const NodeId severityId{1, 1970001u};
  auto baseType = mAddressSpace->try_create_sync<ObjectTypeAccessor>(
    NodeId{ObjectTypeId::BaseEventType}, NodeClass::ObjectType);
  ASSERT_TRUE(baseType.is_good());
  baseType.value().set_browse_name(QualifiedName{0, "BaseEventType"});
  auto severity = mAddressSpace->try_create_sync<VariableAccessor>(severityId, NodeClass::Variable);
  ASSERT_TRUE(severity.is_good());
  severity.value().set_browse_name(QualifiedName{0, "Severity"});
  baseType.value().add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, severityId, true);

  struct Observation
  {
    std::mutex mutex;
    std::vector<std::shared_ptr<const event_type_model::DeclarationsResult>> models;
    std::promise<void> complete;
  };

  auto observation = std::make_shared<Observation>();
  auto completed = observation->complete.get_future();
  mEventBus->register_event_item(serverObjectId,
    88,
    0,
    EventDeliveryCallback{[observation](IntegerId,
                            std::shared_ptr<const BaseEvent>,
                            std::shared_ptr<const event_type_model::DeclarationsResult>
                              declarationModel)
      {
        std::lock_guard lock(observation->mutex);
        observation->models.push_back(std::move(declarationModel));
        if (observation->models.size() == 2)
          observation->complete.set_value();
      }});

  auto first = make_event(deviceNodeId, 111);
  auto second = make_event(deviceNodeId, 222);
  mEventBus->emit(first);
  mEventBus->emit(second);

  ASSERT_EQ(completed.wait_for(dispatchTimeout), std::future_status::ready);
  std::lock_guard lock(observation->mutex);
  ASSERT_EQ(observation->models.size(), 2u);
  ASSERT_NE(observation->models[0], nullptr);
  EXPECT_EQ(observation->models[0], observation->models[1])
    << "the second Event of the same concrete EventType must reuse the immutable declaration model";
  ASSERT_TRUE(observation->models[0]->is_good());
  const auto& declarations = observation->models[0]->value();
  const auto declaration = std::find_if(declarations.begin(),
    declarations.end(),
    [](const event_type_model::Declaration& candidate) {
      return candidate.browsePath.size() == 1 && candidate.browsePath.front() == QualifiedName{0, "Severity"};
    });
  ASSERT_NE(declaration, declarations.end());
  ASSERT_TRUE(declaration->accessor.has_value());
  EXPECT_EQ(declaration->accessor->get_node_id(), severityId);
}

// @relation(AC-COMP-SVR-EVENTDECL-06-MODEL-GENERATION-INVALIDATION, scope=function)
TEST_F(EventBusTest, InvalidatesDeclarationModelAfterCommittedReferenceMutation)
{
  const NodeId firstSeverityId{1, 1970011u};
  const NodeId replacementSeverityId{1, 1970012u};
  auto baseType = mAddressSpace->try_create_sync<ObjectTypeAccessor>(
    NodeId{ObjectTypeId::BaseEventType}, NodeClass::ObjectType);
  ASSERT_TRUE(baseType.is_good());
  baseType.value().set_browse_name(QualifiedName{0, "BaseEventType"});
  auto firstSeverity = mAddressSpace->try_create_sync<VariableAccessor>(firstSeverityId, NodeClass::Variable);
  ASSERT_TRUE(firstSeverity.is_good());
  firstSeverity.value().set_browse_name(QualifiedName{0, "Severity"});
  baseType.value().add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, firstSeverityId, true);

  struct Observation
  {
    std::atomic_uint32_t count{0};
    std::promise<std::shared_ptr<const event_type_model::DeclarationsResult>> first;
    std::promise<std::shared_ptr<const event_type_model::DeclarationsResult>> second;
  };

  auto observation = std::make_shared<Observation>();
  auto firstModelFuture = observation->first.get_future();
  auto secondModelFuture = observation->second.get_future();
  mEventBus->register_event_item(serverObjectId,
    89,
    0,
    EventDeliveryCallback{[observation](IntegerId,
                            std::shared_ptr<const BaseEvent>,
                            std::shared_ptr<const event_type_model::DeclarationsResult>
                              model)
      {
        if (observation->count.fetch_add(1) == 0)
          observation->first.set_value(std::move(model));
        else
          observation->second.set_value(std::move(model));
      }},
    true);

  auto firstEvent = make_event(deviceNodeId, 111);
  mEventBus->emit(firstEvent);
  ASSERT_EQ(firstModelFuture.wait_for(dispatchTimeout), std::future_status::ready);
  auto firstModel = firstModelFuture.get();
  ASSERT_NE(firstModel, nullptr);
  ASSERT_TRUE(firstModel->is_good());

  auto replacementSeverity =
    mAddressSpace->try_create_sync<VariableAccessor>(replacementSeverityId, NodeClass::Variable);
  ASSERT_TRUE(replacementSeverity.is_good());
  replacementSeverity.value().set_browse_name(QualifiedName{0, "Severity"});
  auto removed =
    baseType.value().try_remove_reference_sync(NodeId{ReferenceTypeId::HasProperty}, firstSeverityId, true);
  ASSERT_TRUE(removed.is_good()) << to_string(removed.status_code().as_status());
  baseType.value().add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, replacementSeverityId, true);

  auto secondEvent = make_event(deviceNodeId, 222);
  mEventBus->emit(secondEvent);
  ASSERT_EQ(secondModelFuture.wait_for(dispatchTimeout), std::future_status::ready);
  auto secondModel = secondModelFuture.get();
  ASSERT_NE(secondModel, nullptr);
  ASSERT_TRUE(secondModel->is_good());
  EXPECT_NE(firstModel, secondModel);

  const auto replacement = std::find_if(secondModel->value().begin(),
    secondModel->value().end(),
    [](const event_type_model::Declaration& candidate) {
      return candidate.browsePath.size() == 1 && candidate.browsePath.front() == QualifiedName{0, "Severity"};
    });
  ASSERT_NE(replacement, secondModel->value().end());
  ASSERT_TRUE(replacement->accessor.has_value());
  EXPECT_EQ(replacement->accessor->get_node_id(), replacementSeverityId);
}

// @relation(AC-COMP-SVR-EVENTDECL-06-MODEL-GENERATION-INVALIDATION, scope=function)
TEST_F(EventBusTest, AChangeDuringDeclarationResolutionStillAnswersTheEvent)
{
  const NodeId severityId{1, 1970021u};
  auto baseType = mAddressSpace->try_create_sync<ObjectTypeAccessor>(
    NodeId{ObjectTypeId::BaseEventType}, NodeClass::ObjectType);
  ASSERT_TRUE(baseType.is_good());
  baseType.value().set_browse_name(QualifiedName{0, "BaseEventType"});
  auto severity = mAddressSpace->try_create_sync<VariableAccessor>(severityId, NodeClass::Variable);
  ASSERT_TRUE(severity.is_good());
  severity.value().set_browse_name(QualifiedName{0, "Severity"});
  baseType.value().add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, severityId, true);

  std::promise<std::shared_ptr<const event_type_model::DeclarationsResult>> completion;
  auto completed = completion.get_future();
  EventBusTestAccess::on_strand(*mEventBus,
    [&](auto& guarded)
    {
      const auto generationBeforeResolution = mAddressSpace->model_generation();
      guarded.resolve_event_type_declarations(NodeId{ObjectTypeId::BaseEventType},
        [&completion](std::shared_ptr<const event_type_model::DeclarationsResult> result)
        { completion.set_value(std::move(result)); });

      mAddressSpace->create_node_async(NodeId{1, 1970022u},
        NodeClass::Object,
        [](NodeAccessorResult result) { EXPECT_TRUE(result.is_good()); });
      EXPECT_GT(mAddressSpace->model_generation(), generationBeforeResolution);
    });

  ASSERT_EQ(completed.wait_for(dispatchTimeout), std::future_status::ready);
  auto declarations = completed.get();
  ASSERT_NE(declarations, nullptr);
  ASSERT_TRUE(declarations->is_good()) << to_string(declarations->status_code().as_status());
  const auto resolvedSeverity = std::find_if(declarations->value().begin(),
    declarations->value().end(),
    [](const event_type_model::Declaration& candidate) {
      return candidate.browsePath.size() == 1 && candidate.browsePath.front() == QualifiedName{0, "Severity"};
    });
  ASSERT_NE(resolvedSeverity, declarations->value().end());
  ASSERT_TRUE(resolvedSeverity->accessor.has_value());
  EXPECT_EQ(resolvedSeverity->accessor->get_node_id(), severityId);
}

// D-NR-EVENT-DECLARATIONS-FAIL-WHILE-NODES-ARE-CREATED: every resolution sees the model change, as when Sessions
// with diagnostics create their Nodes while an audit Event is raised.
// @relation(AC-COMP-SVR-EVENTDECL-06-A-RESOLUTION-WHILE-THE-MODEL-KEEPS-CHANGING-ANSWERS-THE-EVENT, scope=function)
TEST_F(EventBusTest, AnEventsDeclarationsAreAnsweredWhileTheModelKeepsChanging)
{
  struct Observation
  {
    std::atomic_uint32_t resolverCalls{0};
    std::mutex mutex;
    std::condition_variable delivered;
    std::vector<std::shared_ptr<const event_type_model::DeclarationsResult>> models;
  };
  auto observation = std::make_shared<Observation>();
  EventBusTestAccess::on_strand(*mEventBus,
    [observation](auto& guarded)
    {
      guarded.declaration_resolver() =
        [observation](AddressSpace space, NodeId, event_type_model::CollectCallback onComplete)
      {
        // A Node created while the declarations are read, answered once it is held.
        const auto call = observation->resolverCalls.fetch_add(1) + 1;
        space.create_node_async(NodeId{1, 1990000u + call},
          NodeClass::Object,
          [onComplete](NodeAccessorResult) mutable
          { onComplete(event_type_model::DeclarationsResult{event_type_model::Declarations{}}); });
      };
    });
  mEventBus->register_event_item(serverObjectId,
    91,
    0,
    EventDeliveryCallback{[observation](IntegerId,
                            std::shared_ptr<const BaseEvent>,
                            std::shared_ptr<const event_type_model::DeclarationsResult>
                              model)
      {
        const std::lock_guard lock{observation->mutex};
        observation->models.push_back(std::move(model));
        observation->delivered.notify_all();
      }},
    true);
  const auto delivered = [&observation](std::size_t count)
  {
    std::unique_lock lock{observation->mutex};
    return observation->delivered.wait_for(
      lock, dispatchTimeout * 5, [&observation, count] { return observation->models.size() >= count; });
  };

  auto first = make_event(deviceNodeId, 301);
  mEventBus->emit(first);
  ASSERT_TRUE(delivered(1));
  {
    const std::lock_guard lock{observation->mutex};
    ASSERT_NE(observation->models[0], nullptr);
    EXPECT_TRUE(observation->models[0]->is_good()) << to_string(observation->models[0]->status_code());
  }
  EXPECT_EQ(observation->resolverCalls.load(), 1u) << "the declarations read are the Event's answer";

  // Read while the model changed, they answer that Event only: the next one reads them again.
  auto second = make_event(deviceNodeId, 302);
  mEventBus->emit(second);
  ASSERT_TRUE(delivered(2));
  EXPECT_EQ(observation->resolverCalls.load(), 2u);
}

/// An event type in a namespace wrapped in `HistoryNamespace`, which the address space reaches only through the
/// members of `Namespace`, below the BaseEventType of namespace 0.
class EventFieldDeclarations : public EventBusTest
{
protected:
  void SetUp() override
  {
    EventBusTest::SetUp();
    auto inner = default_ns::Namespace::create("urn:test:event-fields:wrapped", mThreadPool.get_executor());
    auto index =
      mAddressSpace->try_add_namespace_sync(std::make_shared<history::HistoryNamespace>(std::move(inner), nullptr));
    ASSERT_TRUE(index.is_good()) << to_string(index.status_code());
    mIndex = index.value();
    auto baseType = mAddressSpace->try_create_sync<ObjectTypeAccessor>(
      NodeId{ObjectTypeId::BaseEventType}, NodeClass::ObjectType);
    ASSERT_TRUE(baseType.is_good());
    baseType.value().set_browse_name(QualifiedName{0, "BaseEventType"});
    mWidgetType = NodeId{mIndex, "WidgetEventType"};
    auto widgetType = mAddressSpace->try_create_sync<ObjectTypeAccessor>(mWidgetType, NodeClass::ObjectType);
    ASSERT_TRUE(widgetType.is_good());
    widgetType.value().set_browse_name(QualifiedName{mIndex, "WidgetEventType"});
    ASSERT_TRUE(widgetType.value()
                  .try_add_reference_sync(NodeId{ReferenceTypeId::HasSubtype},
                    ExpandedNodeId{NodeId{ObjectTypeId::BaseEventType}},
                    false)
                  .is_good());

    mModels = std::make_shared<Models>();
    mEventBus->register_event_item(serverObjectId,
      92,
      0,
      EventDeliveryCallback{[models = mModels](IntegerId,
                              std::shared_ptr<const BaseEvent>,
                              std::shared_ptr<const event_type_model::DeclarationsResult>
                                model)
        {
          const std::lock_guard lock{models->mutex};
          models->received.push_back(std::move(model));
          models->delivered.notify_all();
        }},
      true);
  }

  /// A Property of the widget type named @p name.
  NodeId add_field(const std::string& name)
  {
    const NodeId fieldId{mIndex, String{name}};
    auto field = mAddressSpace->try_create_sync<VariableAccessor>(fieldId, NodeClass::Variable);
    EXPECT_TRUE(field.is_good());
    field.value().set_browse_name(QualifiedName{mIndex, name});
    auto widgetType = mAddressSpace->try_find_node_sync(mWidgetType);
    EXPECT_TRUE(widgetType.is_good());
    EXPECT_TRUE(widgetType.value()
                  .try_add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, ExpandedNodeId{fieldId})
                  .is_good());
    return fieldId;
  }

  /// The declarations the next widget Event is delivered with.
  std::shared_ptr<const event_type_model::DeclarationsResult> deliver_widget_event()
  {
    std::size_t before = 0;
    {
      const std::lock_guard lock{mModels->mutex};
      before = mModels->received.size();
    }
    auto event = make_event(deviceNodeId, 400);
    event.eventType = mWidgetType;
    mEventBus->emit(event);
    std::unique_lock lock{mModels->mutex};
    if (!mModels->delivered.wait_for(
          lock, dispatchTimeout, [this, before] { return mModels->received.size() > before; }))
    {
      return nullptr;
    }
    return mModels->received.back();
  }

  bool declares(const event_type_model::DeclarationsResult& model, const std::string& name) const
  {
    return std::ranges::any_of(model.value(),
      [this, &name](const event_type_model::Declaration& declaration)
      {
        return declaration.browsePath.size() == 1 &&
               declaration.browsePath.front() == QualifiedName{mIndex, name};
      });
  }

  struct Models
  {
    std::mutex mutex;
    std::condition_variable delivered;
    std::vector<std::shared_ptr<const event_type_model::DeclarationsResult>> received;
  };

  uint16_t mIndex{0};
  NodeId mWidgetType;
  std::shared_ptr<Models> mModels;
};

// @relation(AC-COMP-ADDRSP-MODEL-GENERATION-01-A-FIELD-ADDED-TO-ANOTHER-NAMESPACES-EVENT-TYPE-IS-DELIVERED, scope=function)
TEST_F(EventFieldDeclarations, AFieldAddedToAnotherNamespacesEventTypeIsDelivered)
{
  const auto before = deliver_widget_event();
  ASSERT_NE(before, nullptr);
  ASSERT_TRUE(before->is_good()) << to_string(before->status_code());
  EXPECT_FALSE(declares(*before, "Widget"));

  add_field("Widget");

  const auto after = deliver_widget_event();
  ASSERT_NE(after, nullptr);
  ASSERT_TRUE(after->is_good()) << to_string(after->status_code());
  EXPECT_TRUE(declares(*after, "Widget")) << "the declarations of the widget type were reused after its field was added";
}

// @relation(AC-COMP-ADDRSP-MODEL-GENERATION-01-A-RENAMED-FIELD-IS-SEEN-AFTER-A-BROWSE-NAME-WRITE, scope=function)
TEST_F(EventFieldDeclarations, ARenamedFieldIsSeenAfterABrowseNameWrite)
{
  const auto fieldId = add_field("Widget");
  const auto before = deliver_widget_event();
  ASSERT_NE(before, nullptr);
  ASSERT_TRUE(before->is_good()) << to_string(before->status_code());
  EXPECT_TRUE(declares(*before, "Widget"));

  auto field = mAddressSpace->try_find_node_sync(fieldId);
  ASSERT_TRUE(field.is_good());
  field.value().set_browse_name(QualifiedName{mIndex, "Gadget"});

  const auto after = deliver_widget_event();
  ASSERT_NE(after, nullptr);
  ASSERT_TRUE(after->is_good()) << to_string(after->status_code());
  EXPECT_TRUE(declares(*after, "Gadget")) << "the declarations still name the field by its old BrowseName";
  EXPECT_FALSE(declares(*after, "Widget"));
}

// Handle allocation
// ============================================================================

TEST_F(EventBusTest, RegisterReturnsUniqueHandleSynchronously)
{
  // Handle allocation is on the caller's thread (atomic fetch_add).
  // We don't drain the strand between calls; handles must still be unique.
  auto h1 =
    mEventBus->register_event_item(serverObjectId, 1, 0, [](IntegerId, std::shared_ptr<const BaseEvent>) {});
  auto h2 =
    mEventBus->register_event_item(serverObjectId, 2, 0, [](IntegerId, std::shared_ptr<const BaseEvent>) {});
  auto h3 =
    mEventBus->register_event_item(serverObjectId, 3, 0, [](IntegerId, std::shared_ptr<const BaseEvent>) {});

  EXPECT_NE(h1, h2);
  EXPECT_NE(h2, h3);
  EXPECT_NE(h1, h3);
}

// ============================================================================
// Lifetime: in-flight events to deregistered MI are safe
// ============================================================================

TEST_F(EventBusTest, InFlightEventsToDeregisteredMIAreSafe)
{
  // Burst emit, deregister, drain - no crashes, no UAF. The strand-component
  // lifetime invariant: posted lambdas weak-capture the bus, so a destroyed
  // bus is harmless (lambdas no-op); the registry erase is also posted, so
  // the order is bus-FIFO.
  auto tracker = std::make_shared<DeliveryTracker>();
  auto handle = mEventBus->register_event_item(serverObjectId,
    1,
    0,
    [tracker](IntegerId id, std::shared_ptr<const BaseEvent> ev) { tracker->on_event(id, ev); });

  for (int i = 0; i < 20; ++i)
  {
    auto event = make_event(deviceNodeId, 100);
    mEventBus->emit(event);
  }
  mEventBus->deregister_event_item(handle);

  // Drain pending work; the surviving count is whatever raced ahead of the
  // deregister post. The contract is "no crash and no callbacks to freed
  // state", not a specific delivered count.
  wait_idle();
  EXPECT_LE(tracker->delivery_count(), 20u);
}

// ============================================================================
// emit_to_monitored_item - ConditionRefresh2 scoping (Part 9 section 5.5.8)
// ============================================================================

TEST_F(EventBusTest, EmitToMonitoredItem_DeliversOnlyToTargetItem)
{
  // Two event items on the SAME subscription (id=1) with monitoredItemIds 10
  // and 11. emit_to_monitored_item targeting item 10 must reach ONLY item 10,
  // proving ConditionRefresh2 can scope a refresh to a single MonitoredItem
  // (unlike emit_to_subscription which fans out to the whole subscription).
  auto item10Tracker = std::make_shared<DeliveryTracker>();
  auto item11Tracker = std::make_shared<DeliveryTracker>();

  mEventBus->register_event_item(serverObjectId,
    10,
    1,
    [item10Tracker](IntegerId id, std::shared_ptr<const BaseEvent> ev) { item10Tracker->on_event(id, ev); });
  mEventBus->register_event_item(serverObjectId,
    11,
    1,
    [item11Tracker](IntegerId id, std::shared_ptr<const BaseEvent> ev) { item11Tracker->on_event(id, ev); });

  auto event = make_event(deviceNodeId, 500);
  mEventBus->emit_to_monitored_item(1, 10, event);

  ASSERT_TRUE(item10Tracker->wait_for_count(1, dispatchTimeout));
  EXPECT_EQ(item10Tracker->delivery_count(), 1u);
  EXPECT_EQ(item10Tracker->deliveries()[0].first, 10u);

  // The other item on the same subscription must NOT receive the event.
  wait_idle();
  EXPECT_EQ(item11Tracker->delivery_count(), 0u);
}

TEST_F(EventBusTest, EmitToMonitoredItem_WrongSubscription_NoDelivery)
{
  // Same monitoredItemId number on a different subscription must not match.
  auto tracker = std::make_shared<DeliveryTracker>();
  mEventBus->register_event_item(serverObjectId,
    10,
    1,
    [tracker](IntegerId id, std::shared_ptr<const BaseEvent> ev) { tracker->on_event(id, ev); });

  auto event = make_event(deviceNodeId, 500);
  mEventBus->emit_to_monitored_item(2, 10, event);

  wait_idle();
  EXPECT_EQ(tracker->delivery_count(), 0u);
}

// ============================================================================
// resolve_event_item_node_async - MonitoredItemId -> monitored NodeId
// ============================================================================

TEST_F(EventBusTest, ResolveEventItemNode_KnownItem_ReturnsMonitoredNode)
{
  mEventBus->register_event_item(deviceNodeId, 42, 7, [](IntegerId, std::shared_ptr<const BaseEvent>) {});

  std::promise<std::optional<NodeId>> promise;
  mEventBus->resolve_event_item_node_async(
    7, 42, [&promise](std::optional<NodeId> node) { promise.set_value(std::move(node)); });

  auto resolved = promise.get_future().get();
  ASSERT_TRUE(resolved.has_value());
  EXPECT_EQ(*resolved, deviceNodeId);
}

TEST_F(EventBusTest, ResolveEventItemNode_UnknownItem_ReturnsNullopt)
{
  mEventBus->register_event_item(deviceNodeId, 42, 7, [](IntegerId, std::shared_ptr<const BaseEvent>) {});

  // Unknown (subscriptionId, monitoredItemId) pair.
  std::promise<std::optional<NodeId>> promise;
  mEventBus->resolve_event_item_node_async(
    7, 999, [&promise](std::optional<NodeId> node) { promise.set_value(std::move(node)); });

  EXPECT_FALSE(promise.get_future().get().has_value());
}

// Dispatch-queue depth cap (P1.D #3): a burst of emits faster than dispatch drains must not grow the
// bus's pending-task queue without limit. Once a dispatch task is in flight (and stalled here), the
// queue is bounded by dropping the oldest pending task, recorded in dropped_dispatch_count().
TEST_F(EventBusTest, PendingDispatchQueueCapDropsOldest)
{
  auto bus = std::make_shared<EventBus>(*mAddressSpace, /*maxPendingDispatches=*/3);

  EventBusTestAccess::on_strand(*bus,
    [](auto& g)
    {
      // A task that runs but never completes keeps mDispatching true, so later enqueues only queue.
      g.enqueue_dispatch([](std::function<void()> /*onComplete*/) {}, DroppedEventInfo{});

      // Fill to the cap (3), then push one more to force a drop-oldest.
      for (int i = 0; i < 3; ++i)
      {
        g.enqueue_dispatch([](std::function<void()> onComplete) { onComplete(); }, DroppedEventInfo{});
      }
      EXPECT_EQ(g.pending_dispatches().size(), 3u);

      g.enqueue_dispatch([](std::function<void()> onComplete) { onComplete(); }, DroppedEventInfo{});
      EXPECT_EQ(g.pending_dispatches().size(), 3u);  // stayed bounded
    });

  EXPECT_EQ(bus->dropped_dispatch_count(), 1u);

  bus.reset();
}

// When the pending-dispatch cap drops the oldest event, the dropped-event observer must be invoked
// with that event's identity (so the host can surface/persist the loss). Falsifiable: if the drop
// path does not invoke mOnDispatchDropped, `dropped` stays empty and the assertions fail.
TEST_F(EventBusTest, DroppedDispatchInvokesObserverWithEventIdentity)
{
  auto bus = std::make_shared<EventBus>(*mAddressSpace, /*maxPendingDispatches=*/1);

  std::vector<DroppedEventInfo> dropped;

  EventBusTestAccess::on_strand(*bus,
    [&dropped](auto& g)
    {
      g.on_dispatch_dropped() = [&dropped](const DroppedEventInfo& info)
      {
        dropped.push_back(info);
      };

      // In-flight stall so subsequent enqueues only queue (never drain).
      g.enqueue_dispatch([](std::function<void()> /*onComplete*/) {}, DroppedEventInfo{});

      // First queued entry carries a recognisable identity; it is the oldest, so the next enqueue
      // (cap == 1) drops it and must report its identity.
      DroppedEventInfo first;
      first.eventType = NodeId{ObjectTypeId::AuditWriteUpdateEventType};
      first.sourceNode = NodeId{2, "the-written-node"};
      first.sourceName = "Attribute/Write";
      first.severity = 1;
      g.enqueue_dispatch([](std::function<void()> onComplete) { onComplete(); }, first);

      // Overflow: drops the oldest queued entry (`first`).
      g.enqueue_dispatch([](std::function<void()> onComplete) { onComplete(); }, DroppedEventInfo{});
    });

  ASSERT_EQ(dropped.size(), 1u);
  EXPECT_EQ(dropped[0].eventType, NodeId{ObjectTypeId::AuditWriteUpdateEventType});
  EXPECT_EQ(dropped[0].sourceNode, (NodeId{2, "the-written-node"}));
  EXPECT_EQ(dropped[0].sourceName, "Attribute/Write");
  EXPECT_EQ(dropped[0].severity, 1);
  EXPECT_EQ(bus->dropped_dispatch_count(), 1u);

  bus.reset();
}

// Server shutdown closes the application's event listener on the dispatch strand before reporting
// completion: an event emitted before the close but delivered after it, and any event emitted later, never
// reaches the listener, and a listener set afterwards is refused. Found by the certificate-validation
// integration matrix (2026-10-02): a listener ran after Server::try_shutdown_sync had returned and wrote
// into an object the application had already destroyed.
// @relation(AC-COMP-SVR-EVENTBUS-DISPATCH-02-NO-LISTENER-AFTER-SHUTDOWN, scope=function)
TEST_F(EventBusTest, NoEventReachesTheListenerOnceItIsClosed)
{
  std::atomic<int> listenerCalls{0};
  mEventBus->set_event_listener([&](const BaseEvent&) { ++listenerCalls; });

  // Control: before the close the listener is called.
  auto tracker = std::make_shared<DeliveryTracker>();
  mEventBus->register_event_item(serverObjectId,
    1,
    7,
    [tracker](IntegerId id, std::shared_ptr<const BaseEvent> event)
    { tracker->on_event(id, std::move(event)); });
  auto before = make_event(deviceNodeId, 100);
  mEventBus->emit(before);
  ASSERT_TRUE(tracker->wait_for_count(1, dispatchTimeout));
  EXPECT_EQ(listenerCalls.load(), 1);

  // An event emitted, then the close: the close runs on the same strand, after which nothing is delivered
  // to the listener.
  auto inFlight = make_event(deviceNodeId, 200);
  mEventBus->emit(inFlight);
  std::promise<void> closed;
  mEventBus->close_listener_async([&closed] { closed.set_value(); });
  ASSERT_EQ(closed.get_future().wait_for(dispatchTimeout), std::future_status::ready);
  ASSERT_TRUE(tracker->wait_for_count(2, dispatchTimeout));
  const int atClose = listenerCalls.load();

  mEventBus->set_event_listener([&](const BaseEvent&) { ++listenerCalls; });
  auto after = make_event(deviceNodeId, 300);
  mEventBus->emit(after);
  ASSERT_TRUE(tracker->wait_for_count(3, dispatchTimeout)) << "subscribers are still served";
  EXPECT_EQ(listenerCalls.load(), atClose) << "neither the closed listener nor a new one is called";
}

// ============================================================================
// The climb: which inverse References carry an Event to their source (NR-60, DL-9)
// ============================================================================

// Part 3 section 7.18 obliges delivery at the source of a HasNotifier whose target generates an Event, and
// section 5.3.3.3 a) has a subtype inherit its supertype's semantic. R is an application subtype of
// HasNotifier from P to S; Q, with no Reference to S, is the control that the Event is not given to every
// subscribable Object.
// @relation(AC-SVR-ADDRSP-174-HASNOTIFIER-SUBTYPE-DELIVERS, scope=function)
TEST_F(EventBusTest, AnApplicationSubtypeOfHasNotifierDelivers)
{
  add_event_source_reference_types();
  const NodeId subtypeR{1, 22000u};
  const NodeId notifierP{1, 22001u};
  const NodeId sourceS{1, 22002u};
  const NodeId unrelatedQ{1, 22003u};
  ensure_reference_type(subtypeR);
  link(NodeId{ReferenceTypeId::HasNotifier}, NodeId{ReferenceTypeId::HasSubtype}, subtypeR);
  for (const auto& nodeId : {notifierP, sourceS, unrelatedQ})
    make_notifier(nodeId);
  link(notifierP, subtypeR, sourceS);
  auto atP = std::make_shared<DeliveryTracker>();
  auto atQ = std::make_shared<DeliveryTracker>();
  subscribe(notifierP, 1, atP);
  subscribe(unrelatedQ, 2, atQ);

  auto event1 = make_event(sourceS);
  mEventBus->emit(event1);

  EXPECT_TRUE(atP->wait_for_count(1, dispatchTimeout))
    << "an Event at the target of an application subtype of HasNotifier did not reach the source";
  wait_idle();
  EXPECT_EQ(atQ->delivery_count(), 0u) << "the Event reached an Object with no Reference to its source";
}

// The Server Object is the root of the event hierarchy (Part 9 section 6.2); NR-60 does not continue the
// climb above it, and DL-46 keeps that for an Event whose SourceNode is the Server Object. X holds a
// HasNotifier to the Server Object, which holds one to S: an Event at S and an Event at the Server Object
// each reach the Server Object (the control) and not X.
// @relation(AC-SVR-ADDRSP-174-CLIMB-STOPS-AT-SERVER-OBJECT, scope=function)
TEST_F(EventBusTest, TheClimbDoesNotContinueAboveTheServerObject)
{
  const NodeId sourceS{1, 22100u};
  const NodeId aboveX{1, 22101u};
  make_notifier(sourceS);
  make_notifier(aboveX);
  link(serverObjectId, NodeId{ReferenceTypeId::HasNotifier}, sourceS);
  link(aboveX, NodeId{ReferenceTypeId::HasNotifier}, serverObjectId);
  auto atServer = std::make_shared<DeliveryTracker>();
  auto atX = std::make_shared<DeliveryTracker>();
  subscribe(serverObjectId, 1, atServer);
  subscribe(aboveX, 2, atX);

  auto event2 = make_event(sourceS);
  mEventBus->emit(event2);
  auto serverOwnEvent = make_event(serverObjectId);
  mEventBus->emit(serverOwnEvent);

  EXPECT_TRUE(atServer->wait_for_count(2, dispatchTimeout))
    << "the Server Object did not receive both Events";
  wait_idle();
  std::size_t fromS = 0;
  std::size_t fromServerObject = 0;
  for (const auto& [id, event] : atX->deliveries())
  {
    fromS += event->sourceNode == sourceS ? 1u : 0u;
    fromServerObject += event->sourceNode == serverObjectId ? 1u : 0u;
  }
  EXPECT_EQ(fromS, 0u)
    << "the climb from S continued above the Server Object to an Object that references it";
  EXPECT_EQ(fromServerObject, 0u)
    << "the Event whose SourceNode is the Server Object climbed to an Object that references it";
}

// Part 3 section 7.17: an ObjectType may be the source of a HasEventSource to its InstanceDeclaration, and
// "is not considered a source of Event Subscriptions"; NR-60 does not continue the climb above it. A guard on
// a model the specification does not allow (a HasNotifier to an ObjectType). Z, which holds a HasEventSource
// to D, is the control that the climb follows HasEventSource from D at all.
// @relation(AC-SVR-ADDRSP-174-CLIMB-STOPS-AT-OBJECTTYPE, scope=function)
TEST_F(EventBusTest, TheClimbDoesNotContinueAboveAnObjectType)
{
  const NodeId objectTypeT{1, 22200u};
  const NodeId declarationD{1, 22201u};
  const NodeId aboveY{1, 22202u};
  const NodeId areaZ{1, 22203u};
  ASSERT_TRUE(
    mAddressSpace->try_create_sync<ObjectTypeAccessor>(objectTypeT, NodeClass::ObjectType).is_good());
  ASSERT_TRUE(mAddressSpace->try_create_sync<ObjectAccessor>(declarationD, NodeClass::Object).is_good());
  link(objectTypeT, NodeId{ReferenceTypeId::HasComponent}, declarationD);
  link(objectTypeT, NodeId{ReferenceTypeId::HasEventSource}, declarationD);
  make_notifier(aboveY);
  make_notifier(areaZ);
  link(aboveY, NodeId{ReferenceTypeId::HasNotifier}, objectTypeT);
  link(areaZ, NodeId{ReferenceTypeId::HasEventSource}, declarationD);
  auto atY = std::make_shared<DeliveryTracker>();
  auto atZ = std::make_shared<DeliveryTracker>();
  subscribe(aboveY, 1, atY);
  subscribe(areaZ, 2, atZ);

  auto event3 = make_event(declarationD);
  mEventBus->emit(event3);

  EXPECT_TRUE(atZ->wait_for_count(1, dispatchTimeout))
    << "the Event at D did not reach Z, which holds a HasEventSource to D";
  wait_idle();
  EXPECT_EQ(atY->delivery_count(), 0u) << "the climb continued above an ObjectType";
}

// Part 9 section 6.2 links areas to their ConditionSources by HasNotifier and HasEventSource, and a Variable
// cannot be the target of HasNotifier (Part 3 section 7.18), so an area reaches a Variable source only by
// HasEventSource (NR-60). B, with no Reference to V, is the control.
// @relation(AC-SVR-AC-085-AREA-RECEIVES-ITS-SOURCES-EVENTS, scope=function)
TEST_F(EventBusTest, AnAreaLinkedByHasEventSourceReceivesItsSourcesEvents)
{
  const NodeId areaA{1, 22300u};
  const NodeId variableV{1, 22301u};
  const NodeId otherB{1, 22302u};
  make_notifier(areaA);
  make_notifier(otherB);
  link(serverObjectId, NodeId{ReferenceTypeId::HasNotifier}, areaA);
  ASSERT_TRUE(mAddressSpace->try_create_sync<VariableAccessor>(variableV, NodeClass::Variable).is_good());
  link(areaA, NodeId{ReferenceTypeId::HasEventSource}, variableV);
  auto atA = std::make_shared<DeliveryTracker>();
  auto atB = std::make_shared<DeliveryTracker>();
  subscribe(areaA, 1, atA);
  subscribe(otherB, 2, atB);

  auto event4 = make_event(variableV);
  mEventBus->emit(event4);

  EXPECT_TRUE(atA->wait_for_count(1, dispatchTimeout))
    << "the area did not receive the Event of the source it links by HasEventSource";
  wait_idle();
  EXPECT_EQ(atB->delivery_count(), 0u) << "the Event reached an Object with no Reference to its source";
}

// DL-9: an application ReferenceType is decided by its supertypes; when that lookup fails the Reference is
// not followed, and the failure is logged once per type per model generation, so an Event storm through a
// broken type cannot log once per Event. The Server Object's three Events are the control that the failure
// does not stop the dispatch.
// @relation(AC-COMP-SVR-EVENT-CLIMB-REFERENCE-TYPES-02-FAILED-LOOKUP-LOGGED-ONCE, scope=function)
TEST_F(EventBusTest, AFailedReferenceTypeLookupIsLoggedOncePerGenerationAndNotFollowed)
{
  auto sink = std::make_shared<RecordingLogSink>();
  mAddressSpace->set_logger(Logger{sink, std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace), "test"});
  const NodeId brokenR{1, 22400u};
  const NodeId missingSupertype{1, 22499u};
  const NodeId notifierP{1, 22401u};
  const NodeId sourceS{1, 22402u};
  ensure_reference_type(brokenR);
  auto broken = mAddressSpace->try_find_node_sync(brokenR);
  ASSERT_TRUE(broken.is_good());
  ASSERT_TRUE(
    broken.value()
      .try_add_reference_sync(NodeId{ReferenceTypeId::HasSubtype}, ExpandedNodeId{missingSupertype}, false)
      .is_good());
  make_notifier(notifierP);
  make_notifier(sourceS);
  link(notifierP, brokenR, sourceS);
  auto atP = std::make_shared<DeliveryTracker>();
  auto atServer = std::make_shared<DeliveryTracker>();
  subscribe(notifierP, 1, atP);
  subscribe(serverObjectId, 2, atServer);

  auto event5 = make_event(sourceS);
  mEventBus->emit(event5);
  auto event6 = make_event(sourceS);
  mEventBus->emit(event6);
  ASSERT_TRUE(atServer->wait_for_count(2, dispatchTimeout))
    << "the Server Object did not receive both Events";
  wait_idle();
  // The model generation moves with a new Node.
  make_notifier(NodeId{1, 22403u});
  auto event7 = make_event(sourceS);
  mEventBus->emit(event7);
  ASSERT_TRUE(atServer->wait_for_count(3, dispatchTimeout))
    << "the Server Object did not receive the third Event";
  wait_idle();

  EXPECT_EQ(atP->delivery_count(), 0u) << "a Reference whose type could not be decided was followed";
  EXPECT_EQ(sink->count(LogLevel::Warning, "events", "EventBus.EventSourceReferenceType"), 2u)
    << "the failed lookup was not logged once before and once after the model generation moved";
}

// DL-9 decides a namespace-0 ReferenceType by its NodeId, on the fact that the namespace 0 the server loads
// has no subtype of HasEventSource but HasNotifier. A guard on that fact: every ReferenceType reached from
// References (i=31) by HasSubtype is walked back to References by its inverse HasSubtype, and only
// HasNotifier passes through HasEventSource. It fails when a NodeSet the build loads adds such a subtype.
// @relation(AC-COMP-SVR-EVENT-CLIMB-REFERENCE-TYPES-01-NAMESPACE-ZERO-GUARD, scope=function)
TEST(EventSourceReferenceTypes, NamespaceZeroHasNoSubtypeOfHasEventSourceButHasNotifier)
{
  boost::asio::thread_pool threadPool{2};
  ua::server::CreateConfig config{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};
  auto server = ua::server::Server::create(threadPool.get_executor(),
    std::move(config),
    ua::server::ServerComponents{.crypto = test_helpers::test_crypto()});
  auto addressSpace = server.address_space();
  const NodeId references{ReferenceTypeId::References};
  const NodeId hasSubtype{ReferenceTypeId::HasSubtype};
  const NodeId hasEventSource{ReferenceTypeId::HasEventSource};

  // Every ReferenceType of namespace 0 below References.
  std::vector<NodeId> referenceTypes;
  std::unordered_set<NodeId> seen{references};
  std::vector<NodeId> toVisit{references};
  while (!toVisit.empty())
  {
    const NodeId current = toVisit.back();
    toVisit.pop_back();
    auto node = addressSpace.try_find_node_sync(current);
    ASSERT_TRUE(node.is_good()) << to_string(current);
    auto refs = node.value().try_get_references_sync();
    ASSERT_TRUE(refs.is_good()) << to_string(current);
    for (const auto& reference : refs.value())
    {
      if (!reference.is_forward() || reference.type_id() != hasSubtype || !reference.target_id().is_local())
        continue;
      const NodeId subtype = reference.target_id().node_id();
      if (subtype.namespace_index() != 0 || !seen.insert(subtype).second)
        continue;
      referenceTypes.push_back(subtype);
      toVisit.push_back(subtype);
    }
  }
  ASSERT_GT(referenceTypes.size(), 30u) << "namespace 0 was not loaded";

  // Each one's supertype chain, by inverse HasSubtype, to References.
  std::vector<NodeId> throughHasEventSource;
  for (const auto& referenceType : referenceTypes)
  {
    if (referenceType == hasEventSource)
      continue;
    NodeId current = referenceType;
    for (int depth = 0; depth < 64 && current != references; ++depth)
    {
      auto node = addressSpace.try_find_node_sync(current);
      ASSERT_TRUE(node.is_good()) << to_string(current);
      auto refs = node.value().try_get_references_sync();
      ASSERT_TRUE(refs.is_good()) << to_string(current);
      std::optional<NodeId> supertype;
      for (const auto& reference : refs.value())
      {
        if (!reference.is_forward() && reference.type_id() == hasSubtype && reference.target_id().is_local())
          supertype = reference.target_id().node_id();
      }
      ASSERT_TRUE(supertype.has_value()) << to_string(current) << " has no supertype";
      current = *supertype;
      if (current == hasEventSource)
      {
        throughHasEventSource.push_back(referenceType);
        break;
      }
    }
  }
  ASSERT_EQ(throughHasEventSource.size(), 1u) << "namespace 0 holds another subtype of HasEventSource";
  EXPECT_EQ(throughHasEventSource[0], NodeId{ReferenceTypeId::HasNotifier});

  (void)server.try_shutdown_sync({.grace = std::chrono::seconds{0}});
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Part 3 section 5.4: "A View that supports Events shall provide all Events that occur in any Object used as
// EventNotifier that is part of the content of the View." The content of a View is its membership (NR-16,
// NR-28 rule 1), not what lies below the View Node. A and B are members, reachable in V's context from the
// View Node (A by Organizes, B from A by an application non-hierarchical ReferenceType); C lies below the
// View Node by Organizes and is not a member. The View's own Event is the control that V delivers at all.
// @relation(AC-SVR-EVT-ATTR-005-VIEW-AGGREGATES-EVENTS, scope=function)
TEST_F(EventBusTest, AViewDeliversTheEventsOfItsMembersNotOfWhatLiesBelowItsNode)
{
  const NodeId viewV{1, 22500u};
  const NodeId memberA{1, 22501u};
  const NodeId memberB{1, 22502u};
  const NodeId belowC{1, 22503u};
  const NodeId nonHierarchicalR{1, 22504u};
  const NodeId nonHierarchicalReferences{ReferenceTypeId::NonHierarchicalReferences};
  ensure_reference_type(nonHierarchicalReferences);
  ensure_reference_type(nonHierarchicalR);
  link(nonHierarchicalReferences, NodeId{ReferenceTypeId::HasSubtype}, nonHierarchicalR);
  auto view = mAddressSpace->try_create_sync<ViewAccessor>(viewV, NodeClass::View);
  ASSERT_TRUE(view.is_good());
  view.value().set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
  for (const auto& nodeId : {memberA, memberB, belowC})
    make_notifier(nodeId);
  link(viewV, NodeId{ReferenceTypeId::Organizes}, memberA);
  link(memberA, nonHierarchicalR, memberB);
  link(viewV, NodeId{ReferenceTypeId::Organizes}, belowC);
  ASSERT_TRUE(view.value().try_add_node_to_view_sync(memberA).is_good());
  ASSERT_TRUE(view.value().try_add_node_to_view_sync(memberB).is_good());
  auto atView = std::make_shared<DeliveryTracker>();
  subscribe(viewV, 1, atView);

  for (const auto& source : {viewV, memberA, memberB, belowC})
  {
    auto event = make_event(source);
    mEventBus->emit(event);
  }
  atView->wait_for_count(4, dispatchTimeout);
  wait_idle();

  std::set<NodeId> sources;
  for (const auto& [id, event] : atView->deliveries())
    sources.insert(event->sourceNode);
  EXPECT_TRUE(sources.contains(viewV)) << "the View's own Event was not delivered";
  EXPECT_TRUE(sources.contains(memberA)) << "the Event of member A was not delivered through the View";
  EXPECT_TRUE(sources.contains(memberB))
    << "the Event of member B, not below the View Node by a hierarchical Reference, was not delivered";
  EXPECT_FALSE(sources.contains(belowC))
    << "the Event of C, below the View Node but not a member, was delivered through the View";
}
