// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the tier-2 ua::client::detail::AlarmConditionTrackerImpl (client design section 8.8): the
// no-own-strand Alarms & Conditions tracker sub-object of EventSubscriberImpl. The tracker is constructed
// via EventSubscriberImpl::ensure_alarm_tracker over the mockable interfaces (FakeEventBackboneOps for the
// subscriber's backbone create/modify, a recording WireOps for the Condition Method calls), and its OWN
// logic is exercised directly through its on-strand hook entry points (the AlarmConditionTrackerTestAccess
// interface posts them onto the tracker's strand exactly as the subscriber's dispatch would). Covered:
//   - ConditionRefresh: refresh_async issues the well-known ConditionType.ConditionRefresh Method
//     (CL-AC-011), then collects conditions until the matching RefreshEnd (collect-until-RefreshEnd,
//     CL-AC-003/004) before completing; the tracked set reflects the refreshed conditions;
//   - Refresh re-entrancy (section 9.6.7): a second refresh while one is awaiting its RefreshEnd is REJECTED
//   with
//     Bad_RefreshInProgress (not queued), with no extra wire call;
//   - RefreshRequired (CL-AC-007): triggers an immediate refresh when idle, queues a follow-on while a
//     window is open;
//   - Ack short-circuit (CL-AC-010): acknowledge on an already-acked branch completes Bad_Condition
//     BranchAlreadyAcked inline (source-tagged) with NO wire call; the explicit-EventId overload does not
//     short-circuit; confirm is symmetric;
//   - Method routing (CL-AC-009/019/020): a Condition Method call targets ObjectId == ConditionId (never
//     the Type node), carries the branch's lastEventId + comment;
//   - AlarmHandle routing (T30): AlarmConditionTracker::handle(key) allocates a handle whose methods reach
//   the
//     tracker's wrappers with the right key; a stale handle after the tracker is gone fails safely;
//   - cache-then-observer ordering (CL-EVT-003): the tracker cache is updated BEFORE the added/removed
//     observer fires;
//   - Lifetime: the tracker runs on the subscriber's strand (no strand of its own); a deferred Call
//     completion after the owning subscriber is gone bails via weak-capture (no deref).
//
// @verifies CL-AC-003
// @relation(CL-AC-003, scope=file)
// @verifies CL-AC-004
// @relation(CL-AC-004, scope=file)
// @verifies CL-AC-005
// @relation(CL-AC-005, scope=file)
// @verifies CL-AC-006
// @relation(CL-AC-006, scope=file)
// @verifies CL-AC-007
// @relation(CL-AC-007, scope=file)
// @verifies CL-AC-009
// @relation(CL-AC-009, scope=file)
// @verifies CL-AC-010
// @relation(CL-AC-010, scope=file)
// @verifies CL-AC-011
// @relation(CL-AC-011, scope=file)
// @verifies CL-AC-012
// @relation(CL-AC-012, scope=file)
// @verifies CL-AC-013
// @relation(CL-AC-013, scope=file)
// @verifies CL-AC-017
// @relation(CL-AC-017, scope=file)
// @verifies CL-AC-019
// @relation(CL-AC-019, scope=file)
// @verifies CL-AC-020
// @relation(CL-AC-020, scope=file)
// @verifies CL-AC-026
// @relation(CL-AC-026, scope=file)
// @verifies CL-EVT-003
// @relation(CL-EVT-003, scope=file)

#include "ua_alarm_condition_tracker_impl.h"

#include "ua_alarm_condition_tracker.h"
#include "ua_alarm_condition_tracker_test_access.h"
#include "ua_attribute_id.h"
#include "ua_client_observers.h"
#include "ua_event_filter.h"
#include "ua_simple_attribute_operand.h"
#include "ua_connection.h"
#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"
#include "ua_date_time.h"
#include "ua_error_detail.h"
#include "ua_event_backbone_ops.h"
#include "ua_event_subscriber_impl.h"
#include "ua_event_subscriber_test_access.h"
#include "ua_localized_text.h"
#include "ua_log_entry.h"
#include "ua_log_sink.h"
#include "ua_logger.h"
#include "ua_method_id.h"
#include "ua_objecttype_id.h"
#include "ua_observer_sink.h"
#include "ua_status.h"

#include "fake_connection_ops.h"
#include "fake_session_ops.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/io_context.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace
{

using ua::Result;
using ua::Status;
using ua::StatusCode;
using ua::VoidResult;
using ua::client::AlarmConditionTracker;
using ua::client::AlarmConditionTrackerPolicy;
using ua::client::AlarmHandle;
using ua::client::AlarmObserver;
using ua::client::DataIntegrityKind;
using ua::client::EventNotification;
using ua::client::Session;
using ua::client::TrackedCondition;
using ua::client::TrackedKey;
using ua::client::TwoStateValue;
using ua::client::detail::AlarmConditionTrackerHandleFactory;
using ua::client::detail::AlarmConditionTrackerImpl;
using ua::client::detail::AlarmConditionTrackerTestAccess;
using ua::client::detail::BackboneRecoveryReason;
using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionImplTestAccess;
using ua::client::detail::EventBackboneCreated;
using ua::client::detail::EventBackboneOps;
using ua::client::detail::EventFilterDiagnostics;
using ua::client::detail::EventSubscriberImpl;
using ua::client::detail::EventSubscriberTestAccess;
using ua::client::detail::limit_inequality;
using ua::client::detail::non_exclusive_cross_group;
using ua::client::detail::ObserverSink;
using ua::client::detail::ObserverSlots;
using ua::test_helpers::FakeReopen;
using ua::test_helpers::FakeSessionOps;

// The minimal backbone interface the subscriber needs so a tracker can attach + create its default Server
// backbone. It is not the subject under test here (the collapsing backbone has its own suite); it only has
// to succeed so the tracker is wired.
class FakeEventBackboneOps : public EventBackboneOps
{
public:
  std::uint32_t nextSubscriptionId = 100;
  std::uint32_t nextMonitoredItemId = 500;

  void create_backbone_async(ua::NodeId /*notifier*/, ua::EventFilter /*filter*/,
    std::uint32_t /*clientHandle*/, std::uint32_t /*queueSize*/,
    std::function<void(Result<EventBackboneCreated>)> callback) noexcept override
  {
    EventBackboneCreated created;
    created.subscriptionId = nextSubscriptionId++;
    created.monitoredItemId = nextMonitoredItemId++;
    callback(Result<EventBackboneCreated>{created});
  }

  void modify_backbone_filter_async(std::uint32_t /*subscriptionId*/, std::uint32_t /*monitoredItemId*/,
    std::uint32_t /*clientHandle*/, ua::EventFilter /*filter*/,
    std::function<void(Result<EventFilterDiagnostics>)> callback) noexcept override
  {
    callback(Result<EventFilterDiagnostics>{EventFilterDiagnostics{}});
  }

  void delete_backbone_async(std::uint32_t /*subscriptionId*/, std::uint32_t /*monitoredItemId*/,
    std::function<void(VoidResult)> callback) noexcept override
  {
    callback(VoidResult{});
  }

  // These fixtures drive trackers, which attach as hooks rather than as OfType consumers, so the subtype
  // closure is not required here: report the hierarchy as "these types have no declared subtypes",
  // which is the honest answer for a fake with no type hierarchy in it.
  void resolve_event_subtypes_async(std::vector<ua::NodeId> roots,
    std::function<void(Result<std::vector<ua::NodeId>>)> callback) noexcept override
  {
    callback(Result<std::vector<ua::NodeId>>{std::move(roots)});
  }
};

// A WireOps that RECORDS every Condition Method Call and answers it with a scriptable response (default:
// Good-empty). `deferCalls` captures the completion instead of firing it, so a test can drop the tracker
// mid-flight and prove the completion bails via weak-capture.
class RecordingWireOps : public ua::test_helpers::FakeWireOps
{
public:
  std::vector<ua::CallRequest> callRequests;
  std::deque<Result<ua::CallResponse>> scriptedCallResponses;  // FIFO; else Good-empty
  bool deferCalls = false;
  std::vector<std::function<void()>> deferredCalls;

  void call_async(
    ua::CallRequest request, std::function<void(Result<ua::CallResponse>)> callback) noexcept override
  {
    callRequests.push_back(request);
    Result<ua::CallResponse> response = ua::CallResponse{};
    if (!scriptedCallResponses.empty())
    {
      response = std::move(scriptedCallResponses.front());
      scriptedCallResponses.pop_front();
    }
    auto deliver = [callback = std::move(callback), response = std::move(response)]() mutable
    {
      callback(std::move(response));
    };
    if (deferCalls)
    {
      deferredCalls.push_back(std::move(deliver));
      return;
    }
    deliver();
  }

  void fire_deferred_calls()
  {
    auto pending = std::move(deferredCalls);
    deferredCalls.clear();
    for (auto& invoke : pending)
    {
      invoke();
    }
  }
};

// A LogSink that copies each entry's level, message, and string-valued fields so a test can assert an
// advisory was emitted with a given structured `source` field (CL-AC-005).
class CapturingLogSink : public ua::LogSink
{
public:
  void log(const ua::LogEntry& entry) override
  {
    Record record;
    record.level = entry.level;
    record.message = entry.message;
    for (const auto& field : entry.fields)
    {
      if (const auto* text = std::get_if<std::string_view>(&field.value))
      {
        record.fields.emplace_back(std::string{field.key}, std::string{*text});
      }
    }
    std::lock_guard lock(mMutex);
    mRecords.push_back(std::move(record));
  }

  bool has_field(std::string_view key, std::string_view value) const
  {
    std::lock_guard lock(mMutex);
    for (const auto& record : mRecords)
    {
      for (const auto& field : record.fields)
      {
        if (field.first == key && field.second == value)
        {
          return true;
        }
      }
    }
    return false;
  }

private:
  struct Record
  {
    ua::LogLevel level{};
    std::string message;
    std::vector<std::pair<std::string, std::string>> fields;
  };

  mutable std::mutex mMutex;
  std::vector<Record> mRecords;
};

struct Fixture
{
  boost::asio::io_context ctx;
  std::shared_ptr<FakeEventBackboneOps> backbone = std::make_shared<FakeEventBackboneOps>();
  std::shared_ptr<RecordingWireOps> wire = std::make_shared<RecordingWireOps>();
  std::shared_ptr<EventSubscriberImpl> subscriber;
  std::shared_ptr<AlarmConditionTrackerImpl> tracker;

  void make(AlarmConditionTrackerPolicy policy = {}, ua::Logger logger = ua::Logger{},
    std::weak_ptr<ObserverSink> observerSink = {})
  {
    subscriber = EventSubscriberImpl::create(
      ctx.get_executor(), backbone, std::move(logger), {}, std::move(observerSink));
    tracker = subscriber->ensure_alarm_tracker(wire, policy);
    drain();  // let start_async attach the hook + create the default Server backbone
  }

  void drain()
  {
    ctx.run();
    ctx.restart();
  }
};

// ---- Event / notification builders (by-name field model, matching the tracker's decode) ----

// A single-segment field: the leaf's Value (ConditionName, Retain, BranchId, limit doubles, MaxTimeShelved).
void add_field(EventNotification& event, std::string_view name, ua::Variant value)
{
  event.fields.push_back(std::move(value));
  event.fieldPaths.push_back({ua::QualifiedName{0, std::string{name}}});
}

// A two-segment sub-state field: the spec-shaped path a server carries a TwoStateVariable Boolean at, e.g.
// [AckedState, Id]. This is the wire shape the tracker's two-segment decode reads (single-segment <State>
// would be the display-name LocalizedText, not the Boolean).
void add_state_field(EventNotification& event, std::string_view stateName, bool id)
{
  event.fields.push_back(ua::Variant{id});
  event.fieldPaths.push_back(
    {ua::QualifiedName{0, std::string{stateName}}, ua::QualifiedName{0, std::string{"Id"}}});
}

// The two-segment [parent, child] field (e.g. [LimitState, CurrentState]) carrying an arbitrary Variant.
void add_two_segment_field(
  EventNotification& event, std::string_view parent, std::string_view child, ua::Variant value)
{
  event.fields.push_back(std::move(value));
  event.fieldPaths.push_back(
    {ua::QualifiedName{0, std::string{parent}}, ua::QualifiedName{0, std::string{child}}});
}

// The ConditionId via the EMPTY-browse-path NodeId operand (Part 4 Table 133) - how a spec-shaped server
// carries the condition instance's own NodeId (CL-AC-002).
void add_condition_id(EventNotification& event, const ua::NodeId& conditionId)
{
  event.fields.push_back(ua::Variant{conditionId});
  event.fieldPaths.push_back({});  // empty browse path
}

struct ConditionFields
{
  ua::NodeId conditionId;
  ua::NodeId branchId{};
  ua::ByteString eventId{};
  bool retain = true;
  std::uint16_t severity = 100;
  ua::DateTime receiveTime{};  ///< CL-AC-005 ordering source
  ua::NodeId eventTypeId{ua::ObjectTypeId::ConditionType};
  std::optional<bool> acked;
  std::optional<bool> confirmed;
  std::optional<bool> active;
  std::optional<double> maxTimeShelved;  ///< drives the timed_shelve_async pre-flight
  ua::LocalizedText conditionName{};
  ua::NodeId conditionClassId{};
  ua::LocalizedText conditionClassName{};
  // ---- Optional AlarmConditionType sub-states (CL-AC-016) ----
  std::optional<bool> suppressed;
  std::optional<bool> outOfService;
  std::optional<bool> silence;
  std::optional<bool> latched;
  std::optional<bool> suppressedOrShelved;
  std::optional<ua::LocalizedText> shelvingState;  ///< ShelvingState.CurrentState
  // ---- Optional AlarmConditionType properties (CL-AC-022) ----
  std::optional<ua::Duration> reAlarmTime;
  std::optional<std::int16_t> reAlarmRepeatCount;
  std::optional<ua::Duration> onDelay;
  std::optional<ua::Duration> offDelay;
  std::optional<bool> audibleEnabled;
  std::optional<ua::AudioDataType> audibleSound;
  std::optional<bool> firstInGroupFlag;
  std::optional<ua::NodeId> firstInGroup;
  // ---- Discrete / OffNormal / Discrepancy subtype properties (CL-AC-021) ----
  std::optional<ua::NodeId> normalState;
  std::optional<ua::NodeId> targetValueNode;
  std::optional<ua::Duration> expectedTime;
  std::optional<double> tolerance;
};

EventNotification make_condition_event(const ConditionFields& fields)
{
  EventNotification event;
  event.eventTypeId = fields.eventTypeId;
  event.eventId = fields.eventId;
  event.severity = fields.severity;
  event.receiveTime = fields.receiveTime;
  add_condition_id(event, fields.conditionId);
  add_field(event, "BranchId", ua::Variant{fields.branchId});
  add_field(event, "Retain", ua::Variant{fields.retain});
  add_field(event, "ConditionName", ua::Variant{fields.conditionName});
  add_field(event, "ConditionClassId", ua::Variant{fields.conditionClassId});
  add_field(event, "ConditionClassName", ua::Variant{fields.conditionClassName});
  if (fields.acked.has_value())
  {
    add_state_field(event, "AckedState", *fields.acked);
  }
  if (fields.confirmed.has_value())
  {
    add_state_field(event, "ConfirmedState", *fields.confirmed);
  }
  if (fields.active.has_value())
  {
    add_state_field(event, "ActiveState", *fields.active);
  }
  if (fields.maxTimeShelved.has_value())
  {
    add_field(event, "MaxTimeShelved", ua::Variant{*fields.maxTimeShelved});
  }
  // CL-AC-016 optional sub-states - spec-shaped two-segment [<State>, "Id"], single-segment aggregate,
  // and the two-segment ShelvingState/CurrentState. Only appended when set (an omitted optional -> absent
  // field -> nullopt on decode).
  if (fields.suppressed.has_value())
  {
    add_state_field(event, "SuppressedState", *fields.suppressed);
  }
  if (fields.outOfService.has_value())
  {
    add_state_field(event, "OutOfServiceState", *fields.outOfService);
  }
  if (fields.silence.has_value())
  {
    add_state_field(event, "SilenceState", *fields.silence);
  }
  if (fields.latched.has_value())
  {
    add_state_field(event, "LatchedState", *fields.latched);
  }
  if (fields.suppressedOrShelved.has_value())
  {
    add_field(event, "SuppressedOrShelved", ua::Variant{*fields.suppressedOrShelved});
  }
  if (fields.shelvingState.has_value())
  {
    add_two_segment_field(event, "ShelvingState", "CurrentState", ua::Variant{*fields.shelvingState});
  }
  if (fields.reAlarmTime.has_value())
  {
    add_field(event, "ReAlarmTime", ua::Variant{*fields.reAlarmTime});
  }
  if (fields.reAlarmRepeatCount.has_value())
  {
    add_field(event, "ReAlarmRepeatCount", ua::Variant{*fields.reAlarmRepeatCount});
  }
  if (fields.onDelay.has_value())
  {
    add_field(event, "OnDelay", ua::Variant{*fields.onDelay});
  }
  if (fields.offDelay.has_value())
  {
    add_field(event, "OffDelay", ua::Variant{*fields.offDelay});
  }
  if (fields.audibleEnabled.has_value())
  {
    add_field(event, "AudibleEnabled", ua::Variant{*fields.audibleEnabled});
  }
  if (fields.audibleSound.has_value())
  {
    add_field(event, "AudibleSound", ua::Variant{*fields.audibleSound});
  }
  if (fields.firstInGroupFlag.has_value())
  {
    add_field(event, "FirstInGroupFlag", ua::Variant{*fields.firstInGroupFlag});
  }
  if (fields.firstInGroup.has_value())
  {
    add_field(event, "FirstInGroup", ua::Variant{*fields.firstInGroup});
  }
  if (fields.normalState.has_value())
  {
    add_field(event, "NormalState", ua::Variant{*fields.normalState});
  }
  if (fields.targetValueNode.has_value())
  {
    add_field(event, "TargetValueNode", ua::Variant{*fields.targetValueNode});
  }
  if (fields.expectedTime.has_value())
  {
    add_field(event, "ExpectedTime", ua::Variant{*fields.expectedTime});
  }
  if (fields.tolerance.has_value())
  {
    add_field(event, "Tolerance", ua::Variant{*fields.tolerance});
  }
  return event;
}

EventNotification make_refresh_notification(ua::ByteString eventId)
{
  EventNotification event;
  event.eventId = std::move(eventId);
  return event;
}

TrackedKey trunk_key(const ua::NodeId& conditionId)
{
  TrackedKey key;
  key.conditionId = conditionId;
  key.branchId = ua::NodeId{};
  return key;
}

ua::NodeId method_node(ua::MethodId method)
{
  return ua::NodeId{static_cast<std::uint32_t>(method)};
}

const ua::NodeId testConditionId{2, 4242U};
const ua::ByteString testEventId{0xAA, 0xBB, 0xCC};
const ua::ByteString refreshId{0x01, 0x02};

// The RefreshEnd's OWN EventId. OPC 10000-9 5.5.7 issues the RefreshStart (step 1) and the RefreshEnd
// (step 4) as two separate Event instances, so they never share an EventId - it says only that the copies
// WITHIN each set match. These tests used to post the end with refreshId, the start's id, and that one
// shortcut hid a defect that wedged the tracker against every conforming server: the end was looked up
// among the open start ids, never matched, and the window stayed open for the life of the tracker.
const ua::ByteString refreshEndId{0x03, 0x04};

TEST(AlarmConditionTrackerClose, CompletesAfterTheTrackerIsDestroyedBeforeDispatch)
{
  boost::asio::io_context context;
  auto tracker = AlarmConditionTrackerImpl::create(
    boost::asio::make_strand(context), context.get_executor(), {}, {}, ua::Logger{}, {});
  const std::weak_ptr<AlarmConditionTrackerImpl> lifetime = tracker;
  unsigned completions = 0;
  tracker->close_async(
    [&](VoidResult result)
    {
      ++completions;
      EXPECT_TRUE(result.is_good());
    });
  tracker.reset();
  EXPECT_TRUE(lifetime.expired());
  context.run();
  EXPECT_EQ(completions, 1U);
}

TEST(AlarmConditionTrackerClose, ClearsTrackedStateAndCompletesPendingRefresh)
{
  Fixture fixture;
  fixture.make();
  AlarmConditionTrackerTestAccess::post_event(*fixture.tracker,
    make_condition_event(ConditionFields{.conditionId = testConditionId, .eventId = testEventId}));
  fixture.drain();
  ASSERT_EQ(AlarmConditionTrackerTestAccess::tracked_count(*fixture.tracker), 1U);
  unsigned refreshCompletions = 0;
  StatusCode refreshStatus;
  fixture.tracker->refresh_async(
    [&](VoidResult result)
    {
      ++refreshCompletions;
      refreshStatus = result.status_code();
    });
  fixture.drain();
  ASSERT_TRUE(AlarmConditionTrackerTestAccess::has_pending_refresh_callback(*fixture.tracker));
  unsigned closeCompletions = 0;
  fixture.tracker->close_async(
    [&](VoidResult result)
    {
      ++closeCompletions;
      EXPECT_TRUE(result.is_good());
    });
  fixture.drain();
  EXPECT_EQ(closeCompletions, 1U);
  EXPECT_EQ(refreshCompletions, 1U);
  EXPECT_EQ(refreshStatus, StatusCode{Status::BadConnectionClosed});
  EXPECT_TRUE(AlarmConditionTrackerTestAccess::closing(*fixture.tracker));
  EXPECT_FALSE(AlarmConditionTrackerTestAccess::refresh_in_progress(*fixture.tracker));
  EXPECT_FALSE(AlarmConditionTrackerTestAccess::has_pending_refresh_callback(*fixture.tracker));
  EXPECT_EQ(AlarmConditionTrackerTestAccess::tracked_count(*fixture.tracker), 0U);
  EXPECT_EQ(AlarmConditionTrackerTestAccess::active_window_count(*fixture.tracker), 0U);
  EXPECT_EQ(fixture.tracker->info()->trackedConditionCount, 0U);
}

TEST(AlarmConditionTrackerClose, AnEmptyCompletionStillClosesTheTracker)
{
  Fixture fixture;
  fixture.make();
  fixture.tracker->close_async({});
  fixture.drain();
  EXPECT_TRUE(AlarmConditionTrackerTestAccess::closing(*fixture.tracker));
}

// ============================ Refresh (CL-AC-003/004/011) ============================

// @verifies CL-AC-011
// @relation(CL-AC-011, scope=function)
TEST(AlarmConditionTrackerRefresh, RefreshIssuesConditionRefreshMethodCallOnConditionType)
{
  Fixture f;
  f.make();

  std::optional<VoidResult> refreshResult;
  f.tracker->refresh_async([&](VoidResult result) { refreshResult = result; });
  f.drain();

  // The trigger is the well-known NS=0 ConditionType.ConditionRefresh Method on the ConditionType node
  // (CL-AC-011 - the exception to CL-AC-009's ObjectId == ConditionId rule).
  ASSERT_EQ(f.wire->callRequests.size(), 1U);
  ASSERT_EQ(f.wire->callRequests[0].methods_to_call().size(), 1U);
  const auto& method = f.wire->callRequests[0].methods_to_call()[0];
  EXPECT_EQ(method.object_id(), ua::NodeId{ua::ObjectTypeId::ConditionType});
  EXPECT_EQ(method.method_id(), method_node(ua::MethodId::ConditionType_ConditionRefresh));

  // A Good Call only CONFIRMS the trigger - the pending callback stays open until RefreshEnd arrives.
  EXPECT_FALSE(refreshResult.has_value());
  EXPECT_TRUE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));
  EXPECT_TRUE(AlarmConditionTrackerTestAccess::has_pending_refresh_callback(*f.tracker));
}

// @verifies CL-AC-003
// @verifies CL-AC-004
// @relation(CL-AC-003, CL-AC-004, scope=function)
TEST(AlarmConditionTrackerRefresh, RefreshCollectsUntilRefreshEndThenCompletesWithTrackedSet)
{
  Fixture f;
  f.make();

  std::optional<VoidResult> refreshResult;
  f.tracker->refresh_async([&](VoidResult result) { refreshResult = result; });
  f.drain();

  // RefreshStart opens the collection window (keyed on its EventId, CL-AC-004).
  AlarmConditionTrackerTestAccess::post_refresh_start(*f.tracker, make_refresh_notification(refreshId));
  f.drain();
  EXPECT_EQ(f.tracker->info()->openRefreshWindowCount, 1U);
  EXPECT_FALSE(refreshResult.has_value());  // still collecting

  // A condition delivered during the window is tracked.
  ConditionFields condition;
  condition.conditionId = testConditionId;
  condition.eventId = testEventId;
  condition.acked = false;
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
  f.drain();
  EXPECT_EQ(f.tracker->info()->trackedConditionCount, 1U);
  EXPECT_FALSE(refreshResult.has_value());  // window still open - not done

  // The matching RefreshEnd closes the window and completes the refresh.
  AlarmConditionTrackerTestAccess::post_refresh_end(*f.tracker, make_refresh_notification(refreshEndId));
  f.drain();
  ASSERT_TRUE(refreshResult.has_value());
  EXPECT_TRUE(refreshResult->is_good());
  EXPECT_EQ(f.tracker->info()->openRefreshWindowCount, 0U);
  EXPECT_FALSE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));

  // The tracked set reflects the refreshed condition (read through the real snapshot path).
  std::optional<Result<TrackedCondition>> readBack;
  f.tracker->get_condition_async(
    trunk_key(testConditionId), [&](Result<TrackedCondition> result) { readBack = std::move(result); });
  f.drain();
  ASSERT_TRUE(readBack.has_value());
  ASSERT_TRUE(readBack->is_good());
  EXPECT_EQ(readBack->value().key.conditionId, testConditionId);
  EXPECT_EQ(readBack->value().lastEventId, testEventId);  // CL-AC-019
}

// section 3.1 (Slice EV1 re-review): the CL-EVT-001 mandatory-field hard-drop must NOT apply to the Part 9
// Refresh* CONTROL events. A RefreshStart delivered THROUGH THE REAL DECODE PATH (on_publish_events_async ->
// decode_notification) with a null Time / ReceiveTime - a corner a server may cut on a synthetic control
// event - must STILL open the refresh window. If decode dropped it, handle_refresh_end would never drain the
// window and every subsequent refresh_async would return Bad_RefreshInProgress forever (the ConditionRefresh
// subsystem wedges permanently). RED before the exemption: the RefreshStart is dropped for null
// Time/ReceiveTime and no window opens.
// @verifies CL-AC-004
// @verifies CL-AC-008
// @relation(CL-AC-004, CL-AC-008, scope=function)
TEST(AlarmConditionTrackerRefresh, RefreshStartWithNullTimesDeliveredThroughDecodeOpensWindow)
{
  Fixture f;
  f.make();
  f.tracker->refresh_async([](VoidResult) {});
  f.drain();
  ASSERT_GE(EventSubscriberTestAccess::created_backbone_count(*f.subscriber), 1U);

  const auto composite = EventSubscriberTestAccess::last_sent_filter(*f.subscriber);
  ASSERT_TRUE(composite.has_value());
  const std::uint32_t backboneHandle = EventSubscriberTestAccess::backbone_client_handle(*f.subscriber, 0);

  // Build a wire RefreshStart matching the backbone composite positionally: EventType = RefreshStart, a valid
  // EventId, but Time + ReceiveTime NULL (the section 6.4.2 corner); every other selected field null.
  ua::EventFieldList wire;
  wire.client_handle() = backboneHandle;
  for (const auto& clause : composite->select_clauses())
  {
    const std::string_view name = clause.browse_path().size() == 1
                                    ? static_cast<std::string_view>(clause.browse_path()[0].name())
                                    : std::string_view{};
    if (name == "EventType")
    {
      wire.event_fields().push_back(ua::Variant{ua::NodeId{ua::ObjectTypeId::RefreshStartEventType}});
    }
    else if (name == "EventId")
    {
      wire.event_fields().push_back(ua::Variant{ua::ByteString{0x0A, 0x0B}});
    }
    else
    {
      wire.event_fields().push_back(ua::Variant{});  // null - including Time / ReceiveTime (the corner)
    }
  }

  std::vector<ua::EventFieldList> notifications;
  notifications.push_back(std::move(wire));
  f.subscriber->on_publish_events_async(backboneHandle, std::move(notifications), [] {});
  f.drain();

  EXPECT_EQ(f.tracker->info()->openRefreshWindowCount, 1U)
    << "a RefreshStart with null Time/ReceiveTime must STILL open the window through the real decode path - "
       "Refresh CONTROL events are exempt from the CL-EVT-001 mandatory-field hard-drop (dropping one would "
       "permanently wedge ConditionRefresh)";
}

// Closing ONE of several overlapping refresh windows must decrement the OBSERVABLE openRefreshWindowCount
// immediately (the info() snapshot), not leave it stuck at its peak until the last window closes. Regression
// guard for the "snapshot not republished on the non-empty RefreshEnd branch" defect.
// @verifies CL-AC-004
// @relation(CL-AC-004, scope=function)
TEST(AlarmConditionTrackerRefresh, ClosingOneOfSeveralWindowsDecrementsObservableCountImmediately)
{
  Fixture f;
  f.make();

  std::optional<VoidResult> refreshResult;
  f.tracker->refresh_async([&](VoidResult result) { refreshResult = result; });
  f.drain();

  // Two overlapping refresh cycles with distinct EventIds -> two windows (CL-AC-004).
  const ua::ByteString e1{0xE1};
  const ua::ByteString e2{0xE2};
  // Each cycle's END carries its own EventId, distinct from its start's and from the other cycle's.
  const ua::ByteString e1End{0xF1};
  const ua::ByteString e2End{0xF2};
  AlarmConditionTrackerTestAccess::post_refresh_start(*f.tracker, make_refresh_notification(e1));
  AlarmConditionTrackerTestAccess::post_refresh_start(*f.tracker, make_refresh_notification(e2));
  f.drain();
  EXPECT_EQ(f.tracker->info()->openRefreshWindowCount, 2U);

  AlarmConditionTrackerTestAccess::post_refresh_end(*f.tracker, make_refresh_notification(e1End));
  f.drain();
  EXPECT_EQ(f.tracker->info()->openRefreshWindowCount, 1U)
    << "closing one of two windows must immediately publish openRefreshWindowCount == 1";
  EXPECT_FALSE(refreshResult.has_value()) << "the refresh is not complete while a window remains open";

  AlarmConditionTrackerTestAccess::post_refresh_end(*f.tracker, make_refresh_notification(e2End));
  f.drain();
  EXPECT_EQ(f.tracker->info()->openRefreshWindowCount, 0U);
  ASSERT_TRUE(refreshResult.has_value());
  EXPECT_TRUE(refreshResult->is_good());
}

// A RefreshEnd carries its OWN EventId, never the RefreshStart's - OPC 10000-9 5.5.7 issues them as two
// separate Event instances and matches EventIds only among the copies WITHIN each set. The window must
// therefore close on an end whose EventId the tracker has never seen before. Closing on an EventId MATCH is
// the defect this pins: it can never fire against a conforming server, so the window stayed open forever,
// the in-progress latch never cleared, and every later refresh_async returned Bad_RefreshInProgress for the
// life of the tracker.
// @verifies CL-AC-004
// @relation(CL-AC-004, scope=function)
TEST(AlarmConditionTrackerRefresh, RefreshEndClosesTheWindowThoughItsEventIdDiffersFromTheStartsRefreshEnd)
{
  Fixture f;
  f.make();

  std::optional<VoidResult> refreshResult;
  f.tracker->refresh_async([&](VoidResult result) { refreshResult = result; });
  f.drain();

  AlarmConditionTrackerTestAccess::post_refresh_start(*f.tracker, make_refresh_notification(refreshId));
  f.drain();
  ASSERT_EQ(f.tracker->info()->openRefreshWindowCount, 1U);

  ASSERT_NE(refreshEndId, refreshId) << "the premise: the end's EventId is not the start's";
  AlarmConditionTrackerTestAccess::post_refresh_end(*f.tracker, make_refresh_notification(refreshEndId));
  f.drain();

  EXPECT_EQ(f.tracker->info()->openRefreshWindowCount, 0U)
    << "an unrecognised EventId on a RefreshEnd still closes the window; the pairing is positional";
  ASSERT_TRUE(refreshResult.has_value()) << "the callback completes when the window closes";
  EXPECT_TRUE(refreshResult->is_good());
  EXPECT_FALSE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker))
    << "the in-progress latch must clear, or every later refresh_async returns Bad_RefreshInProgress";
}

// 5.5.7 step 4 queues a COPY of the one RefreshEnd into every Notifier MonitoredItem of the Subscription,
// and "each of the Event copies shall contain the same EventId". Two copies are one refresh ending, so they
// must close ONE window - a per-copy close would drain a second, unrelated cycle that is still replaying.
// @verifies CL-AC-004
// @relation(CL-AC-004, scope=function)
TEST(AlarmConditionTrackerRefresh, DuplicateRefreshEndCopiesCloseOneWindowNotTwo)
{
  Fixture f;
  f.make();

  const ua::ByteString firstStart{0xA1};
  const ua::ByteString secondStart{0xA2};
  AlarmConditionTrackerTestAccess::post_refresh_start(*f.tracker, make_refresh_notification(firstStart));
  AlarmConditionTrackerTestAccess::post_refresh_start(*f.tracker, make_refresh_notification(secondStart));
  f.drain();
  ASSERT_EQ(f.tracker->info()->openRefreshWindowCount, 2U);

  // The same RefreshEnd arriving twice - the second is another Notifier's copy, not a second refresh ending.
  AlarmConditionTrackerTestAccess::post_refresh_end(*f.tracker, make_refresh_notification(refreshEndId));
  AlarmConditionTrackerTestAccess::post_refresh_end(*f.tracker, make_refresh_notification(refreshEndId));
  f.drain();

  EXPECT_EQ(f.tracker->info()->openRefreshWindowCount, 1U)
    << "the repeated copy must be collapsed; the second cycle is still replaying";
}

// Within an OPEN refresh window, a refresh-replay event whose ReceiveTime is OLDER than the tracked branch's
// (a later live event already advanced it) must be DROPPED - not overwrite the live state - and emit the
// CL-AC-005 advisory. Outside a window last-arrived semantics are unchanged.
// @verifies CL-AC-005
// @relation(CL-AC-005, scope=function)
TEST(AlarmConditionTrackerRefresh, StaleReplayDoesNotOverwriteNewerLiveBranchStateAndEmitsAdvisory)
{
  auto sink = std::make_shared<CapturingLogSink>();
  ua::Logger logger{sink, std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Trace), "test"};
  Fixture f;
  f.make({}, logger);

  // A change-observer counter proves the dropped replay fires NO change.
  int changed = 0;
  f.tracker->on_condition_changed_async([&](const TrackedCondition&) { ++changed; }, [](VoidResult) {});
  f.drain();

  // Seed the branch (added) at an early ReceiveTime, severity 100.
  ConditionFields seed;
  seed.conditionId = testConditionId;
  seed.eventId = ua::ByteString{0x01};
  seed.severity = 100;
  seed.receiveTime = ua::DateTime{2026, 1, 1, 0, 0, 1.0};
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(seed));
  f.drain();
  EXPECT_EQ(f.tracker->info()->trackedConditionCount, 1U);

  // Open a refresh window.
  f.tracker->refresh_async([](VoidResult) {});
  f.drain();
  const ua::ByteString windowId{0xE1};
  AlarmConditionTrackerTestAccess::post_refresh_start(*f.tracker, make_refresh_notification(windowId));
  f.drain();

  // A LIVE change with a NEWER ReceiveTime (severity 500) is applied.
  ConditionFields live = seed;
  live.eventId = ua::ByteString{0x02};
  live.severity = 500;
  live.receiveTime = ua::DateTime{2026, 1, 1, 0, 0, 3.0};
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(live));
  f.drain();
  EXPECT_EQ(changed, 1) << "the live change must be delivered";

  // A refresh-replay with an OLDER ReceiveTime (severity 200) must be DROPPED.
  ConditionFields stale = seed;
  stale.eventId = ua::ByteString{0x03};
  stale.severity = 200;
  stale.receiveTime = ua::DateTime{2026, 1, 1, 0, 0, 2.0};
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(stale));
  f.drain();

  std::optional<Result<TrackedCondition>> readBack;
  f.tracker->get_condition_async(
    trunk_key(testConditionId), [&](Result<TrackedCondition> result) { readBack = std::move(result); });
  f.drain();
  ASSERT_TRUE(readBack.has_value());
  ASSERT_TRUE(readBack->is_good());
  EXPECT_EQ(readBack->value().severity, 500)
    << "the stale replay (older ReceiveTime) must NOT overwrite the newer live state (CL-AC-005)";
  EXPECT_EQ(changed, 1) << "the dropped replay must fire no change observer";
  EXPECT_TRUE(sink->has_field("source", "client.tier2.alarm_tracker.refresh_replay_skipped_for_newer_live"))
    << "the drop must emit the CL-AC-005 advisory with its source tag";

  AlarmConditionTrackerTestAccess::post_refresh_end(*f.tracker, make_refresh_notification(refreshEndId));
  f.drain();
}

// @verifies CL-AC-011
// @verifies CL-DIAG-003
// @relation(CL-AC-011, CL-DIAG-003, scope=function)
TEST(AlarmConditionTrackerRefresh, RefreshWhileInProgressRejectsBadRefreshInProgress)
{
  Fixture f;
  f.make();

  std::optional<VoidResult> first;
  f.tracker->refresh_async([&](VoidResult result) { first = result; });
  f.drain();
  ASSERT_TRUE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));

  // A second refresh while the first is awaiting its RefreshEnd is REJECTED, not queued (section 9.6.7).
  std::optional<VoidResult> second;
  f.tracker->refresh_async([&](VoidResult result) { second = result; });
  f.drain();

  ASSERT_TRUE(second.has_value());
  EXPECT_TRUE(second->is_bad());
  EXPECT_EQ(second->status_code().as_uint32(), StatusCode{Status::BadRefreshInProgress}.as_uint32());
  ASSERT_NE(second->shared_detail(), nullptr);
  EXPECT_EQ(second->shared_detail()->source, "client.tier2.alarm_tracker.refresh");

  // The reject issued NO extra wire call, and did not disturb the first (still pending).
  EXPECT_EQ(f.wire->callRequests.size(), 1U);
  EXPECT_FALSE(first.has_value());
}

// @verifies CL-AC-011
// @relation(CL-AC-011, scope=function)
TEST(AlarmConditionTrackerRefresh, RefreshUsesConditionRefresh2WhenPolicyPrefersIt)
{
  // This asserts only the policy-driven initial SELECTION (preferConditionRefresh2 -> the first trigger uses
  // ConditionRefresh2). The CL-AC-012 downgrade on Bad_MethodInvalid IS implemented (section 8.8.5 rows
  // 9103/9169); its transparent-retry behaviour is exercised by
  // RefreshDowngradesToLegacyOnRefresh2MethodInvalid below.
  AlarmConditionTrackerPolicy policy;
  policy.preferConditionRefresh2 = true;

  Fixture f;
  f.make(policy);
  ASSERT_TRUE(f.tracker->info()->useRefresh2);

  f.tracker->refresh_async([](VoidResult) {});
  f.drain();

  ASSERT_EQ(f.wire->callRequests.size(), 1U);
  EXPECT_EQ(f.wire->callRequests[0].methods_to_call()[0].method_id(),
    method_node(ua::MethodId::ConditionType_ConditionRefresh2));
}

// @verifies CL-AC-012
// @relation(CL-AC-012, scope=function)
TEST(AlarmConditionTrackerRefresh, RefreshDowngradesToLegacyOnRefresh2MethodInvalid)
{
  AlarmConditionTrackerPolicy policy;
  policy.preferConditionRefresh2 = true;

  Fixture f;
  f.make(policy);
  ASSERT_TRUE(f.tracker->info()->useRefresh2);

  // CL-AC-012 (section 8.8.5 rows 9103/9169): a ConditionRefresh2 Call answered Bad_MethodInvalid must latch
  // mUseRefresh2=false PERMANENTLY and transparently RETRY as legacy ConditionRefresh on the same
  // subscription. The second (legacy) Call answers Good-empty and keeps the refresh alive until RefreshEnd.
  f.wire->scriptedCallResponses.push_back(Result<ua::CallResponse>{StatusCode{Status::BadMethodInvalid}});

  std::optional<VoidResult> refreshResult;
  f.tracker->refresh_async([&](VoidResult result) { refreshResult = result; });
  f.drain();

  // Two Calls: the rejected ConditionRefresh2, then the transparent legacy ConditionRefresh retry.
  ASSERT_EQ(f.wire->callRequests.size(), 2U);
  EXPECT_EQ(f.wire->callRequests[0].methods_to_call()[0].method_id(),
    method_node(ua::MethodId::ConditionType_ConditionRefresh2));
  EXPECT_EQ(f.wire->callRequests[1].methods_to_call()[0].method_id(),
    method_node(ua::MethodId::ConditionType_ConditionRefresh));  // downgraded to legacy

  // The downgrade is transparent: the user callback is NOT completed by the retry (still awaiting
  // RefreshEnd), useRefresh2 is latched false, and the machine remains in-progress (neither wedged nor
  // failed).
  EXPECT_FALSE(refreshResult.has_value());
  EXPECT_FALSE(f.tracker->info()->useRefresh2);
  EXPECT_TRUE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));

  // The refresh ultimately SUCCEEDS on the legacy path when its RefreshEnd arrives.
  AlarmConditionTrackerTestAccess::post_refresh_start(*f.tracker, make_refresh_notification(refreshId));
  f.drain();
  AlarmConditionTrackerTestAccess::post_refresh_end(*f.tracker, make_refresh_notification(refreshEndId));
  f.drain();
  ASSERT_TRUE(refreshResult.has_value());
  EXPECT_TRUE(refreshResult->is_good());
}

// @verifies CL-AC-011
// @relation(CL-AC-011, scope=function)
TEST(AlarmConditionTrackerRefresh, RefreshTriggerFailureCompletesImmediately)
{
  Fixture f;
  f.make();

  // A failed ConditionRefresh trigger means no window will open, so the pending callback must complete
  // immediately with the error (and clear the in-progress guard). Under the default (legacy-from-start)
  // policy there is no ConditionRefresh2 to downgrade from, so even Bad_MethodInvalid terminates the refresh
  // rather than retrying (CL-AC-012's transparent retry applies only to a ConditionRefresh2 trigger).
  f.wire->scriptedCallResponses.push_back(Result<ua::CallResponse>{StatusCode{Status::BadMethodInvalid}});

  std::optional<VoidResult> refreshResult;
  f.tracker->refresh_async([&](VoidResult result) { refreshResult = result; });
  f.drain();

  ASSERT_TRUE(refreshResult.has_value());
  EXPECT_TRUE(refreshResult->is_bad());
  EXPECT_EQ(refreshResult->status_code().as_uint32(), StatusCode{Status::BadMethodInvalid}.as_uint32());
  EXPECT_FALSE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));
  EXPECT_EQ(f.wire->callRequests.size(), 1U);  // no retry - legacy trigger failure terminates
}

// @verifies CL-AC-007
// @verifies CL-AC-003
// @relation(CL-AC-003, CL-AC-007, scope=function)
TEST(AlarmConditionTrackerRefresh, InternalRefreshBadDoesNotWedgeStateMachine)
{
  Fixture f;
  f.make();

  // An INTERNAL trigger (first-event-after-attach, CL-AC-003) starts a refresh with NO user callback. The
  // trigger Call fails with a non-MethodInvalid Bad - section 8.8.4 requires the machine to return to Idle
  // even though no user callback is pending (F1: the reset used to be gated on a pending callback -> stuck
  // forever).
  f.wire->scriptedCallResponses.push_back(
    Result<ua::CallResponse>{StatusCode{Status::BadSubscriptionIdInvalid}});

  AlarmConditionTrackerTestAccess::post_first_event_after_attach(*f.tracker);
  f.drain();

  ASSERT_EQ(f.wire->callRequests.size(), 1U);  // the internal trigger fired exactly one Call
  // The Bad trigger returned the machine to Idle (today: mRefreshInProgress stuck true -> every future
  // refresh wedged with Bad_RefreshInProgress).
  EXPECT_FALSE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));

  // A subsequent user refresh is ACCEPTED (not rejected Bad_RefreshInProgress) and issues a 2nd Call.
  std::optional<VoidResult> refreshResult;
  f.tracker->refresh_async([&](VoidResult r) { refreshResult = r; });
  f.drain();

  EXPECT_FALSE(refreshResult.has_value());  // Good trigger -> awaiting RefreshEnd, not rejected inline
  EXPECT_TRUE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));
  EXPECT_EQ(f.wire->callRequests.size(), 2U);
}

// @verifies CL-AC-007
// @relation(CL-AC-007, scope=function)
TEST(AlarmConditionTrackerRefresh, PendingFollowOnConsumedWhenUserRefreshTriggerFails)
{
  Fixture f;
  f.make();

  // The user trigger Call fails; a RefreshRequired queues a follow-on WHILE it is in flight. F1: the trigger
  // failure must complete the user callback AND still consume the queued follow-on (issue a further
  // ConditionRefresh) - the old code completed the callback but silently dropped the follow-on.
  f.wire->scriptedCallResponses.push_back(
    Result<ua::CallResponse>{StatusCode{Status::BadSubscriptionIdInvalid}});
  f.wire->deferCalls = true;

  std::optional<VoidResult> refreshResult;
  f.tracker->refresh_async([&](VoidResult r) { refreshResult = r; });
  f.drain();
  ASSERT_EQ(f.wire->callRequests.size(), 1U);
  ASSERT_TRUE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));

  // RefreshRequired arrives while the user refresh is in flight -> queues a follow-on (CL-AC-007).
  AlarmConditionTrackerTestAccess::post_refresh_required(
    *f.tracker, make_refresh_notification(ua::ByteString{}));
  f.drain();
  ASSERT_TRUE(AlarmConditionTrackerTestAccess::pending_follow_on(*f.tracker));

  // Complete the in-flight trigger with the Bad; let the follow-on re-issue complete Good.
  f.wire->deferCalls = false;
  f.wire->fire_deferred_calls();
  f.drain();

  ASSERT_TRUE(refreshResult.has_value());
  EXPECT_TRUE(refreshResult->is_bad());
  EXPECT_EQ(f.wire->callRequests.size(), 2U);  // follow-on consumed, not dropped
  EXPECT_FALSE(AlarmConditionTrackerTestAccess::pending_follow_on(*f.tracker));
  EXPECT_TRUE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));  // follow-on now in flight
}

// @verifies CL-AC-007
// @relation(CL-AC-007, scope=function)
TEST(AlarmConditionTrackerRefresh, RefreshRequiredWhileIdleTriggersImmediateRefresh)
{
  Fixture f;
  f.make();
  ASSERT_EQ(f.wire->callRequests.size(), 0U);

  // RefreshRequired with no window open triggers an internal (no user callback) refresh right away.
  AlarmConditionTrackerTestAccess::post_refresh_required(
    *f.tracker, make_refresh_notification(ua::ByteString{}));
  f.drain();

  ASSERT_EQ(f.wire->callRequests.size(), 1U);
  EXPECT_EQ(f.wire->callRequests[0].methods_to_call()[0].method_id(),
    method_node(ua::MethodId::ConditionType_ConditionRefresh));
  EXPECT_TRUE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));
  // Internal refresh - there is no user callback pending.
  EXPECT_FALSE(AlarmConditionTrackerTestAccess::has_pending_refresh_callback(*f.tracker));
}

// @verifies CL-AC-007
// @relation(CL-AC-007, scope=function)
TEST(AlarmConditionTrackerRefresh, RefreshRequiredWhileWindowOpenQueuesFollowOn)
{
  Fixture f;
  f.make();

  std::optional<VoidResult> refreshResult;
  f.tracker->refresh_async([&](VoidResult result) { refreshResult = result; });
  f.drain();
  AlarmConditionTrackerTestAccess::post_refresh_start(*f.tracker, make_refresh_notification(refreshId));
  f.drain();
  ASSERT_EQ(f.wire->callRequests.size(), 1U);

  // RefreshRequired while a window is open must NOT issue a new refresh now - it queues a follow-on.
  AlarmConditionTrackerTestAccess::post_refresh_required(
    *f.tracker, make_refresh_notification(ua::ByteString{}));
  f.drain();
  EXPECT_EQ(f.wire->callRequests.size(), 1U);
  EXPECT_TRUE(AlarmConditionTrackerTestAccess::pending_follow_on(*f.tracker));
  EXPECT_TRUE(f.tracker->info()->pendingFollowOnRefresh);

  // Closing the window drains the queued follow-on: the user callback completes AND a second refresh fires.
  AlarmConditionTrackerTestAccess::post_refresh_end(*f.tracker, make_refresh_notification(refreshEndId));
  f.drain();
  ASSERT_TRUE(refreshResult.has_value());
  EXPECT_TRUE(refreshResult->is_good());
  EXPECT_EQ(f.wire->callRequests.size(), 2U);
  EXPECT_FALSE(AlarmConditionTrackerTestAccess::pending_follow_on(*f.tracker));
}

// ============================ Acknowledge / Confirm (CL-AC-009/010/019/020) ============================

// @verifies CL-AC-010
// @relation(CL-AC-010, scope=function)
TEST(AlarmConditionTrackerAck, AcknowledgeAlreadyAckedBranchShortCircuitsWithoutWireCall)
{
  Fixture f;
  f.make();

  ConditionFields condition;
  condition.conditionId = testConditionId;
  condition.eventId = testEventId;
  condition.acked = true;  // already acknowledged
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
  f.drain();
  ASSERT_EQ(f.tracker->info()->trackedConditionCount, 1U);
  ASSERT_EQ(f.wire->callRequests.size(), 0U);

  std::optional<VoidResult> ackResult;
  f.tracker->acknowledge_async(
    trunk_key(testConditionId), std::nullopt, std::nullopt, [&](VoidResult r) { ackResult = r; });
  f.drain();

  ASSERT_TRUE(ackResult.has_value());
  EXPECT_TRUE(ackResult->is_bad());
  EXPECT_EQ(
    ackResult->status_code().as_uint32(), StatusCode{Status::BadConditionBranchAlreadyAcked}.as_uint32());
  ASSERT_NE(ackResult->shared_detail(), nullptr);
  EXPECT_EQ(ackResult->shared_detail()->source, "client.tier2.alarm_tracker.short_circuit_acked");
  EXPECT_EQ(f.wire->callRequests.size(), 0U);  // short-circuit -> NO wire call
}

// @verifies CL-AC-010
// @verifies CL-AC-009
// @relation(CL-AC-009, CL-AC-010, scope=function)
TEST(AlarmConditionTrackerAck, AcknowledgeWithExplicitEventIdBypassesShortCircuit)
{
  Fixture f;
  f.make();

  ConditionFields condition;
  condition.conditionId = testConditionId;
  condition.eventId = testEventId;
  condition.acked = true;  // already acknowledged - the no-EventId path would short-circuit
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
  f.drain();

  const ua::ByteString explicitEventId{0x11, 0x22};
  std::optional<VoidResult> ackResult;
  f.tracker->acknowledge_async(
    trunk_key(testConditionId), explicitEventId, std::nullopt, [&](VoidResult r) { ackResult = r; });
  f.drain();

  // The explicit-EventId overload does NOT short-circuit: it issues the wire Acknowledge on the ConditionId.
  ASSERT_TRUE(ackResult.has_value());
  EXPECT_TRUE(ackResult->is_good());
  ASSERT_EQ(f.wire->callRequests.size(), 1U);
  const auto& method = f.wire->callRequests[0].methods_to_call()[0];
  EXPECT_EQ(method.object_id(), testConditionId);  // CL-AC-009: ObjectId == ConditionId
  EXPECT_EQ(method.method_id(), method_node(ua::MethodId::AcknowledgeableConditionType_Acknowledge));
  ASSERT_EQ(method.input_arguments().size(), 2U);
  EXPECT_EQ(method.input_arguments()[0].to<ua::ByteString>().value(), explicitEventId);  // the explicit id
}

// @verifies CL-AC-010
// @relation(CL-AC-010, scope=function)
TEST(AlarmConditionTrackerAck, AcknowledgeUnknownBranchWithoutEventIdRejects)
{
  Fixture f;
  f.make();

  std::optional<VoidResult> ackResult;
  f.tracker->acknowledge_async(
    trunk_key(testConditionId), std::nullopt, std::nullopt, [&](VoidResult r) { ackResult = r; });
  f.drain();

  ASSERT_TRUE(ackResult.has_value());
  EXPECT_TRUE(ackResult->is_bad());
  EXPECT_EQ(ackResult->status_code().as_uint32(), StatusCode{Status::BadNodeIdUnknown}.as_uint32());
  ASSERT_NE(ackResult->shared_detail(), nullptr);
  EXPECT_EQ(ackResult->shared_detail()->source, "client.tier2.alarm_tracker.unknown_branch");
  EXPECT_EQ(f.wire->callRequests.size(), 0U);  // no branch state, no explicit id -> no wire call
}

// @verifies CL-AC-010
// @relation(CL-AC-010, scope=function)
TEST(AlarmConditionTrackerAck, ConfirmAlreadyConfirmedBranchShortCircuitsWithoutWireCall)
{
  Fixture f;
  f.make();

  ConditionFields condition;
  condition.conditionId = testConditionId;
  condition.eventId = testEventId;
  condition.confirmed = true;  // already confirmed
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
  f.drain();

  std::optional<VoidResult> confirmResult;
  f.tracker->confirm_async(
    trunk_key(testConditionId), std::nullopt, std::nullopt, [&](VoidResult r) { confirmResult = r; });
  f.drain();

  ASSERT_TRUE(confirmResult.has_value());
  EXPECT_TRUE(confirmResult->is_bad());
  EXPECT_EQ(confirmResult->status_code().as_uint32(),
    StatusCode{Status::BadConditionBranchAlreadyConfirmed}.as_uint32());
  ASSERT_NE(confirmResult->shared_detail(), nullptr);
  EXPECT_EQ(confirmResult->shared_detail()->source, "client.tier2.alarm_tracker.short_circuit_confirmed");
  EXPECT_EQ(f.wire->callRequests.size(), 0U);
}

// ---- timed_shelve_async MaxTimeShelved pre-flight (mirrors the ack/confirm short-circuit on tracked state)
// ----

// @verifies CL-AC-018
// @relation(CL-AC-018, scope=function)
TEST(AlarmConditionTrackerShelve, TimedShelveOverKnownMaxTimeShelvedShortCircuits)
{
  Fixture f;
  f.make();

  ConditionFields condition;
  condition.conditionId = testConditionId;
  condition.eventId = testEventId;
  condition.maxTimeShelved = 60000.0;  // 60s cap, carried by the event and tracked
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
  f.drain();
  ASSERT_EQ(f.tracker->info()->trackedConditionCount, 1U);

  std::optional<VoidResult> result;
  f.tracker->timed_shelve_async(trunk_key(testConditionId), 120000.0, [&](VoidResult r) { result = r; });
  f.drain();

  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->is_bad());
  EXPECT_EQ(result->status_code().as_uint32(), StatusCode{Status::BadShelvingTimeOutOfRange}.as_uint32());
  ASSERT_NE(result->shared_detail(), nullptr);
  EXPECT_EQ(result->shared_detail()->source, "client.tier2.alarm_tracker.short_circuit_max_time_shelved");
  EXPECT_EQ(f.wire->callRequests.size(), 0U);  // short-circuit -> NO wire call
}

// @verifies CL-AC-018
// @relation(CL-AC-018, scope=function)
TEST(AlarmConditionTrackerShelve, TimedShelveUnderKnownMaxTimeShelvedProceeds)
{
  Fixture f;
  f.make();

  ConditionFields condition;
  condition.conditionId = testConditionId;
  condition.eventId = testEventId;
  condition.maxTimeShelved = 60000.0;  // 30s request is under the known cap -> must NOT short-circuit
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
  f.drain();

  std::optional<VoidResult> result;
  f.tracker->timed_shelve_async(trunk_key(testConditionId), 30000.0, [&](VoidResult r) { result = r; });
  f.drain();

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(f.wire->callRequests.size(), 1U);  // under the cap -> the TimedShelve Call is issued
}

// @verifies CL-AC-018
// @relation(CL-AC-018, scope=function)
TEST(AlarmConditionTrackerShelve, TimedShelveWithUnknownMaxTimeShelvedProceeds)
{
  Fixture f;
  f.make();

  ConditionFields condition;  // no MaxTimeShelved carried -> the tracker cannot short-circuit
  condition.conditionId = testConditionId;
  condition.eventId = testEventId;
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
  f.drain();

  std::optional<VoidResult> result;
  f.tracker->timed_shelve_async(trunk_key(testConditionId), 120000.0, [&](VoidResult r) { result = r; });
  f.drain();

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(f.wire->callRequests.size(), 1U);  // unknown cap -> the server stays the authority (proceeds)
}

// @verifies CL-AC-018
// @relation(CL-AC-018, scope=function)
TEST(AlarmConditionTrackerShelve, TimedShelveExactlyAtMaxTimeShelvedProceeds)
{
  // The equality boundary: OPC 10000-9 permits ShelvingTime <= MaxTimeShelved, so a request EQUAL to the cap
  // must PROCEED (the pre-flight uses `>`, not `>=`). This pins the operator so a `>`->`>=` regression fails.
  Fixture f;
  f.make();

  ConditionFields condition;
  condition.conditionId = testConditionId;
  condition.eventId = testEventId;
  condition.maxTimeShelved = 60000.0;
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
  f.drain();

  std::optional<VoidResult> result;
  f.tracker->timed_shelve_async(trunk_key(testConditionId), 60000.0, [&](VoidResult r) { result = r; });
  f.drain();

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(f.wire->callRequests.size(), 1U);  // equal to the cap -> allowed -> the Call is issued
}

// @verifies CL-AC-018
// @relation(CL-AC-018, scope=function)
TEST(AlarmConditionTrackerShelve, TimedShelveWithNanMaxTimeShelvedFailsOpenAndProceeds)
{
  // A malformed server MaxTimeShelved of NaN must NOT wrongly refuse a valid shelve: `shelvingTime > NaN` is
  // false, so the pre-flight fails open and the server stays the authority.
  Fixture f;
  f.make();

  ConditionFields condition;
  condition.conditionId = testConditionId;
  condition.eventId = testEventId;
  condition.maxTimeShelved = std::numeric_limits<double>::quiet_NaN();
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
  f.drain();

  std::optional<VoidResult> result;
  f.tracker->timed_shelve_async(trunk_key(testConditionId), 120000.0, [&](VoidResult r) { result = r; });
  f.drain();

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(f.wire->callRequests.size(), 1U);  // NaN cap -> fail open -> proceeds
}

// @verifies CL-AC-009
// @verifies CL-AC-019
// @verifies CL-AC-020
// @relation(CL-AC-009, CL-AC-019, CL-AC-020, scope=function)
TEST(AlarmConditionTrackerAck, AcknowledgeKnownBranchCarriesLastEventIdAndNullComment)
{
  Fixture f;
  f.make();

  ConditionFields condition;
  condition.conditionId = testConditionId;
  condition.eventId = testEventId;
  condition.acked = false;  // known but not acknowledged -> proceeds to the wire call
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
  f.drain();

  std::optional<VoidResult> ackResult;
  f.tracker->acknowledge_async(
    trunk_key(testConditionId), std::nullopt, std::nullopt, [&](VoidResult r) { ackResult = r; });
  f.drain();

  ASSERT_TRUE(ackResult.has_value());
  EXPECT_TRUE(ackResult->is_good());
  ASSERT_EQ(f.wire->callRequests.size(), 1U);
  const auto& method = f.wire->callRequests[0].methods_to_call()[0];
  EXPECT_EQ(method.object_id(), testConditionId);  // CL-AC-009
  EXPECT_EQ(method.method_id(), method_node(ua::MethodId::AcknowledgeableConditionType_Acknowledge));
  ASSERT_EQ(method.input_arguments().size(), 2U);
  EXPECT_EQ(method.input_arguments()[0].to<ua::ByteString>().value(), testEventId);  // CL-AC-019: lastEventId
  // CL-AC-020: a null Comment is encoded as an empty (NULL) LocalizedText.
  EXPECT_EQ(method.input_arguments()[1].to<ua::LocalizedText>().value(), ua::LocalizedText{});
}

// ============================ AlarmHandle routing (T30) ============================

// @verifies CL-AC-009
// @relation(CL-AC-009, scope=function)
TEST(AlarmConditionTrackerHandle, HandleAcknowledgeRoutesToTrackerWithKey)
{
  Fixture f;
  f.make();

  ConditionFields condition;
  condition.conditionId = testConditionId;
  condition.eventId = testEventId;
  condition.acked = false;
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
  f.drain();

  AlarmConditionTracker publicTracker = AlarmConditionTrackerHandleFactory::create(f.tracker);
  AlarmHandle handle = publicTracker.handle(trunk_key(testConditionId));
  EXPECT_EQ(handle.key(), trunk_key(testConditionId));

  std::optional<VoidResult> ackResult;
  handle.acknowledge_async(std::nullopt, [&](VoidResult r) { ackResult = r; });
  f.drain();

  // The handle reached the tracker's acknowledge wrapper with the right key: the Call targets
  // testConditionId.
  ASSERT_TRUE(ackResult.has_value());
  EXPECT_TRUE(ackResult->is_good());
  ASSERT_EQ(f.wire->callRequests.size(), 1U);
  EXPECT_EQ(f.wire->callRequests[0].methods_to_call()[0].object_id(), testConditionId);
  EXPECT_EQ(f.wire->callRequests[0].methods_to_call()[0].method_id(),
    method_node(ua::MethodId::AcknowledgeableConditionType_Acknowledge));
}

// @verifies CL-AC-017
// @relation(CL-AC-017, scope=function)
TEST(AlarmConditionTrackerHandle, HandleShelveRoutesToTimedShelveWithKey)
{
  Fixture f;
  f.make();

  AlarmConditionTracker publicTracker = AlarmConditionTrackerHandleFactory::create(f.tracker);
  AlarmHandle handle = publicTracker.handle(trunk_key(testConditionId));

  std::optional<VoidResult> shelveResult;
  handle.shelve_async(ua::Duration{5000.0}, [&](VoidResult r) { shelveResult = r; });
  f.drain();

  // A shelve with a duration routes to TimedShelve on the ConditionId carrying the shelving time.
  ASSERT_TRUE(shelveResult.has_value());
  ASSERT_EQ(f.wire->callRequests.size(), 1U);
  const auto& method = f.wire->callRequests[0].methods_to_call()[0];
  EXPECT_EQ(method.object_id(), testConditionId);
  EXPECT_EQ(method.method_id(), method_node(ua::MethodId::ShelvedStateMachineType_TimedShelve));
  ASSERT_EQ(method.input_arguments().size(), 1U);
  EXPECT_DOUBLE_EQ(method.input_arguments()[0].to<ua::Duration>().value(), 5000.0);
}

TEST(AlarmConditionTrackerHandle, StaleHandleAfterTrackerGoneFailsSafely)
{
  Fixture f;
  f.make();

  std::optional<AlarmConditionTracker> publicTracker;
  publicTracker.emplace(AlarmConditionTrackerHandleFactory::create(f.tracker));
  AlarmHandle handle = publicTracker->handle(trunk_key(testConditionId));

  // Drop every strong owner of the tracker Impl: the public handle, the fixture ref, and the subscriber
  // that co-owns it.
  publicTracker.reset();
  f.tracker.reset();
  f.subscriber.reset();

  // The stale handle's weak tracker lock fails -> it completes Bad_ConnectionClosed inline, no deref.
  std::optional<VoidResult> result;
  handle.acknowledge_async(std::nullopt, [&](VoidResult r) { result = r; });

  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->is_bad());
  EXPECT_EQ(result->status_code().as_uint32(), StatusCode{Status::BadConnectionClosed}.as_uint32());
  ASSERT_NE(result->shared_detail(), nullptr);
  EXPECT_EQ(result->shared_detail()->source, "client.tier2.alarm_tracker.tracker_gone");
}

// ============================ cache-then-observer (CL-EVT-003) + Retain (CL-AC-006) ==================

// @verifies CL-EVT-003
// @relation(CL-EVT-003, scope=function)
TEST(AlarmConditionTrackerObservers, ConditionAddedObserverSeesUpdatedCacheBeforeItFires)
{
  Fixture f;
  f.make();

  std::size_t cacheSizeWhenObserverFired = 0;
  std::optional<TrackedCondition> observed;
  f.tracker->on_condition_added_async(
    [&](const TrackedCondition& condition)
    {
      cacheSizeWhenObserverFired = AlarmConditionTrackerTestAccess::tracked_count(*f.tracker);
      observed = condition;
    },
    [](VoidResult) {});
  f.drain();

  ConditionFields condition;
  condition.conditionId = testConditionId;
  condition.eventId = testEventId;
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
  f.drain();

  ASSERT_TRUE(observed.has_value());
  EXPECT_EQ(observed->key.conditionId, testConditionId);
  // The cache already held the new entry at the instant the observer ran (insert BEFORE notify).
  EXPECT_EQ(cacheSizeWhenObserverFired, 1U);
}

// @verifies CL-AC-006
// @relation(CL-AC-006, scope=function)
TEST(AlarmConditionTrackerObservers, RetainFalseRemovesBranchAndFiresRemovedObserver)
{
  Fixture f;
  f.make();

  std::optional<TrackedKey> removedKey;
  f.tracker->on_condition_removed_async(
    [&](TrackedKey key) { removedKey = std::move(key); }, [](VoidResult) {});
  f.drain();

  ConditionFields present;
  present.conditionId = testConditionId;
  present.eventId = testEventId;
  present.retain = true;
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(present));
  f.drain();
  ASSERT_EQ(f.tracker->info()->trackedConditionCount, 1U);

  ConditionFields retired = present;
  retired.retain = false;  // CL-AC-006: Retain=False removes the branch
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(retired));
  f.drain();

  EXPECT_EQ(f.tracker->info()->trackedConditionCount, 0U);
  ASSERT_TRUE(removedKey.has_value());
  EXPECT_EQ(removedKey->conditionId, testConditionId);
}

// ============================ Lifetime (no-own-strand + weak-capture) ============================

TEST(AlarmConditionTrackerLifetime, RunsOnSubscriberStrandWithNoStrandOfItsOwn)
{
  Fixture f;
  f.make();

  // The tracker's strand IS the subscriber's strand (section 8.8 no-own-strand sub-object).
  EXPECT_TRUE(AlarmConditionTrackerTestAccess::strand(*f.tracker) == f.subscriber->event_strand());

  // Runtime proof: a probe posted onto the tracker's strand executes within the subscriber's strand.
  bool ranOnSubscriberStrand = false;
  AlarmConditionTrackerTestAccess::post_probe(
    *f.tracker, [&] { ranOnSubscriberStrand = f.subscriber->event_strand().running_in_this_thread(); });
  f.drain();
  EXPECT_TRUE(ranOnSubscriberStrand);
}

TEST(AlarmConditionTrackerLifetime, DeferredRefreshCompletionAfterTrackerGoneBailsNoDeref)
{
  Fixture f;
  f.make();
  f.wire->deferCalls = true;

  std::optional<VoidResult> refreshResult;
  f.tracker->refresh_async([&](VoidResult r) { refreshResult = r; });
  f.drain();
  ASSERT_EQ(f.wire->callRequests.size(), 1U);  // the trigger Call is captured, not yet completed

  // Destroy the tracker (and its co-owning subscriber) BEFORE the Call completes.
  f.tracker.reset();
  f.subscriber.reset();

  // Firing the deferred completion re-posts through post_borrowing's weak-capture: the weak lock fails and
  // the continuation no-ops. No deref, no crash - and the pending refresh callback never fires.
  f.wire->fire_deferred_calls();
  f.drain();

  EXPECT_FALSE(refreshResult.has_value());
}

// ============================ Data integrity (CL-AC-023 / CL-AC-025) ============================
//
// The tier-2 tracker surfaces limit-alarm data VERBATIM and additionally ADVISES on a detected server-side
// invariant violation: a limit-ordering inversion (CL-AC-023) or a NonExclusive cross-group concurrency
// (CL-AC-025). Detection is two pure predicates over the decoded (raw) TrackedCondition; delivery is a
// source-tagged advisory log AND the AlarmObserver::on_data_integrity_warning observer hook (weak sink).

// A helper to build a NonExclusive limit sub-state value with a given active flag.
TwoStateValue limit_state(bool active)
{
  TwoStateValue value;
  value.id = active;
  return value;
}

// A limit-alarm event builder (by-name field model the tracker's decode reads). Base condition fields plus
// the four thresholds, the four NonExclusive concurrent states, and the ExclusiveLimit CurrentState - each
// present only when set, so an omitted optional surfaces as an absent field.
struct LimitFields
{
  ua::NodeId conditionId;
  ua::ByteString eventId{};
  bool retain = true;
  ua::NodeId eventTypeId{ua::ObjectTypeId::ExclusiveLimitAlarmType};
  std::optional<bool> active;
  std::optional<double> highHighLimit;
  std::optional<double> highLimit;
  std::optional<double> lowLimit;
  std::optional<double> lowLowLimit;
  std::optional<bool> highHighState;
  std::optional<bool> highState;
  std::optional<bool> lowState;
  std::optional<bool> lowLowState;
  std::optional<ua::LocalizedText> limitState;
};

EventNotification make_limit_event(const LimitFields& fields)
{
  EventNotification event;
  event.eventTypeId = fields.eventTypeId;
  event.eventId = fields.eventId;
  event.severity = 100;
  add_condition_id(event, fields.conditionId);
  add_field(event, "BranchId", ua::Variant{ua::ByteString{}});
  add_field(event, "Retain", ua::Variant{fields.retain});
  if (fields.active.has_value())
  {
    add_state_field(event, "ActiveState", *fields.active);
  }
  if (fields.highHighLimit.has_value())
  {
    add_field(event, "HighHighLimit", ua::Variant{*fields.highHighLimit});
  }
  if (fields.highLimit.has_value())
  {
    add_field(event, "HighLimit", ua::Variant{*fields.highLimit});
  }
  if (fields.lowLimit.has_value())
  {
    add_field(event, "LowLimit", ua::Variant{*fields.lowLimit});
  }
  if (fields.lowLowLimit.has_value())
  {
    add_field(event, "LowLowLimit", ua::Variant{*fields.lowLowLimit});
  }
  if (fields.highHighState.has_value())
  {
    add_state_field(event, "HighHighState", *fields.highHighState);
  }
  if (fields.highState.has_value())
  {
    add_state_field(event, "HighState", *fields.highState);
  }
  if (fields.lowState.has_value())
  {
    add_state_field(event, "LowState", *fields.lowState);
  }
  if (fields.lowLowState.has_value())
  {
    add_state_field(event, "LowLowState", *fields.lowLowState);
  }
  if (fields.limitState.has_value())
  {
    add_two_segment_field(event, "LimitState", "CurrentState", ua::Variant{*fields.limitState});
  }
  return event;
}

// ---- limit_inequality predicate (CL-AC-023) ----

// @verifies CL-AC-023
// @relation(CL-AC-023, scope=function)
TEST(AlarmConditionTrackerDataIntegrity, LimitInequalityValidOrderingDoesNotAdvise)
{
  TrackedCondition tc;
  tc.lowLowLimit = 10.0;
  tc.lowLimit = 20.0;
  tc.highLimit = 80.0;
  tc.highHighLimit = 100.0;  // LowLow <= Low <= High <= HighHigh - valid
  EXPECT_FALSE(limit_inequality(tc));
}

// @verifies CL-AC-023
// @relation(CL-AC-023, scope=function)
TEST(AlarmConditionTrackerDataIntegrity, LimitInequalityHighBelowLowAdvises)
{
  TrackedCondition tc;
  tc.lowLowLimit = 10.0;
  tc.lowLimit = 85.0;
  tc.highLimit = 80.0;  // High < Low - inversion
  tc.highHighLimit = 100.0;
  EXPECT_TRUE(limit_inequality(tc));
}

// @verifies CL-AC-023
// @relation(CL-AC-023, scope=function)
TEST(AlarmConditionTrackerDataIntegrity, LimitInequalityPartialLimitsInversionAdvises)
{
  // Only High + Low present (LowLow / HighHigh absent): High=80 < Low=85 is still an inversion (matches
  // integration Row 7). Absent limits impose no constraint but the present pair must be ordered.
  TrackedCondition tc;
  tc.highLimit = 80.0;
  tc.lowLimit = 85.0;
  EXPECT_TRUE(limit_inequality(tc));
}

// @verifies CL-AC-023
// @relation(CL-AC-023, scope=function)
TEST(AlarmConditionTrackerDataIntegrity, LimitInequalitySingleLimitDoesNotAdvise)
{
  TrackedCondition tc;
  tc.highLimit = 80.0;  // a single present limit cannot violate an ordering
  EXPECT_FALSE(limit_inequality(tc));

  TrackedCondition none;  // no limits at all -> no advise
  EXPECT_FALSE(limit_inequality(none));
}

// @verifies CL-AC-023
// @relation(CL-AC-023, scope=function)
TEST(AlarmConditionTrackerDataIntegrity, LimitInequalityNaNBetweenInvertedLimitsStillAdvises)
{
  // section 3.1 finding (NaN masking): a NaN limit decoded from the wire (to<double>() of a NaN Variant
  // is_good()) must be treated as ABSENT for ordering - it must not advance `previous`, or it would sever the
  // transitive chain and hide a real inversion between the valid limits either side of it. lowLow=100 >
  // high=1 is a genuine CL-AC-023 violation that the NaN `low` must NOT mask.
  const double nan = std::numeric_limits<double>::quiet_NaN();
  TrackedCondition tc;
  tc.lowLowLimit = 100.0;
  tc.lowLimit = nan;
  tc.highLimit = 1.0;
  EXPECT_TRUE(limit_inequality(tc));

  TrackedCondition tc2;  // the finding's second scenario: 10 / NaN / 5
  tc2.lowLowLimit = 10.0;
  tc2.lowLimit = nan;
  tc2.highLimit = 5.0;
  EXPECT_TRUE(limit_inequality(tc2));
}

// @verifies CL-AC-023
// @relation(CL-AC-023, scope=function)
TEST(AlarmConditionTrackerDataIntegrity, LimitInequalityNaNWithValidOrderingDoesNotAdvise)
{
  // The flip side: a NaN skipped for ordering must not spuriously advise when the surrounding real limits are
  // correctly ordered (1 <= 5). NaN is treated as absent, leaving a valid non-decreasing projection.
  const double nan = std::numeric_limits<double>::quiet_NaN();
  TrackedCondition tc;
  tc.lowLowLimit = 1.0;
  tc.lowLimit = nan;
  tc.highLimit = 5.0;
  EXPECT_FALSE(limit_inequality(tc));

  TrackedCondition only;  // a lone NaN limit imposes no constraint -> no advise
  only.highLimit = nan;
  EXPECT_FALSE(limit_inequality(only));
}

// ---- non_exclusive_cross_group predicate (CL-AC-025) ----
// These verify the detection LOGIC and the observer/log advisory. The events these drive now carry the
// NonExclusive states in the SPEC-SHAPED two-segment `<State>/Id` form (add_state_field), decoded by the
// tracker's two-segment path lookup - the same wire shape a real server emits (Slice AC1). CL-AC-023 (limit
// doubles) is end-to-end via a limit node's single-segment Value.

// @verifies CL-AC-025
// @relation(CL-AC-025, scope=function)
TEST(AlarmConditionTrackerDataIntegrity, NonExclusiveHighAndLowActiveAdvises)
{
  TrackedCondition tc;
  tc.highState = limit_state(true);
  tc.lowState = limit_state(true);  // cross-group: a high-group AND a low-group state active
  EXPECT_TRUE(non_exclusive_cross_group(tc));
}

// @verifies CL-AC-025
// @relation(CL-AC-025, scope=function)
TEST(AlarmConditionTrackerDataIntegrity, NonExclusiveWithinHighGroupConcurrencyIsLegal)
{
  TrackedCondition tc;
  tc.highState = limit_state(true);
  tc.highHighState = limit_state(true);  // within the high group - legal, no advise
  tc.lowState = limit_state(false);
  tc.lowLowState = limit_state(false);
  EXPECT_FALSE(non_exclusive_cross_group(tc));
}

// @verifies CL-AC-025
// @relation(CL-AC-025, scope=function)
TEST(AlarmConditionTrackerDataIntegrity, NonExclusiveWithinLowGroupConcurrencyIsLegal)
{
  TrackedCondition tc;
  tc.lowState = limit_state(true);
  tc.lowLowState = limit_state(true);  // within the low group - legal
  EXPECT_FALSE(non_exclusive_cross_group(tc));
}

// @verifies CL-AC-025
// @relation(CL-AC-025, scope=function)
TEST(AlarmConditionTrackerDataIntegrity, NonExclusiveOnlyHighActiveDoesNotAdvise)
{
  TrackedCondition tc;
  tc.highState = limit_state(true);
  tc.lowState = limit_state(false);  // low present but inactive -> no cross-group
  EXPECT_FALSE(non_exclusive_cross_group(tc));
}

// ---- decode-by-name of the new limit fields (surfaced verbatim; absent -> nullopt) ----

// @verifies CL-AC-023
// @verifies CL-AC-024
// @verifies CL-AC-025
// @relation(CL-AC-023, CL-AC-024, CL-AC-025, scope=function)
TEST(AlarmConditionTrackerDataIntegrity, DecodesLimitFieldsByNameSurfacedVerbatim)
{
  Fixture f;
  f.make();

  LimitFields alarm;
  alarm.conditionId = testConditionId;
  alarm.eventId = testEventId;
  alarm.active = true;
  alarm.highHighLimit = 100.0;
  alarm.highLimit = 80.0;
  alarm.lowLimit = 20.0;
  alarm.lowLowLimit = 10.0;
  alarm.highState = true;
  alarm.lowState = false;
  alarm.limitState = ua::LocalizedText{"", "High"};
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_limit_event(alarm));
  f.drain();

  std::optional<Result<TrackedCondition>> readBack;
  f.tracker->get_condition_async(
    trunk_key(testConditionId), [&](Result<TrackedCondition> r) { readBack = std::move(r); });
  f.drain();
  ASSERT_TRUE(readBack.has_value());
  ASSERT_TRUE(readBack->is_good());
  const TrackedCondition& tc = readBack->value();

  // Present limits surface VERBATIM (never corrected/dropped).
  ASSERT_TRUE(tc.highHighLimit.has_value());
  EXPECT_DOUBLE_EQ(*tc.highHighLimit, 100.0);
  ASSERT_TRUE(tc.highLimit.has_value());
  EXPECT_DOUBLE_EQ(*tc.highLimit, 80.0);
  ASSERT_TRUE(tc.lowLimit.has_value());
  EXPECT_DOUBLE_EQ(*tc.lowLimit, 20.0);
  ASSERT_TRUE(tc.lowLowLimit.has_value());
  EXPECT_DOUBLE_EQ(*tc.lowLowLimit, 10.0);
  ASSERT_TRUE(tc.highState.has_value());
  EXPECT_EQ(tc.highState->id, true);
  ASSERT_TRUE(tc.lowState.has_value());
  EXPECT_EQ(tc.lowState->id, false);
  ASSERT_TRUE(tc.exclusiveLimitState.has_value());
  EXPECT_EQ(*tc.exclusiveLimitState, (ua::LocalizedText{"", "High"}));

  // Absent fields surface as nullopt (a consumer can tell 'not carried' from a value).
  EXPECT_FALSE(tc.highHighState.has_value());
  EXPECT_FALSE(tc.lowLowState.has_value());
}

// ---- surface-raw guarantee: an inconsistent alarm is still tracked + its base state surfaced ----

// @verifies CL-AC-023
// @relation(CL-AC-023, scope=function)
TEST(AlarmConditionTrackerDataIntegrity, InconsistentAlarmIsStillTrackedAndSurfacedRaw)
{
  Fixture f;
  f.make();

  LimitFields alarm;
  alarm.conditionId = testConditionId;
  alarm.eventId = testEventId;
  alarm.eventTypeId = ua::NodeId{ua::ObjectTypeId::LimitAlarmType};
  alarm.active = true;
  alarm.highLimit = 80.0;
  alarm.lowLimit = 85.0;  // impossible ordering - must NOT be refused/coerced/dropped
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_limit_event(alarm));
  f.drain();

  EXPECT_EQ(f.tracker->info()->trackedConditionCount, 1U);
  std::optional<Result<TrackedCondition>> readBack;
  f.tracker->get_condition_async(
    trunk_key(testConditionId), [&](Result<TrackedCondition> r) { readBack = std::move(r); });
  f.drain();
  ASSERT_TRUE(readBack.has_value());
  ASSERT_TRUE(readBack->is_good()) << "the raw alarm must be surfaced, never refused";
  const TrackedCondition& tc = readBack->value();
  EXPECT_EQ(tc.conditionTypeId, ua::NodeId{ua::ObjectTypeId::LimitAlarmType});
  ASSERT_TRUE(tc.activeState.has_value());
  EXPECT_EQ(tc.activeState->id, true);
  // The raw (impossible) limit values are surfaced exactly as received.
  ASSERT_TRUE(tc.highLimit.has_value());
  EXPECT_DOUBLE_EQ(*tc.highLimit, 80.0);
  ASSERT_TRUE(tc.lowLimit.has_value());
  EXPECT_DOUBLE_EQ(*tc.lowLimit, 85.0);
}

// ---- observer fire: the tracker delivers on_data_integrity_warning via the weak ObserverSink ----

ua::client::ReconnectPolicy fast_reconnect_policy()
{
  ua::client::ReconnectPolicy policy;
  policy.backoff.base = std::chrono::milliseconds{1};
  policy.backoff.max = std::chrono::milliseconds{1};
  policy.backoff.jitterPct = 0.0;
  return policy;
}

// A thread-safe AlarmObserver that captures the on_data_integrity_warning hook + its args (the ObserverSink
// delivers on its own delivery strand - here, the single-threaded io_context drained on the test thread).
class RecordingAlarmObserver : public AlarmObserver
{
public:
  std::atomic<int> dataIntegrityCount{0};
  DataIntegrityKind lastKind{};
  std::shared_ptr<const ua::ErrorDetail> lastDetail;
  TrackedKey lastKey;

  // CL-AC-007: RefreshRequired fan-out capture.
  std::atomic<int> refreshRequiredCount{0};
  std::size_t lastRefreshConditionCount{0};

  void on_data_integrity_warning(const ua::client::Connection&, TrackedKey key, DataIntegrityKind kind,
    std::shared_ptr<const ua::ErrorDetail> detail) override
  {
    lastKind = kind;
    lastKey = std::move(key);
    lastDetail = std::move(detail);
    dataIntegrityCount.fetch_add(1, std::memory_order_release);
  }

  void on_refresh_required(const ua::client::Connection&, std::size_t conditionCount) override
  {
    lastRefreshConditionCount = conditionCount;
    refreshRequiredCount.fetch_add(1, std::memory_order_release);
  }
};

// Builds a live ConnectionImpl + a real per-Connection ObserverSink over it with @p observer installed in the
// alarm slot, sharing @p executor so a single io_context drives both the tracker's strand and the sink's
// delivery strand. Returned by-ref so the test keeps the Connection + sink alive.
struct SinkHarness
{
  std::shared_ptr<FakeSessionOps> session = std::make_shared<FakeSessionOps>();
  std::shared_ptr<FakeReopen> reopen = std::make_shared<FakeReopen>();
  std::shared_ptr<ua::client::detail::ConnectionImpl> connection;
  std::shared_ptr<ObserverSink> sink;

  void build(boost::asio::any_io_executor executor, std::shared_ptr<AlarmObserver> observer)
  {
    connection = ConnectionImplTestAccess::create_with_ops(executor,
      session,
      ConnectionConfig{},
      ua::Logger{},
      reopen->as_ops(),
      Session::ActivateConfig{},
      fast_reconnect_policy(),
      {});
    sink = ObserverSink::create(executor, connection);
    ObserverSlots slots;
    slots.alarm = std::move(observer);
    sink->set_slots(std::move(slots));
  }
};

// @verifies CL-AC-023
// @relation(CL-AC-023, scope=function)
TEST(AlarmConditionTrackerDataIntegrity, InequalityEventFiresObserverOnceWithSourceTaggedDetail)
{
  Fixture f;
  auto observer = std::make_shared<RecordingAlarmObserver>();
  SinkHarness harness;
  harness.build(f.ctx.get_executor(), observer);
  f.make({}, ua::Logger{}, harness.sink);

  LimitFields alarm;
  alarm.conditionId = testConditionId;
  alarm.eventId = testEventId;
  alarm.eventTypeId = ua::NodeId{ua::ObjectTypeId::LimitAlarmType};
  alarm.active = true;
  alarm.highLimit = 80.0;
  alarm.lowLimit = 85.0;  // inequality violation
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_limit_event(alarm));
  f.drain();

  ASSERT_EQ(observer->dataIntegrityCount.load(), 1);
  EXPECT_EQ(observer->lastKind, DataIntegrityKind::LimitInequality);
  EXPECT_EQ(observer->lastKey.conditionId, testConditionId);
  ASSERT_NE(observer->lastDetail, nullptr) << "the ErrorDetail must never be discarded";
  EXPECT_EQ(observer->lastDetail->code, "LimitInequalityViolated")
    << "the ErrorDetail symbolic id must be the source tag";
  EXPECT_EQ(observer->lastDetail->source, "client.tier2.alarm_tracker.limit_inequality");
}

// @verifies CL-AC-025
// @relation(CL-AC-025, scope=function)
TEST(AlarmConditionTrackerDataIntegrity, CrossGroupEventFiresObserverWithNonExclusiveKind)
{
  Fixture f;
  auto observer = std::make_shared<RecordingAlarmObserver>();
  SinkHarness harness;
  harness.build(f.ctx.get_executor(), observer);
  f.make({}, ua::Logger{}, harness.sink);

  LimitFields alarm;
  alarm.conditionId = testConditionId;
  alarm.eventId = testEventId;
  alarm.eventTypeId = ua::NodeId{ua::ObjectTypeId::NonExclusiveLimitAlarmType};
  alarm.active = true;
  alarm.highState = true;
  alarm.lowState = true;  // cross-group concurrency
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_limit_event(alarm));
  f.drain();

  ASSERT_EQ(observer->dataIntegrityCount.load(), 1);
  EXPECT_EQ(observer->lastKind, DataIntegrityKind::NonExclusiveCrossGroup);
  ASSERT_NE(observer->lastDetail, nullptr);
  EXPECT_EQ(observer->lastDetail->code, "NonExclusiveLimitCrossGroup");
}

// @verifies CL-AC-023
// @verifies CL-AC-025
// @relation(CL-AC-023, CL-AC-025, scope=function)
TEST(AlarmConditionTrackerDataIntegrity, ConsistentEventFiresNoObserver)
{
  Fixture f;
  auto observer = std::make_shared<RecordingAlarmObserver>();
  SinkHarness harness;
  harness.build(f.ctx.get_executor(), observer);
  f.make({}, ua::Logger{}, harness.sink);

  LimitFields alarm;
  alarm.conditionId = testConditionId;
  alarm.eventId = testEventId;
  alarm.eventTypeId = ua::NodeId{ua::ObjectTypeId::ExclusiveLimitAlarmType};
  alarm.active = true;
  alarm.highHighLimit = 100.0;
  alarm.highLimit = 80.0;
  alarm.lowLimit = 20.0;
  alarm.lowLowLimit = 10.0;  // consistent
  alarm.highState = true;
  alarm.highHighState = true;  // within-group concurrency - legal
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_limit_event(alarm));
  f.drain();

  EXPECT_EQ(observer->dataIntegrityCount.load(), 0)
    << "a consistent limit alarm must raise no data-integrity advisory";
}

// ============================ Refresh lifecycle: AC007 observer fire + AC003 recovery re-arm
// ============================
//
// CL-AC-007: a RefreshRequiredEventType must ALSO signal AlarmObserver::on_refresh_required (the observer
// wants to know the server asked for a resync), not only drive the internal ConditionRefresh. CL-AC-003: a
// session-CHANGED reconnect (old-session Refresh windows can never complete) must reset the tracker's dead
// refresh state and re-arm the first-event => refresh path so a fresh ConditionRefresh replays retained
// state.

// Drive one inbound Publish for backbone 0 through the REAL demux
// (EventSubscriberImpl::on_publish_events_async -> dispatch_notifications) so any tracker pending its
// first-event-after-attach fires (CL-AC-003). A single null field is enough: the first-event one-shot keys
// only on a non-empty notification list; the field itself is dropped by decode, which is irrelevant to the
// first-event trigger under test here.
void deliver_backbone_first_event(Fixture& f)
{
  const std::uint32_t backboneHandle = EventSubscriberTestAccess::backbone_client_handle(*f.subscriber, 0);
  ua::EventFieldList wire;
  wire.client_handle() = backboneHandle;
  wire.event_fields().push_back(ua::Variant{});
  std::vector<ua::EventFieldList> notifications;
  notifications.push_back(std::move(wire));
  f.subscriber->on_publish_events_async(backboneHandle, std::move(notifications), [] {});
  f.drain();
}

// @verifies CL-AC-007
// @relation(CL-AC-007, scope=function)
TEST(AlarmConditionTrackerRefresh, RefreshRequiredFiresObserverOnceWithTrackedCountAndIssuesRefresh)
{
  Fixture f;
  auto observer = std::make_shared<RecordingAlarmObserver>();
  SinkHarness harness;
  harness.build(f.ctx.get_executor(), observer);
  f.make({}, ua::Logger{}, harness.sink);

  // Seed two tracked conditions so the fired conditionCount is meaningful (!= 0).
  ConditionFields first;
  first.conditionId = testConditionId;
  first.eventId = testEventId;
  first.acked = false;
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(first));
  ConditionFields second;
  second.conditionId = ua::NodeId{2, 4243U};
  second.eventId = ua::ByteString{0xDD, 0xEE};
  second.acked = false;
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(second));
  f.drain();
  ASSERT_EQ(AlarmConditionTrackerTestAccess::tracked_count(*f.tracker), 2U);
  ASSERT_EQ(f.wire->callRequests.size(), 0U);

  // RefreshRequired while idle: the observer must be signalled AND a ConditionRefresh issued.
  AlarmConditionTrackerTestAccess::post_refresh_required(
    *f.tracker, make_refresh_notification(ua::ByteString{}));
  f.drain();

  ASSERT_EQ(observer->refreshRequiredCount.load(), 1) << "on_refresh_required must fire exactly once";
  EXPECT_EQ(observer->lastRefreshConditionCount, 2U) << "conditionCount must equal the tracked count";
  ASSERT_EQ(f.wire->callRequests.size(), 1U);
  EXPECT_EQ(f.wire->callRequests[0].methods_to_call()[0].method_id(),
    method_node(ua::MethodId::ConditionType_ConditionRefresh));
}

// @verifies CL-AC-007
// @relation(CL-AC-007, scope=function)
TEST(AlarmConditionTrackerRefresh, RefreshRequiredWhileBusyFiresObserverWithoutDoubleIssue)
{
  Fixture f;
  auto observer = std::make_shared<RecordingAlarmObserver>();
  SinkHarness harness;
  harness.build(f.ctx.get_executor(), observer);
  f.make({}, ua::Logger{}, harness.sink);

  // A user refresh in flight with an open window: mRefreshInProgress + mActiveRefreshWindows are set.
  f.tracker->refresh_async([](VoidResult) {});
  f.drain();
  AlarmConditionTrackerTestAccess::post_refresh_start(*f.tracker, make_refresh_notification(refreshId));
  f.drain();
  ASSERT_EQ(f.wire->callRequests.size(), 1U);
  ASSERT_TRUE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));

  // RefreshRequired arriving while busy still fires the observer, but the in-progress gate collapses the
  // issue (no second ConditionRefresh) - a follow-on is queued instead.
  AlarmConditionTrackerTestAccess::post_refresh_required(
    *f.tracker, make_refresh_notification(ua::ByteString{}));
  f.drain();

  EXPECT_EQ(observer->refreshRequiredCount.load(), 1)
    << "the observer fires regardless of the issue decision";
  EXPECT_EQ(f.wire->callRequests.size(), 1U) << "the in-progress gate must prevent a double ConditionRefresh";
  EXPECT_TRUE(AlarmConditionTrackerTestAccess::pending_follow_on(*f.tracker));
}

// @verifies CL-AC-003
// @relation(CL-AC-003, scope=function)
TEST(AlarmConditionTrackerRefresh, ReconnectRecoveryReArmsFirstEventSoNextEventReIssuesRefresh)
{
  Fixture f;
  f.make();

  // Baseline: the first post-attach event issues the initial ConditionRefresh (CL-AC-003).
  deliver_backbone_first_event(f);
  ASSERT_EQ(f.wire->callRequests.size(), 1U);
  ASSERT_TRUE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));

  // Complete the initial refresh so the machine is clean before recovery.
  AlarmConditionTrackerTestAccess::post_refresh_start(*f.tracker, make_refresh_notification(refreshId));
  f.drain();
  AlarmConditionTrackerTestAccess::post_refresh_end(*f.tracker, make_refresh_notification(refreshEndId));
  f.drain();
  ASSERT_FALSE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));

  // Control: without recovery the first-event one-shot has already fired - a further event re-issues nothing.
  deliver_backbone_first_event(f);
  ASSERT_EQ(f.wire->callRequests.size(), 1U);

  // Recovery re-arms the first-event path; the NEXT event must re-issue a fresh ConditionRefresh (resync).
  // The affected-set carries THIS backbone's own subscription id (it was recreated this reconnect).
  f.subscriber->on_reconnect_recovered_async(
    {EventSubscriberTestAccess::backbone_subscription_id(*f.subscriber, 0)},
    BackboneRecoveryReason::SessionReestablished);
  f.drain();
  deliver_backbone_first_event(f);
  EXPECT_EQ(f.wire->callRequests.size(), 2U)
    << "after a session-CHANGED recovery the next event must re-issue ConditionRefresh";
}

// @verifies CL-AC-003
// @relation(CL-AC-003, scope=function)
TEST(AlarmConditionTrackerRefresh, ReconnectRecoveryClearsDeadRefreshWindowAndUnwedges)
{
  Fixture f;
  f.make();

  // The first post-attach event issues the initial refresh; a RefreshStart with NO matching RefreshEnd leaves
  // a dead window + mRefreshInProgress stuck - on a session-CHANGED reconnect the RefreshEnd can never
  // arrive.
  deliver_backbone_first_event(f);
  ASSERT_EQ(f.wire->callRequests.size(), 1U);
  AlarmConditionTrackerTestAccess::post_refresh_start(*f.tracker, make_refresh_notification(refreshId));
  f.drain();
  ASSERT_EQ(AlarmConditionTrackerTestAccess::active_window_count(*f.tracker), 1U);
  ASSERT_TRUE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));

  // Recovery must clear the dead window and reset the machine (else every future refresh wedges forever).
  // The affected-set carries THIS backbone's own subscription id (it was recreated this reconnect).
  f.subscriber->on_reconnect_recovered_async(
    {EventSubscriberTestAccess::backbone_subscription_id(*f.subscriber, 0)},
    BackboneRecoveryReason::SessionReestablished);
  f.drain();
  EXPECT_EQ(AlarmConditionTrackerTestAccess::active_window_count(*f.tracker), 0U)
    << "the abandoned old-session refresh window must be cleared on recovery";
  EXPECT_FALSE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));

  // And the re-armed path re-issues on the next event (proof the reset unwedged the subsystem).
  deliver_backbone_first_event(f);
  EXPECT_EQ(f.wire->callRequests.size(), 2U);
}

// @verifies CL-AC-003
// @relation(CL-AC-003, scope=function)
TEST(AlarmConditionTrackerRefresh, ReconnectRecoveryDeliversInFlightUserRefreshBadSessionClosed)
{
  Fixture f;
  f.make();

  // A user refresh is in flight, awaiting its RefreshEnd, when the session is re-established.
  std::optional<VoidResult> refreshResult;
  f.tracker->refresh_async([&](VoidResult result) { refreshResult = result; });
  f.drain();
  ASSERT_TRUE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));
  ASSERT_TRUE(AlarmConditionTrackerTestAccess::has_pending_refresh_callback(*f.tracker));
  ASSERT_FALSE(refreshResult.has_value());

  // Recovery abandons the old-session window: the in-flight user callback must be delivered its reconnect
  // status (never silently dropped - the ErrorDetail rule), and the machine reset. The affected-set carries
  // THIS backbone's own subscription id (it was recreated this reconnect).
  f.subscriber->on_reconnect_recovered_async(
    {EventSubscriberTestAccess::backbone_subscription_id(*f.subscriber, 0)},
    BackboneRecoveryReason::SessionReestablished);
  f.drain();

  ASSERT_TRUE(refreshResult.has_value())
    << "the in-flight user refresh callback must not be silently dropped";
  EXPECT_EQ(refreshResult->status_code().as_status(), ua::Status::BadSessionClosed);
  ASSERT_NE(refreshResult->shared_detail(), nullptr)
    << "the reconnect status must carry a source-tagged detail";
  EXPECT_FALSE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));
  EXPECT_FALSE(AlarmConditionTrackerTestAccess::has_pending_refresh_callback(*f.tracker));
}

// @verifies CL-AC-003
// @relation(CL-AC-003, scope=function)
TEST(AlarmConditionTrackerRefresh, ReconnectRecoveryIssuesNoRefreshWhenNoEventHasArrived)
{
  Fixture f;
  f.make();
  ASSERT_EQ(f.wire->callRequests.size(), 0U);

  // Recovery only RE-ARMS the first-event path; it must NOT itself issue a ConditionRefresh (AC003-D1a). With
  // no post-recovery event delivered, no refresh may be triggered. Falsifiability: if recovery called
  // issue_refresh directly, callRequests would become 1 here. The affected-set carries THIS backbone's own
  // subscription id (it was recreated this reconnect).
  f.subscriber->on_reconnect_recovered_async(
    {EventSubscriberTestAccess::backbone_subscription_id(*f.subscriber, 0)},
    BackboneRecoveryReason::SessionReestablished);
  f.drain();

  EXPECT_EQ(f.wire->callRequests.size(), 0U) << "recovery must not spuriously issue a refresh with no event";
  EXPECT_FALSE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));
}

// @verifies CL-AC-003
// Finding 1 pin (section 3.1, 3/3): a MIXED session-CHANGED reconnect recreates SOME subscriptions while the
// event backbone is TRANSFERRED (kept server-side under the same id, Republish drains its windows). The
// recovery reset must be scoped to the SPECIFICALLY-recreated backbones (their create-time subscription id is
// in the affected set) - it must NOT reset a transferred backbone, which would deliver a FALSE
// Bad_SessionClosed to an in-flight ConditionRefresh, clear the active window (so the Republish-drained
// RefreshEnd later no-ops), and re-arm a redundant refresh. Falsifiability: reverting the affected-set
// `continue`-skip (resetting every created backbone unconditionally) makes the OTHER-id call below reset this
// backbone, failing the window-preserved / in-progress / no-false-completion assertions.
// @relation(CL-AC-003, scope=function)
TEST(AlarmConditionTrackerRefresh, ReconnectRecoveryReArmsOnlyRecreatedBackboneNotTransferred)
{
  Fixture f;
  f.make();

  // Put a user refresh in flight and open a RefreshStart window on the (single) backbone.
  std::optional<VoidResult> refreshResult;
  f.tracker->refresh_async([&](VoidResult result) { refreshResult = result; });
  f.drain();
  AlarmConditionTrackerTestAccess::post_refresh_start(*f.tracker, make_refresh_notification(refreshId));
  f.drain();
  ASSERT_EQ(AlarmConditionTrackerTestAccess::active_window_count(*f.tracker), 1U);
  ASSERT_TRUE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));
  ASSERT_TRUE(AlarmConditionTrackerTestAccess::has_pending_refresh_callback(*f.tracker));
  ASSERT_FALSE(refreshResult.has_value());

  const std::uint32_t backboneSubscriptionId =
    EventSubscriberTestAccess::backbone_subscription_id(*f.subscriber, 0);

  // Recovery whose affected-set names some OTHER subscription (a DIFFERENT sub was recreated; THIS event
  // backbone was TRANSFERRED, kept under its id). It must NOT touch this backbone's tracker: the window stays
  // open, the machine stays in-progress, and the in-flight user callback is NOT falsely completed
  // Bad_SessionClosed - Republish drains the transferred backbone.
  const std::uint32_t otherSubscriptionId = backboneSubscriptionId + 999U;
  f.subscriber->on_reconnect_recovered_async(
    {otherSubscriptionId}, BackboneRecoveryReason::SessionReestablished);
  f.drain();

  EXPECT_EQ(AlarmConditionTrackerTestAccess::active_window_count(*f.tracker), 1U)
    << "a transferred (non-affected) backbone must keep its refresh window";
  EXPECT_TRUE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));
  EXPECT_TRUE(AlarmConditionTrackerTestAccess::has_pending_refresh_callback(*f.tracker));
  EXPECT_FALSE(refreshResult.has_value())
    << "a transferred backbone must not deliver a false Bad_SessionClosed to an in-flight refresh";

  // Now recovery names THIS backbone's actual subscription id (it WAS recreated): the tracker IS reset -
  // window cleared, machine unwedged, and the in-flight callback delivered its reconnect status.
  f.subscriber->on_reconnect_recovered_async(
    {backboneSubscriptionId}, BackboneRecoveryReason::SessionReestablished);
  f.drain();

  EXPECT_EQ(AlarmConditionTrackerTestAccess::active_window_count(*f.tracker), 0U)
    << "the recreated backbone's dead window must be cleared";
  EXPECT_FALSE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));
  ASSERT_TRUE(refreshResult.has_value())
    << "the recreated backbone must complete the in-flight refresh (never silently dropped)";
  EXPECT_EQ(refreshResult->status_code().as_status(), ua::Status::BadSessionClosed);
}

// @relation(AC-SVR-AC-082-COLD-WARM-RESUBSCRIBE, scope=function)

// @verifies CL-AC-013
// @relation(CL-AC-013, scope=function)
TEST(AlarmConditionTrackerRefresh, ColdAndWarmRedundancySwitchClearStateAndIssueRefresh)
{
  for (const ua::RedundancySupport mode : {ua::RedundancySupport::Cold, ua::RedundancySupport::Warm})
  {
    Fixture f;
    f.make();

    ConditionFields condition;
    condition.conditionId = testConditionId;
    condition.eventId = testEventId;
    AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
    AlarmConditionTrackerTestAccess::post_refresh_start(*f.tracker, make_refresh_notification(refreshId));
    f.drain();
    ASSERT_EQ(AlarmConditionTrackerTestAccess::tracked_count(*f.tracker), 1U);
    ASSERT_EQ(AlarmConditionTrackerTestAccess::active_window_count(*f.tracker), 1U);

    f.subscriber->on_redundancy_switch_recovered_async(mode);
    f.drain();

    EXPECT_EQ(AlarmConditionTrackerTestAccess::tracked_count(*f.tracker), 0U);
    EXPECT_EQ(AlarmConditionTrackerTestAccess::active_window_count(*f.tracker), 0U);
    ASSERT_EQ(f.wire->callRequests.size(), 1U);
    EXPECT_EQ(f.wire->callRequests.front().methods_to_call()[0].method_id(),
      method_node(ua::MethodId::ConditionType_ConditionRefresh));
    EXPECT_TRUE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));
  }
}

// @verifies CL-AC-013
// @relation(CL-AC-013, scope=function)
TEST(AlarmConditionTrackerRefresh, NonColdWarmRedundancyModesDoNotRefreshOrClearState)
{
  for (const ua::RedundancySupport mode : {ua::RedundancySupport::None,
         ua::RedundancySupport::Hot,
         ua::RedundancySupport::Transparent,
         ua::RedundancySupport::HotAndMirrored})
  {
    Fixture f;
    f.make();
    ConditionFields condition;
    condition.conditionId = testConditionId;
    condition.eventId = testEventId;
    AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
    f.drain();

    f.subscriber->on_redundancy_switch_recovered_async(mode);
    f.drain();

    EXPECT_EQ(AlarmConditionTrackerTestAccess::tracked_count(*f.tracker), 1U);
    EXPECT_TRUE(f.wire->callRequests.empty());
    EXPECT_FALSE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));
  }
}

// @verifies CL-AC-013
// @relation(CL-AC-013, scope=function)
TEST(AlarmConditionTrackerRefresh, RedundancySwitchRefreshHonoursDisabledPolicy)
{
  Fixture f;
  AlarmConditionTrackerPolicy policy;
  policy.refreshOnRedundancySwitch = false;
  f.make(policy);

  ConditionFields condition;
  condition.conditionId = testConditionId;
  condition.eventId = testEventId;
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
  f.drain();

  f.subscriber->on_redundancy_switch_recovered_async(ua::RedundancySupport::Cold);
  f.drain();

  EXPECT_EQ(AlarmConditionTrackerTestAccess::tracked_count(*f.tracker), 1U);
  EXPECT_TRUE(f.wire->callRequests.empty());
  EXPECT_FALSE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));
}

// @verifies CL-AC-013
// @relation(CL-AC-013, scope=function)
TEST(AlarmConditionTrackerRefresh, ColdSwitchFailsOldUserRefreshWithDetailBeforeReissuing)
{
  Fixture f;
  f.make();
  std::optional<VoidResult> oldRefresh;
  f.tracker->refresh_async([&oldRefresh](VoidResult result) { oldRefresh = std::move(result); });
  f.drain();
  ASSERT_EQ(f.wire->callRequests.size(), 1U);

  f.subscriber->on_redundancy_switch_recovered_async(ua::RedundancySupport::Cold);
  f.drain();

  ASSERT_TRUE(oldRefresh.has_value());
  EXPECT_EQ(oldRefresh->status_code().as_status(), ua::Status::BadSessionClosed);
  ASSERT_NE(oldRefresh->shared_detail(), nullptr);
  EXPECT_EQ(f.wire->callRequests.size(), 2U)
    << "the former-server refresh is abandoned and exactly one new-server refresh is issued";
  EXPECT_TRUE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));
  EXPECT_FALSE(AlarmConditionTrackerTestAccess::has_pending_refresh_callback(*f.tracker));
}

ua::BrowsePathResult resolved_alarm_metric_node(std::uint32_t identifier)
{
  ua::BrowsePathResult result;
  result.status_code() = ua::StatusCode{ua::Status::Good};
  ua::BrowsePathTarget target;
  target.target_id() = ua::ExpandedNodeId{ua::NodeId{identifier}};
  result.targets().push_back(std::move(target));
  return result;
}

void resolve_alarm_metric_paths(RecordingWireOps& wire)
{
  wire.translateHandler = [](const ua::TranslateBrowsePathsToNodeIdsRequest& request)
  {
    ua::TranslateBrowsePathsToNodeIdsResponse response;
    for (std::size_t index = 0; index < request.browse_paths().size(); ++index)
    {
      response.results().push_back(resolved_alarm_metric_node(static_cast<std::uint32_t>(9000U + index)));
    }
    return response;
  };
}

// @verifies CL-AC-026
// @relation(CL-AC-026, scope=function)
TEST(AlarmConditionTrackerMetrics, ReadsAllMandatoryValuesAndRateMinutesThroughPublicView)
{
  Fixture f;
  f.make();
  resolve_alarm_metric_paths(*f.wire);
  const ua::DateTime start{2026, 7, 24, 12, 0, 0.0};
  ua::ReadResponse response;
  for (ua::Variant value : {ua::Variant{std::uint32_t{42}},
         ua::Variant{start},
         ua::Variant{ua::Duration{1500.0}},
         ua::Variant{ua::Duration{2400.0}},
         ua::Variant{3.5},
         ua::Variant{8.25},
         ua::Variant{std::uint32_t{7}},
         ua::Variant{2.75},
         ua::Variant{std::uint16_t{5}},
         ua::Variant{std::uint16_t{15}},
         ua::Variant{std::uint16_t{60}}})
  {
    response.results().push_back(ua::DataValue{std::move(value)});
  }
  f.wire->scriptedReadResponses.push_back(Result<ua::ReadResponse>{std::move(response)});

  AlarmConditionTracker tracker = AlarmConditionTrackerHandleFactory::create(f.tracker);
  auto view = tracker.alarm_metrics(ua::NodeId{2, 8000U});
  std::optional<Result<ua::client::AlarmMetricsSnapshot>> captured;
  view.read_all_async([&](Result<ua::client::AlarmMetricsSnapshot> result) { captured = std::move(result); });
  f.drain();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  const auto& metrics = captured->value();
  EXPECT_EQ(metrics.alarmCount, 42U);
  EXPECT_EQ(metrics.startTime, start);
  EXPECT_DOUBLE_EQ(metrics.maximumActiveState, 1500.0);
  EXPECT_DOUBLE_EQ(metrics.maximumUnAck, 2400.0);
  EXPECT_DOUBLE_EQ(metrics.currentAlarmRate.value, 3.5);
  EXPECT_EQ(metrics.currentAlarmRate.rateMinutes, 5U);
  EXPECT_DOUBLE_EQ(metrics.maximumAlarmRate.value, 8.25);
  EXPECT_EQ(metrics.maximumAlarmRate.rateMinutes, 15U);
  EXPECT_EQ(metrics.maximumReAlarmCount, 7U);
  EXPECT_DOUBLE_EQ(metrics.averageAlarmRate.value, 2.75);
  EXPECT_EQ(metrics.averageAlarmRate.rateMinutes, 60U);
  ASSERT_EQ(f.wire->readRequests.size(), 1U);
  EXPECT_EQ(f.wire->readRequests.front().nodes_to_read().size(), 11U);
}

// @verifies CL-AC-026
// @relation(CL-AC-026, scope=function)
TEST(AlarmConditionTrackerMetrics, ResetResolvesAndCallsInstanceMethod)
{
  Fixture f;
  f.make();
  unsigned translateRequests = 0;
  f.wire->translateHandler = [&translateRequests](const ua::TranslateBrowsePathsToNodeIdsRequest& request)
  {
    ++translateRequests;
    EXPECT_EQ(request.browse_paths().size(), 1U);
    if (!request.browse_paths().empty())
    {
      EXPECT_EQ(request.browse_paths()[0].starting_node(), ua::NodeId(2, 8000U));
    }
    ua::TranslateBrowsePathsToNodeIdsResponse response;
    response.results().push_back(resolved_alarm_metric_node(9000U));
    return response;
  };
  AlarmConditionTracker tracker = AlarmConditionTrackerHandleFactory::create(f.tracker);
  auto view = tracker.alarm_metrics(ua::NodeId{2, 8000U});
  std::optional<VoidResult> captured;
  view.reset_async([&](VoidResult result) { captured = std::move(result); });
  f.drain();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_good());
  EXPECT_EQ(translateRequests, 1U);
  ASSERT_EQ(f.wire->callRequests.size(), 1U);
  const auto& method = f.wire->callRequests.front().methods_to_call()[0];
  EXPECT_EQ(method.object_id(), ua::NodeId(2, 8000U));
  EXPECT_EQ(method.method_id(), ua::NodeId{9000U});
  EXPECT_TRUE(method.input_arguments().empty());

  Fixture stringFixture;
  stringFixture.make();
  const ua::NodeId stringMetricsObject{2, "AlarmMetrics-instance-with-string-identifier"};
  unsigned stringTranslateRequests = 0;
  stringFixture.wire->translateHandler = [&stringMetricsObject, &stringTranslateRequests](
                                           const ua::TranslateBrowsePathsToNodeIdsRequest& request)
  {
    ++stringTranslateRequests;
    EXPECT_EQ(request.browse_paths().size(), 1U);
    if (!request.browse_paths().empty())
    {
      EXPECT_EQ(request.browse_paths()[0].starting_node(), stringMetricsObject);
    }
    ua::TranslateBrowsePathsToNodeIdsResponse response;
    response.results().push_back(resolved_alarm_metric_node(9000U));
    return response;
  };
  AlarmConditionTracker stringTracker = AlarmConditionTrackerHandleFactory::create(stringFixture.tracker);
  auto stringView = stringTracker.alarm_metrics(stringMetricsObject);
  std::optional<VoidResult> stringCaptured;
  stringView.reset_async([&stringCaptured](VoidResult result) { stringCaptured = std::move(result); });
  stringFixture.drain();

  ASSERT_TRUE(stringCaptured.has_value());
  EXPECT_TRUE(stringCaptured->is_good());
  EXPECT_EQ(stringTranslateRequests, 1U);
  ASSERT_EQ(stringFixture.wire->callRequests.size(), 1U);
  const auto& stringMethod = stringFixture.wire->callRequests.front().methods_to_call()[0];
  EXPECT_EQ(stringMethod.object_id(), stringMetricsObject);
  EXPECT_EQ(stringMethod.method_id(), ua::NodeId{9000U});
  EXPECT_TRUE(stringMethod.input_arguments().empty());
}

// @verifies CL-AC-026
// @relation(CL-AC-026, scope=function)
TEST(AlarmConditionTrackerMetrics, TypeMismatchFailsBadDecodingError)
{
  Fixture f;
  f.make();
  resolve_alarm_metric_paths(*f.wire);
  ua::ReadResponse response;
  for (std::size_t index = 0; index < 11; ++index)
  {
    response.results().push_back(ua::DataValue{ua::Variant{std::uint32_t{99}}});
  }
  f.wire->scriptedReadResponses.push_back(Result<ua::ReadResponse>{std::move(response)});
  AlarmConditionTracker tracker = AlarmConditionTrackerHandleFactory::create(f.tracker);
  auto view = tracker.alarm_metrics(ua::NodeId{2, 8000U});
  std::optional<Result<ua::client::AlarmMetricsSnapshot>> captured;
  view.read_all_async([&](Result<ua::client::AlarmMetricsSnapshot> result) { captured = std::move(result); });
  f.drain();
  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadDecodingError);
  ASSERT_NE(captured->shared_detail(), nullptr);
}

// The AlarmMetrics read the chain answers with when it runs to the end: AlarmCount 42 and every other
// mandatory value of its type.
void script_alarm_metrics_read(RecordingWireOps& wire)
{
  ua::ReadResponse response;
  for (ua::Variant value : {ua::Variant{std::uint32_t{42}},
         ua::Variant{ua::DateTime{2026, 7, 24, 12, 0, 0.0}},
         ua::Variant{ua::Duration{1500.0}},
         ua::Variant{ua::Duration{2400.0}},
         ua::Variant{3.5},
         ua::Variant{8.25},
         ua::Variant{std::uint32_t{7}},
         ua::Variant{2.75},
         ua::Variant{std::uint16_t{5}},
         ua::Variant{std::uint16_t{15}},
         ua::Variant{std::uint16_t{60}}})
  {
    response.results().push_back(ua::DataValue{std::move(value)});
  }
  wire.scriptedReadResponses.push_back(Result<ua::ReadResponse>{std::move(response)});
}

ua::ReadResponse one_value_read(ua::Variant value)
{
  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{std::move(value)});
  return response;
}

// A Call answer only this script produces: Good ServiceResult, the method's own Uncertain status.
Result<ua::CallResponse> uncertain_call_answer()
{
  ua::CallMethodResult method;
  method.status_code() = StatusCode{Status::UncertainInitialValue};
  ua::CallResponse response;
  response.results().push_back(std::move(method));
  return Result<ua::CallResponse>{std::move(response)};
}

// Each translate->read or translate->Call chain owns the tracker for its bounded length (post_owning): the
// public completion is owed exactly one answer even if its Connection's last outside owner goes mid-chain.
// Dropping the outside owners while a response is outstanding therefore neither cuts the chain short nor
// leaks the tracker: the chain runs to its real result, answers once, and then releases the tracker. The
// chain never holds the tracker's parent EventSubscriberImpl.
// @relation(AC-CL-AC-026-CHAINS-OUTLIVE-THEIR-OUTSIDE-OWNERS, scope=function)
TEST(AlarmConditionTrackerResponseLifetime, MetricsReadHeldTranslateCompletesAfterItsOutsideOwnersGo)
{
  Fixture f;
  f.make();
  resolve_alarm_metric_paths(*f.wire);
  script_alarm_metrics_read(*f.wire);
  f.wire->deferTranslate = true;
  unsigned completions = 0;
  std::optional<Result<ua::client::AlarmMetricsSnapshot>> captured;
  f.tracker->read_alarm_metrics_async(ua::NodeId{2, 8000U},
    [&completions, &captured](Result<ua::client::AlarmMetricsSnapshot> result)
    {
      ++completions;
      captured = std::move(result);
    });
  f.drain();

  ASSERT_EQ(f.wire->deferredTranslateInvocations.size(), 1U);
  EXPECT_TRUE(f.wire->readRequests.empty());
  EXPECT_TRUE(f.wire->callRequests.empty());
  EXPECT_EQ(completions, 0U);
  const std::weak_ptr<AlarmConditionTrackerImpl> trackerLifetime = f.tracker;
  const std::weak_ptr<EventSubscriberImpl> subscriberLifetime = f.subscriber;
  f.tracker.reset();
  f.subscriber.reset();
  EXPECT_FALSE(trackerLifetime.expired()) << "the outstanding response keeps the tracker for its chain";
  EXPECT_TRUE(subscriberLifetime.expired()) << "the chain does not keep the subscriber";
  EXPECT_EQ(completions, 0U);

  f.wire->fire_deferred_translates();
  f.drain();
  ASSERT_EQ(completions, 1U);
  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_EQ(captured->value().alarmCount, 42U);
  EXPECT_EQ(f.wire->readRequests.size(), 1U);
  EXPECT_TRUE(f.wire->callRequests.empty());
  f.drain();
  EXPECT_EQ(completions, 1U);
  EXPECT_TRUE(trackerLifetime.expired()) << "the tracker is released when its chain ends";
  EXPECT_TRUE(subscriberLifetime.expired());
}

// @relation(AC-CL-AC-026-CHAINS-OUTLIVE-THEIR-OUTSIDE-OWNERS, scope=function)
TEST(AlarmConditionTrackerResponseLifetime, MetricsReadQueuedTranslateCompletesAfterItsOutsideOwnersGo)
{
  Fixture f;
  f.make();
  resolve_alarm_metric_paths(*f.wire);
  script_alarm_metrics_read(*f.wire);
  f.wire->deferTranslate = true;
  unsigned completions = 0;
  std::optional<Result<ua::client::AlarmMetricsSnapshot>> captured;
  f.tracker->read_alarm_metrics_async(ua::NodeId{2, 8000U},
    [&completions, &captured](Result<ua::client::AlarmMetricsSnapshot> result)
    {
      ++completions;
      captured = std::move(result);
    });
  f.drain();

  ASSERT_EQ(f.wire->deferredTranslateInvocations.size(), 1U);
  EXPECT_TRUE(f.wire->readRequests.empty());
  EXPECT_TRUE(f.wire->callRequests.empty());
  EXPECT_EQ(completions, 0U);
  // Queue the response while the owner is live, then drop the outside owners before its strand turn.
  f.wire->fire_deferred_translates();
  EXPECT_TRUE(f.wire->deferredTranslateInvocations.empty());
  EXPECT_EQ(completions, 0U);
  EXPECT_TRUE(f.wire->readRequests.empty());
  EXPECT_TRUE(f.wire->callRequests.empty());

  const std::weak_ptr<AlarmConditionTrackerImpl> trackerLifetime = f.tracker;
  const std::weak_ptr<EventSubscriberImpl> subscriberLifetime = f.subscriber;
  f.tracker.reset();
  f.subscriber.reset();
  EXPECT_FALSE(trackerLifetime.expired()) << "the outstanding response keeps the tracker for its chain";
  EXPECT_TRUE(subscriberLifetime.expired()) << "the chain does not keep the subscriber";
  EXPECT_EQ(completions, 0U);

  f.drain();
  ASSERT_EQ(completions, 1U);
  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_EQ(captured->value().alarmCount, 42U);
  EXPECT_EQ(f.wire->readRequests.size(), 1U);
  EXPECT_TRUE(f.wire->callRequests.empty());
  f.drain();
  EXPECT_EQ(completions, 1U);
  EXPECT_TRUE(trackerLifetime.expired()) << "the tracker is released when its chain ends";
  EXPECT_TRUE(subscriberLifetime.expired());
}

// @relation(AC-CL-AC-026-CHAINS-OUTLIVE-THEIR-OUTSIDE-OWNERS, scope=function)
TEST(AlarmConditionTrackerResponseLifetime, MetricsReadHeldSecondResponseCompletesAfterItsOutsideOwnersGo)
{
  Fixture f;
  f.make();
  resolve_alarm_metric_paths(*f.wire);
  script_alarm_metrics_read(*f.wire);
  f.wire->deferReads = true;
  unsigned completions = 0;
  std::optional<Result<ua::client::AlarmMetricsSnapshot>> captured;
  f.tracker->read_alarm_metrics_async(ua::NodeId{2, 8000U},
    [&completions, &captured](Result<ua::client::AlarmMetricsSnapshot> result)
    {
      ++completions;
      captured = std::move(result);
    });
  f.drain();

  ASSERT_EQ(f.wire->deferredReadInvocations.size(), 1U);
  EXPECT_EQ(f.wire->readRequests.size(), 1U);
  EXPECT_TRUE(f.wire->callRequests.empty());
  EXPECT_EQ(completions, 0U);
  const std::weak_ptr<AlarmConditionTrackerImpl> trackerLifetime = f.tracker;
  const std::weak_ptr<EventSubscriberImpl> subscriberLifetime = f.subscriber;
  f.tracker.reset();
  f.subscriber.reset();
  EXPECT_FALSE(trackerLifetime.expired()) << "the outstanding response keeps the tracker for its chain";
  EXPECT_TRUE(subscriberLifetime.expired()) << "the chain does not keep the subscriber";
  EXPECT_EQ(completions, 0U);

  f.wire->fire_deferred_reads();
  f.drain();
  ASSERT_EQ(completions, 1U);
  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_EQ(captured->value().alarmCount, 42U);
  EXPECT_EQ(f.wire->readRequests.size(), 1U);
  EXPECT_TRUE(f.wire->callRequests.empty());
  f.drain();
  EXPECT_EQ(completions, 1U);
  EXPECT_TRUE(trackerLifetime.expired()) << "the tracker is released when its chain ends";
  EXPECT_TRUE(subscriberLifetime.expired());
}

TEST(AlarmConditionTrackerResponseDetails, MetricsReadTranslatePreservesSharedDetail)
{
  Fixture f;
  f.make();
  resolve_alarm_metric_paths(*f.wire);
  const std::shared_ptr<const ua::ErrorDetail> detail = ua::make_error_detail(
    "MetricsReadTranslateFailure", "injected wire response failure", "test.alarm_tracker.response");
  const StatusCode failure{Status::BadUserAccessDenied, detail};
  f.wire->translateServiceStatus = failure;

  unsigned completions = 0;
  std::optional<Result<ua::client::AlarmMetricsSnapshot>> captured;
  f.tracker->read_alarm_metrics_async(ua::NodeId{2, 8000U},
    [&completions, &captured](Result<ua::client::AlarmMetricsSnapshot> result)
    {
      ++completions;
      captured = std::move(result);
    });
  f.drain();

  ASSERT_EQ(completions, 1U);
  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->status_code(), failure);
  EXPECT_EQ(captured->shared_detail(), detail);
  f.drain();
  EXPECT_EQ(completions, 1U);
  EXPECT_TRUE(f.wire->readRequests.empty());
  EXPECT_TRUE(f.wire->callRequests.empty());
}

TEST(AlarmConditionTrackerResponseDetails, MetricsReadSecondResponsePreservesSharedDetail)
{
  Fixture f;
  f.make();
  resolve_alarm_metric_paths(*f.wire);
  const std::shared_ptr<const ua::ErrorDetail> detail = ua::make_error_detail(
    "MetricsReadSecondResponseFailure", "injected wire response failure", "test.alarm_tracker.response");
  const StatusCode failure{Status::BadUserAccessDenied, detail};
  f.wire->scriptedReadResponses.push_back(Result<ua::ReadResponse>{failure});

  unsigned completions = 0;
  std::optional<Result<ua::client::AlarmMetricsSnapshot>> captured;
  f.tracker->read_alarm_metrics_async(ua::NodeId{2, 8000U},
    [&completions, &captured](Result<ua::client::AlarmMetricsSnapshot> result)
    {
      ++completions;
      captured = std::move(result);
    });
  f.drain();

  ASSERT_EQ(completions, 1U);
  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->status_code(), failure);
  EXPECT_EQ(captured->shared_detail(), detail);
  f.drain();
  EXPECT_EQ(completions, 1U);
  EXPECT_EQ(f.wire->readRequests.size(), 1U);
  EXPECT_TRUE(f.wire->callRequests.empty());
}

// @relation(AC-CL-AC-022-PROPERTY-READ-OUTLIVES-ITS-OUTSIDE-OWNERS, scope=function)
TEST(AlarmConditionTrackerResponseLifetime, PropertyReadHeldTranslateCompletesAfterItsOutsideOwnersGo)
{
  Fixture f;
  f.make();
  resolve_alarm_metric_paths(*f.wire);
  f.wire->scriptedReadResponses.push_back(Result<ua::ReadResponse>{one_value_read(ua::Variant{2.5})});
  f.wire->deferTranslate = true;
  unsigned completions = 0;
  std::optional<Result<ua::Variant>> captured;
  f.tracker->read_property_async(trunk_key(testConditionId),
    ua::QualifiedName{0, "OnDelay"},
    [&completions, &captured](Result<ua::Variant> result)
    {
      ++completions;
      captured = std::move(result);
    });
  f.drain();

  ASSERT_EQ(f.wire->deferredTranslateInvocations.size(), 1U);
  EXPECT_TRUE(f.wire->readRequests.empty());
  EXPECT_TRUE(f.wire->callRequests.empty());
  EXPECT_EQ(completions, 0U);
  const std::weak_ptr<AlarmConditionTrackerImpl> trackerLifetime = f.tracker;
  const std::weak_ptr<EventSubscriberImpl> subscriberLifetime = f.subscriber;
  f.tracker.reset();
  f.subscriber.reset();
  EXPECT_FALSE(trackerLifetime.expired()) << "the outstanding response keeps the tracker for its chain";
  EXPECT_TRUE(subscriberLifetime.expired()) << "the chain does not keep the subscriber";
  EXPECT_EQ(completions, 0U);

  f.wire->fire_deferred_translates();
  f.drain();
  ASSERT_EQ(completions, 1U);
  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_EQ(captured->value(), ua::Variant{2.5});
  EXPECT_EQ(f.wire->readRequests.size(), 1U);
  EXPECT_TRUE(f.wire->callRequests.empty());
  f.drain();
  EXPECT_EQ(completions, 1U);
  EXPECT_TRUE(trackerLifetime.expired()) << "the tracker is released when its chain ends";
  EXPECT_TRUE(subscriberLifetime.expired());
}

// @relation(AC-CL-AC-022-PROPERTY-READ-OUTLIVES-ITS-OUTSIDE-OWNERS, scope=function)
TEST(AlarmConditionTrackerResponseLifetime, PropertyReadQueuedTranslateCompletesAfterItsOutsideOwnersGo)
{
  Fixture f;
  f.make();
  resolve_alarm_metric_paths(*f.wire);
  f.wire->scriptedReadResponses.push_back(Result<ua::ReadResponse>{one_value_read(ua::Variant{2.5})});
  f.wire->deferTranslate = true;
  unsigned completions = 0;
  std::optional<Result<ua::Variant>> captured;
  f.tracker->read_property_async(trunk_key(testConditionId),
    ua::QualifiedName{0, "OnDelay"},
    [&completions, &captured](Result<ua::Variant> result)
    {
      ++completions;
      captured = std::move(result);
    });
  f.drain();

  ASSERT_EQ(f.wire->deferredTranslateInvocations.size(), 1U);
  EXPECT_TRUE(f.wire->readRequests.empty());
  EXPECT_TRUE(f.wire->callRequests.empty());
  EXPECT_EQ(completions, 0U);
  // Queue the response while the owner is live, then drop the outside owners before its strand turn.
  f.wire->fire_deferred_translates();
  EXPECT_TRUE(f.wire->deferredTranslateInvocations.empty());
  EXPECT_EQ(completions, 0U);
  EXPECT_TRUE(f.wire->readRequests.empty());
  EXPECT_TRUE(f.wire->callRequests.empty());

  const std::weak_ptr<AlarmConditionTrackerImpl> trackerLifetime = f.tracker;
  const std::weak_ptr<EventSubscriberImpl> subscriberLifetime = f.subscriber;
  f.tracker.reset();
  f.subscriber.reset();
  EXPECT_FALSE(trackerLifetime.expired()) << "the outstanding response keeps the tracker for its chain";
  EXPECT_TRUE(subscriberLifetime.expired()) << "the chain does not keep the subscriber";
  EXPECT_EQ(completions, 0U);

  f.drain();
  ASSERT_EQ(completions, 1U);
  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_EQ(captured->value(), ua::Variant{2.5});
  EXPECT_EQ(f.wire->readRequests.size(), 1U);
  EXPECT_TRUE(f.wire->callRequests.empty());
  f.drain();
  EXPECT_EQ(completions, 1U);
  EXPECT_TRUE(trackerLifetime.expired()) << "the tracker is released when its chain ends";
  EXPECT_TRUE(subscriberLifetime.expired());
}

// @relation(AC-CL-AC-022-PROPERTY-READ-OUTLIVES-ITS-OUTSIDE-OWNERS, scope=function)
TEST(AlarmConditionTrackerResponseLifetime, PropertyReadHeldSecondResponseCompletesAfterItsOutsideOwnersGo)
{
  Fixture f;
  f.make();
  resolve_alarm_metric_paths(*f.wire);
  f.wire->scriptedReadResponses.push_back(Result<ua::ReadResponse>{one_value_read(ua::Variant{2.5})});
  f.wire->deferReads = true;
  unsigned completions = 0;
  std::optional<Result<ua::Variant>> captured;
  f.tracker->read_property_async(trunk_key(testConditionId),
    ua::QualifiedName{0, "OnDelay"},
    [&completions, &captured](Result<ua::Variant> result)
    {
      ++completions;
      captured = std::move(result);
    });
  f.drain();

  ASSERT_EQ(f.wire->deferredReadInvocations.size(), 1U);
  EXPECT_EQ(f.wire->readRequests.size(), 1U);
  EXPECT_TRUE(f.wire->callRequests.empty());
  EXPECT_EQ(completions, 0U);
  const std::weak_ptr<AlarmConditionTrackerImpl> trackerLifetime = f.tracker;
  const std::weak_ptr<EventSubscriberImpl> subscriberLifetime = f.subscriber;
  f.tracker.reset();
  f.subscriber.reset();
  EXPECT_FALSE(trackerLifetime.expired()) << "the outstanding response keeps the tracker for its chain";
  EXPECT_TRUE(subscriberLifetime.expired()) << "the chain does not keep the subscriber";
  EXPECT_EQ(completions, 0U);

  f.wire->fire_deferred_reads();
  f.drain();
  ASSERT_EQ(completions, 1U);
  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_EQ(captured->value(), ua::Variant{2.5});
  EXPECT_EQ(f.wire->readRequests.size(), 1U);
  EXPECT_TRUE(f.wire->callRequests.empty());
  f.drain();
  EXPECT_EQ(completions, 1U);
  EXPECT_TRUE(trackerLifetime.expired()) << "the tracker is released when its chain ends";
  EXPECT_TRUE(subscriberLifetime.expired());
}

TEST(AlarmConditionTrackerResponseDetails, PropertyReadTranslatePreservesSharedDetail)
{
  Fixture f;
  f.make();
  resolve_alarm_metric_paths(*f.wire);
  const std::shared_ptr<const ua::ErrorDetail> detail = ua::make_error_detail(
    "PropertyReadTranslateFailure", "injected wire response failure", "test.alarm_tracker.response");
  const StatusCode failure{Status::BadUserAccessDenied, detail};
  f.wire->translateServiceStatus = failure;

  unsigned completions = 0;
  std::optional<Result<ua::Variant>> captured;
  f.tracker->read_property_async(trunk_key(testConditionId),
    ua::QualifiedName{0, "OnDelay"},
    [&completions, &captured](Result<ua::Variant> result)
    {
      ++completions;
      captured = std::move(result);
    });
  f.drain();

  ASSERT_EQ(completions, 1U);
  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->status_code(), failure);
  EXPECT_EQ(captured->shared_detail(), detail);
  f.drain();
  EXPECT_EQ(completions, 1U);
  EXPECT_TRUE(f.wire->readRequests.empty());
  EXPECT_TRUE(f.wire->callRequests.empty());
}

TEST(AlarmConditionTrackerResponseDetails, PropertyReadSecondResponsePreservesSharedDetail)
{
  Fixture f;
  f.make();
  resolve_alarm_metric_paths(*f.wire);
  const std::shared_ptr<const ua::ErrorDetail> detail = ua::make_error_detail(
    "PropertyReadSecondResponseFailure", "injected wire response failure", "test.alarm_tracker.response");
  const StatusCode failure{Status::BadUserAccessDenied, detail};
  f.wire->scriptedReadResponses.push_back(Result<ua::ReadResponse>{failure});

  unsigned completions = 0;
  std::optional<Result<ua::Variant>> captured;
  f.tracker->read_property_async(trunk_key(testConditionId),
    ua::QualifiedName{0, "OnDelay"},
    [&completions, &captured](Result<ua::Variant> result)
    {
      ++completions;
      captured = std::move(result);
    });
  f.drain();

  ASSERT_EQ(completions, 1U);
  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->status_code(), failure);
  EXPECT_EQ(captured->shared_detail(), detail);
  f.drain();
  EXPECT_EQ(completions, 1U);
  EXPECT_EQ(f.wire->readRequests.size(), 1U);
  EXPECT_TRUE(f.wire->callRequests.empty());
}

// @relation(AC-CL-AC-026-CHAINS-OUTLIVE-THEIR-OUTSIDE-OWNERS, scope=function)
TEST(AlarmConditionTrackerResponseLifetime, MetricsResetHeldTranslateCompletesAfterItsOutsideOwnersGo)
{
  Fixture f;
  f.make();
  resolve_alarm_metric_paths(*f.wire);
  f.wire->scriptedCallResponses.push_back(uncertain_call_answer());
  f.wire->deferTranslate = true;
  unsigned completions = 0;
  std::optional<VoidResult> captured;
  f.tracker->reset_alarm_metrics_async(ua::NodeId{2, 8000U},
    [&completions, &captured](VoidResult result)
    {
      ++completions;
      captured = std::move(result);
    });
  f.drain();

  ASSERT_EQ(f.wire->deferredTranslateInvocations.size(), 1U);
  EXPECT_TRUE(f.wire->readRequests.empty());
  EXPECT_TRUE(f.wire->callRequests.empty());
  EXPECT_EQ(completions, 0U);
  const std::weak_ptr<AlarmConditionTrackerImpl> trackerLifetime = f.tracker;
  const std::weak_ptr<EventSubscriberImpl> subscriberLifetime = f.subscriber;
  f.tracker.reset();
  f.subscriber.reset();
  EXPECT_FALSE(trackerLifetime.expired()) << "the outstanding response keeps the tracker for its chain";
  EXPECT_TRUE(subscriberLifetime.expired()) << "the chain does not keep the subscriber";
  EXPECT_EQ(completions, 0U);

  f.wire->fire_deferred_translates();
  f.drain();
  ASSERT_EQ(completions, 1U);
  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->status_code(), StatusCode{Status::UncertainInitialValue});
  EXPECT_EQ(f.wire->callRequests.size(), 1U);
  EXPECT_TRUE(f.wire->readRequests.empty());
  f.drain();
  EXPECT_EQ(completions, 1U);
  EXPECT_TRUE(trackerLifetime.expired()) << "the tracker is released when its chain ends";
  EXPECT_TRUE(subscriberLifetime.expired());
}

// @relation(AC-CL-AC-026-CHAINS-OUTLIVE-THEIR-OUTSIDE-OWNERS, scope=function)
TEST(AlarmConditionTrackerResponseLifetime, MetricsResetQueuedTranslateCompletesAfterItsOutsideOwnersGo)
{
  Fixture f;
  f.make();
  resolve_alarm_metric_paths(*f.wire);
  f.wire->scriptedCallResponses.push_back(uncertain_call_answer());
  f.wire->deferTranslate = true;
  unsigned completions = 0;
  std::optional<VoidResult> captured;
  f.tracker->reset_alarm_metrics_async(ua::NodeId{2, 8000U},
    [&completions, &captured](VoidResult result)
    {
      ++completions;
      captured = std::move(result);
    });
  f.drain();

  ASSERT_EQ(f.wire->deferredTranslateInvocations.size(), 1U);
  EXPECT_TRUE(f.wire->readRequests.empty());
  EXPECT_TRUE(f.wire->callRequests.empty());
  EXPECT_EQ(completions, 0U);
  // Queue the response while the owner is live, then drop the outside owners before its strand turn.
  f.wire->fire_deferred_translates();
  EXPECT_TRUE(f.wire->deferredTranslateInvocations.empty());
  EXPECT_EQ(completions, 0U);
  EXPECT_TRUE(f.wire->readRequests.empty());
  EXPECT_TRUE(f.wire->callRequests.empty());

  const std::weak_ptr<AlarmConditionTrackerImpl> trackerLifetime = f.tracker;
  const std::weak_ptr<EventSubscriberImpl> subscriberLifetime = f.subscriber;
  f.tracker.reset();
  f.subscriber.reset();
  EXPECT_FALSE(trackerLifetime.expired()) << "the outstanding response keeps the tracker for its chain";
  EXPECT_TRUE(subscriberLifetime.expired()) << "the chain does not keep the subscriber";
  EXPECT_EQ(completions, 0U);

  f.drain();
  ASSERT_EQ(completions, 1U);
  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->status_code(), StatusCode{Status::UncertainInitialValue});
  EXPECT_EQ(f.wire->callRequests.size(), 1U);
  EXPECT_TRUE(f.wire->readRequests.empty());
  f.drain();
  EXPECT_EQ(completions, 1U);
  EXPECT_TRUE(trackerLifetime.expired()) << "the tracker is released when its chain ends";
  EXPECT_TRUE(subscriberLifetime.expired());
}

// @relation(AC-CL-AC-026-CHAINS-OUTLIVE-THEIR-OUTSIDE-OWNERS, scope=function)
TEST(AlarmConditionTrackerResponseLifetime, MetricsResetHeldSecondResponseCompletesAfterItsOutsideOwnersGo)
{
  Fixture f;
  f.make();
  resolve_alarm_metric_paths(*f.wire);
  f.wire->scriptedCallResponses.push_back(uncertain_call_answer());
  f.wire->deferCalls = true;
  unsigned completions = 0;
  std::optional<VoidResult> captured;
  f.tracker->reset_alarm_metrics_async(ua::NodeId{2, 8000U},
    [&completions, &captured](VoidResult result)
    {
      ++completions;
      captured = std::move(result);
    });
  f.drain();

  ASSERT_EQ(f.wire->deferredCalls.size(), 1U);
  EXPECT_EQ(f.wire->callRequests.size(), 1U);
  EXPECT_TRUE(f.wire->readRequests.empty());
  EXPECT_EQ(completions, 0U);
  const std::weak_ptr<AlarmConditionTrackerImpl> trackerLifetime = f.tracker;
  const std::weak_ptr<EventSubscriberImpl> subscriberLifetime = f.subscriber;
  f.tracker.reset();
  f.subscriber.reset();
  EXPECT_FALSE(trackerLifetime.expired()) << "the outstanding response keeps the tracker for its chain";
  EXPECT_TRUE(subscriberLifetime.expired()) << "the chain does not keep the subscriber";
  EXPECT_EQ(completions, 0U);

  f.wire->fire_deferred_calls();
  f.drain();
  ASSERT_EQ(completions, 1U);
  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->status_code(), StatusCode{Status::UncertainInitialValue});
  EXPECT_EQ(f.wire->callRequests.size(), 1U);
  EXPECT_TRUE(f.wire->readRequests.empty());
  f.drain();
  EXPECT_EQ(completions, 1U);
  EXPECT_TRUE(trackerLifetime.expired()) << "the tracker is released when its chain ends";
  EXPECT_TRUE(subscriberLifetime.expired());
}

TEST(AlarmConditionTrackerResponseDetails, MetricsResetTranslatePreservesSharedDetail)
{
  Fixture f;
  f.make();
  resolve_alarm_metric_paths(*f.wire);
  const std::shared_ptr<const ua::ErrorDetail> detail = ua::make_error_detail(
    "MetricsResetTranslateFailure", "injected wire response failure", "test.alarm_tracker.response");
  const StatusCode failure{Status::BadUserAccessDenied, detail};
  f.wire->translateServiceStatus = failure;

  unsigned completions = 0;
  std::optional<VoidResult> captured;
  f.tracker->reset_alarm_metrics_async(ua::NodeId{2, 8000U},
    [&completions, &captured](VoidResult result)
    {
      ++completions;
      captured = std::move(result);
    });
  f.drain();

  ASSERT_EQ(completions, 1U);
  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->status_code(), failure);
  EXPECT_EQ(captured->shared_detail(), detail);
  f.drain();
  EXPECT_EQ(completions, 1U);
  EXPECT_TRUE(f.wire->readRequests.empty());
  EXPECT_TRUE(f.wire->callRequests.empty());
}

TEST(AlarmConditionTrackerResponseDetails, MetricsResetSecondResponsePreservesSharedDetail)
{
  Fixture f;
  f.make();
  resolve_alarm_metric_paths(*f.wire);
  const std::shared_ptr<const ua::ErrorDetail> detail = ua::make_error_detail(
    "MetricsResetSecondResponseFailure", "injected wire response failure", "test.alarm_tracker.response");
  const StatusCode failure{Status::BadUserAccessDenied, detail};
  f.wire->scriptedCallResponses.push_back(Result<ua::CallResponse>{failure});

  unsigned completions = 0;
  std::optional<VoidResult> captured;
  f.tracker->reset_alarm_metrics_async(ua::NodeId{2, 8000U},
    [&completions, &captured](VoidResult result)
    {
      ++completions;
      captured = std::move(result);
    });
  f.drain();

  ASSERT_EQ(completions, 1U);
  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->status_code(), failure);
  EXPECT_EQ(captured->shared_detail(), detail);
  f.drain();
  EXPECT_EQ(completions, 1U);
  EXPECT_EQ(f.wire->callRequests.size(), 1U);
  EXPECT_TRUE(f.wire->readRequests.empty());
}

// ============================ EventNotification::field() two-segment overload (T22)
// ============================
//
// The additive multi-segment field({...}) overload is the spec-shaped access for a condition sub-state a
// server carries at a MULTI-segment browse path (a TwoStateVariable Boolean at [<State>, "Id"]). It must
// match by the FULL path and never cross-match a single-segment field with the same leaf name - the property
// that keeps the pre-existing single-segment field(name) callers (~19) behaviourally unchanged.

// An event carrying BOTH a single-segment [AckedState] display-name LocalizedText AND a two-segment
// [AckedState, Id] Boolean - the ambiguity the by-path matcher must resolve correctly.
EventNotification make_dual_shape_event()
{
  EventNotification event;
  event.fields.push_back(ua::Variant{ua::LocalizedText{"", "Acknowledged"}});
  event.fieldPaths.push_back({ua::QualifiedName{0, std::string{"AckedState"}}});
  event.fields.push_back(ua::Variant{true});
  event.fieldPaths.push_back(
    {ua::QualifiedName{0, std::string{"AckedState"}}, ua::QualifiedName{0, std::string{"Id"}}});
  return event;
}

TEST(EventNotificationFieldPath, TwoSegmentMatchesFullBrowsePath)
{
  const EventNotification event = make_dual_shape_event();
  const auto id = event.field({"AckedState", "Id"});
  ASSERT_TRUE(id.has_value());
  ASSERT_TRUE(id->to<bool>().is_good());
  EXPECT_TRUE(id->to<bool>().value());
}

TEST(EventNotificationFieldPath, TwoSegmentDoesNotCrossMatchSingleSegmentLeaf)
{
  const EventNotification event = make_dual_shape_event();
  // The single-segment overload returns the display-name LocalizedText (unchanged behaviour) ...
  const auto single = event.field("AckedState");
  ASSERT_TRUE(single.has_value());
  EXPECT_TRUE(single->to<ua::LocalizedText>().is_good());
  EXPECT_FALSE(single->to<bool>().is_good()) << "single-segment [AckedState] is NOT the Boolean";
  // ... and the two-segment overload returns the Boolean, not the display name.
  const auto twoSegment = event.field({"AckedState", "Id"});
  ASSERT_TRUE(twoSegment.has_value());
  EXPECT_TRUE(twoSegment->to<bool>().is_good());
}

TEST(EventNotificationFieldPath, SingleSegmentOverloadIgnoresTwoSegmentFields)
{
  // A two-segment field must never be returned by a single-segment lookup of either of its segment names.
  EventNotification event;
  event.fields.push_back(ua::Variant{true});
  event.fieldPaths.push_back(
    {ua::QualifiedName{0, std::string{"AckedState"}}, ua::QualifiedName{0, std::string{"Id"}}});
  EXPECT_FALSE(event.field("Id").has_value());
  EXPECT_FALSE(event.field("AckedState").has_value());
  EXPECT_TRUE(event.field({"AckedState", "Id"}).has_value());
}

TEST(EventNotificationFieldPath, AbsentOrWrongLengthPathReturnsNullopt)
{
  const EventNotification event = make_dual_shape_event();
  EXPECT_FALSE(event.field({"ConfirmedState", "Id"}).has_value());  // wrong parent
  EXPECT_FALSE(event.field({"AckedState", "TransitionTime"}).has_value());  // wrong child
  EXPECT_FALSE(event.field({"AckedState", "Id", "Extra"}).has_value());  // wrong length
}

// ============================ Two-segment condition decode (CL-AC-002/010/024/025)
// ============================
//
// These drive the tracker with SPEC-SHAPED events (two-segment <State>/Id sub-states, empty-path ConditionId)
// and assert the tracker surfaces the decoded Booleans / limit state / distinct ConditionId - the real-server
// wire shape. They would FAIL on the pre-Slice-AC1 decode (which read the single-segment display-name node
// and left the sub-states nullopt / collapsed distinct ConditionIds onto {null, empty}).

// @verifies CL-AC-002
// @relation(CL-AC-002, scope=function)
TEST(AlarmConditionTrackerDecode, DistinctConditionIdsFromEmptyPathDoNotCollapse)
{
  Fixture f;
  f.make();

  const ua::NodeId condA{2, 111U};
  const ua::NodeId condB{2, 222U};
  ConditionFields a;
  a.conditionId = condA;
  a.eventId = ua::ByteString{0x0A};
  ConditionFields b;
  b.conditionId = condB;
  b.eventId = ua::ByteString{0x0B};
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(a));
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(b));
  f.drain();

  // Two distinct ConditionIds -> two independent tracked entries (pre-slice they collapsed onto {null,
  // empty}).
  EXPECT_EQ(f.tracker->info()->trackedConditionCount, 2U);
  std::optional<Result<TrackedCondition>> readA;
  std::optional<Result<TrackedCondition>> readB;
  f.tracker->get_condition_async(trunk_key(condA), [&](Result<TrackedCondition> r) { readA = std::move(r); });
  f.tracker->get_condition_async(trunk_key(condB), [&](Result<TrackedCondition> r) { readB = std::move(r); });
  f.drain();
  ASSERT_TRUE(readA.has_value() && readA->is_good());
  ASSERT_TRUE(readB.has_value() && readB->is_good());
  EXPECT_EQ(readA->value().key.conditionId, condA);
  EXPECT_EQ(readB->value().key.conditionId, condB);
}

// @verifies CL-AC-024
// @verifies CL-AC-025
// @relation(CL-AC-024, CL-AC-025, scope=function)
TEST(AlarmConditionTrackerDecode, TwoStateSubStatesDecodedFromIdSubComponent)
{
  Fixture f;
  f.make();

  ConditionFields condition;
  condition.conditionId = testConditionId;
  condition.eventId = testEventId;
  condition.acked = true;  // [AckedState, Id] = true
  condition.confirmed = false;  // [ConfirmedState, Id] = false
  condition.active = true;  // [ActiveState, Id] = true
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
  f.drain();

  std::optional<Result<TrackedCondition>> readBack;
  f.tracker->get_condition_async(
    trunk_key(testConditionId), [&](Result<TrackedCondition> r) { readBack = std::move(r); });
  f.drain();
  ASSERT_TRUE(readBack.has_value() && readBack->is_good());
  const TrackedCondition& tc = readBack->value();
  ASSERT_TRUE(tc.ackedState.has_value());
  EXPECT_EQ(tc.ackedState->id, true);
  ASSERT_TRUE(tc.confirmedState.has_value());
  EXPECT_EQ(tc.confirmedState->id, false);
  ASSERT_TRUE(tc.activeState.has_value());
  EXPECT_EQ(tc.activeState->id, true);
}

// @verifies CL-AC-024
// @relation(CL-AC-024, scope=function)
TEST(AlarmConditionTrackerDecode, ExclusiveLimitStateDecodedFromTwoSegmentCurrentState)
{
  Fixture f;
  f.make();

  LimitFields alarm;
  alarm.conditionId = testConditionId;
  alarm.eventId = testEventId;
  alarm.active = true;
  alarm.limitState = ua::LocalizedText{"", "HighHigh"};  // carried at [LimitState, CurrentState]
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_limit_event(alarm));
  f.drain();

  std::optional<Result<TrackedCondition>> readBack;
  f.tracker->get_condition_async(
    trunk_key(testConditionId), [&](Result<TrackedCondition> r) { readBack = std::move(r); });
  f.drain();
  ASSERT_TRUE(readBack.has_value() && readBack->is_good());
  ASSERT_TRUE(readBack->value().exclusiveLimitState.has_value());
  EXPECT_EQ(*readBack->value().exclusiveLimitState, (ua::LocalizedText{"", "HighHigh"}));
}

// @verifies CL-AC-016
// The remaining AlarmConditionType sub-states (Suppressed/OutOfService/Silence/Latched) decode from their
// spec-shaped two-segment [<State>, "Id"] Booleans - the same path rule as the mandatory states. Pre-slice
// the tracker modelled only Enabled/Acked/Confirmed/Active, so these stayed absent.
// @relation(CL-AC-016, scope=function)
TEST(AlarmConditionTrackerDecode, AlarmSubStatesDecodedFromIdSubComponent)
{
  Fixture f;
  f.make();

  ConditionFields condition;
  condition.conditionId = testConditionId;
  condition.eventId = testEventId;
  condition.suppressed = true;  // [SuppressedState, Id] = true
  condition.outOfService = false;  // [OutOfServiceState, Id] = false
  condition.silence = true;  // [SilenceState, Id] = true
  condition.latched = false;  // [LatchedState, Id] = false
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
  f.drain();

  std::optional<Result<TrackedCondition>> readBack;
  f.tracker->get_condition_async(
    trunk_key(testConditionId), [&](Result<TrackedCondition> r) { readBack = std::move(r); });
  f.drain();
  ASSERT_TRUE(readBack.has_value() && readBack->is_good());
  const TrackedCondition& tc = readBack->value();
  ASSERT_TRUE(tc.suppressedState.has_value());
  EXPECT_EQ(tc.suppressedState->id, true);
  ASSERT_TRUE(tc.outOfServiceState.has_value());
  EXPECT_EQ(tc.outOfServiceState->id, false);
  ASSERT_TRUE(tc.silenceState.has_value());
  EXPECT_EQ(tc.silenceState->id, true);
  ASSERT_TRUE(tc.latchedState.has_value());
  EXPECT_EQ(tc.latchedState->id, false);
}

// @verifies CL-AC-016
// The aggregate SuppressedOrShelved is a plain SINGLE-segment Boolean; ShelvingState.CurrentState is a
// StateVariable LocalizedText at the two-segment ["ShelvingState", "CurrentState"] path. Both surface.
// @relation(CL-AC-016, scope=function)
TEST(AlarmConditionTrackerDecode, SuppressedOrShelvedAndShelvingStateDecoded)
{
  Fixture f;
  f.make();

  ConditionFields condition;
  condition.conditionId = testConditionId;
  condition.eventId = testEventId;
  condition.suppressedOrShelved = true;  // single-segment aggregate Boolean
  condition.shelvingState = ua::LocalizedText{"", "OneShotShelved"};  // [ShelvingState, CurrentState]
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
  f.drain();

  std::optional<Result<TrackedCondition>> readBack;
  f.tracker->get_condition_async(
    trunk_key(testConditionId), [&](Result<TrackedCondition> r) { readBack = std::move(r); });
  f.drain();
  ASSERT_TRUE(readBack.has_value() && readBack->is_good());
  const TrackedCondition& tc = readBack->value();
  ASSERT_TRUE(tc.suppressedOrShelved.has_value());
  EXPECT_EQ(*tc.suppressedOrShelved, true);
  ASSERT_TRUE(tc.shelvingState.has_value());
  EXPECT_EQ(*tc.shelvingState, (ua::LocalizedText{"", "OneShotShelved"}));
}

// @verifies CL-AC-016
// An event that omits an optional sub-state must leave that member nullopt - distinct from a present
// `false` - so a consumer can tell "not supported" from "not set". Here the mandatory active is present
// (so decode ran) but every optional CL-AC-016 sub-state is absent.
// @relation(CL-AC-016, scope=function)
TEST(AlarmConditionTrackerDecode, MissingOptionalAlarmSubStatesAreNullopt)
{
  Fixture f;
  f.make();

  ConditionFields condition;
  condition.conditionId = testConditionId;
  condition.eventId = testEventId;
  condition.active = true;  // present optional proves the decode ran
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
  f.drain();

  std::optional<Result<TrackedCondition>> readBack;
  f.tracker->get_condition_async(
    trunk_key(testConditionId), [&](Result<TrackedCondition> r) { readBack = std::move(r); });
  f.drain();
  ASSERT_TRUE(readBack.has_value() && readBack->is_good());
  const TrackedCondition& tc = readBack->value();
  ASSERT_TRUE(tc.activeState.has_value()) << "decode ran (ActiveState present)";
  EXPECT_FALSE(tc.suppressedState.has_value()) << "absent SuppressedState must be nullopt, not Some(false)";
  EXPECT_FALSE(tc.outOfServiceState.has_value());
  EXPECT_FALSE(tc.silenceState.has_value());
  EXPECT_FALSE(tc.latchedState.has_value());
  EXPECT_FALSE(tc.suppressedOrShelved.has_value());
  EXPECT_FALSE(tc.shelvingState.has_value());
}

// A single-segment <State> display-name field (the pre-slice wire shape) must NOT populate the Boolean - it
// is the LocalizedText display name, not the Id. This pins that the decode reads ONLY the two-segment
// sub-state.
TEST(AlarmConditionTrackerDecode, SingleSegmentStateDisplayNameDoesNotPopulateBoolean)
{
  Fixture f;
  f.make();

  EventNotification event;
  event.eventTypeId = ua::NodeId{ua::ObjectTypeId::ConditionType};
  event.eventId = testEventId;
  add_condition_id(event, testConditionId);
  add_field(event, "Retain", ua::Variant{true});
  // A single-segment [AckedState] carrying a display-name LocalizedText - the WRONG shape for the Boolean.
  add_field(event, "AckedState", ua::Variant{ua::LocalizedText{"", "Acknowledged"}});
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, std::move(event));
  f.drain();

  std::optional<Result<TrackedCondition>> readBack;
  f.tracker->get_condition_async(
    trunk_key(testConditionId), [&](Result<TrackedCondition> r) { readBack = std::move(r); });
  f.drain();
  ASSERT_TRUE(readBack.has_value() && readBack->is_good());
  EXPECT_FALSE(readBack->value().ackedState.has_value())
    << "a single-segment display-name field must not be decoded as the AckedState Boolean";
}

// OPC 10000-9 declares BranchId a NodeId Property. This is the same event with the field carried as a
// ByteString instead: a value that ARRIVES but cannot convert to the type the decoder asks for.
EventNotification event_whose_branch_id_is_not_a_node_id(const ConditionFields& fields)
{
  EventNotification event = make_condition_event(fields);
  for (std::size_t i = 0; i < event.fieldPaths.size(); ++i)
  {
    if (event.fieldPaths[i].size() == 1 && event.fieldPaths[i][0].name() == "BranchId")
    {
      event.fields[i] = ua::Variant{ua::ByteString{0x0B, 0xAD}};
    }
  }
  return event;
}

// A field that arrives as the wrong type leaves the decoder's default in place, which for BranchId is a
// null NodeId - indistinguishable from the trunk a server without branches reports. The warning is the
// only thing separating the two, so it is part of the contract, not a diagnostic nicety.
TEST(AlarmConditionTrackerDecode, WrongTypedFieldIsReportedAndItsDefaultKept)
{
  auto sink = std::make_shared<CapturingLogSink>();
  ua::Logger logger{sink, std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Trace), "test"};
  Fixture f;
  f.make({}, logger);

  ConditionFields condition;
  condition.conditionId = testConditionId;
  condition.eventId = testEventId;
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, event_whose_branch_id_is_not_a_node_id(condition));
  f.drain();

  EXPECT_TRUE(sink->has_field("field", "BranchId"));
  EXPECT_TRUE(sink->has_field("expected_type", "NodeId"))
    << "a field that arrived but did not convert must say so; silence reads as an absent field";

  std::optional<Result<TrackedCondition>> readBack;
  f.tracker->get_condition_async(
    trunk_key(testConditionId), [&](Result<TrackedCondition> r) { readBack = std::move(r); });
  f.drain();
  ASSERT_TRUE(readBack.has_value() && readBack->is_good());
  EXPECT_TRUE(readBack->value().key.branchId.is_null())
    << "the undecodable value must be ignored, not guessed at";
}

// Each tracker decodes into its own log. Two trackers run in one process - one per connection is the
// ordinary case - and a mismatch on one says nothing about the other.
TEST(AlarmConditionTrackerDecode, AFieldMismatchIsReportedByTheTrackerThatDecodedIt)
{
  auto reportingSink = std::make_shared<CapturingLogSink>();
  auto quietSink = std::make_shared<CapturingLogSink>();
  Fixture reporting;
  Fixture quiet;
  reporting.make(
    {}, ua::Logger{reportingSink, std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Trace), "test"});
  quiet.make(
    {}, ua::Logger{quietSink, std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Trace), "test"});

  ConditionFields condition;
  condition.conditionId = testConditionId;
  condition.eventId = testEventId;
  AlarmConditionTrackerTestAccess::post_event(
    *reporting.tracker, event_whose_branch_id_is_not_a_node_id(condition));
  AlarmConditionTrackerTestAccess::post_event(*quiet.tracker, make_condition_event(condition));
  reporting.drain();
  quiet.drain();

  EXPECT_TRUE(reportingSink->has_field("field", "BranchId"));
  EXPECT_FALSE(quietSink->has_field("field", "BranchId"))
    << "the tracker that decoded a well-formed event must not inherit another tracker's report";
}

// @verifies CL-AC-010
// The ack short-circuit (CL-AC-010) must be reachable from a TWO-SEGMENT-decoded ackedState.id == true - i.e.
// on the real server wire shape, not only under a fixture that posts the Boolean by single-segment name.
// @relation(CL-AC-010, scope=function)
TEST(AlarmConditionTrackerDecode, AckShortCircuitReachableFromTwoSegmentAckedState)
{
  Fixture f;
  f.make();

  ConditionFields condition;
  condition.conditionId = testConditionId;
  condition.eventId = testEventId;
  condition.acked = true;  // spec-shaped [AckedState, Id] = true (make_condition_event -> add_state_field)
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
  f.drain();
  ASSERT_EQ(f.tracker->info()->trackedConditionCount, 1U);

  std::optional<VoidResult> ackResult;
  f.tracker->acknowledge_async(
    trunk_key(testConditionId), std::nullopt, std::nullopt, [&](VoidResult r) { ackResult = r; });
  f.drain();

  ASSERT_TRUE(ackResult.has_value());
  EXPECT_TRUE(ackResult->is_bad());
  EXPECT_EQ(
    ackResult->status_code().as_uint32(), StatusCode{Status::BadConditionBranchAlreadyAcked}.as_uint32());
  EXPECT_EQ(f.wire->callRequests.size(), 0U) << "the two-segment-decoded acked state must short-circuit";
}

// section 3.1 positional-correlation hazard: the composite EventFilter is a POSITIONAL list; a
// decode-by-slot-index would mis-read when other hooks' SelectClauses shift the tracker's fields. Build an
// event whose tracker fields sit at NON-natural slots (8 unrelated mandatory-ish fields prepended, scrambled
// order after) and confirm the tracker still decodes the empty-path ConditionId and the two-segment
// AckedState/Id by PATH.
TEST(AlarmConditionTrackerDecode, DecodesByPathNotIndexUnderCompositeWidening)
{
  Fixture f;
  f.make();

  EventNotification event;
  event.eventTypeId = ua::NodeId{ua::ObjectTypeId::AcknowledgeableConditionType};
  event.eventId = testEventId;
  for (const auto* mandatory :
    {"EventId", "EventType", "SourceNode", "SourceName", "Time", "ReceiveTime", "Message", "Severity"})
  {
    add_field(event, mandatory, ua::Variant{std::uint32_t{0}});  // junk single-segment fields at slots 0..7
  }
  add_state_field(event, "AckedState", true);  // slot 8: [AckedState, Id]
  add_field(event, "Retain", ua::Variant{true});  // slot 9
  add_condition_id(event, testConditionId);  // slot 10: empty-path ConditionId
  add_field(event, "BranchId", ua::Variant{ua::ByteString{}});  // slot 11
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, std::move(event));
  f.drain();

  std::optional<Result<TrackedCondition>> readBack;
  f.tracker->get_condition_async(
    trunk_key(testConditionId), [&](Result<TrackedCondition> r) { readBack = std::move(r); });
  f.drain();
  ASSERT_TRUE(readBack.has_value());
  ASSERT_TRUE(readBack->is_good())
    << "ConditionId must decode from the empty-path operand regardless of its slot";
  ASSERT_TRUE(readBack->value().ackedState.has_value());
  EXPECT_EQ(readBack->value().ackedState->id, true) << "AckedState/Id must decode by path, not a fixed slot";
}

// DoS lens (section 3.1): the by-path matcher is O(fields . segments) per lookup and the tracker does a fixed
// number of lookups - so decode is linear in an attacker-controlled fieldPaths, never superlinear. A
// complexity pin: a large padded fieldPaths still decodes within a generous wall-clock bound (and still
// tracks the condition).
TEST(AlarmConditionTrackerDecode, LargeFieldPathsDecodeInBoundedTime)
{
  Fixture f;
  f.make();

  EventNotification event;
  event.eventTypeId = ua::NodeId{ua::ObjectTypeId::ConditionType};
  event.eventId = testEventId;
  add_condition_id(event, testConditionId);
  add_field(event, "Retain", ua::Variant{true});
  add_state_field(event, "AckedState", false);
  for (std::size_t i = 0; i < 20000; ++i)
  {
    add_two_segment_field(event, "Junk", "Leaf", ua::Variant{static_cast<std::uint32_t>(i)});
  }

  const auto start = std::chrono::steady_clock::now();
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, std::move(event));
  f.drain();
  const auto elapsed = std::chrono::steady_clock::now() - start;
  EXPECT_LT(elapsed, std::chrono::seconds{2}) << "decode must stay ~linear in |fieldPaths|";
  EXPECT_EQ(f.tracker->info()->trackedConditionCount, 1U);
}

// @verifies CL-AC-021
// @relation(CL-AC-021, scope=function)
TEST(AlarmConditionTrackerDecode, SurfacesOffNormalAndInheritedTripNormalState)
{
  for (const ua::ObjectTypeId eventType :
    {ua::ObjectTypeId::OffNormalAlarmType, ua::ObjectTypeId::TripAlarmType})
  {
    Fixture f;
    f.make();
    ConditionFields condition;
    condition.conditionId = testConditionId;
    condition.eventId = testEventId;
    condition.eventTypeId = ua::NodeId{eventType};
    condition.normalState = ua::NodeId{2, 9100U};
    AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
    f.drain();

    std::optional<Result<TrackedCondition>> readBack;
    f.tracker->get_condition_async(
      trunk_key(testConditionId), [&](Result<TrackedCondition> result) { readBack = std::move(result); });
    f.drain();
    ASSERT_TRUE(readBack.has_value());
    ASSERT_TRUE(readBack->is_good());
    const auto* info = std::get_if<ua::client::OffNormalAlarmInfo>(&readBack->value().subtypeInfo);
    ASSERT_NE(info, nullptr) << "OffNormal subclasses must use the inherited OffNormal payload";
    ASSERT_TRUE(info->normalState.has_value());
    EXPECT_EQ(*info->normalState, ua::NodeId(2, 9100U));
  }
}

// @verifies CL-AC-021
// @relation(CL-AC-021, scope=function)
TEST(AlarmConditionTrackerDecode, SurfacesDiscrepancyMandatoryAndOptionalProperties)
{
  Fixture f;
  f.make();
  ConditionFields condition;
  condition.conditionId = testConditionId;
  condition.eventId = testEventId;
  condition.eventTypeId = ua::NodeId{ua::ObjectTypeId::DiscrepancyAlarmType};
  condition.targetValueNode = ua::NodeId{2, 9200U};
  condition.expectedTime = ua::Duration{2500.0};
  condition.tolerance = 0.125;
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
  f.drain();

  std::optional<Result<TrackedCondition>> readBack;
  f.tracker->get_condition_async(
    trunk_key(testConditionId), [&](Result<TrackedCondition> result) { readBack = std::move(result); });
  f.drain();
  ASSERT_TRUE(readBack.has_value());
  ASSERT_TRUE(readBack->is_good());
  const auto* info = std::get_if<ua::client::DiscrepancyAlarmInfo>(&readBack->value().subtypeInfo);
  ASSERT_NE(info, nullptr);
  EXPECT_EQ(info->targetValueNode, condition.targetValueNode);
  EXPECT_EQ(info->expectedTime, condition.expectedTime);
  EXPECT_EQ(info->tolerance, condition.tolerance);
}

// @verifies CL-AC-021
// @relation(CL-AC-021, scope=function)
TEST(AlarmConditionTrackerDecode, DiscreteMarkerAndMalformedSubtypeFieldsRemainTypedButAbsent)
{
  Fixture discrete;
  discrete.make();
  ConditionFields marker;
  marker.conditionId = testConditionId;
  marker.eventId = testEventId;
  marker.eventTypeId = ua::NodeId{ua::ObjectTypeId::DiscreteAlarmType};
  AlarmConditionTrackerTestAccess::post_event(*discrete.tracker, make_condition_event(marker));
  discrete.drain();
  std::optional<Result<TrackedCondition>> markerRead;
  discrete.tracker->get_condition_async(
    trunk_key(testConditionId), [&](Result<TrackedCondition> result) { markerRead = std::move(result); });
  discrete.drain();
  ASSERT_TRUE(markerRead.has_value() && markerRead->is_good());
  EXPECT_TRUE(std::holds_alternative<ua::client::DiscreteAlarmInfo>(markerRead->value().subtypeInfo));

  Fixture malformed;
  malformed.make();
  EventNotification event = make_condition_event(ConditionFields{.conditionId = testConditionId,
    .eventId = testEventId,
    .eventTypeId = ua::NodeId{ua::ObjectTypeId::DiscrepancyAlarmType}});
  add_field(event, "TargetValueNode", ua::Variant{std::uint32_t{99}});
  add_field(event, "ExpectedTime", ua::Variant{ua::NodeId{2, 1U}});
  AlarmConditionTrackerTestAccess::post_event(*malformed.tracker, std::move(event));
  malformed.drain();
  std::optional<Result<TrackedCondition>> malformedRead;
  malformed.tracker->get_condition_async(
    trunk_key(testConditionId), [&](Result<TrackedCondition> result) { malformedRead = std::move(result); });
  malformed.drain();
  ASSERT_TRUE(malformedRead.has_value() && malformedRead->is_good());
  const auto* info = std::get_if<ua::client::DiscrepancyAlarmInfo>(&malformedRead->value().subtypeInfo);
  ASSERT_NE(info, nullptr);
  EXPECT_FALSE(info->targetValueNode.has_value());
  EXPECT_FALSE(info->expectedTime.has_value());
  EXPECT_FALSE(info->tolerance.has_value());
}

// @verifies CL-AC-022
// @relation(CL-AC-022, scope=function)
TEST(AlarmConditionTrackerDecode, SurfacesReAlarmPropertiesWhenPresent)
{
  Fixture f;
  f.make();
  ConditionFields condition;
  condition.conditionId = testConditionId;
  condition.eventId = testEventId;
  condition.eventTypeId = ua::NodeId{ua::ObjectTypeId::AlarmConditionType};
  condition.reAlarmTime = ua::Duration{30000.0};
  condition.reAlarmRepeatCount = std::int16_t{2};
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
  f.drain();

  std::optional<Result<TrackedCondition>> readBack;
  f.tracker->get_condition_async(
    trunk_key(testConditionId), [&](Result<TrackedCondition> result) { readBack = std::move(result); });
  f.drain();
  ASSERT_TRUE(readBack.has_value() && readBack->is_good());
  EXPECT_EQ(readBack->value().reAlarmTime, condition.reAlarmTime);
  EXPECT_EQ(readBack->value().reAlarmRepeatCount, condition.reAlarmRepeatCount);
}

// @verifies CL-AC-022
// @relation(CL-AC-022, scope=function)
TEST(AlarmConditionTrackerDecode, OnOffDelayMutationFlowsThroughConditionChanged)
{
  Fixture f;
  f.make();
  ConditionFields condition;
  condition.conditionId = testConditionId;
  condition.eventId = testEventId;
  condition.eventTypeId = ua::NodeId{ua::ObjectTypeId::AlarmConditionType};
  condition.onDelay = ua::Duration{2000.0};
  condition.offDelay = ua::Duration{5000.0};
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
  f.drain();

  std::optional<TrackedCondition> changed;
  f.tracker->on_condition_changed_async(
    [&](const TrackedCondition& current) { changed = current; }, [](VoidResult) {});
  f.drain();
  condition.eventId = ua::ByteString{0x02};
  condition.onDelay = ua::Duration{3000.0};
  condition.offDelay = ua::Duration{7000.0};
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
  f.drain();

  ASSERT_TRUE(changed.has_value());
  EXPECT_EQ(changed->onDelay, condition.onDelay);
  EXPECT_EQ(changed->offDelay, condition.offDelay);
}

// @verifies CL-AC-022
// @relation(CL-AC-022, scope=function)
TEST(AlarmConditionTrackerDecode, SurfacesAudibleSoundProperties)
{
  Fixture f;
  f.make();
  ConditionFields condition;
  condition.conditionId = testConditionId;
  condition.eventId = testEventId;
  condition.eventTypeId = ua::NodeId{ua::ObjectTypeId::AlarmConditionType};
  condition.audibleEnabled = true;
  condition.audibleSound = ua::AudioDataType{0x11, 0x22, 0x33};
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
  f.drain();

  std::optional<Result<TrackedCondition>> readBack;
  f.tracker->get_condition_async(
    trunk_key(testConditionId), [&](Result<TrackedCondition> result) { readBack = std::move(result); });
  f.drain();
  ASSERT_TRUE(readBack.has_value() && readBack->is_good());
  EXPECT_EQ(readBack->value().audibleEnabled, condition.audibleEnabled);
  EXPECT_EQ(readBack->value().audibleSound, condition.audibleSound);
}

// @verifies CL-AC-022
// @relation(CL-AC-022, scope=function)
TEST(AlarmConditionTrackerDecode, SurfacesFirstInGroupProperties)
{
  Fixture f;
  f.make();
  ConditionFields condition;
  condition.conditionId = testConditionId;
  condition.eventId = testEventId;
  condition.eventTypeId = ua::NodeId{ua::ObjectTypeId::AlarmConditionType};
  condition.firstInGroupFlag = true;
  condition.firstInGroup = ua::NodeId{2, 9300U};
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
  f.drain();

  std::optional<Result<TrackedCondition>> readBack;
  f.tracker->get_condition_async(
    trunk_key(testConditionId), [&](Result<TrackedCondition> result) { readBack = std::move(result); });
  f.drain();
  ASSERT_TRUE(readBack.has_value() && readBack->is_good());
  EXPECT_EQ(readBack->value().firstInGroupFlag, condition.firstInGroupFlag);
  EXPECT_EQ(readBack->value().firstInGroup, condition.firstInGroup);
}

// @verifies CL-AC-022
// @relation(CL-AC-022, scope=function)
TEST(AlarmConditionTrackerDecode, ExplicitPropertyReadFallbackUsesConditionInstance)
{
  Fixture f;
  f.make();
  f.wire->translateHandler = [](const ua::TranslateBrowsePathsToNodeIdsRequest& request)
  {
    EXPECT_EQ(request.browse_paths().size(), 1U);
    const auto& path = request.browse_paths()[0];
    EXPECT_EQ(path.starting_node(), testConditionId);
    EXPECT_EQ(path.relative_path().elements().size(), 1U);
    const auto& element = path.relative_path().elements()[0];
    EXPECT_EQ(element.reference_type_id(), ua::NodeId{ua::ReferenceTypeId::HierarchicalReferences});
    EXPECT_TRUE(element.include_subtypes());
    EXPECT_EQ(element.target_name(), ua::QualifiedName(0, "OnDelay"));
    ua::TranslateBrowsePathsToNodeIdsResponse response;
    ua::BrowsePathResult result;
    result.status_code() = ua::StatusCode{ua::Status::Good};
    ua::BrowsePathTarget target;
    target.target_id() = ua::ExpandedNodeId{ua::NodeId{9400U}};
    result.targets().push_back(std::move(target));
    response.results().push_back(std::move(result));
    return response;
  };
  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{ua::Variant{ua::Duration{2500.0}}});
  f.wire->scriptedReadResponses.push_back(Result<ua::ReadResponse>{std::move(response)});

  AlarmConditionTracker tracker = AlarmConditionTrackerHandleFactory::create(f.tracker);
  auto handle = tracker.handle(trunk_key(testConditionId));
  std::optional<Result<ua::Variant>> captured;
  handle.read_property_async(
    ua::QualifiedName{0, "OnDelay"}, [&](Result<ua::Variant> result) { captured = std::move(result); });
  f.drain();

  ASSERT_TRUE(captured.has_value() && captured->is_good());
  const auto delay = captured->value().to<ua::Duration>();
  ASSERT_TRUE(delay.is_good());
  EXPECT_DOUBLE_EQ(delay.value(), 2500.0);
  ASSERT_EQ(f.wire->readRequests.size(), 1U);
  ASSERT_EQ(f.wire->readRequests.front().nodes_to_read().size(), 1U);
  EXPECT_EQ(f.wire->readRequests.front().nodes_to_read()[0].node_id(), ua::NodeId{9400U});
}

// ============================ SelectClause builder (CL-AC-002/024/025) ============================
//
// The tracker's filter contribution must REQUEST the spec-shaped clauses so the server returns them: the
// two-segment [<State>, "Id"] sub-states, [LimitState, "CurrentState"], and the empty-path ConditionId
// operand (attributeId == NodeId). Absent these, a spec server returns nothing for the sub-states.

// A SelectClause matches its declaring EventType, browse path, and attribute.
bool has_clause(const ua::EventFilter& filter, const ua::NodeId& typeDefinitionId,
  std::vector<std::string_view> browsePath, ua::AttributeId attr)
{
  for (const auto& clause : filter.select_clauses())
  {
    if (clause.type_definition_id() != typeDefinitionId)
      continue;
    if (clause.browse_path().size() != browsePath.size())
    {
      continue;
    }
    if (clause.attribute_id() != static_cast<ua::IntegerId>(attr))
    {
      continue;
    }
    bool matches = true;
    for (std::size_t i = 0; i < browsePath.size(); ++i)
    {
      if (static_cast<std::string_view>(clause.browse_path()[i].name()) != browsePath[i])
      {
        matches = false;
        break;
      }
    }
    if (matches)
    {
      return true;
    }
  }
  return false;
}

// @verifies AC-CL-AC-024-AN-INACTIVE-EXCLUSIVE-LIMIT-ALARM-DOES
// @relation(AC-CL-AC-024-AN-INACTIVE-EXCLUSIVE-LIMIT-ALARM-DOES, scope=function)
TEST(AlarmConditionTrackerFilter, RequestsTwoSegmentSubStateAndEmptyPathConditionIdClauses)
{
  Fixture f;
  f.make();

  const ua::EventFilter filter = AlarmConditionTrackerTestAccess::filter_contribution(*f.tracker);
  const ua::NodeId conditionType{ua::ObjectTypeId::ConditionType};
  const ua::NodeId acknowledgeableType{ua::ObjectTypeId::AcknowledgeableConditionType};
  const ua::NodeId alarmType{ua::ObjectTypeId::AlarmConditionType};
  const ua::NodeId limitType{ua::ObjectTypeId::LimitAlarmType};
  const ua::NodeId exclusiveLimitType{ua::ObjectTypeId::ExclusiveLimitAlarmType};
  const ua::NodeId nonExclusiveLimitType{ua::ObjectTypeId::NonExclusiveLimitAlarmType};

  // The path alone is insufficient: each operand must name the EventType that declares it.
  EXPECT_TRUE(has_clause(filter, conditionType, {}, ua::AttributeId::NodeId))
    << "the ConditionId operand (empty path, attributeId NodeId) must be requested";

  EXPECT_TRUE(has_clause(filter, conditionType, {"EnabledState", "Id"}, ua::AttributeId::Value));
  for (const std::string_view state : {"AckedState", "ConfirmedState"})
  {
    EXPECT_TRUE(has_clause(filter, acknowledgeableType, {state, "Id"}, ua::AttributeId::Value));
  }
  EXPECT_TRUE(has_clause(filter, alarmType, {"ActiveState", "Id"}, ua::AttributeId::Value));
  for (const std::string_view state : {"HighHighState", "HighState", "LowState", "LowLowState"})
  {
    EXPECT_TRUE(has_clause(filter, nonExclusiveLimitType, {state, "Id"}, ua::AttributeId::Value));
  }

  // CL-AC-024: the ExclusiveLimit CurrentState at [LimitState, CurrentState].
  EXPECT_TRUE(has_clause(filter, exclusiveLimitType, {"LimitState", "CurrentState"}, ua::AttributeId::Value));

  EXPECT_TRUE(has_clause(filter, conditionType, {"Retain"}, ua::AttributeId::Value));
  EXPECT_TRUE(has_clause(filter, limitType, {"HighLimit"}, ua::AttributeId::Value));
  EXPECT_TRUE(has_clause(filter, alarmType, {"MaxTimeShelved"}, ua::AttributeId::Value));

  // Regression guard: the states are NOT requested as single-segment display-name clauses (the pre-slice
  // bug).
  EXPECT_FALSE(has_clause(filter, acknowledgeableType, {"AckedState"}, ua::AttributeId::Value))
    << "AckedState must be requested at [AckedState, Id], not single-segment";
}

// @verifies CL-AC-014
// @relation(CL-AC-014, scope=function)
TEST(AlarmConditionTrackerFilter, RequestsMandatoryConditionClassIdentity)
{
  Fixture fixture;
  fixture.make();

  const ua::EventFilter filter = AlarmConditionTrackerTestAccess::filter_contribution(*fixture.tracker);
  const ua::NodeId conditionType{ua::ObjectTypeId::ConditionType};
  EXPECT_TRUE(has_clause(filter, conditionType, {"ConditionClassId"}, ua::AttributeId::Value));
  EXPECT_TRUE(has_clause(filter, conditionType, {"ConditionClassName"}, ua::AttributeId::Value));
}

// @verifies CL-AC-014
// @relation(CL-AC-014, scope=function)
TEST(AlarmConditionTrackerDecode, SurfacesMandatoryConditionClassIdentity)
{
  Fixture fixture;
  fixture.make();
  ConditionFields condition;
  condition.conditionId = testConditionId;
  condition.eventId = ua::ByteString{0x14};
  condition.conditionClassId = ua::NodeId{ua::ObjectTypeId::ProcessConditionClassType};
  condition.conditionClassName = ua::LocalizedText{"en", "Process"};

  AlarmConditionTrackerTestAccess::post_event(*fixture.tracker, make_condition_event(condition));
  fixture.drain();

  std::optional<Result<TrackedCondition>> readBack;
  fixture.tracker->get_condition_async(
    trunk_key(testConditionId), [&](Result<TrackedCondition> result) { readBack = std::move(result); });
  fixture.drain();
  ASSERT_TRUE(readBack.has_value() && readBack->is_good());
  EXPECT_EQ(readBack->value().conditionClassId, condition.conditionClassId);
  EXPECT_EQ(readBack->value().conditionClassName, condition.conditionClassName);
}

// A SelectClause matches a browse path + attributeId AND the given typeDefinitionId (CL-AC-016 requests the
// AlarmConditionType sub-states against AlarmConditionType - the type that DECLARES them).
bool has_typed_clause(const ua::EventFilter& filter, const ua::NodeId& typeDefinitionId,
  std::vector<std::string_view> browsePath, ua::AttributeId attr)
{
  for (const auto& clause : filter.select_clauses())
  {
    if (clause.type_definition_id() != typeDefinitionId || clause.browse_path().size() != browsePath.size() ||
        clause.attribute_id() != static_cast<ua::IntegerId>(attr))
    {
      continue;
    }
    bool matches = true;
    for (std::size_t i = 0; i < browsePath.size(); ++i)
    {
      if (static_cast<std::string_view>(clause.browse_path()[i].name()) != browsePath[i])
      {
        matches = false;
        break;
      }
    }
    if (matches)
    {
      return true;
    }
  }
  return false;
}

// ConditionType is abstract and every concrete Condition/Alarm is a subtype. The WhereClause must therefore
// use subtype-inclusive OfType, never literal equality.
// Falsifiability: changing the production operator to Equals fails this exact operator assertion.
// @verifies CL-AC-015
// @relation(CL-AC-015, scope=function)
TEST(AlarmConditionTrackerFilter, AdmitsConditionTypeSubtypesWithOfType)
{
  Fixture f;
  f.make();

  const ua::EventFilter filter = AlarmConditionTrackerTestAccess::filter_contribution(*f.tracker);
  ASSERT_EQ(filter.where_clause().elements().size(), 1U);
  const auto& element = filter.where_clause().elements()[0];
  EXPECT_EQ(element.filter_operator(), ua::FilterOperator::OfType);
  ASSERT_EQ(element.filter_operands().size(), 1U);
  const auto* operand = dynamic_cast<const ua::LiteralOperand*>(element.filter_operands()[0].get());
  ASSERT_NE(operand, nullptr);
  const auto typeId = operand->value().to<ua::NodeId>();
  ASSERT_TRUE(typeId.is_good());
  EXPECT_EQ(typeId.value(), ua::NodeId{ua::ObjectTypeId::ConditionType});
}

// @verifies CL-AC-016
// The tracker must REQUEST the remaining AlarmConditionType sub-state clauses so a spec server returns them:
// the Suppressed/OutOfService/Silence/Latched /Id Booleans + ShelvingState/CurrentState (two-segment) and the
// aggregate SuppressedOrShelved (single-segment), each against AlarmConditionType (the declaring type).
// @relation(CL-AC-016, scope=function)
TEST(AlarmConditionTrackerFilter, RequestsAlarmSubStateClauses)
{
  Fixture f;
  f.make();

  const ua::EventFilter filter = AlarmConditionTrackerTestAccess::filter_contribution(*f.tracker);
  const ua::NodeId alarmType{ua::ObjectTypeId::AlarmConditionType};

  for (const std::string_view state :
    {"SuppressedState", "OutOfServiceState", "SilenceState", "LatchedState"})
  {
    EXPECT_TRUE(has_typed_clause(filter, alarmType, {state, "Id"}, ua::AttributeId::Value))
      << "missing two-segment AlarmConditionType [" << state << ", Id] clause";
  }
  EXPECT_TRUE(has_typed_clause(filter, alarmType, {"ShelvingState", "CurrentState"}, ua::AttributeId::Value))
    << "missing two-segment ShelvingState/CurrentState clause";
  EXPECT_TRUE(has_typed_clause(filter, alarmType, {"SuppressedOrShelved"}, ua::AttributeId::Value))
    << "missing single-segment SuppressedOrShelved aggregate clause";

  // The declaring-type distinction: the sub-states are NOT requested against ConditionType (they are declared
  // on AlarmConditionType), so a ConditionType-typed [SuppressedState, Id] clause must be absent.
  EXPECT_FALSE(has_typed_clause(
    filter, ua::NodeId{ua::ObjectTypeId::ConditionType}, {"SuppressedState", "Id"}, ua::AttributeId::Value));
}

// @verifies CL-AC-022
// @relation(CL-AC-022, scope=function)
TEST(AlarmConditionTrackerFilter, RequestsAllOptionalAlarmPropertyClauses)
{
  Fixture f;
  f.make();
  const ua::EventFilter filter = AlarmConditionTrackerTestAccess::filter_contribution(*f.tracker);
  const ua::NodeId alarmType{ua::ObjectTypeId::AlarmConditionType};

  for (const std::string_view property : {"ReAlarmTime",
         "ReAlarmRepeatCount",
         "OnDelay",
         "OffDelay",
         "AudibleEnabled",
         "AudibleSound",
         "FirstInGroupFlag",
         "MaxTimeShelved"})
  {
    EXPECT_TRUE(has_typed_clause(filter, alarmType, {property}, ua::AttributeId::Value))
      << "missing AlarmConditionType Value clause for " << property;
  }
  EXPECT_TRUE(has_typed_clause(filter, alarmType, {"FirstInGroup"}, ua::AttributeId::NodeId))
    << "FirstInGroup is an Object and must select its NodeId attribute";
  EXPECT_TRUE(has_typed_clause(filter, alarmType, {"LatchedState", "Id"}, ua::AttributeId::Value));
}

// @verifies CL-AC-021
// @relation(CL-AC-021, scope=function)
TEST(AlarmConditionTrackerFilter, RequestsTypedOffNormalAndDiscrepancyProperties)
{
  Fixture f;
  f.make();
  const ua::EventFilter filter = AlarmConditionTrackerTestAccess::filter_contribution(*f.tracker);

  EXPECT_TRUE(has_typed_clause(
    filter, ua::NodeId{ua::ObjectTypeId::OffNormalAlarmType}, {"NormalState"}, ua::AttributeId::Value));
  for (const std::string_view property : {"TargetValueNode", "ExpectedTime", "Tolerance"})
  {
    EXPECT_TRUE(has_typed_clause(
      filter, ua::NodeId{ua::ObjectTypeId::DiscrepancyAlarmType}, {property}, ua::AttributeId::Value))
      << "missing DiscrepancyAlarmType property " << property;
  }
}

// ============================ Status routing: the server's code reaches the application
// ============================

// A Call answer with one CallMethodResult whose statusCode is @p methodStatus, under @p serviceResult.
Result<ua::CallResponse> call_answer(StatusCode serviceResult, StatusCode methodStatus)
{
  ua::CallResponse response;
  response.response_header().service_result() = std::move(serviceResult);
  ua::CallMethodResult result;
  result.status_code() = std::move(methodStatus);
  response.results().push_back(std::move(result));
  return Result<ua::CallResponse>{std::move(response)};
}

// A tracked, unacknowledged trunk branch for testConditionId, so acknowledge goes to the wire.
void track_unacked_condition(Fixture& f)
{
  ConditionFields condition;
  condition.conditionId = testConditionId;
  condition.eventId = testEventId;
  condition.acked = false;
  AlarmConditionTrackerTestAccess::post_event(*f.tracker, make_condition_event(condition));
  f.drain();
}

// A Read answer holding @p value with @p status.
Result<ua::ReadResponse> read_answer(ua::Variant value, StatusCode status)
{
  ua::DataValue dataValue{std::move(value)};
  dataValue.status() = std::move(status);
  ua::ReadResponse response;
  response.results().push_back(std::move(dataValue));
  return Result<ua::ReadResponse>{std::move(response)};
}

// The Condition's Property path resolves to ns=0;i=9400 with @p pathStatus.
void resolve_property_path(RecordingWireOps& wire, StatusCode pathStatus)
{
  wire.translateHandler = [pathStatus](const ua::TranslateBrowsePathsToNodeIdsRequest&)
  {
    ua::TranslateBrowsePathsToNodeIdsResponse response;
    ua::BrowsePathResult result;
    result.status_code() = pathStatus;
    ua::BrowsePathTarget target;
    target.target_id() = ua::ExpandedNodeId{ua::NodeId{9400U}};
    result.targets().push_back(std::move(target));
    response.results().push_back(std::move(result));
    return response;
  };
}

// A Condition Method's Good subcode (here Acknowledge's) is the method's result, not plain Good.
// @relation(AC-CL-STATUS-ROUTING-01-A-METHOD-CALLS-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(AlarmConditionTrackerStatusRouting, AnAcknowledgesGoodSubcodeReachesTheApplication)
{
  for (const ua::Status methodStatus : {ua::Status::GoodCompletesAsynchronously, ua::Status::GoodClamped})
  {
    SCOPED_TRACE(ua::StatusCode{methodStatus}.value());
    Fixture f;
    f.make();
    track_unacked_condition(f);
    f.wire->scriptedCallResponses.push_back(call_answer(StatusCode{Status::Good}, StatusCode{methodStatus}));

    AlarmConditionTracker tracker = AlarmConditionTrackerHandleFactory::create(f.tracker);
    std::optional<VoidResult> ackResult;
    tracker.handle(trunk_key(testConditionId))
      .acknowledge_async(std::nullopt, [&](VoidResult r) { ackResult = r; });
    f.drain();

    ASSERT_TRUE(ackResult.has_value());
    EXPECT_EQ(ackResult->status_code(), StatusCode{methodStatus});
    EXPECT_TRUE(ackResult->is_good());
    ASSERT_EQ(f.wire->callRequests.size(), 1U);
  }
}

// An Uncertain statusCode of a Condition Method (here Confirm's) is the method's result.
// @relation(AC-CL-STATUS-ROUTING-01-A-METHOD-CALLS-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(AlarmConditionTrackerStatusRouting, AConfirmsUncertainCodeReachesTheApplication)
{
  Fixture f;
  f.make();
  f.wire->scriptedCallResponses.push_back(
    call_answer(StatusCode{Status::Good}, StatusCode{Status::UncertainNotAllNodesAvailable}));

  std::optional<VoidResult> confirmResult;
  f.tracker->confirm_async(
    trunk_key(testConditionId), testEventId, std::nullopt, [&](VoidResult r) { confirmResult = r; });
  f.drain();

  ASSERT_TRUE(confirmResult.has_value());
  EXPECT_TRUE(confirmResult->is_uncertain());
  EXPECT_EQ(confirmResult->status_code(), StatusCode{Status::UncertainNotAllNodesAvailable});
}

// A Good subcode on the Call's ServiceResult is the method's result when the Method answers plain Good.
// @relation(AC-CL-STATUS-ROUTING-01-A-SERVICE-RESULT-GOOD-SUBCODE-REACHES-THE-APPLICATION, scope=function)
TEST(AlarmConditionTrackerStatusRouting, AnEnablesServiceResultGoodSubcodeReachesTheApplication)
{
  for (const ua::Status serviceStatus :
    {ua::Status::GoodResultsMayBeIncomplete, ua::Status::GoodLocalOverride})
  {
    SCOPED_TRACE(ua::StatusCode{serviceStatus}.value());
    Fixture f;
    f.make();
    f.wire->scriptedCallResponses.push_back(call_answer(StatusCode{serviceStatus}, StatusCode{Status::Good}));

    std::optional<VoidResult> enableResult;
    f.tracker->enable_async(trunk_key(testConditionId), [&](VoidResult r) { enableResult = r; });
    f.drain();

    ASSERT_TRUE(enableResult.has_value());
    EXPECT_EQ(enableResult->status_code(), StatusCode{serviceStatus});
  }
}

// A ServiceFault with an Uncertain serviceResult (a Result holding no CallResponse) completes the method's
// callback with that code.
// @relation(AC-CL-STATUS-ROUTING-03-AN-UNCERTAIN-SERVICE-FAULT-COMPLETES-THE-CALLBACK, scope=function)
TEST(AlarmConditionTrackerStatusRouting, AnUncertainServiceFaultCompletesTheMethodsCallback)
{
  Fixture f;
  f.make();
  f.wire->scriptedCallResponses.push_back(
    Result<ua::CallResponse>{StatusCode{Status::UncertainNotAllNodesAvailable}});

  std::optional<VoidResult> disableResult;
  f.tracker->disable_async(trunk_key(testConditionId), [&](VoidResult r) { disableResult = r; });
  f.drain();

  ASSERT_TRUE(disableResult.has_value());
  EXPECT_EQ(disableResult->status_code(), StatusCode{Status::UncertainNotAllNodesAvailable});
}

// A Good subcode on the ConditionRefresh answer confirms the refresh, which completes with that code when
// its RefreshEnd arrives.
// @relation(AC-CL-STATUS-ROUTING-01-A-METHOD-CALLS-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(AlarmConditionTrackerStatusRouting, ARefreshCompletesWithTheTriggersGoodSubcode)
{
  for (const ua::Status methodStatus : {ua::Status::GoodCompletesAsynchronously, ua::Status::GoodClamped})
  {
    SCOPED_TRACE(ua::StatusCode{methodStatus}.value());
    Fixture f;
    f.make();
    f.wire->scriptedCallResponses.push_back(call_answer(StatusCode{Status::Good}, StatusCode{methodStatus}));

    std::optional<VoidResult> refreshResult;
    f.tracker->refresh_async([&](VoidResult result) { refreshResult = result; });
    f.drain();
    EXPECT_FALSE(refreshResult.has_value());  // confirmed: awaiting RefreshEnd

    AlarmConditionTrackerTestAccess::post_refresh_start(*f.tracker, make_refresh_notification(refreshId));
    AlarmConditionTrackerTestAccess::post_refresh_end(*f.tracker, make_refresh_notification(refreshEndId));
    f.drain();

    ASSERT_TRUE(refreshResult.has_value());
    EXPECT_EQ(refreshResult->status_code(), StatusCode{methodStatus});
    EXPECT_FALSE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));
  }
}

// An Uncertain ConditionRefresh answer with its CallResponse confirms the refresh as a Good one does (the
// server ran the Method, partly successfully): the tracker waits for the RefreshEnd, and the refresh then
// completes with the Uncertain code.
// @relation(AC-CL-STATUS-ROUTING-01-A-METHOD-CALLS-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(AlarmConditionTrackerStatusRouting, AnUncertainRefreshAnswerCompletesTheRefreshAtRefreshEndWithItsCode)
{
  Fixture f;
  f.make();
  f.wire->scriptedCallResponses.push_back(
    call_answer(StatusCode{Status::Good}, StatusCode{Status::UncertainNotAllNodesAvailable}));

  std::optional<VoidResult> refreshResult;
  f.tracker->refresh_async([&](VoidResult result) { refreshResult = result; });
  f.drain();
  EXPECT_FALSE(refreshResult.has_value()) << "confirmed: awaiting RefreshEnd";
  EXPECT_TRUE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));

  AlarmConditionTrackerTestAccess::post_refresh_start(*f.tracker, make_refresh_notification(refreshId));
  AlarmConditionTrackerTestAccess::post_refresh_end(*f.tracker, make_refresh_notification(refreshEndId));
  f.drain();

  ASSERT_TRUE(refreshResult.has_value());
  EXPECT_EQ(refreshResult->status_code(), StatusCode{Status::UncertainNotAllNodesAvailable});
  EXPECT_FALSE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));
}

// An Uncertain ConditionRefresh ServiceFault holds no CallResponse, so nothing says a RefreshEnd will follow:
// the trigger is refused, the refresh completes at once with Bad_InternalError (ServiceAnswerUncertain, the
// code as its inner status) and the tracker does not wait.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST(AlarmConditionTrackerStatusRouting, AnUncertainRefreshServiceFaultIsRefusedAndTheTrackerDoesNotWait)
{
  Fixture f;
  f.make();
  const StatusCode uncertain{Status::UncertainNotAllNodesAvailable};
  f.wire->scriptedCallResponses.push_back(Result<ua::CallResponse>{uncertain});

  std::optional<VoidResult> refreshResult;
  f.tracker->refresh_async([&](VoidResult result) { refreshResult = result; });
  f.drain();

  ASSERT_TRUE(refreshResult.has_value());
  EXPECT_EQ(refreshResult->status_code().as_status(), Status::BadInternalError);
  ASSERT_NE(refreshResult->error_detail(), nullptr);
  EXPECT_EQ(refreshResult->error_detail()->code, "ServiceAnswerUncertain");
  EXPECT_EQ(refreshResult->error_detail()->innerStatus, uncertain.value());
  EXPECT_FALSE(AlarmConditionTrackerTestAccess::refresh_in_progress(*f.tracker));
}

// The AlarmMetrics Reset Method's Good subcode is the reset's result.
// @relation(AC-CL-STATUS-ROUTING-01-A-METHOD-CALLS-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(AlarmConditionTrackerStatusRouting, AMetricsResetsGoodSubcodeReachesTheApplication)
{
  for (const ua::Status methodStatus : {ua::Status::GoodCompletesAsynchronously, ua::Status::GoodClamped})
  {
    SCOPED_TRACE(ua::StatusCode{methodStatus}.value());
    Fixture f;
    f.make();
    resolve_alarm_metric_paths(*f.wire);
    f.wire->scriptedCallResponses.push_back(call_answer(StatusCode{Status::Good}, StatusCode{methodStatus}));
    AlarmConditionTracker tracker = AlarmConditionTrackerHandleFactory::create(f.tracker);
    auto view = tracker.alarm_metrics(ua::NodeId{2, 8000U});

    std::optional<VoidResult> captured;
    view.reset_async([&](VoidResult result) { captured = std::move(result); });
    f.drain();

    ASSERT_TRUE(captured.has_value());
    EXPECT_EQ(captured->status_code(), StatusCode{methodStatus});
  }
}

// A Property read answered Uncertain with a value gives the value with the Uncertain code.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(AlarmConditionTrackerStatusRouting, AnUncertainPropertyValueKeepsItsCode)
{
  Fixture f;
  f.make();
  resolve_property_path(*f.wire, StatusCode{Status::Good});
  f.wire->scriptedReadResponses.push_back(
    read_answer(ua::Variant{ua::Duration{2500.0}}, StatusCode{Status::UncertainLastUsableValue}));
  AlarmConditionTracker tracker = AlarmConditionTrackerHandleFactory::create(f.tracker);

  std::optional<Result<ua::Variant>> captured;
  tracker.handle(trunk_key(testConditionId))
    .read_property_async(
      ua::QualifiedName{0, "OnDelay"}, [&](Result<ua::Variant> result) { captured = std::move(result); });
  f.drain();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_uncertain());
  EXPECT_EQ(captured->status_code(), StatusCode{Status::UncertainLastUsableValue});
  const auto delay = captured->value_or(ua::Variant{}).to<ua::Duration>();
  ASSERT_TRUE(delay.is_good());
  EXPECT_DOUBLE_EQ(delay.value(), 2500.0);
}

// A Property read answered Uncertain without a value gives the code and no value.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(AlarmConditionTrackerStatusRouting, AnUncertainPropertyWithoutAValueGivesTheCodeAlone)
{
  Fixture f;
  f.make();
  resolve_property_path(*f.wire, StatusCode{Status::Good});
  f.wire->scriptedReadResponses.push_back(
    read_answer(ua::Variant{}, StatusCode{Status::UncertainNoCommunicationLastUsableValue}));
  AlarmConditionTracker tracker = AlarmConditionTrackerHandleFactory::create(f.tracker);

  std::optional<Result<ua::Variant>> captured;
  tracker.handle(trunk_key(testConditionId))
    .read_property_async(
      ua::QualifiedName{0, "OnDelay"}, [&](Result<ua::Variant> result) { captured = std::move(result); });
  f.drain();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_uncertain());
  EXPECT_EQ(captured->status_code(), StatusCode{Status::UncertainNoCommunicationLastUsableValue});
  EXPECT_THROW(static_cast<void>(captured->value()), ua::UaException);
}

// The browse path the Property read depends on is used only when the server answers it Good: an Uncertain
// path is refused with Bad_InternalError (ReferencesAnswerUncertain) and nothing is read.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(AlarmConditionTrackerStatusRouting, AnUncertainPropertyPathIsRefusedAndNothingIsRead)
{
  Fixture f;
  f.make();
  resolve_property_path(*f.wire, StatusCode{Status::UncertainReferenceOutOfServer});
  AlarmConditionTracker tracker = AlarmConditionTrackerHandleFactory::create(f.tracker);

  std::optional<Result<ua::Variant>> captured;
  tracker.handle(trunk_key(testConditionId))
    .read_property_async(
      ua::QualifiedName{0, "OnDelay"}, [&](Result<ua::Variant> result) { captured = std::move(result); });
  f.drain();

  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->status_code().as_status(), Status::BadInternalError);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "ReferencesAnswerUncertain");
  EXPECT_TRUE(f.wire->readRequests.empty());
}

// The metrics snapshot carries the worst value's code: one metric answered Uncertain with its value gives
// the snapshot with that code.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(AlarmConditionTrackerStatusRouting, AnUncertainMetricGivesTheSnapshotWithItsCode)
{
  Fixture f;
  f.make();
  resolve_alarm_metric_paths(*f.wire);
  ua::ReadResponse response;
  for (ua::Variant value : {ua::Variant{std::uint32_t{42}},
         ua::Variant{ua::DateTime{2026, 7, 24, 12, 0, 0.0}},
         ua::Variant{ua::Duration{1500.0}},
         ua::Variant{ua::Duration{2400.0}},
         ua::Variant{3.5},
         ua::Variant{8.25},
         ua::Variant{std::uint32_t{7}},
         ua::Variant{2.75},
         ua::Variant{std::uint16_t{5}},
         ua::Variant{std::uint16_t{15}},
         ua::Variant{std::uint16_t{60}}})
  {
    response.results().push_back(ua::DataValue{std::move(value)});
  }
  response.results()[0].status() = StatusCode{Status::UncertainLastUsableValue};
  response.results()[4].status() = StatusCode{Status::GoodLocalOverride};
  f.wire->scriptedReadResponses.push_back(Result<ua::ReadResponse>{std::move(response)});
  AlarmConditionTracker tracker = AlarmConditionTrackerHandleFactory::create(f.tracker);
  auto view = tracker.alarm_metrics(ua::NodeId{2, 8000U});

  std::optional<Result<ua::client::AlarmMetricsSnapshot>> captured;
  view.read_all_async([&](Result<ua::client::AlarmMetricsSnapshot> result) { captured = std::move(result); });
  f.drain();

  ASSERT_TRUE(captured.has_value());
  EXPECT_EQ(captured->status_code(), StatusCode{Status::UncertainLastUsableValue});
  EXPECT_EQ(captured->value_or(ua::client::AlarmMetricsSnapshot{}).alarmCount, 42U);
}

// A metric answered with a Good subcode gives the snapshot with that code.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(AlarmConditionTrackerStatusRouting, AMetricsGoodSubcodeGivesTheSnapshotWithItsCode)
{
  Fixture f;
  f.make();
  resolve_alarm_metric_paths(*f.wire);
  ua::ReadResponse response;
  for (ua::Variant value : {ua::Variant{std::uint32_t{42}},
         ua::Variant{ua::DateTime{2026, 7, 24, 12, 0, 0.0}},
         ua::Variant{ua::Duration{1500.0}},
         ua::Variant{ua::Duration{2400.0}},
         ua::Variant{3.5},
         ua::Variant{8.25},
         ua::Variant{std::uint32_t{7}},
         ua::Variant{2.75},
         ua::Variant{std::uint16_t{5}},
         ua::Variant{std::uint16_t{15}},
         ua::Variant{std::uint16_t{60}}})
  {
    response.results().push_back(ua::DataValue{std::move(value)});
  }
  response.results()[4].status() = StatusCode{Status::GoodLocalOverride};
  f.wire->scriptedReadResponses.push_back(Result<ua::ReadResponse>{std::move(response)});
  AlarmConditionTracker tracker = AlarmConditionTrackerHandleFactory::create(f.tracker);
  auto view = tracker.alarm_metrics(ua::NodeId{2, 8000U});

  std::optional<Result<ua::client::AlarmMetricsSnapshot>> captured;
  view.read_all_async([&](Result<ua::client::AlarmMetricsSnapshot> result) { captured = std::move(result); });
  f.drain();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_EQ(captured->status_code(), StatusCode{Status::GoodLocalOverride});
  EXPECT_DOUBLE_EQ(captured->value().currentAlarmRate.value, 3.5);
}

// The ShelvingState lookup the shelving Call depends on is used only when the server answers it Good: an
// Uncertain path is refused with Bad_InternalError (ReferencesAnswerUncertain) and no Method is called.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(AlarmConditionTrackerStatusRouting, AnUncertainShelvingStateLookupIsRefusedAndNothingIsCalled)
{
  Fixture f;
  f.make();
  f.wire->translateHandler = [](const ua::TranslateBrowsePathsToNodeIdsRequest& request)
  {
    ua::TranslateBrowsePathsToNodeIdsResponse response;
    for (std::size_t index = 0; index < request.browse_paths().size(); ++index)
    {
      ua::BrowsePathResult result;
      result.status_code() =
        index == 0 ? StatusCode{Status::Good} : StatusCode{Status::UncertainReferenceOutOfServer};
      ua::BrowsePathTarget target;
      target.target_id() = ua::ExpandedNodeId{ua::NodeId{static_cast<std::uint32_t>(9500U + index)}};
      result.targets().push_back(std::move(target));
      response.results().push_back(std::move(result));
    }
    return response;
  };

  std::optional<VoidResult> shelveResult;
  f.tracker->one_shot_shelve_async(trunk_key(testConditionId), [&](VoidResult r) { shelveResult = r; });
  f.drain();

  ASSERT_TRUE(shelveResult.has_value());
  EXPECT_EQ(shelveResult->status_code().as_status(), Status::BadInternalError);
  ASSERT_NE(shelveResult->shared_detail(), nullptr);
  EXPECT_EQ(shelveResult->shared_detail()->code, "ReferencesAnswerUncertain");
  EXPECT_TRUE(f.wire->callRequests.empty());
}

}  // namespace
