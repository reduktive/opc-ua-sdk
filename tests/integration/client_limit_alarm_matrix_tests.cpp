// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientLimitAlarm cluster of the client integration-test matrix (the 12 `ClientLimitAlarm.*` rows).
///
/// COMPANION: `client_alarm_live_server_tests.cpp` runs the same surface against a REAL server. These
/// rows keep what only an interface can hold - the wire ARGUMENTS a wrapper builds, server misbehaviour a
/// conforming server will not produce, and branches this server does not emit. What a live server can
/// decide is asserted there, because a fake agrees with whatever the client sends it.
///
/// These exercise the TIER-2 Alarm & Condition tracker's LIMIT handling
/// (`ua::client::detail::AlarmConditionTrackerImpl`, client design section 8.8.5 limit recognition;
/// section 8.8.2 limit-state clearing / staleness) as a LIVE component: a REAL `EventSubscriberImpl` +
/// tracker are built over the mockable event backbone interface + a `FakeWireOps` on a REAL
/// `boost::asio::thread_pool`, and the tracker's OWN decode -> (ConditionId,BranchId)->TrackedCondition map
/// -> observer -> snapshot pipeline is driven through its on-strand hook entry point (the
/// `AlarmConditionTrackerTestAccess` interface posts a decoded `EventNotification` onto the tracker's strand
/// exactly as the subscriber's Publish dispatch would). Every assertion is made through the PUBLIC consumer
/// surface
/// (`get_condition_async` / `list_conditions_async` / `info()`), plus - for the two data-integrity rows
/// - a recording `LogSink` injected into the tracker's `Logger` (the source-tagged advisory arm).
///
/// Why the hook interface and not a real ComplianceWithConditions / MisbehavingServer: identical to the two
/// sibling clusters (`client_alarm_tracker_matrix_tests.cpp` / `client_condition_refresh_matrix_tests.cpp`)
/// - the interface gives deterministic control over event CONTENT (the impossible limit data, the exact
/// two-segment sub-state shape) while exercising the tracker's REAL decode/advisory logic on a real
/// strand/executor. Since Slice AC1 the field extraction IS wired end-to-end: the events these rows feed
/// carry the SPEC-SHAPED wire form a real server emits - the four limit doubles as single-segment Values,
/// each NonExclusive state Boolean at `[<State>, "Id"]`, and the ExclusiveLimit state at
/// `[LimitState, CurrentState]` - decoded by the tracker's by-PATH lookup.
///
/// SCOPE: the tracker's decode models the limit-alarm data verbatim (the four thresholds, the ExclusiveLimit
/// `exclusiveLimitState`, and the concurrent NonExclusive High/HighHigh/Low/LowState vector) and requests
/// all of them in its SelectClause. The "Recognised"/clearing/staleness rows assert the client-observable
/// state the tracker exposes (the most-derived EventType `conditionTypeId` and the `activeState` /
/// optional-substate clearing); the 2 advisory rows (Inequality / HighLow-concurrent) assert the CORRECT
/// spec behaviour - the raw base alarm is surfaced verbatim (never refused/dropped) AND a source-tagged
/// data-integrity advisory fires (CL-AC-023/025 detection). No test skips itself.
///
/// Timing: condition tracking is delivered asynchronously on the executor, so every wait is BOUNDED
/// POLLING on a thread-safe observable (never a fixed sleep). Because the tracker's strand is FIFO, a
/// `get_condition` (or a sentinel add) posted AFTER an event guarantees that event's on-strand handler -
/// including any advisory it would log - has fully run, so the advisory rows read the log sink
/// single-shot rather than polling for something that must never appear. All fakes/sinks are thread-safe.

#include "fake_connection_ops.h"
#include "test_utilities.h"

#include "ua_alarm_condition_tracker.h"
#include "ua_alarm_condition_tracker_impl.h"
#include "ua_alarm_condition_tracker_test_access.h"
#include "ua_event_backbone_ops.h"
#include "ua_event_subscriber_impl.h"

#include "ua_byte_string.h"
#include "ua_localized_text.h"
#include "ua_log_entry.h"
#include "ua_log_level.h"
#include "ua_log_sink.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_objecttype_id.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <variant>
#include <vector>

using ua::Result;
using ua::Status;
using ua::StatusCode;
using ua::VoidResult;
using ua::client::AlarmConditionTracker;
using ua::client::AlarmConditionTrackerPolicy;
using ua::client::EventNotification;
using ua::client::TrackedCondition;
using ua::client::TrackedKey;
using ua::client::detail::AlarmConditionTrackerHandleFactory;
using ua::client::detail::AlarmConditionTrackerImpl;
using ua::client::detail::AlarmConditionTrackerTestAccess;
using ua::client::detail::EventBackboneCreated;
using ua::client::detail::EventBackboneOps;
using ua::client::detail::EventSubscriberImpl;
using namespace std::chrono_literals;

namespace
{

// ---------------------------------------------------------------------------------------------
// Thread-safe event-backbone interface: replies Good so the tracker attaches + creates its default Server
// backbone (this cluster does not assert the composite filter - that is the ClientAlarmTracker slice).
// ---------------------------------------------------------------------------------------------
class RecordingBackboneOps : public EventBackboneOps
{
public:
  void create_backbone_async(ua::NodeId /*notifier*/, ua::EventFilter /*filter*/,
    std::uint32_t /*clientHandle*/, std::uint32_t /*queueSize*/,
    std::function<void(Result<EventBackboneCreated>)> callback) noexcept override
  {
    EventBackboneCreated created;
    created.subscriptionId = mNextSubscriptionId++;
    created.monitoredItemId = mNextMonitoredItemId++;
    mCreateCount++;
    callback(Result<EventBackboneCreated>{created});
  }

  void modify_backbone_filter_async(std::uint32_t /*subscriptionId*/, std::uint32_t /*monitoredItemId*/,
    std::uint32_t /*clientHandle*/, ua::EventFilter /*filter*/,
    std::function<void(Result<ua::client::detail::EventFilterDiagnostics>)> callback) noexcept override
  {
    callback(
      Result<ua::client::detail::EventFilterDiagnostics>{ua::client::detail::EventFilterDiagnostics{}});
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

  std::size_t create_count() const
  {
    return mCreateCount.load();
  }

private:
  std::atomic<std::uint32_t> mNextSubscriptionId{100};
  std::atomic<std::uint32_t> mNextMonitoredItemId{500};
  std::atomic<std::size_t> mCreateCount{0};
};

// ---------------------------------------------------------------------------------------------
// Thread-safe recording LogSink: captures every warning+ entry (message + category + flattened string
// field values, lowercased) so a data-integrity row can assert a source-tagged advisory appeared (or,
// for the consistent-limit rows, that NONE did). The tracker's Logger is wired to this sink at SetUp.
// ---------------------------------------------------------------------------------------------
class RecordingLogSink : public ua::LogSink
{
public:
  void log(const ua::LogEntry& entry) override
  {
    if (entry.level < ua::LogLevel::Warning)
    {
      return;
    }
    std::string haystack = to_lower(entry.message);
    haystack.push_back('\n');
    haystack += to_lower(std::string{entry.category});
    for (const auto& field : entry.fields)
    {
      haystack.push_back('\n');
      if (const auto* text = std::get_if<std::string_view>(&field.value))
      {
        haystack += to_lower(std::string{*text});
      }
    }
    std::lock_guard lock(mMutex);
    mEntries.push_back(std::move(haystack));
  }

  // Count of captured warning+ entries whose (message + category + string-fields) contains @p needle.
  std::size_t count_containing(std::string_view needle) const
  {
    const std::string lowered = to_lower(std::string{needle});
    std::lock_guard lock(mMutex);
    return static_cast<std::size_t>(std::count_if(mEntries.begin(),
      mEntries.end(),
      [&lowered](const std::string& entry) { return entry.find(lowered) != std::string::npos; }));
  }

private:
  static std::string to_lower(std::string value)
  {
    std::transform(value.begin(),
      value.end(),
      value.begin(),
      [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
  }

  mutable std::mutex mMutex;
  std::vector<std::string> mEntries;
};

// ---------------------------------------------------------------------------------------------
// Limit-alarm event builder (by-name field model the tracker's decode reads). The base condition fields
// (ConditionId / BranchId / Retain / ActiveState / AckedState) are what the tracker decodes today; the
// limit values + limit-state fields are carried on the wire exactly as a real LimitAlarm event would
// (the tracker ignores them today - see the findings file - but a data-integrity validator would read
// them). Omitting an optional leaves the field ABSENT (so a modelled optional surfaces as nullopt).
// ---------------------------------------------------------------------------------------------
struct LimitAlarmFields
{
  ua::NodeId conditionId;
  // BranchId is a **NodeId** (OPC 10000-9: HasProperty Variable BranchId NodeId PropertyType Mandatory),
  // not a ByteString. These fixtures built synthetic events carrying a ByteString - matching what the
  // tracker decoded rather than what a server sends - so the rows passed while the real decode failed on
  // every event from every server, collapsing every branch onto the trunk. A null NodeId is the trunk.
  ua::NodeId branchId{};
  ua::ByteString eventId{};
  bool retain = true;
  ua::NodeId eventTypeId{ua::ObjectTypeId::ExclusiveLimitAlarmType};
  std::optional<bool> active;
  std::optional<bool> acked;

  // Exclusive limit thresholds (Doubles) + the ExclusiveLimit current state (a LocalizedText).
  std::optional<double> highHighLimit;
  std::optional<double> highLimit;
  std::optional<double> lowLimit;
  std::optional<double> lowLowLimit;
  std::optional<ua::LocalizedText> limitState;

  // NonExclusive concurrent limit-state active flags.
  std::optional<bool> highHighState;
  std::optional<bool> highState;
  std::optional<bool> lowState;
  std::optional<bool> lowLowState;
};

// A single-segment leaf field (the node's Value: BranchId, Retain, the four limit doubles).
void add_field(EventNotification& event, std::string_view name, ua::Variant value)
{
  event.fields.push_back(std::move(value));
  event.fieldPaths.push_back({ua::QualifiedName{0, std::string{name}}});
}

// A TwoStateVariable Boolean at the SPEC-SHAPED two-segment path [<State>, "Id"] (Slice AC1).
void add_state_field(EventNotification& event, std::string_view stateName, bool id)
{
  event.fields.push_back(ua::Variant{id});
  event.fieldPaths.push_back(
    {ua::QualifiedName{0, std::string{stateName}}, ua::QualifiedName{0, std::string{"Id"}}});
}

// The ConditionId via the EMPTY-browse-path NodeId operand (CL-AC-002).
void add_condition_id(EventNotification& event, const ua::NodeId& conditionId)
{
  event.fields.push_back(ua::Variant{conditionId});
  event.fieldPaths.push_back({});  // empty browse path
}

EventNotification make_limit_event(const LimitAlarmFields& fields)
{
  EventNotification event;
  event.eventTypeId = fields.eventTypeId;
  event.eventId = fields.eventId;
  event.severity = 100;
  add_condition_id(event, fields.conditionId);
  add_field(event, "BranchId", ua::Variant{fields.branchId});
  add_field(event, "Retain", ua::Variant{fields.retain});
  if (fields.active.has_value())
  {
    add_state_field(event, "ActiveState", *fields.active);
  }
  if (fields.acked.has_value())
  {
    add_state_field(event, "AckedState", *fields.acked);
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
  if (fields.limitState.has_value())
  {
    // ExclusiveLimit CurrentState at the two-segment path [LimitState, CurrentState] (CL-AC-024).
    event.fields.push_back(ua::Variant{*fields.limitState});
    event.fieldPaths.push_back(
      {ua::QualifiedName{0, std::string{"LimitState"}}, ua::QualifiedName{0, std::string{"CurrentState"}}});
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
  return event;
}

TrackedKey make_key(const ua::NodeId& conditionId, ua::NodeId branchId = {})
{
  TrackedKey key;
  key.conditionId = conditionId;
  key.branchId = std::move(branchId);
  return key;
}

// ---------------------------------------------------------------------------------------------
// Fixture: one gtest suite `ClientLimitAlarm` (tests named exactly `ClientLimitAlarm.<Row>`). Owns a
// real thread pool, a real EventSubscriberImpl + tracker over the recording backbone interface + FakeWireOps,
// and a recording LogSink wired into the tracker's Logger (via the subscriber's forwarded Logger).
// ---------------------------------------------------------------------------------------------
class ClientLimitAlarm : public ::testing::Test
{
protected:
  void SetUp() override
  {
    auto level = std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Trace);
    ua::Logger logger{mLogSink, level, "client.tier2.alarm_tracker"};
    mSubscriber = EventSubscriberImpl::create(mPool.get_executor(), mBackbone, logger);
    mImpl = mSubscriber->ensure_alarm_tracker(mWire, AlarmConditionTrackerPolicy{});
    mTracker.emplace(AlarmConditionTrackerHandleFactory::create(mImpl));
    ASSERT_TRUE(poll_until([&] { return mBackbone->create_count() >= 1; }))
      << "tracker failed to attach + create its event backbone";
  }

  void TearDown() override
  {
    mTracker.reset();
    mImpl.reset();
    mSubscriber.reset();
    ua::test_utils::drain_with_timeout(mPool);
  }

  void post_event(const LimitAlarmFields& fields)
  {
    AlarmConditionTrackerTestAccess::post_event(*mImpl, make_limit_event(fields));
  }

  template<class Predicate>
  static bool poll_until(
    Predicate predicate, std::chrono::milliseconds timeout = ua::test_utils::default_poll_budget())
  {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline)
    {
      if (predicate())
      {
        return true;
      }
      std::this_thread::sleep_for(2ms);
    }
    return predicate();
  }

  std::size_t tracked_count()
  {
    return mImpl->info()->trackedConditionCount;
  }

  // A strand round-trip read of one tracked condition. Because the tracker's strand is FIFO, once this
  // returns every event posted BEFORE it (and any advisory that event would have logged) has fully run.
  Result<TrackedCondition> get_condition(const TrackedKey& key)
  {
    std::promise<Result<TrackedCondition>> promise;
    auto future = promise.get_future();
    mTracker->get_condition_async(
      key, [&promise](Result<TrackedCondition> result) { promise.set_value(std::move(result)); });
    EXPECT_EQ(future.wait_for(5s), std::future_status::ready) << "get_condition_async did not complete";
    return future.get();
  }

  boost::asio::thread_pool mPool{2};
  std::shared_ptr<RecordingBackboneOps> mBackbone = std::make_shared<RecordingBackboneOps>();
  std::shared_ptr<RecordingLogSink> mLogSink = std::make_shared<RecordingLogSink>();
  std::shared_ptr<ua::test_helpers::FakeWireOps> mWire = std::make_shared<ua::test_helpers::FakeWireOps>();
  std::shared_ptr<EventSubscriberImpl> mSubscriber;
  std::shared_ptr<AlarmConditionTrackerImpl> mImpl;
  std::optional<AlarmConditionTracker> mTracker;

  const ua::NodeId mConditionId{2, 4242U};
  const ua::ByteString mEventId{0xAA, 0xBB, 0xCC};
};

// Assert a recognised exclusive/non-exclusive limit-alarm variant: the most-derived EventType is
// surfaced (not collapsed to ConditionType) and the base ActiveState sub-state is present + True. This
// is the client-observable analog the tracker exposes for the section 8.8.5 "Recognised" rows (the modelled
// ExclusiveLimitInfo / concurrent NonExclusive state vector are not yet built - see the findings file).
void expect_recognised_active_variant(const Result<TrackedCondition>& tracked, const ua::NodeId& expectedType)
{
  ASSERT_TRUE(tracked.is_good());
  EXPECT_EQ(tracked.value().conditionTypeId, expectedType)
    << "the most-derived EventType must be surfaced (limit-alarm variant recognised, not a bare "
       "ConditionType)";
  ASSERT_TRUE(tracked.value().activeState.has_value())
    << "the alarm's ActiveState sub-state must be surfaced (subtype routing recognised the alarm)";
  EXPECT_EQ(tracked.value().activeState->id, true);
}

// =============================================================================================
// Row 1 - ConsistentLimitsSurfacedNoAdvisory  (section 8.8.5, CL-AC-023)
// An ExclusiveLimitAlarmType with a VALID ordering (HighHigh=100 > High=80 > Low=20 > LowLow=10) is
// recognised and surfaced, and NO data-integrity advisory fires.
// [neg: if the validator false-positived on a valid ordering, a spurious advisory fires]
//
// SCOPE: the four limit VALUES are not modelled by the tracker yet, so "all four limits surface" is
// pinned to EventType recognition + activeState (the observable analog). The no-advisory guard becomes
// required once the CL-AC-023 validator lands; today it is anchored on the recognition assertion, so
// the row is not a tautology.
// =============================================================================================
// @verifies CL-AC-023
// @relation(CL-AC-023, scope=function)
TEST_F(ClientLimitAlarm, ConsistentLimitsSurfacedNoAdvisory)
{
  LimitAlarmFields alarm;
  alarm.conditionId = mConditionId;
  alarm.eventId = mEventId;
  alarm.eventTypeId = ua::NodeId{ua::ObjectTypeId::ExclusiveLimitAlarmType};
  alarm.active = true;
  alarm.highHighLimit = 100.0;
  alarm.highLimit = 80.0;
  alarm.lowLimit = 20.0;
  alarm.lowLowLimit = 10.0;  // valid ordering: LowLow < Low < High < HighHigh
  post_event(alarm);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  const auto tracked = get_condition(make_key(mConditionId));  // FIFO round-trip past the limit event
  expect_recognised_active_variant(tracked, ua::NodeId{ua::ObjectTypeId::ExclusiveLimitAlarmType});
  EXPECT_EQ(mLogSink->count_containing("inequal"), 0U)
    << "a valid limit ordering must NOT raise a spurious inequality advisory (CL-AC-023)";
}

// =============================================================================================
// Row 2 - ExclusiveDeviationRecognised  (section 8.8.5, CL-AC-015/024)
// An ExclusiveDeviationAlarmType event is recognised as an exclusive-limit variant: its most-derived
// EventType is surfaced (not collapsed to ConditionType) and its ActiveState sub-state is present.
// [neg: unrecognised -> treated as a generic alarm, LimitState/subtype absent]
//
// SCOPE: the oracle wants the ExclusiveLimitInfo substate populated; the tracker models no
// ExclusiveLimitInfo -> pinned to EventType recognition + activeState.
// =============================================================================================
// @verifies CL-AC-015
// @verifies CL-AC-024
// @relation(CL-AC-015, CL-AC-024, scope=function)
TEST_F(ClientLimitAlarm, ExclusiveDeviationRecognised)
{
  LimitAlarmFields alarm;
  alarm.conditionId = mConditionId;
  alarm.eventId = mEventId;
  alarm.eventTypeId = ua::NodeId{ua::ObjectTypeId::ExclusiveDeviationAlarmType};
  alarm.active = true;
  post_event(alarm);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  expect_recognised_active_variant(
    get_condition(make_key(mConditionId)), ua::NodeId{ua::ObjectTypeId::ExclusiveDeviationAlarmType});
}

// =============================================================================================
// Row 3 - ExclusiveLevelRecognised  (section 8.8.5, CL-AC-015/024)
// An ExclusiveLevelAlarmType event is recognised as an exclusive-limit variant.
// [neg: unrecognised -> LimitState absent]
// SCOPE: ExclusiveLimitInfo not modelled -> pinned to EventType recognition + activeState.
// =============================================================================================
// @verifies CL-AC-015
// @verifies CL-AC-024
// @relation(CL-AC-015, CL-AC-024, scope=function)
TEST_F(ClientLimitAlarm, ExclusiveLevelRecognised)
{
  LimitAlarmFields alarm;
  alarm.conditionId = mConditionId;
  alarm.eventId = mEventId;
  alarm.eventTypeId = ua::NodeId{ua::ObjectTypeId::ExclusiveLevelAlarmType};
  alarm.active = true;
  post_event(alarm);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  expect_recognised_active_variant(
    get_condition(make_key(mConditionId)), ua::NodeId{ua::ObjectTypeId::ExclusiveLevelAlarmType});
}

// =============================================================================================
// Row 4 - ExclusiveLimitStateClearedWhenInactive  (section 8.8.2, CL-AC-024)
// Deliver ExclusiveLimitAlarmType ActiveState/Id=True (LimitState=High); then a follow-up with
// ActiveState/Id=False and LimitState NULL. After the second event the alarm is inactive.
// [neg: an inactive alarm must clear its active limit state, not keep the prior High]
//
// SCOPE: the oracle reads `limitState==nullopt`; the tracker models no limitState -> pinned to the base
// clearing on the modelled ActiveState: True->False. The second event carries LimitState absent (NULL);
// the tracker's whole-condition re-decode replaces the sub-state wholesale, so no stale active state is
// retained. Extend to limitState when the ExclusiveLimit substate lands.
// =============================================================================================
// @verifies CL-AC-024
// @relation(CL-AC-024, scope=function)
TEST_F(ClientLimitAlarm, ExclusiveLimitStateClearedWhenInactive)
{
  LimitAlarmFields active;
  active.conditionId = mConditionId;
  active.eventId = ua::ByteString{0x01};
  active.eventTypeId = ua::NodeId{ua::ObjectTypeId::ExclusiveLimitAlarmType};
  active.active = true;
  active.highLimit = 80.0;
  active.limitState = ua::LocalizedText{"", "High"};
  post_event(active);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));
  ASSERT_TRUE(get_condition(make_key(mConditionId)).value().activeState->id == true);

  LimitAlarmFields inactive;
  inactive.conditionId = mConditionId;
  inactive.eventId = ua::ByteString{0x02};
  inactive.eventTypeId = ua::NodeId{ua::ObjectTypeId::ExclusiveLimitAlarmType};
  inactive.active = false;  // alarm inactive; LimitState omitted (NULL)
  post_event(inactive);
  ASSERT_TRUE(poll_until(
    [&]
    {
      const auto tc = get_condition(make_key(mConditionId));
      return tc.is_good() && tc.value().activeState.has_value() && tc.value().activeState->id == false;
    }))
    << "the inactive event must clear ActiveState to False (not keep the prior active limit state)";
}

// =============================================================================================
// Row 5 - ExclusiveLimitStateDoesNotPersistStale  (section 8.8.2, CL-AC-024)
// Following the inactive/NULL event, a previously-present optional sub-state that is OMITTED in the
// follow-up must clear to nullopt - NOT retain its cached value.
// [neg: NULL must clear, not retain the cached value - else the UI shows a limit for an inactive alarm]
//
// SCOPE: the oracle reads a stale `limitState==High`; the tracker models no limitState -> the identical
// "absent field clears, does not persist stale" RULE is verified on the modelled AckedState optional (the
// same std::optional<TwoStateValue> mechanism the future limitState will use): event A carries
// AckedState=True, event B omits AckedState -> ackedState becomes nullopt, not the stale Some(True).
// =============================================================================================
// @verifies CL-AC-024
// @relation(CL-AC-024, scope=function)
TEST_F(ClientLimitAlarm, ExclusiveLimitStateDoesNotPersistStale)
{
  LimitAlarmFields present;
  present.conditionId = mConditionId;
  present.eventId = ua::ByteString{0x01};
  present.eventTypeId = ua::NodeId{ua::ObjectTypeId::ExclusiveLimitAlarmType};
  present.active = true;
  present.acked = true;  // a present optional sub-state
  post_event(present);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));
  ASSERT_TRUE(get_condition(make_key(mConditionId)).value().ackedState.has_value());

  LimitAlarmFields omitted;
  omitted.conditionId = mConditionId;
  omitted.eventId = ua::ByteString{0x02};
  omitted.eventTypeId = ua::NodeId{ua::ObjectTypeId::ExclusiveLimitAlarmType};
  omitted.active = false;  // AckedState omitted (NULL) - must clear, not persist the stale Some(True)
  post_event(omitted);
  ASSERT_TRUE(poll_until(
    [&]
    {
      const auto tc = get_condition(make_key(mConditionId));
      return tc.is_good() && tc.value().activeState.has_value() && tc.value().activeState->id == false;
    }))
    << "the follow-up event must have been applied";

  const auto after = get_condition(make_key(mConditionId));
  ASSERT_TRUE(after.is_good());
  EXPECT_FALSE(after.value().ackedState.has_value())
    << "an omitted optional sub-state must clear to nullopt, NOT retain the stale prior value (CL-AC-024)";
}

// =============================================================================================
// Row 6 - ExclusiveRateOfChangeRecognised  (section 8.8.5, CL-AC-015/024)
// An ExclusiveRateOfChangeAlarmType event is recognised as an exclusive-limit variant.
// [neg: unrecognised -> LimitState absent]
// SCOPE: ExclusiveLimitInfo not modelled -> pinned to EventType recognition + activeState.
// =============================================================================================
// @verifies CL-AC-015
// @verifies CL-AC-024
// @relation(CL-AC-015, CL-AC-024, scope=function)
TEST_F(ClientLimitAlarm, ExclusiveRateOfChangeRecognised)
{
  LimitAlarmFields alarm;
  alarm.conditionId = mConditionId;
  alarm.eventId = mEventId;
  alarm.eventTypeId = ua::NodeId{ua::ObjectTypeId::ExclusiveRateOfChangeAlarmType};
  alarm.active = true;
  post_event(alarm);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  expect_recognised_active_variant(
    get_condition(make_key(mConditionId)), ua::NodeId{ua::ObjectTypeId::ExclusiveRateOfChangeAlarmType});
}

// =============================================================================================
// Row 7 - InequalityViolationAdvisesButSurfacesRaw  (section 8.8.5, CL-AC-023)  [MisbehavingServer ->
// interface] A LimitAlarmType with High=80, Low=85 (violates High > Low). The tracker must SURFACE the raw
// alarm verbatim (never refuse/coerce/drop) AND additionally ADVISE (a source-tagged data-integrity
// advisory). [neg: advise-and-surface-raw, never coerce or refuse]
//
// RED (by design - CL-AC-023 detection is unimplemented): the tracker
// selects/decodes no limit fields and has no inequality validator, so no advisory is ever produced. The
// GREEN half (raw base alarm surfaced, not refused) passes today; the advisory-fire assertion is RED.
// The advisory is observed via the tracker's source-tagged Logger (the "log a source-tagged advisory"
// arm of the guiding principle); the canonical AlarmObserver::on_data_integrity_warning delivery interface is
// the additional owed piece (findings section 1c/section 2). Suggested source tag:
// client.tier2.alarm_tracker.limit_inequality.
// =============================================================================================
// @verifies CL-AC-023
// @relation(CL-AC-023, scope=function)
TEST_F(ClientLimitAlarm, InequalityViolationAdvisesButSurfacesRaw)
{
  LimitAlarmFields alarm;
  alarm.conditionId = mConditionId;
  alarm.eventId = mEventId;
  alarm.eventTypeId = ua::NodeId{ua::ObjectTypeId::LimitAlarmType};
  alarm.active = true;
  alarm.highLimit = 80.0;
  alarm.lowLimit = 85.0;  // violates High > Low
  post_event(alarm);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  // (a) Raw surfaced verbatim: the impossible-limit alarm is still tracked and its base state surfaced -
  // the tracker did NOT refuse, coerce, or drop it. The FIFO round-trip also drains past the event, so
  // any advisory it would have logged is already recorded when (b) reads the sink.
  const auto tracked = get_condition(make_key(mConditionId));
  ASSERT_TRUE(tracked.is_good()) << "the raw alarm must be surfaced, never refused";
  EXPECT_EQ(tracked.value().conditionTypeId, ua::NodeId{ua::ObjectTypeId::LimitAlarmType})
    << "the raw EventType must be surfaced unchanged";
  ASSERT_TRUE(tracked.value().activeState.has_value());
  EXPECT_EQ(tracked.value().activeState->id, true) << "the raw ActiveState must be surfaced verbatim";

  // (b) Advise: a source-tagged inequality advisory must fire. RED - no validator exists today.
  EXPECT_GE(mLogSink->count_containing("inequal"), 1U)
    << "an inequality (High<Low) invariant violation must raise a data-integrity advisory (CL-AC-023). "
       "RED until the limit-field decode + inequality validator land";
}

// =============================================================================================
// Row 8 - NonExclusiveDeviationRecognised  (section 8.8.5, CL-AC-015/025)
// A NonExclusiveDeviationAlarmType event is recognised as a non-exclusive-limit variant.
// [neg: unrecognised -> non-exclusive states absent]
// SCOPE: the concurrent NonExclusive state vector is not modelled -> pinned to EventType recognition +
// activeState (the observable analog).
// =============================================================================================
// @verifies CL-AC-015
// @verifies CL-AC-025
// @relation(CL-AC-015, CL-AC-025, scope=function)
TEST_F(ClientLimitAlarm, NonExclusiveDeviationRecognised)
{
  LimitAlarmFields alarm;
  alarm.conditionId = mConditionId;
  alarm.eventId = mEventId;
  alarm.eventTypeId = ua::NodeId{ua::ObjectTypeId::NonExclusiveDeviationAlarmType};
  alarm.active = true;
  post_event(alarm);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  expect_recognised_active_variant(
    get_condition(make_key(mConditionId)), ua::NodeId{ua::ObjectTypeId::NonExclusiveDeviationAlarmType});
}

// =============================================================================================
// Row 9 - NonExclusiveHighAndHighHighConcurrentAllowed  (section 8.8.5, CL-AC-025)
// A NonExclusiveLimitAlarmType with HighState=True, HighHighState=True, LowState=False, LowLowState=False
// - WITHIN-group concurrency, which is LEGAL. The alarm is recognised/surfaced and NO advisory fires.
// [neg: within-group concurrency is legal - forcing mutual exclusion (clearing a state) or a spurious
//  advisory is the failure]
//
// SCOPE: the four concurrent states are not modelled -> "all four states surface" is pinned to EventType
// recognition + activeState. The no-advisory guard (no cross-group violation here) becomes required
// once the CL-AC-025 validator lands; today it is anchored on the recognition assertion.
// =============================================================================================
// @verifies CL-AC-025
// @relation(CL-AC-025, scope=function)
TEST_F(ClientLimitAlarm, NonExclusiveHighAndHighHighConcurrentAllowed)
{
  LimitAlarmFields alarm;
  alarm.conditionId = mConditionId;
  alarm.eventId = mEventId;
  alarm.eventTypeId = ua::NodeId{ua::ObjectTypeId::NonExclusiveLimitAlarmType};
  alarm.active = true;
  alarm.highState = true;
  alarm.highHighState = true;  // concurrent within the high group - legal
  alarm.lowState = false;
  alarm.lowLowState = false;
  post_event(alarm);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  const auto tracked = get_condition(make_key(mConditionId));  // FIFO round-trip past the limit event
  expect_recognised_active_variant(tracked, ua::NodeId{ua::ObjectTypeId::NonExclusiveLimitAlarmType});
  EXPECT_EQ(mLogSink->count_containing("cross"), 0U)
    << "within-group concurrency (High + HighHigh) must NOT raise a cross-group advisory (CL-AC-025)";
}

// =============================================================================================
// Row 10 - NonExclusiveHighLowConcurrentAdvises  (section 8.8.5, CL-AC-025)  [MisbehavingServer -> interface]
// A NonExclusiveLimitAlarmType with HighState=True AND LowState=True - an impossible cross-group state.
// The tracker must SURFACE the raw alarm verbatim AND additionally ADVISE (a source-tagged advisory).
// [neg: high + low simultaneously is an invariant violation - a missing cross-group check shows the
//  impossible state as normal with no advisory]
//
// RED (by design - CL-AC-025 detection is unimplemented): the tracker
// selects/decodes no NonExclusive state fields and has no cross-group validator, so no advisory is ever
// produced. The GREEN half (raw base alarm surfaced, not refused) passes today; the advisory-fire
// assertion is RED. Advisory observed via the source-tagged Logger; the canonical
// AlarmObserver::on_data_integrity_warning delivery interface is the additional owed piece (findings section
// 1c/section 2). Suggested source tag: client.tier2.alarm_tracker.non_exclusive_cross_group.
// =============================================================================================
// @verifies CL-AC-025
// @relation(CL-AC-025, scope=function)
TEST_F(ClientLimitAlarm, NonExclusiveHighLowConcurrentAdvises)
{
  LimitAlarmFields alarm;
  alarm.conditionId = mConditionId;
  alarm.eventId = mEventId;
  alarm.eventTypeId = ua::NodeId{ua::ObjectTypeId::NonExclusiveLimitAlarmType};
  alarm.active = true;
  alarm.highState = true;  // high group active
  alarm.lowState = true;  // AND low group active - impossible cross-group state
  post_event(alarm);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  // (a) Raw surfaced verbatim: the impossible cross-group alarm is still tracked and surfaced - the
  // tracker did NOT clear a state, refuse, or drop it. The FIFO round-trip drains past the event.
  const auto tracked = get_condition(make_key(mConditionId));
  ASSERT_TRUE(tracked.is_good()) << "the raw alarm must be surfaced, never refused";
  EXPECT_EQ(tracked.value().conditionTypeId, ua::NodeId{ua::ObjectTypeId::NonExclusiveLimitAlarmType})
    << "the raw EventType must be surfaced unchanged";
  ASSERT_TRUE(tracked.value().activeState.has_value());
  EXPECT_EQ(tracked.value().activeState->id, true) << "the raw ActiveState must be surfaced verbatim";

  // (b) Advise: a source-tagged cross-group advisory must fire. RED - no validator exists today.
  EXPECT_GE(mLogSink->count_containing("cross"), 1U)
    << "concurrent high + low (cross-group) is an invariant violation and must raise a data-integrity "
       "advisory (CL-AC-025). RED until the NonExclusive state decode + cross-group validator land";
}

// =============================================================================================
// Row 11 - NonExclusiveLevelRecognised  (section 8.8.5, CL-AC-015/025)
// A NonExclusiveLevelAlarmType event is recognised as a non-exclusive-limit variant.
// [neg: unrecognised -> non-exclusive states absent]
// SCOPE: concurrent state vector not modelled -> pinned to EventType recognition + activeState.
// =============================================================================================
// @verifies CL-AC-015
// @verifies CL-AC-025
// @relation(CL-AC-015, CL-AC-025, scope=function)
TEST_F(ClientLimitAlarm, NonExclusiveLevelRecognised)
{
  LimitAlarmFields alarm;
  alarm.conditionId = mConditionId;
  alarm.eventId = mEventId;
  alarm.eventTypeId = ua::NodeId{ua::ObjectTypeId::NonExclusiveLevelAlarmType};
  alarm.active = true;
  post_event(alarm);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  expect_recognised_active_variant(
    get_condition(make_key(mConditionId)), ua::NodeId{ua::ObjectTypeId::NonExclusiveLevelAlarmType});
}

// =============================================================================================
// Row 12 - NonExclusiveRateOfChangeRecognised  (section 8.8.5, CL-AC-015/025)
// A NonExclusiveRateOfChangeAlarmType event is recognised as a non-exclusive-limit variant.
// [neg: unrecognised -> non-exclusive states absent]
// SCOPE: concurrent state vector not modelled -> pinned to EventType recognition + activeState.
// =============================================================================================
// @verifies CL-AC-015
// @verifies CL-AC-025
// @relation(CL-AC-015, CL-AC-025, scope=function)
TEST_F(ClientLimitAlarm, NonExclusiveRateOfChangeRecognised)
{
  LimitAlarmFields alarm;
  alarm.conditionId = mConditionId;
  alarm.eventId = mEventId;
  alarm.eventTypeId = ua::NodeId{ua::ObjectTypeId::NonExclusiveRateOfChangeAlarmType};
  alarm.active = true;
  post_event(alarm);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  expect_recognised_active_variant(
    get_condition(make_key(mConditionId)), ua::NodeId{ua::ObjectTypeId::NonExclusiveRateOfChangeAlarmType});
}

}  // namespace
