// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientAlarmTracker cluster of the client integration-test matrix (the 13 `ClientAlarmTracker.*`
///        rows).
///
/// COMPANION: `client_alarm_live_server_tests.cpp` runs the same surface against a REAL server. These
/// rows keep what only an interface can hold - the wire ARGUMENTS a wrapper builds, server misbehaviour a
/// conforming server will not produce, and branches this server does not emit. What a live server can
/// decide is asserted there, because a fake agrees with whatever the client sends it.
///
/// These exercise the TIER-2 Alarm & Condition tracker (`ua::client::AlarmConditionTracker` over the
/// no-own-strand `detail::AlarmConditionTrackerImpl`, client design section 8.8) as a live component: a REAL
/// `EventSubscriberImpl` + tracker are built over the mockable event backbone interface on a REAL
/// `boost::asio::thread_pool`, and the tracker's OWN decode -> (ConditionId,BranchId)->TrackedCondition
/// map -> observer -> snapshot pipeline is driven through its on-strand hook entry points (the
/// `AlarmConditionTrackerTestAccess` interface posts them onto the tracker's strand exactly as the
/// subscriber's Publish dispatch would). Every assertion is made through the PUBLIC consumer surface
/// (`list_conditions_async` / `get_condition_async` / `on_condition_*_async` / `info()`), which is what
/// a tier-2 user observes.
///
/// Why the hook interface and not a real server subscription: the interface gives DETERMINISTIC control over
/// event CONTENT (the exact two-segment sub-state shape, distinct ConditionIds, branch events, refresh
/// replays) that would be awkward to drive single-shot through a live server, while exercising the tracker's
/// REAL decode + map + observer logic on a real strand/executor. Since Slice AC1 the tracker's field
/// extraction IS wired end-to-end: the events these rows feed carry the SPEC-SHAPED wire form a real server
/// emits - each TwoStateVariable Boolean at the two-segment path `[<State>, "Id"]`, the ExclusiveLimit state
/// at
/// `[LimitState, CurrentState]`, and the ConditionId via the empty-browse-path NodeId operand - decoded by
/// the tracker's by-PATH lookup (the same `EventNotification` `decode_notification` builds from the composite
/// filter). The wire-decode hop itself (a real Publish -> `decode_notification` -> EventSubscriber) is proven
/// end-to-end by `client_monitor_event_matrix_tests.cpp::RealInboundPublishRoutesEventToConsumer`.
///
/// Falsifiability: every test encodes its matrix row's `[neg: ...]` falsifier - it fails if the named
/// behaviour regresses. Rows whose full oracle needs behaviour not yet built (the AlarmConditionType
/// sub-state vector's SuppressedState/SuppressedOrShelved aggregate, ConditionClassId/Name - both
/// deferred to the section 8.8 "10a follow-ups") pin the buildable client-observable analog GREEN and
/// document the gap in-file; the cross-server ColdFailover row pins the verified clear-on-close analog and
/// reports the redundancy-harness dependency. No test skips itself.
///
/// Timing: condition tracking is subscription-driven and delivered asynchronously on the executor, so
/// observer-count assertions use BOUNDED POLLING on a thread-safe slot (never a fixed sleep); map-state
/// snapshot reads use a promise bridged off the executor callback. All fakes are thread-safe.

#include "fake_connection_ops.h"
#include "test_utilities.h"

#include "ua_alarm_condition_tracker.h"
#include "ua_alarm_condition_tracker_impl.h"
#include "ua_alarm_condition_tracker_test_access.h"
#include "ua_event_backbone_ops.h"
#include "ua_event_subscriber_impl.h"

#include "ua_attribute_id.h"
#include "ua_byte_string.h"
#include "ua_content_filter_element.h"
#include "ua_error_detail.h"
#include "ua_event_filter.h"
#include "ua_filter_operator.h"
#include "ua_literal_operand.h"
#include "ua_localized_text.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_objecttype_id.h"
#include "ua_result.h"
#include "ua_simple_attribute_operand.h"
#include "ua_status.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
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
// Thread-safe event-backbone interface: records the composite EventFilter of every create so a test can
// assert the tracker's WhereClause contribution (row 9). Replies Good so the tracker attaches.
// ---------------------------------------------------------------------------------------------
class RecordingBackboneOps : public EventBackboneOps
{
public:
  void create_backbone_async(ua::NodeId /*notifier*/, ua::EventFilter filter, std::uint32_t /*clientHandle*/,
    std::uint32_t /*queueSize*/, std::function<void(Result<EventBackboneCreated>)> callback) noexcept override
  {
    {
      std::lock_guard lock(mMutex);
      mCreateFilters.push_back(std::move(filter));
    }
    EventBackboneCreated created;
    created.subscriptionId = mNextSubscriptionId++;
    created.monitoredItemId = mNextMonitoredItemId++;
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
    std::lock_guard lock(mMutex);
    return mCreateFilters.size();
  }

  std::optional<ua::EventFilter> first_create_filter() const
  {
    std::lock_guard lock(mMutex);
    if (mCreateFilters.empty())
    {
      return std::nullopt;
    }
    return mCreateFilters.front();
  }

private:
  mutable std::mutex mMutex;
  std::vector<ua::EventFilter> mCreateFilters;
  std::atomic<std::uint32_t> mNextSubscriptionId{100};
  std::atomic<std::uint32_t> mNextMonitoredItemId{500};
};

// ---------------------------------------------------------------------------------------------
// Event builders - the by-name field model the tracker's decode reads (mirrors the tracker's unit
// suite). `eventTypeId` selects the most-derived EventType; omitted optionals leave the field absent
// (so the tracker surfaces the sub-state as nullopt, distinct from a present `false`).
// ---------------------------------------------------------------------------------------------
struct ConditionFields
{
  ua::NodeId conditionId;
  // BranchId is a **NodeId** (OPC 10000-9: HasProperty Variable BranchId NodeId PropertyType Mandatory),
  // not a ByteString. These fixtures built synthetic events carrying a ByteString - matching what the
  // tracker decoded rather than what a server sends - so the rows passed while the real decode failed on
  // every event from every server, collapsing every branch onto the trunk. A null NodeId is the trunk.
  ua::NodeId branchId{};
  ua::ByteString eventId{};
  bool retain = true;
  ua::NodeId eventTypeId{ua::ObjectTypeId::ConditionType};
  ua::LocalizedText conditionName{};
  ua::NodeId conditionClassId{};
  ua::LocalizedText conditionClassName{};
  std::optional<bool> acked;
  std::optional<bool> confirmed;
  std::optional<bool> active;
  // ---- Optional AlarmConditionType sub-states (CL-AC-016) ----
  std::optional<bool> suppressed;
  std::optional<bool> outOfService;
  std::optional<bool> silence;
  std::optional<bool> latched;
  std::optional<bool> suppressedOrShelved;
  std::optional<ua::LocalizedText> shelvingState;  ///< ShelvingState.CurrentState
  std::optional<ua::Duration> reAlarmTime;
  std::optional<std::int16_t> reAlarmRepeatCount;
  std::optional<ua::Duration> onDelay;
  std::optional<ua::Duration> offDelay;
  std::optional<bool> audibleEnabled;
  std::optional<ua::AudioDataType> audibleSound;
  std::optional<bool> firstInGroupFlag;
  std::optional<ua::NodeId> firstInGroup;
  std::optional<ua::NodeId> normalState;
  std::optional<ua::NodeId> targetValueNode;
  std::optional<ua::Duration> expectedTime;
  std::optional<double> tolerance;
};

// A single-segment leaf field (the node's Value: ConditionName, Retain, BranchId).
void add_field(EventNotification& event, std::string_view name, ua::Variant value)
{
  event.fields.push_back(std::move(value));
  event.fieldPaths.push_back({ua::QualifiedName{0, std::string{name}}});
}

// A TwoStateVariable Boolean at the SPEC-SHAPED two-segment path [<State>, "Id"] (Slice AC1): the wire
// shape a real server emits (the single-segment <State> node's Value is the display-name LocalizedText).
void add_state_field(EventNotification& event, std::string_view stateName, bool id)
{
  event.fields.push_back(ua::Variant{id});
  event.fieldPaths.push_back(
    {ua::QualifiedName{0, std::string{stateName}}, ua::QualifiedName{0, std::string{"Id"}}});
}

// A two-segment [parent, child] field (e.g. [ShelvingState, CurrentState]) carrying an arbitrary Variant.
void add_two_segment_field(
  EventNotification& event, std::string_view parent, std::string_view child, ua::Variant value)
{
  event.fields.push_back(std::move(value));
  event.fieldPaths.push_back(
    {ua::QualifiedName{0, std::string{parent}}, ua::QualifiedName{0, std::string{child}}});
}

// The ConditionId via the EMPTY-browse-path NodeId operand (CL-AC-002) - the condition instance's own NodeId.
void add_condition_id(EventNotification& event, const ua::NodeId& conditionId)
{
  event.fields.push_back(ua::Variant{conditionId});
  event.fieldPaths.push_back({});  // empty browse path
}

EventNotification make_condition_event(const ConditionFields& fields)
{
  EventNotification event;
  event.eventTypeId = fields.eventTypeId;
  event.eventId = fields.eventId;
  event.severity = 100;
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
  // CL-AC-016 optional sub-states - spec-shaped two-segment [<State>, "Id"], single-segment aggregate, and
  // the two-segment ShelvingState/CurrentState. Only appended when set (absent -> nullopt on decode).
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

TrackedKey make_key(const ua::NodeId& conditionId, ua::NodeId branchId = {})
{
  TrackedKey key;
  key.conditionId = conditionId;
  key.branchId = std::move(branchId);
  return key;
}

// Thread-safe observer capture: counts + last payloads per observer kind.
struct ObserverLog
{
  mutable std::mutex mutex;
  int added = 0;
  int changed = 0;
  int removed = 0;
  std::vector<TrackedCondition> addedConditions;
  std::vector<TrackedCondition> changedConditions;
  std::vector<TrackedKey> removedKeys;

  int added_count() const
  {
    std::lock_guard lock(mutex);
    return added;
  }

  int changed_count() const
  {
    std::lock_guard lock(mutex);
    return changed;
  }

  int removed_count() const
  {
    std::lock_guard lock(mutex);
    return removed;
  }
};

// ---------------------------------------------------------------------------------------------
// Fixture: one gtest suite `ClientAlarmTracker` (tests named exactly `ClientAlarmTracker.<Row>`).
// Owns a real thread pool, a real EventSubscriberImpl + tracker over the recording backbone interface, and
// the public AlarmConditionTracker handle. Provides the async->sync bridges every row uses.
// ---------------------------------------------------------------------------------------------
class ClientAlarmTracker : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mSubscriber = EventSubscriberImpl::create(mPool.get_executor(), mBackbone, ua::Logger{});
    mImpl = mSubscriber->ensure_alarm_tracker(mWire, AlarmConditionTrackerPolicy{});
    mTracker.emplace(AlarmConditionTrackerHandleFactory::create(mImpl));
    // The tracker attaches + creates its default Server backbone asynchronously; wait for it so the
    // recorded composite filter (row 9) is available and the component is fully wired.
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

  // Feed one decoded condition event to the tracker's on-strand hook (as the subscriber dispatch would).
  void post_event(const ConditionFields& fields)
  {
    AlarmConditionTrackerTestAccess::post_event(*mImpl, make_condition_event(fields));
  }

  // Bounded polling on a predicate - the sanctioned wait for asynchronously-delivered observables.
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

  // Snapshot read of the whole tracked set through the public handle (delivered on the executor).
  std::vector<TrackedCondition> list_conditions()
  {
    std::promise<Result<std::vector<TrackedCondition>>> promise;
    auto future = promise.get_future();
    mTracker->list_conditions_async(
      [&promise](Result<std::vector<TrackedCondition>> result) { promise.set_value(std::move(result)); });
    EXPECT_EQ(future.wait_for(5s), std::future_status::ready) << "list_conditions_async did not complete";
    auto result = future.get();
    EXPECT_TRUE(result.is_good());
    return result.is_good() ? result.value() : std::vector<TrackedCondition>{};
  }

  // Snapshot read of one tracked condition through the public handle.
  Result<TrackedCondition> get_condition(const TrackedKey& key)
  {
    std::promise<Result<TrackedCondition>> promise;
    auto future = promise.get_future();
    mTracker->get_condition_async(
      key, [&promise](Result<TrackedCondition> result) { promise.set_value(std::move(result)); });
    EXPECT_EQ(future.wait_for(5s), std::future_status::ready) << "get_condition_async did not complete";
    return future.get();
  }

  // Register the added/changed/removed observers on `mLog` and wait until registration is committed on
  // the strand (so a subsequently-posted event is guaranteed to be seen).
  void install_observers()
  {
    await_registration(
      [&](std::function<void(VoidResult)> done)
      {
        mTracker->on_condition_added_async(
          [this](const TrackedCondition& condition)
          {
            std::lock_guard lock(mLog.mutex);
            ++mLog.added;
            mLog.addedConditions.push_back(condition);
          },
          std::move(done));
      });
    await_registration(
      [&](std::function<void(VoidResult)> done)
      {
        mTracker->on_condition_changed_async(
          [this](const TrackedCondition& condition)
          {
            std::lock_guard lock(mLog.mutex);
            ++mLog.changed;
            mLog.changedConditions.push_back(condition);
          },
          std::move(done));
      });
    await_registration(
      [&](std::function<void(VoidResult)> done)
      {
        mTracker->on_condition_removed_async(
          [this](TrackedKey key)
          {
            std::lock_guard lock(mLog.mutex);
            ++mLog.removed;
            mLog.removedKeys.push_back(std::move(key));
          },
          std::move(done));
      });
  }

  template<class Register>
  void await_registration(Register registerCb)
  {
    std::promise<void> promise;
    auto future = promise.get_future();
    registerCb([&promise](VoidResult) { promise.set_value(); });
    ASSERT_EQ(future.wait_for(5s), std::future_status::ready) << "observer registration did not complete";
  }

  boost::asio::thread_pool mPool{2};
  std::shared_ptr<RecordingBackboneOps> mBackbone = std::make_shared<RecordingBackboneOps>();
  std::shared_ptr<ua::test_helpers::FakeWireOps> mWire = std::make_shared<ua::test_helpers::FakeWireOps>();
  std::shared_ptr<EventSubscriberImpl> mSubscriber;
  std::shared_ptr<AlarmConditionTrackerImpl> mImpl;
  std::optional<AlarmConditionTracker> mTracker;
  ObserverLog mLog;

  const ua::NodeId mConditionId{2, 4242U};
  const ua::ByteString mEventId{0xAA, 0xBB, 0xCC};
};

// =============================================================================================
// Row 1 - RetainFalseFiresConditionRemoved  (section 8.8.3, CL-AC-006)
// A final event with Retain=False removes the branch and fires on_condition_removed(key); the entry
// is gone from the active map. [neg: Retain=False must not be treated as a normal update]
// =============================================================================================
// @verifies CL-AC-006
// @relation(CL-AC-006, scope=function)
TEST_F(ClientAlarmTracker, RetainFalseFiresConditionRemoved)
{
  install_observers();

  ConditionFields active;
  active.conditionId = mConditionId;
  active.eventId = mEventId;
  active.retain = true;
  post_event(active);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  ConditionFields cleared = active;
  cleared.retain = false;  // CL-AC-006
  post_event(cleared);

  ASSERT_TRUE(poll_until([&] { return mLog.removed_count() == 1; }))
    << "Retain=False must fire on_condition_removed";
  EXPECT_EQ(tracked_count(), 0U) << "the entry must be absent from the active map";
  EXPECT_EQ(mLog.changed_count(), 0) << "Retain=False must not be delivered as a normal update";
  {
    std::lock_guard lock(mLog.mutex);
    ASSERT_EQ(mLog.removedKeys.size(), 1U);
    EXPECT_EQ(mLog.removedKeys.front(), make_key(mConditionId));
  }
  EXPECT_EQ(get_condition(make_key(mConditionId)).status_code().as_uint32(),
    StatusCode{Status::BadNodeIdUnknown}.as_uint32());
}

// =============================================================================================
// Row 4 - TrunkAndBranchTrackedIndependently  (section 8.8.2, CL-AC-002)
// A trunk event (BranchId=NULL) and a prior-state branch event (BranchId!=NULL) for the SAME
// ConditionId produce two distinct TrackedCondition entries; on_condition_added fires twice.
// [neg: keying on ConditionId alone would let the branch overwrite the trunk]
// =============================================================================================
// @verifies CL-AC-002
// @relation(CL-AC-002, scope=function)
TEST_F(ClientAlarmTracker, TrunkAndBranchTrackedIndependently)
{
  install_observers();

  const ua::NodeId branchId{2, std::string{"branch-1"}};

  ConditionFields trunk;
  trunk.conditionId = mConditionId;
  trunk.eventId = ua::ByteString{0x01};
  post_event(trunk);

  ConditionFields branch;
  branch.conditionId = mConditionId;
  branch.branchId = branchId;
  branch.eventId = ua::ByteString{0x02};
  post_event(branch);

  ASSERT_TRUE(poll_until([&] { return mLog.added_count() == 2; }))
    << "trunk and branch must each fire on_condition_added";
  EXPECT_EQ(tracked_count(), 2U) << "trunk and branch are independent entries";

  EXPECT_TRUE(get_condition(make_key(mConditionId)).is_good()) << "trunk (NULL branch) must survive";
  EXPECT_TRUE(get_condition(make_key(mConditionId, branchId)).is_good()) << "branch must survive";
  EXPECT_EQ(mLog.changed_count(), 0) << "two distinct keys -> two adds, no change";
}

// =============================================================================================
// Row 2 - RetainFalseThenRetainTrueReAdds  (section 8.8.3, CL-AC-006)
// After a branch is removed via Retain=False, the same (ConditionId,BranchId) re-activating with
// Retain=True is a FRESH add - on_condition_added fires again, not on_condition_changed.
// [neg: removal is final; a re-entry must not be a change / dedupe against a tombstone]
// =============================================================================================
// @verifies CL-AC-006
// @relation(CL-AC-006, scope=function)
TEST_F(ClientAlarmTracker, RetainFalseThenRetainTrueReAdds)
{
  install_observers();

  ConditionFields event;
  event.conditionId = mConditionId;
  event.eventId = mEventId;

  event.retain = true;  // add
  post_event(event);
  ASSERT_TRUE(poll_until([&] { return mLog.added_count() == 1; }));

  event.retain = false;  // remove
  post_event(event);
  ASSERT_TRUE(poll_until([&] { return mLog.removed_count() == 1; }));
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 0; }));

  event.retain = true;  // re-activate the same key
  post_event(event);

  ASSERT_TRUE(poll_until([&] { return mLog.added_count() == 2; }))
    << "re-activation after a final removal must fire a fresh on_condition_added";
  EXPECT_EQ(tracked_count(), 1U);
  EXPECT_EQ(mLog.changed_count(), 0)
    << "the re-add must not be delivered as a change (no surviving tombstone to dedupe against)";
}

// =============================================================================================
// Row 3 - UnknownBranchRetainFalseDropsSilently  (section 8.8.7, CL-AC-006)
// A Retain=False event for a (ConditionId,BranchId) that was never tracked (e.g. a pre-attach event
// lost in a race) must NOT fire on_condition_removed and must NOT create a phantom map entry.
// The matrix de-scoped the 'advisory' claim: keep the falsifiable core only.
// [neg: Retain=False for an untracked branch must not fire removed / create an entry]
// =============================================================================================
// @verifies CL-AC-006
// @relation(CL-AC-006, scope=function)
TEST_F(ClientAlarmTracker, UnknownBranchRetainFalseDropsSilently)
{
  install_observers();

  const ua::NodeId unknownConditionId{2, 9999U};
  ConditionFields ghost;
  ghost.conditionId = unknownConditionId;
  ghost.branchId = ua::NodeId{2, std::string{"ghost-branch"}};
  ghost.retain = false;  // untracked -> must drop silently
  post_event(ghost);

  // Sentinel: a later real add proves the tracker's strand has fully processed the ghost event (strand
  // FIFO), so any (wrongly-fired) removed observer post would already be enqueued by now.
  ConditionFields sentinel;
  sentinel.conditionId = mConditionId;
  sentinel.eventId = mEventId;
  post_event(sentinel);
  ASSERT_TRUE(poll_until([&] { return mLog.added_count() == 1; }));

  EXPECT_EQ(mLog.removed_count(), 0) << "Retain=False for an untracked key must not fire removed";
  EXPECT_EQ(tracked_count(), 1U) << "only the sentinel - no phantom entry for the untracked key";
  EXPECT_EQ(get_condition(make_key(unknownConditionId, ua::NodeId{2, std::string{"ghost-branch"}}))
              .status_code()
              .as_uint32(),
    StatusCode{Status::BadNodeIdUnknown}.as_uint32())
    << "the untracked key must remain absent";
}

// =============================================================================================
// Row 5 - TrunkUpdateDoesNotRemoveBranch  (section 8.8.2, CL-AC-002)
// With a trunk+branch pair tracked, a further trunk transition (an update to BranchId=NULL only)
// must leave the live prior-state branch entry present AND unmodified.
// [neg: a shared key would evict or mutate the branch on a trunk update]
// =============================================================================================
// @verifies CL-AC-002
// @relation(CL-AC-002, scope=function)
TEST_F(ClientAlarmTracker, TrunkUpdateDoesNotRemoveBranch)
{
  install_observers();

  const ua::NodeId branchId{2, std::string{"branch-1"}};
  const ua::ByteString branchEventId{0x02};

  ConditionFields trunk;
  trunk.conditionId = mConditionId;
  trunk.eventId = ua::ByteString{0x01};
  trunk.active = true;
  post_event(trunk);

  ConditionFields branch;
  branch.conditionId = mConditionId;
  branch.branchId = branchId;
  branch.eventId = branchEventId;
  branch.active = false;
  post_event(branch);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 2; }));

  // A further trunk transition (same trunk key, a changed field, a new EventId).
  ConditionFields trunkUpdate = trunk;
  trunkUpdate.eventId = ua::ByteString{0x03};
  trunkUpdate.active = false;
  post_event(trunkUpdate);
  ASSERT_TRUE(poll_until([&] { return mLog.changed_count() == 1; }))
    << "the trunk update must be delivered as a change on the trunk key";

  EXPECT_EQ(tracked_count(), 2U) << "the trunk update must not evict the branch";
  const auto branchAfter = get_condition(make_key(mConditionId, branchId));
  ASSERT_TRUE(branchAfter.is_good()) << "the live prior-state branch must still be present";
  EXPECT_EQ(branchAfter.value().lastEventId, branchEventId)
    << "the branch entry must be unmodified by the trunk update";
  ASSERT_TRUE(branchAfter.value().activeState.has_value());
  EXPECT_EQ(branchAfter.value().activeState->id, false) << "the branch's own sub-state must be intact";
}

// =============================================================================================
// Row 6 - NonBranchableConditionNoSynthesisedBranchId  (section 8.8.2, CL-AC-002)
// Driving several transitions on a condition delivered with no BranchId must never fabricate a
// non-NULL BranchId: every tracked entry keeps BranchId=NULL and there is a single trunk entry.
// [neg: the tracker must not synthesise phantom (ConditionId,fakeBranch) entries]
// =============================================================================================
// @verifies CL-AC-002
// @relation(CL-AC-002, scope=function)
TEST_F(ClientAlarmTracker, NonBranchableConditionNoSynthesisedBranchId)
{
  install_observers();

  // Three transitions on the one condition (branchId always NULL) - on a branchable type an unacked
  // transition would spawn a prior-state branch; here none must appear.
  ConditionFields transition;
  transition.conditionId = mConditionId;
  transition.eventId = mEventId;

  transition.active = true;
  transition.acked = false;
  post_event(transition);
  ASSERT_TRUE(poll_until([&] { return mLog.added_count() == 1; }));

  transition.active = false;
  post_event(transition);
  transition.acked = true;
  post_event(transition);
  ASSERT_TRUE(poll_until([&] { return mLog.changed_count() == 2; }));

  EXPECT_EQ(tracked_count(), 1U) << "transitions on a non-branchable condition are updates to one entry";
  const auto conditions = list_conditions();
  ASSERT_EQ(conditions.size(), 1U);
  for (const auto& condition : conditions)
  {
    EXPECT_TRUE(condition.key.branchId.is_null())
      << "the tracker must not synthesise a non-NULL BranchId for a non-branchable condition";
  }
}

// Extract the set of OfType type ids from an EventFilter's WhereClause (mirrors the subscriber's own
// extract_of_types). An OfType element (subtype-inclusive) is FilterOperator::OfType over a LiteralOperand
// whose value is the type NodeId - as opposed to a literal Equals, which would exclude subtypes.
std::vector<ua::NodeId> of_type_ids(const ua::EventFilter& filter)
{
  std::vector<ua::NodeId> types;
  for (const auto& element : filter.where_clause().elements())
  {
    if (element.filter_operator() != ua::FilterOperator::OfType || element.filter_operands().empty())
    {
      continue;
    }
    const auto* literal = dynamic_cast<const ua::LiteralOperand*>(element.filter_operands()[0].get());
    if (literal == nullptr)
    {
      continue;
    }
    if (const auto asNode = literal->value().to<ua::NodeId>(); asNode.is_good())
    {
      types.push_back(asNode.value());
    }
  }
  return types;
}

// =============================================================================================
// Row 7 - RoutesAlarmSubtypeEvents  (section 8.8.5, CL-AC-015)
// An ExclusiveLimitAlarmType event is recognised as an alarm (its AlarmConditionType sub-states are
// surfaced) via EventType inspection, not treated as a bare ConditionType.
// [neg: absent subtype routing -> alarm fields missing]
// =============================================================================================
// @verifies CL-AC-015
// @relation(CL-AC-015, scope=function)
TEST_F(ClientAlarmTracker, RoutesAlarmSubtypeEvents)
{
  ConditionFields alarm;
  alarm.conditionId = mConditionId;
  alarm.eventId = mEventId;
  alarm.eventTypeId = ua::NodeId{ua::ObjectTypeId::ExclusiveLimitAlarmType};
  alarm.active = true;  // an AlarmConditionType sub-state
  post_event(alarm);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  const auto tracked = get_condition(make_key(mConditionId));
  ASSERT_TRUE(tracked.is_good());
  EXPECT_EQ(tracked.value().conditionTypeId, ua::NodeId{ua::ObjectTypeId::ExclusiveLimitAlarmType})
    << "the most-derived EventType must be surfaced for subtype routing";
  ASSERT_TRUE(tracked.value().activeState.has_value())
    << "the alarm's ActiveState sub-state must be surfaced (not dropped as a bare ConditionType)";
  EXPECT_EQ(tracked.value().activeState->id, true);
}

// =============================================================================================
// Row 8 - ConditionSubClassesGroupedByEventType  (section 8.8.5, CL-AC-015/021)
// Two conditions of two different ConditionType sub-classes report two DISTINCT, exact EventType
// NodeIds; grouping by EventType yields two non-empty groups.
// [neg: a collapse-to-ConditionType regression would report one shared type / one group]
// =============================================================================================
// @verifies CL-AC-015
// @verifies CL-AC-021
// @relation(CL-AC-015, CL-AC-021, scope=function)
TEST_F(ClientAlarmTracker, ConditionSubClassesGroupedByEventType)
{
  const ua::NodeId alarmType{ua::ObjectTypeId::AlarmConditionType};
  const ua::NodeId dialogType{ua::ObjectTypeId::DialogConditionType};

  ConditionFields first;
  first.conditionId = ua::NodeId{2, 1001U};
  first.eventId = ua::ByteString{0x01};
  first.eventTypeId = alarmType;
  post_event(first);

  ConditionFields second;
  second.conditionId = ua::NodeId{2, 1002U};
  second.eventId = ua::ByteString{0x02};
  second.eventTypeId = dialogType;
  post_event(second);

  ASSERT_TRUE(poll_until([&] { return tracked_count() == 2; }));
  const auto conditions = list_conditions();
  ASSERT_EQ(conditions.size(), 2U);

  std::map<ua::NodeId, std::vector<TrackedCondition>> byEventType;
  for (const auto& condition : conditions)
  {
    byEventType[condition.conditionTypeId].push_back(condition);
  }
  EXPECT_EQ(byEventType.size(), 2U) << "two distinct sub-class EventTypes must form two groups";
  ASSERT_EQ(byEventType.count(alarmType), 1U) << "the AlarmConditionType sub-class must be reported exactly";
  ASSERT_EQ(byEventType.count(dialogType), 1U)
    << "the DialogConditionType sub-class must be reported exactly";
  EXPECT_EQ(byEventType[alarmType].size(), 1U);
  EXPECT_EQ(byEventType[dialogType].size(), 1U);
}

// =============================================================================================
// Row 8b - AlarmSubtypePropertiesAreTyped  (section 8.8.5, CL-AC-021)
// The public tier-2 tracker surfaces OffNormal-family and Discrepancy properties in a typed union.
// [neg: EventType-only grouping with subtype properties silently dropped]
// =============================================================================================
// @verifies CL-AC-021
// @relation(CL-AC-021, scope=function)
TEST_F(ClientAlarmTracker, AlarmSubtypePropertiesAreTyped)
{
  const ua::NodeId normalState{2, 8101U};
  ConditionFields trip;
  trip.conditionId = ua::NodeId{2, 8100U};
  trip.eventId = ua::ByteString{0x81};
  trip.eventTypeId = ua::NodeId{ua::ObjectTypeId::TripAlarmType};
  trip.normalState = normalState;
  post_event(trip);

  const ua::NodeId targetValue{2, 8201U};
  ConditionFields discrepancy;
  discrepancy.conditionId = ua::NodeId{2, 8200U};
  discrepancy.eventId = ua::ByteString{0x82};
  discrepancy.eventTypeId = ua::NodeId{ua::ObjectTypeId::DiscrepancyAlarmType};
  discrepancy.targetValueNode = targetValue;
  discrepancy.expectedTime = ua::Duration{5000.0};
  discrepancy.tolerance = 0.25;
  post_event(discrepancy);

  ConditionFields discrete;
  discrete.conditionId = ua::NodeId{2, 8300U};
  discrete.eventId = ua::ByteString{0x83};
  discrete.eventTypeId = ua::NodeId{ua::ObjectTypeId::DiscreteAlarmType};
  post_event(discrete);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 3; }));

  const auto tripResult = get_condition(make_key(trip.conditionId));
  ASSERT_TRUE(tripResult.is_good());
  const auto* tripInfo = std::get_if<ua::client::OffNormalAlarmInfo>(&tripResult.value().subtypeInfo);
  ASSERT_NE(tripInfo, nullptr) << "Trip must inherit the typed OffNormal payload";
  EXPECT_EQ(tripInfo->normalState, normalState);

  const auto discrepancyResult = get_condition(make_key(discrepancy.conditionId));
  ASSERT_TRUE(discrepancyResult.is_good());
  const auto* discrepancyInfo =
    std::get_if<ua::client::DiscrepancyAlarmInfo>(&discrepancyResult.value().subtypeInfo);
  ASSERT_NE(discrepancyInfo, nullptr);
  EXPECT_EQ(discrepancyInfo->targetValueNode, targetValue);
  EXPECT_EQ(discrepancyInfo->expectedTime, ua::Duration{5000.0});
  EXPECT_EQ(discrepancyInfo->tolerance, 0.25);

  const auto discreteResult = get_condition(make_key(discrete.conditionId));
  ASSERT_TRUE(discreteResult.is_good());
  EXPECT_TRUE(std::holds_alternative<ua::client::DiscreteAlarmInfo>(discreteResult.value().subtypeInfo));
}

// @verifies CL-AC-022
// @relation(CL-AC-022, scope=function)
TEST_F(ClientAlarmTracker, OptionalAlarmPropertiesSurfaceAndMutateThroughPublicTracker)
{
  install_observers();
  ConditionFields alarm;
  alarm.conditionId = ua::NodeId{2, 8400U};
  alarm.eventId = ua::ByteString{0x84};
  alarm.eventTypeId = ua::NodeId{ua::ObjectTypeId::AlarmConditionType};
  alarm.reAlarmTime = ua::Duration{30000.0};
  alarm.reAlarmRepeatCount = std::int16_t{2};
  alarm.onDelay = ua::Duration{2000.0};
  alarm.offDelay = ua::Duration{5000.0};
  alarm.audibleEnabled = true;
  alarm.audibleSound = ua::AudioDataType{0x10, 0x20};
  alarm.firstInGroupFlag = true;
  alarm.firstInGroup = ua::NodeId{2, 8401U};
  post_event(alarm);
  ASSERT_TRUE(poll_until([&] { return mLog.added_count() == 1; }));

  auto initial = get_condition(make_key(alarm.conditionId));
  ASSERT_TRUE(initial.is_good());
  EXPECT_EQ(initial.value().reAlarmTime, alarm.reAlarmTime);
  EXPECT_EQ(initial.value().reAlarmRepeatCount, alarm.reAlarmRepeatCount);
  EXPECT_EQ(initial.value().audibleSound, alarm.audibleSound);
  EXPECT_EQ(initial.value().firstInGroup, alarm.firstInGroup);

  alarm.eventId = ua::ByteString{0x85};
  alarm.onDelay = ua::Duration{3500.0};
  alarm.offDelay = ua::Duration{7500.0};
  post_event(alarm);
  ASSERT_TRUE(poll_until([&] { return mLog.changed_count() == 1; }));
  std::lock_guard lock(mLog.mutex);
  ASSERT_EQ(mLog.changedConditions.size(), 1U);
  EXPECT_EQ(mLog.changedConditions[0].onDelay, alarm.onDelay);
  EXPECT_EQ(mLog.changedConditions[0].offDelay, alarm.offDelay);
}

// @verifies CL-AC-026
// @relation(CL-AC-026, scope=function)
TEST_F(ClientAlarmTracker, AlarmMetricsViewReadsAndResets)
{
  mWire->translateHandler = [](const ua::TranslateBrowsePathsToNodeIdsRequest& request)
  {
    ua::TranslateBrowsePathsToNodeIdsResponse response;
    for (std::size_t index = 0; index < request.browse_paths().size(); ++index)
    {
      ua::BrowsePathResult result;
      result.status_code() = ua::StatusCode{ua::Status::Good};
      ua::BrowsePathTarget target;
      target.target_id() = ua::ExpandedNodeId{ua::NodeId{static_cast<std::uint32_t>(9100U + index)}};
      result.targets().push_back(std::move(target));
      response.results().push_back(std::move(result));
    }
    return response;
  };
  const ua::DateTime start{2026, 7, 24, 13, 0, 0.0};
  ua::ReadResponse response;
  for (ua::Variant value : {ua::Variant{std::uint32_t{12}},
         ua::Variant{start},
         ua::Variant{ua::Duration{1000.0}},
         ua::Variant{ua::Duration{2000.0}},
         ua::Variant{1.5},
         ua::Variant{4.5},
         ua::Variant{std::uint32_t{3}},
         ua::Variant{2.5},
         ua::Variant{std::uint16_t{5}},
         ua::Variant{std::uint16_t{10}},
         ua::Variant{std::uint16_t{30}}})
  {
    response.results().push_back(ua::DataValue{std::move(value)});
  }
  mWire->scriptedReadResponses.push_back(Result<ua::ReadResponse>{std::move(response)});

  const ua::NodeId metricsObject{2, 9000U};
  auto view = mTracker->alarm_metrics(metricsObject);
  std::promise<Result<ua::client::AlarmMetricsSnapshot>> readPromise;
  auto readFuture = readPromise.get_future();
  view.read_all_async([&readPromise](Result<ua::client::AlarmMetricsSnapshot> result)
    { readPromise.set_value(std::move(result)); });
  ASSERT_EQ(readFuture.wait_for(5s), std::future_status::ready);
  const auto metricsResult = readFuture.get();
  ASSERT_TRUE(metricsResult.is_good());
  EXPECT_EQ(metricsResult.value().alarmCount, 12U);
  EXPECT_EQ(metricsResult.value().startTime, start);
  EXPECT_DOUBLE_EQ(metricsResult.value().currentAlarmRate.value, 1.5);
  EXPECT_EQ(metricsResult.value().currentAlarmRate.rateMinutes, 5U);
  EXPECT_DOUBLE_EQ(metricsResult.value().maximumAlarmRate.value, 4.5);
  EXPECT_EQ(metricsResult.value().maximumAlarmRate.rateMinutes, 10U);
  EXPECT_DOUBLE_EQ(metricsResult.value().averageAlarmRate.value, 2.5);
  EXPECT_EQ(metricsResult.value().averageAlarmRate.rateMinutes, 30U);

  std::promise<VoidResult> resetPromise;
  auto resetFuture = resetPromise.get_future();
  view.reset_async([&resetPromise](VoidResult result) { resetPromise.set_value(std::move(result)); });
  ASSERT_EQ(resetFuture.wait_for(5s), std::future_status::ready);
  EXPECT_TRUE(resetFuture.get().is_good());
  ASSERT_EQ(mWire->callRequests.size(), 1U);
  EXPECT_EQ(mWire->callRequests[0].methods_to_call()[0].object_id(), metricsObject);
  EXPECT_EQ(mWire->callRequests[0].methods_to_call()[0].method_id(), ua::NodeId{9100U});
}

// =============================================================================================
// Row 9 - EventFilterUsesOfTypeConditionType  (section 8.8.5, CL-AC-015)
// The composite EventFilter the tracker contributes to the backbone MonitoredItem carries an
// OfType(ConditionType) WhereClause - so subtype events (AlarmConditionType, ExclusiveLimitAlarmType)
// pass. A literal ConditionType-equality WhereClause would filter every subtype out.
// [neg: literal equality on ConditionType instead of OfType]
// =============================================================================================
// @verifies CL-AC-015
// @relation(CL-AC-015, scope=function)
TEST_F(ClientAlarmTracker, EventFilterUsesOfTypeConditionType)
{
  // The tracker attached + created its backbone during SetUp; capture the composite filter it sent.
  const auto filter = mBackbone->first_create_filter();
  ASSERT_TRUE(filter.has_value()) << "the tracker must create an event backbone with a composite filter";

  const auto types = of_type_ids(*filter);
  EXPECT_THAT(types, ::testing::Contains(ua::NodeId{ua::ObjectTypeId::ConditionType}))
    << "the WhereClause must admit ConditionType via OfType (subtype-inclusive), not literal equality";

  // The SelectClause carries the base + limit-alarm fields in their SPEC-SHAPED form (Slice AC1): real leaf
  // data (whose node Value IS the datum) as single-segment by-BrowseName operands; each TwoStateVariable's
  // Boolean at the two-segment path [<State>, "Id"] (the single-segment node is the display-name
  // LocalizedText, not the Boolean); the ExclusiveLimit CurrentState at [LimitState, CurrentState]; and the
  // ConditionId via the empty-browse-path NodeId operand (CL-AC-002).
  const auto hasClause = [&filter](const std::vector<std::string_view>& browsePath, ua::AttributeId attr)
  {
    for (const auto& clause : filter->select_clauses())
    {
      if (clause.browse_path().size() != browsePath.size() ||
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
  };

  // CL-AC-002: the ConditionId via the empty-path NodeId operand.
  EXPECT_TRUE(hasClause({}, ua::AttributeId::NodeId)) << "ConditionId (empty path, attributeId NodeId)";

  // Real leaf data - single-segment Value operands.
  for (const std::string_view leaf :
    {"BranchId", "Retain", "HighHighLimit", "HighLimit", "LowLimit", "LowLowLimit"})
  {
    EXPECT_TRUE(hasClause({leaf}, ua::AttributeId::Value)) << "missing single-segment leaf clause " << leaf;
  }

  // CL-AC-024/025: each TwoStateVariable Boolean at [<State>, "Id"].
  for (const std::string_view state :
    {"ActiveState", "AckedState", "HighHighState", "HighState", "LowState", "LowLowState"})
  {
    EXPECT_TRUE(hasClause({state, "Id"}, ua::AttributeId::Value))
      << "missing two-segment [" << state << ", Id] clause";
  }

  // CL-AC-024: the ExclusiveLimit CurrentState.
  EXPECT_TRUE(hasClause({"LimitState", "CurrentState"}, ua::AttributeId::Value));

  // Regression guard: the states are NOT requested as single-segment display-name clauses (the pre-slice
  // bug).
  EXPECT_FALSE(hasClause({"AckedState"}, ua::AttributeId::Value))
    << "AckedState must be requested at [AckedState, Id], not single-segment";
}

// =============================================================================================
// Row 10 - ExposesFullAlarmSubStateVector  (section 8.8.2, CL-AC-016)
// An AlarmConditionType event surfaces its FULL modelled sub-state vector - not just EnabledState+
// ActiveState. Slice AC2 models the remaining AlarmConditionType sub-states (SuppressedState,
// OutOfServiceState, SilenceState, LatchedState, the aggregate SuppressedOrShelved, and
// ShelvingState.CurrentState), so this row drives all of them through the real tracker (spec-shaped
// two-segment [<State>, "Id"] Booleans + single-segment SuppressedOrShelved + two-segment
// ShelvingState/CurrentState) and asserts each is surfaced.
// [neg: only Enabled/Acked/Confirmed/Active modelled -> the suppressed/shelving fields are absent]
// =============================================================================================
// @verifies CL-AC-016
// @relation(CL-AC-016, scope=function)
TEST_F(ClientAlarmTracker, ExposesFullAlarmSubStateVector)
{
  ConditionFields alarm;
  alarm.conditionId = mConditionId;
  alarm.eventId = mEventId;
  alarm.eventTypeId = ua::NodeId{ua::ObjectTypeId::AlarmConditionType};
  alarm.active = true;
  alarm.acked = false;
  alarm.suppressed = true;
  alarm.outOfService = false;
  alarm.silence = true;
  alarm.latched = false;
  alarm.suppressedOrShelved = true;
  alarm.shelvingState = ua::LocalizedText{"", "OneShotShelved"};
  post_event(alarm);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  const auto tracked = get_condition(make_key(mConditionId));
  ASSERT_TRUE(tracked.is_good());
  const TrackedCondition& tc = tracked.value();
  ASSERT_TRUE(tc.activeState.has_value()) << "ActiveState must be surfaced";
  EXPECT_EQ(tc.activeState->id, true);
  ASSERT_TRUE(tc.ackedState.has_value())
    << "AckedState must be surfaced too - not only EnabledState+ActiveState";
  EXPECT_EQ(tc.ackedState->id, false);
  // CL-AC-016 remaining sub-states, decoded through the real two-segment/aggregate wire shape.
  ASSERT_TRUE(tc.suppressedState.has_value()) << "SuppressedState must be surfaced";
  EXPECT_EQ(tc.suppressedState->id, true);
  ASSERT_TRUE(tc.outOfServiceState.has_value());
  EXPECT_EQ(tc.outOfServiceState->id, false);
  ASSERT_TRUE(tc.silenceState.has_value());
  EXPECT_EQ(tc.silenceState->id, true);
  ASSERT_TRUE(tc.latchedState.has_value());
  EXPECT_EQ(tc.latchedState->id, false);
  ASSERT_TRUE(tc.suppressedOrShelved.has_value()) << "the aggregate SuppressedOrShelved must be surfaced";
  EXPECT_EQ(*tc.suppressedOrShelved, true);
  ASSERT_TRUE(tc.shelvingState.has_value()) << "ShelvingState.CurrentState must be surfaced";
  EXPECT_EQ(*tc.shelvingState, (ua::LocalizedText{"", "OneShotShelved"}));
}

// =============================================================================================
// Row 11 - MissingOptionalSubStatesAreNullopt  (section 8.8.2, CL-AC-016)
// An AlarmConditionType event that omits an optional sub-state surfaces that sub-state as nullopt -
// distinct from a present `false` - so a consumer can tell 'not supported' from 'not set'. Slice AC2
// models the SuppressedState optional, so this row protects the absent-!=-False rule on the very
// CL-AC-016 sub-state the oracle names (an omitted SuppressedState -> nullopt; a present false -> Some).
// [neg: an absent optional sub-state coerced to False]
// =============================================================================================
// @verifies CL-AC-016
// @relation(CL-AC-016, scope=function)
TEST_F(ClientAlarmTracker, MissingOptionalSubStatesAreNullopt)
{
  // Event A: AlarmConditionType with NO SuppressedState field.
  ConditionFields omitted;
  omitted.conditionId = ua::NodeId{2, 2001U};
  omitted.eventId = ua::ByteString{0x01};
  omitted.eventTypeId = ua::NodeId{ua::ObjectTypeId::AlarmConditionType};
  omitted.active = true;  // present optional, so we know decode ran
  post_event(omitted);

  // Event B: same type but SuppressedState explicitly false.
  ConditionFields presentFalse;
  presentFalse.conditionId = ua::NodeId{2, 2002U};
  presentFalse.eventId = ua::ByteString{0x02};
  presentFalse.eventTypeId = ua::NodeId{ua::ObjectTypeId::AlarmConditionType};
  presentFalse.suppressed = false;
  post_event(presentFalse);

  ASSERT_TRUE(poll_until([&] { return tracked_count() == 2; }));

  const auto absent = get_condition(make_key(ua::NodeId{2, 2001U}));
  ASSERT_TRUE(absent.is_good());
  ASSERT_TRUE(absent.value().activeState.has_value()) << "decode ran (ActiveState present)";
  EXPECT_FALSE(absent.value().suppressedState.has_value())
    << "an omitted optional sub-state must be nullopt, not coerced to False";
  EXPECT_FALSE(absent.value().suppressedOrShelved.has_value());
  EXPECT_FALSE(absent.value().shelvingState.has_value());

  const auto present = get_condition(make_key(ua::NodeId{2, 2002U}));
  ASSERT_TRUE(present.is_good());
  ASSERT_TRUE(present.value().suppressedState.has_value())
    << "a present SuppressedState=false must be Some(false)";
  EXPECT_EQ(present.value().suppressedState->id, false)
    << "nullopt (absent) and Some(false) (present-false) must be distinguishable";
}

// =============================================================================================
// Row 12 - ExposesConditionClassIdAndName  (section 8.8.2, CL-AC-014)
// A tracked condition surfaces both mandatory ConditionType class properties, and on_condition_added
// carries them unchanged. [neg: identity metadata dropped from the SelectClause -> not surfaced]
// =============================================================================================
// @verifies CL-AC-014
// @relation(CL-AC-014, scope=function)
TEST_F(ClientAlarmTracker, ExposesConditionClassIdAndName)
{
  install_observers();

  ConditionFields condition;
  condition.conditionId = mConditionId;
  condition.eventId = mEventId;
  condition.eventTypeId = ua::NodeId{ua::ObjectTypeId::AlarmConditionType};
  condition.conditionName = ua::LocalizedText{"", "TankLevelHigh"};
  condition.conditionClassId = ua::NodeId{ua::ObjectTypeId::ProcessConditionClassType};
  condition.conditionClassName = ua::LocalizedText{"en", "Process"};
  post_event(condition);

  ASSERT_TRUE(poll_until([&] { return mLog.added_count() == 1; }));
  std::lock_guard lock(mLog.mutex);
  ASSERT_EQ(mLog.addedConditions.size(), 1U);
  const auto& added = mLog.addedConditions.front();
  EXPECT_EQ(added.conditionName.text(), "TankLevelHigh")
    << "on_condition_added must carry the condition's identifying name";
  EXPECT_EQ(added.conditionTypeId, ua::NodeId{ua::ObjectTypeId::AlarmConditionType})
    << "on_condition_added must carry the condition's most-derived EventType";
  EXPECT_EQ(added.conditionClassId, condition.conditionClassId)
    << "on_condition_added must carry the mandatory ConditionClassId";
  EXPECT_EQ(added.conditionClassName, condition.conditionClassName)
    << "on_condition_added must carry the mandatory ConditionClassName";
}

// =============================================================================================
// Row 13 - ColdFailoverClearsTrackedConditions  (section 8.8.3, CL-AC-013/002)
// On a cold/warm redundancy switch the tracked set + open refresh windows must be flushed before the
// post-failover refresh repopulates them (no cross-server EventId carryover).
// [neg: cross-server state must be flushed on cold/warm switch]
//
// BLOCKED on the redundancy/reconnect harness: a cross-server cold/warm RedundancySwitch cannot be
// driven by this single-shot fixture (no MisbehavingServer redundancy role exists yet). This row pins
// the VERIFIED client-observable analog of the flush: the tracker's close path (the same operation a
// session-change/failover recovery invokes) clears mTrackedConditions + mActiveRefreshWindows. The
// full cross-server EventId-carryover assertion is reported as blocked on the redundancy harness.
// =============================================================================================
// @verifies CL-AC-013
// @relation(CL-AC-013, scope=function)
TEST_F(ClientAlarmTracker, ColdFailoverClearsTrackedConditions)
{
  ConditionFields first;
  first.conditionId = ua::NodeId{2, 3001U};
  first.eventId = ua::ByteString{0x01};
  post_event(first);

  ConditionFields second;
  second.conditionId = ua::NodeId{2, 3002U};
  second.eventId = ua::ByteString{0x02};
  post_event(second);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 2; }));

  // The flush (invoked by the failover recovery path): the tracked set is cleared.
  std::promise<VoidResult> closed;
  auto closedFuture = closed.get_future();
  mImpl->close_async([&closed](VoidResult result) { closed.set_value(std::move(result)); });
  ASSERT_EQ(closedFuture.wait_for(5s), std::future_status::ready);

  EXPECT_EQ(tracked_count(), 0U) << "the flush must clear every tracked condition before repopulation";
  EXPECT_EQ(mImpl->info()->openRefreshWindowCount, 0U) << "open refresh windows must be flushed too";
}

}  // namespace
