// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientAlarmMethods cluster of the client integration-test matrix (the 30 `ClientAlarmMethods.*`
///        rows).
///
/// COMPANION: `client_alarm_live_server_tests.cpp` runs the same surface against a REAL server. These
/// rows keep what only an interface can hold - the wire ARGUMENTS a wrapper builds, server misbehaviour a
/// conforming server will not produce, and branches this server does not emit. What a live server can
/// decide is asserted there, because a fake agrees with whatever the client sends it.
///
/// These exercise the TIER-2 Alarm & Condition tracker's CONDITION-METHOD WRAPPERS
/// (`ua::client::AlarmConditionTracker` / `AlarmHandle` over the no-own-strand
/// `detail::AlarmConditionTrackerImpl`, client design section 8.8.6/section 8.8.7) as a LIVE component: a
/// REAL `EventSubscriberImpl` + tracker are built over the mockable event-backbone interface + a recording
/// `WireOps` on a REAL `boost::asio::thread_pool`. Each wrapper (acknowledge / confirm / add-comment /
/// enable / disable / silence / suppress / unsuppress / timed-shelve / one-shot-shelve / unshelve) is
/// invoked through the PUBLIC `AlarmConditionTracker` handle, and every method `Call` it emits is captured
/// by the recording wire interface so the ObjectId / MethodId / input-argument shape can be asserted exactly.
/// Condition state (needed for the short-circuit gates and the state-transition oracles) is driven by
/// feeding the tracker decoded `EventNotification`s through its on-strand hook (the
/// `AlarmConditionTrackerTestAccess` interface) exactly as the subscriber's Publish dispatch would.
///
/// Why the hook interface and not a real ComplianceWithConditions / MisbehavingServer / 2-client fixture:
/// identical to the three sibling clusters (`client_alarm_tracker_matrix_tests.cpp` /
/// `client_condition_refresh_matrix_tests.cpp` / `client_limit_alarm_matrix_tests.cpp`) - the interface gives
/// deterministic control over event CONTENT (the "other operator already acted" acked/confirmed state, the
/// MaxTimeShelved cap) while exercising the tracker's REAL decode/short-circuit/method-dispatch logic. Since
/// Slice AC1 the field extraction IS wired end-to-end: the events these rows feed carry the SPEC-SHAPED wire
/// form a real server emits - each TwoStateVariable Boolean at `[<State>, "Id"]` and the ConditionId via the
/// empty-browse-path NodeId operand - so the ack/confirm short-circuit (CL-AC-010) is reachable on the real
/// wire shape. The recording `WireOps` is the falsifiable oracle for what reached the wire. The matrix's
/// `MisbehavingServer` rejection rows (Bad_EventIdUnknown / Bad_NodeIdUnknown) are fabricated by scripting
/// the recording wire's per-method status; the `2-client` short-circuit rows drive the "other operator
/// already acted" state directly through the event interface (the local short-circuit depends only on the
/// tracked sub-state, so the observable is identical).
///
/// SCOPE / analog pinning (see the report accompanying this file for the full audit):
///  - The tracker resolves condition methods to the FIXED well-known base-type MethodId (e.g.
///    AcknowledgeableConditionType.Acknowledge) and calls with ObjectId = the ConditionId - spec-valid for
///    every standard condition method (OPC 10000-9). It has NO method-node cache, NO Browse-then-Call, and
///    NO per-type method resolution (the `AlarmConditionTrackerPolicy.methodCacheCapacity` knob is unused).
///    The two rows that assume that machinery (MethodCacheMissTriggersBrowseThenCall, ConfirmOnNon...) are
///    therefore pinned to the built observable analog and the browse/cache gap is REPORTED.
///  - `timed_shelve_async` now runs a MaxTimeShelved local pre-flight: when the event carried MaxTimeShelved
///    (tracked verbatim on TrackedCondition) and the requested ShelvingTime EXCEEDS it, the wrapper
///    short-circuits with Bad_ShelvingTimeOutOfRange and issues no Call (mirroring the ack/confirm
///    short-circuit on tracked state); an absent/unknown (or NaN) cap proceeds - the server stays the
///    authority. The rows below inject MaxTimeShelved via the event to exercise over/under/unknown.
///  - `place_in_service` / `remove_from_service` / `get_group_memberships` wrappers, and the comment-bearing
///    Suppress2/Unsuppress2 variants, DO NOT EXIST on the interface; the tracker also models no SilencedState
///    / SuppressedState / ShelvingState / OutOfServiceState / Comment sub-state. Rows 27-30 are pinned to the
///    built analog (the wrapper that DOES exist, or the identity surface) and the wrapper gaps are REPORTED.
///
/// Timing: every wait is BOUNDED POLLING on a thread-safe observable (never a fixed sleep). A method
/// wrapper's completion is bridged off the executor callback via a promise; because the recording wire
/// records the request synchronously before firing the completion, reading the captured Call after the
/// completion is race-free. Because the tracker's strand is FIFO, a `get_condition` round-trip posted after
/// an event guarantees that event's on-strand handler has fully run. All fakes are thread-safe.

#include "fake_connection_ops.h"
#include "test_utilities.h"

#include "ua_alarm_condition_tracker.h"
#include "ua_alarm_condition_tracker_impl.h"
#include "ua_alarm_condition_tracker_test_access.h"
#include "ua_event_backbone_ops.h"
#include "ua_event_subscriber_impl.h"

#include "ua_byte_string.h"
#include "ua_call_method_request.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_content_filter_element.h"
#include "ua_error_detail.h"
#include "ua_event_filter.h"
#include "ua_filter_operator.h"
#include "ua_literal_operand.h"
#include "ua_localized_text.h"
#include "ua_logger.h"
#include "ua_method_id.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

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
#include <utility>
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

// Well-known MethodId NodeIds the tracker targets (numeric NodeId in namespace 0 - the tracker builds them
// as `ua::NodeId{static_cast<uint32_t>(MethodId::...)}`).
ua::NodeId method_node(ua::MethodId id)
{
  return ua::NodeId{static_cast<std::uint32_t>(id)};
}

const ua::NodeId acknowledgeMethod = method_node(ua::MethodId::AcknowledgeableConditionType_Acknowledge);
const ua::NodeId confirmMethod = method_node(ua::MethodId::AcknowledgeableConditionType_Confirm);
const ua::NodeId addCommentMethod = method_node(ua::MethodId::ConditionType_AddComment);
const ua::NodeId enableMethodId = method_node(ua::MethodId::ConditionType_Enable);
const ua::NodeId disableMethodId = method_node(ua::MethodId::ConditionType_Disable);
const ua::NodeId silenceMethod = method_node(ua::MethodId::AlarmConditionType_Silence);
const ua::NodeId suppressMethodId = method_node(ua::MethodId::AlarmConditionType_Suppress);
const ua::NodeId unsuppressMethodId = method_node(ua::MethodId::AlarmConditionType_Unsuppress);
const ua::NodeId timedShelveMethod = method_node(ua::MethodId::ShelvedStateMachineType_TimedShelve);
const ua::NodeId oneShotShelveMethod = method_node(ua::MethodId::ShelvedStateMachineType_OneShotShelve);
const ua::NodeId unshelveMethodId = method_node(ua::MethodId::ShelvedStateMachineType_Unshelve);

// Type-node NodeIds an ObjectId must NEVER be (the ObjectId is always the ConditionId).
const ua::NodeId ackTypeNode{ua::ObjectTypeId::AcknowledgeableConditionType};
const ua::NodeId conditionTypeNode{ua::ObjectTypeId::ConditionType};
const ua::NodeId alarmTypeNode{ua::ObjectTypeId::AlarmConditionType};
const ua::NodeId shelvedStateMachineTypeNode{ua::ObjectTypeId::ShelvedStateMachineType};

// ---------------------------------------------------------------------------------------------
// Thread-safe event-backbone interface: replies Good so the tracker attaches + creates its default Server
// backbone (this cluster does not assert the composite filter - that is the ClientAlarmTracker slice).
// ---------------------------------------------------------------------------------------------
class RecordingBackboneOps : public EventBackboneOps
{
public:
  void create_backbone_async(ua::NodeId notifier, ua::EventFilter filter, std::uint32_t /*clientHandle*/,
    std::uint32_t /*queueSize*/, std::function<void(Result<EventBackboneCreated>)> callback) noexcept override
  {
    EventBackboneCreated created;
    created.subscriptionId = mNextSubscriptionId++;
    created.monitoredItemId = mNextMonitoredItemId++;
    {
      // Record the notifier node, the COMPOSITE EventFilter the REAL subscriber computed, and the
      // SubscriptionId handed back for this backbone. The fake only records: every value asserted on below
      // is produced by the production subscriber/tracker, never by this interface.
      std::lock_guard lock(mMutex);
      mNotifiers.push_back(std::move(notifier));
      mFilters.push_back(std::move(filter));
      if (mFilters.size() == 1)
      {
        mFirstSubscriptionId = created.subscriptionId;
      }
    }
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

  // The notifier node the FIRST backbone MonitoredItem was created on (CL-AC-001).
  std::optional<ua::NodeId> first_create_notifier() const
  {
    std::lock_guard lock(mMutex);
    if (mNotifiers.empty())
    {
      return std::nullopt;
    }
    return mNotifiers.front();
  }

  // The composite EventFilter sent with the FIRST create (CL-AC-008).
  std::optional<ua::EventFilter> first_create_filter() const
  {
    std::lock_guard lock(mMutex);
    if (mFilters.empty())
    {
      return std::nullopt;
    }
    return mFilters.front();
  }

  // The SubscriptionId this interface handed back for the first backbone - the one a ConditionRefresh must be
  // scoped to.
  std::uint32_t first_subscription_id() const
  {
    std::lock_guard lock(mMutex);
    return mFirstSubscriptionId;
  }

private:
  mutable std::mutex mMutex;
  std::vector<ua::NodeId> mNotifiers;
  std::vector<ua::EventFilter> mFilters;
  std::uint32_t mFirstSubscriptionId{0};
  std::atomic<std::uint32_t> mNextSubscriptionId{100};
  std::atomic<std::uint32_t> mNextMonitoredItemId{500};
  std::atomic<std::size_t> mCreateCount{0};
};

// ---------------------------------------------------------------------------------------------
// Thread-safe recording WireOps: captures every condition-method Call (ObjectId / MethodId / inputs) so a
// test can assert exactly what reached the wire, and answers each with a per-method scriptable status
// (default Good). Runs on the tracker's pool threads, so all state is mutex-guarded.
// ---------------------------------------------------------------------------------------------
class RecordingMethodWireOps : public ua::test_helpers::FakeWireOps
{
public:
  // Sets (replacing any prior entry) the per-method CallMethodResult status a subsequent Call to @p methodId
  // is answered with. This is how the MisbehavingServer rejection rows fabricate a server-side Bad.
  void set_method_status(const ua::NodeId& methodId, ua::StatusCode status)
  {
    std::lock_guard lock(mMutex);
    for (auto& entry : mMethodStatus)
    {
      if (entry.first == methodId)
      {
        entry.second = status;
        return;
      }
    }
    mMethodStatus.push_back({methodId, status});
  }

  void call_async(
    ua::CallRequest request, std::function<void(Result<ua::CallResponse>)> callback) noexcept override
  {
    ua::StatusCode perMethod{ua::Status::Good};
    {
      std::lock_guard lock(mMutex);
      mCalls.push_back(request);
      if (!request.methods_to_call().empty())
      {
        const ua::NodeId& methodId = request.methods_to_call()[0].method_id();
        for (const auto& entry : mMethodStatus)
        {
          if (entry.first == methodId)
          {
            perMethod = entry.second;
            break;
          }
        }
      }
    }
    ua::CallResponse response;
    ua::CallMethodResult result;
    result.status_code() = perMethod;
    response.results().push_back(std::move(result));
    callback(Result<ua::CallResponse>{std::move(response)});
  }

  std::size_t total_call_count() const
  {
    std::lock_guard lock(mMutex);
    return mCalls.size();
  }

  std::size_t call_count_to(const ua::NodeId& methodId) const
  {
    std::lock_guard lock(mMutex);
    std::size_t count = 0;
    for (const auto& call : mCalls)
    {
      if (!call.methods_to_call().empty() && call.methods_to_call()[0].method_id() == methodId)
      {
        ++count;
      }
    }
    return count;
  }

  std::optional<ua::CallMethodRequest> nth_method(std::size_t index) const
  {
    std::lock_guard lock(mMutex);
    if (index >= mCalls.size() || mCalls[index].methods_to_call().empty())
    {
      return std::nullopt;
    }
    return mCalls[index].methods_to_call()[0];
  }

private:
  mutable std::mutex mMutex;
  std::vector<ua::CallRequest> mCalls;
  std::vector<std::pair<ua::NodeId, ua::StatusCode>> mMethodStatus;
};

// ---------------------------------------------------------------------------------------------
// Condition-event builder - the by-name field model the tracker's decode reads. `eventTypeId` selects the
// most-derived EventType; an omitted optional leaves the field ABSENT (so the tracker surfaces the sub-state
// as nullopt, distinct from a present `false`).
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
  ua::NodeId eventTypeId{ua::ObjectTypeId::AlarmConditionType};
  std::optional<bool> enabled;
  std::optional<bool> acked;
  std::optional<bool> confirmed;
  std::optional<bool> active;
  std::optional<double> maxTimeShelved;  // milliseconds; drives the timed_shelve_async local pre-flight
  std::optional<ua::LocalizedText> shelvingState;  ///< ShelvingState.CurrentState (CL-AC-016)
};

// A single-segment leaf field (the node's Value: BranchId, Retain, MaxTimeShelved).
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

// A two-segment [parent, child] field (e.g. [ShelvingState, CurrentState]) carrying an arbitrary Variant.
void add_two_segment_field(
  EventNotification& event, std::string_view parent, std::string_view child, ua::Variant value)
{
  event.fields.push_back(std::move(value));
  event.fieldPaths.push_back(
    {ua::QualifiedName{0, std::string{parent}}, ua::QualifiedName{0, std::string{child}}});
}

// The ConditionId via the EMPTY-browse-path NodeId operand (CL-AC-002).
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
  if (fields.enabled.has_value())
  {
    add_state_field(event, "EnabledState", *fields.enabled);
  }
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
  if (fields.shelvingState.has_value())
  {
    add_two_segment_field(event, "ShelvingState", "CurrentState", ua::Variant{*fields.shelvingState});
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

// Thread-safe observer capture: count + last payloads per observer kind.
struct ObserverLog
{
  mutable std::mutex mutex;
  int added = 0;
  int changed = 0;
  int removed = 0;
  std::vector<TrackedCondition> changedConditions;

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
};

// ---------------------------------------------------------------------------------------------
// Fixture: one gtest suite `ClientAlarmMethods` (tests named exactly `ClientAlarmMethods.<Row>`). Owns a
// real thread pool, a real EventSubscriberImpl + tracker over the recording backbone interface + recording
// method-wire interface, and the public AlarmConditionTracker handle.
// ---------------------------------------------------------------------------------------------
class ClientAlarmMethods : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mSubscriber = EventSubscriberImpl::create(mPool.get_executor(), mBackbone, ua::Logger{});
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

  // Feed one decoded condition event to the tracker's on-strand hook (as the subscriber dispatch would).
  void post_event(const ConditionFields& fields)
  {
    AlarmConditionTrackerTestAccess::post_event(*mImpl, make_condition_event(fields));
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
  // returns every event posted BEFORE it has fully run.
  Result<TrackedCondition> get_condition(const TrackedKey& key)
  {
    std::promise<Result<TrackedCondition>> promise;
    auto future = promise.get_future();
    mTracker->get_condition_async(
      key, [&promise](Result<TrackedCondition> result) { promise.set_value(std::move(result)); });
    EXPECT_EQ(future.wait_for(5s), std::future_status::ready) << "get_condition_async did not complete";
    return future.get();
  }

  // Invoke a wrapper (op receives the completion callback) and return the delivered VoidResult. The
  // completion is bridged off the executor; the recording wire has already captured the Call by then.
  template<class Op>
  VoidResult invoke(Op op)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    op([&promise](VoidResult result) { promise.set_value(std::move(result)); });
    EXPECT_EQ(future.wait_for(5s), std::future_status::ready) << "method wrapper did not complete";
    return future.get();
  }

  void install_changed_observer()
  {
    std::promise<void> registered;
    auto future = registered.get_future();
    mTracker->on_condition_changed_async(
      [this](const TrackedCondition& condition)
      {
        std::lock_guard lock(mLog.mutex);
        ++mLog.changed;
        mLog.changedConditions.push_back(condition);
      },
      [&registered](VoidResult) { registered.set_value(); });
    ASSERT_EQ(future.wait_for(5s), std::future_status::ready) << "observer registration did not complete";
  }

  boost::asio::thread_pool mPool{2};
  std::shared_ptr<RecordingBackboneOps> mBackbone = std::make_shared<RecordingBackboneOps>();
  std::shared_ptr<RecordingMethodWireOps> mWire = std::make_shared<RecordingMethodWireOps>();
  std::shared_ptr<EventSubscriberImpl> mSubscriber;
  std::shared_ptr<AlarmConditionTrackerImpl> mImpl;
  std::optional<AlarmConditionTracker> mTracker;
  ObserverLog mLog;

  const ua::NodeId mConditionId{2, 4242U};
};

// =============================================================================================
// Row - AcknowledgeExplicitEventId  (section 8.8.6, CL-AC-019)
// Call acknowledge_async(key, E1_explicit, comment) after E2 became the latest tracked event. The Call's
// first argument must be exactly E1 - the explicit EventId overrides lastEventId (which is E2).
// [neg: explicit EventId overrides lastEventId]
// =============================================================================================
// @verifies CL-AC-019
// @relation(CL-AC-019, scope=function)
TEST_F(ClientAlarmMethods, AcknowledgeExplicitEventId)
{
  const ua::ByteString e1{0x01};
  const ua::ByteString e2{0x02};

  ConditionFields first;
  first.conditionId = mConditionId;
  first.eventId = e1;
  first.acked = false;
  post_event(first);

  ConditionFields second = first;
  second.eventId = e2;  // lastEventId advances to E2
  post_event(second);
  ASSERT_TRUE(poll_until([&] { return get_condition(make_key(mConditionId)).value().lastEventId == e2; }));

  const auto result = invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->acknowledge_async(make_key(mConditionId), e1, std::nullopt, std::move(cb)); });
  EXPECT_TRUE(result.is_good());

  ASSERT_EQ(mWire->call_count_to(acknowledgeMethod), 1U) << "exactly one Acknowledge Call must be emitted";
  const auto method = mWire->nth_method(0);
  ASSERT_TRUE(method.has_value());
  ASSERT_GE(method->input_arguments().size(), 1U);
  EXPECT_EQ(method->input_arguments()[0].to<ua::ByteString>().value(), e1)
    << "the explicit EventId E1 must override the tracked lastEventId E2";
}

// =============================================================================================
// Row - AcknowledgeProceedsWhenUnacked  (section 8.8.6, CL-AC-010)
// Track a branch with AckedState/Id=False; call acknowledge_async (no explicit EventId). A Call is emitted
// (the already-acked gate does NOT fire on an unacked branch), and a subsequent server AckedState=True
// event flips the tracked state to True.
// [neg: gate must not mis-fire on an unacked branch]
// =============================================================================================
// @verifies CL-AC-010
// @relation(CL-AC-010, scope=function)
TEST_F(ClientAlarmMethods, AcknowledgeProceedsWhenUnacked)
{
  ConditionFields unacked;
  unacked.conditionId = mConditionId;
  unacked.eventId = ua::ByteString{0xAA};
  unacked.acked = false;
  post_event(unacked);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  const auto result = invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->acknowledge_async(make_key(mConditionId), std::nullopt, std::move(cb)); });
  EXPECT_TRUE(result.is_good()) << "an unacked branch must proceed to the wire, not short-circuit";
  EXPECT_EQ(mWire->call_count_to(acknowledgeMethod), 1U) << "the Acknowledge Call must reach the wire";

  // The server then emits the AckedState transition.
  ConditionFields acked = unacked;
  acked.eventId = ua::ByteString{0xAB};
  acked.acked = true;
  post_event(acked);
  ASSERT_TRUE(poll_until(
    [&]
    {
      const auto tc = get_condition(make_key(mConditionId));
      return tc.is_good() && tc.value().ackedState && tc.value().ackedState->id == true;
    }))
    << "the ensuing event must flip the tracked AckedState to True";
}

// =============================================================================================
// Row - AcknowledgePropagatesBadEventIdUnknown  (section 8.8.7, CL-AC-019)  [MisbehavingServer -> interface]
// The server rejects the Acknowledge Call with Bad_EventIdUnknown. The callback must receive that status
// VERBATIM - not swallowed to Good, not remapped to a generic error.
// [neg: server rejection must surface, not be swallowed]
//
// NOTE: a per-method server rejection surfaces the server's StatusCode verbatim; the tracker attaches its
// own source-tagged ErrorDetail only to its CLIENT-side short-circuits (already-acked / unknown-branch /
// connection-gone), deliberately NOT re-tagging a verbatim server status (re-tagging would obscure it).
// =============================================================================================
// @verifies CL-AC-019
// @relation(CL-AC-019, scope=function)
TEST_F(ClientAlarmMethods, AcknowledgePropagatesBadEventIdUnknown)
{
  ConditionFields unacked;
  unacked.conditionId = mConditionId;
  unacked.eventId = ua::ByteString{0xAA};
  unacked.acked = false;
  post_event(unacked);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  mWire->set_method_status(acknowledgeMethod, StatusCode{Status::BadEventIdUnknown});

  const auto result = invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->acknowledge_async(make_key(mConditionId), std::nullopt, std::move(cb)); });

  EXPECT_TRUE(result.is_bad()) << "a server rejection must surface as a bad Result, never swallowed to Good";
  EXPECT_EQ(result.status_code().as_status(), Status::BadEventIdUnknown)
    << "the server's Bad_EventIdUnknown must surface verbatim, not remapped to a generic error";
}

// =============================================================================================
// Row - AcknowledgeShortCircuitsWhenAlreadyAcked  (section 8.8.5, CL-AC-010)  [2-client -> interface analog]
// The branch is already AckedState/Id=True (an "operator-B" acked it first, driven here through the event
// interface - the local short-circuit depends only on the tracked sub-state, so the observable is identical to a
// real second client). The local client calls acknowledge_async with no explicit EventId: NO Call reaches
// the wire and the callback receives Bad_ConditionBranchAlreadyAcked with a client-side short_circuit_acked
// ErrorDetail. [neg: already-acked -> local short-circuit, no round-trip]
// =============================================================================================
// @verifies CL-AC-010
// @relation(CL-AC-010, scope=function)
TEST_F(ClientAlarmMethods, AcknowledgeShortCircuitsWhenAlreadyAcked)
{
  ConditionFields acked;
  acked.conditionId = mConditionId;
  acked.eventId = ua::ByteString{0xAA};
  acked.acked = true;  // operator-B already acknowledged this branch
  post_event(acked);
  ASSERT_TRUE(poll_until(
    [&]
    {
      const auto tc = get_condition(make_key(mConditionId));
      return tc.is_good() && tc.value().ackedState && tc.value().ackedState->id == true;
    }));

  const auto result = invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->acknowledge_async(make_key(mConditionId), std::nullopt, std::move(cb)); });

  EXPECT_EQ(result.status_code().as_status(), Status::BadConditionBranchAlreadyAcked)
    << "an already-acked branch must short-circuit with Bad_ConditionBranchAlreadyAcked";
  EXPECT_EQ(mWire->total_call_count(), 0U) << "no Call must reach the wire on a local short-circuit";
  const auto detail = result.shared_detail();  // copy the shared_ptr - keeps the ErrorDetail alive
  ASSERT_TRUE(detail != nullptr) << "the short-circuit must carry a client-side ErrorDetail";
  EXPECT_NE(detail->source.find("short_circuit_acked"), std::string::npos)
    << "the ErrorDetail source tag must identify the client-side already-acked short-circuit";
}

// =============================================================================================
// Row - AcknowledgeUsesConditionIdAsObjectId  (section 8.8.6, CL-AC-009)
// Acknowledge on a tracked unacked branch: the wire Call's ObjectId is the ConditionId (never the
// AcknowledgeableConditionType node) and the MethodId is AcknowledgeableConditionType.Acknowledge.
// [neg: ObjectId must be the ConditionId, so a server that does not expose the instance node still accepts]
// =============================================================================================
// @verifies CL-AC-009
// @relation(CL-AC-009, scope=function)
TEST_F(ClientAlarmMethods, AcknowledgeUsesConditionIdAsObjectId)
{
  ConditionFields unacked;
  unacked.conditionId = mConditionId;
  unacked.eventId = ua::ByteString{0xAA};
  unacked.acked = false;
  post_event(unacked);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  const auto result = invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->acknowledge_async(make_key(mConditionId), std::nullopt, std::move(cb)); });
  EXPECT_TRUE(result.is_good());

  const auto method = mWire->nth_method(0);
  ASSERT_TRUE(method.has_value());
  EXPECT_EQ(method->object_id(), mConditionId) << "ObjectId must be the ConditionId, not the Type node";
  EXPECT_EQ(method->method_id(), acknowledgeMethod)
    << "MethodId must be AcknowledgeableConditionType.Acknowledge";
}

// =============================================================================================
// Row - AcknowledgeUsesLastEventIdByDefault  (section 8.8.6, CL-AC-019)
// Deliver two events E1 then E2; call acknowledge_async with no explicit EventId. The Call's first argument
// is E2 (the most recent lastEventId, updated per inbound event).
// [neg: lastEventId must be updated per event, so a stale E1 is not sent]
// =============================================================================================
// @verifies CL-AC-019
// @relation(CL-AC-019, scope=function)
TEST_F(ClientAlarmMethods, AcknowledgeUsesLastEventIdByDefault)
{
  const ua::ByteString e1{0x01};
  const ua::ByteString e2{0x02};

  ConditionFields first;
  first.conditionId = mConditionId;
  first.eventId = e1;
  first.acked = false;
  post_event(first);

  ConditionFields second = first;
  second.eventId = e2;
  post_event(second);
  ASSERT_TRUE(poll_until([&] { return get_condition(make_key(mConditionId)).value().lastEventId == e2; }));

  const auto result = invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->acknowledge_async(make_key(mConditionId), std::nullopt, std::move(cb)); });
  EXPECT_TRUE(result.is_good());

  const auto method = mWire->nth_method(0);
  ASSERT_TRUE(method.has_value());
  ASSERT_GE(method->input_arguments().size(), 1U);
  EXPECT_EQ(method->input_arguments()[0].to<ua::ByteString>().value(), e2)
    << "the default EventId must be the most recent lastEventId (E2), not the stale E1";
}

// =============================================================================================
// Row - AddCommentEmptyTextClearsComment  (section 8.8.6, CL-AC-020)
// add_comment_async with LocalizedText{locale="en", text=""}: the wire Comment arg has locale="en" and an
// empty text (distinct from a fully-null LocalizedText) - an empty-text-with-locale must NOT be collapsed
// to null. [neg: empty-text-with-locale = clear, not null]
//
// SCOPE: the server-side "clears the existing comment" is not observable through the client interface (the
// tracker models no Comment sub-state); the falsifiable oracle is the WIRE argument shape, which is exactly
// what distinguishes "clear" (locale present, text empty) from "no-change" (fully null).
// =============================================================================================
// @verifies CL-AC-020
// @relation(CL-AC-020, scope=function)
TEST_F(ClientAlarmMethods, AddCommentEmptyTextClearsComment)
{
  ConditionFields tracked;
  tracked.conditionId = mConditionId;
  tracked.eventId = ua::ByteString{0xAA};
  post_event(tracked);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  const auto result = invoke(
    [&](std::function<void(VoidResult)> cb)
    {
      mTracker->add_comment_async(
        make_key(mConditionId), ua::ByteString{0xAA}, ua::LocalizedText{"en", ""}, std::move(cb));
    });
  EXPECT_TRUE(result.is_good());

  const auto method = mWire->nth_method(0);
  ASSERT_TRUE(method.has_value());
  EXPECT_EQ(method->method_id(), addCommentMethod);
  ASSERT_GE(method->input_arguments().size(), 2U);
  const auto comment = method->input_arguments()[1].to<ua::LocalizedText>();
  ASSERT_TRUE(comment.is_good());
  EXPECT_EQ(static_cast<std::string_view>(comment.value().locale()), "en")
    << "an empty-text-with-locale must keep the locale (not be collapsed to null)";
  EXPECT_EQ(static_cast<std::string_view>(comment.value().text()), "")
    << "the empty text must be wired as-is (the 'clear' signal)";
}

// =============================================================================================
// Row - AddCommentNonEmptyTextSets  (section 8.8.6, CL-AC-020)
// add_comment_async with LocalizedText{"en","manual ack"}: the wire Comment arg matches the supplied text.
// [neg: the encoding must not drop the text]
//
// SCOPE: the "subsequent event surfaces the new Comment" half is not observable (the tracker models no
// Comment sub-state - decode reads no "Comment" field); the falsifiable oracle is the wire argument.
// =============================================================================================
// @verifies CL-AC-020
// @relation(CL-AC-020, scope=function)
TEST_F(ClientAlarmMethods, AddCommentNonEmptyTextSets)
{
  ConditionFields tracked;
  tracked.conditionId = mConditionId;
  tracked.eventId = ua::ByteString{0xAA};
  post_event(tracked);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  const auto result = invoke(
    [&](std::function<void(VoidResult)> cb)
    {
      mTracker->add_comment_async(
        make_key(mConditionId), ua::ByteString{0xAA}, ua::LocalizedText{"en", "manual ack"}, std::move(cb));
    });
  EXPECT_TRUE(result.is_good());

  const auto method = mWire->nth_method(0);
  ASSERT_TRUE(method.has_value());
  ASSERT_GE(method->input_arguments().size(), 2U);
  const auto comment = method->input_arguments()[1].to<ua::LocalizedText>();
  ASSERT_TRUE(comment.is_good());
  EXPECT_EQ(static_cast<std::string_view>(comment.value().text()), "manual ack")
    << "the supplied comment text must be wired verbatim";
}

// =============================================================================================
// Row - AddCommentNulloptWiresNullLocalizedText  (section 8.8.6, CL-AC-020)
// add_comment_async(key, eventId, std::nullopt): the wire Comment arg is a fully-null LocalizedText (empty
// locale AND empty text), distinct from the empty-text-with-locale "clear" of AddCommentEmptyTextClears.
// [neg: nullopt = no-change, distinct from clear]
// =============================================================================================
// @verifies CL-AC-020
// @relation(CL-AC-020, scope=function)
TEST_F(ClientAlarmMethods, AddCommentNulloptWiresNullLocalizedText)
{
  ConditionFields tracked;
  tracked.conditionId = mConditionId;
  tracked.eventId = ua::ByteString{0xAA};
  post_event(tracked);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  const auto result = invoke(
    [&](std::function<void(VoidResult)> cb) {
      mTracker->add_comment_async(make_key(mConditionId), ua::ByteString{0xAA}, std::nullopt, std::move(cb));
    });
  EXPECT_TRUE(result.is_good());

  const auto method = mWire->nth_method(0);
  ASSERT_TRUE(method.has_value());
  ASSERT_GE(method->input_arguments().size(), 2U);
  const auto comment = method->input_arguments()[1].to<ua::LocalizedText>();
  ASSERT_TRUE(comment.is_good());
  EXPECT_EQ(static_cast<std::string_view>(comment.value().locale()), "")
    << "nullopt must wire a fully-null LocalizedText (empty locale)";
  EXPECT_EQ(static_cast<std::string_view>(comment.value().text()), "")
    << "nullopt must wire a fully-null LocalizedText (empty text) - no-change, distinct from clear";
}

// =============================================================================================
// Row - ConfirmOnNonAcknowledgeableTypeReturnsBadMethodInvalid  (section 8.8.7, CL-AC-009)
// The matrix oracle wants the wrapper to complete INLINE with Bad_MethodInvalid and issue NO Call when the
// condition's type has no Confirm method. The tracker has NO per-type method resolution (no method-node
// cache / Browse), so it cannot pre-empt: it targets the fixed AcknowledgeableConditionType.Confirm MethodId
// and relies on the SERVER to reject. Pinned to that built analog - a Call IS issued (ObjectId=ConditionId,
// MethodId=Confirm) and the server's Bad_MethodInvalid surfaces verbatim to the caller.
// GAP REPORTED: client-side type-method pre-emption (inline Bad_MethodInvalid, no Call) is unbuilt.
// =============================================================================================
// @verifies CL-AC-009
// @relation(CL-AC-009, scope=function)
TEST_F(ClientAlarmMethods, ConfirmOnNonAcknowledgeableTypeReturnsBadMethodInvalid)
{
  ConditionFields tracked;
  tracked.conditionId = mConditionId;
  tracked.eventId = ua::ByteString{0xAA};
  tracked.eventTypeId = ua::NodeId{ua::ObjectTypeId::ConditionType};  // base type: no Confirm method
  post_event(tracked);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  mWire->set_method_status(confirmMethod, StatusCode{Status::BadMethodInvalid});

  const auto result = invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->confirm_async(make_key(mConditionId), std::nullopt, std::move(cb)); });

  // Built analog: the tracker issues the Call (no inline pre-emption) and the server Bad_MethodInvalid
  // surfaces verbatim. The caller still learns the method is invalid - just via a round-trip, not inline.
  EXPECT_EQ(mWire->call_count_to(confirmMethod), 1U)
    << "the tracker has no type-method pre-emption; it issues the Confirm Call and lets the server reject";
  const auto method = mWire->nth_method(0);
  ASSERT_TRUE(method.has_value());
  EXPECT_EQ(method->object_id(), mConditionId) << "ObjectId must be the ConditionId even for the reject case";
  EXPECT_EQ(result.status_code().as_status(), Status::BadMethodInvalid)
    << "the server's Bad_MethodInvalid must surface verbatim to the caller";
}

// =============================================================================================
// Row - ConfirmProceedsWhenUnconfirmed  (section 8.8.6, CL-AC-009)
// Confirm on an acked-but-unconfirmed branch: the Call targets AcknowledgeableConditionType.Confirm with
// ObjectId=ConditionId, and the ensuing event flips ConfirmedState to True.
// [neg: an unconfirmed branch must proceed and confirm]
// =============================================================================================
// @verifies CL-AC-009
// @relation(CL-AC-009, scope=function)
TEST_F(ClientAlarmMethods, ConfirmProceedsWhenUnconfirmed)
{
  ConditionFields unconfirmed;
  unconfirmed.conditionId = mConditionId;
  unconfirmed.eventId = ua::ByteString{0xAA};
  unconfirmed.acked = true;
  unconfirmed.confirmed = false;
  post_event(unconfirmed);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  const auto result = invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->confirm_async(make_key(mConditionId), std::nullopt, std::move(cb)); });
  EXPECT_TRUE(result.is_good()) << "an unconfirmed branch must proceed to the wire";

  const auto method = mWire->nth_method(0);
  ASSERT_TRUE(method.has_value());
  EXPECT_EQ(method->object_id(), mConditionId);
  EXPECT_EQ(method->method_id(), confirmMethod)
    << "the Call must target AcknowledgeableConditionType.Confirm";

  ConditionFields confirmed = unconfirmed;
  confirmed.eventId = ua::ByteString{0xAB};
  confirmed.confirmed = true;
  post_event(confirmed);
  ASSERT_TRUE(poll_until(
    [&]
    {
      const auto tc = get_condition(make_key(mConditionId));
      return tc.is_good() && tc.value().confirmedState && tc.value().confirmedState->id == true;
    }))
    << "the ensuing event must flip the tracked ConfirmedState to True";
}

// =============================================================================================
// Row - ConfirmShortCircuitsWhenAlreadyConfirmed  (section 8.8.6, CL-AC-010)  [2-client -> interface analog]
// The branch is already ConfirmedState/Id=True (driven through the event interface). Confirm with no explicit
// EventId short-circuits: NO Call reaches the wire and the callback receives Bad_ConditionBranchAlready
// Confirmed with a client-side short_circuit_confirmed ErrorDetail. [neg: already-confirmed short-circuit]
// =============================================================================================
// @verifies CL-AC-010
// @relation(CL-AC-010, scope=function)
TEST_F(ClientAlarmMethods, ConfirmShortCircuitsWhenAlreadyConfirmed)
{
  ConditionFields confirmed;
  confirmed.conditionId = mConditionId;
  confirmed.eventId = ua::ByteString{0xAA};
  confirmed.acked = true;
  confirmed.confirmed = true;
  post_event(confirmed);
  ASSERT_TRUE(poll_until(
    [&]
    {
      const auto tc = get_condition(make_key(mConditionId));
      return tc.is_good() && tc.value().confirmedState && tc.value().confirmedState->id == true;
    }));

  const auto result = invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->confirm_async(make_key(mConditionId), std::nullopt, std::move(cb)); });

  EXPECT_EQ(result.status_code().as_status(), Status::BadConditionBranchAlreadyConfirmed)
    << "an already-confirmed branch must short-circuit with Bad_ConditionBranchAlreadyConfirmed";
  EXPECT_EQ(mWire->total_call_count(), 0U) << "no Call must reach the wire on a local short-circuit";
  const auto detail = result.shared_detail();  // copy the shared_ptr - keeps the ErrorDetail alive
  ASSERT_TRUE(detail != nullptr) << "the short-circuit must carry a client-side ErrorDetail";
  EXPECT_NE(detail->source.find("short_circuit_confirmed"), std::string::npos)
    << "the ErrorDetail source tag must identify the client-side already-confirmed short-circuit";
}

// =============================================================================================
// Row - DisableSuppressesFurtherConditionEvents  (section 8.8.6, CL-AC-009; re-tagged per matrix)
// Three-phase: (a) disable_async issues ConditionType.Disable (ObjectId=ConditionId) and a positive
// EnabledState=Disabled event confirms the Disable took effect; (c) re-enable via enable_async and a
// following event resumes transitions. [neg: disabled condition stops emitting until re-enabled]
//
// SCOPE: phase (b) - "a disabled condition emits no further events" - is SERVER behaviour and is not
// observable through the client interface (the interface is where the test posts events; the tracker does not itself
// gate the event stream). Pinned to the client-observable arms (a)+(c): the client issues the correct
// Enable/Disable Calls and tracks the EnabledState transitions. Server-side suppression is REPORTED as
// out-of-scope for the client interface.
// =============================================================================================
// @verifies CL-AC-009
// @relation(CL-AC-009, scope=function)
TEST_F(ClientAlarmMethods, DisableSuppressesFurtherConditionEvents)
{
  ConditionFields active;
  active.conditionId = mConditionId;
  active.eventId = ua::ByteString{0x01};
  active.enabled = true;
  active.active = true;
  post_event(active);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  // (a) Disable -> ConditionType.Disable Call; the ensuing EnabledState=Disabled event confirms it took hold.
  const auto disabled = invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->disable_async(make_key(mConditionId), std::move(cb)); });
  EXPECT_TRUE(disabled.is_good());
  ASSERT_EQ(mWire->call_count_to(disableMethodId), 1U);
  const auto disableMethod = mWire->nth_method(0);
  ASSERT_TRUE(disableMethod.has_value());
  EXPECT_EQ(disableMethod->object_id(), mConditionId);

  ConditionFields disabledEvent = active;
  disabledEvent.eventId = ua::ByteString{0x02};
  disabledEvent.enabled = false;  // server confirms EnabledState=Disabled
  post_event(disabledEvent);
  ASSERT_TRUE(poll_until(
    [&]
    {
      const auto tc = get_condition(make_key(mConditionId));
      return tc.is_good() && tc.value().enabledState.id == false;
    }))
    << "the EnabledState=Disabled event must be tracked (the Disable took effect)";

  // (c) Re-enable -> ConditionType.Enable Call; a following event resumes.
  const auto enabled = invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->enable_async(make_key(mConditionId), std::move(cb)); });
  EXPECT_TRUE(enabled.is_good());
  ASSERT_EQ(mWire->call_count_to(enableMethodId), 1U);

  ConditionFields resumed = active;
  resumed.eventId = ua::ByteString{0x03};
  resumed.enabled = true;
  post_event(resumed);
  ASSERT_TRUE(poll_until(
    [&]
    {
      const auto tc = get_condition(make_key(mConditionId));
      return tc.is_good() && tc.value().enabledState.id == true;
    }))
    << "after re-enable, EnabledState transitions must resume";
}

// =============================================================================================
// Row - EnableAndDisableCallConditionTypeMethods  (section 8.8.6, CL-AC-009)
// disable_async then enable_async: two Calls with MethodId ConditionType.Disable / ConditionType.Enable and
// ObjectId=ConditionId, and the server-reported EnabledState toggles Disabled->Enabled in the events.
// [neg: wrong MethodIds -> Calls fail and EnabledState never changes]
// =============================================================================================
// @verifies CL-AC-009
// @relation(CL-AC-009, scope=function)
TEST_F(ClientAlarmMethods, EnableAndDisableCallConditionTypeMethods)
{
  ConditionFields tracked;
  tracked.conditionId = mConditionId;
  tracked.eventId = ua::ByteString{0x01};
  tracked.enabled = true;
  post_event(tracked);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->disable_async(make_key(mConditionId), std::move(cb)); });
  invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->enable_async(make_key(mConditionId), std::move(cb)); });

  ASSERT_EQ(mWire->total_call_count(), 2U);
  const auto disableMethod = mWire->nth_method(0);
  const auto enableMethod = mWire->nth_method(1);
  ASSERT_TRUE(disableMethod.has_value() && enableMethod.has_value());
  EXPECT_EQ(disableMethod->method_id(), disableMethodId);
  EXPECT_EQ(disableMethod->object_id(), mConditionId);
  EXPECT_EQ(enableMethod->method_id(), enableMethodId);
  EXPECT_EQ(enableMethod->object_id(), mConditionId);

  ConditionFields off = tracked;
  off.eventId = ua::ByteString{0x02};
  off.enabled = false;
  post_event(off);
  ASSERT_TRUE(
    poll_until([&] { return get_condition(make_key(mConditionId)).value().enabledState.id == false; }));

  ConditionFields on = tracked;
  on.eventId = ua::ByteString{0x03};
  on.enabled = true;
  post_event(on);
  ASSERT_TRUE(
    poll_until([&] { return get_condition(make_key(mConditionId)).value().enabledState.id == true; }))
    << "EnabledState must toggle Disabled->Enabled across the ensuing events";
}

// =============================================================================================
// Row - ExplicitEventIdOverloadDoesNotShortCircuit  (section 8.8.6, CL-AC-010/019)
// The trunk is currently acked (the no-EventId overload would short-circuit). Call the explicit-EventId
// overload targeting a historical branch: a Call IS emitted (no local short-circuit) carrying the explicit
// EventId. [neg: explicit-EventId overload bypasses the local gate]
// =============================================================================================
// @verifies CL-AC-010
// @verifies CL-AC-019
// @relation(CL-AC-010, CL-AC-019, scope=function)
TEST_F(ClientAlarmMethods, ExplicitEventIdOverloadDoesNotShortCircuit)
{
  const ua::ByteString historicalEventId{0xDE, 0xAD, 0xBE, 0xEF};

  ConditionFields ackedTrunk;
  ackedTrunk.conditionId = mConditionId;
  ackedTrunk.eventId = ua::ByteString{0x01};
  ackedTrunk.acked = true;  // the trunk is acked: the default overload would short-circuit
  post_event(ackedTrunk);
  ASSERT_TRUE(poll_until(
    [&]
    {
      const auto tc = get_condition(make_key(mConditionId));
      return tc.is_good() && tc.value().ackedState && tc.value().ackedState->id == true;
    }));

  const auto result = invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->acknowledge_async(make_key(mConditionId), historicalEventId, std::nullopt, std::move(cb)); });
  EXPECT_TRUE(result.is_good()) << "the explicit-EventId overload must not short-circuit on the acked trunk";

  ASSERT_EQ(mWire->call_count_to(acknowledgeMethod), 1U)
    << "a Call must be emitted despite the acked trunk (explicit EventId bypasses the local gate)";
  const auto method = mWire->nth_method(0);
  ASSERT_TRUE(method.has_value());
  ASSERT_GE(method->input_arguments().size(), 1U);
  EXPECT_EQ(method->input_arguments()[0].to<ua::ByteString>().value(), historicalEventId)
    << "the Call must carry the explicit historical EventId";
}

// =============================================================================================
// Row - MethodCacheEvictedOnBadNodeIdUnknown  (section 8.8.7, CL-AC-009)  [MisbehavingServer -> interface]
// Solid half (per the matrix's own strengthening): a method Call returning Bad_NodeIdUnknown surfaces
// VERBATIM with NO transparent retry - each wrapper invocation produces exactly one wire Call.
// [neg: invalidate-on-error but never transparently retry]
//
// SCOPE: the matrix's "evict-the-cache-entry + re-browse on the next call" half is dropped, per its own
// note: there is NO mTypeMethodCache in this implementation (methods resolve to fixed well-known base-type
// MethodIds; section 8.8.2 invalidation is a model-change concern, not a per-Call one). The re-browse
// assertion would test behaviour the implementation is not required to have. REPORTED as an unbuilt-cache
// gap.
// =============================================================================================
// @verifies CL-AC-009
// @relation(CL-AC-009, scope=function)
TEST_F(ClientAlarmMethods, MethodCacheEvictedOnBadNodeIdUnknown)
{
  ConditionFields unacked;
  unacked.conditionId = mConditionId;
  unacked.eventId = ua::ByteString{0xAA};
  unacked.acked = false;
  post_event(unacked);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  mWire->set_method_status(acknowledgeMethod, StatusCode{Status::BadNodeIdUnknown});

  const auto first = invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->acknowledge_async(make_key(mConditionId), std::nullopt, std::move(cb)); });
  EXPECT_EQ(first.status_code().as_status(), Status::BadNodeIdUnknown)
    << "the first failure must surface Bad_NodeIdUnknown verbatim";
  EXPECT_EQ(mWire->total_call_count(), 1U) << "exactly one Call - no transparent retry on the first failure";

  const auto second = invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->acknowledge_async(make_key(mConditionId), std::nullopt, std::move(cb)); });
  EXPECT_EQ(second.status_code().as_status(), Status::BadNodeIdUnknown);
  EXPECT_EQ(mWire->total_call_count(), 2U)
    << "the second invocation issues its own single Call - no transparent retry, no cache suppression";
}

// =============================================================================================
// Row - MethodCacheMissTriggersBrowseThenCall  (section 8.8.6, CL-AC-009)
// The matrix oracle expects a Browse(conditionTypeId, HasComponent, NodeClassMask=Method) to precede the
// Call for a condition of a custom subtype not yet in a method cache. The tracker has NO Browse-then-Call:
// it resolves every standard condition method to the FIXED well-known base-type MethodId and Calls directly
// - spec-valid (OPC 10000-9), so a custom subtype needs no per-instance browse. Pinned to that built
// analog: a custom-subtype condition still yields a single Call to the well-known base MethodId with
// ObjectId=ConditionId, and no Browse is issued. GAP REPORTED: lazy Browse-based type-method resolution +
// method cache are unbuilt.
// =============================================================================================
// @verifies CL-AC-009
// @relation(CL-AC-009, scope=function)
TEST_F(ClientAlarmMethods, MethodCacheMissTriggersBrowseThenCall)
{
  ConditionFields customSubtype;
  customSubtype.conditionId = mConditionId;
  customSubtype.eventId = ua::ByteString{0xAA};
  customSubtype.eventTypeId =
    ua::NodeId{2, 7777U};  // a custom (namespace-2) AcknowledgeableCondition subtype
  customSubtype.acked = false;
  post_event(customSubtype);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  const auto result = invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->acknowledge_async(make_key(mConditionId), std::nullopt, std::move(cb)); });
  EXPECT_TRUE(result.is_good());

  EXPECT_EQ(mWire->total_call_count(), 1U) << "a single Call is issued - no Browse-then-Call round-trip";
  EXPECT_EQ(mWire->readCalls, 0U) << "no Browse/Read is issued to resolve the method for a custom subtype";
  const auto method = mWire->nth_method(0);
  ASSERT_TRUE(method.has_value());
  EXPECT_EQ(method->method_id(), acknowledgeMethod)
    << "the well-known base-type Acknowledge MethodId is used directly, even for a custom subtype";
  EXPECT_EQ(method->object_id(), mConditionId);
}

// =============================================================================================
// Row - MethodGoodAndLaterStateEventBothSurfaced  (section 8.8.6, CL-AC-016)
// acknowledge_async completes Good; the corresponding AckedState transition arrives later via the event
// stream. BOTH the method callback (Good) AND a subsequent on_condition_changed carrying AckedState=True
// are observed as distinct events. [neg: method-completion and state-event are not collapsed]
// =============================================================================================
// @verifies CL-AC-016
// @relation(CL-AC-016, scope=function)
TEST_F(ClientAlarmMethods, MethodGoodAndLaterStateEventBothSurfaced)
{
  install_changed_observer();

  ConditionFields unacked;
  unacked.conditionId = mConditionId;
  unacked.eventId = ua::ByteString{0xAA};
  unacked.acked = false;
  post_event(unacked);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  const auto result = invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->acknowledge_async(make_key(mConditionId), std::nullopt, std::move(cb)); });
  EXPECT_TRUE(result.is_good()) << "the method callback must surface Good";

  ConditionFields acked = unacked;
  acked.eventId = ua::ByteString{0xAB};
  acked.acked = true;
  post_event(acked);
  ASSERT_TRUE(poll_until([&] { return mLog.changed_count() == 1; }))
    << "a distinct on_condition_changed must surface the later AckedState transition";
  std::lock_guard lock(mLog.mutex);
  ASSERT_EQ(mLog.changedConditions.size(), 1U);
  ASSERT_TRUE(mLog.changedConditions.front().ackedState.has_value());
  EXPECT_EQ(mLog.changedConditions.front().ackedState->id, true)
    << "the state event carrying AckedState=True must not be collapsed with the method completion";
}

// =============================================================================================
// Row - MethodNeverTargetsTypeNodeAsObjectId  (section 8.8.5, CL-AC-009)  (strengthened)
// Exercise acknowledge/enable/disable/add_comment and capture every Call. Positive precondition: exactly
// four Calls were captured; each ObjectId equals the expected ConditionId and none is a Type-node ObjectId.
// [neg: method ObjectId must never be a Type node]
// =============================================================================================
// @verifies CL-AC-009
// @relation(CL-AC-009, scope=function)
TEST_F(ClientAlarmMethods, MethodNeverTargetsTypeNodeAsObjectId)
{
  ConditionFields unacked;
  unacked.conditionId = mConditionId;
  unacked.eventId = ua::ByteString{0xAA};
  unacked.acked = false;
  post_event(unacked);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->acknowledge_async(make_key(mConditionId), std::nullopt, std::move(cb)); });
  invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->enable_async(make_key(mConditionId), std::move(cb)); });
  invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->disable_async(make_key(mConditionId), std::move(cb)); });
  invoke(
    [&](std::function<void(VoidResult)> cb) {
      mTracker->add_comment_async(make_key(mConditionId), ua::ByteString{0xAA}, std::nullopt, std::move(cb));
    });

  ASSERT_EQ(mWire->total_call_count(), 4U)
    << "exactly the four exercised wrappers must have emitted a Call (positive precondition)";
  for (std::size_t i = 0; i < 4; ++i)
  {
    const auto method = mWire->nth_method(i);
    ASSERT_TRUE(method.has_value());
    EXPECT_EQ(method->object_id(), mConditionId) << "Call " << i << " ObjectId must be the ConditionId";
    EXPECT_NE(method->object_id(), ackTypeNode) << "Call " << i << " ObjectId must not be a Type node";
    EXPECT_NE(method->object_id(), conditionTypeNode) << "Call " << i << " ObjectId must not be a Type node";
    EXPECT_NE(method->object_id(), alarmTypeNode) << "Call " << i << " ObjectId must not be a Type node";
  }
}

// =============================================================================================
// Row - OneShotShelveUsesConditionIdObjectId  (section 8.8.6, CL-AC-017)
// one_shot_shelve_async: the Call has ObjectId=ConditionId and
// MethodId=ShelvedStateMachineType.OneShotShelve. [neg: wrong ObjectId/MethodId -> Call fails or targets the
// wrong method]
// =============================================================================================
// @verifies CL-AC-017
// @relation(CL-AC-017, scope=function)
TEST_F(ClientAlarmMethods, OneShotShelveUsesConditionIdObjectId)
{
  ConditionFields alarm;
  alarm.conditionId = mConditionId;
  alarm.eventId = ua::ByteString{0xAA};
  post_event(alarm);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  const auto result = invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->one_shot_shelve_async(make_key(mConditionId), std::move(cb)); });
  EXPECT_TRUE(result.is_good());

  const auto method = mWire->nth_method(0);
  ASSERT_TRUE(method.has_value());
  EXPECT_EQ(method->object_id(), mConditionId) << "ObjectId must be the ConditionId";
  EXPECT_EQ(method->method_id(), oneShotShelveMethod)
    << "MethodId must be ShelvedStateMachineType.OneShotShelve";
}

// =============================================================================================
// Row - ShelveNeverTargetsShelvedStateMachineTypeNode  (section 8.8.6, CL-AC-017)  (strengthened)
// Exercise timed/one-shot/unshelve and capture Calls. Positive precondition: exactly three shelving Calls
// were emitted; each ObjectId equals the ConditionId and none equals the ShelvedStateMachineType node.
// [neg: shelving ObjectId must not be the state-machine Type node]
// =============================================================================================
// @verifies AC-CL-AC-017-SHELVE-METHOD-TARGETING
// @relation(AC-CL-AC-017-SHELVE-METHOD-TARGETING, scope=function)
TEST_F(ClientAlarmMethods, ShelveNeverTargetsShelvedStateMachineTypeNode)
{
  ConditionFields alarm;
  alarm.conditionId = mConditionId;
  alarm.eventId = ua::ByteString{0xAA};
  post_event(alarm);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->timed_shelve_async(make_key(mConditionId), 30000.0, std::move(cb)); });
  invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->one_shot_shelve_async(make_key(mConditionId), std::move(cb)); });
  invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->unshelve_async(make_key(mConditionId), std::move(cb)); });

  ASSERT_EQ(mWire->total_call_count(), 3U)
    << "exactly the three shelving wrappers must have emitted a Call (positive precondition)";
  for (std::size_t i = 0; i < 3; ++i)
  {
    const auto method = mWire->nth_method(i);
    ASSERT_TRUE(method.has_value());
    EXPECT_EQ(method->object_id(), mConditionId)
      << "shelving Call " << i << " ObjectId must be the ConditionId";
    EXPECT_NE(method->object_id(), shelvedStateMachineTypeNode)
      << "shelving Call " << i << " ObjectId must not be the ShelvedStateMachineType node";
  }
}

// =============================================================================================
// Row - TimedShelveMaxTimeNullProceedsUnconditionally  (section 8.8.7, CL-AC-018)
// timed_shelve_async issues the Call unconditionally when MaxTimeShelved is NULL (no cap).
// [neg: NULL MaxTimeShelved = no cap]
//
// With no MaxTimeShelved carried by the event, the tracked cap is nullopt, so the pre-flight cannot fire and
// timed_shelve proceeds unconditionally - the server remains the authority on a cap it never advertised.
// =============================================================================================
// @verifies CL-AC-018
// @relation(CL-AC-018, scope=function)
TEST_F(ClientAlarmMethods, TimedShelveMaxTimeNullProceedsUnconditionally)
{
  ConditionFields alarm;
  alarm.conditionId = mConditionId;
  alarm.eventId = ua::ByteString{0xAA};
  post_event(alarm);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  const auto result = invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->timed_shelve_async(make_key(mConditionId), 90000.0, std::move(cb)); });
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(mWire->call_count_to(timedShelveMethod), 1U)
    << "with no MaxTimeShelved cap the TimedShelve Call must be issued unconditionally";
}

// =============================================================================================
// Row - TimedShelveShortCircuitsOnMaxTimeExceeded  (section 8.8.6, CL-AC-018)
// With MaxTimeShelved=60s carried by the event (tracked verbatim), timed_shelve(120s) is short-circuited
// LOCALLY by the pre-flight - no Call reaches the wire and the callback receives Bad_ShelvingTimeOutOfRange.
// [neg: duration > MaxTimeShelved must short-circuit]
// =============================================================================================
// @verifies CL-AC-018
// @relation(CL-AC-018, scope=function)
TEST_F(ClientAlarmMethods, TimedShelveShortCircuitsOnMaxTimeExceeded)
{
  ConditionFields alarm;
  alarm.conditionId = mConditionId;
  alarm.eventId = ua::ByteString{0xAA};
  alarm.maxTimeShelved = 60000.0;  // 60s cap, carried by the event and tracked
  post_event(alarm);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  // Request 120s - over the tracked 60s MaxTimeShelved: the local pre-flight short-circuits.
  const auto result = invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->timed_shelve_async(make_key(mConditionId), 120000.0, std::move(cb)); });

  EXPECT_EQ(mWire->total_call_count(), 0U)
    << "duration > tracked MaxTimeShelved must short-circuit locally - no Call reaches the wire";
  EXPECT_EQ(result.status_code().as_status(), Status::BadShelvingTimeOutOfRange)
    << "the local pre-flight rejects with Bad_ShelvingTimeOutOfRange";
}

// =============================================================================================
// Row - TimedShelveUnderMaxProceeds  (section 8.8.6, CL-AC-018)
// timed_shelve(30s) with MaxTimeShelved=60s proceeds: a Call is emitted and shelving succeeds.
// [neg: a valid duration must not be wrongly rejected]
//
// With a KNOWN 60s cap tracked, a 30s request is under it, so the pre-flight must NOT short-circuit: the
// Call is emitted and shelving completes Good. This genuinely exercises the under-cap branch (not merely the
// unknown-cap path - cf. TimedShelveMaxTimeNullProceedsUnconditionally).
// =============================================================================================
// @verifies CL-AC-018
// @relation(CL-AC-018, scope=function)
TEST_F(ClientAlarmMethods, TimedShelveUnderMaxProceeds)
{
  ConditionFields alarm;
  alarm.conditionId = mConditionId;
  alarm.eventId = ua::ByteString{0xAA};
  alarm.maxTimeShelved =
    60000.0;  // a KNOWN 60s cap: 30s is under it, so the pre-flight must NOT short-circuit
  post_event(alarm);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  const auto result = invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->timed_shelve_async(make_key(mConditionId), 30000.0, std::move(cb)); });
  EXPECT_TRUE(result.is_good())
    << "a valid shelving duration under a known cap must reach the wire and succeed";

  const auto method = mWire->nth_method(0);
  ASSERT_TRUE(method.has_value());
  EXPECT_EQ(method->method_id(), timedShelveMethod);
  ASSERT_GE(method->input_arguments().size(), 1U);
  EXPECT_DOUBLE_EQ(method->input_arguments()[0].to<double>().value(), 30000.0)
    << "the requested shelving duration must be wired verbatim";
}

// =============================================================================================
// Row - TimedShelveUsesConditionIdObjectId  (section 8.8.6, CL-AC-017)
// timed_shelve(30s): the Call has ObjectId=ConditionId and MethodId=ShelvedStateMachineType.TimedShelve.
// [neg: ObjectId must be the ConditionId, so a server that does not expose the ShelvedStateMachine node
//  still accepts]
// =============================================================================================
// @verifies CL-AC-017
// @relation(CL-AC-017, scope=function)
TEST_F(ClientAlarmMethods, TimedShelveUsesConditionIdObjectId)
{
  ConditionFields alarm;
  alarm.conditionId = mConditionId;
  alarm.eventId = ua::ByteString{0xAA};
  post_event(alarm);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  const auto result = invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->timed_shelve_async(make_key(mConditionId), 30000.0, std::move(cb)); });
  EXPECT_TRUE(result.is_good());

  const auto method = mWire->nth_method(0);
  ASSERT_TRUE(method.has_value());
  EXPECT_EQ(method->object_id(), mConditionId)
    << "ObjectId must be the ConditionId, not the ShelvedStateMachine";
  EXPECT_EQ(method->method_id(), timedShelveMethod)
    << "MethodId must be ShelvedStateMachineType.TimedShelve";
}

// =============================================================================================
// Row - UnshelveTransitionsShelvingState  (section 8.8.6, CL-AC-016)
// Shelve an alarm, then unshelve: the unshelve Call targets ShelvedStateMachineType.Unshelve with
// ObjectId=ConditionId, AND the tracker reflects the server-reported ShelvingState.CurrentState transition
// (Slice AC2 models ShelvingState.CurrentState). A follow-on event carrying the two-segment
// [ShelvingState, CurrentState] = Unshelved is surfaced on the tracked condition.
// [neg: Unshelve must target the correct node/method; the ShelvingState transition must be surfaced]
// =============================================================================================
// @verifies CL-AC-016
// @relation(CL-AC-016, scope=function)
TEST_F(ClientAlarmMethods, UnshelveTransitionsShelvingState)
{
  ConditionFields alarm;
  alarm.conditionId = mConditionId;
  alarm.eventId = ua::ByteString{0xAA};
  alarm.shelvingState = ua::LocalizedText{"", "OneShotShelved"};  // server reports it shelved
  post_event(alarm);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));
  {
    const auto shelved = get_condition(make_key(mConditionId));
    ASSERT_TRUE(shelved.is_good());
    ASSERT_TRUE(shelved.value().shelvingState.has_value()) << "ShelvingState.CurrentState must be surfaced";
    EXPECT_EQ(*shelved.value().shelvingState, (ua::LocalizedText{"", "OneShotShelved"}));
  }

  invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->one_shot_shelve_async(make_key(mConditionId), std::move(cb)); });
  const auto result = invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->unshelve_async(make_key(mConditionId), std::move(cb)); });
  EXPECT_TRUE(result.is_good());

  ASSERT_EQ(mWire->total_call_count(), 2U);
  const auto unshelveMethod = mWire->nth_method(1);
  ASSERT_TRUE(unshelveMethod.has_value());
  EXPECT_EQ(unshelveMethod->method_id(), unshelveMethodId)
    << "the Unshelve Call must target ShelvedStateMachineType.Unshelve";
  EXPECT_EQ(unshelveMethod->object_id(), mConditionId) << "ObjectId must be the ConditionId";

  // The server reports the resulting ShelvingState transition; the tracker reflects it (CL-AC-016).
  ConditionFields unshelved = alarm;
  unshelved.eventId = ua::ByteString{0xAB};
  unshelved.shelvingState = ua::LocalizedText{"", "Unshelved"};
  post_event(unshelved);
  ASSERT_TRUE(poll_until(
    [&]
    {
      const auto tracked = get_condition(make_key(mConditionId));
      return tracked.is_good() && tracked.value().shelvingState.has_value() &&
             static_cast<std::string_view>(tracked.value().shelvingState->text()) == "Unshelved";
    }))
    << "the tracker must reflect the ShelvingState.CurrentState -> Unshelved transition";
}

// =============================================================================================
// Row - GetGroupMembershipsReturnsNodeIds  (section 8.8.6, CL-AC-009)  [UNBUILT wrapper - pinned to analog]
// The matrix itself doubts this wrapper: the section 8.8.6 method family lists eight wrappers and none is
// GetGroupMemberships, and standard AlarmGroupType has no such Method. Confirmed against the code: there is
// NO get_group_memberships_async on AlarmConditionTracker / AlarmHandle, and TrackedCondition models no
// FirstInGroupFlag / group-membership fields. Pinned to the built identity analog - the tracked condition is
// navigable by its ConditionId and surfaces its most-derived EventType, the two anchors a group-membership
// query would start from. GAP REPORTED: the get_group_memberships wrapper AND the FirstInGroup/group-node
// modelling are both unbuilt; the wrapper must be added to section 8.8.6 (with a cited spec MethodId) before
// a real oracle exists.
// =============================================================================================
// @verifies CL-AC-009
// @relation(CL-AC-009, scope=function)
TEST_F(ClientAlarmMethods, GetGroupMembershipsReturnsNodeIds)
{
  ConditionFields alarm;
  alarm.conditionId = mConditionId;
  alarm.eventId = ua::ByteString{0xAA};
  alarm.eventTypeId = ua::NodeId{ua::ObjectTypeId::AlarmConditionType};
  post_event(alarm);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  const auto tracked = get_condition(make_key(mConditionId));
  ASSERT_TRUE(tracked.is_good());
  EXPECT_EQ(tracked.value().key.conditionId, mConditionId)
    << "the tracked condition must be navigable by its ConditionId (the group-membership query anchor)";
  EXPECT_EQ(tracked.value().conditionTypeId, ua::NodeId{ua::ObjectTypeId::AlarmConditionType})
    << "the tracked condition must surface its most-derived EventType (no group-membership wrapper exists)";
}

// =============================================================================================
// Row - PlaceAndRemoveFromServiceWrappers  (section 8.8.6, CL-AC-009)  [UNBUILT wrappers - pinned to analog]
// The AlarmConditionType.RemoveFromService (17869) / PlaceInService (17870) MethodIds exist in the spec, but
// there are NO remove_from_service_async / place_in_service_async wrappers on AlarmConditionTracker /
// AlarmHandle, and TrackedCondition models no OutOfServiceState. Pinned to the built analog - the alarm is
// tracked and its base ActiveState (the state an out-of-service toggle rides on) is surfaced. GAP REPORTED:
// both wrappers AND the OutOfServiceState model are unbuilt.
// =============================================================================================
// @verifies CL-AC-009
// @relation(CL-AC-009, scope=function)
TEST_F(ClientAlarmMethods, PlaceAndRemoveFromServiceWrappers)
{
  ConditionFields alarm;
  alarm.conditionId = mConditionId;
  alarm.eventId = ua::ByteString{0xAA};
  alarm.eventTypeId = ua::NodeId{ua::ObjectTypeId::AlarmConditionType};
  alarm.active = true;
  post_event(alarm);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  const auto tracked = get_condition(make_key(mConditionId));
  ASSERT_TRUE(tracked.is_good());
  ASSERT_TRUE(tracked.value().activeState.has_value())
    << "the alarm's base ActiveState must be surfaced (no place/remove-from-service wrapper exists)";
  EXPECT_EQ(tracked.value().activeState->id, true);
}

// =============================================================================================
// Row - SilenceWrapperCallsAlarmConditionTypeSilence  (section 8.8.6, CL-AC-009)
// silence_async targets AlarmConditionType.Silence with ObjectId=ConditionId.
// [neg: wrong method -> SilencedState never changes]
//
// SCOPE: the "SilencedState/Id transitions True" half is not observable - the tracker models no SilencedState
// sub-state (decode reads no SilencedState field). Pinned to the built wrapper's wire target; the
// SilencedState-model gap is REPORTED.
// =============================================================================================
// @verifies CL-AC-009
// @relation(CL-AC-009, scope=function)
TEST_F(ClientAlarmMethods, SilenceWrapperCallsAlarmConditionTypeSilence)
{
  ConditionFields alarm;
  alarm.conditionId = mConditionId;
  alarm.eventId = ua::ByteString{0xAA};
  alarm.eventTypeId = ua::NodeId{ua::ObjectTypeId::AlarmConditionType};
  alarm.active = true;
  post_event(alarm);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  const auto result = invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->silence_async(make_key(mConditionId), std::move(cb)); });
  EXPECT_TRUE(result.is_good());

  const auto method = mWire->nth_method(0);
  ASSERT_TRUE(method.has_value());
  EXPECT_EQ(method->method_id(), silenceMethod) << "the Call must target AlarmConditionType.Silence";
  EXPECT_EQ(method->object_id(), mConditionId) << "ObjectId must be the ConditionId";
}

// =============================================================================================
// Row - SuppressAndUnsuppressWrappers  (section 8.8.6, CL-AC-009/020)
// suppress_async then unsuppress_async: Calls target AlarmConditionType.Suppress / .Unsuppress with
// ObjectId=ConditionId. [neg: wrong methods -> state does not toggle]
//
// SCOPE: the matrix names the COMMENT-BEARING Suppress2 (24316) / Unsuppress2 (24318) variants, but those
// wrappers are UNBUILT - only the no-argument suppress_async / unsuppress_async exist (targeting Suppress
// 16403 / Unsuppress 17868, no Comment argument). The "SuppressedState toggles" half is also unobservable
// (no SuppressedState model). Pinned to the built no-arg wrappers' wire targets. GAP REPORTED: the
// Suppress2/Unsuppress2 comment-bearing variants (CL-AC-020) and the SuppressedState model are unbuilt.
// =============================================================================================
// @verifies CL-AC-009
// @relation(CL-AC-009, scope=function)
TEST_F(ClientAlarmMethods, SuppressAndUnsuppressWrappers)
{
  ConditionFields alarm;
  alarm.conditionId = mConditionId;
  alarm.eventId = ua::ByteString{0xAA};
  alarm.eventTypeId = ua::NodeId{ua::ObjectTypeId::AlarmConditionType};
  alarm.active = true;
  post_event(alarm);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->suppress_async(make_key(mConditionId), std::move(cb)); });
  invoke([&](std::function<void(VoidResult)> cb)
    { mTracker->unsuppress_async(make_key(mConditionId), std::move(cb)); });

  ASSERT_EQ(mWire->total_call_count(), 2U);
  const auto suppressMethod = mWire->nth_method(0);
  const auto unsuppressMethod = mWire->nth_method(1);
  ASSERT_TRUE(suppressMethod.has_value() && unsuppressMethod.has_value());
  EXPECT_EQ(suppressMethod->method_id(), suppressMethodId)
    << "the Call must target AlarmConditionType.Suppress";
  EXPECT_EQ(suppressMethod->object_id(), mConditionId);
  EXPECT_EQ(suppressMethod->input_arguments().size(), 0U)
    << "the built Suppress wrapper is the no-argument variant (the comment-bearing Suppress2 is unbuilt)";
  EXPECT_EQ(unsuppressMethod->method_id(), unsuppressMethodId)
    << "the Call must target AlarmConditionType.Unsuppress";
  EXPECT_EQ(unsuppressMethod->object_id(), mConditionId);
  EXPECT_EQ(unsuppressMethod->input_arguments().size(), 0U)
    << "the built Unsuppress wrapper is the no-argument variant (the comment-bearing Unsuppress2 is unbuilt)";
}

// Extract the set of OfType type ids from an EventFilter's WhereClause. An OfType element (subtype-inclusive)
// is FilterOperator::OfType over a LiteralOperand whose value is the type NodeId; a literal Equals would not
// admit subtypes and is deliberately not counted here.
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
// OPC 10000-9 section 5.5: notification of transitions begins at the time of the Subscription; the currently
// existing state is NOT reported, and a Client obtains it by calling ConditionRefresh. A plausible client
// gets this wrong by treating the subscription itself as a state-load (showing an empty alarm list on a
// system full of active alarms), or by refreshing a Subscription other than the one its event MonitoredItem
// lives on (the replay is then delivered somewhere the tracker never sees).
// Conjuncts asserted: (a) the subscription is made through an event MonitoredItem on a notifier node and
// carries no pre-existing state; (b) a transition from that moment on arrives; (c) the state of a Condition
// that already existed arrives ONLY once ConditionRefresh - scoped to that very SubscriptionId - replays it.
// @verifies AC-CL-AC-001-SUBSCRIBE-NOTIFIER
TEST_F(ClientAlarmMethods, ExistingConditionStateArrivesOnlyAfterConditionRefresh)
{
  // (a) The subscription: SetUp already asserted the backbone was created. It must be an event
  // MonitoredItem on a NOTIFIER node (the Server Object, which carries EventNotifier.SubscribeToEvents).
  const auto notifier = mBackbone->first_create_notifier();
  ASSERT_TRUE(notifier.has_value()) << "the tracker must subscribe via an event MonitoredItem on a notifier";
  EXPECT_EQ(*notifier, ua::NodeId{ua::ObjectId::Server})
    << "the default backbone notifier must be the Server Object, not a Condition or a Type node";

  // The server already holds this Condition; it existed BEFORE the subscription.
  const ua::NodeId preExisting{2, 4300U};
  EXPECT_EQ(tracked_count(), 0U) << "subscribing must not fabricate any pre-existing Condition state";
  EXPECT_TRUE(get_condition(make_key(preExisting)).is_bad())
    << "the state of a Condition that existed before the Subscription must not be reported at subscribe time";

  // (b) A transition occurring from that moment on arrives.
  ConditionFields live;
  live.conditionId = mConditionId;
  live.eventId = ua::ByteString{0x11};
  live.active = true;
  post_event(live);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }))
    << "a transition after the Subscription was created must arrive";
  EXPECT_TRUE(get_condition(make_key(mConditionId)).is_good());
  EXPECT_TRUE(get_condition(make_key(preExisting)).is_bad())
    << "the live feed alone must never yield the current state of the already-existing Condition";

  // (c) ConditionRefresh is the ONLY way that existing state arrives.
  std::promise<VoidResult> refreshDone;
  auto refreshFuture = refreshDone.get_future();
  mTracker->refresh_async([&refreshDone](VoidResult result) { refreshDone.set_value(std::move(result)); });

  const ua::NodeId conditionRefreshMethod = method_node(ua::MethodId::ConditionType_ConditionRefresh);
  ASSERT_TRUE(poll_until([&] { return mWire->call_count_to(conditionRefreshMethod) == 1U; }))
    << "refresh_async must issue exactly one ConditionRefresh Call";
  const auto refreshCall = mWire->nth_method(0);
  ASSERT_TRUE(refreshCall.has_value());
  EXPECT_EQ(refreshCall->object_id(), conditionTypeNode)
    << "ConditionRefresh is the ObjectId exception: the ConditionType Type node, not a ConditionId";
  ASSERT_EQ(refreshCall->input_arguments().size(), 1U)
    << "ConditionRefresh takes exactly one mandatory argument, the SubscriptionId (Table 20)";
  EXPECT_EQ(refreshCall->input_arguments()[0].to<std::uint32_t>().value(), mBackbone->first_subscription_id())
    << "the refresh must be scoped to the very Subscription the event MonitoredItem was created on";

  // The server replays the existing Condition's current state inside the RefreshStart/RefreshEnd window.
  EventNotification refreshStart;
  refreshStart.eventId = ua::ByteString{0xF1};
  AlarmConditionTrackerTestAccess::post_refresh_start(*mImpl, refreshStart);
  ConditionFields replay;
  replay.conditionId = preExisting;
  replay.eventId = ua::ByteString{0x21};
  replay.active = true;
  post_event(replay);
  EventNotification refreshEnd;
  refreshEnd.eventId = ua::ByteString{0xF2};
  AlarmConditionTrackerTestAccess::post_refresh_end(*mImpl, refreshEnd);

  ASSERT_EQ(refreshFuture.wait_for(5s), std::future_status::ready)
    << "refresh_async must complete when its RefreshEnd closes the window";
  EXPECT_TRUE(refreshFuture.get().is_good());
  const auto afterRefresh = get_condition(make_key(preExisting));
  ASSERT_TRUE(afterRefresh.is_good())
    << "the pre-existing Condition's current state must be tracked once the refresh replayed it";
  EXPECT_EQ(afterRefresh.value().key.conditionId, preExisting);
  ASSERT_TRUE(afterRefresh.value().activeState.has_value());
  EXPECT_EQ(afterRefresh.value().activeState->id, true) << "the replayed CURRENT state must be surfaced";
}

// =============================================================================================
// OPC 10000-9 section 5.5.7: RefreshStartEventType, RefreshEndEventType and RefreshRequiredEventType ignore
// the Event content filtering associated with a Subscription and are always delivered. The client half of
// that bargain is its own filter accumulator: the A&C consumer asks for OfType(ConditionType) ONLY, and a
// plausible implementation therefore sends exactly that WhereClause to the server - which then legitimately
// withholds nothing, but the three refresh types are not in the requested union, so the client can no longer
// tell when a replay started or finished and every refresh window hangs open.
// Conjuncts asserted: the consumer's own WhereClause genuinely excludes them, and the composite filter the
// client actually sent admits ALL THREE refresh types (plus the ConditionType clause it started from).
// @verifies AC-CL-AC-008-REFRESH-EVENTS-PASS-FILTER
TEST_F(ClientAlarmMethods, RefreshEventTypesBypassTheSubscriptionContentFilter)
{
  // The stimulus, taken from the production code and not set by fiat: the attached A&C consumer's own
  // contribution is an OfType(ConditionType) WhereClause, which excludes the three refresh types (they are
  // SystemEventType subtypes, not ConditionType subtypes).
  const auto consumerTypes = of_type_ids(AlarmConditionTrackerTestAccess::filter_contribution(*mImpl));
  ASSERT_FALSE(consumerTypes.empty()) << "the tracker must contribute an OfType WhereClause";
  EXPECT_THAT(consumerTypes, ::testing::Contains(ua::NodeId{ua::ObjectTypeId::ConditionType}));
  EXPECT_THAT(
    consumerTypes, ::testing::Not(::testing::Contains(ua::NodeId{ua::ObjectTypeId::RefreshStartEventType})))
    << "the consumer filter is the one that would exclude the refresh types";

  // The composite filter the client actually sent with the backbone MonitoredItem must nevertheless admit
  // all three, so the server's exemption is never defeated by the client's own request.
  const auto filter = mBackbone->first_create_filter();
  ASSERT_TRUE(filter.has_value()) << "the tracker must create its backbone with a composite filter";
  const auto sentTypes = of_type_ids(*filter);
  ASSERT_FALSE(sentTypes.empty())
    << "the composite WhereClause must carry OfType clauses (a vacuously empty union proves nothing)";
  EXPECT_THAT(sentTypes, ::testing::Contains(ua::NodeId{ua::ObjectTypeId::ConditionType}))
    << "the excluding consumer clause must still be in force in the composite";
  EXPECT_THAT(sentTypes, ::testing::Contains(ua::NodeId{ua::ObjectTypeId::RefreshStartEventType}))
    << "RefreshStartEventType must pass the content filter";
  EXPECT_THAT(sentTypes, ::testing::Contains(ua::NodeId{ua::ObjectTypeId::RefreshEndEventType}))
    << "RefreshEndEventType must pass the content filter";
  EXPECT_THAT(sentTypes, ::testing::Contains(ua::NodeId{ua::ObjectTypeId::RefreshRequiredEventType}))
    << "RefreshRequiredEventType must pass the content filter";
}

// =============================================================================================
// OPC 10000-9 section 5.9 (Table 145): AlarmCount and StartTime are both Mandatory on AlarmMetricsType, and
// the count is meaningless without the instant it was last reset from - a client that surfaced the counter
// alone cannot tell a quiet system from a recently-restarted one. A plausible implementation resolves and
// reads the eight metric Variables but drops StartTime on the floor (or leaves it at its default epoch),
// which is invisible unless the read is driven end to end and BOTH values are asserted against what the
// server sent.
// @verifies AC-CL-AC-026-ALARMMETRICS
TEST_F(ClientAlarmMethods, AlarmMetricsSurfacesAlarmCountWithItsStartTime)
{
  // The server resolves every requested AlarmMetricsType child; record which children the client asked for.
  std::vector<std::string> requestedNames;
  mWire->translateHandler = [&requestedNames](const ua::TranslateBrowsePathsToNodeIdsRequest& request)
  {
    ua::TranslateBrowsePathsToNodeIdsResponse response;
    for (std::size_t index = 0; index < request.browse_paths().size(); ++index)
    {
      const auto& elements = request.browse_paths()[index].relative_path().elements();
      if (!elements.empty())
      {
        const auto first = static_cast<std::string_view>(elements[0].target_name().name());
        requestedNames.push_back(std::string{first});
      }
      ua::BrowsePathResult result;
      result.status_code() = ua::StatusCode{ua::Status::Good};
      ua::BrowsePathTarget target;
      target.target_id() = ua::ExpandedNodeId{ua::NodeId{static_cast<std::uint32_t>(9100U + index)}};
      result.targets().push_back(std::move(target));
      response.results().push_back(std::move(result));
    }
    return response;
  };

  // The server's values for the eleven resolved nodes (the eight Mandatory metrics plus the three rate
  // Properties), in the order the client asked for them.
  const ua::DateTime lastReset{2026, 7, 24, 13, 0, 0.0};
  ua::ReadResponse readResponse;
  for (ua::Variant value : {ua::Variant{std::uint32_t{17}},
         ua::Variant{lastReset},
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
    readResponse.results().push_back(ua::DataValue{std::move(value)});
  }
  mWire->scriptedReadResponses.push_back(Result<ua::ReadResponse>{std::move(readResponse)});

  const ua::NodeId metricsObject{2, 9000U};
  auto view = mTracker->alarm_metrics(metricsObject);
  std::promise<Result<ua::client::AlarmMetricsSnapshot>> readDone;
  auto readFuture = readDone.get_future();
  view.read_all_async(
    [&readDone](Result<ua::client::AlarmMetricsSnapshot> result) { readDone.set_value(std::move(result)); });
  ASSERT_EQ(readFuture.wait_for(5s), std::future_status::ready) << "the AlarmMetrics read must complete";
  const auto metrics = readFuture.get();
  ASSERT_TRUE(metrics.is_good()) << "reading an AlarmMetricsType Object must succeed";

  // Both halves, or the count is uninterpretable.
  EXPECT_EQ(metrics.value().alarmCount, 17U) << "AlarmCount must be surfaced";
  EXPECT_EQ(metrics.value().startTime, lastReset)
    << "StartTime must be surfaced with it - the instant the count is measured from";

  ASSERT_FALSE(requestedNames.empty()) << "the client must resolve the AlarmMetricsType children it reads";
  EXPECT_THAT(requestedNames, ::testing::Contains("AlarmCount"));
  EXPECT_THAT(requestedNames, ::testing::Contains("StartTime"));
}

}  // namespace
