// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientConditionRefresh cluster of the client integration-test matrix (the 17
///        `ClientConditionRefresh.*` rows).
///
/// COMPANION: `client_alarm_live_server_tests.cpp` runs the same surface against a REAL server. These
/// rows keep what only an interface can hold - the wire ARGUMENTS a wrapper builds, server misbehaviour a
/// conforming server will not produce, and branches this server does not emit. What a live server can
/// decide is asserted there, because a fake agrees with whatever the client sends it.
///
/// These exercise the ConditionRefresh window state machine of the TIER-2 Alarm & Condition tracker
/// (`ua::client::detail::AlarmConditionTrackerImpl`, client design section 8.8.3/section 8.8.4) as a LIVE
/// component: a REAL `EventSubscriberImpl` + tracker are built over the mockable interfaces (a thread-safe
/// recording event backbone + a thread-safe recording `WireOps` for the `ConditionRefresh` Method Call) on a
/// REAL `boost::asio::thread_pool`. The tracker's OWN refresh demultiplexer - the `mActiveRefreshWindows`
/// EventId-keyed window set, the `mUseRefresh2` fallback latch, the `mPendingFollowOnRefresh` serializer,
/// and the CL-AC-005 replay-merge guard - is driven through its on-strand hook entry points (the
/// `AlarmConditionTrackerTestAccess` interface posts them onto the tracker's strand exactly as the
/// subscriber's Publish dispatch would deliver RefreshStart/RefreshEnd/RefreshRequired boundary events +
/// replayed condition events). Every assertion is made through a cross-strand-safe observable: the `WireOps`
/// call log (which ConditionRefresh Method Calls appeared, in order), the atomic `info()` snapshot
/// (openRefreshWindowCount / useRefresh2 / pendingFollowOnRefresh / trackedConditionCount), the public
/// `refresh_async` completion callback, and the added/changed/removed observers.
///
/// Why the hook interface and not a real server: control over event CONTENT and ORDER. These rows drive
/// overlapping refresh windows, duplicate per-Notifier copies of one RefreshEnd, and replays whose
/// ReceiveTime is deliberately older than a live event - none of which a conforming server can be asked
/// to produce on demand. The interface feeds the tracker the SAME `EventNotification` the subscriber's decode
/// would, so the tracker's real refresh logic is exercised precisely and falsifiably. The end-to-end path
/// those events stand in for is covered live in `client_alarm_live_server_tests.cpp`.
///
/// Falsifiability: every test encodes its matrix row's `[neg: ...]` falsifier - it fails if the named
/// behaviour regresses. The redundancy rows drive the event subsystem's real recovered-switch entry point
/// and assert through the public tier-2 tracker plus the wire log; only a full cross-server transport switch
/// remains outside this focused fixture. The reconnect row similarly pins its reachable subsystem boundary.
/// No test skips itself.
///
/// Timing: refresh is subscription-driven and delivered asynchronously on the executor, so every wait is
/// BOUNDED POLLING on a thread-safe observable (never a fixed sleep). All fakes are thread-safe.

#include "fake_connection_ops.h"
#include "test_utilities.h"

#include "ua_alarm_condition_tracker.h"
#include "ua_alarm_condition_tracker_impl.h"
#include "ua_alarm_condition_tracker_test_access.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_event_backbone_ops.h"
#include "ua_event_subscriber_impl.h"

#include "ua_byte_string.h"
#include "ua_date_time.h"
#include "ua_event_filter.h"
#include "ua_localized_text.h"
#include "ua_logger.h"
#include "ua_method_id.h"
#include "ua_node_id.h"
#include "ua_objecttype_id.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <atomic>
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

const ua::NodeId refreshMethodId{static_cast<std::uint32_t>(ua::MethodId::ConditionType_ConditionRefresh)};
const ua::NodeId refresh2MethodId{static_cast<std::uint32_t>(ua::MethodId::ConditionType_ConditionRefresh2)};
const ua::NodeId conditionTypeNode{ua::ObjectTypeId::ConditionType};

// ---------------------------------------------------------------------------------------------
// Thread-safe event-backbone interface: replies Good so the tracker attaches + creates its default Server
// backbone (the ConditionRefresh rows do not assert the filter - that is the ClientAlarmTracker slice).
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
// Thread-safe recording WireOps: records every ConditionRefresh Method Call (so a test can assert which
// well-known Method appeared, in order) and answers each with a per-method scriptable status (default
// Good). Runs on the tracker's pool threads, so all state is mutex-guarded.
// ---------------------------------------------------------------------------------------------
class RecordingRefreshWireOps : public ua::test_helpers::FakeWireOps
{
public:
  // Sets (replacing any prior entry) the per-method CallMethodResult status a subsequent Call to @p methodId
  // is answered with. Replace semantics let a test flip a method from Bad back to Good mid-run.
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

  std::optional<ua::CallRequest> nth_call(std::size_t index) const
  {
    std::lock_guard lock(mMutex);
    if (index >= mCalls.size())
    {
      return std::nullopt;
    }
    return mCalls[index];
  }

private:
  mutable std::mutex mMutex;
  std::vector<ua::CallRequest> mCalls;
  std::vector<std::pair<ua::NodeId, ua::StatusCode>> mMethodStatus;
};

// ---------------------------------------------------------------------------------------------
// Condition-event builder (by-name field model the tracker's decode reads). `receiveTime` is the CL-AC-005
// replay-merge ordering source; `severity` is a cheap distinguishing "changed" field.
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
  std::uint16_t severity = 100;
  ua::DateTime receiveTime{};
  std::optional<bool> active;
};

// A single-segment leaf field (the node's Value: BranchId, Retain).
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

EventNotification make_condition_event(const ConditionFields& fields)
{
  EventNotification event;
  event.eventTypeId = ua::NodeId{ua::ObjectTypeId::ConditionType};
  event.eventId = fields.eventId;
  event.severity = fields.severity;
  event.receiveTime = fields.receiveTime;
  add_condition_id(event, fields.conditionId);
  add_field(event, "BranchId", ua::Variant{fields.branchId});
  add_field(event, "Retain", ua::Variant{fields.retain});
  if (fields.active.has_value())
  {
    add_state_field(event, "ActiveState", *fields.active);
  }
  return event;
}

EventNotification make_boundary_event(ua::ByteString eventId)
{
  EventNotification event;
  event.eventId = std::move(eventId);
  return event;
}

TrackedKey make_key(const ua::NodeId& conditionId, ua::NodeId branchId = {})
{
  TrackedKey key;
  key.conditionId = conditionId;
  key.branchId = std::move(branchId);
  return key;
}

// Thread-safe capture of the refresh_async completion(s): count + the delivered VoidResults.
struct RefreshSlot
{
  mutable std::mutex mutex;
  int completions = 0;
  std::vector<VoidResult> results;

  int count() const
  {
    std::lock_guard lock(mutex);
    return completions;
  }

  VoidResult last() const
  {
    std::lock_guard lock(mutex);
    return results.empty() ? VoidResult{} : results.back();
  }
};

// Thread-safe observer capture.
struct ObserverLog
{
  mutable std::mutex mutex;
  int added = 0;
  int changed = 0;
  int removed = 0;

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
// Fixture: one gtest suite `ClientConditionRefresh` (tests named exactly `ClientConditionRefresh.<Row>`).
// Owns a real thread pool + fakes; each test wires the tracker via `attach(policy)` so refresh-policy
// variation (preferConditionRefresh2) is per-test.
// ---------------------------------------------------------------------------------------------
class ClientConditionRefresh : public ::testing::Test
{
protected:
  void attach(AlarmConditionTrackerPolicy policy = {})
  {
    mSubscriber = EventSubscriberImpl::create(mPool.get_executor(), mBackbone, ua::Logger{});
    mImpl = mSubscriber->ensure_alarm_tracker(mWire, policy);
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

  void refresh_async_into(RefreshSlot& slot)
  {
    mImpl->refresh_async(
      [&slot](VoidResult result)
      {
        std::lock_guard lock(slot.mutex);
        ++slot.completions;
        slot.results.push_back(std::move(result));
      });
  }

  void post_event(const ConditionFields& fields)
  {
    AlarmConditionTrackerTestAccess::post_event(*mImpl, make_condition_event(fields));
  }

  void post_refresh_start(ua::ByteString eventId)
  {
    AlarmConditionTrackerTestAccess::post_refresh_start(*mImpl, make_boundary_event(std::move(eventId)));
  }

  void post_refresh_end(ua::ByteString eventId)
  {
    AlarmConditionTrackerTestAccess::post_refresh_end(*mImpl, make_boundary_event(std::move(eventId)));
  }

  void post_refresh_required()
  {
    AlarmConditionTrackerTestAccess::post_refresh_required(*mImpl, make_boundary_event(ua::ByteString{}));
  }

  void post_first_event_after_attach()
  {
    AlarmConditionTrackerTestAccess::post_first_event_after_attach(*mImpl);
  }

  std::size_t tracked_count()
  {
    return mImpl->info()->trackedConditionCount;
  }

  std::size_t open_window_count()
  {
    return mImpl->info()->openRefreshWindowCount;
  }

  bool use_refresh2()
  {
    return mImpl->info()->useRefresh2;
  }

  bool pending_follow_on()
  {
    return mImpl->info()->pendingFollowOnRefresh;
  }

  Result<TrackedCondition> get_condition(const TrackedKey& key)
  {
    std::promise<Result<TrackedCondition>> promise;
    auto future = promise.get_future();
    mTracker->get_condition_async(
      key, [&promise](Result<TrackedCondition> result) { promise.set_value(std::move(result)); });
    EXPECT_EQ(future.wait_for(5s), std::future_status::ready) << "get_condition_async did not complete";
    return future.get();
  }

  void install_observers()
  {
    await_registration(
      [&](std::function<void(VoidResult)> done)
      {
        mTracker->on_condition_added_async(
          [this](const TrackedCondition&)
          {
            std::lock_guard lock(mLog.mutex);
            ++mLog.added;
          },
          std::move(done));
      });
    await_registration(
      [&](std::function<void(VoidResult)> done)
      {
        mTracker->on_condition_changed_async(
          [this](const TrackedCondition&)
          {
            std::lock_guard lock(mLog.mutex);
            ++mLog.changed;
          },
          std::move(done));
      });
    await_registration(
      [&](std::function<void(VoidResult)> done)
      {
        mTracker->on_condition_removed_async(
          [this](TrackedKey)
          {
            std::lock_guard lock(mLog.mutex);
            ++mLog.removed;
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

  boost::asio::thread_pool mPool{2};
  std::shared_ptr<RecordingBackboneOps> mBackbone = std::make_shared<RecordingBackboneOps>();
  std::shared_ptr<RecordingRefreshWireOps> mWire = std::make_shared<RecordingRefreshWireOps>();
  std::shared_ptr<EventSubscriberImpl> mSubscriber;
  std::shared_ptr<AlarmConditionTrackerImpl> mImpl;
  std::optional<AlarmConditionTracker> mTracker;
  ObserverLog mLog;

  const ua::NodeId mConditionId{2, 4242U};
};

// =============================================================================================
// DuplicateRefreshStartEventIdOpensOneWindow  (CL-AC-004, section 8.8.4)
// Two RefreshStart copies with an identical EventId (N Notifier MIs in one Subscription) open exactly ONE
// window, and refresh_async's callback fires exactly once on the single RefreshEnd.
// [neg: duplicate boundary events must dedupe by EventId]
// =============================================================================================
// @verifies CL-AC-004
// @relation(CL-AC-004, scope=function)
TEST_F(ClientConditionRefresh, DuplicateRefreshStartEventIdOpensOneWindow)
{
  attach();
  RefreshSlot slot;
  refresh_async_into(slot);
  ASSERT_TRUE(poll_until([&] { return mWire->call_count_to(refreshMethodId) >= 1; }))
    << "refresh_async must issue a ConditionRefresh Call";

  const ua::ByteString eventId{0xE1};
  post_refresh_start(eventId);
  post_refresh_start(eventId);  // duplicate EventId - must dedupe
  ASSERT_TRUE(poll_until([&] { return open_window_count() == 1; }))
    << "duplicate RefreshStart EventIds must open exactly one window";
  EXPECT_EQ(slot.count(), 0) << "the window is open - refresh must not have completed yet";

  post_refresh_end(eventId);
  ASSERT_TRUE(poll_until([&] { return slot.count() == 1; }))
    << "the single RefreshEnd must complete the refresh exactly once";
  EXPECT_TRUE(slot.last().is_good());
  EXPECT_EQ(mWire->call_count_to(refreshMethodId), 1U) << "only one trigger - no second Call";
}

// =============================================================================================
// RefreshUsesWellKnownConditionTypeNodeIds  (CL-AC-011, section 8.8.4)
// The ConditionRefresh Call uses ObjectId = ConditionType (NS=0) and MethodId =
// ConditionType.ConditionRefresh, with no preceding Browse.
// [neg: refresh is the exception: Type-node ObjectId, no browse]
// =============================================================================================
// @verifies CL-AC-011
// @relation(CL-AC-011, scope=function)
TEST_F(ClientConditionRefresh, RefreshUsesWellKnownConditionTypeNodeIds)
{
  attach();
  RefreshSlot slot;
  refresh_async_into(slot);
  ASSERT_TRUE(poll_until([&] { return mWire->total_call_count() >= 1; }))
    << "refresh_async must issue a Call";

  const auto call = mWire->nth_call(0);
  ASSERT_TRUE(call.has_value());
  ASSERT_EQ(call->methods_to_call().size(), 1U);
  EXPECT_EQ(call->methods_to_call()[0].object_id(), conditionTypeNode)
    << "ObjectId must be the ConditionType Type-node (CL-AC-011 exception), not a ConditionId";
  EXPECT_EQ(call->methods_to_call()[0].method_id(), refreshMethodId)
    << "MethodId must be ConditionType.ConditionRefresh";
  EXPECT_TRUE(mWire->browseRequests.empty()) << "the refresh must not browse for the method";
}

// =============================================================================================
// DistinctRefreshStartEventIdsCloseIndependently  (CL-AC-004, section 8.8.4)
// Two overlapping refresh cycles with distinct EventIds open two windows; the aggregate refresh completes
// only after BOTH RefreshEnds arrive.
// [neg: overlapping distinct-EventId windows - a single bool/counter reset on the first end completes early]
// =============================================================================================
// @verifies CL-AC-004
// @relation(CL-AC-004, scope=function)
TEST_F(ClientConditionRefresh, DistinctRefreshStartEventIdsCloseIndependently)
{
  attach();
  RefreshSlot slot;
  refresh_async_into(slot);
  ASSERT_TRUE(poll_until([&] { return mWire->call_count_to(refreshMethodId) >= 1; }));

  const ua::ByteString e1{0xE1};
  const ua::ByteString e2{0xE2};
  post_refresh_start(e1);
  post_refresh_start(e2);
  ASSERT_TRUE(poll_until([&] { return open_window_count() == 2; }))
    << "two distinct RefreshStart EventIds must open two independent windows";

  post_refresh_end(e1);
  ASSERT_TRUE(poll_until([&] { return open_window_count() == 1; }));
  EXPECT_EQ(slot.count(), 0)
    << "completion must wait for BOTH RefreshEnds - not fire after the first (single-counter bug)";

  post_refresh_end(e2);
  ASSERT_TRUE(poll_until([&] { return slot.count() == 1; }))
    << "the refresh completes only after the last window closes";
  EXPECT_TRUE(slot.last().is_good());
  EXPECT_EQ(open_window_count(), 0U);
}

// =============================================================================================
// RefreshCallBadPropagatesNoRetry  (CL-AC-011, section 8.8.7)
// A non-Bad_MethodInvalid Bad (Bad_UserAccessDenied) on the ConditionRefresh Call surfaces verbatim to
// refresh_async's callback, the state machine stays Idle, and no retry Call is emitted.
// [neg: non-fallback refresh error must surface without retry]
// =============================================================================================
// @verifies CL-AC-011
// @relation(CL-AC-011, scope=function)
TEST_F(ClientConditionRefresh, RefreshCallBadPropagatesNoRetry)
{
  attach();  // default policy: legacy ConditionRefresh
  mWire->set_method_status(refreshMethodId, StatusCode{Status::BadUserAccessDenied});

  RefreshSlot slot;
  refresh_async_into(slot);
  ASSERT_TRUE(poll_until([&] { return slot.count() == 1; }))
    << "a non-fallback Bad Call must complete refresh_async (not hang)";
  EXPECT_EQ(slot.last().status_code().as_uint32(), StatusCode{Status::BadUserAccessDenied}.as_uint32())
    << "the Bad status must surface verbatim";
  EXPECT_EQ(mWire->call_count_to(refreshMethodId), 1U) << "no retry Call on a non-MethodInvalid Bad";

  // Idle, not wedged: a subsequent refresh is ACCEPTED and issues a fresh Call.
  mWire->set_method_status(refreshMethodId, StatusCode{Status::Good});
  RefreshSlot second;
  refresh_async_into(second);
  ASSERT_TRUE(poll_until([&] { return mWire->call_count_to(refreshMethodId) == 2; }))
    << "after a Bad trigger the machine returns to Idle - the next refresh issues a fresh Call";
}

// =============================================================================================
// Refresh2FallsBackToRefreshOnBadMethodInvalid  (CL-AC-012, section 8.8.4)
// With policy preferConditionRefresh2, a Bad_MethodInvalid on ConditionRefresh2 falls back to a legacy
// ConditionRefresh Call and a window opens (not a Bad completion).
// [neg: Bad_MethodInvalid must fall back, not fail]
// =============================================================================================
// @verifies CL-AC-012
// @relation(CL-AC-012, scope=function)
TEST_F(ClientConditionRefresh, Refresh2FallsBackToRefreshOnBadMethodInvalid)
{
  AlarmConditionTrackerPolicy policy;
  policy.preferConditionRefresh2 = true;
  attach(policy);
  ASSERT_TRUE(use_refresh2()) << "policy preferConditionRefresh2 must start the latch on";
  mWire->set_method_status(refresh2MethodId, StatusCode{Status::BadMethodInvalid});

  RefreshSlot slot;
  refresh_async_into(slot);
  ASSERT_TRUE(poll_until([&]
    { return mWire->call_count_to(refresh2MethodId) == 1 && mWire->call_count_to(refreshMethodId) == 1; }))
    << "Bad_MethodInvalid on Refresh2 must transparently retry as legacy ConditionRefresh";
  ASSERT_TRUE(poll_until([&] { return !use_refresh2(); })) << "the fallback must latch mUseRefresh2 off";
  EXPECT_EQ(slot.count(), 0) << "the fallback keeps the refresh alive until its RefreshEnd - not a Bad";

  const ua::ByteString e1{0xE1};
  post_refresh_start(e1);
  post_refresh_end(e1);
  ASSERT_TRUE(poll_until([&] { return slot.count() == 1; }));
  EXPECT_TRUE(slot.last().is_good()) << "the fallback refresh ultimately succeeds";
}

// =============================================================================================
// Refresh2FallbackDisablesForConnection  (CL-AC-012, section 8.8.4)
// After a fallback occurs, a second refresh on the same Connection calls ConditionRefresh directly with NO
// ConditionRefresh2 probe (the mUseRefresh2 latch persists).
// [neg: fallback latch persists for the Connection]
// =============================================================================================
// @verifies CL-AC-012
// @relation(CL-AC-012, scope=function)
TEST_F(ClientConditionRefresh, Refresh2FallbackDisablesForConnection)
{
  AlarmConditionTrackerPolicy policy;
  policy.preferConditionRefresh2 = true;
  attach(policy);
  mWire->set_method_status(refresh2MethodId, StatusCode{Status::BadMethodInvalid});

  // First refresh: Refresh2 probe -> Bad_MethodInvalid -> legacy fallback -> window closes.
  RefreshSlot first;
  refresh_async_into(first);
  ASSERT_TRUE(poll_until([&] { return !use_refresh2(); })) << "the first refresh must latch the fallback off";
  const ua::ByteString e1{0xE1};
  post_refresh_start(e1);
  post_refresh_end(e1);
  ASSERT_TRUE(poll_until([&] { return first.count() == 1; }));
  ASSERT_EQ(mWire->call_count_to(refresh2MethodId), 1U) << "exactly one Refresh2 probe so far";

  // Second refresh on the SAME Connection: legacy ConditionRefresh DIRECTLY, no new Refresh2 probe.
  RefreshSlot second;
  refresh_async_into(second);
  ASSERT_TRUE(poll_until([&] { return mWire->call_count_to(refreshMethodId) == 2; }))
    << "the second refresh must issue a fresh legacy ConditionRefresh";
  EXPECT_EQ(mWire->call_count_to(refresh2MethodId), 1U)
    << "the fallback latch persists - no wasted Refresh2 probe on the second cycle";
  const ua::ByteString e2{0xE2};
  post_refresh_start(e2);
  post_refresh_end(e2);
  ASSERT_TRUE(poll_until([&] { return second.count() == 1; }));
  EXPECT_TRUE(second.last().is_good());
}

// =============================================================================================
// RefreshIssuedOnInitialSubscribe  (CL-AC-003, section 8.8.3)
// The initial ConditionRefresh is gated on the first-event-after-attach signal (not fired prematurely); a
// pre-existing retained alarm is then delivered to on_condition_added via the refresh replay.
// [neg: initial refresh gated on first-event-after-attach, not fired prematurely]
//
// SCOPE: the full oracle drives a real ComplianceWithConditions server and observes the Call after the
// first Publish. `post_first_event_after_attach` IS the CL-AC-003 gate (the same on-strand hook the
// subscriber fires on the backbone MI's first Publish), so this exercises the real trigger-gating logic;
// the retained-alarm delivery is driven through the replay path the interface feeds.
// The CL-AC-003 RE-SYNC halves added this slice - re-issue ConditionRefresh after a session-CHANGED reconnect
// (scoped to the specifically-recreated backbones) AND after a lossy Republish gap that may have dropped a
// RefreshEnd - are comprehensively UNIT-covered (AlarmConditionTrackerRefresh.Reconnect* +
// SubscriptionsPipeline
// .*Loss* + EventRouterConnectionTest.WirePipelineWiresEventLossResyncCallback for the production wiring).
// The end-to-end reconnect/lossy-drain assertion awaits the reconnect harness this single-shot fixture lacks.
// =============================================================================================
// @verifies CL-AC-003
// @relation(CL-AC-003, scope=function)
TEST_F(ClientConditionRefresh, RefreshIssuedOnInitialSubscribe)
{
  attach();
  install_observers();

  EXPECT_EQ(mWire->call_count_to(refreshMethodId), 0U)
    << "no refresh before the first-event-after-attach gate";
  post_first_event_after_attach();
  ASSERT_TRUE(poll_until([&] { return mWire->call_count_to(refreshMethodId) >= 1; }))
    << "the initial refresh must issue once the first event after attach lands";

  const auto call = mWire->nth_call(0);
  ASSERT_TRUE(call.has_value());
  EXPECT_EQ(call->methods_to_call()[0].object_id(), conditionTypeNode);
  EXPECT_EQ(call->methods_to_call()[0].method_id(), refreshMethodId);

  // The standing retained alarm is delivered via the initial-refresh replay window.
  const ua::ByteString e1{0xE1};
  post_refresh_start(e1);
  ConditionFields retained;
  retained.conditionId = mConditionId;
  retained.eventId = ua::ByteString{0xAA};
  post_event(retained);
  post_refresh_end(e1);
  ASSERT_TRUE(poll_until([&] { return mLog.added_count() == 1; }))
    << "the pre-existing retained alarm must be surfaced via the initial-refresh replay";
}

// =============================================================================================
// RefreshRequiredEventTriggersRefresh  (CL-AC-007, section 8.8.4)
// With the tracker Idle, a RefreshRequiredEventType triggers a ConditionRefresh Call.
// [neg: the RefreshRequired route must not be unwired - else the tracker silently drifts out of sync]
//
// SCOPE: the matrix oracle also names `AlarmObserver::on_refresh_required` firing. That observer IS now wired
// (this slice fires it at the top of handle_refresh_required_on_strand, with conditionCount) and is
// comprehensively UNIT-covered
// (AlarmConditionTrackerRefresh.RefreshRequiredFiresObserverOnceWithTrackedCount... and
// ...WhileBusyFiresObserverWithoutDoubleIssue drive it through the real ObserverSink). This single-shot
// fixture creates the subscriber WITHOUT an ObserverSink, so the end-to-end observer-fire assertion awaits
// the tier-2 observer harness; the Call-emitted behaviour is what this tier-0 row pins.
// =============================================================================================
// @verifies CL-AC-007
// @relation(CL-AC-007, scope=function)
TEST_F(ClientConditionRefresh, RefreshRequiredEventTriggersRefresh)
{
  attach();
  EXPECT_EQ(mWire->call_count_to(refreshMethodId), 0U) << "idle - no refresh yet";
  post_refresh_required();
  ASSERT_TRUE(poll_until([&] { return mWire->call_count_to(refreshMethodId) >= 1; }))
    << "a RefreshRequired event while idle must emit a ConditionRefresh Call";
  EXPECT_EQ(mWire->call_count_to(refreshMethodId), 1U) << "exactly one refresh - not a storm";
}

// =============================================================================================
// RefreshRequiredWhileWindowOpenQueuesSingleFollowOn  (CL-AC-007, section 8.8.4)
// A RefreshRequired arriving while a window is open queues a single follow-on: no refresh is issued while
// the window is open; exactly one follow-on ConditionRefresh fires after the last RefreshEnd.
// [neg: refresh-while-pending must queue, not interleave (avoids the older-overwrites-newer hazard)]
// =============================================================================================
// @verifies CL-AC-007
// @relation(CL-AC-007, scope=function)
TEST_F(ClientConditionRefresh, RefreshRequiredWhileWindowOpenQueuesSingleFollowOn)
{
  attach();
  RefreshSlot slot;
  refresh_async_into(slot);
  ASSERT_TRUE(poll_until([&] { return mWire->call_count_to(refreshMethodId) == 1; }));

  const ua::ByteString e1{0xE1};
  post_refresh_start(e1);
  ASSERT_TRUE(poll_until([&] { return open_window_count() == 1; }));

  post_refresh_required();
  ASSERT_TRUE(poll_until([&] { return pending_follow_on(); }))
    << "RefreshRequired-while-open must set the pending-follow-on flag, not refresh now";
  EXPECT_EQ(mWire->call_count_to(refreshMethodId), 1U)
    << "no interleaved refresh Call while the window is open";

  post_refresh_end(e1);
  ASSERT_TRUE(poll_until([&] { return slot.count() == 1; }))
    << "the user refresh completes on its RefreshEnd";
  ASSERT_TRUE(poll_until([&] { return mWire->call_count_to(refreshMethodId) == 2; }))
    << "exactly one follow-on refresh fires after the last RefreshEnd";
  ASSERT_TRUE(poll_until([&] { return !pending_follow_on(); })) << "the follow-on flag is consumed";
  EXPECT_EQ(mWire->call_count_to(refreshMethodId), 2U) << "the follow-on is single - no refresh storm";
}

// =============================================================================================
// ServerInitiatedRefreshStartAcceptedWithoutPriorCall  (CL-AC-007, section 8.8.7)
// A RefreshStart with no preceding client ConditionRefresh Call (server-initiated) opens a window
// (Idle -> Window-open), applies the replay, and closes normally on the matching RefreshEnd.
// [neg: the tracker must accept a server-started refresh unprompted, not only ones it requested]
// =============================================================================================
// @verifies CL-AC-007
// @relation(CL-AC-007, scope=function)
TEST_F(ClientConditionRefresh, ServerInitiatedRefreshStartAcceptedWithoutPriorCall)
{
  attach();
  install_observers();

  const ua::ByteString e1{0xE1};
  post_refresh_start(e1);  // server-initiated - no client Call precedes it
  ASSERT_TRUE(poll_until([&] { return open_window_count() == 1; }))
    << "the tracker must accept a server-initiated refresh window (Idle -> Window-open)";

  ConditionFields replay;
  replay.conditionId = mConditionId;
  replay.eventId = ua::ByteString{0xAA};
  post_event(replay);
  ASSERT_TRUE(poll_until([&] { return mLog.added_count() == 1; }))
    << "the server-initiated replay is applied";

  post_refresh_end(e1);
  ASSERT_TRUE(poll_until([&] { return open_window_count() == 0; }))
    << "the window closes normally on the matching RefreshEnd";
  EXPECT_EQ(mWire->total_call_count(), 0U) << "no client Call was issued - the refresh was server-initiated";
  EXPECT_TRUE(get_condition(make_key(mConditionId)).is_good());
}

// =============================================================================================
// RefreshEndWithNoOpenWindowIsInert  (CL-AC-004, section 8.8.7)
// A RefreshEnd arriving with no window open and no refresh in flight changes nothing: it issues no Call,
// leaves the ledger able to open and close windows normally, and leaves a later real refresh able to
// complete.
// [neg: a stray RefreshEnd must not corrupt the window ledger or latch the in-progress flag]
//
// OPC 10000-9 5.5.7 issues the RefreshStart and the RefreshEnd as two separate Events, so their EventIds
// never match and a RefreshEnd is paired to a window POSITIONALLY (it closes the oldest). "Unmatched" can
// therefore only mean "no window is open at all" - a RefreshEnd cannot be recognised as stray while a
// window is open, because it is indistinguishable from that window's legitimate end. This is the price of
// the correct pairing rule, and it is bounded: the EventId still collapses the copies of ONE end (below).
// =============================================================================================
// @verifies CL-AC-004
// @relation(CL-AC-004, scope=function)
TEST_F(ClientConditionRefresh, RefreshEndWithNoOpenWindowIsInert)
{
  attach();

  post_refresh_end(ua::ByteString{0xDE, 0xAD});  // nothing is open and nothing is in flight

  // Sentinel: a RefreshStart posted afterwards runs through the same strand (FIFO), so the count reaching 1
  // proves the stray end was processed first rather than merely still queued.
  const ua::ByteString e1{0xE1};
  post_refresh_start(e1);
  ASSERT_TRUE(poll_until([&] { return open_window_count() == 1; }));
  EXPECT_EQ(mWire->total_call_count(), 0U) << "a stray RefreshEnd must not trigger a refresh of its own";

  post_refresh_end(e1);
  ASSERT_TRUE(poll_until([&] { return open_window_count() == 0; }));

  // The tracker still runs a full refresh afterwards: the stray neither consumed a window nor latched
  // mRefreshInProgress (which would return Bad_RefreshInProgress here for the life of the tracker).
  RefreshSlot slot;
  refresh_async_into(slot);
  ASSERT_TRUE(poll_until([&] { return mWire->call_count_to(refreshMethodId) == 1; }));
  const ua::ByteString e2{0xE2};
  post_refresh_start(e2);
  ASSERT_TRUE(poll_until([&] { return open_window_count() == 1; }));
  post_refresh_end(e2);
  ASSERT_TRUE(poll_until([&] { return slot.count() == 1; }))
    << "a real refresh must still complete after a stray RefreshEnd";
  EXPECT_TRUE(slot.last().is_good());
}

// =============================================================================================
// DuplicateRefreshEndCopiesCloseOneWindow  (CL-AC-004, section 8.8.7)
// A ConditionRefresh delivers its RefreshEnd once per Notifier MonitoredItem, and OPC 10000-9 5.5.7 gives
// every copy the same EventId. All copies of one end must close exactly ONE window.
// [neg: a second copy must not close a second, unrelated window and complete the refresh early]
// =============================================================================================
// @verifies CL-AC-004
// @relation(CL-AC-004, scope=function)
TEST_F(ClientConditionRefresh, DuplicateRefreshEndCopiesCloseOneWindow)
{
  attach();
  RefreshSlot slot;
  refresh_async_into(slot);
  ASSERT_TRUE(poll_until([&] { return mWire->call_count_to(refreshMethodId) >= 1; }));

  post_refresh_start(ua::ByteString{0xE1});
  post_refresh_start(ua::ByteString{0xE2});
  ASSERT_TRUE(poll_until([&] { return open_window_count() == 2; }));

  const ua::ByteString endId{0xEE};
  post_refresh_end(endId);
  post_refresh_end(endId);  // the same end, delivered again by a second Notifier
  ASSERT_TRUE(poll_until([&] { return open_window_count() == 1; }));

  // Sentinel: a third window opened after both copies proves both were processed. The count reaching 2
  // means the duplicate closed nothing - a count of 1 would say it consumed the second window.
  post_refresh_start(ua::ByteString{0xE3});
  ASSERT_TRUE(poll_until([&] { return open_window_count() == 2; }))
    << "a duplicate copy of one RefreshEnd must not close a second window";
  EXPECT_EQ(slot.count(), 0) << "the refresh cannot have completed with windows still open";

  post_refresh_end(ua::ByteString{0xEF});
  post_refresh_end(ua::ByteString{0xF0});
  ASSERT_TRUE(poll_until([&] { return slot.count() == 1; }))
    << "the remaining windows close on their own ends and the refresh completes";
  EXPECT_EQ(open_window_count(), 0U);
}

// =============================================================================================
// ReplayAppliedWhenNoLiveEvent  (CL-AC-005, section 8.8.4)
// Within a refresh window, a replay for a branch with NO concurrent live event is applied and surfaced.
// [neg: symmetric positive to the CL-AC-005 drop rule - a replay must NOT be mistaken for stale here]
// =============================================================================================
// @verifies CL-AC-005
// @relation(CL-AC-005, scope=function)
TEST_F(ClientConditionRefresh, ReplayAppliedWhenNoLiveEvent)
{
  attach();
  install_observers();
  RefreshSlot slot;
  refresh_async_into(slot);
  ASSERT_TRUE(poll_until([&] { return mWire->call_count_to(refreshMethodId) == 1; }));

  const ua::ByteString e1{0xE1};
  post_refresh_start(e1);
  ASSERT_TRUE(poll_until([&] { return open_window_count() == 1; }));

  ConditionFields replay;
  replay.conditionId = mConditionId;
  replay.eventId = ua::ByteString{0xAA};
  replay.severity = 250;
  replay.receiveTime = ua::DateTime{2026, 1, 1, 0, 0, 1.0};
  post_event(replay);
  ASSERT_TRUE(poll_until([&] { return mLog.added_count() == 1; }))
    << "a replay with no live event for the branch must be applied (not dropped as stale)";

  post_refresh_end(e1);
  ASSERT_TRUE(poll_until([&] { return slot.count() == 1; }));
  const auto tracked = get_condition(make_key(mConditionId));
  ASSERT_TRUE(tracked.is_good());
  EXPECT_EQ(tracked.value().severity, 250) << "the replayed state must be surfaced";
}

// =============================================================================================
// ReplayDoesNotOverwriteNewerLiveEvent  (CL-AC-005, section 8.8.4)
// Within an open refresh window, a live condition_changed with a NEWER ReceiveTime followed by a
// refresh-replay condition with an OLDER ReceiveTime: the tracked branch state equals the LIVE event; the
// stale replay is dropped (no change observer for it).
// [neg: refresh replay must not clobber a later live transition - the merge is ReceiveTime-ordered, not
//  last-arrived] - drives the CL-AC-005 fix end-to-end.
// =============================================================================================
// @verifies CL-AC-005
// @relation(CL-AC-005, scope=function)
TEST_F(ClientConditionRefresh, ReplayDoesNotOverwriteNewerLiveEvent)
{
  attach();
  install_observers();

  // Seed the branch (added) at an early ReceiveTime.
  ConditionFields seed;
  seed.conditionId = mConditionId;
  seed.eventId = ua::ByteString{0x01};
  seed.severity = 100;
  seed.receiveTime = ua::DateTime{2026, 1, 1, 0, 0, 1.0};
  post_event(seed);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  // Open a refresh window.
  RefreshSlot slot;
  refresh_async_into(slot);
  ASSERT_TRUE(poll_until([&] { return mWire->call_count_to(refreshMethodId) == 1; }));
  const ua::ByteString e1{0xE1};
  post_refresh_start(e1);
  ASSERT_TRUE(poll_until([&] { return open_window_count() == 1; }));

  // A LIVE change with a NEWER ReceiveTime (severity 500).
  ConditionFields live = seed;
  live.eventId = ua::ByteString{0x02};
  live.severity = 500;
  live.receiveTime = ua::DateTime{2026, 1, 1, 0, 0, 3.0};  // newer than seed
  post_event(live);
  ASSERT_TRUE(poll_until([&] { return mLog.changed_count() == 1; })) << "the live change must be delivered";

  // A refresh-replay with an OLDER ReceiveTime (severity 200) must be DROPPED, not overwrite the live state.
  ConditionFields staleReplay = seed;
  staleReplay.eventId = ua::ByteString{0x03};
  staleReplay.severity = 200;
  staleReplay.receiveTime = ua::DateTime{2026, 1, 1, 0, 0, 2.0};  // older than the live event
  post_event(staleReplay);

  // Sentinel: a NEW branch add flows through the strand FIFO AFTER the stale replay; once it lands, the
  // replay has been processed (and dropped by the CL-AC-005 guard).
  ConditionFields sentinel;
  sentinel.conditionId = ua::NodeId{2, 9999U};
  sentinel.eventId = ua::ByteString{0x04};
  sentinel.receiveTime = ua::DateTime{2026, 1, 1, 0, 0, 5.0};
  post_event(sentinel);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 2; }))
    << "the sentinel add proves the stale replay was already processed";

  const auto afterReplay = get_condition(make_key(mConditionId));
  ASSERT_TRUE(afterReplay.is_good());
  EXPECT_EQ(afterReplay.value().severity, 500)
    << "the stale replay (older ReceiveTime) must NOT overwrite the newer live state (CL-AC-005)";
  EXPECT_EQ(mLog.changed_count(), 1) << "the dropped replay must not fire a change observer";

  post_refresh_end(e1);
  ASSERT_TRUE(poll_until([&] { return slot.count() == 1; }));
}

// =============================================================================================
// SecondUserRefreshWhilePendingReturnsBadInvalidState  (CL-AC-004, section 8.8.4 / section 9.6.7)
// A second user-initiated refresh_async while one is still awaiting its RefreshEnd is REJECTED (single
// completion, no second Call); the in-flight refresh is untouched and completes on its own RefreshEnd.
// [neg: a user refresh while one is pending is rejected - not coalesced, not a second wire Call]
//
// SCOPE (oracle conflict - asserting the real, committed behaviour): the matrix row flags that section 8.8.4
// pins queue-single-follow-on for RefreshRequired EVENTS, not a status for a concurrent USER refresh, and
// offers 'Bad_InvalidState' as a placeholder IF reject is chosen. The product HAS chosen reject, using
// Bad_RefreshInProgress (section 9.6.7 - "a ConditionRefresh is already in progress"), which is already
// covered by the tracker's own unit suite. This row asserts that committed status and reports the naming
// discrepancy.
// =============================================================================================
// @verifies CL-AC-004
// @relation(CL-AC-004, scope=function)
TEST_F(ClientConditionRefresh, SecondUserRefreshWhilePendingReturnsBadInvalidState)
{
  attach();
  RefreshSlot first;
  refresh_async_into(first);
  ASSERT_TRUE(poll_until([&] { return mWire->call_count_to(refreshMethodId) == 1; }))
    << "the first refresh is in progress (Good trigger, awaiting RefreshEnd)";

  RefreshSlot second;
  refresh_async_into(second);
  ASSERT_TRUE(poll_until([&] { return second.count() == 1; }))
    << "the concurrent second user refresh must complete (reject) promptly";
  EXPECT_TRUE(second.last().is_bad()) << "a refresh while one is pending is rejected";
  EXPECT_EQ(second.last().status_code().as_uint32(), StatusCode{Status::BadRefreshInProgress}.as_uint32())
    << "the reject uses Bad_RefreshInProgress (committed section 9.6.7 semantics; the matrix's "
       "'Bad_InvalidState' "
       "is a placeholder - see the in-file scope note)";
  EXPECT_EQ(mWire->call_count_to(refreshMethodId), 1U) << "the rejected refresh issues NO second Call";
  EXPECT_EQ(first.count(), 0) << "the in-flight refresh is untouched by the reject";

  const ua::ByteString e1{0xE1};
  post_refresh_start(e1);
  post_refresh_end(e1);
  ASSERT_TRUE(poll_until([&] { return first.count() == 1; }))
    << "the in-flight refresh still completes normally on its RefreshEnd (single completion)";
  EXPECT_TRUE(first.last().is_good());
}

// =============================================================================================
// NoRefreshOnTransparentFailover  (CL-AC-013, section 8.8.3)
// A Transparent redundancy failover (no client-visible reconnect) must emit NO ConditionRefresh Call.
// [neg: transparent failover must NOT refresh]
//
// Drives the real EventSubscriber recovered-switch boundary. The public tier-2 tracker retains its state and
// the wire log stays empty, proving Transparent is excluded from the Cold/Warm trigger classification.
// =============================================================================================
// @verifies CL-AC-013
// @relation(CL-AC-013, scope=function)
TEST_F(ClientConditionRefresh, NoRefreshOnTransparentFailover)
{
  attach();
  install_observers();

  ConditionFields first;
  first.conditionId = ua::NodeId{2, 1U};
  first.eventId = ua::ByteString{0x01};
  post_event(first);
  ConditionFields second;
  second.conditionId = ua::NodeId{2, 2U};
  second.eventId = ua::ByteString{0x02};
  post_event(second);
  ASSERT_TRUE(poll_until([&] { return mLog.added_count() == 2; }))
    << "steady-state condition events flow (proving the strand processed the batch)";

  mSubscriber->on_redundancy_switch_recovered_async(ua::RedundancySupport::Transparent);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 2; }));
  EXPECT_EQ(mWire->call_count_to(refreshMethodId), 0U)
    << "the explicit Transparent recovered-switch signal must not issue ConditionRefresh";
  EXPECT_EQ(mWire->total_call_count(), 0U) << "no wire Call at all from steady-state condition traffic";
}

// =============================================================================================
// RefreshOnColdFailover  (CL-AC-013, section 8.8.3)
// A Cold/Warm RedundancySwitch issues a ConditionRefresh against the new server after re-subscription.
//
// Drives the real EventSubscriber recovered-switch boundary and observes only public tier-2 tracker state
// plus the wire Call. The Cold signal clears former-server state, issues refresh, and the replay repopulates.
// =============================================================================================
// @verifies CL-AC-013
// @relation(CL-AC-013, scope=function)
TEST_F(ClientConditionRefresh, RefreshOnColdFailover)
{
  attach();
  install_observers();

  ConditionFields formerServer;
  formerServer.conditionId = ua::NodeId{2, 7001U};
  formerServer.eventId = ua::ByteString{0xAA};
  post_event(formerServer);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  mSubscriber->on_redundancy_switch_recovered_async(ua::RedundancySupport::Cold);
  ASSERT_TRUE(poll_until([&] { return mWire->call_count_to(refreshMethodId) == 1; }))
    << "the Cold recovered-switch signal must issue ConditionRefresh against the new server";
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 0; }))
    << "former-server condition state must be cleared before the refresh replay";

  const ua::ByteString e1{0xE1};
  post_refresh_start(e1);
  ConditionFields onBackup;
  onBackup.conditionId = mConditionId;
  onBackup.eventId = ua::ByteString{0xBB};
  post_event(onBackup);
  post_refresh_end(e1);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1 && mLog.added_count() == 2; }))
    << "the post-failover refresh repopulates the tracked set from the backup server's replay";
}

// =============================================================================================
// RefreshReissuedAfterReconnect  (CL-AC-003, section 8.8.3) - BLOCKED on the reconnect harness
// After a mid-session channel drop + ReconnectionFSM subscription recovery, a second ConditionRefresh
// reconciles a gap-time state change into the tracked condition.
// [neg: resync after communication disruption - the tracker must not keep the pre-gap state indefinitely]
//
// BLOCKED (verified): dropping the secure channel mid-session and letting the ReconnectionFSM recover the
// subscription - the actual CL-AC-003 reconnect trigger - needs the reconnect harness this single-shot
// fixture lacks. Reachable analog pinned here: a second refresh_async (the post-reconnect resync action)
// re-issues a ConditionRefresh and reconciles the gap's severity change into the tracked state.
// =============================================================================================
// @verifies CL-AC-003
// @relation(CL-AC-003, scope=function)
TEST_F(ClientConditionRefresh, RefreshReissuedAfterReconnect)
{
  attach();
  install_observers();

  ConditionFields standing;
  standing.conditionId = mConditionId;
  standing.eventId = ua::ByteString{0x01};
  standing.severity = 100;
  standing.receiveTime = ua::DateTime{2026, 1, 1, 0, 0, 1.0};
  post_event(standing);
  ASSERT_TRUE(poll_until([&] { return tracked_count() == 1; }));

  RefreshSlot slot;
  refresh_async_into(slot);
  ASSERT_TRUE(poll_until([&] { return mWire->call_count_to(refreshMethodId) == 1; }))
    << "the post-reconnect resync must re-issue a ConditionRefresh";

  const ua::ByteString e1{0xE1};
  post_refresh_start(e1);
  ConditionFields gap = standing;
  gap.eventId = ua::ByteString{0x02};
  gap.severity = 500;
  gap.receiveTime = ua::DateTime{2026, 1, 1, 0, 0, 3.0};  // the change that happened during the gap
  post_event(gap);
  post_refresh_end(e1);
  ASSERT_TRUE(poll_until([&] { return slot.count() == 1; }));

  const auto reconciled = get_condition(make_key(mConditionId));
  ASSERT_TRUE(reconciled.is_good());
  EXPECT_EQ(reconciled.value().severity, 500)
    << "the gap's severity change must be reconciled by the reissued refresh (not left stale at 100)";
}

}  // namespace
