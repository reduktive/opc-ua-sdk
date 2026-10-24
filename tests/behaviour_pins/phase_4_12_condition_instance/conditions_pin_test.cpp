// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.12 (Conditions) - registry + ConditionRefresh.
//
// `Conditions` was already converted to callback-canonical per the
// migration ledger entry of 2026-05-02 (referenced in the runbook section 0). It is
// therefore out of {b} flip scope, but the user's coverage requirements for
// 4.12 explicitly request `ConditionsPin.<Property>` pins covering its
// externally-observable contract: registry semantics, retained-conditions
// enumeration, and the ConditionRefresh emission ordering. Locking those now
// keeps any future async restructure from regressing them silently.
//
// What is pinned:
//   CreateConditionPlacesInstanceInRegistry           - find returns the same instance.
//   FindConditionForUnknownIdReturnsNullptr           - registry miss is observable.
//   DeregisterConditionRemovesFromRegistry            - symmetric to create.
//   RegisterPreCreatedConditionMakesItFindable        - register_condition is observable.
//   RetainedConditionsContainsOnlyRetainedInstances   - filter on snapshot retain bit.
//   RetainedConditionsEmptyWhenNoneRetained           - empty case.
//   ConditionRefreshEmitsRefreshStartAndEndOnEmptyRegistry - fenceposts only.
//   ConditionRefreshEmitsRetainedEventsBetweenStartAndEnd  - sequence + payload.
//   ConditionRefreshSequenceIsStartThenEventsThenEnd  - order observable on sink.
//   CloseAllDisablesAndDeregistersAllConditions       - shutdown contract.
//   AlarmMetricsReportsActiveCountForActiveAlarm      - metrics derived from snapshot.

#include <chrono>
#include <future>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "ua_alarm_condition_payload.h"
#include "ua_alarm_condition_logic.h"
#include "ua_condition_alarm_metrics.h"
#include "ua_byte_string.h"
#include "ua_condition_payload.h"
#include "ua_condition_instance.h"
#include "ua_condition_logic.h"
#include "ua_conditions.h"
#include "ua_conditions_test_access.h"
#include "ua_condition_state_snapshot.h"
#include "ua_sinks.h"
#include "ua_localized_text.h"
#include "ua_node_id.h"
#include "ua_objecttype_id.h"
#include "ua_refresh_end_event_payload.h"
#include "ua_refresh_start_event_payload.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_string.h"
#include <boost/asio/thread_pool.hpp>

namespace ua::test::behaviour_pins
{
namespace
{

// Records every emission with an auto-assigned EventId, mimicking EventBus.
class RecordingEventSink : public EventSink
{
public:
  void emit(BaseEvent& event) override
  {
    ++emitCount;
    if (event.eventId.empty())
    {
      ++mNextId;
      event.eventId = ByteString{std::vector<uint8_t>{
        static_cast<uint8_t>(mNextId & 0xff), static_cast<uint8_t>((mNextId >> 8) & 0xff)}};
    }
    events.push_back(event.clone());
  }

  int emitCount{0};
  std::vector<std::unique_ptr<BaseEvent>> events;

private:
  uint16_t mNextId{0};
};

class ConditionsPin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mManager = ConditionsTestAccess::create(mPool.get_executor(), mSink);
  }

  void TearDown() override
  {
    // Drop the manager's strong refs before joining the pool, so any
    // strand-posted work from condition close/disable can drain on the pool
    // before abort() severs it.
    mManager.reset();
    mPool.join();
  }

  boost::asio::thread_pool mPool{1};
  std::shared_ptr<RecordingEventSink> mSink = std::make_shared<RecordingEventSink>();
  std::shared_ptr<Conditions> mManager;
};

}  // namespace

// ---------------------------------------------------------------------------
// Pin: create_condition places the new instance in the registry.
// ---------------------------------------------------------------------------
//
// Locks the basic registry contract: after `create_condition`, a `find` for
// the same NodeId returns the same instance. A {b}-style restructure that
// dropped the `register_condition` call internal to `create_condition` would
// surface here as a `nullptr` return.

TEST_F(ConditionsPin, CreateConditionPlacesInstanceInRegistry)
{
  auto created = mManager->create_condition_sync(
    NodeId{1, 1000u}, NodeId{1, 100u}, String{"Source"}, std::make_unique<ConditionLogic>());
  ASSERT_NE(created, nullptr);

  auto found = mManager->find_condition_sync(NodeId{1, 1000u});
  ASSERT_NE(found, nullptr);
  EXPECT_EQ(found.get(), created.get()) << "find must return the exact instance create_condition produced";
}

// ---------------------------------------------------------------------------
// Pin: find_condition returns nullptr for unknown NodeId.
// ---------------------------------------------------------------------------
//
// Negative case: no entry, no instance. Falsifies a regression where a stale
// entry from a previous test (or a default-constructed ghost) leaks back.

TEST_F(ConditionsPin, FindConditionForUnknownIdReturnsNullptr)
{
  auto found = mManager->find_condition_sync(NodeId{1, 9999u});
  EXPECT_EQ(found, nullptr);
}

// ---------------------------------------------------------------------------
// Pin: deregister_condition removes the entry from the registry.
// ---------------------------------------------------------------------------
//
// Symmetric to the create-and-find pin; locks the `deregister` contract.

TEST_F(ConditionsPin, DeregisterConditionRemovesFromRegistry)
{
  mManager->create_condition_sync(
    NodeId{1, 1000u}, NodeId{1, 100u}, String{"Source"}, std::make_unique<ConditionLogic>());
  ASSERT_NE(mManager->find_condition_sync(NodeId{1, 1000u}), nullptr);

  mManager->deregister_condition_sync(NodeId{1, 1000u});

  EXPECT_EQ(mManager->find_condition_sync(NodeId{1, 1000u}), nullptr);
}

// ---------------------------------------------------------------------------
// Pin: register_condition makes a pre-created instance findable.
// ---------------------------------------------------------------------------
//
// `register_condition` is the attach-path entry point. Pin locks the
// observable: after register, `find` returns the instance.

TEST_F(ConditionsPin, RegisterPreCreatedConditionMakesItFindable)
{
  auto instance = ConditionInstance::create(mPool.get_executor(),
    std::make_unique<ConditionLogic>(),
    NodeId{1, 3000u},
    NodeId{1, 300u},
    String{"External"},
    mSink);

  mManager->register_condition_sync(instance);

  auto found = mManager->find_condition_sync(NodeId{1, 3000u});
  ASSERT_NE(found, nullptr);
  EXPECT_EQ(found.get(), instance.get());
}

// ---------------------------------------------------------------------------
// Pin: retained_conditions returns only those whose snapshot.retained() is true.
// ---------------------------------------------------------------------------
//
// The retain filter is observable from outside: enable one condition, leave
// another disabled, ask for retained - exactly one comes back. A {b}
// restructure that mis-filtered (e.g., included disabled instances) would
// fail here.

TEST_F(ConditionsPin, RetainedConditionsContainsOnlyRetainedInstances)
{
  auto i1 = mManager->create_condition_sync(
    NodeId{1, 1000u}, NodeId{1, 100u}, String{"S1"}, std::make_unique<ConditionLogic>());
  mManager->create_condition_sync(
    NodeId{1, 2000u}, NodeId{1, 200u}, String{"S2"}, std::make_unique<ConditionLogic>());

  i1->enable_sync();  // sets retained=true on i1, leaves i2 disabled.

  auto retained = mManager->retained_conditions_sync();
  ASSERT_EQ(retained.size(), 1u);
  EXPECT_EQ(retained.front()->condition_id(), NodeId(1, 1000u));
}

// ---------------------------------------------------------------------------
// Pin: retained_conditions is empty when no instance has been enabled.
// ---------------------------------------------------------------------------

TEST_F(ConditionsPin, RetainedConditionsEmptyWhenNoneRetained)
{
  mManager->create_condition_sync(
    NodeId{1, 1000u}, NodeId{1, 100u}, String{"S"}, std::make_unique<ConditionLogic>());

  auto retained = mManager->retained_conditions_sync();
  EXPECT_TRUE(retained.empty());
}

// ---------------------------------------------------------------------------
// Pin: ConditionRefresh on an empty registry emits exactly Start + End.
// ---------------------------------------------------------------------------
//
// Fencepost-only baseline. Locks the contract that the manager always
// emits the start and end events even when there is nothing in between.

TEST_F(ConditionsPin, ConditionRefreshEmitsRefreshStartAndEndOnEmptyRegistry)
{
  RecordingEventSink refreshSink;
  mManager->condition_refresh_sync(refreshSink);

  ASSERT_EQ(refreshSink.events.size(), 2u);
  EXPECT_NE(dynamic_cast<RefreshStartEventPayload*>(refreshSink.events.front().get()), nullptr);
  EXPECT_NE(dynamic_cast<RefreshEndEventPayload*>(refreshSink.events.back().get()), nullptr);
}

// ---------------------------------------------------------------------------
// Pin: ConditionRefresh re-emits each retained condition's current event.
// ---------------------------------------------------------------------------
//
// Covers the body of the refresh sequence: between Start and End there is
// exactly one event per retained condition, of the appropriate
// AlarmConditionPayload / ConditionPayload subtype. This is the only Tier-A path that
// observes `build_refresh_events_async` end-to-end.

TEST_F(ConditionsPin, ConditionRefreshEmitsRetainedEventsBetweenStartAndEnd)
{
  auto instance = mManager->create_condition_sync(
    NodeId{1, 1000u}, NodeId{1, 100u}, String{"AlarmSrc"}, std::make_unique<AlarmConditionLogic>());
  instance->enable_sync();
  instance->activate_sync(500);
  ASSERT_TRUE(instance->snapshot()->retained());

  RecordingEventSink refreshSink;
  mManager->condition_refresh_sync(refreshSink);

  ASSERT_EQ(refreshSink.events.size(), 3u);
  EXPECT_NE(dynamic_cast<RefreshStartEventPayload*>(refreshSink.events[0].get()), nullptr);
  EXPECT_NE(dynamic_cast<AlarmConditionPayload*>(refreshSink.events[1].get()), nullptr)
    << "middle event must be the retained alarm event";
  EXPECT_NE(dynamic_cast<RefreshEndEventPayload*>(refreshSink.events[2].get()), nullptr);
}

// ---------------------------------------------------------------------------
// Pin: refresh sequence is Start, retained event(s), End - in that order.
// ---------------------------------------------------------------------------
//
// Strict ordering pin. With two retained conditions, the sequence is
// [Start, retained1, retained2, End]. Falsifies a regression where the
// fencepost events bracket the wrong span (e.g., End emitted before
// retained payloads).

TEST_F(ConditionsPin, ConditionRefreshSequenceIsStartThenEventsThenEnd)
{
  auto i1 = mManager->create_condition_sync(
    NodeId{1, 1000u}, NodeId{1, 100u}, String{"S1"}, std::make_unique<AlarmConditionLogic>());
  auto i2 = mManager->create_condition_sync(
    NodeId{1, 2000u}, NodeId{1, 200u}, String{"S2"}, std::make_unique<AlarmConditionLogic>());
  i1->enable_sync();
  i1->activate_sync(500);
  i2->enable_sync();
  i2->activate_sync(700);

  RecordingEventSink refreshSink;
  mManager->condition_refresh_sync(refreshSink);

  ASSERT_EQ(refreshSink.events.size(), 4u);
  EXPECT_NE(dynamic_cast<RefreshStartEventPayload*>(refreshSink.events.front().get()), nullptr)
    << "first event must be RefreshStartEventPayload";
  EXPECT_NE(dynamic_cast<RefreshEndEventPayload*>(refreshSink.events.back().get()), nullptr)
    << "last event must be RefreshEndEventPayload";

  // The two middle events are the retained conditions in some order.
  for (size_t i = 1; i < refreshSink.events.size() - 1; ++i)
  {
    EXPECT_NE(dynamic_cast<AlarmConditionPayload*>(refreshSink.events[i].get()), nullptr)
      << "event at index " << i << " is not an AlarmConditionPayload";
  }
}

// ---------------------------------------------------------------------------
// Pin: close_all disables every instance and clears the registry.
// ---------------------------------------------------------------------------
//
// Shutdown contract (two observables):
//   1. close drives every registered instance to disabled
//      (snapshot().enabled() == false) - the instances outlive the manager
//      via the refs held here, so this is the proof that close walked and
//      acted on each registered condition. A {b} restructure that cleared the
//      registry but failed to drive each instance to disabled surfaces here.
//   2. once closed, the manager has cleared its registry and rejects every
//      query with Bad{Shutdown}. This is the documented `find_condition`
//      contract (header: Good{nullptr} only for a live-but-absent id;
//      Bad{Shutdown} when shutting down) - a regression that left the
//      component live after close (mShuttingDown unset) would return
//      Good{nullptr} here and fail the BadShutdown assertions.

TEST_F(ConditionsPin, CloseAllDisablesAndDeregistersAllConditions)
{
  auto i1 = mManager->create_condition_sync(
    NodeId{1, 1000u}, NodeId{1, 100u}, String{"S1"}, std::make_unique<ConditionLogic>());
  auto i2 = mManager->create_condition_sync(
    NodeId{1, 2000u}, NodeId{1, 200u}, String{"S2"}, std::make_unique<ConditionLogic>());
  i1->enable_sync();
  i2->enable_sync();

  // Pre-close: both are registered and findable, so the post-close rejection
  // below is not vacuously true.
  ASSERT_NE(mManager->find_condition_sync(NodeId{1, 1000u}), nullptr);
  ASSERT_NE(mManager->find_condition_sync(NodeId{1, 2000u}), nullptr);

  ConditionsTestAccess::close_sync(*mManager);

  // (1) Disables: every registered instance was driven to disabled.
  EXPECT_FALSE(i1->snapshot()->enabled());
  EXPECT_FALSE(i2->snapshot()->enabled());

  // (2) Deregisters + shutdown contract: the closed manager rejects queries
  // with Bad{Shutdown} (NOT Good{nullptr}).
  EXPECT_EQ(mManager->try_find_condition_sync(NodeId{1, 1000u}).status_code(), Status::BadShutdown);
  EXPECT_EQ(mManager->try_find_condition_sync(NodeId{1, 2000u}).status_code(), Status::BadShutdown);
}

// ---------------------------------------------------------------------------
// Pin: alarm metrics reflect the active-alarm count derived from snapshots.
// ---------------------------------------------------------------------------
//
// `compute_alarm_metrics` derives counts from each instance's snapshot.
// Locks the basic happy-path: one active alarm yields a non-zero
// `active_count()`-style observable in the metrics struct. Falsifies a
// regression that walks the registry but reads stale (pre-snapshot)
// state.

TEST_F(ConditionsPin, AlarmMetricsReportsActiveCountForActiveAlarm)
{
  auto instance = mManager->create_condition_sync(
    NodeId{1, 1000u}, NodeId{1, 100u}, String{"AlarmSrc"}, std::make_unique<AlarmConditionLogic>());
  instance->enable_sync();
  instance->activate_sync(500);
  ASSERT_TRUE(instance->snapshot()->active());

  const auto metrics = mManager->compute_alarm_metrics_sync();
  EXPECT_EQ(metrics.active_count(), 1u) << "compute_alarm_metrics must observe the active alarm";
}

}  // namespace ua::test::behaviour_pins
