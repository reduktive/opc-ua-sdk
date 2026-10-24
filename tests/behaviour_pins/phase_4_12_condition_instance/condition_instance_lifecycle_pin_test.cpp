// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.12 (ConditionInstance) - lifecycle and event-sink emission.
//
// These pins lock externally-observable lifecycle behaviour of `ConditionInstance`
// in logic-only mode (no AddressSpace). The Tier-A `*_async` operations have
// zero-await, single-strand-turn bodies that already match the post-flip
// callback-canonical shape; pinning them now ensures the {b} flip - which deletes
// the `*_coro` adapters and migrates `shared_from_this` -> `weak_from_this()` -
// cannot silently regress these properties.
//
// Logic-only mode (mAddressSpace == nullopt) short-circuits Tier B and exercises
// only the public callback path. This keeps the pins free of AS-fixture drag
// and lets them run as fast unit tests. The runbook's Tier-B AS-driven pins
// (initialize_address_space, attach_address_space, wire_*, register_methods) are
// out of scope here; they belong with the AS pin corpus.
//
// What is pinned:
//   InitializeNoAddressSpaceShortCircuitsCallbackInline  - public callback fires good and inline.
//   AttachNoAddressSpaceShortCircuitsCallbackInline      - same shape for attach.
//   InitializeAndAttachAreIdempotentInLogicOnlyMode      - back-to-back calls remain good.
//   EnableEmitsExactlyOneEventViaEventSink               - emit_count increments by 1.
//   EmittedEventCarriesSourceNodeAndSourceNameFromCtor   - observable on EventSink.
//   EmittedEventEventIdIsAssignedAtEmissionByEventBus    - auto-assignment contract.
//   DisableAfterEnableEmitsAdditionalEvent               - disable produces a separate event.
//   ConditionIdAndSourceNodeAreImmutableAfterCreate      - accessors stable across operations.
//   InitialSnapshotShowsDisabledAndUnretained            - pre-enable invariant.
//   PublicAsyncCallbackFiresOnPoolThreadNotCallerThread  - strand affinity.
//
// What is NOT pinned and why - see runbook section 4 ("Pins explicitly NOT covered") and
// the file-header note above re: Tier-B AS-driven pins.

#include "ua_audit_event_payload.h"
#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "ua_acknowledgeable_condition_logic.h"
#include "ua_alarm_condition_logic.h"
#include "ua_byte_string.h"
#include "ua_condition_instance.h"
#include "ua_condition_logic.h"
#include "ua_condition_state_snapshot.h"
#include "ua_sinks.h"
#include "ua_localized_text.h"
#include "ua_node_id.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_string.h"
#include <boost/asio/thread_pool.hpp>

namespace ua::test::behaviour_pins
{
namespace
{

// ---------------------------------------------------------------------------
// FakeEventSink - records every emitted event, mimicking EventBus's auto-id.
// ---------------------------------------------------------------------------
//
// Replicates the EventBus contract: ConditionInstance emits with an empty
// event_id; the EventBus assigns a unique id during emit(), and the instance
// reads it back via set_last_event_id (used by Acknowledge / Confirm
// flows). Pins that read `last_event_id` rely on this contract.
class FakeEventSink : public EventSink
{
public:
  void emit(BaseEvent& event) override
  {
    // The Condition audit Events the server now raises alongside every transition reach this same
    // sink. They are not what these pins observe - a pin that says "one enable, one event" is
    // about the Condition Event - so the audit family is counted apart rather than folded in.
    if (dynamic_cast<ua::AuditEventPayload*>(&event) != nullptr)
    {
      ++auditEmitCount;
      return;
    }
    ++emitCount;
    if (event.eventId.empty())
    {
      const auto id = static_cast<uint8_t>(emitCount);
      event.eventId = ByteString{std::vector<uint8_t>{id}};
    }
    lastEventId = event.eventId;
    lastSourceNode = event.sourceNode;
    lastSourceName = event.sourceName;
    lastSeverity = event.severity;
    capturedEventIds.push_back(event.eventId);
  }

  int emitCount{0};
  int auditEmitCount{0};
  ByteString lastEventId;
  NodeId lastSourceNode;
  String lastSourceName;
  uint16_t lastSeverity{0};
  std::vector<ByteString> capturedEventIds;
};

// ---------------------------------------------------------------------------
// Fixture - single-pool ConditionInstance with no AddressSpace.
// ---------------------------------------------------------------------------
class ConditionInstanceLifecyclePin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPoolThreadId = std::thread::id{};
    // Capture one of the pool worker thread ids by posting a dispatch.
    std::promise<std::thread::id> idPromise;
    boost::asio::post(
      mPool.get_executor(), [&idPromise]() { idPromise.set_value(std::this_thread::get_id()); });
    mPoolThreadId = idPromise.get_future().get();
  }

  void TearDown() override
  {
    mPool.join();
  }

  std::shared_ptr<ConditionInstance> create_basic_instance()
  {
    return ConditionInstance::create(mPool.get_executor(),
      std::make_unique<ConditionLogic>(),
      NodeId{1, 1000u},
      NodeId{1, 100u},
      String{"PinSource"},
      mSink);
  }

  std::shared_ptr<ConditionInstance> create_alarm_instance()
  {
    return ConditionInstance::create(mPool.get_executor(),
      std::make_unique<AlarmConditionLogic>(),
      NodeId{1, 2000u},
      NodeId{1, 200u},
      String{"PinAlarmSource"},
      mSink);
  }

  // boost::asio::thread_pool is declared FIRST so it destructs LAST. TearDown() calls
  // abort() before any other locals destruct (test rule).
  boost::asio::thread_pool mPool{2};
  std::shared_ptr<FakeEventSink> mSink = std::make_shared<FakeEventSink>();
  std::thread::id mPoolThreadId;
};

}  // namespace

// ---------------------------------------------------------------------------
// Pin: initialize in logic-only mode short-circuits inline.
// ---------------------------------------------------------------------------
//
// Property: when the instance was constructed without an AddressSpace, the
// `initialize_async` body posts to the strand and fires the user's callback
// with `VoidResult{}` (good) without touching any Tier-B coroutine path. The
// pin observes the callback fired with status Good. Falsifies a regression
// where the no-AS short-circuit was removed or routed through Tier B by
// mistake (which would surface as a non-good status when the AS is null).

TEST_F(ConditionInstanceLifecyclePin, InitializeNoAddressSpaceShortCircuitsCallbackInline)
{
  auto instance = create_basic_instance();

  std::promise<VoidResult> done;
  instance->initialize_async([&done](VoidResult result) { done.set_value(std::move(result)); });

  auto fut = done.get_future();
  ASSERT_EQ(fut.wait_for(std::chrono::seconds(2)), std::future_status::ready)
    << "initialize_async did not fire - short-circuit broken?";
  auto result = fut.get();
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(result.status_code(), StatusCode{Status::Good});
}

// ---------------------------------------------------------------------------
// Pin: attach in logic-only mode short-circuits inline.
// ---------------------------------------------------------------------------
//
// Symmetric to the initialize-no-AS pin. Falsifies an `attach_async`
// regression that the {b} flip might introduce when restructuring the
// AttachState per-request struct.

TEST_F(ConditionInstanceLifecyclePin, AttachNoAddressSpaceShortCircuitsCallbackInline)
{
  auto instance = create_basic_instance();

  std::promise<VoidResult> done;
  instance->attach_async([&done](VoidResult result) { done.set_value(std::move(result)); });

  auto fut = done.get_future();
  ASSERT_EQ(fut.wait_for(std::chrono::seconds(2)), std::future_status::ready);
  auto result = fut.get();
  EXPECT_TRUE(result.is_good());
  EXPECT_EQ(result.status_code(), StatusCode{Status::Good});
}

// ---------------------------------------------------------------------------
// Pin: initialize+attach idempotency in logic-only mode.
// ---------------------------------------------------------------------------
//
// Calling either method twice (or in either order) in logic-only mode is a
// no-op observable as `Good`. Locks against a {b}-flip regression that adds a
// `mInitializeState != nullptr` gate but accidentally rejects the no-AS path.

TEST_F(ConditionInstanceLifecyclePin, InitializeAndAttachAreIdempotentInLogicOnlyMode)
{
  auto instance = create_basic_instance();

  for (int i = 0; i < 2; ++i)
  {
    std::promise<VoidResult> done;
    instance->initialize_async([&done](VoidResult result) { done.set_value(std::move(result)); });
    auto fut = done.get_future();
    ASSERT_EQ(fut.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_TRUE(fut.get().is_good()) << "initialize iteration " << i << " regressed";
  }

  for (int i = 0; i < 2; ++i)
  {
    std::promise<VoidResult> done;
    instance->attach_async([&done](VoidResult result) { done.set_value(std::move(result)); });
    auto fut = done.get_future();
    ASSERT_EQ(fut.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_TRUE(fut.get().is_good()) << "attach iteration " << i << " regressed";
  }
}

// ---------------------------------------------------------------------------
// Pin: enable emits exactly one event via the EventSink.
// ---------------------------------------------------------------------------
//
// Externally observable: a single enable raises `emit_count` by 1. Locks the
// invariant that the {b} flip's `apply_transition` rewiring still emits
// exactly one event for one transition. Counts both before and after
// (delta-based) so unrelated background activity cannot mask the assertion.

TEST_F(ConditionInstanceLifecyclePin, EnableEmitsExactlyOneEventViaEventSink)
{
  auto instance = create_basic_instance();
  const int before = mSink->emitCount;

  instance->enable_sync();

  EXPECT_EQ(mSink->emitCount - before, 1) << "enable should emit exactly one event";
}

// ---------------------------------------------------------------------------
// Pin: emitted event carries the source_node / source_name from the ctor.
// ---------------------------------------------------------------------------
//
// Locks the contract that Tier-A operations populate the event's mandatory
// BaseEventType fields (`source_node`, `source_name`) from the values passed
// to `ConditionInstance::create`, not from any post-construction setter.
// The {b} flip's per-flow struct rewrite must not drop this hand-off.

TEST_F(ConditionInstanceLifecyclePin, EmittedEventCarriesSourceNodeAndSourceNameFromCtor)
{
  auto instance = create_basic_instance();
  instance->enable_sync();

  EXPECT_EQ(mSink->lastSourceNode, NodeId(1, 100u));
  EXPECT_EQ(std::string{mSink->lastSourceName}, std::string{"PinSource"});
}

// ---------------------------------------------------------------------------
// Pin: EventBus auto-assignment contract - emitted EventId is non-empty.
// ---------------------------------------------------------------------------
//
// `ConditionInstance::emit_condition_event` emits with empty `event_id`; the
// EventBus / FakeEventSink assigns a unique id during emit(); the instance
// reads it back via `set_last_event_id`. This pin observes the externally
// visible part of that contract: after a successful enable, the fake's
// `last_event_id` is non-empty. Falsifies a {b} regression where the
// emit/set_last_event_id pair is split across continuations and the second
// half gets dropped.

TEST_F(ConditionInstanceLifecyclePin, EmittedEventEventIdIsAssignedAtEmissionByEventBus)
{
  auto instance = create_basic_instance();
  instance->enable_sync();

  ASSERT_EQ(mSink->emitCount, 1);
  EXPECT_FALSE(mSink->lastEventId.empty()) << "EventBus must assign a non-empty EventId";
}

// ---------------------------------------------------------------------------
// Pin: disable after enable emits a separate (additional) event.
// ---------------------------------------------------------------------------
//
// Two transitions = two events; the {b} flip's `apply_transition` rewrite
// must emit one event per state change. This pin counts events around the
// disable call to assert the delta is exactly 1.

TEST_F(ConditionInstanceLifecyclePin, DisableAfterEnableEmitsAdditionalEvent)
{
  auto instance = create_basic_instance();
  instance->enable_sync();
  const int afterEnable = mSink->emitCount;

  instance->disable_sync();

  EXPECT_EQ(mSink->emitCount - afterEnable, 1) << "disable should emit exactly one event";
}

// ---------------------------------------------------------------------------
// Pin: condition_id and source_node accessors are immutable after construct.
// ---------------------------------------------------------------------------
//
// In logic-only mode `mConditionId` is set in the constructor and never
// changes (the {b} AS-bound init path may rewrite it to the subtree root but
// that is gated on AS != nullopt). The pin observes that enabling /
// disabling / re-initialising the instance does not perturb the accessors.

TEST_F(ConditionInstanceLifecyclePin, ConditionIdAndSourceNodeAreImmutableAfterCreate)
{
  auto instance = create_basic_instance();
  EXPECT_EQ(instance->condition_id(), NodeId(1, 1000u));
  EXPECT_EQ(instance->source_node(), NodeId(1, 100u));

  instance->enable_sync();
  EXPECT_EQ(instance->condition_id(), NodeId(1, 1000u));
  EXPECT_EQ(instance->source_node(), NodeId(1, 100u));

  instance->disable_sync();
  EXPECT_EQ(instance->condition_id(), NodeId(1, 1000u));
  EXPECT_EQ(instance->source_node(), NodeId(1, 100u));
}

// ---------------------------------------------------------------------------
// Pin: initial snapshot - disabled and unretained.
// ---------------------------------------------------------------------------
//
// Pre-enable invariant: the snapshot reports `enabled() == false` and
// `retained() == false`. Locks the post-construction state - a {b}
// regression that initialised `mEnabled = true` (e.g., via a
// `set_initial_enabled` call placed too eagerly) would flip this.

TEST_F(ConditionInstanceLifecyclePin, InitialSnapshotShowsDisabledAndUnretained)
{
  auto instance = create_basic_instance();

  auto snapshot = instance->snapshot();
  ASSERT_NE(snapshot, nullptr);
  EXPECT_FALSE(snapshot->enabled());
  EXPECT_FALSE(snapshot->retained());
}

// ---------------------------------------------------------------------------
// Pin: callback fires on a pool thread, never on the caller's thread.
// ---------------------------------------------------------------------------
//
// `boost::asio::strand<boost::asio::any_io_executor>` does not expose a `running_in_this_thread()` accessor,
// so we use a thread-id capture. The fixture posts a sentinel onto the pool to learn one pool worker's id at
// SetUp time. The pin asserts the user's callback thread id is NOT the main test thread - i.e., it ran on the
// pool. (A 2-thread pool can serve different work on either thread, so we cannot pin a single specific worker
// id; we can pin "not the caller".)

TEST_F(ConditionInstanceLifecyclePin, PublicAsyncCallbackFiresOnPoolThreadNotCallerThread)
{
  auto instance = create_basic_instance();

  const auto callerId = std::this_thread::get_id();
  std::promise<std::thread::id> tidPromise;
  instance->enable_async(
    [&tidPromise](VoidResult /*result*/) { tidPromise.set_value(std::this_thread::get_id()); });

  auto fut = tidPromise.get_future();
  ASSERT_EQ(fut.wait_for(std::chrono::seconds(2)), std::future_status::ready);
  const auto callbackTid = fut.get();
  EXPECT_NE(callbackTid, callerId) << "callback fired on the caller thread - strand affinity broken";
}

}  // namespace ua::test::behaviour_pins
