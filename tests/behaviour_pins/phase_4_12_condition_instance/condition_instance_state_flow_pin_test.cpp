// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.12 (ConditionInstance) - ack/confirm flow,
// retain-bit re-trigger timing, and per-operation event emission.
//
// These pins lock externally-observable state-machine flow on top of the
// callback-canonical Tier-A surface. The {b} flip migrates `shared_from_this`
// captures to `weak_from_this()` and rewires `apply_transition`'s emit /
// notify-wired-vars sequencing into per-flow continuations; both must
// preserve the snapshot transitions and event counts asserted here.
//
// What is pinned:
//   ActivateAlarmFlipsActiveAndRetainedTrue                 - alarm becomes retained.
//   AcknowledgeOnAcknowledgeableLogicMarksAcked             - ack flips snapshot.
//   AcknowledgeWithUnknownEventIdReturnsBadEventIdUnknown   - failure mode + detail.
//   ConfirmAfterAcknowledgeMarksConfirmed                   - confirm flips snapshot.
//   ActivateOnNonAlarmLogicReturnsBadNotSupported           - type-mismatch path.
//   AcknowledgeOnNonAcknowledgeableLogicReturnsBadNotSupported  - same shape.
//   DeactivateAfterUnacknowledgedKeepsRetainTrue            - retain re-trigger contract.
//   DeactivateAfterAcknowledgedClearsRetain                 - retain True->False edge.
//   DisableAfterEnableSnapshotsDisabledAndUnretained        - disable clears retain.
//   AcknowledgeRespondsToTheEventIdJustEmitted              - round-trip via FakeEventSink.

#include "ua_audit_event_payload.h"
#include <chrono>
#include <future>
#include <memory>
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
  }

  int emitCount{0};
  int auditEmitCount{0};
  ByteString lastEventId;
};

class ConditionInstancePin : public ::testing::Test
{
protected:
  void SetUp() override
  {}

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

  std::shared_ptr<ConditionInstance> create_acknowledgeable_instance()
  {
    auto logic = std::make_unique<AcknowledgeableConditionLogic>();
    logic->set_supports_confirm(true);
    return ConditionInstance::create(mPool.get_executor(),
      std::move(logic),
      NodeId{1, 3000u},
      NodeId{1, 300u},
      String{"PinAckSource"},
      mSink);
  }

  boost::asio::thread_pool mPool{2};
  std::shared_ptr<FakeEventSink> mSink = std::make_shared<FakeEventSink>();
};

}  // namespace

// ---------------------------------------------------------------------------
// Pin: activate on an AlarmConditionLogic flips active=true and retain=true.
// ---------------------------------------------------------------------------
//
// Externally observable on the snapshot: after `enable + activate`, the
// alarm's `active()` and `retained()` are both true. The {b} flip's
// `apply_transition` rewrite must preserve the retain re-evaluation that
// happens when the alarm becomes active.

TEST_F(ConditionInstancePin, ActivateAlarmFlipsActiveAndRetainedTrue)
{
  auto instance = create_alarm_instance();
  instance->enable_sync();
  instance->activate_sync(/*severity=*/500);

  auto snapshot = instance->snapshot();
  ASSERT_NE(snapshot, nullptr);
  EXPECT_TRUE(snapshot->active());
  EXPECT_TRUE(snapshot->retained());
  EXPECT_EQ(snapshot->severity(), 500);
}

// ---------------------------------------------------------------------------
// Pin: acknowledge against the just-emitted EventId flips acked=true.
// ---------------------------------------------------------------------------
//
// The acknowledge round-trip relies on the EventBus auto-assigning an
// EventId during emit(), the instance reading it back via
// `set_last_event_id`, and the subsequent `acknowledge_sync` using that id
// to find the matching emission. The pin observes the externally-visible
// outcome: after the round-trip, `snapshot->acked() == true`. A {b}
// regression that loses the emit/set-last-id hand-off would surface as
// `acked == false` (or BadEventIdUnknown in the captured Result).

TEST_F(ConditionInstancePin, AcknowledgeOnAcknowledgeableLogicMarksAcked)
{
  auto instance = create_acknowledgeable_instance();
  instance->enable_sync();

  ASSERT_GE(mSink->emitCount, 1);
  const auto eventId = mSink->lastEventId;
  ASSERT_FALSE(eventId.empty());

  auto result = instance->try_acknowledge_sync(eventId, LocalizedText{"", "Ack from pin"});
  ASSERT_TRUE(result.is_good()) << "acknowledge failed: " << std::hex << result.status_code().as_uint32();

  auto snapshot = instance->snapshot();
  EXPECT_TRUE(snapshot->acked());
}

// ---------------------------------------------------------------------------
// Pin: acknowledge with an unknown EventId returns BadEventIdUnknown + detail.
// ---------------------------------------------------------------------------
//
// One of two documented failure modes for acknowledge. Asserts both the
// status code AND a non-null `shared_detail()` so the
// ErrorDetail-propagation invariant holds. A {b} regression
// that drops the detail at the strand-post boundary would surface here.

TEST_F(ConditionInstancePin, AcknowledgeWithUnknownEventIdReturnsBadEventIdUnknown)
{
  auto instance = create_acknowledgeable_instance();
  instance->enable_sync();

  const ByteString bogusId{std::vector<uint8_t>{0xff, 0xee, 0xdd}};
  auto result = instance->try_acknowledge_sync(bogusId, LocalizedText{"", "Ack"});

  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadEventIdUnknown});
  EXPECT_NE(result.shared_detail(), nullptr)
    << "BadEventIdUnknown must carry an ErrorDetail (the highest-priority repository rule)";
}

// ---------------------------------------------------------------------------
// Pin: confirm after acknowledge marks confirmed=true.
// ---------------------------------------------------------------------------
//
// Two-step round-trip: acknowledge generates a fresh emission with a new
// event id; confirm uses that new id. Locks the contract that
// `apply_transition` after acknowledge produces a fresh emission whose id
// can drive confirm.

TEST_F(ConditionInstancePin, ConfirmAfterAcknowledgeMarksConfirmed)
{
  auto instance = create_acknowledgeable_instance();
  instance->enable_sync();

  const auto firstEventId = mSink->lastEventId;
  ASSERT_FALSE(firstEventId.empty());
  auto ackResult = instance->try_acknowledge_sync(firstEventId, LocalizedText{"", "Ack"});
  ASSERT_TRUE(ackResult.is_good());

  const auto ackEventId = mSink->lastEventId;
  ASSERT_FALSE(ackEventId.empty());
  ASSERT_NE(ackEventId, firstEventId) << "acknowledge must emit a new event with a fresh id";

  auto confirmResult = instance->try_confirm_sync(ackEventId, LocalizedText{"", "Confirmed"});
  EXPECT_TRUE(confirmResult.is_good())
    << "confirm failed: " << std::hex << confirmResult.status_code().as_uint32();

  auto snapshot = instance->snapshot();
  EXPECT_TRUE(snapshot->confirmed());
}

// ---------------------------------------------------------------------------
// Pin: activate on a base ConditionLogic instance returns BadNotSupported + detail.
// ---------------------------------------------------------------------------
//
// `activate_async` performs `dynamic_cast<AlarmConditionLogic>` on the
// logic; mismatch yields `BadNotSupported`. Asserts both status and detail
// (highest-priority rule). The {b} flip must preserve this synchronous
// type-mismatch path.

TEST_F(ConditionInstancePin, ActivateOnNonAlarmLogicReturnsBadNotSupported)
{
  auto instance = create_basic_instance();

  auto result = instance->try_activate_sync(/*severity=*/100);

  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadNotSupported});
  EXPECT_NE(result.shared_detail(), nullptr) << "BadNotSupported must carry an ErrorDetail";
}

// ---------------------------------------------------------------------------
// Pin: acknowledge on a base ConditionLogic instance returns BadNotSupported + detail.
// ---------------------------------------------------------------------------
//
// Symmetric to the activate type-mismatch pin, for the
// `AcknowledgeableConditionLogic` cast.

TEST_F(ConditionInstancePin, AcknowledgeOnNonAcknowledgeableLogicReturnsBadNotSupported)
{
  auto instance = create_basic_instance();
  instance->enable_sync();

  const ByteString anyId{std::vector<uint8_t>{0x01}};
  auto result = instance->try_acknowledge_sync(anyId, LocalizedText{"", "Ack"});

  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadNotSupported});
  EXPECT_NE(result.shared_detail(), nullptr);
}

// ---------------------------------------------------------------------------
// Pin: deactivate before acknowledge keeps retain=true (re-trigger window).
// ---------------------------------------------------------------------------
//
// Per Part 9 section 5.5.2, an unacknowledged alarm that returns to inactive
// retains `Retain == true` until the user acknowledges. The pin observes
// the externally-visible snapshot bit. The {b} flip's per-flow restructure
// must not collapse the retain bit prematurely on deactivate.

TEST_F(ConditionInstancePin, DeactivateAfterUnacknowledgedKeepsRetainTrue)
{
  auto alarmLogic = std::make_unique<AlarmConditionLogic>();
  // Default ack support; unconfirmed deactivate keeps retain.
  auto instance = ConditionInstance::create(mPool.get_executor(),
    std::move(alarmLogic),
    NodeId{1, 4000u},
    NodeId{1, 400u},
    String{"PinUnackedSource"},
    mSink);

  instance->enable_sync();
  instance->activate_sync(500);
  ASSERT_TRUE(instance->snapshot()->active());
  ASSERT_TRUE(instance->snapshot()->retained());

  instance->deactivate_sync();

  auto snapshot = instance->snapshot();
  EXPECT_FALSE(snapshot->active());
  EXPECT_TRUE(snapshot->retained())
    << "Retain must remain true while alarm is inactive but unacknowledged (Part 9 section 5.5.2)";
}

// ---------------------------------------------------------------------------
// Pin: deactivate after acknowledge clears retain (Retain True->False edge).
// ---------------------------------------------------------------------------
//
// The complementary half of the previous pin: once the alarm has been
// acknowledged AND deactivated, retain drops. The Retain True->False edge
// must produce one final event so subscriptions see the cleanup. We
// observe both the snapshot transition AND that emission.

TEST_F(ConditionInstancePin, DeactivateAfterAcknowledgedClearsRetain)
{
  auto instance = create_alarm_instance();
  instance->enable_sync();
  instance->activate_sync(500);

  ASSERT_GE(mSink->emitCount, 1);
  const auto eventId = mSink->lastEventId;
  ASSERT_FALSE(eventId.empty());
  auto ackResult = instance->try_acknowledge_sync(eventId, LocalizedText{"", "Ack"});
  ASSERT_TRUE(ackResult.is_good());

  const int beforeDeactivate = mSink->emitCount;
  instance->deactivate_sync();

  auto snapshot = instance->snapshot();
  EXPECT_FALSE(snapshot->active());
  EXPECT_FALSE(snapshot->retained())
    << "Retain True->False edge: acknowledged + deactivated alarm clears retain";
  EXPECT_GE(mSink->emitCount, beforeDeactivate + 1)
    << "Retain True->False edge must emit at least one event (Part 9 section 5.5.2)";
}

// ---------------------------------------------------------------------------
// Pin: disable after enable returns the snapshot to disabled / unretained.
// ---------------------------------------------------------------------------
//
// Locks that disable resets the externally-observable snapshot bits. A {b}
// regression that left `enabled() == true` after `disable_sync` (e.g., by
// dropping the `apply_transition` call from a continuation) would surface
// here.

TEST_F(ConditionInstancePin, DisableAfterEnableSnapshotsDisabledAndUnretained)
{
  auto instance = create_basic_instance();
  instance->enable_sync();
  ASSERT_TRUE(instance->snapshot()->enabled());

  instance->disable_sync();

  auto snapshot = instance->snapshot();
  EXPECT_FALSE(snapshot->enabled());
  EXPECT_FALSE(snapshot->retained());
}

// ---------------------------------------------------------------------------
// Pin: acknowledge round-trips with the EventId just observed on EventSink.
// ---------------------------------------------------------------------------
//
// Tighter form of the acknowledge happy-path pin: explicitly observes that
// the EventId the FakeEventSink saw is the same EventId acknowledge
// accepts. Falsifies a {b} regression where the emit/set_last_event_id
// pair runs in the wrong order (the instance's stored last id must match
// the emission's assigned id).

TEST_F(ConditionInstancePin, AcknowledgeRespondsToTheEventIdJustEmitted)
{
  auto instance = create_acknowledgeable_instance();
  instance->enable_sync();

  ASSERT_EQ(mSink->emitCount, 1);
  const auto observedId = mSink->lastEventId;

  auto result = instance->try_acknowledge_sync(observedId, LocalizedText{"", "Pin ack"});
  EXPECT_TRUE(result.is_good())
    << "the EventBus-assigned id must round-trip: instance must accept the id the sink saw";
}

}  // namespace ua::test::behaviour_pins
