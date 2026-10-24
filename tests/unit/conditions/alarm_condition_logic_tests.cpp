// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_alarm_condition_logic.h"
#include "ua_limit_alarm_logic.h"

#include "ua_acknowledgeable_condition_payload.h"
#include "ua_alarm_condition_payload.h"
#include "ua_condition_payload.h"
#include "ua_data_value.h"
#include "ua_object_id.h"
#include "ua_qualified_name.h"
#include "ua_status.h"
#include "ua_variant.h"

#include <gtest/gtest.h>

#include <array>
#include <limits>

namespace ua::test
{

/// Test-access helper to read protected/private state from AlarmConditionLogic.
class AlarmConditionLogicTestAccess
{
public:
  explicit AlarmConditionLogicTestAccess(AlarmConditionLogic& logic) : mLogic(logic)
  {}

  bool enabled() const
  {
    return mLogic.enabled();
  }

  bool retained() const
  {
    return mLogic.retained();
  }

  uint16_t severity() const
  {
    return mLogic.severity();
  }

  bool acknowledged() const
  {
    return mLogic.acknowledged();
  }

  bool confirmed() const
  {
    return mLogic.confirmed();
  }

  bool active() const
  {
    return mLogic.active();
  }

  const TwoStateVariableState& active_state() const
  {
    return mLogic.active_state();
  }

  const TwoStateVariableState& acked_state() const
  {
    return mLogic.acked_state();
  }

  ShelveState shelve_state() const
  {
    return mLogic.shelve_state();
  }

  bool suppressed_or_shelved() const
  {
    return mLogic.suppressed_or_shelved();
  }

  bool raw_active() const
  {
    return mLogic.raw_active();
  }

  bool on_delay_pending() const
  {
    return mLogic.mOnDelayPending;
  }

  bool off_delay_pending() const
  {
    return mLogic.mOffDelayPending;
  }

  const std::optional<TwoStateVariableState>& suppressed_state() const
  {
    return mLogic.mSuppressedState;
  }

  const std::optional<TwoStateVariableState>& out_of_service_state() const
  {
    return mLogic.mOutOfServiceState;
  }

  const std::optional<TwoStateVariableState>& silence_state() const
  {
    return mLogic.mSilenceState;
  }

  const std::optional<TwoStateVariableState>& latched_state() const
  {
    return mLogic.mLatchedState;
  }

  const ByteString& last_event_id() const
  {
    return mLogic.last_event_id();
  }

  void set_raw_active(bool value)
  {
    mLogic.mRawActive = value;
  }

  void set_on_delay_pending(bool value)
  {
    mLogic.mOnDelayPending = value;
  }

  void set_off_delay_pending(bool value)
  {
    mLogic.mOffDelayPending = value;
  }

  void set_active_transition_time(DateTime value)
  {
    mLogic.mActiveState.transitionTime = value;
  }

  const std::vector<ConditionBranch>& branches() const
  {
    return mLogic.branches();
  }

private:
  AlarmConditionLogic& mLogic;
};

class AlarmConditionLogicTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mLogic.set_source(NodeId{1, 100}, String{"TestSource"});
  }

  AlarmConditionLogic mLogic;
  AlarmConditionLogicTestAccess mAccess{mLogic};

  /// Helper: enable the condition and set a known event ID.
  ByteString enable_and_set_event_id()
  {
    mLogic.enable();
    ByteString eventId{std::vector<uint8_t>{1, 2, 3}};
    mLogic.set_last_event_id(eventId);
    return eventId;
  }

  /// Helper: enable, activate, and set a known event ID.
  ByteString enable_activate_and_set_event_id(uint16_t severity = 500)
  {
    mLogic.enable();
    mLogic.activate(severity);
    ByteString eventId{std::vector<uint8_t>{1, 2, 3}};
    mLogic.set_last_event_id(eventId);
    return eventId;
  }
};

// =============================================================================
// Initial state
// =============================================================================

TEST_F(AlarmConditionLogicTest, StartsInactiveAndDisabled)
{
  EXPECT_FALSE(mAccess.enabled());
  EXPECT_FALSE(mAccess.active());
  EXPECT_FALSE(mAccess.retained());
  EXPECT_FALSE(mAccess.suppressed_or_shelved());
  EXPECT_EQ(mAccess.shelve_state(), ShelveState::Unshelved);
}

// =============================================================================
// Activate / Deactivate
// =============================================================================

TEST_F(AlarmConditionLogicTest, ActivateSetsActiveStateAndResetsAckedState)
{
  enable_and_set_event_id();

  // Acknowledge first so we can verify it gets reset
  mLogic.acknowledge(mAccess.last_event_id(), LocalizedText{"", "Ack"});
  ASSERT_TRUE(mAccess.acknowledged());

  auto transition = mLogic.activate(500);

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.active());
  EXPECT_TRUE(mAccess.active_state().id);
  EXPECT_EQ(mAccess.active_state().currentState.text(), "Active");
  EXPECT_FALSE(mAccess.acknowledged());
  EXPECT_EQ(mAccess.acked_state().currentState.text(), "Unacknowledged");
}

TEST_F(AlarmConditionLogicTest, ActivateResetsConfirmedStateWhenSupported)
{
  mLogic.set_supports_confirm(true);
  auto eventId = enable_and_set_event_id();
  mLogic.confirm(eventId, LocalizedText{"", "Confirm"});
  ASSERT_TRUE(mAccess.confirmed());

  mLogic.activate(500);

  EXPECT_FALSE(mAccess.confirmed());
}

TEST_F(AlarmConditionLogicTest, DeactivateSetsActiveStateFalse)
{
  mLogic.enable();
  mLogic.activate(500);
  ASSERT_TRUE(mAccess.active());

  auto transition = mLogic.deactivate();

  EXPECT_TRUE(transition.changed);
  EXPECT_FALSE(mAccess.active());
  EXPECT_FALSE(mAccess.active_state().id);
  EXPECT_EQ(mAccess.active_state().currentState.text(), "Inactive");
}

TEST_F(AlarmConditionLogicTest, ActivateEmitsEventWhenRetained)
{
  mLogic.enable();

  auto transition = mLogic.activate(500);

  EXPECT_TRUE(transition.emitEvent);
}

// =============================================================================
// Retain logic
// =============================================================================

TEST_F(AlarmConditionLogicTest, RetainTrueWhenActive)
{
  mLogic.enable();
  mLogic.activate(500);

  EXPECT_TRUE(mAccess.retained());
}

TEST_F(AlarmConditionLogicTest, RetainTrueWhenInactiveButUnacknowledged)
{
  mLogic.enable();
  mLogic.activate(500);
  mLogic.deactivate();

  // Still unacknowledged from the activation
  EXPECT_FALSE(mAccess.active());
  EXPECT_FALSE(mAccess.acknowledged());
  EXPECT_TRUE(mAccess.retained());
}

TEST_F(AlarmConditionLogicTest, RetainFalseWhenInactiveAndAcknowledged)
{
  auto eventId = enable_activate_and_set_event_id();
  mLogic.deactivate();
  mLogic.acknowledge(eventId, LocalizedText{"", "Ack"});

  EXPECT_FALSE(mAccess.active());
  EXPECT_TRUE(mAccess.acknowledged());
  EXPECT_FALSE(mAccess.retained());
}

TEST_F(AlarmConditionLogicTest, RetainTrueWhenAckedButUnconfirmedWithConfirmSupport)
{
  mLogic.set_supports_confirm(true);
  auto eventId = enable_activate_and_set_event_id();
  mLogic.deactivate();
  mLogic.acknowledge(eventId, LocalizedText{"", "Ack"});

  EXPECT_FALSE(mAccess.active());
  EXPECT_TRUE(mAccess.acknowledged());
  EXPECT_FALSE(mAccess.confirmed());
  EXPECT_TRUE(mAccess.retained());
}

TEST_F(AlarmConditionLogicTest, RetainFalseWhenInactiveAckedAndConfirmed)
{
  mLogic.set_supports_confirm(true);
  auto eventId = enable_activate_and_set_event_id();
  mLogic.deactivate();
  mLogic.acknowledge(eventId, LocalizedText{"", "Ack"});
  mLogic.confirm(eventId, LocalizedText{"", "Confirm"});

  EXPECT_FALSE(mAccess.active());
  EXPECT_TRUE(mAccess.acknowledged());
  EXPECT_TRUE(mAccess.confirmed());
  EXPECT_FALSE(mAccess.retained());
}

TEST_F(AlarmConditionLogicTest, RetainFalseWhenDisabled)
{
  mLogic.enable();
  mLogic.activate(500);
  mLogic.disable();

  EXPECT_FALSE(mAccess.retained());
}

// =============================================================================
// Shelving transitions
// =============================================================================

TEST_F(AlarmConditionLogicTest, TimedShelveFromUnshelved)
{
  auto transition = mLogic.timed_shelve(5000.0);

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(transition.status.is_good());
  EXPECT_EQ(mAccess.shelve_state(), ShelveState::TimedShelved);
  ASSERT_EQ(transition.timerCommands.size(), 1);
  EXPECT_EQ(transition.timerCommands[0].kind, TimerCommand::Kind::StartShelveTimer);
  EXPECT_DOUBLE_EQ(transition.timerCommands[0].durationMs, 5000.0);
}

TEST_F(AlarmConditionLogicTest, OneShotShelveFromUnshelved)
{
  auto transition = mLogic.one_shot_shelve();

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(transition.status.is_good());
  EXPECT_EQ(mAccess.shelve_state(), ShelveState::OneShotShelved);
  EXPECT_TRUE(transition.timerCommands.empty());
}

TEST_F(AlarmConditionLogicTest, UnshelveFromTimedShelved)
{
  mLogic.timed_shelve(5000.0);

  auto transition = mLogic.unshelve();

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(transition.status.is_good());
  EXPECT_EQ(mAccess.shelve_state(), ShelveState::Unshelved);
  ASSERT_EQ(transition.timerCommands.size(), 1);
  EXPECT_EQ(transition.timerCommands[0].kind, TimerCommand::Kind::CancelShelveTimer);
}

TEST_F(AlarmConditionLogicTest, UnshelveFromOneShotShelved)
{
  mLogic.one_shot_shelve();

  auto transition = mLogic.unshelve();

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(transition.status.is_good());
  EXPECT_EQ(mAccess.shelve_state(), ShelveState::Unshelved);
  // No cancel timer for one-shot
  EXPECT_TRUE(transition.timerCommands.empty());
}

// OPC 10000-9 5.8.17.1: "Any Transition Occurs" is generated when the Condition goes to an inactive state
// and returns a OneShotShelved alarm to Unshelved, so the next activation is reported. A TimedShelve
// survives the same deactivation.
TEST_F(AlarmConditionLogicTest, DeactivationEndsAOneShotShelveButNotATimedShelve)
{
  mLogic.enable();
  mLogic.activate(500);
  ASSERT_TRUE(mLogic.one_shot_shelve().status.is_good());
  mLogic.deactivate();
  EXPECT_EQ(mAccess.shelve_state(), ShelveState::Unshelved);

  mLogic.activate(500);
  ASSERT_TRUE(mLogic.timed_shelve(5000.0).status.is_good());
  mLogic.deactivate();
  EXPECT_EQ(mAccess.shelve_state(), ShelveState::TimedShelved);
}

// OPC 10000-9 5.8.17.4: a negative or NaN ShelvingTime names no time; it is refused with
// Bad_ShelvingTimeOutOfRange and the alarm stays unshelved.
TEST_F(AlarmConditionLogicTest, TimedShelveRefusesANegativeOrNaNDuration)
{
  EXPECT_EQ(mLogic.timed_shelve(-1.0).status, StatusCode{Status::BadShelvingTimeOutOfRange});
  EXPECT_EQ(mLogic.timed_shelve(std::numeric_limits<double>::quiet_NaN()).status,
    StatusCode{Status::BadShelvingTimeOutOfRange});
  EXPECT_EQ(mAccess.shelve_state(), ShelveState::Unshelved);
}

TEST_F(AlarmConditionLogicTest, ShelveTimerExpiredTransitionsToUnshelved)
{
  mLogic.timed_shelve(5000.0);

  auto transition = mLogic.on_shelve_timer_expired();

  EXPECT_TRUE(transition.changed);
  EXPECT_EQ(mAccess.shelve_state(), ShelveState::Unshelved);
}

TEST_F(AlarmConditionLogicTest, ShelveTimerExpiredNoopWhenNotTimedShelved)
{
  auto transition = mLogic.on_shelve_timer_expired();

  EXPECT_FALSE(transition.changed);
  EXPECT_EQ(mAccess.shelve_state(), ShelveState::Unshelved);
}

// =============================================================================
// Shelving error codes
// =============================================================================

TEST_F(AlarmConditionLogicTest, TimedShelveWhenAlreadyTimedShelvedReturnsBadConditionAlreadyShelved)
{
  mLogic.timed_shelve(5000.0);

  auto transition = mLogic.timed_shelve(3000.0);

  EXPECT_EQ(transition.status, StatusCode{Status::BadConditionAlreadyShelved});
  EXPECT_FALSE(transition.changed);
}

TEST_F(AlarmConditionLogicTest, TimedShelveWhenOneShotShelvedReturnsBadConditionAlreadyShelved)
{
  mLogic.one_shot_shelve();

  auto transition = mLogic.timed_shelve(3000.0);

  EXPECT_EQ(transition.status, StatusCode{Status::BadConditionAlreadyShelved});
}

TEST_F(AlarmConditionLogicTest, OneShotShelveWhenAlreadyShelvedReturnsBadConditionAlreadyShelved)
{
  mLogic.timed_shelve(5000.0);

  auto transition = mLogic.one_shot_shelve();

  EXPECT_EQ(transition.status, StatusCode{Status::BadConditionAlreadyShelved});
}

TEST_F(AlarmConditionLogicTest, UnshelveWhenUnshelvedReturnsBadConditionNotShelved)
{
  auto transition = mLogic.unshelve();

  EXPECT_EQ(transition.status, StatusCode{Status::BadConditionNotShelved});
  EXPECT_FALSE(transition.changed);
}

// Covers SVR-AC-113 (coverage-audit retag).
// @verifies AC-SVR-AC-113-TIMEDSHELVE-MAXTIME
TEST_F(AlarmConditionLogicTest, TimedShelveExceedsMaxTimeShelvedReturnsBadShelvingTimeOutOfRange)
{
  mLogic.set_max_time_shelved(10000.0);

  auto transition = mLogic.timed_shelve(15000.0);

  EXPECT_EQ(transition.status, StatusCode{Status::BadShelvingTimeOutOfRange});
  EXPECT_FALSE(transition.changed);
  EXPECT_EQ(mAccess.shelve_state(), ShelveState::Unshelved);
}

TEST_F(AlarmConditionLogicTest, TimedShelveWithinMaxTimeShelvedSucceeds)
{
  mLogic.set_max_time_shelved(10000.0);

  auto transition = mLogic.timed_shelve(5000.0);

  EXPECT_TRUE(transition.status.is_good());
  EXPECT_EQ(mAccess.shelve_state(), ShelveState::TimedShelved);
}

// =============================================================================
// SuppressedOrShelved
// =============================================================================

// Covers SVR-AC-102 (coverage-audit retag).
TEST_F(AlarmConditionLogicTest, SuppressedOrShelvedTrueWhenSuppressed)
{
  mLogic.set_supports_suppressed(true);
  mLogic.suppress();

  EXPECT_TRUE(mAccess.suppressed_or_shelved());
}

TEST_F(AlarmConditionLogicTest, SuppressedOrShelvedTrueWhenOutOfService)
{
  mLogic.set_supports_out_of_service(true);
  mLogic.remove_from_service();

  EXPECT_TRUE(mAccess.suppressed_or_shelved());
}

TEST_F(AlarmConditionLogicTest, SuppressedOrShelvedTrueWhenShelved)
{
  mLogic.timed_shelve(5000.0);

  EXPECT_TRUE(mAccess.suppressed_or_shelved());
}

TEST_F(AlarmConditionLogicTest, SuppressedOrShelvedFalseWhenNoneActive)
{
  EXPECT_FALSE(mAccess.suppressed_or_shelved());
}

TEST_F(AlarmConditionLogicTest, SuppressedOrShelvedFalseAfterUnsuppress)
{
  mLogic.set_supports_suppressed(true);
  mLogic.suppress();
  ASSERT_TRUE(mAccess.suppressed_or_shelved());

  mLogic.unsuppress();

  EXPECT_FALSE(mAccess.suppressed_or_shelved());
}

TEST_F(AlarmConditionLogicTest, SuppressedOrShelvedFalseAfterPlaceInService)
{
  mLogic.set_supports_out_of_service(true);
  mLogic.remove_from_service();
  ASSERT_TRUE(mAccess.suppressed_or_shelved());

  mLogic.place_in_service();

  EXPECT_FALSE(mAccess.suppressed_or_shelved());
}

// =============================================================================
// Suppress / Unsuppress
// =============================================================================

TEST_F(AlarmConditionLogicTest, SuppressSetsStateTrue)
{
  mLogic.set_supports_suppressed(true);

  auto transition = mLogic.suppress();

  EXPECT_TRUE(transition.changed);
  ASSERT_TRUE(mAccess.suppressed_state().has_value());
  EXPECT_TRUE(mAccess.suppressed_state()->id);
  EXPECT_EQ(mAccess.suppressed_state()->currentState.text(), "Suppressed");
}

TEST_F(AlarmConditionLogicTest, UnsuppressSetsStateFalse)
{
  mLogic.set_supports_suppressed(true);
  mLogic.suppress();

  auto transition = mLogic.unsuppress();

  EXPECT_TRUE(transition.changed);
  ASSERT_TRUE(mAccess.suppressed_state().has_value());
  EXPECT_FALSE(mAccess.suppressed_state()->id);
  EXPECT_EQ(mAccess.suppressed_state()->currentState.text(), "Unsuppressed");
}

// =============================================================================
// RemoveFromService / PlaceInService
// =============================================================================

TEST_F(AlarmConditionLogicTest, RemoveFromServiceSetsStateTrue)
{
  mLogic.set_supports_out_of_service(true);

  auto transition = mLogic.remove_from_service();

  EXPECT_TRUE(transition.changed);
  ASSERT_TRUE(mAccess.out_of_service_state().has_value());
  EXPECT_TRUE(mAccess.out_of_service_state()->id);
  EXPECT_EQ(mAccess.out_of_service_state()->currentState.text(), "OutOfService");
}

TEST_F(AlarmConditionLogicTest, PlaceInServiceSetsStateFalse)
{
  mLogic.set_supports_out_of_service(true);
  mLogic.remove_from_service();

  auto transition = mLogic.place_in_service();

  EXPECT_TRUE(transition.changed);
  ASSERT_TRUE(mAccess.out_of_service_state().has_value());
  EXPECT_FALSE(mAccess.out_of_service_state()->id);
  EXPECT_EQ(mAccess.out_of_service_state()->currentState.text(), "InService");
}

// =============================================================================
// Silence
// =============================================================================

TEST_F(AlarmConditionLogicTest, SilenceSetsStateTrue)
{
  mLogic.set_supports_silence(true);

  auto transition = mLogic.silence();

  EXPECT_TRUE(transition.changed);
  ASSERT_TRUE(mAccess.silence_state().has_value());
  EXPECT_TRUE(mAccess.silence_state()->id);
  EXPECT_EQ(mAccess.silence_state()->currentState.text(), "Silenced");
}

TEST_F(AlarmConditionLogicTest, ActivateResetsSilenceState)
{
  mLogic.set_supports_silence(true);
  mLogic.enable();
  mLogic.silence();
  ASSERT_TRUE(mAccess.silence_state()->id);

  mLogic.activate(500);

  ASSERT_TRUE(mAccess.silence_state().has_value());
  EXPECT_FALSE(mAccess.silence_state()->id);
  EXPECT_EQ(mAccess.silence_state()->currentState.text(), "NotSilenced");
}

// Part 9 section 5.8.2: expiry presents a still-active Alarm as newly alarmed.
// @verifies AC-SVR-AC-123-REALARM-RESETS-STATES
// @relation(AC-SVR-AC-123-REALARM-RESETS-STATES, scope=function)
TEST_F(AlarmConditionLogicTest, ReAlarmExpiryResetsSilenceAckedAndActiveTime)
{
  mLogic.set_supports_silence(true);
  mLogic.set_re_alarm_time(250.0);
  mLogic.enable();
  mLogic.activate(500);
  const ByteString eventId{std::vector<uint8_t>{1, 2, 3}};
  mLogic.set_last_event_id(eventId);
  mLogic.acknowledge(eventId, LocalizedText{"", "Ack"});
  mLogic.silence();
  mAccess.set_active_transition_time(DateTime{});
  ASSERT_TRUE(mAccess.acknowledged());
  ASSERT_TRUE(mAccess.silence_state()->id);

  const auto transition = mLogic.on_re_alarm_timer_expired();

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(transition.emitEvent);
  EXPECT_TRUE(mAccess.active());
  EXPECT_FALSE(mAccess.active_state().transitionTime.is_null());
  EXPECT_FALSE(mAccess.acknowledged());
  EXPECT_EQ(mAccess.acked_state().currentState.text(), "Unacknowledged");
  ASSERT_TRUE(mAccess.silence_state().has_value());
  EXPECT_FALSE(mAccess.silence_state()->id);
  EXPECT_EQ(mAccess.silence_state()->currentState.text(), "NotSilenced");
  ASSERT_EQ(transition.timerCommands.size(), 1);
  EXPECT_EQ(transition.timerCommands[0].kind, TimerCommand::Kind::StartReAlarmTimer);
  EXPECT_DOUBLE_EQ(transition.timerCommands[0].durationMs, 250.0);

  const auto event = mLogic.build_event();
  const auto* alarm = dynamic_cast<const AlarmConditionPayload*>(event.get());
  ASSERT_NE(alarm, nullptr);
  EXPECT_FALSE(alarm->ackedState.id);
  ASSERT_TRUE(alarm->silenceState.has_value());
  EXPECT_FALSE(alarm->silenceState->id);
  EXPECT_FALSE(alarm->activeState.transitionTime.is_null());
  ASSERT_TRUE(alarm->reAlarmTime.has_value());
  EXPECT_DOUBLE_EQ(alarm->reAlarmTime->as<double>(), 250.0);
}

// @relation(AC-SVR-AC-123-REALARM-RESETS-STATES, scope=function)
TEST_F(AlarmConditionLogicTest, ReAlarmExpiryWhileInactiveDoesNothing)
{
  mLogic.set_supports_silence(true);
  mLogic.set_re_alarm_time(250.0);
  mLogic.enable();

  const auto transition = mLogic.on_re_alarm_timer_expired();

  EXPECT_FALSE(transition.changed);
  EXPECT_FALSE(transition.emitEvent);
  EXPECT_TRUE(transition.timerCommands.empty());
  EXPECT_FALSE(mAccess.active());
}

// @relation(AC-SVR-AC-123-REALARM-RESETS-STATES, scope=function)
TEST_F(AlarmConditionLogicTest, ConfiguredReAlarmTimerStartsOnActivationAndCancelsOnDeactivation)
{
  mLogic.set_re_alarm_time(250.0);
  mLogic.enable();

  const auto activated = mLogic.activate(500);

  ASSERT_EQ(activated.timerCommands.size(), 1);
  EXPECT_EQ(activated.timerCommands[0].kind, TimerCommand::Kind::StartReAlarmTimer);
  EXPECT_DOUBLE_EQ(activated.timerCommands[0].durationMs, 250.0);

  const auto deactivated = mLogic.deactivate();

  ASSERT_EQ(deactivated.timerCommands.size(), 1);
  EXPECT_EQ(deactivated.timerCommands[0].kind, TimerCommand::Kind::CancelReAlarmTimer);
}

// =============================================================================
// Disabled-state negative test
// =============================================================================

TEST_F(AlarmConditionLogicTest, ActivateWhileDisabled_NoTransitionEmitted)
{
  // Do NOT enable. Calling activate() on a disabled alarm should not produce a
  // meaningful transition event.
  auto transition = mLogic.activate(500);

  EXPECT_FALSE(transition.emitEvent);
}

// =============================================================================
// On/off delay with timer commands
// =============================================================================

TEST_F(AlarmConditionLogicTest, OnDelayExpiredActivatesWhenRawActiveTrue)
{
  mLogic.enable();
  mLogic.set_on_delay(1000.0);

  // Simulate: subclass set raw active and started on delay
  // We need to manipulate private state for this test
  mAccess.set_raw_active(true);
  mAccess.set_on_delay_pending(true);

  auto transition = mLogic.on_delay_expired();

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.active());
}

TEST_F(AlarmConditionLogicTest, OnDelayExpiredDoesNothingWhenRawActiveFalse)
{
  mLogic.enable();
  mLogic.set_on_delay(1000.0);

  // Raw active was cleared during the delay (violation cleared)
  mAccess.set_raw_active(false);
  mAccess.set_on_delay_pending(true);

  auto transition = mLogic.on_delay_expired();

  EXPECT_FALSE(transition.changed);
  EXPECT_FALSE(mAccess.active());
  EXPECT_FALSE(mAccess.on_delay_pending());
}

// Covers SVR-AC-104 (coverage-audit retag).
TEST_F(AlarmConditionLogicTest, OffDelayExpiredDeactivatesWhenRawActiveFalse)
{
  mLogic.enable();
  mLogic.activate(500);
  mLogic.set_off_delay(1000.0);

  // Simulate: subclass cleared raw active and started off delay
  mAccess.set_raw_active(false);
  mAccess.set_off_delay_pending(true);

  auto transition = mLogic.off_delay_expired();

  EXPECT_TRUE(transition.changed);
  EXPECT_FALSE(mAccess.active());
}

TEST_F(AlarmConditionLogicTest, OffDelayExpiredDoesNothingWhenRawActiveTrue)
{
  mLogic.enable();
  mLogic.activate(500);
  mLogic.set_off_delay(1000.0);

  // Raw active returned during the delay (violation returned)
  mAccess.set_raw_active(true);
  mAccess.set_off_delay_pending(true);

  auto transition = mLogic.off_delay_expired();

  EXPECT_FALSE(transition.changed);
  EXPECT_TRUE(mAccess.active());
  EXPECT_FALSE(mAccess.off_delay_pending());
}

// =============================================================================
// On/off delay end-to-end via LimitAlarmLogic
// =============================================================================

// =============================================================================
// Latched state behavior
// =============================================================================

TEST_F(AlarmConditionLogicTest, ActivationSetsLatchedStateTrue)
{
  mLogic.set_supports_latched(true);
  mLogic.enable();

  mLogic.activate(500);

  ASSERT_TRUE(mAccess.latched_state().has_value());
  EXPECT_TRUE(mAccess.latched_state()->id);
  EXPECT_EQ(mAccess.latched_state()->currentState.text(), "Latched");
}

TEST_F(AlarmConditionLogicTest, DeactivationDoesNotClearLatchedState)
{
  mLogic.set_supports_latched(true);
  mLogic.enable();
  mLogic.activate(500);
  ASSERT_TRUE(mAccess.latched_state()->id);

  mLogic.deactivate();

  // Latched stays true after deactivation
  EXPECT_TRUE(mAccess.latched_state()->id);
}

TEST_F(AlarmConditionLogicTest, ResetClearsLatchedStateWhenInactiveAndAcknowledged)
{
  mLogic.set_supports_latched(true);
  auto eventId = enable_activate_and_set_event_id();
  mLogic.deactivate();
  mLogic.acknowledge(eventId, LocalizedText{"", "Ack"});

  auto transition = mLogic.reset();

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(transition.status.is_good());
  ASSERT_TRUE(mAccess.latched_state().has_value());
  EXPECT_FALSE(mAccess.latched_state()->id);
  EXPECT_EQ(mAccess.latched_state()->currentState.text(), "Unlatched");
}

// @relation(AC-SVR-AC-114-RESET-WHILE-ACTIVE-REFUSED, scope=function)

TEST_F(AlarmConditionLogicTest, ResetFailsWhenStillActive)
{
  mLogic.set_supports_latched(true);
  enable_activate_and_set_event_id();

  auto transition = mLogic.reset();

  EXPECT_EQ(transition.status, StatusCode{Status::BadInvalidState});
  EXPECT_FALSE(transition.changed);
  EXPECT_TRUE(mAccess.latched_state()->id);
}

TEST_F(AlarmConditionLogicTest, ResetFailsWhenUnacknowledged)
{
  mLogic.set_supports_latched(true);
  mLogic.enable();
  mLogic.activate(500);
  mLogic.deactivate();
  // Not acknowledged

  auto transition = mLogic.reset();

  EXPECT_EQ(transition.status, StatusCode{Status::BadInvalidState});
  EXPECT_FALSE(transition.changed);
}

TEST_F(AlarmConditionLogicTest, ResetFailsWhenLatchNotSupported)
{
  // No latched state configured
  auto transition = mLogic.reset();

  EXPECT_EQ(transition.status, StatusCode{Status::BadInvalidState});
  EXPECT_FALSE(transition.changed);
}

// =============================================================================
// build_event
// =============================================================================

TEST_F(AlarmConditionLogicTest, BuildEventReturnsAlarmConditionType)
{
  mLogic.enable();
  mLogic.activate(500);

  auto event = mLogic.build_event();

  ASSERT_NE(event, nullptr);
  auto* alarm = dynamic_cast<AlarmConditionPayload*>(event.get());
  ASSERT_NE(alarm, nullptr);

  EXPECT_EQ(alarm->sourceNode, NodeId(1, 100));
  EXPECT_EQ(alarm->sourceName, String{"TestSource"});
  EXPECT_TRUE(alarm->activeState.id);
  EXPECT_EQ(alarm->activeState.currentState.text(), "Active");
  EXPECT_TRUE(alarm->retain);
}

// Part 9 5.8.10: ShelvingState is the ShelvedStateMachineType of an AlarmCondition, and a Client selects
// ShelvingState/CurrentState and ShelvingState/CurrentState/Id in its EventFilter to learn whether an
// alarm supports shelving and whether it is shelved. A payload that omits the state machine answers
// both selects with null, which a Client (the CTT's A & C Shelving unit among them) reads as "this
// alarm cannot be shelved". The fields must track the state through a shelve.
TEST_F(AlarmConditionLogicTest, BuildEventCarriesShelvingStateThroughAShelve)
{
  const std::array<QualifiedName, 2> currentState{
    QualifiedName{0, "ShelvingState"}, QualifiedName{0, "CurrentState"}};
  const std::array<QualifiedName, 3> currentStateId{
    QualifiedName{0, "ShelvingState"}, QualifiedName{0, "CurrentState"}, QualifiedName{0, "Id"}};
  const Variant unshelvedName{LocalizedText{"", "Unshelved"}};
  const Variant unshelvedId{NodeId{ObjectId::ShelvedStateMachineType_Unshelved}};
  const Variant oneShotName{LocalizedText{"", "OneShotShelved"}};
  const Variant oneShotId{NodeId{ObjectId::ShelvedStateMachineType_OneShotShelved}};

  auto unshelved = mLogic.build_event();
  ASSERT_NE(unshelved, nullptr);
  EXPECT_EQ(unshelved->resolve_field(currentState), unshelvedName);
  EXPECT_EQ(unshelved->resolve_field(currentStateId), unshelvedId);

  ASSERT_TRUE(mLogic.one_shot_shelve().status.is_good());
  auto shelved = mLogic.build_event();
  ASSERT_NE(shelved, nullptr);
  EXPECT_EQ(shelved->resolve_field(currentState), oneShotName);
  EXPECT_EQ(shelved->resolve_field(currentStateId), oneShotId);
}

// OPC 10000-9 5.8.17.1: ShelvingState/UnshelveTime is "the remaining time in milliseconds until the Alarm
// automatically transitions into the Un-shelved state" - initialised with the ShelvingTime of a TimedShelve,
// and with MaxTimeShelved, or the maximum Duration when there is none, for a OneShotShelve.
TEST_F(AlarmConditionLogicTest, BuildEventCarriesUnshelveTime)
{
  const std::array<QualifiedName, 2> unshelveTime{
    QualifiedName{0, "ShelvingState"}, QualifiedName{0, "UnshelveTime"}};

  ASSERT_TRUE(mLogic.timed_shelve(60000.0).status.is_good());
  const auto timed = mLogic.build_event()->resolve_field(unshelveTime).as<double>();
  EXPECT_GT(timed, 59000.0) << "the remaining time starts at the ShelvingTime";
  EXPECT_LE(timed, 60000.0) << "and only counts down";

  // UnshelveTime is "initialised with the ShelvingTime argument", however large: the largest Double is
  // reported as asked, even though the timer that ends the shelve saturates.
  ASSERT_TRUE(mLogic.unshelve().status.is_good());
  ASSERT_TRUE(mLogic.timed_shelve(std::numeric_limits<double>::max()).status.is_good());
  EXPECT_EQ(
    mLogic.build_event()->resolve_field(unshelveTime).as<double>(), std::numeric_limits<double>::max());

  ASSERT_TRUE(mLogic.unshelve().status.is_good());
  ASSERT_TRUE(mLogic.one_shot_shelve().status.is_good());
  EXPECT_EQ(
    mLogic.build_event()->resolve_field(unshelveTime).as<double>(), std::numeric_limits<double>::max())
    << "a OneShotShelve without MaxTimeShelved lasts the maximum Duration";
}

TEST_F(AlarmConditionLogicTest, BuildEventIncludesAckedAndConfirmedState)
{
  mLogic.set_supports_confirm(true);
  mLogic.enable();
  mLogic.activate(500);

  auto event = mLogic.build_event();
  auto* alarm = dynamic_cast<AlarmConditionPayload*>(event.get());
  ASSERT_NE(alarm, nullptr);

  EXPECT_FALSE(alarm->ackedState.id);
  EXPECT_EQ(alarm->ackedState.currentState.text(), "Unacknowledged");
  ASSERT_TRUE(alarm->confirmedState.has_value());
  EXPECT_FALSE(alarm->confirmedState->id);
}

TEST_F(AlarmConditionLogicTest, BuildEventIncludesOptionalStates)
{
  mLogic.set_supports_suppressed(true);
  mLogic.set_supports_out_of_service(true);
  mLogic.set_supports_silence(true);
  mLogic.set_supports_latched(true);
  mLogic.enable();

  auto event = mLogic.build_event();
  auto* alarm = dynamic_cast<AlarmConditionPayload*>(event.get());
  ASSERT_NE(alarm, nullptr);

  EXPECT_TRUE(alarm->suppressedState.has_value());
  EXPECT_TRUE(alarm->outOfServiceState.has_value());
  EXPECT_TRUE(alarm->silenceState.has_value());
  EXPECT_TRUE(alarm->latchedState.has_value());
}

TEST_F(AlarmConditionLogicTest, BuildEventIncludesSuppressedOrShelved)
{
  mLogic.set_supports_suppressed(true);
  mLogic.suppress();
  mLogic.enable();

  auto event = mLogic.build_event();
  auto* alarm = dynamic_cast<AlarmConditionPayload*>(event.get());
  ASSERT_NE(alarm, nullptr);

  EXPECT_TRUE(alarm->suppressedOrShelved);
}

TEST_F(AlarmConditionLogicTest, BuildEventIncludesInputNode)
{
  mLogic.set_input_node(NodeId{2, 42});
  mLogic.enable();

  auto event = mLogic.build_event();
  auto* alarm = dynamic_cast<AlarmConditionPayload*>(event.get());
  ASSERT_NE(alarm, nullptr);

  EXPECT_EQ(alarm->inputNode, NodeId(2, 42));
}

TEST_F(AlarmConditionLogicTest, BuildEventIncludesDelayAndMaxTimeShelved)
{
  mLogic.set_on_delay(1000.0);
  mLogic.set_off_delay(2000.0);
  mLogic.set_max_time_shelved(30000.0);
  mLogic.enable();

  auto event = mLogic.build_event();
  auto* alarm = dynamic_cast<AlarmConditionPayload*>(event.get());
  ASSERT_NE(alarm, nullptr);

  EXPECT_TRUE(alarm->onDelay.has_value());
  EXPECT_TRUE(alarm->offDelay.has_value());
  EXPECT_TRUE(alarm->maxTimeShelved.has_value());
}

// =============================================================================
// on_enabled override
// =============================================================================

TEST_F(AlarmConditionLogicTest, EnableResetsAckedAndConfirmedState)
{
  mLogic.set_supports_confirm(true);
  auto eventId = enable_activate_and_set_event_id();
  mLogic.acknowledge(eventId, LocalizedText{"", "Ack"});
  mLogic.confirm(eventId, LocalizedText{"", "Confirm"});
  ASSERT_TRUE(mAccess.acknowledged());
  ASSERT_TRUE(mAccess.confirmed());

  mLogic.disable();
  mLogic.enable();

  EXPECT_FALSE(mAccess.acknowledged());
  EXPECT_FALSE(mAccess.confirmed());
}

// =============================================================================
// set_initial_active
// =============================================================================

TEST_F(AlarmConditionLogicTest, SetInitialActive_True_SetsActiveState)
{
  mLogic.set_initial_active(true, 500);

  EXPECT_TRUE(mAccess.active());
  EXPECT_TRUE(mAccess.active_state().id);
  EXPECT_EQ(mAccess.active_state().currentState.text(), "Active");
  EXPECT_TRUE(mAccess.raw_active());
}

TEST_F(AlarmConditionLogicTest, SetInitialActive_False_LeavesInactive)
{
  mLogic.set_initial_active(false, 0);

  EXPECT_FALSE(mAccess.active());
  EXPECT_FALSE(mAccess.active_state().id);
  EXPECT_EQ(mAccess.active_state().currentState.text(), "Inactive");
}

TEST_F(AlarmConditionLogicTest, SetInitialActive_SetsSeverity)
{
  mLogic.set_initial_active(true, 750);

  auto event = mLogic.build_event();
  EXPECT_EQ(event->severity, 750);
}

TEST_F(AlarmConditionLogicTest, SetInitialActive_UpdatesRetain)
{
  // Enable, then set initial active => retained should be true.
  mLogic.enable();
  mLogic.set_initial_active(true, 500);

  EXPECT_TRUE(mAccess.retained());
}

TEST_F(AlarmConditionLogicTest, SetInitialActive_SetsStateWithoutTransition)
{
  // set_initial_active returns void (no ConditionStateTransition), meaning it sets
  // state directly without producing an event transition. Verify the state is set
  // and that the retain computation reflects the active state.
  mLogic.set_initial_enabled(true);
  mLogic.set_initial_active(true, 500);

  EXPECT_TRUE(mAccess.active());
  EXPECT_EQ(mAccess.severity(), 500);
  // Active + unacked + enabled => retained
  EXPECT_TRUE(mAccess.retained());
}

// =============================================================================
// set_initial_suppressed
// =============================================================================

TEST_F(AlarmConditionLogicTest, SetInitialSuppressed_SetsState)
{
  mLogic.set_supports_suppressed(true);
  mLogic.set_initial_suppressed(true);

  ASSERT_TRUE(mAccess.suppressed_state().has_value());
  EXPECT_TRUE(mAccess.suppressed_state()->id);
  EXPECT_EQ(mAccess.suppressed_state()->currentState.text(), "Suppressed");
  EXPECT_TRUE(mAccess.suppressed_or_shelved());

  // Reset and test false
  mLogic.set_initial_suppressed(false);

  ASSERT_TRUE(mAccess.suppressed_state().has_value());
  EXPECT_FALSE(mAccess.suppressed_state()->id);
  EXPECT_EQ(mAccess.suppressed_state()->currentState.text(), "Unsuppressed");
  EXPECT_FALSE(mAccess.suppressed_or_shelved());
}

TEST_F(AlarmConditionLogicTest, SetInitialSuppressed_NotSupported_NoEffect)
{
  // Do NOT call set_supports_suppressed - state is nullopt
  mLogic.set_initial_suppressed(true);

  EXPECT_FALSE(mAccess.suppressed_state().has_value());
}

// =============================================================================
// set_initial_out_of_service
// =============================================================================

TEST_F(AlarmConditionLogicTest, SetInitialOutOfService_SetsState)
{
  mLogic.set_supports_out_of_service(true);
  mLogic.set_initial_out_of_service(true);

  ASSERT_TRUE(mAccess.out_of_service_state().has_value());
  EXPECT_TRUE(mAccess.out_of_service_state()->id);
  EXPECT_EQ(mAccess.out_of_service_state()->currentState.text(), "OutOfService");
  EXPECT_TRUE(mAccess.suppressed_or_shelved());

  // Reset and test false
  mLogic.set_initial_out_of_service(false);

  ASSERT_TRUE(mAccess.out_of_service_state().has_value());
  EXPECT_FALSE(mAccess.out_of_service_state()->id);
  EXPECT_EQ(mAccess.out_of_service_state()->currentState.text(), "InService");
  EXPECT_FALSE(mAccess.suppressed_or_shelved());
}

TEST_F(AlarmConditionLogicTest, SetInitialOutOfService_NotSupported_NoEffect)
{
  mLogic.set_initial_out_of_service(true);

  EXPECT_FALSE(mAccess.out_of_service_state().has_value());
}

// =============================================================================
// set_initial_silenced
// =============================================================================

TEST_F(AlarmConditionLogicTest, SetInitialSilenced_SetsState)
{
  mLogic.set_supports_silence(true);
  mLogic.set_initial_silenced(true);

  ASSERT_TRUE(mAccess.silence_state().has_value());
  EXPECT_TRUE(mAccess.silence_state()->id);
  EXPECT_EQ(mAccess.silence_state()->currentState.text(), "Silenced");

  // Reset and test false
  mLogic.set_initial_silenced(false);

  ASSERT_TRUE(mAccess.silence_state().has_value());
  EXPECT_FALSE(mAccess.silence_state()->id);
  EXPECT_EQ(mAccess.silence_state()->currentState.text(), "NotSilenced");
}

TEST_F(AlarmConditionLogicTest, SetInitialSilenced_NotSupported_NoEffect)
{
  mLogic.set_initial_silenced(true);

  EXPECT_FALSE(mAccess.silence_state().has_value());
}

// =============================================================================
// set_initial_latched
// =============================================================================

TEST_F(AlarmConditionLogicTest, SetInitialLatched_SetsState)
{
  mLogic.set_supports_latched(true);
  mLogic.set_initial_latched(true);

  ASSERT_TRUE(mAccess.latched_state().has_value());
  EXPECT_TRUE(mAccess.latched_state()->id);
  EXPECT_EQ(mAccess.latched_state()->currentState.text(), "Latched");

  // Reset and test false
  mLogic.set_initial_latched(false);

  ASSERT_TRUE(mAccess.latched_state().has_value());
  EXPECT_FALSE(mAccess.latched_state()->id);
  EXPECT_EQ(mAccess.latched_state()->currentState.text(), "Unlatched");
}

TEST_F(AlarmConditionLogicTest, SetInitialLatched_NotSupported_NoEffect)
{
  mLogic.set_initial_latched(true);

  EXPECT_FALSE(mAccess.latched_state().has_value());
}

// =============================================================================
// set_initial_shelved
// =============================================================================

TEST_F(AlarmConditionLogicTest, SetInitialShelved_TimedShelved)
{
  mLogic.set_initial_shelved(ShelveState::TimedShelved);

  EXPECT_EQ(mAccess.shelve_state(), ShelveState::TimedShelved);
  EXPECT_TRUE(mAccess.suppressed_or_shelved());
}

TEST_F(AlarmConditionLogicTest, SetInitialShelved_OneShotShelved)
{
  mLogic.set_initial_shelved(ShelveState::OneShotShelved);

  EXPECT_EQ(mAccess.shelve_state(), ShelveState::OneShotShelved);
  EXPECT_TRUE(mAccess.suppressed_or_shelved());
}

TEST_F(AlarmConditionLogicTest, SetInitialShelved_Unshelved)
{
  mLogic.set_initial_shelved(ShelveState::Unshelved);

  EXPECT_EQ(mAccess.shelve_state(), ShelveState::Unshelved);
  EXPECT_FALSE(mAccess.suppressed_or_shelved());
}

// =============================================================================
// ConditionPayload branches
// =============================================================================

// COND-030: BranchId is null for trunk events
TEST_F(AlarmConditionLogicTest, BranchId_NullForCurrentState)
{
  enable_activate_and_set_event_id();
  auto event = mLogic.build_event();

  auto* cond = dynamic_cast<ConditionPayload*>(event.get());
  ASSERT_NE(cond, nullptr);
  EXPECT_TRUE(cond->branchId.is_null());
}

// COND-240: Branch created when unacked state changes
// Covers SVR-AC-030 (coverage-audit retag).
TEST_F(AlarmConditionLogicTest, Branch_CreatedWhenUnackedStateChanges)
{
  mLogic.set_supports_branches(true);
  mLogic.enable();
  mLogic.activate(500);
  mLogic.set_last_event_id(ByteString{std::vector<uint8_t>{1, 2, 3}});

  // Activate again while previous activation is unacknowledged
  auto transition = mLogic.activate(800);

  EXPECT_TRUE(transition.changed);
  ASSERT_EQ(transition.branchEvents.size(), 1u);
  EXPECT_FALSE(transition.branchEvents[0].branchId.is_null());
  EXPECT_TRUE(transition.branchEvents[0].retain);

  // Branch should be stored
  ASSERT_EQ(mAccess.branches().size(), 1u);
  EXPECT_EQ(mAccess.branches()[0].branchId, transition.branchEvents[0].branchId);

  // Branch snapshot should capture the previous active+unacked state
  auto* ackSnapshot = dynamic_cast<AcknowledgeableConditionPayload*>(mAccess.branches()[0].snapshot.get());
  ASSERT_NE(ackSnapshot, nullptr);
  EXPECT_FALSE(ackSnapshot->ackedState.id);  // was unacknowledged

  auto* alarmSnapshot = dynamic_cast<AlarmConditionPayload*>(mAccess.branches()[0].snapshot.get());
  ASSERT_NE(alarmSnapshot, nullptr);
  EXPECT_TRUE(alarmSnapshot->activeState.id);  // was active
  EXPECT_EQ(mAccess.branches()[0].snapshot->severity, 500u);
}

// Branch created on deactivate while unacked
TEST_F(AlarmConditionLogicTest, Branch_CreatedOnDeactivateWhileUnacked)
{
  mLogic.set_supports_branches(true);
  mLogic.enable();
  mLogic.activate(500);
  mLogic.set_last_event_id(ByteString{std::vector<uint8_t>{1, 2, 3}});

  auto transition = mLogic.deactivate();

  ASSERT_EQ(transition.branchEvents.size(), 1u);
  EXPECT_FALSE(transition.branchEvents[0].branchId.is_null());
  EXPECT_TRUE(transition.branchEvents[0].retain);

  // Branch snapshot captures active state
  auto* alarmSnapshot = dynamic_cast<AlarmConditionPayload*>(mAccess.branches()[0].snapshot.get());
  ASSERT_NE(alarmSnapshot, nullptr);
  EXPECT_TRUE(alarmSnapshot->activeState.id);
}

// No branch created when branches not supported (default)
TEST_F(AlarmConditionLogicTest, Branch_NotCreatedWhenBranchesNotSupported)
{
  // branches not enabled (default)
  mLogic.enable();
  mLogic.activate(500);
  mLogic.set_last_event_id(ByteString{std::vector<uint8_t>{1, 2, 3}});

  auto transition = mLogic.activate(800);

  EXPECT_TRUE(transition.branchEvents.empty());
  EXPECT_TRUE(mAccess.branches().empty());
}

// No branch created when trunk is already acknowledged
TEST_F(AlarmConditionLogicTest, Branch_NotCreatedWhenAlreadyAcked)
{
  mLogic.set_supports_branches(true);
  mLogic.enable();
  mLogic.activate(500);
  ByteString eventId{std::vector<uint8_t>{1, 2, 3}};
  mLogic.set_last_event_id(eventId);
  mLogic.acknowledge(eventId, LocalizedText{"", "acked"});
  mLogic.set_last_event_id(ByteString{std::vector<uint8_t>{4, 5, 6}});

  auto transition = mLogic.activate(800);

  EXPECT_TRUE(transition.branchEvents.empty());
  EXPECT_TRUE(mAccess.branches().empty());
}

// COND-031: Branch event has non-null BranchId
TEST_F(AlarmConditionLogicTest, BranchId_NonNullForBranch)
{
  mLogic.set_supports_branches(true);
  mLogic.enable();
  mLogic.activate(500);
  mLogic.set_last_event_id(ByteString{std::vector<uint8_t>{1, 2, 3}});
  mLogic.activate(800);

  // Build branch event from stored snapshot
  auto branchId = mAccess.branches()[0].branchId;
  auto event = mLogic.build_branch_event(branchId, true);

  auto* cond = dynamic_cast<ConditionPayload*>(event.get());
  ASSERT_NE(cond, nullptr);
  EXPECT_FALSE(cond->branchId.is_null());
  EXPECT_EQ(cond->branchId, branchId);
  EXPECT_TRUE(cond->retain);
}

// COND-241: Branch deleted after acknowledgement
TEST_F(AlarmConditionLogicTest, Branch_DeletedAfterAcknowledgement)
{
  mLogic.set_supports_branches(true);
  mLogic.enable();
  mLogic.activate(500);
  mLogic.set_last_event_id(ByteString{std::vector<uint8_t>{1, 2, 3}});

  // Create branch by re-activating
  mLogic.activate(800);

  // Simulate shell assigning EventId to the branch
  auto branchId = mAccess.branches()[0].branchId;
  ByteString branchEventId{std::vector<uint8_t>{10, 20, 30}};
  mLogic.set_branch_event_id(branchId, branchEventId);

  // Acknowledge the branch
  auto transition = mLogic.acknowledge(branchEventId, LocalizedText{"", "branch acked"});

  EXPECT_TRUE(transition.status.is_good());
  EXPECT_TRUE(transition.changed);
  ASSERT_EQ(transition.branchEvents.size(), 1u);
  EXPECT_EQ(transition.branchEvents[0].branchId, branchId);
  EXPECT_FALSE(transition.branchEvents[0].retain);  // resolved - retain=false

  // Remove branch (as the shell would after emitting)
  mLogic.remove_branch(branchId);
  EXPECT_TRUE(mAccess.branches().empty());
}

// COND-242: Trunk retain true while branches exist
TEST_F(AlarmConditionLogicTest, Branch_TrunkRetainTrueWhileBranchesExist)
{
  mLogic.set_supports_branches(true);
  mLogic.enable();
  mLogic.activate(500);
  mLogic.set_last_event_id(ByteString{std::vector<uint8_t>{1, 2, 3}});

  // Create branch by re-activating
  mLogic.activate(800);
  ByteString trunkEventId{std::vector<uint8_t>{4, 5, 6}};
  mLogic.set_last_event_id(trunkEventId);

  // Acknowledge and deactivate trunk
  mLogic.acknowledge(trunkEventId, LocalizedText{"", "trunk acked"});
  mLogic.deactivate();

  // Trunk is inactive + acked, but branch is still unresolved
  EXPECT_TRUE(mAccess.retained());  // retained because branch exists

  // Simulate acknowledging the branch
  auto branchId = mAccess.branches()[0].branchId;
  ByteString branchEventId{std::vector<uint8_t>{10, 20, 30}};
  mLogic.set_branch_event_id(branchId, branchEventId);
  mLogic.acknowledge(branchEventId, LocalizedText{"", "branch acked"});
  mLogic.remove_branch(branchId);

  // Now trunk should not be retained (inactive, acked, no branches)
  EXPECT_FALSE(mAccess.retained());
}

// COND-044: Disable sets retain false on all branches
TEST_F(AlarmConditionLogicTest, Retain_DisableSetsRetainFalseOnAllBranches)
{
  mLogic.set_supports_branches(true);
  mLogic.enable();
  mLogic.activate(500);
  mLogic.set_last_event_id(ByteString{std::vector<uint8_t>{1, 2, 3}});

  // Create first branch
  mLogic.activate(600);
  mLogic.set_last_event_id(ByteString{std::vector<uint8_t>{4, 5, 6}});

  // Create second branch
  mLogic.activate(800);

  ASSERT_EQ(mAccess.branches().size(), 2u);

  auto transition = mLogic.disable();

  // Disable should produce branch_events for each branch with retain=false
  ASSERT_EQ(transition.branchEvents.size(), 2u);
  EXPECT_FALSE(transition.branchEvents[0].retain);
  EXPECT_FALSE(transition.branchEvents[1].retain);

  // All branches cleared
  EXPECT_TRUE(mAccess.branches().empty());
}

// Multiple branches: create 2 branches, verify all tracked
TEST_F(AlarmConditionLogicTest, Branch_MultipleBranchesTracked)
{
  mLogic.set_supports_branches(true);
  mLogic.enable();
  mLogic.activate(500);
  mLogic.set_last_event_id(ByteString{std::vector<uint8_t>{1, 2, 3}});

  mLogic.activate(600);
  mLogic.set_last_event_id(ByteString{std::vector<uint8_t>{4, 5, 6}});

  mLogic.activate(800);

  EXPECT_EQ(mAccess.branches().size(), 2u);
  EXPECT_NE(mAccess.branches()[0].branchId, mAccess.branches()[1].branchId);
}

// A condition that toggles without acknowledgement must not grow branches without limit: the cap
// drops the oldest (Retain=False) when a new branch would exceed it.
TEST_F(AlarmConditionLogicTest, Branch_CapDropsOldestWhenExceeded)
{
  mLogic.set_supports_branches(true);
  mLogic.set_max_branches(2);
  mLogic.enable();

  mLogic.activate(500);
  mLogic.set_last_event_id(ByteString{std::vector<uint8_t>{1}});
  mLogic.activate(600);  // branch 1
  mLogic.set_last_event_id(ByteString{std::vector<uint8_t>{2}});
  mLogic.activate(700);  // branch 2
  ASSERT_EQ(mAccess.branches().size(), 2u);
  auto oldestId = mAccess.branches().front().branchId;

  mLogic.set_last_event_id(ByteString{std::vector<uint8_t>{3}});
  auto overflow = mLogic.activate(800);  // branch 3 -> cap exceeded, drop oldest

  // The live set stays bounded and the oldest branch is gone.
  EXPECT_EQ(mAccess.branches().size(), 2u);
  for (const auto& b : mAccess.branches())
  {
    EXPECT_NE(b.branchId, oldestId);
  }

  // The transition emits Retain=False for the evicted branch and Retain=True for the new one (last).
  ASSERT_GE(overflow.branchEvents.size(), 2u);
  bool sawEviction = false;
  for (const auto& ev : overflow.branchEvents)
  {
    if (ev.branchId == oldestId)
    {
      EXPECT_FALSE(ev.retain);
      sawEviction = true;
    }
  }
  EXPECT_TRUE(sawEviction);
  EXPECT_TRUE(overflow.branchEvents.back().retain);
}

// Confirm on branch (with confirm support)
TEST_F(AlarmConditionLogicTest, Branch_ConfirmOnBranch)
{
  mLogic.set_supports_branches(true);
  mLogic.set_supports_confirm(true);
  mLogic.enable();
  mLogic.activate(500);
  mLogic.set_last_event_id(ByteString{std::vector<uint8_t>{1, 2, 3}});

  // Create branch
  mLogic.activate(800);
  auto branchId = mAccess.branches()[0].branchId;
  ByteString branchEventId{std::vector<uint8_t>{10, 20, 30}};
  mLogic.set_branch_event_id(branchId, branchEventId);

  // Acknowledge the branch (not yet resolved because confirm is needed)
  auto ackTransition = mLogic.acknowledge(branchEventId, LocalizedText{"", "acked"});
  ASSERT_EQ(ackTransition.branchEvents.size(), 1u);
  EXPECT_TRUE(ackTransition.branchEvents[0].retain);  // still needs confirm

  // Confirm the branch
  auto confirmTransition = mLogic.confirm(branchEventId, LocalizedText{"", "confirmed"});
  EXPECT_TRUE(confirmTransition.status.is_good());
  ASSERT_EQ(confirmTransition.branchEvents.size(), 1u);
  EXPECT_FALSE(confirmTransition.branchEvents[0].retain);  // now resolved
}

// AddComment on branch via branch EventId
TEST_F(AlarmConditionLogicTest, Branch_AddCommentOnBranch)
{
  mLogic.set_supports_branches(true);
  mLogic.enable();
  mLogic.activate(500);
  mLogic.set_last_event_id(ByteString{std::vector<uint8_t>{1, 2, 3}});

  mLogic.activate(800);
  auto branchId = mAccess.branches()[0].branchId;
  ByteString branchEventId{std::vector<uint8_t>{10, 20, 30}};
  mLogic.set_branch_event_id(branchId, branchEventId);

  auto transition = mLogic.add_comment(branchEventId, LocalizedText{"", "branch comment"});
  EXPECT_TRUE(transition.status.is_good());
  EXPECT_TRUE(transition.changed);
  ASSERT_EQ(transition.branchEvents.size(), 1u);
  EXPECT_TRUE(transition.branchEvents[0].retain);

  // Verify branch snapshot was updated (build_branch_event returns cloned snapshot)
  auto event = mLogic.build_branch_event(branchId, true);
  ASSERT_NE(event, nullptr);
  auto* cond = dynamic_cast<ConditionPayload*>(event.get());
  ASSERT_NE(cond, nullptr);
  EXPECT_EQ(cond->branchId, branchId);
}

// Branch snapshot captures correct severity from time of branching
TEST_F(AlarmConditionLogicTest, Branch_SnapshotCapturesCorrectSeverity)
{
  mLogic.set_supports_branches(true);
  mLogic.enable();
  mLogic.activate(500);
  mLogic.set_last_event_id(ByteString{std::vector<uint8_t>{1, 2, 3}});

  // Activate with new severity - old severity should be in branch
  mLogic.activate(900);

  ASSERT_EQ(mAccess.branches().size(), 1u);
  EXPECT_EQ(mAccess.branches()[0].snapshot->severity, 500u);

  // Current trunk should have new severity
  EXPECT_EQ(mAccess.severity(), 900u);
}

// =============================================================================
// Restart recovery, InputNode, and latch reset
// =============================================================================

// Part 9 section 5.8.2 states ActiveState recovery as a *shall*: after the AlarmManager restarts, an alarm
// whose input is still in the alarm zone must come back active. A plausible implementation rebuilds
// the alarm from its configuration and then waits for the next input change, which leaves a
// still-violated input reported as normal - and because limit evaluation is change-driven (an
// unchanged limit yields no transition), it may never correct itself.
// @verifies AC-SVR-AC-100-ACTIVESTATE-RECOVERY
TEST_F(AlarmConditionLogicTest, ActiveStateComesBackActiveAfterAlarmManagerRestart)
{
  LimitConfig config;
  config.highLimit = 80.0;
  config.severityHigh = 700;

  // Before the restart: the input sits above the High limit, so the alarm is active.
  LimitAlarmLogic before;
  AlarmConditionLogicTestAccess beforeAccess{before};
  before.set_source(NodeId{1, 100}, String{"TestSource"});
  before.set_limits(config);
  before.enable();
  before.evaluate_input(Variant{95.0}, DateTime::now());
  ASSERT_TRUE(beforeAccess.active());
  ASSERT_EQ(beforeAccess.severity(), 700u);

  // The restart: the manager rebuilds the alarm from configuration only. Assert the rebuilt alarm
  // starts inactive, so the recovery below cannot be mistaken for state that survived the restart.
  LimitAlarmLogic after;
  AlarmConditionLogicTestAccess afterAccess{after};
  after.set_source(NodeId{1, 100}, String{"TestSource"});
  after.set_limits(config);
  after.enable();
  ASSERT_FALSE(afterAccess.active());

  // Recovery: the manager re-reads the input, which is still in alarm. Activation is decided by the
  // limit evaluation, not asserted into place.
  after.evaluate_input(Variant{95.0}, DateTime::now());

  EXPECT_TRUE(afterAccess.active());
  EXPECT_TRUE(afterAccess.active_state().id);
  EXPECT_EQ(afterAccess.active_state().currentState.text(), "Active");
  EXPECT_EQ(afterAccess.severity(), 700u);
  EXPECT_TRUE(afterAccess.retained());

  // The recovered state is what a client sees, not merely internal state.
  auto event = after.build_event();
  ASSERT_NE(event, nullptr);
  auto* alarm = dynamic_cast<AlarmConditionPayload*>(event.get());
  ASSERT_NE(alarm, nullptr);
  EXPECT_TRUE(alarm->activeState.id);
  EXPECT_EQ(alarm->activeState.currentState.text(), "Active");
  EXPECT_TRUE(alarm->retain);
}

// Part 9 section 5.8.2: where the alarm's input Variable is not exposed in the address space, InputNode must
// be the null NodeId. Both tempting implementations mislead the client - substituting SourceNode says
// "browse here" and hands back a Node that is not the input, and any other placeholder is a link that
// fails to resolve. Null is the only value that says "there is no such Node".
// @verifies AC-SVR-AC-101-INPUTNODE-NULL-WHEN-ABSENT
TEST_F(AlarmConditionLogicTest, InputNodeIsNullWhenTheInputIsNotInTheAddressSpace)
{
  // No set_input_node call: the alarm is driven from a source the SDK samples directly.
  mLogic.enable();
  mLogic.activate(500);

  auto event = mLogic.build_event();
  ASSERT_NE(event, nullptr);
  auto* alarm = dynamic_cast<AlarmConditionPayload*>(event.get());
  ASSERT_NE(alarm, nullptr);

  EXPECT_TRUE(alarm->inputNode.is_null());
  EXPECT_EQ(alarm->inputNode, NodeId{});

  // The fixture set a real SourceNode, so the null above is a decision rather than an empty payload:
  // the source must not stand in for the input.
  ASSERT_FALSE(alarm->sourceNode.is_null());
  EXPECT_NE(alarm->inputNode, alarm->sourceNode);
}

// Part 9 section 5.8: Reset is offered exactly where LatchedState is, and it is refused while the alarm is
// still active. An implementation that treats Reset as an unconditional "clear the latch" defeats
// latching entirely - the latch exists to hold the record until an operator clears it *after* the
// condition has gone away, so clearing it mid-alarm discards the very event latching was there to
// keep.
// @verifies AC-SVR-AC-106-LATCHEDSTATE-NEEDS-RESET
TEST_F(AlarmConditionLogicTest, ResetIsRefusedWhileTheLatchedAlarmIsActiveAndClearsTheLatchOnceItIsNot)
{
  mLogic.set_supports_latched(true);
  ASSERT_TRUE(mLogic.supports_latched());

  auto eventId = enable_activate_and_set_event_id();
  ASSERT_TRUE(mAccess.active());
  ASSERT_TRUE(mAccess.latched_state().has_value());
  ASSERT_TRUE(mAccess.latched_state()->id);

  // Still active: Reset is refused, and the latch it would have cleared is still there to be read.
  auto refused = mLogic.reset();
  EXPECT_EQ(refused.status, StatusCode{Status::BadInvalidState});
  EXPECT_FALSE(refused.changed);
  ASSERT_TRUE(mAccess.latched_state().has_value());
  EXPECT_TRUE(mAccess.latched_state()->id);
  EXPECT_EQ(mAccess.latched_state()->currentState.text(), "Latched");

  // No longer active, and acknowledged as Part 9 requires before the latch may be cleared.
  mLogic.deactivate();
  mLogic.acknowledge(eventId, LocalizedText{"", "Ack"});
  ASSERT_FALSE(mAccess.active());
  ASSERT_TRUE(mAccess.acknowledged());

  auto accepted = mLogic.reset();
  EXPECT_TRUE(accepted.status.is_good());
  EXPECT_TRUE(accepted.changed);
  ASSERT_TRUE(mAccess.latched_state().has_value());
  EXPECT_FALSE(mAccess.latched_state()->id);
  EXPECT_EQ(mAccess.latched_state()->currentState.text(), "Unlatched");

  // Reset is co-extensive with LatchedState: an alarm that exposes no LatchedState has no latch to
  // reset and refuses the call outright, so the operation never appears without the state it acts on.
  AlarmConditionLogic unlatched;
  unlatched.set_source(NodeId{1, 101}, String{"NoLatchSource"});
  unlatched.enable();
  ASSERT_FALSE(unlatched.supports_latched());

  auto unsupported = unlatched.reset();
  EXPECT_EQ(unsupported.status, StatusCode{Status::BadInvalidState});
  EXPECT_FALSE(unsupported.changed);
}

// Part 9 section 5.8.2: OffDelay delays the *client-visible* inactive transition, and an input that bounces
// back into the alarm zone before the delay elapses must not produce a fresh alarm. The obvious
// implementation deactivates on the clearing sample and re-activates on the returning one, which is
// precisely the alarm-per-oscillation flood OffDelay exists to prevent - and because re-activation
// resets AckedState, it also silently discards an acknowledgement the operator has already given.
// @verifies AC-SVR-AC-104-OFFDELAY-NO-REGENERATION
TEST_F(AlarmConditionLogicTest, AlarmReturningToActiveWithinOffDelayStaysActiveAndIsNotRegenerated)
{
  LimitConfig config;
  config.highLimit = 80.0;
  config.severityHigh = 700;

  LimitAlarmLogic delayed;
  AlarmConditionLogicTestAccess delayedAccess{delayed};
  delayed.set_source(NodeId{1, 100}, String{"TestSource"});
  delayed.set_limits(config);
  delayed.set_off_delay(2000.0);
  delayed.enable();

  // The input enters the alarm zone, so the alarm activates and the operator acknowledges it.
  // Activation is decided by the limit evaluation, not asserted into place.
  auto raised = delayed.evaluate_input(Variant{95.0}, DateTime::now());
  ASSERT_TRUE(delayedAccess.active());
  ASSERT_TRUE(raised.emitEvent);
  ByteString eventId{std::vector<uint8_t>{1, 2, 3}};
  delayed.set_last_event_id(eventId);
  delayed.acknowledge(eventId, LocalizedText{"", "Ack"});
  ASSERT_TRUE(delayedAccess.acknowledged());

  // The input clears, but OffDelay has not elapsed: the alarm the client sees is still active.
  delayed.evaluate_input(Variant{50.0}, DateTime::now());
  EXPECT_TRUE(delayedAccess.active());
  EXPECT_TRUE(delayedAccess.active_state().id);
  EXPECT_EQ(delayedAccess.active_state().currentState.text(), "Active");

  // The input returns to the alarm zone inside the same window. It stayed active throughout, and no
  // new alarm Event is generated - a regenerated alarm would also have thrown away the acknowledgement.
  auto returned = delayed.evaluate_input(Variant{95.0}, DateTime::now());
  EXPECT_FALSE(returned.emitEvent);
  EXPECT_TRUE(delayedAccess.active());
  EXPECT_TRUE(delayedAccess.acknowledged());

  // What the client reads, not merely internal state: one unbroken active, still-acknowledged alarm.
  auto event = delayed.build_event();
  ASSERT_NE(event, nullptr);
  auto* alarm = dynamic_cast<AlarmConditionPayload*>(event.get());
  ASSERT_NE(alarm, nullptr);
  EXPECT_TRUE(alarm->activeState.id);
  EXPECT_EQ(alarm->activeState.currentState.text(), "Active");
  EXPECT_TRUE(alarm->ackedState.id);

  // OffDelay is a delay, not a permanent hold: once the input has stayed clear and the shell reports
  // the off-delay timer expired, the alarm does go inactive. Without this the assertions above would
  // also pass for an implementation that simply ignores a clearing input.
  delayed.evaluate_input(Variant{50.0}, DateTime::now());
  auto expired = delayed.off_delay_expired();
  EXPECT_TRUE(expired.changed);
  EXPECT_FALSE(delayedAccess.active());
  EXPECT_FALSE(delayedAccess.active_state().id);
}

// Part 9 section 5.8.3: recovering SuppressedState across a restart is a SHOULD, but the fallback is a SHALL
// - where it cannot be determined the alarm must come back *not* suppressed. An implementation that
// carries the pre-restart value forward, or that treats "assume it was suppressed" as the cautious
// choice, leaves the alarm hidden from the operator with nothing on screen to say so.
// @verifies AC-SVR-AC-108-SUPPRESSEDSTATE-RECOVERY
TEST_F(AlarmConditionLogicTest, SuppressedStateRecoversAsNotSuppressedWhenItCannotBeDetermined)
{
  // Before the restart the alarm really was suppressed, so the false below is a recovery decision and
  // not merely a state nothing ever set.
  mLogic.set_supports_suppressed(true);
  mLogic.enable();
  mLogic.suppress();
  ASSERT_TRUE(mAccess.suppressed_state().has_value());
  ASSERT_TRUE(mAccess.suppressed_state()->id);
  ASSERT_TRUE(mAccess.suppressed_or_shelved());

  // The restart: the alarm is rebuilt from configuration alone. Nothing seeds SuppressedState - that
  // is what "cannot be determined" means, so set_initial_suppressed is deliberately never called.
  AlarmConditionLogic restarted;
  AlarmConditionLogicTestAccess restartedAccess{restarted};
  restarted.set_source(NodeId{1, 100}, String{"TestSource"});
  restarted.set_supports_suppressed(true);
  restarted.set_initial_enabled(true);

  ASSERT_TRUE(restartedAccess.suppressed_state().has_value());
  EXPECT_FALSE(restartedAccess.suppressed_state()->id);
  EXPECT_FALSE(restartedAccess.suppressed_or_shelved());

  // The recovered value is what a client reads, not merely internal state.
  auto event = restarted.build_event();
  ASSERT_NE(event, nullptr);
  auto* alarm = dynamic_cast<AlarmConditionPayload*>(event.get());
  ASSERT_NE(alarm, nullptr);
  ASSERT_TRUE(alarm->suppressedState.has_value());
  EXPECT_FALSE(alarm->suppressedState->id);
  EXPECT_FALSE(alarm->suppressedOrShelved);
}

// Part 9 section 5.8.3, mirroring SuppressedState: an alarm left out of service reports nothing, and silence
// after a restart is indistinguishable from a healthy plant. Where OutOfServiceState cannot be
// determined the SHALL fallback is in-service, so an implementation that preserves the pre-restart
// value on the assumption that maintenance is still in progress hides a live plant from the operator.
// @verifies AC-SVR-AC-109-OUTOFSERVICESTATE-RECOVERY
TEST_F(AlarmConditionLogicTest, OutOfServiceStateRecoversAsInServiceWhenItCannotBeDetermined)
{
  // Before the restart the alarm really was out of service.
  mLogic.set_supports_out_of_service(true);
  mLogic.enable();
  mLogic.remove_from_service();
  ASSERT_TRUE(mAccess.out_of_service_state().has_value());
  ASSERT_TRUE(mAccess.out_of_service_state()->id);
  ASSERT_TRUE(mAccess.suppressed_or_shelved());

  // The restart rebuilds from configuration alone; set_initial_out_of_service is never called.
  AlarmConditionLogic restarted;
  AlarmConditionLogicTestAccess restartedAccess{restarted};
  restarted.set_source(NodeId{1, 100}, String{"TestSource"});
  restarted.set_supports_out_of_service(true);
  restarted.set_initial_enabled(true);

  ASSERT_TRUE(restartedAccess.out_of_service_state().has_value());
  EXPECT_FALSE(restartedAccess.out_of_service_state()->id);
  EXPECT_FALSE(restartedAccess.suppressed_or_shelved());

  auto event = restarted.build_event();
  ASSERT_NE(event, nullptr);
  auto* alarm = dynamic_cast<AlarmConditionPayload*>(event.get());
  ASSERT_NE(alarm, nullptr);
  ASSERT_TRUE(alarm->outOfServiceState.has_value());
  EXPECT_FALSE(alarm->outOfServiceState->id);
  EXPECT_FALSE(alarm->suppressedOrShelved);
}

// Part 9 section 5.8.10: a shelf is operator-initiated and time-bounded, so a shelf recovered across a
// restart has no remaining duration left to expire against - it would never unshelve itself. Where
// the shelving state cannot be determined the state machine must come back Unshelved; an
// implementation that restores TimedShelved without its timer shelves the alarm permanently.
// @verifies AC-SVR-AC-110-SHELVEDSTATE-RECOVERY
TEST_F(AlarmConditionLogicTest, ShelvedStateRecoversAsUnshelvedWhenItCannotBeDetermined)
{
  // Before the restart the alarm really was shelved.
  mLogic.enable();
  auto shelved = mLogic.timed_shelve(5000.0);
  ASSERT_TRUE(shelved.status.is_good());
  ASSERT_EQ(mAccess.shelve_state(), ShelveState::TimedShelved);
  ASSERT_TRUE(mAccess.suppressed_or_shelved());

  // The restart rebuilds from configuration alone; set_initial_shelved is never called.
  AlarmConditionLogic restarted;
  AlarmConditionLogicTestAccess restartedAccess{restarted};
  restarted.set_source(NodeId{1, 100}, String{"TestSource"});
  restarted.set_initial_enabled(true);

  EXPECT_EQ(restartedAccess.shelve_state(), ShelveState::Unshelved);
  EXPECT_FALSE(restartedAccess.suppressed_or_shelved());

  auto event = restarted.build_event();
  ASSERT_NE(event, nullptr);
  auto* alarm = dynamic_cast<AlarmConditionPayload*>(event.get());
  ASSERT_NE(alarm, nullptr);
  EXPECT_FALSE(alarm->suppressedOrShelved);

  // The state machine is really in Unshelved rather than merely reporting it: Unshelve is refused,
  // which is the answer only the Unshelved state gives.
  auto unshelveWhileUnshelved = restarted.unshelve();
  EXPECT_EQ(unshelveWhileUnshelved.status, StatusCode{Status::BadConditionNotShelved});
  EXPECT_FALSE(unshelveWhileUnshelved.changed);
}

// Part 9 section 5.8: the one recovery in this family that derives rather than defaults. An operator
// silences an alarm they have acknowledged, so where SilenceState cannot be determined AckedState is
// the best evidence available. An implementation that follows the sibling states and defaults to
// false makes every already-acknowledged alarm in the plant sound again the moment the server
// restarts - the audible flood the operator had already dealt with.
// @verifies AC-SVR-AC-122-SILENCESTATE-RECOVERY
TEST_F(AlarmConditionLogicTest, SilenceStateRecoversFromAckedStateWhenItCannotBeDetermined)
{
  // The acknowledged alarm. Configuration first, then the state the restart could recover; SilenceState
  // itself is deliberately never seeded, which is the "cannot be determined" case.
  AlarmConditionLogic ackedRestart;
  AlarmConditionLogicTestAccess ackedAccess{ackedRestart};
  ackedRestart.set_source(NodeId{1, 100}, String{"AckedSource"});
  ackedRestart.set_supports_silence(true);
  ackedRestart.set_initial_enabled(true);
  ackedRestart.set_initial_active(true, 500);
  ackedRestart.set_initial_acked(true);
  ASSERT_TRUE(ackedAccess.acknowledged());

  ASSERT_TRUE(ackedAccess.silence_state().has_value());
  EXPECT_TRUE(ackedAccess.silence_state()->id);

  auto ackedEvent = ackedRestart.build_event();
  ASSERT_NE(ackedEvent, nullptr);
  auto* ackedAlarm = dynamic_cast<AlarmConditionPayload*>(ackedEvent.get());
  ASSERT_NE(ackedAlarm, nullptr);
  ASSERT_TRUE(ackedAlarm->silenceState.has_value());
  EXPECT_TRUE(ackedAlarm->silenceState->id);

  // The unacknowledged alarm, recovered the same way, must come back audible.
  AlarmConditionLogic unackedRestart;
  AlarmConditionLogicTestAccess unackedAccess{unackedRestart};
  unackedRestart.set_source(NodeId{1, 101}, String{"UnackedSource"});
  unackedRestart.set_supports_silence(true);
  unackedRestart.set_initial_enabled(true);
  unackedRestart.set_initial_active(true, 500);
  unackedRestart.set_initial_acked(false);
  ASSERT_FALSE(unackedAccess.acknowledged());

  ASSERT_TRUE(unackedAccess.silence_state().has_value());
  EXPECT_FALSE(unackedAccess.silence_state()->id);

  auto unackedEvent = unackedRestart.build_event();
  ASSERT_NE(unackedEvent, nullptr);
  auto* unackedAlarm = dynamic_cast<AlarmConditionPayload*>(unackedEvent.get());
  ASSERT_NE(unackedAlarm, nullptr);
  ASSERT_TRUE(unackedAlarm->silenceState.has_value());
  EXPECT_FALSE(unackedAlarm->silenceState->id);
}

// Part 9 section 5.8.12, Table 61: OutOfServiceState is optional on AlarmConditionType, so an instance that
// does not expose it has nothing for RemoveFromService to act on and the call must be rejected
// (Bad_NodeIdInvalid or Bad_MethodInvalid depending on how the call resolves). The tempting
// implementation materialises the missing sub-state on demand and reports success - which invents a
// state the instance never declared and leaves the operator believing the alarm is out of service
// while it goes on firing.
// @verifies AC-SVR-AC-131-NO-OUTOFSERVICE-REJECTS-REMOVE
TEST_F(AlarmConditionLogicTest, RemoveFromServiceIsRefusedWhereTheAlarmDoesNotExposeOutOfServiceState)
{
  // A live alarm that never declared OutOfServiceState: set_supports_out_of_service is deliberately
  // not called, which is exactly the instance shape the obligation is about.
  mLogic.enable();
  mLogic.activate(500);
  ASSERT_FALSE(mLogic.supports_out_of_service());
  ASSERT_FALSE(mAccess.out_of_service_state().has_value());
  ASSERT_FALSE(mAccess.suppressed_or_shelved());

  auto refused = mLogic.remove_from_service();

  // Rejected. The requirement admits either of two StatusCodes depending on how the call resolves, so
  // this logic-tier path must select its documented Bad_MethodInvalid result.
  EXPECT_EQ(refused.status.as_status(), Status::BadMethodInvalid);
  EXPECT_FALSE(refused.status.is_good());
  EXPECT_FALSE(refused.changed);

  // A rejected call must not conjure the sub-state it could not act on, nor report the alarm as
  // suppressed-or-shelved on the strength of it.
  EXPECT_FALSE(mLogic.supports_out_of_service());
  EXPECT_FALSE(mAccess.out_of_service_state().has_value());
  EXPECT_FALSE(mAccess.suppressed_or_shelved());

  // What a client reads, not merely internal state: no OutOfServiceState field appears at all, and the
  // alarm is not reported as suppressed or shelved.
  auto event = mLogic.build_event();
  ASSERT_NE(event, nullptr);
  auto* alarm = dynamic_cast<AlarmConditionPayload*>(event.get());
  ASSERT_NE(alarm, nullptr);
  EXPECT_FALSE(alarm->outOfServiceState.has_value());
  EXPECT_FALSE(alarm->suppressedOrShelved);

  // Positive control: the same call on an alarm that does expose OutOfServiceState is accepted, so the
  // refusal above is a decision about the instance's composition and not a call that never works.
  AlarmConditionLogic serviceable;
  AlarmConditionLogicTestAccess serviceableAccess{serviceable};
  serviceable.set_source(NodeId{1, 101}, String{"ServiceableSource"});
  serviceable.set_supports_out_of_service(true);
  serviceable.enable();
  ASSERT_TRUE(serviceable.supports_out_of_service());

  auto accepted = serviceable.remove_from_service();
  EXPECT_TRUE(accepted.status.is_good());
  EXPECT_TRUE(accepted.changed);
  ASSERT_TRUE(serviceableAccess.out_of_service_state().has_value());
  EXPECT_TRUE(serviceableAccess.out_of_service_state()->id);
  EXPECT_EQ(serviceableAccess.out_of_service_state()->currentState.text(), "OutOfService");
  EXPECT_TRUE(serviceableAccess.suppressed_or_shelved());
}

}  // namespace ua::test
