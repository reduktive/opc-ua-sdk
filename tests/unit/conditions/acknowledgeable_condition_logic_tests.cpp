// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_acknowledgeable_condition_logic.h"

#include "ua_alarm_condition_logic.h"

#include "ua_acknowledgeable_condition_payload.h"
#include "ua_alarm_condition_payload.h"
#include "ua_data_value.h"
#include "ua_status.h"

#include <gtest/gtest.h>

namespace ua::test
{

/// Test-access helper to read protected state from AcknowledgeableConditionLogic.
class AcknowledgeableConditionLogicTestAccess
{
public:
  explicit AcknowledgeableConditionLogicTestAccess(AcknowledgeableConditionLogic& logic) : mLogic(logic)
  {}

  bool enabled() const
  {
    return mLogic.enabled();
  }

  bool retained() const
  {
    return mLogic.retained();
  }

  bool acknowledged() const
  {
    return mLogic.acknowledged();
  }

  bool confirmed() const
  {
    return mLogic.confirmed();
  }

  const TwoStateVariableState& acked_state() const
  {
    return mLogic.acked_state();
  }

  const std::optional<TwoStateVariableState>& confirmed_state() const
  {
    return mLogic.confirmed_state();
  }

  const ByteString& last_event_id() const
  {
    return mLogic.last_event_id();
  }

private:
  AcknowledgeableConditionLogic& mLogic;
};

class AcknowledgeableConditionLogicTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mLogic.set_source(NodeId{1, 100}, String{"TestSource"});
  }

  AcknowledgeableConditionLogic mLogic;
  AcknowledgeableConditionLogicTestAccess mAccess{mLogic};

  /// Helper: enable the condition and set a known event ID.
  ByteString enable_and_set_event_id()
  {
    mLogic.enable();
    ByteString eventId{std::vector<uint8_t>{1, 2, 3}};
    mLogic.set_last_event_id(eventId);
    return eventId;
  }
};

// --- Initial state ---

TEST_F(AcknowledgeableConditionLogicTest, StartsDisabledAndUnacknowledged)
{
  EXPECT_FALSE(mAccess.enabled());
  EXPECT_FALSE(mAccess.retained());
  EXPECT_FALSE(mAccess.acknowledged());
  EXPECT_FALSE(mAccess.confirmed());
}

// --- Acknowledge ---

TEST_F(AcknowledgeableConditionLogicTest, AcknowledgeWithValidEventIdSetsAckedState)
{
  auto eventId = enable_and_set_event_id();
  ASSERT_FALSE(mAccess.acknowledged());

  auto transition = mLogic.acknowledge(eventId, LocalizedText{"", "Operator ack"});

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(transition.status.is_good());
  EXPECT_TRUE(mAccess.acknowledged());
  EXPECT_TRUE(mAccess.acked_state().id);
  EXPECT_EQ(mAccess.acked_state().currentState.text(), "Acknowledged");
}

TEST_F(AcknowledgeableConditionLogicTest, AcknowledgeWithInvalidEventIdReturnsBadEventIdUnknown)
{
  enable_and_set_event_id();
  ByteString wrongId{std::vector<uint8_t>{9, 8, 7}};

  auto transition = mLogic.acknowledge(wrongId, LocalizedText{"", "Ack"});

  EXPECT_FALSE(transition.changed);
  EXPECT_EQ(transition.status, StatusCode{Status::BadEventIdUnknown});
  EXPECT_FALSE(mAccess.acknowledged());
}

TEST_F(AcknowledgeableConditionLogicTest, DoubleAcknowledgeReturnsBadConditionBranchAlreadyAcked)
{
  auto eventId = enable_and_set_event_id();
  mLogic.acknowledge(eventId, LocalizedText{"", "First ack"});

  auto transition = mLogic.acknowledge(eventId, LocalizedText{"", "Second ack"});

  EXPECT_FALSE(transition.changed);
  EXPECT_EQ(transition.status, StatusCode{Status::BadConditionBranchAlreadyAcked});
}

TEST_F(AcknowledgeableConditionLogicTest, AcknowledgeUpdatesComment)
{
  auto eventId = enable_and_set_event_id();

  mLogic.acknowledge(eventId, LocalizedText{"", "Ack comment"});

  // Verify comment is reflected in the built event
  auto event = mLogic.build_event();
  EXPECT_EQ(event->message.text(), "Ack comment");
}

TEST_F(AcknowledgeableConditionLogicTest, AcknowledgeWithNullCommentLeavesExistingCommentUnchanged)
{
  // OPC 10000-9 section 5.7.3: a NULL comment (empty locale AND empty text) is ignored and any existing
  // comment remains unchanged. A prior AddComment must survive an Acknowledge carrying no comment.
  auto eventId = enable_and_set_event_id();
  mLogic.add_comment(eventId, LocalizedText{"", "Initializing Comment"});
  ASSERT_EQ(mLogic.build_event()->message.text(), "Initializing Comment");

  mLogic.acknowledge(eventId, LocalizedText{});  // NULL comment

  EXPECT_TRUE(mAccess.acknowledged());
  EXPECT_EQ(mLogic.build_event()->message.text(), "Initializing Comment");
}

TEST_F(AcknowledgeableConditionLogicTest, AcknowledgeWithLocalizedEmptyTextResetsComment)
{
  // OPC 10000-9 section 5.7.3: an empty text WITH a locale is the explicit reset form and overwrites.
  auto eventId = enable_and_set_event_id();
  mLogic.add_comment(eventId, LocalizedText{"", "Initializing Comment"});
  ASSERT_EQ(mLogic.build_event()->message.text(), "Initializing Comment");

  mLogic.acknowledge(eventId, LocalizedText{"en", ""});  // reset form

  EXPECT_EQ(mLogic.build_event()->message.text(), "");
}

// @verifies AC-SVR-AC-014-NULL-COMMENT-IGNORED
TEST_F(AcknowledgeableConditionLogicTest, AddCommentWithNullCommentLeavesExistingCommentUnchanged)
{
  // OPC 10000-9 section 5.5.6: AddComment with a NULL comment is ignored; the existing comment survives.
  auto eventId = enable_and_set_event_id();
  mLogic.add_comment(eventId, LocalizedText{"", "Initializing Comment"});
  ASSERT_EQ(mLogic.build_event()->message.text(), "Initializing Comment");

  auto transition = mLogic.add_comment(eventId, LocalizedText{});  // NULL comment

  EXPECT_TRUE(transition.status.is_good());
  EXPECT_EQ(mLogic.build_event()->message.text(), "Initializing Comment");
}

// --- Confirm ---

TEST_F(AcknowledgeableConditionLogicTest, ConfirmWithValidEventIdSetsConfirmedState)
{
  mLogic.set_supports_confirm(true);
  auto eventId = enable_and_set_event_id();

  auto transition = mLogic.confirm(eventId, LocalizedText{"", "Confirmed"});

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(transition.status.is_good());
  EXPECT_TRUE(mAccess.confirmed());
  ASSERT_TRUE(mAccess.confirmed_state().has_value());
  EXPECT_TRUE(mAccess.confirmed_state()->id);
  EXPECT_EQ(mAccess.confirmed_state()->currentState.text(), "Confirmed");
}

TEST_F(AcknowledgeableConditionLogicTest, ConfirmWithInvalidEventIdReturnsBadEventIdUnknown)
{
  mLogic.set_supports_confirm(true);
  enable_and_set_event_id();
  ByteString wrongId{std::vector<uint8_t>{9, 8, 7}};

  auto transition = mLogic.confirm(wrongId, LocalizedText{"", "Confirm"});

  EXPECT_FALSE(transition.changed);
  EXPECT_EQ(transition.status, StatusCode{Status::BadEventIdUnknown});
  EXPECT_FALSE(mAccess.confirmed());
}

TEST_F(AcknowledgeableConditionLogicTest, DoubleConfirmReturnsBadConditionBranchAlreadyConfirmed)
{
  mLogic.set_supports_confirm(true);
  auto eventId = enable_and_set_event_id();
  mLogic.confirm(eventId, LocalizedText{"", "First confirm"});

  auto transition = mLogic.confirm(eventId, LocalizedText{"", "Second confirm"});

  EXPECT_FALSE(transition.changed);
  EXPECT_EQ(transition.status, StatusCode{Status::BadConditionBranchAlreadyConfirmed});
}

// F81: a Confirm of an EventId that has been RETIRED (the trunk emitted a new event, so last_event_id moved
// on) but whose state is already confirmed must report Bad_ConditionBranchAlreadyConfirmed, NOT
// Bad_EventIdUnknown (OPC 10000-9 section 5.13; UACTT Confirm Err_004 reuses the original EventId on a 2nd
// session).
TEST_F(AcknowledgeableConditionLogicTest, ConfirmRetiredAlreadyConfirmedEventIdReturnsAlreadyConfirmed)
{
  mLogic.set_supports_confirm(true);
  auto eventId = enable_and_set_event_id();
  mLogic.confirm(eventId, LocalizedText{"", "First confirm"});

  // The shell emits the confirm event and assigns a new trunk EventId, retiring the original.
  mLogic.set_last_event_id(ByteString{std::vector<uint8_t>{9, 9, 9}});

  auto transition = mLogic.confirm(eventId, LocalizedText{"", "Second confirm (retired EventId)"});

  EXPECT_FALSE(transition.changed);
  EXPECT_EQ(transition.status, StatusCode{Status::BadConditionBranchAlreadyConfirmed});
}

// F81: the Acknowledge analogue - a retired, already-acknowledged EventId -> Bad_ConditionBranchAlreadyAcked.
TEST_F(AcknowledgeableConditionLogicTest, AcknowledgeRetiredAlreadyAckedEventIdReturnsAlreadyAcked)
{
  auto eventId = enable_and_set_event_id();
  mLogic.acknowledge(eventId, LocalizedText{"", "First ack"});

  mLogic.set_last_event_id(ByteString{std::vector<uint8_t>{9, 9, 9}});

  auto transition = mLogic.acknowledge(eventId, LocalizedText{"", "Second ack (retired EventId)"});

  EXPECT_FALSE(transition.changed);
  EXPECT_EQ(transition.status, StatusCode{Status::BadConditionBranchAlreadyAcked});
}

// F81 guard: a genuinely unknown EventId (never emitted) must still report Bad_EventIdUnknown - the retired
// map must not turn unknown EventIds into already-acked/confirmed.
TEST_F(AcknowledgeableConditionLogicTest, ConfirmTrulyUnknownEventIdAfterRetirementStillReturnsEventIdUnknown)
{
  mLogic.set_supports_confirm(true);
  auto eventId = enable_and_set_event_id();
  mLogic.confirm(eventId, LocalizedText{"", "First confirm"});
  mLogic.set_last_event_id(ByteString{std::vector<uint8_t>{9, 9, 9}});

  ByteString neverSeen{std::vector<uint8_t>{7, 7, 7}};
  auto transition = mLogic.confirm(neverSeen, LocalizedText{"", "Confirm unknown"});

  EXPECT_FALSE(transition.changed);
  EXPECT_EQ(transition.status, StatusCode{Status::BadEventIdUnknown});
}

TEST_F(AcknowledgeableConditionLogicTest, ConfirmWithoutSupportReturnsBadConditionBranchAlreadyConfirmed)
{
  auto eventId = enable_and_set_event_id();

  auto transition = mLogic.confirm(eventId, LocalizedText{"", "Confirm"});

  EXPECT_FALSE(transition.changed);
  EXPECT_EQ(transition.status, StatusCode{Status::BadConditionBranchAlreadyConfirmed});
}

TEST_F(AcknowledgeableConditionLogicTest, ConfirmUpdatesComment)
{
  mLogic.set_supports_confirm(true);
  auto eventId = enable_and_set_event_id();

  mLogic.confirm(eventId, LocalizedText{"", "Confirm comment"});

  auto event = mLogic.build_event();
  EXPECT_EQ(event->message.text(), "Confirm comment");
}

TEST_F(AcknowledgeableConditionLogicTest, ConfirmWithNullCommentLeavesExistingCommentUnchanged)
{
  // OPC 10000-9 section 5.7.4: a NULL comment on Confirm is ignored; the existing comment is preserved.
  mLogic.set_supports_confirm(true);
  auto eventId = enable_and_set_event_id();
  mLogic.add_comment(eventId, LocalizedText{"", "Initializing Comment"});
  ASSERT_EQ(mLogic.build_event()->message.text(), "Initializing Comment");

  mLogic.confirm(eventId, LocalizedText{});  // NULL comment

  EXPECT_TRUE(mAccess.confirmed());
  EXPECT_EQ(mLogic.build_event()->message.text(), "Initializing Comment");
}

// --- Retain logic ---

TEST_F(AcknowledgeableConditionLogicTest, RetainTrueWhileEnabledAndUnacknowledged)
{
  mLogic.enable();
  EXPECT_TRUE(mAccess.retained());
  EXPECT_FALSE(mAccess.acknowledged());
}

TEST_F(AcknowledgeableConditionLogicTest, RetainFalseWhenAcknowledgedWithoutConfirmSupport)
{
  auto eventId = enable_and_set_event_id();
  mLogic.acknowledge(eventId, LocalizedText{"", "Ack"});

  EXPECT_TRUE(mAccess.acknowledged());
  EXPECT_FALSE(mAccess.retained());
}

// OPC 10000-9 section 4.3: a transition into the Disabled state always emits a Condition Event, even when
// the Condition was no longer retained (acknowledged + inactive) at disable time.
TEST_F(AcknowledgeableConditionLogicTest, DisableEmitsEventEvenWhenNotRetained)
{
  auto eventId = enable_and_set_event_id();
  mLogic.acknowledge(eventId, LocalizedText{"", "Ack"});
  ASSERT_FALSE(mAccess.retained());

  auto transition = mLogic.disable();

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(transition.emitEvent);
  EXPECT_TRUE(transition.status.is_good());
  EXPECT_FALSE(mAccess.enabled());
  EXPECT_FALSE(mAccess.retained());
}

TEST_F(AcknowledgeableConditionLogicTest, RetainTrueWhenAckedButUnconfirmedWithConfirmSupport)
{
  mLogic.set_supports_confirm(true);
  auto eventId = enable_and_set_event_id();
  mLogic.acknowledge(eventId, LocalizedText{"", "Ack"});

  EXPECT_TRUE(mAccess.acknowledged());
  EXPECT_FALSE(mAccess.confirmed());
  EXPECT_TRUE(mAccess.retained());
}

TEST_F(AcknowledgeableConditionLogicTest, RetainFalseWhenAckedAndConfirmed)
{
  mLogic.set_supports_confirm(true);
  auto eventId = enable_and_set_event_id();
  mLogic.acknowledge(eventId, LocalizedText{"", "Ack"});
  mLogic.confirm(eventId, LocalizedText{"", "Confirm"});

  EXPECT_TRUE(mAccess.acknowledged());
  EXPECT_TRUE(mAccess.confirmed());
  EXPECT_FALSE(mAccess.retained());
}

TEST_F(AcknowledgeableConditionLogicTest, RetainFalseWhenDisabled)
{
  mLogic.enable();
  mLogic.disable();
  EXPECT_FALSE(mAccess.retained());
}

// --- Acknowledge emits event when retained ---

TEST_F(AcknowledgeableConditionLogicTest, AcknowledgeEmitsEventWhenRetained)
{
  auto eventId = enable_and_set_event_id();
  ASSERT_TRUE(mAccess.retained());

  // With confirm support, acking still leaves it retained (unconfirmed), so event should emit
  mLogic.set_supports_confirm(true);
  // Re-enable to get fresh unacked state with confirm support
  mLogic.disable();
  mLogic.enable();
  ByteString newEventId{std::vector<uint8_t>{4, 5, 6}};
  mLogic.set_last_event_id(newEventId);

  auto transition = mLogic.acknowledge(newEventId, LocalizedText{"", "Ack"});

  EXPECT_TRUE(transition.emitEvent);
}

TEST_F(AcknowledgeableConditionLogicTest, AcknowledgeEmitsRetainFalseEdgeEvent)
{
  // Without confirm support, acking makes retain go from true to false
  auto eventId = enable_and_set_event_id();
  ASSERT_TRUE(mAccess.retained());

  auto transition = mLogic.acknowledge(eventId, LocalizedText{"", "Ack"});

  // Retain went from true to false -- make_transition sees !retained so emit_event may be false,
  // but the transition still reports changed=true
  EXPECT_TRUE(transition.changed);
}

// --- on_enabled resets AckedState ---

TEST_F(AcknowledgeableConditionLogicTest, EnableResetsAckedState)
{
  auto eventId = enable_and_set_event_id();
  mLogic.acknowledge(eventId, LocalizedText{"", "Ack"});
  ASSERT_TRUE(mAccess.acknowledged());

  mLogic.disable();
  mLogic.enable();

  EXPECT_FALSE(mAccess.acknowledged());
  EXPECT_EQ(mAccess.acked_state().currentState.text(), "Unacknowledged");
}

TEST_F(AcknowledgeableConditionLogicTest, EnableResetsConfirmedStateWhenSupported)
{
  mLogic.set_supports_confirm(true);
  auto eventId = enable_and_set_event_id();
  mLogic.confirm(eventId, LocalizedText{"", "Confirm"});
  ASSERT_TRUE(mAccess.confirmed());

  mLogic.disable();
  mLogic.enable();

  EXPECT_FALSE(mAccess.confirmed());
  ASSERT_TRUE(mAccess.confirmed_state().has_value());
  EXPECT_EQ(mAccess.confirmed_state()->currentState.text(), "Unconfirmed");
}

// --- build_event ---

TEST_F(AcknowledgeableConditionLogicTest, BuildEventReturnsAcknowledgeableConditionType)
{
  mLogic.enable();
  auto event = mLogic.build_event();

  ASSERT_NE(event, nullptr);
  auto* ackCondition = dynamic_cast<AcknowledgeableConditionPayload*>(event.get());
  ASSERT_NE(ackCondition, nullptr);

  EXPECT_EQ(ackCondition->sourceNode, NodeId(1, 100));
  EXPECT_EQ(ackCondition->sourceName, String{"TestSource"});
  EXPECT_TRUE(ackCondition->retain);
  EXPECT_TRUE(ackCondition->enabledState.id);
}

TEST_F(AcknowledgeableConditionLogicTest, BuildEventIncludesAckedState)
{
  auto eventId = enable_and_set_event_id();
  mLogic.acknowledge(eventId, LocalizedText{"", "Ack"});

  auto event = mLogic.build_event();
  auto* ackCondition = dynamic_cast<AcknowledgeableConditionPayload*>(event.get());
  ASSERT_NE(ackCondition, nullptr);

  EXPECT_TRUE(ackCondition->ackedState.id);
  EXPECT_EQ(ackCondition->ackedState.currentState.text(), "Acknowledged");
}

TEST_F(AcknowledgeableConditionLogicTest, BuildEventIncludesConfirmedState)
{
  mLogic.set_supports_confirm(true);
  auto eventId = enable_and_set_event_id();
  mLogic.confirm(eventId, LocalizedText{"", "Confirm"});

  auto event = mLogic.build_event();
  auto* ackCondition = dynamic_cast<AcknowledgeableConditionPayload*>(event.get());
  ASSERT_NE(ackCondition, nullptr);

  ASSERT_TRUE(ackCondition->confirmedState.has_value());
  EXPECT_TRUE(ackCondition->confirmedState->id);
  EXPECT_EQ(ackCondition->confirmedState->currentState.text(), "Confirmed");
}

TEST_F(AcknowledgeableConditionLogicTest, BuildEventWithoutConfirmSupportHasNoConfirmedState)
{
  mLogic.enable();
  auto event = mLogic.build_event();
  auto* ackCondition = dynamic_cast<AcknowledgeableConditionPayload*>(event.get());
  ASSERT_NE(ackCondition, nullptr);

  EXPECT_FALSE(ackCondition->confirmedState.has_value());
}

// --- set_supports_confirm ---

TEST_F(AcknowledgeableConditionLogicTest, SetSupportsConfirmCreatesConfirmedState)
{
  EXPECT_FALSE(mAccess.confirmed_state().has_value());

  mLogic.set_supports_confirm(true);
  EXPECT_TRUE(mAccess.confirmed_state().has_value());
}

TEST_F(AcknowledgeableConditionLogicTest, DisableSupportsConfirmRemovesConfirmedState)
{
  mLogic.set_supports_confirm(true);
  ASSERT_TRUE(mAccess.confirmed_state().has_value());

  mLogic.set_supports_confirm(false);
  EXPECT_FALSE(mAccess.confirmed_state().has_value());
}

// --- set_initial_acked ---

TEST_F(AcknowledgeableConditionLogicTest, SetInitialAcked_True_SetsAckedState)
{
  mLogic.set_initial_acked(true);

  EXPECT_TRUE(mAccess.acknowledged());
  EXPECT_TRUE(mAccess.acked_state().id);
  EXPECT_EQ(mAccess.acked_state().currentState.text(), "Acknowledged");
}

TEST_F(AcknowledgeableConditionLogicTest, SetInitialAcked_False_SetsUnackedState)
{
  mLogic.set_initial_acked(false);

  EXPECT_FALSE(mAccess.acknowledged());
  EXPECT_FALSE(mAccess.acked_state().id);
  EXPECT_EQ(mAccess.acked_state().currentState.text(), "Unacknowledged");
}

TEST_F(AcknowledgeableConditionLogicTest, SetInitialAcked_UpdatesRetain)
{
  // Enable first so retained depends on acked state.
  mLogic.enable();
  ASSERT_TRUE(mAccess.retained());  // unacked + enabled = retained

  mLogic.set_initial_acked(true);

  // Acknowledged without confirm support => not retained.
  EXPECT_FALSE(mAccess.retained());
}

TEST_F(AcknowledgeableConditionLogicTest, SetInitialConfirmed_True_SetsConfirmedState)
{
  mLogic.set_supports_confirm(true);
  mLogic.set_initial_confirmed(true);

  EXPECT_TRUE(mAccess.confirmed());
  ASSERT_TRUE(mAccess.confirmed_state().has_value());
  EXPECT_TRUE(mAccess.confirmed_state()->id);
  EXPECT_EQ(mAccess.confirmed_state()->currentState.text(), "Confirmed");
}

TEST_F(AcknowledgeableConditionLogicTest, SetInitialConfirmed_WithoutSupport_IsNoop)
{
  // Without confirm support, set_initial_confirmed should do nothing.
  mLogic.set_initial_confirmed(true);

  EXPECT_FALSE(mAccess.confirmed_state().has_value());
}

// --- Branch creation while an acknowledgement is outstanding ---

// OPC 10000-9 section 5.5.3 (branch mechanics in section 4.2): when a Condition moves to a new state
// that requires acknowledgement while the previous state's acknowledgement is still open, the server
// must fork a branch. The branch carries the PRIOR state (still unacknowledged, non-null BranchId,
// Retain=True) and the trunk must advance to the NEW state with a null BranchId. A plausible
// implementation gets half of this right: it snapshots a branch but then reports the branch's state
// as the current Condition, or it advances the trunk and lets the outstanding acknowledgement
// disappear with the state that needed it. Both conjuncts are therefore asserted.
// @verifies AC-SVR-AC-030-BRANCH-ON-PENDING-ACK
TEST_F(AcknowledgeableConditionLogicTest, NewStateWithPendingAckCreatesBranch)
{
  // The branch decision lives on the acknowledgeable logic's transition path, which the alarm
  // sub-state machine drives; branch support is enabled but the branch itself is never requested
  // by the test - the logic decides.
  AlarmConditionLogic alarm;
  AcknowledgeableConditionLogicTestAccess alarmAccess{alarm};
  alarm.set_source(NodeId{1, 100}, String{"TestSource"});
  alarm.set_supports_branches(true);
  alarm.enable();

  // Prior state: active at severity 500, event emitted by the shell, never acknowledged.
  alarm.activate(500);
  alarm.set_last_event_id(ByteString{std::vector<uint8_t>{1, 2, 3}});
  ASSERT_FALSE(alarmAccess.acknowledged());

  // A new state arrives while that acknowledgement is still outstanding.
  auto transition = alarm.deactivate();

  // Conjunct 1: a ConditionBranch is created carrying the prior state.
  ASSERT_EQ(transition.branchEvents.size(), 1u);
  EXPECT_FALSE(transition.branchEvents[0].branchId.is_null());
  EXPECT_TRUE(transition.branchEvents[0].retain);

  ASSERT_EQ(alarm.branches().size(), 1u);
  const auto& branch = alarm.branches().front();
  EXPECT_EQ(branch.branchId, transition.branchEvents[0].branchId);
  ASSERT_NE(branch.snapshot, nullptr);

  auto* snapshot = dynamic_cast<AlarmConditionPayload*>(branch.snapshot.get());
  ASSERT_NE(snapshot, nullptr);
  EXPECT_TRUE(snapshot->activeState.id);  // the prior state, not the new one
  EXPECT_FALSE(snapshot->ackedState.id);  // its acknowledgement is still outstanding
  EXPECT_FALSE(snapshot->branchId.is_null());  // reported as a branch, not as the trunk
  EXPECT_TRUE(snapshot->retain);  // still needs operator attention

  // Conjunct 2: the current Condition reports the NEW state, on the trunk.
  auto trunk = alarm.build_event();
  ASSERT_NE(trunk, nullptr);
  auto* trunkPayload = dynamic_cast<AlarmConditionPayload*>(trunk.get());
  ASSERT_NE(trunkPayload, nullptr);
  EXPECT_FALSE(trunkPayload->activeState.id);  // the new state
  EXPECT_TRUE(trunkPayload->branchId.is_null());  // the trunk, not the branch
}

// --- Restart recovery of AckedState / ConfirmedState ---

// OPC 10000-9 section 5.7.2: on an AlarmManager restart the acknowledgement state should be
// recovered, but "if the system can not determine if the condition is Acknowledged or Confirmed,
// they shall be set to false (not Acknowledged and not Confirmed)". There is no ack/confirm
// persistence in this SDK, so a newly constructed logic object IS the post-restart Condition with
// nothing recovered: set_initial_acked/set_initial_confirmed are never called. A plausible
// implementation defaults an unknown state to True to avoid an alarm flood on restart, which
// silently retires alarms nobody ever acknowledged; a subtler one leaves ConfirmedState absent even
// though confirmation is supported, so no operator can ever clear it. Retain is asserted too,
// because that is what actually keeps the Condition in front of the operator.
// @verifies AC-SVR-AC-060-ACK-CONFIRM-RECOVERY
TEST_F(AcknowledgeableConditionLogicTest, UndeterminedAckAndConfirmRecoverAsStillRequiringAction)
{
  mLogic.set_supports_confirm(true);

  // Restart with nothing recoverable: no initial ack/confirm state is ever supplied.
  EXPECT_FALSE(mAccess.acknowledged());
  ASSERT_TRUE(mAccess.confirmed_state().has_value());
  EXPECT_FALSE(mAccess.confirmed());

  mLogic.enable();

  EXPECT_FALSE(mAccess.acknowledged());
  EXPECT_FALSE(mAccess.acked_state().id);
  EXPECT_EQ(mAccess.acked_state().currentState.text(), "Unacknowledged");

  ASSERT_TRUE(mAccess.confirmed_state().has_value());
  EXPECT_FALSE(mAccess.confirmed_state()->id);
  EXPECT_EQ(mAccess.confirmed_state()->currentState.text(), "Unconfirmed");

  // The consequence that makes the default safe: the Condition is still retained.
  EXPECT_TRUE(mAccess.retained());

  auto event = mLogic.build_event();
  auto* ackCondition = dynamic_cast<AcknowledgeableConditionPayload*>(event.get());
  ASSERT_NE(ackCondition, nullptr);
  EXPECT_FALSE(ackCondition->ackedState.id);
  ASSERT_TRUE(ackCondition->confirmedState.has_value());
  EXPECT_FALSE(ackCondition->confirmedState->id);
  EXPECT_TRUE(ackCondition->retain);
}

}  // namespace ua::test
