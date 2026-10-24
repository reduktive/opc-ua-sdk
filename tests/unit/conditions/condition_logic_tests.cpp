// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_condition_logic.h"

#include "ua_condition_payload.h"
#include "ua_data_value.h"
#include "ua_objecttype_id.h"
#include "ua_status.h"

#include <gtest/gtest.h>

namespace ua::test
{

/// Test-access helper to read protected state from ConditionLogic.
class ConditionLogicTestAccess
{
public:
  explicit ConditionLogicTestAccess(ConditionLogic& logic) : mLogic(logic)
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

  const StatusCode& quality() const
  {
    return mLogic.quality();
  }

  const ByteString& last_event_id() const
  {
    return mLogic.last_event_id();
  }

  const TwoStateVariableState& enabled_state() const
  {
    return mLogic.enabled_state();
  }

private:
  ConditionLogic& mLogic;
};

class ConditionLogicTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mLogic.set_source(NodeId{1, 100}, String{"TestSource"});
  }

  ConditionLogic mLogic;
  ConditionLogicTestAccess mAccess{mLogic};
};

// --- Enable / Disable ---

TEST_F(ConditionLogicTest, StartsDisabled)
{
  EXPECT_FALSE(mAccess.enabled());
  EXPECT_FALSE(mAccess.retained());
}

TEST_F(ConditionLogicTest, EnableTransitionsToEnabled)
{
  auto transition = mLogic.enable();

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(transition.emitEvent);
  EXPECT_TRUE(transition.status.is_good());
  EXPECT_TRUE(mAccess.enabled());
  EXPECT_TRUE(mAccess.retained());

  // EnabledState should reflect the transition
  EXPECT_TRUE(mAccess.enabled_state().id);
  EXPECT_EQ(mAccess.enabled_state().currentState.text(), "Enabled");
}

TEST_F(ConditionLogicTest, EnableWhenAlreadyEnabledReturnsBadConditionAlreadyEnabled)
{
  mLogic.enable();
  auto transition = mLogic.enable();

  EXPECT_FALSE(transition.changed);
  EXPECT_FALSE(transition.emitEvent);
  EXPECT_EQ(transition.status, StatusCode{Status::BadConditionAlreadyEnabled});
}

TEST_F(ConditionLogicTest, DisableTransitionsToDisabled)
{
  mLogic.enable();
  auto transition = mLogic.disable();

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(transition.emitEvent);  // Retain True->False edge emits
  EXPECT_TRUE(transition.status.is_good());
  EXPECT_FALSE(mAccess.enabled());
  EXPECT_FALSE(mAccess.retained());

  EXPECT_FALSE(mAccess.enabled_state().id);
  EXPECT_EQ(mAccess.enabled_state().currentState.text(), "Disabled");
}

TEST_F(ConditionLogicTest, DisableWhenAlreadyDisabledReturnsBadConditionAlreadyDisabled)
{
  auto transition = mLogic.disable();

  EXPECT_FALSE(transition.changed);
  EXPECT_FALSE(transition.emitEvent);
  EXPECT_EQ(transition.status, StatusCode{Status::BadConditionAlreadyDisabled});
}

TEST_F(ConditionLogicTest, DisableFromRetainedEmitsEvent)
{
  mLogic.enable();
  ASSERT_TRUE(mAccess.retained());

  auto transition = mLogic.disable();
  EXPECT_TRUE(transition.emitEvent);
}

TEST_F(ConditionLogicTest, EnableDisableEnableCycle)
{
  auto t1 = mLogic.enable();
  EXPECT_TRUE(t1.changed);
  EXPECT_TRUE(mAccess.enabled());

  auto t2 = mLogic.disable();
  EXPECT_TRUE(t2.changed);
  EXPECT_FALSE(mAccess.enabled());

  auto t3 = mLogic.enable();
  EXPECT_TRUE(t3.changed);
  EXPECT_TRUE(mAccess.enabled());
}

// --- Severity ---

TEST_F(ConditionLogicTest, SetSeverityWhileEnabledEmitsEvent)
{
  mLogic.enable();
  auto transition = mLogic.set_severity(500);

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(transition.emitEvent);
  EXPECT_EQ(mAccess.severity(), 500);
}

TEST_F(ConditionLogicTest, SetSeverityWhileDisabledDoesNotEmitEvent)
{
  auto transition = mLogic.set_severity(500);

  EXPECT_TRUE(transition.changed);
  EXPECT_FALSE(transition.emitEvent);
  EXPECT_EQ(mAccess.severity(), 500);
}

// --- Quality ---

TEST_F(ConditionLogicTest, SetQualityWhileEnabledEmitsEvent)
{
  mLogic.enable();
  auto transition = mLogic.set_quality(StatusCode{Status::UncertainLastUsableValue});

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(transition.emitEvent);
  EXPECT_EQ(mAccess.quality(), StatusCode{Status::UncertainLastUsableValue});
}

TEST_F(ConditionLogicTest, SetQualityWhileDisabledDoesNotEmitEvent)
{
  auto transition = mLogic.set_quality(StatusCode{Status::UncertainLastUsableValue});

  EXPECT_TRUE(transition.changed);
  EXPECT_FALSE(transition.emitEvent);
}

// --- AddComment ---

TEST_F(ConditionLogicTest, AddCommentWithValidEventIdSucceeds)
{
  mLogic.enable();
  ByteString eventId{std::vector<uint8_t>{1, 2, 3}};
  mLogic.set_last_event_id(eventId);

  auto transition = mLogic.add_comment(eventId, LocalizedText{"", "Test comment"});

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(transition.emitEvent);
  EXPECT_TRUE(transition.status.is_good());
}

TEST_F(ConditionLogicTest, AddCommentWithInvalidEventIdReturnsBadEventIdUnknown)
{
  mLogic.enable();
  ByteString validId{std::vector<uint8_t>{1, 2, 3}};
  ByteString wrongId{std::vector<uint8_t>{4, 5, 6}};
  mLogic.set_last_event_id(validId);

  auto transition = mLogic.add_comment(wrongId, LocalizedText{"", "Test comment"});

  EXPECT_FALSE(transition.changed);
  EXPECT_FALSE(transition.emitEvent);
  EXPECT_EQ(transition.status, StatusCode{Status::BadEventIdUnknown});
}

TEST_F(ConditionLogicTest, AddCommentWhileDisabledDoesNotEmitEvent)
{
  // Even with matching event ID, if disabled (not retained), no event emission
  ByteString eventId{std::vector<uint8_t>{1, 2, 3}};
  mLogic.set_last_event_id(eventId);

  auto transition = mLogic.add_comment(eventId, LocalizedText{"", "Comment"});

  EXPECT_TRUE(transition.changed);
  EXPECT_FALSE(transition.emitEvent);
}

// --- Setters ---

TEST_F(ConditionLogicTest, SetConditionName)
{
  mLogic.set_condition_name(String{"TestCondition"});

  mLogic.enable();
  auto event = mLogic.build_event();
  auto* condition = dynamic_cast<ConditionPayload*>(event.get());
  ASSERT_NE(condition, nullptr);
  EXPECT_EQ(condition->conditionName, String{"TestCondition"});
}

TEST_F(ConditionLogicTest, SetConditionClass)
{
  mLogic.set_condition_class(NodeId{ObjectTypeId::ConditionType}, LocalizedText{"", "ConditionType"});

  mLogic.enable();
  auto event = mLogic.build_event();
  auto* condition = dynamic_cast<ConditionPayload*>(event.get());
  ASSERT_NE(condition, nullptr);
  EXPECT_EQ(condition->conditionClassId, NodeId{ObjectTypeId::ConditionType});
}

// Part 9 mandatory condition fields must be present with correct datatypes even when the application
// sets nothing: ConditionClassId defaults to BaseConditionClassType, Quality to a Good StatusCode,
// and Comment to an empty-but-typed LocalizedText (not a null Variant).
TEST_F(ConditionLogicTest, BuildEventPopulatesMandatoryFieldDefaults)
{
  mLogic.enable();
  auto event = mLogic.build_event();
  auto* condition = dynamic_cast<ConditionPayload*>(event.get());
  ASSERT_NE(condition, nullptr);

  EXPECT_EQ(condition->conditionClassId, NodeId{ObjectTypeId::BaseConditionClassType});
  // ConditionClassName must match the DisplayName of the ConditionClassId node (Part 9).
  EXPECT_EQ(condition->conditionClassName, LocalizedText("", "BaseConditionClassType"));

  const auto* quality = condition->quality.value.try_as<StatusCode>();
  ASSERT_NE(quality, nullptr) << "Quality must be a StatusCode";
  EXPECT_TRUE(quality->is_good());

  EXPECT_NE(condition->comment.value.try_as<LocalizedText>(), nullptr) << "Comment must be a LocalizedText";
}

TEST_F(ConditionLogicTest, SetClientUserId)
{
  mLogic.set_client_user_id(String{"admin"});

  mLogic.enable();
  auto event = mLogic.build_event();
  auto* condition = dynamic_cast<ConditionPayload*>(event.get());
  ASSERT_NE(condition, nullptr);
  EXPECT_EQ(condition->clientUserId, String{"admin"});
}

// --- Build Event ---

TEST_F(ConditionLogicTest, BuildEventReturnsConditionType)
{
  mLogic.enable();
  auto event = mLogic.build_event();

  ASSERT_NE(event, nullptr);
  auto* condition = dynamic_cast<ConditionPayload*>(event.get());
  ASSERT_NE(condition, nullptr);

  EXPECT_EQ(condition->sourceNode, NodeId(1, 100));
  EXPECT_EQ(condition->sourceName, String{"TestSource"});
  EXPECT_TRUE(condition->retain);
  EXPECT_TRUE(condition->enabledState.id);
}

TEST_F(ConditionLogicTest, BuildEventWhileDisabledShowsNotRetained)
{
  auto event = mLogic.build_event();

  auto* condition = dynamic_cast<ConditionPayload*>(event.get());
  ASSERT_NE(condition, nullptr);
  EXPECT_FALSE(condition->retain);
  EXPECT_FALSE(condition->enabledState.id);
}

TEST_F(ConditionLogicTest, BuildEventIncludesSeverity)
{
  mLogic.enable();
  mLogic.set_severity(750);

  auto event = mLogic.build_event();
  EXPECT_EQ(event->severity, 750);
}

TEST_F(ConditionLogicTest, BuildEventIncludesSupportsFilteredRetain)
{
  mLogic.set_supports_filtered_retain(true);
  mLogic.enable();

  auto event = mLogic.build_event();
  auto* condition = dynamic_cast<ConditionPayload*>(event.get());
  ASSERT_NE(condition, nullptr);
  EXPECT_TRUE(condition->supportsFilteredRetain);
}

// --- Retain logic ---

TEST_F(ConditionLogicTest, RetainIsTrueWhenEnabled)
{
  mLogic.enable();
  EXPECT_TRUE(mAccess.retained());
}

TEST_F(ConditionLogicTest, RetainIsFalseWhenDisabled)
{
  EXPECT_FALSE(mAccess.retained());
}

TEST_F(ConditionLogicTest, RetainTransitionFromTrueToFalseEmitsEvent)
{
  mLogic.enable();
  ASSERT_TRUE(mAccess.retained());

  // Disable causes Retain True->False, which should emit
  auto transition = mLogic.disable();
  EXPECT_TRUE(transition.emitEvent);
}

TEST_F(ConditionLogicTest, StateChangeWhileNotRetainedDoesNotEmitEvent)
{
  // ConditionPayload is disabled (not retained). State changes should not emit.
  auto transition = mLogic.set_severity(100);
  EXPECT_FALSE(transition.emitEvent);
}

// --- SetSeverity tracks LastSeverity ---

TEST_F(ConditionLogicTest, SetSeverityTracksLastSeverityInEvent)
{
  mLogic.enable();
  mLogic.set_severity(100);
  mLogic.set_severity(500);

  auto event = mLogic.build_event();
  auto* condition = dynamic_cast<ConditionPayload*>(event.get());
  ASSERT_NE(condition, nullptr);

  // last_severity should hold the value before the last set_severity call (100)
  EXPECT_EQ(condition->lastSeverity.value.as<uint16_t>(), 100);
}

// --- set_initial_enabled ---

TEST_F(ConditionLogicTest, SetInitialEnabled_True_SetsEnabledWithoutEvent)
{
  mLogic.set_initial_enabled(true);

  EXPECT_TRUE(mAccess.enabled());
  EXPECT_TRUE(mAccess.retained());
  EXPECT_TRUE(mAccess.enabled_state().id);
  EXPECT_EQ(mAccess.enabled_state().currentState.text(), "Enabled");
}

TEST_F(ConditionLogicTest, SetInitialEnabled_False_LeavesDisabled)
{
  mLogic.set_initial_enabled(false);

  EXPECT_FALSE(mAccess.enabled());
  EXPECT_FALSE(mAccess.retained());
  EXPECT_FALSE(mAccess.enabled_state().id);
  EXPECT_EQ(mAccess.enabled_state().currentState.text(), "Disabled");
}

TEST_F(ConditionLogicTest, SetInitialEnabled_DoesNotEmitEvent)
{
  // set_initial_enabled sets state directly without returning a transition.
  // Verify by checking that after set_initial_enabled(true), calling enable()
  // returns BadConditionAlreadyEnabled (proving the state was set without going
  // through the normal enable path that emits).
  mLogic.set_initial_enabled(true);

  auto transition = mLogic.enable();
  EXPECT_EQ(transition.status, StatusCode{Status::BadConditionAlreadyEnabled});
  EXPECT_FALSE(transition.changed);
}

// ===========================================================================
// Phase D.3: Communication Failure & Miscellaneous Logic
// ===========================================================================

// COND-1100: Quality can be set to Bad_NoCommunication
TEST_F(ConditionLogicTest, SetQuality_BadNoCommunication_SetsQualityCorrectly)
{
  mLogic.enable();
  auto transition = mLogic.set_quality(StatusCode{Status::BadNoCommunication});

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(transition.emitEvent);
  EXPECT_EQ(mAccess.quality(), StatusCode{Status::BadNoCommunication});
}

// COND-1102: Initial quality is Good (no quality issue) before any input
// Covers SVR-AC-052 (coverage-audit retag).
TEST_F(ConditionLogicTest, InitialQuality_IsGood)
{
  EXPECT_TRUE(mAccess.quality().is_good()) << "Initial quality should be Good before any set_quality call";
}

// COND-1100: Quality can transition from bad back to good
TEST_F(ConditionLogicTest, SetQuality_BadToGood_EmitsEvent)
{
  mLogic.enable();
  mLogic.set_quality(StatusCode{Status::BadNoCommunication});

  auto transition = mLogic.set_quality(StatusCode{Status::Good});

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(transition.emitEvent);
  EXPECT_TRUE(mAccess.quality().is_good());
}

// COND-1102: Quality value appears in built event
TEST_F(ConditionLogicTest, BuildEvent_IncludesQuality)
{
  mLogic.enable();
  mLogic.set_quality(StatusCode{Status::BadNoCommunication});

  auto event = mLogic.build_event();
  auto* condition = dynamic_cast<ConditionPayload*>(event.get());
  ASSERT_NE(condition, nullptr);
  EXPECT_EQ(condition->quality.value.as<StatusCode>(), StatusCode{Status::BadNoCommunication});
}

// Part 9 section 5.5.2: a Server that supports no quality information shall return Good. The plausible
// wrong answers are both "honest looking": leaving Quality unset (a null Variant, so the mandatory
// field carries no StatusCode at all), or reporting Uncertain - which asserts the server *has*
// quality information and doubts it, and would be filtered out by clients that hide uncertain
// alarms. Nothing in this fixture sets quality, so the value asserted here is the one the
// production default produces, on the accessor and in the field actually emitted to clients.
// @verifies AC-SVR-AC-052-NO-QUALITY-MEANS-GOOD
TEST_F(ConditionLogicTest, QualityWithoutQualityInformationIsGoodNotUncertainOrNull)
{
  // No set_quality() call anywhere: this condition tracks no quality information.
  EXPECT_EQ(mAccess.quality(), StatusCode{Status::Good});
  EXPECT_TRUE(mAccess.quality().is_good());
  EXPECT_FALSE(mAccess.quality().is_uncertain());

  mLogic.enable();
  auto event = mLogic.build_event();
  auto* condition = dynamic_cast<ConditionPayload*>(event.get());
  ASSERT_NE(condition, nullptr);

  const auto* quality = condition->quality.value.try_as<StatusCode>();
  ASSERT_NE(quality, nullptr) << "Quality must carry a StatusCode, not a null value";
  EXPECT_EQ(*quality, StatusCode{Status::Good});
  EXPECT_TRUE(quality->is_good());
  EXPECT_FALSE(quality->is_uncertain());
}

// Part 9 section 5.5.6: three LocalizedText payloads must be told apart by a comment-bearing method - NULL
// (locale and text both empty) means "no comment supplied" and preserves the existing one, an empty
// text carried WITH a non-empty locale is the explicit reset, and non-empty text is a new comment.
// The locale is the only thing separating the first two, so an implementation that decides on the
// text alone ("nothing was typed, so there is nothing to record") collapses the reset into the
// ignore case and makes an applied comment permanent: an operator could correct a comment but never
// withdraw one. This drives all three shapes through add_comment() in sequence and reads the Comment
// the way a client does - off the emitted event field, not an internal accessor.
// @verifies AC-SVR-AC-055-COMMENT-RESET-SHAPE
TEST_F(ConditionLogicTest, EmptyCommentTextWithALocaleClearsTheExistingComment)
{
  mLogic.enable();
  const ByteString eventId{std::vector<uint8_t>{7, 8, 9}};
  mLogic.set_last_event_id(eventId);

  // (3) Non-empty text: recorded as the current comment.
  auto applied = mLogic.add_comment(eventId, LocalizedText{"en", "Pump overheating"});
  ASSERT_TRUE(applied.status.is_good());
  {
    auto event = mLogic.build_event();
    auto* condition = dynamic_cast<ConditionPayload*>(event.get());
    ASSERT_NE(condition, nullptr);
    const auto* comment = condition->comment.value.try_as<LocalizedText>();
    ASSERT_NE(comment, nullptr) << "Comment must be a LocalizedText";
    ASSERT_EQ(comment->text(), String{"Pump overheating"});
  }

  // (1) NULL LocalizedText: ignored, the existing comment survives. Establishes that "empty text"
  // on its own is not what clears the comment, so the reset below cannot pass by accident.
  auto ignored = mLogic.add_comment(eventId, LocalizedText{});
  ASSERT_TRUE(ignored.status.is_good());
  {
    auto event = mLogic.build_event();
    auto* condition = dynamic_cast<ConditionPayload*>(event.get());
    ASSERT_NE(condition, nullptr);
    const auto* comment = condition->comment.value.try_as<LocalizedText>();
    ASSERT_NE(comment, nullptr) << "Comment must be a LocalizedText";
    ASSERT_EQ(comment->text(), String{"Pump overheating"}) << "A NULL comment must preserve the existing one";
  }

  // (2) Empty text plus a non-empty locale: the reset form.
  auto reset = mLogic.add_comment(eventId, LocalizedText{"en", ""});
  EXPECT_TRUE(reset.changed);
  EXPECT_TRUE(reset.status.is_good());

  auto event = mLogic.build_event();
  auto* condition = dynamic_cast<ConditionPayload*>(event.get());
  ASSERT_NE(condition, nullptr);
  const auto* comment = condition->comment.value.try_as<LocalizedText>();
  ASSERT_NE(comment, nullptr) << "Comment must remain a typed LocalizedText after a reset, not a null value";
  EXPECT_TRUE(comment->text().empty()) << "Empty text with a locale must clear the comment";
  EXPECT_NE(comment->text(), String{"Pump overheating"});
}

// Part 9 section 5.5.4: while a Condition is Disabled only EventId, EventType, SourceNode, SourceName, Time
// and EnabledState stay valid; a read of any other Condition Variable must report
// Bad_ConditionDisabled rather than the value it last held. The plausible implementation treats
// disabling as an event-suppression concern only - it clears Retain, stops emitting, and leaves the
// state fields exactly as they were - so the state this class hands to the read path (the
// address-space Quality read is served straight off this Quality state) keeps returning the last
// live value with a Good status. A client that polls rather than subscribes then cannot tell a
// disabled Condition from a healthy live one. This drives the real enable/set/disable path and reads
// the same getter the read path uses, and it checks both directions of the rule: the state Variable
// goes Bad, while the whitelisted EnabledState and the source identification stay valid, so a
// blanket "everything is Bad now" is not a pass either.
// @verifies AC-SVR-AC-011-DISABLED-VARIABLES-BAD
TEST_F(ConditionLogicTest, DisabledConditionReportsStateVariablesAsBadNotTheirLastValues)
{
  mLogic.enable();
  mLogic.set_quality(StatusCode{Status::UncertainLastUsableValue});
  mLogic.set_severity(700);

  // The stale value must be observable while enabled, otherwise the assertions below could pass
  // against a Condition that never held a value at all.
  ASSERT_TRUE(mAccess.enabled());
  ASSERT_EQ(mAccess.quality(), StatusCode{Status::UncertainLastUsableValue});

  auto transition = mLogic.disable();
  ASSERT_TRUE(transition.changed);
  ASSERT_FALSE(mAccess.enabled());

  // ConditionLogic's chosen disabled-state representation makes Quality unavailable.
  EXPECT_EQ(mAccess.quality(), StatusCode{Status::BadConditionDisabled});
  EXPECT_FALSE(mAccess.quality().is_good());
  EXPECT_NE(mAccess.quality(), StatusCode{Status::UncertainLastUsableValue})
    << "A disabled Condition must not keep serving the value its Quality held while enabled";

  // EnabledState remains valid while disabled - it is how a Client learns the Condition is disabled.
  EXPECT_FALSE(mAccess.enabled_state().id);
  EXPECT_EQ(mAccess.enabled_state().currentState.text(), "Disabled");

  // SourceNode and SourceName remain valid as well.
  auto event = mLogic.build_event();
  auto* condition = dynamic_cast<ConditionPayload*>(event.get());
  ASSERT_NE(condition, nullptr);
  EXPECT_EQ(condition->sourceNode, NodeId(1, 100));
  EXPECT_EQ(condition->sourceName, String{"TestSource"});
}

}  // namespace ua::test
