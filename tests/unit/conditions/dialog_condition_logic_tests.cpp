// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_dialog_condition_logic.h"

#include "ua_data_value.h"
#include "ua_dialog_condition_payload.h"
#include "ua_status.h"
#include "ua_variant.h"

#include <gtest/gtest.h>

namespace ua::test
{

/// Test-access helper to read protected/private state from DialogConditionLogic.
class DialogConditionLogicTestAccess
{
public:
  explicit DialogConditionLogicTestAccess(DialogConditionLogic& logic) : mLogic(logic)
  {}

  bool enabled() const
  {
    return mLogic.enabled();
  }

  bool retained() const
  {
    return mLogic.retained();
  }

  const TwoStateVariableState& dialog_state() const
  {
    return mLogic.dialog_state();
  }

  int32_t last_response() const
  {
    return mLogic.last_response();
  }

  const LocalizedText& prompt() const
  {
    return mLogic.mPrompt;
  }

  int32_t default_response() const
  {
    return mLogic.mDefaultResponse;
  }

  int32_t ok_response() const
  {
    return mLogic.mOkResponse;
  }

  int32_t cancel_response() const
  {
    return mLogic.mCancelResponse;
  }

  int32_t num_options() const
  {
    return mLogic.mNumOptions;
  }

private:
  DialogConditionLogic& mLogic;
};

class DialogConditionLogicTest : public ::testing::Test
{
protected:
  DialogConditionLogic mLogic;
  DialogConditionLogicTestAccess mAccess{mLogic};

  void SetUp() override
  {
    mLogic.set_source(NodeId{1, 100}, String{"TestSource"});
  }

  void enable_with_options(int32_t numOptions)
  {
    mLogic.enable();
    mLogic.set_response_options(numOptions);
  }

  void enable_activate_with_options(
    int32_t numOptions, LocalizedText prompt = LocalizedText{"", "Test prompt"})
  {
    mLogic.enable();
    mLogic.set_response_options(numOptions);
    mLogic.activate_dialog(std::move(prompt));
  }
};

// =============================================================================
// Initial state
// =============================================================================

TEST_F(DialogConditionLogicTest, StartsDisabledAndInactive)
{
  EXPECT_FALSE(mAccess.enabled());
  EXPECT_FALSE(mAccess.dialog_state().id);
  EXPECT_FALSE(mAccess.retained());
  EXPECT_EQ(mAccess.last_response(), -1);
}

// =============================================================================
// Disabled-state negative test
// =============================================================================

TEST_F(DialogConditionLogicTest, ActivateDialogWhileDisabled_NoTransitionEmitted)
{
  // Do NOT enable. Activating a dialog while disabled should not produce an event.
  mLogic.set_response_options(3);

  auto transition = mLogic.activate_dialog(LocalizedText{"", "Should not work"});

  EXPECT_FALSE(transition.emitEvent);
}

// =============================================================================
// activate_dialog
// =============================================================================

TEST_F(DialogConditionLogicTest, ActivateDialogSetsDialogStateActive)
{
  mLogic.enable();
  mLogic.set_response_options(3);

  auto transition = mLogic.activate_dialog(LocalizedText{"", "Do you want to continue?"});

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.dialog_state().id);
  EXPECT_EQ(mAccess.prompt().text(), "Do you want to continue?");
}

TEST_F(DialogConditionLogicTest, ActivateDialogSetsRetainTrue)
{
  mLogic.enable();
  mLogic.set_response_options(3);

  mLogic.activate_dialog(LocalizedText{"", "Prompt"});

  EXPECT_TRUE(mAccess.retained());
}

TEST_F(DialogConditionLogicTest, ActivateDialogEmitsEventWhenRetained)
{
  mLogic.enable();
  mLogic.set_response_options(3);

  auto transition = mLogic.activate_dialog(LocalizedText{"", "Prompt"});

  EXPECT_TRUE(transition.emitEvent);
}

// =============================================================================
// respond (single-arg)
// =============================================================================

TEST_F(DialogConditionLogicTest, RespondDeactivatesDialog)
{
  enable_activate_with_options(3);
  ASSERT_TRUE(mAccess.dialog_state().id);

  auto transition = mLogic.respond(1);

  EXPECT_TRUE(transition.changed);
  EXPECT_FALSE(mAccess.dialog_state().id);
  EXPECT_EQ(mAccess.last_response(), 1);
}

TEST_F(DialogConditionLogicTest, RespondClearsRetain)
{
  enable_activate_with_options(3);
  ASSERT_TRUE(mAccess.retained());

  mLogic.respond(0);

  EXPECT_FALSE(mAccess.retained());
}

TEST_F(DialogConditionLogicTest, RespondReturnsBadDialogNotActiveWhenInactive)
{
  mLogic.enable();
  mLogic.set_response_options(3);
  // Do not activate

  auto transition = mLogic.respond(0);

  EXPECT_EQ(transition.status, StatusCode{Status::BadDialogNotActive});
  EXPECT_FALSE(transition.changed);
}

TEST_F(DialogConditionLogicTest, RespondReturnsBadDialogResponseInvalidForNegativeIndex)
{
  enable_activate_with_options(3);

  auto transition = mLogic.respond(-1);

  EXPECT_EQ(transition.status, StatusCode{Status::BadDialogResponseInvalid});
  EXPECT_FALSE(transition.changed);
  EXPECT_TRUE(mAccess.dialog_state().id);  // Dialog remains active
}

TEST_F(DialogConditionLogicTest, RespondReturnsBadDialogResponseInvalidForOutOfRangeIndex)
{
  enable_activate_with_options(3);

  auto transition = mLogic.respond(3);  // valid: 0, 1, 2

  EXPECT_EQ(transition.status, StatusCode{Status::BadDialogResponseInvalid});
  EXPECT_FALSE(transition.changed);
  EXPECT_TRUE(mAccess.dialog_state().id);  // Dialog remains active
}

TEST_F(DialogConditionLogicTest, RespondAcceptsLastValidIndex)
{
  enable_activate_with_options(3);

  auto transition = mLogic.respond(2);  // valid: 0, 1, 2

  EXPECT_TRUE(transition.changed);
  EXPECT_FALSE(mAccess.dialog_state().id);
  EXPECT_EQ(mAccess.last_response(), 2);
}

TEST_F(DialogConditionLogicTest, RespondAcceptsFirstValidIndex)
{
  enable_activate_with_options(3);

  auto transition = mLogic.respond(0);

  EXPECT_TRUE(transition.changed);
  EXPECT_EQ(mAccess.last_response(), 0);
}

// =============================================================================
// respond with comment
// =============================================================================

TEST_F(DialogConditionLogicTest, RespondWithCommentDeactivatesDialogAndSetsComment)
{
  enable_activate_with_options(3);
  mLogic.set_last_event_id(ByteString{std::vector<uint8_t>{1, 2, 3}});

  auto transition = mLogic.respond(1, LocalizedText{"", "User chose option 1"});

  EXPECT_TRUE(transition.changed);
  EXPECT_FALSE(mAccess.dialog_state().id);
  EXPECT_EQ(mAccess.last_response(), 1);
}

TEST_F(DialogConditionLogicTest, RespondWithCommentReturnsBadDialogNotActiveWhenInactive)
{
  mLogic.enable();
  mLogic.set_response_options(3);

  auto transition = mLogic.respond(0, LocalizedText{"", "Comment"});

  EXPECT_EQ(transition.status, StatusCode{Status::BadDialogNotActive});
}

TEST_F(DialogConditionLogicTest, RespondWithCommentReturnsBadDialogResponseInvalidForOutOfRange)
{
  enable_activate_with_options(3);

  auto transition = mLogic.respond(5, LocalizedText{"", "Comment"});

  EXPECT_EQ(transition.status, StatusCode{Status::BadDialogResponseInvalid});
  EXPECT_TRUE(mAccess.dialog_state().id);  // Dialog remains active
}

// =============================================================================
// compute_retain
// =============================================================================

TEST_F(DialogConditionLogicTest, RetainFalseWhenDisabled)
{
  // Not enabled, dialog not active
  EXPECT_FALSE(mAccess.retained());
}

TEST_F(DialogConditionLogicTest, RetainFalseWhenEnabledButDialogInactive)
{
  mLogic.enable();
  EXPECT_FALSE(mAccess.retained());
}

TEST_F(DialogConditionLogicTest, RetainTrueWhenEnabledAndDialogActive)
{
  mLogic.enable();
  mLogic.set_response_options(3);
  mLogic.activate_dialog(LocalizedText{"", "Prompt"});

  EXPECT_TRUE(mAccess.retained());
}

TEST_F(DialogConditionLogicTest, RetainFalseAfterDialogResponded)
{
  enable_activate_with_options(3);
  ASSERT_TRUE(mAccess.retained());

  mLogic.respond(0);

  EXPECT_FALSE(mAccess.retained());
}

// =============================================================================
// Configuration
// =============================================================================

TEST_F(DialogConditionLogicTest, ConfigurationRoundTrip)
{
  mLogic.set_response_options(5);
  EXPECT_EQ(mAccess.num_options(), 5);

  mLogic.set_default_response(2);
  EXPECT_EQ(mAccess.default_response(), 2);

  mLogic.set_ok_response(0);
  EXPECT_EQ(mAccess.ok_response(), 0);

  mLogic.set_cancel_response(1);
  EXPECT_EQ(mAccess.cancel_response(), 1);
}

// =============================================================================
// build_event
// =============================================================================

TEST_F(DialogConditionLogicTest, BuildEventReturnsDialogConditionType)
{
  mLogic.enable();
  mLogic.set_response_options(3);
  mLogic.set_default_response(0);
  mLogic.set_ok_response(0);
  mLogic.set_cancel_response(2);
  mLogic.activate_dialog(LocalizedText{"", "Proceed?"});

  auto event = mLogic.build_event();

  ASSERT_NE(event, nullptr);
  auto* dialog = dynamic_cast<DialogConditionPayload*>(event.get());
  ASSERT_NE(dialog, nullptr);

  EXPECT_TRUE(dialog->dialogState.id);
  EXPECT_EQ(dialog->prompt.text(), "Proceed?");
  EXPECT_EQ(dialog->responseOptionSet.size(), 3u);
  EXPECT_EQ(dialog->defaultResponse, 0);
  EXPECT_EQ(dialog->okResponse, 0);
  EXPECT_EQ(dialog->cancelResponse, 2);
  EXPECT_EQ(dialog->lastResponse, -1);
}

TEST_F(DialogConditionLogicTest, BuildEventAfterRespondShowsLastResponse)
{
  enable_activate_with_options(3);
  mLogic.respond(1);

  auto event = mLogic.build_event();

  auto* dialog = dynamic_cast<DialogConditionPayload*>(event.get());
  ASSERT_NE(dialog, nullptr);

  EXPECT_FALSE(dialog->dialogState.id);
  EXPECT_EQ(dialog->lastResponse, 1);
}

}  // namespace ua::test
