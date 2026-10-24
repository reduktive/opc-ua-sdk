// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_off_normal_alarm_logic.h"

#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_off_normal_alarm_payload.h"
#include "ua_qualified_name.h"
#include "ua_status.h"
#include "ua_variant.h"

#include <gtest/gtest.h>

#include <array>

namespace ua::test
{

/// Test-access helper to read protected/private state from OffNormalAlarmLogic.
class OffNormalAlarmLogicTestAccess
{
public:
  explicit OffNormalAlarmLogicTestAccess(OffNormalAlarmLogic& logic) : mLogic(logic)
  {}

  bool enabled() const
  {
    return mLogic.enabled();
  }

  bool retained() const
  {
    return mLogic.retained();
  }

  bool active() const
  {
    return mLogic.active();
  }

  bool acknowledged() const
  {
    return mLogic.acknowledged();
  }

  const TwoStateVariableState& active_state() const
  {
    return mLogic.active_state();
  }

  const Variant& normal_state() const
  {
    return mLogic.normal_state();
  }

  const NodeId& normal_state_node() const
  {
    return mLogic.normal_state_node();
  }

private:
  OffNormalAlarmLogic& mLogic;
};

class OffNormalAlarmLogicTest : public ::testing::Test
{
protected:
  OffNormalAlarmLogic mLogic;
  OffNormalAlarmLogicTestAccess mAccess{mLogic};

  void SetUp() override
  {
    mLogic.set_source(NodeId{1, 100}, String{"TestSource"});
  }

  void enable_with_normal_state(Variant normalValue)
  {
    mLogic.enable();
    mLogic.set_normal_state(std::move(normalValue));
  }
};

// =============================================================================
// Configuration
// =============================================================================

// An OffNormalAlarm is an AlarmConditionType, so its events carry every AlarmConditionType field. Its
// builder once set ActiveState and SuppressedOrShelved by hand and nothing else, so ShelvingState,
// MaxTimeShelved and InputNode reached Clients as null while the plain alarm carried them - and a Client
// that reads ShelvingState/CurrentState to decide whether an alarm can be shelved never shelved it.
TEST_F(OffNormalAlarmLogicTest, BuildEventCarriesTheAlarmConditionFields)
{
  mLogic.set_max_time_shelved(60000.0);
  const std::array<QualifiedName, 2> shelvingState{
    QualifiedName{0, "ShelvingState"}, QualifiedName{0, "CurrentState"}};
  const std::array<QualifiedName, 1> maxTimeShelved{QualifiedName{0, "MaxTimeShelved"}};
  const Variant unshelved{LocalizedText{"", "Unshelved"}};

  const auto event = mLogic.build_event();
  ASSERT_NE(event, nullptr);
  EXPECT_EQ(event->resolve_field(shelvingState), unshelved);
  EXPECT_EQ(event->resolve_field(maxTimeShelved), Variant{60000.0});
}

TEST_F(OffNormalAlarmLogicTest, ConfigurationRoundTrip)
{
  Variant normalValue{int32_t{42}};
  mLogic.set_normal_state(normalValue);
  EXPECT_EQ(mAccess.normal_state(), normalValue);

  NodeId nodeId{1, 100};
  mLogic.set_normal_state_node(nodeId);
  EXPECT_EQ(mAccess.normal_state_node(), nodeId);
}

// =============================================================================
// evaluate_input: activate when different from normal
// =============================================================================

TEST_F(OffNormalAlarmLogicTest, EvaluateInputActivatesWhenDifferentFromNormal)
{
  enable_with_normal_state(Variant{int32_t{0}});

  auto transition = mLogic.evaluate_input(Variant{int32_t{1}}, DateTime::now());

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.active());
}

TEST_F(OffNormalAlarmLogicTest, EvaluateInputDoesNotReactivateWhenAlreadyActive)
{
  enable_with_normal_state(Variant{int32_t{0}});
  mLogic.evaluate_input(Variant{int32_t{1}}, DateTime::now());
  ASSERT_TRUE(mAccess.active());

  // Evaluating a different off-normal value should not re-activate
  auto transition = mLogic.evaluate_input(Variant{int32_t{2}}, DateTime::now());

  EXPECT_FALSE(transition.changed);
  EXPECT_TRUE(mAccess.active());
}

// =============================================================================
// evaluate_input: deactivate when equal to normal
// =============================================================================

TEST_F(OffNormalAlarmLogicTest, EvaluateInputDeactivatesWhenEqualToNormal)
{
  enable_with_normal_state(Variant{int32_t{0}});
  mLogic.evaluate_input(Variant{int32_t{1}}, DateTime::now());
  ASSERT_TRUE(mAccess.active());

  auto transition = mLogic.evaluate_input(Variant{int32_t{0}}, DateTime::now());

  EXPECT_TRUE(transition.changed);
  EXPECT_FALSE(mAccess.active());
}

TEST_F(OffNormalAlarmLogicTest, EvaluateInputDoesNothingWhenAlreadyInactiveAndNormal)
{
  enable_with_normal_state(Variant{int32_t{0}});

  auto transition = mLogic.evaluate_input(Variant{int32_t{0}}, DateTime::now());

  EXPECT_FALSE(transition.changed);
  EXPECT_FALSE(mAccess.active());
}

// =============================================================================
// evaluate_input: different types
// =============================================================================

TEST_F(OffNormalAlarmLogicTest, EvaluateInputWorksWithBoolValues)
{
  enable_with_normal_state(Variant{true});

  // false != true -> activate
  auto transition = mLogic.evaluate_input(Variant{false}, DateTime::now());
  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.active());

  // true == true -> deactivate
  transition = mLogic.evaluate_input(Variant{true}, DateTime::now());
  EXPECT_TRUE(transition.changed);
  EXPECT_FALSE(mAccess.active());
}

TEST_F(OffNormalAlarmLogicTest, EvaluateInputWorksWithDoubleValues)
{
  enable_with_normal_state(Variant{0.0});

  auto transition = mLogic.evaluate_input(Variant{1.5}, DateTime::now());
  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.active());

  transition = mLogic.evaluate_input(Variant{0.0}, DateTime::now());
  EXPECT_TRUE(transition.changed);
  EXPECT_FALSE(mAccess.active());
}

TEST_F(OffNormalAlarmLogicTest, EvaluateInputWorksWithStringValues)
{
  enable_with_normal_state(Variant{String{"Normal"}});

  auto transition = mLogic.evaluate_input(Variant{String{"Fault"}}, DateTime::now());
  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.active());

  transition = mLogic.evaluate_input(Variant{String{"Normal"}}, DateTime::now());
  EXPECT_TRUE(transition.changed);
  EXPECT_FALSE(mAccess.active());
}

// =============================================================================
// build_event
// =============================================================================

TEST_F(OffNormalAlarmLogicTest, BuildEventReturnsOffNormalAlarmType)
{
  enable_with_normal_state(Variant{int32_t{0}});
  mLogic.evaluate_input(Variant{int32_t{1}}, DateTime::now());

  NodeId normalStateNode{1, 200};
  mLogic.set_normal_state_node(normalStateNode);

  auto event = mLogic.build_event();

  ASSERT_NE(event, nullptr);
  auto* offNormalAlarm = dynamic_cast<OffNormalAlarmPayload*>(event.get());
  ASSERT_NE(offNormalAlarm, nullptr);

  EXPECT_TRUE(offNormalAlarm->activeState.id);
  EXPECT_EQ(offNormalAlarm->normalState, normalStateNode);
}

TEST_F(OffNormalAlarmLogicTest, BuildEventWhenInactiveHasInactiveState)
{
  enable_with_normal_state(Variant{int32_t{0}});

  auto event = mLogic.build_event();

  auto* offNormalAlarm = dynamic_cast<OffNormalAlarmPayload*>(event.get());
  ASSERT_NE(offNormalAlarm, nullptr);
  EXPECT_FALSE(offNormalAlarm->activeState.id);
}

// =============================================================================
// COND-1103: Communication failure reporting
// =============================================================================

// COND-1103: OffNormalAlarmPayload (supertype of SystemOffNormalAlarmPayload) can report
// communication failures. When the input deviates from the normal state the
// alarm activates and emits an OffNormalAlarmPayload event.
TEST_F(OffNormalAlarmLogicTest, CommunicationFailure_ActivatesAndEmitsCorrectEventType)
{
  enable_with_normal_state(Variant{false});  // Normal = false (communication OK)

  // Simulate communication failure: input becomes true (off-normal)
  auto transition = mLogic.evaluate_input(Variant{true}, DateTime::now());
  EXPECT_TRUE(transition.emitEvent);
  EXPECT_TRUE(mAccess.active()) << "Alarm should activate on off-normal condition";

  // Verify the event type is OffNormalAlarmPayload (which SystemOffNormalAlarmPayload inherits from)
  auto event = mLogic.build_event();
  ASSERT_NE(event, nullptr);
  auto* offNormal = dynamic_cast<OffNormalAlarmPayload*>(event.get());
  ASSERT_NE(offNormal, nullptr) << "Event should be OffNormalAlarmPayload type";
  EXPECT_TRUE(offNormal->activeState.id) << "ActiveState should be true in event";
}

// =============================================================================
// NormalState when the normal-state Variable is not in the address space
// =============================================================================

// Part 9 section 5.8.17/section 5.8.24.2: NormalState points at the Variable holding the alarm's normal
// value. When that value is baked into the alarm configuration and no such Variable exists, NormalState must
// be the null NodeId. Two tempting implementations mislead the client: substituting SourceNode says "browse
// here" and returns a Node that is not the normal-state Variable, and any other placeholder is a
// dangling id that fails to resolve. Null is the only value that says "there is no such Node".
// @verifies AC-SVR-AC-117-NORMALSTATE-NULL-WHEN-ABSENT
TEST_F(OffNormalAlarmLogicTest, NormalStateIsNullWhenTheNormalStateVariableIsNotInTheAddressSpace)
{
  // No set_normal_state_node call: the normal value is configured directly on the alarm, so there is
  // no NormalState Variable in the address space to point at.
  enable_with_normal_state(Variant{int32_t{0}});
  ASSERT_EQ(mAccess.normal_state(), Variant{int32_t{0}}) << "The normal state must be configured out of "
                                                            "the address space for this to be the "
                                                            "absent-Variable case";

  // Drive the real evaluation path so the event carries a populated, activated alarm.
  auto transition = mLogic.evaluate_input(Variant{int32_t{1}}, DateTime::now());
  ASSERT_TRUE(transition.changed);
  ASSERT_TRUE(mAccess.active());

  EXPECT_TRUE(mAccess.normal_state_node().is_null());

  auto event = mLogic.build_event();
  ASSERT_NE(event, nullptr);
  auto* offNormal = dynamic_cast<OffNormalAlarmPayload*>(event.get());
  ASSERT_NE(offNormal, nullptr);

  EXPECT_TRUE(offNormal->normalState.is_null());
  EXPECT_EQ(offNormal->normalState, NodeId{});

  // The fixture set a real SourceNode, so the null above is a decision rather than an empty payload:
  // the source must not stand in for the missing NormalState Variable.
  ASSERT_FALSE(offNormal->sourceNode.is_null());
  EXPECT_NE(offNormal->normalState, offNormal->sourceNode);
}

}  // namespace ua::test
