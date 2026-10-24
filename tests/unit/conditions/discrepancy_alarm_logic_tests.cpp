// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_discrepancy_alarm_logic.h"

#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_discrepancy_alarm_payload.h"
#include "ua_status.h"
#include "ua_variant.h"

#include <chrono>

#include <gtest/gtest.h>

namespace ua::test
{

namespace
{

/// Create a DateTime offset from another by the given number of milliseconds.
DateTime offset_ms(const DateTime& base, int64_t ms)
{
  auto tp =
    base.value() + std::chrono::duration_cast<datetime::OneHundredNanoSeconds>(std::chrono::milliseconds{ms});
  return DateTime{tp};
}

}  // namespace

/// Test-access helper to read protected/private state from DiscrepancyAlarmLogic.
class DiscrepancyAlarmLogicTestAccess
{
public:
  explicit DiscrepancyAlarmLogicTestAccess(DiscrepancyAlarmLogic& logic) : mLogic(logic)
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

  const NodeId& target_value_node() const
  {
    return mLogic.target_value_node();
  }

  double expected_time_ms() const
  {
    return mLogic.expected_time_ms();
  }

  const std::optional<double>& tolerance() const
  {
    return mLogic.tolerance();
  }

private:
  DiscrepancyAlarmLogic& mLogic;
};

class DiscrepancyAlarmLogicTest : public ::testing::Test
{
protected:
  DiscrepancyAlarmLogic mLogic;
  DiscrepancyAlarmLogicTestAccess mAccess{mLogic};

  void SetUp() override
  {
    mLogic.set_source(NodeId{1, 100}, String{"TestSource"});
  }

  void enable_with_target(Variant targetValue, double expectedTimeMs)
  {
    mLogic.enable();
    mLogic.set_target_value(std::move(targetValue));
    mLogic.set_expected_time(expectedTimeMs);
  }
};

// =============================================================================
// Configuration
// =============================================================================

TEST_F(DiscrepancyAlarmLogicTest, ConfigurationRoundTrip)
{
  NodeId nodeId{1, 200};
  mLogic.set_target_value_node(nodeId);
  EXPECT_EQ(mAccess.target_value_node(), nodeId);

  mLogic.set_expected_time(5000.0);
  EXPECT_DOUBLE_EQ(mAccess.expected_time_ms(), 5000.0);

  mLogic.set_tolerance(0.5);
  ASSERT_TRUE(mAccess.tolerance().has_value());
  EXPECT_DOUBLE_EQ(*mAccess.tolerance(), 0.5);
}

// =============================================================================
// =============================================================================
// evaluate_input: activate when expected time exceeded
// =============================================================================

// Covers SVR-AC-219 (coverage-audit retag).
TEST_F(DiscrepancyAlarmLogicTest, ActivatesWhenExpectedTimeExceeded)
{
  enable_with_target(Variant{100.0}, 1000.0);

  auto t0 = DateTime::now();
  // Off-target, start tracking
  auto transition = mLogic.evaluate_input(Variant{50.0}, t0);
  EXPECT_FALSE(transition.changed);
  EXPECT_FALSE(mAccess.active());

  // Still off-target, but expected time exceeded
  auto t1 = offset_ms(t0, 1001);
  transition = mLogic.evaluate_input(Variant{50.0}, t1);
  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.active());
}

TEST_F(DiscrepancyAlarmLogicTest, DoesNotActivateBeforeExpectedTimeElapsed)
{
  enable_with_target(Variant{100.0}, 5000.0);

  auto t0 = DateTime::now();
  mLogic.evaluate_input(Variant{50.0}, t0);

  // Only 2 seconds elapsed, expected time is 5 seconds
  auto t1 = offset_ms(t0, 2000);
  auto transition = mLogic.evaluate_input(Variant{50.0}, t1);
  EXPECT_FALSE(transition.changed);
  EXPECT_FALSE(mAccess.active());
}

// =============================================================================
// evaluate_input: deactivate when target reached
// =============================================================================

// Covers SVR-AC-211 (coverage-audit retag).
// @verifies AC-SVR-AC-211-DISCREPANCY-NORMAL-AT-TARGET
TEST_F(DiscrepancyAlarmLogicTest, DeactivatesWhenTargetReached)
{
  enable_with_target(Variant{100.0}, 1000.0);

  auto t0 = DateTime::now();
  mLogic.evaluate_input(Variant{50.0}, t0);

  auto t1 = offset_ms(t0, 1001);
  mLogic.evaluate_input(Variant{50.0}, t1);
  ASSERT_TRUE(mAccess.active());

  // Reach target - deactivate
  auto transition = mLogic.evaluate_input(Variant{100.0}, t1);
  EXPECT_TRUE(transition.changed);
  EXPECT_FALSE(mAccess.active());
}

TEST_F(DiscrepancyAlarmLogicTest, ReachingTargetBeforeTimeoutPreventsActivation)
{
  enable_with_target(Variant{100.0}, 5000.0);

  auto t0 = DateTime::now();
  mLogic.evaluate_input(Variant{50.0}, t0);
  EXPECT_FALSE(mAccess.active());

  // Reach target before expected time elapses - should clear tracking
  auto t1 = offset_ms(t0, 1000);
  auto transition = mLogic.evaluate_input(Variant{100.0}, t1);
  EXPECT_FALSE(transition.changed);
  EXPECT_FALSE(mAccess.active());
}

TEST_F(DiscrepancyAlarmLogicTest, ReachingTargetResetsTrackingTimer)
{
  enable_with_target(Variant{100.0}, 2000.0);

  auto t0 = DateTime::now();
  // Start discrepancy tracking
  mLogic.evaluate_input(Variant{50.0}, t0);

  // Reach target at 1 second - resets tracking
  auto t1 = offset_ms(t0, 1000);
  mLogic.evaluate_input(Variant{100.0}, t1);

  // Go off-target again at 1.5 seconds - starts new tracking
  auto t2 = offset_ms(t0, 1500);
  mLogic.evaluate_input(Variant{50.0}, t2);

  // At 3 seconds (only 1.5s since new tracking) - should NOT activate
  auto t3 = offset_ms(t0, 3000);
  auto transition = mLogic.evaluate_input(Variant{50.0}, t3);
  EXPECT_FALSE(transition.changed);
  EXPECT_FALSE(mAccess.active());

  // At 3.6 seconds (>2s since new tracking) - should activate
  auto t4 = offset_ms(t0, 3600);
  transition = mLogic.evaluate_input(Variant{50.0}, t4);
  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.active());
}

// =============================================================================
// evaluate_input: tolerance
// =============================================================================

TEST_F(DiscrepancyAlarmLogicTest, ToleranceAllowsNearTargetValues)
{
  enable_with_target(Variant{100.0}, 1000.0);
  mLogic.set_tolerance(5.0);

  auto t0 = DateTime::now();
  // Within tolerance (|97 - 100| = 3 <= 5) - treated as at-target
  auto transition = mLogic.evaluate_input(Variant{97.0}, t0);
  EXPECT_FALSE(transition.changed);
  EXPECT_FALSE(mAccess.active());
}

TEST_F(DiscrepancyAlarmLogicTest, ToleranceRejectsOutOfRangeValues)
{
  enable_with_target(Variant{100.0}, 1000.0);
  mLogic.set_tolerance(5.0);

  auto t0 = DateTime::now();
  // Outside tolerance (|90 - 100| = 10 > 5) - off-target
  mLogic.evaluate_input(Variant{90.0}, t0);

  // Expected time exceeded
  auto t1 = offset_ms(t0, 1001);
  auto transition = mLogic.evaluate_input(Variant{90.0}, t1);
  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.active());
}

// =============================================================================
// evaluate_input: no re-activation when already active
// =============================================================================

TEST_F(DiscrepancyAlarmLogicTest, DoesNotReActivateWhenAlreadyActive)
{
  enable_with_target(Variant{100.0}, 1000.0);

  auto t0 = DateTime::now();
  mLogic.evaluate_input(Variant{50.0}, t0);

  auto t1 = offset_ms(t0, 1001);
  mLogic.evaluate_input(Variant{50.0}, t1);
  ASSERT_TRUE(mAccess.active());

  // Still off-target - should not re-activate
  auto t2 = offset_ms(t0, 2000);
  auto transition = mLogic.evaluate_input(Variant{60.0}, t2);
  EXPECT_FALSE(transition.changed);
  EXPECT_TRUE(mAccess.active());
}

// =============================================================================
// evaluate_input: at-target when disabled has no effect
// =============================================================================

TEST_F(DiscrepancyAlarmLogicTest, DoesNothingWhenAtTargetAndAlreadyInactive)
{
  enable_with_target(Variant{100.0}, 1000.0);

  auto t0 = DateTime::now();
  auto transition = mLogic.evaluate_input(Variant{100.0}, t0);
  EXPECT_FALSE(transition.changed);
  EXPECT_FALSE(mAccess.active());
}

// =============================================================================
// build_event
// =============================================================================

TEST_F(DiscrepancyAlarmLogicTest, BuildEventReturnsDiscrepancyAlarmType)
{
  enable_with_target(Variant{100.0}, 5000.0);
  mLogic.set_tolerance(2.5);

  NodeId targetNode{1, 300};
  mLogic.set_target_value_node(targetNode);

  auto event = mLogic.build_event();

  ASSERT_NE(event, nullptr);
  auto* discrepancyAlarm = dynamic_cast<DiscrepancyAlarmPayload*>(event.get());
  ASSERT_NE(discrepancyAlarm, nullptr);

  EXPECT_EQ(discrepancyAlarm->targetValueNode, targetNode);
  EXPECT_EQ(discrepancyAlarm->expectedTime, Variant{5000.0});
  ASSERT_TRUE(discrepancyAlarm->tolerance.has_value());
  EXPECT_DOUBLE_EQ(*discrepancyAlarm->tolerance, 2.5);
}

TEST_F(DiscrepancyAlarmLogicTest, BuildEventWithoutToleranceHasNoTolerance)
{
  enable_with_target(Variant{100.0}, 5000.0);

  auto event = mLogic.build_event();

  auto* discrepancyAlarm = dynamic_cast<DiscrepancyAlarmPayload*>(event.get());
  ASSERT_NE(discrepancyAlarm, nullptr);
  EXPECT_FALSE(discrepancyAlarm->tolerance.has_value());
}

TEST_F(DiscrepancyAlarmLogicTest, BuildEventCapturesActiveState)
{
  enable_with_target(Variant{100.0}, 1000.0);

  auto t0 = DateTime::now();
  mLogic.evaluate_input(Variant{50.0}, t0);
  auto t1 = offset_ms(t0, 1001);
  mLogic.evaluate_input(Variant{50.0}, t1);
  ASSERT_TRUE(mAccess.active());

  auto event = mLogic.build_event();
  auto* discrepancyAlarm = dynamic_cast<DiscrepancyAlarmPayload*>(event.get());
  ASSERT_NE(discrepancyAlarm, nullptr);
  EXPECT_TRUE(discrepancyAlarm->activeState.id);
}

// =============================================================================
// evaluate_input: integer comparison
// =============================================================================

TEST_F(DiscrepancyAlarmLogicTest, WorksWithIntegerTargetValues)
{
  enable_with_target(Variant{int32_t{42}}, 1000.0);

  auto t0 = DateTime::now();
  // Off-target
  mLogic.evaluate_input(Variant{int32_t{10}}, t0);

  auto t1 = offset_ms(t0, 1001);
  auto transition = mLogic.evaluate_input(Variant{int32_t{10}}, t1);
  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.active());

  // Reach target
  transition = mLogic.evaluate_input(Variant{int32_t{42}}, t1);
  EXPECT_TRUE(transition.changed);
  EXPECT_FALSE(mAccess.active());
}

}  // namespace ua::test
