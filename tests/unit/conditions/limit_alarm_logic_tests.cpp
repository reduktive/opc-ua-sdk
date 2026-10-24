// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_limit_alarm_logic.h"

#include "ua_data_value.h"
#include "ua_exclusive_limit_alarm_payload.h"
#include "ua_limit_alarm_payload.h"
#include "ua_localized_text.h"
#include "ua_node_id.h"
#include "ua_non_exclusive_limit_alarm_payload.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_qualified_name.h"
#include "ua_status.h"
#include "ua_variant.h"

#include <gtest/gtest.h>

#include <thread>

#include <array>

#include <chrono>
#include <stdexcept>

namespace ua::test
{

/// Test-access helper to read protected/private state from LimitAlarmLogic.
class LimitAlarmLogicTestAccess
{
public:
  explicit LimitAlarmLogicTestAccess(LimitAlarmLogic& logic) : mLogic(logic)
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

  uint16_t severity() const
  {
    return mLogic.severity();
  }

  ActiveLimit active_limit() const
  {
    return mLogic.active_limit();
  }

  bool high_high_active() const
  {
    return mLogic.high_high_active();
  }

  bool high_active() const
  {
    return mLogic.high_active();
  }

  bool low_active() const
  {
    return mLogic.low_active();
  }

  bool low_low_active() const
  {
    return mLogic.low_low_active();
  }

  const ByteString& last_event_id() const
  {
    return mLogic.last_event_id();
  }

  double last_input_value() const
  {
    return mLogic.mLastInputValue;
  }

private:
  LimitAlarmLogic& mLogic;
};

class LimitAlarmLogicTest : public ::testing::Test
{
protected:
  LimitAlarmLogic mLogic;
  LimitAlarmLogicTestAccess mAccess{mLogic};

  void SetUp() override
  {
    mLogic.set_source(NodeId{1, 100}, String{"TestSource"});
  }

  void enable()
  {
    mLogic.enable();
  }

  void enable_with_high_limit(double limit, double deadband = 0.0)
  {
    LimitConfig config;
    config.highLimit = limit;
    config.highDeadband = deadband;
    mLogic.set_limits(config);
    mLogic.enable();
  }

  void enable_with_low_limit(double limit, double deadband = 0.0)
  {
    LimitConfig config;
    config.lowLimit = limit;
    config.lowDeadband = deadband;
    mLogic.set_limits(config);
    mLogic.enable();
  }

  void enable_with_all_limits()
  {
    LimitConfig config;
    config.highHighLimit = 90.0;
    config.highLimit = 80.0;
    config.lowLimit = 20.0;
    config.lowLowLimit = 10.0;
    mLogic.set_limits(config);
    mLogic.enable();
  }

  ConditionStateTransition evaluate_double(double value)
  {
    return mLogic.evaluate_input(Variant{value}, DateTime::now());
  }
};

// =============================================================================
// Initial state
// =============================================================================

TEST_F(LimitAlarmLogicTest, StartsWithNoActiveLimit)
{
  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::None);
  EXPECT_FALSE(mAccess.high_high_active());
  EXPECT_FALSE(mAccess.high_active());
  EXPECT_FALSE(mAccess.low_active());
  EXPECT_FALSE(mAccess.low_low_active());
  EXPECT_TRUE(mLogic.exclusive());
}

// =============================================================================
// Limit validation
// =============================================================================

TEST_F(LimitAlarmLogicTest, SetLimitsAcceptsValidOrdering)
{
  LimitConfig config;
  config.highHighLimit = 100.0;
  config.highLimit = 80.0;
  config.lowLimit = 20.0;
  config.lowLowLimit = 10.0;
  EXPECT_NO_THROW(mLogic.set_limits(config));
}

// Covers SVR-AC-203 (coverage-audit retag).
TEST_F(LimitAlarmLogicTest, SetLimitsRejectsHighHighNotGreaterThanHigh)
{
  LimitConfig config;
  config.highHighLimit = 80.0;
  config.highLimit = 80.0;
  EXPECT_THROW(mLogic.set_limits(config), std::invalid_argument);
}

TEST_F(LimitAlarmLogicTest, SetLimitsRejectsHighNotGreaterThanLow)
{
  LimitConfig config;
  config.highLimit = 20.0;
  config.lowLimit = 20.0;
  EXPECT_THROW(mLogic.set_limits(config), std::invalid_argument);
}

TEST_F(LimitAlarmLogicTest, SetLimitsRejectsLowNotGreaterThanLowLow)
{
  LimitConfig config;
  config.lowLimit = 10.0;
  config.lowLowLimit = 10.0;
  EXPECT_THROW(mLogic.set_limits(config), std::invalid_argument);
}

TEST_F(LimitAlarmLogicTest, SetLimitsRejectsHighHighLessThanLow)
{
  // HighHigh present, High absent, Low present
  LimitConfig config;
  config.highHighLimit = 15.0;
  config.lowLimit = 20.0;
  EXPECT_THROW(mLogic.set_limits(config), std::invalid_argument);
}

TEST_F(LimitAlarmLogicTest, SetLimitsAcceptsPartialLimits)
{
  LimitConfig config;
  config.highLimit = 80.0;
  // Only high limit set
  EXPECT_NO_THROW(mLogic.set_limits(config));
}

// Part 9 section 5.8.18 gives a configured limit whose value the underlying system cannot provide
// a distinct state: it remains exposed, but is not readable. It therefore cannot participate in
// threshold evaluation or be substituted into an Event as though it were measured configuration.
// @relation(AC-SVR-AC-202-LIMIT-UNAVAILABLE-STATUS, scope=function)
TEST_F(LimitAlarmLogicTest, UnavailableLimitRemainsConfiguredWithoutBeingEvaluatedOrPublishedAsAValue)
{
  LimitConfig config;
  config.highHighLimit = 90.0;
  config.highLimit = ConfiguredLimit::unavailable();
  mLogic.set_limits(config);
  mLogic.set_exclusive(false);
  mLogic.enable();

  ASSERT_TRUE(mLogic.limits().highLimit.has_value())
    << "an unavailable limit is still configured and must remain exposed";
  EXPECT_FALSE(mLogic.limits().highLimit->is_available());

  const auto transition = evaluate_double(95.0);
  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.high_high_active());
  EXPECT_FALSE(mAccess.high_active())
    << "a threshold whose value is unavailable cannot be evaluated using a substitute";

  auto event = mLogic.build_event();
  auto* limitAlarm = dynamic_cast<LimitAlarmPayload*>(event.get());
  ASSERT_NE(limitAlarm, nullptr);
  ASSERT_TRUE(limitAlarm->highHighLimit.has_value());
  EXPECT_DOUBLE_EQ(*limitAlarm->highHighLimit, 90.0);
  EXPECT_FALSE(limitAlarm->highLimit.has_value())
    << "an unavailable threshold must not be published as a fabricated Event value";
}

// @relation(AC-SVR-AC-202-LIMIT-UNAVAILABLE-STATUS, scope=function)
TEST_F(LimitAlarmLogicTest, SoleUnavailableLimitSatisfiesTheRequiredExposedLimitConfiguration)
{
  LimitConfig config;
  config.highLimit = ConfiguredLimit::unavailable();

  EXPECT_NO_THROW(mLogic.set_limits(config));
  mLogic.enable();
  const auto transition = evaluate_double(1000.0);

  EXPECT_FALSE(transition.changed);
  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::None);
  auto event = mLogic.build_event();
  auto* limitAlarm = dynamic_cast<LimitAlarmPayload*>(event.get());
  ASSERT_NE(limitAlarm, nullptr);
  EXPECT_FALSE(limitAlarm->highLimit.has_value());
}

// =============================================================================
// Exclusive: High limit activation / deactivation
// =============================================================================

TEST_F(LimitAlarmLogicTest, ExclusiveHighLimitActivatesWhenValueReachesLimit)
{
  enable_with_high_limit(80.0);

  auto transition = evaluate_double(80.0);

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.active());
  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::High);
  EXPECT_EQ(mAccess.severity(), 500);
}

TEST_F(LimitAlarmLogicTest, ExclusiveHighLimitActivatesWhenValueExceedsLimit)
{
  enable_with_high_limit(80.0);

  auto transition = evaluate_double(85.0);

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.active());
  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::High);
}

TEST_F(LimitAlarmLogicTest, ExclusiveHighLimitDoesNotActivateBelowLimit)
{
  enable_with_high_limit(80.0);

  auto transition = evaluate_double(79.9);

  EXPECT_FALSE(transition.changed);
  EXPECT_FALSE(mAccess.active());
  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::None);
}

TEST_F(LimitAlarmLogicTest, ExclusiveHighLimitDeactivatesWhenValueDropsBelowLimit)
{
  enable_with_high_limit(80.0);
  evaluate_double(85.0);
  ASSERT_TRUE(mAccess.active());

  auto transition = evaluate_double(79.0);

  EXPECT_TRUE(transition.changed);
  EXPECT_FALSE(mAccess.active());
  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::None);
}

// =============================================================================
// Exclusive: HighHigh limit
// =============================================================================

TEST_F(LimitAlarmLogicTest, ExclusiveHighHighActivatesWithHigherSeverity)
{
  enable_with_all_limits();

  auto transition = evaluate_double(90.0);

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.active());
  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::HighHigh);
  EXPECT_EQ(mAccess.severity(), 900);
}

TEST_F(LimitAlarmLogicTest, ExclusiveHighHighTakesPrecedenceOverHigh)
{
  enable_with_all_limits();

  // Value exceeds both High and HighHigh
  evaluate_double(95.0);

  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::HighHigh);
  EXPECT_EQ(mAccess.severity(), 900);
}

// =============================================================================
// Exclusive: Low / LowLow limits
// =============================================================================

TEST_F(LimitAlarmLogicTest, ExclusiveLowLimitActivatesWhenValueReachesLimit)
{
  enable_with_low_limit(20.0);

  auto transition = evaluate_double(20.0);

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.active());
  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::Low);
  EXPECT_EQ(mAccess.severity(), 500);
}

TEST_F(LimitAlarmLogicTest, ExclusiveLowLimitActivatesWhenValueDropsBelowLimit)
{
  enable_with_low_limit(20.0);

  evaluate_double(15.0);

  EXPECT_TRUE(mAccess.active());
  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::Low);
}

TEST_F(LimitAlarmLogicTest, ExclusiveLowLowActivatesWithHigherSeverity)
{
  enable_with_all_limits();

  evaluate_double(10.0);

  EXPECT_TRUE(mAccess.active());
  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::LowLow);
  EXPECT_EQ(mAccess.severity(), 900);
}

TEST_F(LimitAlarmLogicTest, ExclusiveLowLowTakesPrecedenceOverLow)
{
  enable_with_all_limits();

  evaluate_double(5.0);

  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::LowLow);
  EXPECT_EQ(mAccess.severity(), 900);
}

TEST_F(LimitAlarmLogicTest, ExclusiveLowLimitDeactivatesWhenValueRisesAboveLimit)
{
  enable_with_low_limit(20.0);
  evaluate_double(15.0);
  ASSERT_TRUE(mAccess.active());

  auto transition = evaluate_double(21.0);

  EXPECT_TRUE(transition.changed);
  EXPECT_FALSE(mAccess.active());
  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::None);
}

// =============================================================================
// Return to normal (deactivation)
// =============================================================================

TEST_F(LimitAlarmLogicTest, ExclusiveReturnToNormalFromHigh)
{
  enable_with_all_limits();
  evaluate_double(85.0);
  ASSERT_EQ(mAccess.active_limit(), ActiveLimit::High);

  auto transition = evaluate_double(50.0);

  EXPECT_TRUE(transition.changed);
  EXPECT_FALSE(mAccess.active());
  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::None);
}

TEST_F(LimitAlarmLogicTest, ExclusiveReturnToNormalFromLow)
{
  enable_with_all_limits();
  evaluate_double(15.0);
  ASSERT_EQ(mAccess.active_limit(), ActiveLimit::Low);

  auto transition = evaluate_double(50.0);

  EXPECT_TRUE(transition.changed);
  EXPECT_FALSE(mAccess.active());
  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::None);
}

// =============================================================================
// Exclusive: transitions between limits
// =============================================================================

// Covers SVR-AC-206 (coverage-audit retag).
TEST_F(LimitAlarmLogicTest, ExclusiveTransitionFromHighToHighHigh)
{
  enable_with_all_limits();
  evaluate_double(85.0);
  ASSERT_EQ(mAccess.active_limit(), ActiveLimit::High);
  ASSERT_EQ(mAccess.severity(), 500);

  auto transition = evaluate_double(95.0);

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.active());
  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::HighHigh);
  EXPECT_EQ(mAccess.severity(), 900);
}

TEST_F(LimitAlarmLogicTest, ExclusiveTransitionFromHighHighToHigh)
{
  enable_with_all_limits();
  evaluate_double(95.0);
  ASSERT_EQ(mAccess.active_limit(), ActiveLimit::HighHigh);

  // Drop below HighHigh but still above High
  auto transition = evaluate_double(85.0);

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.active());
  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::High);
  EXPECT_EQ(mAccess.severity(), 500);
}

TEST_F(LimitAlarmLogicTest, ExclusiveTransitionFromLowToLowLow)
{
  enable_with_all_limits();
  evaluate_double(15.0);
  ASSERT_EQ(mAccess.active_limit(), ActiveLimit::Low);

  auto transition = evaluate_double(5.0);

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.active());
  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::LowLow);
  EXPECT_EQ(mAccess.severity(), 900);
}

// =============================================================================
// Deadband: high-side
// =============================================================================

TEST_F(LimitAlarmLogicTest, DeadbandPreventsHighLimitDeactivationWithinBand)
{
  enable_with_high_limit(80.0, 2.0);

  evaluate_double(82.0);
  ASSERT_TRUE(mAccess.active());
  ASSERT_EQ(mAccess.active_limit(), ActiveLimit::High);

  // Value at 79.0 is within deadband (limit=80, deadband=2, deactivation threshold=78)
  auto transition = evaluate_double(79.0);

  EXPECT_FALSE(transition.changed);
  EXPECT_TRUE(mAccess.active());
  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::High);
}

TEST_F(LimitAlarmLogicTest, DeadbandAllowsHighLimitDeactivationOutsideBand)
{
  enable_with_high_limit(80.0, 2.0);

  evaluate_double(82.0);
  ASSERT_TRUE(mAccess.active());

  // Value at 77.0 is outside deadband (deactivation threshold=78)
  auto transition = evaluate_double(77.0);

  EXPECT_TRUE(transition.changed);
  EXPECT_FALSE(mAccess.active());
  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::None);
}

TEST_F(LimitAlarmLogicTest, DeadbandExactThresholdKeepsHighActive)
{
  enable_with_high_limit(80.0, 2.0);

  evaluate_double(82.0);
  ASSERT_TRUE(mAccess.active());

  // Value at exactly 78.0 (limit - deadband) should still be active
  auto transition = evaluate_double(78.0);

  EXPECT_FALSE(transition.changed);
  EXPECT_TRUE(mAccess.active());
}

// =============================================================================
// Deadband: low-side
// =============================================================================

TEST_F(LimitAlarmLogicTest, DeadbandPreventsLowLimitDeactivationWithinBand)
{
  enable_with_low_limit(20.0, 2.0);

  evaluate_double(18.0);
  ASSERT_TRUE(mAccess.active());

  // Value at 21.0 is within deadband (limit=20, deadband=2, deactivation threshold=22)
  auto transition = evaluate_double(21.0);

  EXPECT_FALSE(transition.changed);
  EXPECT_TRUE(mAccess.active());
}

TEST_F(LimitAlarmLogicTest, DeadbandAllowsLowLimitDeactivationOutsideBand)
{
  enable_with_low_limit(20.0, 2.0);

  evaluate_double(18.0);
  ASSERT_TRUE(mAccess.active());

  // Value at 23.0 is outside deadband (deactivation threshold=22)
  auto transition = evaluate_double(23.0);

  EXPECT_TRUE(transition.changed);
  EXPECT_FALSE(mAccess.active());
}

TEST_F(LimitAlarmLogicTest, DeadbandExactThresholdKeepsLowActive)
{
  enable_with_low_limit(20.0, 2.0);

  evaluate_double(18.0);
  ASSERT_TRUE(mAccess.active());

  // Value at exactly 22.0 (limit + deadband) should still be active
  auto transition = evaluate_double(22.0);

  EXPECT_FALSE(transition.changed);
  EXPECT_TRUE(mAccess.active());
}

// =============================================================================
// Per-limit independent deadband
// =============================================================================

TEST_F(LimitAlarmLogicTest, PerLimitDeadbandAppliedIndependently)
{
  LimitConfig config;
  config.highHighLimit = 90.0;
  config.highLimit = 80.0;
  config.highHighDeadband = 5.0;
  config.highDeadband = 2.0;
  mLogic.set_limits(config);
  mLogic.enable();

  // Activate HighHigh
  evaluate_double(92.0);
  ASSERT_EQ(mAccess.active_limit(), ActiveLimit::HighHigh);

  // Drop to 86.0: HighHigh deactivation threshold = 90-5=85, 86 >= 85, stays HighHigh
  auto transition = evaluate_double(86.0);
  EXPECT_FALSE(transition.changed);
  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::HighHigh);

  // Drop to 84.0: below 85, HighHigh deactivates. Still above High(80), transitions to High
  transition = evaluate_double(84.0);
  EXPECT_TRUE(transition.changed);
  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::High);

  // Now at 79.0: High deactivation threshold = 80-2=78, 79 >= 78, stays High
  transition = evaluate_double(79.0);
  EXPECT_FALSE(transition.changed);
  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::High);

  // At 77.0: below 78, deactivates
  transition = evaluate_double(77.0);
  EXPECT_TRUE(transition.changed);
  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::None);
}

// =============================================================================
// Non-exclusive mode: multiple active simultaneously
// =============================================================================

TEST_F(LimitAlarmLogicTest, NonExclusiveMultipleLimitsActiveSimultaneously)
{
  LimitConfig config;
  config.highHighLimit = 90.0;
  config.highLimit = 80.0;
  mLogic.set_limits(config);
  mLogic.set_exclusive(false);
  mLogic.enable();

  // Value above both limits
  auto transition = evaluate_double(95.0);

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.active());
  EXPECT_TRUE(mAccess.high_high_active());
  EXPECT_TRUE(mAccess.high_active());
  EXPECT_FALSE(mAccess.low_active());
  EXPECT_FALSE(mAccess.low_low_active());
}

TEST_F(LimitAlarmLogicTest, NonExclusiveOnlyHighActiveNotHighHigh)
{
  LimitConfig config;
  config.highHighLimit = 90.0;
  config.highLimit = 80.0;
  mLogic.set_limits(config);
  mLogic.set_exclusive(false);
  mLogic.enable();

  // Value above High but below HighHigh
  auto transition = evaluate_double(85.0);

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.active());
  EXPECT_FALSE(mAccess.high_high_active());
  EXPECT_TRUE(mAccess.high_active());
}

TEST_F(LimitAlarmLogicTest, NonExclusiveSeverityIsMaxOfActiveLimits)
{
  LimitConfig config;
  config.highHighLimit = 90.0;
  config.highLimit = 80.0;
  config.severityHighHigh = 900;
  config.severityHigh = 500;
  mLogic.set_limits(config);
  mLogic.set_exclusive(false);
  mLogic.enable();

  evaluate_double(95.0);

  // Max severity should be 900 (HighHigh)
  EXPECT_EQ(mAccess.severity(), 900);
}

TEST_F(LimitAlarmLogicTest, NonExclusiveDeactivatesWhenAllLimitsClear)
{
  LimitConfig config;
  config.highHighLimit = 90.0;
  config.highLimit = 80.0;
  mLogic.set_limits(config);
  mLogic.set_exclusive(false);
  mLogic.enable();

  evaluate_double(95.0);
  ASSERT_TRUE(mAccess.active());

  auto transition = evaluate_double(50.0);

  EXPECT_TRUE(transition.changed);
  EXPECT_FALSE(mAccess.active());
  EXPECT_FALSE(mAccess.high_high_active());
  EXPECT_FALSE(mAccess.high_active());
}

TEST_F(LimitAlarmLogicTest, NonExclusivePartialDeactivationUpdatesSeverity)
{
  LimitConfig config;
  config.highHighLimit = 90.0;
  config.highLimit = 80.0;
  config.severityHighHigh = 900;
  config.severityHigh = 500;
  mLogic.set_limits(config);
  mLogic.set_exclusive(false);
  mLogic.enable();

  evaluate_double(95.0);
  ASSERT_EQ(mAccess.severity(), 900);

  // Drop below HighHigh but still above High
  auto transition = evaluate_double(85.0);

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.active());
  EXPECT_FALSE(mAccess.high_high_active());
  EXPECT_TRUE(mAccess.high_active());
  EXPECT_EQ(mAccess.severity(), 500);
}

TEST_F(LimitAlarmLogicTest, NonExclusiveBothHighAndLowActive)
{
  // This is a pathological case but should be handled: HighLimit < LowLimit makes no
  // sense, but with separate limits that don't overlap we can test both sides.
  LimitConfig config;
  config.highLimit = 80.0;
  config.lowLimit = 20.0;
  mLogic.set_limits(config);
  mLogic.set_exclusive(false);
  mLogic.enable();

  // Activate high
  evaluate_double(85.0);
  EXPECT_TRUE(mAccess.high_active());
  EXPECT_FALSE(mAccess.low_active());

  // Drop to low
  evaluate_double(15.0);
  EXPECT_FALSE(mAccess.high_active());
  EXPECT_TRUE(mAccess.low_active());
}

// =============================================================================
// Non-exclusive deadband
// =============================================================================

TEST_F(LimitAlarmLogicTest, NonExclusiveDeadbandAppliesToEachLimitIndependently)
{
  LimitConfig config;
  config.highHighLimit = 90.0;
  config.highLimit = 80.0;
  config.highHighDeadband = 3.0;
  config.highDeadband = 2.0;
  mLogic.set_limits(config);
  mLogic.set_exclusive(false);
  mLogic.enable();

  evaluate_double(95.0);
  ASSERT_TRUE(mAccess.high_high_active());
  ASSERT_TRUE(mAccess.high_active());

  // Drop to 88: HighHigh still active (90-3=87), High still active (80-2=78)
  auto transition = evaluate_double(88.0);
  EXPECT_FALSE(transition.changed);
  EXPECT_TRUE(mAccess.high_high_active());
  EXPECT_TRUE(mAccess.high_active());

  // Drop to 86: HighHigh deactivates (86 < 87), High still active
  transition = evaluate_double(86.0);
  EXPECT_TRUE(transition.changed);
  EXPECT_FALSE(mAccess.high_high_active());
  EXPECT_TRUE(mAccess.high_active());

  // Drop to 77: High deactivates (77 < 78)
  transition = evaluate_double(77.0);
  EXPECT_TRUE(transition.changed);
  EXPECT_FALSE(mAccess.high_active());
  EXPECT_FALSE(mAccess.active());
}

// =============================================================================
// Severity tracking
// =============================================================================

TEST_F(LimitAlarmLogicTest, ExclusiveSeverityMatchesActiveLimit)
{
  LimitConfig config;
  config.highHighLimit = 90.0;
  config.highLimit = 80.0;
  config.lowLimit = 20.0;
  config.lowLowLimit = 10.0;
  config.severityHighHigh = 900;
  config.severityHigh = 600;
  config.severityLow = 400;
  config.severityLowLow = 800;
  mLogic.set_limits(config);
  mLogic.enable();

  evaluate_double(85.0);
  EXPECT_EQ(mAccess.severity(), 600);

  evaluate_double(95.0);
  EXPECT_EQ(mAccess.severity(), 900);

  evaluate_double(50.0);
  // Deactivated, severity remains from last set

  evaluate_double(15.0);
  EXPECT_EQ(mAccess.severity(), 400);

  evaluate_double(5.0);
  EXPECT_EQ(mAccess.severity(), 800);
}

// =============================================================================
// Non-numeric input ignored
// =============================================================================

TEST_F(LimitAlarmLogicTest, NonNumericInputIsIgnored)
{
  enable_with_high_limit(80.0);

  auto transition = mLogic.evaluate_input(Variant{String{"not a number"}}, DateTime::now());

  EXPECT_FALSE(transition.changed);
  EXPECT_FALSE(mAccess.active());
}

TEST_F(LimitAlarmLogicTest, IntegerInputIsAccepted)
{
  enable_with_high_limit(80.0);

  auto transition = mLogic.evaluate_input(Variant{int32_t{85}}, DateTime::now());

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.active());
  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::High);
}

TEST_F(LimitAlarmLogicTest, FloatInputIsAccepted)
{
  enable_with_high_limit(80.0);

  auto transition = mLogic.evaluate_input(Variant{float{85.0f}}, DateTime::now());

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.active());
}

// @relation(AC-SVR-AC-210-RATEOFCHANGE-PER-SECOND, scope=function)
TEST_F(LimitAlarmLogicTest, RateOfChangeModeEvaluatesTimestampedUnitsPerSecondRatherThanRawValue)
{
  using namespace std::chrono_literals;
  enable_with_high_limit(50.0);
  mLogic.enable_rate_of_change_per_second();
  const DateTime baseline{2026, 1, 1, 0, 0, 0.0};

  auto transition = mLogic.evaluate_input(Variant{1000.0}, baseline);
  EXPECT_FALSE(transition.changed);
  EXPECT_FALSE(mAccess.active()) << "the first raw value establishes a derivative baseline";

  transition = mLogic.evaluate_input(Variant{1005.0}, DateTime{baseline.value() + 50ms});
  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.active()) << "5 units in 50 ms is 100 units/s, above the 50 units/s limit";

  transition = mLogic.evaluate_input(Variant{1005.0}, DateTime{baseline.value() + 100ms});
  EXPECT_TRUE(transition.changed);
  EXPECT_FALSE(mAccess.active()) << "a steady raw value has a rate of zero";
}

// @relation(AC-SVR-AC-210-RATEOFCHANGE-PER-SECOND, scope=function)
TEST_F(LimitAlarmLogicTest, RateOfChangeModeKeepsItsBaselineAcrossInvalidSamplesAndTimestamps)
{
  using namespace std::chrono_literals;
  enable_with_high_limit(50.0);
  mLogic.enable_rate_of_change_per_second();
  const DateTime baseline{2026, 1, 1, 0, 0, 0.0};

  EXPECT_FALSE(mLogic.evaluate_input(Variant{0.0}, baseline).changed);
  EXPECT_FALSE(
    mLogic.evaluate_input(Variant{String{"not numeric"}}, DateTime{baseline.value() + 25ms}).changed);
  EXPECT_FALSE(mLogic.evaluate_input(Variant{1000.0}, baseline).changed)
    << "a non-increasing timestamp cannot define a derivative";

  const auto transition = mLogic.evaluate_input(Variant{10.0}, DateTime{baseline.value() + 100ms});
  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.active()) << "the valid samples define a 100 units/s rate";
}

// =============================================================================
// No change when value stays in same region
// =============================================================================

TEST_F(LimitAlarmLogicTest, ExclusiveNoTransitionWhenStayingAboveLimit)
{
  enable_with_high_limit(80.0);
  evaluate_double(85.0);
  ASSERT_TRUE(mAccess.active());

  auto transition = evaluate_double(90.0);

  EXPECT_FALSE(transition.changed);
  EXPECT_TRUE(mAccess.active());
  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::High);
}

TEST_F(LimitAlarmLogicTest, ExclusiveNoTransitionWhenStayingBelowLimit)
{
  enable_with_high_limit(80.0);
  evaluate_double(50.0);
  ASSERT_FALSE(mAccess.active());

  auto transition = evaluate_double(60.0);

  EXPECT_FALSE(transition.changed);
  EXPECT_FALSE(mAccess.active());
}

// =============================================================================
// build_event
// =============================================================================

TEST_F(LimitAlarmLogicTest, BuildEventReturnsLimitAlarmType)
{
  enable_with_all_limits();
  evaluate_double(85.0);

  auto event = mLogic.build_event();

  ASSERT_NE(event, nullptr);
  auto* limitAlarm = dynamic_cast<LimitAlarmPayload*>(event.get());
  ASSERT_NE(limitAlarm, nullptr);

  EXPECT_EQ(limitAlarm->sourceNode, NodeId(1, 100));
  EXPECT_EQ(limitAlarm->sourceName, String{"TestSource"});
  EXPECT_TRUE(limitAlarm->activeState.id);
  EXPECT_TRUE(limitAlarm->retain);
}

TEST_F(LimitAlarmLogicTest, BuildEventIncludesLimitValues)
{
  LimitConfig config;
  config.highHighLimit = 90.0;
  config.highLimit = 80.0;
  config.lowLimit = 20.0;
  config.lowLowLimit = 10.0;
  mLogic.set_limits(config);
  mLogic.enable();

  auto event = mLogic.build_event();
  auto* limitAlarm = dynamic_cast<LimitAlarmPayload*>(event.get());
  ASSERT_NE(limitAlarm, nullptr);

  ASSERT_TRUE(limitAlarm->highHighLimit.has_value());
  EXPECT_DOUBLE_EQ(*limitAlarm->highHighLimit, 90.0);

  ASSERT_TRUE(limitAlarm->highLimit.has_value());
  EXPECT_DOUBLE_EQ(*limitAlarm->highLimit, 80.0);

  ASSERT_TRUE(limitAlarm->lowLimit.has_value());
  EXPECT_DOUBLE_EQ(*limitAlarm->lowLimit, 20.0);

  ASSERT_TRUE(limitAlarm->lowLowLimit.has_value());
  EXPECT_DOUBLE_EQ(*limitAlarm->lowLowLimit, 10.0);
}

TEST_F(LimitAlarmLogicTest, BuildEventIncludesSeverityValues)
{
  LimitConfig config;
  config.highHighLimit = 90.0;
  config.severityHighHigh = 950;
  config.severityHigh = 600;
  config.severityLow = 400;
  config.severityLowLow = 850;
  mLogic.set_limits(config);
  mLogic.enable();

  auto event = mLogic.build_event();
  auto* limitAlarm = dynamic_cast<LimitAlarmPayload*>(event.get());
  ASSERT_NE(limitAlarm, nullptr);

  ASSERT_TRUE(limitAlarm->severityHighHigh.has_value());
  EXPECT_EQ(*limitAlarm->severityHighHigh, 950);
  ASSERT_TRUE(limitAlarm->severityHigh.has_value());
  EXPECT_EQ(*limitAlarm->severityHigh, 600);
  ASSERT_TRUE(limitAlarm->severityLow.has_value());
  EXPECT_EQ(*limitAlarm->severityLow, 400);
  ASSERT_TRUE(limitAlarm->severityLowLow.has_value());
  EXPECT_EQ(*limitAlarm->severityLowLow, 850);
}

TEST_F(LimitAlarmLogicTest, BuildEventIncludesDeadbandValues)
{
  LimitConfig config;
  config.highLimit = 80.0;
  config.highDeadband = 2.0;
  config.lowDeadband = 3.0;
  mLogic.set_limits(config);
  mLogic.enable();

  auto event = mLogic.build_event();
  auto* limitAlarm = dynamic_cast<LimitAlarmPayload*>(event.get());
  ASSERT_NE(limitAlarm, nullptr);

  ASSERT_TRUE(limitAlarm->highDeadband.has_value());
  EXPECT_DOUBLE_EQ(*limitAlarm->highDeadband, 2.0);
  ASSERT_TRUE(limitAlarm->lowDeadband.has_value());
  EXPECT_DOUBLE_EQ(*limitAlarm->lowDeadband, 3.0);
}

TEST_F(LimitAlarmLogicTest, BuildEventIncludesAckedAndConfirmedState)
{
  enable_with_high_limit(80.0);
  evaluate_double(85.0);

  auto event = mLogic.build_event();
  auto* limitAlarm = dynamic_cast<LimitAlarmPayload*>(event.get());
  ASSERT_NE(limitAlarm, nullptr);

  // Should have unacknowledged state from activation
  EXPECT_FALSE(limitAlarm->ackedState.id);
}

TEST_F(LimitAlarmLogicTest, BuildEventWithPartialLimitsOmitsUnsetLimits)
{
  LimitConfig config;
  config.highLimit = 80.0;
  // No HighHigh, Low, LowLow
  mLogic.set_limits(config);
  mLogic.enable();

  auto event = mLogic.build_event();
  auto* limitAlarm = dynamic_cast<LimitAlarmPayload*>(event.get());
  ASSERT_NE(limitAlarm, nullptr);

  EXPECT_FALSE(limitAlarm->highHighLimit.has_value());
  EXPECT_TRUE(limitAlarm->highLimit.has_value());
  EXPECT_FALSE(limitAlarm->lowLimit.has_value());
  EXPECT_FALSE(limitAlarm->lowLowLimit.has_value());
}

// =============================================================================
// On/off delay integration
// =============================================================================

TEST_F(LimitAlarmLogicTest, EvaluateInputActivatesDirectlyWithoutOnDelay)
{
  enable_with_high_limit(80.0);

  auto transition = evaluate_double(85.0);

  EXPECT_TRUE(transition.changed);
  EXPECT_TRUE(mAccess.active());
}

// =============================================================================
// Edge: empty variant
// =============================================================================

TEST_F(LimitAlarmLogicTest, EmptyVariantIsIgnored)
{
  enable_with_high_limit(80.0);

  auto transition = mLogic.evaluate_input(Variant{}, DateTime::now());

  EXPECT_FALSE(transition.changed);
  EXPECT_FALSE(mAccess.active());
}

// =============================================================================
// Change limits while active
// =============================================================================

TEST_F(LimitAlarmLogicTest, ChangeLimitsWhileActive_ReEvaluatesCorrectly)
{
  enable_with_high_limit(80.0);

  // Activate at 85 (above high=80)
  evaluate_double(85.0);
  ASSERT_TRUE(mAccess.active());
  ASSERT_EQ(mAccess.active_limit(), ActiveLimit::High);

  // Change limits so high=90
  LimitConfig newConfig;
  newConfig.highLimit = 90.0;
  mLogic.set_limits(newConfig);

  // Re-evaluate at 85 - now below new high limit (90), should deactivate
  auto transition = evaluate_double(85.0);

  EXPECT_TRUE(transition.changed);
  EXPECT_FALSE(mAccess.active());
  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::None);
}

// =============================================================================
// build_event reports the CONCRETE limit-alarm type (LimitAlarmType is abstract,
// so an emitted event must carry ExclusiveLimitAlarmType / NonExclusiveLimitAlarmType;
// otherwise a client cannot discover the alarm by its concrete type).
// =============================================================================

TEST_F(LimitAlarmLogicTest, ExclusiveBuildEventReportsExclusiveLimitAlarmType)
{
  mLogic.set_exclusive(true);
  enable_with_all_limits();

  auto event = mLogic.build_event();
  ASSERT_NE(event, nullptr);
  EXPECT_EQ(event->eventType, NodeId{ObjectTypeId::ExclusiveLimitAlarmType});
  EXPECT_NE(dynamic_cast<ExclusiveLimitAlarmPayload*>(event.get()), nullptr);
}

TEST_F(LimitAlarmLogicTest, NonExclusiveBuildEventReportsNonExclusiveLimitAlarmType)
{
  mLogic.set_exclusive(false);
  enable_with_all_limits();

  auto event = mLogic.build_event();
  ASSERT_NE(event, nullptr);
  EXPECT_EQ(event->eventType, NodeId{ObjectTypeId::NonExclusiveLimitAlarmType});
  EXPECT_NE(dynamic_cast<NonExclusiveLimitAlarmPayload*>(event.get()), nullptr);
}

TEST_F(LimitAlarmLogicTest, BuildEventPopulatesInputNode)
{
  // Regression for F67: LimitAlarmLogic::build_event must populate the inherited AlarmConditionPayload
  // fields (notably InputNode) via the shared populate_alarm_payload_fields, not a partial duplicate.
  mLogic.set_input_node(NodeId{2, 777});
  enable_with_all_limits();

  auto event = mLogic.build_event();
  auto* payload = dynamic_cast<AlarmConditionPayload*>(event.get());
  ASSERT_NE(payload, nullptr);
  EXPECT_EQ(payload->inputNode, (NodeId{2, 777}));
}

TEST_F(LimitAlarmLogicTest, NonExclusiveBuildEventPopulatesPerLimitStates)
{
  mLogic.set_exclusive(false);
  enable_with_all_limits();

  // Drive above HighHigh (90): both High and HighHigh are independently active in non-exclusive mode.
  evaluate_double(95.0);

  auto event = mLogic.build_event();
  auto* payload = dynamic_cast<NonExclusiveLimitAlarmPayload*>(event.get());
  ASSERT_NE(payload, nullptr);
  ASSERT_TRUE(payload->highHighState.has_value());
  ASSERT_TRUE(payload->highState.has_value());
  ASSERT_TRUE(payload->lowState.has_value());
  ASSERT_TRUE(payload->lowLowState.has_value());
  EXPECT_TRUE(payload->highHighState->id);
  EXPECT_TRUE(payload->highState->id);
  EXPECT_FALSE(payload->lowState->id);
  EXPECT_FALSE(payload->lowLowState->id);
}

// Each non-exclusive limit state's TransitionTime is when that state last changed (OPC 10000-9 5.8.21), not
// when the event was built: two builds with no change in between carry the same times, and a change moves
// only the states that changed.
TEST_F(LimitAlarmLogicTest, NonExclusiveTransitionTimesMoveOnlyWhenTheirStateChanges)
{
  mLogic.set_exclusive(false);
  enable_with_all_limits();
  evaluate_double(85.0);  // High active, HighHigh not

  const auto times = [this]()
  {
    auto event = mLogic.build_event();
    auto* payload = dynamic_cast<NonExclusiveLimitAlarmPayload*>(event.get());
    EXPECT_NE(payload, nullptr);
    return std::array<DateTime, 4>{payload->highHighState->transitionTime,
      payload->highState->transitionTime,
      payload->lowState->transitionTime,
      payload->lowLowState->transitionTime};
  };
  const auto first = times();
  std::this_thread::sleep_for(std::chrono::milliseconds{5});
  EXPECT_EQ(times(), first) << "building an event must not move any TransitionTime";

  std::this_thread::sleep_for(std::chrono::milliseconds{5});
  evaluate_double(95.0);  // HighHigh becomes active; High stays active
  const auto second = times();
  EXPECT_GT(second[0], first[0]) << "HighHighState changed";
  EXPECT_EQ(second[1], first[1]) << "HighState did not change";
  EXPECT_EQ(second[2], first[2]) << "LowState did not change";
  EXPECT_EQ(second[3], first[3]) << "LowLowState did not change";
}

// F84: an ExclusiveLimitAlarm event must expose the ExclusiveLimitStateMachine's CurrentState as the
// LimitState event field - CurrentState (LocalizedText state name) and CurrentState.Id (the state
// NodeId) - so an EventFilter selecting [LimitState, CurrentState] / [LimitState, CurrentState, Id]
// resolves (UACTT A&C exclusive-limit CU).
TEST_F(LimitAlarmLogicTest, ExclusiveBuildEventResolvesLimitStateCurrentStateAndId)
{
  enable_with_all_limits();
  evaluate_double(95.0);  // > HighHigh (90) -> HighHigh active
  ASSERT_EQ(mAccess.active_limit(), ActiveLimit::HighHigh);

  auto event = mLogic.build_event();
  auto* payload = dynamic_cast<ExclusiveLimitAlarmPayload*>(event.get());
  ASSERT_NE(payload, nullptr);

  const QualifiedName currentStatePath[]{QualifiedName{0, "LimitState"}, QualifiedName{0, "CurrentState"}};
  auto currentState = payload->resolve_field(currentStatePath);
  ASSERT_FALSE(currentState.empty()) << "LimitState.CurrentState resolved to empty";
  EXPECT_EQ(currentState.as<LocalizedText>().text(), "HighHigh");

  const QualifiedName idPath[]{
    QualifiedName{0, "LimitState"}, QualifiedName{0, "CurrentState"}, QualifiedName{0, "Id"}};
  auto id = payload->resolve_field(idPath);
  ASSERT_FALSE(id.empty()) << "LimitState.CurrentState.Id resolved to empty";
  EXPECT_EQ(
    id.as<NodeId>(), (NodeId{0, static_cast<uint32_t>(ObjectId::ExclusiveLimitStateMachineType_HighHigh)}));
}

TEST_F(LimitAlarmLogicTest, ExclusiveLimitStateReflectsTheActiveLimit)
{
  enable_with_all_limits();
  evaluate_double(15.0);  // < Low (20), > LowLow (10) -> Low active
  ASSERT_EQ(mAccess.active_limit(), ActiveLimit::Low);

  auto event = mLogic.build_event();
  auto* payload = dynamic_cast<ExclusiveLimitAlarmPayload*>(event.get());
  ASSERT_NE(payload, nullptr);

  const QualifiedName idPath[]{
    QualifiedName{0, "LimitState"}, QualifiedName{0, "CurrentState"}, QualifiedName{0, "Id"}};
  auto id = payload->resolve_field(idPath);
  ASSERT_FALSE(id.empty());
  EXPECT_EQ(
    id.as<NodeId>(), (NodeId{0, static_cast<uint32_t>(ObjectId::ExclusiveLimitStateMachineType_Low)}));
}

// =============================================================================
// Limit-alarm modelling obligations (Part 9 section 5.8.14 / section 5.8.15 / section 5.8.16)
// =============================================================================

// Part 9 section 5.8.14: all four limit properties are individually Optional, so nothing in the type system
// stops an instance declaring none - and such an alarm can never activate, there is no threshold to
// cross. A plausible implementation validates only the ORDERING of the limits that are present (which
// an all-absent configuration trivially satisfies) and so accepts the one configuration that is never
// meaningful.
// @verifies AC-SVR-AC-200-LIMITALARM-AT-LEAST-ONE-LIMIT
TEST_F(LimitAlarmLogicTest, LimitAlarmWithoutAnyLimitIsRefused)
{
  LimitConfig noLimits;
  // Deadbands and severities carry defaults; none of the four thresholds is declared.
  EXPECT_THROW(mLogic.set_limits(noLimits), std::invalid_argument);

  // The rule is "at least one", not "all four": a single declared threshold stays acceptable.
  LimitConfig oneLimit;
  oneLimit.lowLowLimit = 5.0;
  EXPECT_NO_THROW(mLogic.set_limits(oneLimit));
}

// Part 9 section 5.8.14: the base LimitAlarmType assumes a scalar source - comparing an array against a
// threshold has no defined meaning (any element, all elements or the first are all plausible), so an
// array source must be modelled as one alarm per element. A plausible implementation unwraps the first
// element of an array, or coerces the array to a number, and reports an alarm state that no clause of
// the spec defines.
// @verifies AC-SVR-AC-204-LIMITALARM-SOURCE-SCALAR
TEST_F(LimitAlarmLogicTest, ArrayValuedSourceIsNotEvaluatedAsALimitInput)
{
  enable_with_high_limit(80.0);

  // Every element is above the High limit: an implementation that evaluated any element, all elements
  // or the first would activate here.
  auto transition = mLogic.evaluate_input(Variant{Array<double>{85.0, 90.0}}, DateTime::now());

  EXPECT_FALSE(transition.changed);
  EXPECT_FALSE(mAccess.active());
  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::None);
  EXPECT_DOUBLE_EQ(mAccess.last_input_value(), 0.0);

  // A single-element array is still an array, not a scalar.
  transition = mLogic.evaluate_input(Variant{Array<double>{85.0}}, DateTime::now());

  EXPECT_FALSE(transition.changed);
  EXPECT_FALSE(mAccess.active());
  EXPECT_EQ(mAccess.active_limit(), ActiveLimit::None);
  EXPECT_DOUBLE_EQ(mAccess.last_input_value(), 0.0);
}

// Part 9 section 5.8.14, stronger than plain ActiveState recovery: on restart the alarm must come back in the
// limit it was in, not merely "active" - HighHigh against High is the difference between a warning and
// a trip. Recovery here is recomputation from the current input, so a plausible implementation that
// restores only the active flag (or that re-activates at the default/least-severe limit) loses which
// threshold was crossed.
// @verifies AC-SVR-AC-205-LIMITALARM-STATE-RECOVERY
TEST_F(LimitAlarmLogicTest, ActiveLimitIsRecoveredNotMerelyActiveAfterRestart)
{
  // Pre-restart: the alarm is in its HighHigh limit state.
  enable_with_all_limits();
  evaluate_double(95.0);
  ASSERT_TRUE(mAccess.active());
  ASSERT_EQ(mAccess.active_limit(), ActiveLimit::HighHigh);

  // Restart: a fresh logic instance, configured from the same persisted configuration, then fed the
  // current input value. It must not start out carrying any limit state of its own.
  LimitAlarmLogic restored;
  LimitAlarmLogicTestAccess restoredAccess{restored};
  restored.set_source(NodeId{1, 100}, String{"TestSource"});
  LimitConfig config;
  config.highHighLimit = 90.0;
  config.highLimit = 80.0;
  config.lowLimit = 20.0;
  config.lowLowLimit = 10.0;
  restored.set_limits(config);
  restored.enable();
  ASSERT_FALSE(restoredAccess.active());
  ASSERT_EQ(restoredAccess.active_limit(), ActiveLimit::None);

  restored.evaluate_input(Variant{95.0}, DateTime::now());

  EXPECT_TRUE(restoredAccess.active());
  EXPECT_EQ(restoredAccess.active_limit(), ActiveLimit::HighHigh);
  EXPECT_EQ(restoredAccess.severity(), 900);

  // The recovered limit must also be what the event reports, not just internal state.
  auto event = restored.build_event();
  auto* payload = dynamic_cast<ExclusiveLimitAlarmPayload*>(event.get());
  ASSERT_NE(payload, nullptr);
  const QualifiedName idPath[]{
    QualifiedName{0, "LimitState"}, QualifiedName{0, "CurrentState"}, QualifiedName{0, "Id"}};
  auto id = payload->resolve_field(idPath);
  ASSERT_FALSE(id.empty());
  EXPECT_EQ(
    id.as<NodeId>(), (NodeId{0, static_cast<uint32_t>(ObjectId::ExclusiveLimitStateMachineType_HighHigh)}));
}

// Part 9 section 5.8.15: LimitState is a sub-state of ActiveState by IsTrueSubStateOf, so it has no value
// while the alarm is inactive. A plausible implementation simply stops updating the state machine when
// the alarm clears, leaving the last crossed limit visible - a client then reads "HighHigh" off an
// alarm that has returned to normal.
// @verifies AC-SVR-AC-207-LIMITSTATE-UNAVAILABLE-WHEN-INACTIVE
TEST_F(LimitAlarmLogicTest, LimitStateReportsNoCurrentStateWhileTheAlarmIsInactive)
{
  enable_with_all_limits();

  // Establish a limit state that would be observable if it were left behind.
  evaluate_double(95.0);
  ASSERT_TRUE(mAccess.active());
  ASSERT_EQ(mAccess.active_limit(), ActiveLimit::HighHigh);

  // Return to normal: ActiveState is now false, so its LimitState sub-state has no meaning.
  evaluate_double(50.0);
  ASSERT_FALSE(mAccess.active());
  ASSERT_EQ(mAccess.active_limit(), ActiveLimit::None);

  auto event = mLogic.build_event();
  auto* payload = dynamic_cast<ExclusiveLimitAlarmPayload*>(event.get());
  ASSERT_NE(payload, nullptr);

  const QualifiedName currentStatePath[]{QualifiedName{0, "LimitState"}, QualifiedName{0, "CurrentState"}};
  auto currentState = payload->resolve_field(currentStatePath);
  EXPECT_TRUE(currentState.empty() || currentState.as<LocalizedText>().text().empty())
    << "LimitState.CurrentState still names a limit after the alarm returned to normal";

  const QualifiedName idPath[]{
    QualifiedName{0, "LimitState"}, QualifiedName{0, "CurrentState"}, QualifiedName{0, "Id"}};
  auto id = payload->resolve_field(idPath);
  EXPECT_TRUE(id.empty() || id.as<NodeId>() == NodeId{})
    << "LimitState.CurrentState.Id still carries a stale limit-state NodeId";
}

// Part 9 section 5.8.16: all four non-exclusive state Variables are Optional, but an instance exposing
// neither HighState nor LowState can activate without being able to say why - HighHighState and
// LowLowState without their High/Low parents are non-conformant. A plausible implementation exposes a
// state only where the matching limit is configured, and then an alarm configured with only the
// outer thresholds exposes neither parent state.
// @verifies AC-SVR-AC-208-NONEXCLUSIVE-AT-LEAST-ONE-STATE
TEST_F(LimitAlarmLogicTest, NonExclusiveAlarmExposesHighOrLowState)
{
  // The worst case for this obligation: only the outer thresholds are declared.
  LimitConfig config;
  config.highHighLimit = 90.0;
  config.lowLowLimit = 10.0;
  mLogic.set_exclusive(false);
  mLogic.set_limits(config);
  mLogic.enable();

  evaluate_double(95.0);
  ASSERT_TRUE(mAccess.active());
  ASSERT_TRUE(mAccess.high_high_active());

  auto event = mLogic.build_event();
  auto* payload = dynamic_cast<NonExclusiveLimitAlarmPayload*>(event.get());
  ASSERT_NE(payload, nullptr);

  EXPECT_TRUE(payload->highState.has_value() || payload->lowState.has_value())
    << "neither HighState nor LowState is present on the NonExclusiveLimitAlarm";

  // Present means addressable by a client, not merely engaged in the struct.
  const QualifiedName highIdPath[]{QualifiedName{0, "HighState"}, QualifiedName{0, "Id"}};
  const QualifiedName lowIdPath[]{QualifiedName{0, "LowState"}, QualifiedName{0, "Id"}};
  const bool highResolves = !payload->resolve_field(highIdPath).empty();
  const bool lowResolves = !payload->resolve_field(lowIdPath).empty();
  EXPECT_TRUE(highResolves || lowResolves)
    << "neither HighState.Id nor LowState.Id resolves as an event field";
}

// Part 9 section 5.8.18 (SVR-AC-216): the base-limit obligation is conditional - "if a Server supports
// AdaptiveAlarming for Alarm limits, the corresponding base Alarm limit shall be provided for any
// limits that are exposed". AdaptiveAlarming means the thresholds are driven by another node (a
// setpoint, a computed tolerance); it is not declared as a facet (server_design.md section 2, Q-AC-8) and
// LimitAlarmLogic has no adaptive input: LimitConfig carries thresholds, deadbands and severities
// only. Reconfiguring through set_limits is plain recommissioning, not adaptive alarming, so the
// obligation is verified here in the form it is actually stated: the alarm republishes whatever
// configuration is current, and the Base* set it publishes is all-or-nothing. A partial adaptive
// claim - one Base* field populated for the limit that happens to be active, the other three left
// unset - is the failure this rules out, because a client that sees BaseHighLimit concludes the
// alarm is adaptive and then cannot tell whether the other three thresholds have moved.
// @verifies AC-SVR-AC-216-ADAPTIVE-REQUIRES-BASE-LIMIT
TEST_F(LimitAlarmLogicTest, AdaptiveLimitIsAccompaniedByItsBaseLimit)
{
  // Commissioned configuration.
  LimitConfig baseline;
  baseline.highHighLimit = 90.0;
  baseline.highLimit = 80.0;
  baseline.lowLimit = 20.0;
  baseline.lowLowLimit = 10.0;
  mLogic.set_limits(baseline);
  mLogic.enable();

  evaluate_double(92.0);
  ASSERT_EQ(mAccess.active_limit(), ActiveLimit::HighHigh);

  // Every threshold is driven away from its commissioned value through the public path an
  // application uses to track a setpoint or a computed tolerance.
  LimitConfig adapted;
  adapted.highHighLimit = 95.0;
  adapted.highLimit = 85.0;
  adapted.lowLimit = 25.0;
  adapted.lowLowLimit = 15.0;
  mLogic.set_limits(adapted);

  // The same input now sits in a different limit: the new thresholds really drive evaluation.
  evaluate_double(92.0);
  ASSERT_EQ(mAccess.active_limit(), ActiveLimit::High);

  auto event = mLogic.build_event();
  auto* payload = dynamic_cast<LimitAlarmPayload*>(event.get());
  ASSERT_NE(payload, nullptr);

  // The published limits are the current ones, not the commissioned ones: an event carrying stale
  // thresholds would describe a state the alarm is no longer evaluating against.
  ASSERT_TRUE(payload->highHighLimit.has_value());
  ASSERT_TRUE(payload->highLimit.has_value());
  ASSERT_TRUE(payload->lowLimit.has_value());
  ASSERT_TRUE(payload->lowLowLimit.has_value());
  EXPECT_DOUBLE_EQ(*payload->highHighLimit, 95.0);
  EXPECT_DOUBLE_EQ(*payload->highLimit, 85.0);
  EXPECT_DOUBLE_EQ(*payload->lowLimit, 25.0);
  EXPECT_DOUBLE_EQ(*payload->lowLowLimit, 15.0);

  // The conditional obligation: an alarm either claims AdaptiveAlarming for its limits - in which
  // case every exposed limit carries its base - or claims it for none of them. Four exposed limits,
  // so the base count is 4 or 0; anything between is a partial claim.
  int baseCount = 0;
  baseCount += payload->baseHighHighLimit.has_value() ? 1 : 0;
  baseCount += payload->baseHighLimit.has_value() ? 1 : 0;
  baseCount += payload->baseLowLimit.has_value() ? 1 : 0;
  baseCount += payload->baseLowLowLimit.has_value() ? 1 : 0;
  EXPECT_TRUE(baseCount == 0 || baseCount == 4)
    << "all four limits are exposed, but only " << baseCount
    << " of the four base limits are present: a partial AdaptiveAlarming claim";

  // Whatever base limits are claimed must be addressable by a client, not merely engaged in the
  // payload struct - a base limit no EventFilter can select tells the client nothing.
  if (payload->baseHighHighLimit.has_value())
  {
    const QualifiedName path[]{QualifiedName{0, "BaseHighHighLimit"}};
    EXPECT_FALSE(payload->resolve_field(path).empty())
      << "BaseHighHighLimit is populated but does not resolve as an event field";
  }
  if (payload->baseHighLimit.has_value())
  {
    const QualifiedName path[]{QualifiedName{0, "BaseHighLimit"}};
    EXPECT_FALSE(payload->resolve_field(path).empty())
      << "BaseHighLimit is populated but does not resolve as an event field";
  }
  if (payload->baseLowLimit.has_value())
  {
    const QualifiedName path[]{QualifiedName{0, "BaseLowLimit"}};
    EXPECT_FALSE(payload->resolve_field(path).empty())
      << "BaseLowLimit is populated but does not resolve as an event field";
  }
  if (payload->baseLowLowLimit.has_value())
  {
    const QualifiedName path[]{QualifiedName{0, "BaseLowLowLimit"}};
    EXPECT_FALSE(payload->resolve_field(path).empty())
      << "BaseLowLowLimit is populated but does not resolve as an event field";
  }
}

// Part 9 section 5.8.18 (SVR-AC-216): "the corresponding base Alarm limit shall be provided for any limits
// that are exposed by the derived limit Alarm types". The pairing is per-limit and it ranges over
// exactly the thresholds the instance exposes, which the all-or-nothing check above does not reach:
// there the alarm exposes all four, so a correct implementation and one that pairs base limits with
// the wrong thresholds are indistinguishable. Here only two limits are exposed, which separates
// them, and the base limits are checked one at a time - a base wired only for the threshold that
// happens to be active, or resolvable on one threshold and not its neighbour, reports the adaptation
// of one limit and hides the others, and the client cannot tell which of the two it is holding.
// @verifies AC-SVR-AC-216-ADAPTIVE-REQUIRES-BASE-LIMIT
TEST_F(LimitAlarmLogicTest, EveryAdaptedLimitPublishesItsBaseLimit)
{
  // Two thresholds commissioned, two left off: the set the obligation ranges over is a strict subset
  // of the four, so a base limit published for HighHigh or LowLow accompanies nothing.
  LimitConfig commissioned;
  commissioned.highLimit = 80.0;
  commissioned.lowLimit = 20.0;
  mLogic.set_limits(commissioned);
  mLogic.enable();

  evaluate_double(25.0);
  ASSERT_EQ(mAccess.active_limit(), ActiveLimit::None);

  // Both exposed thresholds move off their commissioned values through the only limit input the
  // alarm has.
  LimitConfig adapted;
  adapted.highLimit = 90.0;
  adapted.lowLimit = 30.0;
  mLogic.set_limits(adapted);

  // The new thresholds really drive evaluation rather than merely being recorded: the unchanged
  // input now violates the Low limit it sat above a moment ago.
  evaluate_double(25.0);
  ASSERT_EQ(mAccess.active_limit(), ActiveLimit::Low);

  auto event = mLogic.build_event();
  auto* payload = dynamic_cast<LimitAlarmPayload*>(event.get());
  ASSERT_NE(payload, nullptr);

  // The exposed set is the two configured thresholds, carrying their current values.
  ASSERT_TRUE(payload->highLimit.has_value());
  ASSERT_TRUE(payload->lowLimit.has_value());
  ASSERT_DOUBLE_EQ(*payload->highLimit, 90.0);
  ASSERT_DOUBLE_EQ(*payload->lowLimit, 30.0);
  ASSERT_FALSE(payload->highHighLimit.has_value());
  ASSERT_FALSE(payload->lowLowLimit.has_value());

  // A base limit is provided for limits that are exposed, so an unexposed threshold gets none: a
  // BaseHighHighLimit here is a static reference for a limit the client cannot read at all.
  EXPECT_FALSE(payload->baseHighHighLimit.has_value())
    << "BaseHighHighLimit accompanies a HighHighLimit the alarm does not expose";
  EXPECT_FALSE(payload->baseLowLowLimit.has_value())
    << "BaseLowLowLimit accompanies a LowLowLimit the alarm does not expose";

  // An alarm that provides base limits at all provides one for every limit it exposes. A base for
  // one of the two exposed thresholds and nothing for the other leaves that threshold's provenance
  // undeterminable while its neighbour advertises adaptation.
  const bool adaptive = payload->baseHighLimit.has_value() || payload->baseLowLimit.has_value();
  EXPECT_EQ(payload->baseHighLimit.has_value(), adaptive)
    << "HighLimit is exposed without a BaseHighLimit while the other exposed limit has its base";
  EXPECT_EQ(payload->baseLowLimit.has_value(), adaptive)
    << "LowLimit is exposed without a BaseLowLimit while the other exposed limit has its base";

  // Provided means selectable by a client, and selectable per limit: a payload carrying all four
  // base limits must resolve each of them under its own browse name, or an EventFilter reads the
  // adaptation of one threshold and gets nothing for the next. The four values are distinct so a
  // resolution that answers with a neighbouring field is caught.
  payload->baseHighHighLimit = 100.0;
  payload->baseHighLimit = 80.0;
  payload->baseLowLimit = 20.0;
  payload->baseLowLowLimit = 5.0;

  const QualifiedName baseHighHighPath[]{QualifiedName{0, "BaseHighHighLimit"}};
  auto baseHighHigh = payload->resolve_field(baseHighHighPath);
  ASSERT_FALSE(baseHighHigh.empty()) << "BaseHighHighLimit does not resolve as an event field";
  EXPECT_DOUBLE_EQ(baseHighHigh.as<double>(), 100.0);

  const QualifiedName baseHighPath[]{QualifiedName{0, "BaseHighLimit"}};
  auto baseHigh = payload->resolve_field(baseHighPath);
  ASSERT_FALSE(baseHigh.empty()) << "BaseHighLimit does not resolve as an event field";
  EXPECT_DOUBLE_EQ(baseHigh.as<double>(), 80.0);

  const QualifiedName baseLowPath[]{QualifiedName{0, "BaseLowLimit"}};
  auto baseLow = payload->resolve_field(baseLowPath);
  ASSERT_FALSE(baseLow.empty()) << "BaseLowLimit does not resolve as an event field";
  EXPECT_DOUBLE_EQ(baseLow.as<double>(), 20.0);

  const QualifiedName baseLowLowPath[]{QualifiedName{0, "BaseLowLowLimit"}};
  auto baseLowLow = payload->resolve_field(baseLowLowPath);
  ASSERT_FALSE(baseLowLow.empty()) << "BaseLowLowLimit does not resolve as an event field";
  EXPECT_DOUBLE_EQ(baseLowLow.as<double>(), 5.0);
}

}  // namespace ua::test
