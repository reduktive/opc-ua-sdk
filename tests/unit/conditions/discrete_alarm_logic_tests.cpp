// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_discrete_alarm_logic.h"

#include "ua_data_value.h"
#include "ua_discrete_alarm_payload.h"
#include "ua_status.h"
#include "ua_variant.h"

#include <gtest/gtest.h>

namespace ua::test
{

/// Test-access helper to read protected/private state from DiscreteAlarmLogic.
class DiscreteAlarmLogicTestAccess
{
public:
  explicit DiscreteAlarmLogicTestAccess(DiscreteAlarmLogic& logic) : mLogic(logic)
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

private:
  DiscreteAlarmLogic& mLogic;
};

class DiscreteAlarmLogicTest : public ::testing::Test
{
protected:
  DiscreteAlarmLogic mLogic;
  DiscreteAlarmLogicTestAccess mAccess{mLogic};

  void SetUp() override
  {
    mLogic.set_source(NodeId{1, 100}, String{"TestSource"});
  }

  ByteString enable_and_set_event_id()
  {
    mLogic.enable();
    ByteString eventId{std::vector<uint8_t>{1, 2, 3}};
    mLogic.set_last_event_id(eventId);
    return eventId;
  }
};

// =============================================================================
// build_event
// =============================================================================

TEST_F(DiscreteAlarmLogicTest, BuildEventReturnsDiscreteAlarmType)
{
  enable_and_set_event_id();
  mLogic.activate(500);

  auto event = mLogic.build_event();

  ASSERT_NE(event, nullptr);
  auto* discreteAlarm = dynamic_cast<DiscreteAlarmPayload*>(event.get());
  ASSERT_NE(discreteAlarm, nullptr);

  EXPECT_EQ(event->sourceNode, NodeId(1, 100));
  EXPECT_EQ(event->sourceName, String{"TestSource"});
  EXPECT_TRUE(discreteAlarm->activeState.id);
}

TEST_F(DiscreteAlarmLogicTest, BuildEventWhenInactiveHasInactiveState)
{
  enable_and_set_event_id();

  auto event = mLogic.build_event();

  auto* discreteAlarm = dynamic_cast<DiscreteAlarmPayload*>(event.get());
  ASSERT_NE(discreteAlarm, nullptr);
  EXPECT_FALSE(discreteAlarm->activeState.id);
}

}  // namespace ua::test
