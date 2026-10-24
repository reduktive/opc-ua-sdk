// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the ReconnectionFSM cause-priority / upgrade logic (section 8.3.4) and the name helpers.
// The priority order drives which in-flight reconnect an incoming trigger pre-empts.
//
// Falsifiability: a flat-priority stub fails the strict-ordering and upgrade assertions; empty-name
// stubs fail the naming assertions.

#include "ua_reconnect_fsm_logic.h"
#include "ua_reconnect_types.h"

#include <gtest/gtest.h>

namespace
{

using namespace ua::client;
using ua::client::detail::reconnect_cause_name;
using ua::client::detail::reconnect_cause_priority;
using ua::client::detail::reconnect_cause_upgrades;
using ua::client::detail::reconnect_fsm_state_name;
using ua::client::detail::ReconnectFsmState;

TEST(ReconnectCausePriority, TransportAndKeepAliveShareLowestPriority)
{
  EXPECT_EQ(reconnect_cause_priority(TransportDropped{}), reconnect_cause_priority(KeepAliveMissed{}));
}

TEST(ReconnectCausePriority, StrictlyIncreasingByRequiredAction)
{
  EXPECT_LT(reconnect_cause_priority(TransportDropped{}), reconnect_cause_priority(SessionInvalid{}));
  EXPECT_LT(reconnect_cause_priority(SessionInvalid{}), reconnect_cause_priority(SecurityFailure{}));
  EXPECT_LT(reconnect_cause_priority(SecurityFailure{}), reconnect_cause_priority(CertRotated{}));
  EXPECT_LT(reconnect_cause_priority(CertRotated{}), reconnect_cause_priority(ServerShutdown{}));
  EXPECT_LT(reconnect_cause_priority(ServerShutdown{}), reconnect_cause_priority(RedundancySwitchInfo{}));
}

TEST(ReconnectCauseUpgrade, HigherPriorityUpgrades)
{
  EXPECT_TRUE(reconnect_cause_upgrades(TransportDropped{}, SessionInvalid{}));
  EXPECT_TRUE(reconnect_cause_upgrades(SecurityFailure{}, ServerShutdown{}));
  EXPECT_TRUE(reconnect_cause_upgrades(TransportDropped{}, RedundancySwitchInfo{}));
}

TEST(ReconnectCauseUpgrade, LowerOrEqualPriorityDoesNotUpgrade)
{
  EXPECT_FALSE(reconnect_cause_upgrades(ServerShutdown{}, SecurityFailure{}));  // lower
  EXPECT_FALSE(reconnect_cause_upgrades(TransportDropped{}, KeepAliveMissed{}));  // equal
  EXPECT_FALSE(reconnect_cause_upgrades(CertRotated{}, CertRotated{}));  // same
}

TEST(ReconnectCauseName, NamesEachCause)
{
  EXPECT_EQ(reconnect_cause_name(TransportDropped{}), "TransportDropped");
  EXPECT_EQ(reconnect_cause_name(KeepAliveMissed{}), "KeepAliveMissed");
  EXPECT_EQ(reconnect_cause_name(SecurityFailure{}), "SecurityFailure");
  EXPECT_EQ(reconnect_cause_name(SessionInvalid{}), "SessionInvalid");
  EXPECT_EQ(reconnect_cause_name(CertRotated{}), "CertRotated");
  EXPECT_EQ(reconnect_cause_name(ServerShutdown{}), "ServerShutdown");
  EXPECT_EQ(reconnect_cause_name(RedundancySwitchInfo{}), "RedundancySwitch");
}

TEST(ReconnectFsmStateName, NamesRepresentativeStates)
{
  EXPECT_EQ(reconnect_fsm_state_name(ReconnectFsmState::Active), "Active");
  EXPECT_EQ(reconnect_fsm_state_name(ReconnectFsmState::OpeningChannel), "OpeningChannel");
  EXPECT_EQ(reconnect_fsm_state_name(ReconnectFsmState::ReReadingNamespace), "ReReadingNamespace");
  EXPECT_EQ(reconnect_fsm_state_name(ReconnectFsmState::Failed), "Failed");
  EXPECT_EQ(reconnect_fsm_state_name(ReconnectFsmState::Cancelled), "Cancelled");
}

}  // namespace
