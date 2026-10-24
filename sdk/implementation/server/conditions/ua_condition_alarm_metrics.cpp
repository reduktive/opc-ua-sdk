// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_condition_alarm_metrics.h"

#include "ua_condition_state_snapshot.h"

#include <algorithm>

namespace ua
{

ConditionAlarmMetrics::ConditionAlarmMetrics(
  const std::vector<std::shared_ptr<ConditionInstance>>& conditions)
{
  for (const auto& instance : conditions)
  {
    auto snap = instance->snapshot();
    if (!snap || !snap->enabled())
    {
      continue;
    }

    const uint16_t sev = snap->severity();

    if (snap->active())
    {
      ++mActiveCount;
      mHighestActiveSeverity = std::max(mHighestActiveSeverity, sev);
    }

    if (!snap->acked())
    {
      ++mUnacknowledgedCount;
      mHighestUnackSeverity = std::max(mHighestUnackSeverity, sev);
    }

    if (!snap->confirmed())
    {
      ++mUnconfirmedCount;
    }
  }
}

uint32_t ConditionAlarmMetrics::active_count() const
{
  return mActiveCount;
}

uint32_t ConditionAlarmMetrics::unacknowledged_count() const
{
  return mUnacknowledgedCount;
}

uint32_t ConditionAlarmMetrics::unconfirmed_count() const
{
  return mUnconfirmedCount;
}

uint16_t ConditionAlarmMetrics::highest_active_severity() const
{
  return mHighestActiveSeverity;
}

uint16_t ConditionAlarmMetrics::highest_unack_severity() const
{
  return mHighestUnackSeverity;
}

}  // namespace ua
