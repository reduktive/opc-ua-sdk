// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Aggregate alarm metrics summarising a collection of condition instances.
/// @ingroup server

#ifndef UA_CONDITION_ALARM_METRICS_H
#define UA_CONDITION_ALARM_METRICS_H

#include "ua_condition_instance.h"

#include <cstdint>
#include <memory>
#include <vector>

namespace ua
{

/// Aggregate alarm metrics summarising a collection of condition instances.
///
/// Each metric (active count, unacknowledged count, highest severity, ...) is
/// computed once at construction by snapshotting every supplied
/// @ref ConditionInstance, and is thereafter returned from the cached value by
/// the corresponding accessor. The object is an immutable value snapshot: it
/// does not track later changes to the source conditions, and a fresh instance
/// must be constructed to observe updated metrics.
///
/// @note Construction reads each condition's state snapshot, which is itself
///       mutex-protected; the resulting accessors are plain reads of cached
///       values and are safe to call from any thread.
/// @see ConditionInstance
/// @ingroup server
class ConditionAlarmMetrics
{
public:
  /// Computes the alarm metrics from the given condition instances.
  ///
  /// Snapshots each condition once and caches the derived metrics. Null entries
  /// and disabled conditions (no readable snapshot, or EnabledState off) are
  /// skipped entirely and contribute to no count or severity.
  ///
  /// @param conditions Condition instances to aggregate. Borrowed for the
  ///                   duration of the call only; no ownership is retained and
  ///                   the metrics do not reference the conditions afterwards.
  explicit ConditionAlarmMetrics(const std::vector<std::shared_ptr<ConditionInstance>>& conditions);

  /// Returns the number of enabled conditions that were in the active state.
  /// @return The count of enabled, active conditions in the snapshot.
  uint32_t active_count() const;

  /// Returns the number of enabled conditions that were unacknowledged.
  ///
  /// Counts every enabled condition whose AckedState is off, independent of
  /// whether it is active.
  /// @return The count of enabled, unacknowledged conditions in the snapshot.
  uint32_t unacknowledged_count() const;

  /// Returns the number of enabled conditions that were unconfirmed.
  ///
  /// Counts every enabled condition whose ConfirmedState is off, independent of
  /// its acknowledgement state.
  /// @return The count of enabled, unconfirmed conditions in the snapshot.
  uint32_t unconfirmed_count() const;

  /// Returns the highest severity among the active conditions.
  ///
  /// The value is an OPC UA severity (1-1000, higher is more severe); 0 when no
  /// enabled condition was active.
  /// @return The highest severity among active conditions, or 0 if none were active.
  uint16_t highest_active_severity() const;

  /// Returns the highest severity among the unacknowledged conditions.
  ///
  /// The value is an OPC UA severity (1-1000, higher is more severe); 0 when no
  /// enabled condition was unacknowledged. Like @ref unacknowledged_count, this
  /// considers AckedState alone and does not require the condition to be active.
  /// @return The highest severity among unacknowledged conditions, or 0 if none were unacknowledged.
  uint16_t highest_unack_severity() const;

private:
  // Cached at construction from snapshots
  uint32_t mActiveCount{0};
  uint32_t mUnacknowledgedCount{0};
  uint32_t mUnconfirmedCount{0};
  uint16_t mHighestActiveSeverity{0};
  uint16_t mHighestUnackSeverity{0};
};

}  // namespace ua

#endif  // !UA_CONDITION_ALARM_METRICS_H
