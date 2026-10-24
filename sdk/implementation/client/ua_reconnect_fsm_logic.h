// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_RECONNECT_FSM_LOGIC_H
#define UA_RECONNECT_FSM_LOGIC_H

/// @file
/// @brief ReconnectionFSM state enum + pure cause-priority / naming logic (client tier-1, detail).
/// @ingroup client

#include "ua_reconnect_types.h"

#include <string_view>

namespace ua::client::detail
{

/// The ReconnectionFSM's states (section 8.3.4). Detail: surfaced only via `ReconnectionFSMInfo`.
enum class ReconnectFsmState
{
  Idle,
  Active,
  GettingEndpoints,
  OpeningChannel,
  ActivatingSession,
  CreatingSession,
  ReReadingNamespace,
  RecoveringSubscriptions,
  Installing,
  BackingOff,
  ShutdownDeferred,
  Failed,
  Cancelled,
};

/// Priority of a reconnect cause for the trigger-upgrade rule (section 8.3.4).
///
/// Higher = a more disruptive required client action (KeepAliveMissed/TransportDropped=0 ... Redundancy
/// switch=5). Equal-priority causes never upgrade one another.
///
/// @param cause The cause to rank.
/// @return Its priority (0..5), or -1 when a failed payload construction left the variant valueless.
[[nodiscard]] int reconnect_cause_priority(const ReconnectCause& cause) noexcept;

/// Whether an incoming trigger should UPGRADE (pre-empt) the in-flight cause.
///
/// True iff @p incoming has strictly greater priority than @p current (section 8.3.1 / section 8.3.4) - a
/// same-or-lower-priority trigger is dropped while a reconnect is already in flight.
///
/// @param current  The cause the FSM is currently running.
/// @param incoming The newly triggered cause.
/// @return `true` if the in-flight sequence should be replaced by @p incoming.
[[nodiscard]] bool reconnect_cause_upgrades(
  const ReconnectCause& current, const ReconnectCause& incoming) noexcept;

/// Stable, human-readable name for a cause (error-chain / diagnostics).
///
/// @param cause The cause to name.
/// @return A static string_view naming @p cause, or "Unknown" for a valueless variant.
[[nodiscard]] std::string_view reconnect_cause_name(const ReconnectCause& cause) noexcept;

/// Stable, human-readable name for a state (error-chain / diagnostics).
///
/// @param state The state to name.
/// @return A static string_view naming @p state.
[[nodiscard]] std::string_view reconnect_fsm_state_name(ReconnectFsmState state) noexcept;

}  // namespace ua::client::detail

#endif  // UA_RECONNECT_FSM_LOGIC_H
