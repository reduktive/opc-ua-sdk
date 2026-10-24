// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_reconnect_fsm_logic.h"

#include <variant>

namespace ua::client::detail
{

int reconnect_cause_priority(const ReconnectCause& cause) noexcept
{
  // Every declared alternative needs an explicit priority when the public variant changes.
  static_assert(std::variant_size_v<ReconnectCause> == 7);
  if (std::holds_alternative<KeepAliveMissed>(cause) || std::holds_alternative<TransportDropped>(cause))
    return 0;
  if (std::holds_alternative<SessionInvalid>(cause))
    return 1;
  if (std::holds_alternative<SecurityFailure>(cause))
    return 2;
  if (std::holds_alternative<CertRotated>(cause))
    return 3;
  if (std::holds_alternative<ServerShutdown>(cause))
    return 4;
  if (std::holds_alternative<RedundancySwitchInfo>(cause))
    return 5;
  // A failed payload construction can leave the public variant without a value. It cannot replace
  // a valid trigger; every valid trigger can replace it.
  return -1;
}

bool reconnect_cause_upgrades(const ReconnectCause& current, const ReconnectCause& incoming) noexcept
{
  return reconnect_cause_priority(incoming) > reconnect_cause_priority(current);
}

std::string_view reconnect_cause_name(const ReconnectCause& cause) noexcept
{
  static_assert(std::variant_size_v<ReconnectCause> == 7);
  if (std::holds_alternative<TransportDropped>(cause))
    return "TransportDropped";
  if (std::holds_alternative<KeepAliveMissed>(cause))
    return "KeepAliveMissed";
  if (std::holds_alternative<SecurityFailure>(cause))
    return "SecurityFailure";
  if (std::holds_alternative<SessionInvalid>(cause))
    return "SessionInvalid";
  if (std::holds_alternative<CertRotated>(cause))
    return "CertRotated";
  if (std::holds_alternative<ServerShutdown>(cause))
    return "ServerShutdown";
  if (std::holds_alternative<RedundancySwitchInfo>(cause))
    return "RedundancySwitch";
  return "Unknown";
}

std::string_view reconnect_fsm_state_name(ReconnectFsmState state) noexcept
{
  switch (state)
  {
  case ReconnectFsmState::Idle:
    return "Idle";
  case ReconnectFsmState::Active:
    return "Active";
  case ReconnectFsmState::GettingEndpoints:
    return "GettingEndpoints";
  case ReconnectFsmState::OpeningChannel:
    return "OpeningChannel";
  case ReconnectFsmState::ActivatingSession:
    return "ActivatingSession";
  case ReconnectFsmState::CreatingSession:
    return "CreatingSession";
  case ReconnectFsmState::ReReadingNamespace:
    return "ReReadingNamespace";
  case ReconnectFsmState::RecoveringSubscriptions:
    return "RecoveringSubscriptions";
  case ReconnectFsmState::Installing:
    return "Installing";
  case ReconnectFsmState::BackingOff:
    return "BackingOff";
  case ReconnectFsmState::ShutdownDeferred:
    return "ShutdownDeferred";
  case ReconnectFsmState::Failed:
    return "Failed";
  case ReconnectFsmState::Cancelled:
    return "Cancelled";
  }
  return "Unknown";
}

}  // namespace ua::client::detail
