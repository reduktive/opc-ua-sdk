// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Per-session descriptive facts exposed as SessionDiagnosticsDataType.
/// @ingroup server

#ifndef UA_SESSION_DESCRIPTION_H
#define UA_SESSION_DESCRIPTION_H

#include "ua_application_description.h"
#include "ua_date_time.h"

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <vector>

namespace ua::server
{

/// The non-counter half of OPC 10000-5 `SessionDiagnosticsDataType`: who connected, how they
/// addressed the server, and when.
///
/// Kept separate from @ref SessionSecurityState because Part 5 treats the two differently -
/// 12.12 restricts the security record to authorised users, while these fields carry no such
/// restriction.
///
/// @note The descriptive fields are written on the owning session's strand at CreateSession and
///       ActivateSession and read by the diagnostics Variables' value sources on whichever thread
///       serves the Read, so both sides hold @ref mutex. @ref lastActivityTicks is the exception
///       and is atomic, because it is written on every request.
/// @ingroup server
struct SessionDescriptiveState
{
  /// Guards every field below except @ref lastActivityTicks. Held only to copy fields.
  mutable std::mutex mutex;

  /// Name from CreateSession, or the server-assigned substitute when the client sent none
  /// (OPC 10000-4 5.6.2.2: "If this parameter is null or empty the Server shall assign a value").
  std::string sessionName;

  /// ApplicationDescription the client supplied in CreateSession.
  ApplicationDescription clientDescription;

  /// CreateSession `serverUri`. Legitimately empty for a non-gateway server: Part 4 5.6.2.2 says
  /// the client specifies it "only if the EndpointDescription has a gatewayServerUri".
  std::string serverUri;

  /// The network address the client used to reach this session's endpoint.
  std::string endpointUrl;

  /// Locale preference from ActivateSession, in priority order. Re-activation may replace it.
  std::vector<std::string> localeIds;

  /// The timeout the server GRANTED, not the one requested. Part 5 Table 230 describes the field
  /// as the requested value, but the BrowseName is `ActualSessionTimeout` and Part 4 5.6.2.2 calls
  /// the revised value the "Actual maximum number of milliseconds" - the description reads as a
  /// drafting error, and the granted value is the one a client needs for keep-alive sizing.
  std::chrono::milliseconds revisedSessionTimeout{};

  /// Server wall-clock time at which the session was opened.
  DateTime clientConnectionTime;

  /// Steady-clock origin paired with @ref clientConnectionTime, so a monotonic activity tick can be
  /// converted to wall-clock without sampling the wall clock on the request path.
  std::chrono::steady_clock::time_point connectionSteadyOrigin{};

  /// Steady-clock tick of the most recent request on this session. Drives both the OPC 10000-4
  /// 5.6.2 inactivity reset and `ClientLastContactTime`; the diagnostics value is derived from it
  /// at read time rather than written here, so a request costs one store and no clock conversion.
  std::atomic<std::chrono::steady_clock::rep> lastActivityTicks{};

  /// Records a request arriving. Callable from the owning session's strand.
  ///
  /// @param at The steady-clock time the request arrived at.
  void note_activity(std::chrono::steady_clock::time_point at) noexcept
  {
    lastActivityTicks.store(at.time_since_epoch().count(), std::memory_order_relaxed);
  }

  /// The steady-clock tick of the last request.
  ///
  /// @return The steady-clock time point of the most recent request on this session.
  std::chrono::steady_clock::time_point last_activity() const noexcept
  {
    return std::chrono::steady_clock::time_point{
      std::chrono::steady_clock::duration{lastActivityTicks.load(std::memory_order_relaxed)}};
  }

  /// `ClientLastContactTime` as wall-clock, derived from the monotonic tick.
  ///
  /// @return The wall-clock time of the most recent request, converted from @ref last_activity()
  ///         against @ref connectionSteadyOrigin.
  DateTime last_contact_time() const noexcept
  {
    const auto elapsed =
      std::chrono::duration_cast<datetime::OneHundredNanoSeconds>(last_activity() - connectionSteadyOrigin);
    DateTime contact{clientConnectionTime};
    contact.value() += elapsed;
    return contact;
  }
};

}  // namespace ua::server

#endif  // !UA_SESSION_DESCRIPTION_H
