// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_RECONNECT_POLICY_H
#define UA_RECONNECT_POLICY_H

/// @file
/// @brief Reconnect backoff schedule and policy (client tier-1, ConnectionConfig).
/// @ingroup client

#include <chrono>
#include <cstddef>
#include <optional>

namespace ua::client
{

/// How a reconnect recovers the Session's subscriptions.
enum class SubscriptionRecovery
{
  /// Attempt `TransferSubscriptions` first; recreate any the server would not transfer.
  TransferThenRecreate,
  /// Always recreate subscriptions from the client's records (skip transfer).
  RecreateOnly,
};

/// Exponential-with-jitter backoff schedule for reconnect attempts.
///
/// `next(attempt)` returns the delay before the given 1-based attempt as
/// `clamp(base * factor^(attempt-1), base, max)` scaled by a random `+/-jitterPct` jitter.
///
/// **Saturating by construction.** With `maxAttempts` unset the attempt index is unbounded, and
/// `base_ms * factor^(attempt-1)` overflows `int64` milliseconds around attempt 54 - which would wrap
/// the delay to a tiny value and collapse the backoff into a reconnect storm. `next` therefore stops
/// scaling as soon as the running value reaches `max`; it never computes the raw power first.
/// @ingroup client
struct BackoffPolicy
{
  /// Delay before the first reconnect attempt.
  std::chrono::milliseconds base{std::chrono::seconds{1}};

  /// Hard ceiling on the pre-jitter delay.
  std::chrono::milliseconds max{std::chrono::seconds{60}};

  /// Fractional jitter applied to the clamped delay (0.25 = +/-25%). 0 disables jitter (deterministic).
  double jitterPct = 0.25;

  /// Growth factor per attempt (2.0 = binary exponential).
  double factor = 2.0;

  /// Returns the delay before 1-based @p attempt (attempt 0 is treated as attempt 1).
  ///
  /// The result is `clamp(base * factor^(attempt-1), base, max)` scaled by `+/-jitterPct`; because
  /// jitter is applied after the clamp, the value may exceed `max` by up to `jitterPct`. Saturating:
  /// see the type-level note.
  ///
  /// @param attempt The 1-based attempt index.
  /// @return The delay to wait before that attempt.
  [[nodiscard]] std::chrono::milliseconds next(std::size_t attempt) const;
};

/// Policy governing automatic reconnect (`ConnectionConfig.reconnect`; unset = single-shot connect).
/// @ingroup client
struct ReconnectPolicy
{
  /// Backoff schedule between attempts.
  BackoffPolicy backoff;

  /// Maximum reconnect attempts before terminal failure; unset means retry forever.
  std::optional<std::size_t> maxAttempts;

  /// How subscriptions are recovered after a reconnect.
  SubscriptionRecovery subscriptionRecovery = SubscriptionRecovery::TransferThenRecreate;

  /// Per-step deadline guarding a stuck reconnect step; unset uses the default service timeout.
  std::optional<std::chrono::milliseconds> perStepTimeout;

  /// Multiplier applied to the backoff while a server-announced shutdown is in effect (CL-SESS-025).
  std::size_t shutdownBackoffMultiplier = 4;

  /// Minimum time a reconnect must stay Active before it counts as a genuine recovery (storm guard,
  /// section 8.3.4). If a reconnect reaches Active but drops again within this window, the next attempt is
  /// PACED through the backoff (with an escalating streak) instead of an immediate, budget-reset attempt  -
  /// so a peer that accepts every handshake but fails immediately cannot drive a zero-delay reconnect storm.
  /// The streak resets once a reconnect stays healthy for this long. Advisory (Part 5 section 6.3.1: "slow
  /// retry logic ... progressively increase the delay"); does not apply to ServerShutdown (which has its own
  /// backoff multiplier).
  ///
  /// A value of zero (or negative) disables the guard: every reconnect that reaches Active immediately
  /// counts as healthy, so re-drops always get a fresh, zero-delay, budget-reset attempt. Interaction with
  /// `maxAttempts`: while the guard is active a paced storm counts toward `maxAttempts`, so a *finite*
  /// `maxAttempts` lets a flapping-but-briefly-recovering link fail terminally (fail-fast). Leave
  /// `maxAttempts` unset (the default) to pace such a link forever without ever giving up.
  std::chrono::milliseconds minHealthyDwell{std::chrono::seconds{10}};
};

/// Keep-alive poll policy (section 8.2A.6, CL-RECONN-009 / CL-SESS-025). While the Connection is `Active` the
/// orchestrator polls `Server.ServerStatus.State` on this interval to detect a silently-dead link (a
/// half-open TCP / hung server / black-hole) that issues no Publishes to signal a drop - the independent
/// liveness signal the Publish-fatal path cannot cover on a subscription-less Connection. Keep-alive is a
/// reconnect-adjacent concern (a miss drives the reconnect FSM), so it travels with `ReconnectPolicy`; a
/// single-shot Connection with no reconnect wiring has nothing to do on a miss.
/// @ingroup client
struct KeepAlivePolicy
{
  /// Interval between keep-alive polls. `<= 0` DISABLES the keep-alive timer (opt-out / single-shot).
  std::chrono::milliseconds interval{5000};
  /// Consecutive missed polls before a `KeepAliveMissed` reconnect is triggered (0 is treated as 1).
  std::size_t missedBeforeReconnect{3};
};

}  // namespace ua::client

#endif  // UA_RECONNECT_POLICY_H
