// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_reconnect_policy.h"

#include <algorithm>
#include <cstdint>
#include <random>

namespace ua::client
{
namespace
{

/// Returns a jitter multiplier in [-1, 1). Thread-local PRNG: jitter only de-correlates reconnect
/// timing across clients, so a fast non-cryptographic generator is appropriate.
double jitter_unit()
{
  static thread_local std::mt19937 engine{std::random_device{}()};
  std::uniform_real_distribution<double> distribution{-1.0, 1.0};
  return distribution(engine);
}

}  // namespace

std::chrono::milliseconds BackoffPolicy::next(std::size_t attempt) const
{
  const double baseMs = static_cast<double>(base.count());
  const double maxMs = static_cast<double>(max.count());

  // Saturating scale: apply `factor` once per prior attempt, but stop as soon as the running value
  // reaches `max`. This never lets the value approach the int64-millisecond overflow that a raw
  // `factor^(attempt-1)` would hit around attempt 54 (which would wrap the delay into a reconnect
  // storm). The `factor > 1.0` guard also bounds the loop for a degenerate non-growing config.
  double nominal = baseMs;
  const std::size_t steps = (attempt > 0) ? attempt - 1 : 0;
  for (std::size_t i = 0; i < steps && nominal < maxMs && factor > 1.0; ++i)
  {
    nominal *= factor;
  }
  nominal = std::clamp(nominal, baseMs, maxMs);

  // Jitter is applied AFTER the clamp (per the section 7.7 formula), so the delivered delay may exceed `max`
  // by up to jitterPct - deliberate spacing widening during a long outage.
  if (jitterPct > 0.0)
  {
    nominal *= (1.0 + jitter_unit() * jitterPct);
  }
  if (nominal < 0.0)
  {
    nominal = 0.0;
  }
  return std::chrono::milliseconds{static_cast<std::int64_t>(nominal)};
}

}  // namespace ua::client
