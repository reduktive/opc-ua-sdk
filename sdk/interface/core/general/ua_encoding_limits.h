// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Codec encode/decode resource limits derived from the application configuration.
/// @ingroup general

#ifndef UA_ENCODING_LIMITS_H
#define UA_ENCODING_LIMITS_H

#include "ua_application_configuration.h"
#include "ua_execution_limits.h"
#include "ua_resource_budgets.h"

#include <cstddef>
#include <limits>

namespace ua
{

/// Resource limits applied when encoding or decoding OPC UA messages.
///
/// Bounds the work a single encode/decode may perform, guarding against
/// hostile or malformed input that would otherwise exhaust memory or stack.
/// Groups the structural-work limits (@ref ExecutionLimits, from which the
/// per-operation @ref StackDepth, @ref WorkBudget and @ref LoopLimit budgets are
/// allocated) together with the server-side size caps for individual values.
///
/// The size caps default to a bounded floor (1 MB string / 16 MB ByteString /
/// 65535 array - matching the server-config defaults) so a bare-constructed
/// decoder is fail-closed against hostile input; populate from an
/// @ref ApplicationConfig via @ref make_encoding_limits and override the
/// caps as required. Trusted local input (e.g. NodeSet import) must raise the
/// caps explicitly. This is a plain value type with no internal
/// synchronisation; share a copy per encode/decode operation rather than across
/// threads.
/// @ingroup general
struct EncodingLimits
{
  /// Structural-work limits (stack-depth and loop budgets) for a single operation.
  ExecutionLimits execution;

  /// Maximum length, in bytes, of a single decoded UTF-8 String. Defaults to a bounded 1 MB floor
  /// (matching the server-config default) so a bare-constructed decoder is fail-closed rather than an
  /// allocation bomb; trusted local input must opt the cap up explicitly.
  size_t maxStringLength{static_cast<size_t>(1) * 1024 * 1024};
  /// Maximum length, in bytes, of a single decoded ByteString. Defaults to a bounded 16 MB floor
  /// (matching the server-config default); trusted local input must opt the cap up explicitly.
  size_t maxByteStringLength{static_cast<size_t>(16) * 1024 * 1024};
  /// Maximum element count of a single decoded array. Defaults to a bounded 65535 floor (matching the
  /// server-config default); trusted local input must opt the cap up explicitly.
  size_t maxArrayLength{65535u};

  /// Allocates a fresh @ref StackDepth work-budget from the configured decode limits.
  ///
  /// The returned budget tracks nodes and edges (bounded by @ref ExecutionLimits::decodeWorkLimit)
  /// plus a live recursion-depth counter (bounded by @ref ExecutionLimits::decodeRecursionDepthLimit)
  /// for one structural descent; copies share the same budget state. Allow one per encode/decode
  /// operation.
  ///
  /// @return A fresh @ref StackDepth budget seeded from the configured decode-work and
  ///         recursion-depth limits.
  [[nodiscard]] StackDepth stack_depth() const
  {
    return StackDepth{execution.decodeWorkLimit, execution.decodeRecursionDepthLimit};
  }

  /// Allocates a fresh @ref WorkBudget bounding the nodes and edges of one operation.
  ///
  /// The node and edge caps default to the square of the configured decode-work
  /// limit (saturated at the maximum on overflow), preserving the historical
  /// behaviour where that limit primarily bounded structural work.
  ///
  /// @return A fresh @ref WorkBudget whose node and edge caps are seeded from the configured
  ///         decode-work limit.
  [[nodiscard]] WorkBudget work_budget() const
  {
    // Default nodes+edges to N^2 (with overflow protection) to preserve historical call-site
    // expectations where the decode-work limit primarily bounded structural work.
    const auto maxWork = compute_default_max_edges(execution.decodeWorkLimit);
    return WorkBudget{maxWork, maxWork};
  }

  /// Allocates a fresh @ref LoopLimit from the configured loop-iteration limit.
  ///
  /// @return A fresh @ref LoopLimit seeded from @ref ExecutionLimits::loopLimit.
  [[nodiscard]] LoopLimit loop_limit() const
  {
    return LoopLimit{execution.loopLimit};
  }

private:
  static size_t compute_default_max_edges(size_t maxNodes)
  {
    if (maxNodes == 0)
    {
      return 0;
    }

    constexpr size_t max = std::numeric_limits<size_t>::max();
    if (maxNodes > max / maxNodes)
    {
      return max;
    }
    return maxNodes * maxNodes;
  }
};

/// Builds `EncodingLimits` from an application's configured execution limits.
///
/// Copies the execution limits out of @p cfg; the size caps
/// (`EncodingLimits::maxStringLength` and friends) are left at their bounded
/// floor defaults for the caller to tighten or (for trusted input) raise.
///
/// @param cfg Configuration supplying the execution limits.
/// @return Encoding limits with @p cfg's execution limits and bounded-floor size caps.
[[nodiscard]] inline EncodingLimits make_encoding_limits(const ApplicationConfig& cfg)
{
  EncodingLimits out{.execution = cfg.execution_limits()};
  return out;
}

/// Builds `EncodingLimits` for **trusted, locally-sourced** input, with the size caps lifted to
/// unbounded.
///
/// The bounded-floor size caps exist to fail closed against hostile *remote* wire input; applied to a
/// trusted local document (the built-in NS0 nodeset, or an operator-supplied NodeSet file) they would
/// instead (mis)reject large-but-legitimate values. Use this ONLY where the input's provenance is
/// trusted - never for data arriving over a network endpoint. The structural-work limits (stack depth,
/// loop budgets) are retained from @p cfg, so deeply-nested malformed local input is still bounded.
///
/// @param cfg Configuration supplying the execution limits.
/// @return Encoding limits with @p cfg's execution limits and unbounded size caps.
[[nodiscard]] inline EncodingLimits make_trusted_local_encoding_limits(const ApplicationConfig& cfg)
{
  EncodingLimits out{.execution = cfg.execution_limits()};
  out.maxStringLength = std::numeric_limits<size_t>::max();
  out.maxByteStringLength = std::numeric_limits<size_t>::max();
  out.maxArrayLength = std::numeric_limits<size_t>::max();
  return out;
}

}  // namespace ua

#endif  // !UA_ENCODING_LIMITS_H
