// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Configured maxima that bound recursion depth and iteration during request processing.
/// @ingroup general

#ifndef UA_EXECUTION_LIMITS_H
#define UA_EXECUTION_LIMITS_H

#include <cstddef>

namespace ua
{

/// Configured maxima that bound the work a single request may perform.
///
/// These are the configured ceilings (not per-call progress state): they seed the initial values of
/// the path-local execution budget tokens (@ref StackDepth, @ref DepthBudget, @ref LoopLimit) at
/// request entry points. Exceeding a seeded budget during processing fails the operation with
/// @ref ua::Status::BadEncodingLimitsExceeded rather than risking unbounded stack growth or
/// non-terminating traversal of the address space.
///
/// Every limit must be strictly greater than zero; a configuration carrying a zero limit is rejected
/// at validation time.
/// @ingroup general
/// @see StackDepth, DepthBudget, LoopLimit, ExecutionLimits::decodeWorkLimit,
///      ExecutionLimits::decodeRecursionDepthLimit, ExecutionLimits::instantiationDepthLimit,
///      ExecutionLimits::loopLimit
struct ExecutionLimits
{
  /// Compares two limit sets field-by-field for equality.
  ///
  /// @return @c true when every corresponding limit is equal; @c false otherwise.
  bool operator==(const ExecutionLimits&) const = default;

  /// Maximum cumulative node/edge WORK a single NodeSet traversal may perform, in work units.
  ///
  /// Seeds the @ref WorkBudget allocated by @ref EncodingLimits::work_budget(), which bounds the total
  /// fan-out / structural cost of one operation (dense or highly branched input), independent of
  /// nesting depth. Must be greater than zero. Defaults to 10000.
  ///
  /// @warning This limit governs NODESET PROCESSING ONLY - the import and export engines are its only
  ///          consumers. It does NOT bound decoding of messages received on the wire: the binary codec
  ///          carries @ref EncodingLimits::stack_depth(), which charges recursion depth but not nodes, so
  ///          a wide-shallow message is bounded by @ref connection_protocol::Limits::maxMessageSize and
  ///          @ref server::ServerConfig::ServerCapabilities::maxArrayLength rather than by
  ///          this field. Use
  ///          @ref decodeRecursionDepthLimit for the deep-narrow wire case.
  size_t decodeWorkLimit{10000};

  /// Maximum LIVE recursion / nesting depth a single encode/decode may reach, in recursion levels.
  ///
  /// Seeds the live recursion-depth counter of the codec (@ref StackDepth::enter_recursion): it
  /// bounds deep-narrow nesting to guard the native call stack against overflow on hostile wire
  /// input, and unwinds as the recursion returns (so wide-shallow structures are not penalised).
  /// Must be greater than zero. Defaults to 100 (matching @ref StackDepth::defaultMaxDepth); keep
  /// this well under the smallest thread stack any decode runs on (see @ref StackDepth for the
  /// 1 MB-stack rationale).
  size_t decodeRecursionDepthLimit{100};

  /// Maximum logical descent a single instantiation traversal may reach, in descent levels.
  ///
  /// Seeds the @ref DepthBudget consumed while an instantiation flow descends nested type/instance
  /// structures. Unlike @ref decodeRecursionDepthLimit this bounds a monotonic logical descent in
  /// callback/continuation flows (there is no native stack to unwind). Must be greater than zero.
  /// Defaults to 10000.
  size_t instantiationDepthLimit{10000};

  /// Smallest @ref loopLimit the server's own NS0 NodeSet import can complete under.
  ///
  /// Enforced by `ApplicationConfig::validate`. Empirically the import needs about six iterations
  /// for its deepest type-hierarchy walk; the margin here is deliberate so a NodeSet revision does not
  /// silently move the floor. See also the guarded consume sites in the import engine and parser.
  constexpr static size_t minWorkableLoopLimit{16};

  /// Maximum number of loop iterations permitted for a single request, in iterations.
  ///
  /// Seeds the @ref LoopLimit consumed while iterating during processing (for example address-space
  /// traversal). Must be greater than zero. Defaults to 10000.
  size_t loopLimit{10000};
};

}  // namespace ua

#endif  // !UA_EXECUTION_LIMITS_H
