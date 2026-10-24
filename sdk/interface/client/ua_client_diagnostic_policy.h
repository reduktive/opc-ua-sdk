// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CLIENT_DIAGNOSTIC_POLICY_H
#define UA_CLIENT_DIAGNOSTIC_POLICY_H

/// @file
/// @brief Per-Connection diagnostics policy knobs (client design section 7.10.4).
/// @ingroup client

#include <cstdint>
#include <optional>

namespace ua::client
{

/// Per-Connection tunables for how the SDK surfaces decoded server diagnostics (client design
/// section 7.10.4).
///
/// This is the single home for the diagnostics-related knobs so a Connection's diagnostic behaviour is
/// configured in one place. It is attached to @ref ConnectionConfig and decomposed into an immutable member
/// at `ua::client::detail::ConnectionImpl` construction (read from any strand without synchronisation).
///
/// The defaults preserve the pre-policy behaviour exactly: the error-chain / advisory observer fires whenever
/// the server attaches a `DiagnosticInfo` (which it only does when a request set `returnDiagnostics != 0`),
/// and the decoded chain is depth-capped at 32.
///
/// @note This type grows as its requirements are wired. The `WrapLevel` field (CL-DIAG-015) is not yet
///       present. It is added
///       when their wiring lands, so a field present here is always enforced (no inert knobs).
/// @ingroup client
struct ClientDiagnosticPolicy
{
  /// The wrap level.
  enum class WrapLevel
  {
    Minimal,
    Standard,
    Verbose,
  };

  /// Overrides the Client-wide default on every request issued by this Connection. An engaged zero
  /// explicitly suppresses diagnostics for this Connection.
  std::optional<std::uint32_t> requestedDiagnosticsMask;

  /// Opts direct tier-0 Session service results into one SDK context wrap. False preserves the raw incoming
  /// rich StatusCode and ErrorDetail pointer exactly (CL-DIAG-004).
  bool wrapTier0 = false;

  /// Controls SDK tier-boundary links and their context richness. Standard is the default.
  WrapLevel wrapLevel = WrapLevel::Standard;

  /// When true (the default), a decoded server diagnostic on a wire response fires the
  /// `ua::client::ClientObserver` error-chain hook (`on_error_chain` on a bad service result,
  /// `on_advisory_diagnostic` on a good one). When false the observer surface is a strict no-op  -  the
  /// response is delivered unchanged and no observer fires. Independent of the always-on CL-DIAG-005
  /// wire-crossing marker on the `Result` chain, which is attached regardless of this flag. (CL-DIAG-012)
  bool emitOnErrorChainObserver = true;

  /// Cap on the decoded `ErrorDetail` chain depth. When a server `DiagnosticInfo` chain would exceed this,
  /// the decoder truncates after the cap and appends a single `client.diagnostic.truncated` sentinel link
  /// (which itself counts toward the depth). (CL-DIAG-009)
  ///
  /// **This is the second bound, not the first.** It limits the work and memory spent CONVERTING an
  /// already-decoded `DiagnosticInfo` into an `ErrorDetail` chain; it does not protect the decoder's
  /// stack. The stack bound is @ref ua::ExecutionLimits::decodeRecursionDepthLimit (default 100),
  /// applied while the `DiagnosticInfo` is still being read off the wire - the binary decoder charges
  /// recursion for each nested `InnerDiagnosticInfo` - so a hostile chain is already bounded at 100
  /// before this cap of 32 is ever consulted.
  ///
  /// This is the ONLY value a caller sets. It is carried unchanged into the internal decoder and into
  /// @ref ua::DiagnosticDecodeOptions::maxChainDepth, whose own default is "no cap" because it lives in
  /// `core`, which holds no policy.
  /// @see ua::ExecutionLimits::decodeRecursionDepthLimit, ua::DiagnosticDecodeOptions::maxChainDepth
  std::uint32_t maxChainDepth = 32;
};

}  // namespace ua::client

#endif  // UA_CLIENT_DIAGNOSTIC_POLICY_H
