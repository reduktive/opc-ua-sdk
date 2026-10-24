// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TYPE_DEFER_GATE_H
#define UA_TYPE_DEFER_GATE_H

/// @file
/// @brief The decode-and-defer eligibility + budget gate for the @ref ua::client::detail::TypeResolver
///        codec hook (client design section 9.2 / section 9.8 override 2, GATED-LAZY).
///
/// The gate encapsulates the three DECISIONS the ratified decode-and-defer policy makes when the codec
/// hits an unknown `ExtensionObject` encoding while decoding a message:
///   1. **Eligibility (a security boundary, strict-unless-listed).** Only application-data responses
///      (`ReadResponse` values, `CallResponse` outputs, `PublishResponse` NotificationData) may DEFER.
///      Security / handshake bodies (OPN, Create/ActivateSession signatures) are strict-decode: they
///      fail closed, never emitting a placeholder (the design specification fail-closed; do not defer a check
///      on attacker-influenced bytes).
///   2. **Budget (a DoS guard).** At most `maxDistinctUnresolvedTypesPerMessage` distinct unknown
///      encodings are resolved per message; over that the message surfaces terminal
///      `UnresolvedExtensionObject` placeholders WITHOUT further resolution  -  the decode still succeeds.
///      Re-decode-after-resolution is bounded to `maxReDecodePasses` (= 1).
///   3. **Bounded advisory dedup.** The "unresolved / fallback-used" advisory is coalesced per DataType
///      so a hot loop does not flood, but the dedup structure itself is LRU-bounded so a hostile server
///      emitting many distinct types cannot grow it without limit (section 9.6.18.4).
///
/// The gate holds no async state and takes no lock; the resolver consults it on the connection strand.
/// The actual `UnresolvedExtensionObject` placeholder produced downstream maps to the existing core
/// `ua::UnknownStructure` (which preserves the raw encoded body); wiring the core codec callsite to
/// consult this gate is a later slice  -  the gate is the reusable, independently-tested decision core.
/// @ingroup client

#include "ua_lru_map.h"
#include "ua_node_id.h"
#include "ua_type_resolution_policy.h"

#include <cstddef>

namespace ua::client::detail
{

/// The eligibility class of the message being decoded (the security boundary of decode-and-defer).
enum class MessageClass
{
  /// `ReadResponse` values, `CallResponse` outputs, `PublishResponse` NotificationData  -  deferral-eligible.
  ApplicationData,

  /// OPN / Create / ActivateSession and any body feeding an authentication, signature, or authorization
  /// check  -  strict-decode, fails closed, never defers.
  SecurityCritical,
};

/// What the codec does with the set of unknown encodings found in one message.
enum class DeferDecision
{
  /// Eligible and within budget: emit placeholders, drive `resolve_async`, re-decode once resolved.
  Defer,

  /// Eligible but OVER the distinct-type budget: surface terminal `UnresolvedExtensionObject`
  /// placeholders with no further resolution. The decode still SUCCEEDS (never a hard failure).
  Placeholder,

  /// Not eligible (security-critical): fail closed. The codec surfaces a decode error, never a placeholder.
  StrictFail,
};

/// The decode-and-defer decision core (client design section 9.2 / section 9.8 override 2). Copyable value
/// type; the resolver holds one and consults it on the connection strand.
class TypeDeferGate
{
public:
  /// @param policy The budget knobs (distinct-type cap, re-decode passes, advisory dedup cap).
  explicit TypeDeferGate(TypeDeferPolicy policy);

  /// Decides what the codec does for one message given its eligibility @p messageClass and the number of
  /// DISTINCT unknown encodings @p distinctUnresolvedCount found while decoding it.
  ///
  /// - `SecurityCritical`  to  `StrictFail` unconditionally (fail closed).
  /// - `ApplicationData` with count <= `maxDistinctUnresolvedTypesPerMessage`  to  `Defer`.
  /// - `ApplicationData` with count > that cap  to  `Placeholder` (over budget; decode still succeeds).
  [[nodiscard]] DeferDecision classify(
    MessageClass messageClass, std::size_t distinctUnresolvedCount) const noexcept;

  /// The bounded re-decode budget: true iff a re-decode pass at zero-based @p passIndex is permitted
  /// (i.e. `passIndex < maxReDecodePasses`). section 9.8 override 2 fixes the cap at 1, so only pass 0 runs.
  [[nodiscard]] bool may_redecode(std::size_t passIndex) const noexcept;

  /// Records an advisory sighting of @p dataTypeId for coalescing.
  /// @return true the FIRST time this DataType is seen (fire the advisory), false on a repeat (coalesce).
  ///         The backing set is LRU-bounded at `advisoryDedupCap`, so it never grows without limit  -  a
  ///         re-sighting after eviction fires once more, which is the acceptable coarsening
  ///         (section 9.6.18.4).
  [[nodiscard]] bool record_advisory_first_seen(const ua::NodeId& dataTypeId);

  /// @return The current size of the bounded advisory dedup set (never exceeds `advisoryDedupCap`).
  [[nodiscard]] std::size_t advisory_dedup_size() const noexcept
  {
    return mAdvisorySeen.size();
  }

  /// @return The policy this gate enforces.
  [[nodiscard]] const TypeDeferPolicy& policy() const noexcept
  {
    return mPolicy;
  }

private:
  TypeDeferPolicy mPolicy;
  // Bounded dedup: value is unused (a presence set); the LruMap caps size and evicts LRU past the cap.
  ua::LruMap<ua::NodeId, bool> mAdvisorySeen;
};

}  // namespace ua::client::detail

#endif  // UA_TYPE_DEFER_GATE_H
