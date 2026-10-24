// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TYPE_RESOLUTION_POLICY_H
#define UA_TYPE_RESOLUTION_POLICY_H

/// @file
/// @brief Per-Connection policy knobs for the `ua::client::detail::TypeResolver` (client design
///        section 8.6) and its decode-and-defer codec hook (section 9.2 / section 9.8 override 2).
/// @ingroup client

#include "ua_node_id.h"

#include <chrono>
#include <cstddef>
#include <vector>

namespace ua::client
{

/// How the `ua::client::detail::TypeResolver` populates its registry (client design section 8.6).
enum class TypeResolutionMode
{
  /// Fetch on first decode failure (decode-and-defer). No connect-time scan; the codec emits an
  /// `UnresolvedExtensionObject` placeholder and the tier-1 wrap drives `resolve_async` on demand.
  Lazy,

  /// Scan the declared interest set (`eagerTypes`) at connect time so the registry is warm before the
  /// first structured read.
  Eager,

  /// Eager pre-cache of the interest set plus lazy decode-and-defer on a later miss.
  EagerThenLazy,
};

/// The decode-and-defer budget knobs (client design section 9.2 / section 9.8 override 2, GATED-LAZY).
///
/// These bound the resolve fan-out and the advisory bookkeeping so a malformed or adversarial response
/// carrying many unknown encodings cannot drive unbounded resolve / re-decode work or grow the
/// advisory dedup structure without limit (DoS guard, section 9.6.18.4).
/// @ingroup client
struct TypeDeferPolicy
{
  /// Ceiling on the number of *distinct* unresolved encoding types the codec will attempt to resolve for
  /// one message. Over this, the message surfaces terminal `UnresolvedExtensionObject` placeholders
  /// without further resolution attempts  -  the decode still succeeds (section 9.8 override 2).
  std::size_t maxDistinctUnresolvedTypesPerMessage = 32;

  /// The bounded re-decode-after-resolution budget: at most this many placeholder re-decode passes over
  /// one message (section 9.8 override 2 fixes this at 1).
  std::size_t maxReDecodePasses = 1;

  /// LRU ceiling on the advisory "fallback used / unresolved type" dedup set (section 9.6.18.4). A hostile
  /// server emitting many distinct types must not turn the flood-prevention structure itself into an
  /// unbounded memory sink; past this the least-recently-seen entry is evicted (coalescing coarsens).
  std::size_t advisoryDedupCap = 1024;
};

/// Per-Connection type-resolution tunables (client design section 8.6; the struct section 9.8.3 completed
/// with the three previously-missing fields `resolutionTimeout` / `tier2WaitForResolution` /
/// `eagerScanBudget`).
/// @ingroup client
struct TypeResolutionPolicy
{
  /// The resolution mode (Lazy / Eager / EagerThenLazy).
  TypeResolutionMode mode = TypeResolutionMode::Lazy;

  /// Explicit eager interest: these DataType (or encoding) NodeIds are resolved at connect time.
  std::vector<ua::NodeId> eagerTypes;

  /// Deprecated `.bsd`-style `DataTypeDictionary` fallback, consulted only when `DataTypeDefinition` is
  /// absent (CL-ADDRSP-011). Default on; turning it off makes a missing definition a hard resolution
  /// failure.
  bool allowDictionaryFallback = true;

  // --- section 9.8.3 fields (previously referenced by section 8.6 prose but undeclared) ---

  /// Per-`resolve_async` deadline (section 9.6.18.3/.6). Armed when an encoding's resolution starts and
  /// cancelled when it settles; on expiry every waiter on that encoding completes `Bad_Timeout`, so a server
  /// that never answers the discovery Browse/Read cannot park a typed read indefinitely. A non-positive
  /// value disables the deadline.
  std::chrono::milliseconds resolutionTimeout{10000};

  /// Whether a tier-2 typed read BLOCKS until resolution completes (default) or returns immediately with
  /// an `UnresolvedExtensionObject` placeholder (section 9.6.18.3). Tier-1 reads always return immediately.
  bool tier2WaitForResolution = true;

  /// Cap on the connect-time eager scan (section 9.6.18.7). On exhaustion the resolver switches to
  /// `EagerThenLazy` for the remainder and fires an advisory, so a pathological `eagerTypes` set does not
  /// block bootstrap unboundedly.
  std::size_t eagerScanBudget = 500;

  /// The decode-and-defer budget (section 9.2 / section 9.8 override 2).
  TypeDeferPolicy defer;
};

}  // namespace ua::client

#endif  // UA_TYPE_RESOLUTION_POLICY_H
