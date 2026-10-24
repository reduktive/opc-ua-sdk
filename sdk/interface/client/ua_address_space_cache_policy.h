// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ADDRESS_SPACE_CACHE_POLICY_H
#define UA_ADDRESS_SPACE_CACHE_POLICY_H

/// @file
/// @brief Per-Connection policy knobs for the optional client-side
///        `ua::client::detail::AddressSpaceCache` (client design section 7.7 / section 8.7).
/// @ingroup client

#include <chrono>
#include <cstddef>

namespace ua::client
{

/// Per-Connection tunables for the optional client-side address-space cache (section 8.7).
///
/// The cache trades a bounded amount of client memory for fewer server round-trips: it substitutes
/// server-assigned numeric handles (RegisterNodes) into repeated access operations, caches the static
/// attributes tier-2 pre-flights against, and optionally caches Browse results for repeated subtree
/// walks. It is opt-in: when @ref enabled is false the cache is a clean pass-through no-op and every
/// operation goes wire-direct.
///
/// The numeric defaults are the frozen SDK policy choices (client design section 9.8.2), not spec-mandated;
/// real workloads override them here.
/// @ingroup client
struct AddressSpaceCachePolicy
{
  /// Master switch. When false the cache is disabled (a clean no-op) and every operation goes
  /// wire-direct. Opt-in (section 8.7).
  bool enabled = false;

  /// When true, repeated access to a Node auto-registers it (RegisterNodes) and substitutes the returned
  /// numeric alias into later requests (CL-VIEW-009).
  bool useRegisterNodes = true;

  /// Ceiling on the RegisterNodes alias sub-cache; the least-recently-used alias is evicted (and its node
  /// queued for UnregisterNodes) past this (section 9.8.2).
  std::size_t maxRegisteredNodes = 1024;

  /// Ceiling on the static-attribute sub-cache (ArrayDimensions / AccessLevelEx / DataType / ValueRank /
  /// AccessLevel / UserAccessLevel) that drives tier-2 pre-flight (section 9.8.2).
  std::size_t maxCachedAttributes = 4096;

  /// Ceiling on the Browse-result sub-cache that accelerates repeated `BrowseCursor` walks (section 9.8.2).
  std::size_t maxCachedBrowses = 256;

  /// The evicted/explicitly-released nodes are coalesced into one UnregisterNodes call once this many
  /// have accumulated (whichever comes first with @ref unregisterCoalesceWindow) (section 9.8.2,
  /// CL-VIEW-010).
  std::size_t unregisterBatchSize = 32;

  /// The single-armed-with-rearm coalesce window: a steady stream of evictions never flushes the pending
  /// UnregisterNodes batch until the stream quiets for this long (section 9.8.2, CL-VIEW-010).
  std::chrono::milliseconds unregisterCoalesceWindow{100};

  /// Idle time-to-live for a cached Browse result; a lookup treats an older entry as a miss and drops it
  /// (section 9.8.2).
  std::chrono::seconds browseEntryTtl{30};
};

}  // namespace ua::client

#endif  // UA_ADDRESS_SPACE_CACHE_POLICY_H
