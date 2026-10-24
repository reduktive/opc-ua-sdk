// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SEMANTIC_CHANGE_CACHE_TEST_ACCESS_H
#define UA_SEMANTIC_CHANGE_CACHE_TEST_ACCESS_H

/// @file
/// @brief Test-only access to @ref ua::client::detail::SemanticChangeCache strand-private state, for the
///        SemanticChangeCache unit suite (see the design specification).
///
/// A friend of @ref ua::client::detail::SemanticChangeCache. Adds NO public members to the cache for
/// testing: it reads `mEntries` / `mObserverHook` directly. The tests drain the cache's strand (an
/// `io_context` `run()`) before reading this state, so every self-marshalled mutation has settled.

#include "ua_node_id.h"
#include "ua_semantic_change_cache.h"

#include <cstddef>

namespace ua::client::detail
{

/// Friend accessor for @ref SemanticChangeCache unit tests.
struct SemanticChangeCacheTestAccess
{
  /// @return The number of registry entries currently held (live + not-yet-pruned expired weak refs).
  static std::size_t entry_count(const SemanticChangeCache& cache)
  {
    return cache.mEntries.size();
  }

  /// @return True iff an entry exists for @p nodeId (regardless of whether its weak ref still locks).
  static bool has_entry(const SemanticChangeCache& cache, const ua::NodeId& nodeId)
  {
    return cache.mEntries.find(nodeId) != cache.mEntries.end();
  }

  /// @return True iff @p nodeId has a live (lockable) registered state.
  static bool entry_is_live(const SemanticChangeCache& cache, const ua::NodeId& nodeId)
  {
    auto entry = cache.mEntries.find(nodeId);
    return entry != cache.mEntries.end() && !entry->second.expired();
  }

  /// @return True iff the observer hook is still installed (dropped by @ref SemanticChangeCache::close).
  static bool hook_installed(const SemanticChangeCache& cache)
  {
    return static_cast<bool>(cache.mObserverHook);
  }

  /// @return The strand the cache marshals its mutations onto. Structural section 8.18.2 check: the cache
  /// must NOT
  ///         fabricate its own strand  -  this must equal the strand injected at construction.
  static boost::asio::strand<boost::asio::any_io_executor> post_strand(const SemanticChangeCache& cache)
  {
    return cache.mStrand;
  }
};

}  // namespace ua::client::detail

#endif  // UA_SEMANTIC_CHANGE_CACHE_TEST_ACCESS_H
