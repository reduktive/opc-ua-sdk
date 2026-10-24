// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ADDRESS_SPACE_CACHE_TEST_ACCESS_H
#define UA_ADDRESS_SPACE_CACHE_TEST_ACCESS_H

/// @file
/// @brief Test-only access to @ref ua::client::detail::AddressSpaceCache strand-private state, for the
///        AddressSpaceCache unit suite (see the design specification).
///
/// A friend of @ref ua::client::detail::AddressSpaceCache. Adds NO public members to the cache for testing:
/// it reads the sub-caches, the pending-unregister batch, and the session generation directly. The cache's
/// synchronous methods run on the caller's thread (the design's caller-on-strand contract), so the single-
/// threaded unit tests read this state directly without a strand hop.

#include "ua_address_space_cache.h"
#include "ua_node_id.h"
#include "ua_on_strand.h"
#include "ua_sync_wait.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <cstdint>
#include <functional>
#include <optional>
#include <type_traits>
#include <vector>

namespace ua::client::detail
{

/// Friend accessor for @ref AddressSpaceCache unit tests.
struct AddressSpaceCacheTestAccess
{
  template<typename Operation>
  static auto on_strand(
    AddressSpaceCache& cache, Operation operation) -> std::invoke_result_t<Operation, AddressSpaceCache&>
  {
    using Result = std::invoke_result_t<Operation, AddressSpaceCache&>;
    if (cache.mStrand.running_in_this_thread())
    {
      return std::invoke(std::move(operation), cache);
    }

    // Off the strand, the wait is blocking_call's: refused (thrown) on a thread of the cache's executor,
    // and answered with an error, not a hang, when the cache is gone before the hop runs. An exception
    // from @p operation is rethrown here as a UaException.
    using Held = std::conditional_t<std::is_void_v<Result>, ua::VoidResult, ua::Result<Result>>;
    auto held = ua::async::detail::blocking_call<Held>(boost::asio::any_io_executor{cache.mStrand},
      [&cache, &operation](std::function<void(Held)> complete)
      {
        ua::async::post_borrowing(&cache,
          cache.mStrand,
          cache.mLogger,
          [operation = std::move(operation), complete = std::move(complete)](
            AddressSpaceCache& strong) mutable
          {
            try
            {
              if constexpr (std::is_void_v<Result>)
              {
                std::invoke(std::move(operation), strong);
                complete(Held{});
              }
              else
              {
                complete(Held{std::invoke(std::move(operation), strong)});
              }
            }
            catch (...)
            {
              complete(Held{ua::exception_to_status_code(std::current_exception())});
            }
          })();
      });
    if constexpr (std::is_void_v<Result>)
    {
      held.value();
    }
    else
    {
      return std::move(held).value();
    }
  }

  /// @return The cached alias entry for @p node, or `nullopt` (does not reorder the LRU).
  static std::optional<AliasEntry> alias(const AddressSpaceCache& cache, const ua::NodeId& node)
  {
    const auto* entry = cache.mAliasCache.peek(node);
    if (entry == nullptr)
    {
      return std::nullopt;
    }
    return *entry;
  }

  /// @return The number of alias entries currently held.
  static std::size_t alias_count(const AddressSpaceCache& cache)
  {
    return cache.mAliasCache.size();
  }

  /// @return The cached attribute entry for @p node, or `nullopt` (does not reorder the LRU).
  static std::optional<AttributeEntry> attributes(const AddressSpaceCache& cache, const ua::NodeId& node)
  {
    const auto* entry = cache.mAttributeCache.peek(node);
    if (entry == nullptr)
    {
      return std::nullopt;
    }
    return *entry;
  }

  /// @return The number of attribute entries currently held.
  static std::size_t attribute_count(const AddressSpaceCache& cache)
  {
    return cache.mAttributeCache.size();
  }

  /// @return The number of browse entries currently held.
  static std::size_t browse_count(const AddressSpaceCache& cache)
  {
    return cache.mBrowseCache.size();
  }

  /// @return A snapshot of the pending UnregisterNodes batch (the server handles queued for release).
  static std::vector<ua::NodeId> pending_unregister(const AddressSpaceCache& cache)
  {
    return cache.mPendingUnregisterBatch;
  }

  /// @return The current session generation (bumped on each `on_session_changed_async`).
  static std::uint64_t session_generation(const AddressSpaceCache& cache)
  {
    return cache.mSessionGeneration;
  }

  /// @return The strand the cache posts all async work onto. Structural section 8.7 check: the cache must NOT
  ///         fabricate its own strand  -  this must compare equal to the strand injected at construction
  ///         (ConnectionImpl's strand), so the sync caller-on-strand and async-marshalled paths share one
  ///         serialization domain.
  static boost::asio::strand<boost::asio::any_io_executor> post_strand(const AddressSpaceCache& cache)
  {
    return cache.mStrand;
  }

  /// Forces the session generation to @p generation WITHOUT clearing the alias cache, so the
  /// defence-in-depth stale-generation drop in `lookup_for_request` (a missed `on_session_changed_async`)
  /// can be exercised. Not a production path.
  static void set_session_generation(AddressSpaceCache& cache, std::uint64_t generation)
  {
    cache.mSessionGeneration = generation;
  }
};

}  // namespace ua::client::detail

#endif  // UA_ADDRESS_SPACE_CACHE_TEST_ACCESS_H
