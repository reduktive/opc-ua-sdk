// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_BROWSE_CURSOR_TEST_ACCESS_H
#define UA_BROWSE_CURSOR_TEST_ACCESS_H

/// @file
/// @brief Test-only construction of a @ref ua::client::BrowseCursor over a fake wire interface, for the
///        BrowseCursor unit suite (see the design specification).
///
/// A friend of @ref ua::client::BrowseCursor. Adds NO public constructor to the cursor for testing: it
/// builds the shared walk state (mirroring `TypedAccess::browse`) and hands it to the cursor's private
/// constructor, so the cursor can be exercised against a `FakeWireOps` with no real `ConnectionImpl`.

#include "ua_browse_cursor.h"
#include "ua_browse_cursor_state.h"
#include "ua_node_id.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <memory>
#include <utility>

namespace ua::client::detail
{

class AddressSpaceCache;

/// Friend constructor for @ref BrowseCursor unit tests.
struct BrowseCursorTestAccess
{
  /// Builds a @ref BrowseCursor over @p wireOps starting at @p start with @p options, delivering on
  /// @p executor (mirrors `TypedAccess::browse`, but against a fake interface). No read-surface cache is wired
  /// (an empty cache weak)  -  the disabled / no-cache pass-through path.
  static BrowseCursor make(std::weak_ptr<WireOps> wireOps, boost::asio::any_io_executor executor,
    ua::NodeId start, BrowseOptions options = {},
    std::function<void(std::shared_ptr<const ua::ErrorDetail>)> emitAdvisory = {},
    std::shared_ptr<const ua::client::NamespaceTable> namespaceTable = {},
    std::shared_ptr<const std::atomic<std::uint64_t>> sessionGeneration = {})
  {
    auto state = std::make_shared<BrowseCursorState>();
    state->wireOps = std::move(wireOps);
    state->executor = std::move(executor);
    state->startNode = std::move(start);
    state->options = std::move(options);
    state->emitAdvisory = std::move(emitAdvisory);  // CL-VIEW-017 advisory interface (empty = no-op)
    state->namespaceTable = std::move(namespaceTable);  // CL-VIEW-018 URI resolution snapshot (null = no-op)
    state->sessionGeneration = std::move(sessionGeneration);
    return BrowseCursor{std::move(state)};
  }

  /// Builds a @ref BrowseCursor wired to the read-surface Browse @p cache (held weak) and the connection
  /// @p strand the cache lookups/installs hop onto (mirrors the enabled-cache `TypedAccess::browse`).
  static BrowseCursor make_with_cache(std::weak_ptr<WireOps> wireOps, boost::asio::any_io_executor executor,
    ua::NodeId start, BrowseOptions options, std::weak_ptr<AddressSpaceCache> cache,
    boost::asio::strand<boost::asio::any_io_executor> strand)
  {
    auto state = std::make_shared<BrowseCursorState>();
    state->wireOps = std::move(wireOps);
    state->executor = std::move(executor);
    state->cache = std::move(cache);
    state->strand = std::move(strand);
    state->startNode = std::move(start);
    state->options = std::move(options);
    return BrowseCursor{std::move(state)};
  }
};

}  // namespace ua::client::detail

#endif  // UA_BROWSE_CURSOR_TEST_ACCESS_H
