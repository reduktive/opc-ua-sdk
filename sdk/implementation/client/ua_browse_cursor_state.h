// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_BROWSE_CURSOR_STATE_H
#define UA_BROWSE_CURSOR_STATE_H

/// @file
/// @brief The strand-free walk state a @ref ua::client::BrowseCursor iterates (client design section 7.5),
///        shared between the cursor implementation and `TypedAccess::browse` that constructs it.
/// @ingroup client

#include "ua_browse_cursor.h"
#include "ua_continuation_point.h"
#include "ua_error_detail.h"
#include "ua_node_id.h"
#include "ua_reference_description.h"
#include "ua_status_code.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

namespace ua::client
{
class NamespaceTable;
}  // namespace ua::client

namespace ua::client::detail
{

class WireOps;
class AddressSpaceCache;

/// The walk state a @ref BrowseCursor iterates. Held by a `std::shared_ptr` so every wire-op completion can
/// weak-capture it and bail cleanly if the cursor was dropped mid-flight (section 9.8.3: liveness is not
/// guaranteed across an async boundary).
struct BrowseCursorState
{
  std::weak_ptr<WireOps>
    wireOps;  ///< the upward wire interface (section 8.2A.13); locked per op, bail if gone
  /// Cross-thread Session generation published by ConnectionImpl. A continuation point records the
  /// generation of the operation that obtained it; BrowseNext is allowed only while this value matches.
  std::shared_ptr<const std::atomic<std::uint64_t>> sessionGeneration;
  std::uint64_t continuationGeneration = 0;
  std::uint64_t operationGeneration = 0;
  boost::asio::any_io_executor executor;  ///< where buffered yields / boundary failures are delivered
  // Advisory-emission interface (CL-VIEW-017): invoked to surface a non-conformant remote reference (a remote
  // target that omits its mandatory displayName). Production wires it to the Connection's ObserverSink
  // (weak-captured, so no ownership cycle); a unit test injects a recording callback. Empty on a cursor built
  // without one (the default) -> no advisory is emitted (a strict no-op). A mockable interface per
  // the design specification so the advisory branch is unit-coverable without a live ObserverSink/Connection.
  std::function<void(std::shared_ptr<const ua::ErrorDetail>)> emitAdvisory;
  // The per-Connection NamespaceTable snapshot (CL-VIEW-018), taken at cursor construction. Used to resolve a
  // LOCAL target's URI-bearing ExpandedNodeId to a local NamespaceIndex (the encoded index is 0 on the wire
  // when a URI is present, Part 6 section 5.2.2.10). An immutable snapshot: it stays valid for the walk even
  // if ConnectionImpl installs a newer table mid-flight. EMPTY (null) on a cursor built without one, or
  // before the namespace array has been read -> resolution is a strict no-op (the target's URI is preserved
  // verbatim). Held by shared_ptr<const> (a value snapshot, no ownership cycle).
  std::shared_ptr<const ua::client::NamespaceTable> namespaceTable;
  // The optional read-surface Browse cache (section 8.7) + the connection strand it self-serializes on. Both
  // are EMPTY / default when the per-Connection cache policy is disabled: TypedAccess::browse wires the cache
  // weak ONLY when enabled, so a disabled cursor never force-constructs or consults the cache (a strict pass-
  // through no-op). The cache is held WEAK (no ownership cycle back into ConnectionImpl). The initial-browse
  // lookup/install is caller-ON-STRAND, but the cursor runs on @ref executor, so those consults hop onto the
  // @ref strand (shared with the cache's own invalidation path) and hop back to @ref executor to continue.
  std::weak_ptr<AddressSpaceCache> cache;
  // std::optional because a strand<any_io_executor> has NO safe default constructor (default-constructing one
  // queries an empty executor and throws bad_executor). It is engaged ONLY on the enabled-cache path (set
  // alongside @ref cache in TypedAccess::browse); the disabled path leaves it nullopt and never hops.
  std::optional<boost::asio::strand<boost::asio::any_io_executor>> strand;
  ua::NodeId startNode;  ///< the node the walk starts from
  BrowseOptions options;  ///< the walk parameters

  std::vector<ua::ReferenceDescription> page;  ///< the current BrowseResult page
  /// The code the current page was answered with: the page's BrowseResult statusCode combined with the
  /// response's ServiceResult. Every entry of the page is yielded with it, so a Good subcode or an
  /// Uncertain code reaches the caller.
  ua::StatusCode pageStatus{ua::Status::Good};
  std::size_t pos = 0;  ///< index of the next unconsumed entry in @ref page
  ua::ContinuationPoint continuationPoint;  ///< non-null/non-empty => a further page can be fetched
  /// Empty pages with a continuation point received in a row (API-D1.1); bounded by
  /// `options.continuationLimits`, reset by a page with references.
  std::uint32_t consecutiveEmptyPages = 0;
  bool started = false;  ///< the initial Browse has been issued
  bool closed = false;  ///< the continuation point has been released; no more advances
  bool advancing = false;  ///< a wire op is in flight (single-in-flight forward-iterator guard)
};

}  // namespace ua::client::detail

#endif  // UA_BROWSE_CURSOR_STATE_H
