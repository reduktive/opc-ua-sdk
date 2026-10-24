// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_browse_cursor.h"

#include "ua_address_space_cache.h"
#include "ua_browse_cursor_state.h"
#include "ua_browse_description.h"
#include "ua_browse_next_request.h"
#include "ua_browse_next_response.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_result.h"
#include "ua_sync_wait.h"
#include "ua_connection_ops.h"
#include "ua_continuation_point.h"
#include "ua_error_detail.h"
#include "ua_namespace_table.h"
#include "ua_reference_description.h"
#include "ua_status.h"

#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>
#include "ua_on_strand.h"

namespace ua::client
{

namespace detail
{

namespace
{

constexpr std::string_view nextSource = "client.tier2.browse_cursor.next";
constexpr std::string_view closeSource = "client.tier2.browse_cursor.close";
constexpr std::string_view goneSource = "client.tier2.browse_cursor.connection_gone";

/// Builds the initial Browse request for @p state's start node and options.
ua::BrowseRequest make_browse_request(const BrowseCursorState& state)
{
  ua::BrowseDescription browseDescription;
  browseDescription.node_id() = state.startNode;
  browseDescription.browse_direction() = state.options.direction;
  browseDescription.reference_type_id() = state.options.referenceTypeId;
  browseDescription.include_subtypes() = state.options.includeSubtypes;
  browseDescription.node_class_mask() = state.options.nodeClassMask;
  browseDescription.result_mask() = state.options.resultMask;

  ua::BrowseRequest request;
  if (state.options.viewTimestamp.has_value())
  {
    request.view().timestamp() = *state.options.viewTimestamp;
  }
  if (state.options.viewVersion.has_value())
  {
    request.view().view_version() = *state.options.viewVersion;
  }
  request.requested_max_references_per_node() = state.options.requestedMaxReferencesPerNode;
  request.nodes_to_browse().push_back(std::move(browseDescription));
  return request;
}

/// Builds the read-surface cache key for @p state's initial browse  -  EVERY `BrowseDescription` field
/// @ref make_browse_request sends that shapes the returned references, so only a byte-equivalent browse hits
/// the same entry (section 8.7 / section 3.1 wrong-shape guard). `includeSubtypes` is keyed because a subtype
/// walk is a strict superset of a non-subtype one. `requestedMaxReferencesPerNode` is deliberately NOT keyed
/// -  it is a per-page hint the cursor hides behind its per-entry forward-iterator, not a field that changes
/// WHICH references the walk ultimately yields.
CachedBrowseKey make_browse_key(const BrowseCursorState& state)
{
  CachedBrowseKey key;
  key.node = state.startNode;
  key.direction = state.options.direction;
  key.referenceTypeId = state.options.referenceTypeId;
  key.includeSubtypes = state.options.includeSubtypes;
  key.nodeClassMask = state.options.nodeClassMask;
  key.resultMask = state.options.resultMask;
  return key;
}

/// Builds a BrowseNext request for @p continuationPoint. When @p release is true it is a release-only
/// BrowseNext (frees the server continuation point without returning references).
ua::BrowseNextRequest make_browse_next_request(const ua::ContinuationPoint& continuationPoint, bool release)
{
  ua::BrowseNextRequest request;
  request.release_continuation_points() = release;
  request.continuation_points().push_back(continuationPoint);
  return request;
}

/// Flattens a wire @ref ua::ReferenceDescription into a @ref BrowseCursor::Entry. The target node id is kept
/// as the full @ref ua::ExpandedNodeId so a cross-server reference's serverIndex / namespaceUri survive
/// (CL-VIEW-017); the type-definition ExpandedNodeId is still flattened to its local NodeId. A REMOTE
/// reference (`targetNodeId.server_index() != 0`) that omits its mandatory displayName (Part 4 section 7.30
/// fn1) is a non-conformant server: the entry is surfaced verbatim AND an advisory is emitted via @p state's
/// `emitAdvisory` interface (never for a local reference, never for a remote reference that carries a
/// displayName).
BrowseCursor::Entry to_entry(
  const ua::ReferenceDescription& reference, const std::shared_ptr<BrowseCursorState>& state)
{
  BrowseCursor::Entry entry;
  entry.targetNodeId = reference.node_id();  // full ExpandedNodeId: serverIndex + namespaceUri preserved
  entry.browseName = reference.browse_name();
  entry.displayName = reference.display_name();
  entry.referenceTypeId = reference.reference_type_id();
  entry.typeDefinition = reference.type_definition().node_id();
  entry.nodeClass = reference.node_class();
  entry.isForward = reference.is_forward();

  if (entry.targetNodeId.server_index() != 0 &&
      static_cast<std::string_view>(entry.displayName.text()).empty() && state->emitAdvisory)
  {
    state->emitAdvisory(ua::make_error_detail("RemoteReferenceMissingDisplayName",
      "a remote reference (serverIndex != 0) omitted its mandatory displayName (Part 4 section 7.30) - the "
      "server is non-conformant; the reference is surfaced with an empty displayName",
      "client.tier2.browse.remote_reference"));
  }

  // CL-VIEW-018 (Part 6 section 5.2.2.10): a LOCAL target (serverIndex == 0) whose ExpandedNodeId carries a
  // non-empty NamespaceUri has that URI resolved to a local NamespaceIndex against the Connection's
  // NamespaceTable snapshot (the encoded index is 0 on the wire when a URI is present, so the URI is the
  // authoritative namespace). A resolved URI collapses the target to a plain local NodeId (index set, URI
  // dropped) so the entry's node_id() is directly usable for follow-up ops; an UNMAPPED URI is preserved
  // VERBATIM (URI intact, no stale index substituted) for user inspection. A REMOTE target (serverIndex != 0)
  // is left untouched - its URI belongs to the remote server's namespace space, not the local table
  // (CL-VIEW-017). No table snapshot (null, e.g. before the namespace array is read) is a strict no-op.
  if (state->namespaceTable && entry.targetNodeId.server_index() == 0 &&
      !static_cast<std::string_view>(entry.targetNodeId.namespace_uri()).empty())
  {
    auto resolved = state->namespaceTable->resolve_local(entry.targetNodeId);
    if (resolved.is_good())
    {
      entry.targetNodeId = ua::ExpandedNodeId{resolved.value()};  // local index authoritative; URI dropped
    }
    // else: URI not in the local NamespaceArray -> preserve the ExpandedNodeId verbatim (URI intact).
  }

  // CL-VIEW-018: the typeDefinition is ALSO an ExpandedNodeId subject to the same URI-overrides-index
  // invariant (Part 6 section 5.2.2.10), so resolve a LOCAL (serverIndex 0) URI-bearing type definition to
  // its local index too - otherwise the cursor would honour the invariant for the target but silently yield a
  // wrong NS0 index for the adjacent type definition. Entry.typeDefinition is a plain NodeId (it cannot carry
  // a URI), so an unmapped / remote / URI-less type definition falls back to the wire NodeId (index as
  // encoded)
  // - a strict improvement over the unconditional flatten, never worse.
  const ua::ExpandedNodeId& typeDefinition = reference.type_definition();
  if (state->namespaceTable && typeDefinition.server_index() == 0 &&
      !static_cast<std::string_view>(typeDefinition.namespace_uri()).empty())
  {
    auto resolvedType = state->namespaceTable->resolve_local(typeDefinition);
    if (resolvedType.is_good())
    {
      entry.typeDefinition = resolvedType.value();  // local index authoritative
    }
  }
  return entry;
}

/// Posts @p result to @p executor for the entry callback (callbacks always run on the executor).
void deliver_entry(const boost::asio::any_io_executor& executor,
  std::function<void(ua::Result<BrowseCursor::Entry>)> callback, ua::Result<BrowseCursor::Entry> result)
{
  boost::asio::post(executor,
    ua::async::guarded(ua::Logger{},
      [callback = std::move(callback), result = std::move(result)]() mutable
      { callback(std::move(result)); }));
}

/// Posts @p result to @p executor for the void callback.
void deliver_void(const boost::asio::any_io_executor& executor, std::function<void(ua::VoidResult)> callback,
  ua::VoidResult result)
{
  boost::asio::post(executor,
    ua::async::guarded(ua::Logger{},
      [callback = std::move(callback), result = std::move(result)]() mutable
      { callback(std::move(result)); }));
}

void advance_cursor(
  const std::shared_ptr<BrowseCursorState>& state, std::function<void(ua::Result<BrowseCursor::Entry>)> cb);

/// Issues the initial wire Browse for @p state (@p installKey engaged => install the single-page result on a
/// Good, continuation-point-free response). Forward-declared: the enabled-cache miss path calls it after the
/// strand hop, and the disabled path calls it inline.
void issue_initial_browse_wire(const std::shared_ptr<BrowseCursorState>& state,
  const std::shared_ptr<WireOps>& wireOps, std::optional<CachedBrowseKey> installKey,
  std::function<void(ua::Result<BrowseCursor::Entry>)> cb);

/// Yields @p entry with the code its page was answered with: a Good subcode or an Uncertain code of the
/// page is the status of the Result holding the entry.
ua::Result<BrowseCursor::Entry> page_entry(const BrowseCursorState& state, BrowseCursor::Entry entry)
{
  return ua::detail::held(std::move(entry), state.pageStatus);
}

/// Applies one returned BrowseResult page to @p state and yields the first entry (or chains a BrowseNext
/// when the page was empty but a continuation point is held, or reports exhaustion). @p serviceResult is
/// the ServiceResult of the response the page came in; it is combined with the page's own status.
void apply_browse_result(const std::shared_ptr<BrowseCursorState>& state, const ua::BrowseResult& result,
  const ua::StatusCode& serviceResult, std::function<void(ua::Result<BrowseCursor::Entry>)> cb)
{
  if (state->sessionGeneration &&
      state->sessionGeneration->load(std::memory_order_relaxed) != state->operationGeneration)
  {
    state->continuationPoint = ua::ContinuationPoint{};
    deliver_entry(state->executor,
      std::move(cb),
      ua::Result<BrowseCursor::Entry>{ua::Status::BadSessionIdInvalid,
        ua::make_error_detail("BrowseCursorSessionChanged",
          "the Session changed while the browse page was in flight; its continuation point was discarded",
          "client.tier2.browse.session_binding")});
    return;
  }
  if (state->closed)
  {
    // close_async raced this in-flight advance: it set closed=true and released the continuation point the
    // advance was fetching from. A freshly-returned continuation point must NOT be stored into a closed
    // cursor  -  ~BrowseCursor early-returns on `closed`, so it would leak server-side until the Session
    // timeout. Release it now with a release-only BrowseNext, then complete the pending next() as closed.
    if (!result.continuation_point().empty())
    {
      if (auto wireOps = state->wireOps.lock())
      {
        wireOps->browse_next_async(make_browse_next_request(result.continuation_point(), /*release=*/true),
          [](ua::Result<ua::BrowseNextResponse>) {});  // fire-and-forget: advisory, no state capture
      }
      state->continuationPoint = ua::ContinuationPoint{};
    }
    deliver_entry(state->executor,
      std::move(cb),
      ua::Result<BrowseCursor::Entry>{ua::Status::BadInvalidState,
        ua::make_error_detail("BrowseCursorClosed",
          "the cursor was closed during an in-flight advance; its returned continuation point was released",
          std::string{closeSource})});
    return;
  }
  if (result.status_code().is_bad())
  {
    deliver_entry(state->executor,
      std::move(cb),
      ua::Result<BrowseCursor::Entry>{result.status_code(),
        ua::make_error_detail(
          "BrowseResultBad", "the server returned a bad per-node Browse status", std::string{nextSource})});
    return;
  }
  // CL-VIEW-005: a Good_MoreData status paired with an EMPTY continuation point is non-conformant (Part 4
  // section 7.6: the continuation point is the ONLY normative "more results" signal). The walk proceeds
  // exactly as for a plain Good response (the empty CP below is treated as done); surface the server bug via
  // an advisory.
  if (result.status_code().as_status() == ua::Status::GoodMoreData && result.continuation_point().empty() &&
      state->emitAdvisory)
  {
    state->emitAdvisory(ua::make_error_detail("BrowseGoodMoreDataWithoutContinuationPoint",
      "the server returned Good_MoreData but no continuation point (Part 4 section 7.6) - Good_MoreData is "
      "not the "
      "normative 'more results' signal, so the walk is treated as done at this page",
      "client.tier2.browse.good_more_data"));
  }
  state->page = result.references().payload();
  state->pageStatus = ua::detail::combined_status(serviceResult, result.status_code());
  state->pos = 0;
  state->continuationPoint = result.continuation_point();
  if (!state->continuationPoint.empty())
  {
    state->continuationGeneration = state->operationGeneration;
  }

  if (state->pos < state->page.size())
  {
    state->consecutiveEmptyPages = 0;
    auto entry = to_entry(state->page[state->pos++], state);
    deliver_entry(state->executor, std::move(cb), page_entry(*state, std::move(entry)));
    return;
  }
  if (!state->continuationPoint.empty())
  {
    // API-D1.1: an empty page with a continuation point is not the end (Part 4 5.8.2.1 lets a server stop
    // early, for example when access control filtered a whole page): ask again, up to the configured number
    // of empty pages in a row. One more fails with Bad_Timeout and releases the point. This replaces the
    // same-continuation-point check (API-D1.3), which ended such a conforming walk early.
    const std::uint32_t limit = state->options.continuationLimits.maxConsecutiveEmptyPages;
    if (++state->consecutiveEmptyPages > limit)
    {
      if (auto wireOps = state->wireOps.lock())
      {
        wireOps->browse_next_async(make_browse_next_request(state->continuationPoint, /*release=*/true),
          [](ua::Result<ua::BrowseNextResponse>) {});  // fire-and-forget: advisory, no state capture
      }
      state->continuationPoint = ua::ContinuationPoint{};
      deliver_entry(state->executor,
        std::move(cb),
        ua::Result<BrowseCursor::Entry>{ua::Status::BadTimeout,
          ua::ErrorDetail::build("BrowseCursorEmptyPageLimitExceeded",
            "the server returned more empty pages in a row than the cursor's ContinuationLimits allow; the "
            "continuation point was released",
            std::string{nextSource})
            .context(ua::ContextKeys::countActual, state->consecutiveEmptyPages)
            .context(ua::ContextKeys::limit, limit)});
      return;
    }
    advance_cursor(state, std::move(cb));
    return;
  }
  // No references and no continuation point: the walk is exhausted.
  deliver_entry(state->executor,
    std::move(cb),
    ua::Result<BrowseCursor::Entry>{ua::Status::BadNoData,
      ua::make_error_detail("BrowseCursorExhausted",
        "the browse walk yielded no further references (the cursor is exhausted)",
        std::string{nextSource})});
}

/// Best-effort install of @p references as the single-page read-surface cache entry under @p key. Hops onto
/// the connection strand (the cache's caller-on-strand serialization domain, shared with its invalidation
/// path) and weak-locks the cache. Fire-and-forget; a gone cache is a clean skip (no crash). Independent of
/// cursor liveness  -  the page was already fetched, so caching it does not require the cursor to still be
/// alive.
void install_single_page(
  const BrowseCursorState& state, CachedBrowseKey key, std::vector<ua::ReferenceDescription> references)
{
  if (!state.strand.has_value())
  {
    return;  // no strand wired: defensive (the caller only installs on the enabled-cache path)
  }
  std::weak_ptr<AddressSpaceCache> weakCache = state.cache;
  ua::async::post_borrowing(weakCache,
    *state.strand,
    ua::Logger{},
    [key = std::move(key), references = std::move(references)](AddressSpaceCache& cache) mutable
    {
      BrowseEntry entry;
      entry.references = std::move(references);
      entry.installedAt = std::chrono::steady_clock::now();
      cache.install_browse(std::move(key), std::move(entry));  // caller-on-strand
    })();
}

/// Serves a read-surface cache HIT (runs on the executor after the strand hop): adopts @p entry's references
/// as the current single page and yields the first entry, exactly as a single-page wire Browse would. A
/// cached page holds NO continuation point, so `has_more`/close/`~BrowseCursor` stay clean no-ops. Respects a
/// close that raced the cache hop.
void serve_cached_page(const std::shared_ptr<BrowseCursorState>& state, BrowseEntry entry,
  std::function<void(ua::Result<BrowseCursor::Entry>)> cb)
{
  state->advancing = false;
  state->started = true;
  if (state->closed)
  {
    // close_async raced the cache hop (a cached page holds no continuation point, so there is nothing to
    // release): complete the pending next() as closed.
    deliver_entry(state->executor,
      std::move(cb),
      ua::Result<BrowseCursor::Entry>{ua::Status::BadInvalidState,
        ua::make_error_detail("BrowseCursorClosed",
          "the cursor was closed during the read-surface cache lookup",
          std::string{closeSource})});
    return;
  }
  state->page = std::move(entry.references);
  // Only a page answered plain Good is cached, so a cached page is yielded plain Good.
  state->pageStatus = ua::StatusCode{ua::Status::Good};
  state->pos = 0;
  state->continuationPoint = ua::ContinuationPoint{};
  if (state->pos < state->page.size())
  {
    auto served = to_entry(state->page[state->pos++], state);
    deliver_entry(state->executor, std::move(cb), page_entry(*state, std::move(served)));
    return;
  }
  // A cached EMPTY single page: the walk is exhausted (mirrors the wire single-page-empty path).
  deliver_entry(state->executor,
    std::move(cb),
    ua::Result<BrowseCursor::Entry>{ua::Status::BadNoData,
      ua::make_error_detail("BrowseCursorExhausted",
        "the cached browse page yielded no references (the cursor is exhausted)",
        std::string{nextSource})});
}

/// Issues the initial wire Browse for @p state and delivers its first entry (the walk's cache-MISS / disabled
/// path). When @p installKey is engaged AND the response is a WHOLE single page (Good service result, no
/// continuation point) it is installed into the read-surface cache  -  single-page-only (v1): a continuation-
/// point-bearing (multi-page) result is NOT cached. @p installKey is `nullopt` on the disabled / unwired
/// path, so that path is byte-for-byte the pre-cache behaviour (no install, no strand hop). Weak-captures @p
/// state.
void issue_initial_browse_wire(const std::shared_ptr<BrowseCursorState>& state,
  const std::shared_ptr<WireOps>& wireOps, std::optional<CachedBrowseKey> installKey,
  std::function<void(ua::Result<BrowseCursor::Entry>)> cb)
{
  std::weak_ptr<BrowseCursorState> weak = state;
  wireOps->browse_async(make_browse_request(*state),
    [weak, installKey = std::move(installKey), cb = std::move(cb)](
      ua::Result<ua::BrowseResponse> response) mutable
    {
      auto locked = weak.lock();
      if (!locked)
      {
        return;  // the cursor was dropped mid-flight: bail (UAF guard) - do not touch freed state
      }
      locked->advancing = false;
      locked->started = true;
      if (!response.has_value())
      {
        deliver_entry(locked->executor,
          std::move(cb),
          ua::Result<BrowseCursor::Entry>{response.status_code(), response.shared_detail()});
        return;
      }
      // Facade flatten (mirrors ua_discovery.cpp:47 + the read/write value facades): the tier-0 wire-op
      // funnel returns the response verbatim and does NOT lift a bad ResponseHeader.serviceResult into the
      // outer Result. A service-level bad on Browse must abort the walk carrying THAT code (CL-VIEW-006), not
      // be misreported as the empty-results BadUnexpectedError below. Checked BEFORE the empty-results guard
      // so a service fault wins over the shape check.
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        deliver_entry(locked->executor,
          std::move(cb),
          ua::Result<BrowseCursor::Entry>{serviceResult,
            ua::make_error_detail("BrowseServiceFault",
              "the server returned a bad service-level result for the Browse",
              std::string{nextSource})});
        return;
      }
      const auto& results = response.value().results();
      if (results.empty())
      {
        deliver_entry(locked->executor,
          std::move(cb),
          ua::Result<BrowseCursor::Entry>{ua::Status::BadUnexpectedError,
            ua::make_error_detail("BrowseEmptyResults",
              "the server returned a Good Browse response with no result for the single node",
              std::string{nextSource})});
        return;
      }
      const ua::BrowseResult& result = results[0];
      // Read-surface cache install (section 8.7): only a WHOLE single page is cached  -  a multi-page
      // (continuation-point-bearing) result is NOT installed (single-page-only, v1)  -  and never when a
      // close raced the in-flight browse. Strand-hopped + weak; a gone cache is a clean skip. The status gate
      // keys on the EXACT plain-Good sub-code (not is_good()): a Good_MoreData page with an empty
      // continuation point is server-flagged-incomplete (CL-VIEW-005, Part 4 section 7.6)  -  caching it as a
      // "whole page" would poison the cache with a truncated result and suppress the non-conformance advisory
      // on every cache hit (BrowseEntry stores only the references, so a hit cannot re-derive the
      // Good_MoreData status). Only an unambiguously-complete plain-Good page is installed; any other Good
      // sub-code is served but not cached. A response whose ServiceResult is not plain Good is not cached
      // either: the cache keeps References only, so a hit could not answer that code again.
      if (installKey.has_value() && !locked->closed && result.status_code().as_status() == ua::Status::Good &&
          serviceResult.as_status() == ua::Status::Good && result.continuation_point().empty())
      {
        install_single_page(*locked, std::move(*installKey), result.references().payload());
      }
      apply_browse_result(locked, result, serviceResult, std::move(cb));
    });
}

/// Enabled-cache initial-browse path: hops onto the connection strand to consult `lookup_browse(@p key)`
/// (caller-on-strand, serialized with `on_model_change_async`'s LruMap mutation), then hops back to the
/// executor to serve a HIT from cache (no wire Browse) or issue the wire Browse on a MISS. Weak-captures the
/// cursor state (dropped mid-hop  to  bail) and the cache (gone  to  treated as a MISS  to  wire Browse). @p
/// state's `advancing` flag is already set by @ref advance_cursor, so the single-in-flight forward-iterator
/// guard holds across BOTH hops  -  no second `next()` can start and reorder pages.
void consult_browse_cache_then_initial(const std::shared_ptr<BrowseCursorState>& state, CachedBrowseKey key,
  std::function<void(ua::Result<BrowseCursor::Entry>)> cb)
{
  std::weak_ptr<BrowseCursorState> weak = state;
  ua::async::post_borrowing(weak,
    *state->strand,
    ua::Logger{},
    [weak, key, cb = std::move(cb)](BrowseCursorState&) mutable
    {
      auto locked = weak.lock();
      if (!locked)
      {
        return;  // cursor dropped mid-hop: bail (no delivery owed to a gone cursor)
      }
      std::optional<BrowseEntry> hit;
      if (auto cache = locked->cache.lock())
      {
        hit = cache->lookup_browse(key);  // caller-on-strand lookup
      }
      const boost::asio::any_io_executor executor = locked->executor;
      // Hop back to the executor to continue the walk (cursor-state mutation + the user callback are
      // executor-affine; the strand is only for the cache touch).
      ua::async::post_borrowing(weak,
        executor,
        ua::Logger{},
        [weak, key, hit = std::move(hit), cb = std::move(cb)](BrowseCursorState&) mutable
        {
          auto cursorState = weak.lock();
          if (!cursorState)
          {
            return;
          }
          if (hit.has_value())
          {
            serve_cached_page(cursorState, std::move(*hit), std::move(cb));  // HIT: serve, no wire Browse
            return;
          }
          auto wireOps = cursorState->wireOps.lock();
          if (!wireOps)
          {
            // The wire interface (and the Connection behind it) went away during the hop: complete with the
            // same boundary failure the synchronous gone path uses.
            cursorState->advancing = false;
            deliver_entry(cursorState->executor,
              std::move(cb),
              ua::Result<BrowseCursor::Entry>{ua::Status::BadConnectionClosed,
                ua::make_error_detail("BrowseCursorConnectionGone",
                  "the Connection was dropped before the browse advance could be issued",
                  std::string{goneSource})});
            return;
          }
          issue_initial_browse_wire(
            cursorState, wireOps, std::move(key), std::move(cb));  // MISS: wire + install
        })();
    })();
}

/// Drives one @ref BrowseCursor::next_async step: yields a buffered entry, or issues the initial Browse /
/// a BrowseNext, or reports exhaustion. Every wire completion weak-captures @p state and bails if gone.
void advance_cursor(
  const std::shared_ptr<BrowseCursorState>& state, std::function<void(ua::Result<BrowseCursor::Entry>)> cb)
{
  if (state->closed)
  {
    deliver_entry(state->executor,
      std::move(cb),
      ua::Result<BrowseCursor::Entry>{ua::Status::BadInvalidState,
        ua::make_error_detail(
          "BrowseCursorClosed", "next() called on a closed cursor", std::string{nextSource})});
    return;
  }
  if (state->advancing)
  {
    deliver_entry(state->executor,
      std::move(cb),
      ua::Result<BrowseCursor::Entry>{ua::Status::BadInvalidState,
        ua::make_error_detail("BrowseCursorBusy",
          "next() called while a prior advance is still in flight (forward-iterator: await each next)",
          std::string{nextSource})});
    return;
  }
  if (state->pos < state->page.size())
  {
    auto entry = to_entry(state->page[state->pos++], state);
    deliver_entry(state->executor, std::move(cb), page_entry(*state, std::move(entry)));
    return;
  }

  const bool needInitialBrowse = !state->started;
  const bool haveContinuation = !state->continuationPoint.empty();
  if (!needInitialBrowse && !haveContinuation)
  {
    deliver_entry(state->executor,
      std::move(cb),
      ua::Result<BrowseCursor::Entry>{ua::Status::BadNoData,
        ua::make_error_detail("BrowseCursorExhausted",
          "next() called on an exhausted cursor (no continuation point)",
          std::string{nextSource})});
    return;
  }

  if (needInitialBrowse && state->options.viewTimestamp.has_value() && state->options.viewVersion.has_value())
  {
    deliver_entry(state->executor,
      std::move(cb),
      ua::Result<BrowseCursor::Entry>{ua::Status::BadInvalidArgument,
        ua::make_error_detail("BrowseViewParametersMutuallyExclusive",
          "viewTimestamp and viewVersion are mutually exclusive (OPC 10000-4 section 7.45)",
          std::string{nextSource})});
    return;
  }

  auto wireOps = state->wireOps.lock();
  if (!wireOps)
  {
    // The wire interface (and the Connection behind it) is gone: complete with a boundary failure rather than
    // dereferencing it (section 7.5 / section 8.2A.13 gone path).
    deliver_entry(state->executor,
      std::move(cb),
      ua::Result<BrowseCursor::Entry>{ua::Status::BadConnectionClosed,
        ua::make_error_detail("BrowseCursorConnectionGone",
          "the Connection was dropped before the browse advance could be issued",
          std::string{goneSource})});
    return;
  }

  state->advancing = true;
  state->operationGeneration =
    state->sessionGeneration ? state->sessionGeneration->load(std::memory_order_relaxed) : 0;
  std::weak_ptr<BrowseCursorState> weak = state;
  if (needInitialBrowse)
  {
    // Read-surface Browse cache (section 8.7): on the INITIAL browse only, an ENABLED cache is consulted on a
    // strand hop before the wire Browse (a HIT serves the cached page with no wire Browse; a MISS issues the
    // Browse and installs its single page). A disabled / unwired cursor takes NEITHER the hop nor the install
    // -  the wire Browse is issued exactly as before (a byte-for-byte pass-through, strict no-op).
    auto cache = state->cache.lock();
    const bool hasViewSelection =
      state->options.viewTimestamp.has_value() || state->options.viewVersion.has_value();
    if (!hasViewSelection && cache && cache->enabled() && state->strand.has_value())
    {
      consult_browse_cache_then_initial(state, make_browse_key(*state), std::move(cb));
      return;
    }
    issue_initial_browse_wire(state, wireOps, /*installKey=*/std::nullopt, std::move(cb));
    return;
  }

  if (state->sessionGeneration && state->operationGeneration != state->continuationGeneration)
  {
    state->advancing = false;
    state->continuationPoint = ua::ContinuationPoint{};
    deliver_entry(state->executor,
      std::move(cb),
      ua::Result<BrowseCursor::Entry>{ua::Status::BadSessionIdInvalid,
        ua::make_error_detail("BrowseCursorSessionChanged",
          "the Browse continuation point belongs to a Session that has been replaced",
          "client.tier2.browse.session_binding")});
    return;
  }

  wireOps->browse_next_on_session_async(state->continuationGeneration,
    make_browse_next_request(state->continuationPoint, /*release=*/false),
    [weak, cb = std::move(cb)](ua::Result<ua::BrowseNextResponse> response) mutable
    {
      auto locked = weak.lock();
      if (!locked)
      {
        return;  // the cursor was dropped mid-flight: bail (UAF guard)
      }
      locked->advancing = false;
      if (!response.has_value())
      {
        deliver_entry(locked->executor,
          std::move(cb),
          ua::Result<BrowseCursor::Entry>{response.status_code(), response.shared_detail()});
        return;
      }
      // Same facade flatten as the initial Browse: a bad BrowseNext ResponseHeader.serviceResult (which the
      // funnel returns verbatim) aborts the walk carrying that code, ahead of the empty-results shape check.
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        deliver_entry(locked->executor,
          std::move(cb),
          ua::Result<BrowseCursor::Entry>{serviceResult,
            ua::make_error_detail("BrowseNextServiceFault",
              "the server returned a bad service-level result for the BrowseNext",
              std::string{nextSource})});
        return;
      }
      const auto& results = response.value().results();
      if (results.empty())
      {
        deliver_entry(locked->executor,
          std::move(cb),
          ua::Result<BrowseCursor::Entry>{ua::Status::BadUnexpectedError,
            ua::make_error_detail("BrowseNextEmptyResults",
              "the server returned a Good BrowseNext response with no result",
              std::string{nextSource})});
        return;
      }
      apply_browse_result(locked, results[0], serviceResult, std::move(cb));
    });
}

/// Issues the best-effort release-only BrowseNext for @p state's held continuation point (idempotent).
/// Skips when there is nothing to release or the wire interface is gone. Clears the local continuation point.
void release_continuation_point(BrowseCursorState& state)
{
  if (state.closed || state.continuationPoint.empty())
  {
    return;
  }
  auto wireOps = state.wireOps.lock();
  if (!wireOps)
  {
    state.continuationPoint = ua::ContinuationPoint{};
    return;  // interface gone: nothing to free server-side, bail cleanly
  }
  if (state.sessionGeneration &&
      state.sessionGeneration->load(std::memory_order_relaxed) != state.continuationGeneration)
  {
    state.continuationPoint = ua::ContinuationPoint{};
    return;  // stale Session-bound continuation point must never be sent on the replacement Session
  }
  wireOps->browse_next_on_session_async(state.continuationGeneration,
    make_browse_next_request(state.continuationPoint, /*release=*/true),
    [](ua::Result<ua::BrowseNextResponse>) {});  // fire-and-forget: no state capture, result is advisory
  state.continuationPoint = ua::ContinuationPoint{};
}

}  // namespace

}  // namespace detail

BrowseCursor::BrowseCursor(std::shared_ptr<detail::BrowseCursorState> state) : mState(std::move(state))
{}

BrowseCursor::~BrowseCursor()
{
  if (!mState)
  {
    return;  // moved-from
  }
  detail::release_continuation_point(*mState);
}

bool BrowseCursor::has_more() const noexcept
{
  if (!mState)
  {
    return false;
  }
  if (mState->pos < mState->page.size())
  {
    return true;  // buffered entries remain
  }
  if (!mState->continuationPoint.empty())
  {
    return true;  // a further page can be fetched
  }
  return !mState->started && !mState->closed;  // the initial Browse has not been issued yet
}

void BrowseCursor::next_async(std::function<void(ua::Result<Entry>)> callback) noexcept
{
  if (!mState)
  {
    callback(ua::Result<Entry>{ua::Status::BadInvalidState,
      ua::make_error_detail(
        "BrowseCursorEmpty", "next() called on a moved-from cursor", std::string{detail::nextSource})});
    return;
  }
  detail::advance_cursor(mState, std::move(callback));
}

ua::Result<BrowseCursor::Entry> BrowseCursor::try_next_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<Entry>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this](auto completion) { next_async(std::move(completion)); });
}

BrowseCursor::Entry BrowseCursor::next_sync()
{
  return ua::detail::good_value(try_next_sync());
}

void BrowseCursor::close_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mState)
  {
    callback(ua::VoidResult{ua::Status::BadInvalidState});
    return;
  }
  auto state = mState;
  if (state->closed || state->continuationPoint.empty())
  {
    // Nothing to release (idempotent): mark closed and report Good on the executor.
    state->closed = true;
    detail::deliver_void(state->executor, std::move(callback), ua::VoidResult{});
    return;
  }
  auto wireOps = state->wireOps.lock();
  if (!wireOps)
  {
    // The wire interface is gone: there is nothing to free server-side. Clear locally and report Good
    // (best-effort release, idempotent).
    state->closed = true;
    state->continuationPoint = ua::ContinuationPoint{};
    detail::deliver_void(state->executor, std::move(callback), ua::VoidResult{});
    return;
  }
  if (state->sessionGeneration &&
      state->sessionGeneration->load(std::memory_order_relaxed) != state->continuationGeneration)
  {
    state->closed = true;
    state->continuationPoint = ua::ContinuationPoint{};
    detail::deliver_void(state->executor, std::move(callback), ua::VoidResult{});
    return;
  }
  state->closed = true;
  auto continuationPoint = state->continuationPoint;
  state->continuationPoint = ua::ContinuationPoint{};
  auto executor = state->executor;
  wireOps->browse_next_on_session_async(state->continuationGeneration,
    detail::make_browse_next_request(continuationPoint, /*release=*/true),
    [callback = std::move(callback), executor](ua::Result<ua::BrowseNextResponse> response) mutable
    {
      // The continuation point is already cleared locally; surface the service result so a release failure
      // is not silently swallowed (the design specification), but the cursor is closed regardless.
      if (!response.has_value())
      {
        detail::deliver_void(
          executor, std::move(callback), ua::VoidResult{response.status_code(), response.shared_detail()});
        return;
      }
      detail::deliver_void(executor,
        std::move(callback),
        ua::VoidResult{ua::detail::combined_status(
          response.status_code(), response.value().response_header().service_result())});
    });
}

ua::VoidResult BrowseCursor::try_close_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this](auto completion) { close_async(std::move(completion)); });
}

void BrowseCursor::close_sync()
{
  try_close_sync().value();
}

}  // namespace ua::client
