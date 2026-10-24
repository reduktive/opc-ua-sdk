// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_BROWSE_CURSOR_H
#define UA_BROWSE_CURSOR_H

/// @file
/// @brief Tier-2 public `BrowseCursor`: a forward iterator over references from a start node that hides
///        the BrowseResult / BrowseNext continuation-point dance (client design section 7.5).
/// @ingroup client

#include "ua_browse_direction.h"
#include "ua_continuation_limits.h"
#include "ua_date_time.h"
#include "ua_expanded_node_id.h"
#include "ua_localized_text.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_result.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>

namespace ua::client
{

namespace detail
{
class ConnectionImpl;
struct ConnectionHandleFactory;
struct BrowseCursorState;
struct BrowseCursorTestAccess;
}  // namespace detail

class TypedAccess;

/// The parameters of a @ref BrowseCursor walk (client design section 7.5). Defaults browse every forward
/// reference of every node class, returning all result fields, at the server's default page size.
/// @ingroup client
struct BrowseOptions
{
  /// Optional historical instant for a View browse. Mutually exclusive with @ref viewVersion.
  std::optional<ua::DateTime> viewTimestamp;

  /// Optional version for a View browse. Mutually exclusive with @ref viewTimestamp.
  std::optional<std::uint32_t> viewVersion;

  /// Which direction to follow references (Forward / Inverse / Both).
  ua::BrowseDirection direction = ua::BrowseDirection::Forward;

  /// Restrict to this reference type (and, per @ref includeSubtypes, its subtypes). An empty NodeId means
  /// "all reference types".
  ua::NodeId referenceTypeId;

  /// When a @ref referenceTypeId is given, also follow its subtypes.
  bool includeSubtypes = true;

  /// Restrict to these node classes (a bit mask of `NodeClass` values). 0 means "all node classes".
  std::uint32_t nodeClassMask = 0;

  /// Which `ReferenceDescription` fields the server should populate (a bit mask). Defaults to all fields.
  std::uint32_t resultMask = 0x3F;

  /// The maximum references the server returns per page (0 = server default). Exhaustion of a page with a
  /// non-null continuation point transparently drives a BrowseNext.
  std::uint32_t requestedMaxReferencesPerNode = 0;

  /// How many empty pages with a continuation point the cursor re-requests in a row before `next` fails
  /// with `Bad_Timeout`; see @ref ContinuationLimits.
  ContinuationLimits continuationLimits{};
};

/// A forward iterator over the references from a start node (client design section 7.5).
///
/// `BrowseCursor` hides the BrowseResult / BrowseNext continuation-point dance behind a forward-iterator
/// shape: @ref next_async yields one @ref Entry at a time, transparently issuing a BrowseNext when the
/// current page is exhausted and the server held back a continuation point. The cursor idiom is unified
/// with `HistoryReadCursor` (section 8.9): the same @ref has_more predicate name, the same section 7.0 async
/// / sync / try_sync triple on @ref next_async, and the same close-on-destruct + explicit-@ref close_async
/// continuation-point release. Element granularity is per-@ref Entry (vs the history cursor's per-page
/// vector)  -  an intentional, kept difference.
///
/// Move-only: the moved-from cursor releases its continuation point on drop. Not directly constructible;
/// obtained from `TypedAccess::browse`.
///
/// @warning A `BrowseCursor` is a forward iterator: issue one @ref next_async (or a `*_sync` variant) at a
///          time and await its completion before issuing the next. Overlapping advances are rejected.
/// @warning The `*_sync` / `try_*_sync` variants block the calling thread; they MUST NOT be called from
///          the Connection's executor thread.
/// @ingroup client
class BrowseCursor
{
public:
  BrowseCursor(const BrowseCursor&) = delete;
  BrowseCursor& operator=(const BrowseCursor&) = delete;
  /// Returns or updates the browse cursor.
  BrowseCursor(BrowseCursor&&) noexcept = default;
  /// @return A reference to this object.
  /// Supports value-handle comparison or assignment.
  BrowseCursor& operator=(BrowseCursor&&) noexcept = default;

  /// Posts a release-only BrowseNext (`releaseContinuationPoints = true`) to free the server's
  /// continuation point. Idempotent; skipped when no continuation point is held or the wire interface is
  /// gone.
  ~BrowseCursor();

  /// One reference yielded by the walk (a flattened `ReferenceDescription`).
  struct Entry
  {
    /// The target node the reference points at, as an `ExpandedNodeId` (CL-VIEW-017). A LOCAL target has
    /// `server_index() == 0` (and a plain NodeId in `node_id()`); a REMOTE target (`server_index() != 0`)
    /// points at a node on ANOTHER server  -  the SDK preserves the serverIndex + namespace URI verbatim and
    /// does NOT auto-connect to follow it (following the remote reference is the user's responsibility,
    /// OPEN-VIEW-5). NamespaceTable resolution is applied to local references only.
    ///
    /// @warning For a REMOTE target, compare via `targetNodeId.node_id()` or guard on
    ///          `targetNodeId.server_index() != 0` first: the implicit `NodeId(const ExpandedNodeId&)`
    ///          conversion THROWS `UaException(Bad_InvalidArgument)` for a remote / URI-qualified value, so a
    ///          bare `entry.targetNodeId == someNodeId` on a remote target would throw from what looks like a
    ///          pure comparison. A local target compares as its plain NodeId without surprise.
    ua::ExpandedNodeId targetNodeId;
    /// The target's BrowseName.
    ua::QualifiedName browseName;
    /// The target's DisplayName.
    ua::LocalizedText displayName;
    /// The reference's type.
    ua::NodeId referenceTypeId;
    /// The target's type definition (for Object / Variable targets).
    ua::NodeId typeDefinition;
    /// The target's node class.
    ua::NodeClass nodeClass = ua::NodeClass::Unspecified;
    /// True for a forward reference, false for an inverse one.
    bool isForward = true;
  };

  /// @return True iff more entries remain to yield  -  the current page has unconsumed entries, a
  ///         continuation point is held, or the initial Browse has not yet been issued. False once the
  ///         walk is fully drained.
  ///
  /// @warning This reads the strand-free walk state directly (no synchronization). Poll it only from the
  ///          same logical walk flow that awaits @ref next_async  -  i.e. between awaited steps of a single
  ///          sequential walk, never concurrently with an in-flight @ref next_async (or from another
  ///          thread). It is a hint about the last-observed state, consistent only within that sequential
  ///          flow; an overlapping advance would read a torn view.
  [[nodiscard]] bool has_more() const noexcept;

  /// Fetches the next reference. Stream-shaped: exhaustion of the current page with a held continuation
  /// point drives a BrowseNext transparently. The callback receives a bad Result when the walk is already
  /// exhausted, on a server-side failure, or when the wire interface is gone (section 7.0 triple). An
  /// entry is yielded with the code its page was answered with (the page's BrowseResult statusCode
  /// combined with the response's ServiceResult): a Good subcode such as Good_MoreData, or an Uncertain
  /// code, is the status of the Result holding the entry.
  ///
  /// @param callback Receives the next @ref Entry (or a bad Result) on the executor.
  void next_async(std::function<void(ua::Result<Entry>)> callback) noexcept;

  /// @return The operation result, including status and diagnostic detail on failure.
  /// Blocking `try_*` bridge over @ref next_async; never throws. MUST NOT run on the executor thread.
  ua::Result<Entry> try_next_sync() noexcept;

  /// @return The requested value.
  /// Blocking bridge over @ref next_async; throws `UaException` when the Result is not Good (an entry of
  /// an Uncertain page included; try_next_sync() returns it). A Good subcode on the answer is not
  /// returned; try_next_sync() returns it. MUST NOT run on the executor thread.
  Entry next_sync();

  /// Explicitly releases the continuation point now (a release-only BrowseNext). Idempotent (section 7.0
  /// triple).
  ///
  /// @param callback Receives the release BrowseNext's ServiceResult (or a bad Result) on the executor;
  ///                `Good` when nothing had to be released.
  void close_async(std::function<void(ua::VoidResult)> callback) noexcept;

  /// @return The requested value.
  /// Blocking `try_*` bridge over @ref close_async; never throws. MUST NOT run on the executor thread.
  ua::VoidResult try_close_sync() noexcept;

  /// Blocking bridge over @ref close_async; throws `UaException` on a bad Result. MUST NOT run on the
  /// executor thread.
  void close_sync();

private:
  friend class TypedAccess;
  friend struct ua::client::detail::ConnectionHandleFactory;
  friend struct ua::client::detail::BrowseCursorTestAccess;

  explicit BrowseCursor(std::shared_ptr<detail::BrowseCursorState> state);

  std::shared_ptr<detail::BrowseCursorState> mState;
};

}  // namespace ua::client

#endif  // UA_BROWSE_CURSOR_H
