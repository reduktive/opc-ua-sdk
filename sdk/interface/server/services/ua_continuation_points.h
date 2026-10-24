// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Server-side continuation points that resume paginated Browse and HistoryRead requests.
/// @ingroup server

#ifndef UA_CONTINUATION_POINTS_H
#define UA_CONTINUATION_POINTS_H

#include <memory>
#include <utility>

#include "ua_browse_description.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_counter.h"
#include "ua_namespace_history_delegate.h"
#include "ua_node.h"
#include "ua_reference.h"
#include "ua_timestamps_to_return.h"
#include "ua_view_description.h"

namespace ua::detail
{
/// A namespace's resume token with the namespace that issued it; defined by the address space.
class ResumeToken;
}  // namespace ua::detail

namespace ua::server
{

/// An operation a service answered for at its partial-result deadline and handed to a continuation
/// point while it keeps running; defined by the server's services.
class PausedOperation;

/// Releases @p operation when the continuation point holding it goes away unused.
/// @param operation The running operation whose continuation ownership is released.
void release_paused_operation(PausedOperation& operation) noexcept;

/// Captured state that lets a truncated Browse be continued by BrowseNext.
///
/// When a Browse produces more references than the client requested (or more
/// than @ref max_refs_per_node permits), the server returns a slice plus an
/// opaque continuation point. This object holds everything needed to resume:
/// the originating @ref ViewDescription and @ref BrowseDescription, the
/// per-node reference cap, the References read but not yet returned, and the
/// resume token of the namespace's last answer. It is identified by a
/// server-generated @ref Guid that is handed to the client and matched on the
/// subsequent BrowseNext request.
///
/// The point owns the resume token: a token that is not taken back for a
/// BrowseNext is released once, through the namespace that issued it, when
/// the point is destroyed or assigned over - released by the Client, freed
/// for a new request, expired, or discarded with its Session.
///
/// Move-only: copying would duplicate ownership of the resume token. Instances
/// are not internally synchronized; serialize access externally (the server
/// confines each continuation point to its session).
/// @ingroup server
class BrowseContinuationPoint
{
public:
  /// Constructs a continuation point holding no resume token and no References,
  /// so a BrowseNext with it has nothing left to read.
  ///
  /// Generates a fresh @ref Guid identifier. A token a continuation point holds
  /// always comes with the namespace that issued it, so it can be released
  /// (the constructor taking a `ua::detail::ResumeToken`).
  ///
  /// @param viewDescription   View the Browse was issued against.
  /// @param maxRefsPerNode    Maximum references returned per node, as
  ///                          negotiated for the originating request.
  /// @param browseDescription The node and reference filter being browsed.
  BrowseContinuationPoint(
    ViewDescription viewDescription, Counter maxRefsPerNode, const BrowseDescription& browseDescription);

  /// Constructs a continuation point holding the resume token of a namespace's
  /// answer, and the References of that answer not yet returned.
  ///
  /// Generates a fresh @ref Guid identifier. A token not taken back
  /// (@ref take_resume_token) is released through the namespace that issued it
  /// when this object is destroyed or assigned over.
  ///
  /// @param viewDescription    View the Browse was issued against.
  /// @param maxRefsPerNode     Maximum references returned per node.
  /// @param browseDescription  The node and reference filter being browsed.
  /// @param resumeToken        The namespace's token and its issuer; moved in.
  /// @param bufferedReferences References read but not yet returned, replayed
  ///                           by BrowseNext before the token is passed back.
  BrowseContinuationPoint(ViewDescription viewDescription, Counter maxRefsPerNode,
    const BrowseDescription& browseDescription, ua::detail::ResumeToken&& resumeToken,
    References bufferedReferences);

  /// Constructs a continuation point for a Browse operation that was still running when its request
  /// reached the partial-result deadline. A BrowseNext with it returns that operation's results once
  /// they are in; destroying it unused releases the operation.
  /// @param viewDescription View used by the original Browse request.
  /// @param maxRefsPerNode Negotiated per-node reference limit.
  /// @param browseDescription Node and reference filter of the paused Browse.
  /// @param paused Shared ownership of the operation continued by this point.
  BrowseContinuationPoint(ViewDescription viewDescription, Counter maxRefsPerNode,
    const BrowseDescription& browseDescription, shared_ptr<PausedOperation> paused);

  /// Releases the resume token through the namespace that issued it, if one is
  /// still held, and the paused operation, if one is still held.
  ~BrowseContinuationPoint();

  /// Deleted: a continuation point always references a concrete Browse.
  BrowseContinuationPoint() = delete;
  /// Deleted: copying would duplicate ownership of the resume token.
  BrowseContinuationPoint(const BrowseContinuationPoint&) = delete;
  /// Deleted: copying would duplicate ownership of the resume token.
  BrowseContinuationPoint& operator=(const BrowseContinuationPoint&) = delete;

  /// Move-constructs, transferring the resume token and the paused operation.
  ///
  /// @param other Source; left holding neither, and must not be reused except
  ///              to assign or destroy.
  BrowseContinuationPoint(BrowseContinuationPoint&& other) noexcept;

  /// Move-assigns, releasing this object's token and paused operation before
  /// taking @p other 's.
  ///
  /// @param other Source; left holding neither, and must not be reused except
  ///              to assign or destroy.
  /// @return Reference to this object.
  BrowseContinuationPoint& operator=(BrowseContinuationPoint&& other) noexcept;

  /// Takes the paused operation this point continues, if any. The point no longer releases it.
  /// @return The paused operation, or null for a point that pages an ordinary Browse.
  shared_ptr<PausedOperation> take_paused()
  {
    return std::exchange(mPaused, nullptr);
  }

  /// Server-generated identifier matched against incoming BrowseNext requests.
  /// @return The server-generated @ref Guid identifying this continuation point.
  const Guid& identifier() const
  {
    return mIdentifier;
  }

  /// View the originating Browse was issued against.
  /// @return The @ref ViewDescription the originating Browse targeted.
  const ViewDescription& view_description() const
  {
    return mViewDescription;
  }

  /// Maximum number of references to return per node, as negotiated for the
  /// originating Browse request.
  /// @return The per-node reference cap negotiated for the originating Browse.
  Counter max_refs_per_node() const
  {
    return mMaxRefsPerNode;
  }

  /// Node and reference filter being browsed.
  /// @return The @ref BrowseDescription (node plus reference filter) being browsed.
  const BrowseDescription& browse_description() const
  {
    return mBrowseDescription;
  }

  /// Whether the point holds a resume token: the namespace has References left
  /// to return after the buffered ones.
  /// @return True when a namespace resume token is still owned.
  [[nodiscard]] bool has_resume_token() const noexcept;

  /// Takes the resume token, to pass back to the namespace that issued it; the
  /// point no longer releases it. Empty when the point holds none.
  /// @return The transferred token and issuer, or an empty token when none is held.
  [[nodiscard]] ua::detail::ResumeToken take_resume_token() noexcept;

  /// The References read from the namespace but not yet returned. A namespace
  /// page can hold more References than the result had room for (the
  /// maxReferencesPerNode cap falls inside it, or the namespace answered more
  /// than it was asked for), and its resume token points past the whole page,
  /// so BrowseNext replays these (re-applying the filters) before passing the
  /// token back.
  /// @return The buffered References to replay before the namespace token resumes.
  const References& buffered_references() const
  {
    return mBufferedReferences;
  }

  /// Stores the References to replay before the namespace token resumes,
  /// replacing any buffer already held.
  ///
  /// @param references The References not yet returned; moved in.
  /// @see buffered_references
  void set_buffered_references(References references)
  {
    mBufferedReferences = std::move(references);
  }

private:
  Guid mIdentifier;
  ViewDescription mViewDescription;
  Counter mMaxRefsPerNode;
  BrowseDescription mBrowseDescription;
  std::unique_ptr<ua::detail::ResumeToken> mResumeToken;
  References mBufferedReferences;
  shared_ptr<PausedOperation> mPaused;
};

/// Server-side state that lets a HistoryRead be resumed across service calls.
///
/// When a HistoryRead cannot return all values in one response, the SDK creates one
/// HistoryContinuationPoint per unfinished operation and hands the client an opaque
/// identifier. On the follow-up request the client returns that identifier and the SDK
/// replays the stored @ref NamespaceHistoryDelegate::Cursor back to the delegate to fetch
/// the next page.
///
/// The handle owns the delegate cursor: its destructor (and move-assignment overwrite)
/// calls @ref NamespaceHistoryDelegate::release_cursor exactly once on the last owning
/// instance, so the delegate can reclaim any per-cursor resources. It is move-only to keep
/// that ownership single, and is not thread-safe - it is created, accessed, and destroyed on
/// the session's serialized service path.
/// @ingroup server
class HistoryContinuationPoint
{
public:
  /// Constructs a continuation point and assigns it a fresh random identifier.
  ///
  /// Takes ownership of @p cursor; the delegate's @ref NamespaceHistoryDelegate::release_cursor
  /// will be invoked with it when this handle (or its last move target) is destroyed.
  ///
  /// @param namespaceIndex     Namespace whose history delegate owns the cursor.
  /// @param cursor             Opaque pagination state produced by the delegate; moved in.
  /// @param delegate           History delegate that produced and will reclaim the cursor.
  ///                           Must outlive this handle.
  /// @param timestampsToReturn Timestamps the original request asked for, replayed on resume.
  /// @param detailKind         Which HistoryRead operation this point continues.
  HistoryContinuationPoint(uint16_t namespaceIndex, NamespaceHistoryDelegate::Cursor cursor,
    shared_ptr<NamespaceHistoryDelegate> delegate, TimestampsToReturn timestampsToReturn,
    NamespaceHistoryDelegate::DetailKind detailKind)
    : mNamespaceIndex(namespaceIndex), mCursor(std::move(cursor)), mDelegate(std::move(delegate)),
      mTimestampsToReturn(timestampsToReturn), mDetailKind(detailKind)
  {
    mIdentifier.generate();
  }

  /// Releases the owned cursor back to the delegate, if one is still held.
  ///
  /// Calls @ref NamespaceHistoryDelegate::release_cursor only when this instance still owns a
  /// delegate and a cursor - a moved-from handle releases nothing.
  /// Constructs a continuation point for a HistoryRead operation that was still running when its request
  /// reached the partial-result deadline. A HistoryRead with it returns that operation's results once they
  /// are in; destroying it unused releases the operation.
  /// @param namespaceIndex Namespace owning the history request.
  /// @param timestampsToReturn Timestamp selection from the original request.
  /// @param detailKind History detail kind continued by this point.
  /// @param paused Shared ownership of the operation continued by this point.
  HistoryContinuationPoint(uint16_t namespaceIndex, TimestampsToReturn timestampsToReturn,
    NamespaceHistoryDelegate::DetailKind detailKind, shared_ptr<PausedOperation> paused)
    : mNamespaceIndex(namespaceIndex), mTimestampsToReturn(timestampsToReturn), mDetailKind(detailKind),
      mPaused(std::move(paused))
  {
    mIdentifier.generate();
  }

  ~HistoryContinuationPoint()
  {
    if (mDelegate && mCursor.has_value())
      mDelegate->release_cursor(std::move(mCursor));
    if (mPaused)
      release_paused_operation(*mPaused);
  }

  HistoryContinuationPoint(
    const HistoryContinuationPoint&) = delete;  ///< Non-copyable: cursor ownership is unique.
  HistoryContinuationPoint& operator=(
    const HistoryContinuationPoint&) = delete;  ///< Non-copyable: cursor ownership is unique.

  /// Move-constructs from @p other, transferring cursor ownership and leaving @p other inert.
  ///
  /// @param other Source handle; left holding no delegate so it releases no cursor.
  /// @post @p other holds no delegate and will release no cursor on destruction.
  HistoryContinuationPoint(HistoryContinuationPoint&& other) noexcept
    : mIdentifier(other.mIdentifier), mNamespaceIndex(other.mNamespaceIndex),
      mCursor(std::move(other.mCursor)), mDelegate(std::move(other.mDelegate)),
      mTimestampsToReturn(other.mTimestampsToReturn), mDetailKind(other.mDetailKind),
      mPaused(std::move(other.mPaused))
  {
    other.mDelegate = nullptr;  // prevent double release_cursor
    other.mPaused = nullptr;  // prevent releasing the paused operation twice
  }

  /// Move-assigns from @p other, releasing any cursor this handle currently owns first.
  ///
  /// Releases this instance's existing cursor via @ref NamespaceHistoryDelegate::release_cursor
  /// before adopting @p other's state, then leaves @p other inert.
  ///
  /// @param other Source handle; left holding no delegate so it releases no cursor.
  /// @return Reference to this handle.
  /// @post @p other holds no delegate and will release no cursor on destruction.
  HistoryContinuationPoint& operator=(HistoryContinuationPoint&& other) noexcept
  {
    if (this != &other)
    {
      if (mDelegate && mCursor.has_value())
        mDelegate->release_cursor(std::move(mCursor));

      mIdentifier = other.mIdentifier;
      mNamespaceIndex = other.mNamespaceIndex;
      mCursor = std::move(other.mCursor);
      mDelegate = std::move(other.mDelegate);
      mTimestampsToReturn = other.mTimestampsToReturn;
      mDetailKind = other.mDetailKind;
      other.mDelegate = nullptr;
      if (mPaused)
        release_paused_operation(*mPaused);
      mPaused = std::move(other.mPaused);
      other.mPaused = nullptr;
    }
    return *this;
  }

  /// Takes the paused operation this point continues, if any. The point no longer releases it.
  /// @return The paused operation, or null for a point that pages an ordinary HistoryRead.
  shared_ptr<PausedOperation> take_paused()
  {
    return std::exchange(mPaused, nullptr);
  }

  /// Whether this point continues a paused operation rather than a delegate's cursor.
  /// @return True when this point owns a paused operation.
  bool is_paused() const
  {
    return mPaused != nullptr;
  }

  /// Returns the random identifier the client uses to resume this read.
  /// @return The @ref Guid the client presents to resume this HistoryRead.
  const Guid& identifier() const
  {
    return mIdentifier;
  }

  /// Returns the namespace index whose history delegate owns the cursor.
  /// @return The namespace index whose history delegate owns the cursor.
  uint16_t namespace_index() const
  {
    return mNamespaceIndex;
  }

  /// Returns a mutable reference to the owned delegate cursor.
  ///
  /// Used to replay the stored pagination state to the delegate on a continuation request.
  /// The reference is valid only while this handle is alive.
  /// @return Mutable reference to the owned delegate cursor.
  NamespaceHistoryDelegate::Cursor& cursor()
  {
    return mCursor;
  }

  /// Returns a read-only reference to the owned delegate cursor.
  ///
  /// The reference is valid only while this handle is alive.
  /// @return Read-only reference to the owned delegate cursor.
  const NamespaceHistoryDelegate::Cursor& cursor() const
  {
    return mCursor;
  }

  /// Returns the history delegate that produced and will reclaim the cursor.
  ///
  /// Never null on a live (non-moved-from) handle.
  /// @return The @ref NamespaceHistoryDelegate that produced and will reclaim the cursor.
  const shared_ptr<NamespaceHistoryDelegate>& delegate() const
  {
    return mDelegate;
  }

  /// Returns the timestamps the originating request asked for, replayed on resume.
  /// @return The @ref TimestampsToReturn the originating HistoryRead requested.
  TimestampsToReturn timestamps_to_return() const
  {
    return mTimestampsToReturn;
  }

  /// Returns which HistoryRead operation this continuation point continues.
  /// @return The @ref NamespaceHistoryDelegate::DetailKind this continuation point continues.
  NamespaceHistoryDelegate::DetailKind detail_kind() const
  {
    return mDetailKind;
  }

private:
  Guid mIdentifier;
  uint16_t mNamespaceIndex;
  NamespaceHistoryDelegate::Cursor mCursor;
  shared_ptr<NamespaceHistoryDelegate> mDelegate;
  TimestampsToReturn mTimestampsToReturn;
  NamespaceHistoryDelegate::DetailKind mDetailKind;
  shared_ptr<PausedOperation> mPaused;
};

/// Active continuation points keyed by their @ref HistoryContinuationPoint::identifier.
using HistoryContinuationPoints = std::unordered_map<Guid, HistoryContinuationPoint>;

}  // namespace ua::server

#endif  // UA_CONTINUATION_POINTS_H
