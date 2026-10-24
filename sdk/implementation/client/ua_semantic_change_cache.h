// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SEMANTIC_CHANGE_CACHE_H
#define UA_SEMANTIC_CHANGE_CACHE_H

/// @file
/// @brief The per-Connection, lazily-constructed DataAccess Property invalidation cache (client design
///        section 8.18.2/section 8.18.3): a strand-confined NodeId to weak(TypedPropertiesState) registry
///        that flips each registered handle's `invalidated` flag when a `SemanticsChanged` status bit
///        (CL-DA-010) or a `SemanticChangeEventType` (CL-DA-011) names its NodeId, so the next typed read
///        re-resolves the Properties before combining them with the freshly-read Value.
/// @ingroup client
///
/// **Strand model (the design specification).** The cache has **no private strand** (section 8.18.2: it lives
/// on `ConnectionImpl`'s strand). The strand is injected at construction; every state mutation (`mEntries` +
/// `mObserverHook`) is confined to that single serialization domain. The public mutators self-marshal onto
/// the strand (`post_borrowing`), so they are safe to call from any thread  -  in particular from the
/// off-strand DataAccess handle-build completion (which runs on the executor) and from the subscription /
/// event trigger paths (W8). The cache never fabricates a strand of its own.

#include "ua_logger.h"
#include "ua_node_id.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <memory>
#include <unordered_map>
#include <vector>

namespace ua::client::detail
{

struct SemanticChangeCacheTestAccess;

/// The minimal per-typed-handle Property snapshot the @ref SemanticChangeCache tracks (client design
/// section 8.18.2 "TypedPropertiesState"). It carries only the invalidation flag the cache flips; the
/// DataAccess per-handle state (`DataAccessHandleBase` and its typed derivatives) derives from it and adds
/// the resolved Property values. Held by `shared_ptr`; the cache keeps only a `weak_ptr`, so a dropped
/// handle's state prunes lazily.
///
/// The `std::atomic<bool>` member makes this type (and every derived state) implicitly non-copyable and
/// non-movable, which is correct: the state is only ever created via `make_shared` and mutated in place  -
/// never copied as a whole object.
struct TypedPropertiesState
{
  /// Flipped `true` by the cache on a `SemanticsChanged` bit / `SemanticChangeEventType` naming this
  /// handle's NodeId (CL-DA-010/011); the next typed read re-resolves the Properties and clears it. Atomic
  /// because the cache flips it on the Connection strand while a handle read observes it from the executor.
  std::atomic<bool> invalidated{false};
};

/// The per-Connection DataAccess Property invalidation cache (client design section 8.18.2/section 8.18.3).
///
/// Lifetime: held by `shared_ptr` and derives from `enable_shared_from_this` so every self-marshalled
/// completion (`post_borrowing`) weak-captures the cache and no-ops if it is gone. Owned by `ConnectionImpl`
/// behind a lazily-constructed `shared_ptr`; never outlives the parent Connection.
class SemanticChangeCache : public std::enable_shared_from_this<SemanticChangeCache>
{
public:
  /// The RAII registration handle a DataAccess typed handle holds while it is registered (client design
  /// section 8.18.2). It is stored on the shared @ref TypedPropertiesState (a detail-only struct), so its
  /// lifetime tracks the handle-state: the last handle copy's destruction destroys the state (and this
  /// Ticket), and the cache's `weak_ptr` entry then prunes lazily on the next @ref invalidate_async walk.
  ///
  /// The Ticket deliberately holds **no strong reference back to the state** (that would form a
  /// state and Ticket cycle and leak the state). Entry validity is driven purely by the handle's own strong
  /// reference to its state; the Ticket carries the NodeId + a weak cache back-ref for identity/diagnostics.
  class Ticket
  {
  public:
    /// An empty Ticket (no registration): the DataAccess handle holds one of these when the Connection had
    /// no cache at build time (a gone/absent cache is a clean no-op  -  the manual refresh path still works).
    Ticket() = default;

    /// @return The NodeId this Ticket registered under (empty when the Ticket is empty).
    [[nodiscard]] const ua::NodeId& node_id() const noexcept
    {
      return mNodeId;
    }

    /// @return True iff this Ticket refers to a live registration (a non-empty NodeId + a lockable cache).
    [[nodiscard]] bool registered() const noexcept
    {
      return !mCache.expired();
    }

  private:
    friend class SemanticChangeCache;
    friend struct SemanticChangeCacheTestAccess;

    Ticket(std::weak_ptr<SemanticChangeCache> cache, ua::NodeId nodeId)
      : mCache(std::move(cache)), mNodeId(std::move(nodeId))
    {}

    std::weak_ptr<SemanticChangeCache>
      mCache;  ///< identity back-ref (weak); no strong state ref (cycle-free)
    ua::NodeId mNodeId;  ///< the key this registration lives under in `mEntries`
  };

  /// Creates the cache over @p strand  -  `ConnectionImpl`'s strand (section 8.18.2: the cache has **no
  /// private strand**). Installs a stub observer-hook sentinel (@ref mObserverHook) representing the
  /// on-strand `on_semantic_change` subscription the real trigger wiring (W8) replaces.
  ///
  /// @param strand `ConnectionImpl`'s strand  -  the single serialization domain shared by every mutation.
  /// @param logger Logger for the guarded self-marshalled boundaries.
  /// @return A shared cache.
  [[nodiscard]] static std::shared_ptr<SemanticChangeCache> create(
    boost::asio::strand<boost::asio::any_io_executor> strand, ua::Logger logger);

  SemanticChangeCache(const SemanticChangeCache&) = delete;
  SemanticChangeCache& operator=(const SemanticChangeCache&) = delete;
  SemanticChangeCache(SemanticChangeCache&&) = delete;
  SemanticChangeCache& operator=(SemanticChangeCache&&) = delete;
  ~SemanticChangeCache() = default;

  /// Registers @p state under @p nodeId and returns a @ref Ticket that keeps the registration while the
  /// handle-state lives. The `mEntries` insertion (a `weak_ptr`) is marshalled onto the strand (mEntries is
  /// strand-only); the Ticket is returned synchronously so the DataAccess handle-build completion (which
  /// runs off-strand) can store it. Callable from any thread.
  ///
  /// @param nodeId The Variable NodeId the DataAccess handle targets.
  /// @param state  The handle's shared Property snapshot (kept as a `weak_ptr` in `mEntries`).
  /// @return A Ticket the handle stores on its shared state.
  [[nodiscard]] Ticket register_state(ua::NodeId nodeId, std::shared_ptr<TypedPropertiesState> state);

  /// Invalidates each affected NodeId (CL-DA-010/011): on the strand, for each NodeId look up `mEntries`;
  /// if the `weak_ptr` still locks  to  `state->invalidated.store(true)`; else erase the dead entry (prune).
  /// Self-marshals onto the strand  -  callable from any thread. **This is the single invalidation entry both
  /// the in-band `SemanticsChanged` status-bit path (via the SubscriptionsPipeline publish path) and the
  /// `SemanticChangeEventType` event path (via the section 8.13 EventSubscriber, wired in W8) route
  /// through.**
  ///
  /// @param affected The NodeIds a semantic change named.
  void invalidate_async(std::vector<ua::NodeId> affected);

  /// Drops the observer hook and clears `mEntries` (Connection close, section 8.18.3). Self-marshals onto the
  /// strand; idempotent. Subsequent handle reads locks fail (their interfaces are gone) and surface Bad.
  void close();

private:
  SemanticChangeCache(boost::asio::strand<boost::asio::any_io_executor> strand, ua::Logger logger);

  friend struct SemanticChangeCacheTestAccess;

  // --- on-strand bodies (touch mEntries / mObserverHook only here) ---
  void register_on_strand(ua::NodeId nodeId, std::weak_ptr<TypedPropertiesState> state);
  void invalidate_on_strand(const std::vector<ua::NodeId>& affected);
  void close_on_strand();
  /// Sweeps + erases every expired weak entry from `mEntries` (opportunistic prune, M2). Strand-only.
  void prune_expired_on_strand();

  // No private strand (section 8.18.2): mStrand is ConnectionImpl's, injected at construction.
  boost::asio::strand<boost::asio::any_io_executor> mStrand;
  ua::Logger mLogger;
  // Strand-only. NodeId-keyed weak registry; walked on every invalidate, entries pruned when weak refs
  // expire (lazy). std::hash<ua::NodeId> keys it (NodeId is hashable, as in AddressSpaceCache).
  std::unordered_map<ua::NodeId, std::weak_ptr<TypedPropertiesState>> mEntries;
  // Strand-only. The observer-hook sentinel: a placeholder for the real `on_semantic_change` subscription
  // (W8). Non-null once created; reset by close(). Modelled as shared_ptr<void> so the W8 slice can replace
  // the sentinel with the concrete SemanticChangeHook object without changing this header's shape.
  std::shared_ptr<void> mObserverHook;
};

}  // namespace ua::client::detail

#endif  // UA_SEMANTIC_CHANGE_CACHE_H
