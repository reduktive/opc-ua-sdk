// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ORPHANED_SUBSCRIPTION_STORE_H
#define UA_ORPHANED_SUBSCRIPTION_STORE_H

#include "ua_integer_id.h"
#include "ua_array.h"
#include "ua_notification_message.h"
#include "ua_retained_notification_authorization.h"
#include "ua_string.h"
#include "ua_subscription_transfer_authorization.h"

#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

namespace ua::server
{

class Subscription;

/// A retransmittable NotificationMessage and the immutable response-header string table its
/// DiagnosticInfo indices address. The shared table is null on the ordinary diagnostics-free path,
/// so retransmission entries allocate no auxiliary storage unless diagnostics were actually emitted.
struct RetransmissionEntry
{
  IntegerId subscriptionId{0};
  NotificationMessage message;
  std::shared_ptr<const Array<String>> diagnosticStringTable;
  std::vector<RetainedEventProjection> eventProjections;
  std::vector<RetainedDataProjection> dataProjections;
};

/// A subscription detached from a Session that closed with deleteSubscriptions=false (Part 4 5.7.4).
/// It is kept alive here - on its own strand and lifetime timer - until a new Session transfers it
/// (TransferSubscriptions, 5.13) or its own lifetime expires.
struct OrphanedSubscription
{
  std::shared_ptr<Subscription> subscription;
  /// Retransmission entries carried over so post-transfer Republish preserves diagnostic indices.
  std::vector<RetransmissionEntry> retransmissionEntries;
  /// Immutable owning identity, verified ApplicationUri and source-channel mode captured at orphan time.
  SubscriptionTransferContext transferContext;
};

/// Server-level, thread-safe holder for orphaned subscriptions. Owned by ServerImpl and injected into
/// every session's SubscriptionsPipeline. Holding the shared_ptr keeps the subscription (and its
/// strand-local publishing/lifetime timer) alive while it has no owning session.
///
/// A store is a handle onto shared state: a copy refers to the same parked subscriptions, which are closed
/// and dropped when the last copy goes. A pipeline, and the expiry callback of each subscription it parks,
/// can outlive the server, and hold a @ref Weak instead: once the server's store has gone they find none
/// (COMP-SVR-SUBSCRIPTION-SERVER-STATE-01).
class OrphanedSubscriptionStore
{
public:
  class Weak;

  /// @param maxEntries Hard cap on parked subscriptions; parking past it drops the oldest
  ///                   (drop-oldest), bounding memory against a client that orphans without limit.
  ///                   Clamped to >= 1.
  explicit OrphanedSubscriptionStore(size_t maxEntries = 1000);

  /// A weak handle onto this store's state.
  Weak weak() const;

  /// Sets the drop-oldest capacity (clamped to >= 1). Intended for startup configuration before any
  /// subscription is parked; lowering it below the current size does not retroactively evict.
  void set_max_entries(size_t maxEntries);

  /// Park an orphaned subscription. Its ready/expired callbacks must already be rewired so an
  /// expiry while orphaned calls back into remove(). Re-parking an existing id replaces its entry.
  /// At capacity, the oldest parked subscription is dropped (and closed) to make room.
  void park(IntegerId id, OrphanedSubscription entry);

  /// Drop an orphaned subscription (lifetime expiry). Closes it (stops its timer) then releases the
  /// shared_ptr outside the lock - mirrors SubscriptionsPipeline::delete_subscription.
  void remove(IntegerId id);

  /// Remove and return an orphaned subscription for transfer to a new session; nullopt if absent.
  std::optional<OrphanedSubscription> take(IntegerId id);

  /// Close and drop every parked subscription (server shutdown / test teardown).
  void clear();

  bool contains(IntegerId id) const;
  size_t size() const;

private:
  /// The parked subscriptions every copy of a store shares. Destroyed with the last copy, closing every
  /// subscription still parked so its timer is torn down before the shared_ptr drops.
  struct State
  {
    explicit State(size_t capacity);
    ~State();

    State(const State&) = delete;
    State& operator=(const State&) = delete;
    State(State&&) = delete;
    State& operator=(State&&) = delete;

    /// Empties the store under its lock and closes what it held, outside the lock.
    void clear();

    mutable std::mutex mutex;
    std::unordered_map<IntegerId, OrphanedSubscription> entries;
    // Park order (FIFO) for drop-oldest eviction. Kept in lockstep with entries' keys.
    std::deque<IntegerId> parkOrder;
    size_t maxEntries;
  };

  explicit OrphanedSubscriptionStore(std::shared_ptr<State> state);

  std::shared_ptr<State> mState;
};

/// A weak handle onto a store's state, for a holder that can outlive the store's owner.
class OrphanedSubscriptionStore::Weak
{
public:
  /// A handle onto no store.
  Weak() = default;

  /// The store while its state lives; nothing once every store sharing it has gone, or for a handle onto no
  /// store.
  std::optional<OrphanedSubscriptionStore> lock() const;

private:
  friend class OrphanedSubscriptionStore;

  explicit Weak(std::weak_ptr<State> state);

  std::weak_ptr<State> mState;
};

}  // namespace ua::server

#endif  // !UA_ORPHANED_SUBSCRIPTION_STORE_H
