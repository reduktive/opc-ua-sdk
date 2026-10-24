// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SUBSCRIPTION_ROUTER_H
#define UA_SUBSCRIPTION_ROUTER_H

#include "ua_integer_id.h"
#include "ua_duration.h"

#include <functional>
#include <cstdint>
#include <mutex>
#include <map>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ua::server
{

class Session;
class Subscription;

/// Server-level registry mapping subscription IDs to their owning session and the subscription
/// object itself. Thread-safe (shared_mutex). Owned by ServerImpl, injected via SessionDependencies.
/// The subscription weak_ptr lets server-wide diagnostics (SubscriptionDiagnosticsArray /
/// SamplingIntervalDiagnosticsArray) read each subscription's cross-strand `get_info()` snapshot
/// without touching any session strand.
///
/// A router is a handle onto shared state: a copy refers to the same registry and tally, which live while
/// any copy does. A holder that can outlive the server - a Subscription whose close a session's teardown
/// queued, a Server Object method the address space keeps - holds a @ref Weak instead, and finds no router
/// once the server's has gone (COMP-SVR-SUBSCRIPTION-SERVER-STATE-01).
class SubscriptionRouter
{
public:
  class Weak;

  /// A router with an empty registry and tally.
  SubscriptionRouter();

  /// A weak handle onto this router's state.
  Weak weak() const;

  void register_subscription(
    IntegerId id, std::weak_ptr<Session> owner, std::weak_ptr<Subscription> subscription);
  void unregister_subscription(IntegerId id);
  std::shared_ptr<Session> find_owner(IntegerId id) const;

  /// Snapshot of all currently-live (subscription, owning-session) pairs. Locks each weak_ptr; only
  /// pairs whose subscription is still alive are returned. Safe to call from any thread.
  std::vector<std::pair<std::shared_ptr<Subscription>, std::shared_ptr<Session>>> live_subscriptions() const;

  /// Lifecycle observers driving the per-subscription `SubscriptionDiagnosticsType` nodes. `onAdded`
  /// fires once when an id is newly registered; `onRemoved` once when it is removed. Both are invoked
  /// without the registry lock held, so the observer may post address-space work freely. Set once at
  /// server startup.
  using SubscriptionAddedCallback =
    std::function<void(IntegerId, std::weak_ptr<Subscription>, std::weak_ptr<Session>)>;
  using SubscriptionRemovedCallback = std::function<void(IntegerId)>;
  void set_lifecycle_observers(SubscriptionAddedCallback onAdded, SubscriptionRemovedCallback onRemoved);

  /// Callback resolving when the per-subscription diagnostic node for an id is ready. Lets the
  /// CreateSubscription pipeline defer its response until the node is visible. Set once at startup.
  using NodeReadinessCallback = std::function<void(IntegerId, std::function<void()>)>;
  void set_node_readiness_callback(NodeReadinessCallback callback);

  /// Invokes @p completion once the diagnostic node for @p id is ready (immediately if no readiness
  /// callback is installed, e.g. when diagnostics nodes are not maintained). Never blocks.
  void when_subscription_node_ready(IntegerId id, std::function<void()> completion) const;

  /// True when a node-readiness callback is installed (i.e. per-subscription diagnostic nodes are
  /// maintained). When false the CreateSubscription pipeline keeps its original synchronous response.
  bool has_node_readiness_callback() const;

  /// Callback bringing the diagnostics that describe MonitoredItems - the per-interval
  /// SamplingIntervalDiagnostics nodes - into line after MonitoredItems were created, modified or
  /// deleted, then invoking its argument. Lets those services defer their responses until a client
  /// browsing the diagnostics next would find them current. Set once at startup.
  using MonitoringReflectionCallback = std::function<void(std::function<void()>)>;
  void set_monitoring_reflection_callback(MonitoringReflectionCallback callback);

  /// Invokes @p completion once the MonitoredItem diagnostics reflect the MonitoredItems as they are now
  /// (immediately if no callback is installed). Never blocks.
  void when_monitoring_reflected(std::function<void()> completion) const;

  /// True when a monitoring-reflection callback is installed. When false the MonitoredItem services keep
  /// their synchronous responses.
  bool has_monitoring_reflection_callback() const;

  /// MonitoredItem counts per sampling interval, as one Subscription reports them.
  using SamplingIntervalCounts = std::map<Duration, uint32_t>;

  /// The sampling intervals in use across every Subscription, and a generation that changes whenever
  /// that set does - an interval coming into use or going out of it, not a count changing.
  struct SamplingIntervalsInUse
  {
    uint64_t generation{0};
    std::vector<Duration> intervals;
  };

  /// Replaces one Subscription's contribution, @p before, with @p after in the server-wide counts. Each
  /// Subscription reports the difference whenever its own counts change, so the server never scans the
  /// Subscriptions to learn which intervals are in use. Thread-safe.
  void update_sampling_intervals(const SamplingIntervalCounts& before, const SamplingIntervalCounts& after);

  /// The intervals in use now. Thread-safe.
  SamplingIntervalsInUse sampling_intervals_in_use() const;

private:
  struct Entry
  {
    std::weak_ptr<Session> owner;
    std::weak_ptr<Subscription> subscription;
  };

  /// The registry and the tally every copy of a router shares.
  struct State
  {
    mutable std::shared_mutex mutex;
    std::unordered_map<IntegerId, Entry> entries;

    // Set once at startup before any subscription exists; copied out under the lock to be invoked.
    SubscriptionAddedCallback onAdded;
    SubscriptionRemovedCallback onRemoved;
    NodeReadinessCallback nodeReadiness;
    MonitoringReflectionCallback monitoringReflection;

    mutable std::mutex intervalMutex;
    std::map<Duration, uint32_t> intervalCounts;  // guarded by intervalMutex; never holds a zero count
    uint64_t intervalGeneration{0};  // guarded by intervalMutex
  };

  explicit SubscriptionRouter(std::shared_ptr<State> state);

  std::shared_ptr<State> mState;
};

/// A weak handle onto a router's state, for a holder that can outlive the router's owner.
class SubscriptionRouter::Weak
{
public:
  /// A handle onto no router.
  Weak() = default;

  /// The router while its state lives; nothing once every router sharing it has gone, or for a handle onto
  /// no router.
  std::optional<SubscriptionRouter> lock() const;

private:
  friend class SubscriptionRouter;

  explicit Weak(std::weak_ptr<State> state);

  std::weak_ptr<State> mState;
};

}  // namespace ua::server

#endif  // !UA_SUBSCRIPTION_ROUTER_H
