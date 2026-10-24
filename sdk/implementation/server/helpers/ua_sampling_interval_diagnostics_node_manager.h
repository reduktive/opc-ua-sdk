// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SAMPLING_INTERVAL_DIAGNOSTICS_NODE_MANAGER_H
#define UA_SAMPLING_INTERVAL_DIAGNOSTICS_NODE_MANAGER_H

#include "ua_address_space.h"
#include "ua_node_id.h"
#include "ua_sampling_interval_diagnostics_data_type.h"
#include "ua_server_model.h"
#include "ua_subscription_router.h"
#include "ua_weak_address_space.h"

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

namespace ua::server
{

/// One SamplingIntervalDiagnosticsDataType per distinct revised sampling interval of every live
/// MonitoredItem, in the order the intervals are first met. The value of the SamplingIntervalDiagnosticsArray
/// and of each per-interval node under it.
std::vector<SamplingIntervalDiagnosticsDataType> aggregate_sampling_interval_diagnostics(
  const std::vector<SubscriptionDiagnosticsEntry>& subscriptions);

/// Maintains one SamplingIntervalDiagnosticsType node per distinct sampling interval under the
/// SamplingIntervalDiagnosticsArray (OPC 10000-5 6.3.6), BrowseName the interval in milliseconds, so a
/// client can browse the array for the intervals in use as well as read its Value.
///
/// Which intervals are in use comes from the router's server-wide tally, which the Subscriptions keep
/// current as their MonitoredItems change; nothing here scans them. A reconciliation does work only when
/// that set has changed since the last one - otherwise it answers at once - and the nodes' values are
/// read live. While diagnostics are disabled there are no per-interval nodes: Part 5 6.3.3 has dynamic
/// diagnostic Nodes not appear then. Reconciliations are serialised and coalesced.
class SamplingIntervalDiagnosticsNodeManager
  : public std::enable_shared_from_this<SamplingIntervalDiagnosticsNodeManager>
{
public:
  /// @param addressSpace Address space the nodes are created in.
  /// @param arrayNodeId  The SamplingIntervalDiagnosticsArray the per-interval nodes hang off.
  /// @param provider     Snapshot of every live Subscription's diagnostics; called from any thread.
  /// @param router   The server-wide tally of the sampling intervals in use; must outlive the manager.
  /// @param enabled  The ServerDiagnostics EnabledFlag, or null for always enabled.
  static std::shared_ptr<SamplingIntervalDiagnosticsNodeManager> create(AddressSpace addressSpace,
    NodeId arrayNodeId, SubscriptionDiagnosticsProvider provider, const SubscriptionRouter& router,
    std::shared_ptr<const std::atomic<bool>> enabled);

  /// Brings the per-interval nodes into line with the MonitoredItems as they are now, then invokes
  /// @p completion (on an arbitrary thread) - also when a node could not be created, so a caller
  /// deferring a response on it never hangs.
  void reconcile_async(std::function<void()> completion);

private:
  SamplingIntervalDiagnosticsNodeManager(AddressSpace addressSpace, NodeId arrayNodeId, NodeId stagingNodeId,
    SubscriptionDiagnosticsProvider provider, const SubscriptionRouter& router,
    std::shared_ptr<const std::atomic<bool>> enabled);

  /// What a reconciliation brings the nodes into line with: the set in use, or none while disabled.
  struct Target
  {
    bool enabled{true};
    uint64_t generation{0};
    bool operator==(const Target&) const = default;
  };

  Target current_target() const;

  class ReconcileOperation;

  /// Starts a run for the waiting completions if none is running. Call without mMutex held.
  void start_next_run();

  /// Ends a run: records what the nodes now match (nullopt when the run failed, so the next request
  /// reconciles again), releases the completions it was started for, and starts another if more arrived.
  void finish_run(std::vector<std::function<void()>> completions, std::optional<Target> reconciled);

  // Held weakly, so that a run waiting for a namespace's answer does not keep the address space (CALLS-21
  // rule 1); the run's strand and logger are taken from it at creation.
  WeakAddressSpace mAddressSpace;
  boost::asio::any_io_executor mExecutor;
  Logger mLogger;
  NodeId mArrayNodeId;
  // Hidden holder a node is built under, so it is reachable from the array only once it is complete.
  NodeId mStagingNodeId;
  SubscriptionDiagnosticsProvider mProvider;
  // A handle onto the server's router: the manager can outlive the server while its reconciliations run.
  SubscriptionRouter mRouter;
  std::shared_ptr<const std::atomic<bool>> mEnabled;

  // Touched only by the running ReconcileOperation, of which there is at most one.
  std::map<Duration, NodeId> mNodes;

  std::mutex mMutex;
  bool mRunning{false};
  std::optional<Target> mReconciled;  // guarded by mMutex: what the nodes were last brought into line with
  std::vector<std::function<void()>> mWaiting;
};

}  // namespace ua::server

#endif  // !UA_SAMPLING_INTERVAL_DIAGNOSTICS_NODE_MANAGER_H
