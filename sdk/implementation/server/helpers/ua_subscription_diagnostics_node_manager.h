// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SUBSCRIPTION_DIAGNOSTICS_NODE_MANAGER_H
#define UA_SUBSCRIPTION_DIAGNOSTICS_NODE_MANAGER_H

/// @file
/// @brief Maintains the per-subscription `SubscriptionDiagnosticsType` child nodes under the
///        server's `SubscriptionDiagnosticsArray` (i=2290), one per live subscription.
/// @ingroup server

#include "ua_address_space.h"
#include "ua_integer_id.h"
#include "ua_node_id.h"

#include <functional>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ua
{
class SubscriptionDiagnosticsDataType;
}  // namespace ua

namespace ua::server
{

struct SubscriptionInfo;
class Subscription;
class Session;

/// Builds a @ref SubscriptionDiagnosticsDataType record from a cross-strand subscription snapshot.
///
/// Shared by the server-wide `SubscriptionDiagnosticsArray` read handler and the per-subscription
/// diagnostic nodes maintained by @ref SubscriptionDiagnosticsNodeManager.
SubscriptionDiagnosticsDataType build_subscription_diagnostics(
  const SubscriptionInfo& info, const NodeId& sessionId);

/// Maintains the dynamic per-subscription `SubscriptionDiagnosticsType` instance nodes that hang off
/// `Server.ServerDiagnostics.SubscriptionDiagnosticsArray` via `HasComponent` (OPC 10000-5 6.3.7).
///
/// For each live subscription a `SubscriptionDiagnosticsType` (VariableType i=2172) instance is
/// instantiated whose BrowseName is the SubscriptionId and whose field children report live values.
/// The manager is driven by @ref SubscriptionRouter add/remove callbacks; both fire on arbitrary
/// (subscription) strands, so all bookkeeping is mutex-guarded and node mutations are posted
/// asynchronously to the address space. Node removal goes through `delete_node_async` (never the
/// synchronous `NodeSubtree` destructor, which would block a strand on the namespace strand).
///
/// Owned by @ref ServerImpl as a `shared_ptr`; in-flight create flows hold a `weak_ptr` so they
/// no-op safely if the manager is torn down mid-instantiation. Each create runs on a strand minted
/// for that create alone, which serialises only its own steps - the bookkeeping above it stays
/// mutex-guarded because the callbacks that drive it still arrive from arbitrary strands.
/// @ingroup server
class SubscriptionDiagnosticsNodeManager
  : public std::enable_shared_from_this<SubscriptionDiagnosticsNodeManager>
{
public:
  /// @param addressSpace Address space the diagnostic nodes are created in.
  /// @param arrayNodeId  The `SubscriptionDiagnosticsArray` node the per-subscription instances hang
  ///                     off (normally `VariableId::Server_ServerDiagnostics_SubscriptionDiagnosticsArray`).
  static std::shared_ptr<SubscriptionDiagnosticsNodeManager> create(
    AddressSpace addressSpace, NodeId arrayNodeId);

  /// Creates the per-subscription diagnostic node for @p id (idempotent; a second call for an id that
  /// already has - or is creating - a node is a no-op). The captured weak pointers feed the live
  /// read handlers: @p subscription for the counters/state snapshot, @p owner for the SessionId.
  void on_subscription_added(
    IntegerId id, std::weak_ptr<Subscription> subscription, std::weak_ptr<Session> owner);

  /// Removes the per-subscription diagnostic node for @p id (asynchronously). Safe to call for an id
  /// whose node is still being created - removal is deferred until creation completes.
  void on_subscription_removed(IntegerId id);

  /// Invokes @p completion once the per-subscription node for @p id is fully built, linked and wired
  /// (or immediately if it is already done, or its creation failed / was never started - so callers
  /// never hang). Lets CreateSubscription defer its response until the diagnostic node is visible.
  /// @p completion may run on an arbitrary thread.
  void when_ready_async(IntegerId id, std::function<void()> completion);

private:
  SubscriptionDiagnosticsNodeManager(AddressSpace addressSpace, NodeId arrayNodeId, NodeId stagingNodeId);

  // Defined in the .cpp; a nested class, so it reaches the members below without a friend line.
  class CreateOperation;

  void finalize_create(IntegerId id, NodeId rootId);
  void fail_create(IntegerId id);
  // Collects + clears the readiness completions registered for `id` (caller invokes them OUTSIDE the
  // lock). Call under mMutex.
  std::vector<std::function<void()>> take_ready_completions(IntegerId id);
  void remove_node(NodeId rootId);

  AddressSpace mAddressSpace;
  NodeId mArrayNodeId;
  // Hidden holder the instance subtree is instantiated under so it is NOT reachable from the
  // SubscriptionDiagnosticsArray until fully built + wired. Only then is the array HasComponent edge
  // added (link_into_array), making the node atomically visible to clients with all children and live
  // read handlers in place. Created once at construction.
  NodeId mStagingNodeId;

  std::mutex mMutex;
  std::unordered_map<IntegerId, NodeId> mNodes;  // id -> created instance root node id
  std::unordered_set<IntegerId> mPending;  // creation in flight
  std::unordered_set<IntegerId> mRemovedWhilePending;  // removal arrived before creation finished
  // Readiness completions awaiting the in-flight creation of an id (fired on terminal create/fail).
  std::unordered_map<IntegerId, std::vector<std::function<void()>>> mPendingReady;
};

}  // namespace ua::server

#endif  // UA_SUBSCRIPTION_DIAGNOSTICS_NODE_MANAGER_H
