// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Per-namespace NodeManagement service delegate.
/// @ingroup server

#ifndef UA_NAMESPACE_DELEGATES_H
#define UA_NAMESPACE_DELEGATES_H

#include <atomic>
#include <functional>
#include <memory>
#include <vector>

#include "ua_add_nodes_item.h"
#include "ua_add_nodes_result.h"
#include "ua_add_references_item.h"
#include "ua_address_space.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_delete_nodes_item.h"
#include "ua_delete_references_item.h"
#include "ua_result.h"
#include "ua_server_authentication.h"
#include "ua_status_code.h"

namespace ua::server
{

// clang-format off

/// Extension interface through which a server applies the OPC UA NodeManagement service.
///
/// A delegate implements the AddNodes, AddReferences, DeleteNodes, and
/// DeleteReferences operations on behalf of a namespace. The SDK validates and
/// authorizes the request, then dispatches each batch to the delegate; the
/// delegate effects the mutation against the supplied @ref AddressSpace and
/// reports a per-item outcome.
///
/// All operations are callback-canonical (`*_async`). A delegate may complete
/// its callback inline or after deferred work; per the SDK post discipline the
/// caller is responsible for unwinding the stack, so the delegate need not post.
///
/// Every operation is called on a thread of the Server's executor, which must not block: a
/// namespace may answer an address-space operation by posting to that same executor. Use the
/// `*_async` address-space operations here; the blocking `AddressSpace::try_find_node_sync`,
/// `try_create_node_sync` and `try_delete_node_sync` refuse on this thread with Bad_WouldBlock.
/// A delegate written with blocking calls must first move the work to a thread the application
/// owns, and complete the callback from there.
/// @ingroup server
class NodeManagementDelegate
{
public:
  virtual ~NodeManagementDelegate() = default;

  NodeManagementDelegate(const NodeManagementDelegate&) = delete;
  NodeManagementDelegate& operator=(const NodeManagementDelegate&) = delete;
  NodeManagementDelegate(NodeManagementDelegate&&) = delete;
  NodeManagementDelegate& operator=(NodeManagementDelegate&&) = delete;

protected:
  /// Protected default constructor: the deleted copy/move members above suppress the
  /// implicit default ctor, but derived classes must be able to construct this base.
  NodeManagementDelegate() = default;

public:

  /// Per-request context: caller identity, endpoint security, and a cancellation flag.
  ///
  /// Passed to every delegate method as `shared_ptr<const Context>` so a
  /// delegate that performs deferred (e.g. coroutine) work can safely extend
  /// the context's lifetime past the originating call. The SDK owns the
  /// context; the delegate must not mutate it.
  struct Context
  {
    /// Authenticated identity of the session issuing the request; never null.
    std::shared_ptr<const UserIdentity> userIdentity;

    /// Security context of the endpoint the request arrived on; never null.
    std::shared_ptr<const EndpointSecurityContext> endpointSecurity;

    /// Cooperative cancellation flag; set true when the request is cancelled.
    ///
    /// A long-running delegate should poll this and abandon work when it
    /// becomes true. Never null.
    std::shared_ptr<const std::atomic_bool> cancelled;
  };

  /// Namespace selected for one AddNodes item before authorization.
  ///
  /// Preparation selects only this routing fact. It does not reserve or assign a NodeId and does
  /// not imply that the namespace supports creation or that the caller is authorized.
  struct AddNodeDestination
  {
    uint16_t namespaceIndex{};  ///< Namespace the SDK authorized the node to be created in.
  };

  /// One AddNodes item explicitly bound to the destination the SDK authorized.
  ///
  /// The mutation delegate must create the item in `destination` and return a non-null NodeId
  /// in that namespace on success.
  struct AuthorizedAddNode
  {
    AddNodesItem item;                 ///< The AddNodes item as the client requested it.
    AddNodeDestination destination;    ///< The namespace the SDK authorized it into.
  };

  /// Per-item outcome of side-effect-free AddNodes destination preparation.
  using PrepareAddNodesItemResult = Result<AddNodeDestination>;

  /// Completion callback for @ref prepare_add_nodes_async.
  using PrepareAddNodesCallback = std::function<void(BatchResult<PrepareAddNodesItemResult>)>;

  /// Per-item outcome of an AddNodes operation.
  ///
  /// Good carries the @ref AddNodesResult (the assigned NodeId and status);
  /// bad carries an @ref ErrorDetail describing why the item could not be added.
  using AddNodesItemResult = Result<AddNodesResult>;

  /// Completion callback for @ref add_nodes_async.
  ///
  /// Receives a @ref BatchResult whose `batchStatus` reports whether the batch as
  /// a whole was accepted, and whose `items` holds one @ref AddNodesItemResult per
  /// request item in request order.
  using AddNodesCompleteCallback = std::function<void(BatchResult<AddNodesItemResult>)>;

  /// Completion callback shared by AddReferences, DeleteNodes, and DeleteReferences.
  ///
  /// Receives a @ref BatchResult whose `batchStatus` reports whether the batch as
  /// a whole was accepted, and whose `items` holds one @ref VoidResult per request
  /// item in request order - good when the item succeeded, otherwise carrying its
  /// @ref ErrorDetail.
  using NodeMgmtCompleteCallback = std::function<void(BatchResult<VoidResult>)>;

  // --- Async (callback-canonical) - pure virtual -------------------------

  /// Selects the destination namespace for each AddNodes item without mutation.
  ///
  /// For an explicit `requestedNewNodeId`, the returned namespace must equal the requested
  /// namespace. For a null identifier, the delegate applies its routing policy. Preparation must
  /// not reserve an identifier, mutate the address space, or decide authorization/capability.
  /// Invoke @p callback exactly once, inline or asynchronously.
  ///
  /// @param context      Request context; the delegate may extend its lifetime.
  /// @param addressSpace Read-only routing context. Preparation must not mutate it.
  /// @param items        Owned items to route, in request order.
  /// @param callback     One destination result per item.
  virtual void prepare_add_nodes_async(std::shared_ptr<const Context> context, AddressSpace addressSpace,
    std::vector<AddNodesItem> items, PrepareAddNodesCallback callback) noexcept;

  /// Adds authorized nodes to the address space.
  ///
  /// The delegate creates each requested node and reports its per-item outcome
  /// through @p callback. The callback runs on an unspecified worker thread -
  /// do not block it. This overload never throws; per-item and batch-level
  /// failures are reported through the @ref BatchResult passed to @p callback.
  ///
  /// @param context      Request context (identity, endpoint security,
  ///                     cancellation); the delegate may extend its lifetime.
  /// @param addressSpace Address space the nodes are added to.
  /// @param items        Nodes paired with their authorized destinations, in request order.
  /// @param callback     Receives the per-item outcomes as a
  ///                     @ref BatchResult of @ref AddNodesItemResult.
  virtual void add_nodes_async(std::shared_ptr<const Context> context, AddressSpace addressSpace,
    std::vector<AuthorizedAddNode> items, AddNodesCompleteCallback callback) = 0;

  /// Adds references to the address space.
  ///
  /// The delegate creates each requested reference and reports its per-item
  /// outcome through @p callback. The callback runs on an unspecified worker
  /// thread - do not block it. This overload never throws; per-item and
  /// batch-level failures are reported through the @ref BatchResult passed to
  /// @p callback.
  ///
  /// @param context      Request context (identity, endpoint security,
  ///                     cancellation); the delegate may extend its lifetime.
  /// @param addressSpace Address space the references are added to.
  /// @param items        References to add, in request order.
  /// @param callback     Receives the per-item outcomes as a
  ///                     @ref BatchResult of @ref VoidResult.
  virtual void add_references_async(std::shared_ptr<const Context> context, AddressSpace addressSpace,
    std::vector<AddReferencesItem> items, NodeMgmtCompleteCallback callback) = 0;

  /// Deletes nodes from the address space.
  ///
  /// The delegate removes each requested node and reports its per-item outcome
  /// through @p callback. The callback runs on an unspecified worker thread -
  /// do not block it. This overload never throws; per-item and batch-level
  /// failures are reported through the @ref BatchResult passed to @p callback.
  ///
  /// A delegate that deletes through @p addressSpace passes each item's
  /// `deleteTargetReferences` as the deletion's `ReferenceHalves`: TRUE as
  /// `ReferenceHalves::Both`, which also removes the References other nodes hold
  /// to the deleted node, FALSE as `ReferenceHalves::ThisHalfOnly`, which leaves
  /// them unresolved (OPC 10000-4 5.7.4.1 and 5.7.4.2, Table 28).
  ///
  /// @param context      Request context (identity, endpoint security,
  ///                     cancellation); the delegate may extend its lifetime.
  /// @param addressSpace Address space the nodes are removed from.
  /// @param items        Nodes to delete, in request order.
  /// @param callback     Receives the per-item outcomes as a
  ///                     @ref BatchResult of @ref VoidResult.
  virtual void delete_nodes_async(std::shared_ptr<const Context> context, AddressSpace addressSpace,
    std::vector<DeleteNodesItem> items, NodeMgmtCompleteCallback callback) = 0;

  /// Deletes references from the address space.
  ///
  /// The delegate removes each requested reference and reports its per-item
  /// outcome through @p callback. A delegate that removes through the source
  /// Node's accessor passes the item's `deleteBidirectional` through as the
  /// accessor's `ReferenceHalves`: `ReferenceHalves::Both` for TRUE, which also
  /// removes the target's half whatever the type, and
  /// `ReferenceHalves::ThisHalfOnly` for FALSE, which removes "only the
  /// specified Reference" (OPC 10000-4 5.7.5.1); see
  /// NodeAccessor::remove_reference_async. The callback runs on an unspecified
  /// worker thread - do not block it. This overload never throws; per-item and
  /// batch-level failures are reported through the @ref BatchResult passed to
  /// @p callback.
  ///
  /// @param context      Request context (identity, endpoint security,
  ///                     cancellation); the delegate may extend its lifetime.
  /// @param addressSpace Address space the references are removed from.
  /// @param items        References to delete, in request order.
  /// @param callback     Receives the per-item outcomes as a
  ///                     @ref BatchResult of @ref VoidResult.
  virtual void delete_references_async(std::shared_ptr<const Context> context, AddressSpace addressSpace,
    std::vector<DeleteReferencesItem> items, NodeMgmtCompleteCallback callback) = 0;
};

// clang-format on

}  // namespace ua::server

#endif  // UA_NAMESPACE_DELEGATES_H
