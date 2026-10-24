// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Per-namespace RegisterNodes and UnregisterNodes overrides.
/// @ingroup address_space

#ifndef UA_NAMESPACE_SERVICE_DELEGATES_H
#define UA_NAMESPACE_SERVICE_DELEGATES_H

#include <atomic>
#include <cstddef>
#include <functional>
#include <memory>
#include <vector>

#include "ua_built_in_types_fwd_decl.h"
#include "ua_node_id.h"
#include "ua_result.h"
#include "ua_status_code.h"

namespace ua
{

/// Optional capability hook for namespaces that implement RegisterNodes/UnregisterNodes.
///
/// A namespace inherits from this interface to take over RegisterNodes and UnregisterNodes for its
/// own nodes - for example to allocate optimized, session-scoped NodeId aliases that make repeated
/// access to externally-backed nodes cheaper. Namespaces that do not provide a delegate get the
/// default behaviour: RegisterNodes echoes back the requested NodeIds unchanged, and
/// UnregisterNodes is a no-op.
///
/// Implementations must be safe to call from the server's worker threads; the SDK does not
/// serialize delegate calls onto any particular strand.
/// @ingroup address_space
class NamespaceRegisterNodesDelegate
{
public:
  /// Request-wide inputs shared by every item in a single Register/Unregister batch.
  struct Context
  {
    shared_ptr<std::atomic_bool> cancelled;  ///< Set to true if the request is cancelled while in
                                             ///< flight; the delegate may poll it at any time to
                                             ///< abort long-running work early.
  };

  /// One node to register or unregister within a batch, paired with its position in the request.
  struct Item
  {
    size_t index;  ///< Index of this item in the originating service request, for correlation;
                   ///< preserve it in the corresponding result.
    NodeId nodeId;  ///< Node the client asked to register or unregister.
  };

  /// Callback delivering the per-item RegisterNodes outcomes for an entire batch.
  ///
  /// Invoked exactly once per @ref register_nodes_async call. The @ref BatchResult carries a
  /// batch-level status plus, on success, one registered NodeId per input item in the same order.
  /// On batch-level failure the status carries the cause and the items vector may be empty.
  using RegisterCompleteCallback = std::function<void(BatchResult<NodeId>)>;

  /// Callback signalling completion of an UnregisterNodes batch.
  ///
  /// Invoked exactly once per @ref unregister_nodes_async call. Carries only a single batch-level
  /// status - there are no per-node results.
  using UnregisterCompleteCallback = std::function<void(VoidResult)>;

  virtual ~NamespaceRegisterNodesDelegate() = default;

  NamespaceRegisterNodesDelegate(const NamespaceRegisterNodesDelegate&) = delete;
  NamespaceRegisterNodesDelegate& operator=(const NamespaceRegisterNodesDelegate&) = delete;
  NamespaceRegisterNodesDelegate(NamespaceRegisterNodesDelegate&&) = delete;
  NamespaceRegisterNodesDelegate& operator=(NamespaceRegisterNodesDelegate&&) = delete;

protected:
  /// Protected default constructor: the deleted copy/move members above suppress the
  /// implicit default ctor, but derived classes must be able to construct this base.
  NamespaceRegisterNodesDelegate() = default;

public:
  /// Registers the given nodes and delivers the resulting NodeIds asynchronously.
  ///
  /// Invokes @p callback exactly once when the batch completes. The callback may run on any worker
  /// thread; do not block it. This overload never throws - failures are reported through the
  /// @ref BatchResult payload, not by throwing.
  ///
  /// On batch success, the @ref BatchResult items vector has the same size and order as @p items,
  /// each entry being the (possibly aliased) NodeId the client should use for subsequent access.
  ///
  /// @param context  Request-wide inputs for the batch; valid only for the duration of the call.
  /// @param items    Nodes to register, taken by value so the delegate may retain them.
  /// @param callback Receives the @ref BatchResult; invoked exactly once.
  /// @note Must not throw.
  /// @see unregister_nodes_async
  virtual void register_nodes_async(
    const Context& context, std::vector<Item> items, RegisterCompleteCallback callback) noexcept = 0;

  /// Releases registrations previously created by @ref register_nodes_async.
  ///
  /// Invokes @p callback exactly once when the batch completes. The callback may run on any worker
  /// thread; do not block it. This overload never throws - completion and any batch-level failure
  /// are reported through the @ref VoidResult, not by throwing.
  ///
  /// @param context  Request-wide inputs for the batch; valid only for the duration of the call.
  /// @param items    Nodes to unregister, taken by value so the delegate may retain them.
  /// @param callback Receives the @ref VoidResult; invoked exactly once.
  /// @note Must not throw.
  /// @see register_nodes_async
  virtual void unregister_nodes_async(
    const Context& context, std::vector<Item> items, UnregisterCompleteCallback callback) noexcept = 0;
};

}  // namespace ua

#endif  // UA_NAMESPACE_SERVICE_DELEGATES_H
