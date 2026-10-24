// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief RAII handle owning the nodes created by an instantiation.
/// @ingroup address_space

#ifndef UA_NODE_SUBTREE_H
#define UA_NODE_SUBTREE_H

#include "ua_address_space.h"
#include "ua_weak_address_space.h"

namespace ua
{

/// An owning, move-only handle to the nodes produced by a single instantiation.
///
/// Returned by the instantiation engine, it records the subtree's root. On
/// destruction the handle fires a fire-and-forget async delete of exactly the nodes it
/// created (reverse creation order, one single-node @ref AddressSpace::delete_node_async
/// each - not a reference-walked cascade) - never a blocking/synchronous call - giving
/// instantiated subtrees RAII lifetime tied to
/// this object. Call release() to keep the nodes alive past the handle's lifetime,
/// or remove_async() to delete them eagerly.
///
/// The handle is move-only: moving transfers ownership and leaves the source
/// released, so only one handle ever owns a given subtree. It does not keep the address space
/// alive: once the address space is released its nodes are gone with it, and cleanup does nothing.
/// @ingroup address_space
class NodeSubtree
{
public:
  /// Constructs an empty handle that owns no nodes.
  NodeSubtree() = default;

  /// Constructs a handle owning a freshly instantiated subtree.
  ///
  /// @param addressSpace Address space the nodes live in and are deleted from on
  ///                     cleanup; the handle keeps a weak handle to it.
  /// @param rootId       Node id of the subtree's root.
  /// @param createdNodes Ids of every node created for the subtree, in creation
  ///                     order; cleanup deletes them in reverse.
  NodeSubtree(AddressSpace addressSpace, NodeId rootId, std::vector<NodeId> createdNodes);

  NodeSubtree(const NodeSubtree&) = delete;
  NodeSubtree& operator=(const NodeSubtree&) = delete;

  /// Move-constructs, transferring ownership and leaving @p other released.
  ///
  /// @param other Handle whose owned subtree is transferred; left released.
  NodeSubtree(NodeSubtree&& other) noexcept;

  /// Move-assigns, removing this handle's current subtree before taking @p other's.
  ///
  /// Any nodes currently owned by this handle are deleted (as if by remove_async())
  /// before ownership of @p other's subtree is adopted; @p other is left released.
  ///
  /// @param other Handle whose owned subtree is adopted; left released.
  /// @return Reference to this handle.
  NodeSubtree& operator=(NodeSubtree&& other) noexcept;

  /// Deletes the owned nodes unless the handle was released or already removed.
  ~NodeSubtree();

  /// Returns the node id of the subtree's root.
  ///
  /// @return The NodeId identifying the subtree's root node.
  const NodeId& root() const;

  /// Abandons ownership so the nodes are not deleted on destruction.
  ///
  /// After this call the subtree outlives the handle; destruction and remove_async()
  /// become no-ops. Idempotent.
  ///
  /// @post root() still returns the root id, but the handle no longer deletes any nodes.
  void release();

  /// Asynchronously deletes the owned subtree and releases the handle.
  ///
  /// Fire-and-forget deletes exactly the nodes this handle recorded as created, in
  /// reverse creation order, each via a single-node @ref AddressSpace::delete_node_async
  /// (deleteForwardHierarchicallyReferencedNodes=false). This is deliberately NOT a
  /// forward-hierarchical cascade from the root: the handle knows precisely which nodes
  /// it created, so the work stays bounded and never over-deletes the surrounding address
  /// space the subtree is embedded in. Then marks the handle released so destruction will
  /// not delete it again. Makes no synchronous call and never blocks, so it is safe to
  /// call from a destructor on any thread. Idempotent.
  void remove_async();

  /// Records a node as part of the owned subtree so cleanup will delete it.
  ///
  /// Internal hook used while building the subtree; the node is appended to the
  /// creation-order list. Not intended for general use.
  ///
  /// @param id Node id to track for cleanup.
  void add_created_node(NodeId id);

private:
  optional<WeakAddressSpace> mAddressSpace;
  NodeId mRootId;
  std::vector<NodeId> mCreatedNodes;
  bool mReleased{false};
};

/// The outcome of an instantiation: a NodeSubtree, or an @ref ErrorDetail on failure.
using NodeSubtreeResult = Result<NodeSubtree>;

}  // namespace ua

#endif  // UA_NODE_SUBTREE_H
