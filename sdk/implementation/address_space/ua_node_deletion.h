// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_NODE_DELETION_H
#define UA_NODE_DELETION_H

#include "ua_address_space.h"
#include "ua_node_id.h"
#include "ua_result.h"

#include <functional>

namespace ua
{
class AddressSpaceImpl;
}  // namespace ua

namespace ua::detail
{

struct NamespaceRegistrationRoute;

/// The address space's deletion of Nodes through the namespaces' batched members (NR-70 B7a; NR-17 rule 3,
/// NR-30 rule 5).
///
/// A delete is one `delete_nodes_async` call per namespace, split by `maxNodesPerNodeManagement`, each passed
/// the delete's `ReferenceHalves`. With `Both`, when a call answers, the halves that other namespaces hold of
/// its deleted Nodes' References are removed there with one `remove_references_async` per referrer namespace,
/// and the call's Nodes are answered once those removals have answered: a removal that leaves a Reference
/// behind is logged, and makes its Node's answer `Uncertain_ReferenceNotDeleted`. A subtree delete finds the
/// subtree one level at a time, each level with one batched lookup and one `read_references_async` per
/// namespace, and then deletes the levels deepest first.
///
/// Every step holds the address space weakly; a step that finds it gone answers `Bad_Shutdown`
/// (`AddressSpaceGone`) and the delete ends with that status. The completions given to the namespaces hold
/// neither the address space nor a namespace.
class NodeDeletion
{
public:
  /// Deletes @p nodeId, and with @p subtree its forward hierarchical subtree, then calls @p callback once
  /// with the worst of the Nodes' answers: Bad above Uncertain above Good. With @p halves
  /// `ThisHalfOnly`, no namespace removes another Node's half of a Reference to a deleted Node.
  static void run(const shared_ptr<AddressSpaceImpl>& addressSpace, WeakAddressSpace selfHandle,
    const NodeId& nodeId, bool subtree, ReferenceHalves halves,
    shared_ptr<const NamespaceRegistrationRoute> registrationRoute,
    std::function<void(VoidResult)> callback) noexcept;

  /// The namespace that holds @p namespaceIndex in @p addressSpace, through @p registrationRoute; null when
  /// none does. The steps of a delete resolve through it.
  static shared_ptr<Namespace> resolve_namespace(const AddressSpaceImpl& addressSpace,
    uint16_t namespaceIndex, const shared_ptr<const NamespaceRegistrationRoute>& registrationRoute) noexcept;
};

}  // namespace ua::detail

#endif  // UA_NODE_DELETION_H
