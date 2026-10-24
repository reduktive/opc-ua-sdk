// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_EXTERNAL_GUARD_LINKER_H
#define UA_EXTERNAL_GUARD_LINKER_H

#include "ua_address_space.h"
#include "instantiation/ua_instantiation_options.h"
#include "ua_node_class.h"
#include "ua_node_utilities.h"
#include "ua_qualified_name.h"
#include "ua_namespace_items.h"
#include "ua_node_accessor.h"
#include "ua_resource_budgets.h"
#include "ua_result.h"

#include <functional>
#include <memory>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace ua::instantiation_detail
{

struct InstantiatedTypeBinding
{
  NodeId typeDefinitionId;
  NodeId instanceId;

  bool operator==(const InstantiatedTypeBinding&) const = default;
};

struct InstantiatedNodeBinding
{
  NodeId declarationId;
  NodeId instanceId;
  NodeId parentInstanceId;
  NodeId parentReferenceType;
  QualifiedName browseName;
  NodeClass nodeClass{NodeClass::Object};
  std::optional<NodeId> typeDefinitionId;
};

/// One Node an instantiation creates (NR-31): planned by the walk, created with the others in one batch after
/// it.
struct PlannedNode
{
  NodeCreation creation;
  /// The InstanceDeclaration whose Value the created Variable is given; none for the root and other
  /// NodeClasses.
  std::optional<NodeAccessor> declaration;
};

/// One Reference half an instantiation adds once its Nodes exist, and whether a refusal fails the
/// instantiation; a half whose refusal does not is best-effort, as the per-member flow had it.
struct PlannedHalf
{
  ReferenceChange change;
  bool required{false};
};

/// Exact declaration-to-instance identities collected by one subtree instantiation.
///
/// InstantiateChildrenOperation is strictly sequential, including its recursive sub-operations, so
/// this context is mutated by only one body at a time. The shared ownership lets every nested one
/// contribute to the single post-instantiation topology pass without adding public API surface.
class InstantiationContext
{
public:
  void record_type(NodeId typeDefinitionId, NodeId instanceId);
  void record_node(InstantiatedNodeBinding binding);

  const std::vector<InstantiatedTypeBinding>& types() const noexcept;
  const std::vector<InstantiatedNodeBinding>& nodes() const noexcept;

  /// Whether this instantiation created @p node as a member.
  bool created(const NodeId& node) const noexcept;

  /// The caller's resolver for members declared with an abstract type (InstantiationOptions).
  MemberTypeResolver memberTypeResolver;

  /// The ReferenceType answers of this instantiation, shared by every nested walk: which types are
  /// hierarchical is asked once per ReferenceType, not once per Reference.
  const std::shared_ptr<node_utils::RefTypeCache>& reference_type_cache() const noexcept;

  /// Plans @p node's creation; its NodeId is then planned (@ref planned).
  void plan_node(PlannedNode node);
  /// Plans a Reference half, added once every planned Node exists.
  void plan_half(PlannedHalf half);
  /// Plans the hierarchical Reference of @p referenceType from @p parent to @p child, named @p browseName:
  /// the forward half on @p parent, best-effort, and the inverse half on @p child, required.
  void plan_link(
    const NodeId& parent, const NodeId& referenceType, const NodeId& child, const QualifiedName& browseName);
  /// Whether this instantiation plans to create @p node.
  bool planned(const NodeId& node) const noexcept;
  /// The member planned under @p parent with @p browseName; nothing when none is.
  std::optional<NodeId> planned_child(const NodeId& parent, const QualifiedName& browseName) const;
  /// The ReferenceTypes of the links planned from @p parent to @p child.
  std::vector<NodeId> planned_link_types(const NodeId& parent, const NodeId& child) const;
  const std::vector<PlannedNode>& planned_nodes() const noexcept;
  const std::vector<PlannedHalf>& planned_halves() const noexcept;

private:
  std::vector<InstantiatedTypeBinding> mTypes;
  std::vector<InstantiatedNodeBinding> mNodes;
  std::shared_ptr<node_utils::RefTypeCache> mReferenceTypeCache{std::make_shared<node_utils::RefTypeCache>()};
  std::vector<PlannedNode> mPlannedNodes;
  std::vector<PlannedHalf> mPlannedHalves;
  std::unordered_set<NodeId> mPlannedIds;
  // The members planned under each parent, with their BrowseNames, for the walk's existing-member check.
  std::unordered_map<NodeId, std::vector<std::pair<QualifiedName, NodeId>>> mPlannedChildren;
};

/// Materialises the Part 16 section 4.6.5 links required by external ExpressionGuard operands.
///
/// Only operands whose TypeDefinitionId resolves inside the just-instantiated owner subtree are
/// considered. Variables already owned by the machine are left alone. External Variables receive
/// a bidirectional link from the StateMachine instance using the same hierarchical ReferenceType
/// that attached the Variable to its original instantiated parent. An Uncertain answer to a lookup,
/// References read or Value read the linking makes is not acted on: the completion is answered
/// `Bad_InternalError` (`LookupAnswerUncertain`, `ReferencesAnswerUncertain` or `ReadAnswerUncertain`), whose
/// cause is the Uncertain code.
void wire_external_guard_variables_async(AddressSpace addressSpace, DepthBudget budget,
  std::shared_ptr<const InstantiationContext> context, std::function<void(VoidResult)> completion) noexcept;

}  // namespace ua::instantiation_detail

#endif  // UA_EXTERNAL_GUARD_LINKER_H
