// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_VIEW_NODE_DEFAULT_H
#define UA_VIEW_NODE_DEFAULT_H

#include <unordered_set>
#include "ua_default_base_node.h"
#include "ua_event_notifier_type.h"

namespace ua::default_ns
{

class ViewNode : public BaseNode
{
public:
  ViewNode() = delete;
  ViewNode(const ViewNode&) = delete;
  ViewNode(ViewNode&&) noexcept = delete;
  ViewNode& operator=(const ViewNode&) = delete;
  ViewNode& operator=(ViewNode&&) noexcept = delete;
  ~ViewNode() override = default;

  NodeClass get_node_class() const override;

  static shared_ptr<ViewNode> create(const NodeId& nodeId);

  void is_node_in_view_async(NodeId nodeId, IsNodeInViewCallback callback) const noexcept override;
  void add_node_to_view_async(NodeId nodeId, ViewModifyCallback callback) noexcept override;

  /// Adds @p nodeId to this View's members.
  ///
  /// @return `true` when @p nodeId was not a member.
  bool add_member(const NodeId& nodeId);

  /// Removes @p nodeId from this View's members.
  ///
  /// @param nodeId The member to remove; typically a Node that was deleted.
  /// @return `true` when @p nodeId was a member.
  bool remove_member(const NodeId& nodeId);

private:
  std::unordered_set<NodeId> mNodesInView;

  explicit ViewNode(const NodeId& nodeId);

  bool is_attribute_id_valid(AttributeId attributeId) const override;
};

}  // namespace ua::default_ns

#endif  // UA_VIEW_NODE_DEFAULT_H
