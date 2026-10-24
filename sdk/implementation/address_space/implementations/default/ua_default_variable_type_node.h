// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_VARIABLE_TYPE_NODE_H
#define UA_VARIABLE_TYPE_NODE_H

#include "ua_default_base_node.h"

namespace ua::default_ns
{

class VariableTypeNode : public BaseNode
{
public:
  VariableTypeNode() = delete;
  VariableTypeNode(const VariableTypeNode&) = delete;
  VariableTypeNode(VariableTypeNode&&) noexcept = delete;
  VariableTypeNode& operator=(const VariableTypeNode&) = delete;
  VariableTypeNode& operator=(VariableTypeNode&&) noexcept = delete;
  ~VariableTypeNode() override = default;

  NodeClass get_node_class() const override;

  static shared_ptr<VariableTypeNode> create(const NodeId& nodeId);

private:
  explicit VariableTypeNode(const NodeId& nodeId);

  bool is_attribute_id_valid(AttributeId attributeId) const override;
};

}  // namespace ua::default_ns

#endif  // UA_VARIABLE_TYPE_NODE_H
