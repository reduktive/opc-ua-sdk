// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_default_variable_type_node.h"

namespace ua::default_ns
{
VariableTypeNode::VariableTypeNode(const NodeId& nodeId) : BaseNode(nodeId, NodeClass::VariableType)
{}

shared_ptr<VariableTypeNode> VariableTypeNode::create(const NodeId& nodeId)
{
  struct Wrapper : public VariableTypeNode
  {
  public:
    explicit Wrapper(const NodeId& nodeId) : VariableTypeNode(nodeId)
    {}
  };

  return make_shared<Wrapper>(nodeId);
}

bool VariableTypeNode::is_attribute_id_valid(AttributeId attributeId) const
{
  switch (attributeId)
  {
  case AttributeId::Value:
  case AttributeId::DataType:
  case AttributeId::ValueRank:
  case AttributeId::ArrayDimensions:
  case AttributeId::IsAbstract:
    return true;

  default:
    return BaseNode::is_attribute_id_valid(attributeId);
  }
}

NodeClass VariableTypeNode::get_node_class() const
{
  return NodeClass::VariableType;
}

}  // namespace ua::default_ns
