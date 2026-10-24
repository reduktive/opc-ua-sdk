// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_default_data_type_node.h"

namespace ua::default_ns
{
DataTypeNode::DataTypeNode(const NodeId& nodeId) : BaseNode(nodeId, NodeClass::DataType)
{}

shared_ptr<DataTypeNode> DataTypeNode::create(const NodeId& nodeId)
{
  struct Wrapper : public DataTypeNode
  {
  public:
    explicit Wrapper(const NodeId& nodeId) : DataTypeNode(nodeId)
    {}
  };

  return make_shared<Wrapper>(nodeId);
}

bool DataTypeNode::is_attribute_id_valid(AttributeId attributeId) const
{
  switch (attributeId)
  {
  case AttributeId::IsAbstract:
  case AttributeId::DataTypeDefinition:
    return true;

  default:
    return BaseNode::is_attribute_id_valid(attributeId);
  }
}

NodeClass DataTypeNode::get_node_class() const
{
  return NodeClass::DataType;
}

}  // namespace ua::default_ns
