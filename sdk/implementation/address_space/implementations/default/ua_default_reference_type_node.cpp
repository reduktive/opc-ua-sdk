// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_default_reference_type_node.h"

namespace ua::default_ns
{
ReferenceTypeNode::ReferenceTypeNode(const NodeId& nodeId) : BaseNode(nodeId, NodeClass::ReferenceType)
{}

shared_ptr<ReferenceTypeNode> ReferenceTypeNode::create(const NodeId& nodeId)
{
  struct Wrapper : public ReferenceTypeNode
  {
  public:
    explicit Wrapper(const NodeId& nodeId) : ReferenceTypeNode(nodeId)
    {}
  };

  return make_shared<Wrapper>(nodeId);
}

bool ReferenceTypeNode::is_attribute_id_valid(AttributeId attributeId) const
{
  switch (attributeId)
  {
  case AttributeId::IsAbstract:
  case AttributeId::Symmetric:
  case AttributeId::InverseName:
    return true;

  default:
    return BaseNode::is_attribute_id_valid(attributeId);
  }
}

NodeClass ReferenceTypeNode::get_node_class() const
{
  return NodeClass::ReferenceType;
}

}  // namespace ua::default_ns
