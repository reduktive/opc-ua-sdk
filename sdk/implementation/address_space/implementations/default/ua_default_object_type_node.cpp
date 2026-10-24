// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_default_object_type_node.h"

namespace ua::default_ns
{
ObjectTypeNode::ObjectTypeNode(const NodeId& nodeId) : BaseNode(nodeId, NodeClass::ObjectType)
{}

shared_ptr<ObjectTypeNode> ObjectTypeNode::create(const NodeId& nodeId)
{
  struct Wrapper : public ObjectTypeNode
  {
  public:
    explicit Wrapper(const NodeId& nodeId) : ObjectTypeNode(nodeId)
    {}
  };

  return make_shared<Wrapper>(nodeId);
}

bool ObjectTypeNode::is_attribute_id_valid(AttributeId attributeId) const
{
  switch (attributeId)
  {
  case AttributeId::IsAbstract:
    return true;

  default:
    return BaseNode::is_attribute_id_valid(attributeId);
  }
}

NodeClass ObjectTypeNode::get_node_class() const
{
  return NodeClass::ObjectType;
}

}  // namespace ua::default_ns
