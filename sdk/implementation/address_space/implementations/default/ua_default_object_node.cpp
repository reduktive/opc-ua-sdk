// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_default_object_node.h"

namespace ua::default_ns
{
ObjectNode::ObjectNode(const NodeId& nodeId) : BaseNode(nodeId, NodeClass::Object)
{}

shared_ptr<ObjectNode> ObjectNode::create(const NodeId& nodeId)
{
  struct Wrapper : public ObjectNode
  {
  public:
    explicit Wrapper(const NodeId& nodeId) : ObjectNode(nodeId)
    {}
  };

  return make_shared<Wrapper>(nodeId);
}

bool ObjectNode::is_attribute_id_valid(AttributeId attributeId) const
{
  switch (attributeId)
  {
  case AttributeId::EventNotifier:
    return true;

  default:
    return BaseNode::is_attribute_id_valid(attributeId);
  }
}

NodeClass ObjectNode::get_node_class() const
{
  return NodeClass::Object;
}

}  // namespace ua::default_ns
