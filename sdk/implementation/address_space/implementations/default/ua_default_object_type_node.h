// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_OBJECT_TYPE_NODE_H
#define UA_OBJECT_TYPE_NODE_H

#include "ua_default_base_node.h"

namespace ua::default_ns
{

class ObjectTypeNode : public BaseNode
{
public:
  ObjectTypeNode() = delete;
  ObjectTypeNode(const ObjectTypeNode&) = delete;
  ObjectTypeNode(ObjectTypeNode&&) noexcept = delete;
  ObjectTypeNode& operator=(const ObjectTypeNode&) = delete;
  ObjectTypeNode& operator=(ObjectTypeNode&&) noexcept = delete;
  ~ObjectTypeNode() override = default;

  NodeClass get_node_class() const override;

  static shared_ptr<ObjectTypeNode> create(const NodeId& nodeId);

private:
  explicit ObjectTypeNode(const NodeId& nodeId);

  bool is_attribute_id_valid(AttributeId attributeId) const override;
};

}  // namespace ua::default_ns

#endif  // UA_OBJECT_TYPE_NODE_H
