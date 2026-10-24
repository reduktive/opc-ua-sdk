// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_OBJECT_NODE_DEFAULT_H
#define UA_OBJECT_NODE_DEFAULT_H

#include "ua_default_base_node.h"
#include "ua_event_notifier_type.h"

namespace ua::default_ns
{

class ObjectNode : public BaseNode
{
public:
  ObjectNode() = delete;
  ObjectNode(const ObjectNode&) = delete;
  ObjectNode(ObjectNode&&) noexcept = delete;
  ObjectNode& operator=(const ObjectNode&) = delete;
  ObjectNode& operator=(ObjectNode&&) noexcept = delete;
  ~ObjectNode() override = default;

  NodeClass get_node_class() const override;

  static shared_ptr<ObjectNode> create(const NodeId& nodeId);

private:
  explicit ObjectNode(const NodeId& nodeId);

  bool is_attribute_id_valid(AttributeId attributeId) const override;
};

}  // namespace ua::default_ns

#endif  // UA_OBJECT_NODE_DEFAULT_H
