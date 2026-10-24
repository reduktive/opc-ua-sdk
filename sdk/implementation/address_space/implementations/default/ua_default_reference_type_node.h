// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_REFERENCE_TYPE_NODE_H
#define UA_REFERENCE_TYPE_NODE_H

#include "ua_default_base_node.h"

namespace ua::default_ns
{

class ReferenceTypeNode : public BaseNode
{
public:
  ReferenceTypeNode() = delete;
  ReferenceTypeNode(const ReferenceTypeNode&) = delete;
  ReferenceTypeNode(ReferenceTypeNode&&) noexcept = delete;
  ReferenceTypeNode& operator=(const ReferenceTypeNode&) = delete;
  ReferenceTypeNode& operator=(ReferenceTypeNode&&) noexcept = delete;
  ~ReferenceTypeNode() override = default;

  NodeClass get_node_class() const override;

  static shared_ptr<ReferenceTypeNode> create(const NodeId& nodeId);

private:
  explicit ReferenceTypeNode(const NodeId& nodeId);

  bool is_attribute_id_valid(AttributeId attributeId) const override;
};

}  // namespace ua::default_ns

#endif  // UA_REFERENCE_TYPE_NODE_H
