// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_NODE_H
#define UA_DATA_TYPE_NODE_H

#include "ua_default_base_node.h"

namespace ua::default_ns
{

class DataTypeNode : public BaseNode
{
public:
  DataTypeNode() = delete;
  DataTypeNode(const DataTypeNode&) = delete;
  DataTypeNode(DataTypeNode&&) noexcept = delete;
  DataTypeNode& operator=(const DataTypeNode&) = delete;
  DataTypeNode& operator=(DataTypeNode&&) noexcept = delete;
  ~DataTypeNode() override = default;

  NodeClass get_node_class() const override;

  static shared_ptr<DataTypeNode> create(const NodeId& nodeId);

private:
  explicit DataTypeNode(const NodeId& nodeId);

  bool is_attribute_id_valid(AttributeId attributeId) const override;
};

}  // namespace ua::default_ns

#endif  // UA_DATA_TYPE_NODE_H
