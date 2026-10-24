// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_METHOD_NODE_H
#define UA_METHOD_NODE_H

#include "ua_default_base_node.h"

namespace ua::default_ns
{

class MethodNode : public BaseNode, public MethodCallSource
{
public:
  using Handler = std::function<void(const CallMethodRequest& methodToCall,
    shared_ptr<const MethodCallContext> context, CallMethodCompleteCallback callback)>;

  MethodNode() = delete;
  MethodNode(const MethodNode&) = delete;
  MethodNode(MethodNode&&) noexcept = delete;
  MethodNode& operator=(const MethodNode&) = delete;
  MethodNode& operator=(MethodNode&&) noexcept = delete;
  ~MethodNode() override = default;

  NodeClass get_node_class() const override;

  void call(const CallMethodRequest& methodToCall, shared_ptr<const MethodCallContext> context,
    CallMethodCompleteCallback callback) const override;

  MethodCallSource* method_call_source() noexcept override
  {
    return this;
  }

  void set_handler(Handler handler);
  StatusCode set_call_handler(CallHandler handler) override;

  static shared_ptr<MethodNode> create(const NodeId& nodeId);

private:
  Handler mHandler;

  explicit MethodNode(const NodeId& nodeId);

  bool is_attribute_id_valid(AttributeId attributeId) const override;
};

}  // namespace ua::default_ns

#endif  // UA_METHOD_NODE_H
