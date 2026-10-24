// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_default_method_node.h"

#include "ua_call_method_result.h"
#include "ua_callback_safety.h"
#include "ua_to_result.h"

namespace ua::default_ns
{
MethodNode::MethodNode(const NodeId& nodeId) : BaseNode(nodeId, NodeClass::Method), mHandler{}
{}

shared_ptr<MethodNode> MethodNode::create(const NodeId& nodeId)
{
  struct Wrapper : public MethodNode
  {
  public:
    explicit Wrapper(const NodeId& nodeId) : MethodNode(nodeId)
    {}
  };

  return make_shared<Wrapper>(nodeId);
}

bool MethodNode::is_attribute_id_valid(AttributeId attributeId) const
{
  switch (attributeId)
  {
  case AttributeId::Executable:
    return true;

  default:
    return BaseNode::is_attribute_id_valid(attributeId);
  }
}

void MethodNode::call(const CallMethodRequest& methodToCall, shared_ptr<const MethodCallContext> context,
  CallMethodCompleteCallback callback) const
{
  Handler handler;
  {
    const ReadLock lock(mMutex);
    handler = mHandler;
  }

  if (handler)
  {
    // Race-resolution: user handler may invoke the callback OR throw; if it
    // throws after invoking, the catch must not double-fire. make_fire_once
    // wraps the callback in a CAS guard shared by both paths.
    auto guarded = detail::make_fire_once<CallResult>(std::move(callback));
    try
    {
      handler(methodToCall, context, guarded);
    }
    catch (...)
    {
      guarded(ua::exception_to_status_code(std::current_exception()));
    }
  }
  else
  {
    CallMethodResult result;
    result.status_code() = Status::BadNotSupported;
    callback(CallResult{std::move(result)});
  }
}

void MethodNode::set_handler(MethodNode::Handler handler)
{
  const WriteLock lock(mMutex);
  mHandler = std::move(handler);
}

StatusCode MethodNode::set_call_handler(CallHandler handler)
{
  set_handler(std::move(handler));
  return StatusCode{Status::Good};
}

NodeClass MethodNode::get_node_class() const
{
  return NodeClass::Method;
}

}  // namespace ua::default_ns
