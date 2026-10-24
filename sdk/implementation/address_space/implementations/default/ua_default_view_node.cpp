// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_default_view_node.h"
#include "ua_callback_safety.h"
#include "ua_error_detail.h"
#include "ua_to_result.h"

namespace ua::default_ns
{
ViewNode::ViewNode(const NodeId& nodeId) : BaseNode(nodeId, NodeClass::View)
{}

shared_ptr<ViewNode> ViewNode::create(const NodeId& nodeId)
{
  struct Wrapper : public ViewNode
  {
  public:
    explicit Wrapper(const NodeId& nodeId) : ViewNode(nodeId)
    {}
  };

  return make_shared<Wrapper>(nodeId);
}

void ViewNode::is_node_in_view_async(NodeId nodeId, IsNodeInViewCallback callback) const noexcept
{
  BoolResult result = [&]() -> BoolResult
  {
    try
    {
      const ReadLock lock(mMutex);
      return mNodesInView.find(nodeId) != mNodesInView.end();
    }
    catch (...)
    {
      return ua::exception_to_status_code(std::current_exception());
    }
  }();

  detail::invoke_user_callback(std::move(callback), std::move(result));
}

bool ViewNode::remove_member(const NodeId& nodeId)
{
  const WriteLock lock(mMutex);
  return mNodesInView.erase(nodeId) > 0;
}

void ViewNode::add_node_to_view_async(NodeId nodeId, ViewModifyCallback callback) noexcept
{
  // The member only: the namespace that holds the View advances its ViewVersion (NR-55), when the add is made
  // through it.
  VoidResult result{};
  try
  {
    (void)add_member(nodeId);
  }
  catch (...)
  {
    result = VoidResult{ua::exception_to_status_code(std::current_exception())};
  }
  detail::invoke_user_callback(std::move(callback), std::move(result));
}

bool ViewNode::add_member(const NodeId& nodeId)
{
  const WriteLock lock(mMutex);
  return mNodesInView.insert(nodeId).second;
}

bool ViewNode::is_attribute_id_valid(AttributeId attributeId) const
{
  switch (attributeId)
  {
  case AttributeId::ContainsNoLoops:
  case AttributeId::EventNotifier:
    return true;

  default:
    return BaseNode::is_attribute_id_valid(attributeId);
  }
}

NodeClass ViewNode::get_node_class() const
{
  return NodeClass::View;
}

}  // namespace ua::default_ns
