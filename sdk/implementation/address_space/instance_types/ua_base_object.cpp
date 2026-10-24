// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_base_object.h"

#include "ua_instance_utils.h"
#include "ua_instantiation_service.h"
#include "ua_namespace_route.h"
#include "ua_objecttype_id.h"
#include "ua_to_result.h"

namespace ua
{

BaseObject::BaseObject(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : mAddressSpace(std::move(addressSpace)), mNodeId(std::move(nodeId)), mOwned(std::move(owned))
{}

const NodeId& BaseObject::node_id() const
{
  return mNodeId;
}

void BaseObject::release()
{
  if (mOwned)
  {
    mOwned->release();
    mOwned.reset();
  }
}

void BaseObject::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  auto existingCopy = NodeId{existingInstance};
  instance_utils::attach_subtype_async(addressSpace,
    existingCopy,
    NodeId{ObjectTypeId::BaseObjectType},
    [weakAddressSpace = addressSpace.weak(), existingCopy, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (st.is_bad())
      {
        complete(BaseObjectResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(BaseObjectResult{detail::address_space_gone("BaseObject")});
        return;
      }
      complete(
        BaseObjectResult{BaseObject{std::move(*lockedAddressSpace), std::move(existingCopy), std::nullopt}});
    });
}

void BaseObject::create_object_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  NodeId typeDefinition, InstantiationOptions options, CreateImplCompleteCallback complete) noexcept
{
  // This *_async facade is documented as never-throwing. Setting up the call below
  // (constructing the completion lambda / its std::function target) may allocate and
  // throw std::bad_alloc; convert any such throw into a bad Result delivered to the
  // callback so nothing escapes the noexcept boundary. The callback is captured by
  // copy so a live handle remains for the error path if the setup throws.
  try
  {
    InstantiationService inst{addressSpace};
    inst.instantiate_object_async(parent,
      browseName,
      typeDefinition,
      options,
      [weakAddressSpace = addressSpace.weak(), complete](NodeSubtreeResult result) mutable
      {
        if (!result.has_value())
        {
          complete(CreateResult{result.status_code(), result.shared_detail()});
          return;
        }
        auto lockedAddressSpace = weakAddressSpace.lock();
        if (!lockedAddressSpace)
        {
          complete(CreateResult{detail::address_space_gone("BaseObject")});
          return;
        }
        const StatusCode answered = result.status_code();
        auto subtree = std::move(result).value();
        auto rootId = subtree.root();
        complete(CreateResult{
          CreateResultData{std::move(*lockedAddressSpace), std::move(rootId), std::move(subtree)}, answered});
      });
  }
  catch (...)
  {
    if (complete)
    {
      complete(CreateResult{ua::exception_to_status_code(std::current_exception())});
    }
  }
}

}  // namespace ua
