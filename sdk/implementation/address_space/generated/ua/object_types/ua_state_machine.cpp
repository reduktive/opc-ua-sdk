// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_state_machine.h"

#include "ua_instance_utils.h"
#include "ua_sync_wait.h"
#include "ua_to_result.h"
#include "ua_weak_address_space.h"

#include <boost/asio/any_io_executor.hpp>

#include <functional>
#include <tuple>

#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"

namespace ua
{
namespace
{

struct StateMachineTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::StateMachineType};
  }

  static QualifiedName current_state_browse_name()
  {
    return QualifiedName{0, "CurrentState"};
  }

  static QualifiedName last_transition_browse_name()
  {
    return QualifiedName{0, "LastTransition"};
  }
};

}  // namespace

StateMachine::StateMachine(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void StateMachine::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    StateMachineTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(StateMachineResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(StateMachineResult{
        StateMachine{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)}, code});
    });
}

StateMachineResult StateMachine::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StateMachineResult>(addressSpace.executor(),
      [&](std::function<void(StateMachineResult)> complete)
      {
        StateMachine::create_async(std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

StateMachine StateMachine::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void StateMachine::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void StateMachine::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // StateMachineType has subtypes - subtype match.
  instance_utils::attach_subtype_async(addressSpace,
    existingInstance,
    StateMachineTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(StateMachineResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(StateMachineResult{::ua::detail::address_space_gone("StateMachine")});
        return;
      }
      complete(StateMachine{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

StateMachineResult StateMachine::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StateMachineResult>(addressSpace.executor(),
      [&](std::function<void(StateMachineResult)> complete)
      {
        StateMachine::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

StateMachine StateMachine::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void StateMachine::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Child-object accessors ---

void StateMachine::current_state_async(std::function<void(StateVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StateVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<StateVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    StateMachineTypeTraits::current_state_browse_name(),
    "StateMachine",
    std::move(complete));
}

StateVariableResult StateMachine::try_current_state_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StateVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StateVariableResult)> complete) { current_state_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

StateVariable StateMachine::current_state_sync() const
{
  return ::ua::detail::good_value(try_current_state_sync());
}

void StateMachine::last_transition_async(
  std::function<void(TransitionVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TransitionVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<TransitionVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    StateMachineTypeTraits::last_transition_browse_name(),
    "StateMachine",
    std::move(complete));
}

TransitionVariableResult StateMachine::try_last_transition_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionVariableResult)> complete)
      { last_transition_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TransitionVariable StateMachine::last_transition_sync() const
{
  return ::ua::detail::good_value(try_last_transition_sync());
}

}  // namespace ua
