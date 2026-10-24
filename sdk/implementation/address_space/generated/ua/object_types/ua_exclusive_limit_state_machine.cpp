// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_exclusive_limit_state_machine.h"

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

struct ExclusiveLimitStateMachineTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::ExclusiveLimitStateMachineType};
  }

  static QualifiedName high_high_browse_name()
  {
    return QualifiedName{0, "HighHigh"};
  }

  static QualifiedName high_browse_name()
  {
    return QualifiedName{0, "High"};
  }

  static QualifiedName low_browse_name()
  {
    return QualifiedName{0, "Low"};
  }

  static QualifiedName low_low_browse_name()
  {
    return QualifiedName{0, "LowLow"};
  }

  static QualifiedName low_low_to_low_browse_name()
  {
    return QualifiedName{0, "LowLowToLow"};
  }

  static QualifiedName low_to_low_low_browse_name()
  {
    return QualifiedName{0, "LowToLowLow"};
  }

  static QualifiedName high_high_to_high_browse_name()
  {
    return QualifiedName{0, "HighHighToHigh"};
  }

  static QualifiedName high_to_high_high_browse_name()
  {
    return QualifiedName{0, "HighToHighHigh"};
  }
};

}  // namespace

ExclusiveLimitStateMachine::ExclusiveLimitStateMachine(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void ExclusiveLimitStateMachine::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    ExclusiveLimitStateMachineTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(ExclusiveLimitStateMachineResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(ExclusiveLimitStateMachineResult{
        ExclusiveLimitStateMachine{
          std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

ExclusiveLimitStateMachineResult ExclusiveLimitStateMachine::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ExclusiveLimitStateMachineResult>(addressSpace.executor(),
      [&](std::function<void(ExclusiveLimitStateMachineResult)> complete)
      {
        ExclusiveLimitStateMachine::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ExclusiveLimitStateMachine ExclusiveLimitStateMachine::create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void ExclusiveLimitStateMachine::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void ExclusiveLimitStateMachine::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // ExclusiveLimitStateMachineType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    ExclusiveLimitStateMachineTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(ExclusiveLimitStateMachineResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(
          ExclusiveLimitStateMachineResult{::ua::detail::address_space_gone("ExclusiveLimitStateMachine")});
        return;
      }
      complete(ExclusiveLimitStateMachine{
        std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

ExclusiveLimitStateMachineResult ExclusiveLimitStateMachine::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ExclusiveLimitStateMachineResult>(addressSpace.executor(),
      [&](std::function<void(ExclusiveLimitStateMachineResult)> complete)
      {
        ExclusiveLimitStateMachine::attach_async(
          std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ExclusiveLimitStateMachine ExclusiveLimitStateMachine::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void ExclusiveLimitStateMachine::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Child-object accessors ---

void ExclusiveLimitStateMachine::high_high_async(std::function<void(StateResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StateResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<State>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ExclusiveLimitStateMachineTypeTraits::high_high_browse_name(),
    "ExclusiveLimitStateMachine",
    std::move(complete));
}

StateResult ExclusiveLimitStateMachine::try_high_high_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StateResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StateResult)> complete) { high_high_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

State ExclusiveLimitStateMachine::high_high_sync() const
{
  return ::ua::detail::good_value(try_high_high_sync());
}

void ExclusiveLimitStateMachine::high_async(std::function<void(StateResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StateResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<State>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ExclusiveLimitStateMachineTypeTraits::high_browse_name(),
    "ExclusiveLimitStateMachine",
    std::move(complete));
}

StateResult ExclusiveLimitStateMachine::try_high_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StateResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StateResult)> complete) { high_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

State ExclusiveLimitStateMachine::high_sync() const
{
  return ::ua::detail::good_value(try_high_sync());
}

void ExclusiveLimitStateMachine::low_async(std::function<void(StateResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StateResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<State>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ExclusiveLimitStateMachineTypeTraits::low_browse_name(),
    "ExclusiveLimitStateMachine",
    std::move(complete));
}

StateResult ExclusiveLimitStateMachine::try_low_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StateResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StateResult)> complete) { low_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

State ExclusiveLimitStateMachine::low_sync() const
{
  return ::ua::detail::good_value(try_low_sync());
}

void ExclusiveLimitStateMachine::low_low_async(std::function<void(StateResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StateResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<State>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ExclusiveLimitStateMachineTypeTraits::low_low_browse_name(),
    "ExclusiveLimitStateMachine",
    std::move(complete));
}

StateResult ExclusiveLimitStateMachine::try_low_low_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StateResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StateResult)> complete) { low_low_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

State ExclusiveLimitStateMachine::low_low_sync() const
{
  return ::ua::detail::good_value(try_low_low_sync());
}

void ExclusiveLimitStateMachine::low_low_to_low_async(
  std::function<void(TransitionResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TransitionResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<Transition>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ExclusiveLimitStateMachineTypeTraits::low_low_to_low_browse_name(),
    "ExclusiveLimitStateMachine",
    std::move(complete));
}

TransitionResult ExclusiveLimitStateMachine::try_low_low_to_low_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete) { low_low_to_low_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition ExclusiveLimitStateMachine::low_low_to_low_sync() const
{
  return ::ua::detail::good_value(try_low_low_to_low_sync());
}

void ExclusiveLimitStateMachine::low_to_low_low_async(
  std::function<void(TransitionResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TransitionResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<Transition>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ExclusiveLimitStateMachineTypeTraits::low_to_low_low_browse_name(),
    "ExclusiveLimitStateMachine",
    std::move(complete));
}

TransitionResult ExclusiveLimitStateMachine::try_low_to_low_low_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete) { low_to_low_low_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition ExclusiveLimitStateMachine::low_to_low_low_sync() const
{
  return ::ua::detail::good_value(try_low_to_low_low_sync());
}

void ExclusiveLimitStateMachine::high_high_to_high_async(
  std::function<void(TransitionResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TransitionResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<Transition>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ExclusiveLimitStateMachineTypeTraits::high_high_to_high_browse_name(),
    "ExclusiveLimitStateMachine",
    std::move(complete));
}

TransitionResult ExclusiveLimitStateMachine::try_high_high_to_high_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete) { high_high_to_high_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition ExclusiveLimitStateMachine::high_high_to_high_sync() const
{
  return ::ua::detail::good_value(try_high_high_to_high_sync());
}

void ExclusiveLimitStateMachine::high_to_high_high_async(
  std::function<void(TransitionResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TransitionResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<Transition>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ExclusiveLimitStateMachineTypeTraits::high_to_high_high_browse_name(),
    "ExclusiveLimitStateMachine",
    std::move(complete));
}

TransitionResult ExclusiveLimitStateMachine::try_high_to_high_high_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TransitionResult)> complete) { high_to_high_high_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Transition ExclusiveLimitStateMachine::high_to_high_high_sync() const
{
  return ::ua::detail::good_value(try_high_to_high_high_sync());
}

}  // namespace ua
