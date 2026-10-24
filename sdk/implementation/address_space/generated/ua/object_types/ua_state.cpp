// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_state.h"

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

struct StateTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::StateType};
  }

  static QualifiedName state_number_browse_name()
  {
    return QualifiedName{0, "StateNumber"};
  }
};

}  // namespace

State::State(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void State::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    StateTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(StateResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(StateResult{
        State{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)}, code});
    });
}

StateResult State::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StateResult>(addressSpace.executor(),
      [&](std::function<void(StateResult)> complete)
      {
        State::create_async(std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

State State::create_sync(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
  const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void State::create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
  const InstantiationOptions& options, CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void State::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // StateType has subtypes - subtype match.
  instance_utils::attach_subtype_async(addressSpace,
    existingInstance,
    StateTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(StateResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(StateResult{::ua::detail::address_space_gone("State")});
        return;
      }
      complete(State{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

StateResult State::try_attach_sync(AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StateResult>(addressSpace.executor(),
      [&](std::function<void(StateResult)> complete)
      {
        State::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

State State::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void State::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void State::find_property_async(
  QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<Property>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasProperty},
    std::move(browseName),
    "State",
    std::move(complete));
}

// --- Property accessors ---

void State::state_number_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(StateTypeTraits::state_number_browse_name(), std::move(complete));
}

PropertyResult State::try_state_number_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { state_number_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property State::state_number_property_sync() const
{
  return ::ua::detail::good_value(try_state_number_property_sync());
}

// --- Typed value read shortcuts ---

void State::read_state_number_async(std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    StateTypeTraits::state_number_browse_name(),
    &Variant::is_uint32,
    {"State", "state_number", "State::read_state_number_async"},
    std::move(complete));
}

UInt32Result State::try_read_state_number_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete) { read_state_number_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t State::read_state_number_sync() const
{
  return ::ua::detail::good_value(try_read_state_number_sync());
}

// --- Typed value write shortcuts ---

void State::write_state_number_async(uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    StateTypeTraits::state_number_browse_name(),
    "State",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult State::try_write_state_number_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_state_number_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void State::write_state_number_sync(uint32_t value) const
{
  try_write_state_number_sync(value).value();
}

}  // namespace ua
