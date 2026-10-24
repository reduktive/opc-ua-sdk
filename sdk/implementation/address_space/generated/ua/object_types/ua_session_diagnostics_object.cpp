// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_session_diagnostics_object.h"

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

struct SessionDiagnosticsObjectTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::SessionDiagnosticsObjectType};
  }

  static QualifiedName current_role_ids_browse_name()
  {
    return QualifiedName{0, "CurrentRoleIds"};
  }
};

}  // namespace

SessionDiagnosticsObject::SessionDiagnosticsObject(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void SessionDiagnosticsObject::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    SessionDiagnosticsObjectTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(SessionDiagnosticsObjectResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(SessionDiagnosticsObjectResult{
        SessionDiagnosticsObject{
          std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

SessionDiagnosticsObjectResult SessionDiagnosticsObject::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<SessionDiagnosticsObjectResult>(addressSpace.executor(),
      [&](std::function<void(SessionDiagnosticsObjectResult)> complete)
      {
        SessionDiagnosticsObject::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

SessionDiagnosticsObject SessionDiagnosticsObject::create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void SessionDiagnosticsObject::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void SessionDiagnosticsObject::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // SessionDiagnosticsObjectType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    SessionDiagnosticsObjectTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(SessionDiagnosticsObjectResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(
          SessionDiagnosticsObjectResult{::ua::detail::address_space_gone("SessionDiagnosticsObject")});
        return;
      }
      complete(
        SessionDiagnosticsObject{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

SessionDiagnosticsObjectResult SessionDiagnosticsObject::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<SessionDiagnosticsObjectResult>(addressSpace.executor(),
      [&](std::function<void(SessionDiagnosticsObjectResult)> complete)
      {
        SessionDiagnosticsObject::attach_async(
          std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

SessionDiagnosticsObject SessionDiagnosticsObject::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void SessionDiagnosticsObject::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void SessionDiagnosticsObject::find_property_async(
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
    "SessionDiagnosticsObject",
    std::move(complete));
}

// --- Property accessors ---

void SessionDiagnosticsObject::current_role_ids_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    SessionDiagnosticsObjectTypeTraits::current_role_ids_browse_name(), std::move(complete));
}

PropertyResult SessionDiagnosticsObject::try_current_role_ids_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { current_role_ids_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property SessionDiagnosticsObject::current_role_ids_property_sync() const
{
  return ::ua::detail::good_value(try_current_role_ids_property_sync());
}

// --- Typed value read shortcuts ---

void SessionDiagnosticsObject::read_current_role_ids_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    SessionDiagnosticsObjectTypeTraits::current_role_ids_browse_name(),
    &Variant::is_node_id,
    {"SessionDiagnosticsObject", "current_role_ids", "SessionDiagnosticsObject::read_current_role_ids_async"},
    std::move(complete));
}

NodeIdResult SessionDiagnosticsObject::try_read_current_role_ids_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeIdResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(NodeIdResult)> complete) { read_current_role_ids_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NodeId SessionDiagnosticsObject::read_current_role_ids_sync() const
{
  return ::ua::detail::good_value(try_read_current_role_ids_sync());
}

// --- Typed value write shortcuts ---

void SessionDiagnosticsObject::write_current_role_ids_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    SessionDiagnosticsObjectTypeTraits::current_role_ids_browse_name(),
    "SessionDiagnosticsObject",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult SessionDiagnosticsObject::try_write_current_role_ids_sync(NodeId value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_current_role_ids_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void SessionDiagnosticsObject::write_current_role_ids_sync(NodeId value) const
{
  try_write_current_role_ids_sync(value).value();
}

}  // namespace ua
