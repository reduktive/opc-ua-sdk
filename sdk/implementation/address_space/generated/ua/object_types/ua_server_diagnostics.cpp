// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_server_diagnostics.h"

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

struct ServerDiagnosticsTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::ServerDiagnosticsType};
  }

  static QualifiedName enabled_flag_browse_name()
  {
    return QualifiedName{0, "EnabledFlag"};
  }
};

}  // namespace

ServerDiagnostics::ServerDiagnostics(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void ServerDiagnostics::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    ServerDiagnosticsTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(ServerDiagnosticsResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(ServerDiagnosticsResult{
        ServerDiagnostics{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

ServerDiagnosticsResult ServerDiagnostics::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ServerDiagnosticsResult>(addressSpace.executor(),
      [&](std::function<void(ServerDiagnosticsResult)> complete)
      {
        ServerDiagnostics::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ServerDiagnostics ServerDiagnostics::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void ServerDiagnostics::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void ServerDiagnostics::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // ServerDiagnosticsType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    ServerDiagnosticsTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(ServerDiagnosticsResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(ServerDiagnosticsResult{::ua::detail::address_space_gone("ServerDiagnostics")});
        return;
      }
      complete(ServerDiagnostics{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

ServerDiagnosticsResult ServerDiagnostics::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ServerDiagnosticsResult>(addressSpace.executor(),
      [&](std::function<void(ServerDiagnosticsResult)> complete)
      {
        ServerDiagnostics::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ServerDiagnostics ServerDiagnostics::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void ServerDiagnostics::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void ServerDiagnostics::find_property_async(
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
    "ServerDiagnostics",
    std::move(complete));
}

// --- Property accessors ---

void ServerDiagnostics::enabled_flag_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ServerDiagnosticsTypeTraits::enabled_flag_browse_name(), std::move(complete));
}

PropertyResult ServerDiagnostics::try_enabled_flag_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { enabled_flag_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerDiagnostics::enabled_flag_property_sync() const
{
  return ::ua::detail::good_value(try_enabled_flag_property_sync());
}

// --- Typed value read shortcuts ---

void ServerDiagnostics::read_enabled_flag_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    ServerDiagnosticsTypeTraits::enabled_flag_browse_name(),
    &Variant::is_boolean,
    {"ServerDiagnostics", "enabled_flag", "ServerDiagnostics::read_enabled_flag_async"},
    std::move(complete));
}

BoolResult ServerDiagnostics::try_read_enabled_flag_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BoolResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BoolResult)> complete) { read_enabled_flag_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

bool ServerDiagnostics::read_enabled_flag_sync() const
{
  return ::ua::detail::good_value(try_read_enabled_flag_sync());
}

// --- Typed value write shortcuts ---

void ServerDiagnostics::write_enabled_flag_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ServerDiagnosticsTypeTraits::enabled_flag_browse_name(),
    "ServerDiagnostics",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ServerDiagnostics::try_write_enabled_flag_sync(bool value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_enabled_flag_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerDiagnostics::write_enabled_flag_sync(bool value) const
{
  try_write_enabled_flag_sync(value).value();
}

}  // namespace ua
