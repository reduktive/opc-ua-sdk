// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_role_set.h"

#include "ua_instance_utils.h"
#include "ua_sync_wait.h"
#include "ua_to_result.h"
#include "ua_weak_address_space.h"

#include <boost/asio/any_io_executor.hpp>

#include <functional>
#include <tuple>

#include "ua_call_method_result.h"
#include "ua_method_adapter.h"
#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"

namespace ua
{
namespace
{

struct RoleSetTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::RoleSetType};
  }

  static QualifiedName add_role_browse_name()
  {
    return QualifiedName{0, "AddRole"};
  }

  static QualifiedName remove_role_browse_name()
  {
    return QualifiedName{0, "RemoveRole"};
  }
};

}  // namespace

RoleSet::RoleSet(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void RoleSet::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    RoleSetTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(RoleSetResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(RoleSetResult{
        RoleSet{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)}, code});
    });
}

RoleSetResult RoleSet::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<RoleSetResult>(addressSpace.executor(),
      [&](std::function<void(RoleSetResult)> complete)
      {
        RoleSet::create_async(std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

RoleSet RoleSet::create_sync(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
  const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void RoleSet::create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
  const InstantiationOptions& options, CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void RoleSet::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // RoleSetType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    RoleSetTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(RoleSetResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(RoleSetResult{::ua::detail::address_space_gone("RoleSet")});
        return;
      }
      complete(RoleSet{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

RoleSetResult RoleSet::try_attach_sync(AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<RoleSetResult>(addressSpace.executor(),
      [&](std::function<void(RoleSetResult)> complete)
      {
        RoleSet::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

RoleSet RoleSet::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void RoleSet::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

void RoleSet::add_role_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    RoleSetTypeTraits::add_role_browse_name(),
    std::move(complete));
}

MethodAccessorResult RoleSet::try_add_role_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { add_role_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor RoleSet::add_role_method_sync() const
{
  return ::ua::detail::good_value(try_add_role_method_sync());
}

void RoleSet::remove_role_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    RoleSetTypeTraits::remove_role_browse_name(),
    std::move(complete));
}

MethodAccessorResult RoleSet::try_remove_role_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { remove_role_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor RoleSet::remove_role_method_sync() const
{
  return ::ua::detail::good_value(try_remove_role_method_sync());
}

// --- Method handler registration ---

void RoleSet::set_add_role_handler_async(
  AddRoleHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "RoleSet", "RoleSet::set_add_role_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String, String>, std::tuple<NodeId>> adapter{
      [handler = std::move(handler)](
        const MethodCall& call, const String& in0, const String& in1) -> MethodResult<NodeId>
      {
        AddRoleInputArguments typedIn{.roleName = in0, .namespaceUri = in1};
        return detail::method_result_from_struct<NodeId>(handler(call, typedIn),
          [](const AddRoleOutputArguments& out) { return std::tuple<NodeId>{out.roleNodeId}; });
      },
      Inputs<String, String>{{Arg<String>{.name = "RoleName"}, Arg<String>{.name = "NamespaceUri"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, RoleSetTypeTraits::add_role_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult RoleSet::try_set_add_role_handler_sync(AddRoleHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_add_role_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void RoleSet::set_add_role_handler_sync(AddRoleHandler handler) const
{
  try_set_add_role_handler_sync(std::move(handler)).value();
}

void RoleSet::set_add_role_handler_async(
  AddRoleAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "RoleSet", "RoleSet::set_add_role_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String, String>, std::tuple<NodeId>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const String& in0, const String& in1, MethodResultCallback<NodeId> complete)
      {
        AddRoleInputArguments typedIn{.roleName = in0, .namespaceUri = in1};
        handler(call,
          typedIn,
          detail::struct_method_result_callback<AddRoleOutputArguments>(
            std::move(complete),
            [](const AddRoleOutputArguments& out) { return std::tuple<NodeId>{out.roleNodeId}; },
            logger,
            call.method_id()));
      },
      Inputs<String, String>{{Arg<String>{.name = "RoleName"}, Arg<String>{.name = "NamespaceUri"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, RoleSetTypeTraits::add_role_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult RoleSet::try_set_add_role_handler_sync(AddRoleAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_add_role_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void RoleSet::set_add_role_handler_sync(AddRoleAsyncHandler handler) const
{
  try_set_add_role_handler_sync(std::move(handler)).value();
}

void RoleSet::set_remove_role_handler_async(
  RemoveRoleHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "RoleSet", "RoleSet::set_remove_role_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<NodeId>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const NodeId& in0) -> MethodResult<>
      {
        RemoveRoleInputArguments typedIn{.roleNodeId = in0};
        return handler(call, typedIn);
      },
      Inputs<NodeId>{{Arg<NodeId>{.name = "RoleNodeId"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, RoleSetTypeTraits::remove_role_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult RoleSet::try_set_remove_role_handler_sync(RemoveRoleHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_remove_role_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void RoleSet::set_remove_role_handler_sync(RemoveRoleHandler handler) const
{
  try_set_remove_role_handler_sync(std::move(handler)).value();
}

void RoleSet::set_remove_role_handler_async(
  RemoveRoleAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "RoleSet", "RoleSet::set_remove_role_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<NodeId>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const NodeId& in0, MethodResultCallback<> complete)
      {
        RemoveRoleInputArguments typedIn{.roleNodeId = in0};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<NodeId>{{Arg<NodeId>{.name = "RoleNodeId"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, RoleSetTypeTraits::remove_role_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult RoleSet::try_set_remove_role_handler_sync(RemoveRoleAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_remove_role_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void RoleSet::set_remove_role_handler_sync(RemoveRoleAsyncHandler handler) const
{
  try_set_remove_role_handler_sync(std::move(handler)).value();
}

}  // namespace ua
