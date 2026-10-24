// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_alias_name_category.h"

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

struct AliasNameCategoryTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::AliasNameCategoryType};
  }

  static QualifiedName find_alias_browse_name()
  {
    return QualifiedName{0, "FindAlias"};
  }

  static QualifiedName last_change_browse_name()
  {
    return QualifiedName{0, "LastChange"};
  }
};

}  // namespace

AliasNameCategory::AliasNameCategory(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void AliasNameCategory::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    AliasNameCategoryTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(AliasNameCategoryResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(AliasNameCategoryResult{
        AliasNameCategory{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

AliasNameCategoryResult AliasNameCategory::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<AliasNameCategoryResult>(addressSpace.executor(),
      [&](std::function<void(AliasNameCategoryResult)> complete)
      {
        AliasNameCategory::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

AliasNameCategory AliasNameCategory::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void AliasNameCategory::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void AliasNameCategory::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // AliasNameCategoryType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    AliasNameCategoryTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(AliasNameCategoryResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(AliasNameCategoryResult{::ua::detail::address_space_gone("AliasNameCategory")});
        return;
      }
      complete(AliasNameCategory{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

AliasNameCategoryResult AliasNameCategory::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<AliasNameCategoryResult>(addressSpace.executor(),
      [&](std::function<void(AliasNameCategoryResult)> complete)
      {
        AliasNameCategory::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

AliasNameCategory AliasNameCategory::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void AliasNameCategory::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

void AliasNameCategory::find_alias_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AliasNameCategoryTypeTraits::find_alias_browse_name(),
    std::move(complete));
}

MethodAccessorResult AliasNameCategory::try_find_alias_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { find_alias_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor AliasNameCategory::find_alias_method_sync() const
{
  return ::ua::detail::good_value(try_find_alias_method_sync());
}

// --- Common property helper ---

void AliasNameCategory::find_property_async(
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
    "AliasNameCategory",
    std::move(complete));
}

// --- Property accessors ---

void AliasNameCategory::last_change_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AliasNameCategoryTypeTraits::last_change_browse_name(), std::move(complete));
}

PropertyResult AliasNameCategory::try_last_change_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { last_change_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property AliasNameCategory::last_change_property_sync() const
{
  return ::ua::detail::good_value(try_last_change_property_sync());
}

// --- Method handler registration ---

void AliasNameCategory::set_find_alias_handler_async(
  FindAliasHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AliasNameCategory",
        "AliasNameCategory::set_find_alias_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String, NodeId>, std::tuple<std::vector<Variant>>> adapter{
      [handler = std::move(handler)](
        const MethodCall& call, const String& in0, const NodeId& in1) -> MethodResult<std::vector<Variant>>
      {
        FindAliasInputArguments typedIn{.aliasNameSearchPattern = in0, .referenceTypeFilter = in1};
        return detail::method_result_from_struct<std::vector<Variant>>(handler(call, typedIn),
          [](const FindAliasOutputArguments& out)
          { return std::tuple<std::vector<Variant>>{out.aliasNodeList}; });
      },
      Inputs<String, NodeId>{
        {Arg<String>{.name = "AliasNameSearchPattern"}, Arg<NodeId>{.name = "ReferenceTypeFilter"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      AliasNameCategoryTypeTraits::find_alias_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AliasNameCategory::try_set_find_alias_handler_sync(FindAliasHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_find_alias_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AliasNameCategory::set_find_alias_handler_sync(FindAliasHandler handler) const
{
  try_set_find_alias_handler_sync(std::move(handler)).value();
}

void AliasNameCategory::set_find_alias_handler_async(
  FindAliasAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AliasNameCategory",
        "AliasNameCategory::set_find_alias_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String, NodeId>, std::tuple<std::vector<Variant>>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](const MethodCall& call,
        const String& in0,
        const NodeId& in1,
        MethodResultCallback<std::vector<Variant>>
          complete)
      {
        FindAliasInputArguments typedIn{.aliasNameSearchPattern = in0, .referenceTypeFilter = in1};
        handler(call,
          typedIn,
          detail::struct_method_result_callback<FindAliasOutputArguments>(
            std::move(complete),
            [](const FindAliasOutputArguments& out)
            { return std::tuple<std::vector<Variant>>{out.aliasNodeList}; },
            logger,
            call.method_id()));
      },
      Inputs<String, NodeId>{
        {Arg<String>{.name = "AliasNameSearchPattern"}, Arg<NodeId>{.name = "ReferenceTypeFilter"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      AliasNameCategoryTypeTraits::find_alias_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AliasNameCategory::try_set_find_alias_handler_sync(FindAliasAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_find_alias_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AliasNameCategory::set_find_alias_handler_sync(FindAliasAsyncHandler handler) const
{
  try_set_find_alias_handler_sync(std::move(handler)).value();
}

}  // namespace ua
