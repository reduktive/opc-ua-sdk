// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_key_credential_configuration_folder.h"

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

struct KeyCredentialConfigurationFolderTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::KeyCredentialConfigurationFolderType};
  }

  static QualifiedName create_credential_browse_name()
  {
    return QualifiedName{0, "CreateCredential"};
  }
};

}  // namespace

KeyCredentialConfigurationFolder::KeyCredentialConfigurationFolder(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void KeyCredentialConfigurationFolder::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    KeyCredentialConfigurationFolderTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(KeyCredentialConfigurationFolderResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(KeyCredentialConfigurationFolderResult{
        KeyCredentialConfigurationFolder{
          std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

KeyCredentialConfigurationFolderResult KeyCredentialConfigurationFolder::try_create_sync(
  AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
  const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<KeyCredentialConfigurationFolderResult>(addressSpace.executor(),
      [&](std::function<void(KeyCredentialConfigurationFolderResult)> complete)
      {
        KeyCredentialConfigurationFolder::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

KeyCredentialConfigurationFolder KeyCredentialConfigurationFolder::create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void KeyCredentialConfigurationFolder::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void KeyCredentialConfigurationFolder::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // KeyCredentialConfigurationFolderType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    KeyCredentialConfigurationFolderTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(KeyCredentialConfigurationFolderResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(KeyCredentialConfigurationFolderResult{
          ::ua::detail::address_space_gone("KeyCredentialConfigurationFolder")});
        return;
      }
      complete(KeyCredentialConfigurationFolder{
        std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

KeyCredentialConfigurationFolderResult KeyCredentialConfigurationFolder::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<KeyCredentialConfigurationFolderResult>(addressSpace.executor(),
      [&](std::function<void(KeyCredentialConfigurationFolderResult)> complete)
      {
        KeyCredentialConfigurationFolder::attach_async(
          std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

KeyCredentialConfigurationFolder KeyCredentialConfigurationFolder::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void KeyCredentialConfigurationFolder::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

void KeyCredentialConfigurationFolder::create_credential_method_async(
  MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    KeyCredentialConfigurationFolderTypeTraits::create_credential_browse_name(),
    std::move(complete));
}

MethodAccessorResult KeyCredentialConfigurationFolder::try_create_credential_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { create_credential_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor KeyCredentialConfigurationFolder::create_credential_method_sync() const
{
  return ::ua::detail::good_value(try_create_credential_method_sync());
}

// --- Method handler registration ---

void KeyCredentialConfigurationFolder::set_create_credential_handler_async(
  CreateCredentialHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "KeyCredentialConfigurationFolder",
        "KeyCredentialConfigurationFolder::set_create_credential_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String, String, String, Array<String>>, std::tuple<NodeId>> adapter{
      [handler = std::move(handler)](const MethodCall& call,
        const String& in0,
        const String& in1,
        const String& in2,
        const Array<String>& in3) -> MethodResult<NodeId>
      {
        CreateCredentialInputArguments typedIn{
          .name = in0, .resourceUri = in1, .profileUri = in2, .endpointUrls = in3.payload()};
        return detail::method_result_from_struct<NodeId>(handler(call, typedIn),
          [](const CreateCredentialOutputArguments& out)
          { return std::tuple<NodeId>{out.credentialNodeId}; });
      },
      Inputs<String, String, String, Array<String>>{{Arg<String>{.name = "Name"},
        Arg<String>{.name = "ResourceUri"},
        Arg<String>{.name = "ProfileUri"},
        Arg<Array<String>>{.name = "EndpointUrls"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      KeyCredentialConfigurationFolderTypeTraits::create_credential_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult KeyCredentialConfigurationFolder::try_set_create_credential_handler_sync(
  CreateCredentialHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_create_credential_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void KeyCredentialConfigurationFolder::set_create_credential_handler_sync(
  CreateCredentialHandler handler) const
{
  try_set_create_credential_handler_sync(std::move(handler)).value();
}

void KeyCredentialConfigurationFolder::set_create_credential_handler_async(
  CreateCredentialAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "KeyCredentialConfigurationFolder",
        "KeyCredentialConfigurationFolder::set_create_credential_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String, String, String, Array<String>>, std::tuple<NodeId>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](const MethodCall& call,
        const String& in0,
        const String& in1,
        const String& in2,
        const Array<String>& in3,
        MethodResultCallback<NodeId>
          complete)
      {
        CreateCredentialInputArguments typedIn{
          .name = in0, .resourceUri = in1, .profileUri = in2, .endpointUrls = in3.payload()};
        handler(call,
          typedIn,
          detail::struct_method_result_callback<CreateCredentialOutputArguments>(
            std::move(complete),
            [](const CreateCredentialOutputArguments& out)
            { return std::tuple<NodeId>{out.credentialNodeId}; },
            logger,
            call.method_id()));
      },
      Inputs<String, String, String, Array<String>>{{Arg<String>{.name = "Name"},
        Arg<String>{.name = "ResourceUri"},
        Arg<String>{.name = "ProfileUri"},
        Arg<Array<String>>{.name = "EndpointUrls"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      KeyCredentialConfigurationFolderTypeTraits::create_credential_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult KeyCredentialConfigurationFolder::try_set_create_credential_handler_sync(
  CreateCredentialAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_create_credential_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void KeyCredentialConfigurationFolder::set_create_credential_handler_sync(
  CreateCredentialAsyncHandler handler) const
{
  try_set_create_credential_handler_sync(std::move(handler)).value();
}

}  // namespace ua
