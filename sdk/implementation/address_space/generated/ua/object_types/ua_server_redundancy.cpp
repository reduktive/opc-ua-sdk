// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_server_redundancy.h"

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

struct ServerRedundancyTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::ServerRedundancyType};
  }

  static QualifiedName redundancy_support_browse_name()
  {
    return QualifiedName{0, "RedundancySupport"};
  }

  static QualifiedName redundant_server_array_browse_name()
  {
    return QualifiedName{0, "RedundantServerArray"};
  }
};

}  // namespace

ServerRedundancy::ServerRedundancy(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void ServerRedundancy::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    ServerRedundancyTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(ServerRedundancyResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(ServerRedundancyResult{
        ServerRedundancy{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

ServerRedundancyResult ServerRedundancy::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ServerRedundancyResult>(addressSpace.executor(),
      [&](std::function<void(ServerRedundancyResult)> complete)
      {
        ServerRedundancy::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ServerRedundancy ServerRedundancy::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void ServerRedundancy::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void ServerRedundancy::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // ServerRedundancyType has subtypes - subtype match.
  instance_utils::attach_subtype_async(addressSpace,
    existingInstance,
    ServerRedundancyTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(ServerRedundancyResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(ServerRedundancyResult{::ua::detail::address_space_gone("ServerRedundancy")});
        return;
      }
      complete(ServerRedundancy{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

ServerRedundancyResult ServerRedundancy::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ServerRedundancyResult>(addressSpace.executor(),
      [&](std::function<void(ServerRedundancyResult)> complete)
      {
        ServerRedundancy::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ServerRedundancy ServerRedundancy::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void ServerRedundancy::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void ServerRedundancy::find_property_async(
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
    "ServerRedundancy",
    std::move(complete));
}

// --- Property accessors ---

void ServerRedundancy::redundancy_support_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ServerRedundancyTypeTraits::redundancy_support_browse_name(), std::move(complete));
}

PropertyResult ServerRedundancy::try_redundancy_support_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { redundancy_support_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerRedundancy::redundancy_support_property_sync() const
{
  return ::ua::detail::good_value(try_redundancy_support_property_sync());
}

void ServerRedundancy::redundant_server_array_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ServerRedundancyTypeTraits::redundant_server_array_browse_name(), std::move(complete));
}

PropertyResult ServerRedundancy::try_redundant_server_array_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { redundant_server_array_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerRedundancy::redundant_server_array_property_sync() const
{
  return ::ua::detail::good_value(try_redundant_server_array_property_sync());
}

}  // namespace ua
