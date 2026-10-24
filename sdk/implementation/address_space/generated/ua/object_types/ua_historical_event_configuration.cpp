// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_historical_event_configuration.h"

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

struct HistoricalEventConfigurationTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::HistoricalEventConfigurationType};
  }

  static QualifiedName event_types_browse_name()
  {
    return QualifiedName{0, "EventTypes"};
  }

  static QualifiedName start_of_archive_browse_name()
  {
    return QualifiedName{0, "StartOfArchive"};
  }

  static QualifiedName start_of_online_archive_browse_name()
  {
    return QualifiedName{0, "StartOfOnlineArchive"};
  }

  static QualifiedName sort_by_event_fields_browse_name()
  {
    return QualifiedName{0, "SortByEventFields"};
  }
};

}  // namespace

HistoricalEventConfiguration::HistoricalEventConfiguration(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void HistoricalEventConfiguration::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    HistoricalEventConfigurationTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(HistoricalEventConfigurationResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(HistoricalEventConfigurationResult{
        HistoricalEventConfiguration{
          std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

HistoricalEventConfigurationResult HistoricalEventConfiguration::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<HistoricalEventConfigurationResult>(addressSpace.executor(),
      [&](std::function<void(HistoricalEventConfigurationResult)> complete)
      {
        HistoricalEventConfiguration::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

HistoricalEventConfiguration HistoricalEventConfiguration::create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void HistoricalEventConfiguration::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void HistoricalEventConfiguration::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // HistoricalEventConfigurationType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    HistoricalEventConfigurationTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(HistoricalEventConfigurationResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(HistoricalEventConfigurationResult{
          ::ua::detail::address_space_gone("HistoricalEventConfiguration")});
        return;
      }
      complete(HistoricalEventConfiguration{
        std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

HistoricalEventConfigurationResult HistoricalEventConfiguration::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<HistoricalEventConfigurationResult>(addressSpace.executor(),
      [&](std::function<void(HistoricalEventConfigurationResult)> complete)
      {
        HistoricalEventConfiguration::attach_async(
          std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

HistoricalEventConfiguration HistoricalEventConfiguration::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void HistoricalEventConfiguration::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void HistoricalEventConfiguration::find_property_async(
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
    "HistoricalEventConfiguration",
    std::move(complete));
}

// --- Property accessors ---

void HistoricalEventConfiguration::start_of_archive_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    HistoricalEventConfigurationTypeTraits::start_of_archive_browse_name(), std::move(complete));
}

PropertyResult HistoricalEventConfiguration::try_start_of_archive_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { start_of_archive_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property HistoricalEventConfiguration::start_of_archive_property_sync() const
{
  return ::ua::detail::good_value(try_start_of_archive_property_sync());
}

void HistoricalEventConfiguration::start_of_online_archive_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    HistoricalEventConfigurationTypeTraits::start_of_online_archive_browse_name(), std::move(complete));
}

PropertyResult HistoricalEventConfiguration::try_start_of_online_archive_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { start_of_online_archive_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property HistoricalEventConfiguration::start_of_online_archive_property_sync() const
{
  return ::ua::detail::good_value(try_start_of_online_archive_property_sync());
}

void HistoricalEventConfiguration::sort_by_event_fields_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    HistoricalEventConfigurationTypeTraits::sort_by_event_fields_browse_name(), std::move(complete));
}

PropertyResult HistoricalEventConfiguration::try_sort_by_event_fields_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { sort_by_event_fields_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property HistoricalEventConfiguration::sort_by_event_fields_property_sync() const
{
  return ::ua::detail::good_value(try_sort_by_event_fields_property_sync());
}

// --- Child-object accessors ---

void HistoricalEventConfiguration::event_types_async(
  std::function<void(FolderResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(FolderResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<Folder>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    HistoricalEventConfigurationTypeTraits::event_types_browse_name(),
    "HistoricalEventConfiguration",
    std::move(complete));
}

FolderResult HistoricalEventConfiguration::try_event_types_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<FolderResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(FolderResult)> complete) { event_types_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Folder HistoricalEventConfiguration::event_types_sync() const
{
  return ::ua::detail::good_value(try_event_types_sync());
}

}  // namespace ua
