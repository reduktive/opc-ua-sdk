// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_operation_limits.h"

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

struct OperationLimitsTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::OperationLimitsType};
  }

  static QualifiedName max_nodes_per_read_browse_name()
  {
    return QualifiedName{0, "MaxNodesPerRead"};
  }

  static QualifiedName max_nodes_per_history_read_data_browse_name()
  {
    return QualifiedName{0, "MaxNodesPerHistoryReadData"};
  }

  static QualifiedName max_nodes_per_history_read_events_browse_name()
  {
    return QualifiedName{0, "MaxNodesPerHistoryReadEvents"};
  }

  static QualifiedName max_nodes_per_write_browse_name()
  {
    return QualifiedName{0, "MaxNodesPerWrite"};
  }

  static QualifiedName max_nodes_per_history_update_data_browse_name()
  {
    return QualifiedName{0, "MaxNodesPerHistoryUpdateData"};
  }

  static QualifiedName max_nodes_per_history_update_events_browse_name()
  {
    return QualifiedName{0, "MaxNodesPerHistoryUpdateEvents"};
  }

  static QualifiedName max_nodes_per_method_call_browse_name()
  {
    return QualifiedName{0, "MaxNodesPerMethodCall"};
  }

  static QualifiedName max_nodes_per_browse_browse_name()
  {
    return QualifiedName{0, "MaxNodesPerBrowse"};
  }

  static QualifiedName max_nodes_per_register_nodes_browse_name()
  {
    return QualifiedName{0, "MaxNodesPerRegisterNodes"};
  }

  static QualifiedName max_nodes_per_translate_browse_paths_to_node_ids_browse_name()
  {
    return QualifiedName{0, "MaxNodesPerTranslateBrowsePathsToNodeIds"};
  }

  static QualifiedName max_nodes_per_node_management_browse_name()
  {
    return QualifiedName{0, "MaxNodesPerNodeManagement"};
  }

  static QualifiedName max_monitored_items_per_call_browse_name()
  {
    return QualifiedName{0, "MaxMonitoredItemsPerCall"};
  }
};

}  // namespace

OperationLimits::OperationLimits(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void OperationLimits::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    OperationLimitsTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(OperationLimitsResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(OperationLimitsResult{
        OperationLimits{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

OperationLimitsResult OperationLimits::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<OperationLimitsResult>(addressSpace.executor(),
      [&](std::function<void(OperationLimitsResult)> complete)
      {
        OperationLimits::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

OperationLimits OperationLimits::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void OperationLimits::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void OperationLimits::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // OperationLimitsType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    OperationLimitsTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(OperationLimitsResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(OperationLimitsResult{::ua::detail::address_space_gone("OperationLimits")});
        return;
      }
      complete(OperationLimits{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

OperationLimitsResult OperationLimits::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<OperationLimitsResult>(addressSpace.executor(),
      [&](std::function<void(OperationLimitsResult)> complete)
      {
        OperationLimits::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

OperationLimits OperationLimits::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void OperationLimits::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void OperationLimits::find_property_async(
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
    "OperationLimits",
    std::move(complete));
}

// --- Property accessors ---

void OperationLimits::max_nodes_per_read_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(OperationLimitsTypeTraits::max_nodes_per_read_browse_name(), std::move(complete));
}

PropertyResult OperationLimits::try_max_nodes_per_read_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_nodes_per_read_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property OperationLimits::max_nodes_per_read_property_sync() const
{
  return ::ua::detail::good_value(try_max_nodes_per_read_property_sync());
}

void OperationLimits::max_nodes_per_history_read_data_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    OperationLimitsTypeTraits::max_nodes_per_history_read_data_browse_name(), std::move(complete));
}

PropertyResult OperationLimits::try_max_nodes_per_history_read_data_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_nodes_per_history_read_data_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property OperationLimits::max_nodes_per_history_read_data_property_sync() const
{
  return ::ua::detail::good_value(try_max_nodes_per_history_read_data_property_sync());
}

void OperationLimits::max_nodes_per_history_read_events_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    OperationLimitsTypeTraits::max_nodes_per_history_read_events_browse_name(), std::move(complete));
}

PropertyResult OperationLimits::try_max_nodes_per_history_read_events_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_nodes_per_history_read_events_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property OperationLimits::max_nodes_per_history_read_events_property_sync() const
{
  return ::ua::detail::good_value(try_max_nodes_per_history_read_events_property_sync());
}

void OperationLimits::max_nodes_per_write_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(OperationLimitsTypeTraits::max_nodes_per_write_browse_name(), std::move(complete));
}

PropertyResult OperationLimits::try_max_nodes_per_write_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_nodes_per_write_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property OperationLimits::max_nodes_per_write_property_sync() const
{
  return ::ua::detail::good_value(try_max_nodes_per_write_property_sync());
}

void OperationLimits::max_nodes_per_history_update_data_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    OperationLimitsTypeTraits::max_nodes_per_history_update_data_browse_name(), std::move(complete));
}

PropertyResult OperationLimits::try_max_nodes_per_history_update_data_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_nodes_per_history_update_data_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property OperationLimits::max_nodes_per_history_update_data_property_sync() const
{
  return ::ua::detail::good_value(try_max_nodes_per_history_update_data_property_sync());
}

void OperationLimits::max_nodes_per_history_update_events_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    OperationLimitsTypeTraits::max_nodes_per_history_update_events_browse_name(), std::move(complete));
}

PropertyResult OperationLimits::try_max_nodes_per_history_update_events_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_nodes_per_history_update_events_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property OperationLimits::max_nodes_per_history_update_events_property_sync() const
{
  return ::ua::detail::good_value(try_max_nodes_per_history_update_events_property_sync());
}

void OperationLimits::max_nodes_per_method_call_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    OperationLimitsTypeTraits::max_nodes_per_method_call_browse_name(), std::move(complete));
}

PropertyResult OperationLimits::try_max_nodes_per_method_call_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_nodes_per_method_call_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property OperationLimits::max_nodes_per_method_call_property_sync() const
{
  return ::ua::detail::good_value(try_max_nodes_per_method_call_property_sync());
}

void OperationLimits::max_nodes_per_browse_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(OperationLimitsTypeTraits::max_nodes_per_browse_browse_name(), std::move(complete));
}

PropertyResult OperationLimits::try_max_nodes_per_browse_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_nodes_per_browse_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property OperationLimits::max_nodes_per_browse_property_sync() const
{
  return ::ua::detail::good_value(try_max_nodes_per_browse_property_sync());
}

void OperationLimits::max_nodes_per_register_nodes_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    OperationLimitsTypeTraits::max_nodes_per_register_nodes_browse_name(), std::move(complete));
}

PropertyResult OperationLimits::try_max_nodes_per_register_nodes_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_nodes_per_register_nodes_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property OperationLimits::max_nodes_per_register_nodes_property_sync() const
{
  return ::ua::detail::good_value(try_max_nodes_per_register_nodes_property_sync());
}

void OperationLimits::max_nodes_per_translate_browse_paths_to_node_ids_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    OperationLimitsTypeTraits::max_nodes_per_translate_browse_paths_to_node_ids_browse_name(),
    std::move(complete));
}

PropertyResult
  OperationLimits::try_max_nodes_per_translate_browse_paths_to_node_ids_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_nodes_per_translate_browse_paths_to_node_ids_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property OperationLimits::max_nodes_per_translate_browse_paths_to_node_ids_property_sync() const
{
  return ::ua::detail::good_value(try_max_nodes_per_translate_browse_paths_to_node_ids_property_sync());
}

void OperationLimits::max_nodes_per_node_management_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    OperationLimitsTypeTraits::max_nodes_per_node_management_browse_name(), std::move(complete));
}

PropertyResult OperationLimits::try_max_nodes_per_node_management_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_nodes_per_node_management_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property OperationLimits::max_nodes_per_node_management_property_sync() const
{
  return ::ua::detail::good_value(try_max_nodes_per_node_management_property_sync());
}

void OperationLimits::max_monitored_items_per_call_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    OperationLimitsTypeTraits::max_monitored_items_per_call_browse_name(), std::move(complete));
}

PropertyResult OperationLimits::try_max_monitored_items_per_call_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_monitored_items_per_call_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property OperationLimits::max_monitored_items_per_call_property_sync() const
{
  return ::ua::detail::good_value(try_max_monitored_items_per_call_property_sync());
}

// --- Typed value read shortcuts ---

void OperationLimits::read_max_nodes_per_read_async(std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    OperationLimitsTypeTraits::max_nodes_per_read_browse_name(),
    &Variant::is_uint32,
    {"OperationLimits", "max_nodes_per_read", "OperationLimits::read_max_nodes_per_read_async"},
    std::move(complete));
}

UInt32Result OperationLimits::try_read_max_nodes_per_read_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete)
      { read_max_nodes_per_read_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t OperationLimits::read_max_nodes_per_read_sync() const
{
  return ::ua::detail::good_value(try_read_max_nodes_per_read_sync());
}

void OperationLimits::read_max_nodes_per_history_read_data_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    OperationLimitsTypeTraits::max_nodes_per_history_read_data_browse_name(),
    &Variant::is_uint32,
    {"OperationLimits",
      "max_nodes_per_history_read_data",
      "OperationLimits::read_max_nodes_per_history_read_data_async"},
    std::move(complete));
}

UInt32Result OperationLimits::try_read_max_nodes_per_history_read_data_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete)
      { read_max_nodes_per_history_read_data_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t OperationLimits::read_max_nodes_per_history_read_data_sync() const
{
  return ::ua::detail::good_value(try_read_max_nodes_per_history_read_data_sync());
}

void OperationLimits::read_max_nodes_per_history_read_events_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    OperationLimitsTypeTraits::max_nodes_per_history_read_events_browse_name(),
    &Variant::is_uint32,
    {"OperationLimits",
      "max_nodes_per_history_read_events",
      "OperationLimits::read_max_nodes_per_history_read_events_async"},
    std::move(complete));
}

UInt32Result OperationLimits::try_read_max_nodes_per_history_read_events_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete)
      { read_max_nodes_per_history_read_events_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t OperationLimits::read_max_nodes_per_history_read_events_sync() const
{
  return ::ua::detail::good_value(try_read_max_nodes_per_history_read_events_sync());
}

void OperationLimits::read_max_nodes_per_write_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    OperationLimitsTypeTraits::max_nodes_per_write_browse_name(),
    &Variant::is_uint32,
    {"OperationLimits", "max_nodes_per_write", "OperationLimits::read_max_nodes_per_write_async"},
    std::move(complete));
}

UInt32Result OperationLimits::try_read_max_nodes_per_write_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete)
      { read_max_nodes_per_write_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t OperationLimits::read_max_nodes_per_write_sync() const
{
  return ::ua::detail::good_value(try_read_max_nodes_per_write_sync());
}

void OperationLimits::read_max_nodes_per_history_update_data_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    OperationLimitsTypeTraits::max_nodes_per_history_update_data_browse_name(),
    &Variant::is_uint32,
    {"OperationLimits",
      "max_nodes_per_history_update_data",
      "OperationLimits::read_max_nodes_per_history_update_data_async"},
    std::move(complete));
}

UInt32Result OperationLimits::try_read_max_nodes_per_history_update_data_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete)
      { read_max_nodes_per_history_update_data_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t OperationLimits::read_max_nodes_per_history_update_data_sync() const
{
  return ::ua::detail::good_value(try_read_max_nodes_per_history_update_data_sync());
}

void OperationLimits::read_max_nodes_per_history_update_events_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    OperationLimitsTypeTraits::max_nodes_per_history_update_events_browse_name(),
    &Variant::is_uint32,
    {"OperationLimits",
      "max_nodes_per_history_update_events",
      "OperationLimits::read_max_nodes_per_history_update_events_async"},
    std::move(complete));
}

UInt32Result OperationLimits::try_read_max_nodes_per_history_update_events_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete)
      { read_max_nodes_per_history_update_events_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t OperationLimits::read_max_nodes_per_history_update_events_sync() const
{
  return ::ua::detail::good_value(try_read_max_nodes_per_history_update_events_sync());
}

void OperationLimits::read_max_nodes_per_method_call_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    OperationLimitsTypeTraits::max_nodes_per_method_call_browse_name(),
    &Variant::is_uint32,
    {"OperationLimits", "max_nodes_per_method_call", "OperationLimits::read_max_nodes_per_method_call_async"},
    std::move(complete));
}

UInt32Result OperationLimits::try_read_max_nodes_per_method_call_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete)
      { read_max_nodes_per_method_call_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t OperationLimits::read_max_nodes_per_method_call_sync() const
{
  return ::ua::detail::good_value(try_read_max_nodes_per_method_call_sync());
}

void OperationLimits::read_max_nodes_per_browse_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    OperationLimitsTypeTraits::max_nodes_per_browse_browse_name(),
    &Variant::is_uint32,
    {"OperationLimits", "max_nodes_per_browse", "OperationLimits::read_max_nodes_per_browse_async"},
    std::move(complete));
}

UInt32Result OperationLimits::try_read_max_nodes_per_browse_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete)
      { read_max_nodes_per_browse_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t OperationLimits::read_max_nodes_per_browse_sync() const
{
  return ::ua::detail::good_value(try_read_max_nodes_per_browse_sync());
}

void OperationLimits::read_max_nodes_per_register_nodes_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    OperationLimitsTypeTraits::max_nodes_per_register_nodes_browse_name(),
    &Variant::is_uint32,
    {"OperationLimits",
      "max_nodes_per_register_nodes",
      "OperationLimits::read_max_nodes_per_register_nodes_async"},
    std::move(complete));
}

UInt32Result OperationLimits::try_read_max_nodes_per_register_nodes_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete)
      { read_max_nodes_per_register_nodes_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t OperationLimits::read_max_nodes_per_register_nodes_sync() const
{
  return ::ua::detail::good_value(try_read_max_nodes_per_register_nodes_sync());
}

void OperationLimits::read_max_nodes_per_translate_browse_paths_to_node_ids_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    OperationLimitsTypeTraits::max_nodes_per_translate_browse_paths_to_node_ids_browse_name(),
    &Variant::is_uint32,
    {"OperationLimits",
      "max_nodes_per_translate_browse_paths_to_node_ids",
      "OperationLimits::read_max_nodes_per_translate_browse_paths_to_node_ids_async"},
    std::move(complete));
}

UInt32Result OperationLimits::try_read_max_nodes_per_translate_browse_paths_to_node_ids_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete)
      { read_max_nodes_per_translate_browse_paths_to_node_ids_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t OperationLimits::read_max_nodes_per_translate_browse_paths_to_node_ids_sync() const
{
  return ::ua::detail::good_value(try_read_max_nodes_per_translate_browse_paths_to_node_ids_sync());
}

void OperationLimits::read_max_nodes_per_node_management_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    OperationLimitsTypeTraits::max_nodes_per_node_management_browse_name(),
    &Variant::is_uint32,
    {"OperationLimits",
      "max_nodes_per_node_management",
      "OperationLimits::read_max_nodes_per_node_management_async"},
    std::move(complete));
}

UInt32Result OperationLimits::try_read_max_nodes_per_node_management_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete)
      { read_max_nodes_per_node_management_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t OperationLimits::read_max_nodes_per_node_management_sync() const
{
  return ::ua::detail::good_value(try_read_max_nodes_per_node_management_sync());
}

void OperationLimits::read_max_monitored_items_per_call_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    OperationLimitsTypeTraits::max_monitored_items_per_call_browse_name(),
    &Variant::is_uint32,
    {"OperationLimits",
      "max_monitored_items_per_call",
      "OperationLimits::read_max_monitored_items_per_call_async"},
    std::move(complete));
}

UInt32Result OperationLimits::try_read_max_monitored_items_per_call_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete)
      { read_max_monitored_items_per_call_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t OperationLimits::read_max_monitored_items_per_call_sync() const
{
  return ::ua::detail::good_value(try_read_max_monitored_items_per_call_sync());
}

// --- Typed value write shortcuts ---

void OperationLimits::write_max_nodes_per_read_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    OperationLimitsTypeTraits::max_nodes_per_read_browse_name(),
    "OperationLimits",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult OperationLimits::try_write_max_nodes_per_read_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_nodes_per_read_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void OperationLimits::write_max_nodes_per_read_sync(uint32_t value) const
{
  try_write_max_nodes_per_read_sync(value).value();
}

void OperationLimits::write_max_nodes_per_history_read_data_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    OperationLimitsTypeTraits::max_nodes_per_history_read_data_browse_name(),
    "OperationLimits",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult OperationLimits::try_write_max_nodes_per_history_read_data_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_nodes_per_history_read_data_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void OperationLimits::write_max_nodes_per_history_read_data_sync(uint32_t value) const
{
  try_write_max_nodes_per_history_read_data_sync(value).value();
}

void OperationLimits::write_max_nodes_per_history_read_events_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    OperationLimitsTypeTraits::max_nodes_per_history_read_events_browse_name(),
    "OperationLimits",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult OperationLimits::try_write_max_nodes_per_history_read_events_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_nodes_per_history_read_events_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void OperationLimits::write_max_nodes_per_history_read_events_sync(uint32_t value) const
{
  try_write_max_nodes_per_history_read_events_sync(value).value();
}

void OperationLimits::write_max_nodes_per_write_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    OperationLimitsTypeTraits::max_nodes_per_write_browse_name(),
    "OperationLimits",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult OperationLimits::try_write_max_nodes_per_write_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_nodes_per_write_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void OperationLimits::write_max_nodes_per_write_sync(uint32_t value) const
{
  try_write_max_nodes_per_write_sync(value).value();
}

void OperationLimits::write_max_nodes_per_history_update_data_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    OperationLimitsTypeTraits::max_nodes_per_history_update_data_browse_name(),
    "OperationLimits",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult OperationLimits::try_write_max_nodes_per_history_update_data_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_nodes_per_history_update_data_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void OperationLimits::write_max_nodes_per_history_update_data_sync(uint32_t value) const
{
  try_write_max_nodes_per_history_update_data_sync(value).value();
}

void OperationLimits::write_max_nodes_per_history_update_events_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    OperationLimitsTypeTraits::max_nodes_per_history_update_events_browse_name(),
    "OperationLimits",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult OperationLimits::try_write_max_nodes_per_history_update_events_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_nodes_per_history_update_events_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void OperationLimits::write_max_nodes_per_history_update_events_sync(uint32_t value) const
{
  try_write_max_nodes_per_history_update_events_sync(value).value();
}

void OperationLimits::write_max_nodes_per_method_call_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    OperationLimitsTypeTraits::max_nodes_per_method_call_browse_name(),
    "OperationLimits",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult OperationLimits::try_write_max_nodes_per_method_call_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_nodes_per_method_call_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void OperationLimits::write_max_nodes_per_method_call_sync(uint32_t value) const
{
  try_write_max_nodes_per_method_call_sync(value).value();
}

void OperationLimits::write_max_nodes_per_browse_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    OperationLimitsTypeTraits::max_nodes_per_browse_browse_name(),
    "OperationLimits",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult OperationLimits::try_write_max_nodes_per_browse_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_nodes_per_browse_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void OperationLimits::write_max_nodes_per_browse_sync(uint32_t value) const
{
  try_write_max_nodes_per_browse_sync(value).value();
}

void OperationLimits::write_max_nodes_per_register_nodes_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    OperationLimitsTypeTraits::max_nodes_per_register_nodes_browse_name(),
    "OperationLimits",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult OperationLimits::try_write_max_nodes_per_register_nodes_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_nodes_per_register_nodes_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void OperationLimits::write_max_nodes_per_register_nodes_sync(uint32_t value) const
{
  try_write_max_nodes_per_register_nodes_sync(value).value();
}

void OperationLimits::write_max_nodes_per_translate_browse_paths_to_node_ids_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    OperationLimitsTypeTraits::max_nodes_per_translate_browse_paths_to_node_ids_browse_name(),
    "OperationLimits",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult OperationLimits::try_write_max_nodes_per_translate_browse_paths_to_node_ids_sync(
  uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_nodes_per_translate_browse_paths_to_node_ids_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void OperationLimits::write_max_nodes_per_translate_browse_paths_to_node_ids_sync(uint32_t value) const
{
  try_write_max_nodes_per_translate_browse_paths_to_node_ids_sync(value).value();
}

void OperationLimits::write_max_nodes_per_node_management_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    OperationLimitsTypeTraits::max_nodes_per_node_management_browse_name(),
    "OperationLimits",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult OperationLimits::try_write_max_nodes_per_node_management_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_nodes_per_node_management_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void OperationLimits::write_max_nodes_per_node_management_sync(uint32_t value) const
{
  try_write_max_nodes_per_node_management_sync(value).value();
}

void OperationLimits::write_max_monitored_items_per_call_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    OperationLimitsTypeTraits::max_monitored_items_per_call_browse_name(),
    "OperationLimits",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult OperationLimits::try_write_max_monitored_items_per_call_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_monitored_items_per_call_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void OperationLimits::write_max_monitored_items_per_call_sync(uint32_t value) const
{
  try_write_max_monitored_items_per_call_sync(value).value();
}

}  // namespace ua
