// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_priority_mapping_table.h"

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

struct PriorityMappingTableTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::PriorityMappingTableType};
  }

  static QualifiedName priority_mappping_entries_browse_name()
  {
    return QualifiedName{0, "PriorityMapppingEntries"};
  }

  static QualifiedName add_priority_mapping_entry_browse_name()
  {
    return QualifiedName{0, "AddPriorityMappingEntry"};
  }

  static QualifiedName delete_priority_mapping_entry_browse_name()
  {
    return QualifiedName{0, "DeletePriorityMappingEntry"};
  }
};

}  // namespace

PriorityMappingTable::PriorityMappingTable(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void PriorityMappingTable::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    PriorityMappingTableTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(PriorityMappingTableResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(PriorityMappingTableResult{
        PriorityMappingTable{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

PriorityMappingTableResult PriorityMappingTable::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PriorityMappingTableResult>(addressSpace.executor(),
      [&](std::function<void(PriorityMappingTableResult)> complete)
      {
        PriorityMappingTable::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

PriorityMappingTable PriorityMappingTable::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void PriorityMappingTable::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void PriorityMappingTable::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // PriorityMappingTableType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    PriorityMappingTableTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(PriorityMappingTableResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(PriorityMappingTableResult{::ua::detail::address_space_gone("PriorityMappingTable")});
        return;
      }
      complete(
        PriorityMappingTable{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

PriorityMappingTableResult PriorityMappingTable::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PriorityMappingTableResult>(addressSpace.executor(),
      [&](std::function<void(PriorityMappingTableResult)> complete)
      {
        PriorityMappingTable::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

PriorityMappingTable PriorityMappingTable::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void PriorityMappingTable::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

void PriorityMappingTable::add_priority_mapping_entry_method_async(
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
    PriorityMappingTableTypeTraits::add_priority_mapping_entry_browse_name(),
    std::move(complete));
}

MethodAccessorResult PriorityMappingTable::try_add_priority_mapping_entry_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { add_priority_mapping_entry_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor PriorityMappingTable::add_priority_mapping_entry_method_sync() const
{
  return ::ua::detail::good_value(try_add_priority_mapping_entry_method_sync());
}

void PriorityMappingTable::delete_priority_mapping_entry_method_async(
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
    PriorityMappingTableTypeTraits::delete_priority_mapping_entry_browse_name(),
    std::move(complete));
}

MethodAccessorResult PriorityMappingTable::try_delete_priority_mapping_entry_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { delete_priority_mapping_entry_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor PriorityMappingTable::delete_priority_mapping_entry_method_sync() const
{
  return ::ua::detail::good_value(try_delete_priority_mapping_entry_method_sync());
}

// --- Common property helper ---

void PriorityMappingTable::find_property_async(
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
    "PriorityMappingTable",
    std::move(complete));
}

// --- Property accessors ---

void PriorityMappingTable::priority_mappping_entries_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    PriorityMappingTableTypeTraits::priority_mappping_entries_browse_name(), std::move(complete));
}

PropertyResult PriorityMappingTable::try_priority_mappping_entries_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { priority_mappping_entries_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property PriorityMappingTable::priority_mappping_entries_property_sync() const
{
  return ::ua::detail::good_value(try_priority_mappping_entries_property_sync());
}

// --- Method handler registration ---

void PriorityMappingTable::set_add_priority_mapping_entry_handler_async(
  AddPriorityMappingEntryHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "PriorityMappingTable",
        "PriorityMappingTable::set_add_priority_mapping_entry_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String, String, uint8_t, uint32_t>, std::tuple<>> adapter{
      [handler = std::move(handler)](
        const MethodCall& call, const String& in0, const String& in1, const uint8_t& in2, const uint32_t& in3)
        -> MethodResult<>
      {
        AddPriorityMappingEntryInputArguments typedIn{
          .mappingUri = in0, .priorityLabel = in1, .priorityValuePcp = in2, .priorityValueDscp = in3};
        return handler(call, typedIn);
      },
      Inputs<String, String, uint8_t, uint32_t>{{Arg<String>{.name = "MappingUri"},
        Arg<String>{.name = "PriorityLabel"},
        Arg<uint8_t>{.name = "PriorityValue_PCP"},
        Arg<uint32_t>{.name = "PriorityValue_DSCP"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      PriorityMappingTableTypeTraits::add_priority_mapping_entry_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult PriorityMappingTable::try_set_add_priority_mapping_entry_handler_sync(
  AddPriorityMappingEntryHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_add_priority_mapping_entry_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void PriorityMappingTable::set_add_priority_mapping_entry_handler_sync(
  AddPriorityMappingEntryHandler handler) const
{
  try_set_add_priority_mapping_entry_handler_sync(std::move(handler)).value();
}

void PriorityMappingTable::set_add_priority_mapping_entry_handler_async(
  AddPriorityMappingEntryAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "PriorityMappingTable",
        "PriorityMappingTable::set_add_priority_mapping_entry_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String, String, uint8_t, uint32_t>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](const MethodCall& call,
        const String& in0,
        const String& in1,
        const uint8_t& in2,
        const uint32_t& in3,
        MethodResultCallback<>
          complete)
      {
        AddPriorityMappingEntryInputArguments typedIn{
          .mappingUri = in0, .priorityLabel = in1, .priorityValuePcp = in2, .priorityValueDscp = in3};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<String, String, uint8_t, uint32_t>{{Arg<String>{.name = "MappingUri"},
        Arg<String>{.name = "PriorityLabel"},
        Arg<uint8_t>{.name = "PriorityValue_PCP"},
        Arg<uint32_t>{.name = "PriorityValue_DSCP"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      PriorityMappingTableTypeTraits::add_priority_mapping_entry_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult PriorityMappingTable::try_set_add_priority_mapping_entry_handler_sync(
  AddPriorityMappingEntryAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_add_priority_mapping_entry_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void PriorityMappingTable::set_add_priority_mapping_entry_handler_sync(
  AddPriorityMappingEntryAsyncHandler handler) const
{
  try_set_add_priority_mapping_entry_handler_sync(std::move(handler)).value();
}

void PriorityMappingTable::set_delete_priority_mapping_entry_handler_async(
  DeletePriorityMappingEntryHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "PriorityMappingTable",
        "PriorityMappingTable::set_delete_priority_mapping_entry_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String, String>, std::tuple<>> adapter{
      [handler = std::move(handler)](
        const MethodCall& call, const String& in0, const String& in1) -> MethodResult<>
      {
        DeletePriorityMappingEntryInputArguments typedIn{.mappingUri = in0, .priorityLabel = in1};
        return handler(call, typedIn);
      },
      Inputs<String, String>{{Arg<String>{.name = "MappingUri"}, Arg<String>{.name = "PriorityLabel"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      PriorityMappingTableTypeTraits::delete_priority_mapping_entry_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult PriorityMappingTable::try_set_delete_priority_mapping_entry_handler_sync(
  DeletePriorityMappingEntryHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_delete_priority_mapping_entry_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void PriorityMappingTable::set_delete_priority_mapping_entry_handler_sync(
  DeletePriorityMappingEntryHandler handler) const
{
  try_set_delete_priority_mapping_entry_handler_sync(std::move(handler)).value();
}

void PriorityMappingTable::set_delete_priority_mapping_entry_handler_async(
  DeletePriorityMappingEntryAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "PriorityMappingTable",
        "PriorityMappingTable::set_delete_priority_mapping_entry_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String, String>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const String& in0, const String& in1, MethodResultCallback<> complete)
      {
        DeletePriorityMappingEntryInputArguments typedIn{.mappingUri = in0, .priorityLabel = in1};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<String, String>{{Arg<String>{.name = "MappingUri"}, Arg<String>{.name = "PriorityLabel"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      PriorityMappingTableTypeTraits::delete_priority_mapping_entry_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult PriorityMappingTable::try_set_delete_priority_mapping_entry_handler_sync(
  DeletePriorityMappingEntryAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_delete_priority_mapping_entry_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void PriorityMappingTable::set_delete_priority_mapping_entry_handler_sync(
  DeletePriorityMappingEntryAsyncHandler handler) const
{
  try_set_delete_priority_mapping_entry_handler_sync(std::move(handler)).value();
}

}  // namespace ua
