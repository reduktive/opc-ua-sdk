// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_serialization_entity.h"

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

struct SerializationEntityTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::SerializationEntityType};
  }

  static QualifiedName serialized_data_browse_name()
  {
    return QualifiedName{0, "SerializedData"};
  }

  static QualifiedName include_reference_types_browse_name()
  {
    return QualifiedName{0, "IncludeReferenceTypes"};
  }

  static QualifiedName exclude_reference_types_browse_name()
  {
    return QualifiedName{0, "ExcludeReferenceTypes"};
  }

  static QualifiedName serialization_depth_browse_name()
  {
    return QualifiedName{0, "SerializationDepth"};
  }

  static QualifiedName consider_sub_element_serialization_properties_browse_name()
  {
    return QualifiedName{0, "ConsiderSubElementSerializationProperties"};
  }

  static QualifiedName custom_meta_data_properties_browse_name()
  {
    return QualifiedName{0, "CustomMetaDataProperties"};
  }

  static QualifiedName custom_meta_data_ref_browse_name()
  {
    return QualifiedName{0, "CustomMetaDataRef"};
  }

  static QualifiedName include_status_browse_name()
  {
    return QualifiedName{0, "IncludeStatus"};
  }

  static QualifiedName include_source_timestamp_browse_name()
  {
    return QualifiedName{0, "IncludeSourceTimestamp"};
  }

  static QualifiedName include_dictionary_reference_browse_name()
  {
    return QualifiedName{0, "IncludeDictionaryReference"};
  }

  static QualifiedName configure_serialization_browse_name()
  {
    return QualifiedName{0, "ConfigureSerialization"};
  }
};

}  // namespace

SerializationEntity::SerializationEntity(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void SerializationEntity::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    SerializationEntityTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(SerializationEntityResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(SerializationEntityResult{
        SerializationEntity{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

SerializationEntityResult SerializationEntity::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<SerializationEntityResult>(addressSpace.executor(),
      [&](std::function<void(SerializationEntityResult)> complete)
      {
        SerializationEntity::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

SerializationEntity SerializationEntity::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void SerializationEntity::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void SerializationEntity::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // SerializationEntityType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    SerializationEntityTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(SerializationEntityResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(SerializationEntityResult{::ua::detail::address_space_gone("SerializationEntity")});
        return;
      }
      complete(
        SerializationEntity{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

SerializationEntityResult SerializationEntity::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<SerializationEntityResult>(addressSpace.executor(),
      [&](std::function<void(SerializationEntityResult)> complete)
      {
        SerializationEntity::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

SerializationEntity SerializationEntity::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void SerializationEntity::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

void SerializationEntity::configure_serialization_method_async(
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
    SerializationEntityTypeTraits::configure_serialization_browse_name(),
    std::move(complete));
}

MethodAccessorResult SerializationEntity::try_configure_serialization_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { configure_serialization_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor SerializationEntity::configure_serialization_method_sync() const
{
  return ::ua::detail::good_value(try_configure_serialization_method_sync());
}

// --- Common property helper ---

void SerializationEntity::find_property_async(
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
    "SerializationEntity",
    std::move(complete));
}

// --- Property accessors ---

void SerializationEntity::include_reference_types_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    SerializationEntityTypeTraits::include_reference_types_browse_name(), std::move(complete));
}

PropertyResult SerializationEntity::try_include_reference_types_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { include_reference_types_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property SerializationEntity::include_reference_types_property_sync() const
{
  return ::ua::detail::good_value(try_include_reference_types_property_sync());
}

void SerializationEntity::exclude_reference_types_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    SerializationEntityTypeTraits::exclude_reference_types_browse_name(), std::move(complete));
}

PropertyResult SerializationEntity::try_exclude_reference_types_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { exclude_reference_types_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property SerializationEntity::exclude_reference_types_property_sync() const
{
  return ::ua::detail::good_value(try_exclude_reference_types_property_sync());
}

void SerializationEntity::serialization_depth_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(SerializationEntityTypeTraits::serialization_depth_browse_name(), std::move(complete));
}

PropertyResult SerializationEntity::try_serialization_depth_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { serialization_depth_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property SerializationEntity::serialization_depth_property_sync() const
{
  return ::ua::detail::good_value(try_serialization_depth_property_sync());
}

void SerializationEntity::consider_sub_element_serialization_properties_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    SerializationEntityTypeTraits::consider_sub_element_serialization_properties_browse_name(),
    std::move(complete));
}

PropertyResult
  SerializationEntity::try_consider_sub_element_serialization_properties_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { consider_sub_element_serialization_properties_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property SerializationEntity::consider_sub_element_serialization_properties_property_sync() const
{
  return ::ua::detail::good_value(try_consider_sub_element_serialization_properties_property_sync());
}

void SerializationEntity::custom_meta_data_properties_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    SerializationEntityTypeTraits::custom_meta_data_properties_browse_name(), std::move(complete));
}

PropertyResult SerializationEntity::try_custom_meta_data_properties_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { custom_meta_data_properties_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property SerializationEntity::custom_meta_data_properties_property_sync() const
{
  return ::ua::detail::good_value(try_custom_meta_data_properties_property_sync());
}

void SerializationEntity::custom_meta_data_ref_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(SerializationEntityTypeTraits::custom_meta_data_ref_browse_name(), std::move(complete));
}

PropertyResult SerializationEntity::try_custom_meta_data_ref_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { custom_meta_data_ref_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property SerializationEntity::custom_meta_data_ref_property_sync() const
{
  return ::ua::detail::good_value(try_custom_meta_data_ref_property_sync());
}

void SerializationEntity::include_status_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(SerializationEntityTypeTraits::include_status_browse_name(), std::move(complete));
}

PropertyResult SerializationEntity::try_include_status_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { include_status_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property SerializationEntity::include_status_property_sync() const
{
  return ::ua::detail::good_value(try_include_status_property_sync());
}

void SerializationEntity::include_source_timestamp_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    SerializationEntityTypeTraits::include_source_timestamp_browse_name(), std::move(complete));
}

PropertyResult SerializationEntity::try_include_source_timestamp_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { include_source_timestamp_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property SerializationEntity::include_source_timestamp_property_sync() const
{
  return ::ua::detail::good_value(try_include_source_timestamp_property_sync());
}

void SerializationEntity::include_dictionary_reference_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    SerializationEntityTypeTraits::include_dictionary_reference_browse_name(), std::move(complete));
}

PropertyResult SerializationEntity::try_include_dictionary_reference_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { include_dictionary_reference_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property SerializationEntity::include_dictionary_reference_property_sync() const
{
  return ::ua::detail::good_value(try_include_dictionary_reference_property_sync());
}

// --- Typed value read shortcuts ---

void SerializationEntity::read_include_reference_types_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    SerializationEntityTypeTraits::include_reference_types_browse_name(),
    &Variant::is_node_id,
    {"SerializationEntity",
      "include_reference_types",
      "SerializationEntity::read_include_reference_types_async"},
    std::move(complete));
}

NodeIdResult SerializationEntity::try_read_include_reference_types_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeIdResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(NodeIdResult)> complete)
      { read_include_reference_types_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NodeId SerializationEntity::read_include_reference_types_sync() const
{
  return ::ua::detail::good_value(try_read_include_reference_types_sync());
}

void SerializationEntity::read_exclude_reference_types_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    SerializationEntityTypeTraits::exclude_reference_types_browse_name(),
    &Variant::is_node_id,
    {"SerializationEntity",
      "exclude_reference_types",
      "SerializationEntity::read_exclude_reference_types_async"},
    std::move(complete));
}

NodeIdResult SerializationEntity::try_read_exclude_reference_types_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeIdResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(NodeIdResult)> complete)
      { read_exclude_reference_types_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NodeId SerializationEntity::read_exclude_reference_types_sync() const
{
  return ::ua::detail::good_value(try_read_exclude_reference_types_sync());
}

void SerializationEntity::read_serialization_depth_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    SerializationEntityTypeTraits::serialization_depth_browse_name(),
    &Variant::is_uint16,
    {"SerializationEntity", "serialization_depth", "SerializationEntity::read_serialization_depth_async"},
    std::move(complete));
}

UInt16Result SerializationEntity::try_read_serialization_depth_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt16Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt16Result)> complete)
      { read_serialization_depth_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint16_t SerializationEntity::read_serialization_depth_sync() const
{
  return ::ua::detail::good_value(try_read_serialization_depth_sync());
}

void SerializationEntity::read_consider_sub_element_serialization_properties_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    SerializationEntityTypeTraits::consider_sub_element_serialization_properties_browse_name(),
    &Variant::is_boolean,
    {"SerializationEntity",
      "consider_sub_element_serialization_properties",
      "SerializationEntity::read_consider_sub_element_serialization_properties_async"},
    std::move(complete));
}

BoolResult SerializationEntity::try_read_consider_sub_element_serialization_properties_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BoolResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BoolResult)> complete)
      { read_consider_sub_element_serialization_properties_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

bool SerializationEntity::read_consider_sub_element_serialization_properties_sync() const
{
  return ::ua::detail::good_value(try_read_consider_sub_element_serialization_properties_sync());
}

void SerializationEntity::read_custom_meta_data_ref_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    SerializationEntityTypeTraits::custom_meta_data_ref_browse_name(),
    &Variant::is_node_id,
    {"SerializationEntity", "custom_meta_data_ref", "SerializationEntity::read_custom_meta_data_ref_async"},
    std::move(complete));
}

NodeIdResult SerializationEntity::try_read_custom_meta_data_ref_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeIdResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(NodeIdResult)> complete)
      { read_custom_meta_data_ref_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NodeId SerializationEntity::read_custom_meta_data_ref_sync() const
{
  return ::ua::detail::good_value(try_read_custom_meta_data_ref_sync());
}

void SerializationEntity::read_include_status_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    SerializationEntityTypeTraits::include_status_browse_name(),
    &Variant::is_boolean,
    {"SerializationEntity", "include_status", "SerializationEntity::read_include_status_async"},
    std::move(complete));
}

BoolResult SerializationEntity::try_read_include_status_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BoolResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BoolResult)> complete) { read_include_status_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

bool SerializationEntity::read_include_status_sync() const
{
  return ::ua::detail::good_value(try_read_include_status_sync());
}

void SerializationEntity::read_include_source_timestamp_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    SerializationEntityTypeTraits::include_source_timestamp_browse_name(),
    &Variant::is_boolean,
    {"SerializationEntity",
      "include_source_timestamp",
      "SerializationEntity::read_include_source_timestamp_async"},
    std::move(complete));
}

BoolResult SerializationEntity::try_read_include_source_timestamp_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BoolResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BoolResult)> complete)
      { read_include_source_timestamp_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

bool SerializationEntity::read_include_source_timestamp_sync() const
{
  return ::ua::detail::good_value(try_read_include_source_timestamp_sync());
}

void SerializationEntity::read_include_dictionary_reference_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    SerializationEntityTypeTraits::include_dictionary_reference_browse_name(),
    &Variant::is_boolean,
    {"SerializationEntity",
      "include_dictionary_reference",
      "SerializationEntity::read_include_dictionary_reference_async"},
    std::move(complete));
}

BoolResult SerializationEntity::try_read_include_dictionary_reference_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BoolResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BoolResult)> complete)
      { read_include_dictionary_reference_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

bool SerializationEntity::read_include_dictionary_reference_sync() const
{
  return ::ua::detail::good_value(try_read_include_dictionary_reference_sync());
}

// --- Typed value write shortcuts ---

void SerializationEntity::write_include_reference_types_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    SerializationEntityTypeTraits::include_reference_types_browse_name(),
    "SerializationEntity",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult SerializationEntity::try_write_include_reference_types_sync(NodeId value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_include_reference_types_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void SerializationEntity::write_include_reference_types_sync(NodeId value) const
{
  try_write_include_reference_types_sync(value).value();
}

void SerializationEntity::write_exclude_reference_types_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    SerializationEntityTypeTraits::exclude_reference_types_browse_name(),
    "SerializationEntity",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult SerializationEntity::try_write_exclude_reference_types_sync(NodeId value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_exclude_reference_types_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void SerializationEntity::write_exclude_reference_types_sync(NodeId value) const
{
  try_write_exclude_reference_types_sync(value).value();
}

void SerializationEntity::write_serialization_depth_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    SerializationEntityTypeTraits::serialization_depth_browse_name(),
    "SerializationEntity",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult SerializationEntity::try_write_serialization_depth_sync(uint16_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_serialization_depth_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void SerializationEntity::write_serialization_depth_sync(uint16_t value) const
{
  try_write_serialization_depth_sync(value).value();
}

void SerializationEntity::write_consider_sub_element_serialization_properties_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    SerializationEntityTypeTraits::consider_sub_element_serialization_properties_browse_name(),
    "SerializationEntity",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult SerializationEntity::try_write_consider_sub_element_serialization_properties_sync(
  bool value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_consider_sub_element_serialization_properties_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void SerializationEntity::write_consider_sub_element_serialization_properties_sync(bool value) const
{
  try_write_consider_sub_element_serialization_properties_sync(value).value();
}

void SerializationEntity::write_custom_meta_data_ref_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    SerializationEntityTypeTraits::custom_meta_data_ref_browse_name(),
    "SerializationEntity",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult SerializationEntity::try_write_custom_meta_data_ref_sync(NodeId value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_custom_meta_data_ref_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void SerializationEntity::write_custom_meta_data_ref_sync(NodeId value) const
{
  try_write_custom_meta_data_ref_sync(value).value();
}

void SerializationEntity::write_include_status_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    SerializationEntityTypeTraits::include_status_browse_name(),
    "SerializationEntity",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult SerializationEntity::try_write_include_status_sync(bool value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_include_status_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void SerializationEntity::write_include_status_sync(bool value) const
{
  try_write_include_status_sync(value).value();
}

void SerializationEntity::write_include_source_timestamp_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    SerializationEntityTypeTraits::include_source_timestamp_browse_name(),
    "SerializationEntity",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult SerializationEntity::try_write_include_source_timestamp_sync(bool value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_include_source_timestamp_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void SerializationEntity::write_include_source_timestamp_sync(bool value) const
{
  try_write_include_source_timestamp_sync(value).value();
}

void SerializationEntity::write_include_dictionary_reference_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    SerializationEntityTypeTraits::include_dictionary_reference_browse_name(),
    "SerializationEntity",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult SerializationEntity::try_write_include_dictionary_reference_sync(bool value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_include_dictionary_reference_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void SerializationEntity::write_include_dictionary_reference_sync(bool value) const
{
  try_write_include_dictionary_reference_sync(value).value();
}

// --- Method handler registration ---

void SerializationEntity::set_configure_serialization_handler_async(
  ConfigureSerializationHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "SerializationEntity",
        "SerializationEntity::set_configure_serialization_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<Array<Variant>>, std::tuple<std::vector<int32_t>>> adapter{
      [handler = std::move(handler)](
        const MethodCall& call, const Array<Variant>& in0) -> MethodResult<std::vector<int32_t>>
      {
        ConfigureSerializationInputArguments typedIn{.serializationFilterProperties = in0.payload()};
        return detail::method_result_from_struct<std::vector<int32_t>>(handler(call, typedIn),
          [](const ConfigureSerializationOutputArguments& out)
          { return std::tuple<std::vector<int32_t>>{out.results}; });
      },
      Inputs<Array<Variant>>{{Arg<Array<Variant>>{.name = "SerializationFilterProperties"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      SerializationEntityTypeTraits::configure_serialization_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult SerializationEntity::try_set_configure_serialization_handler_sync(
  ConfigureSerializationHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_configure_serialization_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void SerializationEntity::set_configure_serialization_handler_sync(
  ConfigureSerializationHandler handler) const
{
  try_set_configure_serialization_handler_sync(std::move(handler)).value();
}

void SerializationEntity::set_configure_serialization_handler_async(
  ConfigureSerializationAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "SerializationEntity",
        "SerializationEntity::set_configure_serialization_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<Array<Variant>>, std::tuple<std::vector<int32_t>>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](const MethodCall& call,
        const Array<Variant>& in0,
        MethodResultCallback<std::vector<int32_t>>
          complete)
      {
        ConfigureSerializationInputArguments typedIn{.serializationFilterProperties = in0.payload()};
        handler(call,
          typedIn,
          detail::struct_method_result_callback<ConfigureSerializationOutputArguments>(
            std::move(complete),
            [](const ConfigureSerializationOutputArguments& out)
            { return std::tuple<std::vector<int32_t>>{out.results}; },
            logger,
            call.method_id()));
      },
      Inputs<Array<Variant>>{{Arg<Array<Variant>>{.name = "SerializationFilterProperties"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      SerializationEntityTypeTraits::configure_serialization_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult SerializationEntity::try_set_configure_serialization_handler_sync(
  ConfigureSerializationAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_configure_serialization_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void SerializationEntity::set_configure_serialization_handler_sync(
  ConfigureSerializationAsyncHandler handler) const
{
  try_set_configure_serialization_handler_sync(std::move(handler)).value();
}

// --- Child-object accessors ---

void SerializationEntity::serialized_data_async(
  std::function<void(BaseDataVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BaseDataVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<BaseDataVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    SerializationEntityTypeTraits::serialized_data_browse_name(),
    "SerializationEntity",
    std::move(complete));
}

BaseDataVariableResult SerializationEntity::try_serialized_data_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { serialized_data_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable SerializationEntity::serialized_data_sync() const
{
  return ::ua::detail::good_value(try_serialized_data_sync());
}

}  // namespace ua
