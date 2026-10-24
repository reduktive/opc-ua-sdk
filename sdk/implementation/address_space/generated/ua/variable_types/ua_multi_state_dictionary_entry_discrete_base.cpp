// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_multi_state_dictionary_entry_discrete_base.h"

#include "ua_instance_utils.h"
#include "ua_sync_wait.h"
#include "ua_to_result.h"
#include "ua_weak_address_space.h"

#include <boost/asio/any_io_executor.hpp>

#include <functional>

#include "ua_referencetype_id.h"
#include "ua_variabletype_id.h"

namespace ua
{
namespace
{

struct MultiStateDictionaryEntryDiscreteBaseTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{VariableTypeId::MultiStateDictionaryEntryDiscreteBaseType};
  }

  static QualifiedName enum_dictionary_entries_browse_name()
  {
    return QualifiedName{0, "EnumDictionaryEntries"};
  }

  static QualifiedName value_as_dictionary_entries_browse_name()
  {
    return QualifiedName{0, "ValueAsDictionaryEntries"};
  }

  static QualifiedName enum_values_browse_name()
  {
    return QualifiedName{0, "EnumValues"};
  }

  static QualifiedName value_as_text_browse_name()
  {
    return QualifiedName{0, "ValueAsText"};
  }

  static QualifiedName definition_browse_name()
  {
    return QualifiedName{0, "Definition"};
  }

  static QualifiedName value_precision_browse_name()
  {
    return QualifiedName{0, "ValuePrecision"};
  }
};

}  // namespace

MultiStateDictionaryEntryDiscreteBase::MultiStateDictionaryEntryDiscreteBase(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseDataVariable(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void MultiStateDictionaryEntryDiscreteBase::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, VariableInstantiationAttributes attributes,
  CreateCompleteCallback complete) noexcept
{
  create_variable_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    MultiStateDictionaryEntryDiscreteBaseTypeTraits::type_definition_id(),
    std::move(options),
    std::move(attributes),
    [complete = std::move(complete)](BaseVariable::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(MultiStateDictionaryEntryDiscreteBaseResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      auto wireAddressSpace = data.addressSpace;
      auto wireNodeId = data.nodeId;
      auto ownedSubtree = std::make_shared<decltype(data.subtree)>(std::move(data.subtree));
      instance_utils::wire_value_as_text_async(std::move(wireAddressSpace),
        std::move(wireNodeId),
        [weakAddressSpace = data.addressSpace.weak(),
          nodeId = std::move(data.nodeId),
          ownedSubtree,
          code,
          complete = std::move(complete)](VoidResult) mutable
        {
          auto wiredAddressSpace = weakAddressSpace.lock();
          if (!wiredAddressSpace)
          {
            complete(MultiStateDictionaryEntryDiscreteBaseResult{
              ::ua::detail::address_space_gone("MultiStateDictionaryEntryDiscreteBase")});
            return;
          }
          complete(MultiStateDictionaryEntryDiscreteBaseResult{
            MultiStateDictionaryEntryDiscreteBase{
              std::move(*wiredAddressSpace), std::move(nodeId), std::move(*ownedSubtree)},
            code});
        });
    });
}

MultiStateDictionaryEntryDiscreteBaseResult MultiStateDictionaryEntryDiscreteBase::try_create_sync(
  AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
  const InstantiationOptions& options, const VariableInstantiationAttributes& attributes) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MultiStateDictionaryEntryDiscreteBaseResult>(
      addressSpace.executor(),
      [&](std::function<void(MultiStateDictionaryEntryDiscreteBaseResult)> complete)
      {
        MultiStateDictionaryEntryDiscreteBase::create_async(
          std::move(addressSpace), parent, browseName, options, attributes, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MultiStateDictionaryEntryDiscreteBase MultiStateDictionaryEntryDiscreteBase::create_sync(
  AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
  const InstantiationOptions& options, const VariableInstantiationAttributes& attributes)
{
  return ::ua::detail::good_value(
    try_create_sync(std::move(addressSpace), parent, browseName, options, attributes));
}

void MultiStateDictionaryEntryDiscreteBase::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes, CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    VariableInstantiationAttributes{attributes},
    std::move(complete));
}

void MultiStateDictionaryEntryDiscreteBase::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // MultiStateDictionaryEntryDiscreteBaseType has subtypes - subtype match.
  instance_utils::attach_subtype_async(addressSpace,
    existingInstance,
    MultiStateDictionaryEntryDiscreteBaseTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(MultiStateDictionaryEntryDiscreteBaseResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(MultiStateDictionaryEntryDiscreteBaseResult{
          ::ua::detail::address_space_gone("MultiStateDictionaryEntryDiscreteBase")});
        return;
      }
      complete(MultiStateDictionaryEntryDiscreteBase{
        std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

MultiStateDictionaryEntryDiscreteBaseResult MultiStateDictionaryEntryDiscreteBase::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MultiStateDictionaryEntryDiscreteBaseResult>(
      addressSpace.executor(),
      [&](std::function<void(MultiStateDictionaryEntryDiscreteBaseResult)> complete)
      {
        MultiStateDictionaryEntryDiscreteBase::attach_async(
          std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MultiStateDictionaryEntryDiscreteBase MultiStateDictionaryEntryDiscreteBase::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void MultiStateDictionaryEntryDiscreteBase::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void MultiStateDictionaryEntryDiscreteBase::find_property_async(
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
    "MultiStateDictionaryEntryDiscreteBase",
    std::move(complete));
}

// --- Property accessors ---

void MultiStateDictionaryEntryDiscreteBase::enum_dictionary_entries_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(MultiStateDictionaryEntryDiscreteBaseTypeTraits::enum_dictionary_entries_browse_name(),
    std::move(complete));
}

PropertyResult
  MultiStateDictionaryEntryDiscreteBase::try_enum_dictionary_entries_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { enum_dictionary_entries_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property MultiStateDictionaryEntryDiscreteBase::enum_dictionary_entries_property_sync() const
{
  return ::ua::detail::good_value(try_enum_dictionary_entries_property_sync());
}

void MultiStateDictionaryEntryDiscreteBase::value_as_dictionary_entries_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    MultiStateDictionaryEntryDiscreteBaseTypeTraits::value_as_dictionary_entries_browse_name(),
    std::move(complete));
}

PropertyResult
  MultiStateDictionaryEntryDiscreteBase::try_value_as_dictionary_entries_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { value_as_dictionary_entries_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property MultiStateDictionaryEntryDiscreteBase::value_as_dictionary_entries_property_sync() const
{
  return ::ua::detail::good_value(try_value_as_dictionary_entries_property_sync());
}

void MultiStateDictionaryEntryDiscreteBase::enum_values_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    MultiStateDictionaryEntryDiscreteBaseTypeTraits::enum_values_browse_name(), std::move(complete));
}

PropertyResult MultiStateDictionaryEntryDiscreteBase::try_enum_values_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { enum_values_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property MultiStateDictionaryEntryDiscreteBase::enum_values_property_sync() const
{
  return ::ua::detail::good_value(try_enum_values_property_sync());
}

void MultiStateDictionaryEntryDiscreteBase::value_as_text_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    MultiStateDictionaryEntryDiscreteBaseTypeTraits::value_as_text_browse_name(), std::move(complete));
}

PropertyResult MultiStateDictionaryEntryDiscreteBase::try_value_as_text_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { value_as_text_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property MultiStateDictionaryEntryDiscreteBase::value_as_text_property_sync() const
{
  return ::ua::detail::good_value(try_value_as_text_property_sync());
}

void MultiStateDictionaryEntryDiscreteBase::definition_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    MultiStateDictionaryEntryDiscreteBaseTypeTraits::definition_browse_name(), std::move(complete));
}

PropertyResult MultiStateDictionaryEntryDiscreteBase::try_definition_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { definition_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property MultiStateDictionaryEntryDiscreteBase::definition_property_sync() const
{
  return ::ua::detail::good_value(try_definition_property_sync());
}

void MultiStateDictionaryEntryDiscreteBase::value_precision_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    MultiStateDictionaryEntryDiscreteBaseTypeTraits::value_precision_browse_name(), std::move(complete));
}

PropertyResult MultiStateDictionaryEntryDiscreteBase::try_value_precision_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { value_precision_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property MultiStateDictionaryEntryDiscreteBase::value_precision_property_sync() const
{
  return ::ua::detail::good_value(try_value_precision_property_sync());
}

// --- Typed value read shortcuts ---

void MultiStateDictionaryEntryDiscreteBase::read_enum_dictionary_entries_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    MultiStateDictionaryEntryDiscreteBaseTypeTraits::enum_dictionary_entries_browse_name(),
    &Variant::is_node_id,
    {"MultiStateDictionaryEntryDiscreteBase",
      "enum_dictionary_entries",
      "MultiStateDictionaryEntryDiscreteBase::read_enum_dictionary_entries_async"},
    std::move(complete));
}

NodeIdResult MultiStateDictionaryEntryDiscreteBase::try_read_enum_dictionary_entries_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeIdResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(NodeIdResult)> complete)
      { read_enum_dictionary_entries_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NodeId MultiStateDictionaryEntryDiscreteBase::read_enum_dictionary_entries_sync() const
{
  return ::ua::detail::good_value(try_read_enum_dictionary_entries_sync());
}

void MultiStateDictionaryEntryDiscreteBase::read_value_as_dictionary_entries_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    MultiStateDictionaryEntryDiscreteBaseTypeTraits::value_as_dictionary_entries_browse_name(),
    &Variant::is_node_id,
    {"MultiStateDictionaryEntryDiscreteBase",
      "value_as_dictionary_entries",
      "MultiStateDictionaryEntryDiscreteBase::read_value_as_dictionary_entries_async"},
    std::move(complete));
}

NodeIdResult MultiStateDictionaryEntryDiscreteBase::try_read_value_as_dictionary_entries_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeIdResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(NodeIdResult)> complete)
      { read_value_as_dictionary_entries_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NodeId MultiStateDictionaryEntryDiscreteBase::read_value_as_dictionary_entries_sync() const
{
  return ::ua::detail::good_value(try_read_value_as_dictionary_entries_sync());
}

void MultiStateDictionaryEntryDiscreteBase::read_value_as_text_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    MultiStateDictionaryEntryDiscreteBaseTypeTraits::value_as_text_browse_name(),
    &Variant::is_localized_text,
    {"MultiStateDictionaryEntryDiscreteBase",
      "value_as_text",
      "MultiStateDictionaryEntryDiscreteBase::read_value_as_text_async"},
    std::move(complete));
}

LocalizedTextResult MultiStateDictionaryEntryDiscreteBase::try_read_value_as_text_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LocalizedTextResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(LocalizedTextResult)> complete)
      { read_value_as_text_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LocalizedText MultiStateDictionaryEntryDiscreteBase::read_value_as_text_sync() const
{
  return ::ua::detail::good_value(try_read_value_as_text_sync());
}

void MultiStateDictionaryEntryDiscreteBase::read_definition_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    MultiStateDictionaryEntryDiscreteBaseTypeTraits::definition_browse_name(),
    &Variant::is_string,
    {"MultiStateDictionaryEntryDiscreteBase",
      "definition",
      "MultiStateDictionaryEntryDiscreteBase::read_definition_async"},
    std::move(complete));
}

StringResult MultiStateDictionaryEntryDiscreteBase::try_read_definition_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_definition_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String MultiStateDictionaryEntryDiscreteBase::read_definition_sync() const
{
  return ::ua::detail::good_value(try_read_definition_sync());
}

void MultiStateDictionaryEntryDiscreteBase::read_value_precision_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    MultiStateDictionaryEntryDiscreteBaseTypeTraits::value_precision_browse_name(),
    &Variant::is_double,
    {"MultiStateDictionaryEntryDiscreteBase",
      "value_precision",
      "MultiStateDictionaryEntryDiscreteBase::read_value_precision_async"},
    std::move(complete));
}

DoubleResult MultiStateDictionaryEntryDiscreteBase::try_read_value_precision_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<DoubleResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(DoubleResult)> complete) { read_value_precision_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

double MultiStateDictionaryEntryDiscreteBase::read_value_precision_sync() const
{
  return ::ua::detail::good_value(try_read_value_precision_sync());
}

// --- Typed value write shortcuts ---

void MultiStateDictionaryEntryDiscreteBase::write_enum_dictionary_entries_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    MultiStateDictionaryEntryDiscreteBaseTypeTraits::enum_dictionary_entries_browse_name(),
    "MultiStateDictionaryEntryDiscreteBase",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult MultiStateDictionaryEntryDiscreteBase::try_write_enum_dictionary_entries_sync(
  NodeId value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_enum_dictionary_entries_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void MultiStateDictionaryEntryDiscreteBase::write_enum_dictionary_entries_sync(NodeId value) const
{
  try_write_enum_dictionary_entries_sync(value).value();
}

void MultiStateDictionaryEntryDiscreteBase::write_value_as_dictionary_entries_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    MultiStateDictionaryEntryDiscreteBaseTypeTraits::value_as_dictionary_entries_browse_name(),
    "MultiStateDictionaryEntryDiscreteBase",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult MultiStateDictionaryEntryDiscreteBase::try_write_value_as_dictionary_entries_sync(
  NodeId value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_value_as_dictionary_entries_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void MultiStateDictionaryEntryDiscreteBase::write_value_as_dictionary_entries_sync(NodeId value) const
{
  try_write_value_as_dictionary_entries_sync(value).value();
}

void MultiStateDictionaryEntryDiscreteBase::write_value_as_text_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    MultiStateDictionaryEntryDiscreteBaseTypeTraits::value_as_text_browse_name(),
    "MultiStateDictionaryEntryDiscreteBase",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult MultiStateDictionaryEntryDiscreteBase::try_write_value_as_text_sync(
  LocalizedText value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_value_as_text_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void MultiStateDictionaryEntryDiscreteBase::write_value_as_text_sync(LocalizedText value) const
{
  try_write_value_as_text_sync(value).value();
}

void MultiStateDictionaryEntryDiscreteBase::write_definition_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    MultiStateDictionaryEntryDiscreteBaseTypeTraits::definition_browse_name(),
    "MultiStateDictionaryEntryDiscreteBase",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult MultiStateDictionaryEntryDiscreteBase::try_write_definition_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_definition_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void MultiStateDictionaryEntryDiscreteBase::write_definition_sync(String value) const
{
  try_write_definition_sync(value).value();
}

void MultiStateDictionaryEntryDiscreteBase::write_value_precision_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    MultiStateDictionaryEntryDiscreteBaseTypeTraits::value_precision_browse_name(),
    "MultiStateDictionaryEntryDiscreteBase",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult MultiStateDictionaryEntryDiscreteBase::try_write_value_precision_sync(double value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_value_precision_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void MultiStateDictionaryEntryDiscreteBase::write_value_precision_sync(double value) const
{
  try_write_value_precision_sync(value).value();
}

}  // namespace ua
