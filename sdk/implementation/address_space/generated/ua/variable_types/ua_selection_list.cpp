// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_selection_list.h"

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

struct SelectionListTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{VariableTypeId::SelectionListType};
  }

  static QualifiedName selections_browse_name()
  {
    return QualifiedName{0, "Selections"};
  }

  static QualifiedName selection_descriptions_browse_name()
  {
    return QualifiedName{0, "SelectionDescriptions"};
  }

  static QualifiedName restrict_to_list_browse_name()
  {
    return QualifiedName{0, "RestrictToList"};
  }
};

}  // namespace

SelectionList::SelectionList(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseDataVariable(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void SelectionList::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, VariableInstantiationAttributes attributes,
  CreateCompleteCallback complete) noexcept
{
  create_variable_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    SelectionListTypeTraits::type_definition_id(),
    std::move(options),
    std::move(attributes),
    [complete = std::move(complete)](BaseVariable::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(SelectionListResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(SelectionListResult{
        SelectionList{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)}, code});
    });
}

SelectionListResult SelectionList::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<SelectionListResult>(addressSpace.executor(),
      [&](std::function<void(SelectionListResult)> complete)
      {
        SelectionList::create_async(
          std::move(addressSpace), parent, browseName, options, attributes, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

SelectionList SelectionList::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes)
{
  return ::ua::detail::good_value(
    try_create_sync(std::move(addressSpace), parent, browseName, options, attributes));
}

void SelectionList::create_async(AddressSpace addressSpace, const NodeId& parent,
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

void SelectionList::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // SelectionListType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    SelectionListTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(SelectionListResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(SelectionListResult{::ua::detail::address_space_gone("SelectionList")});
        return;
      }
      complete(SelectionList{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

SelectionListResult SelectionList::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<SelectionListResult>(addressSpace.executor(),
      [&](std::function<void(SelectionListResult)> complete)
      {
        SelectionList::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

SelectionList SelectionList::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void SelectionList::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void SelectionList::find_property_async(
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
    "SelectionList",
    std::move(complete));
}

// --- Property accessors ---

void SelectionList::selections_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(SelectionListTypeTraits::selections_browse_name(), std::move(complete));
}

PropertyResult SelectionList::try_selections_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { selections_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property SelectionList::selections_property_sync() const
{
  return ::ua::detail::good_value(try_selections_property_sync());
}

void SelectionList::selection_descriptions_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(SelectionListTypeTraits::selection_descriptions_browse_name(), std::move(complete));
}

PropertyResult SelectionList::try_selection_descriptions_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { selection_descriptions_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property SelectionList::selection_descriptions_property_sync() const
{
  return ::ua::detail::good_value(try_selection_descriptions_property_sync());
}

void SelectionList::restrict_to_list_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(SelectionListTypeTraits::restrict_to_list_browse_name(), std::move(complete));
}

PropertyResult SelectionList::try_restrict_to_list_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { restrict_to_list_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property SelectionList::restrict_to_list_property_sync() const
{
  return ::ua::detail::good_value(try_restrict_to_list_property_sync());
}

// --- Typed value read shortcuts ---

void SelectionList::read_selection_descriptions_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    SelectionListTypeTraits::selection_descriptions_browse_name(),
    &Variant::is_localized_text,
    {"SelectionList", "selection_descriptions", "SelectionList::read_selection_descriptions_async"},
    std::move(complete));
}

LocalizedTextResult SelectionList::try_read_selection_descriptions_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LocalizedTextResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(LocalizedTextResult)> complete)
      { read_selection_descriptions_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LocalizedText SelectionList::read_selection_descriptions_sync() const
{
  return ::ua::detail::good_value(try_read_selection_descriptions_sync());
}

void SelectionList::read_restrict_to_list_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    SelectionListTypeTraits::restrict_to_list_browse_name(),
    &Variant::is_boolean,
    {"SelectionList", "restrict_to_list", "SelectionList::read_restrict_to_list_async"},
    std::move(complete));
}

BoolResult SelectionList::try_read_restrict_to_list_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BoolResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BoolResult)> complete) { read_restrict_to_list_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

bool SelectionList::read_restrict_to_list_sync() const
{
  return ::ua::detail::good_value(try_read_restrict_to_list_sync());
}

// --- Typed value write shortcuts ---

void SelectionList::write_selection_descriptions_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    SelectionListTypeTraits::selection_descriptions_browse_name(),
    "SelectionList",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult SelectionList::try_write_selection_descriptions_sync(LocalizedText value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_selection_descriptions_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void SelectionList::write_selection_descriptions_sync(LocalizedText value) const
{
  try_write_selection_descriptions_sync(value).value();
}

void SelectionList::write_restrict_to_list_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    SelectionListTypeTraits::restrict_to_list_browse_name(),
    "SelectionList",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult SelectionList::try_write_restrict_to_list_sync(bool value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_restrict_to_list_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void SelectionList::write_restrict_to_list_sync(bool value) const
{
  try_write_restrict_to_list_sync(value).value();
}

}  // namespace ua
