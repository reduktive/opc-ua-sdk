// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_quantity.h"

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

struct QuantityTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::QuantityType};
  }

  static QualifiedName symbol_browse_name()
  {
    return QualifiedName{0, "Symbol"};
  }

  static QualifiedName annotation_browse_name()
  {
    return QualifiedName{0, "Annotation"};
  }

  static QualifiedName conversion_service_browse_name()
  {
    return QualifiedName{0, "ConversionService"};
  }

  static QualifiedName dimension_browse_name()
  {
    return QualifiedName{0, "Dimension"};
  }

  static QualifiedName server_units_browse_name()
  {
    return QualifiedName{0, "ServerUnits"};
  }
};

}  // namespace

Quantity::Quantity(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void Quantity::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    QuantityTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(QuantityResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(QuantityResult{
        Quantity{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)}, code});
    });
}

QuantityResult Quantity::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<QuantityResult>(addressSpace.executor(),
      [&](std::function<void(QuantityResult)> complete)
      {
        Quantity::create_async(std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Quantity Quantity::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void Quantity::create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
  const InstantiationOptions& options, CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void Quantity::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // QuantityType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    QuantityTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(QuantityResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(QuantityResult{::ua::detail::address_space_gone("Quantity")});
        return;
      }
      complete(Quantity{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

QuantityResult Quantity::try_attach_sync(AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<QuantityResult>(addressSpace.executor(),
      [&](std::function<void(QuantityResult)> complete)
      {
        Quantity::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Quantity Quantity::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void Quantity::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void Quantity::find_property_async(
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
    "Quantity",
    std::move(complete));
}

// --- Property accessors ---

void Quantity::symbol_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(QuantityTypeTraits::symbol_browse_name(), std::move(complete));
}

PropertyResult Quantity::try_symbol_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { symbol_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property Quantity::symbol_property_sync() const
{
  return ::ua::detail::good_value(try_symbol_property_sync());
}

void Quantity::annotation_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(QuantityTypeTraits::annotation_browse_name(), std::move(complete));
}

PropertyResult Quantity::try_annotation_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { annotation_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property Quantity::annotation_property_sync() const
{
  return ::ua::detail::good_value(try_annotation_property_sync());
}

void Quantity::conversion_service_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(QuantityTypeTraits::conversion_service_browse_name(), std::move(complete));
}

PropertyResult Quantity::try_conversion_service_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { conversion_service_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property Quantity::conversion_service_property_sync() const
{
  return ::ua::detail::good_value(try_conversion_service_property_sync());
}

void Quantity::dimension_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(QuantityTypeTraits::dimension_browse_name(), std::move(complete));
}

PropertyResult Quantity::try_dimension_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { dimension_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property Quantity::dimension_property_sync() const
{
  return ::ua::detail::good_value(try_dimension_property_sync());
}

// --- Typed value read shortcuts ---

void Quantity::read_symbol_async(std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    QuantityTypeTraits::symbol_browse_name(),
    &Variant::is_localized_text,
    {"Quantity", "symbol", "Quantity::read_symbol_async"},
    std::move(complete));
}

LocalizedTextResult Quantity::try_read_symbol_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LocalizedTextResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(LocalizedTextResult)> complete) { read_symbol_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LocalizedText Quantity::read_symbol_sync() const
{
  return ::ua::detail::good_value(try_read_symbol_sync());
}

// --- Typed value write shortcuts ---

void Quantity::write_symbol_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    QuantityTypeTraits::symbol_browse_name(),
    "Quantity",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult Quantity::try_write_symbol_sync(LocalizedText value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_symbol_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void Quantity::write_symbol_sync(LocalizedText value) const
{
  try_write_symbol_sync(value).value();
}

// --- Child-object accessors ---

void Quantity::server_units_async(std::function<void(BaseObjectResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BaseObjectResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<BaseObject>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    QuantityTypeTraits::server_units_browse_name(),
    "Quantity",
    std::move(complete));
}

BaseObjectResult Quantity::try_server_units_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseObjectResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseObjectResult)> complete) { server_units_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseObject Quantity::server_units_sync() const
{
  return ::ua::detail::good_value(try_server_units_sync());
}

}  // namespace ua
