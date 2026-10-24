// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_trust_list.h"

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

struct TrustListTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::TrustListType};
  }

  static QualifiedName last_update_time_browse_name()
  {
    return QualifiedName{0, "LastUpdateTime"};
  }

  static QualifiedName update_frequency_browse_name()
  {
    return QualifiedName{0, "UpdateFrequency"};
  }

  static QualifiedName activity_timeout_browse_name()
  {
    return QualifiedName{0, "ActivityTimeout"};
  }

  static QualifiedName default_validation_options_browse_name()
  {
    return QualifiedName{0, "DefaultValidationOptions"};
  }

  static QualifiedName open_with_masks_browse_name()
  {
    return QualifiedName{0, "OpenWithMasks"};
  }

  static QualifiedName close_and_update_browse_name()
  {
    return QualifiedName{0, "CloseAndUpdate"};
  }

  static QualifiedName add_certificate_browse_name()
  {
    return QualifiedName{0, "AddCertificate"};
  }

  static QualifiedName remove_certificate_browse_name()
  {
    return QualifiedName{0, "RemoveCertificate"};
  }

  static QualifiedName size_browse_name()
  {
    return QualifiedName{0, "Size"};
  }

  static QualifiedName writable_browse_name()
  {
    return QualifiedName{0, "Writable"};
  }

  static QualifiedName user_writable_browse_name()
  {
    return QualifiedName{0, "UserWritable"};
  }

  static QualifiedName open_count_browse_name()
  {
    return QualifiedName{0, "OpenCount"};
  }

  static QualifiedName mime_type_browse_name()
  {
    return QualifiedName{0, "MimeType"};
  }

  static QualifiedName max_byte_string_length_browse_name()
  {
    return QualifiedName{0, "MaxByteStringLength"};
  }

  static QualifiedName last_modified_time_browse_name()
  {
    return QualifiedName{0, "LastModifiedTime"};
  }
};

}  // namespace

TrustList::TrustList(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void TrustList::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    TrustListTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(TrustListResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(TrustListResult{
        TrustList{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)}, code});
    });
}

TrustListResult TrustList::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TrustListResult>(addressSpace.executor(),
      [&](std::function<void(TrustListResult)> complete)
      {
        TrustList::create_async(std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TrustList TrustList::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void TrustList::create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
  const InstantiationOptions& options, CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void TrustList::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // TrustListType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    TrustListTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(TrustListResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(TrustListResult{::ua::detail::address_space_gone("TrustList")});
        return;
      }
      complete(TrustList{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

TrustListResult TrustList::try_attach_sync(AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TrustListResult>(addressSpace.executor(),
      [&](std::function<void(TrustListResult)> complete)
      {
        TrustList::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TrustList TrustList::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void TrustList::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

void TrustList::open_with_masks_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    TrustListTypeTraits::open_with_masks_browse_name(),
    std::move(complete));
}

MethodAccessorResult TrustList::try_open_with_masks_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { open_with_masks_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor TrustList::open_with_masks_method_sync() const
{
  return ::ua::detail::good_value(try_open_with_masks_method_sync());
}

void TrustList::close_and_update_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    TrustListTypeTraits::close_and_update_browse_name(),
    std::move(complete));
}

MethodAccessorResult TrustList::try_close_and_update_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { close_and_update_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor TrustList::close_and_update_method_sync() const
{
  return ::ua::detail::good_value(try_close_and_update_method_sync());
}

void TrustList::add_certificate_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    TrustListTypeTraits::add_certificate_browse_name(),
    std::move(complete));
}

MethodAccessorResult TrustList::try_add_certificate_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { add_certificate_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor TrustList::add_certificate_method_sync() const
{
  return ::ua::detail::good_value(try_add_certificate_method_sync());
}

void TrustList::remove_certificate_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    TrustListTypeTraits::remove_certificate_browse_name(),
    std::move(complete));
}

MethodAccessorResult TrustList::try_remove_certificate_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { remove_certificate_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor TrustList::remove_certificate_method_sync() const
{
  return ::ua::detail::good_value(try_remove_certificate_method_sync());
}

// --- Common property helper ---

void TrustList::find_property_async(
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
    "TrustList",
    std::move(complete));
}

// --- Property accessors ---

void TrustList::last_update_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TrustListTypeTraits::last_update_time_browse_name(), std::move(complete));
}

PropertyResult TrustList::try_last_update_time_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { last_update_time_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property TrustList::last_update_time_property_sync() const
{
  return ::ua::detail::good_value(try_last_update_time_property_sync());
}

void TrustList::update_frequency_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TrustListTypeTraits::update_frequency_browse_name(), std::move(complete));
}

PropertyResult TrustList::try_update_frequency_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { update_frequency_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property TrustList::update_frequency_property_sync() const
{
  return ::ua::detail::good_value(try_update_frequency_property_sync());
}

void TrustList::activity_timeout_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TrustListTypeTraits::activity_timeout_browse_name(), std::move(complete));
}

PropertyResult TrustList::try_activity_timeout_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { activity_timeout_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property TrustList::activity_timeout_property_sync() const
{
  return ::ua::detail::good_value(try_activity_timeout_property_sync());
}

void TrustList::default_validation_options_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TrustListTypeTraits::default_validation_options_browse_name(), std::move(complete));
}

PropertyResult TrustList::try_default_validation_options_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { default_validation_options_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property TrustList::default_validation_options_property_sync() const
{
  return ::ua::detail::good_value(try_default_validation_options_property_sync());
}

void TrustList::size_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TrustListTypeTraits::size_browse_name(), std::move(complete));
}

PropertyResult TrustList::try_size_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { size_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property TrustList::size_property_sync() const
{
  return ::ua::detail::good_value(try_size_property_sync());
}

void TrustList::writable_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TrustListTypeTraits::writable_browse_name(), std::move(complete));
}

PropertyResult TrustList::try_writable_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { writable_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property TrustList::writable_property_sync() const
{
  return ::ua::detail::good_value(try_writable_property_sync());
}

void TrustList::user_writable_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TrustListTypeTraits::user_writable_browse_name(), std::move(complete));
}

PropertyResult TrustList::try_user_writable_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { user_writable_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property TrustList::user_writable_property_sync() const
{
  return ::ua::detail::good_value(try_user_writable_property_sync());
}

void TrustList::open_count_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TrustListTypeTraits::open_count_browse_name(), std::move(complete));
}

PropertyResult TrustList::try_open_count_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { open_count_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property TrustList::open_count_property_sync() const
{
  return ::ua::detail::good_value(try_open_count_property_sync());
}

void TrustList::mime_type_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TrustListTypeTraits::mime_type_browse_name(), std::move(complete));
}

PropertyResult TrustList::try_mime_type_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { mime_type_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property TrustList::mime_type_property_sync() const
{
  return ::ua::detail::good_value(try_mime_type_property_sync());
}

void TrustList::max_byte_string_length_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TrustListTypeTraits::max_byte_string_length_browse_name(), std::move(complete));
}

PropertyResult TrustList::try_max_byte_string_length_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_byte_string_length_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property TrustList::max_byte_string_length_property_sync() const
{
  return ::ua::detail::good_value(try_max_byte_string_length_property_sync());
}

void TrustList::last_modified_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TrustListTypeTraits::last_modified_time_browse_name(), std::move(complete));
}

PropertyResult TrustList::try_last_modified_time_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { last_modified_time_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property TrustList::last_modified_time_property_sync() const
{
  return ::ua::detail::good_value(try_last_modified_time_property_sync());
}

// --- Typed value read shortcuts ---

void TrustList::read_size_async(std::function<void(UInt64Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt64Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint64_t>(*mAddressSpace,
    mNodeId,
    TrustListTypeTraits::size_browse_name(),
    &Variant::is_uint64,
    {"TrustList", "size", "TrustList::read_size_async"},
    std::move(complete));
}

UInt64Result TrustList::try_read_size_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt64Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt64Result)> complete) { read_size_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint64_t TrustList::read_size_sync() const
{
  return ::ua::detail::good_value(try_read_size_sync());
}

void TrustList::read_writable_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    TrustListTypeTraits::writable_browse_name(),
    &Variant::is_boolean,
    {"TrustList", "writable", "TrustList::read_writable_async"},
    std::move(complete));
}

BoolResult TrustList::try_read_writable_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BoolResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BoolResult)> complete) { read_writable_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

bool TrustList::read_writable_sync() const
{
  return ::ua::detail::good_value(try_read_writable_sync());
}

void TrustList::read_user_writable_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    TrustListTypeTraits::user_writable_browse_name(),
    &Variant::is_boolean,
    {"TrustList", "user_writable", "TrustList::read_user_writable_async"},
    std::move(complete));
}

BoolResult TrustList::try_read_user_writable_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BoolResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BoolResult)> complete) { read_user_writable_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

bool TrustList::read_user_writable_sync() const
{
  return ::ua::detail::good_value(try_read_user_writable_sync());
}

void TrustList::read_open_count_async(std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    TrustListTypeTraits::open_count_browse_name(),
    &Variant::is_uint16,
    {"TrustList", "open_count", "TrustList::read_open_count_async"},
    std::move(complete));
}

UInt16Result TrustList::try_read_open_count_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt16Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt16Result)> complete) { read_open_count_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint16_t TrustList::read_open_count_sync() const
{
  return ::ua::detail::good_value(try_read_open_count_sync());
}

void TrustList::read_mime_type_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    TrustListTypeTraits::mime_type_browse_name(),
    &Variant::is_string,
    {"TrustList", "mime_type", "TrustList::read_mime_type_async"},
    std::move(complete));
}

StringResult TrustList::try_read_mime_type_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_mime_type_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String TrustList::read_mime_type_sync() const
{
  return ::ua::detail::good_value(try_read_mime_type_sync());
}

void TrustList::read_max_byte_string_length_async(std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    TrustListTypeTraits::max_byte_string_length_browse_name(),
    &Variant::is_uint32,
    {"TrustList", "max_byte_string_length", "TrustList::read_max_byte_string_length_async"},
    std::move(complete));
}

UInt32Result TrustList::try_read_max_byte_string_length_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete)
      { read_max_byte_string_length_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t TrustList::read_max_byte_string_length_sync() const
{
  return ::ua::detail::good_value(try_read_max_byte_string_length_sync());
}

void TrustList::read_last_modified_time_async(std::function<void(DateTimeResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DateTimeResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<DateTime>(*mAddressSpace,
    mNodeId,
    TrustListTypeTraits::last_modified_time_browse_name(),
    &Variant::is_date_time,
    {"TrustList", "last_modified_time", "TrustList::read_last_modified_time_async"},
    std::move(complete));
}

DateTimeResult TrustList::try_read_last_modified_time_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<DateTimeResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(DateTimeResult)> complete)
      { read_last_modified_time_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

DateTime TrustList::read_last_modified_time_sync() const
{
  return ::ua::detail::good_value(try_read_last_modified_time_sync());
}

// --- Typed value write shortcuts ---

void TrustList::write_size_async(uint64_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    TrustListTypeTraits::size_browse_name(),
    "TrustList",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult TrustList::try_write_size_sync(uint64_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_size_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TrustList::write_size_sync(uint64_t value) const
{
  try_write_size_sync(value).value();
}

void TrustList::write_writable_async(bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    TrustListTypeTraits::writable_browse_name(),
    "TrustList",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult TrustList::try_write_writable_sync(bool value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_writable_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TrustList::write_writable_sync(bool value) const
{
  try_write_writable_sync(value).value();
}

void TrustList::write_user_writable_async(bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    TrustListTypeTraits::user_writable_browse_name(),
    "TrustList",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult TrustList::try_write_user_writable_sync(bool value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_user_writable_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TrustList::write_user_writable_sync(bool value) const
{
  try_write_user_writable_sync(value).value();
}

void TrustList::write_open_count_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    TrustListTypeTraits::open_count_browse_name(),
    "TrustList",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult TrustList::try_write_open_count_sync(uint16_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_open_count_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TrustList::write_open_count_sync(uint16_t value) const
{
  try_write_open_count_sync(value).value();
}

void TrustList::write_mime_type_async(String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    TrustListTypeTraits::mime_type_browse_name(),
    "TrustList",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult TrustList::try_write_mime_type_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_mime_type_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TrustList::write_mime_type_sync(String value) const
{
  try_write_mime_type_sync(value).value();
}

void TrustList::write_max_byte_string_length_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    TrustListTypeTraits::max_byte_string_length_browse_name(),
    "TrustList",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult TrustList::try_write_max_byte_string_length_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_byte_string_length_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TrustList::write_max_byte_string_length_sync(uint32_t value) const
{
  try_write_max_byte_string_length_sync(value).value();
}

void TrustList::write_last_modified_time_async(
  DateTime value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    TrustListTypeTraits::last_modified_time_browse_name(),
    "TrustList",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult TrustList::try_write_last_modified_time_sync(DateTime value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_last_modified_time_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TrustList::write_last_modified_time_sync(DateTime value) const
{
  try_write_last_modified_time_sync(value).value();
}

// --- Method handler registration ---

void TrustList::set_open_with_masks_handler_async(
  OpenWithMasksHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "TrustList",
        "TrustList::set_open_with_masks_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<uint32_t>, std::tuple<uint32_t>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const uint32_t& in0) -> MethodResult<uint32_t>
      {
        OpenWithMasksInputArguments typedIn{.masks = in0};
        return detail::method_result_from_struct<uint32_t>(handler(call, typedIn),
          [](const OpenWithMasksOutputArguments& out) { return std::tuple<uint32_t>{out.fileHandle}; });
      },
      Inputs<uint32_t>{{Arg<uint32_t>{.name = "Masks"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, TrustListTypeTraits::open_with_masks_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult TrustList::try_set_open_with_masks_handler_sync(OpenWithMasksHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_open_with_masks_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TrustList::set_open_with_masks_handler_sync(OpenWithMasksHandler handler) const
{
  try_set_open_with_masks_handler_sync(std::move(handler)).value();
}

void TrustList::set_open_with_masks_handler_async(
  OpenWithMasksAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "TrustList",
        "TrustList::set_open_with_masks_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<uint32_t>, std::tuple<uint32_t>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const uint32_t& in0, MethodResultCallback<uint32_t> complete)
      {
        OpenWithMasksInputArguments typedIn{.masks = in0};
        handler(call,
          typedIn,
          detail::struct_method_result_callback<OpenWithMasksOutputArguments>(
            std::move(complete),
            [](const OpenWithMasksOutputArguments& out) { return std::tuple<uint32_t>{out.fileHandle}; },
            logger,
            call.method_id()));
      },
      Inputs<uint32_t>{{Arg<uint32_t>{.name = "Masks"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, TrustListTypeTraits::open_with_masks_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult TrustList::try_set_open_with_masks_handler_sync(OpenWithMasksAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_open_with_masks_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TrustList::set_open_with_masks_handler_sync(OpenWithMasksAsyncHandler handler) const
{
  try_set_open_with_masks_handler_sync(std::move(handler)).value();
}

void TrustList::set_close_and_update_handler_async(
  CloseAndUpdateHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "TrustList",
        "TrustList::set_close_and_update_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<uint32_t>, std::tuple<bool>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const uint32_t& in0) -> MethodResult<bool>
      {
        CloseAndUpdateInputArguments typedIn{.fileHandle = in0};
        return detail::method_result_from_struct<bool>(handler(call, typedIn),
          [](const CloseAndUpdateOutputArguments& out)
          { return std::tuple<bool>{out.applyChangesRequired}; });
      },
      Inputs<uint32_t>{{Arg<uint32_t>{.name = "FileHandle"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, TrustListTypeTraits::close_and_update_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult TrustList::try_set_close_and_update_handler_sync(CloseAndUpdateHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_close_and_update_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TrustList::set_close_and_update_handler_sync(CloseAndUpdateHandler handler) const
{
  try_set_close_and_update_handler_sync(std::move(handler)).value();
}

void TrustList::set_close_and_update_handler_async(
  CloseAndUpdateAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "TrustList",
        "TrustList::set_close_and_update_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<uint32_t>, std::tuple<bool>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const uint32_t& in0, MethodResultCallback<bool> complete)
      {
        CloseAndUpdateInputArguments typedIn{.fileHandle = in0};
        handler(call,
          typedIn,
          detail::struct_method_result_callback<CloseAndUpdateOutputArguments>(
            std::move(complete),
            [](const CloseAndUpdateOutputArguments& out)
            { return std::tuple<bool>{out.applyChangesRequired}; },
            logger,
            call.method_id()));
      },
      Inputs<uint32_t>{{Arg<uint32_t>{.name = "FileHandle"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, TrustListTypeTraits::close_and_update_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult TrustList::try_set_close_and_update_handler_sync(CloseAndUpdateAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_close_and_update_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TrustList::set_close_and_update_handler_sync(CloseAndUpdateAsyncHandler handler) const
{
  try_set_close_and_update_handler_sync(std::move(handler)).value();
}

void TrustList::set_add_certificate_handler_async(
  AddCertificateHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "TrustList",
        "TrustList::set_add_certificate_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<ByteString, bool>, std::tuple<>> adapter{
      [handler = std::move(handler)](
        const MethodCall& call, const ByteString& in0, const bool& in1) -> MethodResult<>
      {
        AddCertificateInputArguments typedIn{.certificate = in0, .isTrustedCertificate = in1};
        return handler(call, typedIn);
      },
      Inputs<ByteString, bool>{
        {Arg<ByteString>{.name = "Certificate"}, Arg<bool>{.name = "IsTrustedCertificate"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, TrustListTypeTraits::add_certificate_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult TrustList::try_set_add_certificate_handler_sync(AddCertificateHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_add_certificate_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TrustList::set_add_certificate_handler_sync(AddCertificateHandler handler) const
{
  try_set_add_certificate_handler_sync(std::move(handler)).value();
}

void TrustList::set_add_certificate_handler_async(
  AddCertificateAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "TrustList",
        "TrustList::set_add_certificate_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<ByteString, bool>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const ByteString& in0, const bool& in1, MethodResultCallback<> complete)
      {
        AddCertificateInputArguments typedIn{.certificate = in0, .isTrustedCertificate = in1};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<ByteString, bool>{
        {Arg<ByteString>{.name = "Certificate"}, Arg<bool>{.name = "IsTrustedCertificate"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, TrustListTypeTraits::add_certificate_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult TrustList::try_set_add_certificate_handler_sync(AddCertificateAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_add_certificate_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TrustList::set_add_certificate_handler_sync(AddCertificateAsyncHandler handler) const
{
  try_set_add_certificate_handler_sync(std::move(handler)).value();
}

void TrustList::set_remove_certificate_handler_async(
  RemoveCertificateHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "TrustList",
        "TrustList::set_remove_certificate_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String, bool>, std::tuple<>> adapter{
      [handler = std::move(handler)](
        const MethodCall& call, const String& in0, const bool& in1) -> MethodResult<>
      {
        RemoveCertificateInputArguments typedIn{.thumbprint = in0, .isTrustedCertificate = in1};
        return handler(call, typedIn);
      },
      Inputs<String, bool>{{Arg<String>{.name = "Thumbprint"}, Arg<bool>{.name = "IsTrustedCertificate"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      TrustListTypeTraits::remove_certificate_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult TrustList::try_set_remove_certificate_handler_sync(RemoveCertificateHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_remove_certificate_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TrustList::set_remove_certificate_handler_sync(RemoveCertificateHandler handler) const
{
  try_set_remove_certificate_handler_sync(std::move(handler)).value();
}

void TrustList::set_remove_certificate_handler_async(
  RemoveCertificateAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "TrustList",
        "TrustList::set_remove_certificate_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String, bool>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const String& in0, const bool& in1, MethodResultCallback<> complete)
      {
        RemoveCertificateInputArguments typedIn{.thumbprint = in0, .isTrustedCertificate = in1};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<String, bool>{{Arg<String>{.name = "Thumbprint"}, Arg<bool>{.name = "IsTrustedCertificate"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      TrustListTypeTraits::remove_certificate_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult TrustList::try_set_remove_certificate_handler_sync(
  RemoveCertificateAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_remove_certificate_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TrustList::set_remove_certificate_handler_sync(RemoveCertificateAsyncHandler handler) const
{
  try_set_remove_certificate_handler_sync(std::move(handler)).value();
}

}  // namespace ua
