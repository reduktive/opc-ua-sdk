// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_address_space_file.h"

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

struct AddressSpaceFileTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::AddressSpaceFileType};
  }

  static QualifiedName export_namespace_browse_name()
  {
    return QualifiedName{0, "ExportNamespace"};
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

AddressSpaceFile::AddressSpaceFile(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void AddressSpaceFile::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    AddressSpaceFileTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(AddressSpaceFileResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(AddressSpaceFileResult{
        AddressSpaceFile{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

AddressSpaceFileResult AddressSpaceFile::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<AddressSpaceFileResult>(addressSpace.executor(),
      [&](std::function<void(AddressSpaceFileResult)> complete)
      {
        AddressSpaceFile::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

AddressSpaceFile AddressSpaceFile::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void AddressSpaceFile::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void AddressSpaceFile::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // AddressSpaceFileType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    AddressSpaceFileTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(AddressSpaceFileResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(AddressSpaceFileResult{::ua::detail::address_space_gone("AddressSpaceFile")});
        return;
      }
      complete(AddressSpaceFile{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

AddressSpaceFileResult AddressSpaceFile::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<AddressSpaceFileResult>(addressSpace.executor(),
      [&](std::function<void(AddressSpaceFileResult)> complete)
      {
        AddressSpaceFile::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

AddressSpaceFile AddressSpaceFile::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void AddressSpaceFile::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

void AddressSpaceFile::export_namespace_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AddressSpaceFileTypeTraits::export_namespace_browse_name(),
    std::move(complete));
}

MethodAccessorResult AddressSpaceFile::try_export_namespace_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { export_namespace_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor AddressSpaceFile::export_namespace_method_sync() const
{
  return ::ua::detail::good_value(try_export_namespace_method_sync());
}

// --- Common property helper ---

void AddressSpaceFile::find_property_async(
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
    "AddressSpaceFile",
    std::move(complete));
}

// --- Property accessors ---

void AddressSpaceFile::size_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AddressSpaceFileTypeTraits::size_browse_name(), std::move(complete));
}

PropertyResult AddressSpaceFile::try_size_property_sync() const noexcept
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

Property AddressSpaceFile::size_property_sync() const
{
  return ::ua::detail::good_value(try_size_property_sync());
}

void AddressSpaceFile::writable_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AddressSpaceFileTypeTraits::writable_browse_name(), std::move(complete));
}

PropertyResult AddressSpaceFile::try_writable_property_sync() const noexcept
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

Property AddressSpaceFile::writable_property_sync() const
{
  return ::ua::detail::good_value(try_writable_property_sync());
}

void AddressSpaceFile::user_writable_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AddressSpaceFileTypeTraits::user_writable_browse_name(), std::move(complete));
}

PropertyResult AddressSpaceFile::try_user_writable_property_sync() const noexcept
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

Property AddressSpaceFile::user_writable_property_sync() const
{
  return ::ua::detail::good_value(try_user_writable_property_sync());
}

void AddressSpaceFile::open_count_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AddressSpaceFileTypeTraits::open_count_browse_name(), std::move(complete));
}

PropertyResult AddressSpaceFile::try_open_count_property_sync() const noexcept
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

Property AddressSpaceFile::open_count_property_sync() const
{
  return ::ua::detail::good_value(try_open_count_property_sync());
}

void AddressSpaceFile::mime_type_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AddressSpaceFileTypeTraits::mime_type_browse_name(), std::move(complete));
}

PropertyResult AddressSpaceFile::try_mime_type_property_sync() const noexcept
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

Property AddressSpaceFile::mime_type_property_sync() const
{
  return ::ua::detail::good_value(try_mime_type_property_sync());
}

void AddressSpaceFile::max_byte_string_length_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AddressSpaceFileTypeTraits::max_byte_string_length_browse_name(), std::move(complete));
}

PropertyResult AddressSpaceFile::try_max_byte_string_length_property_sync() const noexcept
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

Property AddressSpaceFile::max_byte_string_length_property_sync() const
{
  return ::ua::detail::good_value(try_max_byte_string_length_property_sync());
}

void AddressSpaceFile::last_modified_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AddressSpaceFileTypeTraits::last_modified_time_browse_name(), std::move(complete));
}

PropertyResult AddressSpaceFile::try_last_modified_time_property_sync() const noexcept
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

Property AddressSpaceFile::last_modified_time_property_sync() const
{
  return ::ua::detail::good_value(try_last_modified_time_property_sync());
}

// --- Typed value read shortcuts ---

void AddressSpaceFile::read_size_async(std::function<void(UInt64Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt64Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint64_t>(*mAddressSpace,
    mNodeId,
    AddressSpaceFileTypeTraits::size_browse_name(),
    &Variant::is_uint64,
    {"AddressSpaceFile", "size", "AddressSpaceFile::read_size_async"},
    std::move(complete));
}

UInt64Result AddressSpaceFile::try_read_size_sync() const noexcept
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

uint64_t AddressSpaceFile::read_size_sync() const
{
  return ::ua::detail::good_value(try_read_size_sync());
}

void AddressSpaceFile::read_writable_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    AddressSpaceFileTypeTraits::writable_browse_name(),
    &Variant::is_boolean,
    {"AddressSpaceFile", "writable", "AddressSpaceFile::read_writable_async"},
    std::move(complete));
}

BoolResult AddressSpaceFile::try_read_writable_sync() const noexcept
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

bool AddressSpaceFile::read_writable_sync() const
{
  return ::ua::detail::good_value(try_read_writable_sync());
}

void AddressSpaceFile::read_user_writable_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    AddressSpaceFileTypeTraits::user_writable_browse_name(),
    &Variant::is_boolean,
    {"AddressSpaceFile", "user_writable", "AddressSpaceFile::read_user_writable_async"},
    std::move(complete));
}

BoolResult AddressSpaceFile::try_read_user_writable_sync() const noexcept
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

bool AddressSpaceFile::read_user_writable_sync() const
{
  return ::ua::detail::good_value(try_read_user_writable_sync());
}

void AddressSpaceFile::read_open_count_async(std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    AddressSpaceFileTypeTraits::open_count_browse_name(),
    &Variant::is_uint16,
    {"AddressSpaceFile", "open_count", "AddressSpaceFile::read_open_count_async"},
    std::move(complete));
}

UInt16Result AddressSpaceFile::try_read_open_count_sync() const noexcept
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

uint16_t AddressSpaceFile::read_open_count_sync() const
{
  return ::ua::detail::good_value(try_read_open_count_sync());
}

void AddressSpaceFile::read_mime_type_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    AddressSpaceFileTypeTraits::mime_type_browse_name(),
    &Variant::is_string,
    {"AddressSpaceFile", "mime_type", "AddressSpaceFile::read_mime_type_async"},
    std::move(complete));
}

StringResult AddressSpaceFile::try_read_mime_type_sync() const noexcept
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

String AddressSpaceFile::read_mime_type_sync() const
{
  return ::ua::detail::good_value(try_read_mime_type_sync());
}

void AddressSpaceFile::read_max_byte_string_length_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    AddressSpaceFileTypeTraits::max_byte_string_length_browse_name(),
    &Variant::is_uint32,
    {"AddressSpaceFile", "max_byte_string_length", "AddressSpaceFile::read_max_byte_string_length_async"},
    std::move(complete));
}

UInt32Result AddressSpaceFile::try_read_max_byte_string_length_sync() const noexcept
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

uint32_t AddressSpaceFile::read_max_byte_string_length_sync() const
{
  return ::ua::detail::good_value(try_read_max_byte_string_length_sync());
}

void AddressSpaceFile::read_last_modified_time_async(
  std::function<void(DateTimeResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DateTimeResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<DateTime>(*mAddressSpace,
    mNodeId,
    AddressSpaceFileTypeTraits::last_modified_time_browse_name(),
    &Variant::is_date_time,
    {"AddressSpaceFile", "last_modified_time", "AddressSpaceFile::read_last_modified_time_async"},
    std::move(complete));
}

DateTimeResult AddressSpaceFile::try_read_last_modified_time_sync() const noexcept
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

DateTime AddressSpaceFile::read_last_modified_time_sync() const
{
  return ::ua::detail::good_value(try_read_last_modified_time_sync());
}

// --- Typed value write shortcuts ---

void AddressSpaceFile::write_size_async(
  uint64_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AddressSpaceFileTypeTraits::size_browse_name(),
    "AddressSpaceFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AddressSpaceFile::try_write_size_sync(uint64_t value) const noexcept
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

void AddressSpaceFile::write_size_sync(uint64_t value) const
{
  try_write_size_sync(value).value();
}

void AddressSpaceFile::write_writable_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AddressSpaceFileTypeTraits::writable_browse_name(),
    "AddressSpaceFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AddressSpaceFile::try_write_writable_sync(bool value) const noexcept
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

void AddressSpaceFile::write_writable_sync(bool value) const
{
  try_write_writable_sync(value).value();
}

void AddressSpaceFile::write_user_writable_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AddressSpaceFileTypeTraits::user_writable_browse_name(),
    "AddressSpaceFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AddressSpaceFile::try_write_user_writable_sync(bool value) const noexcept
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

void AddressSpaceFile::write_user_writable_sync(bool value) const
{
  try_write_user_writable_sync(value).value();
}

void AddressSpaceFile::write_open_count_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AddressSpaceFileTypeTraits::open_count_browse_name(),
    "AddressSpaceFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AddressSpaceFile::try_write_open_count_sync(uint16_t value) const noexcept
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

void AddressSpaceFile::write_open_count_sync(uint16_t value) const
{
  try_write_open_count_sync(value).value();
}

void AddressSpaceFile::write_mime_type_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AddressSpaceFileTypeTraits::mime_type_browse_name(),
    "AddressSpaceFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AddressSpaceFile::try_write_mime_type_sync(String value) const noexcept
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

void AddressSpaceFile::write_mime_type_sync(String value) const
{
  try_write_mime_type_sync(value).value();
}

void AddressSpaceFile::write_max_byte_string_length_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AddressSpaceFileTypeTraits::max_byte_string_length_browse_name(),
    "AddressSpaceFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AddressSpaceFile::try_write_max_byte_string_length_sync(uint32_t value) const noexcept
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

void AddressSpaceFile::write_max_byte_string_length_sync(uint32_t value) const
{
  try_write_max_byte_string_length_sync(value).value();
}

void AddressSpaceFile::write_last_modified_time_async(
  DateTime value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AddressSpaceFileTypeTraits::last_modified_time_browse_name(),
    "AddressSpaceFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AddressSpaceFile::try_write_last_modified_time_sync(DateTime value) const noexcept
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

void AddressSpaceFile::write_last_modified_time_sync(DateTime value) const
{
  try_write_last_modified_time_sync(value).value();
}

// --- Method handler registration ---

void AddressSpaceFile::set_export_namespace_handler_async(
  ExportNamespaceHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AddressSpaceFile",
        "AddressSpaceFile::set_export_namespace_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call) -> MethodResult<> { return handler(call); },
      Inputs<>{},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      AddressSpaceFileTypeTraits::export_namespace_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AddressSpaceFile::try_set_export_namespace_handler_sync(
  ExportNamespaceHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_export_namespace_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AddressSpaceFile::set_export_namespace_handler_sync(ExportNamespaceHandler handler) const
{
  try_set_export_namespace_handler_sync(std::move(handler)).value();
}

void AddressSpaceFile::set_export_namespace_handler_async(
  ExportNamespaceAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AddressSpaceFile",
        "AddressSpaceFile::set_export_namespace_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, MethodResultCallback<> complete) { handler(call, std::move(complete)); },
      Inputs<>{},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      AddressSpaceFileTypeTraits::export_namespace_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AddressSpaceFile::try_set_export_namespace_handler_sync(
  ExportNamespaceAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_export_namespace_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AddressSpaceFile::set_export_namespace_handler_sync(ExportNamespaceAsyncHandler handler) const
{
  try_set_export_namespace_handler_sync(std::move(handler)).value();
}

}  // namespace ua
