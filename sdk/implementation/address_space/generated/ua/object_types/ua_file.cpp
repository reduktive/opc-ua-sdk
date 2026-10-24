// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_file.h"

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

struct FileTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::FileType};
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

  static QualifiedName open_browse_name()
  {
    return QualifiedName{0, "Open"};
  }

  static QualifiedName close_browse_name()
  {
    return QualifiedName{0, "Close"};
  }

  static QualifiedName read_browse_name()
  {
    return QualifiedName{0, "Read"};
  }

  static QualifiedName write_browse_name()
  {
    return QualifiedName{0, "Write"};
  }

  static QualifiedName get_position_browse_name()
  {
    return QualifiedName{0, "GetPosition"};
  }

  static QualifiedName set_position_browse_name()
  {
    return QualifiedName{0, "SetPosition"};
  }
};

}  // namespace

File::File(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void File::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    FileTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(FileResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(FileResult{
        File{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)}, code});
    });
}

FileResult File::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<FileResult>(addressSpace.executor(),
      [&](std::function<void(FileResult)> complete)
      {
        File::create_async(std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

File File::create_sync(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
  const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void File::create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
  const InstantiationOptions& options, CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void File::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // FileType has subtypes - subtype match.
  instance_utils::attach_subtype_async(addressSpace,
    existingInstance,
    FileTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(FileResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(FileResult{::ua::detail::address_space_gone("File")});
        return;
      }
      complete(File{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

FileResult File::try_attach_sync(AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<FileResult>(addressSpace.executor(),
      [&](std::function<void(FileResult)> complete)
      {
        File::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

File File::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void File::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

void File::open_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    FileTypeTraits::open_browse_name(),
    std::move(complete));
}

MethodAccessorResult File::try_open_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete) { open_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor File::open_method_sync() const
{
  return ::ua::detail::good_value(try_open_method_sync());
}

void File::close_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    FileTypeTraits::close_browse_name(),
    std::move(complete));
}

MethodAccessorResult File::try_close_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete) { close_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor File::close_method_sync() const
{
  return ::ua::detail::good_value(try_close_method_sync());
}

void File::read_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    FileTypeTraits::read_browse_name(),
    std::move(complete));
}

MethodAccessorResult File::try_read_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete) { read_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor File::read_method_sync() const
{
  return ::ua::detail::good_value(try_read_method_sync());
}

void File::write_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    FileTypeTraits::write_browse_name(),
    std::move(complete));
}

MethodAccessorResult File::try_write_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete) { write_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor File::write_method_sync() const
{
  return ::ua::detail::good_value(try_write_method_sync());
}

void File::get_position_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    FileTypeTraits::get_position_browse_name(),
    std::move(complete));
}

MethodAccessorResult File::try_get_position_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { get_position_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor File::get_position_method_sync() const
{
  return ::ua::detail::good_value(try_get_position_method_sync());
}

void File::set_position_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    FileTypeTraits::set_position_browse_name(),
    std::move(complete));
}

MethodAccessorResult File::try_set_position_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { set_position_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor File::set_position_method_sync() const
{
  return ::ua::detail::good_value(try_set_position_method_sync());
}

// --- Common property helper ---

void File::find_property_async(
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
    "File",
    std::move(complete));
}

// --- Property accessors ---

void File::size_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(FileTypeTraits::size_browse_name(), std::move(complete));
}

PropertyResult File::try_size_property_sync() const noexcept
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

Property File::size_property_sync() const
{
  return ::ua::detail::good_value(try_size_property_sync());
}

void File::writable_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(FileTypeTraits::writable_browse_name(), std::move(complete));
}

PropertyResult File::try_writable_property_sync() const noexcept
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

Property File::writable_property_sync() const
{
  return ::ua::detail::good_value(try_writable_property_sync());
}

void File::user_writable_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(FileTypeTraits::user_writable_browse_name(), std::move(complete));
}

PropertyResult File::try_user_writable_property_sync() const noexcept
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

Property File::user_writable_property_sync() const
{
  return ::ua::detail::good_value(try_user_writable_property_sync());
}

void File::open_count_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(FileTypeTraits::open_count_browse_name(), std::move(complete));
}

PropertyResult File::try_open_count_property_sync() const noexcept
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

Property File::open_count_property_sync() const
{
  return ::ua::detail::good_value(try_open_count_property_sync());
}

void File::mime_type_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(FileTypeTraits::mime_type_browse_name(), std::move(complete));
}

PropertyResult File::try_mime_type_property_sync() const noexcept
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

Property File::mime_type_property_sync() const
{
  return ::ua::detail::good_value(try_mime_type_property_sync());
}

void File::max_byte_string_length_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(FileTypeTraits::max_byte_string_length_browse_name(), std::move(complete));
}

PropertyResult File::try_max_byte_string_length_property_sync() const noexcept
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

Property File::max_byte_string_length_property_sync() const
{
  return ::ua::detail::good_value(try_max_byte_string_length_property_sync());
}

void File::last_modified_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(FileTypeTraits::last_modified_time_browse_name(), std::move(complete));
}

PropertyResult File::try_last_modified_time_property_sync() const noexcept
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

Property File::last_modified_time_property_sync() const
{
  return ::ua::detail::good_value(try_last_modified_time_property_sync());
}

// --- Typed value read shortcuts ---

void File::read_size_async(std::function<void(UInt64Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt64Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint64_t>(*mAddressSpace,
    mNodeId,
    FileTypeTraits::size_browse_name(),
    &Variant::is_uint64,
    {"File", "size", "File::read_size_async"},
    std::move(complete));
}

UInt64Result File::try_read_size_sync() const noexcept
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

uint64_t File::read_size_sync() const
{
  return ::ua::detail::good_value(try_read_size_sync());
}

void File::read_writable_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    FileTypeTraits::writable_browse_name(),
    &Variant::is_boolean,
    {"File", "writable", "File::read_writable_async"},
    std::move(complete));
}

BoolResult File::try_read_writable_sync() const noexcept
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

bool File::read_writable_sync() const
{
  return ::ua::detail::good_value(try_read_writable_sync());
}

void File::read_user_writable_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    FileTypeTraits::user_writable_browse_name(),
    &Variant::is_boolean,
    {"File", "user_writable", "File::read_user_writable_async"},
    std::move(complete));
}

BoolResult File::try_read_user_writable_sync() const noexcept
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

bool File::read_user_writable_sync() const
{
  return ::ua::detail::good_value(try_read_user_writable_sync());
}

void File::read_open_count_async(std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    FileTypeTraits::open_count_browse_name(),
    &Variant::is_uint16,
    {"File", "open_count", "File::read_open_count_async"},
    std::move(complete));
}

UInt16Result File::try_read_open_count_sync() const noexcept
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

uint16_t File::read_open_count_sync() const
{
  return ::ua::detail::good_value(try_read_open_count_sync());
}

void File::read_mime_type_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    FileTypeTraits::mime_type_browse_name(),
    &Variant::is_string,
    {"File", "mime_type", "File::read_mime_type_async"},
    std::move(complete));
}

StringResult File::try_read_mime_type_sync() const noexcept
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

String File::read_mime_type_sync() const
{
  return ::ua::detail::good_value(try_read_mime_type_sync());
}

void File::read_max_byte_string_length_async(std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    FileTypeTraits::max_byte_string_length_browse_name(),
    &Variant::is_uint32,
    {"File", "max_byte_string_length", "File::read_max_byte_string_length_async"},
    std::move(complete));
}

UInt32Result File::try_read_max_byte_string_length_sync() const noexcept
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

uint32_t File::read_max_byte_string_length_sync() const
{
  return ::ua::detail::good_value(try_read_max_byte_string_length_sync());
}

void File::read_last_modified_time_async(std::function<void(DateTimeResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DateTimeResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<DateTime>(*mAddressSpace,
    mNodeId,
    FileTypeTraits::last_modified_time_browse_name(),
    &Variant::is_date_time,
    {"File", "last_modified_time", "File::read_last_modified_time_async"},
    std::move(complete));
}

DateTimeResult File::try_read_last_modified_time_sync() const noexcept
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

DateTime File::read_last_modified_time_sync() const
{
  return ::ua::detail::good_value(try_read_last_modified_time_sync());
}

// --- Typed value write shortcuts ---

void File::write_size_async(uint64_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    FileTypeTraits::size_browse_name(),
    "File",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult File::try_write_size_sync(uint64_t value) const noexcept
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

void File::write_size_sync(uint64_t value) const
{
  try_write_size_sync(value).value();
}

void File::write_writable_async(bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    FileTypeTraits::writable_browse_name(),
    "File",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult File::try_write_writable_sync(bool value) const noexcept
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

void File::write_writable_sync(bool value) const
{
  try_write_writable_sync(value).value();
}

void File::write_user_writable_async(bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    FileTypeTraits::user_writable_browse_name(),
    "File",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult File::try_write_user_writable_sync(bool value) const noexcept
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

void File::write_user_writable_sync(bool value) const
{
  try_write_user_writable_sync(value).value();
}

void File::write_open_count_async(uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    FileTypeTraits::open_count_browse_name(),
    "File",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult File::try_write_open_count_sync(uint16_t value) const noexcept
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

void File::write_open_count_sync(uint16_t value) const
{
  try_write_open_count_sync(value).value();
}

void File::write_mime_type_async(String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    FileTypeTraits::mime_type_browse_name(),
    "File",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult File::try_write_mime_type_sync(String value) const noexcept
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

void File::write_mime_type_sync(String value) const
{
  try_write_mime_type_sync(value).value();
}

void File::write_max_byte_string_length_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    FileTypeTraits::max_byte_string_length_browse_name(),
    "File",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult File::try_write_max_byte_string_length_sync(uint32_t value) const noexcept
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

void File::write_max_byte_string_length_sync(uint32_t value) const
{
  try_write_max_byte_string_length_sync(value).value();
}

void File::write_last_modified_time_async(
  DateTime value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    FileTypeTraits::last_modified_time_browse_name(),
    "File",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult File::try_write_last_modified_time_sync(DateTime value) const noexcept
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

void File::write_last_modified_time_sync(DateTime value) const
{
  try_write_last_modified_time_sync(value).value();
}

// --- Method handler registration ---

void File::set_open_handler_async(OpenHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "File", "File::set_open_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<uint8_t>, std::tuple<uint32_t>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const uint8_t& in0) -> MethodResult<uint32_t>
      {
        OpenInputArguments typedIn{.mode = in0};
        return detail::method_result_from_struct<uint32_t>(handler(call, typedIn),
          [](const OpenOutputArguments& out) { return std::tuple<uint32_t>{out.fileHandle}; });
      },
      Inputs<uint8_t>{{Arg<uint8_t>{.name = "Mode"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, FileTypeTraits::open_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult File::try_set_open_handler_sync(OpenHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_open_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void File::set_open_handler_sync(OpenHandler handler) const
{
  try_set_open_handler_sync(std::move(handler)).value();
}

void File::set_open_handler_async(
  OpenAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "File", "File::set_open_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<uint8_t>, std::tuple<uint32_t>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const uint8_t& in0, MethodResultCallback<uint32_t> complete)
      {
        OpenInputArguments typedIn{.mode = in0};
        handler(call,
          typedIn,
          detail::struct_method_result_callback<OpenOutputArguments>(
            std::move(complete),
            [](const OpenOutputArguments& out) { return std::tuple<uint32_t>{out.fileHandle}; },
            logger,
            call.method_id()));
      },
      Inputs<uint8_t>{{Arg<uint8_t>{.name = "Mode"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, FileTypeTraits::open_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult File::try_set_open_handler_sync(OpenAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_open_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void File::set_open_handler_sync(OpenAsyncHandler handler) const
{
  try_set_open_handler_sync(std::move(handler)).value();
}

void File::set_close_handler_async(CloseHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "File", "File::set_close_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<uint32_t>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const uint32_t& in0) -> MethodResult<>
      {
        CloseInputArguments typedIn{.fileHandle = in0};
        return handler(call, typedIn);
      },
      Inputs<uint32_t>{{Arg<uint32_t>{.name = "FileHandle"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, FileTypeTraits::close_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult File::try_set_close_handler_sync(CloseHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_close_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void File::set_close_handler_sync(CloseHandler handler) const
{
  try_set_close_handler_sync(std::move(handler)).value();
}

void File::set_close_handler_async(
  CloseAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "File", "File::set_close_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<uint32_t>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const uint32_t& in0, MethodResultCallback<> complete)
      {
        CloseInputArguments typedIn{.fileHandle = in0};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<uint32_t>{{Arg<uint32_t>{.name = "FileHandle"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, FileTypeTraits::close_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult File::try_set_close_handler_sync(CloseAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_close_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void File::set_close_handler_sync(CloseAsyncHandler handler) const
{
  try_set_close_handler_sync(std::move(handler)).value();
}

void File::set_read_handler_async(ReadHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "File", "File::set_read_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<uint32_t, int32_t>, std::tuple<ByteString>> adapter{
      [handler = std::move(handler)](
        const MethodCall& call, const uint32_t& in0, const int32_t& in1) -> MethodResult<ByteString>
      {
        ReadInputArguments typedIn{.fileHandle = in0, .length = in1};
        return detail::method_result_from_struct<ByteString>(handler(call, typedIn),
          [](const ReadOutputArguments& out) { return std::tuple<ByteString>{out.data}; });
      },
      Inputs<uint32_t, int32_t>{{Arg<uint32_t>{.name = "FileHandle"}, Arg<int32_t>{.name = "Length"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, FileTypeTraits::read_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult File::try_set_read_handler_sync(ReadHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_read_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void File::set_read_handler_sync(ReadHandler handler) const
{
  try_set_read_handler_sync(std::move(handler)).value();
}

void File::set_read_handler_async(
  ReadAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "File", "File::set_read_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<uint32_t, int32_t>, std::tuple<ByteString>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](const MethodCall& call,
        const uint32_t& in0,
        const int32_t& in1,
        MethodResultCallback<ByteString>
          complete)
      {
        ReadInputArguments typedIn{.fileHandle = in0, .length = in1};
        handler(call,
          typedIn,
          detail::struct_method_result_callback<ReadOutputArguments>(
            std::move(complete),
            [](const ReadOutputArguments& out) { return std::tuple<ByteString>{out.data}; },
            logger,
            call.method_id()));
      },
      Inputs<uint32_t, int32_t>{{Arg<uint32_t>{.name = "FileHandle"}, Arg<int32_t>{.name = "Length"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, FileTypeTraits::read_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult File::try_set_read_handler_sync(ReadAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_read_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void File::set_read_handler_sync(ReadAsyncHandler handler) const
{
  try_set_read_handler_sync(std::move(handler)).value();
}

void File::set_write_handler_async(WriteHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "File", "File::set_write_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<uint32_t, ByteString>, std::tuple<>> adapter{
      [handler = std::move(handler)](
        const MethodCall& call, const uint32_t& in0, const ByteString& in1) -> MethodResult<>
      {
        WriteInputArguments typedIn{.fileHandle = in0, .data = in1};
        return handler(call, typedIn);
      },
      Inputs<uint32_t, ByteString>{{Arg<uint32_t>{.name = "FileHandle"}, Arg<ByteString>{.name = "Data"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, FileTypeTraits::write_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult File::try_set_write_handler_sync(WriteHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_write_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void File::set_write_handler_sync(WriteHandler handler) const
{
  try_set_write_handler_sync(std::move(handler)).value();
}

void File::set_write_handler_async(
  WriteAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "File", "File::set_write_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<uint32_t, ByteString>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const uint32_t& in0, const ByteString& in1, MethodResultCallback<> complete)
      {
        WriteInputArguments typedIn{.fileHandle = in0, .data = in1};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<uint32_t, ByteString>{{Arg<uint32_t>{.name = "FileHandle"}, Arg<ByteString>{.name = "Data"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, FileTypeTraits::write_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult File::try_set_write_handler_sync(WriteAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_write_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void File::set_write_handler_sync(WriteAsyncHandler handler) const
{
  try_set_write_handler_sync(std::move(handler)).value();
}

void File::set_get_position_handler_async(
  GetPositionHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "File", "File::set_get_position_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<uint32_t>, std::tuple<uint64_t>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const uint32_t& in0) -> MethodResult<uint64_t>
      {
        GetPositionInputArguments typedIn{.fileHandle = in0};
        return detail::method_result_from_struct<uint64_t>(handler(call, typedIn),
          [](const GetPositionOutputArguments& out) { return std::tuple<uint64_t>{out.position}; });
      },
      Inputs<uint32_t>{{Arg<uint32_t>{.name = "FileHandle"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, FileTypeTraits::get_position_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult File::try_set_get_position_handler_sync(GetPositionHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_get_position_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void File::set_get_position_handler_sync(GetPositionHandler handler) const
{
  try_set_get_position_handler_sync(std::move(handler)).value();
}

void File::set_get_position_handler_async(
  GetPositionAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "File", "File::set_get_position_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<uint32_t>, std::tuple<uint64_t>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const uint32_t& in0, MethodResultCallback<uint64_t> complete)
      {
        GetPositionInputArguments typedIn{.fileHandle = in0};
        handler(call,
          typedIn,
          detail::struct_method_result_callback<GetPositionOutputArguments>(
            std::move(complete),
            [](const GetPositionOutputArguments& out) { return std::tuple<uint64_t>{out.position}; },
            logger,
            call.method_id()));
      },
      Inputs<uint32_t>{{Arg<uint32_t>{.name = "FileHandle"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, FileTypeTraits::get_position_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult File::try_set_get_position_handler_sync(GetPositionAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_get_position_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void File::set_get_position_handler_sync(GetPositionAsyncHandler handler) const
{
  try_set_get_position_handler_sync(std::move(handler)).value();
}

void File::set_set_position_handler_async(
  SetPositionHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "File", "File::set_set_position_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<uint32_t, uint64_t>, std::tuple<>> adapter{
      [handler = std::move(handler)](
        const MethodCall& call, const uint32_t& in0, const uint64_t& in1) -> MethodResult<>
      {
        SetPositionInputArguments typedIn{.fileHandle = in0, .position = in1};
        return handler(call, typedIn);
      },
      Inputs<uint32_t, uint64_t>{{Arg<uint32_t>{.name = "FileHandle"}, Arg<uint64_t>{.name = "Position"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, FileTypeTraits::set_position_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult File::try_set_set_position_handler_sync(SetPositionHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_set_position_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void File::set_set_position_handler_sync(SetPositionHandler handler) const
{
  try_set_set_position_handler_sync(std::move(handler)).value();
}

void File::set_set_position_handler_async(
  SetPositionAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "File", "File::set_set_position_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<uint32_t, uint64_t>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const uint32_t& in0, const uint64_t& in1, MethodResultCallback<> complete)
      {
        SetPositionInputArguments typedIn{.fileHandle = in0, .position = in1};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<uint32_t, uint64_t>{{Arg<uint32_t>{.name = "FileHandle"}, Arg<uint64_t>{.name = "Position"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, FileTypeTraits::set_position_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult File::try_set_set_position_handler_sync(SetPositionAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_set_position_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void File::set_set_position_handler_sync(SetPositionAsyncHandler handler) const
{
  try_set_set_position_handler_sync(std::move(handler)).value();
}

}  // namespace ua
