// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_configuration_file.h"

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

struct ConfigurationFileTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::ConfigurationFileType};
  }

  static QualifiedName last_update_time_browse_name()
  {
    return QualifiedName{0, "LastUpdateTime"};
  }

  static QualifiedName current_version_browse_name()
  {
    return QualifiedName{0, "CurrentVersion"};
  }

  static QualifiedName activity_timeout_browse_name()
  {
    return QualifiedName{0, "ActivityTimeout"};
  }

  static QualifiedName supported_data_type_browse_name()
  {
    return QualifiedName{0, "SupportedDataType"};
  }

  static QualifiedName confirm_update_browse_name()
  {
    return QualifiedName{0, "ConfirmUpdate"};
  }

  static QualifiedName close_and_update_browse_name()
  {
    return QualifiedName{0, "CloseAndUpdate"};
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

ConfigurationFile::ConfigurationFile(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void ConfigurationFile::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    ConfigurationFileTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(ConfigurationFileResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(ConfigurationFileResult{
        ConfigurationFile{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

ConfigurationFileResult ConfigurationFile::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ConfigurationFileResult>(addressSpace.executor(),
      [&](std::function<void(ConfigurationFileResult)> complete)
      {
        ConfigurationFile::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ConfigurationFile ConfigurationFile::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void ConfigurationFile::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void ConfigurationFile::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // ConfigurationFileType has subtypes - subtype match.
  instance_utils::attach_subtype_async(addressSpace,
    existingInstance,
    ConfigurationFileTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(ConfigurationFileResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(ConfigurationFileResult{::ua::detail::address_space_gone("ConfigurationFile")});
        return;
      }
      complete(ConfigurationFile{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

ConfigurationFileResult ConfigurationFile::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ConfigurationFileResult>(addressSpace.executor(),
      [&](std::function<void(ConfigurationFileResult)> complete)
      {
        ConfigurationFile::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ConfigurationFile ConfigurationFile::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void ConfigurationFile::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

void ConfigurationFile::confirm_update_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ConfigurationFileTypeTraits::confirm_update_browse_name(),
    std::move(complete));
}

MethodAccessorResult ConfigurationFile::try_confirm_update_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { confirm_update_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor ConfigurationFile::confirm_update_method_sync() const
{
  return ::ua::detail::good_value(try_confirm_update_method_sync());
}

void ConfigurationFile::close_and_update_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ConfigurationFileTypeTraits::close_and_update_browse_name(),
    std::move(complete));
}

MethodAccessorResult ConfigurationFile::try_close_and_update_method_sync() const noexcept
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

MethodAccessor ConfigurationFile::close_and_update_method_sync() const
{
  return ::ua::detail::good_value(try_close_and_update_method_sync());
}

// --- Common property helper ---

void ConfigurationFile::find_property_async(
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
    "ConfigurationFile",
    std::move(complete));
}

// --- Property accessors ---

void ConfigurationFile::last_update_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ConfigurationFileTypeTraits::last_update_time_browse_name(), std::move(complete));
}

PropertyResult ConfigurationFile::try_last_update_time_property_sync() const noexcept
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

Property ConfigurationFile::last_update_time_property_sync() const
{
  return ::ua::detail::good_value(try_last_update_time_property_sync());
}

void ConfigurationFile::current_version_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ConfigurationFileTypeTraits::current_version_browse_name(), std::move(complete));
}

PropertyResult ConfigurationFile::try_current_version_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { current_version_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ConfigurationFile::current_version_property_sync() const
{
  return ::ua::detail::good_value(try_current_version_property_sync());
}

void ConfigurationFile::activity_timeout_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ConfigurationFileTypeTraits::activity_timeout_browse_name(), std::move(complete));
}

PropertyResult ConfigurationFile::try_activity_timeout_property_sync() const noexcept
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

Property ConfigurationFile::activity_timeout_property_sync() const
{
  return ::ua::detail::good_value(try_activity_timeout_property_sync());
}

void ConfigurationFile::supported_data_type_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ConfigurationFileTypeTraits::supported_data_type_browse_name(), std::move(complete));
}

PropertyResult ConfigurationFile::try_supported_data_type_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { supported_data_type_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ConfigurationFile::supported_data_type_property_sync() const
{
  return ::ua::detail::good_value(try_supported_data_type_property_sync());
}

void ConfigurationFile::size_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ConfigurationFileTypeTraits::size_browse_name(), std::move(complete));
}

PropertyResult ConfigurationFile::try_size_property_sync() const noexcept
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

Property ConfigurationFile::size_property_sync() const
{
  return ::ua::detail::good_value(try_size_property_sync());
}

void ConfigurationFile::writable_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ConfigurationFileTypeTraits::writable_browse_name(), std::move(complete));
}

PropertyResult ConfigurationFile::try_writable_property_sync() const noexcept
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

Property ConfigurationFile::writable_property_sync() const
{
  return ::ua::detail::good_value(try_writable_property_sync());
}

void ConfigurationFile::user_writable_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ConfigurationFileTypeTraits::user_writable_browse_name(), std::move(complete));
}

PropertyResult ConfigurationFile::try_user_writable_property_sync() const noexcept
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

Property ConfigurationFile::user_writable_property_sync() const
{
  return ::ua::detail::good_value(try_user_writable_property_sync());
}

void ConfigurationFile::open_count_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ConfigurationFileTypeTraits::open_count_browse_name(), std::move(complete));
}

PropertyResult ConfigurationFile::try_open_count_property_sync() const noexcept
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

Property ConfigurationFile::open_count_property_sync() const
{
  return ::ua::detail::good_value(try_open_count_property_sync());
}

void ConfigurationFile::mime_type_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ConfigurationFileTypeTraits::mime_type_browse_name(), std::move(complete));
}

PropertyResult ConfigurationFile::try_mime_type_property_sync() const noexcept
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

Property ConfigurationFile::mime_type_property_sync() const
{
  return ::ua::detail::good_value(try_mime_type_property_sync());
}

void ConfigurationFile::max_byte_string_length_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ConfigurationFileTypeTraits::max_byte_string_length_browse_name(), std::move(complete));
}

PropertyResult ConfigurationFile::try_max_byte_string_length_property_sync() const noexcept
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

Property ConfigurationFile::max_byte_string_length_property_sync() const
{
  return ::ua::detail::good_value(try_max_byte_string_length_property_sync());
}

void ConfigurationFile::last_modified_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ConfigurationFileTypeTraits::last_modified_time_browse_name(), std::move(complete));
}

PropertyResult ConfigurationFile::try_last_modified_time_property_sync() const noexcept
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

Property ConfigurationFile::last_modified_time_property_sync() const
{
  return ::ua::detail::good_value(try_last_modified_time_property_sync());
}

// --- Typed value read shortcuts ---

void ConfigurationFile::read_supported_data_type_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    ConfigurationFileTypeTraits::supported_data_type_browse_name(),
    &Variant::is_node_id,
    {"ConfigurationFile", "supported_data_type", "ConfigurationFile::read_supported_data_type_async"},
    std::move(complete));
}

NodeIdResult ConfigurationFile::try_read_supported_data_type_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeIdResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(NodeIdResult)> complete)
      { read_supported_data_type_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NodeId ConfigurationFile::read_supported_data_type_sync() const
{
  return ::ua::detail::good_value(try_read_supported_data_type_sync());
}

void ConfigurationFile::read_size_async(std::function<void(UInt64Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt64Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint64_t>(*mAddressSpace,
    mNodeId,
    ConfigurationFileTypeTraits::size_browse_name(),
    &Variant::is_uint64,
    {"ConfigurationFile", "size", "ConfigurationFile::read_size_async"},
    std::move(complete));
}

UInt64Result ConfigurationFile::try_read_size_sync() const noexcept
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

uint64_t ConfigurationFile::read_size_sync() const
{
  return ::ua::detail::good_value(try_read_size_sync());
}

void ConfigurationFile::read_writable_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    ConfigurationFileTypeTraits::writable_browse_name(),
    &Variant::is_boolean,
    {"ConfigurationFile", "writable", "ConfigurationFile::read_writable_async"},
    std::move(complete));
}

BoolResult ConfigurationFile::try_read_writable_sync() const noexcept
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

bool ConfigurationFile::read_writable_sync() const
{
  return ::ua::detail::good_value(try_read_writable_sync());
}

void ConfigurationFile::read_user_writable_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    ConfigurationFileTypeTraits::user_writable_browse_name(),
    &Variant::is_boolean,
    {"ConfigurationFile", "user_writable", "ConfigurationFile::read_user_writable_async"},
    std::move(complete));
}

BoolResult ConfigurationFile::try_read_user_writable_sync() const noexcept
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

bool ConfigurationFile::read_user_writable_sync() const
{
  return ::ua::detail::good_value(try_read_user_writable_sync());
}

void ConfigurationFile::read_open_count_async(std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    ConfigurationFileTypeTraits::open_count_browse_name(),
    &Variant::is_uint16,
    {"ConfigurationFile", "open_count", "ConfigurationFile::read_open_count_async"},
    std::move(complete));
}

UInt16Result ConfigurationFile::try_read_open_count_sync() const noexcept
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

uint16_t ConfigurationFile::read_open_count_sync() const
{
  return ::ua::detail::good_value(try_read_open_count_sync());
}

void ConfigurationFile::read_mime_type_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    ConfigurationFileTypeTraits::mime_type_browse_name(),
    &Variant::is_string,
    {"ConfigurationFile", "mime_type", "ConfigurationFile::read_mime_type_async"},
    std::move(complete));
}

StringResult ConfigurationFile::try_read_mime_type_sync() const noexcept
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

String ConfigurationFile::read_mime_type_sync() const
{
  return ::ua::detail::good_value(try_read_mime_type_sync());
}

void ConfigurationFile::read_max_byte_string_length_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    ConfigurationFileTypeTraits::max_byte_string_length_browse_name(),
    &Variant::is_uint32,
    {"ConfigurationFile", "max_byte_string_length", "ConfigurationFile::read_max_byte_string_length_async"},
    std::move(complete));
}

UInt32Result ConfigurationFile::try_read_max_byte_string_length_sync() const noexcept
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

uint32_t ConfigurationFile::read_max_byte_string_length_sync() const
{
  return ::ua::detail::good_value(try_read_max_byte_string_length_sync());
}

void ConfigurationFile::read_last_modified_time_async(
  std::function<void(DateTimeResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DateTimeResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<DateTime>(*mAddressSpace,
    mNodeId,
    ConfigurationFileTypeTraits::last_modified_time_browse_name(),
    &Variant::is_date_time,
    {"ConfigurationFile", "last_modified_time", "ConfigurationFile::read_last_modified_time_async"},
    std::move(complete));
}

DateTimeResult ConfigurationFile::try_read_last_modified_time_sync() const noexcept
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

DateTime ConfigurationFile::read_last_modified_time_sync() const
{
  return ::ua::detail::good_value(try_read_last_modified_time_sync());
}

// --- Typed value write shortcuts ---

void ConfigurationFile::write_supported_data_type_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ConfigurationFileTypeTraits::supported_data_type_browse_name(),
    "ConfigurationFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ConfigurationFile::try_write_supported_data_type_sync(NodeId value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_supported_data_type_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ConfigurationFile::write_supported_data_type_sync(NodeId value) const
{
  try_write_supported_data_type_sync(value).value();
}

void ConfigurationFile::write_size_async(
  uint64_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ConfigurationFileTypeTraits::size_browse_name(),
    "ConfigurationFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ConfigurationFile::try_write_size_sync(uint64_t value) const noexcept
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

void ConfigurationFile::write_size_sync(uint64_t value) const
{
  try_write_size_sync(value).value();
}

void ConfigurationFile::write_writable_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ConfigurationFileTypeTraits::writable_browse_name(),
    "ConfigurationFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ConfigurationFile::try_write_writable_sync(bool value) const noexcept
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

void ConfigurationFile::write_writable_sync(bool value) const
{
  try_write_writable_sync(value).value();
}

void ConfigurationFile::write_user_writable_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ConfigurationFileTypeTraits::user_writable_browse_name(),
    "ConfigurationFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ConfigurationFile::try_write_user_writable_sync(bool value) const noexcept
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

void ConfigurationFile::write_user_writable_sync(bool value) const
{
  try_write_user_writable_sync(value).value();
}

void ConfigurationFile::write_open_count_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ConfigurationFileTypeTraits::open_count_browse_name(),
    "ConfigurationFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ConfigurationFile::try_write_open_count_sync(uint16_t value) const noexcept
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

void ConfigurationFile::write_open_count_sync(uint16_t value) const
{
  try_write_open_count_sync(value).value();
}

void ConfigurationFile::write_mime_type_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ConfigurationFileTypeTraits::mime_type_browse_name(),
    "ConfigurationFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ConfigurationFile::try_write_mime_type_sync(String value) const noexcept
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

void ConfigurationFile::write_mime_type_sync(String value) const
{
  try_write_mime_type_sync(value).value();
}

void ConfigurationFile::write_max_byte_string_length_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ConfigurationFileTypeTraits::max_byte_string_length_browse_name(),
    "ConfigurationFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ConfigurationFile::try_write_max_byte_string_length_sync(uint32_t value) const noexcept
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

void ConfigurationFile::write_max_byte_string_length_sync(uint32_t value) const
{
  try_write_max_byte_string_length_sync(value).value();
}

void ConfigurationFile::write_last_modified_time_async(
  DateTime value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ConfigurationFileTypeTraits::last_modified_time_browse_name(),
    "ConfigurationFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ConfigurationFile::try_write_last_modified_time_sync(DateTime value) const noexcept
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

void ConfigurationFile::write_last_modified_time_sync(DateTime value) const
{
  try_write_last_modified_time_sync(value).value();
}

// --- Method handler registration ---

void ConfigurationFile::set_confirm_update_handler_async(
  ConfirmUpdateHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ConfigurationFile",
        "ConfigurationFile::set_confirm_update_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<Guid>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const Guid& in0) -> MethodResult<>
      {
        ConfirmUpdateInputArguments typedIn{.updateId = in0};
        return handler(call, typedIn);
      },
      Inputs<Guid>{{Arg<Guid>{.name = "UpdateId"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      ConfigurationFileTypeTraits::confirm_update_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ConfigurationFile::try_set_confirm_update_handler_sync(ConfirmUpdateHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_confirm_update_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ConfigurationFile::set_confirm_update_handler_sync(ConfirmUpdateHandler handler) const
{
  try_set_confirm_update_handler_sync(std::move(handler)).value();
}

void ConfigurationFile::set_confirm_update_handler_async(
  ConfirmUpdateAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ConfigurationFile",
        "ConfigurationFile::set_confirm_update_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<Guid>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const Guid& in0, MethodResultCallback<> complete)
      {
        ConfirmUpdateInputArguments typedIn{.updateId = in0};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<Guid>{{Arg<Guid>{.name = "UpdateId"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      ConfigurationFileTypeTraits::confirm_update_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ConfigurationFile::try_set_confirm_update_handler_sync(
  ConfirmUpdateAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_confirm_update_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ConfigurationFile::set_confirm_update_handler_sync(ConfirmUpdateAsyncHandler handler) const
{
  try_set_confirm_update_handler_sync(std::move(handler)).value();
}

void ConfigurationFile::set_close_and_update_handler_async(
  CloseAndUpdateHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ConfigurationFile",
        "ConfigurationFile::set_close_and_update_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<uint32_t, Variant, Array<Variant>, Variant, Variant>,
      std::tuple<std::vector<StatusCode>, Variant, Guid>>
      adapter{[handler = std::move(handler)](const MethodCall& call,
                const uint32_t& in0,
                const Variant& in1,
                const Array<Variant>& in2,
                const Variant& in3,
                const Variant& in4) -> MethodResult<std::vector<StatusCode>, Variant, Guid>
        {
          CloseAndUpdateInputArguments typedIn{.fileHandle = in0,
            .versionToUpdate = in1,
            .targets = in2.payload(),
            .revertAfterTime = in3,
            .restartDelayTime = in4};
          return detail::method_result_from_struct<std::vector<StatusCode>, Variant, Guid>(
            handler(call, typedIn),
            [](const CloseAndUpdateOutputArguments& out)
            {
              return std::tuple<std::vector<StatusCode>, Variant, Guid>{
                out.updateResults, out.newVersion, out.updateId};
            });
        },
        Inputs<uint32_t, Variant, Array<Variant>, Variant, Variant>{{Arg<uint32_t>{.name = "FileHandle"},
          Arg<Variant>{.name = "VersionToUpdate"},
          Arg<Array<Variant>>{.name = "Targets"},
          Arg<Variant>{.name = "RevertAfterTime"},
          Arg<Variant>{.name = "RestartDelayTime"}}},
        mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      ConfigurationFileTypeTraits::close_and_update_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ConfigurationFile::try_set_close_and_update_handler_sync(
  CloseAndUpdateHandler handler) const noexcept
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

void ConfigurationFile::set_close_and_update_handler_sync(CloseAndUpdateHandler handler) const
{
  try_set_close_and_update_handler_sync(std::move(handler)).value();
}

void ConfigurationFile::set_close_and_update_handler_async(
  CloseAndUpdateAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ConfigurationFile",
        "ConfigurationFile::set_close_and_update_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<uint32_t, Variant, Array<Variant>, Variant, Variant>,
      std::tuple<std::vector<StatusCode>, Variant, Guid>>
      adapter{[handler = std::move(handler), logger = mAddressSpace->logger()](const MethodCall& call,
                const uint32_t& in0,
                const Variant& in1,
                const Array<Variant>& in2,
                const Variant& in3,
                const Variant& in4,
                MethodResultCallback<std::vector<StatusCode>, Variant, Guid>
                  complete)
        {
          CloseAndUpdateInputArguments typedIn{.fileHandle = in0,
            .versionToUpdate = in1,
            .targets = in2.payload(),
            .revertAfterTime = in3,
            .restartDelayTime = in4};
          handler(call,
            typedIn,
            detail::struct_method_result_callback<CloseAndUpdateOutputArguments>(
              std::move(complete),
              [](const CloseAndUpdateOutputArguments& out)
              {
                return std::tuple<std::vector<StatusCode>, Variant, Guid>{
                  out.updateResults, out.newVersion, out.updateId};
              },
              logger,
              call.method_id()));
        },
        Inputs<uint32_t, Variant, Array<Variant>, Variant, Variant>{{Arg<uint32_t>{.name = "FileHandle"},
          Arg<Variant>{.name = "VersionToUpdate"},
          Arg<Array<Variant>>{.name = "Targets"},
          Arg<Variant>{.name = "RevertAfterTime"},
          Arg<Variant>{.name = "RestartDelayTime"}}},
        mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      ConfigurationFileTypeTraits::close_and_update_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ConfigurationFile::try_set_close_and_update_handler_sync(
  CloseAndUpdateAsyncHandler handler) const noexcept
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

void ConfigurationFile::set_close_and_update_handler_sync(CloseAndUpdateAsyncHandler handler) const
{
  try_set_close_and_update_handler_sync(std::move(handler)).value();
}

}  // namespace ua
