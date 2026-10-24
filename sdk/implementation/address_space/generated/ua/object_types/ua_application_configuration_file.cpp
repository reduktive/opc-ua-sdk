// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_application_configuration_file.h"

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

struct ApplicationConfigurationFileTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::ApplicationConfigurationFileType};
  }

  static QualifiedName available_networks_browse_name()
  {
    return QualifiedName{0, "AvailableNetworks"};
  }

  static QualifiedName available_ports_browse_name()
  {
    return QualifiedName{0, "AvailablePorts"};
  }

  static QualifiedName max_endpoints_browse_name()
  {
    return QualifiedName{0, "MaxEndpoints"};
  }

  static QualifiedName max_certificate_groups_browse_name()
  {
    return QualifiedName{0, "MaxCertificateGroups"};
  }

  static QualifiedName security_policy_uris_browse_name()
  {
    return QualifiedName{0, "SecurityPolicyUris"};
  }

  static QualifiedName user_token_types_browse_name()
  {
    return QualifiedName{0, "UserTokenTypes"};
  }

  static QualifiedName certificate_types_browse_name()
  {
    return QualifiedName{0, "CertificateTypes"};
  }

  static QualifiedName certificate_group_purposes_browse_name()
  {
    return QualifiedName{0, "CertificateGroupPurposes"};
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

ApplicationConfigurationFile::ApplicationConfigurationFile(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void ApplicationConfigurationFile::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    ApplicationConfigurationFileTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(ApplicationConfigurationFileResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(ApplicationConfigurationFileResult{
        ApplicationConfigurationFile{
          std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

ApplicationConfigurationFileResult ApplicationConfigurationFile::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ApplicationConfigurationFileResult>(addressSpace.executor(),
      [&](std::function<void(ApplicationConfigurationFileResult)> complete)
      {
        ApplicationConfigurationFile::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ApplicationConfigurationFile ApplicationConfigurationFile::create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void ApplicationConfigurationFile::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void ApplicationConfigurationFile::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // ApplicationConfigurationFileType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    ApplicationConfigurationFileTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(ApplicationConfigurationFileResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(ApplicationConfigurationFileResult{
          ::ua::detail::address_space_gone("ApplicationConfigurationFile")});
        return;
      }
      complete(ApplicationConfigurationFile{
        std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

ApplicationConfigurationFileResult ApplicationConfigurationFile::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ApplicationConfigurationFileResult>(addressSpace.executor(),
      [&](std::function<void(ApplicationConfigurationFileResult)> complete)
      {
        ApplicationConfigurationFile::attach_async(
          std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ApplicationConfigurationFile ApplicationConfigurationFile::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void ApplicationConfigurationFile::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void ApplicationConfigurationFile::find_property_async(
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
    "ApplicationConfigurationFile",
    std::move(complete));
}

// --- Property accessors ---

void ApplicationConfigurationFile::available_networks_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ApplicationConfigurationFileTypeTraits::available_networks_browse_name(), std::move(complete));
}

PropertyResult ApplicationConfigurationFile::try_available_networks_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { available_networks_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ApplicationConfigurationFile::available_networks_property_sync() const
{
  return ::ua::detail::good_value(try_available_networks_property_sync());
}

void ApplicationConfigurationFile::available_ports_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ApplicationConfigurationFileTypeTraits::available_ports_browse_name(), std::move(complete));
}

PropertyResult ApplicationConfigurationFile::try_available_ports_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { available_ports_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ApplicationConfigurationFile::available_ports_property_sync() const
{
  return ::ua::detail::good_value(try_available_ports_property_sync());
}

void ApplicationConfigurationFile::max_endpoints_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ApplicationConfigurationFileTypeTraits::max_endpoints_browse_name(), std::move(complete));
}

PropertyResult ApplicationConfigurationFile::try_max_endpoints_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_endpoints_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ApplicationConfigurationFile::max_endpoints_property_sync() const
{
  return ::ua::detail::good_value(try_max_endpoints_property_sync());
}

void ApplicationConfigurationFile::max_certificate_groups_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ApplicationConfigurationFileTypeTraits::max_certificate_groups_browse_name(), std::move(complete));
}

PropertyResult ApplicationConfigurationFile::try_max_certificate_groups_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_certificate_groups_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ApplicationConfigurationFile::max_certificate_groups_property_sync() const
{
  return ::ua::detail::good_value(try_max_certificate_groups_property_sync());
}

void ApplicationConfigurationFile::security_policy_uris_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ApplicationConfigurationFileTypeTraits::security_policy_uris_browse_name(), std::move(complete));
}

PropertyResult ApplicationConfigurationFile::try_security_policy_uris_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { security_policy_uris_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ApplicationConfigurationFile::security_policy_uris_property_sync() const
{
  return ::ua::detail::good_value(try_security_policy_uris_property_sync());
}

void ApplicationConfigurationFile::user_token_types_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ApplicationConfigurationFileTypeTraits::user_token_types_browse_name(), std::move(complete));
}

PropertyResult ApplicationConfigurationFile::try_user_token_types_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { user_token_types_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ApplicationConfigurationFile::user_token_types_property_sync() const
{
  return ::ua::detail::good_value(try_user_token_types_property_sync());
}

void ApplicationConfigurationFile::certificate_types_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ApplicationConfigurationFileTypeTraits::certificate_types_browse_name(), std::move(complete));
}

PropertyResult ApplicationConfigurationFile::try_certificate_types_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { certificate_types_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ApplicationConfigurationFile::certificate_types_property_sync() const
{
  return ::ua::detail::good_value(try_certificate_types_property_sync());
}

void ApplicationConfigurationFile::certificate_group_purposes_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ApplicationConfigurationFileTypeTraits::certificate_group_purposes_browse_name(), std::move(complete));
}

PropertyResult ApplicationConfigurationFile::try_certificate_group_purposes_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { certificate_group_purposes_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ApplicationConfigurationFile::certificate_group_purposes_property_sync() const
{
  return ::ua::detail::good_value(try_certificate_group_purposes_property_sync());
}

void ApplicationConfigurationFile::last_update_time_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ApplicationConfigurationFileTypeTraits::last_update_time_browse_name(), std::move(complete));
}

PropertyResult ApplicationConfigurationFile::try_last_update_time_property_sync() const noexcept
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

Property ApplicationConfigurationFile::last_update_time_property_sync() const
{
  return ::ua::detail::good_value(try_last_update_time_property_sync());
}

void ApplicationConfigurationFile::current_version_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ApplicationConfigurationFileTypeTraits::current_version_browse_name(), std::move(complete));
}

PropertyResult ApplicationConfigurationFile::try_current_version_property_sync() const noexcept
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

Property ApplicationConfigurationFile::current_version_property_sync() const
{
  return ::ua::detail::good_value(try_current_version_property_sync());
}

void ApplicationConfigurationFile::activity_timeout_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ApplicationConfigurationFileTypeTraits::activity_timeout_browse_name(), std::move(complete));
}

PropertyResult ApplicationConfigurationFile::try_activity_timeout_property_sync() const noexcept
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

Property ApplicationConfigurationFile::activity_timeout_property_sync() const
{
  return ::ua::detail::good_value(try_activity_timeout_property_sync());
}

void ApplicationConfigurationFile::supported_data_type_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ApplicationConfigurationFileTypeTraits::supported_data_type_browse_name(), std::move(complete));
}

PropertyResult ApplicationConfigurationFile::try_supported_data_type_property_sync() const noexcept
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

Property ApplicationConfigurationFile::supported_data_type_property_sync() const
{
  return ::ua::detail::good_value(try_supported_data_type_property_sync());
}

void ApplicationConfigurationFile::size_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ApplicationConfigurationFileTypeTraits::size_browse_name(), std::move(complete));
}

PropertyResult ApplicationConfigurationFile::try_size_property_sync() const noexcept
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

Property ApplicationConfigurationFile::size_property_sync() const
{
  return ::ua::detail::good_value(try_size_property_sync());
}

void ApplicationConfigurationFile::writable_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ApplicationConfigurationFileTypeTraits::writable_browse_name(), std::move(complete));
}

PropertyResult ApplicationConfigurationFile::try_writable_property_sync() const noexcept
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

Property ApplicationConfigurationFile::writable_property_sync() const
{
  return ::ua::detail::good_value(try_writable_property_sync());
}

void ApplicationConfigurationFile::user_writable_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ApplicationConfigurationFileTypeTraits::user_writable_browse_name(), std::move(complete));
}

PropertyResult ApplicationConfigurationFile::try_user_writable_property_sync() const noexcept
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

Property ApplicationConfigurationFile::user_writable_property_sync() const
{
  return ::ua::detail::good_value(try_user_writable_property_sync());
}

void ApplicationConfigurationFile::open_count_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ApplicationConfigurationFileTypeTraits::open_count_browse_name(), std::move(complete));
}

PropertyResult ApplicationConfigurationFile::try_open_count_property_sync() const noexcept
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

Property ApplicationConfigurationFile::open_count_property_sync() const
{
  return ::ua::detail::good_value(try_open_count_property_sync());
}

void ApplicationConfigurationFile::mime_type_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ApplicationConfigurationFileTypeTraits::mime_type_browse_name(), std::move(complete));
}

PropertyResult ApplicationConfigurationFile::try_mime_type_property_sync() const noexcept
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

Property ApplicationConfigurationFile::mime_type_property_sync() const
{
  return ::ua::detail::good_value(try_mime_type_property_sync());
}

void ApplicationConfigurationFile::max_byte_string_length_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ApplicationConfigurationFileTypeTraits::max_byte_string_length_browse_name(), std::move(complete));
}

PropertyResult ApplicationConfigurationFile::try_max_byte_string_length_property_sync() const noexcept
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

Property ApplicationConfigurationFile::max_byte_string_length_property_sync() const
{
  return ::ua::detail::good_value(try_max_byte_string_length_property_sync());
}

void ApplicationConfigurationFile::last_modified_time_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ApplicationConfigurationFileTypeTraits::last_modified_time_browse_name(), std::move(complete));
}

PropertyResult ApplicationConfigurationFile::try_last_modified_time_property_sync() const noexcept
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

Property ApplicationConfigurationFile::last_modified_time_property_sync() const
{
  return ::ua::detail::good_value(try_last_modified_time_property_sync());
}

// --- Typed value read shortcuts ---

void ApplicationConfigurationFile::read_available_networks_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    ApplicationConfigurationFileTypeTraits::available_networks_browse_name(),
    &Variant::is_string,
    {"ApplicationConfigurationFile",
      "available_networks",
      "ApplicationConfigurationFile::read_available_networks_async"},
    std::move(complete));
}

StringResult ApplicationConfigurationFile::try_read_available_networks_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete)
      { read_available_networks_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String ApplicationConfigurationFile::read_available_networks_sync() const
{
  return ::ua::detail::good_value(try_read_available_networks_sync());
}

void ApplicationConfigurationFile::read_max_endpoints_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    ApplicationConfigurationFileTypeTraits::max_endpoints_browse_name(),
    &Variant::is_uint16,
    {"ApplicationConfigurationFile",
      "max_endpoints",
      "ApplicationConfigurationFile::read_max_endpoints_async"},
    std::move(complete));
}

UInt16Result ApplicationConfigurationFile::try_read_max_endpoints_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt16Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt16Result)> complete) { read_max_endpoints_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint16_t ApplicationConfigurationFile::read_max_endpoints_sync() const
{
  return ::ua::detail::good_value(try_read_max_endpoints_sync());
}

void ApplicationConfigurationFile::read_max_certificate_groups_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    ApplicationConfigurationFileTypeTraits::max_certificate_groups_browse_name(),
    &Variant::is_uint16,
    {"ApplicationConfigurationFile",
      "max_certificate_groups",
      "ApplicationConfigurationFile::read_max_certificate_groups_async"},
    std::move(complete));
}

UInt16Result ApplicationConfigurationFile::try_read_max_certificate_groups_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt16Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt16Result)> complete)
      { read_max_certificate_groups_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint16_t ApplicationConfigurationFile::read_max_certificate_groups_sync() const
{
  return ::ua::detail::good_value(try_read_max_certificate_groups_sync());
}

void ApplicationConfigurationFile::read_certificate_types_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    ApplicationConfigurationFileTypeTraits::certificate_types_browse_name(),
    &Variant::is_node_id,
    {"ApplicationConfigurationFile",
      "certificate_types",
      "ApplicationConfigurationFile::read_certificate_types_async"},
    std::move(complete));
}

NodeIdResult ApplicationConfigurationFile::try_read_certificate_types_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeIdResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(NodeIdResult)> complete) { read_certificate_types_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NodeId ApplicationConfigurationFile::read_certificate_types_sync() const
{
  return ::ua::detail::good_value(try_read_certificate_types_sync());
}

void ApplicationConfigurationFile::read_certificate_group_purposes_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    ApplicationConfigurationFileTypeTraits::certificate_group_purposes_browse_name(),
    &Variant::is_node_id,
    {"ApplicationConfigurationFile",
      "certificate_group_purposes",
      "ApplicationConfigurationFile::read_certificate_group_purposes_async"},
    std::move(complete));
}

NodeIdResult ApplicationConfigurationFile::try_read_certificate_group_purposes_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeIdResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(NodeIdResult)> complete)
      { read_certificate_group_purposes_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NodeId ApplicationConfigurationFile::read_certificate_group_purposes_sync() const
{
  return ::ua::detail::good_value(try_read_certificate_group_purposes_sync());
}

void ApplicationConfigurationFile::read_supported_data_type_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    ApplicationConfigurationFileTypeTraits::supported_data_type_browse_name(),
    &Variant::is_node_id,
    {"ApplicationConfigurationFile",
      "supported_data_type",
      "ApplicationConfigurationFile::read_supported_data_type_async"},
    std::move(complete));
}

NodeIdResult ApplicationConfigurationFile::try_read_supported_data_type_sync() const noexcept
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

NodeId ApplicationConfigurationFile::read_supported_data_type_sync() const
{
  return ::ua::detail::good_value(try_read_supported_data_type_sync());
}

void ApplicationConfigurationFile::read_size_async(std::function<void(UInt64Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt64Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint64_t>(*mAddressSpace,
    mNodeId,
    ApplicationConfigurationFileTypeTraits::size_browse_name(),
    &Variant::is_uint64,
    {"ApplicationConfigurationFile", "size", "ApplicationConfigurationFile::read_size_async"},
    std::move(complete));
}

UInt64Result ApplicationConfigurationFile::try_read_size_sync() const noexcept
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

uint64_t ApplicationConfigurationFile::read_size_sync() const
{
  return ::ua::detail::good_value(try_read_size_sync());
}

void ApplicationConfigurationFile::read_writable_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    ApplicationConfigurationFileTypeTraits::writable_browse_name(),
    &Variant::is_boolean,
    {"ApplicationConfigurationFile", "writable", "ApplicationConfigurationFile::read_writable_async"},
    std::move(complete));
}

BoolResult ApplicationConfigurationFile::try_read_writable_sync() const noexcept
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

bool ApplicationConfigurationFile::read_writable_sync() const
{
  return ::ua::detail::good_value(try_read_writable_sync());
}

void ApplicationConfigurationFile::read_user_writable_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    ApplicationConfigurationFileTypeTraits::user_writable_browse_name(),
    &Variant::is_boolean,
    {"ApplicationConfigurationFile",
      "user_writable",
      "ApplicationConfigurationFile::read_user_writable_async"},
    std::move(complete));
}

BoolResult ApplicationConfigurationFile::try_read_user_writable_sync() const noexcept
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

bool ApplicationConfigurationFile::read_user_writable_sync() const
{
  return ::ua::detail::good_value(try_read_user_writable_sync());
}

void ApplicationConfigurationFile::read_open_count_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    ApplicationConfigurationFileTypeTraits::open_count_browse_name(),
    &Variant::is_uint16,
    {"ApplicationConfigurationFile", "open_count", "ApplicationConfigurationFile::read_open_count_async"},
    std::move(complete));
}

UInt16Result ApplicationConfigurationFile::try_read_open_count_sync() const noexcept
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

uint16_t ApplicationConfigurationFile::read_open_count_sync() const
{
  return ::ua::detail::good_value(try_read_open_count_sync());
}

void ApplicationConfigurationFile::read_mime_type_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    ApplicationConfigurationFileTypeTraits::mime_type_browse_name(),
    &Variant::is_string,
    {"ApplicationConfigurationFile", "mime_type", "ApplicationConfigurationFile::read_mime_type_async"},
    std::move(complete));
}

StringResult ApplicationConfigurationFile::try_read_mime_type_sync() const noexcept
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

String ApplicationConfigurationFile::read_mime_type_sync() const
{
  return ::ua::detail::good_value(try_read_mime_type_sync());
}

void ApplicationConfigurationFile::read_max_byte_string_length_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    ApplicationConfigurationFileTypeTraits::max_byte_string_length_browse_name(),
    &Variant::is_uint32,
    {"ApplicationConfigurationFile",
      "max_byte_string_length",
      "ApplicationConfigurationFile::read_max_byte_string_length_async"},
    std::move(complete));
}

UInt32Result ApplicationConfigurationFile::try_read_max_byte_string_length_sync() const noexcept
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

uint32_t ApplicationConfigurationFile::read_max_byte_string_length_sync() const
{
  return ::ua::detail::good_value(try_read_max_byte_string_length_sync());
}

void ApplicationConfigurationFile::read_last_modified_time_async(
  std::function<void(DateTimeResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DateTimeResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<DateTime>(*mAddressSpace,
    mNodeId,
    ApplicationConfigurationFileTypeTraits::last_modified_time_browse_name(),
    &Variant::is_date_time,
    {"ApplicationConfigurationFile",
      "last_modified_time",
      "ApplicationConfigurationFile::read_last_modified_time_async"},
    std::move(complete));
}

DateTimeResult ApplicationConfigurationFile::try_read_last_modified_time_sync() const noexcept
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

DateTime ApplicationConfigurationFile::read_last_modified_time_sync() const
{
  return ::ua::detail::good_value(try_read_last_modified_time_sync());
}

// --- Typed value write shortcuts ---

void ApplicationConfigurationFile::write_available_networks_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ApplicationConfigurationFileTypeTraits::available_networks_browse_name(),
    "ApplicationConfigurationFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ApplicationConfigurationFile::try_write_available_networks_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_available_networks_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ApplicationConfigurationFile::write_available_networks_sync(String value) const
{
  try_write_available_networks_sync(value).value();
}

void ApplicationConfigurationFile::write_max_endpoints_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ApplicationConfigurationFileTypeTraits::max_endpoints_browse_name(),
    "ApplicationConfigurationFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ApplicationConfigurationFile::try_write_max_endpoints_sync(uint16_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_endpoints_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ApplicationConfigurationFile::write_max_endpoints_sync(uint16_t value) const
{
  try_write_max_endpoints_sync(value).value();
}

void ApplicationConfigurationFile::write_max_certificate_groups_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ApplicationConfigurationFileTypeTraits::max_certificate_groups_browse_name(),
    "ApplicationConfigurationFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ApplicationConfigurationFile::try_write_max_certificate_groups_sync(uint16_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_certificate_groups_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ApplicationConfigurationFile::write_max_certificate_groups_sync(uint16_t value) const
{
  try_write_max_certificate_groups_sync(value).value();
}

void ApplicationConfigurationFile::write_certificate_types_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ApplicationConfigurationFileTypeTraits::certificate_types_browse_name(),
    "ApplicationConfigurationFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ApplicationConfigurationFile::try_write_certificate_types_sync(NodeId value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_certificate_types_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ApplicationConfigurationFile::write_certificate_types_sync(NodeId value) const
{
  try_write_certificate_types_sync(value).value();
}

void ApplicationConfigurationFile::write_certificate_group_purposes_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ApplicationConfigurationFileTypeTraits::certificate_group_purposes_browse_name(),
    "ApplicationConfigurationFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ApplicationConfigurationFile::try_write_certificate_group_purposes_sync(
  NodeId value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_certificate_group_purposes_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ApplicationConfigurationFile::write_certificate_group_purposes_sync(NodeId value) const
{
  try_write_certificate_group_purposes_sync(value).value();
}

void ApplicationConfigurationFile::write_supported_data_type_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ApplicationConfigurationFileTypeTraits::supported_data_type_browse_name(),
    "ApplicationConfigurationFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ApplicationConfigurationFile::try_write_supported_data_type_sync(NodeId value) const noexcept
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

void ApplicationConfigurationFile::write_supported_data_type_sync(NodeId value) const
{
  try_write_supported_data_type_sync(value).value();
}

void ApplicationConfigurationFile::write_size_async(
  uint64_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ApplicationConfigurationFileTypeTraits::size_browse_name(),
    "ApplicationConfigurationFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ApplicationConfigurationFile::try_write_size_sync(uint64_t value) const noexcept
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

void ApplicationConfigurationFile::write_size_sync(uint64_t value) const
{
  try_write_size_sync(value).value();
}

void ApplicationConfigurationFile::write_writable_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ApplicationConfigurationFileTypeTraits::writable_browse_name(),
    "ApplicationConfigurationFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ApplicationConfigurationFile::try_write_writable_sync(bool value) const noexcept
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

void ApplicationConfigurationFile::write_writable_sync(bool value) const
{
  try_write_writable_sync(value).value();
}

void ApplicationConfigurationFile::write_user_writable_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ApplicationConfigurationFileTypeTraits::user_writable_browse_name(),
    "ApplicationConfigurationFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ApplicationConfigurationFile::try_write_user_writable_sync(bool value) const noexcept
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

void ApplicationConfigurationFile::write_user_writable_sync(bool value) const
{
  try_write_user_writable_sync(value).value();
}

void ApplicationConfigurationFile::write_open_count_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ApplicationConfigurationFileTypeTraits::open_count_browse_name(),
    "ApplicationConfigurationFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ApplicationConfigurationFile::try_write_open_count_sync(uint16_t value) const noexcept
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

void ApplicationConfigurationFile::write_open_count_sync(uint16_t value) const
{
  try_write_open_count_sync(value).value();
}

void ApplicationConfigurationFile::write_mime_type_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ApplicationConfigurationFileTypeTraits::mime_type_browse_name(),
    "ApplicationConfigurationFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ApplicationConfigurationFile::try_write_mime_type_sync(String value) const noexcept
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

void ApplicationConfigurationFile::write_mime_type_sync(String value) const
{
  try_write_mime_type_sync(value).value();
}

void ApplicationConfigurationFile::write_max_byte_string_length_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ApplicationConfigurationFileTypeTraits::max_byte_string_length_browse_name(),
    "ApplicationConfigurationFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ApplicationConfigurationFile::try_write_max_byte_string_length_sync(uint32_t value) const noexcept
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

void ApplicationConfigurationFile::write_max_byte_string_length_sync(uint32_t value) const
{
  try_write_max_byte_string_length_sync(value).value();
}

void ApplicationConfigurationFile::write_last_modified_time_async(
  DateTime value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ApplicationConfigurationFileTypeTraits::last_modified_time_browse_name(),
    "ApplicationConfigurationFile",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ApplicationConfigurationFile::try_write_last_modified_time_sync(DateTime value) const noexcept
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

void ApplicationConfigurationFile::write_last_modified_time_sync(DateTime value) const
{
  try_write_last_modified_time_sync(value).value();
}

}  // namespace ua
