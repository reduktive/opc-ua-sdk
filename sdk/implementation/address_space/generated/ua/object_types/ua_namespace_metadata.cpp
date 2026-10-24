// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_namespace_metadata.h"

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

struct NamespaceMetadataTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::NamespaceMetadataType};
  }

  static QualifiedName namespace_uri_browse_name()
  {
    return QualifiedName{0, "NamespaceUri"};
  }

  static QualifiedName namespace_version_browse_name()
  {
    return QualifiedName{0, "NamespaceVersion"};
  }

  static QualifiedName namespace_publication_date_browse_name()
  {
    return QualifiedName{0, "NamespacePublicationDate"};
  }

  static QualifiedName is_namespace_subset_browse_name()
  {
    return QualifiedName{0, "IsNamespaceSubset"};
  }

  static QualifiedName static_node_id_types_browse_name()
  {
    return QualifiedName{0, "StaticNodeIdTypes"};
  }

  static QualifiedName static_numeric_node_id_range_browse_name()
  {
    return QualifiedName{0, "StaticNumericNodeIdRange"};
  }

  static QualifiedName static_string_node_id_pattern_browse_name()
  {
    return QualifiedName{0, "StaticStringNodeIdPattern"};
  }

  static QualifiedName namespace_file_browse_name()
  {
    return QualifiedName{0, "NamespaceFile"};
  }

  static QualifiedName default_role_permissions_browse_name()
  {
    return QualifiedName{0, "DefaultRolePermissions"};
  }

  static QualifiedName default_user_role_permissions_browse_name()
  {
    return QualifiedName{0, "DefaultUserRolePermissions"};
  }

  static QualifiedName default_access_restrictions_browse_name()
  {
    return QualifiedName{0, "DefaultAccessRestrictions"};
  }

  static QualifiedName configuration_version_browse_name()
  {
    return QualifiedName{0, "ConfigurationVersion"};
  }

  static QualifiedName model_version_browse_name()
  {
    return QualifiedName{0, "ModelVersion"};
  }
};

}  // namespace

NamespaceMetadata::NamespaceMetadata(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void NamespaceMetadata::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    NamespaceMetadataTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(NamespaceMetadataResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(NamespaceMetadataResult{
        NamespaceMetadata{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

NamespaceMetadataResult NamespaceMetadata::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NamespaceMetadataResult>(addressSpace.executor(),
      [&](std::function<void(NamespaceMetadataResult)> complete)
      {
        NamespaceMetadata::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NamespaceMetadata NamespaceMetadata::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void NamespaceMetadata::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void NamespaceMetadata::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // NamespaceMetadataType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    NamespaceMetadataTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(NamespaceMetadataResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(NamespaceMetadataResult{::ua::detail::address_space_gone("NamespaceMetadata")});
        return;
      }
      complete(NamespaceMetadata{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

NamespaceMetadataResult NamespaceMetadata::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NamespaceMetadataResult>(addressSpace.executor(),
      [&](std::function<void(NamespaceMetadataResult)> complete)
      {
        NamespaceMetadata::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NamespaceMetadata NamespaceMetadata::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void NamespaceMetadata::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void NamespaceMetadata::find_property_async(
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
    "NamespaceMetadata",
    std::move(complete));
}

// --- Property accessors ---

void NamespaceMetadata::namespace_uri_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NamespaceMetadataTypeTraits::namespace_uri_browse_name(), std::move(complete));
}

PropertyResult NamespaceMetadata::try_namespace_uri_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { namespace_uri_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NamespaceMetadata::namespace_uri_property_sync() const
{
  return ::ua::detail::good_value(try_namespace_uri_property_sync());
}

void NamespaceMetadata::namespace_version_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NamespaceMetadataTypeTraits::namespace_version_browse_name(), std::move(complete));
}

PropertyResult NamespaceMetadata::try_namespace_version_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { namespace_version_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NamespaceMetadata::namespace_version_property_sync() const
{
  return ::ua::detail::good_value(try_namespace_version_property_sync());
}

void NamespaceMetadata::namespace_publication_date_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NamespaceMetadataTypeTraits::namespace_publication_date_browse_name(), std::move(complete));
}

PropertyResult NamespaceMetadata::try_namespace_publication_date_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { namespace_publication_date_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NamespaceMetadata::namespace_publication_date_property_sync() const
{
  return ::ua::detail::good_value(try_namespace_publication_date_property_sync());
}

void NamespaceMetadata::is_namespace_subset_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NamespaceMetadataTypeTraits::is_namespace_subset_browse_name(), std::move(complete));
}

PropertyResult NamespaceMetadata::try_is_namespace_subset_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { is_namespace_subset_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NamespaceMetadata::is_namespace_subset_property_sync() const
{
  return ::ua::detail::good_value(try_is_namespace_subset_property_sync());
}

void NamespaceMetadata::static_node_id_types_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NamespaceMetadataTypeTraits::static_node_id_types_browse_name(), std::move(complete));
}

PropertyResult NamespaceMetadata::try_static_node_id_types_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { static_node_id_types_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NamespaceMetadata::static_node_id_types_property_sync() const
{
  return ::ua::detail::good_value(try_static_node_id_types_property_sync());
}

void NamespaceMetadata::static_numeric_node_id_range_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NamespaceMetadataTypeTraits::static_numeric_node_id_range_browse_name(), std::move(complete));
}

PropertyResult NamespaceMetadata::try_static_numeric_node_id_range_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { static_numeric_node_id_range_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NamespaceMetadata::static_numeric_node_id_range_property_sync() const
{
  return ::ua::detail::good_value(try_static_numeric_node_id_range_property_sync());
}

void NamespaceMetadata::static_string_node_id_pattern_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NamespaceMetadataTypeTraits::static_string_node_id_pattern_browse_name(), std::move(complete));
}

PropertyResult NamespaceMetadata::try_static_string_node_id_pattern_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { static_string_node_id_pattern_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NamespaceMetadata::static_string_node_id_pattern_property_sync() const
{
  return ::ua::detail::good_value(try_static_string_node_id_pattern_property_sync());
}

void NamespaceMetadata::default_role_permissions_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NamespaceMetadataTypeTraits::default_role_permissions_browse_name(), std::move(complete));
}

PropertyResult NamespaceMetadata::try_default_role_permissions_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { default_role_permissions_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NamespaceMetadata::default_role_permissions_property_sync() const
{
  return ::ua::detail::good_value(try_default_role_permissions_property_sync());
}

void NamespaceMetadata::default_user_role_permissions_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NamespaceMetadataTypeTraits::default_user_role_permissions_browse_name(), std::move(complete));
}

PropertyResult NamespaceMetadata::try_default_user_role_permissions_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { default_user_role_permissions_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NamespaceMetadata::default_user_role_permissions_property_sync() const
{
  return ::ua::detail::good_value(try_default_user_role_permissions_property_sync());
}

void NamespaceMetadata::default_access_restrictions_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NamespaceMetadataTypeTraits::default_access_restrictions_browse_name(), std::move(complete));
}

PropertyResult NamespaceMetadata::try_default_access_restrictions_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { default_access_restrictions_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NamespaceMetadata::default_access_restrictions_property_sync() const
{
  return ::ua::detail::good_value(try_default_access_restrictions_property_sync());
}

void NamespaceMetadata::configuration_version_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NamespaceMetadataTypeTraits::configuration_version_browse_name(), std::move(complete));
}

PropertyResult NamespaceMetadata::try_configuration_version_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { configuration_version_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NamespaceMetadata::configuration_version_property_sync() const
{
  return ::ua::detail::good_value(try_configuration_version_property_sync());
}

void NamespaceMetadata::model_version_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NamespaceMetadataTypeTraits::model_version_browse_name(), std::move(complete));
}

PropertyResult NamespaceMetadata::try_model_version_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { model_version_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NamespaceMetadata::model_version_property_sync() const
{
  return ::ua::detail::good_value(try_model_version_property_sync());
}

// --- Typed value read shortcuts ---

void NamespaceMetadata::read_namespace_uri_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    NamespaceMetadataTypeTraits::namespace_uri_browse_name(),
    &Variant::is_string,
    {"NamespaceMetadata", "namespace_uri", "NamespaceMetadata::read_namespace_uri_async"},
    std::move(complete));
}

StringResult NamespaceMetadata::try_read_namespace_uri_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_namespace_uri_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String NamespaceMetadata::read_namespace_uri_sync() const
{
  return ::ua::detail::good_value(try_read_namespace_uri_sync());
}

void NamespaceMetadata::read_namespace_version_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    NamespaceMetadataTypeTraits::namespace_version_browse_name(),
    &Variant::is_string,
    {"NamespaceMetadata", "namespace_version", "NamespaceMetadata::read_namespace_version_async"},
    std::move(complete));
}

StringResult NamespaceMetadata::try_read_namespace_version_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_namespace_version_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String NamespaceMetadata::read_namespace_version_sync() const
{
  return ::ua::detail::good_value(try_read_namespace_version_sync());
}

void NamespaceMetadata::read_namespace_publication_date_async(
  std::function<void(DateTimeResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DateTimeResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<DateTime>(*mAddressSpace,
    mNodeId,
    NamespaceMetadataTypeTraits::namespace_publication_date_browse_name(),
    &Variant::is_date_time,
    {"NamespaceMetadata",
      "namespace_publication_date",
      "NamespaceMetadata::read_namespace_publication_date_async"},
    std::move(complete));
}

DateTimeResult NamespaceMetadata::try_read_namespace_publication_date_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<DateTimeResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(DateTimeResult)> complete)
      { read_namespace_publication_date_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

DateTime NamespaceMetadata::read_namespace_publication_date_sync() const
{
  return ::ua::detail::good_value(try_read_namespace_publication_date_sync());
}

void NamespaceMetadata::read_is_namespace_subset_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    NamespaceMetadataTypeTraits::is_namespace_subset_browse_name(),
    &Variant::is_boolean,
    {"NamespaceMetadata", "is_namespace_subset", "NamespaceMetadata::read_is_namespace_subset_async"},
    std::move(complete));
}

BoolResult NamespaceMetadata::try_read_is_namespace_subset_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BoolResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BoolResult)> complete) { read_is_namespace_subset_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

bool NamespaceMetadata::read_is_namespace_subset_sync() const
{
  return ::ua::detail::good_value(try_read_is_namespace_subset_sync());
}

void NamespaceMetadata::read_static_string_node_id_pattern_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    NamespaceMetadataTypeTraits::static_string_node_id_pattern_browse_name(),
    &Variant::is_string,
    {"NamespaceMetadata",
      "static_string_node_id_pattern",
      "NamespaceMetadata::read_static_string_node_id_pattern_async"},
    std::move(complete));
}

StringResult NamespaceMetadata::try_read_static_string_node_id_pattern_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete)
      { read_static_string_node_id_pattern_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String NamespaceMetadata::read_static_string_node_id_pattern_sync() const
{
  return ::ua::detail::good_value(try_read_static_string_node_id_pattern_sync());
}

// --- Typed value write shortcuts ---

void NamespaceMetadata::write_namespace_uri_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NamespaceMetadataTypeTraits::namespace_uri_browse_name(),
    "NamespaceMetadata",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NamespaceMetadata::try_write_namespace_uri_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_namespace_uri_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NamespaceMetadata::write_namespace_uri_sync(String value) const
{
  try_write_namespace_uri_sync(value).value();
}

void NamespaceMetadata::write_namespace_version_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NamespaceMetadataTypeTraits::namespace_version_browse_name(),
    "NamespaceMetadata",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NamespaceMetadata::try_write_namespace_version_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_namespace_version_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NamespaceMetadata::write_namespace_version_sync(String value) const
{
  try_write_namespace_version_sync(value).value();
}

void NamespaceMetadata::write_namespace_publication_date_async(
  DateTime value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NamespaceMetadataTypeTraits::namespace_publication_date_browse_name(),
    "NamespaceMetadata",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NamespaceMetadata::try_write_namespace_publication_date_sync(DateTime value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_namespace_publication_date_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NamespaceMetadata::write_namespace_publication_date_sync(DateTime value) const
{
  try_write_namespace_publication_date_sync(value).value();
}

void NamespaceMetadata::write_is_namespace_subset_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NamespaceMetadataTypeTraits::is_namespace_subset_browse_name(),
    "NamespaceMetadata",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NamespaceMetadata::try_write_is_namespace_subset_sync(bool value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_is_namespace_subset_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NamespaceMetadata::write_is_namespace_subset_sync(bool value) const
{
  try_write_is_namespace_subset_sync(value).value();
}

void NamespaceMetadata::write_static_string_node_id_pattern_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NamespaceMetadataTypeTraits::static_string_node_id_pattern_browse_name(),
    "NamespaceMetadata",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NamespaceMetadata::try_write_static_string_node_id_pattern_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_static_string_node_id_pattern_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NamespaceMetadata::write_static_string_node_id_pattern_sync(String value) const
{
  try_write_static_string_node_id_pattern_sync(value).value();
}

// --- Child-object accessors ---

void NamespaceMetadata::namespace_file_async(
  std::function<void(AddressSpaceFileResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(AddressSpaceFileResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<AddressSpaceFile>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    NamespaceMetadataTypeTraits::namespace_file_browse_name(),
    "NamespaceMetadata",
    std::move(complete));
}

AddressSpaceFileResult NamespaceMetadata::try_namespace_file_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<AddressSpaceFileResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(AddressSpaceFileResult)> complete)
      { namespace_file_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

AddressSpaceFile NamespaceMetadata::namespace_file_sync() const
{
  return ::ua::detail::good_value(try_namespace_file_sync());
}

}  // namespace ua
