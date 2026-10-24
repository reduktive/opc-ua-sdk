// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_historical_data_configuration.h"

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

struct HistoricalDataConfigurationTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::HistoricalDataConfigurationType};
  }

  static QualifiedName aggregate_functions_browse_name()
  {
    return QualifiedName{0, "AggregateFunctions"};
  }

  static QualifiedName stepped_browse_name()
  {
    return QualifiedName{0, "Stepped"};
  }

  static QualifiedName definition_browse_name()
  {
    return QualifiedName{0, "Definition"};
  }

  static QualifiedName max_time_interval_browse_name()
  {
    return QualifiedName{0, "MaxTimeInterval"};
  }

  static QualifiedName min_time_interval_browse_name()
  {
    return QualifiedName{0, "MinTimeInterval"};
  }

  static QualifiedName exception_deviation_browse_name()
  {
    return QualifiedName{0, "ExceptionDeviation"};
  }

  static QualifiedName exception_deviation_format_browse_name()
  {
    return QualifiedName{0, "ExceptionDeviationFormat"};
  }

  static QualifiedName start_of_archive_browse_name()
  {
    return QualifiedName{0, "StartOfArchive"};
  }

  static QualifiedName start_of_online_archive_browse_name()
  {
    return QualifiedName{0, "StartOfOnlineArchive"};
  }

  static QualifiedName server_timestamp_supported_browse_name()
  {
    return QualifiedName{0, "ServerTimestampSupported"};
  }

  static QualifiedName max_time_stored_values_browse_name()
  {
    return QualifiedName{0, "MaxTimeStoredValues"};
  }

  static QualifiedName max_count_stored_values_browse_name()
  {
    return QualifiedName{0, "MaxCountStoredValues"};
  }
};

}  // namespace

HistoricalDataConfiguration::HistoricalDataConfiguration(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void HistoricalDataConfiguration::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    HistoricalDataConfigurationTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(HistoricalDataConfigurationResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(HistoricalDataConfigurationResult{
        HistoricalDataConfiguration{
          std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

HistoricalDataConfigurationResult HistoricalDataConfiguration::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<HistoricalDataConfigurationResult>(addressSpace.executor(),
      [&](std::function<void(HistoricalDataConfigurationResult)> complete)
      {
        HistoricalDataConfiguration::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

HistoricalDataConfiguration HistoricalDataConfiguration::create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void HistoricalDataConfiguration::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void HistoricalDataConfiguration::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // HistoricalDataConfigurationType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    HistoricalDataConfigurationTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(HistoricalDataConfigurationResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(
          HistoricalDataConfigurationResult{::ua::detail::address_space_gone("HistoricalDataConfiguration")});
        return;
      }
      complete(HistoricalDataConfiguration{
        std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

HistoricalDataConfigurationResult HistoricalDataConfiguration::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<HistoricalDataConfigurationResult>(addressSpace.executor(),
      [&](std::function<void(HistoricalDataConfigurationResult)> complete)
      {
        HistoricalDataConfiguration::attach_async(
          std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

HistoricalDataConfiguration HistoricalDataConfiguration::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void HistoricalDataConfiguration::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void HistoricalDataConfiguration::find_property_async(
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
    "HistoricalDataConfiguration",
    std::move(complete));
}

// --- Property accessors ---

void HistoricalDataConfiguration::stepped_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(HistoricalDataConfigurationTypeTraits::stepped_browse_name(), std::move(complete));
}

PropertyResult HistoricalDataConfiguration::try_stepped_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { stepped_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property HistoricalDataConfiguration::stepped_property_sync() const
{
  return ::ua::detail::good_value(try_stepped_property_sync());
}

void HistoricalDataConfiguration::definition_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(HistoricalDataConfigurationTypeTraits::definition_browse_name(), std::move(complete));
}

PropertyResult HistoricalDataConfiguration::try_definition_property_sync() const noexcept
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

Property HistoricalDataConfiguration::definition_property_sync() const
{
  return ::ua::detail::good_value(try_definition_property_sync());
}

void HistoricalDataConfiguration::max_time_interval_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    HistoricalDataConfigurationTypeTraits::max_time_interval_browse_name(), std::move(complete));
}

PropertyResult HistoricalDataConfiguration::try_max_time_interval_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_time_interval_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property HistoricalDataConfiguration::max_time_interval_property_sync() const
{
  return ::ua::detail::good_value(try_max_time_interval_property_sync());
}

void HistoricalDataConfiguration::min_time_interval_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    HistoricalDataConfigurationTypeTraits::min_time_interval_browse_name(), std::move(complete));
}

PropertyResult HistoricalDataConfiguration::try_min_time_interval_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { min_time_interval_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property HistoricalDataConfiguration::min_time_interval_property_sync() const
{
  return ::ua::detail::good_value(try_min_time_interval_property_sync());
}

void HistoricalDataConfiguration::exception_deviation_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    HistoricalDataConfigurationTypeTraits::exception_deviation_browse_name(), std::move(complete));
}

PropertyResult HistoricalDataConfiguration::try_exception_deviation_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { exception_deviation_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property HistoricalDataConfiguration::exception_deviation_property_sync() const
{
  return ::ua::detail::good_value(try_exception_deviation_property_sync());
}

void HistoricalDataConfiguration::exception_deviation_format_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    HistoricalDataConfigurationTypeTraits::exception_deviation_format_browse_name(), std::move(complete));
}

PropertyResult HistoricalDataConfiguration::try_exception_deviation_format_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { exception_deviation_format_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property HistoricalDataConfiguration::exception_deviation_format_property_sync() const
{
  return ::ua::detail::good_value(try_exception_deviation_format_property_sync());
}

void HistoricalDataConfiguration::start_of_archive_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    HistoricalDataConfigurationTypeTraits::start_of_archive_browse_name(), std::move(complete));
}

PropertyResult HistoricalDataConfiguration::try_start_of_archive_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { start_of_archive_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property HistoricalDataConfiguration::start_of_archive_property_sync() const
{
  return ::ua::detail::good_value(try_start_of_archive_property_sync());
}

void HistoricalDataConfiguration::start_of_online_archive_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    HistoricalDataConfigurationTypeTraits::start_of_online_archive_browse_name(), std::move(complete));
}

PropertyResult HistoricalDataConfiguration::try_start_of_online_archive_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { start_of_online_archive_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property HistoricalDataConfiguration::start_of_online_archive_property_sync() const
{
  return ::ua::detail::good_value(try_start_of_online_archive_property_sync());
}

void HistoricalDataConfiguration::server_timestamp_supported_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    HistoricalDataConfigurationTypeTraits::server_timestamp_supported_browse_name(), std::move(complete));
}

PropertyResult HistoricalDataConfiguration::try_server_timestamp_supported_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { server_timestamp_supported_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property HistoricalDataConfiguration::server_timestamp_supported_property_sync() const
{
  return ::ua::detail::good_value(try_server_timestamp_supported_property_sync());
}

void HistoricalDataConfiguration::max_time_stored_values_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    HistoricalDataConfigurationTypeTraits::max_time_stored_values_browse_name(), std::move(complete));
}

PropertyResult HistoricalDataConfiguration::try_max_time_stored_values_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_time_stored_values_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property HistoricalDataConfiguration::max_time_stored_values_property_sync() const
{
  return ::ua::detail::good_value(try_max_time_stored_values_property_sync());
}

void HistoricalDataConfiguration::max_count_stored_values_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    HistoricalDataConfigurationTypeTraits::max_count_stored_values_browse_name(), std::move(complete));
}

PropertyResult HistoricalDataConfiguration::try_max_count_stored_values_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_count_stored_values_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property HistoricalDataConfiguration::max_count_stored_values_property_sync() const
{
  return ::ua::detail::good_value(try_max_count_stored_values_property_sync());
}

// --- Typed value read shortcuts ---

void HistoricalDataConfiguration::read_stepped_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    HistoricalDataConfigurationTypeTraits::stepped_browse_name(),
    &Variant::is_boolean,
    {"HistoricalDataConfiguration", "stepped", "HistoricalDataConfiguration::read_stepped_async"},
    std::move(complete));
}

BoolResult HistoricalDataConfiguration::try_read_stepped_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BoolResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BoolResult)> complete) { read_stepped_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

bool HistoricalDataConfiguration::read_stepped_sync() const
{
  return ::ua::detail::good_value(try_read_stepped_sync());
}

void HistoricalDataConfiguration::read_definition_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    HistoricalDataConfigurationTypeTraits::definition_browse_name(),
    &Variant::is_string,
    {"HistoricalDataConfiguration", "definition", "HistoricalDataConfiguration::read_definition_async"},
    std::move(complete));
}

StringResult HistoricalDataConfiguration::try_read_definition_sync() const noexcept
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

String HistoricalDataConfiguration::read_definition_sync() const
{
  return ::ua::detail::good_value(try_read_definition_sync());
}

void HistoricalDataConfiguration::read_exception_deviation_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    HistoricalDataConfigurationTypeTraits::exception_deviation_browse_name(),
    &Variant::is_double,
    {"HistoricalDataConfiguration",
      "exception_deviation",
      "HistoricalDataConfiguration::read_exception_deviation_async"},
    std::move(complete));
}

DoubleResult HistoricalDataConfiguration::try_read_exception_deviation_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<DoubleResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(DoubleResult)> complete)
      { read_exception_deviation_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

double HistoricalDataConfiguration::read_exception_deviation_sync() const
{
  return ::ua::detail::good_value(try_read_exception_deviation_sync());
}

void HistoricalDataConfiguration::read_server_timestamp_supported_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    HistoricalDataConfigurationTypeTraits::server_timestamp_supported_browse_name(),
    &Variant::is_boolean,
    {"HistoricalDataConfiguration",
      "server_timestamp_supported",
      "HistoricalDataConfiguration::read_server_timestamp_supported_async"},
    std::move(complete));
}

BoolResult HistoricalDataConfiguration::try_read_server_timestamp_supported_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BoolResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BoolResult)> complete)
      { read_server_timestamp_supported_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

bool HistoricalDataConfiguration::read_server_timestamp_supported_sync() const
{
  return ::ua::detail::good_value(try_read_server_timestamp_supported_sync());
}

void HistoricalDataConfiguration::read_max_count_stored_values_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    HistoricalDataConfigurationTypeTraits::max_count_stored_values_browse_name(),
    &Variant::is_uint32,
    {"HistoricalDataConfiguration",
      "max_count_stored_values",
      "HistoricalDataConfiguration::read_max_count_stored_values_async"},
    std::move(complete));
}

UInt32Result HistoricalDataConfiguration::try_read_max_count_stored_values_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete)
      { read_max_count_stored_values_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t HistoricalDataConfiguration::read_max_count_stored_values_sync() const
{
  return ::ua::detail::good_value(try_read_max_count_stored_values_sync());
}

// --- Typed value write shortcuts ---

void HistoricalDataConfiguration::write_stepped_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    HistoricalDataConfigurationTypeTraits::stepped_browse_name(),
    "HistoricalDataConfiguration",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult HistoricalDataConfiguration::try_write_stepped_sync(bool value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_stepped_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void HistoricalDataConfiguration::write_stepped_sync(bool value) const
{
  try_write_stepped_sync(value).value();
}

void HistoricalDataConfiguration::write_definition_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    HistoricalDataConfigurationTypeTraits::definition_browse_name(),
    "HistoricalDataConfiguration",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult HistoricalDataConfiguration::try_write_definition_sync(String value) const noexcept
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

void HistoricalDataConfiguration::write_definition_sync(String value) const
{
  try_write_definition_sync(value).value();
}

void HistoricalDataConfiguration::write_exception_deviation_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    HistoricalDataConfigurationTypeTraits::exception_deviation_browse_name(),
    "HistoricalDataConfiguration",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult HistoricalDataConfiguration::try_write_exception_deviation_sync(double value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_exception_deviation_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void HistoricalDataConfiguration::write_exception_deviation_sync(double value) const
{
  try_write_exception_deviation_sync(value).value();
}

void HistoricalDataConfiguration::write_server_timestamp_supported_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    HistoricalDataConfigurationTypeTraits::server_timestamp_supported_browse_name(),
    "HistoricalDataConfiguration",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult HistoricalDataConfiguration::try_write_server_timestamp_supported_sync(bool value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_server_timestamp_supported_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void HistoricalDataConfiguration::write_server_timestamp_supported_sync(bool value) const
{
  try_write_server_timestamp_supported_sync(value).value();
}

void HistoricalDataConfiguration::write_max_count_stored_values_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    HistoricalDataConfigurationTypeTraits::max_count_stored_values_browse_name(),
    "HistoricalDataConfiguration",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult HistoricalDataConfiguration::try_write_max_count_stored_values_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_count_stored_values_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void HistoricalDataConfiguration::write_max_count_stored_values_sync(uint32_t value) const
{
  try_write_max_count_stored_values_sync(value).value();
}

// --- Child-object accessors ---

void HistoricalDataConfiguration::aggregate_functions_async(
  std::function<void(FolderResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(FolderResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<Folder>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    HistoricalDataConfigurationTypeTraits::aggregate_functions_browse_name(),
    "HistoricalDataConfiguration",
    std::move(complete));
}

FolderResult HistoricalDataConfiguration::try_aggregate_functions_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<FolderResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(FolderResult)> complete) { aggregate_functions_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Folder HistoricalDataConfiguration::aggregate_functions_sync() const
{
  return ::ua::detail::good_value(try_aggregate_functions_sync());
}

}  // namespace ua
