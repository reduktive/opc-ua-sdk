// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_server_capabilities.h"

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

struct ServerCapabilitiesTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::ServerCapabilitiesType};
  }

  static QualifiedName server_profile_array_browse_name()
  {
    return QualifiedName{0, "ServerProfileArray"};
  }

  static QualifiedName locale_id_array_browse_name()
  {
    return QualifiedName{0, "LocaleIdArray"};
  }

  static QualifiedName min_supported_sample_rate_browse_name()
  {
    return QualifiedName{0, "MinSupportedSampleRate"};
  }

  static QualifiedName max_browse_continuation_points_browse_name()
  {
    return QualifiedName{0, "MaxBrowseContinuationPoints"};
  }

  static QualifiedName max_query_continuation_points_browse_name()
  {
    return QualifiedName{0, "MaxQueryContinuationPoints"};
  }

  static QualifiedName max_history_continuation_points_browse_name()
  {
    return QualifiedName{0, "MaxHistoryContinuationPoints"};
  }

  static QualifiedName max_log_object_continuation_points_browse_name()
  {
    return QualifiedName{0, "MaxLogObjectContinuationPoints"};
  }

  static QualifiedName software_certificates_browse_name()
  {
    return QualifiedName{0, "SoftwareCertificates"};
  }

  static QualifiedName max_array_length_browse_name()
  {
    return QualifiedName{0, "MaxArrayLength"};
  }

  static QualifiedName max_string_length_browse_name()
  {
    return QualifiedName{0, "MaxStringLength"};
  }

  static QualifiedName max_byte_string_length_browse_name()
  {
    return QualifiedName{0, "MaxByteStringLength"};
  }

  static QualifiedName operation_limits_browse_name()
  {
    return QualifiedName{0, "OperationLimits"};
  }

  static QualifiedName modelling_rules_browse_name()
  {
    return QualifiedName{0, "ModellingRules"};
  }

  static QualifiedName aggregate_functions_browse_name()
  {
    return QualifiedName{0, "AggregateFunctions"};
  }

  static QualifiedName role_set_browse_name()
  {
    return QualifiedName{0, "RoleSet"};
  }

  static QualifiedName max_sessions_browse_name()
  {
    return QualifiedName{0, "MaxSessions"};
  }

  static QualifiedName max_subscriptions_browse_name()
  {
    return QualifiedName{0, "MaxSubscriptions"};
  }

  static QualifiedName max_monitored_items_browse_name()
  {
    return QualifiedName{0, "MaxMonitoredItems"};
  }

  static QualifiedName max_subscriptions_per_session_browse_name()
  {
    return QualifiedName{0, "MaxSubscriptionsPerSession"};
  }

  static QualifiedName max_monitored_items_per_subscription_browse_name()
  {
    return QualifiedName{0, "MaxMonitoredItemsPerSubscription"};
  }

  static QualifiedName max_select_clause_parameters_browse_name()
  {
    return QualifiedName{0, "MaxSelectClauseParameters"};
  }

  static QualifiedName max_where_clause_parameters_browse_name()
  {
    return QualifiedName{0, "MaxWhereClauseParameters"};
  }

  static QualifiedName max_monitored_items_queue_size_browse_name()
  {
    return QualifiedName{0, "MaxMonitoredItemsQueueSize"};
  }

  static QualifiedName conformance_units_browse_name()
  {
    return QualifiedName{0, "ConformanceUnits"};
  }
};

}  // namespace

ServerCapabilities::ServerCapabilities(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void ServerCapabilities::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    ServerCapabilitiesTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(ServerCapabilitiesResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(ServerCapabilitiesResult{
        ServerCapabilities{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

ServerCapabilitiesResult ServerCapabilities::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ServerCapabilitiesResult>(addressSpace.executor(),
      [&](std::function<void(ServerCapabilitiesResult)> complete)
      {
        ServerCapabilities::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ServerCapabilities ServerCapabilities::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void ServerCapabilities::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void ServerCapabilities::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // ServerCapabilitiesType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    ServerCapabilitiesTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(ServerCapabilitiesResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(ServerCapabilitiesResult{::ua::detail::address_space_gone("ServerCapabilities")});
        return;
      }
      complete(ServerCapabilities{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

ServerCapabilitiesResult ServerCapabilities::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ServerCapabilitiesResult>(addressSpace.executor(),
      [&](std::function<void(ServerCapabilitiesResult)> complete)
      {
        ServerCapabilities::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ServerCapabilities ServerCapabilities::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void ServerCapabilities::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void ServerCapabilities::find_property_async(
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
    "ServerCapabilities",
    std::move(complete));
}

// --- Property accessors ---

void ServerCapabilities::server_profile_array_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ServerCapabilitiesTypeTraits::server_profile_array_browse_name(), std::move(complete));
}

PropertyResult ServerCapabilities::try_server_profile_array_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { server_profile_array_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerCapabilities::server_profile_array_property_sync() const
{
  return ::ua::detail::good_value(try_server_profile_array_property_sync());
}

void ServerCapabilities::locale_id_array_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ServerCapabilitiesTypeTraits::locale_id_array_browse_name(), std::move(complete));
}

PropertyResult ServerCapabilities::try_locale_id_array_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { locale_id_array_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerCapabilities::locale_id_array_property_sync() const
{
  return ::ua::detail::good_value(try_locale_id_array_property_sync());
}

void ServerCapabilities::min_supported_sample_rate_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ServerCapabilitiesTypeTraits::min_supported_sample_rate_browse_name(), std::move(complete));
}

PropertyResult ServerCapabilities::try_min_supported_sample_rate_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { min_supported_sample_rate_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerCapabilities::min_supported_sample_rate_property_sync() const
{
  return ::ua::detail::good_value(try_min_supported_sample_rate_property_sync());
}

void ServerCapabilities::max_browse_continuation_points_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ServerCapabilitiesTypeTraits::max_browse_continuation_points_browse_name(), std::move(complete));
}

PropertyResult ServerCapabilities::try_max_browse_continuation_points_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_browse_continuation_points_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerCapabilities::max_browse_continuation_points_property_sync() const
{
  return ::ua::detail::good_value(try_max_browse_continuation_points_property_sync());
}

void ServerCapabilities::max_query_continuation_points_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ServerCapabilitiesTypeTraits::max_query_continuation_points_browse_name(), std::move(complete));
}

PropertyResult ServerCapabilities::try_max_query_continuation_points_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_query_continuation_points_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerCapabilities::max_query_continuation_points_property_sync() const
{
  return ::ua::detail::good_value(try_max_query_continuation_points_property_sync());
}

void ServerCapabilities::max_history_continuation_points_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ServerCapabilitiesTypeTraits::max_history_continuation_points_browse_name(), std::move(complete));
}

PropertyResult ServerCapabilities::try_max_history_continuation_points_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_history_continuation_points_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerCapabilities::max_history_continuation_points_property_sync() const
{
  return ::ua::detail::good_value(try_max_history_continuation_points_property_sync());
}

void ServerCapabilities::max_log_object_continuation_points_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ServerCapabilitiesTypeTraits::max_log_object_continuation_points_browse_name(), std::move(complete));
}

PropertyResult ServerCapabilities::try_max_log_object_continuation_points_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_log_object_continuation_points_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerCapabilities::max_log_object_continuation_points_property_sync() const
{
  return ::ua::detail::good_value(try_max_log_object_continuation_points_property_sync());
}

void ServerCapabilities::software_certificates_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ServerCapabilitiesTypeTraits::software_certificates_browse_name(), std::move(complete));
}

PropertyResult ServerCapabilities::try_software_certificates_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { software_certificates_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerCapabilities::software_certificates_property_sync() const
{
  return ::ua::detail::good_value(try_software_certificates_property_sync());
}

void ServerCapabilities::max_array_length_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ServerCapabilitiesTypeTraits::max_array_length_browse_name(), std::move(complete));
}

PropertyResult ServerCapabilities::try_max_array_length_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_array_length_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerCapabilities::max_array_length_property_sync() const
{
  return ::ua::detail::good_value(try_max_array_length_property_sync());
}

void ServerCapabilities::max_string_length_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ServerCapabilitiesTypeTraits::max_string_length_browse_name(), std::move(complete));
}

PropertyResult ServerCapabilities::try_max_string_length_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_string_length_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerCapabilities::max_string_length_property_sync() const
{
  return ::ua::detail::good_value(try_max_string_length_property_sync());
}

void ServerCapabilities::max_byte_string_length_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ServerCapabilitiesTypeTraits::max_byte_string_length_browse_name(), std::move(complete));
}

PropertyResult ServerCapabilities::try_max_byte_string_length_property_sync() const noexcept
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

Property ServerCapabilities::max_byte_string_length_property_sync() const
{
  return ::ua::detail::good_value(try_max_byte_string_length_property_sync());
}

void ServerCapabilities::max_sessions_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ServerCapabilitiesTypeTraits::max_sessions_browse_name(), std::move(complete));
}

PropertyResult ServerCapabilities::try_max_sessions_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_sessions_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerCapabilities::max_sessions_property_sync() const
{
  return ::ua::detail::good_value(try_max_sessions_property_sync());
}

void ServerCapabilities::max_subscriptions_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ServerCapabilitiesTypeTraits::max_subscriptions_browse_name(), std::move(complete));
}

PropertyResult ServerCapabilities::try_max_subscriptions_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_subscriptions_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerCapabilities::max_subscriptions_property_sync() const
{
  return ::ua::detail::good_value(try_max_subscriptions_property_sync());
}

void ServerCapabilities::max_monitored_items_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ServerCapabilitiesTypeTraits::max_monitored_items_browse_name(), std::move(complete));
}

PropertyResult ServerCapabilities::try_max_monitored_items_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_monitored_items_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerCapabilities::max_monitored_items_property_sync() const
{
  return ::ua::detail::good_value(try_max_monitored_items_property_sync());
}

void ServerCapabilities::max_subscriptions_per_session_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ServerCapabilitiesTypeTraits::max_subscriptions_per_session_browse_name(), std::move(complete));
}

PropertyResult ServerCapabilities::try_max_subscriptions_per_session_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_subscriptions_per_session_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerCapabilities::max_subscriptions_per_session_property_sync() const
{
  return ::ua::detail::good_value(try_max_subscriptions_per_session_property_sync());
}

void ServerCapabilities::max_monitored_items_per_subscription_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ServerCapabilitiesTypeTraits::max_monitored_items_per_subscription_browse_name(), std::move(complete));
}

PropertyResult ServerCapabilities::try_max_monitored_items_per_subscription_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_monitored_items_per_subscription_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerCapabilities::max_monitored_items_per_subscription_property_sync() const
{
  return ::ua::detail::good_value(try_max_monitored_items_per_subscription_property_sync());
}

void ServerCapabilities::max_select_clause_parameters_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ServerCapabilitiesTypeTraits::max_select_clause_parameters_browse_name(), std::move(complete));
}

PropertyResult ServerCapabilities::try_max_select_clause_parameters_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_select_clause_parameters_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerCapabilities::max_select_clause_parameters_property_sync() const
{
  return ::ua::detail::good_value(try_max_select_clause_parameters_property_sync());
}

void ServerCapabilities::max_where_clause_parameters_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ServerCapabilitiesTypeTraits::max_where_clause_parameters_browse_name(), std::move(complete));
}

PropertyResult ServerCapabilities::try_max_where_clause_parameters_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_where_clause_parameters_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerCapabilities::max_where_clause_parameters_property_sync() const
{
  return ::ua::detail::good_value(try_max_where_clause_parameters_property_sync());
}

void ServerCapabilities::max_monitored_items_queue_size_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ServerCapabilitiesTypeTraits::max_monitored_items_queue_size_browse_name(), std::move(complete));
}

PropertyResult ServerCapabilities::try_max_monitored_items_queue_size_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_monitored_items_queue_size_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerCapabilities::max_monitored_items_queue_size_property_sync() const
{
  return ::ua::detail::good_value(try_max_monitored_items_queue_size_property_sync());
}

void ServerCapabilities::conformance_units_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ServerCapabilitiesTypeTraits::conformance_units_browse_name(), std::move(complete));
}

PropertyResult ServerCapabilities::try_conformance_units_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { conformance_units_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerCapabilities::conformance_units_property_sync() const
{
  return ::ua::detail::good_value(try_conformance_units_property_sync());
}

// --- Typed value read shortcuts ---

void ServerCapabilities::read_server_profile_array_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::server_profile_array_browse_name(),
    &Variant::is_string,
    {"ServerCapabilities", "server_profile_array", "ServerCapabilities::read_server_profile_array_async"},
    std::move(complete));
}

StringResult ServerCapabilities::try_read_server_profile_array_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete)
      { read_server_profile_array_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String ServerCapabilities::read_server_profile_array_sync() const
{
  return ::ua::detail::good_value(try_read_server_profile_array_sync());
}

void ServerCapabilities::read_max_browse_continuation_points_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_browse_continuation_points_browse_name(),
    &Variant::is_uint16,
    {"ServerCapabilities",
      "max_browse_continuation_points",
      "ServerCapabilities::read_max_browse_continuation_points_async"},
    std::move(complete));
}

UInt16Result ServerCapabilities::try_read_max_browse_continuation_points_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt16Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt16Result)> complete)
      { read_max_browse_continuation_points_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint16_t ServerCapabilities::read_max_browse_continuation_points_sync() const
{
  return ::ua::detail::good_value(try_read_max_browse_continuation_points_sync());
}

void ServerCapabilities::read_max_query_continuation_points_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_query_continuation_points_browse_name(),
    &Variant::is_uint16,
    {"ServerCapabilities",
      "max_query_continuation_points",
      "ServerCapabilities::read_max_query_continuation_points_async"},
    std::move(complete));
}

UInt16Result ServerCapabilities::try_read_max_query_continuation_points_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt16Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt16Result)> complete)
      { read_max_query_continuation_points_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint16_t ServerCapabilities::read_max_query_continuation_points_sync() const
{
  return ::ua::detail::good_value(try_read_max_query_continuation_points_sync());
}

void ServerCapabilities::read_max_history_continuation_points_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_history_continuation_points_browse_name(),
    &Variant::is_uint16,
    {"ServerCapabilities",
      "max_history_continuation_points",
      "ServerCapabilities::read_max_history_continuation_points_async"},
    std::move(complete));
}

UInt16Result ServerCapabilities::try_read_max_history_continuation_points_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt16Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt16Result)> complete)
      { read_max_history_continuation_points_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint16_t ServerCapabilities::read_max_history_continuation_points_sync() const
{
  return ::ua::detail::good_value(try_read_max_history_continuation_points_sync());
}

void ServerCapabilities::read_max_log_object_continuation_points_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_log_object_continuation_points_browse_name(),
    &Variant::is_uint16,
    {"ServerCapabilities",
      "max_log_object_continuation_points",
      "ServerCapabilities::read_max_log_object_continuation_points_async"},
    std::move(complete));
}

UInt16Result ServerCapabilities::try_read_max_log_object_continuation_points_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt16Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt16Result)> complete)
      { read_max_log_object_continuation_points_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint16_t ServerCapabilities::read_max_log_object_continuation_points_sync() const
{
  return ::ua::detail::good_value(try_read_max_log_object_continuation_points_sync());
}

void ServerCapabilities::read_max_array_length_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_array_length_browse_name(),
    &Variant::is_uint32,
    {"ServerCapabilities", "max_array_length", "ServerCapabilities::read_max_array_length_async"},
    std::move(complete));
}

UInt32Result ServerCapabilities::try_read_max_array_length_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete) { read_max_array_length_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t ServerCapabilities::read_max_array_length_sync() const
{
  return ::ua::detail::good_value(try_read_max_array_length_sync());
}

void ServerCapabilities::read_max_string_length_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_string_length_browse_name(),
    &Variant::is_uint32,
    {"ServerCapabilities", "max_string_length", "ServerCapabilities::read_max_string_length_async"},
    std::move(complete));
}

UInt32Result ServerCapabilities::try_read_max_string_length_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete) { read_max_string_length_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t ServerCapabilities::read_max_string_length_sync() const
{
  return ::ua::detail::good_value(try_read_max_string_length_sync());
}

void ServerCapabilities::read_max_byte_string_length_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_byte_string_length_browse_name(),
    &Variant::is_uint32,
    {"ServerCapabilities", "max_byte_string_length", "ServerCapabilities::read_max_byte_string_length_async"},
    std::move(complete));
}

UInt32Result ServerCapabilities::try_read_max_byte_string_length_sync() const noexcept
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

uint32_t ServerCapabilities::read_max_byte_string_length_sync() const
{
  return ::ua::detail::good_value(try_read_max_byte_string_length_sync());
}

void ServerCapabilities::read_max_sessions_async(std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_sessions_browse_name(),
    &Variant::is_uint32,
    {"ServerCapabilities", "max_sessions", "ServerCapabilities::read_max_sessions_async"},
    std::move(complete));
}

UInt32Result ServerCapabilities::try_read_max_sessions_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete) { read_max_sessions_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t ServerCapabilities::read_max_sessions_sync() const
{
  return ::ua::detail::good_value(try_read_max_sessions_sync());
}

void ServerCapabilities::read_max_subscriptions_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_subscriptions_browse_name(),
    &Variant::is_uint32,
    {"ServerCapabilities", "max_subscriptions", "ServerCapabilities::read_max_subscriptions_async"},
    std::move(complete));
}

UInt32Result ServerCapabilities::try_read_max_subscriptions_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete) { read_max_subscriptions_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t ServerCapabilities::read_max_subscriptions_sync() const
{
  return ::ua::detail::good_value(try_read_max_subscriptions_sync());
}

void ServerCapabilities::read_max_monitored_items_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_monitored_items_browse_name(),
    &Variant::is_uint32,
    {"ServerCapabilities", "max_monitored_items", "ServerCapabilities::read_max_monitored_items_async"},
    std::move(complete));
}

UInt32Result ServerCapabilities::try_read_max_monitored_items_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete)
      { read_max_monitored_items_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t ServerCapabilities::read_max_monitored_items_sync() const
{
  return ::ua::detail::good_value(try_read_max_monitored_items_sync());
}

void ServerCapabilities::read_max_subscriptions_per_session_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_subscriptions_per_session_browse_name(),
    &Variant::is_uint32,
    {"ServerCapabilities",
      "max_subscriptions_per_session",
      "ServerCapabilities::read_max_subscriptions_per_session_async"},
    std::move(complete));
}

UInt32Result ServerCapabilities::try_read_max_subscriptions_per_session_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete)
      { read_max_subscriptions_per_session_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t ServerCapabilities::read_max_subscriptions_per_session_sync() const
{
  return ::ua::detail::good_value(try_read_max_subscriptions_per_session_sync());
}

void ServerCapabilities::read_max_monitored_items_per_subscription_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_monitored_items_per_subscription_browse_name(),
    &Variant::is_uint32,
    {"ServerCapabilities",
      "max_monitored_items_per_subscription",
      "ServerCapabilities::read_max_monitored_items_per_subscription_async"},
    std::move(complete));
}

UInt32Result ServerCapabilities::try_read_max_monitored_items_per_subscription_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete)
      { read_max_monitored_items_per_subscription_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t ServerCapabilities::read_max_monitored_items_per_subscription_sync() const
{
  return ::ua::detail::good_value(try_read_max_monitored_items_per_subscription_sync());
}

void ServerCapabilities::read_max_select_clause_parameters_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_select_clause_parameters_browse_name(),
    &Variant::is_uint32,
    {"ServerCapabilities",
      "max_select_clause_parameters",
      "ServerCapabilities::read_max_select_clause_parameters_async"},
    std::move(complete));
}

UInt32Result ServerCapabilities::try_read_max_select_clause_parameters_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete)
      { read_max_select_clause_parameters_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t ServerCapabilities::read_max_select_clause_parameters_sync() const
{
  return ::ua::detail::good_value(try_read_max_select_clause_parameters_sync());
}

void ServerCapabilities::read_max_where_clause_parameters_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_where_clause_parameters_browse_name(),
    &Variant::is_uint32,
    {"ServerCapabilities",
      "max_where_clause_parameters",
      "ServerCapabilities::read_max_where_clause_parameters_async"},
    std::move(complete));
}

UInt32Result ServerCapabilities::try_read_max_where_clause_parameters_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete)
      { read_max_where_clause_parameters_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t ServerCapabilities::read_max_where_clause_parameters_sync() const
{
  return ::ua::detail::good_value(try_read_max_where_clause_parameters_sync());
}

void ServerCapabilities::read_max_monitored_items_queue_size_async(
  std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_monitored_items_queue_size_browse_name(),
    &Variant::is_uint32,
    {"ServerCapabilities",
      "max_monitored_items_queue_size",
      "ServerCapabilities::read_max_monitored_items_queue_size_async"},
    std::move(complete));
}

UInt32Result ServerCapabilities::try_read_max_monitored_items_queue_size_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete)
      { read_max_monitored_items_queue_size_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t ServerCapabilities::read_max_monitored_items_queue_size_sync() const
{
  return ::ua::detail::good_value(try_read_max_monitored_items_queue_size_sync());
}

void ServerCapabilities::read_conformance_units_async(
  std::function<void(QualifiedNameResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(QualifiedNameResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<QualifiedName>(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::conformance_units_browse_name(),
    &Variant::is_qualified_name,
    {"ServerCapabilities", "conformance_units", "ServerCapabilities::read_conformance_units_async"},
    std::move(complete));
}

QualifiedNameResult ServerCapabilities::try_read_conformance_units_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<QualifiedNameResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(QualifiedNameResult)> complete)
      { read_conformance_units_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

QualifiedName ServerCapabilities::read_conformance_units_sync() const
{
  return ::ua::detail::good_value(try_read_conformance_units_sync());
}

// --- Typed value write shortcuts ---

void ServerCapabilities::write_server_profile_array_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::server_profile_array_browse_name(),
    "ServerCapabilities",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ServerCapabilities::try_write_server_profile_array_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_server_profile_array_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerCapabilities::write_server_profile_array_sync(String value) const
{
  try_write_server_profile_array_sync(value).value();
}

void ServerCapabilities::write_max_browse_continuation_points_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_browse_continuation_points_browse_name(),
    "ServerCapabilities",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ServerCapabilities::try_write_max_browse_continuation_points_sync(uint16_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_browse_continuation_points_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerCapabilities::write_max_browse_continuation_points_sync(uint16_t value) const
{
  try_write_max_browse_continuation_points_sync(value).value();
}

void ServerCapabilities::write_max_query_continuation_points_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_query_continuation_points_browse_name(),
    "ServerCapabilities",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ServerCapabilities::try_write_max_query_continuation_points_sync(uint16_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_query_continuation_points_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerCapabilities::write_max_query_continuation_points_sync(uint16_t value) const
{
  try_write_max_query_continuation_points_sync(value).value();
}

void ServerCapabilities::write_max_history_continuation_points_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_history_continuation_points_browse_name(),
    "ServerCapabilities",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ServerCapabilities::try_write_max_history_continuation_points_sync(uint16_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_history_continuation_points_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerCapabilities::write_max_history_continuation_points_sync(uint16_t value) const
{
  try_write_max_history_continuation_points_sync(value).value();
}

void ServerCapabilities::write_max_log_object_continuation_points_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_log_object_continuation_points_browse_name(),
    "ServerCapabilities",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ServerCapabilities::try_write_max_log_object_continuation_points_sync(
  uint16_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_log_object_continuation_points_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerCapabilities::write_max_log_object_continuation_points_sync(uint16_t value) const
{
  try_write_max_log_object_continuation_points_sync(value).value();
}

void ServerCapabilities::write_max_array_length_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_array_length_browse_name(),
    "ServerCapabilities",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ServerCapabilities::try_write_max_array_length_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_array_length_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerCapabilities::write_max_array_length_sync(uint32_t value) const
{
  try_write_max_array_length_sync(value).value();
}

void ServerCapabilities::write_max_string_length_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_string_length_browse_name(),
    "ServerCapabilities",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ServerCapabilities::try_write_max_string_length_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_string_length_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerCapabilities::write_max_string_length_sync(uint32_t value) const
{
  try_write_max_string_length_sync(value).value();
}

void ServerCapabilities::write_max_byte_string_length_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_byte_string_length_browse_name(),
    "ServerCapabilities",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ServerCapabilities::try_write_max_byte_string_length_sync(uint32_t value) const noexcept
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

void ServerCapabilities::write_max_byte_string_length_sync(uint32_t value) const
{
  try_write_max_byte_string_length_sync(value).value();
}

void ServerCapabilities::write_max_sessions_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_sessions_browse_name(),
    "ServerCapabilities",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ServerCapabilities::try_write_max_sessions_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_sessions_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerCapabilities::write_max_sessions_sync(uint32_t value) const
{
  try_write_max_sessions_sync(value).value();
}

void ServerCapabilities::write_max_subscriptions_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_subscriptions_browse_name(),
    "ServerCapabilities",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ServerCapabilities::try_write_max_subscriptions_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_subscriptions_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerCapabilities::write_max_subscriptions_sync(uint32_t value) const
{
  try_write_max_subscriptions_sync(value).value();
}

void ServerCapabilities::write_max_monitored_items_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_monitored_items_browse_name(),
    "ServerCapabilities",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ServerCapabilities::try_write_max_monitored_items_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_monitored_items_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerCapabilities::write_max_monitored_items_sync(uint32_t value) const
{
  try_write_max_monitored_items_sync(value).value();
}

void ServerCapabilities::write_max_subscriptions_per_session_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_subscriptions_per_session_browse_name(),
    "ServerCapabilities",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ServerCapabilities::try_write_max_subscriptions_per_session_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_subscriptions_per_session_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerCapabilities::write_max_subscriptions_per_session_sync(uint32_t value) const
{
  try_write_max_subscriptions_per_session_sync(value).value();
}

void ServerCapabilities::write_max_monitored_items_per_subscription_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_monitored_items_per_subscription_browse_name(),
    "ServerCapabilities",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ServerCapabilities::try_write_max_monitored_items_per_subscription_sync(
  uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_monitored_items_per_subscription_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerCapabilities::write_max_monitored_items_per_subscription_sync(uint32_t value) const
{
  try_write_max_monitored_items_per_subscription_sync(value).value();
}

void ServerCapabilities::write_max_select_clause_parameters_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_select_clause_parameters_browse_name(),
    "ServerCapabilities",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ServerCapabilities::try_write_max_select_clause_parameters_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_select_clause_parameters_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerCapabilities::write_max_select_clause_parameters_sync(uint32_t value) const
{
  try_write_max_select_clause_parameters_sync(value).value();
}

void ServerCapabilities::write_max_where_clause_parameters_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_where_clause_parameters_browse_name(),
    "ServerCapabilities",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ServerCapabilities::try_write_max_where_clause_parameters_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_where_clause_parameters_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerCapabilities::write_max_where_clause_parameters_sync(uint32_t value) const
{
  try_write_max_where_clause_parameters_sync(value).value();
}

void ServerCapabilities::write_max_monitored_items_queue_size_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::max_monitored_items_queue_size_browse_name(),
    "ServerCapabilities",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ServerCapabilities::try_write_max_monitored_items_queue_size_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_max_monitored_items_queue_size_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerCapabilities::write_max_monitored_items_queue_size_sync(uint32_t value) const
{
  try_write_max_monitored_items_queue_size_sync(value).value();
}

void ServerCapabilities::write_conformance_units_async(
  QualifiedName value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ServerCapabilitiesTypeTraits::conformance_units_browse_name(),
    "ServerCapabilities",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ServerCapabilities::try_write_conformance_units_sync(QualifiedName value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_conformance_units_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerCapabilities::write_conformance_units_sync(QualifiedName value) const
{
  try_write_conformance_units_sync(value).value();
}

// --- Child-object accessors ---

void ServerCapabilities::operation_limits_async(
  std::function<void(OperationLimitsResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(OperationLimitsResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<OperationLimits>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ServerCapabilitiesTypeTraits::operation_limits_browse_name(),
    "ServerCapabilities",
    std::move(complete));
}

OperationLimitsResult ServerCapabilities::try_operation_limits_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<OperationLimitsResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(OperationLimitsResult)> complete)
      { operation_limits_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

OperationLimits ServerCapabilities::operation_limits_sync() const
{
  return ::ua::detail::good_value(try_operation_limits_sync());
}

void ServerCapabilities::modelling_rules_async(std::function<void(FolderResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(FolderResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<Folder>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ServerCapabilitiesTypeTraits::modelling_rules_browse_name(),
    "ServerCapabilities",
    std::move(complete));
}

FolderResult ServerCapabilities::try_modelling_rules_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<FolderResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(FolderResult)> complete) { modelling_rules_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Folder ServerCapabilities::modelling_rules_sync() const
{
  return ::ua::detail::good_value(try_modelling_rules_sync());
}

void ServerCapabilities::aggregate_functions_async(std::function<void(FolderResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(FolderResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<Folder>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ServerCapabilitiesTypeTraits::aggregate_functions_browse_name(),
    "ServerCapabilities",
    std::move(complete));
}

FolderResult ServerCapabilities::try_aggregate_functions_sync() const noexcept
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

Folder ServerCapabilities::aggregate_functions_sync() const
{
  return ::ua::detail::good_value(try_aggregate_functions_sync());
}

void ServerCapabilities::role_set_async(std::function<void(RoleSetResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(RoleSetResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<RoleSet>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ServerCapabilitiesTypeTraits::role_set_browse_name(),
    "ServerCapabilities",
    std::move(complete));
}

RoleSetResult ServerCapabilities::try_role_set_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<RoleSetResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(RoleSetResult)> complete) { role_set_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

RoleSet ServerCapabilities::role_set_sync() const
{
  return ::ua::detail::good_value(try_role_set_sync());
}

}  // namespace ua
