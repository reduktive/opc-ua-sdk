// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_non_exclusive_deviation_alarm.h"

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

struct NonExclusiveDeviationAlarmTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::NonExclusiveDeviationAlarmType};
  }

  static QualifiedName setpoint_node_browse_name()
  {
    return QualifiedName{0, "SetpointNode"};
  }

  static QualifiedName base_setpoint_node_browse_name()
  {
    return QualifiedName{0, "BaseSetpointNode"};
  }

  static QualifiedName high_high_limit_browse_name()
  {
    return QualifiedName{0, "HighHighLimit"};
  }

  static QualifiedName high_limit_browse_name()
  {
    return QualifiedName{0, "HighLimit"};
  }

  static QualifiedName low_limit_browse_name()
  {
    return QualifiedName{0, "LowLimit"};
  }

  static QualifiedName low_low_limit_browse_name()
  {
    return QualifiedName{0, "LowLowLimit"};
  }

  static QualifiedName base_high_high_limit_browse_name()
  {
    return QualifiedName{0, "BaseHighHighLimit"};
  }

  static QualifiedName base_high_limit_browse_name()
  {
    return QualifiedName{0, "BaseHighLimit"};
  }

  static QualifiedName base_low_limit_browse_name()
  {
    return QualifiedName{0, "BaseLowLimit"};
  }

  static QualifiedName base_low_low_limit_browse_name()
  {
    return QualifiedName{0, "BaseLowLowLimit"};
  }

  static QualifiedName severity_high_high_browse_name()
  {
    return QualifiedName{0, "SeverityHighHigh"};
  }

  static QualifiedName severity_high_browse_name()
  {
    return QualifiedName{0, "SeverityHigh"};
  }

  static QualifiedName severity_low_browse_name()
  {
    return QualifiedName{0, "SeverityLow"};
  }

  static QualifiedName severity_low_low_browse_name()
  {
    return QualifiedName{0, "SeverityLowLow"};
  }

  static QualifiedName high_high_deadband_browse_name()
  {
    return QualifiedName{0, "HighHighDeadband"};
  }

  static QualifiedName high_deadband_browse_name()
  {
    return QualifiedName{0, "HighDeadband"};
  }

  static QualifiedName low_deadband_browse_name()
  {
    return QualifiedName{0, "LowDeadband"};
  }

  static QualifiedName low_low_deadband_browse_name()
  {
    return QualifiedName{0, "LowLowDeadband"};
  }

  static QualifiedName input_node_browse_name()
  {
    return QualifiedName{0, "InputNode"};
  }

  static QualifiedName suppressed_or_shelved_browse_name()
  {
    return QualifiedName{0, "SuppressedOrShelved"};
  }

  static QualifiedName max_time_shelved_browse_name()
  {
    return QualifiedName{0, "MaxTimeShelved"};
  }

  static QualifiedName audible_enabled_browse_name()
  {
    return QualifiedName{0, "AudibleEnabled"};
  }

  static QualifiedName on_delay_browse_name()
  {
    return QualifiedName{0, "OnDelay"};
  }

  static QualifiedName off_delay_browse_name()
  {
    return QualifiedName{0, "OffDelay"};
  }

  static QualifiedName re_alarm_time_browse_name()
  {
    return QualifiedName{0, "ReAlarmTime"};
  }

  static QualifiedName condition_class_id_browse_name()
  {
    return QualifiedName{0, "ConditionClassId"};
  }

  static QualifiedName condition_class_name_browse_name()
  {
    return QualifiedName{0, "ConditionClassName"};
  }

  static QualifiedName condition_sub_class_id_browse_name()
  {
    return QualifiedName{0, "ConditionSubClassId"};
  }

  static QualifiedName condition_sub_class_name_browse_name()
  {
    return QualifiedName{0, "ConditionSubClassName"};
  }

  static QualifiedName condition_name_browse_name()
  {
    return QualifiedName{0, "ConditionName"};
  }

  static QualifiedName branch_id_browse_name()
  {
    return QualifiedName{0, "BranchId"};
  }

  static QualifiedName retain_browse_name()
  {
    return QualifiedName{0, "Retain"};
  }

  static QualifiedName supports_filtered_retain_browse_name()
  {
    return QualifiedName{0, "SupportsFilteredRetain"};
  }

  static QualifiedName client_user_id_browse_name()
  {
    return QualifiedName{0, "ClientUserId"};
  }

  static QualifiedName event_id_browse_name()
  {
    return QualifiedName{0, "EventId"};
  }

  static QualifiedName event_type_browse_name()
  {
    return QualifiedName{0, "EventType"};
  }

  static QualifiedName source_node_browse_name()
  {
    return QualifiedName{0, "SourceNode"};
  }

  static QualifiedName source_name_browse_name()
  {
    return QualifiedName{0, "SourceName"};
  }

  static QualifiedName time_browse_name()
  {
    return QualifiedName{0, "Time"};
  }

  static QualifiedName receive_time_browse_name()
  {
    return QualifiedName{0, "ReceiveTime"};
  }

  static QualifiedName local_time_browse_name()
  {
    return QualifiedName{0, "LocalTime"};
  }

  static QualifiedName message_browse_name()
  {
    return QualifiedName{0, "Message"};
  }

  static QualifiedName severity_browse_name()
  {
    return QualifiedName{0, "Severity"};
  }
};

}  // namespace

NonExclusiveDeviationAlarm::NonExclusiveDeviationAlarm(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void NonExclusiveDeviationAlarm::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    NonExclusiveDeviationAlarmTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(NonExclusiveDeviationAlarmResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(NonExclusiveDeviationAlarmResult{
        NonExclusiveDeviationAlarm{
          std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

NonExclusiveDeviationAlarmResult NonExclusiveDeviationAlarm::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NonExclusiveDeviationAlarmResult>(addressSpace.executor(),
      [&](std::function<void(NonExclusiveDeviationAlarmResult)> complete)
      {
        NonExclusiveDeviationAlarm::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NonExclusiveDeviationAlarm NonExclusiveDeviationAlarm::create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void NonExclusiveDeviationAlarm::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void NonExclusiveDeviationAlarm::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // NonExclusiveDeviationAlarmType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    NonExclusiveDeviationAlarmTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(NonExclusiveDeviationAlarmResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(
          NonExclusiveDeviationAlarmResult{::ua::detail::address_space_gone("NonExclusiveDeviationAlarm")});
        return;
      }
      complete(NonExclusiveDeviationAlarm{
        std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

NonExclusiveDeviationAlarmResult NonExclusiveDeviationAlarm::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NonExclusiveDeviationAlarmResult>(addressSpace.executor(),
      [&](std::function<void(NonExclusiveDeviationAlarmResult)> complete)
      {
        NonExclusiveDeviationAlarm::attach_async(
          std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NonExclusiveDeviationAlarm NonExclusiveDeviationAlarm::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void NonExclusiveDeviationAlarm::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void NonExclusiveDeviationAlarm::find_property_async(
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
    "NonExclusiveDeviationAlarm",
    std::move(complete));
}

// --- Property accessors ---

void NonExclusiveDeviationAlarm::setpoint_node_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveDeviationAlarmTypeTraits::setpoint_node_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_setpoint_node_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { setpoint_node_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::setpoint_node_property_sync() const
{
  return ::ua::detail::good_value(try_setpoint_node_property_sync());
}

void NonExclusiveDeviationAlarm::base_setpoint_node_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveDeviationAlarmTypeTraits::base_setpoint_node_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_base_setpoint_node_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { base_setpoint_node_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::base_setpoint_node_property_sync() const
{
  return ::ua::detail::good_value(try_base_setpoint_node_property_sync());
}

void NonExclusiveDeviationAlarm::high_high_limit_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveDeviationAlarmTypeTraits::high_high_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_high_high_limit_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { high_high_limit_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::high_high_limit_property_sync() const
{
  return ::ua::detail::good_value(try_high_high_limit_property_sync());
}

void NonExclusiveDeviationAlarm::high_limit_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveDeviationAlarmTypeTraits::high_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_high_limit_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { high_limit_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::high_limit_property_sync() const
{
  return ::ua::detail::good_value(try_high_limit_property_sync());
}

void NonExclusiveDeviationAlarm::low_limit_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveDeviationAlarmTypeTraits::low_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_low_limit_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { low_limit_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::low_limit_property_sync() const
{
  return ::ua::detail::good_value(try_low_limit_property_sync());
}

void NonExclusiveDeviationAlarm::low_low_limit_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveDeviationAlarmTypeTraits::low_low_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_low_low_limit_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { low_low_limit_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::low_low_limit_property_sync() const
{
  return ::ua::detail::good_value(try_low_low_limit_property_sync());
}

void NonExclusiveDeviationAlarm::base_high_high_limit_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveDeviationAlarmTypeTraits::base_high_high_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_base_high_high_limit_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { base_high_high_limit_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::base_high_high_limit_property_sync() const
{
  return ::ua::detail::good_value(try_base_high_high_limit_property_sync());
}

void NonExclusiveDeviationAlarm::base_high_limit_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveDeviationAlarmTypeTraits::base_high_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_base_high_limit_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { base_high_limit_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::base_high_limit_property_sync() const
{
  return ::ua::detail::good_value(try_base_high_limit_property_sync());
}

void NonExclusiveDeviationAlarm::base_low_limit_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveDeviationAlarmTypeTraits::base_low_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_base_low_limit_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { base_low_limit_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::base_low_limit_property_sync() const
{
  return ::ua::detail::good_value(try_base_low_limit_property_sync());
}

void NonExclusiveDeviationAlarm::base_low_low_limit_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveDeviationAlarmTypeTraits::base_low_low_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_base_low_low_limit_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { base_low_low_limit_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::base_low_low_limit_property_sync() const
{
  return ::ua::detail::good_value(try_base_low_low_limit_property_sync());
}

void NonExclusiveDeviationAlarm::severity_high_high_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveDeviationAlarmTypeTraits::severity_high_high_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_severity_high_high_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { severity_high_high_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::severity_high_high_property_sync() const
{
  return ::ua::detail::good_value(try_severity_high_high_property_sync());
}

void NonExclusiveDeviationAlarm::severity_high_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveDeviationAlarmTypeTraits::severity_high_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_severity_high_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { severity_high_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::severity_high_property_sync() const
{
  return ::ua::detail::good_value(try_severity_high_property_sync());
}

void NonExclusiveDeviationAlarm::severity_low_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveDeviationAlarmTypeTraits::severity_low_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_severity_low_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { severity_low_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::severity_low_property_sync() const
{
  return ::ua::detail::good_value(try_severity_low_property_sync());
}

void NonExclusiveDeviationAlarm::severity_low_low_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveDeviationAlarmTypeTraits::severity_low_low_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_severity_low_low_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { severity_low_low_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::severity_low_low_property_sync() const
{
  return ::ua::detail::good_value(try_severity_low_low_property_sync());
}

void NonExclusiveDeviationAlarm::high_high_deadband_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveDeviationAlarmTypeTraits::high_high_deadband_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_high_high_deadband_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { high_high_deadband_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::high_high_deadband_property_sync() const
{
  return ::ua::detail::good_value(try_high_high_deadband_property_sync());
}

void NonExclusiveDeviationAlarm::high_deadband_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveDeviationAlarmTypeTraits::high_deadband_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_high_deadband_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { high_deadband_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::high_deadband_property_sync() const
{
  return ::ua::detail::good_value(try_high_deadband_property_sync());
}

void NonExclusiveDeviationAlarm::low_deadband_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveDeviationAlarmTypeTraits::low_deadband_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_low_deadband_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { low_deadband_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::low_deadband_property_sync() const
{
  return ::ua::detail::good_value(try_low_deadband_property_sync());
}

void NonExclusiveDeviationAlarm::low_low_deadband_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveDeviationAlarmTypeTraits::low_low_deadband_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_low_low_deadband_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { low_low_deadband_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::low_low_deadband_property_sync() const
{
  return ::ua::detail::good_value(try_low_low_deadband_property_sync());
}

void NonExclusiveDeviationAlarm::input_node_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveDeviationAlarmTypeTraits::input_node_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_input_node_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { input_node_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::input_node_property_sync() const
{
  return ::ua::detail::good_value(try_input_node_property_sync());
}

void NonExclusiveDeviationAlarm::suppressed_or_shelved_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveDeviationAlarmTypeTraits::suppressed_or_shelved_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_suppressed_or_shelved_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { suppressed_or_shelved_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::suppressed_or_shelved_property_sync() const
{
  return ::ua::detail::good_value(try_suppressed_or_shelved_property_sync());
}

void NonExclusiveDeviationAlarm::max_time_shelved_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveDeviationAlarmTypeTraits::max_time_shelved_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_max_time_shelved_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { max_time_shelved_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::max_time_shelved_property_sync() const
{
  return ::ua::detail::good_value(try_max_time_shelved_property_sync());
}

void NonExclusiveDeviationAlarm::audible_enabled_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveDeviationAlarmTypeTraits::audible_enabled_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_audible_enabled_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { audible_enabled_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::audible_enabled_property_sync() const
{
  return ::ua::detail::good_value(try_audible_enabled_property_sync());
}

void NonExclusiveDeviationAlarm::on_delay_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveDeviationAlarmTypeTraits::on_delay_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_on_delay_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { on_delay_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::on_delay_property_sync() const
{
  return ::ua::detail::good_value(try_on_delay_property_sync());
}

void NonExclusiveDeviationAlarm::off_delay_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveDeviationAlarmTypeTraits::off_delay_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_off_delay_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { off_delay_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::off_delay_property_sync() const
{
  return ::ua::detail::good_value(try_off_delay_property_sync());
}

void NonExclusiveDeviationAlarm::re_alarm_time_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveDeviationAlarmTypeTraits::re_alarm_time_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_re_alarm_time_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { re_alarm_time_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::re_alarm_time_property_sync() const
{
  return ::ua::detail::good_value(try_re_alarm_time_property_sync());
}

void NonExclusiveDeviationAlarm::condition_class_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveDeviationAlarmTypeTraits::condition_class_id_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_condition_class_id_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { condition_class_id_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::condition_class_id_property_sync() const
{
  return ::ua::detail::good_value(try_condition_class_id_property_sync());
}

void NonExclusiveDeviationAlarm::condition_class_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveDeviationAlarmTypeTraits::condition_class_name_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_condition_class_name_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { condition_class_name_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::condition_class_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_class_name_property_sync());
}

void NonExclusiveDeviationAlarm::condition_sub_class_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveDeviationAlarmTypeTraits::condition_sub_class_id_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_condition_sub_class_id_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { condition_sub_class_id_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::condition_sub_class_id_property_sync() const
{
  return ::ua::detail::good_value(try_condition_sub_class_id_property_sync());
}

void NonExclusiveDeviationAlarm::condition_sub_class_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveDeviationAlarmTypeTraits::condition_sub_class_name_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_condition_sub_class_name_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { condition_sub_class_name_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::condition_sub_class_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_sub_class_name_property_sync());
}

void NonExclusiveDeviationAlarm::condition_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveDeviationAlarmTypeTraits::condition_name_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_condition_name_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { condition_name_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::condition_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_name_property_sync());
}

void NonExclusiveDeviationAlarm::branch_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveDeviationAlarmTypeTraits::branch_id_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_branch_id_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { branch_id_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::branch_id_property_sync() const
{
  return ::ua::detail::good_value(try_branch_id_property_sync());
}

void NonExclusiveDeviationAlarm::retain_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveDeviationAlarmTypeTraits::retain_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_retain_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { retain_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::retain_property_sync() const
{
  return ::ua::detail::good_value(try_retain_property_sync());
}

void NonExclusiveDeviationAlarm::supports_filtered_retain_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveDeviationAlarmTypeTraits::supports_filtered_retain_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_supports_filtered_retain_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { supports_filtered_retain_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::supports_filtered_retain_property_sync() const
{
  return ::ua::detail::good_value(try_supports_filtered_retain_property_sync());
}

void NonExclusiveDeviationAlarm::client_user_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveDeviationAlarmTypeTraits::client_user_id_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_client_user_id_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { client_user_id_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::client_user_id_property_sync() const
{
  return ::ua::detail::good_value(try_client_user_id_property_sync());
}

void NonExclusiveDeviationAlarm::event_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveDeviationAlarmTypeTraits::event_id_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_event_id_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { event_id_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::event_id_property_sync() const
{
  return ::ua::detail::good_value(try_event_id_property_sync());
}

void NonExclusiveDeviationAlarm::event_type_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveDeviationAlarmTypeTraits::event_type_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_event_type_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { event_type_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::event_type_property_sync() const
{
  return ::ua::detail::good_value(try_event_type_property_sync());
}

void NonExclusiveDeviationAlarm::source_node_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveDeviationAlarmTypeTraits::source_node_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_source_node_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { source_node_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::source_node_property_sync() const
{
  return ::ua::detail::good_value(try_source_node_property_sync());
}

void NonExclusiveDeviationAlarm::source_name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveDeviationAlarmTypeTraits::source_name_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_source_name_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { source_name_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::source_name_property_sync() const
{
  return ::ua::detail::good_value(try_source_name_property_sync());
}

void NonExclusiveDeviationAlarm::time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveDeviationAlarmTypeTraits::time_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_time_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { time_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::time_property_sync() const
{
  return ::ua::detail::good_value(try_time_property_sync());
}

void NonExclusiveDeviationAlarm::receive_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveDeviationAlarmTypeTraits::receive_time_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_receive_time_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { receive_time_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::receive_time_property_sync() const
{
  return ::ua::detail::good_value(try_receive_time_property_sync());
}

void NonExclusiveDeviationAlarm::local_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveDeviationAlarmTypeTraits::local_time_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_local_time_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { local_time_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::local_time_property_sync() const
{
  return ::ua::detail::good_value(try_local_time_property_sync());
}

void NonExclusiveDeviationAlarm::message_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveDeviationAlarmTypeTraits::message_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_message_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { message_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::message_property_sync() const
{
  return ::ua::detail::good_value(try_message_property_sync());
}

void NonExclusiveDeviationAlarm::severity_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveDeviationAlarmTypeTraits::severity_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveDeviationAlarm::try_severity_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { severity_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveDeviationAlarm::severity_property_sync() const
{
  return ::ua::detail::good_value(try_severity_property_sync());
}

// --- Typed value read shortcuts ---

void NonExclusiveDeviationAlarm::read_setpoint_node_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::setpoint_node_browse_name(),
    &Variant::is_node_id,
    {"NonExclusiveDeviationAlarm", "setpoint_node", "NonExclusiveDeviationAlarm::read_setpoint_node_async"},
    std::move(complete));
}

NodeIdResult NonExclusiveDeviationAlarm::try_read_setpoint_node_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeIdResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(NodeIdResult)> complete) { read_setpoint_node_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NodeId NonExclusiveDeviationAlarm::read_setpoint_node_sync() const
{
  return ::ua::detail::good_value(try_read_setpoint_node_sync());
}

void NonExclusiveDeviationAlarm::read_base_setpoint_node_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::base_setpoint_node_browse_name(),
    &Variant::is_node_id,
    {"NonExclusiveDeviationAlarm",
      "base_setpoint_node",
      "NonExclusiveDeviationAlarm::read_base_setpoint_node_async"},
    std::move(complete));
}

NodeIdResult NonExclusiveDeviationAlarm::try_read_base_setpoint_node_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeIdResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(NodeIdResult)> complete)
      { read_base_setpoint_node_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NodeId NonExclusiveDeviationAlarm::read_base_setpoint_node_sync() const
{
  return ::ua::detail::good_value(try_read_base_setpoint_node_sync());
}

void NonExclusiveDeviationAlarm::read_high_high_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::high_high_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveDeviationAlarm",
      "high_high_limit",
      "NonExclusiveDeviationAlarm::read_high_high_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveDeviationAlarm::try_read_high_high_limit_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<DoubleResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(DoubleResult)> complete) { read_high_high_limit_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

double NonExclusiveDeviationAlarm::read_high_high_limit_sync() const
{
  return ::ua::detail::good_value(try_read_high_high_limit_sync());
}

void NonExclusiveDeviationAlarm::read_high_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::high_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveDeviationAlarm", "high_limit", "NonExclusiveDeviationAlarm::read_high_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveDeviationAlarm::try_read_high_limit_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<DoubleResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(DoubleResult)> complete) { read_high_limit_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

double NonExclusiveDeviationAlarm::read_high_limit_sync() const
{
  return ::ua::detail::good_value(try_read_high_limit_sync());
}

void NonExclusiveDeviationAlarm::read_low_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::low_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveDeviationAlarm", "low_limit", "NonExclusiveDeviationAlarm::read_low_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveDeviationAlarm::try_read_low_limit_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<DoubleResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(DoubleResult)> complete) { read_low_limit_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

double NonExclusiveDeviationAlarm::read_low_limit_sync() const
{
  return ::ua::detail::good_value(try_read_low_limit_sync());
}

void NonExclusiveDeviationAlarm::read_low_low_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::low_low_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveDeviationAlarm", "low_low_limit", "NonExclusiveDeviationAlarm::read_low_low_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveDeviationAlarm::try_read_low_low_limit_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<DoubleResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(DoubleResult)> complete) { read_low_low_limit_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

double NonExclusiveDeviationAlarm::read_low_low_limit_sync() const
{
  return ::ua::detail::good_value(try_read_low_low_limit_sync());
}

void NonExclusiveDeviationAlarm::read_base_high_high_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::base_high_high_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveDeviationAlarm",
      "base_high_high_limit",
      "NonExclusiveDeviationAlarm::read_base_high_high_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveDeviationAlarm::try_read_base_high_high_limit_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<DoubleResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(DoubleResult)> complete)
      { read_base_high_high_limit_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

double NonExclusiveDeviationAlarm::read_base_high_high_limit_sync() const
{
  return ::ua::detail::good_value(try_read_base_high_high_limit_sync());
}

void NonExclusiveDeviationAlarm::read_base_high_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::base_high_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveDeviationAlarm",
      "base_high_limit",
      "NonExclusiveDeviationAlarm::read_base_high_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveDeviationAlarm::try_read_base_high_limit_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<DoubleResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(DoubleResult)> complete) { read_base_high_limit_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

double NonExclusiveDeviationAlarm::read_base_high_limit_sync() const
{
  return ::ua::detail::good_value(try_read_base_high_limit_sync());
}

void NonExclusiveDeviationAlarm::read_base_low_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::base_low_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveDeviationAlarm", "base_low_limit", "NonExclusiveDeviationAlarm::read_base_low_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveDeviationAlarm::try_read_base_low_limit_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<DoubleResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(DoubleResult)> complete) { read_base_low_limit_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

double NonExclusiveDeviationAlarm::read_base_low_limit_sync() const
{
  return ::ua::detail::good_value(try_read_base_low_limit_sync());
}

void NonExclusiveDeviationAlarm::read_base_low_low_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::base_low_low_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveDeviationAlarm",
      "base_low_low_limit",
      "NonExclusiveDeviationAlarm::read_base_low_low_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveDeviationAlarm::try_read_base_low_low_limit_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<DoubleResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(DoubleResult)> complete)
      { read_base_low_low_limit_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

double NonExclusiveDeviationAlarm::read_base_low_low_limit_sync() const
{
  return ::ua::detail::good_value(try_read_base_low_low_limit_sync());
}

void NonExclusiveDeviationAlarm::read_severity_high_high_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::severity_high_high_browse_name(),
    &Variant::is_uint16,
    {"NonExclusiveDeviationAlarm",
      "severity_high_high",
      "NonExclusiveDeviationAlarm::read_severity_high_high_async"},
    std::move(complete));
}

UInt16Result NonExclusiveDeviationAlarm::try_read_severity_high_high_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt16Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt16Result)> complete)
      { read_severity_high_high_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint16_t NonExclusiveDeviationAlarm::read_severity_high_high_sync() const
{
  return ::ua::detail::good_value(try_read_severity_high_high_sync());
}

void NonExclusiveDeviationAlarm::read_severity_high_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::severity_high_browse_name(),
    &Variant::is_uint16,
    {"NonExclusiveDeviationAlarm", "severity_high", "NonExclusiveDeviationAlarm::read_severity_high_async"},
    std::move(complete));
}

UInt16Result NonExclusiveDeviationAlarm::try_read_severity_high_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt16Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt16Result)> complete) { read_severity_high_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint16_t NonExclusiveDeviationAlarm::read_severity_high_sync() const
{
  return ::ua::detail::good_value(try_read_severity_high_sync());
}

void NonExclusiveDeviationAlarm::read_severity_low_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::severity_low_browse_name(),
    &Variant::is_uint16,
    {"NonExclusiveDeviationAlarm", "severity_low", "NonExclusiveDeviationAlarm::read_severity_low_async"},
    std::move(complete));
}

UInt16Result NonExclusiveDeviationAlarm::try_read_severity_low_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt16Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt16Result)> complete) { read_severity_low_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint16_t NonExclusiveDeviationAlarm::read_severity_low_sync() const
{
  return ::ua::detail::good_value(try_read_severity_low_sync());
}

void NonExclusiveDeviationAlarm::read_severity_low_low_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::severity_low_low_browse_name(),
    &Variant::is_uint16,
    {"NonExclusiveDeviationAlarm",
      "severity_low_low",
      "NonExclusiveDeviationAlarm::read_severity_low_low_async"},
    std::move(complete));
}

UInt16Result NonExclusiveDeviationAlarm::try_read_severity_low_low_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt16Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt16Result)> complete) { read_severity_low_low_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint16_t NonExclusiveDeviationAlarm::read_severity_low_low_sync() const
{
  return ::ua::detail::good_value(try_read_severity_low_low_sync());
}

void NonExclusiveDeviationAlarm::read_high_high_deadband_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::high_high_deadband_browse_name(),
    &Variant::is_double,
    {"NonExclusiveDeviationAlarm",
      "high_high_deadband",
      "NonExclusiveDeviationAlarm::read_high_high_deadband_async"},
    std::move(complete));
}

DoubleResult NonExclusiveDeviationAlarm::try_read_high_high_deadband_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<DoubleResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(DoubleResult)> complete)
      { read_high_high_deadband_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

double NonExclusiveDeviationAlarm::read_high_high_deadband_sync() const
{
  return ::ua::detail::good_value(try_read_high_high_deadband_sync());
}

void NonExclusiveDeviationAlarm::read_high_deadband_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::high_deadband_browse_name(),
    &Variant::is_double,
    {"NonExclusiveDeviationAlarm", "high_deadband", "NonExclusiveDeviationAlarm::read_high_deadband_async"},
    std::move(complete));
}

DoubleResult NonExclusiveDeviationAlarm::try_read_high_deadband_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<DoubleResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(DoubleResult)> complete) { read_high_deadband_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

double NonExclusiveDeviationAlarm::read_high_deadband_sync() const
{
  return ::ua::detail::good_value(try_read_high_deadband_sync());
}

void NonExclusiveDeviationAlarm::read_low_deadband_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::low_deadband_browse_name(),
    &Variant::is_double,
    {"NonExclusiveDeviationAlarm", "low_deadband", "NonExclusiveDeviationAlarm::read_low_deadband_async"},
    std::move(complete));
}

DoubleResult NonExclusiveDeviationAlarm::try_read_low_deadband_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<DoubleResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(DoubleResult)> complete) { read_low_deadband_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

double NonExclusiveDeviationAlarm::read_low_deadband_sync() const
{
  return ::ua::detail::good_value(try_read_low_deadband_sync());
}

void NonExclusiveDeviationAlarm::read_low_low_deadband_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::low_low_deadband_browse_name(),
    &Variant::is_double,
    {"NonExclusiveDeviationAlarm",
      "low_low_deadband",
      "NonExclusiveDeviationAlarm::read_low_low_deadband_async"},
    std::move(complete));
}

DoubleResult NonExclusiveDeviationAlarm::try_read_low_low_deadband_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<DoubleResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(DoubleResult)> complete) { read_low_low_deadband_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

double NonExclusiveDeviationAlarm::read_low_low_deadband_sync() const
{
  return ::ua::detail::good_value(try_read_low_low_deadband_sync());
}

void NonExclusiveDeviationAlarm::read_input_node_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::input_node_browse_name(),
    &Variant::is_node_id,
    {"NonExclusiveDeviationAlarm", "input_node", "NonExclusiveDeviationAlarm::read_input_node_async"},
    std::move(complete));
}

NodeIdResult NonExclusiveDeviationAlarm::try_read_input_node_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeIdResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(NodeIdResult)> complete) { read_input_node_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NodeId NonExclusiveDeviationAlarm::read_input_node_sync() const
{
  return ::ua::detail::good_value(try_read_input_node_sync());
}

void NonExclusiveDeviationAlarm::read_suppressed_or_shelved_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::suppressed_or_shelved_browse_name(),
    &Variant::is_boolean,
    {"NonExclusiveDeviationAlarm",
      "suppressed_or_shelved",
      "NonExclusiveDeviationAlarm::read_suppressed_or_shelved_async"},
    std::move(complete));
}

BoolResult NonExclusiveDeviationAlarm::try_read_suppressed_or_shelved_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BoolResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BoolResult)> complete)
      { read_suppressed_or_shelved_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

bool NonExclusiveDeviationAlarm::read_suppressed_or_shelved_sync() const
{
  return ::ua::detail::good_value(try_read_suppressed_or_shelved_sync());
}

void NonExclusiveDeviationAlarm::read_audible_enabled_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::audible_enabled_browse_name(),
    &Variant::is_boolean,
    {"NonExclusiveDeviationAlarm",
      "audible_enabled",
      "NonExclusiveDeviationAlarm::read_audible_enabled_async"},
    std::move(complete));
}

BoolResult NonExclusiveDeviationAlarm::try_read_audible_enabled_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BoolResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BoolResult)> complete) { read_audible_enabled_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

bool NonExclusiveDeviationAlarm::read_audible_enabled_sync() const
{
  return ::ua::detail::good_value(try_read_audible_enabled_sync());
}

void NonExclusiveDeviationAlarm::read_condition_class_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::condition_class_id_browse_name(),
    &Variant::is_node_id,
    {"NonExclusiveDeviationAlarm",
      "condition_class_id",
      "NonExclusiveDeviationAlarm::read_condition_class_id_async"},
    std::move(complete));
}

NodeIdResult NonExclusiveDeviationAlarm::try_read_condition_class_id_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeIdResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(NodeIdResult)> complete)
      { read_condition_class_id_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NodeId NonExclusiveDeviationAlarm::read_condition_class_id_sync() const
{
  return ::ua::detail::good_value(try_read_condition_class_id_sync());
}

void NonExclusiveDeviationAlarm::read_condition_class_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::condition_class_name_browse_name(),
    &Variant::is_localized_text,
    {"NonExclusiveDeviationAlarm",
      "condition_class_name",
      "NonExclusiveDeviationAlarm::read_condition_class_name_async"},
    std::move(complete));
}

LocalizedTextResult NonExclusiveDeviationAlarm::try_read_condition_class_name_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LocalizedTextResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(LocalizedTextResult)> complete)
      { read_condition_class_name_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LocalizedText NonExclusiveDeviationAlarm::read_condition_class_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_class_name_sync());
}

void NonExclusiveDeviationAlarm::read_condition_sub_class_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::condition_sub_class_id_browse_name(),
    &Variant::is_node_id,
    {"NonExclusiveDeviationAlarm",
      "condition_sub_class_id",
      "NonExclusiveDeviationAlarm::read_condition_sub_class_id_async"},
    std::move(complete));
}

NodeIdResult NonExclusiveDeviationAlarm::try_read_condition_sub_class_id_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeIdResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(NodeIdResult)> complete)
      { read_condition_sub_class_id_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NodeId NonExclusiveDeviationAlarm::read_condition_sub_class_id_sync() const
{
  return ::ua::detail::good_value(try_read_condition_sub_class_id_sync());
}

void NonExclusiveDeviationAlarm::read_condition_sub_class_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::condition_sub_class_name_browse_name(),
    &Variant::is_localized_text,
    {"NonExclusiveDeviationAlarm",
      "condition_sub_class_name",
      "NonExclusiveDeviationAlarm::read_condition_sub_class_name_async"},
    std::move(complete));
}

LocalizedTextResult NonExclusiveDeviationAlarm::try_read_condition_sub_class_name_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LocalizedTextResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(LocalizedTextResult)> complete)
      { read_condition_sub_class_name_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LocalizedText NonExclusiveDeviationAlarm::read_condition_sub_class_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_sub_class_name_sync());
}

void NonExclusiveDeviationAlarm::read_condition_name_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::condition_name_browse_name(),
    &Variant::is_string,
    {"NonExclusiveDeviationAlarm", "condition_name", "NonExclusiveDeviationAlarm::read_condition_name_async"},
    std::move(complete));
}

StringResult NonExclusiveDeviationAlarm::try_read_condition_name_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_condition_name_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String NonExclusiveDeviationAlarm::read_condition_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_name_sync());
}

void NonExclusiveDeviationAlarm::read_branch_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::branch_id_browse_name(),
    &Variant::is_node_id,
    {"NonExclusiveDeviationAlarm", "branch_id", "NonExclusiveDeviationAlarm::read_branch_id_async"},
    std::move(complete));
}

NodeIdResult NonExclusiveDeviationAlarm::try_read_branch_id_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeIdResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(NodeIdResult)> complete) { read_branch_id_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NodeId NonExclusiveDeviationAlarm::read_branch_id_sync() const
{
  return ::ua::detail::good_value(try_read_branch_id_sync());
}

void NonExclusiveDeviationAlarm::read_retain_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::retain_browse_name(),
    &Variant::is_boolean,
    {"NonExclusiveDeviationAlarm", "retain", "NonExclusiveDeviationAlarm::read_retain_async"},
    std::move(complete));
}

BoolResult NonExclusiveDeviationAlarm::try_read_retain_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BoolResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BoolResult)> complete) { read_retain_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

bool NonExclusiveDeviationAlarm::read_retain_sync() const
{
  return ::ua::detail::good_value(try_read_retain_sync());
}

void NonExclusiveDeviationAlarm::read_supports_filtered_retain_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::supports_filtered_retain_browse_name(),
    &Variant::is_boolean,
    {"NonExclusiveDeviationAlarm",
      "supports_filtered_retain",
      "NonExclusiveDeviationAlarm::read_supports_filtered_retain_async"},
    std::move(complete));
}

BoolResult NonExclusiveDeviationAlarm::try_read_supports_filtered_retain_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BoolResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BoolResult)> complete)
      { read_supports_filtered_retain_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

bool NonExclusiveDeviationAlarm::read_supports_filtered_retain_sync() const
{
  return ::ua::detail::good_value(try_read_supports_filtered_retain_sync());
}

void NonExclusiveDeviationAlarm::read_client_user_id_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::client_user_id_browse_name(),
    &Variant::is_string,
    {"NonExclusiveDeviationAlarm", "client_user_id", "NonExclusiveDeviationAlarm::read_client_user_id_async"},
    std::move(complete));
}

StringResult NonExclusiveDeviationAlarm::try_read_client_user_id_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_client_user_id_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String NonExclusiveDeviationAlarm::read_client_user_id_sync() const
{
  return ::ua::detail::good_value(try_read_client_user_id_sync());
}

void NonExclusiveDeviationAlarm::read_event_id_async(
  std::function<void(ByteStringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(ByteStringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<ByteString>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::event_id_browse_name(),
    &Variant::is_byte_string,
    {"NonExclusiveDeviationAlarm", "event_id", "NonExclusiveDeviationAlarm::read_event_id_async"},
    std::move(complete));
}

ByteStringResult NonExclusiveDeviationAlarm::try_read_event_id_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ByteStringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(ByteStringResult)> complete) { read_event_id_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ByteString NonExclusiveDeviationAlarm::read_event_id_sync() const
{
  return ::ua::detail::good_value(try_read_event_id_sync());
}

void NonExclusiveDeviationAlarm::read_event_type_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::event_type_browse_name(),
    &Variant::is_node_id,
    {"NonExclusiveDeviationAlarm", "event_type", "NonExclusiveDeviationAlarm::read_event_type_async"},
    std::move(complete));
}

NodeIdResult NonExclusiveDeviationAlarm::try_read_event_type_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeIdResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(NodeIdResult)> complete) { read_event_type_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NodeId NonExclusiveDeviationAlarm::read_event_type_sync() const
{
  return ::ua::detail::good_value(try_read_event_type_sync());
}

void NonExclusiveDeviationAlarm::read_source_node_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::source_node_browse_name(),
    &Variant::is_node_id,
    {"NonExclusiveDeviationAlarm", "source_node", "NonExclusiveDeviationAlarm::read_source_node_async"},
    std::move(complete));
}

NodeIdResult NonExclusiveDeviationAlarm::try_read_source_node_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeIdResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(NodeIdResult)> complete) { read_source_node_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NodeId NonExclusiveDeviationAlarm::read_source_node_sync() const
{
  return ::ua::detail::good_value(try_read_source_node_sync());
}

void NonExclusiveDeviationAlarm::read_source_name_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::source_name_browse_name(),
    &Variant::is_string,
    {"NonExclusiveDeviationAlarm", "source_name", "NonExclusiveDeviationAlarm::read_source_name_async"},
    std::move(complete));
}

StringResult NonExclusiveDeviationAlarm::try_read_source_name_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_source_name_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String NonExclusiveDeviationAlarm::read_source_name_sync() const
{
  return ::ua::detail::good_value(try_read_source_name_sync());
}

void NonExclusiveDeviationAlarm::read_message_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::message_browse_name(),
    &Variant::is_localized_text,
    {"NonExclusiveDeviationAlarm", "message", "NonExclusiveDeviationAlarm::read_message_async"},
    std::move(complete));
}

LocalizedTextResult NonExclusiveDeviationAlarm::try_read_message_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LocalizedTextResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(LocalizedTextResult)> complete) { read_message_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LocalizedText NonExclusiveDeviationAlarm::read_message_sync() const
{
  return ::ua::detail::good_value(try_read_message_sync());
}

void NonExclusiveDeviationAlarm::read_severity_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::severity_browse_name(),
    &Variant::is_uint16,
    {"NonExclusiveDeviationAlarm", "severity", "NonExclusiveDeviationAlarm::read_severity_async"},
    std::move(complete));
}

UInt16Result NonExclusiveDeviationAlarm::try_read_severity_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt16Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt16Result)> complete) { read_severity_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint16_t NonExclusiveDeviationAlarm::read_severity_sync() const
{
  return ::ua::detail::good_value(try_read_severity_sync());
}

// --- Typed value write shortcuts ---

void NonExclusiveDeviationAlarm::write_setpoint_node_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::setpoint_node_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_setpoint_node_sync(NodeId value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_setpoint_node_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_setpoint_node_sync(NodeId value) const
{
  try_write_setpoint_node_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_base_setpoint_node_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::base_setpoint_node_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_base_setpoint_node_sync(NodeId value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_base_setpoint_node_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_base_setpoint_node_sync(NodeId value) const
{
  try_write_base_setpoint_node_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_high_high_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::high_high_limit_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_high_high_limit_sync(double value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_high_high_limit_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_high_high_limit_sync(double value) const
{
  try_write_high_high_limit_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_high_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::high_limit_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_high_limit_sync(double value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_high_limit_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_high_limit_sync(double value) const
{
  try_write_high_limit_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_low_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::low_limit_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_low_limit_sync(double value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_low_limit_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_low_limit_sync(double value) const
{
  try_write_low_limit_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_low_low_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::low_low_limit_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_low_low_limit_sync(double value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_low_low_limit_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_low_low_limit_sync(double value) const
{
  try_write_low_low_limit_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_base_high_high_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::base_high_high_limit_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_base_high_high_limit_sync(double value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_base_high_high_limit_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_base_high_high_limit_sync(double value) const
{
  try_write_base_high_high_limit_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_base_high_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::base_high_limit_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_base_high_limit_sync(double value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_base_high_limit_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_base_high_limit_sync(double value) const
{
  try_write_base_high_limit_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_base_low_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::base_low_limit_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_base_low_limit_sync(double value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_base_low_limit_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_base_low_limit_sync(double value) const
{
  try_write_base_low_limit_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_base_low_low_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::base_low_low_limit_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_base_low_low_limit_sync(double value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_base_low_low_limit_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_base_low_low_limit_sync(double value) const
{
  try_write_base_low_low_limit_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_severity_high_high_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::severity_high_high_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_severity_high_high_sync(uint16_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_severity_high_high_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_severity_high_high_sync(uint16_t value) const
{
  try_write_severity_high_high_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_severity_high_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::severity_high_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_severity_high_sync(uint16_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_severity_high_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_severity_high_sync(uint16_t value) const
{
  try_write_severity_high_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_severity_low_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::severity_low_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_severity_low_sync(uint16_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_severity_low_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_severity_low_sync(uint16_t value) const
{
  try_write_severity_low_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_severity_low_low_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::severity_low_low_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_severity_low_low_sync(uint16_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_severity_low_low_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_severity_low_low_sync(uint16_t value) const
{
  try_write_severity_low_low_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_high_high_deadband_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::high_high_deadband_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_high_high_deadband_sync(double value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_high_high_deadband_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_high_high_deadband_sync(double value) const
{
  try_write_high_high_deadband_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_high_deadband_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::high_deadband_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_high_deadband_sync(double value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_high_deadband_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_high_deadband_sync(double value) const
{
  try_write_high_deadband_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_low_deadband_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::low_deadband_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_low_deadband_sync(double value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_low_deadband_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_low_deadband_sync(double value) const
{
  try_write_low_deadband_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_low_low_deadband_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::low_low_deadband_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_low_low_deadband_sync(double value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_low_low_deadband_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_low_low_deadband_sync(double value) const
{
  try_write_low_low_deadband_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_input_node_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::input_node_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_input_node_sync(NodeId value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_input_node_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_input_node_sync(NodeId value) const
{
  try_write_input_node_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_suppressed_or_shelved_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::suppressed_or_shelved_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_suppressed_or_shelved_sync(bool value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_suppressed_or_shelved_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_suppressed_or_shelved_sync(bool value) const
{
  try_write_suppressed_or_shelved_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_audible_enabled_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::audible_enabled_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_audible_enabled_sync(bool value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_audible_enabled_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_audible_enabled_sync(bool value) const
{
  try_write_audible_enabled_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_condition_class_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::condition_class_id_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_condition_class_id_sync(NodeId value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_condition_class_id_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_condition_class_id_sync(NodeId value) const
{
  try_write_condition_class_id_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_condition_class_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::condition_class_name_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_condition_class_name_sync(LocalizedText value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_condition_class_name_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_condition_class_name_sync(LocalizedText value) const
{
  try_write_condition_class_name_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_condition_sub_class_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::condition_sub_class_id_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_condition_sub_class_id_sync(NodeId value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_condition_sub_class_id_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_condition_sub_class_id_sync(NodeId value) const
{
  try_write_condition_sub_class_id_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_condition_sub_class_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::condition_sub_class_name_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_condition_sub_class_name_sync(
  LocalizedText value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_condition_sub_class_name_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_condition_sub_class_name_sync(LocalizedText value) const
{
  try_write_condition_sub_class_name_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_condition_name_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::condition_name_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_condition_name_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_condition_name_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_condition_name_sync(String value) const
{
  try_write_condition_name_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_branch_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::branch_id_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_branch_id_sync(NodeId value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_branch_id_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_branch_id_sync(NodeId value) const
{
  try_write_branch_id_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_retain_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::retain_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_retain_sync(bool value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_retain_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_retain_sync(bool value) const
{
  try_write_retain_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_supports_filtered_retain_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::supports_filtered_retain_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_supports_filtered_retain_sync(bool value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_supports_filtered_retain_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_supports_filtered_retain_sync(bool value) const
{
  try_write_supports_filtered_retain_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_client_user_id_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::client_user_id_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_client_user_id_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_client_user_id_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_client_user_id_sync(String value) const
{
  try_write_client_user_id_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_event_id_async(
  ByteString value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::event_id_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_event_id_sync(ByteString value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_event_id_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_event_id_sync(ByteString value) const
{
  try_write_event_id_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_event_type_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::event_type_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_event_type_sync(NodeId value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_event_type_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_event_type_sync(NodeId value) const
{
  try_write_event_type_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_source_node_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::source_node_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_source_node_sync(NodeId value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_source_node_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_source_node_sync(NodeId value) const
{
  try_write_source_node_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_source_name_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::source_name_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_source_name_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_source_name_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_source_name_sync(String value) const
{
  try_write_source_name_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_message_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::message_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_message_sync(LocalizedText value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_message_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_message_sync(LocalizedText value) const
{
  try_write_message_sync(value).value();
}

void NonExclusiveDeviationAlarm::write_severity_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveDeviationAlarmTypeTraits::severity_browse_name(),
    "NonExclusiveDeviationAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveDeviationAlarm::try_write_severity_sync(uint16_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_severity_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void NonExclusiveDeviationAlarm::write_severity_sync(uint16_t value) const
{
  try_write_severity_sync(value).value();
}

}  // namespace ua
