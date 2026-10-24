// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_non_exclusive_rate_of_change_alarm.h"

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

struct NonExclusiveRateOfChangeAlarmTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::NonExclusiveRateOfChangeAlarmType};
  }

  static QualifiedName engineering_units_browse_name()
  {
    return QualifiedName{0, "EngineeringUnits"};
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

NonExclusiveRateOfChangeAlarm::NonExclusiveRateOfChangeAlarm(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void NonExclusiveRateOfChangeAlarm::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    NonExclusiveRateOfChangeAlarmTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(NonExclusiveRateOfChangeAlarmResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(NonExclusiveRateOfChangeAlarmResult{
        NonExclusiveRateOfChangeAlarm{
          std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

NonExclusiveRateOfChangeAlarmResult NonExclusiveRateOfChangeAlarm::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NonExclusiveRateOfChangeAlarmResult>(addressSpace.executor(),
      [&](std::function<void(NonExclusiveRateOfChangeAlarmResult)> complete)
      {
        NonExclusiveRateOfChangeAlarm::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NonExclusiveRateOfChangeAlarm NonExclusiveRateOfChangeAlarm::create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void NonExclusiveRateOfChangeAlarm::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void NonExclusiveRateOfChangeAlarm::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // NonExclusiveRateOfChangeAlarmType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    NonExclusiveRateOfChangeAlarmTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(NonExclusiveRateOfChangeAlarmResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(NonExclusiveRateOfChangeAlarmResult{
          ::ua::detail::address_space_gone("NonExclusiveRateOfChangeAlarm")});
        return;
      }
      complete(NonExclusiveRateOfChangeAlarm{
        std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

NonExclusiveRateOfChangeAlarmResult NonExclusiveRateOfChangeAlarm::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NonExclusiveRateOfChangeAlarmResult>(addressSpace.executor(),
      [&](std::function<void(NonExclusiveRateOfChangeAlarmResult)> complete)
      {
        NonExclusiveRateOfChangeAlarm::attach_async(
          std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NonExclusiveRateOfChangeAlarm NonExclusiveRateOfChangeAlarm::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void NonExclusiveRateOfChangeAlarm::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void NonExclusiveRateOfChangeAlarm::find_property_async(
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
    "NonExclusiveRateOfChangeAlarm",
    std::move(complete));
}

// --- Property accessors ---

void NonExclusiveRateOfChangeAlarm::engineering_units_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::engineering_units_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_engineering_units_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { engineering_units_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property NonExclusiveRateOfChangeAlarm::engineering_units_property_sync() const
{
  return ::ua::detail::good_value(try_engineering_units_property_sync());
}

void NonExclusiveRateOfChangeAlarm::high_high_limit_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::high_high_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_high_high_limit_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::high_high_limit_property_sync() const
{
  return ::ua::detail::good_value(try_high_high_limit_property_sync());
}

void NonExclusiveRateOfChangeAlarm::high_limit_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveRateOfChangeAlarmTypeTraits::high_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_high_limit_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::high_limit_property_sync() const
{
  return ::ua::detail::good_value(try_high_limit_property_sync());
}

void NonExclusiveRateOfChangeAlarm::low_limit_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveRateOfChangeAlarmTypeTraits::low_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_low_limit_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::low_limit_property_sync() const
{
  return ::ua::detail::good_value(try_low_limit_property_sync());
}

void NonExclusiveRateOfChangeAlarm::low_low_limit_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::low_low_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_low_low_limit_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::low_low_limit_property_sync() const
{
  return ::ua::detail::good_value(try_low_low_limit_property_sync());
}

void NonExclusiveRateOfChangeAlarm::base_high_high_limit_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::base_high_high_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_base_high_high_limit_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::base_high_high_limit_property_sync() const
{
  return ::ua::detail::good_value(try_base_high_high_limit_property_sync());
}

void NonExclusiveRateOfChangeAlarm::base_high_limit_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::base_high_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_base_high_limit_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::base_high_limit_property_sync() const
{
  return ::ua::detail::good_value(try_base_high_limit_property_sync());
}

void NonExclusiveRateOfChangeAlarm::base_low_limit_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::base_low_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_base_low_limit_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::base_low_limit_property_sync() const
{
  return ::ua::detail::good_value(try_base_low_limit_property_sync());
}

void NonExclusiveRateOfChangeAlarm::base_low_low_limit_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::base_low_low_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_base_low_low_limit_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::base_low_low_limit_property_sync() const
{
  return ::ua::detail::good_value(try_base_low_low_limit_property_sync());
}

void NonExclusiveRateOfChangeAlarm::severity_high_high_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::severity_high_high_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_severity_high_high_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::severity_high_high_property_sync() const
{
  return ::ua::detail::good_value(try_severity_high_high_property_sync());
}

void NonExclusiveRateOfChangeAlarm::severity_high_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::severity_high_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_severity_high_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::severity_high_property_sync() const
{
  return ::ua::detail::good_value(try_severity_high_property_sync());
}

void NonExclusiveRateOfChangeAlarm::severity_low_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::severity_low_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_severity_low_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::severity_low_property_sync() const
{
  return ::ua::detail::good_value(try_severity_low_property_sync());
}

void NonExclusiveRateOfChangeAlarm::severity_low_low_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::severity_low_low_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_severity_low_low_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::severity_low_low_property_sync() const
{
  return ::ua::detail::good_value(try_severity_low_low_property_sync());
}

void NonExclusiveRateOfChangeAlarm::high_high_deadband_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::high_high_deadband_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_high_high_deadband_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::high_high_deadband_property_sync() const
{
  return ::ua::detail::good_value(try_high_high_deadband_property_sync());
}

void NonExclusiveRateOfChangeAlarm::high_deadband_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::high_deadband_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_high_deadband_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::high_deadband_property_sync() const
{
  return ::ua::detail::good_value(try_high_deadband_property_sync());
}

void NonExclusiveRateOfChangeAlarm::low_deadband_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::low_deadband_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_low_deadband_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::low_deadband_property_sync() const
{
  return ::ua::detail::good_value(try_low_deadband_property_sync());
}

void NonExclusiveRateOfChangeAlarm::low_low_deadband_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::low_low_deadband_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_low_low_deadband_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::low_low_deadband_property_sync() const
{
  return ::ua::detail::good_value(try_low_low_deadband_property_sync());
}

void NonExclusiveRateOfChangeAlarm::input_node_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveRateOfChangeAlarmTypeTraits::input_node_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_input_node_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::input_node_property_sync() const
{
  return ::ua::detail::good_value(try_input_node_property_sync());
}

void NonExclusiveRateOfChangeAlarm::suppressed_or_shelved_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::suppressed_or_shelved_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_suppressed_or_shelved_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::suppressed_or_shelved_property_sync() const
{
  return ::ua::detail::good_value(try_suppressed_or_shelved_property_sync());
}

void NonExclusiveRateOfChangeAlarm::max_time_shelved_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::max_time_shelved_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_max_time_shelved_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::max_time_shelved_property_sync() const
{
  return ::ua::detail::good_value(try_max_time_shelved_property_sync());
}

void NonExclusiveRateOfChangeAlarm::audible_enabled_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::audible_enabled_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_audible_enabled_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::audible_enabled_property_sync() const
{
  return ::ua::detail::good_value(try_audible_enabled_property_sync());
}

void NonExclusiveRateOfChangeAlarm::on_delay_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveRateOfChangeAlarmTypeTraits::on_delay_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_on_delay_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::on_delay_property_sync() const
{
  return ::ua::detail::good_value(try_on_delay_property_sync());
}

void NonExclusiveRateOfChangeAlarm::off_delay_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveRateOfChangeAlarmTypeTraits::off_delay_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_off_delay_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::off_delay_property_sync() const
{
  return ::ua::detail::good_value(try_off_delay_property_sync());
}

void NonExclusiveRateOfChangeAlarm::re_alarm_time_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::re_alarm_time_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_re_alarm_time_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::re_alarm_time_property_sync() const
{
  return ::ua::detail::good_value(try_re_alarm_time_property_sync());
}

void NonExclusiveRateOfChangeAlarm::condition_class_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::condition_class_id_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_condition_class_id_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::condition_class_id_property_sync() const
{
  return ::ua::detail::good_value(try_condition_class_id_property_sync());
}

void NonExclusiveRateOfChangeAlarm::condition_class_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::condition_class_name_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_condition_class_name_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::condition_class_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_class_name_property_sync());
}

void NonExclusiveRateOfChangeAlarm::condition_sub_class_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::condition_sub_class_id_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_condition_sub_class_id_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::condition_sub_class_id_property_sync() const
{
  return ::ua::detail::good_value(try_condition_sub_class_id_property_sync());
}

void NonExclusiveRateOfChangeAlarm::condition_sub_class_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::condition_sub_class_name_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_condition_sub_class_name_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::condition_sub_class_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_sub_class_name_property_sync());
}

void NonExclusiveRateOfChangeAlarm::condition_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::condition_name_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_condition_name_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::condition_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_name_property_sync());
}

void NonExclusiveRateOfChangeAlarm::branch_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveRateOfChangeAlarmTypeTraits::branch_id_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_branch_id_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::branch_id_property_sync() const
{
  return ::ua::detail::good_value(try_branch_id_property_sync());
}

void NonExclusiveRateOfChangeAlarm::retain_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveRateOfChangeAlarmTypeTraits::retain_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_retain_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::retain_property_sync() const
{
  return ::ua::detail::good_value(try_retain_property_sync());
}

void NonExclusiveRateOfChangeAlarm::supports_filtered_retain_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::supports_filtered_retain_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_supports_filtered_retain_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::supports_filtered_retain_property_sync() const
{
  return ::ua::detail::good_value(try_supports_filtered_retain_property_sync());
}

void NonExclusiveRateOfChangeAlarm::client_user_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::client_user_id_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_client_user_id_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::client_user_id_property_sync() const
{
  return ::ua::detail::good_value(try_client_user_id_property_sync());
}

void NonExclusiveRateOfChangeAlarm::event_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveRateOfChangeAlarmTypeTraits::event_id_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_event_id_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::event_id_property_sync() const
{
  return ::ua::detail::good_value(try_event_id_property_sync());
}

void NonExclusiveRateOfChangeAlarm::event_type_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveRateOfChangeAlarmTypeTraits::event_type_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_event_type_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::event_type_property_sync() const
{
  return ::ua::detail::good_value(try_event_type_property_sync());
}

void NonExclusiveRateOfChangeAlarm::source_node_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::source_node_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_source_node_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::source_node_property_sync() const
{
  return ::ua::detail::good_value(try_source_node_property_sync());
}

void NonExclusiveRateOfChangeAlarm::source_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::source_name_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_source_name_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::source_name_property_sync() const
{
  return ::ua::detail::good_value(try_source_name_property_sync());
}

void NonExclusiveRateOfChangeAlarm::time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveRateOfChangeAlarmTypeTraits::time_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_time_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::time_property_sync() const
{
  return ::ua::detail::good_value(try_time_property_sync());
}

void NonExclusiveRateOfChangeAlarm::receive_time_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveRateOfChangeAlarmTypeTraits::receive_time_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_receive_time_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::receive_time_property_sync() const
{
  return ::ua::detail::good_value(try_receive_time_property_sync());
}

void NonExclusiveRateOfChangeAlarm::local_time_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveRateOfChangeAlarmTypeTraits::local_time_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_local_time_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::local_time_property_sync() const
{
  return ::ua::detail::good_value(try_local_time_property_sync());
}

void NonExclusiveRateOfChangeAlarm::message_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveRateOfChangeAlarmTypeTraits::message_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_message_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::message_property_sync() const
{
  return ::ua::detail::good_value(try_message_property_sync());
}

void NonExclusiveRateOfChangeAlarm::severity_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveRateOfChangeAlarmTypeTraits::severity_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveRateOfChangeAlarm::try_severity_property_sync() const noexcept
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

Property NonExclusiveRateOfChangeAlarm::severity_property_sync() const
{
  return ::ua::detail::good_value(try_severity_property_sync());
}

// --- Typed value read shortcuts ---

void NonExclusiveRateOfChangeAlarm::read_high_high_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::high_high_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveRateOfChangeAlarm",
      "high_high_limit",
      "NonExclusiveRateOfChangeAlarm::read_high_high_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveRateOfChangeAlarm::try_read_high_high_limit_sync() const noexcept
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

double NonExclusiveRateOfChangeAlarm::read_high_high_limit_sync() const
{
  return ::ua::detail::good_value(try_read_high_high_limit_sync());
}

void NonExclusiveRateOfChangeAlarm::read_high_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::high_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveRateOfChangeAlarm", "high_limit", "NonExclusiveRateOfChangeAlarm::read_high_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveRateOfChangeAlarm::try_read_high_limit_sync() const noexcept
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

double NonExclusiveRateOfChangeAlarm::read_high_limit_sync() const
{
  return ::ua::detail::good_value(try_read_high_limit_sync());
}

void NonExclusiveRateOfChangeAlarm::read_low_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::low_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveRateOfChangeAlarm", "low_limit", "NonExclusiveRateOfChangeAlarm::read_low_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveRateOfChangeAlarm::try_read_low_limit_sync() const noexcept
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

double NonExclusiveRateOfChangeAlarm::read_low_limit_sync() const
{
  return ::ua::detail::good_value(try_read_low_limit_sync());
}

void NonExclusiveRateOfChangeAlarm::read_low_low_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::low_low_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveRateOfChangeAlarm",
      "low_low_limit",
      "NonExclusiveRateOfChangeAlarm::read_low_low_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveRateOfChangeAlarm::try_read_low_low_limit_sync() const noexcept
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

double NonExclusiveRateOfChangeAlarm::read_low_low_limit_sync() const
{
  return ::ua::detail::good_value(try_read_low_low_limit_sync());
}

void NonExclusiveRateOfChangeAlarm::read_base_high_high_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::base_high_high_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveRateOfChangeAlarm",
      "base_high_high_limit",
      "NonExclusiveRateOfChangeAlarm::read_base_high_high_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveRateOfChangeAlarm::try_read_base_high_high_limit_sync() const noexcept
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

double NonExclusiveRateOfChangeAlarm::read_base_high_high_limit_sync() const
{
  return ::ua::detail::good_value(try_read_base_high_high_limit_sync());
}

void NonExclusiveRateOfChangeAlarm::read_base_high_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::base_high_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveRateOfChangeAlarm",
      "base_high_limit",
      "NonExclusiveRateOfChangeAlarm::read_base_high_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveRateOfChangeAlarm::try_read_base_high_limit_sync() const noexcept
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

double NonExclusiveRateOfChangeAlarm::read_base_high_limit_sync() const
{
  return ::ua::detail::good_value(try_read_base_high_limit_sync());
}

void NonExclusiveRateOfChangeAlarm::read_base_low_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::base_low_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveRateOfChangeAlarm",
      "base_low_limit",
      "NonExclusiveRateOfChangeAlarm::read_base_low_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveRateOfChangeAlarm::try_read_base_low_limit_sync() const noexcept
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

double NonExclusiveRateOfChangeAlarm::read_base_low_limit_sync() const
{
  return ::ua::detail::good_value(try_read_base_low_limit_sync());
}

void NonExclusiveRateOfChangeAlarm::read_base_low_low_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::base_low_low_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveRateOfChangeAlarm",
      "base_low_low_limit",
      "NonExclusiveRateOfChangeAlarm::read_base_low_low_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveRateOfChangeAlarm::try_read_base_low_low_limit_sync() const noexcept
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

double NonExclusiveRateOfChangeAlarm::read_base_low_low_limit_sync() const
{
  return ::ua::detail::good_value(try_read_base_low_low_limit_sync());
}

void NonExclusiveRateOfChangeAlarm::read_severity_high_high_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::severity_high_high_browse_name(),
    &Variant::is_uint16,
    {"NonExclusiveRateOfChangeAlarm",
      "severity_high_high",
      "NonExclusiveRateOfChangeAlarm::read_severity_high_high_async"},
    std::move(complete));
}

UInt16Result NonExclusiveRateOfChangeAlarm::try_read_severity_high_high_sync() const noexcept
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

uint16_t NonExclusiveRateOfChangeAlarm::read_severity_high_high_sync() const
{
  return ::ua::detail::good_value(try_read_severity_high_high_sync());
}

void NonExclusiveRateOfChangeAlarm::read_severity_high_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::severity_high_browse_name(),
    &Variant::is_uint16,
    {"NonExclusiveRateOfChangeAlarm",
      "severity_high",
      "NonExclusiveRateOfChangeAlarm::read_severity_high_async"},
    std::move(complete));
}

UInt16Result NonExclusiveRateOfChangeAlarm::try_read_severity_high_sync() const noexcept
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

uint16_t NonExclusiveRateOfChangeAlarm::read_severity_high_sync() const
{
  return ::ua::detail::good_value(try_read_severity_high_sync());
}

void NonExclusiveRateOfChangeAlarm::read_severity_low_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::severity_low_browse_name(),
    &Variant::is_uint16,
    {"NonExclusiveRateOfChangeAlarm",
      "severity_low",
      "NonExclusiveRateOfChangeAlarm::read_severity_low_async"},
    std::move(complete));
}

UInt16Result NonExclusiveRateOfChangeAlarm::try_read_severity_low_sync() const noexcept
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

uint16_t NonExclusiveRateOfChangeAlarm::read_severity_low_sync() const
{
  return ::ua::detail::good_value(try_read_severity_low_sync());
}

void NonExclusiveRateOfChangeAlarm::read_severity_low_low_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::severity_low_low_browse_name(),
    &Variant::is_uint16,
    {"NonExclusiveRateOfChangeAlarm",
      "severity_low_low",
      "NonExclusiveRateOfChangeAlarm::read_severity_low_low_async"},
    std::move(complete));
}

UInt16Result NonExclusiveRateOfChangeAlarm::try_read_severity_low_low_sync() const noexcept
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

uint16_t NonExclusiveRateOfChangeAlarm::read_severity_low_low_sync() const
{
  return ::ua::detail::good_value(try_read_severity_low_low_sync());
}

void NonExclusiveRateOfChangeAlarm::read_high_high_deadband_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::high_high_deadband_browse_name(),
    &Variant::is_double,
    {"NonExclusiveRateOfChangeAlarm",
      "high_high_deadband",
      "NonExclusiveRateOfChangeAlarm::read_high_high_deadband_async"},
    std::move(complete));
}

DoubleResult NonExclusiveRateOfChangeAlarm::try_read_high_high_deadband_sync() const noexcept
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

double NonExclusiveRateOfChangeAlarm::read_high_high_deadband_sync() const
{
  return ::ua::detail::good_value(try_read_high_high_deadband_sync());
}

void NonExclusiveRateOfChangeAlarm::read_high_deadband_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::high_deadband_browse_name(),
    &Variant::is_double,
    {"NonExclusiveRateOfChangeAlarm",
      "high_deadband",
      "NonExclusiveRateOfChangeAlarm::read_high_deadband_async"},
    std::move(complete));
}

DoubleResult NonExclusiveRateOfChangeAlarm::try_read_high_deadband_sync() const noexcept
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

double NonExclusiveRateOfChangeAlarm::read_high_deadband_sync() const
{
  return ::ua::detail::good_value(try_read_high_deadband_sync());
}

void NonExclusiveRateOfChangeAlarm::read_low_deadband_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::low_deadband_browse_name(),
    &Variant::is_double,
    {"NonExclusiveRateOfChangeAlarm",
      "low_deadband",
      "NonExclusiveRateOfChangeAlarm::read_low_deadband_async"},
    std::move(complete));
}

DoubleResult NonExclusiveRateOfChangeAlarm::try_read_low_deadband_sync() const noexcept
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

double NonExclusiveRateOfChangeAlarm::read_low_deadband_sync() const
{
  return ::ua::detail::good_value(try_read_low_deadband_sync());
}

void NonExclusiveRateOfChangeAlarm::read_low_low_deadband_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::low_low_deadband_browse_name(),
    &Variant::is_double,
    {"NonExclusiveRateOfChangeAlarm",
      "low_low_deadband",
      "NonExclusiveRateOfChangeAlarm::read_low_low_deadband_async"},
    std::move(complete));
}

DoubleResult NonExclusiveRateOfChangeAlarm::try_read_low_low_deadband_sync() const noexcept
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

double NonExclusiveRateOfChangeAlarm::read_low_low_deadband_sync() const
{
  return ::ua::detail::good_value(try_read_low_low_deadband_sync());
}

void NonExclusiveRateOfChangeAlarm::read_input_node_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::input_node_browse_name(),
    &Variant::is_node_id,
    {"NonExclusiveRateOfChangeAlarm", "input_node", "NonExclusiveRateOfChangeAlarm::read_input_node_async"},
    std::move(complete));
}

NodeIdResult NonExclusiveRateOfChangeAlarm::try_read_input_node_sync() const noexcept
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

NodeId NonExclusiveRateOfChangeAlarm::read_input_node_sync() const
{
  return ::ua::detail::good_value(try_read_input_node_sync());
}

void NonExclusiveRateOfChangeAlarm::read_suppressed_or_shelved_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::suppressed_or_shelved_browse_name(),
    &Variant::is_boolean,
    {"NonExclusiveRateOfChangeAlarm",
      "suppressed_or_shelved",
      "NonExclusiveRateOfChangeAlarm::read_suppressed_or_shelved_async"},
    std::move(complete));
}

BoolResult NonExclusiveRateOfChangeAlarm::try_read_suppressed_or_shelved_sync() const noexcept
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

bool NonExclusiveRateOfChangeAlarm::read_suppressed_or_shelved_sync() const
{
  return ::ua::detail::good_value(try_read_suppressed_or_shelved_sync());
}

void NonExclusiveRateOfChangeAlarm::read_audible_enabled_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::audible_enabled_browse_name(),
    &Variant::is_boolean,
    {"NonExclusiveRateOfChangeAlarm",
      "audible_enabled",
      "NonExclusiveRateOfChangeAlarm::read_audible_enabled_async"},
    std::move(complete));
}

BoolResult NonExclusiveRateOfChangeAlarm::try_read_audible_enabled_sync() const noexcept
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

bool NonExclusiveRateOfChangeAlarm::read_audible_enabled_sync() const
{
  return ::ua::detail::good_value(try_read_audible_enabled_sync());
}

void NonExclusiveRateOfChangeAlarm::read_condition_class_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::condition_class_id_browse_name(),
    &Variant::is_node_id,
    {"NonExclusiveRateOfChangeAlarm",
      "condition_class_id",
      "NonExclusiveRateOfChangeAlarm::read_condition_class_id_async"},
    std::move(complete));
}

NodeIdResult NonExclusiveRateOfChangeAlarm::try_read_condition_class_id_sync() const noexcept
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

NodeId NonExclusiveRateOfChangeAlarm::read_condition_class_id_sync() const
{
  return ::ua::detail::good_value(try_read_condition_class_id_sync());
}

void NonExclusiveRateOfChangeAlarm::read_condition_class_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::condition_class_name_browse_name(),
    &Variant::is_localized_text,
    {"NonExclusiveRateOfChangeAlarm",
      "condition_class_name",
      "NonExclusiveRateOfChangeAlarm::read_condition_class_name_async"},
    std::move(complete));
}

LocalizedTextResult NonExclusiveRateOfChangeAlarm::try_read_condition_class_name_sync() const noexcept
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

LocalizedText NonExclusiveRateOfChangeAlarm::read_condition_class_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_class_name_sync());
}

void NonExclusiveRateOfChangeAlarm::read_condition_sub_class_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::condition_sub_class_id_browse_name(),
    &Variant::is_node_id,
    {"NonExclusiveRateOfChangeAlarm",
      "condition_sub_class_id",
      "NonExclusiveRateOfChangeAlarm::read_condition_sub_class_id_async"},
    std::move(complete));
}

NodeIdResult NonExclusiveRateOfChangeAlarm::try_read_condition_sub_class_id_sync() const noexcept
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

NodeId NonExclusiveRateOfChangeAlarm::read_condition_sub_class_id_sync() const
{
  return ::ua::detail::good_value(try_read_condition_sub_class_id_sync());
}

void NonExclusiveRateOfChangeAlarm::read_condition_sub_class_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::condition_sub_class_name_browse_name(),
    &Variant::is_localized_text,
    {"NonExclusiveRateOfChangeAlarm",
      "condition_sub_class_name",
      "NonExclusiveRateOfChangeAlarm::read_condition_sub_class_name_async"},
    std::move(complete));
}

LocalizedTextResult NonExclusiveRateOfChangeAlarm::try_read_condition_sub_class_name_sync() const noexcept
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

LocalizedText NonExclusiveRateOfChangeAlarm::read_condition_sub_class_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_sub_class_name_sync());
}

void NonExclusiveRateOfChangeAlarm::read_condition_name_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::condition_name_browse_name(),
    &Variant::is_string,
    {"NonExclusiveRateOfChangeAlarm",
      "condition_name",
      "NonExclusiveRateOfChangeAlarm::read_condition_name_async"},
    std::move(complete));
}

StringResult NonExclusiveRateOfChangeAlarm::try_read_condition_name_sync() const noexcept
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

String NonExclusiveRateOfChangeAlarm::read_condition_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_name_sync());
}

void NonExclusiveRateOfChangeAlarm::read_branch_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::branch_id_browse_name(),
    &Variant::is_node_id,
    {"NonExclusiveRateOfChangeAlarm", "branch_id", "NonExclusiveRateOfChangeAlarm::read_branch_id_async"},
    std::move(complete));
}

NodeIdResult NonExclusiveRateOfChangeAlarm::try_read_branch_id_sync() const noexcept
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

NodeId NonExclusiveRateOfChangeAlarm::read_branch_id_sync() const
{
  return ::ua::detail::good_value(try_read_branch_id_sync());
}

void NonExclusiveRateOfChangeAlarm::read_retain_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::retain_browse_name(),
    &Variant::is_boolean,
    {"NonExclusiveRateOfChangeAlarm", "retain", "NonExclusiveRateOfChangeAlarm::read_retain_async"},
    std::move(complete));
}

BoolResult NonExclusiveRateOfChangeAlarm::try_read_retain_sync() const noexcept
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

bool NonExclusiveRateOfChangeAlarm::read_retain_sync() const
{
  return ::ua::detail::good_value(try_read_retain_sync());
}

void NonExclusiveRateOfChangeAlarm::read_supports_filtered_retain_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::supports_filtered_retain_browse_name(),
    &Variant::is_boolean,
    {"NonExclusiveRateOfChangeAlarm",
      "supports_filtered_retain",
      "NonExclusiveRateOfChangeAlarm::read_supports_filtered_retain_async"},
    std::move(complete));
}

BoolResult NonExclusiveRateOfChangeAlarm::try_read_supports_filtered_retain_sync() const noexcept
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

bool NonExclusiveRateOfChangeAlarm::read_supports_filtered_retain_sync() const
{
  return ::ua::detail::good_value(try_read_supports_filtered_retain_sync());
}

void NonExclusiveRateOfChangeAlarm::read_client_user_id_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::client_user_id_browse_name(),
    &Variant::is_string,
    {"NonExclusiveRateOfChangeAlarm",
      "client_user_id",
      "NonExclusiveRateOfChangeAlarm::read_client_user_id_async"},
    std::move(complete));
}

StringResult NonExclusiveRateOfChangeAlarm::try_read_client_user_id_sync() const noexcept
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

String NonExclusiveRateOfChangeAlarm::read_client_user_id_sync() const
{
  return ::ua::detail::good_value(try_read_client_user_id_sync());
}

void NonExclusiveRateOfChangeAlarm::read_event_id_async(
  std::function<void(ByteStringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(ByteStringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<ByteString>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::event_id_browse_name(),
    &Variant::is_byte_string,
    {"NonExclusiveRateOfChangeAlarm", "event_id", "NonExclusiveRateOfChangeAlarm::read_event_id_async"},
    std::move(complete));
}

ByteStringResult NonExclusiveRateOfChangeAlarm::try_read_event_id_sync() const noexcept
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

ByteString NonExclusiveRateOfChangeAlarm::read_event_id_sync() const
{
  return ::ua::detail::good_value(try_read_event_id_sync());
}

void NonExclusiveRateOfChangeAlarm::read_event_type_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::event_type_browse_name(),
    &Variant::is_node_id,
    {"NonExclusiveRateOfChangeAlarm", "event_type", "NonExclusiveRateOfChangeAlarm::read_event_type_async"},
    std::move(complete));
}

NodeIdResult NonExclusiveRateOfChangeAlarm::try_read_event_type_sync() const noexcept
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

NodeId NonExclusiveRateOfChangeAlarm::read_event_type_sync() const
{
  return ::ua::detail::good_value(try_read_event_type_sync());
}

void NonExclusiveRateOfChangeAlarm::read_source_node_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::source_node_browse_name(),
    &Variant::is_node_id,
    {"NonExclusiveRateOfChangeAlarm", "source_node", "NonExclusiveRateOfChangeAlarm::read_source_node_async"},
    std::move(complete));
}

NodeIdResult NonExclusiveRateOfChangeAlarm::try_read_source_node_sync() const noexcept
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

NodeId NonExclusiveRateOfChangeAlarm::read_source_node_sync() const
{
  return ::ua::detail::good_value(try_read_source_node_sync());
}

void NonExclusiveRateOfChangeAlarm::read_source_name_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::source_name_browse_name(),
    &Variant::is_string,
    {"NonExclusiveRateOfChangeAlarm", "source_name", "NonExclusiveRateOfChangeAlarm::read_source_name_async"},
    std::move(complete));
}

StringResult NonExclusiveRateOfChangeAlarm::try_read_source_name_sync() const noexcept
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

String NonExclusiveRateOfChangeAlarm::read_source_name_sync() const
{
  return ::ua::detail::good_value(try_read_source_name_sync());
}

void NonExclusiveRateOfChangeAlarm::read_message_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::message_browse_name(),
    &Variant::is_localized_text,
    {"NonExclusiveRateOfChangeAlarm", "message", "NonExclusiveRateOfChangeAlarm::read_message_async"},
    std::move(complete));
}

LocalizedTextResult NonExclusiveRateOfChangeAlarm::try_read_message_sync() const noexcept
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

LocalizedText NonExclusiveRateOfChangeAlarm::read_message_sync() const
{
  return ::ua::detail::good_value(try_read_message_sync());
}

void NonExclusiveRateOfChangeAlarm::read_severity_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::severity_browse_name(),
    &Variant::is_uint16,
    {"NonExclusiveRateOfChangeAlarm", "severity", "NonExclusiveRateOfChangeAlarm::read_severity_async"},
    std::move(complete));
}

UInt16Result NonExclusiveRateOfChangeAlarm::try_read_severity_sync() const noexcept
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

uint16_t NonExclusiveRateOfChangeAlarm::read_severity_sync() const
{
  return ::ua::detail::good_value(try_read_severity_sync());
}

// --- Typed value write shortcuts ---

void NonExclusiveRateOfChangeAlarm::write_high_high_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::high_high_limit_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_high_high_limit_sync(double value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_high_high_limit_sync(double value) const
{
  try_write_high_high_limit_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_high_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::high_limit_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_high_limit_sync(double value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_high_limit_sync(double value) const
{
  try_write_high_limit_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_low_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::low_limit_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_low_limit_sync(double value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_low_limit_sync(double value) const
{
  try_write_low_limit_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_low_low_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::low_low_limit_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_low_low_limit_sync(double value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_low_low_limit_sync(double value) const
{
  try_write_low_low_limit_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_base_high_high_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::base_high_high_limit_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_base_high_high_limit_sync(double value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_base_high_high_limit_sync(double value) const
{
  try_write_base_high_high_limit_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_base_high_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::base_high_limit_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_base_high_limit_sync(double value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_base_high_limit_sync(double value) const
{
  try_write_base_high_limit_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_base_low_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::base_low_limit_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_base_low_limit_sync(double value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_base_low_limit_sync(double value) const
{
  try_write_base_low_limit_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_base_low_low_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::base_low_low_limit_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_base_low_low_limit_sync(double value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_base_low_low_limit_sync(double value) const
{
  try_write_base_low_low_limit_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_severity_high_high_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::severity_high_high_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_severity_high_high_sync(uint16_t value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_severity_high_high_sync(uint16_t value) const
{
  try_write_severity_high_high_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_severity_high_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::severity_high_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_severity_high_sync(uint16_t value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_severity_high_sync(uint16_t value) const
{
  try_write_severity_high_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_severity_low_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::severity_low_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_severity_low_sync(uint16_t value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_severity_low_sync(uint16_t value) const
{
  try_write_severity_low_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_severity_low_low_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::severity_low_low_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_severity_low_low_sync(uint16_t value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_severity_low_low_sync(uint16_t value) const
{
  try_write_severity_low_low_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_high_high_deadband_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::high_high_deadband_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_high_high_deadband_sync(double value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_high_high_deadband_sync(double value) const
{
  try_write_high_high_deadband_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_high_deadband_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::high_deadband_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_high_deadband_sync(double value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_high_deadband_sync(double value) const
{
  try_write_high_deadband_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_low_deadband_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::low_deadband_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_low_deadband_sync(double value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_low_deadband_sync(double value) const
{
  try_write_low_deadband_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_low_low_deadband_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::low_low_deadband_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_low_low_deadband_sync(double value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_low_low_deadband_sync(double value) const
{
  try_write_low_low_deadband_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_input_node_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::input_node_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_input_node_sync(NodeId value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_input_node_sync(NodeId value) const
{
  try_write_input_node_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_suppressed_or_shelved_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::suppressed_or_shelved_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_suppressed_or_shelved_sync(bool value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_suppressed_or_shelved_sync(bool value) const
{
  try_write_suppressed_or_shelved_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_audible_enabled_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::audible_enabled_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_audible_enabled_sync(bool value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_audible_enabled_sync(bool value) const
{
  try_write_audible_enabled_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_condition_class_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::condition_class_id_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_condition_class_id_sync(NodeId value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_condition_class_id_sync(NodeId value) const
{
  try_write_condition_class_id_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_condition_class_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::condition_class_name_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_condition_class_name_sync(
  LocalizedText value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_condition_class_name_sync(LocalizedText value) const
{
  try_write_condition_class_name_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_condition_sub_class_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::condition_sub_class_id_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_condition_sub_class_id_sync(NodeId value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_condition_sub_class_id_sync(NodeId value) const
{
  try_write_condition_sub_class_id_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_condition_sub_class_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::condition_sub_class_name_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_condition_sub_class_name_sync(
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

void NonExclusiveRateOfChangeAlarm::write_condition_sub_class_name_sync(LocalizedText value) const
{
  try_write_condition_sub_class_name_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_condition_name_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::condition_name_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_condition_name_sync(String value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_condition_name_sync(String value) const
{
  try_write_condition_name_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_branch_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::branch_id_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_branch_id_sync(NodeId value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_branch_id_sync(NodeId value) const
{
  try_write_branch_id_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_retain_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::retain_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_retain_sync(bool value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_retain_sync(bool value) const
{
  try_write_retain_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_supports_filtered_retain_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::supports_filtered_retain_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_supports_filtered_retain_sync(bool value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_supports_filtered_retain_sync(bool value) const
{
  try_write_supports_filtered_retain_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_client_user_id_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::client_user_id_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_client_user_id_sync(String value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_client_user_id_sync(String value) const
{
  try_write_client_user_id_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_event_id_async(
  ByteString value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::event_id_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_event_id_sync(ByteString value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_event_id_sync(ByteString value) const
{
  try_write_event_id_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_event_type_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::event_type_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_event_type_sync(NodeId value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_event_type_sync(NodeId value) const
{
  try_write_event_type_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_source_node_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::source_node_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_source_node_sync(NodeId value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_source_node_sync(NodeId value) const
{
  try_write_source_node_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_source_name_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::source_name_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_source_name_sync(String value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_source_name_sync(String value) const
{
  try_write_source_name_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_message_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::message_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_message_sync(LocalizedText value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_message_sync(LocalizedText value) const
{
  try_write_message_sync(value).value();
}

void NonExclusiveRateOfChangeAlarm::write_severity_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveRateOfChangeAlarmTypeTraits::severity_browse_name(),
    "NonExclusiveRateOfChangeAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveRateOfChangeAlarm::try_write_severity_sync(uint16_t value) const noexcept
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

void NonExclusiveRateOfChangeAlarm::write_severity_sync(uint16_t value) const
{
  try_write_severity_sync(value).value();
}

}  // namespace ua
