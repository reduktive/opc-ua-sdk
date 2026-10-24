// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_non_exclusive_level_alarm.h"

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

struct NonExclusiveLevelAlarmTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::NonExclusiveLevelAlarmType};
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

NonExclusiveLevelAlarm::NonExclusiveLevelAlarm(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void NonExclusiveLevelAlarm::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    NonExclusiveLevelAlarmTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(NonExclusiveLevelAlarmResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(NonExclusiveLevelAlarmResult{
        NonExclusiveLevelAlarm{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

NonExclusiveLevelAlarmResult NonExclusiveLevelAlarm::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NonExclusiveLevelAlarmResult>(addressSpace.executor(),
      [&](std::function<void(NonExclusiveLevelAlarmResult)> complete)
      {
        NonExclusiveLevelAlarm::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NonExclusiveLevelAlarm NonExclusiveLevelAlarm::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void NonExclusiveLevelAlarm::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void NonExclusiveLevelAlarm::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // NonExclusiveLevelAlarmType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    NonExclusiveLevelAlarmTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(NonExclusiveLevelAlarmResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(NonExclusiveLevelAlarmResult{::ua::detail::address_space_gone("NonExclusiveLevelAlarm")});
        return;
      }
      complete(
        NonExclusiveLevelAlarm{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

NonExclusiveLevelAlarmResult NonExclusiveLevelAlarm::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NonExclusiveLevelAlarmResult>(addressSpace.executor(),
      [&](std::function<void(NonExclusiveLevelAlarmResult)> complete)
      {
        NonExclusiveLevelAlarm::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NonExclusiveLevelAlarm NonExclusiveLevelAlarm::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void NonExclusiveLevelAlarm::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void NonExclusiveLevelAlarm::find_property_async(
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
    "NonExclusiveLevelAlarm",
    std::move(complete));
}

// --- Property accessors ---

void NonExclusiveLevelAlarm::high_high_limit_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::high_high_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_high_high_limit_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::high_high_limit_property_sync() const
{
  return ::ua::detail::good_value(try_high_high_limit_property_sync());
}

void NonExclusiveLevelAlarm::high_limit_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::high_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_high_limit_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::high_limit_property_sync() const
{
  return ::ua::detail::good_value(try_high_limit_property_sync());
}

void NonExclusiveLevelAlarm::low_limit_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::low_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_low_limit_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::low_limit_property_sync() const
{
  return ::ua::detail::good_value(try_low_limit_property_sync());
}

void NonExclusiveLevelAlarm::low_low_limit_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::low_low_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_low_low_limit_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::low_low_limit_property_sync() const
{
  return ::ua::detail::good_value(try_low_low_limit_property_sync());
}

void NonExclusiveLevelAlarm::base_high_high_limit_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveLevelAlarmTypeTraits::base_high_high_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_base_high_high_limit_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::base_high_high_limit_property_sync() const
{
  return ::ua::detail::good_value(try_base_high_high_limit_property_sync());
}

void NonExclusiveLevelAlarm::base_high_limit_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::base_high_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_base_high_limit_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::base_high_limit_property_sync() const
{
  return ::ua::detail::good_value(try_base_high_limit_property_sync());
}

void NonExclusiveLevelAlarm::base_low_limit_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::base_low_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_base_low_limit_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::base_low_limit_property_sync() const
{
  return ::ua::detail::good_value(try_base_low_limit_property_sync());
}

void NonExclusiveLevelAlarm::base_low_low_limit_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveLevelAlarmTypeTraits::base_low_low_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_base_low_low_limit_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::base_low_low_limit_property_sync() const
{
  return ::ua::detail::good_value(try_base_low_low_limit_property_sync());
}

void NonExclusiveLevelAlarm::severity_high_high_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveLevelAlarmTypeTraits::severity_high_high_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_severity_high_high_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::severity_high_high_property_sync() const
{
  return ::ua::detail::good_value(try_severity_high_high_property_sync());
}

void NonExclusiveLevelAlarm::severity_high_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::severity_high_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_severity_high_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::severity_high_property_sync() const
{
  return ::ua::detail::good_value(try_severity_high_property_sync());
}

void NonExclusiveLevelAlarm::severity_low_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::severity_low_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_severity_low_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::severity_low_property_sync() const
{
  return ::ua::detail::good_value(try_severity_low_property_sync());
}

void NonExclusiveLevelAlarm::severity_low_low_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::severity_low_low_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_severity_low_low_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::severity_low_low_property_sync() const
{
  return ::ua::detail::good_value(try_severity_low_low_property_sync());
}

void NonExclusiveLevelAlarm::high_high_deadband_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveLevelAlarmTypeTraits::high_high_deadband_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_high_high_deadband_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::high_high_deadband_property_sync() const
{
  return ::ua::detail::good_value(try_high_high_deadband_property_sync());
}

void NonExclusiveLevelAlarm::high_deadband_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::high_deadband_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_high_deadband_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::high_deadband_property_sync() const
{
  return ::ua::detail::good_value(try_high_deadband_property_sync());
}

void NonExclusiveLevelAlarm::low_deadband_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::low_deadband_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_low_deadband_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::low_deadband_property_sync() const
{
  return ::ua::detail::good_value(try_low_deadband_property_sync());
}

void NonExclusiveLevelAlarm::low_low_deadband_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::low_low_deadband_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_low_low_deadband_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::low_low_deadband_property_sync() const
{
  return ::ua::detail::good_value(try_low_low_deadband_property_sync());
}

void NonExclusiveLevelAlarm::input_node_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::input_node_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_input_node_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::input_node_property_sync() const
{
  return ::ua::detail::good_value(try_input_node_property_sync());
}

void NonExclusiveLevelAlarm::suppressed_or_shelved_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveLevelAlarmTypeTraits::suppressed_or_shelved_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_suppressed_or_shelved_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::suppressed_or_shelved_property_sync() const
{
  return ::ua::detail::good_value(try_suppressed_or_shelved_property_sync());
}

void NonExclusiveLevelAlarm::max_time_shelved_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::max_time_shelved_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_max_time_shelved_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::max_time_shelved_property_sync() const
{
  return ::ua::detail::good_value(try_max_time_shelved_property_sync());
}

void NonExclusiveLevelAlarm::audible_enabled_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::audible_enabled_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_audible_enabled_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::audible_enabled_property_sync() const
{
  return ::ua::detail::good_value(try_audible_enabled_property_sync());
}

void NonExclusiveLevelAlarm::on_delay_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::on_delay_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_on_delay_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::on_delay_property_sync() const
{
  return ::ua::detail::good_value(try_on_delay_property_sync());
}

void NonExclusiveLevelAlarm::off_delay_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::off_delay_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_off_delay_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::off_delay_property_sync() const
{
  return ::ua::detail::good_value(try_off_delay_property_sync());
}

void NonExclusiveLevelAlarm::re_alarm_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::re_alarm_time_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_re_alarm_time_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::re_alarm_time_property_sync() const
{
  return ::ua::detail::good_value(try_re_alarm_time_property_sync());
}

void NonExclusiveLevelAlarm::condition_class_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveLevelAlarmTypeTraits::condition_class_id_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_condition_class_id_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::condition_class_id_property_sync() const
{
  return ::ua::detail::good_value(try_condition_class_id_property_sync());
}

void NonExclusiveLevelAlarm::condition_class_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveLevelAlarmTypeTraits::condition_class_name_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_condition_class_name_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::condition_class_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_class_name_property_sync());
}

void NonExclusiveLevelAlarm::condition_sub_class_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveLevelAlarmTypeTraits::condition_sub_class_id_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_condition_sub_class_id_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::condition_sub_class_id_property_sync() const
{
  return ::ua::detail::good_value(try_condition_sub_class_id_property_sync());
}

void NonExclusiveLevelAlarm::condition_sub_class_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveLevelAlarmTypeTraits::condition_sub_class_name_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_condition_sub_class_name_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::condition_sub_class_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_sub_class_name_property_sync());
}

void NonExclusiveLevelAlarm::condition_name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::condition_name_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_condition_name_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::condition_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_name_property_sync());
}

void NonExclusiveLevelAlarm::branch_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::branch_id_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_branch_id_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::branch_id_property_sync() const
{
  return ::ua::detail::good_value(try_branch_id_property_sync());
}

void NonExclusiveLevelAlarm::retain_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::retain_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_retain_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::retain_property_sync() const
{
  return ::ua::detail::good_value(try_retain_property_sync());
}

void NonExclusiveLevelAlarm::supports_filtered_retain_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveLevelAlarmTypeTraits::supports_filtered_retain_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_supports_filtered_retain_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::supports_filtered_retain_property_sync() const
{
  return ::ua::detail::good_value(try_supports_filtered_retain_property_sync());
}

void NonExclusiveLevelAlarm::client_user_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::client_user_id_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_client_user_id_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::client_user_id_property_sync() const
{
  return ::ua::detail::good_value(try_client_user_id_property_sync());
}

void NonExclusiveLevelAlarm::event_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::event_id_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_event_id_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::event_id_property_sync() const
{
  return ::ua::detail::good_value(try_event_id_property_sync());
}

void NonExclusiveLevelAlarm::event_type_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::event_type_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_event_type_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::event_type_property_sync() const
{
  return ::ua::detail::good_value(try_event_type_property_sync());
}

void NonExclusiveLevelAlarm::source_node_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::source_node_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_source_node_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::source_node_property_sync() const
{
  return ::ua::detail::good_value(try_source_node_property_sync());
}

void NonExclusiveLevelAlarm::source_name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::source_name_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_source_name_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::source_name_property_sync() const
{
  return ::ua::detail::good_value(try_source_name_property_sync());
}

void NonExclusiveLevelAlarm::time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::time_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_time_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::time_property_sync() const
{
  return ::ua::detail::good_value(try_time_property_sync());
}

void NonExclusiveLevelAlarm::receive_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::receive_time_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_receive_time_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::receive_time_property_sync() const
{
  return ::ua::detail::good_value(try_receive_time_property_sync());
}

void NonExclusiveLevelAlarm::local_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::local_time_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_local_time_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::local_time_property_sync() const
{
  return ::ua::detail::good_value(try_local_time_property_sync());
}

void NonExclusiveLevelAlarm::message_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::message_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_message_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::message_property_sync() const
{
  return ::ua::detail::good_value(try_message_property_sync());
}

void NonExclusiveLevelAlarm::severity_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLevelAlarmTypeTraits::severity_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLevelAlarm::try_severity_property_sync() const noexcept
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

Property NonExclusiveLevelAlarm::severity_property_sync() const
{
  return ::ua::detail::good_value(try_severity_property_sync());
}

// --- Typed value read shortcuts ---

void NonExclusiveLevelAlarm::read_high_high_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::high_high_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveLevelAlarm", "high_high_limit", "NonExclusiveLevelAlarm::read_high_high_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveLevelAlarm::try_read_high_high_limit_sync() const noexcept
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

double NonExclusiveLevelAlarm::read_high_high_limit_sync() const
{
  return ::ua::detail::good_value(try_read_high_high_limit_sync());
}

void NonExclusiveLevelAlarm::read_high_limit_async(std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::high_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveLevelAlarm", "high_limit", "NonExclusiveLevelAlarm::read_high_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveLevelAlarm::try_read_high_limit_sync() const noexcept
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

double NonExclusiveLevelAlarm::read_high_limit_sync() const
{
  return ::ua::detail::good_value(try_read_high_limit_sync());
}

void NonExclusiveLevelAlarm::read_low_limit_async(std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::low_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveLevelAlarm", "low_limit", "NonExclusiveLevelAlarm::read_low_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveLevelAlarm::try_read_low_limit_sync() const noexcept
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

double NonExclusiveLevelAlarm::read_low_limit_sync() const
{
  return ::ua::detail::good_value(try_read_low_limit_sync());
}

void NonExclusiveLevelAlarm::read_low_low_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::low_low_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveLevelAlarm", "low_low_limit", "NonExclusiveLevelAlarm::read_low_low_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveLevelAlarm::try_read_low_low_limit_sync() const noexcept
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

double NonExclusiveLevelAlarm::read_low_low_limit_sync() const
{
  return ::ua::detail::good_value(try_read_low_low_limit_sync());
}

void NonExclusiveLevelAlarm::read_base_high_high_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::base_high_high_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveLevelAlarm",
      "base_high_high_limit",
      "NonExclusiveLevelAlarm::read_base_high_high_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveLevelAlarm::try_read_base_high_high_limit_sync() const noexcept
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

double NonExclusiveLevelAlarm::read_base_high_high_limit_sync() const
{
  return ::ua::detail::good_value(try_read_base_high_high_limit_sync());
}

void NonExclusiveLevelAlarm::read_base_high_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::base_high_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveLevelAlarm", "base_high_limit", "NonExclusiveLevelAlarm::read_base_high_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveLevelAlarm::try_read_base_high_limit_sync() const noexcept
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

double NonExclusiveLevelAlarm::read_base_high_limit_sync() const
{
  return ::ua::detail::good_value(try_read_base_high_limit_sync());
}

void NonExclusiveLevelAlarm::read_base_low_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::base_low_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveLevelAlarm", "base_low_limit", "NonExclusiveLevelAlarm::read_base_low_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveLevelAlarm::try_read_base_low_limit_sync() const noexcept
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

double NonExclusiveLevelAlarm::read_base_low_limit_sync() const
{
  return ::ua::detail::good_value(try_read_base_low_limit_sync());
}

void NonExclusiveLevelAlarm::read_base_low_low_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::base_low_low_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveLevelAlarm", "base_low_low_limit", "NonExclusiveLevelAlarm::read_base_low_low_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveLevelAlarm::try_read_base_low_low_limit_sync() const noexcept
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

double NonExclusiveLevelAlarm::read_base_low_low_limit_sync() const
{
  return ::ua::detail::good_value(try_read_base_low_low_limit_sync());
}

void NonExclusiveLevelAlarm::read_severity_high_high_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::severity_high_high_browse_name(),
    &Variant::is_uint16,
    {"NonExclusiveLevelAlarm", "severity_high_high", "NonExclusiveLevelAlarm::read_severity_high_high_async"},
    std::move(complete));
}

UInt16Result NonExclusiveLevelAlarm::try_read_severity_high_high_sync() const noexcept
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

uint16_t NonExclusiveLevelAlarm::read_severity_high_high_sync() const
{
  return ::ua::detail::good_value(try_read_severity_high_high_sync());
}

void NonExclusiveLevelAlarm::read_severity_high_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::severity_high_browse_name(),
    &Variant::is_uint16,
    {"NonExclusiveLevelAlarm", "severity_high", "NonExclusiveLevelAlarm::read_severity_high_async"},
    std::move(complete));
}

UInt16Result NonExclusiveLevelAlarm::try_read_severity_high_sync() const noexcept
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

uint16_t NonExclusiveLevelAlarm::read_severity_high_sync() const
{
  return ::ua::detail::good_value(try_read_severity_high_sync());
}

void NonExclusiveLevelAlarm::read_severity_low_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::severity_low_browse_name(),
    &Variant::is_uint16,
    {"NonExclusiveLevelAlarm", "severity_low", "NonExclusiveLevelAlarm::read_severity_low_async"},
    std::move(complete));
}

UInt16Result NonExclusiveLevelAlarm::try_read_severity_low_sync() const noexcept
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

uint16_t NonExclusiveLevelAlarm::read_severity_low_sync() const
{
  return ::ua::detail::good_value(try_read_severity_low_sync());
}

void NonExclusiveLevelAlarm::read_severity_low_low_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::severity_low_low_browse_name(),
    &Variant::is_uint16,
    {"NonExclusiveLevelAlarm", "severity_low_low", "NonExclusiveLevelAlarm::read_severity_low_low_async"},
    std::move(complete));
}

UInt16Result NonExclusiveLevelAlarm::try_read_severity_low_low_sync() const noexcept
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

uint16_t NonExclusiveLevelAlarm::read_severity_low_low_sync() const
{
  return ::ua::detail::good_value(try_read_severity_low_low_sync());
}

void NonExclusiveLevelAlarm::read_high_high_deadband_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::high_high_deadband_browse_name(),
    &Variant::is_double,
    {"NonExclusiveLevelAlarm", "high_high_deadband", "NonExclusiveLevelAlarm::read_high_high_deadband_async"},
    std::move(complete));
}

DoubleResult NonExclusiveLevelAlarm::try_read_high_high_deadband_sync() const noexcept
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

double NonExclusiveLevelAlarm::read_high_high_deadband_sync() const
{
  return ::ua::detail::good_value(try_read_high_high_deadband_sync());
}

void NonExclusiveLevelAlarm::read_high_deadband_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::high_deadband_browse_name(),
    &Variant::is_double,
    {"NonExclusiveLevelAlarm", "high_deadband", "NonExclusiveLevelAlarm::read_high_deadband_async"},
    std::move(complete));
}

DoubleResult NonExclusiveLevelAlarm::try_read_high_deadband_sync() const noexcept
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

double NonExclusiveLevelAlarm::read_high_deadband_sync() const
{
  return ::ua::detail::good_value(try_read_high_deadband_sync());
}

void NonExclusiveLevelAlarm::read_low_deadband_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::low_deadband_browse_name(),
    &Variant::is_double,
    {"NonExclusiveLevelAlarm", "low_deadband", "NonExclusiveLevelAlarm::read_low_deadband_async"},
    std::move(complete));
}

DoubleResult NonExclusiveLevelAlarm::try_read_low_deadband_sync() const noexcept
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

double NonExclusiveLevelAlarm::read_low_deadband_sync() const
{
  return ::ua::detail::good_value(try_read_low_deadband_sync());
}

void NonExclusiveLevelAlarm::read_low_low_deadband_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::low_low_deadband_browse_name(),
    &Variant::is_double,
    {"NonExclusiveLevelAlarm", "low_low_deadband", "NonExclusiveLevelAlarm::read_low_low_deadband_async"},
    std::move(complete));
}

DoubleResult NonExclusiveLevelAlarm::try_read_low_low_deadband_sync() const noexcept
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

double NonExclusiveLevelAlarm::read_low_low_deadband_sync() const
{
  return ::ua::detail::good_value(try_read_low_low_deadband_sync());
}

void NonExclusiveLevelAlarm::read_input_node_async(std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::input_node_browse_name(),
    &Variant::is_node_id,
    {"NonExclusiveLevelAlarm", "input_node", "NonExclusiveLevelAlarm::read_input_node_async"},
    std::move(complete));
}

NodeIdResult NonExclusiveLevelAlarm::try_read_input_node_sync() const noexcept
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

NodeId NonExclusiveLevelAlarm::read_input_node_sync() const
{
  return ::ua::detail::good_value(try_read_input_node_sync());
}

void NonExclusiveLevelAlarm::read_suppressed_or_shelved_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::suppressed_or_shelved_browse_name(),
    &Variant::is_boolean,
    {"NonExclusiveLevelAlarm",
      "suppressed_or_shelved",
      "NonExclusiveLevelAlarm::read_suppressed_or_shelved_async"},
    std::move(complete));
}

BoolResult NonExclusiveLevelAlarm::try_read_suppressed_or_shelved_sync() const noexcept
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

bool NonExclusiveLevelAlarm::read_suppressed_or_shelved_sync() const
{
  return ::ua::detail::good_value(try_read_suppressed_or_shelved_sync());
}

void NonExclusiveLevelAlarm::read_audible_enabled_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::audible_enabled_browse_name(),
    &Variant::is_boolean,
    {"NonExclusiveLevelAlarm", "audible_enabled", "NonExclusiveLevelAlarm::read_audible_enabled_async"},
    std::move(complete));
}

BoolResult NonExclusiveLevelAlarm::try_read_audible_enabled_sync() const noexcept
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

bool NonExclusiveLevelAlarm::read_audible_enabled_sync() const
{
  return ::ua::detail::good_value(try_read_audible_enabled_sync());
}

void NonExclusiveLevelAlarm::read_condition_class_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::condition_class_id_browse_name(),
    &Variant::is_node_id,
    {"NonExclusiveLevelAlarm", "condition_class_id", "NonExclusiveLevelAlarm::read_condition_class_id_async"},
    std::move(complete));
}

NodeIdResult NonExclusiveLevelAlarm::try_read_condition_class_id_sync() const noexcept
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

NodeId NonExclusiveLevelAlarm::read_condition_class_id_sync() const
{
  return ::ua::detail::good_value(try_read_condition_class_id_sync());
}

void NonExclusiveLevelAlarm::read_condition_class_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::condition_class_name_browse_name(),
    &Variant::is_localized_text,
    {"NonExclusiveLevelAlarm",
      "condition_class_name",
      "NonExclusiveLevelAlarm::read_condition_class_name_async"},
    std::move(complete));
}

LocalizedTextResult NonExclusiveLevelAlarm::try_read_condition_class_name_sync() const noexcept
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

LocalizedText NonExclusiveLevelAlarm::read_condition_class_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_class_name_sync());
}

void NonExclusiveLevelAlarm::read_condition_sub_class_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::condition_sub_class_id_browse_name(),
    &Variant::is_node_id,
    {"NonExclusiveLevelAlarm",
      "condition_sub_class_id",
      "NonExclusiveLevelAlarm::read_condition_sub_class_id_async"},
    std::move(complete));
}

NodeIdResult NonExclusiveLevelAlarm::try_read_condition_sub_class_id_sync() const noexcept
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

NodeId NonExclusiveLevelAlarm::read_condition_sub_class_id_sync() const
{
  return ::ua::detail::good_value(try_read_condition_sub_class_id_sync());
}

void NonExclusiveLevelAlarm::read_condition_sub_class_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::condition_sub_class_name_browse_name(),
    &Variant::is_localized_text,
    {"NonExclusiveLevelAlarm",
      "condition_sub_class_name",
      "NonExclusiveLevelAlarm::read_condition_sub_class_name_async"},
    std::move(complete));
}

LocalizedTextResult NonExclusiveLevelAlarm::try_read_condition_sub_class_name_sync() const noexcept
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

LocalizedText NonExclusiveLevelAlarm::read_condition_sub_class_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_sub_class_name_sync());
}

void NonExclusiveLevelAlarm::read_condition_name_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::condition_name_browse_name(),
    &Variant::is_string,
    {"NonExclusiveLevelAlarm", "condition_name", "NonExclusiveLevelAlarm::read_condition_name_async"},
    std::move(complete));
}

StringResult NonExclusiveLevelAlarm::try_read_condition_name_sync() const noexcept
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

String NonExclusiveLevelAlarm::read_condition_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_name_sync());
}

void NonExclusiveLevelAlarm::read_branch_id_async(std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::branch_id_browse_name(),
    &Variant::is_node_id,
    {"NonExclusiveLevelAlarm", "branch_id", "NonExclusiveLevelAlarm::read_branch_id_async"},
    std::move(complete));
}

NodeIdResult NonExclusiveLevelAlarm::try_read_branch_id_sync() const noexcept
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

NodeId NonExclusiveLevelAlarm::read_branch_id_sync() const
{
  return ::ua::detail::good_value(try_read_branch_id_sync());
}

void NonExclusiveLevelAlarm::read_retain_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::retain_browse_name(),
    &Variant::is_boolean,
    {"NonExclusiveLevelAlarm", "retain", "NonExclusiveLevelAlarm::read_retain_async"},
    std::move(complete));
}

BoolResult NonExclusiveLevelAlarm::try_read_retain_sync() const noexcept
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

bool NonExclusiveLevelAlarm::read_retain_sync() const
{
  return ::ua::detail::good_value(try_read_retain_sync());
}

void NonExclusiveLevelAlarm::read_supports_filtered_retain_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::supports_filtered_retain_browse_name(),
    &Variant::is_boolean,
    {"NonExclusiveLevelAlarm",
      "supports_filtered_retain",
      "NonExclusiveLevelAlarm::read_supports_filtered_retain_async"},
    std::move(complete));
}

BoolResult NonExclusiveLevelAlarm::try_read_supports_filtered_retain_sync() const noexcept
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

bool NonExclusiveLevelAlarm::read_supports_filtered_retain_sync() const
{
  return ::ua::detail::good_value(try_read_supports_filtered_retain_sync());
}

void NonExclusiveLevelAlarm::read_client_user_id_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::client_user_id_browse_name(),
    &Variant::is_string,
    {"NonExclusiveLevelAlarm", "client_user_id", "NonExclusiveLevelAlarm::read_client_user_id_async"},
    std::move(complete));
}

StringResult NonExclusiveLevelAlarm::try_read_client_user_id_sync() const noexcept
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

String NonExclusiveLevelAlarm::read_client_user_id_sync() const
{
  return ::ua::detail::good_value(try_read_client_user_id_sync());
}

void NonExclusiveLevelAlarm::read_event_id_async(
  std::function<void(ByteStringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(ByteStringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<ByteString>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::event_id_browse_name(),
    &Variant::is_byte_string,
    {"NonExclusiveLevelAlarm", "event_id", "NonExclusiveLevelAlarm::read_event_id_async"},
    std::move(complete));
}

ByteStringResult NonExclusiveLevelAlarm::try_read_event_id_sync() const noexcept
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

ByteString NonExclusiveLevelAlarm::read_event_id_sync() const
{
  return ::ua::detail::good_value(try_read_event_id_sync());
}

void NonExclusiveLevelAlarm::read_event_type_async(std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::event_type_browse_name(),
    &Variant::is_node_id,
    {"NonExclusiveLevelAlarm", "event_type", "NonExclusiveLevelAlarm::read_event_type_async"},
    std::move(complete));
}

NodeIdResult NonExclusiveLevelAlarm::try_read_event_type_sync() const noexcept
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

NodeId NonExclusiveLevelAlarm::read_event_type_sync() const
{
  return ::ua::detail::good_value(try_read_event_type_sync());
}

void NonExclusiveLevelAlarm::read_source_node_async(std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::source_node_browse_name(),
    &Variant::is_node_id,
    {"NonExclusiveLevelAlarm", "source_node", "NonExclusiveLevelAlarm::read_source_node_async"},
    std::move(complete));
}

NodeIdResult NonExclusiveLevelAlarm::try_read_source_node_sync() const noexcept
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

NodeId NonExclusiveLevelAlarm::read_source_node_sync() const
{
  return ::ua::detail::good_value(try_read_source_node_sync());
}

void NonExclusiveLevelAlarm::read_source_name_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::source_name_browse_name(),
    &Variant::is_string,
    {"NonExclusiveLevelAlarm", "source_name", "NonExclusiveLevelAlarm::read_source_name_async"},
    std::move(complete));
}

StringResult NonExclusiveLevelAlarm::try_read_source_name_sync() const noexcept
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

String NonExclusiveLevelAlarm::read_source_name_sync() const
{
  return ::ua::detail::good_value(try_read_source_name_sync());
}

void NonExclusiveLevelAlarm::read_message_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::message_browse_name(),
    &Variant::is_localized_text,
    {"NonExclusiveLevelAlarm", "message", "NonExclusiveLevelAlarm::read_message_async"},
    std::move(complete));
}

LocalizedTextResult NonExclusiveLevelAlarm::try_read_message_sync() const noexcept
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

LocalizedText NonExclusiveLevelAlarm::read_message_sync() const
{
  return ::ua::detail::good_value(try_read_message_sync());
}

void NonExclusiveLevelAlarm::read_severity_async(std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::severity_browse_name(),
    &Variant::is_uint16,
    {"NonExclusiveLevelAlarm", "severity", "NonExclusiveLevelAlarm::read_severity_async"},
    std::move(complete));
}

UInt16Result NonExclusiveLevelAlarm::try_read_severity_sync() const noexcept
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

uint16_t NonExclusiveLevelAlarm::read_severity_sync() const
{
  return ::ua::detail::good_value(try_read_severity_sync());
}

// --- Typed value write shortcuts ---

void NonExclusiveLevelAlarm::write_high_high_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::high_high_limit_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_high_high_limit_sync(double value) const noexcept
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

void NonExclusiveLevelAlarm::write_high_high_limit_sync(double value) const
{
  try_write_high_high_limit_sync(value).value();
}

void NonExclusiveLevelAlarm::write_high_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::high_limit_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_high_limit_sync(double value) const noexcept
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

void NonExclusiveLevelAlarm::write_high_limit_sync(double value) const
{
  try_write_high_limit_sync(value).value();
}

void NonExclusiveLevelAlarm::write_low_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::low_limit_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_low_limit_sync(double value) const noexcept
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

void NonExclusiveLevelAlarm::write_low_limit_sync(double value) const
{
  try_write_low_limit_sync(value).value();
}

void NonExclusiveLevelAlarm::write_low_low_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::low_low_limit_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_low_low_limit_sync(double value) const noexcept
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

void NonExclusiveLevelAlarm::write_low_low_limit_sync(double value) const
{
  try_write_low_low_limit_sync(value).value();
}

void NonExclusiveLevelAlarm::write_base_high_high_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::base_high_high_limit_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_base_high_high_limit_sync(double value) const noexcept
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

void NonExclusiveLevelAlarm::write_base_high_high_limit_sync(double value) const
{
  try_write_base_high_high_limit_sync(value).value();
}

void NonExclusiveLevelAlarm::write_base_high_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::base_high_limit_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_base_high_limit_sync(double value) const noexcept
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

void NonExclusiveLevelAlarm::write_base_high_limit_sync(double value) const
{
  try_write_base_high_limit_sync(value).value();
}

void NonExclusiveLevelAlarm::write_base_low_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::base_low_limit_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_base_low_limit_sync(double value) const noexcept
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

void NonExclusiveLevelAlarm::write_base_low_limit_sync(double value) const
{
  try_write_base_low_limit_sync(value).value();
}

void NonExclusiveLevelAlarm::write_base_low_low_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::base_low_low_limit_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_base_low_low_limit_sync(double value) const noexcept
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

void NonExclusiveLevelAlarm::write_base_low_low_limit_sync(double value) const
{
  try_write_base_low_low_limit_sync(value).value();
}

void NonExclusiveLevelAlarm::write_severity_high_high_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::severity_high_high_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_severity_high_high_sync(uint16_t value) const noexcept
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

void NonExclusiveLevelAlarm::write_severity_high_high_sync(uint16_t value) const
{
  try_write_severity_high_high_sync(value).value();
}

void NonExclusiveLevelAlarm::write_severity_high_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::severity_high_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_severity_high_sync(uint16_t value) const noexcept
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

void NonExclusiveLevelAlarm::write_severity_high_sync(uint16_t value) const
{
  try_write_severity_high_sync(value).value();
}

void NonExclusiveLevelAlarm::write_severity_low_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::severity_low_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_severity_low_sync(uint16_t value) const noexcept
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

void NonExclusiveLevelAlarm::write_severity_low_sync(uint16_t value) const
{
  try_write_severity_low_sync(value).value();
}

void NonExclusiveLevelAlarm::write_severity_low_low_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::severity_low_low_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_severity_low_low_sync(uint16_t value) const noexcept
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

void NonExclusiveLevelAlarm::write_severity_low_low_sync(uint16_t value) const
{
  try_write_severity_low_low_sync(value).value();
}

void NonExclusiveLevelAlarm::write_high_high_deadband_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::high_high_deadband_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_high_high_deadband_sync(double value) const noexcept
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

void NonExclusiveLevelAlarm::write_high_high_deadband_sync(double value) const
{
  try_write_high_high_deadband_sync(value).value();
}

void NonExclusiveLevelAlarm::write_high_deadband_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::high_deadband_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_high_deadband_sync(double value) const noexcept
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

void NonExclusiveLevelAlarm::write_high_deadband_sync(double value) const
{
  try_write_high_deadband_sync(value).value();
}

void NonExclusiveLevelAlarm::write_low_deadband_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::low_deadband_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_low_deadband_sync(double value) const noexcept
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

void NonExclusiveLevelAlarm::write_low_deadband_sync(double value) const
{
  try_write_low_deadband_sync(value).value();
}

void NonExclusiveLevelAlarm::write_low_low_deadband_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::low_low_deadband_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_low_low_deadband_sync(double value) const noexcept
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

void NonExclusiveLevelAlarm::write_low_low_deadband_sync(double value) const
{
  try_write_low_low_deadband_sync(value).value();
}

void NonExclusiveLevelAlarm::write_input_node_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::input_node_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_input_node_sync(NodeId value) const noexcept
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

void NonExclusiveLevelAlarm::write_input_node_sync(NodeId value) const
{
  try_write_input_node_sync(value).value();
}

void NonExclusiveLevelAlarm::write_suppressed_or_shelved_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::suppressed_or_shelved_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_suppressed_or_shelved_sync(bool value) const noexcept
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

void NonExclusiveLevelAlarm::write_suppressed_or_shelved_sync(bool value) const
{
  try_write_suppressed_or_shelved_sync(value).value();
}

void NonExclusiveLevelAlarm::write_audible_enabled_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::audible_enabled_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_audible_enabled_sync(bool value) const noexcept
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

void NonExclusiveLevelAlarm::write_audible_enabled_sync(bool value) const
{
  try_write_audible_enabled_sync(value).value();
}

void NonExclusiveLevelAlarm::write_condition_class_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::condition_class_id_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_condition_class_id_sync(NodeId value) const noexcept
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

void NonExclusiveLevelAlarm::write_condition_class_id_sync(NodeId value) const
{
  try_write_condition_class_id_sync(value).value();
}

void NonExclusiveLevelAlarm::write_condition_class_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::condition_class_name_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_condition_class_name_sync(LocalizedText value) const noexcept
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

void NonExclusiveLevelAlarm::write_condition_class_name_sync(LocalizedText value) const
{
  try_write_condition_class_name_sync(value).value();
}

void NonExclusiveLevelAlarm::write_condition_sub_class_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::condition_sub_class_id_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_condition_sub_class_id_sync(NodeId value) const noexcept
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

void NonExclusiveLevelAlarm::write_condition_sub_class_id_sync(NodeId value) const
{
  try_write_condition_sub_class_id_sync(value).value();
}

void NonExclusiveLevelAlarm::write_condition_sub_class_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::condition_sub_class_name_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_condition_sub_class_name_sync(LocalizedText value) const noexcept
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

void NonExclusiveLevelAlarm::write_condition_sub_class_name_sync(LocalizedText value) const
{
  try_write_condition_sub_class_name_sync(value).value();
}

void NonExclusiveLevelAlarm::write_condition_name_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::condition_name_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_condition_name_sync(String value) const noexcept
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

void NonExclusiveLevelAlarm::write_condition_name_sync(String value) const
{
  try_write_condition_name_sync(value).value();
}

void NonExclusiveLevelAlarm::write_branch_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::branch_id_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_branch_id_sync(NodeId value) const noexcept
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

void NonExclusiveLevelAlarm::write_branch_id_sync(NodeId value) const
{
  try_write_branch_id_sync(value).value();
}

void NonExclusiveLevelAlarm::write_retain_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::retain_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_retain_sync(bool value) const noexcept
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

void NonExclusiveLevelAlarm::write_retain_sync(bool value) const
{
  try_write_retain_sync(value).value();
}

void NonExclusiveLevelAlarm::write_supports_filtered_retain_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::supports_filtered_retain_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_supports_filtered_retain_sync(bool value) const noexcept
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

void NonExclusiveLevelAlarm::write_supports_filtered_retain_sync(bool value) const
{
  try_write_supports_filtered_retain_sync(value).value();
}

void NonExclusiveLevelAlarm::write_client_user_id_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::client_user_id_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_client_user_id_sync(String value) const noexcept
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

void NonExclusiveLevelAlarm::write_client_user_id_sync(String value) const
{
  try_write_client_user_id_sync(value).value();
}

void NonExclusiveLevelAlarm::write_event_id_async(
  ByteString value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::event_id_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_event_id_sync(ByteString value) const noexcept
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

void NonExclusiveLevelAlarm::write_event_id_sync(ByteString value) const
{
  try_write_event_id_sync(value).value();
}

void NonExclusiveLevelAlarm::write_event_type_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::event_type_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_event_type_sync(NodeId value) const noexcept
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

void NonExclusiveLevelAlarm::write_event_type_sync(NodeId value) const
{
  try_write_event_type_sync(value).value();
}

void NonExclusiveLevelAlarm::write_source_node_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::source_node_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_source_node_sync(NodeId value) const noexcept
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

void NonExclusiveLevelAlarm::write_source_node_sync(NodeId value) const
{
  try_write_source_node_sync(value).value();
}

void NonExclusiveLevelAlarm::write_source_name_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::source_name_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_source_name_sync(String value) const noexcept
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

void NonExclusiveLevelAlarm::write_source_name_sync(String value) const
{
  try_write_source_name_sync(value).value();
}

void NonExclusiveLevelAlarm::write_message_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::message_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_message_sync(LocalizedText value) const noexcept
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

void NonExclusiveLevelAlarm::write_message_sync(LocalizedText value) const
{
  try_write_message_sync(value).value();
}

void NonExclusiveLevelAlarm::write_severity_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLevelAlarmTypeTraits::severity_browse_name(),
    "NonExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLevelAlarm::try_write_severity_sync(uint16_t value) const noexcept
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

void NonExclusiveLevelAlarm::write_severity_sync(uint16_t value) const
{
  try_write_severity_sync(value).value();
}

}  // namespace ua
