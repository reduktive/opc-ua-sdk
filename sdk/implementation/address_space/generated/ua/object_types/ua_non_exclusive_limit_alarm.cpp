// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_non_exclusive_limit_alarm.h"

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

struct NonExclusiveLimitAlarmTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::NonExclusiveLimitAlarmType};
  }

  static QualifiedName active_state_browse_name()
  {
    return QualifiedName{0, "ActiveState"};
  }

  static QualifiedName high_high_state_browse_name()
  {
    return QualifiedName{0, "HighHighState"};
  }

  static QualifiedName high_state_browse_name()
  {
    return QualifiedName{0, "HighState"};
  }

  static QualifiedName low_state_browse_name()
  {
    return QualifiedName{0, "LowState"};
  }

  static QualifiedName low_low_state_browse_name()
  {
    return QualifiedName{0, "LowLowState"};
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

NonExclusiveLimitAlarm::NonExclusiveLimitAlarm(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void NonExclusiveLimitAlarm::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    NonExclusiveLimitAlarmTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(NonExclusiveLimitAlarmResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(NonExclusiveLimitAlarmResult{
        NonExclusiveLimitAlarm{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

NonExclusiveLimitAlarmResult NonExclusiveLimitAlarm::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NonExclusiveLimitAlarmResult>(addressSpace.executor(),
      [&](std::function<void(NonExclusiveLimitAlarmResult)> complete)
      {
        NonExclusiveLimitAlarm::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NonExclusiveLimitAlarm NonExclusiveLimitAlarm::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void NonExclusiveLimitAlarm::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void NonExclusiveLimitAlarm::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // NonExclusiveLimitAlarmType has subtypes - subtype match.
  instance_utils::attach_subtype_async(addressSpace,
    existingInstance,
    NonExclusiveLimitAlarmTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(NonExclusiveLimitAlarmResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(NonExclusiveLimitAlarmResult{::ua::detail::address_space_gone("NonExclusiveLimitAlarm")});
        return;
      }
      complete(
        NonExclusiveLimitAlarm{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

NonExclusiveLimitAlarmResult NonExclusiveLimitAlarm::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NonExclusiveLimitAlarmResult>(addressSpace.executor(),
      [&](std::function<void(NonExclusiveLimitAlarmResult)> complete)
      {
        NonExclusiveLimitAlarm::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NonExclusiveLimitAlarm NonExclusiveLimitAlarm::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void NonExclusiveLimitAlarm::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void NonExclusiveLimitAlarm::find_property_async(
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
    "NonExclusiveLimitAlarm",
    std::move(complete));
}

// --- Property accessors ---

void NonExclusiveLimitAlarm::high_high_limit_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::high_high_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_high_high_limit_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::high_high_limit_property_sync() const
{
  return ::ua::detail::good_value(try_high_high_limit_property_sync());
}

void NonExclusiveLimitAlarm::high_limit_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::high_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_high_limit_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::high_limit_property_sync() const
{
  return ::ua::detail::good_value(try_high_limit_property_sync());
}

void NonExclusiveLimitAlarm::low_limit_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::low_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_low_limit_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::low_limit_property_sync() const
{
  return ::ua::detail::good_value(try_low_limit_property_sync());
}

void NonExclusiveLimitAlarm::low_low_limit_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::low_low_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_low_low_limit_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::low_low_limit_property_sync() const
{
  return ::ua::detail::good_value(try_low_low_limit_property_sync());
}

void NonExclusiveLimitAlarm::base_high_high_limit_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveLimitAlarmTypeTraits::base_high_high_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_base_high_high_limit_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::base_high_high_limit_property_sync() const
{
  return ::ua::detail::good_value(try_base_high_high_limit_property_sync());
}

void NonExclusiveLimitAlarm::base_high_limit_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::base_high_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_base_high_limit_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::base_high_limit_property_sync() const
{
  return ::ua::detail::good_value(try_base_high_limit_property_sync());
}

void NonExclusiveLimitAlarm::base_low_limit_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::base_low_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_base_low_limit_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::base_low_limit_property_sync() const
{
  return ::ua::detail::good_value(try_base_low_limit_property_sync());
}

void NonExclusiveLimitAlarm::base_low_low_limit_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveLimitAlarmTypeTraits::base_low_low_limit_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_base_low_low_limit_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::base_low_low_limit_property_sync() const
{
  return ::ua::detail::good_value(try_base_low_low_limit_property_sync());
}

void NonExclusiveLimitAlarm::severity_high_high_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveLimitAlarmTypeTraits::severity_high_high_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_severity_high_high_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::severity_high_high_property_sync() const
{
  return ::ua::detail::good_value(try_severity_high_high_property_sync());
}

void NonExclusiveLimitAlarm::severity_high_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::severity_high_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_severity_high_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::severity_high_property_sync() const
{
  return ::ua::detail::good_value(try_severity_high_property_sync());
}

void NonExclusiveLimitAlarm::severity_low_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::severity_low_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_severity_low_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::severity_low_property_sync() const
{
  return ::ua::detail::good_value(try_severity_low_property_sync());
}

void NonExclusiveLimitAlarm::severity_low_low_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::severity_low_low_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_severity_low_low_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::severity_low_low_property_sync() const
{
  return ::ua::detail::good_value(try_severity_low_low_property_sync());
}

void NonExclusiveLimitAlarm::high_high_deadband_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveLimitAlarmTypeTraits::high_high_deadband_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_high_high_deadband_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::high_high_deadband_property_sync() const
{
  return ::ua::detail::good_value(try_high_high_deadband_property_sync());
}

void NonExclusiveLimitAlarm::high_deadband_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::high_deadband_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_high_deadband_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::high_deadband_property_sync() const
{
  return ::ua::detail::good_value(try_high_deadband_property_sync());
}

void NonExclusiveLimitAlarm::low_deadband_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::low_deadband_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_low_deadband_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::low_deadband_property_sync() const
{
  return ::ua::detail::good_value(try_low_deadband_property_sync());
}

void NonExclusiveLimitAlarm::low_low_deadband_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::low_low_deadband_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_low_low_deadband_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::low_low_deadband_property_sync() const
{
  return ::ua::detail::good_value(try_low_low_deadband_property_sync());
}

void NonExclusiveLimitAlarm::input_node_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::input_node_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_input_node_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::input_node_property_sync() const
{
  return ::ua::detail::good_value(try_input_node_property_sync());
}

void NonExclusiveLimitAlarm::suppressed_or_shelved_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveLimitAlarmTypeTraits::suppressed_or_shelved_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_suppressed_or_shelved_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::suppressed_or_shelved_property_sync() const
{
  return ::ua::detail::good_value(try_suppressed_or_shelved_property_sync());
}

void NonExclusiveLimitAlarm::max_time_shelved_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::max_time_shelved_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_max_time_shelved_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::max_time_shelved_property_sync() const
{
  return ::ua::detail::good_value(try_max_time_shelved_property_sync());
}

void NonExclusiveLimitAlarm::audible_enabled_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::audible_enabled_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_audible_enabled_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::audible_enabled_property_sync() const
{
  return ::ua::detail::good_value(try_audible_enabled_property_sync());
}

void NonExclusiveLimitAlarm::on_delay_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::on_delay_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_on_delay_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::on_delay_property_sync() const
{
  return ::ua::detail::good_value(try_on_delay_property_sync());
}

void NonExclusiveLimitAlarm::off_delay_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::off_delay_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_off_delay_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::off_delay_property_sync() const
{
  return ::ua::detail::good_value(try_off_delay_property_sync());
}

void NonExclusiveLimitAlarm::re_alarm_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::re_alarm_time_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_re_alarm_time_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::re_alarm_time_property_sync() const
{
  return ::ua::detail::good_value(try_re_alarm_time_property_sync());
}

void NonExclusiveLimitAlarm::condition_class_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveLimitAlarmTypeTraits::condition_class_id_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_condition_class_id_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::condition_class_id_property_sync() const
{
  return ::ua::detail::good_value(try_condition_class_id_property_sync());
}

void NonExclusiveLimitAlarm::condition_class_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveLimitAlarmTypeTraits::condition_class_name_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_condition_class_name_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::condition_class_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_class_name_property_sync());
}

void NonExclusiveLimitAlarm::condition_sub_class_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveLimitAlarmTypeTraits::condition_sub_class_id_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_condition_sub_class_id_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::condition_sub_class_id_property_sync() const
{
  return ::ua::detail::good_value(try_condition_sub_class_id_property_sync());
}

void NonExclusiveLimitAlarm::condition_sub_class_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveLimitAlarmTypeTraits::condition_sub_class_name_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_condition_sub_class_name_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::condition_sub_class_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_sub_class_name_property_sync());
}

void NonExclusiveLimitAlarm::condition_name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::condition_name_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_condition_name_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::condition_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_name_property_sync());
}

void NonExclusiveLimitAlarm::branch_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::branch_id_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_branch_id_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::branch_id_property_sync() const
{
  return ::ua::detail::good_value(try_branch_id_property_sync());
}

void NonExclusiveLimitAlarm::retain_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::retain_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_retain_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::retain_property_sync() const
{
  return ::ua::detail::good_value(try_retain_property_sync());
}

void NonExclusiveLimitAlarm::supports_filtered_retain_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    NonExclusiveLimitAlarmTypeTraits::supports_filtered_retain_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_supports_filtered_retain_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::supports_filtered_retain_property_sync() const
{
  return ::ua::detail::good_value(try_supports_filtered_retain_property_sync());
}

void NonExclusiveLimitAlarm::client_user_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::client_user_id_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_client_user_id_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::client_user_id_property_sync() const
{
  return ::ua::detail::good_value(try_client_user_id_property_sync());
}

void NonExclusiveLimitAlarm::event_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::event_id_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_event_id_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::event_id_property_sync() const
{
  return ::ua::detail::good_value(try_event_id_property_sync());
}

void NonExclusiveLimitAlarm::event_type_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::event_type_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_event_type_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::event_type_property_sync() const
{
  return ::ua::detail::good_value(try_event_type_property_sync());
}

void NonExclusiveLimitAlarm::source_node_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::source_node_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_source_node_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::source_node_property_sync() const
{
  return ::ua::detail::good_value(try_source_node_property_sync());
}

void NonExclusiveLimitAlarm::source_name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::source_name_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_source_name_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::source_name_property_sync() const
{
  return ::ua::detail::good_value(try_source_name_property_sync());
}

void NonExclusiveLimitAlarm::time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::time_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_time_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::time_property_sync() const
{
  return ::ua::detail::good_value(try_time_property_sync());
}

void NonExclusiveLimitAlarm::receive_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::receive_time_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_receive_time_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::receive_time_property_sync() const
{
  return ::ua::detail::good_value(try_receive_time_property_sync());
}

void NonExclusiveLimitAlarm::local_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::local_time_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_local_time_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::local_time_property_sync() const
{
  return ::ua::detail::good_value(try_local_time_property_sync());
}

void NonExclusiveLimitAlarm::message_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::message_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_message_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::message_property_sync() const
{
  return ::ua::detail::good_value(try_message_property_sync());
}

void NonExclusiveLimitAlarm::severity_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(NonExclusiveLimitAlarmTypeTraits::severity_browse_name(), std::move(complete));
}

PropertyResult NonExclusiveLimitAlarm::try_severity_property_sync() const noexcept
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

Property NonExclusiveLimitAlarm::severity_property_sync() const
{
  return ::ua::detail::good_value(try_severity_property_sync());
}

// --- Typed value read shortcuts ---

void NonExclusiveLimitAlarm::read_high_high_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::high_high_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveLimitAlarm", "high_high_limit", "NonExclusiveLimitAlarm::read_high_high_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveLimitAlarm::try_read_high_high_limit_sync() const noexcept
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

double NonExclusiveLimitAlarm::read_high_high_limit_sync() const
{
  return ::ua::detail::good_value(try_read_high_high_limit_sync());
}

void NonExclusiveLimitAlarm::read_high_limit_async(std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::high_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveLimitAlarm", "high_limit", "NonExclusiveLimitAlarm::read_high_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveLimitAlarm::try_read_high_limit_sync() const noexcept
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

double NonExclusiveLimitAlarm::read_high_limit_sync() const
{
  return ::ua::detail::good_value(try_read_high_limit_sync());
}

void NonExclusiveLimitAlarm::read_low_limit_async(std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::low_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveLimitAlarm", "low_limit", "NonExclusiveLimitAlarm::read_low_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveLimitAlarm::try_read_low_limit_sync() const noexcept
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

double NonExclusiveLimitAlarm::read_low_limit_sync() const
{
  return ::ua::detail::good_value(try_read_low_limit_sync());
}

void NonExclusiveLimitAlarm::read_low_low_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::low_low_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveLimitAlarm", "low_low_limit", "NonExclusiveLimitAlarm::read_low_low_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveLimitAlarm::try_read_low_low_limit_sync() const noexcept
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

double NonExclusiveLimitAlarm::read_low_low_limit_sync() const
{
  return ::ua::detail::good_value(try_read_low_low_limit_sync());
}

void NonExclusiveLimitAlarm::read_base_high_high_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::base_high_high_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveLimitAlarm",
      "base_high_high_limit",
      "NonExclusiveLimitAlarm::read_base_high_high_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveLimitAlarm::try_read_base_high_high_limit_sync() const noexcept
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

double NonExclusiveLimitAlarm::read_base_high_high_limit_sync() const
{
  return ::ua::detail::good_value(try_read_base_high_high_limit_sync());
}

void NonExclusiveLimitAlarm::read_base_high_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::base_high_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveLimitAlarm", "base_high_limit", "NonExclusiveLimitAlarm::read_base_high_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveLimitAlarm::try_read_base_high_limit_sync() const noexcept
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

double NonExclusiveLimitAlarm::read_base_high_limit_sync() const
{
  return ::ua::detail::good_value(try_read_base_high_limit_sync());
}

void NonExclusiveLimitAlarm::read_base_low_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::base_low_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveLimitAlarm", "base_low_limit", "NonExclusiveLimitAlarm::read_base_low_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveLimitAlarm::try_read_base_low_limit_sync() const noexcept
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

double NonExclusiveLimitAlarm::read_base_low_limit_sync() const
{
  return ::ua::detail::good_value(try_read_base_low_limit_sync());
}

void NonExclusiveLimitAlarm::read_base_low_low_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::base_low_low_limit_browse_name(),
    &Variant::is_double,
    {"NonExclusiveLimitAlarm", "base_low_low_limit", "NonExclusiveLimitAlarm::read_base_low_low_limit_async"},
    std::move(complete));
}

DoubleResult NonExclusiveLimitAlarm::try_read_base_low_low_limit_sync() const noexcept
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

double NonExclusiveLimitAlarm::read_base_low_low_limit_sync() const
{
  return ::ua::detail::good_value(try_read_base_low_low_limit_sync());
}

void NonExclusiveLimitAlarm::read_severity_high_high_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::severity_high_high_browse_name(),
    &Variant::is_uint16,
    {"NonExclusiveLimitAlarm", "severity_high_high", "NonExclusiveLimitAlarm::read_severity_high_high_async"},
    std::move(complete));
}

UInt16Result NonExclusiveLimitAlarm::try_read_severity_high_high_sync() const noexcept
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

uint16_t NonExclusiveLimitAlarm::read_severity_high_high_sync() const
{
  return ::ua::detail::good_value(try_read_severity_high_high_sync());
}

void NonExclusiveLimitAlarm::read_severity_high_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::severity_high_browse_name(),
    &Variant::is_uint16,
    {"NonExclusiveLimitAlarm", "severity_high", "NonExclusiveLimitAlarm::read_severity_high_async"},
    std::move(complete));
}

UInt16Result NonExclusiveLimitAlarm::try_read_severity_high_sync() const noexcept
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

uint16_t NonExclusiveLimitAlarm::read_severity_high_sync() const
{
  return ::ua::detail::good_value(try_read_severity_high_sync());
}

void NonExclusiveLimitAlarm::read_severity_low_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::severity_low_browse_name(),
    &Variant::is_uint16,
    {"NonExclusiveLimitAlarm", "severity_low", "NonExclusiveLimitAlarm::read_severity_low_async"},
    std::move(complete));
}

UInt16Result NonExclusiveLimitAlarm::try_read_severity_low_sync() const noexcept
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

uint16_t NonExclusiveLimitAlarm::read_severity_low_sync() const
{
  return ::ua::detail::good_value(try_read_severity_low_sync());
}

void NonExclusiveLimitAlarm::read_severity_low_low_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::severity_low_low_browse_name(),
    &Variant::is_uint16,
    {"NonExclusiveLimitAlarm", "severity_low_low", "NonExclusiveLimitAlarm::read_severity_low_low_async"},
    std::move(complete));
}

UInt16Result NonExclusiveLimitAlarm::try_read_severity_low_low_sync() const noexcept
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

uint16_t NonExclusiveLimitAlarm::read_severity_low_low_sync() const
{
  return ::ua::detail::good_value(try_read_severity_low_low_sync());
}

void NonExclusiveLimitAlarm::read_high_high_deadband_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::high_high_deadband_browse_name(),
    &Variant::is_double,
    {"NonExclusiveLimitAlarm", "high_high_deadband", "NonExclusiveLimitAlarm::read_high_high_deadband_async"},
    std::move(complete));
}

DoubleResult NonExclusiveLimitAlarm::try_read_high_high_deadband_sync() const noexcept
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

double NonExclusiveLimitAlarm::read_high_high_deadband_sync() const
{
  return ::ua::detail::good_value(try_read_high_high_deadband_sync());
}

void NonExclusiveLimitAlarm::read_high_deadband_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::high_deadband_browse_name(),
    &Variant::is_double,
    {"NonExclusiveLimitAlarm", "high_deadband", "NonExclusiveLimitAlarm::read_high_deadband_async"},
    std::move(complete));
}

DoubleResult NonExclusiveLimitAlarm::try_read_high_deadband_sync() const noexcept
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

double NonExclusiveLimitAlarm::read_high_deadband_sync() const
{
  return ::ua::detail::good_value(try_read_high_deadband_sync());
}

void NonExclusiveLimitAlarm::read_low_deadband_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::low_deadband_browse_name(),
    &Variant::is_double,
    {"NonExclusiveLimitAlarm", "low_deadband", "NonExclusiveLimitAlarm::read_low_deadband_async"},
    std::move(complete));
}

DoubleResult NonExclusiveLimitAlarm::try_read_low_deadband_sync() const noexcept
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

double NonExclusiveLimitAlarm::read_low_deadband_sync() const
{
  return ::ua::detail::good_value(try_read_low_deadband_sync());
}

void NonExclusiveLimitAlarm::read_low_low_deadband_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::low_low_deadband_browse_name(),
    &Variant::is_double,
    {"NonExclusiveLimitAlarm", "low_low_deadband", "NonExclusiveLimitAlarm::read_low_low_deadband_async"},
    std::move(complete));
}

DoubleResult NonExclusiveLimitAlarm::try_read_low_low_deadband_sync() const noexcept
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

double NonExclusiveLimitAlarm::read_low_low_deadband_sync() const
{
  return ::ua::detail::good_value(try_read_low_low_deadband_sync());
}

void NonExclusiveLimitAlarm::read_input_node_async(std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::input_node_browse_name(),
    &Variant::is_node_id,
    {"NonExclusiveLimitAlarm", "input_node", "NonExclusiveLimitAlarm::read_input_node_async"},
    std::move(complete));
}

NodeIdResult NonExclusiveLimitAlarm::try_read_input_node_sync() const noexcept
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

NodeId NonExclusiveLimitAlarm::read_input_node_sync() const
{
  return ::ua::detail::good_value(try_read_input_node_sync());
}

void NonExclusiveLimitAlarm::read_suppressed_or_shelved_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::suppressed_or_shelved_browse_name(),
    &Variant::is_boolean,
    {"NonExclusiveLimitAlarm",
      "suppressed_or_shelved",
      "NonExclusiveLimitAlarm::read_suppressed_or_shelved_async"},
    std::move(complete));
}

BoolResult NonExclusiveLimitAlarm::try_read_suppressed_or_shelved_sync() const noexcept
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

bool NonExclusiveLimitAlarm::read_suppressed_or_shelved_sync() const
{
  return ::ua::detail::good_value(try_read_suppressed_or_shelved_sync());
}

void NonExclusiveLimitAlarm::read_audible_enabled_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::audible_enabled_browse_name(),
    &Variant::is_boolean,
    {"NonExclusiveLimitAlarm", "audible_enabled", "NonExclusiveLimitAlarm::read_audible_enabled_async"},
    std::move(complete));
}

BoolResult NonExclusiveLimitAlarm::try_read_audible_enabled_sync() const noexcept
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

bool NonExclusiveLimitAlarm::read_audible_enabled_sync() const
{
  return ::ua::detail::good_value(try_read_audible_enabled_sync());
}

void NonExclusiveLimitAlarm::read_condition_class_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::condition_class_id_browse_name(),
    &Variant::is_node_id,
    {"NonExclusiveLimitAlarm", "condition_class_id", "NonExclusiveLimitAlarm::read_condition_class_id_async"},
    std::move(complete));
}

NodeIdResult NonExclusiveLimitAlarm::try_read_condition_class_id_sync() const noexcept
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

NodeId NonExclusiveLimitAlarm::read_condition_class_id_sync() const
{
  return ::ua::detail::good_value(try_read_condition_class_id_sync());
}

void NonExclusiveLimitAlarm::read_condition_class_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::condition_class_name_browse_name(),
    &Variant::is_localized_text,
    {"NonExclusiveLimitAlarm",
      "condition_class_name",
      "NonExclusiveLimitAlarm::read_condition_class_name_async"},
    std::move(complete));
}

LocalizedTextResult NonExclusiveLimitAlarm::try_read_condition_class_name_sync() const noexcept
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

LocalizedText NonExclusiveLimitAlarm::read_condition_class_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_class_name_sync());
}

void NonExclusiveLimitAlarm::read_condition_sub_class_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::condition_sub_class_id_browse_name(),
    &Variant::is_node_id,
    {"NonExclusiveLimitAlarm",
      "condition_sub_class_id",
      "NonExclusiveLimitAlarm::read_condition_sub_class_id_async"},
    std::move(complete));
}

NodeIdResult NonExclusiveLimitAlarm::try_read_condition_sub_class_id_sync() const noexcept
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

NodeId NonExclusiveLimitAlarm::read_condition_sub_class_id_sync() const
{
  return ::ua::detail::good_value(try_read_condition_sub_class_id_sync());
}

void NonExclusiveLimitAlarm::read_condition_sub_class_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::condition_sub_class_name_browse_name(),
    &Variant::is_localized_text,
    {"NonExclusiveLimitAlarm",
      "condition_sub_class_name",
      "NonExclusiveLimitAlarm::read_condition_sub_class_name_async"},
    std::move(complete));
}

LocalizedTextResult NonExclusiveLimitAlarm::try_read_condition_sub_class_name_sync() const noexcept
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

LocalizedText NonExclusiveLimitAlarm::read_condition_sub_class_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_sub_class_name_sync());
}

void NonExclusiveLimitAlarm::read_condition_name_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::condition_name_browse_name(),
    &Variant::is_string,
    {"NonExclusiveLimitAlarm", "condition_name", "NonExclusiveLimitAlarm::read_condition_name_async"},
    std::move(complete));
}

StringResult NonExclusiveLimitAlarm::try_read_condition_name_sync() const noexcept
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

String NonExclusiveLimitAlarm::read_condition_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_name_sync());
}

void NonExclusiveLimitAlarm::read_branch_id_async(std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::branch_id_browse_name(),
    &Variant::is_node_id,
    {"NonExclusiveLimitAlarm", "branch_id", "NonExclusiveLimitAlarm::read_branch_id_async"},
    std::move(complete));
}

NodeIdResult NonExclusiveLimitAlarm::try_read_branch_id_sync() const noexcept
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

NodeId NonExclusiveLimitAlarm::read_branch_id_sync() const
{
  return ::ua::detail::good_value(try_read_branch_id_sync());
}

void NonExclusiveLimitAlarm::read_retain_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::retain_browse_name(),
    &Variant::is_boolean,
    {"NonExclusiveLimitAlarm", "retain", "NonExclusiveLimitAlarm::read_retain_async"},
    std::move(complete));
}

BoolResult NonExclusiveLimitAlarm::try_read_retain_sync() const noexcept
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

bool NonExclusiveLimitAlarm::read_retain_sync() const
{
  return ::ua::detail::good_value(try_read_retain_sync());
}

void NonExclusiveLimitAlarm::read_supports_filtered_retain_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::supports_filtered_retain_browse_name(),
    &Variant::is_boolean,
    {"NonExclusiveLimitAlarm",
      "supports_filtered_retain",
      "NonExclusiveLimitAlarm::read_supports_filtered_retain_async"},
    std::move(complete));
}

BoolResult NonExclusiveLimitAlarm::try_read_supports_filtered_retain_sync() const noexcept
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

bool NonExclusiveLimitAlarm::read_supports_filtered_retain_sync() const
{
  return ::ua::detail::good_value(try_read_supports_filtered_retain_sync());
}

void NonExclusiveLimitAlarm::read_client_user_id_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::client_user_id_browse_name(),
    &Variant::is_string,
    {"NonExclusiveLimitAlarm", "client_user_id", "NonExclusiveLimitAlarm::read_client_user_id_async"},
    std::move(complete));
}

StringResult NonExclusiveLimitAlarm::try_read_client_user_id_sync() const noexcept
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

String NonExclusiveLimitAlarm::read_client_user_id_sync() const
{
  return ::ua::detail::good_value(try_read_client_user_id_sync());
}

void NonExclusiveLimitAlarm::read_event_id_async(
  std::function<void(ByteStringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(ByteStringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<ByteString>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::event_id_browse_name(),
    &Variant::is_byte_string,
    {"NonExclusiveLimitAlarm", "event_id", "NonExclusiveLimitAlarm::read_event_id_async"},
    std::move(complete));
}

ByteStringResult NonExclusiveLimitAlarm::try_read_event_id_sync() const noexcept
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

ByteString NonExclusiveLimitAlarm::read_event_id_sync() const
{
  return ::ua::detail::good_value(try_read_event_id_sync());
}

void NonExclusiveLimitAlarm::read_event_type_async(std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::event_type_browse_name(),
    &Variant::is_node_id,
    {"NonExclusiveLimitAlarm", "event_type", "NonExclusiveLimitAlarm::read_event_type_async"},
    std::move(complete));
}

NodeIdResult NonExclusiveLimitAlarm::try_read_event_type_sync() const noexcept
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

NodeId NonExclusiveLimitAlarm::read_event_type_sync() const
{
  return ::ua::detail::good_value(try_read_event_type_sync());
}

void NonExclusiveLimitAlarm::read_source_node_async(std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::source_node_browse_name(),
    &Variant::is_node_id,
    {"NonExclusiveLimitAlarm", "source_node", "NonExclusiveLimitAlarm::read_source_node_async"},
    std::move(complete));
}

NodeIdResult NonExclusiveLimitAlarm::try_read_source_node_sync() const noexcept
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

NodeId NonExclusiveLimitAlarm::read_source_node_sync() const
{
  return ::ua::detail::good_value(try_read_source_node_sync());
}

void NonExclusiveLimitAlarm::read_source_name_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::source_name_browse_name(),
    &Variant::is_string,
    {"NonExclusiveLimitAlarm", "source_name", "NonExclusiveLimitAlarm::read_source_name_async"},
    std::move(complete));
}

StringResult NonExclusiveLimitAlarm::try_read_source_name_sync() const noexcept
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

String NonExclusiveLimitAlarm::read_source_name_sync() const
{
  return ::ua::detail::good_value(try_read_source_name_sync());
}

void NonExclusiveLimitAlarm::read_message_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::message_browse_name(),
    &Variant::is_localized_text,
    {"NonExclusiveLimitAlarm", "message", "NonExclusiveLimitAlarm::read_message_async"},
    std::move(complete));
}

LocalizedTextResult NonExclusiveLimitAlarm::try_read_message_sync() const noexcept
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

LocalizedText NonExclusiveLimitAlarm::read_message_sync() const
{
  return ::ua::detail::good_value(try_read_message_sync());
}

void NonExclusiveLimitAlarm::read_severity_async(std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::severity_browse_name(),
    &Variant::is_uint16,
    {"NonExclusiveLimitAlarm", "severity", "NonExclusiveLimitAlarm::read_severity_async"},
    std::move(complete));
}

UInt16Result NonExclusiveLimitAlarm::try_read_severity_sync() const noexcept
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

uint16_t NonExclusiveLimitAlarm::read_severity_sync() const
{
  return ::ua::detail::good_value(try_read_severity_sync());
}

// --- Typed value write shortcuts ---

void NonExclusiveLimitAlarm::write_high_high_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::high_high_limit_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_high_high_limit_sync(double value) const noexcept
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

void NonExclusiveLimitAlarm::write_high_high_limit_sync(double value) const
{
  try_write_high_high_limit_sync(value).value();
}

void NonExclusiveLimitAlarm::write_high_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::high_limit_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_high_limit_sync(double value) const noexcept
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

void NonExclusiveLimitAlarm::write_high_limit_sync(double value) const
{
  try_write_high_limit_sync(value).value();
}

void NonExclusiveLimitAlarm::write_low_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::low_limit_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_low_limit_sync(double value) const noexcept
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

void NonExclusiveLimitAlarm::write_low_limit_sync(double value) const
{
  try_write_low_limit_sync(value).value();
}

void NonExclusiveLimitAlarm::write_low_low_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::low_low_limit_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_low_low_limit_sync(double value) const noexcept
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

void NonExclusiveLimitAlarm::write_low_low_limit_sync(double value) const
{
  try_write_low_low_limit_sync(value).value();
}

void NonExclusiveLimitAlarm::write_base_high_high_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::base_high_high_limit_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_base_high_high_limit_sync(double value) const noexcept
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

void NonExclusiveLimitAlarm::write_base_high_high_limit_sync(double value) const
{
  try_write_base_high_high_limit_sync(value).value();
}

void NonExclusiveLimitAlarm::write_base_high_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::base_high_limit_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_base_high_limit_sync(double value) const noexcept
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

void NonExclusiveLimitAlarm::write_base_high_limit_sync(double value) const
{
  try_write_base_high_limit_sync(value).value();
}

void NonExclusiveLimitAlarm::write_base_low_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::base_low_limit_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_base_low_limit_sync(double value) const noexcept
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

void NonExclusiveLimitAlarm::write_base_low_limit_sync(double value) const
{
  try_write_base_low_limit_sync(value).value();
}

void NonExclusiveLimitAlarm::write_base_low_low_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::base_low_low_limit_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_base_low_low_limit_sync(double value) const noexcept
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

void NonExclusiveLimitAlarm::write_base_low_low_limit_sync(double value) const
{
  try_write_base_low_low_limit_sync(value).value();
}

void NonExclusiveLimitAlarm::write_severity_high_high_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::severity_high_high_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_severity_high_high_sync(uint16_t value) const noexcept
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

void NonExclusiveLimitAlarm::write_severity_high_high_sync(uint16_t value) const
{
  try_write_severity_high_high_sync(value).value();
}

void NonExclusiveLimitAlarm::write_severity_high_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::severity_high_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_severity_high_sync(uint16_t value) const noexcept
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

void NonExclusiveLimitAlarm::write_severity_high_sync(uint16_t value) const
{
  try_write_severity_high_sync(value).value();
}

void NonExclusiveLimitAlarm::write_severity_low_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::severity_low_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_severity_low_sync(uint16_t value) const noexcept
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

void NonExclusiveLimitAlarm::write_severity_low_sync(uint16_t value) const
{
  try_write_severity_low_sync(value).value();
}

void NonExclusiveLimitAlarm::write_severity_low_low_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::severity_low_low_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_severity_low_low_sync(uint16_t value) const noexcept
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

void NonExclusiveLimitAlarm::write_severity_low_low_sync(uint16_t value) const
{
  try_write_severity_low_low_sync(value).value();
}

void NonExclusiveLimitAlarm::write_high_high_deadband_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::high_high_deadband_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_high_high_deadband_sync(double value) const noexcept
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

void NonExclusiveLimitAlarm::write_high_high_deadband_sync(double value) const
{
  try_write_high_high_deadband_sync(value).value();
}

void NonExclusiveLimitAlarm::write_high_deadband_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::high_deadband_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_high_deadband_sync(double value) const noexcept
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

void NonExclusiveLimitAlarm::write_high_deadband_sync(double value) const
{
  try_write_high_deadband_sync(value).value();
}

void NonExclusiveLimitAlarm::write_low_deadband_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::low_deadband_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_low_deadband_sync(double value) const noexcept
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

void NonExclusiveLimitAlarm::write_low_deadband_sync(double value) const
{
  try_write_low_deadband_sync(value).value();
}

void NonExclusiveLimitAlarm::write_low_low_deadband_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::low_low_deadband_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_low_low_deadband_sync(double value) const noexcept
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

void NonExclusiveLimitAlarm::write_low_low_deadband_sync(double value) const
{
  try_write_low_low_deadband_sync(value).value();
}

void NonExclusiveLimitAlarm::write_input_node_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::input_node_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_input_node_sync(NodeId value) const noexcept
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

void NonExclusiveLimitAlarm::write_input_node_sync(NodeId value) const
{
  try_write_input_node_sync(value).value();
}

void NonExclusiveLimitAlarm::write_suppressed_or_shelved_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::suppressed_or_shelved_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_suppressed_or_shelved_sync(bool value) const noexcept
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

void NonExclusiveLimitAlarm::write_suppressed_or_shelved_sync(bool value) const
{
  try_write_suppressed_or_shelved_sync(value).value();
}

void NonExclusiveLimitAlarm::write_audible_enabled_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::audible_enabled_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_audible_enabled_sync(bool value) const noexcept
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

void NonExclusiveLimitAlarm::write_audible_enabled_sync(bool value) const
{
  try_write_audible_enabled_sync(value).value();
}

void NonExclusiveLimitAlarm::write_condition_class_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::condition_class_id_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_condition_class_id_sync(NodeId value) const noexcept
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

void NonExclusiveLimitAlarm::write_condition_class_id_sync(NodeId value) const
{
  try_write_condition_class_id_sync(value).value();
}

void NonExclusiveLimitAlarm::write_condition_class_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::condition_class_name_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_condition_class_name_sync(LocalizedText value) const noexcept
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

void NonExclusiveLimitAlarm::write_condition_class_name_sync(LocalizedText value) const
{
  try_write_condition_class_name_sync(value).value();
}

void NonExclusiveLimitAlarm::write_condition_sub_class_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::condition_sub_class_id_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_condition_sub_class_id_sync(NodeId value) const noexcept
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

void NonExclusiveLimitAlarm::write_condition_sub_class_id_sync(NodeId value) const
{
  try_write_condition_sub_class_id_sync(value).value();
}

void NonExclusiveLimitAlarm::write_condition_sub_class_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::condition_sub_class_name_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_condition_sub_class_name_sync(LocalizedText value) const noexcept
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

void NonExclusiveLimitAlarm::write_condition_sub_class_name_sync(LocalizedText value) const
{
  try_write_condition_sub_class_name_sync(value).value();
}

void NonExclusiveLimitAlarm::write_condition_name_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::condition_name_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_condition_name_sync(String value) const noexcept
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

void NonExclusiveLimitAlarm::write_condition_name_sync(String value) const
{
  try_write_condition_name_sync(value).value();
}

void NonExclusiveLimitAlarm::write_branch_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::branch_id_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_branch_id_sync(NodeId value) const noexcept
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

void NonExclusiveLimitAlarm::write_branch_id_sync(NodeId value) const
{
  try_write_branch_id_sync(value).value();
}

void NonExclusiveLimitAlarm::write_retain_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::retain_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_retain_sync(bool value) const noexcept
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

void NonExclusiveLimitAlarm::write_retain_sync(bool value) const
{
  try_write_retain_sync(value).value();
}

void NonExclusiveLimitAlarm::write_supports_filtered_retain_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::supports_filtered_retain_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_supports_filtered_retain_sync(bool value) const noexcept
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

void NonExclusiveLimitAlarm::write_supports_filtered_retain_sync(bool value) const
{
  try_write_supports_filtered_retain_sync(value).value();
}

void NonExclusiveLimitAlarm::write_client_user_id_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::client_user_id_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_client_user_id_sync(String value) const noexcept
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

void NonExclusiveLimitAlarm::write_client_user_id_sync(String value) const
{
  try_write_client_user_id_sync(value).value();
}

void NonExclusiveLimitAlarm::write_event_id_async(
  ByteString value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::event_id_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_event_id_sync(ByteString value) const noexcept
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

void NonExclusiveLimitAlarm::write_event_id_sync(ByteString value) const
{
  try_write_event_id_sync(value).value();
}

void NonExclusiveLimitAlarm::write_event_type_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::event_type_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_event_type_sync(NodeId value) const noexcept
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

void NonExclusiveLimitAlarm::write_event_type_sync(NodeId value) const
{
  try_write_event_type_sync(value).value();
}

void NonExclusiveLimitAlarm::write_source_node_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::source_node_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_source_node_sync(NodeId value) const noexcept
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

void NonExclusiveLimitAlarm::write_source_node_sync(NodeId value) const
{
  try_write_source_node_sync(value).value();
}

void NonExclusiveLimitAlarm::write_source_name_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::source_name_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_source_name_sync(String value) const noexcept
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

void NonExclusiveLimitAlarm::write_source_name_sync(String value) const
{
  try_write_source_name_sync(value).value();
}

void NonExclusiveLimitAlarm::write_message_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::message_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_message_sync(LocalizedText value) const noexcept
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

void NonExclusiveLimitAlarm::write_message_sync(LocalizedText value) const
{
  try_write_message_sync(value).value();
}

void NonExclusiveLimitAlarm::write_severity_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    NonExclusiveLimitAlarmTypeTraits::severity_browse_name(),
    "NonExclusiveLimitAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult NonExclusiveLimitAlarm::try_write_severity_sync(uint16_t value) const noexcept
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

void NonExclusiveLimitAlarm::write_severity_sync(uint16_t value) const
{
  try_write_severity_sync(value).value();
}

// --- Child-object accessors ---

void NonExclusiveLimitAlarm::active_state_async(
  std::function<void(TwoStateVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TwoStateVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<TwoStateVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    NonExclusiveLimitAlarmTypeTraits::active_state_browse_name(),
    "NonExclusiveLimitAlarm",
    std::move(complete));
}

TwoStateVariableResult NonExclusiveLimitAlarm::try_active_state_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TwoStateVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TwoStateVariableResult)> complete) { active_state_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TwoStateVariable NonExclusiveLimitAlarm::active_state_sync() const
{
  return ::ua::detail::good_value(try_active_state_sync());
}

void NonExclusiveLimitAlarm::high_high_state_async(
  std::function<void(TwoStateVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TwoStateVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<TwoStateVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    NonExclusiveLimitAlarmTypeTraits::high_high_state_browse_name(),
    "NonExclusiveLimitAlarm",
    std::move(complete));
}

TwoStateVariableResult NonExclusiveLimitAlarm::try_high_high_state_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TwoStateVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TwoStateVariableResult)> complete)
      { high_high_state_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TwoStateVariable NonExclusiveLimitAlarm::high_high_state_sync() const
{
  return ::ua::detail::good_value(try_high_high_state_sync());
}

void NonExclusiveLimitAlarm::high_state_async(
  std::function<void(TwoStateVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TwoStateVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<TwoStateVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    NonExclusiveLimitAlarmTypeTraits::high_state_browse_name(),
    "NonExclusiveLimitAlarm",
    std::move(complete));
}

TwoStateVariableResult NonExclusiveLimitAlarm::try_high_state_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TwoStateVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TwoStateVariableResult)> complete) { high_state_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TwoStateVariable NonExclusiveLimitAlarm::high_state_sync() const
{
  return ::ua::detail::good_value(try_high_state_sync());
}

void NonExclusiveLimitAlarm::low_state_async(
  std::function<void(TwoStateVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TwoStateVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<TwoStateVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    NonExclusiveLimitAlarmTypeTraits::low_state_browse_name(),
    "NonExclusiveLimitAlarm",
    std::move(complete));
}

TwoStateVariableResult NonExclusiveLimitAlarm::try_low_state_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TwoStateVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TwoStateVariableResult)> complete) { low_state_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TwoStateVariable NonExclusiveLimitAlarm::low_state_sync() const
{
  return ::ua::detail::good_value(try_low_state_sync());
}

void NonExclusiveLimitAlarm::low_low_state_async(
  std::function<void(TwoStateVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TwoStateVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<TwoStateVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    NonExclusiveLimitAlarmTypeTraits::low_low_state_browse_name(),
    "NonExclusiveLimitAlarm",
    std::move(complete));
}

TwoStateVariableResult NonExclusiveLimitAlarm::try_low_low_state_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TwoStateVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TwoStateVariableResult)> complete)
      { low_low_state_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TwoStateVariable NonExclusiveLimitAlarm::low_low_state_sync() const
{
  return ::ua::detail::good_value(try_low_low_state_sync());
}

}  // namespace ua
