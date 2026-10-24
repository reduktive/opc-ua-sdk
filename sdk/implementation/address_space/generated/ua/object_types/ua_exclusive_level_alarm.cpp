// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_exclusive_level_alarm.h"

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

struct ExclusiveLevelAlarmTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::ExclusiveLevelAlarmType};
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

ExclusiveLevelAlarm::ExclusiveLevelAlarm(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void ExclusiveLevelAlarm::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    ExclusiveLevelAlarmTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(ExclusiveLevelAlarmResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(ExclusiveLevelAlarmResult{
        ExclusiveLevelAlarm{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

ExclusiveLevelAlarmResult ExclusiveLevelAlarm::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ExclusiveLevelAlarmResult>(addressSpace.executor(),
      [&](std::function<void(ExclusiveLevelAlarmResult)> complete)
      {
        ExclusiveLevelAlarm::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ExclusiveLevelAlarm ExclusiveLevelAlarm::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void ExclusiveLevelAlarm::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void ExclusiveLevelAlarm::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // ExclusiveLevelAlarmType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    ExclusiveLevelAlarmTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(ExclusiveLevelAlarmResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(ExclusiveLevelAlarmResult{::ua::detail::address_space_gone("ExclusiveLevelAlarm")});
        return;
      }
      complete(
        ExclusiveLevelAlarm{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

ExclusiveLevelAlarmResult ExclusiveLevelAlarm::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ExclusiveLevelAlarmResult>(addressSpace.executor(),
      [&](std::function<void(ExclusiveLevelAlarmResult)> complete)
      {
        ExclusiveLevelAlarm::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ExclusiveLevelAlarm ExclusiveLevelAlarm::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void ExclusiveLevelAlarm::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void ExclusiveLevelAlarm::find_property_async(
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
    "ExclusiveLevelAlarm",
    std::move(complete));
}

// --- Property accessors ---

void ExclusiveLevelAlarm::high_high_limit_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::high_high_limit_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_high_high_limit_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::high_high_limit_property_sync() const
{
  return ::ua::detail::good_value(try_high_high_limit_property_sync());
}

void ExclusiveLevelAlarm::high_limit_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::high_limit_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_high_limit_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::high_limit_property_sync() const
{
  return ::ua::detail::good_value(try_high_limit_property_sync());
}

void ExclusiveLevelAlarm::low_limit_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::low_limit_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_low_limit_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::low_limit_property_sync() const
{
  return ::ua::detail::good_value(try_low_limit_property_sync());
}

void ExclusiveLevelAlarm::low_low_limit_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::low_low_limit_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_low_low_limit_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::low_low_limit_property_sync() const
{
  return ::ua::detail::good_value(try_low_low_limit_property_sync());
}

void ExclusiveLevelAlarm::base_high_high_limit_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::base_high_high_limit_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_base_high_high_limit_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::base_high_high_limit_property_sync() const
{
  return ::ua::detail::good_value(try_base_high_high_limit_property_sync());
}

void ExclusiveLevelAlarm::base_high_limit_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::base_high_limit_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_base_high_limit_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::base_high_limit_property_sync() const
{
  return ::ua::detail::good_value(try_base_high_limit_property_sync());
}

void ExclusiveLevelAlarm::base_low_limit_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::base_low_limit_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_base_low_limit_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::base_low_limit_property_sync() const
{
  return ::ua::detail::good_value(try_base_low_limit_property_sync());
}

void ExclusiveLevelAlarm::base_low_low_limit_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::base_low_low_limit_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_base_low_low_limit_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::base_low_low_limit_property_sync() const
{
  return ::ua::detail::good_value(try_base_low_low_limit_property_sync());
}

void ExclusiveLevelAlarm::severity_high_high_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::severity_high_high_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_severity_high_high_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::severity_high_high_property_sync() const
{
  return ::ua::detail::good_value(try_severity_high_high_property_sync());
}

void ExclusiveLevelAlarm::severity_high_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::severity_high_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_severity_high_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::severity_high_property_sync() const
{
  return ::ua::detail::good_value(try_severity_high_property_sync());
}

void ExclusiveLevelAlarm::severity_low_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::severity_low_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_severity_low_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::severity_low_property_sync() const
{
  return ::ua::detail::good_value(try_severity_low_property_sync());
}

void ExclusiveLevelAlarm::severity_low_low_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::severity_low_low_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_severity_low_low_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::severity_low_low_property_sync() const
{
  return ::ua::detail::good_value(try_severity_low_low_property_sync());
}

void ExclusiveLevelAlarm::high_high_deadband_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::high_high_deadband_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_high_high_deadband_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::high_high_deadband_property_sync() const
{
  return ::ua::detail::good_value(try_high_high_deadband_property_sync());
}

void ExclusiveLevelAlarm::high_deadband_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::high_deadband_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_high_deadband_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::high_deadband_property_sync() const
{
  return ::ua::detail::good_value(try_high_deadband_property_sync());
}

void ExclusiveLevelAlarm::low_deadband_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::low_deadband_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_low_deadband_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::low_deadband_property_sync() const
{
  return ::ua::detail::good_value(try_low_deadband_property_sync());
}

void ExclusiveLevelAlarm::low_low_deadband_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::low_low_deadband_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_low_low_deadband_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::low_low_deadband_property_sync() const
{
  return ::ua::detail::good_value(try_low_low_deadband_property_sync());
}

void ExclusiveLevelAlarm::input_node_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::input_node_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_input_node_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::input_node_property_sync() const
{
  return ::ua::detail::good_value(try_input_node_property_sync());
}

void ExclusiveLevelAlarm::suppressed_or_shelved_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ExclusiveLevelAlarmTypeTraits::suppressed_or_shelved_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_suppressed_or_shelved_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::suppressed_or_shelved_property_sync() const
{
  return ::ua::detail::good_value(try_suppressed_or_shelved_property_sync());
}

void ExclusiveLevelAlarm::max_time_shelved_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::max_time_shelved_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_max_time_shelved_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::max_time_shelved_property_sync() const
{
  return ::ua::detail::good_value(try_max_time_shelved_property_sync());
}

void ExclusiveLevelAlarm::audible_enabled_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::audible_enabled_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_audible_enabled_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::audible_enabled_property_sync() const
{
  return ::ua::detail::good_value(try_audible_enabled_property_sync());
}

void ExclusiveLevelAlarm::on_delay_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::on_delay_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_on_delay_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::on_delay_property_sync() const
{
  return ::ua::detail::good_value(try_on_delay_property_sync());
}

void ExclusiveLevelAlarm::off_delay_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::off_delay_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_off_delay_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::off_delay_property_sync() const
{
  return ::ua::detail::good_value(try_off_delay_property_sync());
}

void ExclusiveLevelAlarm::re_alarm_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::re_alarm_time_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_re_alarm_time_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::re_alarm_time_property_sync() const
{
  return ::ua::detail::good_value(try_re_alarm_time_property_sync());
}

void ExclusiveLevelAlarm::condition_class_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::condition_class_id_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_condition_class_id_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::condition_class_id_property_sync() const
{
  return ::ua::detail::good_value(try_condition_class_id_property_sync());
}

void ExclusiveLevelAlarm::condition_class_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::condition_class_name_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_condition_class_name_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::condition_class_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_class_name_property_sync());
}

void ExclusiveLevelAlarm::condition_sub_class_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ExclusiveLevelAlarmTypeTraits::condition_sub_class_id_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_condition_sub_class_id_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::condition_sub_class_id_property_sync() const
{
  return ::ua::detail::good_value(try_condition_sub_class_id_property_sync());
}

void ExclusiveLevelAlarm::condition_sub_class_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ExclusiveLevelAlarmTypeTraits::condition_sub_class_name_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_condition_sub_class_name_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::condition_sub_class_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_sub_class_name_property_sync());
}

void ExclusiveLevelAlarm::condition_name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::condition_name_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_condition_name_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::condition_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_name_property_sync());
}

void ExclusiveLevelAlarm::branch_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::branch_id_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_branch_id_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::branch_id_property_sync() const
{
  return ::ua::detail::good_value(try_branch_id_property_sync());
}

void ExclusiveLevelAlarm::retain_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::retain_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_retain_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::retain_property_sync() const
{
  return ::ua::detail::good_value(try_retain_property_sync());
}

void ExclusiveLevelAlarm::supports_filtered_retain_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ExclusiveLevelAlarmTypeTraits::supports_filtered_retain_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_supports_filtered_retain_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::supports_filtered_retain_property_sync() const
{
  return ::ua::detail::good_value(try_supports_filtered_retain_property_sync());
}

void ExclusiveLevelAlarm::client_user_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::client_user_id_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_client_user_id_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::client_user_id_property_sync() const
{
  return ::ua::detail::good_value(try_client_user_id_property_sync());
}

void ExclusiveLevelAlarm::event_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::event_id_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_event_id_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::event_id_property_sync() const
{
  return ::ua::detail::good_value(try_event_id_property_sync());
}

void ExclusiveLevelAlarm::event_type_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::event_type_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_event_type_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::event_type_property_sync() const
{
  return ::ua::detail::good_value(try_event_type_property_sync());
}

void ExclusiveLevelAlarm::source_node_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::source_node_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_source_node_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::source_node_property_sync() const
{
  return ::ua::detail::good_value(try_source_node_property_sync());
}

void ExclusiveLevelAlarm::source_name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::source_name_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_source_name_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::source_name_property_sync() const
{
  return ::ua::detail::good_value(try_source_name_property_sync());
}

void ExclusiveLevelAlarm::time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::time_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_time_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::time_property_sync() const
{
  return ::ua::detail::good_value(try_time_property_sync());
}

void ExclusiveLevelAlarm::receive_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::receive_time_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_receive_time_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::receive_time_property_sync() const
{
  return ::ua::detail::good_value(try_receive_time_property_sync());
}

void ExclusiveLevelAlarm::local_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::local_time_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_local_time_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::local_time_property_sync() const
{
  return ::ua::detail::good_value(try_local_time_property_sync());
}

void ExclusiveLevelAlarm::message_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::message_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_message_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::message_property_sync() const
{
  return ::ua::detail::good_value(try_message_property_sync());
}

void ExclusiveLevelAlarm::severity_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ExclusiveLevelAlarmTypeTraits::severity_browse_name(), std::move(complete));
}

PropertyResult ExclusiveLevelAlarm::try_severity_property_sync() const noexcept
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

Property ExclusiveLevelAlarm::severity_property_sync() const
{
  return ::ua::detail::good_value(try_severity_property_sync());
}

// --- Typed value read shortcuts ---

void ExclusiveLevelAlarm::read_high_high_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::high_high_limit_browse_name(),
    &Variant::is_double,
    {"ExclusiveLevelAlarm", "high_high_limit", "ExclusiveLevelAlarm::read_high_high_limit_async"},
    std::move(complete));
}

DoubleResult ExclusiveLevelAlarm::try_read_high_high_limit_sync() const noexcept
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

double ExclusiveLevelAlarm::read_high_high_limit_sync() const
{
  return ::ua::detail::good_value(try_read_high_high_limit_sync());
}

void ExclusiveLevelAlarm::read_high_limit_async(std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::high_limit_browse_name(),
    &Variant::is_double,
    {"ExclusiveLevelAlarm", "high_limit", "ExclusiveLevelAlarm::read_high_limit_async"},
    std::move(complete));
}

DoubleResult ExclusiveLevelAlarm::try_read_high_limit_sync() const noexcept
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

double ExclusiveLevelAlarm::read_high_limit_sync() const
{
  return ::ua::detail::good_value(try_read_high_limit_sync());
}

void ExclusiveLevelAlarm::read_low_limit_async(std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::low_limit_browse_name(),
    &Variant::is_double,
    {"ExclusiveLevelAlarm", "low_limit", "ExclusiveLevelAlarm::read_low_limit_async"},
    std::move(complete));
}

DoubleResult ExclusiveLevelAlarm::try_read_low_limit_sync() const noexcept
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

double ExclusiveLevelAlarm::read_low_limit_sync() const
{
  return ::ua::detail::good_value(try_read_low_limit_sync());
}

void ExclusiveLevelAlarm::read_low_low_limit_async(std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::low_low_limit_browse_name(),
    &Variant::is_double,
    {"ExclusiveLevelAlarm", "low_low_limit", "ExclusiveLevelAlarm::read_low_low_limit_async"},
    std::move(complete));
}

DoubleResult ExclusiveLevelAlarm::try_read_low_low_limit_sync() const noexcept
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

double ExclusiveLevelAlarm::read_low_low_limit_sync() const
{
  return ::ua::detail::good_value(try_read_low_low_limit_sync());
}

void ExclusiveLevelAlarm::read_base_high_high_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::base_high_high_limit_browse_name(),
    &Variant::is_double,
    {"ExclusiveLevelAlarm", "base_high_high_limit", "ExclusiveLevelAlarm::read_base_high_high_limit_async"},
    std::move(complete));
}

DoubleResult ExclusiveLevelAlarm::try_read_base_high_high_limit_sync() const noexcept
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

double ExclusiveLevelAlarm::read_base_high_high_limit_sync() const
{
  return ::ua::detail::good_value(try_read_base_high_high_limit_sync());
}

void ExclusiveLevelAlarm::read_base_high_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::base_high_limit_browse_name(),
    &Variant::is_double,
    {"ExclusiveLevelAlarm", "base_high_limit", "ExclusiveLevelAlarm::read_base_high_limit_async"},
    std::move(complete));
}

DoubleResult ExclusiveLevelAlarm::try_read_base_high_limit_sync() const noexcept
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

double ExclusiveLevelAlarm::read_base_high_limit_sync() const
{
  return ::ua::detail::good_value(try_read_base_high_limit_sync());
}

void ExclusiveLevelAlarm::read_base_low_limit_async(std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::base_low_limit_browse_name(),
    &Variant::is_double,
    {"ExclusiveLevelAlarm", "base_low_limit", "ExclusiveLevelAlarm::read_base_low_limit_async"},
    std::move(complete));
}

DoubleResult ExclusiveLevelAlarm::try_read_base_low_limit_sync() const noexcept
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

double ExclusiveLevelAlarm::read_base_low_limit_sync() const
{
  return ::ua::detail::good_value(try_read_base_low_limit_sync());
}

void ExclusiveLevelAlarm::read_base_low_low_limit_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::base_low_low_limit_browse_name(),
    &Variant::is_double,
    {"ExclusiveLevelAlarm", "base_low_low_limit", "ExclusiveLevelAlarm::read_base_low_low_limit_async"},
    std::move(complete));
}

DoubleResult ExclusiveLevelAlarm::try_read_base_low_low_limit_sync() const noexcept
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

double ExclusiveLevelAlarm::read_base_low_low_limit_sync() const
{
  return ::ua::detail::good_value(try_read_base_low_low_limit_sync());
}

void ExclusiveLevelAlarm::read_severity_high_high_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::severity_high_high_browse_name(),
    &Variant::is_uint16,
    {"ExclusiveLevelAlarm", "severity_high_high", "ExclusiveLevelAlarm::read_severity_high_high_async"},
    std::move(complete));
}

UInt16Result ExclusiveLevelAlarm::try_read_severity_high_high_sync() const noexcept
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

uint16_t ExclusiveLevelAlarm::read_severity_high_high_sync() const
{
  return ::ua::detail::good_value(try_read_severity_high_high_sync());
}

void ExclusiveLevelAlarm::read_severity_high_async(std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::severity_high_browse_name(),
    &Variant::is_uint16,
    {"ExclusiveLevelAlarm", "severity_high", "ExclusiveLevelAlarm::read_severity_high_async"},
    std::move(complete));
}

UInt16Result ExclusiveLevelAlarm::try_read_severity_high_sync() const noexcept
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

uint16_t ExclusiveLevelAlarm::read_severity_high_sync() const
{
  return ::ua::detail::good_value(try_read_severity_high_sync());
}

void ExclusiveLevelAlarm::read_severity_low_async(std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::severity_low_browse_name(),
    &Variant::is_uint16,
    {"ExclusiveLevelAlarm", "severity_low", "ExclusiveLevelAlarm::read_severity_low_async"},
    std::move(complete));
}

UInt16Result ExclusiveLevelAlarm::try_read_severity_low_sync() const noexcept
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

uint16_t ExclusiveLevelAlarm::read_severity_low_sync() const
{
  return ::ua::detail::good_value(try_read_severity_low_sync());
}

void ExclusiveLevelAlarm::read_severity_low_low_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::severity_low_low_browse_name(),
    &Variant::is_uint16,
    {"ExclusiveLevelAlarm", "severity_low_low", "ExclusiveLevelAlarm::read_severity_low_low_async"},
    std::move(complete));
}

UInt16Result ExclusiveLevelAlarm::try_read_severity_low_low_sync() const noexcept
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

uint16_t ExclusiveLevelAlarm::read_severity_low_low_sync() const
{
  return ::ua::detail::good_value(try_read_severity_low_low_sync());
}

void ExclusiveLevelAlarm::read_high_high_deadband_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::high_high_deadband_browse_name(),
    &Variant::is_double,
    {"ExclusiveLevelAlarm", "high_high_deadband", "ExclusiveLevelAlarm::read_high_high_deadband_async"},
    std::move(complete));
}

DoubleResult ExclusiveLevelAlarm::try_read_high_high_deadband_sync() const noexcept
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

double ExclusiveLevelAlarm::read_high_high_deadband_sync() const
{
  return ::ua::detail::good_value(try_read_high_high_deadband_sync());
}

void ExclusiveLevelAlarm::read_high_deadband_async(std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::high_deadband_browse_name(),
    &Variant::is_double,
    {"ExclusiveLevelAlarm", "high_deadband", "ExclusiveLevelAlarm::read_high_deadband_async"},
    std::move(complete));
}

DoubleResult ExclusiveLevelAlarm::try_read_high_deadband_sync() const noexcept
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

double ExclusiveLevelAlarm::read_high_deadband_sync() const
{
  return ::ua::detail::good_value(try_read_high_deadband_sync());
}

void ExclusiveLevelAlarm::read_low_deadband_async(std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::low_deadband_browse_name(),
    &Variant::is_double,
    {"ExclusiveLevelAlarm", "low_deadband", "ExclusiveLevelAlarm::read_low_deadband_async"},
    std::move(complete));
}

DoubleResult ExclusiveLevelAlarm::try_read_low_deadband_sync() const noexcept
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

double ExclusiveLevelAlarm::read_low_deadband_sync() const
{
  return ::ua::detail::good_value(try_read_low_deadband_sync());
}

void ExclusiveLevelAlarm::read_low_low_deadband_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::low_low_deadband_browse_name(),
    &Variant::is_double,
    {"ExclusiveLevelAlarm", "low_low_deadband", "ExclusiveLevelAlarm::read_low_low_deadband_async"},
    std::move(complete));
}

DoubleResult ExclusiveLevelAlarm::try_read_low_low_deadband_sync() const noexcept
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

double ExclusiveLevelAlarm::read_low_low_deadband_sync() const
{
  return ::ua::detail::good_value(try_read_low_low_deadband_sync());
}

void ExclusiveLevelAlarm::read_input_node_async(std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::input_node_browse_name(),
    &Variant::is_node_id,
    {"ExclusiveLevelAlarm", "input_node", "ExclusiveLevelAlarm::read_input_node_async"},
    std::move(complete));
}

NodeIdResult ExclusiveLevelAlarm::try_read_input_node_sync() const noexcept
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

NodeId ExclusiveLevelAlarm::read_input_node_sync() const
{
  return ::ua::detail::good_value(try_read_input_node_sync());
}

void ExclusiveLevelAlarm::read_suppressed_or_shelved_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::suppressed_or_shelved_browse_name(),
    &Variant::is_boolean,
    {"ExclusiveLevelAlarm", "suppressed_or_shelved", "ExclusiveLevelAlarm::read_suppressed_or_shelved_async"},
    std::move(complete));
}

BoolResult ExclusiveLevelAlarm::try_read_suppressed_or_shelved_sync() const noexcept
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

bool ExclusiveLevelAlarm::read_suppressed_or_shelved_sync() const
{
  return ::ua::detail::good_value(try_read_suppressed_or_shelved_sync());
}

void ExclusiveLevelAlarm::read_audible_enabled_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::audible_enabled_browse_name(),
    &Variant::is_boolean,
    {"ExclusiveLevelAlarm", "audible_enabled", "ExclusiveLevelAlarm::read_audible_enabled_async"},
    std::move(complete));
}

BoolResult ExclusiveLevelAlarm::try_read_audible_enabled_sync() const noexcept
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

bool ExclusiveLevelAlarm::read_audible_enabled_sync() const
{
  return ::ua::detail::good_value(try_read_audible_enabled_sync());
}

void ExclusiveLevelAlarm::read_condition_class_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::condition_class_id_browse_name(),
    &Variant::is_node_id,
    {"ExclusiveLevelAlarm", "condition_class_id", "ExclusiveLevelAlarm::read_condition_class_id_async"},
    std::move(complete));
}

NodeIdResult ExclusiveLevelAlarm::try_read_condition_class_id_sync() const noexcept
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

NodeId ExclusiveLevelAlarm::read_condition_class_id_sync() const
{
  return ::ua::detail::good_value(try_read_condition_class_id_sync());
}

void ExclusiveLevelAlarm::read_condition_class_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::condition_class_name_browse_name(),
    &Variant::is_localized_text,
    {"ExclusiveLevelAlarm", "condition_class_name", "ExclusiveLevelAlarm::read_condition_class_name_async"},
    std::move(complete));
}

LocalizedTextResult ExclusiveLevelAlarm::try_read_condition_class_name_sync() const noexcept
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

LocalizedText ExclusiveLevelAlarm::read_condition_class_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_class_name_sync());
}

void ExclusiveLevelAlarm::read_condition_sub_class_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::condition_sub_class_id_browse_name(),
    &Variant::is_node_id,
    {"ExclusiveLevelAlarm",
      "condition_sub_class_id",
      "ExclusiveLevelAlarm::read_condition_sub_class_id_async"},
    std::move(complete));
}

NodeIdResult ExclusiveLevelAlarm::try_read_condition_sub_class_id_sync() const noexcept
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

NodeId ExclusiveLevelAlarm::read_condition_sub_class_id_sync() const
{
  return ::ua::detail::good_value(try_read_condition_sub_class_id_sync());
}

void ExclusiveLevelAlarm::read_condition_sub_class_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::condition_sub_class_name_browse_name(),
    &Variant::is_localized_text,
    {"ExclusiveLevelAlarm",
      "condition_sub_class_name",
      "ExclusiveLevelAlarm::read_condition_sub_class_name_async"},
    std::move(complete));
}

LocalizedTextResult ExclusiveLevelAlarm::try_read_condition_sub_class_name_sync() const noexcept
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

LocalizedText ExclusiveLevelAlarm::read_condition_sub_class_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_sub_class_name_sync());
}

void ExclusiveLevelAlarm::read_condition_name_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::condition_name_browse_name(),
    &Variant::is_string,
    {"ExclusiveLevelAlarm", "condition_name", "ExclusiveLevelAlarm::read_condition_name_async"},
    std::move(complete));
}

StringResult ExclusiveLevelAlarm::try_read_condition_name_sync() const noexcept
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

String ExclusiveLevelAlarm::read_condition_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_name_sync());
}

void ExclusiveLevelAlarm::read_branch_id_async(std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::branch_id_browse_name(),
    &Variant::is_node_id,
    {"ExclusiveLevelAlarm", "branch_id", "ExclusiveLevelAlarm::read_branch_id_async"},
    std::move(complete));
}

NodeIdResult ExclusiveLevelAlarm::try_read_branch_id_sync() const noexcept
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

NodeId ExclusiveLevelAlarm::read_branch_id_sync() const
{
  return ::ua::detail::good_value(try_read_branch_id_sync());
}

void ExclusiveLevelAlarm::read_retain_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::retain_browse_name(),
    &Variant::is_boolean,
    {"ExclusiveLevelAlarm", "retain", "ExclusiveLevelAlarm::read_retain_async"},
    std::move(complete));
}

BoolResult ExclusiveLevelAlarm::try_read_retain_sync() const noexcept
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

bool ExclusiveLevelAlarm::read_retain_sync() const
{
  return ::ua::detail::good_value(try_read_retain_sync());
}

void ExclusiveLevelAlarm::read_supports_filtered_retain_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::supports_filtered_retain_browse_name(),
    &Variant::is_boolean,
    {"ExclusiveLevelAlarm",
      "supports_filtered_retain",
      "ExclusiveLevelAlarm::read_supports_filtered_retain_async"},
    std::move(complete));
}

BoolResult ExclusiveLevelAlarm::try_read_supports_filtered_retain_sync() const noexcept
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

bool ExclusiveLevelAlarm::read_supports_filtered_retain_sync() const
{
  return ::ua::detail::good_value(try_read_supports_filtered_retain_sync());
}

void ExclusiveLevelAlarm::read_client_user_id_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::client_user_id_browse_name(),
    &Variant::is_string,
    {"ExclusiveLevelAlarm", "client_user_id", "ExclusiveLevelAlarm::read_client_user_id_async"},
    std::move(complete));
}

StringResult ExclusiveLevelAlarm::try_read_client_user_id_sync() const noexcept
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

String ExclusiveLevelAlarm::read_client_user_id_sync() const
{
  return ::ua::detail::good_value(try_read_client_user_id_sync());
}

void ExclusiveLevelAlarm::read_event_id_async(std::function<void(ByteStringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(ByteStringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<ByteString>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::event_id_browse_name(),
    &Variant::is_byte_string,
    {"ExclusiveLevelAlarm", "event_id", "ExclusiveLevelAlarm::read_event_id_async"},
    std::move(complete));
}

ByteStringResult ExclusiveLevelAlarm::try_read_event_id_sync() const noexcept
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

ByteString ExclusiveLevelAlarm::read_event_id_sync() const
{
  return ::ua::detail::good_value(try_read_event_id_sync());
}

void ExclusiveLevelAlarm::read_event_type_async(std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::event_type_browse_name(),
    &Variant::is_node_id,
    {"ExclusiveLevelAlarm", "event_type", "ExclusiveLevelAlarm::read_event_type_async"},
    std::move(complete));
}

NodeIdResult ExclusiveLevelAlarm::try_read_event_type_sync() const noexcept
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

NodeId ExclusiveLevelAlarm::read_event_type_sync() const
{
  return ::ua::detail::good_value(try_read_event_type_sync());
}

void ExclusiveLevelAlarm::read_source_node_async(std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::source_node_browse_name(),
    &Variant::is_node_id,
    {"ExclusiveLevelAlarm", "source_node", "ExclusiveLevelAlarm::read_source_node_async"},
    std::move(complete));
}

NodeIdResult ExclusiveLevelAlarm::try_read_source_node_sync() const noexcept
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

NodeId ExclusiveLevelAlarm::read_source_node_sync() const
{
  return ::ua::detail::good_value(try_read_source_node_sync());
}

void ExclusiveLevelAlarm::read_source_name_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::source_name_browse_name(),
    &Variant::is_string,
    {"ExclusiveLevelAlarm", "source_name", "ExclusiveLevelAlarm::read_source_name_async"},
    std::move(complete));
}

StringResult ExclusiveLevelAlarm::try_read_source_name_sync() const noexcept
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

String ExclusiveLevelAlarm::read_source_name_sync() const
{
  return ::ua::detail::good_value(try_read_source_name_sync());
}

void ExclusiveLevelAlarm::read_message_async(std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::message_browse_name(),
    &Variant::is_localized_text,
    {"ExclusiveLevelAlarm", "message", "ExclusiveLevelAlarm::read_message_async"},
    std::move(complete));
}

LocalizedTextResult ExclusiveLevelAlarm::try_read_message_sync() const noexcept
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

LocalizedText ExclusiveLevelAlarm::read_message_sync() const
{
  return ::ua::detail::good_value(try_read_message_sync());
}

void ExclusiveLevelAlarm::read_severity_async(std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::severity_browse_name(),
    &Variant::is_uint16,
    {"ExclusiveLevelAlarm", "severity", "ExclusiveLevelAlarm::read_severity_async"},
    std::move(complete));
}

UInt16Result ExclusiveLevelAlarm::try_read_severity_sync() const noexcept
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

uint16_t ExclusiveLevelAlarm::read_severity_sync() const
{
  return ::ua::detail::good_value(try_read_severity_sync());
}

// --- Typed value write shortcuts ---

void ExclusiveLevelAlarm::write_high_high_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::high_high_limit_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_high_high_limit_sync(double value) const noexcept
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

void ExclusiveLevelAlarm::write_high_high_limit_sync(double value) const
{
  try_write_high_high_limit_sync(value).value();
}

void ExclusiveLevelAlarm::write_high_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::high_limit_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_high_limit_sync(double value) const noexcept
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

void ExclusiveLevelAlarm::write_high_limit_sync(double value) const
{
  try_write_high_limit_sync(value).value();
}

void ExclusiveLevelAlarm::write_low_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::low_limit_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_low_limit_sync(double value) const noexcept
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

void ExclusiveLevelAlarm::write_low_limit_sync(double value) const
{
  try_write_low_limit_sync(value).value();
}

void ExclusiveLevelAlarm::write_low_low_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::low_low_limit_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_low_low_limit_sync(double value) const noexcept
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

void ExclusiveLevelAlarm::write_low_low_limit_sync(double value) const
{
  try_write_low_low_limit_sync(value).value();
}

void ExclusiveLevelAlarm::write_base_high_high_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::base_high_high_limit_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_base_high_high_limit_sync(double value) const noexcept
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

void ExclusiveLevelAlarm::write_base_high_high_limit_sync(double value) const
{
  try_write_base_high_high_limit_sync(value).value();
}

void ExclusiveLevelAlarm::write_base_high_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::base_high_limit_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_base_high_limit_sync(double value) const noexcept
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

void ExclusiveLevelAlarm::write_base_high_limit_sync(double value) const
{
  try_write_base_high_limit_sync(value).value();
}

void ExclusiveLevelAlarm::write_base_low_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::base_low_limit_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_base_low_limit_sync(double value) const noexcept
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

void ExclusiveLevelAlarm::write_base_low_limit_sync(double value) const
{
  try_write_base_low_limit_sync(value).value();
}

void ExclusiveLevelAlarm::write_base_low_low_limit_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::base_low_low_limit_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_base_low_low_limit_sync(double value) const noexcept
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

void ExclusiveLevelAlarm::write_base_low_low_limit_sync(double value) const
{
  try_write_base_low_low_limit_sync(value).value();
}

void ExclusiveLevelAlarm::write_severity_high_high_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::severity_high_high_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_severity_high_high_sync(uint16_t value) const noexcept
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

void ExclusiveLevelAlarm::write_severity_high_high_sync(uint16_t value) const
{
  try_write_severity_high_high_sync(value).value();
}

void ExclusiveLevelAlarm::write_severity_high_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::severity_high_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_severity_high_sync(uint16_t value) const noexcept
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

void ExclusiveLevelAlarm::write_severity_high_sync(uint16_t value) const
{
  try_write_severity_high_sync(value).value();
}

void ExclusiveLevelAlarm::write_severity_low_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::severity_low_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_severity_low_sync(uint16_t value) const noexcept
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

void ExclusiveLevelAlarm::write_severity_low_sync(uint16_t value) const
{
  try_write_severity_low_sync(value).value();
}

void ExclusiveLevelAlarm::write_severity_low_low_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::severity_low_low_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_severity_low_low_sync(uint16_t value) const noexcept
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

void ExclusiveLevelAlarm::write_severity_low_low_sync(uint16_t value) const
{
  try_write_severity_low_low_sync(value).value();
}

void ExclusiveLevelAlarm::write_high_high_deadband_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::high_high_deadband_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_high_high_deadband_sync(double value) const noexcept
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

void ExclusiveLevelAlarm::write_high_high_deadband_sync(double value) const
{
  try_write_high_high_deadband_sync(value).value();
}

void ExclusiveLevelAlarm::write_high_deadband_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::high_deadband_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_high_deadband_sync(double value) const noexcept
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

void ExclusiveLevelAlarm::write_high_deadband_sync(double value) const
{
  try_write_high_deadband_sync(value).value();
}

void ExclusiveLevelAlarm::write_low_deadband_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::low_deadband_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_low_deadband_sync(double value) const noexcept
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

void ExclusiveLevelAlarm::write_low_deadband_sync(double value) const
{
  try_write_low_deadband_sync(value).value();
}

void ExclusiveLevelAlarm::write_low_low_deadband_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::low_low_deadband_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_low_low_deadband_sync(double value) const noexcept
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

void ExclusiveLevelAlarm::write_low_low_deadband_sync(double value) const
{
  try_write_low_low_deadband_sync(value).value();
}

void ExclusiveLevelAlarm::write_input_node_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::input_node_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_input_node_sync(NodeId value) const noexcept
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

void ExclusiveLevelAlarm::write_input_node_sync(NodeId value) const
{
  try_write_input_node_sync(value).value();
}

void ExclusiveLevelAlarm::write_suppressed_or_shelved_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::suppressed_or_shelved_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_suppressed_or_shelved_sync(bool value) const noexcept
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

void ExclusiveLevelAlarm::write_suppressed_or_shelved_sync(bool value) const
{
  try_write_suppressed_or_shelved_sync(value).value();
}

void ExclusiveLevelAlarm::write_audible_enabled_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::audible_enabled_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_audible_enabled_sync(bool value) const noexcept
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

void ExclusiveLevelAlarm::write_audible_enabled_sync(bool value) const
{
  try_write_audible_enabled_sync(value).value();
}

void ExclusiveLevelAlarm::write_condition_class_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::condition_class_id_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_condition_class_id_sync(NodeId value) const noexcept
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

void ExclusiveLevelAlarm::write_condition_class_id_sync(NodeId value) const
{
  try_write_condition_class_id_sync(value).value();
}

void ExclusiveLevelAlarm::write_condition_class_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::condition_class_name_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_condition_class_name_sync(LocalizedText value) const noexcept
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

void ExclusiveLevelAlarm::write_condition_class_name_sync(LocalizedText value) const
{
  try_write_condition_class_name_sync(value).value();
}

void ExclusiveLevelAlarm::write_condition_sub_class_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::condition_sub_class_id_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_condition_sub_class_id_sync(NodeId value) const noexcept
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

void ExclusiveLevelAlarm::write_condition_sub_class_id_sync(NodeId value) const
{
  try_write_condition_sub_class_id_sync(value).value();
}

void ExclusiveLevelAlarm::write_condition_sub_class_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::condition_sub_class_name_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_condition_sub_class_name_sync(LocalizedText value) const noexcept
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

void ExclusiveLevelAlarm::write_condition_sub_class_name_sync(LocalizedText value) const
{
  try_write_condition_sub_class_name_sync(value).value();
}

void ExclusiveLevelAlarm::write_condition_name_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::condition_name_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_condition_name_sync(String value) const noexcept
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

void ExclusiveLevelAlarm::write_condition_name_sync(String value) const
{
  try_write_condition_name_sync(value).value();
}

void ExclusiveLevelAlarm::write_branch_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::branch_id_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_branch_id_sync(NodeId value) const noexcept
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

void ExclusiveLevelAlarm::write_branch_id_sync(NodeId value) const
{
  try_write_branch_id_sync(value).value();
}

void ExclusiveLevelAlarm::write_retain_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::retain_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_retain_sync(bool value) const noexcept
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

void ExclusiveLevelAlarm::write_retain_sync(bool value) const
{
  try_write_retain_sync(value).value();
}

void ExclusiveLevelAlarm::write_supports_filtered_retain_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::supports_filtered_retain_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_supports_filtered_retain_sync(bool value) const noexcept
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

void ExclusiveLevelAlarm::write_supports_filtered_retain_sync(bool value) const
{
  try_write_supports_filtered_retain_sync(value).value();
}

void ExclusiveLevelAlarm::write_client_user_id_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::client_user_id_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_client_user_id_sync(String value) const noexcept
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

void ExclusiveLevelAlarm::write_client_user_id_sync(String value) const
{
  try_write_client_user_id_sync(value).value();
}

void ExclusiveLevelAlarm::write_event_id_async(
  ByteString value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::event_id_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_event_id_sync(ByteString value) const noexcept
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

void ExclusiveLevelAlarm::write_event_id_sync(ByteString value) const
{
  try_write_event_id_sync(value).value();
}

void ExclusiveLevelAlarm::write_event_type_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::event_type_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_event_type_sync(NodeId value) const noexcept
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

void ExclusiveLevelAlarm::write_event_type_sync(NodeId value) const
{
  try_write_event_type_sync(value).value();
}

void ExclusiveLevelAlarm::write_source_node_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::source_node_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_source_node_sync(NodeId value) const noexcept
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

void ExclusiveLevelAlarm::write_source_node_sync(NodeId value) const
{
  try_write_source_node_sync(value).value();
}

void ExclusiveLevelAlarm::write_source_name_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::source_name_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_source_name_sync(String value) const noexcept
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

void ExclusiveLevelAlarm::write_source_name_sync(String value) const
{
  try_write_source_name_sync(value).value();
}

void ExclusiveLevelAlarm::write_message_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::message_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_message_sync(LocalizedText value) const noexcept
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

void ExclusiveLevelAlarm::write_message_sync(LocalizedText value) const
{
  try_write_message_sync(value).value();
}

void ExclusiveLevelAlarm::write_severity_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ExclusiveLevelAlarmTypeTraits::severity_browse_name(),
    "ExclusiveLevelAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ExclusiveLevelAlarm::try_write_severity_sync(uint16_t value) const noexcept
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

void ExclusiveLevelAlarm::write_severity_sync(uint16_t value) const
{
  try_write_severity_sync(value).value();
}

}  // namespace ua
