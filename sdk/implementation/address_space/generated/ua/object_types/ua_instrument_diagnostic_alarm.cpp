// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_instrument_diagnostic_alarm.h"

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

struct InstrumentDiagnosticAlarmTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::InstrumentDiagnosticAlarmType};
  }

  static QualifiedName normal_state_browse_name()
  {
    return QualifiedName{0, "NormalState"};
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

InstrumentDiagnosticAlarm::InstrumentDiagnosticAlarm(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void InstrumentDiagnosticAlarm::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    InstrumentDiagnosticAlarmTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(InstrumentDiagnosticAlarmResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(InstrumentDiagnosticAlarmResult{
        InstrumentDiagnosticAlarm{
          std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

InstrumentDiagnosticAlarmResult InstrumentDiagnosticAlarm::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<InstrumentDiagnosticAlarmResult>(addressSpace.executor(),
      [&](std::function<void(InstrumentDiagnosticAlarmResult)> complete)
      {
        InstrumentDiagnosticAlarm::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

InstrumentDiagnosticAlarm InstrumentDiagnosticAlarm::create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void InstrumentDiagnosticAlarm::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void InstrumentDiagnosticAlarm::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // InstrumentDiagnosticAlarmType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    InstrumentDiagnosticAlarmTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(InstrumentDiagnosticAlarmResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(
          InstrumentDiagnosticAlarmResult{::ua::detail::address_space_gone("InstrumentDiagnosticAlarm")});
        return;
      }
      complete(
        InstrumentDiagnosticAlarm{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

InstrumentDiagnosticAlarmResult InstrumentDiagnosticAlarm::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<InstrumentDiagnosticAlarmResult>(addressSpace.executor(),
      [&](std::function<void(InstrumentDiagnosticAlarmResult)> complete)
      {
        InstrumentDiagnosticAlarm::attach_async(
          std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

InstrumentDiagnosticAlarm InstrumentDiagnosticAlarm::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void InstrumentDiagnosticAlarm::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void InstrumentDiagnosticAlarm::find_property_async(
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
    "InstrumentDiagnosticAlarm",
    std::move(complete));
}

// --- Property accessors ---

void InstrumentDiagnosticAlarm::normal_state_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(InstrumentDiagnosticAlarmTypeTraits::normal_state_browse_name(), std::move(complete));
}

PropertyResult InstrumentDiagnosticAlarm::try_normal_state_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { normal_state_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property InstrumentDiagnosticAlarm::normal_state_property_sync() const
{
  return ::ua::detail::good_value(try_normal_state_property_sync());
}

void InstrumentDiagnosticAlarm::input_node_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(InstrumentDiagnosticAlarmTypeTraits::input_node_browse_name(), std::move(complete));
}

PropertyResult InstrumentDiagnosticAlarm::try_input_node_property_sync() const noexcept
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

Property InstrumentDiagnosticAlarm::input_node_property_sync() const
{
  return ::ua::detail::good_value(try_input_node_property_sync());
}

void InstrumentDiagnosticAlarm::suppressed_or_shelved_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    InstrumentDiagnosticAlarmTypeTraits::suppressed_or_shelved_browse_name(), std::move(complete));
}

PropertyResult InstrumentDiagnosticAlarm::try_suppressed_or_shelved_property_sync() const noexcept
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

Property InstrumentDiagnosticAlarm::suppressed_or_shelved_property_sync() const
{
  return ::ua::detail::good_value(try_suppressed_or_shelved_property_sync());
}

void InstrumentDiagnosticAlarm::max_time_shelved_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    InstrumentDiagnosticAlarmTypeTraits::max_time_shelved_browse_name(), std::move(complete));
}

PropertyResult InstrumentDiagnosticAlarm::try_max_time_shelved_property_sync() const noexcept
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

Property InstrumentDiagnosticAlarm::max_time_shelved_property_sync() const
{
  return ::ua::detail::good_value(try_max_time_shelved_property_sync());
}

void InstrumentDiagnosticAlarm::audible_enabled_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    InstrumentDiagnosticAlarmTypeTraits::audible_enabled_browse_name(), std::move(complete));
}

PropertyResult InstrumentDiagnosticAlarm::try_audible_enabled_property_sync() const noexcept
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

Property InstrumentDiagnosticAlarm::audible_enabled_property_sync() const
{
  return ::ua::detail::good_value(try_audible_enabled_property_sync());
}

void InstrumentDiagnosticAlarm::on_delay_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(InstrumentDiagnosticAlarmTypeTraits::on_delay_browse_name(), std::move(complete));
}

PropertyResult InstrumentDiagnosticAlarm::try_on_delay_property_sync() const noexcept
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

Property InstrumentDiagnosticAlarm::on_delay_property_sync() const
{
  return ::ua::detail::good_value(try_on_delay_property_sync());
}

void InstrumentDiagnosticAlarm::off_delay_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(InstrumentDiagnosticAlarmTypeTraits::off_delay_browse_name(), std::move(complete));
}

PropertyResult InstrumentDiagnosticAlarm::try_off_delay_property_sync() const noexcept
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

Property InstrumentDiagnosticAlarm::off_delay_property_sync() const
{
  return ::ua::detail::good_value(try_off_delay_property_sync());
}

void InstrumentDiagnosticAlarm::re_alarm_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(InstrumentDiagnosticAlarmTypeTraits::re_alarm_time_browse_name(), std::move(complete));
}

PropertyResult InstrumentDiagnosticAlarm::try_re_alarm_time_property_sync() const noexcept
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

Property InstrumentDiagnosticAlarm::re_alarm_time_property_sync() const
{
  return ::ua::detail::good_value(try_re_alarm_time_property_sync());
}

void InstrumentDiagnosticAlarm::condition_class_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    InstrumentDiagnosticAlarmTypeTraits::condition_class_id_browse_name(), std::move(complete));
}

PropertyResult InstrumentDiagnosticAlarm::try_condition_class_id_property_sync() const noexcept
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

Property InstrumentDiagnosticAlarm::condition_class_id_property_sync() const
{
  return ::ua::detail::good_value(try_condition_class_id_property_sync());
}

void InstrumentDiagnosticAlarm::condition_class_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    InstrumentDiagnosticAlarmTypeTraits::condition_class_name_browse_name(), std::move(complete));
}

PropertyResult InstrumentDiagnosticAlarm::try_condition_class_name_property_sync() const noexcept
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

Property InstrumentDiagnosticAlarm::condition_class_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_class_name_property_sync());
}

void InstrumentDiagnosticAlarm::condition_sub_class_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    InstrumentDiagnosticAlarmTypeTraits::condition_sub_class_id_browse_name(), std::move(complete));
}

PropertyResult InstrumentDiagnosticAlarm::try_condition_sub_class_id_property_sync() const noexcept
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

Property InstrumentDiagnosticAlarm::condition_sub_class_id_property_sync() const
{
  return ::ua::detail::good_value(try_condition_sub_class_id_property_sync());
}

void InstrumentDiagnosticAlarm::condition_sub_class_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    InstrumentDiagnosticAlarmTypeTraits::condition_sub_class_name_browse_name(), std::move(complete));
}

PropertyResult InstrumentDiagnosticAlarm::try_condition_sub_class_name_property_sync() const noexcept
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

Property InstrumentDiagnosticAlarm::condition_sub_class_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_sub_class_name_property_sync());
}

void InstrumentDiagnosticAlarm::condition_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(InstrumentDiagnosticAlarmTypeTraits::condition_name_browse_name(), std::move(complete));
}

PropertyResult InstrumentDiagnosticAlarm::try_condition_name_property_sync() const noexcept
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

Property InstrumentDiagnosticAlarm::condition_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_name_property_sync());
}

void InstrumentDiagnosticAlarm::branch_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(InstrumentDiagnosticAlarmTypeTraits::branch_id_browse_name(), std::move(complete));
}

PropertyResult InstrumentDiagnosticAlarm::try_branch_id_property_sync() const noexcept
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

Property InstrumentDiagnosticAlarm::branch_id_property_sync() const
{
  return ::ua::detail::good_value(try_branch_id_property_sync());
}

void InstrumentDiagnosticAlarm::retain_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(InstrumentDiagnosticAlarmTypeTraits::retain_browse_name(), std::move(complete));
}

PropertyResult InstrumentDiagnosticAlarm::try_retain_property_sync() const noexcept
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

Property InstrumentDiagnosticAlarm::retain_property_sync() const
{
  return ::ua::detail::good_value(try_retain_property_sync());
}

void InstrumentDiagnosticAlarm::supports_filtered_retain_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    InstrumentDiagnosticAlarmTypeTraits::supports_filtered_retain_browse_name(), std::move(complete));
}

PropertyResult InstrumentDiagnosticAlarm::try_supports_filtered_retain_property_sync() const noexcept
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

Property InstrumentDiagnosticAlarm::supports_filtered_retain_property_sync() const
{
  return ::ua::detail::good_value(try_supports_filtered_retain_property_sync());
}

void InstrumentDiagnosticAlarm::client_user_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(InstrumentDiagnosticAlarmTypeTraits::client_user_id_browse_name(), std::move(complete));
}

PropertyResult InstrumentDiagnosticAlarm::try_client_user_id_property_sync() const noexcept
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

Property InstrumentDiagnosticAlarm::client_user_id_property_sync() const
{
  return ::ua::detail::good_value(try_client_user_id_property_sync());
}

void InstrumentDiagnosticAlarm::event_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(InstrumentDiagnosticAlarmTypeTraits::event_id_browse_name(), std::move(complete));
}

PropertyResult InstrumentDiagnosticAlarm::try_event_id_property_sync() const noexcept
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

Property InstrumentDiagnosticAlarm::event_id_property_sync() const
{
  return ::ua::detail::good_value(try_event_id_property_sync());
}

void InstrumentDiagnosticAlarm::event_type_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(InstrumentDiagnosticAlarmTypeTraits::event_type_browse_name(), std::move(complete));
}

PropertyResult InstrumentDiagnosticAlarm::try_event_type_property_sync() const noexcept
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

Property InstrumentDiagnosticAlarm::event_type_property_sync() const
{
  return ::ua::detail::good_value(try_event_type_property_sync());
}

void InstrumentDiagnosticAlarm::source_node_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(InstrumentDiagnosticAlarmTypeTraits::source_node_browse_name(), std::move(complete));
}

PropertyResult InstrumentDiagnosticAlarm::try_source_node_property_sync() const noexcept
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

Property InstrumentDiagnosticAlarm::source_node_property_sync() const
{
  return ::ua::detail::good_value(try_source_node_property_sync());
}

void InstrumentDiagnosticAlarm::source_name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(InstrumentDiagnosticAlarmTypeTraits::source_name_browse_name(), std::move(complete));
}

PropertyResult InstrumentDiagnosticAlarm::try_source_name_property_sync() const noexcept
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

Property InstrumentDiagnosticAlarm::source_name_property_sync() const
{
  return ::ua::detail::good_value(try_source_name_property_sync());
}

void InstrumentDiagnosticAlarm::time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(InstrumentDiagnosticAlarmTypeTraits::time_browse_name(), std::move(complete));
}

PropertyResult InstrumentDiagnosticAlarm::try_time_property_sync() const noexcept
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

Property InstrumentDiagnosticAlarm::time_property_sync() const
{
  return ::ua::detail::good_value(try_time_property_sync());
}

void InstrumentDiagnosticAlarm::receive_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(InstrumentDiagnosticAlarmTypeTraits::receive_time_browse_name(), std::move(complete));
}

PropertyResult InstrumentDiagnosticAlarm::try_receive_time_property_sync() const noexcept
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

Property InstrumentDiagnosticAlarm::receive_time_property_sync() const
{
  return ::ua::detail::good_value(try_receive_time_property_sync());
}

void InstrumentDiagnosticAlarm::local_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(InstrumentDiagnosticAlarmTypeTraits::local_time_browse_name(), std::move(complete));
}

PropertyResult InstrumentDiagnosticAlarm::try_local_time_property_sync() const noexcept
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

Property InstrumentDiagnosticAlarm::local_time_property_sync() const
{
  return ::ua::detail::good_value(try_local_time_property_sync());
}

void InstrumentDiagnosticAlarm::message_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(InstrumentDiagnosticAlarmTypeTraits::message_browse_name(), std::move(complete));
}

PropertyResult InstrumentDiagnosticAlarm::try_message_property_sync() const noexcept
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

Property InstrumentDiagnosticAlarm::message_property_sync() const
{
  return ::ua::detail::good_value(try_message_property_sync());
}

void InstrumentDiagnosticAlarm::severity_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(InstrumentDiagnosticAlarmTypeTraits::severity_browse_name(), std::move(complete));
}

PropertyResult InstrumentDiagnosticAlarm::try_severity_property_sync() const noexcept
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

Property InstrumentDiagnosticAlarm::severity_property_sync() const
{
  return ::ua::detail::good_value(try_severity_property_sync());
}

// --- Typed value read shortcuts ---

void InstrumentDiagnosticAlarm::read_normal_state_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::normal_state_browse_name(),
    &Variant::is_node_id,
    {"InstrumentDiagnosticAlarm", "normal_state", "InstrumentDiagnosticAlarm::read_normal_state_async"},
    std::move(complete));
}

NodeIdResult InstrumentDiagnosticAlarm::try_read_normal_state_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeIdResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(NodeIdResult)> complete) { read_normal_state_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NodeId InstrumentDiagnosticAlarm::read_normal_state_sync() const
{
  return ::ua::detail::good_value(try_read_normal_state_sync());
}

void InstrumentDiagnosticAlarm::read_input_node_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::input_node_browse_name(),
    &Variant::is_node_id,
    {"InstrumentDiagnosticAlarm", "input_node", "InstrumentDiagnosticAlarm::read_input_node_async"},
    std::move(complete));
}

NodeIdResult InstrumentDiagnosticAlarm::try_read_input_node_sync() const noexcept
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

NodeId InstrumentDiagnosticAlarm::read_input_node_sync() const
{
  return ::ua::detail::good_value(try_read_input_node_sync());
}

void InstrumentDiagnosticAlarm::read_suppressed_or_shelved_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::suppressed_or_shelved_browse_name(),
    &Variant::is_boolean,
    {"InstrumentDiagnosticAlarm",
      "suppressed_or_shelved",
      "InstrumentDiagnosticAlarm::read_suppressed_or_shelved_async"},
    std::move(complete));
}

BoolResult InstrumentDiagnosticAlarm::try_read_suppressed_or_shelved_sync() const noexcept
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

bool InstrumentDiagnosticAlarm::read_suppressed_or_shelved_sync() const
{
  return ::ua::detail::good_value(try_read_suppressed_or_shelved_sync());
}

void InstrumentDiagnosticAlarm::read_audible_enabled_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::audible_enabled_browse_name(),
    &Variant::is_boolean,
    {"InstrumentDiagnosticAlarm", "audible_enabled", "InstrumentDiagnosticAlarm::read_audible_enabled_async"},
    std::move(complete));
}

BoolResult InstrumentDiagnosticAlarm::try_read_audible_enabled_sync() const noexcept
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

bool InstrumentDiagnosticAlarm::read_audible_enabled_sync() const
{
  return ::ua::detail::good_value(try_read_audible_enabled_sync());
}

void InstrumentDiagnosticAlarm::read_condition_class_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::condition_class_id_browse_name(),
    &Variant::is_node_id,
    {"InstrumentDiagnosticAlarm",
      "condition_class_id",
      "InstrumentDiagnosticAlarm::read_condition_class_id_async"},
    std::move(complete));
}

NodeIdResult InstrumentDiagnosticAlarm::try_read_condition_class_id_sync() const noexcept
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

NodeId InstrumentDiagnosticAlarm::read_condition_class_id_sync() const
{
  return ::ua::detail::good_value(try_read_condition_class_id_sync());
}

void InstrumentDiagnosticAlarm::read_condition_class_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::condition_class_name_browse_name(),
    &Variant::is_localized_text,
    {"InstrumentDiagnosticAlarm",
      "condition_class_name",
      "InstrumentDiagnosticAlarm::read_condition_class_name_async"},
    std::move(complete));
}

LocalizedTextResult InstrumentDiagnosticAlarm::try_read_condition_class_name_sync() const noexcept
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

LocalizedText InstrumentDiagnosticAlarm::read_condition_class_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_class_name_sync());
}

void InstrumentDiagnosticAlarm::read_condition_sub_class_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::condition_sub_class_id_browse_name(),
    &Variant::is_node_id,
    {"InstrumentDiagnosticAlarm",
      "condition_sub_class_id",
      "InstrumentDiagnosticAlarm::read_condition_sub_class_id_async"},
    std::move(complete));
}

NodeIdResult InstrumentDiagnosticAlarm::try_read_condition_sub_class_id_sync() const noexcept
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

NodeId InstrumentDiagnosticAlarm::read_condition_sub_class_id_sync() const
{
  return ::ua::detail::good_value(try_read_condition_sub_class_id_sync());
}

void InstrumentDiagnosticAlarm::read_condition_sub_class_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::condition_sub_class_name_browse_name(),
    &Variant::is_localized_text,
    {"InstrumentDiagnosticAlarm",
      "condition_sub_class_name",
      "InstrumentDiagnosticAlarm::read_condition_sub_class_name_async"},
    std::move(complete));
}

LocalizedTextResult InstrumentDiagnosticAlarm::try_read_condition_sub_class_name_sync() const noexcept
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

LocalizedText InstrumentDiagnosticAlarm::read_condition_sub_class_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_sub_class_name_sync());
}

void InstrumentDiagnosticAlarm::read_condition_name_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::condition_name_browse_name(),
    &Variant::is_string,
    {"InstrumentDiagnosticAlarm", "condition_name", "InstrumentDiagnosticAlarm::read_condition_name_async"},
    std::move(complete));
}

StringResult InstrumentDiagnosticAlarm::try_read_condition_name_sync() const noexcept
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

String InstrumentDiagnosticAlarm::read_condition_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_name_sync());
}

void InstrumentDiagnosticAlarm::read_branch_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::branch_id_browse_name(),
    &Variant::is_node_id,
    {"InstrumentDiagnosticAlarm", "branch_id", "InstrumentDiagnosticAlarm::read_branch_id_async"},
    std::move(complete));
}

NodeIdResult InstrumentDiagnosticAlarm::try_read_branch_id_sync() const noexcept
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

NodeId InstrumentDiagnosticAlarm::read_branch_id_sync() const
{
  return ::ua::detail::good_value(try_read_branch_id_sync());
}

void InstrumentDiagnosticAlarm::read_retain_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::retain_browse_name(),
    &Variant::is_boolean,
    {"InstrumentDiagnosticAlarm", "retain", "InstrumentDiagnosticAlarm::read_retain_async"},
    std::move(complete));
}

BoolResult InstrumentDiagnosticAlarm::try_read_retain_sync() const noexcept
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

bool InstrumentDiagnosticAlarm::read_retain_sync() const
{
  return ::ua::detail::good_value(try_read_retain_sync());
}

void InstrumentDiagnosticAlarm::read_supports_filtered_retain_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::supports_filtered_retain_browse_name(),
    &Variant::is_boolean,
    {"InstrumentDiagnosticAlarm",
      "supports_filtered_retain",
      "InstrumentDiagnosticAlarm::read_supports_filtered_retain_async"},
    std::move(complete));
}

BoolResult InstrumentDiagnosticAlarm::try_read_supports_filtered_retain_sync() const noexcept
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

bool InstrumentDiagnosticAlarm::read_supports_filtered_retain_sync() const
{
  return ::ua::detail::good_value(try_read_supports_filtered_retain_sync());
}

void InstrumentDiagnosticAlarm::read_client_user_id_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::client_user_id_browse_name(),
    &Variant::is_string,
    {"InstrumentDiagnosticAlarm", "client_user_id", "InstrumentDiagnosticAlarm::read_client_user_id_async"},
    std::move(complete));
}

StringResult InstrumentDiagnosticAlarm::try_read_client_user_id_sync() const noexcept
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

String InstrumentDiagnosticAlarm::read_client_user_id_sync() const
{
  return ::ua::detail::good_value(try_read_client_user_id_sync());
}

void InstrumentDiagnosticAlarm::read_event_id_async(
  std::function<void(ByteStringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(ByteStringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<ByteString>(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::event_id_browse_name(),
    &Variant::is_byte_string,
    {"InstrumentDiagnosticAlarm", "event_id", "InstrumentDiagnosticAlarm::read_event_id_async"},
    std::move(complete));
}

ByteStringResult InstrumentDiagnosticAlarm::try_read_event_id_sync() const noexcept
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

ByteString InstrumentDiagnosticAlarm::read_event_id_sync() const
{
  return ::ua::detail::good_value(try_read_event_id_sync());
}

void InstrumentDiagnosticAlarm::read_event_type_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::event_type_browse_name(),
    &Variant::is_node_id,
    {"InstrumentDiagnosticAlarm", "event_type", "InstrumentDiagnosticAlarm::read_event_type_async"},
    std::move(complete));
}

NodeIdResult InstrumentDiagnosticAlarm::try_read_event_type_sync() const noexcept
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

NodeId InstrumentDiagnosticAlarm::read_event_type_sync() const
{
  return ::ua::detail::good_value(try_read_event_type_sync());
}

void InstrumentDiagnosticAlarm::read_source_node_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::source_node_browse_name(),
    &Variant::is_node_id,
    {"InstrumentDiagnosticAlarm", "source_node", "InstrumentDiagnosticAlarm::read_source_node_async"},
    std::move(complete));
}

NodeIdResult InstrumentDiagnosticAlarm::try_read_source_node_sync() const noexcept
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

NodeId InstrumentDiagnosticAlarm::read_source_node_sync() const
{
  return ::ua::detail::good_value(try_read_source_node_sync());
}

void InstrumentDiagnosticAlarm::read_source_name_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::source_name_browse_name(),
    &Variant::is_string,
    {"InstrumentDiagnosticAlarm", "source_name", "InstrumentDiagnosticAlarm::read_source_name_async"},
    std::move(complete));
}

StringResult InstrumentDiagnosticAlarm::try_read_source_name_sync() const noexcept
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

String InstrumentDiagnosticAlarm::read_source_name_sync() const
{
  return ::ua::detail::good_value(try_read_source_name_sync());
}

void InstrumentDiagnosticAlarm::read_message_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::message_browse_name(),
    &Variant::is_localized_text,
    {"InstrumentDiagnosticAlarm", "message", "InstrumentDiagnosticAlarm::read_message_async"},
    std::move(complete));
}

LocalizedTextResult InstrumentDiagnosticAlarm::try_read_message_sync() const noexcept
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

LocalizedText InstrumentDiagnosticAlarm::read_message_sync() const
{
  return ::ua::detail::good_value(try_read_message_sync());
}

void InstrumentDiagnosticAlarm::read_severity_async(std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::severity_browse_name(),
    &Variant::is_uint16,
    {"InstrumentDiagnosticAlarm", "severity", "InstrumentDiagnosticAlarm::read_severity_async"},
    std::move(complete));
}

UInt16Result InstrumentDiagnosticAlarm::try_read_severity_sync() const noexcept
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

uint16_t InstrumentDiagnosticAlarm::read_severity_sync() const
{
  return ::ua::detail::good_value(try_read_severity_sync());
}

// --- Typed value write shortcuts ---

void InstrumentDiagnosticAlarm::write_normal_state_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::normal_state_browse_name(),
    "InstrumentDiagnosticAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult InstrumentDiagnosticAlarm::try_write_normal_state_sync(NodeId value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_normal_state_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void InstrumentDiagnosticAlarm::write_normal_state_sync(NodeId value) const
{
  try_write_normal_state_sync(value).value();
}

void InstrumentDiagnosticAlarm::write_input_node_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::input_node_browse_name(),
    "InstrumentDiagnosticAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult InstrumentDiagnosticAlarm::try_write_input_node_sync(NodeId value) const noexcept
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

void InstrumentDiagnosticAlarm::write_input_node_sync(NodeId value) const
{
  try_write_input_node_sync(value).value();
}

void InstrumentDiagnosticAlarm::write_suppressed_or_shelved_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::suppressed_or_shelved_browse_name(),
    "InstrumentDiagnosticAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult InstrumentDiagnosticAlarm::try_write_suppressed_or_shelved_sync(bool value) const noexcept
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

void InstrumentDiagnosticAlarm::write_suppressed_or_shelved_sync(bool value) const
{
  try_write_suppressed_or_shelved_sync(value).value();
}

void InstrumentDiagnosticAlarm::write_audible_enabled_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::audible_enabled_browse_name(),
    "InstrumentDiagnosticAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult InstrumentDiagnosticAlarm::try_write_audible_enabled_sync(bool value) const noexcept
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

void InstrumentDiagnosticAlarm::write_audible_enabled_sync(bool value) const
{
  try_write_audible_enabled_sync(value).value();
}

void InstrumentDiagnosticAlarm::write_condition_class_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::condition_class_id_browse_name(),
    "InstrumentDiagnosticAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult InstrumentDiagnosticAlarm::try_write_condition_class_id_sync(NodeId value) const noexcept
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

void InstrumentDiagnosticAlarm::write_condition_class_id_sync(NodeId value) const
{
  try_write_condition_class_id_sync(value).value();
}

void InstrumentDiagnosticAlarm::write_condition_class_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::condition_class_name_browse_name(),
    "InstrumentDiagnosticAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult InstrumentDiagnosticAlarm::try_write_condition_class_name_sync(LocalizedText value) const noexcept
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

void InstrumentDiagnosticAlarm::write_condition_class_name_sync(LocalizedText value) const
{
  try_write_condition_class_name_sync(value).value();
}

void InstrumentDiagnosticAlarm::write_condition_sub_class_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::condition_sub_class_id_browse_name(),
    "InstrumentDiagnosticAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult InstrumentDiagnosticAlarm::try_write_condition_sub_class_id_sync(NodeId value) const noexcept
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

void InstrumentDiagnosticAlarm::write_condition_sub_class_id_sync(NodeId value) const
{
  try_write_condition_sub_class_id_sync(value).value();
}

void InstrumentDiagnosticAlarm::write_condition_sub_class_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::condition_sub_class_name_browse_name(),
    "InstrumentDiagnosticAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult InstrumentDiagnosticAlarm::try_write_condition_sub_class_name_sync(
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

void InstrumentDiagnosticAlarm::write_condition_sub_class_name_sync(LocalizedText value) const
{
  try_write_condition_sub_class_name_sync(value).value();
}

void InstrumentDiagnosticAlarm::write_condition_name_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::condition_name_browse_name(),
    "InstrumentDiagnosticAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult InstrumentDiagnosticAlarm::try_write_condition_name_sync(String value) const noexcept
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

void InstrumentDiagnosticAlarm::write_condition_name_sync(String value) const
{
  try_write_condition_name_sync(value).value();
}

void InstrumentDiagnosticAlarm::write_branch_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::branch_id_browse_name(),
    "InstrumentDiagnosticAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult InstrumentDiagnosticAlarm::try_write_branch_id_sync(NodeId value) const noexcept
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

void InstrumentDiagnosticAlarm::write_branch_id_sync(NodeId value) const
{
  try_write_branch_id_sync(value).value();
}

void InstrumentDiagnosticAlarm::write_retain_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::retain_browse_name(),
    "InstrumentDiagnosticAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult InstrumentDiagnosticAlarm::try_write_retain_sync(bool value) const noexcept
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

void InstrumentDiagnosticAlarm::write_retain_sync(bool value) const
{
  try_write_retain_sync(value).value();
}

void InstrumentDiagnosticAlarm::write_supports_filtered_retain_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::supports_filtered_retain_browse_name(),
    "InstrumentDiagnosticAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult InstrumentDiagnosticAlarm::try_write_supports_filtered_retain_sync(bool value) const noexcept
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

void InstrumentDiagnosticAlarm::write_supports_filtered_retain_sync(bool value) const
{
  try_write_supports_filtered_retain_sync(value).value();
}

void InstrumentDiagnosticAlarm::write_client_user_id_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::client_user_id_browse_name(),
    "InstrumentDiagnosticAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult InstrumentDiagnosticAlarm::try_write_client_user_id_sync(String value) const noexcept
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

void InstrumentDiagnosticAlarm::write_client_user_id_sync(String value) const
{
  try_write_client_user_id_sync(value).value();
}

void InstrumentDiagnosticAlarm::write_event_id_async(
  ByteString value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::event_id_browse_name(),
    "InstrumentDiagnosticAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult InstrumentDiagnosticAlarm::try_write_event_id_sync(ByteString value) const noexcept
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

void InstrumentDiagnosticAlarm::write_event_id_sync(ByteString value) const
{
  try_write_event_id_sync(value).value();
}

void InstrumentDiagnosticAlarm::write_event_type_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::event_type_browse_name(),
    "InstrumentDiagnosticAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult InstrumentDiagnosticAlarm::try_write_event_type_sync(NodeId value) const noexcept
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

void InstrumentDiagnosticAlarm::write_event_type_sync(NodeId value) const
{
  try_write_event_type_sync(value).value();
}

void InstrumentDiagnosticAlarm::write_source_node_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::source_node_browse_name(),
    "InstrumentDiagnosticAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult InstrumentDiagnosticAlarm::try_write_source_node_sync(NodeId value) const noexcept
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

void InstrumentDiagnosticAlarm::write_source_node_sync(NodeId value) const
{
  try_write_source_node_sync(value).value();
}

void InstrumentDiagnosticAlarm::write_source_name_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::source_name_browse_name(),
    "InstrumentDiagnosticAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult InstrumentDiagnosticAlarm::try_write_source_name_sync(String value) const noexcept
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

void InstrumentDiagnosticAlarm::write_source_name_sync(String value) const
{
  try_write_source_name_sync(value).value();
}

void InstrumentDiagnosticAlarm::write_message_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::message_browse_name(),
    "InstrumentDiagnosticAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult InstrumentDiagnosticAlarm::try_write_message_sync(LocalizedText value) const noexcept
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

void InstrumentDiagnosticAlarm::write_message_sync(LocalizedText value) const
{
  try_write_message_sync(value).value();
}

void InstrumentDiagnosticAlarm::write_severity_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    InstrumentDiagnosticAlarmTypeTraits::severity_browse_name(),
    "InstrumentDiagnosticAlarm",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult InstrumentDiagnosticAlarm::try_write_severity_sync(uint16_t value) const noexcept
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

void InstrumentDiagnosticAlarm::write_severity_sync(uint16_t value) const
{
  try_write_severity_sync(value).value();
}

}  // namespace ua
