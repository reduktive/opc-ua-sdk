// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_alarm_condition.h"

#include "ua_instance_utils.h"
#include "ua_sync_wait.h"
#include "ua_to_result.h"
#include "ua_weak_address_space.h"

#include <boost/asio/any_io_executor.hpp>

#include <functional>
#include <tuple>

#include "ua_call_method_result.h"
#include "ua_method_adapter.h"
#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"

namespace ua
{
namespace
{

struct AlarmConditionTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::AlarmConditionType};
  }

  static QualifiedName enabled_state_browse_name()
  {
    return QualifiedName{0, "EnabledState"};
  }

  static QualifiedName active_state_browse_name()
  {
    return QualifiedName{0, "ActiveState"};
  }

  static QualifiedName input_node_browse_name()
  {
    return QualifiedName{0, "InputNode"};
  }

  static QualifiedName suppressed_state_browse_name()
  {
    return QualifiedName{0, "SuppressedState"};
  }

  static QualifiedName out_of_service_state_browse_name()
  {
    return QualifiedName{0, "OutOfServiceState"};
  }

  static QualifiedName shelving_state_browse_name()
  {
    return QualifiedName{0, "ShelvingState"};
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

  static QualifiedName audible_sound_browse_name()
  {
    return QualifiedName{0, "AudibleSound"};
  }

  static QualifiedName silence_state_browse_name()
  {
    return QualifiedName{0, "SilenceState"};
  }

  static QualifiedName on_delay_browse_name()
  {
    return QualifiedName{0, "OnDelay"};
  }

  static QualifiedName off_delay_browse_name()
  {
    return QualifiedName{0, "OffDelay"};
  }

  static QualifiedName first_in_group_flag_browse_name()
  {
    return QualifiedName{0, "FirstInGroupFlag"};
  }

  static QualifiedName first_in_group_browse_name()
  {
    return QualifiedName{0, "FirstInGroup"};
  }

  static QualifiedName latched_state_browse_name()
  {
    return QualifiedName{0, "LatchedState"};
  }

  static QualifiedName re_alarm_time_browse_name()
  {
    return QualifiedName{0, "ReAlarmTime"};
  }

  static QualifiedName re_alarm_repeat_count_browse_name()
  {
    return QualifiedName{0, "ReAlarmRepeatCount"};
  }

  static QualifiedName silence_browse_name()
  {
    return QualifiedName{0, "Silence"};
  }

  static QualifiedName suppress_browse_name()
  {
    return QualifiedName{0, "Suppress"};
  }

  static QualifiedName suppress2_browse_name()
  {
    return QualifiedName{0, "Suppress2"};
  }

  static QualifiedName unsuppress_browse_name()
  {
    return QualifiedName{0, "Unsuppress"};
  }

  static QualifiedName unsuppress2_browse_name()
  {
    return QualifiedName{0, "Unsuppress2"};
  }

  static QualifiedName remove_from_service_browse_name()
  {
    return QualifiedName{0, "RemoveFromService"};
  }

  static QualifiedName remove_from_service2_browse_name()
  {
    return QualifiedName{0, "RemoveFromService2"};
  }

  static QualifiedName place_in_service_browse_name()
  {
    return QualifiedName{0, "PlaceInService"};
  }

  static QualifiedName place_in_service2_browse_name()
  {
    return QualifiedName{0, "PlaceInService2"};
  }

  static QualifiedName reset_browse_name()
  {
    return QualifiedName{0, "Reset"};
  }

  static QualifiedName reset2_browse_name()
  {
    return QualifiedName{0, "Reset2"};
  }

  static QualifiedName get_group_memberships_browse_name()
  {
    return QualifiedName{0, "GetGroupMemberships"};
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

AlarmCondition::AlarmCondition(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void AlarmCondition::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    AlarmConditionTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(AlarmConditionResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(AlarmConditionResult{
        AlarmCondition{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)}, code});
    });
}

AlarmConditionResult AlarmCondition::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<AlarmConditionResult>(addressSpace.executor(),
      [&](std::function<void(AlarmConditionResult)> complete)
      {
        AlarmCondition::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

AlarmCondition AlarmCondition::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void AlarmCondition::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void AlarmCondition::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // AlarmConditionType has subtypes - subtype match.
  instance_utils::attach_subtype_async(addressSpace,
    existingInstance,
    AlarmConditionTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(AlarmConditionResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(AlarmConditionResult{::ua::detail::address_space_gone("AlarmCondition")});
        return;
      }
      complete(AlarmCondition{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

AlarmConditionResult AlarmCondition::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<AlarmConditionResult>(addressSpace.executor(),
      [&](std::function<void(AlarmConditionResult)> complete)
      {
        AlarmCondition::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

AlarmCondition AlarmCondition::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void AlarmCondition::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

void AlarmCondition::silence_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmConditionTypeTraits::silence_browse_name(),
    std::move(complete));
}

MethodAccessorResult AlarmCondition::try_silence_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete) { silence_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor AlarmCondition::silence_method_sync() const
{
  return ::ua::detail::good_value(try_silence_method_sync());
}

void AlarmCondition::suppress_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmConditionTypeTraits::suppress_browse_name(),
    std::move(complete));
}

MethodAccessorResult AlarmCondition::try_suppress_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { suppress_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor AlarmCondition::suppress_method_sync() const
{
  return ::ua::detail::good_value(try_suppress_method_sync());
}

void AlarmCondition::suppress2_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmConditionTypeTraits::suppress2_browse_name(),
    std::move(complete));
}

MethodAccessorResult AlarmCondition::try_suppress2_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { suppress2_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor AlarmCondition::suppress2_method_sync() const
{
  return ::ua::detail::good_value(try_suppress2_method_sync());
}

void AlarmCondition::unsuppress_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmConditionTypeTraits::unsuppress_browse_name(),
    std::move(complete));
}

MethodAccessorResult AlarmCondition::try_unsuppress_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { unsuppress_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor AlarmCondition::unsuppress_method_sync() const
{
  return ::ua::detail::good_value(try_unsuppress_method_sync());
}

void AlarmCondition::unsuppress2_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmConditionTypeTraits::unsuppress2_browse_name(),
    std::move(complete));
}

MethodAccessorResult AlarmCondition::try_unsuppress2_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { unsuppress2_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor AlarmCondition::unsuppress2_method_sync() const
{
  return ::ua::detail::good_value(try_unsuppress2_method_sync());
}

void AlarmCondition::remove_from_service_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmConditionTypeTraits::remove_from_service_browse_name(),
    std::move(complete));
}

MethodAccessorResult AlarmCondition::try_remove_from_service_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { remove_from_service_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor AlarmCondition::remove_from_service_method_sync() const
{
  return ::ua::detail::good_value(try_remove_from_service_method_sync());
}

void AlarmCondition::remove_from_service2_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmConditionTypeTraits::remove_from_service2_browse_name(),
    std::move(complete));
}

MethodAccessorResult AlarmCondition::try_remove_from_service2_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { remove_from_service2_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor AlarmCondition::remove_from_service2_method_sync() const
{
  return ::ua::detail::good_value(try_remove_from_service2_method_sync());
}

void AlarmCondition::place_in_service_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmConditionTypeTraits::place_in_service_browse_name(),
    std::move(complete));
}

MethodAccessorResult AlarmCondition::try_place_in_service_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { place_in_service_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor AlarmCondition::place_in_service_method_sync() const
{
  return ::ua::detail::good_value(try_place_in_service_method_sync());
}

void AlarmCondition::place_in_service2_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmConditionTypeTraits::place_in_service2_browse_name(),
    std::move(complete));
}

MethodAccessorResult AlarmCondition::try_place_in_service2_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { place_in_service2_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor AlarmCondition::place_in_service2_method_sync() const
{
  return ::ua::detail::good_value(try_place_in_service2_method_sync());
}

void AlarmCondition::reset_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmConditionTypeTraits::reset_browse_name(),
    std::move(complete));
}

MethodAccessorResult AlarmCondition::try_reset_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete) { reset_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor AlarmCondition::reset_method_sync() const
{
  return ::ua::detail::good_value(try_reset_method_sync());
}

void AlarmCondition::reset2_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmConditionTypeTraits::reset2_browse_name(),
    std::move(complete));
}

MethodAccessorResult AlarmCondition::try_reset2_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete) { reset2_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor AlarmCondition::reset2_method_sync() const
{
  return ::ua::detail::good_value(try_reset2_method_sync());
}

void AlarmCondition::get_group_memberships_method_async(
  MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmConditionTypeTraits::get_group_memberships_browse_name(),
    std::move(complete));
}

MethodAccessorResult AlarmCondition::try_get_group_memberships_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { get_group_memberships_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor AlarmCondition::get_group_memberships_method_sync() const
{
  return ::ua::detail::good_value(try_get_group_memberships_method_sync());
}

// --- Common property helper ---

void AlarmCondition::find_property_async(
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
    "AlarmCondition",
    std::move(complete));
}

// --- Property accessors ---

void AlarmCondition::input_node_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmConditionTypeTraits::input_node_browse_name(), std::move(complete));
}

PropertyResult AlarmCondition::try_input_node_property_sync() const noexcept
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

Property AlarmCondition::input_node_property_sync() const
{
  return ::ua::detail::good_value(try_input_node_property_sync());
}

void AlarmCondition::suppressed_or_shelved_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmConditionTypeTraits::suppressed_or_shelved_browse_name(), std::move(complete));
}

PropertyResult AlarmCondition::try_suppressed_or_shelved_property_sync() const noexcept
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

Property AlarmCondition::suppressed_or_shelved_property_sync() const
{
  return ::ua::detail::good_value(try_suppressed_or_shelved_property_sync());
}

void AlarmCondition::max_time_shelved_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmConditionTypeTraits::max_time_shelved_browse_name(), std::move(complete));
}

PropertyResult AlarmCondition::try_max_time_shelved_property_sync() const noexcept
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

Property AlarmCondition::max_time_shelved_property_sync() const
{
  return ::ua::detail::good_value(try_max_time_shelved_property_sync());
}

void AlarmCondition::audible_enabled_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmConditionTypeTraits::audible_enabled_browse_name(), std::move(complete));
}

PropertyResult AlarmCondition::try_audible_enabled_property_sync() const noexcept
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

Property AlarmCondition::audible_enabled_property_sync() const
{
  return ::ua::detail::good_value(try_audible_enabled_property_sync());
}

void AlarmCondition::on_delay_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmConditionTypeTraits::on_delay_browse_name(), std::move(complete));
}

PropertyResult AlarmCondition::try_on_delay_property_sync() const noexcept
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

Property AlarmCondition::on_delay_property_sync() const
{
  return ::ua::detail::good_value(try_on_delay_property_sync());
}

void AlarmCondition::off_delay_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmConditionTypeTraits::off_delay_browse_name(), std::move(complete));
}

PropertyResult AlarmCondition::try_off_delay_property_sync() const noexcept
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

Property AlarmCondition::off_delay_property_sync() const
{
  return ::ua::detail::good_value(try_off_delay_property_sync());
}

void AlarmCondition::re_alarm_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmConditionTypeTraits::re_alarm_time_browse_name(), std::move(complete));
}

PropertyResult AlarmCondition::try_re_alarm_time_property_sync() const noexcept
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

Property AlarmCondition::re_alarm_time_property_sync() const
{
  return ::ua::detail::good_value(try_re_alarm_time_property_sync());
}

void AlarmCondition::condition_class_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmConditionTypeTraits::condition_class_id_browse_name(), std::move(complete));
}

PropertyResult AlarmCondition::try_condition_class_id_property_sync() const noexcept
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

Property AlarmCondition::condition_class_id_property_sync() const
{
  return ::ua::detail::good_value(try_condition_class_id_property_sync());
}

void AlarmCondition::condition_class_name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmConditionTypeTraits::condition_class_name_browse_name(), std::move(complete));
}

PropertyResult AlarmCondition::try_condition_class_name_property_sync() const noexcept
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

Property AlarmCondition::condition_class_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_class_name_property_sync());
}

void AlarmCondition::condition_sub_class_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmConditionTypeTraits::condition_sub_class_id_browse_name(), std::move(complete));
}

PropertyResult AlarmCondition::try_condition_sub_class_id_property_sync() const noexcept
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

Property AlarmCondition::condition_sub_class_id_property_sync() const
{
  return ::ua::detail::good_value(try_condition_sub_class_id_property_sync());
}

void AlarmCondition::condition_sub_class_name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmConditionTypeTraits::condition_sub_class_name_browse_name(), std::move(complete));
}

PropertyResult AlarmCondition::try_condition_sub_class_name_property_sync() const noexcept
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

Property AlarmCondition::condition_sub_class_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_sub_class_name_property_sync());
}

void AlarmCondition::condition_name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmConditionTypeTraits::condition_name_browse_name(), std::move(complete));
}

PropertyResult AlarmCondition::try_condition_name_property_sync() const noexcept
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

Property AlarmCondition::condition_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_name_property_sync());
}

void AlarmCondition::branch_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmConditionTypeTraits::branch_id_browse_name(), std::move(complete));
}

PropertyResult AlarmCondition::try_branch_id_property_sync() const noexcept
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

Property AlarmCondition::branch_id_property_sync() const
{
  return ::ua::detail::good_value(try_branch_id_property_sync());
}

void AlarmCondition::retain_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmConditionTypeTraits::retain_browse_name(), std::move(complete));
}

PropertyResult AlarmCondition::try_retain_property_sync() const noexcept
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

Property AlarmCondition::retain_property_sync() const
{
  return ::ua::detail::good_value(try_retain_property_sync());
}

void AlarmCondition::supports_filtered_retain_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmConditionTypeTraits::supports_filtered_retain_browse_name(), std::move(complete));
}

PropertyResult AlarmCondition::try_supports_filtered_retain_property_sync() const noexcept
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

Property AlarmCondition::supports_filtered_retain_property_sync() const
{
  return ::ua::detail::good_value(try_supports_filtered_retain_property_sync());
}

void AlarmCondition::client_user_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmConditionTypeTraits::client_user_id_browse_name(), std::move(complete));
}

PropertyResult AlarmCondition::try_client_user_id_property_sync() const noexcept
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

Property AlarmCondition::client_user_id_property_sync() const
{
  return ::ua::detail::good_value(try_client_user_id_property_sync());
}

void AlarmCondition::event_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmConditionTypeTraits::event_id_browse_name(), std::move(complete));
}

PropertyResult AlarmCondition::try_event_id_property_sync() const noexcept
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

Property AlarmCondition::event_id_property_sync() const
{
  return ::ua::detail::good_value(try_event_id_property_sync());
}

void AlarmCondition::event_type_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmConditionTypeTraits::event_type_browse_name(), std::move(complete));
}

PropertyResult AlarmCondition::try_event_type_property_sync() const noexcept
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

Property AlarmCondition::event_type_property_sync() const
{
  return ::ua::detail::good_value(try_event_type_property_sync());
}

void AlarmCondition::source_node_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmConditionTypeTraits::source_node_browse_name(), std::move(complete));
}

PropertyResult AlarmCondition::try_source_node_property_sync() const noexcept
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

Property AlarmCondition::source_node_property_sync() const
{
  return ::ua::detail::good_value(try_source_node_property_sync());
}

void AlarmCondition::source_name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmConditionTypeTraits::source_name_browse_name(), std::move(complete));
}

PropertyResult AlarmCondition::try_source_name_property_sync() const noexcept
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

Property AlarmCondition::source_name_property_sync() const
{
  return ::ua::detail::good_value(try_source_name_property_sync());
}

void AlarmCondition::time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmConditionTypeTraits::time_browse_name(), std::move(complete));
}

PropertyResult AlarmCondition::try_time_property_sync() const noexcept
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

Property AlarmCondition::time_property_sync() const
{
  return ::ua::detail::good_value(try_time_property_sync());
}

void AlarmCondition::receive_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmConditionTypeTraits::receive_time_browse_name(), std::move(complete));
}

PropertyResult AlarmCondition::try_receive_time_property_sync() const noexcept
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

Property AlarmCondition::receive_time_property_sync() const
{
  return ::ua::detail::good_value(try_receive_time_property_sync());
}

void AlarmCondition::local_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmConditionTypeTraits::local_time_browse_name(), std::move(complete));
}

PropertyResult AlarmCondition::try_local_time_property_sync() const noexcept
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

Property AlarmCondition::local_time_property_sync() const
{
  return ::ua::detail::good_value(try_local_time_property_sync());
}

void AlarmCondition::message_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmConditionTypeTraits::message_browse_name(), std::move(complete));
}

PropertyResult AlarmCondition::try_message_property_sync() const noexcept
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

Property AlarmCondition::message_property_sync() const
{
  return ::ua::detail::good_value(try_message_property_sync());
}

void AlarmCondition::severity_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlarmConditionTypeTraits::severity_browse_name(), std::move(complete));
}

PropertyResult AlarmCondition::try_severity_property_sync() const noexcept
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

Property AlarmCondition::severity_property_sync() const
{
  return ::ua::detail::good_value(try_severity_property_sync());
}

// --- Typed value read shortcuts ---

void AlarmCondition::read_input_node_async(std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::input_node_browse_name(),
    &Variant::is_node_id,
    {"AlarmCondition", "input_node", "AlarmCondition::read_input_node_async"},
    std::move(complete));
}

NodeIdResult AlarmCondition::try_read_input_node_sync() const noexcept
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

NodeId AlarmCondition::read_input_node_sync() const
{
  return ::ua::detail::good_value(try_read_input_node_sync());
}

void AlarmCondition::read_suppressed_or_shelved_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::suppressed_or_shelved_browse_name(),
    &Variant::is_boolean,
    {"AlarmCondition", "suppressed_or_shelved", "AlarmCondition::read_suppressed_or_shelved_async"},
    std::move(complete));
}

BoolResult AlarmCondition::try_read_suppressed_or_shelved_sync() const noexcept
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

bool AlarmCondition::read_suppressed_or_shelved_sync() const
{
  return ::ua::detail::good_value(try_read_suppressed_or_shelved_sync());
}

void AlarmCondition::read_audible_enabled_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::audible_enabled_browse_name(),
    &Variant::is_boolean,
    {"AlarmCondition", "audible_enabled", "AlarmCondition::read_audible_enabled_async"},
    std::move(complete));
}

BoolResult AlarmCondition::try_read_audible_enabled_sync() const noexcept
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

bool AlarmCondition::read_audible_enabled_sync() const
{
  return ::ua::detail::good_value(try_read_audible_enabled_sync());
}

void AlarmCondition::read_condition_class_id_async(std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::condition_class_id_browse_name(),
    &Variant::is_node_id,
    {"AlarmCondition", "condition_class_id", "AlarmCondition::read_condition_class_id_async"},
    std::move(complete));
}

NodeIdResult AlarmCondition::try_read_condition_class_id_sync() const noexcept
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

NodeId AlarmCondition::read_condition_class_id_sync() const
{
  return ::ua::detail::good_value(try_read_condition_class_id_sync());
}

void AlarmCondition::read_condition_class_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::condition_class_name_browse_name(),
    &Variant::is_localized_text,
    {"AlarmCondition", "condition_class_name", "AlarmCondition::read_condition_class_name_async"},
    std::move(complete));
}

LocalizedTextResult AlarmCondition::try_read_condition_class_name_sync() const noexcept
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

LocalizedText AlarmCondition::read_condition_class_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_class_name_sync());
}

void AlarmCondition::read_condition_sub_class_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::condition_sub_class_id_browse_name(),
    &Variant::is_node_id,
    {"AlarmCondition", "condition_sub_class_id", "AlarmCondition::read_condition_sub_class_id_async"},
    std::move(complete));
}

NodeIdResult AlarmCondition::try_read_condition_sub_class_id_sync() const noexcept
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

NodeId AlarmCondition::read_condition_sub_class_id_sync() const
{
  return ::ua::detail::good_value(try_read_condition_sub_class_id_sync());
}

void AlarmCondition::read_condition_sub_class_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::condition_sub_class_name_browse_name(),
    &Variant::is_localized_text,
    {"AlarmCondition", "condition_sub_class_name", "AlarmCondition::read_condition_sub_class_name_async"},
    std::move(complete));
}

LocalizedTextResult AlarmCondition::try_read_condition_sub_class_name_sync() const noexcept
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

LocalizedText AlarmCondition::read_condition_sub_class_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_sub_class_name_sync());
}

void AlarmCondition::read_condition_name_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::condition_name_browse_name(),
    &Variant::is_string,
    {"AlarmCondition", "condition_name", "AlarmCondition::read_condition_name_async"},
    std::move(complete));
}

StringResult AlarmCondition::try_read_condition_name_sync() const noexcept
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

String AlarmCondition::read_condition_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_name_sync());
}

void AlarmCondition::read_branch_id_async(std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::branch_id_browse_name(),
    &Variant::is_node_id,
    {"AlarmCondition", "branch_id", "AlarmCondition::read_branch_id_async"},
    std::move(complete));
}

NodeIdResult AlarmCondition::try_read_branch_id_sync() const noexcept
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

NodeId AlarmCondition::read_branch_id_sync() const
{
  return ::ua::detail::good_value(try_read_branch_id_sync());
}

void AlarmCondition::read_retain_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::retain_browse_name(),
    &Variant::is_boolean,
    {"AlarmCondition", "retain", "AlarmCondition::read_retain_async"},
    std::move(complete));
}

BoolResult AlarmCondition::try_read_retain_sync() const noexcept
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

bool AlarmCondition::read_retain_sync() const
{
  return ::ua::detail::good_value(try_read_retain_sync());
}

void AlarmCondition::read_supports_filtered_retain_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::supports_filtered_retain_browse_name(),
    &Variant::is_boolean,
    {"AlarmCondition", "supports_filtered_retain", "AlarmCondition::read_supports_filtered_retain_async"},
    std::move(complete));
}

BoolResult AlarmCondition::try_read_supports_filtered_retain_sync() const noexcept
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

bool AlarmCondition::read_supports_filtered_retain_sync() const
{
  return ::ua::detail::good_value(try_read_supports_filtered_retain_sync());
}

void AlarmCondition::read_client_user_id_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::client_user_id_browse_name(),
    &Variant::is_string,
    {"AlarmCondition", "client_user_id", "AlarmCondition::read_client_user_id_async"},
    std::move(complete));
}

StringResult AlarmCondition::try_read_client_user_id_sync() const noexcept
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

String AlarmCondition::read_client_user_id_sync() const
{
  return ::ua::detail::good_value(try_read_client_user_id_sync());
}

void AlarmCondition::read_event_id_async(std::function<void(ByteStringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(ByteStringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<ByteString>(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::event_id_browse_name(),
    &Variant::is_byte_string,
    {"AlarmCondition", "event_id", "AlarmCondition::read_event_id_async"},
    std::move(complete));
}

ByteStringResult AlarmCondition::try_read_event_id_sync() const noexcept
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

ByteString AlarmCondition::read_event_id_sync() const
{
  return ::ua::detail::good_value(try_read_event_id_sync());
}

void AlarmCondition::read_event_type_async(std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::event_type_browse_name(),
    &Variant::is_node_id,
    {"AlarmCondition", "event_type", "AlarmCondition::read_event_type_async"},
    std::move(complete));
}

NodeIdResult AlarmCondition::try_read_event_type_sync() const noexcept
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

NodeId AlarmCondition::read_event_type_sync() const
{
  return ::ua::detail::good_value(try_read_event_type_sync());
}

void AlarmCondition::read_source_node_async(std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::source_node_browse_name(),
    &Variant::is_node_id,
    {"AlarmCondition", "source_node", "AlarmCondition::read_source_node_async"},
    std::move(complete));
}

NodeIdResult AlarmCondition::try_read_source_node_sync() const noexcept
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

NodeId AlarmCondition::read_source_node_sync() const
{
  return ::ua::detail::good_value(try_read_source_node_sync());
}

void AlarmCondition::read_source_name_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::source_name_browse_name(),
    &Variant::is_string,
    {"AlarmCondition", "source_name", "AlarmCondition::read_source_name_async"},
    std::move(complete));
}

StringResult AlarmCondition::try_read_source_name_sync() const noexcept
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

String AlarmCondition::read_source_name_sync() const
{
  return ::ua::detail::good_value(try_read_source_name_sync());
}

void AlarmCondition::read_message_async(std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::message_browse_name(),
    &Variant::is_localized_text,
    {"AlarmCondition", "message", "AlarmCondition::read_message_async"},
    std::move(complete));
}

LocalizedTextResult AlarmCondition::try_read_message_sync() const noexcept
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

LocalizedText AlarmCondition::read_message_sync() const
{
  return ::ua::detail::good_value(try_read_message_sync());
}

void AlarmCondition::read_severity_async(std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::severity_browse_name(),
    &Variant::is_uint16,
    {"AlarmCondition", "severity", "AlarmCondition::read_severity_async"},
    std::move(complete));
}

UInt16Result AlarmCondition::try_read_severity_sync() const noexcept
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

uint16_t AlarmCondition::read_severity_sync() const
{
  return ::ua::detail::good_value(try_read_severity_sync());
}

// --- Typed value write shortcuts ---

void AlarmCondition::write_input_node_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::input_node_browse_name(),
    "AlarmCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlarmCondition::try_write_input_node_sync(NodeId value) const noexcept
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

void AlarmCondition::write_input_node_sync(NodeId value) const
{
  try_write_input_node_sync(value).value();
}

void AlarmCondition::write_suppressed_or_shelved_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::suppressed_or_shelved_browse_name(),
    "AlarmCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlarmCondition::try_write_suppressed_or_shelved_sync(bool value) const noexcept
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

void AlarmCondition::write_suppressed_or_shelved_sync(bool value) const
{
  try_write_suppressed_or_shelved_sync(value).value();
}

void AlarmCondition::write_audible_enabled_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::audible_enabled_browse_name(),
    "AlarmCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlarmCondition::try_write_audible_enabled_sync(bool value) const noexcept
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

void AlarmCondition::write_audible_enabled_sync(bool value) const
{
  try_write_audible_enabled_sync(value).value();
}

void AlarmCondition::write_condition_class_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::condition_class_id_browse_name(),
    "AlarmCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlarmCondition::try_write_condition_class_id_sync(NodeId value) const noexcept
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

void AlarmCondition::write_condition_class_id_sync(NodeId value) const
{
  try_write_condition_class_id_sync(value).value();
}

void AlarmCondition::write_condition_class_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::condition_class_name_browse_name(),
    "AlarmCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlarmCondition::try_write_condition_class_name_sync(LocalizedText value) const noexcept
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

void AlarmCondition::write_condition_class_name_sync(LocalizedText value) const
{
  try_write_condition_class_name_sync(value).value();
}

void AlarmCondition::write_condition_sub_class_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::condition_sub_class_id_browse_name(),
    "AlarmCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlarmCondition::try_write_condition_sub_class_id_sync(NodeId value) const noexcept
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

void AlarmCondition::write_condition_sub_class_id_sync(NodeId value) const
{
  try_write_condition_sub_class_id_sync(value).value();
}

void AlarmCondition::write_condition_sub_class_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::condition_sub_class_name_browse_name(),
    "AlarmCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlarmCondition::try_write_condition_sub_class_name_sync(LocalizedText value) const noexcept
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

void AlarmCondition::write_condition_sub_class_name_sync(LocalizedText value) const
{
  try_write_condition_sub_class_name_sync(value).value();
}

void AlarmCondition::write_condition_name_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::condition_name_browse_name(),
    "AlarmCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlarmCondition::try_write_condition_name_sync(String value) const noexcept
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

void AlarmCondition::write_condition_name_sync(String value) const
{
  try_write_condition_name_sync(value).value();
}

void AlarmCondition::write_branch_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::branch_id_browse_name(),
    "AlarmCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlarmCondition::try_write_branch_id_sync(NodeId value) const noexcept
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

void AlarmCondition::write_branch_id_sync(NodeId value) const
{
  try_write_branch_id_sync(value).value();
}

void AlarmCondition::write_retain_async(bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::retain_browse_name(),
    "AlarmCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlarmCondition::try_write_retain_sync(bool value) const noexcept
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

void AlarmCondition::write_retain_sync(bool value) const
{
  try_write_retain_sync(value).value();
}

void AlarmCondition::write_supports_filtered_retain_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::supports_filtered_retain_browse_name(),
    "AlarmCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlarmCondition::try_write_supports_filtered_retain_sync(bool value) const noexcept
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

void AlarmCondition::write_supports_filtered_retain_sync(bool value) const
{
  try_write_supports_filtered_retain_sync(value).value();
}

void AlarmCondition::write_client_user_id_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::client_user_id_browse_name(),
    "AlarmCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlarmCondition::try_write_client_user_id_sync(String value) const noexcept
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

void AlarmCondition::write_client_user_id_sync(String value) const
{
  try_write_client_user_id_sync(value).value();
}

void AlarmCondition::write_event_id_async(
  ByteString value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::event_id_browse_name(),
    "AlarmCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlarmCondition::try_write_event_id_sync(ByteString value) const noexcept
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

void AlarmCondition::write_event_id_sync(ByteString value) const
{
  try_write_event_id_sync(value).value();
}

void AlarmCondition::write_event_type_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::event_type_browse_name(),
    "AlarmCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlarmCondition::try_write_event_type_sync(NodeId value) const noexcept
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

void AlarmCondition::write_event_type_sync(NodeId value) const
{
  try_write_event_type_sync(value).value();
}

void AlarmCondition::write_source_node_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::source_node_browse_name(),
    "AlarmCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlarmCondition::try_write_source_node_sync(NodeId value) const noexcept
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

void AlarmCondition::write_source_node_sync(NodeId value) const
{
  try_write_source_node_sync(value).value();
}

void AlarmCondition::write_source_name_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::source_name_browse_name(),
    "AlarmCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlarmCondition::try_write_source_name_sync(String value) const noexcept
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

void AlarmCondition::write_source_name_sync(String value) const
{
  try_write_source_name_sync(value).value();
}

void AlarmCondition::write_message_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::message_browse_name(),
    "AlarmCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlarmCondition::try_write_message_sync(LocalizedText value) const noexcept
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

void AlarmCondition::write_message_sync(LocalizedText value) const
{
  try_write_message_sync(value).value();
}

void AlarmCondition::write_severity_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlarmConditionTypeTraits::severity_browse_name(),
    "AlarmCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlarmCondition::try_write_severity_sync(uint16_t value) const noexcept
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

void AlarmCondition::write_severity_sync(uint16_t value) const
{
  try_write_severity_sync(value).value();
}

// --- Method handler registration ---

void AlarmCondition::set_silence_handler_async(
  SilenceHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AlarmCondition",
        "AlarmCondition::set_silence_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call) -> MethodResult<> { return handler(call); },
      Inputs<>{},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, AlarmConditionTypeTraits::silence_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AlarmCondition::try_set_silence_handler_sync(SilenceHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_silence_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmCondition::set_silence_handler_sync(SilenceHandler handler) const
{
  try_set_silence_handler_sync(std::move(handler)).value();
}

void AlarmCondition::set_silence_handler_async(
  SilenceAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AlarmCondition",
        "AlarmCondition::set_silence_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, MethodResultCallback<> complete) { handler(call, std::move(complete)); },
      Inputs<>{},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, AlarmConditionTypeTraits::silence_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AlarmCondition::try_set_silence_handler_sync(SilenceAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_silence_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmCondition::set_silence_handler_sync(SilenceAsyncHandler handler) const
{
  try_set_silence_handler_sync(std::move(handler)).value();
}

void AlarmCondition::set_suppress_handler_async(
  SuppressHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AlarmCondition",
        "AlarmCondition::set_suppress_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call) -> MethodResult<> { return handler(call); },
      Inputs<>{},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, AlarmConditionTypeTraits::suppress_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AlarmCondition::try_set_suppress_handler_sync(SuppressHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_suppress_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmCondition::set_suppress_handler_sync(SuppressHandler handler) const
{
  try_set_suppress_handler_sync(std::move(handler)).value();
}

void AlarmCondition::set_suppress_handler_async(
  SuppressAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AlarmCondition",
        "AlarmCondition::set_suppress_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, MethodResultCallback<> complete) { handler(call, std::move(complete)); },
      Inputs<>{},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, AlarmConditionTypeTraits::suppress_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AlarmCondition::try_set_suppress_handler_sync(SuppressAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_suppress_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmCondition::set_suppress_handler_sync(SuppressAsyncHandler handler) const
{
  try_set_suppress_handler_sync(std::move(handler)).value();
}

void AlarmCondition::set_suppress2_handler_async(
  Suppress2Handler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AlarmCondition",
        "AlarmCondition::set_suppress2_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<LocalizedText>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const LocalizedText& in0) -> MethodResult<>
      {
        Suppress2InputArguments typedIn{.comment = in0};
        return handler(call, typedIn);
      },
      Inputs<LocalizedText>{{Arg<LocalizedText>{.name = "Comment"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, AlarmConditionTypeTraits::suppress2_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AlarmCondition::try_set_suppress2_handler_sync(Suppress2Handler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_suppress2_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmCondition::set_suppress2_handler_sync(Suppress2Handler handler) const
{
  try_set_suppress2_handler_sync(std::move(handler)).value();
}

void AlarmCondition::set_suppress2_handler_async(
  Suppress2AsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AlarmCondition",
        "AlarmCondition::set_suppress2_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<LocalizedText>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const LocalizedText& in0, MethodResultCallback<> complete)
      {
        Suppress2InputArguments typedIn{.comment = in0};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<LocalizedText>{{Arg<LocalizedText>{.name = "Comment"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, AlarmConditionTypeTraits::suppress2_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AlarmCondition::try_set_suppress2_handler_sync(Suppress2AsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_suppress2_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmCondition::set_suppress2_handler_sync(Suppress2AsyncHandler handler) const
{
  try_set_suppress2_handler_sync(std::move(handler)).value();
}

void AlarmCondition::set_unsuppress_handler_async(
  UnsuppressHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AlarmCondition",
        "AlarmCondition::set_unsuppress_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call) -> MethodResult<> { return handler(call); },
      Inputs<>{},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, AlarmConditionTypeTraits::unsuppress_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AlarmCondition::try_set_unsuppress_handler_sync(UnsuppressHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_unsuppress_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmCondition::set_unsuppress_handler_sync(UnsuppressHandler handler) const
{
  try_set_unsuppress_handler_sync(std::move(handler)).value();
}

void AlarmCondition::set_unsuppress_handler_async(
  UnsuppressAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AlarmCondition",
        "AlarmCondition::set_unsuppress_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, MethodResultCallback<> complete) { handler(call, std::move(complete)); },
      Inputs<>{},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, AlarmConditionTypeTraits::unsuppress_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AlarmCondition::try_set_unsuppress_handler_sync(UnsuppressAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_unsuppress_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmCondition::set_unsuppress_handler_sync(UnsuppressAsyncHandler handler) const
{
  try_set_unsuppress_handler_sync(std::move(handler)).value();
}

void AlarmCondition::set_unsuppress2_handler_async(
  Unsuppress2Handler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AlarmCondition",
        "AlarmCondition::set_unsuppress2_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<LocalizedText>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const LocalizedText& in0) -> MethodResult<>
      {
        Unsuppress2InputArguments typedIn{.comment = in0};
        return handler(call, typedIn);
      },
      Inputs<LocalizedText>{{Arg<LocalizedText>{.name = "Comment"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, AlarmConditionTypeTraits::unsuppress2_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AlarmCondition::try_set_unsuppress2_handler_sync(Unsuppress2Handler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_unsuppress2_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmCondition::set_unsuppress2_handler_sync(Unsuppress2Handler handler) const
{
  try_set_unsuppress2_handler_sync(std::move(handler)).value();
}

void AlarmCondition::set_unsuppress2_handler_async(
  Unsuppress2AsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AlarmCondition",
        "AlarmCondition::set_unsuppress2_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<LocalizedText>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const LocalizedText& in0, MethodResultCallback<> complete)
      {
        Unsuppress2InputArguments typedIn{.comment = in0};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<LocalizedText>{{Arg<LocalizedText>{.name = "Comment"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, AlarmConditionTypeTraits::unsuppress2_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AlarmCondition::try_set_unsuppress2_handler_sync(Unsuppress2AsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_unsuppress2_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmCondition::set_unsuppress2_handler_sync(Unsuppress2AsyncHandler handler) const
{
  try_set_unsuppress2_handler_sync(std::move(handler)).value();
}

void AlarmCondition::set_remove_from_service_handler_async(
  RemoveFromServiceHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AlarmCondition",
        "AlarmCondition::set_remove_from_service_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call) -> MethodResult<> { return handler(call); },
      Inputs<>{},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      AlarmConditionTypeTraits::remove_from_service_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AlarmCondition::try_set_remove_from_service_handler_sync(
  RemoveFromServiceHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_remove_from_service_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmCondition::set_remove_from_service_handler_sync(RemoveFromServiceHandler handler) const
{
  try_set_remove_from_service_handler_sync(std::move(handler)).value();
}

void AlarmCondition::set_remove_from_service_handler_async(
  RemoveFromServiceAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AlarmCondition",
        "AlarmCondition::set_remove_from_service_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, MethodResultCallback<> complete) { handler(call, std::move(complete)); },
      Inputs<>{},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      AlarmConditionTypeTraits::remove_from_service_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AlarmCondition::try_set_remove_from_service_handler_sync(
  RemoveFromServiceAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_remove_from_service_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmCondition::set_remove_from_service_handler_sync(RemoveFromServiceAsyncHandler handler) const
{
  try_set_remove_from_service_handler_sync(std::move(handler)).value();
}

void AlarmCondition::set_remove_from_service2_handler_async(
  RemoveFromService2Handler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AlarmCondition",
        "AlarmCondition::set_remove_from_service2_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<LocalizedText>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const LocalizedText& in0) -> MethodResult<>
      {
        RemoveFromService2InputArguments typedIn{.comment = in0};
        return handler(call, typedIn);
      },
      Inputs<LocalizedText>{{Arg<LocalizedText>{.name = "Comment"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      AlarmConditionTypeTraits::remove_from_service2_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AlarmCondition::try_set_remove_from_service2_handler_sync(
  RemoveFromService2Handler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_remove_from_service2_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmCondition::set_remove_from_service2_handler_sync(RemoveFromService2Handler handler) const
{
  try_set_remove_from_service2_handler_sync(std::move(handler)).value();
}

void AlarmCondition::set_remove_from_service2_handler_async(
  RemoveFromService2AsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AlarmCondition",
        "AlarmCondition::set_remove_from_service2_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<LocalizedText>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const LocalizedText& in0, MethodResultCallback<> complete)
      {
        RemoveFromService2InputArguments typedIn{.comment = in0};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<LocalizedText>{{Arg<LocalizedText>{.name = "Comment"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      AlarmConditionTypeTraits::remove_from_service2_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AlarmCondition::try_set_remove_from_service2_handler_sync(
  RemoveFromService2AsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_remove_from_service2_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmCondition::set_remove_from_service2_handler_sync(RemoveFromService2AsyncHandler handler) const
{
  try_set_remove_from_service2_handler_sync(std::move(handler)).value();
}

void AlarmCondition::set_place_in_service_handler_async(
  PlaceInServiceHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AlarmCondition",
        "AlarmCondition::set_place_in_service_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call) -> MethodResult<> { return handler(call); },
      Inputs<>{},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      AlarmConditionTypeTraits::place_in_service_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AlarmCondition::try_set_place_in_service_handler_sync(PlaceInServiceHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_place_in_service_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmCondition::set_place_in_service_handler_sync(PlaceInServiceHandler handler) const
{
  try_set_place_in_service_handler_sync(std::move(handler)).value();
}

void AlarmCondition::set_place_in_service_handler_async(
  PlaceInServiceAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AlarmCondition",
        "AlarmCondition::set_place_in_service_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, MethodResultCallback<> complete) { handler(call, std::move(complete)); },
      Inputs<>{},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      AlarmConditionTypeTraits::place_in_service_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AlarmCondition::try_set_place_in_service_handler_sync(
  PlaceInServiceAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_place_in_service_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmCondition::set_place_in_service_handler_sync(PlaceInServiceAsyncHandler handler) const
{
  try_set_place_in_service_handler_sync(std::move(handler)).value();
}

void AlarmCondition::set_place_in_service2_handler_async(
  PlaceInService2Handler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AlarmCondition",
        "AlarmCondition::set_place_in_service2_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<LocalizedText>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const LocalizedText& in0) -> MethodResult<>
      {
        PlaceInService2InputArguments typedIn{.comment = in0};
        return handler(call, typedIn);
      },
      Inputs<LocalizedText>{{Arg<LocalizedText>{.name = "Comment"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      AlarmConditionTypeTraits::place_in_service2_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AlarmCondition::try_set_place_in_service2_handler_sync(
  PlaceInService2Handler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_place_in_service2_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmCondition::set_place_in_service2_handler_sync(PlaceInService2Handler handler) const
{
  try_set_place_in_service2_handler_sync(std::move(handler)).value();
}

void AlarmCondition::set_place_in_service2_handler_async(
  PlaceInService2AsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AlarmCondition",
        "AlarmCondition::set_place_in_service2_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<LocalizedText>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const LocalizedText& in0, MethodResultCallback<> complete)
      {
        PlaceInService2InputArguments typedIn{.comment = in0};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<LocalizedText>{{Arg<LocalizedText>{.name = "Comment"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      AlarmConditionTypeTraits::place_in_service2_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AlarmCondition::try_set_place_in_service2_handler_sync(
  PlaceInService2AsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_place_in_service2_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmCondition::set_place_in_service2_handler_sync(PlaceInService2AsyncHandler handler) const
{
  try_set_place_in_service2_handler_sync(std::move(handler)).value();
}

void AlarmCondition::set_reset_handler_async(
  ResetHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AlarmCondition",
        "AlarmCondition::set_reset_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call) -> MethodResult<> { return handler(call); },
      Inputs<>{},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, AlarmConditionTypeTraits::reset_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AlarmCondition::try_set_reset_handler_sync(ResetHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_reset_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmCondition::set_reset_handler_sync(ResetHandler handler) const
{
  try_set_reset_handler_sync(std::move(handler)).value();
}

void AlarmCondition::set_reset_handler_async(
  ResetAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AlarmCondition",
        "AlarmCondition::set_reset_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, MethodResultCallback<> complete) { handler(call, std::move(complete)); },
      Inputs<>{},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, AlarmConditionTypeTraits::reset_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AlarmCondition::try_set_reset_handler_sync(ResetAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_reset_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmCondition::set_reset_handler_sync(ResetAsyncHandler handler) const
{
  try_set_reset_handler_sync(std::move(handler)).value();
}

void AlarmCondition::set_reset2_handler_async(
  Reset2Handler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AlarmCondition",
        "AlarmCondition::set_reset2_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<LocalizedText>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const LocalizedText& in0) -> MethodResult<>
      {
        Reset2InputArguments typedIn{.comment = in0};
        return handler(call, typedIn);
      },
      Inputs<LocalizedText>{{Arg<LocalizedText>{.name = "Comment"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, AlarmConditionTypeTraits::reset2_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AlarmCondition::try_set_reset2_handler_sync(Reset2Handler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_reset2_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmCondition::set_reset2_handler_sync(Reset2Handler handler) const
{
  try_set_reset2_handler_sync(std::move(handler)).value();
}

void AlarmCondition::set_reset2_handler_async(
  Reset2AsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AlarmCondition",
        "AlarmCondition::set_reset2_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<LocalizedText>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const LocalizedText& in0, MethodResultCallback<> complete)
      {
        Reset2InputArguments typedIn{.comment = in0};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<LocalizedText>{{Arg<LocalizedText>{.name = "Comment"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, AlarmConditionTypeTraits::reset2_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AlarmCondition::try_set_reset2_handler_sync(Reset2AsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_reset2_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmCondition::set_reset2_handler_sync(Reset2AsyncHandler handler) const
{
  try_set_reset2_handler_sync(std::move(handler)).value();
}

void AlarmCondition::set_get_group_memberships_handler_async(
  GetGroupMembershipsHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AlarmCondition",
        "AlarmCondition::set_get_group_memberships_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<>, std::tuple<std::vector<NodeId>>> adapter{
      [handler = std::move(handler)](const MethodCall& call) -> MethodResult<std::vector<NodeId>>
      {
        return detail::method_result_from_struct<std::vector<NodeId>>(handler(call),
          [](const GetGroupMembershipsOutputArguments& out)
          { return std::tuple<std::vector<NodeId>>{out.groups}; });
      },
      Inputs<>{},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      AlarmConditionTypeTraits::get_group_memberships_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AlarmCondition::try_set_get_group_memberships_handler_sync(
  GetGroupMembershipsHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_get_group_memberships_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmCondition::set_get_group_memberships_handler_sync(GetGroupMembershipsHandler handler) const
{
  try_set_get_group_memberships_handler_sync(std::move(handler)).value();
}

void AlarmCondition::set_get_group_memberships_handler_async(
  GetGroupMembershipsAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AlarmCondition",
        "AlarmCondition::set_get_group_memberships_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<>, std::tuple<std::vector<NodeId>>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, MethodResultCallback<std::vector<NodeId>> complete)
      {
        handler(call,
          detail::struct_method_result_callback<GetGroupMembershipsOutputArguments>(
            std::move(complete),
            [](const GetGroupMembershipsOutputArguments& out)
            { return std::tuple<std::vector<NodeId>>{out.groups}; },
            logger,
            call.method_id()));
      },
      Inputs<>{},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      AlarmConditionTypeTraits::get_group_memberships_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AlarmCondition::try_set_get_group_memberships_handler_sync(
  GetGroupMembershipsAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_get_group_memberships_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlarmCondition::set_get_group_memberships_handler_sync(GetGroupMembershipsAsyncHandler handler) const
{
  try_set_get_group_memberships_handler_sync(std::move(handler)).value();
}

// --- Child-object accessors ---

void AlarmCondition::enabled_state_async(std::function<void(TwoStateVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TwoStateVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<TwoStateVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmConditionTypeTraits::enabled_state_browse_name(),
    "AlarmCondition",
    std::move(complete));
}

TwoStateVariableResult AlarmCondition::try_enabled_state_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TwoStateVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TwoStateVariableResult)> complete)
      { enabled_state_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TwoStateVariable AlarmCondition::enabled_state_sync() const
{
  return ::ua::detail::good_value(try_enabled_state_sync());
}

void AlarmCondition::active_state_async(std::function<void(TwoStateVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TwoStateVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<TwoStateVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmConditionTypeTraits::active_state_browse_name(),
    "AlarmCondition",
    std::move(complete));
}

TwoStateVariableResult AlarmCondition::try_active_state_sync() const noexcept
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

TwoStateVariable AlarmCondition::active_state_sync() const
{
  return ::ua::detail::good_value(try_active_state_sync());
}

void AlarmCondition::suppressed_state_async(
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
    AlarmConditionTypeTraits::suppressed_state_browse_name(),
    "AlarmCondition",
    std::move(complete));
}

TwoStateVariableResult AlarmCondition::try_suppressed_state_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TwoStateVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TwoStateVariableResult)> complete)
      { suppressed_state_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TwoStateVariable AlarmCondition::suppressed_state_sync() const
{
  return ::ua::detail::good_value(try_suppressed_state_sync());
}

void AlarmCondition::out_of_service_state_async(
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
    AlarmConditionTypeTraits::out_of_service_state_browse_name(),
    "AlarmCondition",
    std::move(complete));
}

TwoStateVariableResult AlarmCondition::try_out_of_service_state_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TwoStateVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TwoStateVariableResult)> complete)
      { out_of_service_state_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TwoStateVariable AlarmCondition::out_of_service_state_sync() const
{
  return ::ua::detail::good_value(try_out_of_service_state_sync());
}

void AlarmCondition::shelving_state_async(
  std::function<void(ShelvedStateMachineResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(ShelvedStateMachineResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<ShelvedStateMachine>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmConditionTypeTraits::shelving_state_browse_name(),
    "AlarmCondition",
    std::move(complete));
}

ShelvedStateMachineResult AlarmCondition::try_shelving_state_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ShelvedStateMachineResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(ShelvedStateMachineResult)> complete)
      { shelving_state_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ShelvedStateMachine AlarmCondition::shelving_state_sync() const
{
  return ::ua::detail::good_value(try_shelving_state_sync());
}

void AlarmCondition::audible_sound_async(std::function<void(AudioVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(AudioVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<AudioVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmConditionTypeTraits::audible_sound_browse_name(),
    "AlarmCondition",
    std::move(complete));
}

AudioVariableResult AlarmCondition::try_audible_sound_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<AudioVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(AudioVariableResult)> complete) { audible_sound_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

AudioVariable AlarmCondition::audible_sound_sync() const
{
  return ::ua::detail::good_value(try_audible_sound_sync());
}

void AlarmCondition::silence_state_async(std::function<void(TwoStateVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TwoStateVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<TwoStateVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmConditionTypeTraits::silence_state_browse_name(),
    "AlarmCondition",
    std::move(complete));
}

TwoStateVariableResult AlarmCondition::try_silence_state_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TwoStateVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TwoStateVariableResult)> complete)
      { silence_state_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TwoStateVariable AlarmCondition::silence_state_sync() const
{
  return ::ua::detail::good_value(try_silence_state_sync());
}

void AlarmCondition::first_in_group_flag_async(
  std::function<void(BaseDataVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BaseDataVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<BaseDataVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmConditionTypeTraits::first_in_group_flag_browse_name(),
    "AlarmCondition",
    std::move(complete));
}

BaseDataVariableResult AlarmCondition::try_first_in_group_flag_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { first_in_group_flag_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable AlarmCondition::first_in_group_flag_sync() const
{
  return ::ua::detail::good_value(try_first_in_group_flag_sync());
}

void AlarmCondition::first_in_group_async(std::function<void(AlarmGroupResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(AlarmGroupResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<AlarmGroup>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmConditionTypeTraits::first_in_group_browse_name(),
    "AlarmCondition",
    std::move(complete));
}

AlarmGroupResult AlarmCondition::try_first_in_group_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<AlarmGroupResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(AlarmGroupResult)> complete) { first_in_group_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

AlarmGroup AlarmCondition::first_in_group_sync() const
{
  return ::ua::detail::good_value(try_first_in_group_sync());
}

void AlarmCondition::latched_state_async(std::function<void(TwoStateVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TwoStateVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<TwoStateVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmConditionTypeTraits::latched_state_browse_name(),
    "AlarmCondition",
    std::move(complete));
}

TwoStateVariableResult AlarmCondition::try_latched_state_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TwoStateVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TwoStateVariableResult)> complete)
      { latched_state_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TwoStateVariable AlarmCondition::latched_state_sync() const
{
  return ::ua::detail::good_value(try_latched_state_sync());
}

void AlarmCondition::re_alarm_repeat_count_async(
  std::function<void(BaseDataVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BaseDataVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<BaseDataVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AlarmConditionTypeTraits::re_alarm_repeat_count_browse_name(),
    "AlarmCondition",
    std::move(complete));
}

BaseDataVariableResult AlarmCondition::try_re_alarm_repeat_count_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { re_alarm_repeat_count_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable AlarmCondition::re_alarm_repeat_count_sync() const
{
  return ::ua::detail::good_value(try_re_alarm_repeat_count_sync());
}

}  // namespace ua
