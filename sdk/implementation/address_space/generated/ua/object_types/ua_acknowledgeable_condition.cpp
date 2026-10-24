// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_acknowledgeable_condition.h"

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

struct AcknowledgeableConditionTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::AcknowledgeableConditionType};
  }

  static QualifiedName enabled_state_browse_name()
  {
    return QualifiedName{0, "EnabledState"};
  }

  static QualifiedName acked_state_browse_name()
  {
    return QualifiedName{0, "AckedState"};
  }

  static QualifiedName confirmed_state_browse_name()
  {
    return QualifiedName{0, "ConfirmedState"};
  }

  static QualifiedName acknowledge_browse_name()
  {
    return QualifiedName{0, "Acknowledge"};
  }

  static QualifiedName confirm_browse_name()
  {
    return QualifiedName{0, "Confirm"};
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

AcknowledgeableCondition::AcknowledgeableCondition(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void AcknowledgeableCondition::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    AcknowledgeableConditionTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(AcknowledgeableConditionResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(AcknowledgeableConditionResult{
        AcknowledgeableCondition{
          std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

AcknowledgeableConditionResult AcknowledgeableCondition::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<AcknowledgeableConditionResult>(addressSpace.executor(),
      [&](std::function<void(AcknowledgeableConditionResult)> complete)
      {
        AcknowledgeableCondition::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

AcknowledgeableCondition AcknowledgeableCondition::create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void AcknowledgeableCondition::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void AcknowledgeableCondition::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // AcknowledgeableConditionType has subtypes - subtype match.
  instance_utils::attach_subtype_async(addressSpace,
    existingInstance,
    AcknowledgeableConditionTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(AcknowledgeableConditionResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(
          AcknowledgeableConditionResult{::ua::detail::address_space_gone("AcknowledgeableCondition")});
        return;
      }
      complete(
        AcknowledgeableCondition{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

AcknowledgeableConditionResult AcknowledgeableCondition::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<AcknowledgeableConditionResult>(addressSpace.executor(),
      [&](std::function<void(AcknowledgeableConditionResult)> complete)
      {
        AcknowledgeableCondition::attach_async(
          std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

AcknowledgeableCondition AcknowledgeableCondition::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void AcknowledgeableCondition::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

void AcknowledgeableCondition::acknowledge_method_async(
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
    AcknowledgeableConditionTypeTraits::acknowledge_browse_name(),
    std::move(complete));
}

MethodAccessorResult AcknowledgeableCondition::try_acknowledge_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { acknowledge_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor AcknowledgeableCondition::acknowledge_method_sync() const
{
  return ::ua::detail::good_value(try_acknowledge_method_sync());
}

void AcknowledgeableCondition::confirm_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    AcknowledgeableConditionTypeTraits::confirm_browse_name(),
    std::move(complete));
}

MethodAccessorResult AcknowledgeableCondition::try_confirm_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete) { confirm_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor AcknowledgeableCondition::confirm_method_sync() const
{
  return ::ua::detail::good_value(try_confirm_method_sync());
}

// --- Common property helper ---

void AcknowledgeableCondition::find_property_async(
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
    "AcknowledgeableCondition",
    std::move(complete));
}

// --- Property accessors ---

void AcknowledgeableCondition::condition_class_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    AcknowledgeableConditionTypeTraits::condition_class_id_browse_name(), std::move(complete));
}

PropertyResult AcknowledgeableCondition::try_condition_class_id_property_sync() const noexcept
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

Property AcknowledgeableCondition::condition_class_id_property_sync() const
{
  return ::ua::detail::good_value(try_condition_class_id_property_sync());
}

void AcknowledgeableCondition::condition_class_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    AcknowledgeableConditionTypeTraits::condition_class_name_browse_name(), std::move(complete));
}

PropertyResult AcknowledgeableCondition::try_condition_class_name_property_sync() const noexcept
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

Property AcknowledgeableCondition::condition_class_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_class_name_property_sync());
}

void AcknowledgeableCondition::condition_sub_class_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    AcknowledgeableConditionTypeTraits::condition_sub_class_id_browse_name(), std::move(complete));
}

PropertyResult AcknowledgeableCondition::try_condition_sub_class_id_property_sync() const noexcept
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

Property AcknowledgeableCondition::condition_sub_class_id_property_sync() const
{
  return ::ua::detail::good_value(try_condition_sub_class_id_property_sync());
}

void AcknowledgeableCondition::condition_sub_class_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    AcknowledgeableConditionTypeTraits::condition_sub_class_name_browse_name(), std::move(complete));
}

PropertyResult AcknowledgeableCondition::try_condition_sub_class_name_property_sync() const noexcept
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

Property AcknowledgeableCondition::condition_sub_class_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_sub_class_name_property_sync());
}

void AcknowledgeableCondition::condition_name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AcknowledgeableConditionTypeTraits::condition_name_browse_name(), std::move(complete));
}

PropertyResult AcknowledgeableCondition::try_condition_name_property_sync() const noexcept
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

Property AcknowledgeableCondition::condition_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_name_property_sync());
}

void AcknowledgeableCondition::branch_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AcknowledgeableConditionTypeTraits::branch_id_browse_name(), std::move(complete));
}

PropertyResult AcknowledgeableCondition::try_branch_id_property_sync() const noexcept
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

Property AcknowledgeableCondition::branch_id_property_sync() const
{
  return ::ua::detail::good_value(try_branch_id_property_sync());
}

void AcknowledgeableCondition::retain_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AcknowledgeableConditionTypeTraits::retain_browse_name(), std::move(complete));
}

PropertyResult AcknowledgeableCondition::try_retain_property_sync() const noexcept
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

Property AcknowledgeableCondition::retain_property_sync() const
{
  return ::ua::detail::good_value(try_retain_property_sync());
}

void AcknowledgeableCondition::supports_filtered_retain_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    AcknowledgeableConditionTypeTraits::supports_filtered_retain_browse_name(), std::move(complete));
}

PropertyResult AcknowledgeableCondition::try_supports_filtered_retain_property_sync() const noexcept
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

Property AcknowledgeableCondition::supports_filtered_retain_property_sync() const
{
  return ::ua::detail::good_value(try_supports_filtered_retain_property_sync());
}

void AcknowledgeableCondition::client_user_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AcknowledgeableConditionTypeTraits::client_user_id_browse_name(), std::move(complete));
}

PropertyResult AcknowledgeableCondition::try_client_user_id_property_sync() const noexcept
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

Property AcknowledgeableCondition::client_user_id_property_sync() const
{
  return ::ua::detail::good_value(try_client_user_id_property_sync());
}

void AcknowledgeableCondition::event_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AcknowledgeableConditionTypeTraits::event_id_browse_name(), std::move(complete));
}

PropertyResult AcknowledgeableCondition::try_event_id_property_sync() const noexcept
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

Property AcknowledgeableCondition::event_id_property_sync() const
{
  return ::ua::detail::good_value(try_event_id_property_sync());
}

void AcknowledgeableCondition::event_type_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AcknowledgeableConditionTypeTraits::event_type_browse_name(), std::move(complete));
}

PropertyResult AcknowledgeableCondition::try_event_type_property_sync() const noexcept
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

Property AcknowledgeableCondition::event_type_property_sync() const
{
  return ::ua::detail::good_value(try_event_type_property_sync());
}

void AcknowledgeableCondition::source_node_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AcknowledgeableConditionTypeTraits::source_node_browse_name(), std::move(complete));
}

PropertyResult AcknowledgeableCondition::try_source_node_property_sync() const noexcept
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

Property AcknowledgeableCondition::source_node_property_sync() const
{
  return ::ua::detail::good_value(try_source_node_property_sync());
}

void AcknowledgeableCondition::source_name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AcknowledgeableConditionTypeTraits::source_name_browse_name(), std::move(complete));
}

PropertyResult AcknowledgeableCondition::try_source_name_property_sync() const noexcept
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

Property AcknowledgeableCondition::source_name_property_sync() const
{
  return ::ua::detail::good_value(try_source_name_property_sync());
}

void AcknowledgeableCondition::time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AcknowledgeableConditionTypeTraits::time_browse_name(), std::move(complete));
}

PropertyResult AcknowledgeableCondition::try_time_property_sync() const noexcept
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

Property AcknowledgeableCondition::time_property_sync() const
{
  return ::ua::detail::good_value(try_time_property_sync());
}

void AcknowledgeableCondition::receive_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AcknowledgeableConditionTypeTraits::receive_time_browse_name(), std::move(complete));
}

PropertyResult AcknowledgeableCondition::try_receive_time_property_sync() const noexcept
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

Property AcknowledgeableCondition::receive_time_property_sync() const
{
  return ::ua::detail::good_value(try_receive_time_property_sync());
}

void AcknowledgeableCondition::local_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AcknowledgeableConditionTypeTraits::local_time_browse_name(), std::move(complete));
}

PropertyResult AcknowledgeableCondition::try_local_time_property_sync() const noexcept
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

Property AcknowledgeableCondition::local_time_property_sync() const
{
  return ::ua::detail::good_value(try_local_time_property_sync());
}

void AcknowledgeableCondition::message_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AcknowledgeableConditionTypeTraits::message_browse_name(), std::move(complete));
}

PropertyResult AcknowledgeableCondition::try_message_property_sync() const noexcept
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

Property AcknowledgeableCondition::message_property_sync() const
{
  return ::ua::detail::good_value(try_message_property_sync());
}

void AcknowledgeableCondition::severity_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AcknowledgeableConditionTypeTraits::severity_browse_name(), std::move(complete));
}

PropertyResult AcknowledgeableCondition::try_severity_property_sync() const noexcept
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

Property AcknowledgeableCondition::severity_property_sync() const
{
  return ::ua::detail::good_value(try_severity_property_sync());
}

// --- Typed value read shortcuts ---

void AcknowledgeableCondition::read_condition_class_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::condition_class_id_browse_name(),
    &Variant::is_node_id,
    {"AcknowledgeableCondition",
      "condition_class_id",
      "AcknowledgeableCondition::read_condition_class_id_async"},
    std::move(complete));
}

NodeIdResult AcknowledgeableCondition::try_read_condition_class_id_sync() const noexcept
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

NodeId AcknowledgeableCondition::read_condition_class_id_sync() const
{
  return ::ua::detail::good_value(try_read_condition_class_id_sync());
}

void AcknowledgeableCondition::read_condition_class_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::condition_class_name_browse_name(),
    &Variant::is_localized_text,
    {"AcknowledgeableCondition",
      "condition_class_name",
      "AcknowledgeableCondition::read_condition_class_name_async"},
    std::move(complete));
}

LocalizedTextResult AcknowledgeableCondition::try_read_condition_class_name_sync() const noexcept
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

LocalizedText AcknowledgeableCondition::read_condition_class_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_class_name_sync());
}

void AcknowledgeableCondition::read_condition_sub_class_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::condition_sub_class_id_browse_name(),
    &Variant::is_node_id,
    {"AcknowledgeableCondition",
      "condition_sub_class_id",
      "AcknowledgeableCondition::read_condition_sub_class_id_async"},
    std::move(complete));
}

NodeIdResult AcknowledgeableCondition::try_read_condition_sub_class_id_sync() const noexcept
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

NodeId AcknowledgeableCondition::read_condition_sub_class_id_sync() const
{
  return ::ua::detail::good_value(try_read_condition_sub_class_id_sync());
}

void AcknowledgeableCondition::read_condition_sub_class_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::condition_sub_class_name_browse_name(),
    &Variant::is_localized_text,
    {"AcknowledgeableCondition",
      "condition_sub_class_name",
      "AcknowledgeableCondition::read_condition_sub_class_name_async"},
    std::move(complete));
}

LocalizedTextResult AcknowledgeableCondition::try_read_condition_sub_class_name_sync() const noexcept
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

LocalizedText AcknowledgeableCondition::read_condition_sub_class_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_sub_class_name_sync());
}

void AcknowledgeableCondition::read_condition_name_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::condition_name_browse_name(),
    &Variant::is_string,
    {"AcknowledgeableCondition", "condition_name", "AcknowledgeableCondition::read_condition_name_async"},
    std::move(complete));
}

StringResult AcknowledgeableCondition::try_read_condition_name_sync() const noexcept
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

String AcknowledgeableCondition::read_condition_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_name_sync());
}

void AcknowledgeableCondition::read_branch_id_async(std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::branch_id_browse_name(),
    &Variant::is_node_id,
    {"AcknowledgeableCondition", "branch_id", "AcknowledgeableCondition::read_branch_id_async"},
    std::move(complete));
}

NodeIdResult AcknowledgeableCondition::try_read_branch_id_sync() const noexcept
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

NodeId AcknowledgeableCondition::read_branch_id_sync() const
{
  return ::ua::detail::good_value(try_read_branch_id_sync());
}

void AcknowledgeableCondition::read_retain_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::retain_browse_name(),
    &Variant::is_boolean,
    {"AcknowledgeableCondition", "retain", "AcknowledgeableCondition::read_retain_async"},
    std::move(complete));
}

BoolResult AcknowledgeableCondition::try_read_retain_sync() const noexcept
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

bool AcknowledgeableCondition::read_retain_sync() const
{
  return ::ua::detail::good_value(try_read_retain_sync());
}

void AcknowledgeableCondition::read_supports_filtered_retain_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::supports_filtered_retain_browse_name(),
    &Variant::is_boolean,
    {"AcknowledgeableCondition",
      "supports_filtered_retain",
      "AcknowledgeableCondition::read_supports_filtered_retain_async"},
    std::move(complete));
}

BoolResult AcknowledgeableCondition::try_read_supports_filtered_retain_sync() const noexcept
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

bool AcknowledgeableCondition::read_supports_filtered_retain_sync() const
{
  return ::ua::detail::good_value(try_read_supports_filtered_retain_sync());
}

void AcknowledgeableCondition::read_client_user_id_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::client_user_id_browse_name(),
    &Variant::is_string,
    {"AcknowledgeableCondition", "client_user_id", "AcknowledgeableCondition::read_client_user_id_async"},
    std::move(complete));
}

StringResult AcknowledgeableCondition::try_read_client_user_id_sync() const noexcept
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

String AcknowledgeableCondition::read_client_user_id_sync() const
{
  return ::ua::detail::good_value(try_read_client_user_id_sync());
}

void AcknowledgeableCondition::read_event_id_async(
  std::function<void(ByteStringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(ByteStringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<ByteString>(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::event_id_browse_name(),
    &Variant::is_byte_string,
    {"AcknowledgeableCondition", "event_id", "AcknowledgeableCondition::read_event_id_async"},
    std::move(complete));
}

ByteStringResult AcknowledgeableCondition::try_read_event_id_sync() const noexcept
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

ByteString AcknowledgeableCondition::read_event_id_sync() const
{
  return ::ua::detail::good_value(try_read_event_id_sync());
}

void AcknowledgeableCondition::read_event_type_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::event_type_browse_name(),
    &Variant::is_node_id,
    {"AcknowledgeableCondition", "event_type", "AcknowledgeableCondition::read_event_type_async"},
    std::move(complete));
}

NodeIdResult AcknowledgeableCondition::try_read_event_type_sync() const noexcept
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

NodeId AcknowledgeableCondition::read_event_type_sync() const
{
  return ::ua::detail::good_value(try_read_event_type_sync());
}

void AcknowledgeableCondition::read_source_node_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::source_node_browse_name(),
    &Variant::is_node_id,
    {"AcknowledgeableCondition", "source_node", "AcknowledgeableCondition::read_source_node_async"},
    std::move(complete));
}

NodeIdResult AcknowledgeableCondition::try_read_source_node_sync() const noexcept
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

NodeId AcknowledgeableCondition::read_source_node_sync() const
{
  return ::ua::detail::good_value(try_read_source_node_sync());
}

void AcknowledgeableCondition::read_source_name_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::source_name_browse_name(),
    &Variant::is_string,
    {"AcknowledgeableCondition", "source_name", "AcknowledgeableCondition::read_source_name_async"},
    std::move(complete));
}

StringResult AcknowledgeableCondition::try_read_source_name_sync() const noexcept
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

String AcknowledgeableCondition::read_source_name_sync() const
{
  return ::ua::detail::good_value(try_read_source_name_sync());
}

void AcknowledgeableCondition::read_message_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::message_browse_name(),
    &Variant::is_localized_text,
    {"AcknowledgeableCondition", "message", "AcknowledgeableCondition::read_message_async"},
    std::move(complete));
}

LocalizedTextResult AcknowledgeableCondition::try_read_message_sync() const noexcept
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

LocalizedText AcknowledgeableCondition::read_message_sync() const
{
  return ::ua::detail::good_value(try_read_message_sync());
}

void AcknowledgeableCondition::read_severity_async(std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::severity_browse_name(),
    &Variant::is_uint16,
    {"AcknowledgeableCondition", "severity", "AcknowledgeableCondition::read_severity_async"},
    std::move(complete));
}

UInt16Result AcknowledgeableCondition::try_read_severity_sync() const noexcept
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

uint16_t AcknowledgeableCondition::read_severity_sync() const
{
  return ::ua::detail::good_value(try_read_severity_sync());
}

// --- Typed value write shortcuts ---

void AcknowledgeableCondition::write_condition_class_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::condition_class_id_browse_name(),
    "AcknowledgeableCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AcknowledgeableCondition::try_write_condition_class_id_sync(NodeId value) const noexcept
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

void AcknowledgeableCondition::write_condition_class_id_sync(NodeId value) const
{
  try_write_condition_class_id_sync(value).value();
}

void AcknowledgeableCondition::write_condition_class_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::condition_class_name_browse_name(),
    "AcknowledgeableCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AcknowledgeableCondition::try_write_condition_class_name_sync(LocalizedText value) const noexcept
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

void AcknowledgeableCondition::write_condition_class_name_sync(LocalizedText value) const
{
  try_write_condition_class_name_sync(value).value();
}

void AcknowledgeableCondition::write_condition_sub_class_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::condition_sub_class_id_browse_name(),
    "AcknowledgeableCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AcknowledgeableCondition::try_write_condition_sub_class_id_sync(NodeId value) const noexcept
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

void AcknowledgeableCondition::write_condition_sub_class_id_sync(NodeId value) const
{
  try_write_condition_sub_class_id_sync(value).value();
}

void AcknowledgeableCondition::write_condition_sub_class_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::condition_sub_class_name_browse_name(),
    "AcknowledgeableCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AcknowledgeableCondition::try_write_condition_sub_class_name_sync(
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

void AcknowledgeableCondition::write_condition_sub_class_name_sync(LocalizedText value) const
{
  try_write_condition_sub_class_name_sync(value).value();
}

void AcknowledgeableCondition::write_condition_name_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::condition_name_browse_name(),
    "AcknowledgeableCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AcknowledgeableCondition::try_write_condition_name_sync(String value) const noexcept
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

void AcknowledgeableCondition::write_condition_name_sync(String value) const
{
  try_write_condition_name_sync(value).value();
}

void AcknowledgeableCondition::write_branch_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::branch_id_browse_name(),
    "AcknowledgeableCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AcknowledgeableCondition::try_write_branch_id_sync(NodeId value) const noexcept
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

void AcknowledgeableCondition::write_branch_id_sync(NodeId value) const
{
  try_write_branch_id_sync(value).value();
}

void AcknowledgeableCondition::write_retain_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::retain_browse_name(),
    "AcknowledgeableCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AcknowledgeableCondition::try_write_retain_sync(bool value) const noexcept
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

void AcknowledgeableCondition::write_retain_sync(bool value) const
{
  try_write_retain_sync(value).value();
}

void AcknowledgeableCondition::write_supports_filtered_retain_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::supports_filtered_retain_browse_name(),
    "AcknowledgeableCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AcknowledgeableCondition::try_write_supports_filtered_retain_sync(bool value) const noexcept
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

void AcknowledgeableCondition::write_supports_filtered_retain_sync(bool value) const
{
  try_write_supports_filtered_retain_sync(value).value();
}

void AcknowledgeableCondition::write_client_user_id_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::client_user_id_browse_name(),
    "AcknowledgeableCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AcknowledgeableCondition::try_write_client_user_id_sync(String value) const noexcept
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

void AcknowledgeableCondition::write_client_user_id_sync(String value) const
{
  try_write_client_user_id_sync(value).value();
}

void AcknowledgeableCondition::write_event_id_async(
  ByteString value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::event_id_browse_name(),
    "AcknowledgeableCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AcknowledgeableCondition::try_write_event_id_sync(ByteString value) const noexcept
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

void AcknowledgeableCondition::write_event_id_sync(ByteString value) const
{
  try_write_event_id_sync(value).value();
}

void AcknowledgeableCondition::write_event_type_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::event_type_browse_name(),
    "AcknowledgeableCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AcknowledgeableCondition::try_write_event_type_sync(NodeId value) const noexcept
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

void AcknowledgeableCondition::write_event_type_sync(NodeId value) const
{
  try_write_event_type_sync(value).value();
}

void AcknowledgeableCondition::write_source_node_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::source_node_browse_name(),
    "AcknowledgeableCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AcknowledgeableCondition::try_write_source_node_sync(NodeId value) const noexcept
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

void AcknowledgeableCondition::write_source_node_sync(NodeId value) const
{
  try_write_source_node_sync(value).value();
}

void AcknowledgeableCondition::write_source_name_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::source_name_browse_name(),
    "AcknowledgeableCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AcknowledgeableCondition::try_write_source_name_sync(String value) const noexcept
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

void AcknowledgeableCondition::write_source_name_sync(String value) const
{
  try_write_source_name_sync(value).value();
}

void AcknowledgeableCondition::write_message_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::message_browse_name(),
    "AcknowledgeableCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AcknowledgeableCondition::try_write_message_sync(LocalizedText value) const noexcept
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

void AcknowledgeableCondition::write_message_sync(LocalizedText value) const
{
  try_write_message_sync(value).value();
}

void AcknowledgeableCondition::write_severity_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AcknowledgeableConditionTypeTraits::severity_browse_name(),
    "AcknowledgeableCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AcknowledgeableCondition::try_write_severity_sync(uint16_t value) const noexcept
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

void AcknowledgeableCondition::write_severity_sync(uint16_t value) const
{
  try_write_severity_sync(value).value();
}

// --- Method handler registration ---

void AcknowledgeableCondition::set_acknowledge_handler_async(
  AcknowledgeHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AcknowledgeableCondition",
        "AcknowledgeableCondition::set_acknowledge_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<ByteString, LocalizedText>, std::tuple<>> adapter{
      [handler = std::move(handler)](
        const MethodCall& call, const ByteString& in0, const LocalizedText& in1) -> MethodResult<>
      {
        AcknowledgeInputArguments typedIn{.eventId = in0, .comment = in1};
        return handler(call, typedIn);
      },
      Inputs<ByteString, LocalizedText>{
        {Arg<ByteString>{.name = "EventId"}, Arg<LocalizedText>{.name = "Comment"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      AcknowledgeableConditionTypeTraits::acknowledge_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AcknowledgeableCondition::try_set_acknowledge_handler_sync(
  AcknowledgeHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_acknowledge_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AcknowledgeableCondition::set_acknowledge_handler_sync(AcknowledgeHandler handler) const
{
  try_set_acknowledge_handler_sync(std::move(handler)).value();
}

void AcknowledgeableCondition::set_acknowledge_handler_async(
  AcknowledgeAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AcknowledgeableCondition",
        "AcknowledgeableCondition::set_acknowledge_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<ByteString, LocalizedText>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](const MethodCall& call,
        const ByteString& in0,
        const LocalizedText& in1,
        MethodResultCallback<>
          complete)
      {
        AcknowledgeInputArguments typedIn{.eventId = in0, .comment = in1};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<ByteString, LocalizedText>{
        {Arg<ByteString>{.name = "EventId"}, Arg<LocalizedText>{.name = "Comment"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      AcknowledgeableConditionTypeTraits::acknowledge_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AcknowledgeableCondition::try_set_acknowledge_handler_sync(
  AcknowledgeAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_acknowledge_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AcknowledgeableCondition::set_acknowledge_handler_sync(AcknowledgeAsyncHandler handler) const
{
  try_set_acknowledge_handler_sync(std::move(handler)).value();
}

void AcknowledgeableCondition::set_confirm_handler_async(
  ConfirmHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AcknowledgeableCondition",
        "AcknowledgeableCondition::set_confirm_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<ByteString, LocalizedText>, std::tuple<>> adapter{
      [handler = std::move(handler)](
        const MethodCall& call, const ByteString& in0, const LocalizedText& in1) -> MethodResult<>
      {
        ConfirmInputArguments typedIn{.eventId = in0, .comment = in1};
        return handler(call, typedIn);
      },
      Inputs<ByteString, LocalizedText>{
        {Arg<ByteString>{.name = "EventId"}, Arg<LocalizedText>{.name = "Comment"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      AcknowledgeableConditionTypeTraits::confirm_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AcknowledgeableCondition::try_set_confirm_handler_sync(ConfirmHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_confirm_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AcknowledgeableCondition::set_confirm_handler_sync(ConfirmHandler handler) const
{
  try_set_confirm_handler_sync(std::move(handler)).value();
}

void AcknowledgeableCondition::set_confirm_handler_async(
  ConfirmAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "AcknowledgeableCondition",
        "AcknowledgeableCondition::set_confirm_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<ByteString, LocalizedText>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](const MethodCall& call,
        const ByteString& in0,
        const LocalizedText& in1,
        MethodResultCallback<>
          complete)
      {
        ConfirmInputArguments typedIn{.eventId = in0, .comment = in1};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<ByteString, LocalizedText>{
        {Arg<ByteString>{.name = "EventId"}, Arg<LocalizedText>{.name = "Comment"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      AcknowledgeableConditionTypeTraits::confirm_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult AcknowledgeableCondition::try_set_confirm_handler_sync(ConfirmAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_confirm_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AcknowledgeableCondition::set_confirm_handler_sync(ConfirmAsyncHandler handler) const
{
  try_set_confirm_handler_sync(std::move(handler)).value();
}

// --- Child-object accessors ---

void AcknowledgeableCondition::enabled_state_async(
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
    AcknowledgeableConditionTypeTraits::enabled_state_browse_name(),
    "AcknowledgeableCondition",
    std::move(complete));
}

TwoStateVariableResult AcknowledgeableCondition::try_enabled_state_sync() const noexcept
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

TwoStateVariable AcknowledgeableCondition::enabled_state_sync() const
{
  return ::ua::detail::good_value(try_enabled_state_sync());
}

void AcknowledgeableCondition::acked_state_async(
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
    AcknowledgeableConditionTypeTraits::acked_state_browse_name(),
    "AcknowledgeableCondition",
    std::move(complete));
}

TwoStateVariableResult AcknowledgeableCondition::try_acked_state_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TwoStateVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TwoStateVariableResult)> complete) { acked_state_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TwoStateVariable AcknowledgeableCondition::acked_state_sync() const
{
  return ::ua::detail::good_value(try_acked_state_sync());
}

void AcknowledgeableCondition::confirmed_state_async(
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
    AcknowledgeableConditionTypeTraits::confirmed_state_browse_name(),
    "AcknowledgeableCondition",
    std::move(complete));
}

TwoStateVariableResult AcknowledgeableCondition::try_confirmed_state_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TwoStateVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TwoStateVariableResult)> complete)
      { confirmed_state_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TwoStateVariable AcknowledgeableCondition::confirmed_state_sync() const
{
  return ::ua::detail::good_value(try_confirmed_state_sync());
}

}  // namespace ua
