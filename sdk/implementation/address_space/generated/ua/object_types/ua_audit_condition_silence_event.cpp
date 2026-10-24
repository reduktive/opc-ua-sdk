// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_audit_condition_silence_event.h"

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

struct AuditConditionSilenceEventTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::AuditConditionSilenceEventType};
  }

  static QualifiedName method_id_browse_name()
  {
    return QualifiedName{0, "MethodId"};
  }

  static QualifiedName status_code_id_browse_name()
  {
    return QualifiedName{0, "StatusCodeId"};
  }

  static QualifiedName input_arguments_browse_name()
  {
    return QualifiedName{0, "InputArguments"};
  }

  static QualifiedName output_arguments_browse_name()
  {
    return QualifiedName{0, "OutputArguments"};
  }

  static QualifiedName action_time_stamp_browse_name()
  {
    return QualifiedName{0, "ActionTimeStamp"};
  }

  static QualifiedName status_browse_name()
  {
    return QualifiedName{0, "Status"};
  }

  static QualifiedName server_id_browse_name()
  {
    return QualifiedName{0, "ServerId"};
  }

  static QualifiedName client_audit_entry_id_browse_name()
  {
    return QualifiedName{0, "ClientAuditEntryId"};
  }

  static QualifiedName client_user_id_browse_name()
  {
    return QualifiedName{0, "ClientUserId"};
  }

  static QualifiedName client_application_uri_browse_name()
  {
    return QualifiedName{0, "ClientApplicationUri"};
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
};

}  // namespace

AuditConditionSilenceEvent::AuditConditionSilenceEvent(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void AuditConditionSilenceEvent::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    AuditConditionSilenceEventTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(AuditConditionSilenceEventResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(AuditConditionSilenceEventResult{
        AuditConditionSilenceEvent{
          std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

AuditConditionSilenceEventResult AuditConditionSilenceEvent::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<AuditConditionSilenceEventResult>(addressSpace.executor(),
      [&](std::function<void(AuditConditionSilenceEventResult)> complete)
      {
        AuditConditionSilenceEvent::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

AuditConditionSilenceEvent AuditConditionSilenceEvent::create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void AuditConditionSilenceEvent::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void AuditConditionSilenceEvent::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // AuditConditionSilenceEventType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    AuditConditionSilenceEventTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(AuditConditionSilenceEventResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(
          AuditConditionSilenceEventResult{::ua::detail::address_space_gone("AuditConditionSilenceEvent")});
        return;
      }
      complete(AuditConditionSilenceEvent{
        std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

AuditConditionSilenceEventResult AuditConditionSilenceEvent::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<AuditConditionSilenceEventResult>(addressSpace.executor(),
      [&](std::function<void(AuditConditionSilenceEventResult)> complete)
      {
        AuditConditionSilenceEvent::attach_async(
          std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

AuditConditionSilenceEvent AuditConditionSilenceEvent::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void AuditConditionSilenceEvent::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void AuditConditionSilenceEvent::find_property_async(
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
    "AuditConditionSilenceEvent",
    std::move(complete));
}

// --- Property accessors ---

void AuditConditionSilenceEvent::method_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AuditConditionSilenceEventTypeTraits::method_id_browse_name(), std::move(complete));
}

PropertyResult AuditConditionSilenceEvent::try_method_id_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { method_id_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property AuditConditionSilenceEvent::method_id_property_sync() const
{
  return ::ua::detail::good_value(try_method_id_property_sync());
}

void AuditConditionSilenceEvent::status_code_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    AuditConditionSilenceEventTypeTraits::status_code_id_browse_name(), std::move(complete));
}

PropertyResult AuditConditionSilenceEvent::try_status_code_id_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { status_code_id_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property AuditConditionSilenceEvent::status_code_id_property_sync() const
{
  return ::ua::detail::good_value(try_status_code_id_property_sync());
}

void AuditConditionSilenceEvent::input_arguments_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    AuditConditionSilenceEventTypeTraits::input_arguments_browse_name(), std::move(complete));
}

PropertyResult AuditConditionSilenceEvent::try_input_arguments_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { input_arguments_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property AuditConditionSilenceEvent::input_arguments_property_sync() const
{
  return ::ua::detail::good_value(try_input_arguments_property_sync());
}

void AuditConditionSilenceEvent::output_arguments_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    AuditConditionSilenceEventTypeTraits::output_arguments_browse_name(), std::move(complete));
}

PropertyResult AuditConditionSilenceEvent::try_output_arguments_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { output_arguments_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property AuditConditionSilenceEvent::output_arguments_property_sync() const
{
  return ::ua::detail::good_value(try_output_arguments_property_sync());
}

void AuditConditionSilenceEvent::action_time_stamp_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    AuditConditionSilenceEventTypeTraits::action_time_stamp_browse_name(), std::move(complete));
}

PropertyResult AuditConditionSilenceEvent::try_action_time_stamp_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { action_time_stamp_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property AuditConditionSilenceEvent::action_time_stamp_property_sync() const
{
  return ::ua::detail::good_value(try_action_time_stamp_property_sync());
}

void AuditConditionSilenceEvent::status_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AuditConditionSilenceEventTypeTraits::status_browse_name(), std::move(complete));
}

PropertyResult AuditConditionSilenceEvent::try_status_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { status_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property AuditConditionSilenceEvent::status_property_sync() const
{
  return ::ua::detail::good_value(try_status_property_sync());
}

void AuditConditionSilenceEvent::server_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AuditConditionSilenceEventTypeTraits::server_id_browse_name(), std::move(complete));
}

PropertyResult AuditConditionSilenceEvent::try_server_id_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { server_id_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property AuditConditionSilenceEvent::server_id_property_sync() const
{
  return ::ua::detail::good_value(try_server_id_property_sync());
}

void AuditConditionSilenceEvent::client_audit_entry_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    AuditConditionSilenceEventTypeTraits::client_audit_entry_id_browse_name(), std::move(complete));
}

PropertyResult AuditConditionSilenceEvent::try_client_audit_entry_id_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { client_audit_entry_id_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property AuditConditionSilenceEvent::client_audit_entry_id_property_sync() const
{
  return ::ua::detail::good_value(try_client_audit_entry_id_property_sync());
}

void AuditConditionSilenceEvent::client_user_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    AuditConditionSilenceEventTypeTraits::client_user_id_browse_name(), std::move(complete));
}

PropertyResult AuditConditionSilenceEvent::try_client_user_id_property_sync() const noexcept
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

Property AuditConditionSilenceEvent::client_user_id_property_sync() const
{
  return ::ua::detail::good_value(try_client_user_id_property_sync());
}

void AuditConditionSilenceEvent::client_application_uri_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    AuditConditionSilenceEventTypeTraits::client_application_uri_browse_name(), std::move(complete));
}

PropertyResult AuditConditionSilenceEvent::try_client_application_uri_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { client_application_uri_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property AuditConditionSilenceEvent::client_application_uri_property_sync() const
{
  return ::ua::detail::good_value(try_client_application_uri_property_sync());
}

void AuditConditionSilenceEvent::event_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AuditConditionSilenceEventTypeTraits::event_id_browse_name(), std::move(complete));
}

PropertyResult AuditConditionSilenceEvent::try_event_id_property_sync() const noexcept
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

Property AuditConditionSilenceEvent::event_id_property_sync() const
{
  return ::ua::detail::good_value(try_event_id_property_sync());
}

void AuditConditionSilenceEvent::event_type_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AuditConditionSilenceEventTypeTraits::event_type_browse_name(), std::move(complete));
}

PropertyResult AuditConditionSilenceEvent::try_event_type_property_sync() const noexcept
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

Property AuditConditionSilenceEvent::event_type_property_sync() const
{
  return ::ua::detail::good_value(try_event_type_property_sync());
}

void AuditConditionSilenceEvent::source_node_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AuditConditionSilenceEventTypeTraits::source_node_browse_name(), std::move(complete));
}

PropertyResult AuditConditionSilenceEvent::try_source_node_property_sync() const noexcept
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

Property AuditConditionSilenceEvent::source_node_property_sync() const
{
  return ::ua::detail::good_value(try_source_node_property_sync());
}

void AuditConditionSilenceEvent::source_name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AuditConditionSilenceEventTypeTraits::source_name_browse_name(), std::move(complete));
}

PropertyResult AuditConditionSilenceEvent::try_source_name_property_sync() const noexcept
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

Property AuditConditionSilenceEvent::source_name_property_sync() const
{
  return ::ua::detail::good_value(try_source_name_property_sync());
}

void AuditConditionSilenceEvent::time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AuditConditionSilenceEventTypeTraits::time_browse_name(), std::move(complete));
}

PropertyResult AuditConditionSilenceEvent::try_time_property_sync() const noexcept
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

Property AuditConditionSilenceEvent::time_property_sync() const
{
  return ::ua::detail::good_value(try_time_property_sync());
}

void AuditConditionSilenceEvent::receive_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AuditConditionSilenceEventTypeTraits::receive_time_browse_name(), std::move(complete));
}

PropertyResult AuditConditionSilenceEvent::try_receive_time_property_sync() const noexcept
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

Property AuditConditionSilenceEvent::receive_time_property_sync() const
{
  return ::ua::detail::good_value(try_receive_time_property_sync());
}

void AuditConditionSilenceEvent::local_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AuditConditionSilenceEventTypeTraits::local_time_browse_name(), std::move(complete));
}

PropertyResult AuditConditionSilenceEvent::try_local_time_property_sync() const noexcept
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

Property AuditConditionSilenceEvent::local_time_property_sync() const
{
  return ::ua::detail::good_value(try_local_time_property_sync());
}

void AuditConditionSilenceEvent::message_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AuditConditionSilenceEventTypeTraits::message_browse_name(), std::move(complete));
}

PropertyResult AuditConditionSilenceEvent::try_message_property_sync() const noexcept
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

Property AuditConditionSilenceEvent::message_property_sync() const
{
  return ::ua::detail::good_value(try_message_property_sync());
}

void AuditConditionSilenceEvent::severity_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AuditConditionSilenceEventTypeTraits::severity_browse_name(), std::move(complete));
}

PropertyResult AuditConditionSilenceEvent::try_severity_property_sync() const noexcept
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

Property AuditConditionSilenceEvent::severity_property_sync() const
{
  return ::ua::detail::good_value(try_severity_property_sync());
}

void AuditConditionSilenceEvent::condition_class_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    AuditConditionSilenceEventTypeTraits::condition_class_id_browse_name(), std::move(complete));
}

PropertyResult AuditConditionSilenceEvent::try_condition_class_id_property_sync() const noexcept
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

Property AuditConditionSilenceEvent::condition_class_id_property_sync() const
{
  return ::ua::detail::good_value(try_condition_class_id_property_sync());
}

void AuditConditionSilenceEvent::condition_class_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    AuditConditionSilenceEventTypeTraits::condition_class_name_browse_name(), std::move(complete));
}

PropertyResult AuditConditionSilenceEvent::try_condition_class_name_property_sync() const noexcept
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

Property AuditConditionSilenceEvent::condition_class_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_class_name_property_sync());
}

void AuditConditionSilenceEvent::condition_sub_class_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    AuditConditionSilenceEventTypeTraits::condition_sub_class_id_browse_name(), std::move(complete));
}

PropertyResult AuditConditionSilenceEvent::try_condition_sub_class_id_property_sync() const noexcept
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

Property AuditConditionSilenceEvent::condition_sub_class_id_property_sync() const
{
  return ::ua::detail::good_value(try_condition_sub_class_id_property_sync());
}

void AuditConditionSilenceEvent::condition_sub_class_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    AuditConditionSilenceEventTypeTraits::condition_sub_class_name_browse_name(), std::move(complete));
}

PropertyResult AuditConditionSilenceEvent::try_condition_sub_class_name_property_sync() const noexcept
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

Property AuditConditionSilenceEvent::condition_sub_class_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_sub_class_name_property_sync());
}

// --- Typed value read shortcuts ---

void AuditConditionSilenceEvent::read_method_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::method_id_browse_name(),
    &Variant::is_node_id,
    {"AuditConditionSilenceEvent", "method_id", "AuditConditionSilenceEvent::read_method_id_async"},
    std::move(complete));
}

NodeIdResult AuditConditionSilenceEvent::try_read_method_id_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeIdResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(NodeIdResult)> complete) { read_method_id_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NodeId AuditConditionSilenceEvent::read_method_id_sync() const
{
  return ::ua::detail::good_value(try_read_method_id_sync());
}

void AuditConditionSilenceEvent::read_status_code_id_async(
  std::function<void(Result<StatusCode>)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(Result<StatusCode>{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<StatusCode>(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::status_code_id_browse_name(),
    &Variant::is_status_code,
    {"AuditConditionSilenceEvent", "status_code_id", "AuditConditionSilenceEvent::read_status_code_id_async"},
    std::move(complete));
}

Result<StatusCode> AuditConditionSilenceEvent::try_read_status_code_id_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<Result<StatusCode>>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(Result<StatusCode>)> complete)
      { read_status_code_id_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

StatusCode AuditConditionSilenceEvent::read_status_code_id_sync() const
{
  return ::ua::detail::good_value(try_read_status_code_id_sync());
}

void AuditConditionSilenceEvent::read_status_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::status_browse_name(),
    &Variant::is_boolean,
    {"AuditConditionSilenceEvent", "status", "AuditConditionSilenceEvent::read_status_async"},
    std::move(complete));
}

BoolResult AuditConditionSilenceEvent::try_read_status_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BoolResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BoolResult)> complete) { read_status_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

bool AuditConditionSilenceEvent::read_status_sync() const
{
  return ::ua::detail::good_value(try_read_status_sync());
}

void AuditConditionSilenceEvent::read_server_id_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::server_id_browse_name(),
    &Variant::is_string,
    {"AuditConditionSilenceEvent", "server_id", "AuditConditionSilenceEvent::read_server_id_async"},
    std::move(complete));
}

StringResult AuditConditionSilenceEvent::try_read_server_id_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_server_id_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String AuditConditionSilenceEvent::read_server_id_sync() const
{
  return ::ua::detail::good_value(try_read_server_id_sync());
}

void AuditConditionSilenceEvent::read_client_audit_entry_id_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::client_audit_entry_id_browse_name(),
    &Variant::is_string,
    {"AuditConditionSilenceEvent",
      "client_audit_entry_id",
      "AuditConditionSilenceEvent::read_client_audit_entry_id_async"},
    std::move(complete));
}

StringResult AuditConditionSilenceEvent::try_read_client_audit_entry_id_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete)
      { read_client_audit_entry_id_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String AuditConditionSilenceEvent::read_client_audit_entry_id_sync() const
{
  return ::ua::detail::good_value(try_read_client_audit_entry_id_sync());
}

void AuditConditionSilenceEvent::read_client_user_id_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::client_user_id_browse_name(),
    &Variant::is_string,
    {"AuditConditionSilenceEvent", "client_user_id", "AuditConditionSilenceEvent::read_client_user_id_async"},
    std::move(complete));
}

StringResult AuditConditionSilenceEvent::try_read_client_user_id_sync() const noexcept
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

String AuditConditionSilenceEvent::read_client_user_id_sync() const
{
  return ::ua::detail::good_value(try_read_client_user_id_sync());
}

void AuditConditionSilenceEvent::read_client_application_uri_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::client_application_uri_browse_name(),
    &Variant::is_string,
    {"AuditConditionSilenceEvent",
      "client_application_uri",
      "AuditConditionSilenceEvent::read_client_application_uri_async"},
    std::move(complete));
}

StringResult AuditConditionSilenceEvent::try_read_client_application_uri_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete)
      { read_client_application_uri_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String AuditConditionSilenceEvent::read_client_application_uri_sync() const
{
  return ::ua::detail::good_value(try_read_client_application_uri_sync());
}

void AuditConditionSilenceEvent::read_event_id_async(
  std::function<void(ByteStringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(ByteStringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<ByteString>(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::event_id_browse_name(),
    &Variant::is_byte_string,
    {"AuditConditionSilenceEvent", "event_id", "AuditConditionSilenceEvent::read_event_id_async"},
    std::move(complete));
}

ByteStringResult AuditConditionSilenceEvent::try_read_event_id_sync() const noexcept
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

ByteString AuditConditionSilenceEvent::read_event_id_sync() const
{
  return ::ua::detail::good_value(try_read_event_id_sync());
}

void AuditConditionSilenceEvent::read_event_type_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::event_type_browse_name(),
    &Variant::is_node_id,
    {"AuditConditionSilenceEvent", "event_type", "AuditConditionSilenceEvent::read_event_type_async"},
    std::move(complete));
}

NodeIdResult AuditConditionSilenceEvent::try_read_event_type_sync() const noexcept
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

NodeId AuditConditionSilenceEvent::read_event_type_sync() const
{
  return ::ua::detail::good_value(try_read_event_type_sync());
}

void AuditConditionSilenceEvent::read_source_node_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::source_node_browse_name(),
    &Variant::is_node_id,
    {"AuditConditionSilenceEvent", "source_node", "AuditConditionSilenceEvent::read_source_node_async"},
    std::move(complete));
}

NodeIdResult AuditConditionSilenceEvent::try_read_source_node_sync() const noexcept
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

NodeId AuditConditionSilenceEvent::read_source_node_sync() const
{
  return ::ua::detail::good_value(try_read_source_node_sync());
}

void AuditConditionSilenceEvent::read_source_name_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::source_name_browse_name(),
    &Variant::is_string,
    {"AuditConditionSilenceEvent", "source_name", "AuditConditionSilenceEvent::read_source_name_async"},
    std::move(complete));
}

StringResult AuditConditionSilenceEvent::try_read_source_name_sync() const noexcept
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

String AuditConditionSilenceEvent::read_source_name_sync() const
{
  return ::ua::detail::good_value(try_read_source_name_sync());
}

void AuditConditionSilenceEvent::read_message_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::message_browse_name(),
    &Variant::is_localized_text,
    {"AuditConditionSilenceEvent", "message", "AuditConditionSilenceEvent::read_message_async"},
    std::move(complete));
}

LocalizedTextResult AuditConditionSilenceEvent::try_read_message_sync() const noexcept
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

LocalizedText AuditConditionSilenceEvent::read_message_sync() const
{
  return ::ua::detail::good_value(try_read_message_sync());
}

void AuditConditionSilenceEvent::read_severity_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::severity_browse_name(),
    &Variant::is_uint16,
    {"AuditConditionSilenceEvent", "severity", "AuditConditionSilenceEvent::read_severity_async"},
    std::move(complete));
}

UInt16Result AuditConditionSilenceEvent::try_read_severity_sync() const noexcept
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

uint16_t AuditConditionSilenceEvent::read_severity_sync() const
{
  return ::ua::detail::good_value(try_read_severity_sync());
}

void AuditConditionSilenceEvent::read_condition_class_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::condition_class_id_browse_name(),
    &Variant::is_node_id,
    {"AuditConditionSilenceEvent",
      "condition_class_id",
      "AuditConditionSilenceEvent::read_condition_class_id_async"},
    std::move(complete));
}

NodeIdResult AuditConditionSilenceEvent::try_read_condition_class_id_sync() const noexcept
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

NodeId AuditConditionSilenceEvent::read_condition_class_id_sync() const
{
  return ::ua::detail::good_value(try_read_condition_class_id_sync());
}

void AuditConditionSilenceEvent::read_condition_class_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::condition_class_name_browse_name(),
    &Variant::is_localized_text,
    {"AuditConditionSilenceEvent",
      "condition_class_name",
      "AuditConditionSilenceEvent::read_condition_class_name_async"},
    std::move(complete));
}

LocalizedTextResult AuditConditionSilenceEvent::try_read_condition_class_name_sync() const noexcept
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

LocalizedText AuditConditionSilenceEvent::read_condition_class_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_class_name_sync());
}

void AuditConditionSilenceEvent::read_condition_sub_class_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::condition_sub_class_id_browse_name(),
    &Variant::is_node_id,
    {"AuditConditionSilenceEvent",
      "condition_sub_class_id",
      "AuditConditionSilenceEvent::read_condition_sub_class_id_async"},
    std::move(complete));
}

NodeIdResult AuditConditionSilenceEvent::try_read_condition_sub_class_id_sync() const noexcept
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

NodeId AuditConditionSilenceEvent::read_condition_sub_class_id_sync() const
{
  return ::ua::detail::good_value(try_read_condition_sub_class_id_sync());
}

void AuditConditionSilenceEvent::read_condition_sub_class_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::condition_sub_class_name_browse_name(),
    &Variant::is_localized_text,
    {"AuditConditionSilenceEvent",
      "condition_sub_class_name",
      "AuditConditionSilenceEvent::read_condition_sub_class_name_async"},
    std::move(complete));
}

LocalizedTextResult AuditConditionSilenceEvent::try_read_condition_sub_class_name_sync() const noexcept
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

LocalizedText AuditConditionSilenceEvent::read_condition_sub_class_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_sub_class_name_sync());
}

// --- Typed value write shortcuts ---

void AuditConditionSilenceEvent::write_method_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::method_id_browse_name(),
    "AuditConditionSilenceEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AuditConditionSilenceEvent::try_write_method_id_sync(NodeId value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_method_id_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AuditConditionSilenceEvent::write_method_id_sync(NodeId value) const
{
  try_write_method_id_sync(value).value();
}

void AuditConditionSilenceEvent::write_status_code_id_async(
  StatusCode value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::status_code_id_browse_name(),
    "AuditConditionSilenceEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AuditConditionSilenceEvent::try_write_status_code_id_sync(StatusCode value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_status_code_id_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AuditConditionSilenceEvent::write_status_code_id_sync(StatusCode value) const
{
  try_write_status_code_id_sync(value).value();
}

void AuditConditionSilenceEvent::write_status_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::status_browse_name(),
    "AuditConditionSilenceEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AuditConditionSilenceEvent::try_write_status_sync(bool value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_status_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AuditConditionSilenceEvent::write_status_sync(bool value) const
{
  try_write_status_sync(value).value();
}

void AuditConditionSilenceEvent::write_server_id_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::server_id_browse_name(),
    "AuditConditionSilenceEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AuditConditionSilenceEvent::try_write_server_id_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_server_id_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AuditConditionSilenceEvent::write_server_id_sync(String value) const
{
  try_write_server_id_sync(value).value();
}

void AuditConditionSilenceEvent::write_client_audit_entry_id_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::client_audit_entry_id_browse_name(),
    "AuditConditionSilenceEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AuditConditionSilenceEvent::try_write_client_audit_entry_id_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_client_audit_entry_id_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AuditConditionSilenceEvent::write_client_audit_entry_id_sync(String value) const
{
  try_write_client_audit_entry_id_sync(value).value();
}

void AuditConditionSilenceEvent::write_client_user_id_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::client_user_id_browse_name(),
    "AuditConditionSilenceEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AuditConditionSilenceEvent::try_write_client_user_id_sync(String value) const noexcept
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

void AuditConditionSilenceEvent::write_client_user_id_sync(String value) const
{
  try_write_client_user_id_sync(value).value();
}

void AuditConditionSilenceEvent::write_client_application_uri_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::client_application_uri_browse_name(),
    "AuditConditionSilenceEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AuditConditionSilenceEvent::try_write_client_application_uri_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_client_application_uri_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AuditConditionSilenceEvent::write_client_application_uri_sync(String value) const
{
  try_write_client_application_uri_sync(value).value();
}

void AuditConditionSilenceEvent::write_event_id_async(
  ByteString value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::event_id_browse_name(),
    "AuditConditionSilenceEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AuditConditionSilenceEvent::try_write_event_id_sync(ByteString value) const noexcept
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

void AuditConditionSilenceEvent::write_event_id_sync(ByteString value) const
{
  try_write_event_id_sync(value).value();
}

void AuditConditionSilenceEvent::write_event_type_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::event_type_browse_name(),
    "AuditConditionSilenceEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AuditConditionSilenceEvent::try_write_event_type_sync(NodeId value) const noexcept
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

void AuditConditionSilenceEvent::write_event_type_sync(NodeId value) const
{
  try_write_event_type_sync(value).value();
}

void AuditConditionSilenceEvent::write_source_node_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::source_node_browse_name(),
    "AuditConditionSilenceEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AuditConditionSilenceEvent::try_write_source_node_sync(NodeId value) const noexcept
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

void AuditConditionSilenceEvent::write_source_node_sync(NodeId value) const
{
  try_write_source_node_sync(value).value();
}

void AuditConditionSilenceEvent::write_source_name_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::source_name_browse_name(),
    "AuditConditionSilenceEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AuditConditionSilenceEvent::try_write_source_name_sync(String value) const noexcept
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

void AuditConditionSilenceEvent::write_source_name_sync(String value) const
{
  try_write_source_name_sync(value).value();
}

void AuditConditionSilenceEvent::write_message_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::message_browse_name(),
    "AuditConditionSilenceEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AuditConditionSilenceEvent::try_write_message_sync(LocalizedText value) const noexcept
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

void AuditConditionSilenceEvent::write_message_sync(LocalizedText value) const
{
  try_write_message_sync(value).value();
}

void AuditConditionSilenceEvent::write_severity_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::severity_browse_name(),
    "AuditConditionSilenceEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AuditConditionSilenceEvent::try_write_severity_sync(uint16_t value) const noexcept
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

void AuditConditionSilenceEvent::write_severity_sync(uint16_t value) const
{
  try_write_severity_sync(value).value();
}

void AuditConditionSilenceEvent::write_condition_class_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::condition_class_id_browse_name(),
    "AuditConditionSilenceEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AuditConditionSilenceEvent::try_write_condition_class_id_sync(NodeId value) const noexcept
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

void AuditConditionSilenceEvent::write_condition_class_id_sync(NodeId value) const
{
  try_write_condition_class_id_sync(value).value();
}

void AuditConditionSilenceEvent::write_condition_class_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::condition_class_name_browse_name(),
    "AuditConditionSilenceEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AuditConditionSilenceEvent::try_write_condition_class_name_sync(LocalizedText value) const noexcept
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

void AuditConditionSilenceEvent::write_condition_class_name_sync(LocalizedText value) const
{
  try_write_condition_class_name_sync(value).value();
}

void AuditConditionSilenceEvent::write_condition_sub_class_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::condition_sub_class_id_browse_name(),
    "AuditConditionSilenceEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AuditConditionSilenceEvent::try_write_condition_sub_class_id_sync(NodeId value) const noexcept
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

void AuditConditionSilenceEvent::write_condition_sub_class_id_sync(NodeId value) const
{
  try_write_condition_sub_class_id_sync(value).value();
}

void AuditConditionSilenceEvent::write_condition_sub_class_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AuditConditionSilenceEventTypeTraits::condition_sub_class_name_browse_name(),
    "AuditConditionSilenceEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AuditConditionSilenceEvent::try_write_condition_sub_class_name_sync(
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

void AuditConditionSilenceEvent::write_condition_sub_class_name_sync(LocalizedText value) const
{
  try_write_condition_sub_class_name_sync(value).value();
}

}  // namespace ua
