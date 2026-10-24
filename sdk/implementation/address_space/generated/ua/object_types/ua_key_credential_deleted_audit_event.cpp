// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_key_credential_deleted_audit_event.h"

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

struct KeyCredentialDeletedAuditEventTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::KeyCredentialDeletedAuditEventType};
  }

  static QualifiedName resource_uri_browse_name()
  {
    return QualifiedName{0, "ResourceUri"};
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

KeyCredentialDeletedAuditEvent::KeyCredentialDeletedAuditEvent(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void KeyCredentialDeletedAuditEvent::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    KeyCredentialDeletedAuditEventTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(KeyCredentialDeletedAuditEventResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(KeyCredentialDeletedAuditEventResult{
        KeyCredentialDeletedAuditEvent{
          std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

KeyCredentialDeletedAuditEventResult KeyCredentialDeletedAuditEvent::try_create_sync(
  AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
  const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<KeyCredentialDeletedAuditEventResult>(addressSpace.executor(),
      [&](std::function<void(KeyCredentialDeletedAuditEventResult)> complete)
      {
        KeyCredentialDeletedAuditEvent::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

KeyCredentialDeletedAuditEvent KeyCredentialDeletedAuditEvent::create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void KeyCredentialDeletedAuditEvent::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void KeyCredentialDeletedAuditEvent::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // KeyCredentialDeletedAuditEventType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    KeyCredentialDeletedAuditEventTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(KeyCredentialDeletedAuditEventResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(KeyCredentialDeletedAuditEventResult{
          ::ua::detail::address_space_gone("KeyCredentialDeletedAuditEvent")});
        return;
      }
      complete(KeyCredentialDeletedAuditEvent{
        std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

KeyCredentialDeletedAuditEventResult KeyCredentialDeletedAuditEvent::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<KeyCredentialDeletedAuditEventResult>(addressSpace.executor(),
      [&](std::function<void(KeyCredentialDeletedAuditEventResult)> complete)
      {
        KeyCredentialDeletedAuditEvent::attach_async(
          std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

KeyCredentialDeletedAuditEvent KeyCredentialDeletedAuditEvent::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void KeyCredentialDeletedAuditEvent::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void KeyCredentialDeletedAuditEvent::find_property_async(
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
    "KeyCredentialDeletedAuditEvent",
    std::move(complete));
}

// --- Property accessors ---

void KeyCredentialDeletedAuditEvent::resource_uri_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialDeletedAuditEventTypeTraits::resource_uri_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialDeletedAuditEvent::try_resource_uri_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { resource_uri_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property KeyCredentialDeletedAuditEvent::resource_uri_property_sync() const
{
  return ::ua::detail::good_value(try_resource_uri_property_sync());
}

void KeyCredentialDeletedAuditEvent::method_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(KeyCredentialDeletedAuditEventTypeTraits::method_id_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialDeletedAuditEvent::try_method_id_property_sync() const noexcept
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

Property KeyCredentialDeletedAuditEvent::method_id_property_sync() const
{
  return ::ua::detail::good_value(try_method_id_property_sync());
}

void KeyCredentialDeletedAuditEvent::status_code_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialDeletedAuditEventTypeTraits::status_code_id_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialDeletedAuditEvent::try_status_code_id_property_sync() const noexcept
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

Property KeyCredentialDeletedAuditEvent::status_code_id_property_sync() const
{
  return ::ua::detail::good_value(try_status_code_id_property_sync());
}

void KeyCredentialDeletedAuditEvent::input_arguments_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialDeletedAuditEventTypeTraits::input_arguments_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialDeletedAuditEvent::try_input_arguments_property_sync() const noexcept
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

Property KeyCredentialDeletedAuditEvent::input_arguments_property_sync() const
{
  return ::ua::detail::good_value(try_input_arguments_property_sync());
}

void KeyCredentialDeletedAuditEvent::output_arguments_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialDeletedAuditEventTypeTraits::output_arguments_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialDeletedAuditEvent::try_output_arguments_property_sync() const noexcept
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

Property KeyCredentialDeletedAuditEvent::output_arguments_property_sync() const
{
  return ::ua::detail::good_value(try_output_arguments_property_sync());
}

void KeyCredentialDeletedAuditEvent::action_time_stamp_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialDeletedAuditEventTypeTraits::action_time_stamp_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialDeletedAuditEvent::try_action_time_stamp_property_sync() const noexcept
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

Property KeyCredentialDeletedAuditEvent::action_time_stamp_property_sync() const
{
  return ::ua::detail::good_value(try_action_time_stamp_property_sync());
}

void KeyCredentialDeletedAuditEvent::status_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(KeyCredentialDeletedAuditEventTypeTraits::status_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialDeletedAuditEvent::try_status_property_sync() const noexcept
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

Property KeyCredentialDeletedAuditEvent::status_property_sync() const
{
  return ::ua::detail::good_value(try_status_property_sync());
}

void KeyCredentialDeletedAuditEvent::server_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(KeyCredentialDeletedAuditEventTypeTraits::server_id_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialDeletedAuditEvent::try_server_id_property_sync() const noexcept
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

Property KeyCredentialDeletedAuditEvent::server_id_property_sync() const
{
  return ::ua::detail::good_value(try_server_id_property_sync());
}

void KeyCredentialDeletedAuditEvent::client_audit_entry_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialDeletedAuditEventTypeTraits::client_audit_entry_id_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialDeletedAuditEvent::try_client_audit_entry_id_property_sync() const noexcept
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

Property KeyCredentialDeletedAuditEvent::client_audit_entry_id_property_sync() const
{
  return ::ua::detail::good_value(try_client_audit_entry_id_property_sync());
}

void KeyCredentialDeletedAuditEvent::client_user_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialDeletedAuditEventTypeTraits::client_user_id_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialDeletedAuditEvent::try_client_user_id_property_sync() const noexcept
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

Property KeyCredentialDeletedAuditEvent::client_user_id_property_sync() const
{
  return ::ua::detail::good_value(try_client_user_id_property_sync());
}

void KeyCredentialDeletedAuditEvent::client_application_uri_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialDeletedAuditEventTypeTraits::client_application_uri_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialDeletedAuditEvent::try_client_application_uri_property_sync() const noexcept
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

Property KeyCredentialDeletedAuditEvent::client_application_uri_property_sync() const
{
  return ::ua::detail::good_value(try_client_application_uri_property_sync());
}

void KeyCredentialDeletedAuditEvent::event_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(KeyCredentialDeletedAuditEventTypeTraits::event_id_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialDeletedAuditEvent::try_event_id_property_sync() const noexcept
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

Property KeyCredentialDeletedAuditEvent::event_id_property_sync() const
{
  return ::ua::detail::good_value(try_event_id_property_sync());
}

void KeyCredentialDeletedAuditEvent::event_type_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialDeletedAuditEventTypeTraits::event_type_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialDeletedAuditEvent::try_event_type_property_sync() const noexcept
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

Property KeyCredentialDeletedAuditEvent::event_type_property_sync() const
{
  return ::ua::detail::good_value(try_event_type_property_sync());
}

void KeyCredentialDeletedAuditEvent::source_node_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialDeletedAuditEventTypeTraits::source_node_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialDeletedAuditEvent::try_source_node_property_sync() const noexcept
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

Property KeyCredentialDeletedAuditEvent::source_node_property_sync() const
{
  return ::ua::detail::good_value(try_source_node_property_sync());
}

void KeyCredentialDeletedAuditEvent::source_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialDeletedAuditEventTypeTraits::source_name_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialDeletedAuditEvent::try_source_name_property_sync() const noexcept
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

Property KeyCredentialDeletedAuditEvent::source_name_property_sync() const
{
  return ::ua::detail::good_value(try_source_name_property_sync());
}

void KeyCredentialDeletedAuditEvent::time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(KeyCredentialDeletedAuditEventTypeTraits::time_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialDeletedAuditEvent::try_time_property_sync() const noexcept
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

Property KeyCredentialDeletedAuditEvent::time_property_sync() const
{
  return ::ua::detail::good_value(try_time_property_sync());
}

void KeyCredentialDeletedAuditEvent::receive_time_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialDeletedAuditEventTypeTraits::receive_time_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialDeletedAuditEvent::try_receive_time_property_sync() const noexcept
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

Property KeyCredentialDeletedAuditEvent::receive_time_property_sync() const
{
  return ::ua::detail::good_value(try_receive_time_property_sync());
}

void KeyCredentialDeletedAuditEvent::local_time_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialDeletedAuditEventTypeTraits::local_time_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialDeletedAuditEvent::try_local_time_property_sync() const noexcept
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

Property KeyCredentialDeletedAuditEvent::local_time_property_sync() const
{
  return ::ua::detail::good_value(try_local_time_property_sync());
}

void KeyCredentialDeletedAuditEvent::message_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(KeyCredentialDeletedAuditEventTypeTraits::message_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialDeletedAuditEvent::try_message_property_sync() const noexcept
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

Property KeyCredentialDeletedAuditEvent::message_property_sync() const
{
  return ::ua::detail::good_value(try_message_property_sync());
}

void KeyCredentialDeletedAuditEvent::severity_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(KeyCredentialDeletedAuditEventTypeTraits::severity_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialDeletedAuditEvent::try_severity_property_sync() const noexcept
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

Property KeyCredentialDeletedAuditEvent::severity_property_sync() const
{
  return ::ua::detail::good_value(try_severity_property_sync());
}

void KeyCredentialDeletedAuditEvent::condition_class_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialDeletedAuditEventTypeTraits::condition_class_id_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialDeletedAuditEvent::try_condition_class_id_property_sync() const noexcept
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

Property KeyCredentialDeletedAuditEvent::condition_class_id_property_sync() const
{
  return ::ua::detail::good_value(try_condition_class_id_property_sync());
}

void KeyCredentialDeletedAuditEvent::condition_class_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialDeletedAuditEventTypeTraits::condition_class_name_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialDeletedAuditEvent::try_condition_class_name_property_sync() const noexcept
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

Property KeyCredentialDeletedAuditEvent::condition_class_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_class_name_property_sync());
}

void KeyCredentialDeletedAuditEvent::condition_sub_class_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialDeletedAuditEventTypeTraits::condition_sub_class_id_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialDeletedAuditEvent::try_condition_sub_class_id_property_sync() const noexcept
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

Property KeyCredentialDeletedAuditEvent::condition_sub_class_id_property_sync() const
{
  return ::ua::detail::good_value(try_condition_sub_class_id_property_sync());
}

void KeyCredentialDeletedAuditEvent::condition_sub_class_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialDeletedAuditEventTypeTraits::condition_sub_class_name_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialDeletedAuditEvent::try_condition_sub_class_name_property_sync() const noexcept
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

Property KeyCredentialDeletedAuditEvent::condition_sub_class_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_sub_class_name_property_sync());
}

// --- Typed value read shortcuts ---

void KeyCredentialDeletedAuditEvent::read_resource_uri_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::resource_uri_browse_name(),
    &Variant::is_string,
    {"KeyCredentialDeletedAuditEvent",
      "resource_uri",
      "KeyCredentialDeletedAuditEvent::read_resource_uri_async"},
    std::move(complete));
}

StringResult KeyCredentialDeletedAuditEvent::try_read_resource_uri_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_resource_uri_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String KeyCredentialDeletedAuditEvent::read_resource_uri_sync() const
{
  return ::ua::detail::good_value(try_read_resource_uri_sync());
}

void KeyCredentialDeletedAuditEvent::read_method_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::method_id_browse_name(),
    &Variant::is_node_id,
    {"KeyCredentialDeletedAuditEvent", "method_id", "KeyCredentialDeletedAuditEvent::read_method_id_async"},
    std::move(complete));
}

NodeIdResult KeyCredentialDeletedAuditEvent::try_read_method_id_sync() const noexcept
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

NodeId KeyCredentialDeletedAuditEvent::read_method_id_sync() const
{
  return ::ua::detail::good_value(try_read_method_id_sync());
}

void KeyCredentialDeletedAuditEvent::read_status_code_id_async(
  std::function<void(Result<StatusCode>)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(Result<StatusCode>{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<StatusCode>(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::status_code_id_browse_name(),
    &Variant::is_status_code,
    {"KeyCredentialDeletedAuditEvent",
      "status_code_id",
      "KeyCredentialDeletedAuditEvent::read_status_code_id_async"},
    std::move(complete));
}

Result<StatusCode> KeyCredentialDeletedAuditEvent::try_read_status_code_id_sync() const noexcept
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

StatusCode KeyCredentialDeletedAuditEvent::read_status_code_id_sync() const
{
  return ::ua::detail::good_value(try_read_status_code_id_sync());
}

void KeyCredentialDeletedAuditEvent::read_status_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::status_browse_name(),
    &Variant::is_boolean,
    {"KeyCredentialDeletedAuditEvent", "status", "KeyCredentialDeletedAuditEvent::read_status_async"},
    std::move(complete));
}

BoolResult KeyCredentialDeletedAuditEvent::try_read_status_sync() const noexcept
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

bool KeyCredentialDeletedAuditEvent::read_status_sync() const
{
  return ::ua::detail::good_value(try_read_status_sync());
}

void KeyCredentialDeletedAuditEvent::read_server_id_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::server_id_browse_name(),
    &Variant::is_string,
    {"KeyCredentialDeletedAuditEvent", "server_id", "KeyCredentialDeletedAuditEvent::read_server_id_async"},
    std::move(complete));
}

StringResult KeyCredentialDeletedAuditEvent::try_read_server_id_sync() const noexcept
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

String KeyCredentialDeletedAuditEvent::read_server_id_sync() const
{
  return ::ua::detail::good_value(try_read_server_id_sync());
}

void KeyCredentialDeletedAuditEvent::read_client_audit_entry_id_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::client_audit_entry_id_browse_name(),
    &Variant::is_string,
    {"KeyCredentialDeletedAuditEvent",
      "client_audit_entry_id",
      "KeyCredentialDeletedAuditEvent::read_client_audit_entry_id_async"},
    std::move(complete));
}

StringResult KeyCredentialDeletedAuditEvent::try_read_client_audit_entry_id_sync() const noexcept
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

String KeyCredentialDeletedAuditEvent::read_client_audit_entry_id_sync() const
{
  return ::ua::detail::good_value(try_read_client_audit_entry_id_sync());
}

void KeyCredentialDeletedAuditEvent::read_client_user_id_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::client_user_id_browse_name(),
    &Variant::is_string,
    {"KeyCredentialDeletedAuditEvent",
      "client_user_id",
      "KeyCredentialDeletedAuditEvent::read_client_user_id_async"},
    std::move(complete));
}

StringResult KeyCredentialDeletedAuditEvent::try_read_client_user_id_sync() const noexcept
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

String KeyCredentialDeletedAuditEvent::read_client_user_id_sync() const
{
  return ::ua::detail::good_value(try_read_client_user_id_sync());
}

void KeyCredentialDeletedAuditEvent::read_client_application_uri_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::client_application_uri_browse_name(),
    &Variant::is_string,
    {"KeyCredentialDeletedAuditEvent",
      "client_application_uri",
      "KeyCredentialDeletedAuditEvent::read_client_application_uri_async"},
    std::move(complete));
}

StringResult KeyCredentialDeletedAuditEvent::try_read_client_application_uri_sync() const noexcept
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

String KeyCredentialDeletedAuditEvent::read_client_application_uri_sync() const
{
  return ::ua::detail::good_value(try_read_client_application_uri_sync());
}

void KeyCredentialDeletedAuditEvent::read_event_id_async(
  std::function<void(ByteStringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(ByteStringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<ByteString>(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::event_id_browse_name(),
    &Variant::is_byte_string,
    {"KeyCredentialDeletedAuditEvent", "event_id", "KeyCredentialDeletedAuditEvent::read_event_id_async"},
    std::move(complete));
}

ByteStringResult KeyCredentialDeletedAuditEvent::try_read_event_id_sync() const noexcept
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

ByteString KeyCredentialDeletedAuditEvent::read_event_id_sync() const
{
  return ::ua::detail::good_value(try_read_event_id_sync());
}

void KeyCredentialDeletedAuditEvent::read_event_type_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::event_type_browse_name(),
    &Variant::is_node_id,
    {"KeyCredentialDeletedAuditEvent", "event_type", "KeyCredentialDeletedAuditEvent::read_event_type_async"},
    std::move(complete));
}

NodeIdResult KeyCredentialDeletedAuditEvent::try_read_event_type_sync() const noexcept
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

NodeId KeyCredentialDeletedAuditEvent::read_event_type_sync() const
{
  return ::ua::detail::good_value(try_read_event_type_sync());
}

void KeyCredentialDeletedAuditEvent::read_source_node_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::source_node_browse_name(),
    &Variant::is_node_id,
    {"KeyCredentialDeletedAuditEvent",
      "source_node",
      "KeyCredentialDeletedAuditEvent::read_source_node_async"},
    std::move(complete));
}

NodeIdResult KeyCredentialDeletedAuditEvent::try_read_source_node_sync() const noexcept
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

NodeId KeyCredentialDeletedAuditEvent::read_source_node_sync() const
{
  return ::ua::detail::good_value(try_read_source_node_sync());
}

void KeyCredentialDeletedAuditEvent::read_source_name_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::source_name_browse_name(),
    &Variant::is_string,
    {"KeyCredentialDeletedAuditEvent",
      "source_name",
      "KeyCredentialDeletedAuditEvent::read_source_name_async"},
    std::move(complete));
}

StringResult KeyCredentialDeletedAuditEvent::try_read_source_name_sync() const noexcept
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

String KeyCredentialDeletedAuditEvent::read_source_name_sync() const
{
  return ::ua::detail::good_value(try_read_source_name_sync());
}

void KeyCredentialDeletedAuditEvent::read_message_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::message_browse_name(),
    &Variant::is_localized_text,
    {"KeyCredentialDeletedAuditEvent", "message", "KeyCredentialDeletedAuditEvent::read_message_async"},
    std::move(complete));
}

LocalizedTextResult KeyCredentialDeletedAuditEvent::try_read_message_sync() const noexcept
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

LocalizedText KeyCredentialDeletedAuditEvent::read_message_sync() const
{
  return ::ua::detail::good_value(try_read_message_sync());
}

void KeyCredentialDeletedAuditEvent::read_severity_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::severity_browse_name(),
    &Variant::is_uint16,
    {"KeyCredentialDeletedAuditEvent", "severity", "KeyCredentialDeletedAuditEvent::read_severity_async"},
    std::move(complete));
}

UInt16Result KeyCredentialDeletedAuditEvent::try_read_severity_sync() const noexcept
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

uint16_t KeyCredentialDeletedAuditEvent::read_severity_sync() const
{
  return ::ua::detail::good_value(try_read_severity_sync());
}

void KeyCredentialDeletedAuditEvent::read_condition_class_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::condition_class_id_browse_name(),
    &Variant::is_node_id,
    {"KeyCredentialDeletedAuditEvent",
      "condition_class_id",
      "KeyCredentialDeletedAuditEvent::read_condition_class_id_async"},
    std::move(complete));
}

NodeIdResult KeyCredentialDeletedAuditEvent::try_read_condition_class_id_sync() const noexcept
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

NodeId KeyCredentialDeletedAuditEvent::read_condition_class_id_sync() const
{
  return ::ua::detail::good_value(try_read_condition_class_id_sync());
}

void KeyCredentialDeletedAuditEvent::read_condition_class_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::condition_class_name_browse_name(),
    &Variant::is_localized_text,
    {"KeyCredentialDeletedAuditEvent",
      "condition_class_name",
      "KeyCredentialDeletedAuditEvent::read_condition_class_name_async"},
    std::move(complete));
}

LocalizedTextResult KeyCredentialDeletedAuditEvent::try_read_condition_class_name_sync() const noexcept
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

LocalizedText KeyCredentialDeletedAuditEvent::read_condition_class_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_class_name_sync());
}

void KeyCredentialDeletedAuditEvent::read_condition_sub_class_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::condition_sub_class_id_browse_name(),
    &Variant::is_node_id,
    {"KeyCredentialDeletedAuditEvent",
      "condition_sub_class_id",
      "KeyCredentialDeletedAuditEvent::read_condition_sub_class_id_async"},
    std::move(complete));
}

NodeIdResult KeyCredentialDeletedAuditEvent::try_read_condition_sub_class_id_sync() const noexcept
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

NodeId KeyCredentialDeletedAuditEvent::read_condition_sub_class_id_sync() const
{
  return ::ua::detail::good_value(try_read_condition_sub_class_id_sync());
}

void KeyCredentialDeletedAuditEvent::read_condition_sub_class_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::condition_sub_class_name_browse_name(),
    &Variant::is_localized_text,
    {"KeyCredentialDeletedAuditEvent",
      "condition_sub_class_name",
      "KeyCredentialDeletedAuditEvent::read_condition_sub_class_name_async"},
    std::move(complete));
}

LocalizedTextResult KeyCredentialDeletedAuditEvent::try_read_condition_sub_class_name_sync() const noexcept
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

LocalizedText KeyCredentialDeletedAuditEvent::read_condition_sub_class_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_sub_class_name_sync());
}

// --- Typed value write shortcuts ---

void KeyCredentialDeletedAuditEvent::write_resource_uri_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::resource_uri_browse_name(),
    "KeyCredentialDeletedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialDeletedAuditEvent::try_write_resource_uri_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_resource_uri_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void KeyCredentialDeletedAuditEvent::write_resource_uri_sync(String value) const
{
  try_write_resource_uri_sync(value).value();
}

void KeyCredentialDeletedAuditEvent::write_method_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::method_id_browse_name(),
    "KeyCredentialDeletedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialDeletedAuditEvent::try_write_method_id_sync(NodeId value) const noexcept
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

void KeyCredentialDeletedAuditEvent::write_method_id_sync(NodeId value) const
{
  try_write_method_id_sync(value).value();
}

void KeyCredentialDeletedAuditEvent::write_status_code_id_async(
  StatusCode value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::status_code_id_browse_name(),
    "KeyCredentialDeletedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialDeletedAuditEvent::try_write_status_code_id_sync(StatusCode value) const noexcept
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

void KeyCredentialDeletedAuditEvent::write_status_code_id_sync(StatusCode value) const
{
  try_write_status_code_id_sync(value).value();
}

void KeyCredentialDeletedAuditEvent::write_status_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::status_browse_name(),
    "KeyCredentialDeletedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialDeletedAuditEvent::try_write_status_sync(bool value) const noexcept
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

void KeyCredentialDeletedAuditEvent::write_status_sync(bool value) const
{
  try_write_status_sync(value).value();
}

void KeyCredentialDeletedAuditEvent::write_server_id_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::server_id_browse_name(),
    "KeyCredentialDeletedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialDeletedAuditEvent::try_write_server_id_sync(String value) const noexcept
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

void KeyCredentialDeletedAuditEvent::write_server_id_sync(String value) const
{
  try_write_server_id_sync(value).value();
}

void KeyCredentialDeletedAuditEvent::write_client_audit_entry_id_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::client_audit_entry_id_browse_name(),
    "KeyCredentialDeletedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialDeletedAuditEvent::try_write_client_audit_entry_id_sync(String value) const noexcept
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

void KeyCredentialDeletedAuditEvent::write_client_audit_entry_id_sync(String value) const
{
  try_write_client_audit_entry_id_sync(value).value();
}

void KeyCredentialDeletedAuditEvent::write_client_user_id_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::client_user_id_browse_name(),
    "KeyCredentialDeletedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialDeletedAuditEvent::try_write_client_user_id_sync(String value) const noexcept
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

void KeyCredentialDeletedAuditEvent::write_client_user_id_sync(String value) const
{
  try_write_client_user_id_sync(value).value();
}

void KeyCredentialDeletedAuditEvent::write_client_application_uri_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::client_application_uri_browse_name(),
    "KeyCredentialDeletedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialDeletedAuditEvent::try_write_client_application_uri_sync(String value) const noexcept
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

void KeyCredentialDeletedAuditEvent::write_client_application_uri_sync(String value) const
{
  try_write_client_application_uri_sync(value).value();
}

void KeyCredentialDeletedAuditEvent::write_event_id_async(
  ByteString value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::event_id_browse_name(),
    "KeyCredentialDeletedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialDeletedAuditEvent::try_write_event_id_sync(ByteString value) const noexcept
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

void KeyCredentialDeletedAuditEvent::write_event_id_sync(ByteString value) const
{
  try_write_event_id_sync(value).value();
}

void KeyCredentialDeletedAuditEvent::write_event_type_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::event_type_browse_name(),
    "KeyCredentialDeletedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialDeletedAuditEvent::try_write_event_type_sync(NodeId value) const noexcept
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

void KeyCredentialDeletedAuditEvent::write_event_type_sync(NodeId value) const
{
  try_write_event_type_sync(value).value();
}

void KeyCredentialDeletedAuditEvent::write_source_node_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::source_node_browse_name(),
    "KeyCredentialDeletedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialDeletedAuditEvent::try_write_source_node_sync(NodeId value) const noexcept
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

void KeyCredentialDeletedAuditEvent::write_source_node_sync(NodeId value) const
{
  try_write_source_node_sync(value).value();
}

void KeyCredentialDeletedAuditEvent::write_source_name_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::source_name_browse_name(),
    "KeyCredentialDeletedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialDeletedAuditEvent::try_write_source_name_sync(String value) const noexcept
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

void KeyCredentialDeletedAuditEvent::write_source_name_sync(String value) const
{
  try_write_source_name_sync(value).value();
}

void KeyCredentialDeletedAuditEvent::write_message_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::message_browse_name(),
    "KeyCredentialDeletedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialDeletedAuditEvent::try_write_message_sync(LocalizedText value) const noexcept
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

void KeyCredentialDeletedAuditEvent::write_message_sync(LocalizedText value) const
{
  try_write_message_sync(value).value();
}

void KeyCredentialDeletedAuditEvent::write_severity_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::severity_browse_name(),
    "KeyCredentialDeletedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialDeletedAuditEvent::try_write_severity_sync(uint16_t value) const noexcept
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

void KeyCredentialDeletedAuditEvent::write_severity_sync(uint16_t value) const
{
  try_write_severity_sync(value).value();
}

void KeyCredentialDeletedAuditEvent::write_condition_class_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::condition_class_id_browse_name(),
    "KeyCredentialDeletedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialDeletedAuditEvent::try_write_condition_class_id_sync(NodeId value) const noexcept
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

void KeyCredentialDeletedAuditEvent::write_condition_class_id_sync(NodeId value) const
{
  try_write_condition_class_id_sync(value).value();
}

void KeyCredentialDeletedAuditEvent::write_condition_class_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::condition_class_name_browse_name(),
    "KeyCredentialDeletedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialDeletedAuditEvent::try_write_condition_class_name_sync(
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

void KeyCredentialDeletedAuditEvent::write_condition_class_name_sync(LocalizedText value) const
{
  try_write_condition_class_name_sync(value).value();
}

void KeyCredentialDeletedAuditEvent::write_condition_sub_class_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::condition_sub_class_id_browse_name(),
    "KeyCredentialDeletedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialDeletedAuditEvent::try_write_condition_sub_class_id_sync(NodeId value) const noexcept
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

void KeyCredentialDeletedAuditEvent::write_condition_sub_class_id_sync(NodeId value) const
{
  try_write_condition_sub_class_id_sync(value).value();
}

void KeyCredentialDeletedAuditEvent::write_condition_sub_class_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialDeletedAuditEventTypeTraits::condition_sub_class_name_browse_name(),
    "KeyCredentialDeletedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialDeletedAuditEvent::try_write_condition_sub_class_name_sync(
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

void KeyCredentialDeletedAuditEvent::write_condition_sub_class_name_sync(LocalizedText value) const
{
  try_write_condition_sub_class_name_sync(value).value();
}

}  // namespace ua
