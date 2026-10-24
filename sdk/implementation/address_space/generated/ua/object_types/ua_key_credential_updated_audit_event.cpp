// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_key_credential_updated_audit_event.h"

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

struct KeyCredentialUpdatedAuditEventTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::KeyCredentialUpdatedAuditEventType};
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

KeyCredentialUpdatedAuditEvent::KeyCredentialUpdatedAuditEvent(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void KeyCredentialUpdatedAuditEvent::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    KeyCredentialUpdatedAuditEventTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(KeyCredentialUpdatedAuditEventResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(KeyCredentialUpdatedAuditEventResult{
        KeyCredentialUpdatedAuditEvent{
          std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

KeyCredentialUpdatedAuditEventResult KeyCredentialUpdatedAuditEvent::try_create_sync(
  AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
  const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<KeyCredentialUpdatedAuditEventResult>(addressSpace.executor(),
      [&](std::function<void(KeyCredentialUpdatedAuditEventResult)> complete)
      {
        KeyCredentialUpdatedAuditEvent::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

KeyCredentialUpdatedAuditEvent KeyCredentialUpdatedAuditEvent::create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void KeyCredentialUpdatedAuditEvent::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void KeyCredentialUpdatedAuditEvent::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // KeyCredentialUpdatedAuditEventType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    KeyCredentialUpdatedAuditEventTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(KeyCredentialUpdatedAuditEventResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(KeyCredentialUpdatedAuditEventResult{
          ::ua::detail::address_space_gone("KeyCredentialUpdatedAuditEvent")});
        return;
      }
      complete(KeyCredentialUpdatedAuditEvent{
        std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

KeyCredentialUpdatedAuditEventResult KeyCredentialUpdatedAuditEvent::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<KeyCredentialUpdatedAuditEventResult>(addressSpace.executor(),
      [&](std::function<void(KeyCredentialUpdatedAuditEventResult)> complete)
      {
        KeyCredentialUpdatedAuditEvent::attach_async(
          std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

KeyCredentialUpdatedAuditEvent KeyCredentialUpdatedAuditEvent::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void KeyCredentialUpdatedAuditEvent::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void KeyCredentialUpdatedAuditEvent::find_property_async(
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
    "KeyCredentialUpdatedAuditEvent",
    std::move(complete));
}

// --- Property accessors ---

void KeyCredentialUpdatedAuditEvent::resource_uri_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialUpdatedAuditEventTypeTraits::resource_uri_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialUpdatedAuditEvent::try_resource_uri_property_sync() const noexcept
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

Property KeyCredentialUpdatedAuditEvent::resource_uri_property_sync() const
{
  return ::ua::detail::good_value(try_resource_uri_property_sync());
}

void KeyCredentialUpdatedAuditEvent::method_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(KeyCredentialUpdatedAuditEventTypeTraits::method_id_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialUpdatedAuditEvent::try_method_id_property_sync() const noexcept
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

Property KeyCredentialUpdatedAuditEvent::method_id_property_sync() const
{
  return ::ua::detail::good_value(try_method_id_property_sync());
}

void KeyCredentialUpdatedAuditEvent::status_code_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialUpdatedAuditEventTypeTraits::status_code_id_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialUpdatedAuditEvent::try_status_code_id_property_sync() const noexcept
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

Property KeyCredentialUpdatedAuditEvent::status_code_id_property_sync() const
{
  return ::ua::detail::good_value(try_status_code_id_property_sync());
}

void KeyCredentialUpdatedAuditEvent::input_arguments_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialUpdatedAuditEventTypeTraits::input_arguments_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialUpdatedAuditEvent::try_input_arguments_property_sync() const noexcept
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

Property KeyCredentialUpdatedAuditEvent::input_arguments_property_sync() const
{
  return ::ua::detail::good_value(try_input_arguments_property_sync());
}

void KeyCredentialUpdatedAuditEvent::output_arguments_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialUpdatedAuditEventTypeTraits::output_arguments_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialUpdatedAuditEvent::try_output_arguments_property_sync() const noexcept
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

Property KeyCredentialUpdatedAuditEvent::output_arguments_property_sync() const
{
  return ::ua::detail::good_value(try_output_arguments_property_sync());
}

void KeyCredentialUpdatedAuditEvent::action_time_stamp_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialUpdatedAuditEventTypeTraits::action_time_stamp_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialUpdatedAuditEvent::try_action_time_stamp_property_sync() const noexcept
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

Property KeyCredentialUpdatedAuditEvent::action_time_stamp_property_sync() const
{
  return ::ua::detail::good_value(try_action_time_stamp_property_sync());
}

void KeyCredentialUpdatedAuditEvent::status_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(KeyCredentialUpdatedAuditEventTypeTraits::status_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialUpdatedAuditEvent::try_status_property_sync() const noexcept
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

Property KeyCredentialUpdatedAuditEvent::status_property_sync() const
{
  return ::ua::detail::good_value(try_status_property_sync());
}

void KeyCredentialUpdatedAuditEvent::server_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(KeyCredentialUpdatedAuditEventTypeTraits::server_id_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialUpdatedAuditEvent::try_server_id_property_sync() const noexcept
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

Property KeyCredentialUpdatedAuditEvent::server_id_property_sync() const
{
  return ::ua::detail::good_value(try_server_id_property_sync());
}

void KeyCredentialUpdatedAuditEvent::client_audit_entry_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialUpdatedAuditEventTypeTraits::client_audit_entry_id_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialUpdatedAuditEvent::try_client_audit_entry_id_property_sync() const noexcept
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

Property KeyCredentialUpdatedAuditEvent::client_audit_entry_id_property_sync() const
{
  return ::ua::detail::good_value(try_client_audit_entry_id_property_sync());
}

void KeyCredentialUpdatedAuditEvent::client_user_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialUpdatedAuditEventTypeTraits::client_user_id_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialUpdatedAuditEvent::try_client_user_id_property_sync() const noexcept
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

Property KeyCredentialUpdatedAuditEvent::client_user_id_property_sync() const
{
  return ::ua::detail::good_value(try_client_user_id_property_sync());
}

void KeyCredentialUpdatedAuditEvent::client_application_uri_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialUpdatedAuditEventTypeTraits::client_application_uri_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialUpdatedAuditEvent::try_client_application_uri_property_sync() const noexcept
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

Property KeyCredentialUpdatedAuditEvent::client_application_uri_property_sync() const
{
  return ::ua::detail::good_value(try_client_application_uri_property_sync());
}

void KeyCredentialUpdatedAuditEvent::event_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(KeyCredentialUpdatedAuditEventTypeTraits::event_id_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialUpdatedAuditEvent::try_event_id_property_sync() const noexcept
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

Property KeyCredentialUpdatedAuditEvent::event_id_property_sync() const
{
  return ::ua::detail::good_value(try_event_id_property_sync());
}

void KeyCredentialUpdatedAuditEvent::event_type_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialUpdatedAuditEventTypeTraits::event_type_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialUpdatedAuditEvent::try_event_type_property_sync() const noexcept
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

Property KeyCredentialUpdatedAuditEvent::event_type_property_sync() const
{
  return ::ua::detail::good_value(try_event_type_property_sync());
}

void KeyCredentialUpdatedAuditEvent::source_node_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialUpdatedAuditEventTypeTraits::source_node_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialUpdatedAuditEvent::try_source_node_property_sync() const noexcept
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

Property KeyCredentialUpdatedAuditEvent::source_node_property_sync() const
{
  return ::ua::detail::good_value(try_source_node_property_sync());
}

void KeyCredentialUpdatedAuditEvent::source_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialUpdatedAuditEventTypeTraits::source_name_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialUpdatedAuditEvent::try_source_name_property_sync() const noexcept
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

Property KeyCredentialUpdatedAuditEvent::source_name_property_sync() const
{
  return ::ua::detail::good_value(try_source_name_property_sync());
}

void KeyCredentialUpdatedAuditEvent::time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(KeyCredentialUpdatedAuditEventTypeTraits::time_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialUpdatedAuditEvent::try_time_property_sync() const noexcept
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

Property KeyCredentialUpdatedAuditEvent::time_property_sync() const
{
  return ::ua::detail::good_value(try_time_property_sync());
}

void KeyCredentialUpdatedAuditEvent::receive_time_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialUpdatedAuditEventTypeTraits::receive_time_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialUpdatedAuditEvent::try_receive_time_property_sync() const noexcept
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

Property KeyCredentialUpdatedAuditEvent::receive_time_property_sync() const
{
  return ::ua::detail::good_value(try_receive_time_property_sync());
}

void KeyCredentialUpdatedAuditEvent::local_time_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialUpdatedAuditEventTypeTraits::local_time_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialUpdatedAuditEvent::try_local_time_property_sync() const noexcept
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

Property KeyCredentialUpdatedAuditEvent::local_time_property_sync() const
{
  return ::ua::detail::good_value(try_local_time_property_sync());
}

void KeyCredentialUpdatedAuditEvent::message_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(KeyCredentialUpdatedAuditEventTypeTraits::message_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialUpdatedAuditEvent::try_message_property_sync() const noexcept
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

Property KeyCredentialUpdatedAuditEvent::message_property_sync() const
{
  return ::ua::detail::good_value(try_message_property_sync());
}

void KeyCredentialUpdatedAuditEvent::severity_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(KeyCredentialUpdatedAuditEventTypeTraits::severity_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialUpdatedAuditEvent::try_severity_property_sync() const noexcept
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

Property KeyCredentialUpdatedAuditEvent::severity_property_sync() const
{
  return ::ua::detail::good_value(try_severity_property_sync());
}

void KeyCredentialUpdatedAuditEvent::condition_class_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialUpdatedAuditEventTypeTraits::condition_class_id_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialUpdatedAuditEvent::try_condition_class_id_property_sync() const noexcept
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

Property KeyCredentialUpdatedAuditEvent::condition_class_id_property_sync() const
{
  return ::ua::detail::good_value(try_condition_class_id_property_sync());
}

void KeyCredentialUpdatedAuditEvent::condition_class_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialUpdatedAuditEventTypeTraits::condition_class_name_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialUpdatedAuditEvent::try_condition_class_name_property_sync() const noexcept
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

Property KeyCredentialUpdatedAuditEvent::condition_class_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_class_name_property_sync());
}

void KeyCredentialUpdatedAuditEvent::condition_sub_class_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialUpdatedAuditEventTypeTraits::condition_sub_class_id_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialUpdatedAuditEvent::try_condition_sub_class_id_property_sync() const noexcept
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

Property KeyCredentialUpdatedAuditEvent::condition_sub_class_id_property_sync() const
{
  return ::ua::detail::good_value(try_condition_sub_class_id_property_sync());
}

void KeyCredentialUpdatedAuditEvent::condition_sub_class_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialUpdatedAuditEventTypeTraits::condition_sub_class_name_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialUpdatedAuditEvent::try_condition_sub_class_name_property_sync() const noexcept
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

Property KeyCredentialUpdatedAuditEvent::condition_sub_class_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_sub_class_name_property_sync());
}

// --- Typed value read shortcuts ---

void KeyCredentialUpdatedAuditEvent::read_resource_uri_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::resource_uri_browse_name(),
    &Variant::is_string,
    {"KeyCredentialUpdatedAuditEvent",
      "resource_uri",
      "KeyCredentialUpdatedAuditEvent::read_resource_uri_async"},
    std::move(complete));
}

StringResult KeyCredentialUpdatedAuditEvent::try_read_resource_uri_sync() const noexcept
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

String KeyCredentialUpdatedAuditEvent::read_resource_uri_sync() const
{
  return ::ua::detail::good_value(try_read_resource_uri_sync());
}

void KeyCredentialUpdatedAuditEvent::read_method_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::method_id_browse_name(),
    &Variant::is_node_id,
    {"KeyCredentialUpdatedAuditEvent", "method_id", "KeyCredentialUpdatedAuditEvent::read_method_id_async"},
    std::move(complete));
}

NodeIdResult KeyCredentialUpdatedAuditEvent::try_read_method_id_sync() const noexcept
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

NodeId KeyCredentialUpdatedAuditEvent::read_method_id_sync() const
{
  return ::ua::detail::good_value(try_read_method_id_sync());
}

void KeyCredentialUpdatedAuditEvent::read_status_code_id_async(
  std::function<void(Result<StatusCode>)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(Result<StatusCode>{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<StatusCode>(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::status_code_id_browse_name(),
    &Variant::is_status_code,
    {"KeyCredentialUpdatedAuditEvent",
      "status_code_id",
      "KeyCredentialUpdatedAuditEvent::read_status_code_id_async"},
    std::move(complete));
}

Result<StatusCode> KeyCredentialUpdatedAuditEvent::try_read_status_code_id_sync() const noexcept
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

StatusCode KeyCredentialUpdatedAuditEvent::read_status_code_id_sync() const
{
  return ::ua::detail::good_value(try_read_status_code_id_sync());
}

void KeyCredentialUpdatedAuditEvent::read_status_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::status_browse_name(),
    &Variant::is_boolean,
    {"KeyCredentialUpdatedAuditEvent", "status", "KeyCredentialUpdatedAuditEvent::read_status_async"},
    std::move(complete));
}

BoolResult KeyCredentialUpdatedAuditEvent::try_read_status_sync() const noexcept
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

bool KeyCredentialUpdatedAuditEvent::read_status_sync() const
{
  return ::ua::detail::good_value(try_read_status_sync());
}

void KeyCredentialUpdatedAuditEvent::read_server_id_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::server_id_browse_name(),
    &Variant::is_string,
    {"KeyCredentialUpdatedAuditEvent", "server_id", "KeyCredentialUpdatedAuditEvent::read_server_id_async"},
    std::move(complete));
}

StringResult KeyCredentialUpdatedAuditEvent::try_read_server_id_sync() const noexcept
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

String KeyCredentialUpdatedAuditEvent::read_server_id_sync() const
{
  return ::ua::detail::good_value(try_read_server_id_sync());
}

void KeyCredentialUpdatedAuditEvent::read_client_audit_entry_id_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::client_audit_entry_id_browse_name(),
    &Variant::is_string,
    {"KeyCredentialUpdatedAuditEvent",
      "client_audit_entry_id",
      "KeyCredentialUpdatedAuditEvent::read_client_audit_entry_id_async"},
    std::move(complete));
}

StringResult KeyCredentialUpdatedAuditEvent::try_read_client_audit_entry_id_sync() const noexcept
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

String KeyCredentialUpdatedAuditEvent::read_client_audit_entry_id_sync() const
{
  return ::ua::detail::good_value(try_read_client_audit_entry_id_sync());
}

void KeyCredentialUpdatedAuditEvent::read_client_user_id_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::client_user_id_browse_name(),
    &Variant::is_string,
    {"KeyCredentialUpdatedAuditEvent",
      "client_user_id",
      "KeyCredentialUpdatedAuditEvent::read_client_user_id_async"},
    std::move(complete));
}

StringResult KeyCredentialUpdatedAuditEvent::try_read_client_user_id_sync() const noexcept
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

String KeyCredentialUpdatedAuditEvent::read_client_user_id_sync() const
{
  return ::ua::detail::good_value(try_read_client_user_id_sync());
}

void KeyCredentialUpdatedAuditEvent::read_client_application_uri_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::client_application_uri_browse_name(),
    &Variant::is_string,
    {"KeyCredentialUpdatedAuditEvent",
      "client_application_uri",
      "KeyCredentialUpdatedAuditEvent::read_client_application_uri_async"},
    std::move(complete));
}

StringResult KeyCredentialUpdatedAuditEvent::try_read_client_application_uri_sync() const noexcept
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

String KeyCredentialUpdatedAuditEvent::read_client_application_uri_sync() const
{
  return ::ua::detail::good_value(try_read_client_application_uri_sync());
}

void KeyCredentialUpdatedAuditEvent::read_event_id_async(
  std::function<void(ByteStringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(ByteStringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<ByteString>(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::event_id_browse_name(),
    &Variant::is_byte_string,
    {"KeyCredentialUpdatedAuditEvent", "event_id", "KeyCredentialUpdatedAuditEvent::read_event_id_async"},
    std::move(complete));
}

ByteStringResult KeyCredentialUpdatedAuditEvent::try_read_event_id_sync() const noexcept
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

ByteString KeyCredentialUpdatedAuditEvent::read_event_id_sync() const
{
  return ::ua::detail::good_value(try_read_event_id_sync());
}

void KeyCredentialUpdatedAuditEvent::read_event_type_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::event_type_browse_name(),
    &Variant::is_node_id,
    {"KeyCredentialUpdatedAuditEvent", "event_type", "KeyCredentialUpdatedAuditEvent::read_event_type_async"},
    std::move(complete));
}

NodeIdResult KeyCredentialUpdatedAuditEvent::try_read_event_type_sync() const noexcept
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

NodeId KeyCredentialUpdatedAuditEvent::read_event_type_sync() const
{
  return ::ua::detail::good_value(try_read_event_type_sync());
}

void KeyCredentialUpdatedAuditEvent::read_source_node_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::source_node_browse_name(),
    &Variant::is_node_id,
    {"KeyCredentialUpdatedAuditEvent",
      "source_node",
      "KeyCredentialUpdatedAuditEvent::read_source_node_async"},
    std::move(complete));
}

NodeIdResult KeyCredentialUpdatedAuditEvent::try_read_source_node_sync() const noexcept
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

NodeId KeyCredentialUpdatedAuditEvent::read_source_node_sync() const
{
  return ::ua::detail::good_value(try_read_source_node_sync());
}

void KeyCredentialUpdatedAuditEvent::read_source_name_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::source_name_browse_name(),
    &Variant::is_string,
    {"KeyCredentialUpdatedAuditEvent",
      "source_name",
      "KeyCredentialUpdatedAuditEvent::read_source_name_async"},
    std::move(complete));
}

StringResult KeyCredentialUpdatedAuditEvent::try_read_source_name_sync() const noexcept
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

String KeyCredentialUpdatedAuditEvent::read_source_name_sync() const
{
  return ::ua::detail::good_value(try_read_source_name_sync());
}

void KeyCredentialUpdatedAuditEvent::read_message_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::message_browse_name(),
    &Variant::is_localized_text,
    {"KeyCredentialUpdatedAuditEvent", "message", "KeyCredentialUpdatedAuditEvent::read_message_async"},
    std::move(complete));
}

LocalizedTextResult KeyCredentialUpdatedAuditEvent::try_read_message_sync() const noexcept
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

LocalizedText KeyCredentialUpdatedAuditEvent::read_message_sync() const
{
  return ::ua::detail::good_value(try_read_message_sync());
}

void KeyCredentialUpdatedAuditEvent::read_severity_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::severity_browse_name(),
    &Variant::is_uint16,
    {"KeyCredentialUpdatedAuditEvent", "severity", "KeyCredentialUpdatedAuditEvent::read_severity_async"},
    std::move(complete));
}

UInt16Result KeyCredentialUpdatedAuditEvent::try_read_severity_sync() const noexcept
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

uint16_t KeyCredentialUpdatedAuditEvent::read_severity_sync() const
{
  return ::ua::detail::good_value(try_read_severity_sync());
}

void KeyCredentialUpdatedAuditEvent::read_condition_class_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::condition_class_id_browse_name(),
    &Variant::is_node_id,
    {"KeyCredentialUpdatedAuditEvent",
      "condition_class_id",
      "KeyCredentialUpdatedAuditEvent::read_condition_class_id_async"},
    std::move(complete));
}

NodeIdResult KeyCredentialUpdatedAuditEvent::try_read_condition_class_id_sync() const noexcept
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

NodeId KeyCredentialUpdatedAuditEvent::read_condition_class_id_sync() const
{
  return ::ua::detail::good_value(try_read_condition_class_id_sync());
}

void KeyCredentialUpdatedAuditEvent::read_condition_class_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::condition_class_name_browse_name(),
    &Variant::is_localized_text,
    {"KeyCredentialUpdatedAuditEvent",
      "condition_class_name",
      "KeyCredentialUpdatedAuditEvent::read_condition_class_name_async"},
    std::move(complete));
}

LocalizedTextResult KeyCredentialUpdatedAuditEvent::try_read_condition_class_name_sync() const noexcept
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

LocalizedText KeyCredentialUpdatedAuditEvent::read_condition_class_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_class_name_sync());
}

void KeyCredentialUpdatedAuditEvent::read_condition_sub_class_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::condition_sub_class_id_browse_name(),
    &Variant::is_node_id,
    {"KeyCredentialUpdatedAuditEvent",
      "condition_sub_class_id",
      "KeyCredentialUpdatedAuditEvent::read_condition_sub_class_id_async"},
    std::move(complete));
}

NodeIdResult KeyCredentialUpdatedAuditEvent::try_read_condition_sub_class_id_sync() const noexcept
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

NodeId KeyCredentialUpdatedAuditEvent::read_condition_sub_class_id_sync() const
{
  return ::ua::detail::good_value(try_read_condition_sub_class_id_sync());
}

void KeyCredentialUpdatedAuditEvent::read_condition_sub_class_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::condition_sub_class_name_browse_name(),
    &Variant::is_localized_text,
    {"KeyCredentialUpdatedAuditEvent",
      "condition_sub_class_name",
      "KeyCredentialUpdatedAuditEvent::read_condition_sub_class_name_async"},
    std::move(complete));
}

LocalizedTextResult KeyCredentialUpdatedAuditEvent::try_read_condition_sub_class_name_sync() const noexcept
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

LocalizedText KeyCredentialUpdatedAuditEvent::read_condition_sub_class_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_sub_class_name_sync());
}

// --- Typed value write shortcuts ---

void KeyCredentialUpdatedAuditEvent::write_resource_uri_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::resource_uri_browse_name(),
    "KeyCredentialUpdatedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialUpdatedAuditEvent::try_write_resource_uri_sync(String value) const noexcept
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

void KeyCredentialUpdatedAuditEvent::write_resource_uri_sync(String value) const
{
  try_write_resource_uri_sync(value).value();
}

void KeyCredentialUpdatedAuditEvent::write_method_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::method_id_browse_name(),
    "KeyCredentialUpdatedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialUpdatedAuditEvent::try_write_method_id_sync(NodeId value) const noexcept
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

void KeyCredentialUpdatedAuditEvent::write_method_id_sync(NodeId value) const
{
  try_write_method_id_sync(value).value();
}

void KeyCredentialUpdatedAuditEvent::write_status_code_id_async(
  StatusCode value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::status_code_id_browse_name(),
    "KeyCredentialUpdatedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialUpdatedAuditEvent::try_write_status_code_id_sync(StatusCode value) const noexcept
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

void KeyCredentialUpdatedAuditEvent::write_status_code_id_sync(StatusCode value) const
{
  try_write_status_code_id_sync(value).value();
}

void KeyCredentialUpdatedAuditEvent::write_status_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::status_browse_name(),
    "KeyCredentialUpdatedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialUpdatedAuditEvent::try_write_status_sync(bool value) const noexcept
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

void KeyCredentialUpdatedAuditEvent::write_status_sync(bool value) const
{
  try_write_status_sync(value).value();
}

void KeyCredentialUpdatedAuditEvent::write_server_id_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::server_id_browse_name(),
    "KeyCredentialUpdatedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialUpdatedAuditEvent::try_write_server_id_sync(String value) const noexcept
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

void KeyCredentialUpdatedAuditEvent::write_server_id_sync(String value) const
{
  try_write_server_id_sync(value).value();
}

void KeyCredentialUpdatedAuditEvent::write_client_audit_entry_id_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::client_audit_entry_id_browse_name(),
    "KeyCredentialUpdatedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialUpdatedAuditEvent::try_write_client_audit_entry_id_sync(String value) const noexcept
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

void KeyCredentialUpdatedAuditEvent::write_client_audit_entry_id_sync(String value) const
{
  try_write_client_audit_entry_id_sync(value).value();
}

void KeyCredentialUpdatedAuditEvent::write_client_user_id_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::client_user_id_browse_name(),
    "KeyCredentialUpdatedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialUpdatedAuditEvent::try_write_client_user_id_sync(String value) const noexcept
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

void KeyCredentialUpdatedAuditEvent::write_client_user_id_sync(String value) const
{
  try_write_client_user_id_sync(value).value();
}

void KeyCredentialUpdatedAuditEvent::write_client_application_uri_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::client_application_uri_browse_name(),
    "KeyCredentialUpdatedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialUpdatedAuditEvent::try_write_client_application_uri_sync(String value) const noexcept
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

void KeyCredentialUpdatedAuditEvent::write_client_application_uri_sync(String value) const
{
  try_write_client_application_uri_sync(value).value();
}

void KeyCredentialUpdatedAuditEvent::write_event_id_async(
  ByteString value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::event_id_browse_name(),
    "KeyCredentialUpdatedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialUpdatedAuditEvent::try_write_event_id_sync(ByteString value) const noexcept
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

void KeyCredentialUpdatedAuditEvent::write_event_id_sync(ByteString value) const
{
  try_write_event_id_sync(value).value();
}

void KeyCredentialUpdatedAuditEvent::write_event_type_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::event_type_browse_name(),
    "KeyCredentialUpdatedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialUpdatedAuditEvent::try_write_event_type_sync(NodeId value) const noexcept
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

void KeyCredentialUpdatedAuditEvent::write_event_type_sync(NodeId value) const
{
  try_write_event_type_sync(value).value();
}

void KeyCredentialUpdatedAuditEvent::write_source_node_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::source_node_browse_name(),
    "KeyCredentialUpdatedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialUpdatedAuditEvent::try_write_source_node_sync(NodeId value) const noexcept
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

void KeyCredentialUpdatedAuditEvent::write_source_node_sync(NodeId value) const
{
  try_write_source_node_sync(value).value();
}

void KeyCredentialUpdatedAuditEvent::write_source_name_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::source_name_browse_name(),
    "KeyCredentialUpdatedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialUpdatedAuditEvent::try_write_source_name_sync(String value) const noexcept
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

void KeyCredentialUpdatedAuditEvent::write_source_name_sync(String value) const
{
  try_write_source_name_sync(value).value();
}

void KeyCredentialUpdatedAuditEvent::write_message_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::message_browse_name(),
    "KeyCredentialUpdatedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialUpdatedAuditEvent::try_write_message_sync(LocalizedText value) const noexcept
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

void KeyCredentialUpdatedAuditEvent::write_message_sync(LocalizedText value) const
{
  try_write_message_sync(value).value();
}

void KeyCredentialUpdatedAuditEvent::write_severity_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::severity_browse_name(),
    "KeyCredentialUpdatedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialUpdatedAuditEvent::try_write_severity_sync(uint16_t value) const noexcept
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

void KeyCredentialUpdatedAuditEvent::write_severity_sync(uint16_t value) const
{
  try_write_severity_sync(value).value();
}

void KeyCredentialUpdatedAuditEvent::write_condition_class_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::condition_class_id_browse_name(),
    "KeyCredentialUpdatedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialUpdatedAuditEvent::try_write_condition_class_id_sync(NodeId value) const noexcept
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

void KeyCredentialUpdatedAuditEvent::write_condition_class_id_sync(NodeId value) const
{
  try_write_condition_class_id_sync(value).value();
}

void KeyCredentialUpdatedAuditEvent::write_condition_class_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::condition_class_name_browse_name(),
    "KeyCredentialUpdatedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialUpdatedAuditEvent::try_write_condition_class_name_sync(
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

void KeyCredentialUpdatedAuditEvent::write_condition_class_name_sync(LocalizedText value) const
{
  try_write_condition_class_name_sync(value).value();
}

void KeyCredentialUpdatedAuditEvent::write_condition_sub_class_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::condition_sub_class_id_browse_name(),
    "KeyCredentialUpdatedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialUpdatedAuditEvent::try_write_condition_sub_class_id_sync(NodeId value) const noexcept
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

void KeyCredentialUpdatedAuditEvent::write_condition_sub_class_id_sync(NodeId value) const
{
  try_write_condition_sub_class_id_sync(value).value();
}

void KeyCredentialUpdatedAuditEvent::write_condition_sub_class_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialUpdatedAuditEventTypeTraits::condition_sub_class_name_browse_name(),
    "KeyCredentialUpdatedAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialUpdatedAuditEvent::try_write_condition_sub_class_name_sync(
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

void KeyCredentialUpdatedAuditEvent::write_condition_sub_class_name_sync(LocalizedText value) const
{
  try_write_condition_sub_class_name_sync(value).value();
}

}  // namespace ua
