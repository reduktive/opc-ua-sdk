// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_program_transition_audit_event.h"

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

struct ProgramTransitionAuditEventTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::ProgramTransitionAuditEventType};
  }

  static QualifiedName transition_browse_name()
  {
    return QualifiedName{0, "Transition"};
  }

  static QualifiedName old_state_id_browse_name()
  {
    return QualifiedName{0, "OldStateId"};
  }

  static QualifiedName new_state_id_browse_name()
  {
    return QualifiedName{0, "NewStateId"};
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

ProgramTransitionAuditEvent::ProgramTransitionAuditEvent(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void ProgramTransitionAuditEvent::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    ProgramTransitionAuditEventTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(ProgramTransitionAuditEventResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(ProgramTransitionAuditEventResult{
        ProgramTransitionAuditEvent{
          std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

ProgramTransitionAuditEventResult ProgramTransitionAuditEvent::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ProgramTransitionAuditEventResult>(addressSpace.executor(),
      [&](std::function<void(ProgramTransitionAuditEventResult)> complete)
      {
        ProgramTransitionAuditEvent::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ProgramTransitionAuditEvent ProgramTransitionAuditEvent::create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void ProgramTransitionAuditEvent::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void ProgramTransitionAuditEvent::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // ProgramTransitionAuditEventType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    ProgramTransitionAuditEventTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(ProgramTransitionAuditEventResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(
          ProgramTransitionAuditEventResult{::ua::detail::address_space_gone("ProgramTransitionAuditEvent")});
        return;
      }
      complete(ProgramTransitionAuditEvent{
        std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

ProgramTransitionAuditEventResult ProgramTransitionAuditEvent::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ProgramTransitionAuditEventResult>(addressSpace.executor(),
      [&](std::function<void(ProgramTransitionAuditEventResult)> complete)
      {
        ProgramTransitionAuditEvent::attach_async(
          std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ProgramTransitionAuditEvent ProgramTransitionAuditEvent::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void ProgramTransitionAuditEvent::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void ProgramTransitionAuditEvent::find_property_async(
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
    "ProgramTransitionAuditEvent",
    std::move(complete));
}

// --- Property accessors ---

void ProgramTransitionAuditEvent::old_state_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramTransitionAuditEventTypeTraits::old_state_id_browse_name(), std::move(complete));
}

PropertyResult ProgramTransitionAuditEvent::try_old_state_id_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { old_state_id_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ProgramTransitionAuditEvent::old_state_id_property_sync() const
{
  return ::ua::detail::good_value(try_old_state_id_property_sync());
}

void ProgramTransitionAuditEvent::new_state_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramTransitionAuditEventTypeTraits::new_state_id_browse_name(), std::move(complete));
}

PropertyResult ProgramTransitionAuditEvent::try_new_state_id_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { new_state_id_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ProgramTransitionAuditEvent::new_state_id_property_sync() const
{
  return ::ua::detail::good_value(try_new_state_id_property_sync());
}

void ProgramTransitionAuditEvent::method_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramTransitionAuditEventTypeTraits::method_id_browse_name(), std::move(complete));
}

PropertyResult ProgramTransitionAuditEvent::try_method_id_property_sync() const noexcept
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

Property ProgramTransitionAuditEvent::method_id_property_sync() const
{
  return ::ua::detail::good_value(try_method_id_property_sync());
}

void ProgramTransitionAuditEvent::status_code_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ProgramTransitionAuditEventTypeTraits::status_code_id_browse_name(), std::move(complete));
}

PropertyResult ProgramTransitionAuditEvent::try_status_code_id_property_sync() const noexcept
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

Property ProgramTransitionAuditEvent::status_code_id_property_sync() const
{
  return ::ua::detail::good_value(try_status_code_id_property_sync());
}

void ProgramTransitionAuditEvent::input_arguments_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ProgramTransitionAuditEventTypeTraits::input_arguments_browse_name(), std::move(complete));
}

PropertyResult ProgramTransitionAuditEvent::try_input_arguments_property_sync() const noexcept
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

Property ProgramTransitionAuditEvent::input_arguments_property_sync() const
{
  return ::ua::detail::good_value(try_input_arguments_property_sync());
}

void ProgramTransitionAuditEvent::output_arguments_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ProgramTransitionAuditEventTypeTraits::output_arguments_browse_name(), std::move(complete));
}

PropertyResult ProgramTransitionAuditEvent::try_output_arguments_property_sync() const noexcept
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

Property ProgramTransitionAuditEvent::output_arguments_property_sync() const
{
  return ::ua::detail::good_value(try_output_arguments_property_sync());
}

void ProgramTransitionAuditEvent::action_time_stamp_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ProgramTransitionAuditEventTypeTraits::action_time_stamp_browse_name(), std::move(complete));
}

PropertyResult ProgramTransitionAuditEvent::try_action_time_stamp_property_sync() const noexcept
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

Property ProgramTransitionAuditEvent::action_time_stamp_property_sync() const
{
  return ::ua::detail::good_value(try_action_time_stamp_property_sync());
}

void ProgramTransitionAuditEvent::status_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramTransitionAuditEventTypeTraits::status_browse_name(), std::move(complete));
}

PropertyResult ProgramTransitionAuditEvent::try_status_property_sync() const noexcept
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

Property ProgramTransitionAuditEvent::status_property_sync() const
{
  return ::ua::detail::good_value(try_status_property_sync());
}

void ProgramTransitionAuditEvent::server_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramTransitionAuditEventTypeTraits::server_id_browse_name(), std::move(complete));
}

PropertyResult ProgramTransitionAuditEvent::try_server_id_property_sync() const noexcept
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

Property ProgramTransitionAuditEvent::server_id_property_sync() const
{
  return ::ua::detail::good_value(try_server_id_property_sync());
}

void ProgramTransitionAuditEvent::client_audit_entry_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ProgramTransitionAuditEventTypeTraits::client_audit_entry_id_browse_name(), std::move(complete));
}

PropertyResult ProgramTransitionAuditEvent::try_client_audit_entry_id_property_sync() const noexcept
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

Property ProgramTransitionAuditEvent::client_audit_entry_id_property_sync() const
{
  return ::ua::detail::good_value(try_client_audit_entry_id_property_sync());
}

void ProgramTransitionAuditEvent::client_user_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ProgramTransitionAuditEventTypeTraits::client_user_id_browse_name(), std::move(complete));
}

PropertyResult ProgramTransitionAuditEvent::try_client_user_id_property_sync() const noexcept
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

Property ProgramTransitionAuditEvent::client_user_id_property_sync() const
{
  return ::ua::detail::good_value(try_client_user_id_property_sync());
}

void ProgramTransitionAuditEvent::client_application_uri_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ProgramTransitionAuditEventTypeTraits::client_application_uri_browse_name(), std::move(complete));
}

PropertyResult ProgramTransitionAuditEvent::try_client_application_uri_property_sync() const noexcept
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

Property ProgramTransitionAuditEvent::client_application_uri_property_sync() const
{
  return ::ua::detail::good_value(try_client_application_uri_property_sync());
}

void ProgramTransitionAuditEvent::event_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramTransitionAuditEventTypeTraits::event_id_browse_name(), std::move(complete));
}

PropertyResult ProgramTransitionAuditEvent::try_event_id_property_sync() const noexcept
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

Property ProgramTransitionAuditEvent::event_id_property_sync() const
{
  return ::ua::detail::good_value(try_event_id_property_sync());
}

void ProgramTransitionAuditEvent::event_type_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramTransitionAuditEventTypeTraits::event_type_browse_name(), std::move(complete));
}

PropertyResult ProgramTransitionAuditEvent::try_event_type_property_sync() const noexcept
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

Property ProgramTransitionAuditEvent::event_type_property_sync() const
{
  return ::ua::detail::good_value(try_event_type_property_sync());
}

void ProgramTransitionAuditEvent::source_node_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramTransitionAuditEventTypeTraits::source_node_browse_name(), std::move(complete));
}

PropertyResult ProgramTransitionAuditEvent::try_source_node_property_sync() const noexcept
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

Property ProgramTransitionAuditEvent::source_node_property_sync() const
{
  return ::ua::detail::good_value(try_source_node_property_sync());
}

void ProgramTransitionAuditEvent::source_name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramTransitionAuditEventTypeTraits::source_name_browse_name(), std::move(complete));
}

PropertyResult ProgramTransitionAuditEvent::try_source_name_property_sync() const noexcept
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

Property ProgramTransitionAuditEvent::source_name_property_sync() const
{
  return ::ua::detail::good_value(try_source_name_property_sync());
}

void ProgramTransitionAuditEvent::time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramTransitionAuditEventTypeTraits::time_browse_name(), std::move(complete));
}

PropertyResult ProgramTransitionAuditEvent::try_time_property_sync() const noexcept
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

Property ProgramTransitionAuditEvent::time_property_sync() const
{
  return ::ua::detail::good_value(try_time_property_sync());
}

void ProgramTransitionAuditEvent::receive_time_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramTransitionAuditEventTypeTraits::receive_time_browse_name(), std::move(complete));
}

PropertyResult ProgramTransitionAuditEvent::try_receive_time_property_sync() const noexcept
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

Property ProgramTransitionAuditEvent::receive_time_property_sync() const
{
  return ::ua::detail::good_value(try_receive_time_property_sync());
}

void ProgramTransitionAuditEvent::local_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramTransitionAuditEventTypeTraits::local_time_browse_name(), std::move(complete));
}

PropertyResult ProgramTransitionAuditEvent::try_local_time_property_sync() const noexcept
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

Property ProgramTransitionAuditEvent::local_time_property_sync() const
{
  return ::ua::detail::good_value(try_local_time_property_sync());
}

void ProgramTransitionAuditEvent::message_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramTransitionAuditEventTypeTraits::message_browse_name(), std::move(complete));
}

PropertyResult ProgramTransitionAuditEvent::try_message_property_sync() const noexcept
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

Property ProgramTransitionAuditEvent::message_property_sync() const
{
  return ::ua::detail::good_value(try_message_property_sync());
}

void ProgramTransitionAuditEvent::severity_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramTransitionAuditEventTypeTraits::severity_browse_name(), std::move(complete));
}

PropertyResult ProgramTransitionAuditEvent::try_severity_property_sync() const noexcept
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

Property ProgramTransitionAuditEvent::severity_property_sync() const
{
  return ::ua::detail::good_value(try_severity_property_sync());
}

void ProgramTransitionAuditEvent::condition_class_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ProgramTransitionAuditEventTypeTraits::condition_class_id_browse_name(), std::move(complete));
}

PropertyResult ProgramTransitionAuditEvent::try_condition_class_id_property_sync() const noexcept
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

Property ProgramTransitionAuditEvent::condition_class_id_property_sync() const
{
  return ::ua::detail::good_value(try_condition_class_id_property_sync());
}

void ProgramTransitionAuditEvent::condition_class_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ProgramTransitionAuditEventTypeTraits::condition_class_name_browse_name(), std::move(complete));
}

PropertyResult ProgramTransitionAuditEvent::try_condition_class_name_property_sync() const noexcept
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

Property ProgramTransitionAuditEvent::condition_class_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_class_name_property_sync());
}

void ProgramTransitionAuditEvent::condition_sub_class_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ProgramTransitionAuditEventTypeTraits::condition_sub_class_id_browse_name(), std::move(complete));
}

PropertyResult ProgramTransitionAuditEvent::try_condition_sub_class_id_property_sync() const noexcept
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

Property ProgramTransitionAuditEvent::condition_sub_class_id_property_sync() const
{
  return ::ua::detail::good_value(try_condition_sub_class_id_property_sync());
}

void ProgramTransitionAuditEvent::condition_sub_class_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ProgramTransitionAuditEventTypeTraits::condition_sub_class_name_browse_name(), std::move(complete));
}

PropertyResult ProgramTransitionAuditEvent::try_condition_sub_class_name_property_sync() const noexcept
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

Property ProgramTransitionAuditEvent::condition_sub_class_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_sub_class_name_property_sync());
}

// --- Typed value read shortcuts ---

void ProgramTransitionAuditEvent::read_method_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::method_id_browse_name(),
    &Variant::is_node_id,
    {"ProgramTransitionAuditEvent", "method_id", "ProgramTransitionAuditEvent::read_method_id_async"},
    std::move(complete));
}

NodeIdResult ProgramTransitionAuditEvent::try_read_method_id_sync() const noexcept
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

NodeId ProgramTransitionAuditEvent::read_method_id_sync() const
{
  return ::ua::detail::good_value(try_read_method_id_sync());
}

void ProgramTransitionAuditEvent::read_status_code_id_async(
  std::function<void(Result<StatusCode>)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(Result<StatusCode>{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<StatusCode>(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::status_code_id_browse_name(),
    &Variant::is_status_code,
    {"ProgramTransitionAuditEvent",
      "status_code_id",
      "ProgramTransitionAuditEvent::read_status_code_id_async"},
    std::move(complete));
}

Result<StatusCode> ProgramTransitionAuditEvent::try_read_status_code_id_sync() const noexcept
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

StatusCode ProgramTransitionAuditEvent::read_status_code_id_sync() const
{
  return ::ua::detail::good_value(try_read_status_code_id_sync());
}

void ProgramTransitionAuditEvent::read_status_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::status_browse_name(),
    &Variant::is_boolean,
    {"ProgramTransitionAuditEvent", "status", "ProgramTransitionAuditEvent::read_status_async"},
    std::move(complete));
}

BoolResult ProgramTransitionAuditEvent::try_read_status_sync() const noexcept
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

bool ProgramTransitionAuditEvent::read_status_sync() const
{
  return ::ua::detail::good_value(try_read_status_sync());
}

void ProgramTransitionAuditEvent::read_server_id_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::server_id_browse_name(),
    &Variant::is_string,
    {"ProgramTransitionAuditEvent", "server_id", "ProgramTransitionAuditEvent::read_server_id_async"},
    std::move(complete));
}

StringResult ProgramTransitionAuditEvent::try_read_server_id_sync() const noexcept
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

String ProgramTransitionAuditEvent::read_server_id_sync() const
{
  return ::ua::detail::good_value(try_read_server_id_sync());
}

void ProgramTransitionAuditEvent::read_client_audit_entry_id_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::client_audit_entry_id_browse_name(),
    &Variant::is_string,
    {"ProgramTransitionAuditEvent",
      "client_audit_entry_id",
      "ProgramTransitionAuditEvent::read_client_audit_entry_id_async"},
    std::move(complete));
}

StringResult ProgramTransitionAuditEvent::try_read_client_audit_entry_id_sync() const noexcept
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

String ProgramTransitionAuditEvent::read_client_audit_entry_id_sync() const
{
  return ::ua::detail::good_value(try_read_client_audit_entry_id_sync());
}

void ProgramTransitionAuditEvent::read_client_user_id_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::client_user_id_browse_name(),
    &Variant::is_string,
    {"ProgramTransitionAuditEvent",
      "client_user_id",
      "ProgramTransitionAuditEvent::read_client_user_id_async"},
    std::move(complete));
}

StringResult ProgramTransitionAuditEvent::try_read_client_user_id_sync() const noexcept
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

String ProgramTransitionAuditEvent::read_client_user_id_sync() const
{
  return ::ua::detail::good_value(try_read_client_user_id_sync());
}

void ProgramTransitionAuditEvent::read_client_application_uri_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::client_application_uri_browse_name(),
    &Variant::is_string,
    {"ProgramTransitionAuditEvent",
      "client_application_uri",
      "ProgramTransitionAuditEvent::read_client_application_uri_async"},
    std::move(complete));
}

StringResult ProgramTransitionAuditEvent::try_read_client_application_uri_sync() const noexcept
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

String ProgramTransitionAuditEvent::read_client_application_uri_sync() const
{
  return ::ua::detail::good_value(try_read_client_application_uri_sync());
}

void ProgramTransitionAuditEvent::read_event_id_async(
  std::function<void(ByteStringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(ByteStringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<ByteString>(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::event_id_browse_name(),
    &Variant::is_byte_string,
    {"ProgramTransitionAuditEvent", "event_id", "ProgramTransitionAuditEvent::read_event_id_async"},
    std::move(complete));
}

ByteStringResult ProgramTransitionAuditEvent::try_read_event_id_sync() const noexcept
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

ByteString ProgramTransitionAuditEvent::read_event_id_sync() const
{
  return ::ua::detail::good_value(try_read_event_id_sync());
}

void ProgramTransitionAuditEvent::read_event_type_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::event_type_browse_name(),
    &Variant::is_node_id,
    {"ProgramTransitionAuditEvent", "event_type", "ProgramTransitionAuditEvent::read_event_type_async"},
    std::move(complete));
}

NodeIdResult ProgramTransitionAuditEvent::try_read_event_type_sync() const noexcept
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

NodeId ProgramTransitionAuditEvent::read_event_type_sync() const
{
  return ::ua::detail::good_value(try_read_event_type_sync());
}

void ProgramTransitionAuditEvent::read_source_node_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::source_node_browse_name(),
    &Variant::is_node_id,
    {"ProgramTransitionAuditEvent", "source_node", "ProgramTransitionAuditEvent::read_source_node_async"},
    std::move(complete));
}

NodeIdResult ProgramTransitionAuditEvent::try_read_source_node_sync() const noexcept
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

NodeId ProgramTransitionAuditEvent::read_source_node_sync() const
{
  return ::ua::detail::good_value(try_read_source_node_sync());
}

void ProgramTransitionAuditEvent::read_source_name_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::source_name_browse_name(),
    &Variant::is_string,
    {"ProgramTransitionAuditEvent", "source_name", "ProgramTransitionAuditEvent::read_source_name_async"},
    std::move(complete));
}

StringResult ProgramTransitionAuditEvent::try_read_source_name_sync() const noexcept
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

String ProgramTransitionAuditEvent::read_source_name_sync() const
{
  return ::ua::detail::good_value(try_read_source_name_sync());
}

void ProgramTransitionAuditEvent::read_message_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::message_browse_name(),
    &Variant::is_localized_text,
    {"ProgramTransitionAuditEvent", "message", "ProgramTransitionAuditEvent::read_message_async"},
    std::move(complete));
}

LocalizedTextResult ProgramTransitionAuditEvent::try_read_message_sync() const noexcept
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

LocalizedText ProgramTransitionAuditEvent::read_message_sync() const
{
  return ::ua::detail::good_value(try_read_message_sync());
}

void ProgramTransitionAuditEvent::read_severity_async(
  std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::severity_browse_name(),
    &Variant::is_uint16,
    {"ProgramTransitionAuditEvent", "severity", "ProgramTransitionAuditEvent::read_severity_async"},
    std::move(complete));
}

UInt16Result ProgramTransitionAuditEvent::try_read_severity_sync() const noexcept
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

uint16_t ProgramTransitionAuditEvent::read_severity_sync() const
{
  return ::ua::detail::good_value(try_read_severity_sync());
}

void ProgramTransitionAuditEvent::read_condition_class_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::condition_class_id_browse_name(),
    &Variant::is_node_id,
    {"ProgramTransitionAuditEvent",
      "condition_class_id",
      "ProgramTransitionAuditEvent::read_condition_class_id_async"},
    std::move(complete));
}

NodeIdResult ProgramTransitionAuditEvent::try_read_condition_class_id_sync() const noexcept
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

NodeId ProgramTransitionAuditEvent::read_condition_class_id_sync() const
{
  return ::ua::detail::good_value(try_read_condition_class_id_sync());
}

void ProgramTransitionAuditEvent::read_condition_class_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::condition_class_name_browse_name(),
    &Variant::is_localized_text,
    {"ProgramTransitionAuditEvent",
      "condition_class_name",
      "ProgramTransitionAuditEvent::read_condition_class_name_async"},
    std::move(complete));
}

LocalizedTextResult ProgramTransitionAuditEvent::try_read_condition_class_name_sync() const noexcept
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

LocalizedText ProgramTransitionAuditEvent::read_condition_class_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_class_name_sync());
}

void ProgramTransitionAuditEvent::read_condition_sub_class_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::condition_sub_class_id_browse_name(),
    &Variant::is_node_id,
    {"ProgramTransitionAuditEvent",
      "condition_sub_class_id",
      "ProgramTransitionAuditEvent::read_condition_sub_class_id_async"},
    std::move(complete));
}

NodeIdResult ProgramTransitionAuditEvent::try_read_condition_sub_class_id_sync() const noexcept
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

NodeId ProgramTransitionAuditEvent::read_condition_sub_class_id_sync() const
{
  return ::ua::detail::good_value(try_read_condition_sub_class_id_sync());
}

void ProgramTransitionAuditEvent::read_condition_sub_class_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::condition_sub_class_name_browse_name(),
    &Variant::is_localized_text,
    {"ProgramTransitionAuditEvent",
      "condition_sub_class_name",
      "ProgramTransitionAuditEvent::read_condition_sub_class_name_async"},
    std::move(complete));
}

LocalizedTextResult ProgramTransitionAuditEvent::try_read_condition_sub_class_name_sync() const noexcept
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

LocalizedText ProgramTransitionAuditEvent::read_condition_sub_class_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_sub_class_name_sync());
}

// --- Typed value write shortcuts ---

void ProgramTransitionAuditEvent::write_method_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::method_id_browse_name(),
    "ProgramTransitionAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramTransitionAuditEvent::try_write_method_id_sync(NodeId value) const noexcept
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

void ProgramTransitionAuditEvent::write_method_id_sync(NodeId value) const
{
  try_write_method_id_sync(value).value();
}

void ProgramTransitionAuditEvent::write_status_code_id_async(
  StatusCode value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::status_code_id_browse_name(),
    "ProgramTransitionAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramTransitionAuditEvent::try_write_status_code_id_sync(StatusCode value) const noexcept
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

void ProgramTransitionAuditEvent::write_status_code_id_sync(StatusCode value) const
{
  try_write_status_code_id_sync(value).value();
}

void ProgramTransitionAuditEvent::write_status_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::status_browse_name(),
    "ProgramTransitionAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramTransitionAuditEvent::try_write_status_sync(bool value) const noexcept
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

void ProgramTransitionAuditEvent::write_status_sync(bool value) const
{
  try_write_status_sync(value).value();
}

void ProgramTransitionAuditEvent::write_server_id_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::server_id_browse_name(),
    "ProgramTransitionAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramTransitionAuditEvent::try_write_server_id_sync(String value) const noexcept
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

void ProgramTransitionAuditEvent::write_server_id_sync(String value) const
{
  try_write_server_id_sync(value).value();
}

void ProgramTransitionAuditEvent::write_client_audit_entry_id_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::client_audit_entry_id_browse_name(),
    "ProgramTransitionAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramTransitionAuditEvent::try_write_client_audit_entry_id_sync(String value) const noexcept
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

void ProgramTransitionAuditEvent::write_client_audit_entry_id_sync(String value) const
{
  try_write_client_audit_entry_id_sync(value).value();
}

void ProgramTransitionAuditEvent::write_client_user_id_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::client_user_id_browse_name(),
    "ProgramTransitionAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramTransitionAuditEvent::try_write_client_user_id_sync(String value) const noexcept
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

void ProgramTransitionAuditEvent::write_client_user_id_sync(String value) const
{
  try_write_client_user_id_sync(value).value();
}

void ProgramTransitionAuditEvent::write_client_application_uri_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::client_application_uri_browse_name(),
    "ProgramTransitionAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramTransitionAuditEvent::try_write_client_application_uri_sync(String value) const noexcept
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

void ProgramTransitionAuditEvent::write_client_application_uri_sync(String value) const
{
  try_write_client_application_uri_sync(value).value();
}

void ProgramTransitionAuditEvent::write_event_id_async(
  ByteString value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::event_id_browse_name(),
    "ProgramTransitionAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramTransitionAuditEvent::try_write_event_id_sync(ByteString value) const noexcept
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

void ProgramTransitionAuditEvent::write_event_id_sync(ByteString value) const
{
  try_write_event_id_sync(value).value();
}

void ProgramTransitionAuditEvent::write_event_type_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::event_type_browse_name(),
    "ProgramTransitionAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramTransitionAuditEvent::try_write_event_type_sync(NodeId value) const noexcept
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

void ProgramTransitionAuditEvent::write_event_type_sync(NodeId value) const
{
  try_write_event_type_sync(value).value();
}

void ProgramTransitionAuditEvent::write_source_node_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::source_node_browse_name(),
    "ProgramTransitionAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramTransitionAuditEvent::try_write_source_node_sync(NodeId value) const noexcept
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

void ProgramTransitionAuditEvent::write_source_node_sync(NodeId value) const
{
  try_write_source_node_sync(value).value();
}

void ProgramTransitionAuditEvent::write_source_name_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::source_name_browse_name(),
    "ProgramTransitionAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramTransitionAuditEvent::try_write_source_name_sync(String value) const noexcept
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

void ProgramTransitionAuditEvent::write_source_name_sync(String value) const
{
  try_write_source_name_sync(value).value();
}

void ProgramTransitionAuditEvent::write_message_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::message_browse_name(),
    "ProgramTransitionAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramTransitionAuditEvent::try_write_message_sync(LocalizedText value) const noexcept
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

void ProgramTransitionAuditEvent::write_message_sync(LocalizedText value) const
{
  try_write_message_sync(value).value();
}

void ProgramTransitionAuditEvent::write_severity_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::severity_browse_name(),
    "ProgramTransitionAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramTransitionAuditEvent::try_write_severity_sync(uint16_t value) const noexcept
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

void ProgramTransitionAuditEvent::write_severity_sync(uint16_t value) const
{
  try_write_severity_sync(value).value();
}

void ProgramTransitionAuditEvent::write_condition_class_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::condition_class_id_browse_name(),
    "ProgramTransitionAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramTransitionAuditEvent::try_write_condition_class_id_sync(NodeId value) const noexcept
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

void ProgramTransitionAuditEvent::write_condition_class_id_sync(NodeId value) const
{
  try_write_condition_class_id_sync(value).value();
}

void ProgramTransitionAuditEvent::write_condition_class_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::condition_class_name_browse_name(),
    "ProgramTransitionAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramTransitionAuditEvent::try_write_condition_class_name_sync(
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

void ProgramTransitionAuditEvent::write_condition_class_name_sync(LocalizedText value) const
{
  try_write_condition_class_name_sync(value).value();
}

void ProgramTransitionAuditEvent::write_condition_sub_class_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::condition_sub_class_id_browse_name(),
    "ProgramTransitionAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramTransitionAuditEvent::try_write_condition_sub_class_id_sync(NodeId value) const noexcept
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

void ProgramTransitionAuditEvent::write_condition_sub_class_id_sync(NodeId value) const
{
  try_write_condition_sub_class_id_sync(value).value();
}

void ProgramTransitionAuditEvent::write_condition_sub_class_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramTransitionAuditEventTypeTraits::condition_sub_class_name_browse_name(),
    "ProgramTransitionAuditEvent",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramTransitionAuditEvent::try_write_condition_sub_class_name_sync(
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

void ProgramTransitionAuditEvent::write_condition_sub_class_name_sync(LocalizedText value) const
{
  try_write_condition_sub_class_name_sync(value).value();
}

// --- Child-object accessors ---

void ProgramTransitionAuditEvent::transition_async(
  std::function<void(FiniteTransitionVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(FiniteTransitionVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<FiniteTransitionVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ProgramTransitionAuditEventTypeTraits::transition_browse_name(),
    "ProgramTransitionAuditEvent",
    std::move(complete));
}

FiniteTransitionVariableResult ProgramTransitionAuditEvent::try_transition_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<FiniteTransitionVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(FiniteTransitionVariableResult)> complete)
      { transition_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

FiniteTransitionVariable ProgramTransitionAuditEvent::transition_sync() const
{
  return ::ua::detail::good_value(try_transition_sync());
}

}  // namespace ua
