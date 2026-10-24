// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_dialog_condition.h"

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

struct DialogConditionTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::DialogConditionType};
  }

  static QualifiedName enabled_state_browse_name()
  {
    return QualifiedName{0, "EnabledState"};
  }

  static QualifiedName dialog_state_browse_name()
  {
    return QualifiedName{0, "DialogState"};
  }

  static QualifiedName prompt_browse_name()
  {
    return QualifiedName{0, "Prompt"};
  }

  static QualifiedName response_option_set_browse_name()
  {
    return QualifiedName{0, "ResponseOptionSet"};
  }

  static QualifiedName default_response_browse_name()
  {
    return QualifiedName{0, "DefaultResponse"};
  }

  static QualifiedName ok_response_browse_name()
  {
    return QualifiedName{0, "OkResponse"};
  }

  static QualifiedName cancel_response_browse_name()
  {
    return QualifiedName{0, "CancelResponse"};
  }

  static QualifiedName last_response_browse_name()
  {
    return QualifiedName{0, "LastResponse"};
  }

  static QualifiedName respond_browse_name()
  {
    return QualifiedName{0, "Respond"};
  }

  static QualifiedName respond2_browse_name()
  {
    return QualifiedName{0, "Respond2"};
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

DialogCondition::DialogCondition(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void DialogCondition::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    DialogConditionTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(DialogConditionResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(DialogConditionResult{
        DialogCondition{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

DialogConditionResult DialogCondition::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<DialogConditionResult>(addressSpace.executor(),
      [&](std::function<void(DialogConditionResult)> complete)
      {
        DialogCondition::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

DialogCondition DialogCondition::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void DialogCondition::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void DialogCondition::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // DialogConditionType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    DialogConditionTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(DialogConditionResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(DialogConditionResult{::ua::detail::address_space_gone("DialogCondition")});
        return;
      }
      complete(DialogCondition{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

DialogConditionResult DialogCondition::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<DialogConditionResult>(addressSpace.executor(),
      [&](std::function<void(DialogConditionResult)> complete)
      {
        DialogCondition::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

DialogCondition DialogCondition::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void DialogCondition::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

void DialogCondition::respond_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    DialogConditionTypeTraits::respond_browse_name(),
    std::move(complete));
}

MethodAccessorResult DialogCondition::try_respond_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete) { respond_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor DialogCondition::respond_method_sync() const
{
  return ::ua::detail::good_value(try_respond_method_sync());
}

void DialogCondition::respond2_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    DialogConditionTypeTraits::respond2_browse_name(),
    std::move(complete));
}

MethodAccessorResult DialogCondition::try_respond2_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { respond2_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor DialogCondition::respond2_method_sync() const
{
  return ::ua::detail::good_value(try_respond2_method_sync());
}

// --- Common property helper ---

void DialogCondition::find_property_async(
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
    "DialogCondition",
    std::move(complete));
}

// --- Property accessors ---

void DialogCondition::prompt_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(DialogConditionTypeTraits::prompt_browse_name(), std::move(complete));
}

PropertyResult DialogCondition::try_prompt_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { prompt_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property DialogCondition::prompt_property_sync() const
{
  return ::ua::detail::good_value(try_prompt_property_sync());
}

void DialogCondition::response_option_set_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(DialogConditionTypeTraits::response_option_set_browse_name(), std::move(complete));
}

PropertyResult DialogCondition::try_response_option_set_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { response_option_set_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property DialogCondition::response_option_set_property_sync() const
{
  return ::ua::detail::good_value(try_response_option_set_property_sync());
}

void DialogCondition::default_response_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(DialogConditionTypeTraits::default_response_browse_name(), std::move(complete));
}

PropertyResult DialogCondition::try_default_response_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { default_response_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property DialogCondition::default_response_property_sync() const
{
  return ::ua::detail::good_value(try_default_response_property_sync());
}

void DialogCondition::ok_response_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(DialogConditionTypeTraits::ok_response_browse_name(), std::move(complete));
}

PropertyResult DialogCondition::try_ok_response_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { ok_response_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property DialogCondition::ok_response_property_sync() const
{
  return ::ua::detail::good_value(try_ok_response_property_sync());
}

void DialogCondition::cancel_response_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(DialogConditionTypeTraits::cancel_response_browse_name(), std::move(complete));
}

PropertyResult DialogCondition::try_cancel_response_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { cancel_response_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property DialogCondition::cancel_response_property_sync() const
{
  return ::ua::detail::good_value(try_cancel_response_property_sync());
}

void DialogCondition::last_response_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(DialogConditionTypeTraits::last_response_browse_name(), std::move(complete));
}

PropertyResult DialogCondition::try_last_response_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { last_response_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property DialogCondition::last_response_property_sync() const
{
  return ::ua::detail::good_value(try_last_response_property_sync());
}

void DialogCondition::condition_class_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(DialogConditionTypeTraits::condition_class_id_browse_name(), std::move(complete));
}

PropertyResult DialogCondition::try_condition_class_id_property_sync() const noexcept
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

Property DialogCondition::condition_class_id_property_sync() const
{
  return ::ua::detail::good_value(try_condition_class_id_property_sync());
}

void DialogCondition::condition_class_name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(DialogConditionTypeTraits::condition_class_name_browse_name(), std::move(complete));
}

PropertyResult DialogCondition::try_condition_class_name_property_sync() const noexcept
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

Property DialogCondition::condition_class_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_class_name_property_sync());
}

void DialogCondition::condition_sub_class_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(DialogConditionTypeTraits::condition_sub_class_id_browse_name(), std::move(complete));
}

PropertyResult DialogCondition::try_condition_sub_class_id_property_sync() const noexcept
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

Property DialogCondition::condition_sub_class_id_property_sync() const
{
  return ::ua::detail::good_value(try_condition_sub_class_id_property_sync());
}

void DialogCondition::condition_sub_class_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(DialogConditionTypeTraits::condition_sub_class_name_browse_name(), std::move(complete));
}

PropertyResult DialogCondition::try_condition_sub_class_name_property_sync() const noexcept
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

Property DialogCondition::condition_sub_class_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_sub_class_name_property_sync());
}

void DialogCondition::condition_name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(DialogConditionTypeTraits::condition_name_browse_name(), std::move(complete));
}

PropertyResult DialogCondition::try_condition_name_property_sync() const noexcept
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

Property DialogCondition::condition_name_property_sync() const
{
  return ::ua::detail::good_value(try_condition_name_property_sync());
}

void DialogCondition::branch_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(DialogConditionTypeTraits::branch_id_browse_name(), std::move(complete));
}

PropertyResult DialogCondition::try_branch_id_property_sync() const noexcept
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

Property DialogCondition::branch_id_property_sync() const
{
  return ::ua::detail::good_value(try_branch_id_property_sync());
}

void DialogCondition::retain_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(DialogConditionTypeTraits::retain_browse_name(), std::move(complete));
}

PropertyResult DialogCondition::try_retain_property_sync() const noexcept
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

Property DialogCondition::retain_property_sync() const
{
  return ::ua::detail::good_value(try_retain_property_sync());
}

void DialogCondition::supports_filtered_retain_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(DialogConditionTypeTraits::supports_filtered_retain_browse_name(), std::move(complete));
}

PropertyResult DialogCondition::try_supports_filtered_retain_property_sync() const noexcept
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

Property DialogCondition::supports_filtered_retain_property_sync() const
{
  return ::ua::detail::good_value(try_supports_filtered_retain_property_sync());
}

void DialogCondition::client_user_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(DialogConditionTypeTraits::client_user_id_browse_name(), std::move(complete));
}

PropertyResult DialogCondition::try_client_user_id_property_sync() const noexcept
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

Property DialogCondition::client_user_id_property_sync() const
{
  return ::ua::detail::good_value(try_client_user_id_property_sync());
}

void DialogCondition::event_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(DialogConditionTypeTraits::event_id_browse_name(), std::move(complete));
}

PropertyResult DialogCondition::try_event_id_property_sync() const noexcept
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

Property DialogCondition::event_id_property_sync() const
{
  return ::ua::detail::good_value(try_event_id_property_sync());
}

void DialogCondition::event_type_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(DialogConditionTypeTraits::event_type_browse_name(), std::move(complete));
}

PropertyResult DialogCondition::try_event_type_property_sync() const noexcept
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

Property DialogCondition::event_type_property_sync() const
{
  return ::ua::detail::good_value(try_event_type_property_sync());
}

void DialogCondition::source_node_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(DialogConditionTypeTraits::source_node_browse_name(), std::move(complete));
}

PropertyResult DialogCondition::try_source_node_property_sync() const noexcept
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

Property DialogCondition::source_node_property_sync() const
{
  return ::ua::detail::good_value(try_source_node_property_sync());
}

void DialogCondition::source_name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(DialogConditionTypeTraits::source_name_browse_name(), std::move(complete));
}

PropertyResult DialogCondition::try_source_name_property_sync() const noexcept
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

Property DialogCondition::source_name_property_sync() const
{
  return ::ua::detail::good_value(try_source_name_property_sync());
}

void DialogCondition::time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(DialogConditionTypeTraits::time_browse_name(), std::move(complete));
}

PropertyResult DialogCondition::try_time_property_sync() const noexcept
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

Property DialogCondition::time_property_sync() const
{
  return ::ua::detail::good_value(try_time_property_sync());
}

void DialogCondition::receive_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(DialogConditionTypeTraits::receive_time_browse_name(), std::move(complete));
}

PropertyResult DialogCondition::try_receive_time_property_sync() const noexcept
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

Property DialogCondition::receive_time_property_sync() const
{
  return ::ua::detail::good_value(try_receive_time_property_sync());
}

void DialogCondition::local_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(DialogConditionTypeTraits::local_time_browse_name(), std::move(complete));
}

PropertyResult DialogCondition::try_local_time_property_sync() const noexcept
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

Property DialogCondition::local_time_property_sync() const
{
  return ::ua::detail::good_value(try_local_time_property_sync());
}

void DialogCondition::message_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(DialogConditionTypeTraits::message_browse_name(), std::move(complete));
}

PropertyResult DialogCondition::try_message_property_sync() const noexcept
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

Property DialogCondition::message_property_sync() const
{
  return ::ua::detail::good_value(try_message_property_sync());
}

void DialogCondition::severity_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(DialogConditionTypeTraits::severity_browse_name(), std::move(complete));
}

PropertyResult DialogCondition::try_severity_property_sync() const noexcept
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

Property DialogCondition::severity_property_sync() const
{
  return ::ua::detail::good_value(try_severity_property_sync());
}

// --- Typed value read shortcuts ---

void DialogCondition::read_prompt_async(std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::prompt_browse_name(),
    &Variant::is_localized_text,
    {"DialogCondition", "prompt", "DialogCondition::read_prompt_async"},
    std::move(complete));
}

LocalizedTextResult DialogCondition::try_read_prompt_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LocalizedTextResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(LocalizedTextResult)> complete) { read_prompt_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LocalizedText DialogCondition::read_prompt_sync() const
{
  return ::ua::detail::good_value(try_read_prompt_sync());
}

void DialogCondition::read_response_option_set_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::response_option_set_browse_name(),
    &Variant::is_localized_text,
    {"DialogCondition", "response_option_set", "DialogCondition::read_response_option_set_async"},
    std::move(complete));
}

LocalizedTextResult DialogCondition::try_read_response_option_set_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LocalizedTextResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(LocalizedTextResult)> complete)
      { read_response_option_set_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LocalizedText DialogCondition::read_response_option_set_sync() const
{
  return ::ua::detail::good_value(try_read_response_option_set_sync());
}

void DialogCondition::read_default_response_async(std::function<void(Int32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(Int32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<int32_t>(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::default_response_browse_name(),
    &Variant::is_int32,
    {"DialogCondition", "default_response", "DialogCondition::read_default_response_async"},
    std::move(complete));
}

Int32Result DialogCondition::try_read_default_response_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<Int32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(Int32Result)> complete) { read_default_response_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

int32_t DialogCondition::read_default_response_sync() const
{
  return ::ua::detail::good_value(try_read_default_response_sync());
}

void DialogCondition::read_ok_response_async(std::function<void(Int32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(Int32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<int32_t>(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::ok_response_browse_name(),
    &Variant::is_int32,
    {"DialogCondition", "ok_response", "DialogCondition::read_ok_response_async"},
    std::move(complete));
}

Int32Result DialogCondition::try_read_ok_response_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<Int32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(Int32Result)> complete) { read_ok_response_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

int32_t DialogCondition::read_ok_response_sync() const
{
  return ::ua::detail::good_value(try_read_ok_response_sync());
}

void DialogCondition::read_cancel_response_async(std::function<void(Int32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(Int32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<int32_t>(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::cancel_response_browse_name(),
    &Variant::is_int32,
    {"DialogCondition", "cancel_response", "DialogCondition::read_cancel_response_async"},
    std::move(complete));
}

Int32Result DialogCondition::try_read_cancel_response_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<Int32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(Int32Result)> complete) { read_cancel_response_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

int32_t DialogCondition::read_cancel_response_sync() const
{
  return ::ua::detail::good_value(try_read_cancel_response_sync());
}

void DialogCondition::read_last_response_async(std::function<void(Int32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(Int32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<int32_t>(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::last_response_browse_name(),
    &Variant::is_int32,
    {"DialogCondition", "last_response", "DialogCondition::read_last_response_async"},
    std::move(complete));
}

Int32Result DialogCondition::try_read_last_response_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<Int32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(Int32Result)> complete) { read_last_response_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

int32_t DialogCondition::read_last_response_sync() const
{
  return ::ua::detail::good_value(try_read_last_response_sync());
}

void DialogCondition::read_condition_class_id_async(std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::condition_class_id_browse_name(),
    &Variant::is_node_id,
    {"DialogCondition", "condition_class_id", "DialogCondition::read_condition_class_id_async"},
    std::move(complete));
}

NodeIdResult DialogCondition::try_read_condition_class_id_sync() const noexcept
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

NodeId DialogCondition::read_condition_class_id_sync() const
{
  return ::ua::detail::good_value(try_read_condition_class_id_sync());
}

void DialogCondition::read_condition_class_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::condition_class_name_browse_name(),
    &Variant::is_localized_text,
    {"DialogCondition", "condition_class_name", "DialogCondition::read_condition_class_name_async"},
    std::move(complete));
}

LocalizedTextResult DialogCondition::try_read_condition_class_name_sync() const noexcept
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

LocalizedText DialogCondition::read_condition_class_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_class_name_sync());
}

void DialogCondition::read_condition_sub_class_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::condition_sub_class_id_browse_name(),
    &Variant::is_node_id,
    {"DialogCondition", "condition_sub_class_id", "DialogCondition::read_condition_sub_class_id_async"},
    std::move(complete));
}

NodeIdResult DialogCondition::try_read_condition_sub_class_id_sync() const noexcept
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

NodeId DialogCondition::read_condition_sub_class_id_sync() const
{
  return ::ua::detail::good_value(try_read_condition_sub_class_id_sync());
}

void DialogCondition::read_condition_sub_class_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::condition_sub_class_name_browse_name(),
    &Variant::is_localized_text,
    {"DialogCondition", "condition_sub_class_name", "DialogCondition::read_condition_sub_class_name_async"},
    std::move(complete));
}

LocalizedTextResult DialogCondition::try_read_condition_sub_class_name_sync() const noexcept
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

LocalizedText DialogCondition::read_condition_sub_class_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_sub_class_name_sync());
}

void DialogCondition::read_condition_name_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::condition_name_browse_name(),
    &Variant::is_string,
    {"DialogCondition", "condition_name", "DialogCondition::read_condition_name_async"},
    std::move(complete));
}

StringResult DialogCondition::try_read_condition_name_sync() const noexcept
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

String DialogCondition::read_condition_name_sync() const
{
  return ::ua::detail::good_value(try_read_condition_name_sync());
}

void DialogCondition::read_branch_id_async(std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::branch_id_browse_name(),
    &Variant::is_node_id,
    {"DialogCondition", "branch_id", "DialogCondition::read_branch_id_async"},
    std::move(complete));
}

NodeIdResult DialogCondition::try_read_branch_id_sync() const noexcept
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

NodeId DialogCondition::read_branch_id_sync() const
{
  return ::ua::detail::good_value(try_read_branch_id_sync());
}

void DialogCondition::read_retain_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::retain_browse_name(),
    &Variant::is_boolean,
    {"DialogCondition", "retain", "DialogCondition::read_retain_async"},
    std::move(complete));
}

BoolResult DialogCondition::try_read_retain_sync() const noexcept
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

bool DialogCondition::read_retain_sync() const
{
  return ::ua::detail::good_value(try_read_retain_sync());
}

void DialogCondition::read_supports_filtered_retain_async(
  std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::supports_filtered_retain_browse_name(),
    &Variant::is_boolean,
    {"DialogCondition", "supports_filtered_retain", "DialogCondition::read_supports_filtered_retain_async"},
    std::move(complete));
}

BoolResult DialogCondition::try_read_supports_filtered_retain_sync() const noexcept
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

bool DialogCondition::read_supports_filtered_retain_sync() const
{
  return ::ua::detail::good_value(try_read_supports_filtered_retain_sync());
}

void DialogCondition::read_client_user_id_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::client_user_id_browse_name(),
    &Variant::is_string,
    {"DialogCondition", "client_user_id", "DialogCondition::read_client_user_id_async"},
    std::move(complete));
}

StringResult DialogCondition::try_read_client_user_id_sync() const noexcept
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

String DialogCondition::read_client_user_id_sync() const
{
  return ::ua::detail::good_value(try_read_client_user_id_sync());
}

void DialogCondition::read_event_id_async(std::function<void(ByteStringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(ByteStringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<ByteString>(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::event_id_browse_name(),
    &Variant::is_byte_string,
    {"DialogCondition", "event_id", "DialogCondition::read_event_id_async"},
    std::move(complete));
}

ByteStringResult DialogCondition::try_read_event_id_sync() const noexcept
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

ByteString DialogCondition::read_event_id_sync() const
{
  return ::ua::detail::good_value(try_read_event_id_sync());
}

void DialogCondition::read_event_type_async(std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::event_type_browse_name(),
    &Variant::is_node_id,
    {"DialogCondition", "event_type", "DialogCondition::read_event_type_async"},
    std::move(complete));
}

NodeIdResult DialogCondition::try_read_event_type_sync() const noexcept
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

NodeId DialogCondition::read_event_type_sync() const
{
  return ::ua::detail::good_value(try_read_event_type_sync());
}

void DialogCondition::read_source_node_async(std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::source_node_browse_name(),
    &Variant::is_node_id,
    {"DialogCondition", "source_node", "DialogCondition::read_source_node_async"},
    std::move(complete));
}

NodeIdResult DialogCondition::try_read_source_node_sync() const noexcept
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

NodeId DialogCondition::read_source_node_sync() const
{
  return ::ua::detail::good_value(try_read_source_node_sync());
}

void DialogCondition::read_source_name_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::source_name_browse_name(),
    &Variant::is_string,
    {"DialogCondition", "source_name", "DialogCondition::read_source_name_async"},
    std::move(complete));
}

StringResult DialogCondition::try_read_source_name_sync() const noexcept
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

String DialogCondition::read_source_name_sync() const
{
  return ::ua::detail::good_value(try_read_source_name_sync());
}

void DialogCondition::read_message_async(std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::message_browse_name(),
    &Variant::is_localized_text,
    {"DialogCondition", "message", "DialogCondition::read_message_async"},
    std::move(complete));
}

LocalizedTextResult DialogCondition::try_read_message_sync() const noexcept
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

LocalizedText DialogCondition::read_message_sync() const
{
  return ::ua::detail::good_value(try_read_message_sync());
}

void DialogCondition::read_severity_async(std::function<void(UInt16Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt16Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint16_t>(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::severity_browse_name(),
    &Variant::is_uint16,
    {"DialogCondition", "severity", "DialogCondition::read_severity_async"},
    std::move(complete));
}

UInt16Result DialogCondition::try_read_severity_sync() const noexcept
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

uint16_t DialogCondition::read_severity_sync() const
{
  return ::ua::detail::good_value(try_read_severity_sync());
}

// --- Typed value write shortcuts ---

void DialogCondition::write_prompt_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::prompt_browse_name(),
    "DialogCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult DialogCondition::try_write_prompt_sync(LocalizedText value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_prompt_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void DialogCondition::write_prompt_sync(LocalizedText value) const
{
  try_write_prompt_sync(value).value();
}

void DialogCondition::write_response_option_set_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::response_option_set_browse_name(),
    "DialogCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult DialogCondition::try_write_response_option_set_sync(LocalizedText value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_response_option_set_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void DialogCondition::write_response_option_set_sync(LocalizedText value) const
{
  try_write_response_option_set_sync(value).value();
}

void DialogCondition::write_default_response_async(
  int32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::default_response_browse_name(),
    "DialogCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult DialogCondition::try_write_default_response_sync(int32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_default_response_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void DialogCondition::write_default_response_sync(int32_t value) const
{
  try_write_default_response_sync(value).value();
}

void DialogCondition::write_ok_response_async(
  int32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::ok_response_browse_name(),
    "DialogCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult DialogCondition::try_write_ok_response_sync(int32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_ok_response_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void DialogCondition::write_ok_response_sync(int32_t value) const
{
  try_write_ok_response_sync(value).value();
}

void DialogCondition::write_cancel_response_async(
  int32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::cancel_response_browse_name(),
    "DialogCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult DialogCondition::try_write_cancel_response_sync(int32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_cancel_response_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void DialogCondition::write_cancel_response_sync(int32_t value) const
{
  try_write_cancel_response_sync(value).value();
}

void DialogCondition::write_last_response_async(
  int32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::last_response_browse_name(),
    "DialogCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult DialogCondition::try_write_last_response_sync(int32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_last_response_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void DialogCondition::write_last_response_sync(int32_t value) const
{
  try_write_last_response_sync(value).value();
}

void DialogCondition::write_condition_class_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::condition_class_id_browse_name(),
    "DialogCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult DialogCondition::try_write_condition_class_id_sync(NodeId value) const noexcept
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

void DialogCondition::write_condition_class_id_sync(NodeId value) const
{
  try_write_condition_class_id_sync(value).value();
}

void DialogCondition::write_condition_class_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::condition_class_name_browse_name(),
    "DialogCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult DialogCondition::try_write_condition_class_name_sync(LocalizedText value) const noexcept
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

void DialogCondition::write_condition_class_name_sync(LocalizedText value) const
{
  try_write_condition_class_name_sync(value).value();
}

void DialogCondition::write_condition_sub_class_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::condition_sub_class_id_browse_name(),
    "DialogCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult DialogCondition::try_write_condition_sub_class_id_sync(NodeId value) const noexcept
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

void DialogCondition::write_condition_sub_class_id_sync(NodeId value) const
{
  try_write_condition_sub_class_id_sync(value).value();
}

void DialogCondition::write_condition_sub_class_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::condition_sub_class_name_browse_name(),
    "DialogCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult DialogCondition::try_write_condition_sub_class_name_sync(LocalizedText value) const noexcept
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

void DialogCondition::write_condition_sub_class_name_sync(LocalizedText value) const
{
  try_write_condition_sub_class_name_sync(value).value();
}

void DialogCondition::write_condition_name_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::condition_name_browse_name(),
    "DialogCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult DialogCondition::try_write_condition_name_sync(String value) const noexcept
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

void DialogCondition::write_condition_name_sync(String value) const
{
  try_write_condition_name_sync(value).value();
}

void DialogCondition::write_branch_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::branch_id_browse_name(),
    "DialogCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult DialogCondition::try_write_branch_id_sync(NodeId value) const noexcept
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

void DialogCondition::write_branch_id_sync(NodeId value) const
{
  try_write_branch_id_sync(value).value();
}

void DialogCondition::write_retain_async(bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::retain_browse_name(),
    "DialogCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult DialogCondition::try_write_retain_sync(bool value) const noexcept
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

void DialogCondition::write_retain_sync(bool value) const
{
  try_write_retain_sync(value).value();
}

void DialogCondition::write_supports_filtered_retain_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::supports_filtered_retain_browse_name(),
    "DialogCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult DialogCondition::try_write_supports_filtered_retain_sync(bool value) const noexcept
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

void DialogCondition::write_supports_filtered_retain_sync(bool value) const
{
  try_write_supports_filtered_retain_sync(value).value();
}

void DialogCondition::write_client_user_id_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::client_user_id_browse_name(),
    "DialogCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult DialogCondition::try_write_client_user_id_sync(String value) const noexcept
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

void DialogCondition::write_client_user_id_sync(String value) const
{
  try_write_client_user_id_sync(value).value();
}

void DialogCondition::write_event_id_async(
  ByteString value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::event_id_browse_name(),
    "DialogCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult DialogCondition::try_write_event_id_sync(ByteString value) const noexcept
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

void DialogCondition::write_event_id_sync(ByteString value) const
{
  try_write_event_id_sync(value).value();
}

void DialogCondition::write_event_type_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::event_type_browse_name(),
    "DialogCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult DialogCondition::try_write_event_type_sync(NodeId value) const noexcept
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

void DialogCondition::write_event_type_sync(NodeId value) const
{
  try_write_event_type_sync(value).value();
}

void DialogCondition::write_source_node_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::source_node_browse_name(),
    "DialogCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult DialogCondition::try_write_source_node_sync(NodeId value) const noexcept
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

void DialogCondition::write_source_node_sync(NodeId value) const
{
  try_write_source_node_sync(value).value();
}

void DialogCondition::write_source_name_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::source_name_browse_name(),
    "DialogCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult DialogCondition::try_write_source_name_sync(String value) const noexcept
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

void DialogCondition::write_source_name_sync(String value) const
{
  try_write_source_name_sync(value).value();
}

void DialogCondition::write_message_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::message_browse_name(),
    "DialogCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult DialogCondition::try_write_message_sync(LocalizedText value) const noexcept
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

void DialogCondition::write_message_sync(LocalizedText value) const
{
  try_write_message_sync(value).value();
}

void DialogCondition::write_severity_async(
  uint16_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    DialogConditionTypeTraits::severity_browse_name(),
    "DialogCondition",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult DialogCondition::try_write_severity_sync(uint16_t value) const noexcept
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

void DialogCondition::write_severity_sync(uint16_t value) const
{
  try_write_severity_sync(value).value();
}

// --- Method handler registration ---

void DialogCondition::set_respond_handler_async(
  RespondHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "DialogCondition",
        "DialogCondition::set_respond_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<int32_t>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const int32_t& in0) -> MethodResult<>
      {
        RespondInputArguments typedIn{.selectedResponse = in0};
        return handler(call, typedIn);
      },
      Inputs<int32_t>{{Arg<int32_t>{.name = "SelectedResponse"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, DialogConditionTypeTraits::respond_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult DialogCondition::try_set_respond_handler_sync(RespondHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_respond_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void DialogCondition::set_respond_handler_sync(RespondHandler handler) const
{
  try_set_respond_handler_sync(std::move(handler)).value();
}

void DialogCondition::set_respond_handler_async(
  RespondAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "DialogCondition",
        "DialogCondition::set_respond_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<int32_t>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const int32_t& in0, MethodResultCallback<> complete)
      {
        RespondInputArguments typedIn{.selectedResponse = in0};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<int32_t>{{Arg<int32_t>{.name = "SelectedResponse"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, DialogConditionTypeTraits::respond_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult DialogCondition::try_set_respond_handler_sync(RespondAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_respond_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void DialogCondition::set_respond_handler_sync(RespondAsyncHandler handler) const
{
  try_set_respond_handler_sync(std::move(handler)).value();
}

void DialogCondition::set_respond2_handler_async(
  Respond2Handler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "DialogCondition",
        "DialogCondition::set_respond2_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<int32_t, LocalizedText>, std::tuple<>> adapter{
      [handler = std::move(handler)](
        const MethodCall& call, const int32_t& in0, const LocalizedText& in1) -> MethodResult<>
      {
        Respond2InputArguments typedIn{.selectedResponse = in0, .comment = in1};
        return handler(call, typedIn);
      },
      Inputs<int32_t, LocalizedText>{
        {Arg<int32_t>{.name = "SelectedResponse"}, Arg<LocalizedText>{.name = "Comment"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, DialogConditionTypeTraits::respond2_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult DialogCondition::try_set_respond2_handler_sync(Respond2Handler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_respond2_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void DialogCondition::set_respond2_handler_sync(Respond2Handler handler) const
{
  try_set_respond2_handler_sync(std::move(handler)).value();
}

void DialogCondition::set_respond2_handler_async(
  Respond2AsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "DialogCondition",
        "DialogCondition::set_respond2_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<int32_t, LocalizedText>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const int32_t& in0, const LocalizedText& in1, MethodResultCallback<> complete)
      {
        Respond2InputArguments typedIn{.selectedResponse = in0, .comment = in1};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<int32_t, LocalizedText>{
        {Arg<int32_t>{.name = "SelectedResponse"}, Arg<LocalizedText>{.name = "Comment"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, DialogConditionTypeTraits::respond2_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult DialogCondition::try_set_respond2_handler_sync(Respond2AsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_respond2_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void DialogCondition::set_respond2_handler_sync(Respond2AsyncHandler handler) const
{
  try_set_respond2_handler_sync(std::move(handler)).value();
}

// --- Child-object accessors ---

void DialogCondition::enabled_state_async(std::function<void(TwoStateVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TwoStateVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<TwoStateVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    DialogConditionTypeTraits::enabled_state_browse_name(),
    "DialogCondition",
    std::move(complete));
}

TwoStateVariableResult DialogCondition::try_enabled_state_sync() const noexcept
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

TwoStateVariable DialogCondition::enabled_state_sync() const
{
  return ::ua::detail::good_value(try_enabled_state_sync());
}

void DialogCondition::dialog_state_async(std::function<void(TwoStateVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(TwoStateVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<TwoStateVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    DialogConditionTypeTraits::dialog_state_browse_name(),
    "DialogCondition",
    std::move(complete));
}

TwoStateVariableResult DialogCondition::try_dialog_state_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TwoStateVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(TwoStateVariableResult)> complete) { dialog_state_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TwoStateVariable DialogCondition::dialog_state_sync() const
{
  return ::ua::detail::good_value(try_dialog_state_sync());
}

}  // namespace ua
