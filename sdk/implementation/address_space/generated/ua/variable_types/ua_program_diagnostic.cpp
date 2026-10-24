// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_program_diagnostic.h"

#include "ua_instance_utils.h"
#include "ua_sync_wait.h"
#include "ua_to_result.h"
#include "ua_weak_address_space.h"

#include <boost/asio/any_io_executor.hpp>

#include <functional>

#include "ua_referencetype_id.h"
#include "ua_variabletype_id.h"

namespace ua
{
namespace
{

struct ProgramDiagnosticTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{VariableTypeId::ProgramDiagnosticType};
  }

  static QualifiedName create_session_id_browse_name()
  {
    return QualifiedName{0, "CreateSessionId"};
  }

  static QualifiedName create_client_name_browse_name()
  {
    return QualifiedName{0, "CreateClientName"};
  }

  static QualifiedName invocation_creation_time_browse_name()
  {
    return QualifiedName{0, "InvocationCreationTime"};
  }

  static QualifiedName last_transition_time_browse_name()
  {
    return QualifiedName{0, "LastTransitionTime"};
  }

  static QualifiedName last_method_call_browse_name()
  {
    return QualifiedName{0, "LastMethodCall"};
  }

  static QualifiedName last_method_session_id_browse_name()
  {
    return QualifiedName{0, "LastMethodSessionId"};
  }

  static QualifiedName last_method_input_arguments_browse_name()
  {
    return QualifiedName{0, "LastMethodInputArguments"};
  }

  static QualifiedName last_method_output_arguments_browse_name()
  {
    return QualifiedName{0, "LastMethodOutputArguments"};
  }

  static QualifiedName last_method_call_time_browse_name()
  {
    return QualifiedName{0, "LastMethodCallTime"};
  }

  static QualifiedName last_method_return_status_browse_name()
  {
    return QualifiedName{0, "LastMethodReturnStatus"};
  }
};

}  // namespace

ProgramDiagnostic::ProgramDiagnostic(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseDataVariable(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void ProgramDiagnostic::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, VariableInstantiationAttributes attributes,
  CreateCompleteCallback complete) noexcept
{
  create_variable_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    ProgramDiagnosticTypeTraits::type_definition_id(),
    std::move(options),
    std::move(attributes),
    [complete = std::move(complete)](BaseVariable::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(ProgramDiagnosticResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(ProgramDiagnosticResult{
        ProgramDiagnostic{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

ProgramDiagnosticResult ProgramDiagnostic::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ProgramDiagnosticResult>(addressSpace.executor(),
      [&](std::function<void(ProgramDiagnosticResult)> complete)
      {
        ProgramDiagnostic::create_async(
          std::move(addressSpace), parent, browseName, options, attributes, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ProgramDiagnostic ProgramDiagnostic::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes)
{
  return ::ua::detail::good_value(
    try_create_sync(std::move(addressSpace), parent, browseName, options, attributes));
}

void ProgramDiagnostic::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes, CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    VariableInstantiationAttributes{attributes},
    std::move(complete));
}

void ProgramDiagnostic::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // ProgramDiagnosticType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    ProgramDiagnosticTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(ProgramDiagnosticResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(ProgramDiagnosticResult{::ua::detail::address_space_gone("ProgramDiagnostic")});
        return;
      }
      complete(ProgramDiagnostic{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

ProgramDiagnosticResult ProgramDiagnostic::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ProgramDiagnosticResult>(addressSpace.executor(),
      [&](std::function<void(ProgramDiagnosticResult)> complete)
      {
        ProgramDiagnostic::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ProgramDiagnostic ProgramDiagnostic::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void ProgramDiagnostic::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void ProgramDiagnostic::find_property_async(
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
    "ProgramDiagnostic",
    std::move(complete));
}

// --- Property accessors ---

void ProgramDiagnostic::create_session_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramDiagnosticTypeTraits::create_session_id_browse_name(), std::move(complete));
}

PropertyResult ProgramDiagnostic::try_create_session_id_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { create_session_id_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ProgramDiagnostic::create_session_id_property_sync() const
{
  return ::ua::detail::good_value(try_create_session_id_property_sync());
}

void ProgramDiagnostic::create_client_name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramDiagnosticTypeTraits::create_client_name_browse_name(), std::move(complete));
}

PropertyResult ProgramDiagnostic::try_create_client_name_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { create_client_name_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ProgramDiagnostic::create_client_name_property_sync() const
{
  return ::ua::detail::good_value(try_create_client_name_property_sync());
}

void ProgramDiagnostic::invocation_creation_time_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ProgramDiagnosticTypeTraits::invocation_creation_time_browse_name(), std::move(complete));
}

PropertyResult ProgramDiagnostic::try_invocation_creation_time_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { invocation_creation_time_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ProgramDiagnostic::invocation_creation_time_property_sync() const
{
  return ::ua::detail::good_value(try_invocation_creation_time_property_sync());
}

void ProgramDiagnostic::last_transition_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramDiagnosticTypeTraits::last_transition_time_browse_name(), std::move(complete));
}

PropertyResult ProgramDiagnostic::try_last_transition_time_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { last_transition_time_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ProgramDiagnostic::last_transition_time_property_sync() const
{
  return ::ua::detail::good_value(try_last_transition_time_property_sync());
}

void ProgramDiagnostic::last_method_call_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramDiagnosticTypeTraits::last_method_call_browse_name(), std::move(complete));
}

PropertyResult ProgramDiagnostic::try_last_method_call_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { last_method_call_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ProgramDiagnostic::last_method_call_property_sync() const
{
  return ::ua::detail::good_value(try_last_method_call_property_sync());
}

void ProgramDiagnostic::last_method_session_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramDiagnosticTypeTraits::last_method_session_id_browse_name(), std::move(complete));
}

PropertyResult ProgramDiagnostic::try_last_method_session_id_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { last_method_session_id_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ProgramDiagnostic::last_method_session_id_property_sync() const
{
  return ::ua::detail::good_value(try_last_method_session_id_property_sync());
}

void ProgramDiagnostic::last_method_input_arguments_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ProgramDiagnosticTypeTraits::last_method_input_arguments_browse_name(), std::move(complete));
}

PropertyResult ProgramDiagnostic::try_last_method_input_arguments_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { last_method_input_arguments_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ProgramDiagnostic::last_method_input_arguments_property_sync() const
{
  return ::ua::detail::good_value(try_last_method_input_arguments_property_sync());
}

void ProgramDiagnostic::last_method_output_arguments_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ProgramDiagnosticTypeTraits::last_method_output_arguments_browse_name(), std::move(complete));
}

PropertyResult ProgramDiagnostic::try_last_method_output_arguments_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { last_method_output_arguments_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ProgramDiagnostic::last_method_output_arguments_property_sync() const
{
  return ::ua::detail::good_value(try_last_method_output_arguments_property_sync());
}

void ProgramDiagnostic::last_method_call_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramDiagnosticTypeTraits::last_method_call_time_browse_name(), std::move(complete));
}

PropertyResult ProgramDiagnostic::try_last_method_call_time_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { last_method_call_time_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ProgramDiagnostic::last_method_call_time_property_sync() const
{
  return ::ua::detail::good_value(try_last_method_call_time_property_sync());
}

void ProgramDiagnostic::last_method_return_status_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    ProgramDiagnosticTypeTraits::last_method_return_status_browse_name(), std::move(complete));
}

PropertyResult ProgramDiagnostic::try_last_method_return_status_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { last_method_return_status_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ProgramDiagnostic::last_method_return_status_property_sync() const
{
  return ::ua::detail::good_value(try_last_method_return_status_property_sync());
}

// --- Typed value read shortcuts ---

void ProgramDiagnostic::read_create_session_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    ProgramDiagnosticTypeTraits::create_session_id_browse_name(),
    &Variant::is_node_id,
    {"ProgramDiagnostic", "create_session_id", "ProgramDiagnostic::read_create_session_id_async"},
    std::move(complete));
}

NodeIdResult ProgramDiagnostic::try_read_create_session_id_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeIdResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(NodeIdResult)> complete) { read_create_session_id_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NodeId ProgramDiagnostic::read_create_session_id_sync() const
{
  return ::ua::detail::good_value(try_read_create_session_id_sync());
}

void ProgramDiagnostic::read_create_client_name_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    ProgramDiagnosticTypeTraits::create_client_name_browse_name(),
    &Variant::is_string,
    {"ProgramDiagnostic", "create_client_name", "ProgramDiagnostic::read_create_client_name_async"},
    std::move(complete));
}

StringResult ProgramDiagnostic::try_read_create_client_name_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete)
      { read_create_client_name_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String ProgramDiagnostic::read_create_client_name_sync() const
{
  return ::ua::detail::good_value(try_read_create_client_name_sync());
}

void ProgramDiagnostic::read_last_method_call_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    ProgramDiagnosticTypeTraits::last_method_call_browse_name(),
    &Variant::is_string,
    {"ProgramDiagnostic", "last_method_call", "ProgramDiagnostic::read_last_method_call_async"},
    std::move(complete));
}

StringResult ProgramDiagnostic::try_read_last_method_call_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_last_method_call_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String ProgramDiagnostic::read_last_method_call_sync() const
{
  return ::ua::detail::good_value(try_read_last_method_call_sync());
}

void ProgramDiagnostic::read_last_method_session_id_async(
  std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    ProgramDiagnosticTypeTraits::last_method_session_id_browse_name(),
    &Variant::is_node_id,
    {"ProgramDiagnostic", "last_method_session_id", "ProgramDiagnostic::read_last_method_session_id_async"},
    std::move(complete));
}

NodeIdResult ProgramDiagnostic::try_read_last_method_session_id_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeIdResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(NodeIdResult)> complete)
      { read_last_method_session_id_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NodeId ProgramDiagnostic::read_last_method_session_id_sync() const
{
  return ::ua::detail::good_value(try_read_last_method_session_id_sync());
}

// --- Typed value write shortcuts ---

void ProgramDiagnostic::write_create_session_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramDiagnosticTypeTraits::create_session_id_browse_name(),
    "ProgramDiagnostic",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramDiagnostic::try_write_create_session_id_sync(NodeId value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_create_session_id_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ProgramDiagnostic::write_create_session_id_sync(NodeId value) const
{
  try_write_create_session_id_sync(value).value();
}

void ProgramDiagnostic::write_create_client_name_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramDiagnosticTypeTraits::create_client_name_browse_name(),
    "ProgramDiagnostic",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramDiagnostic::try_write_create_client_name_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_create_client_name_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ProgramDiagnostic::write_create_client_name_sync(String value) const
{
  try_write_create_client_name_sync(value).value();
}

void ProgramDiagnostic::write_last_method_call_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramDiagnosticTypeTraits::last_method_call_browse_name(),
    "ProgramDiagnostic",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramDiagnostic::try_write_last_method_call_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_last_method_call_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ProgramDiagnostic::write_last_method_call_sync(String value) const
{
  try_write_last_method_call_sync(value).value();
}

void ProgramDiagnostic::write_last_method_session_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProgramDiagnosticTypeTraits::last_method_session_id_browse_name(),
    "ProgramDiagnostic",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProgramDiagnostic::try_write_last_method_session_id_sync(NodeId value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_last_method_session_id_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ProgramDiagnostic::write_last_method_session_id_sync(NodeId value) const
{
  try_write_last_method_session_id_sync(value).value();
}

}  // namespace ua
