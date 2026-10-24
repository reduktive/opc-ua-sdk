// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_program_diagnostic2.h"

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

struct ProgramDiagnostic2TypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{VariableTypeId::ProgramDiagnostic2Type};
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

  static QualifiedName last_method_input_values_browse_name()
  {
    return QualifiedName{0, "LastMethodInputValues"};
  }

  static QualifiedName last_method_output_values_browse_name()
  {
    return QualifiedName{0, "LastMethodOutputValues"};
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

ProgramDiagnostic2::ProgramDiagnostic2(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseDataVariable(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void ProgramDiagnostic2::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, VariableInstantiationAttributes attributes,
  CreateCompleteCallback complete) noexcept
{
  create_variable_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    ProgramDiagnostic2TypeTraits::type_definition_id(),
    std::move(options),
    std::move(attributes),
    [complete = std::move(complete)](BaseVariable::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(ProgramDiagnostic2Result{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(ProgramDiagnostic2Result{
        ProgramDiagnostic2{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

ProgramDiagnostic2Result ProgramDiagnostic2::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ProgramDiagnostic2Result>(addressSpace.executor(),
      [&](std::function<void(ProgramDiagnostic2Result)> complete)
      {
        ProgramDiagnostic2::create_async(
          std::move(addressSpace), parent, browseName, options, attributes, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ProgramDiagnostic2 ProgramDiagnostic2::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes)
{
  return ::ua::detail::good_value(
    try_create_sync(std::move(addressSpace), parent, browseName, options, attributes));
}

void ProgramDiagnostic2::create_async(AddressSpace addressSpace, const NodeId& parent,
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

void ProgramDiagnostic2::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // ProgramDiagnostic2Type is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    ProgramDiagnostic2TypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(ProgramDiagnostic2Result{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(ProgramDiagnostic2Result{::ua::detail::address_space_gone("ProgramDiagnostic2")});
        return;
      }
      complete(ProgramDiagnostic2{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

ProgramDiagnostic2Result ProgramDiagnostic2::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ProgramDiagnostic2Result>(addressSpace.executor(),
      [&](std::function<void(ProgramDiagnostic2Result)> complete)
      {
        ProgramDiagnostic2::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ProgramDiagnostic2 ProgramDiagnostic2::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void ProgramDiagnostic2::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void ProgramDiagnostic2::find_property_async(
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
    "ProgramDiagnostic2",
    std::move(complete));
}

// --- Property accessors ---

void ProgramDiagnostic2::last_transition_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProgramDiagnostic2TypeTraits::last_transition_time_browse_name(), std::move(complete));
}

PropertyResult ProgramDiagnostic2::try_last_transition_time_property_sync() const noexcept
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

Property ProgramDiagnostic2::last_transition_time_property_sync() const
{
  return ::ua::detail::good_value(try_last_transition_time_property_sync());
}

// --- Child-object accessors ---

void ProgramDiagnostic2::create_session_id_async(
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
    ProgramDiagnostic2TypeTraits::create_session_id_browse_name(),
    "ProgramDiagnostic2",
    std::move(complete));
}

BaseDataVariableResult ProgramDiagnostic2::try_create_session_id_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { create_session_id_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable ProgramDiagnostic2::create_session_id_sync() const
{
  return ::ua::detail::good_value(try_create_session_id_sync());
}

void ProgramDiagnostic2::create_client_name_async(
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
    ProgramDiagnostic2TypeTraits::create_client_name_browse_name(),
    "ProgramDiagnostic2",
    std::move(complete));
}

BaseDataVariableResult ProgramDiagnostic2::try_create_client_name_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { create_client_name_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable ProgramDiagnostic2::create_client_name_sync() const
{
  return ::ua::detail::good_value(try_create_client_name_sync());
}

void ProgramDiagnostic2::invocation_creation_time_async(
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
    ProgramDiagnostic2TypeTraits::invocation_creation_time_browse_name(),
    "ProgramDiagnostic2",
    std::move(complete));
}

BaseDataVariableResult ProgramDiagnostic2::try_invocation_creation_time_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { invocation_creation_time_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable ProgramDiagnostic2::invocation_creation_time_sync() const
{
  return ::ua::detail::good_value(try_invocation_creation_time_sync());
}

void ProgramDiagnostic2::last_method_call_async(
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
    ProgramDiagnostic2TypeTraits::last_method_call_browse_name(),
    "ProgramDiagnostic2",
    std::move(complete));
}

BaseDataVariableResult ProgramDiagnostic2::try_last_method_call_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { last_method_call_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable ProgramDiagnostic2::last_method_call_sync() const
{
  return ::ua::detail::good_value(try_last_method_call_sync());
}

void ProgramDiagnostic2::last_method_session_id_async(
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
    ProgramDiagnostic2TypeTraits::last_method_session_id_browse_name(),
    "ProgramDiagnostic2",
    std::move(complete));
}

BaseDataVariableResult ProgramDiagnostic2::try_last_method_session_id_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { last_method_session_id_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable ProgramDiagnostic2::last_method_session_id_sync() const
{
  return ::ua::detail::good_value(try_last_method_session_id_sync());
}

void ProgramDiagnostic2::last_method_input_arguments_async(
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
    ProgramDiagnostic2TypeTraits::last_method_input_arguments_browse_name(),
    "ProgramDiagnostic2",
    std::move(complete));
}

BaseDataVariableResult ProgramDiagnostic2::try_last_method_input_arguments_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { last_method_input_arguments_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable ProgramDiagnostic2::last_method_input_arguments_sync() const
{
  return ::ua::detail::good_value(try_last_method_input_arguments_sync());
}

void ProgramDiagnostic2::last_method_output_arguments_async(
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
    ProgramDiagnostic2TypeTraits::last_method_output_arguments_browse_name(),
    "ProgramDiagnostic2",
    std::move(complete));
}

BaseDataVariableResult ProgramDiagnostic2::try_last_method_output_arguments_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { last_method_output_arguments_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable ProgramDiagnostic2::last_method_output_arguments_sync() const
{
  return ::ua::detail::good_value(try_last_method_output_arguments_sync());
}

void ProgramDiagnostic2::last_method_input_values_async(
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
    ProgramDiagnostic2TypeTraits::last_method_input_values_browse_name(),
    "ProgramDiagnostic2",
    std::move(complete));
}

BaseDataVariableResult ProgramDiagnostic2::try_last_method_input_values_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { last_method_input_values_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable ProgramDiagnostic2::last_method_input_values_sync() const
{
  return ::ua::detail::good_value(try_last_method_input_values_sync());
}

void ProgramDiagnostic2::last_method_output_values_async(
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
    ProgramDiagnostic2TypeTraits::last_method_output_values_browse_name(),
    "ProgramDiagnostic2",
    std::move(complete));
}

BaseDataVariableResult ProgramDiagnostic2::try_last_method_output_values_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { last_method_output_values_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable ProgramDiagnostic2::last_method_output_values_sync() const
{
  return ::ua::detail::good_value(try_last_method_output_values_sync());
}

void ProgramDiagnostic2::last_method_call_time_async(
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
    ProgramDiagnostic2TypeTraits::last_method_call_time_browse_name(),
    "ProgramDiagnostic2",
    std::move(complete));
}

BaseDataVariableResult ProgramDiagnostic2::try_last_method_call_time_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { last_method_call_time_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable ProgramDiagnostic2::last_method_call_time_sync() const
{
  return ::ua::detail::good_value(try_last_method_call_time_sync());
}

void ProgramDiagnostic2::last_method_return_status_async(
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
    ProgramDiagnostic2TypeTraits::last_method_return_status_browse_name(),
    "ProgramDiagnostic2",
    std::move(complete));
}

BaseDataVariableResult ProgramDiagnostic2::try_last_method_return_status_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { last_method_return_status_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable ProgramDiagnostic2::last_method_return_status_sync() const
{
  return ::ua::detail::good_value(try_last_method_return_status_sync());
}

}  // namespace ua
