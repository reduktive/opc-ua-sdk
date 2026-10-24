// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Adding a typed Method to the address space, and binding a typed handler to an existing one.
/// @ingroup address_space

#ifndef UA_ADD_METHOD_H
#define UA_ADD_METHOD_H

#include "ua_address_space.h"
#include "ua_data_type_of.h"
#include "ua_expanded_node_id.h"
#include "ua_localized_text.h"
#include "ua_method_adapter.h"
#include "ua_method_arguments.h"
#include "ua_method_result.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_result.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace ua
{

/// The choices @ref add_method_sync leaves to the caller.
/// @ingroup address_space
struct MethodConfig
{
  /// The Method node's NodeId. Unset: a new GUID identifier in the parent's namespace, or in namespace 1
  /// when the parent is in namespace 0, which a server's own nodes may not use (OPC 10000-5 4.1).
  std::optional<NodeId> nodeId{};
  /// The Method node's Description attribute. Unset: none.
  std::optional<LocalizedText> description{};
  /// The reference from the parent to the Method.
  NodeId parentReferenceType{ReferenceTypeId::HasComponent};
};

/// @cond ADD_METHOD_DETAIL
namespace detail
{

/// One argument as the SDK publishes and checks it: the C++ description with its DataType still to be
/// resolved against the server's namespace array (D-20).
struct MethodArgumentDescription
{
  std::string name;
  LocalizedText description;
  ExpandedNodeId dataType;
  int32_t valueRank{ValueRank::scalar};
  std::vector<uint32_t> arrayDimensions;
};

template<typename T>
MethodArgumentDescription describe_argument(const Arg<T>& argument)
{
  MethodArgumentDescription described;
  described.name = argument.name;
  described.description = argument.description;
  if (argument.dataType)
  {
    described.dataType = ExpandedNodeId{*argument.dataType};
  }
  else
  {
    described.dataType = data_type_of<T>();
  }
  if (argument.valueRank)
  {
    described.valueRank = *argument.valueRank;
    if (described.valueRank > 0)
    {
      described.arrayDimensions.assign(static_cast<std::size_t>(described.valueRank), 0U);
    }
  }
  else
  {
    described.valueRank = value_rank_of<T>().as_int32();
    described.arrayDimensions = array_dimensions_of<T>();
  }
  return described;
}

template<typename... T>
std::vector<MethodArgumentDescription> describe_arguments(const std::tuple<Arg<T>...>& arguments)
{
  return std::apply([](const Arg<T>&... each)
    { return std::vector<MethodArgumentDescription>{describe_argument(each)...}; },
    arguments);
}

void add_method_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  std::vector<MethodArgumentDescription> inputs, std::vector<MethodArgumentDescription> outputs,
  MethodCallSource::CallHandler handler, MethodConfig config,
  std::function<void(Result<MethodAccessor>)> done) noexcept;

Result<MethodAccessor> try_add_method_sync(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  std::vector<MethodArgumentDescription> inputs, std::vector<MethodArgumentDescription> outputs,
  MethodCallSource::CallHandler handler, MethodConfig config) noexcept;

/// Which Method a binding names: the Method node, or the Object and the Method's BrowseName under it.
struct MethodBindingTarget
{
  NodeId node;
  std::optional<QualifiedName> methodBrowseName;
};

void bind_method_async(AddressSpace addressSpace, MethodBindingTarget target,
  std::vector<MethodArgumentDescription> inputs, std::vector<MethodArgumentDescription> outputs,
  MethodCallSource::CallHandler handler, std::function<void(VoidResult)> done) noexcept;

VoidResult try_bind_method_sync(AddressSpace addressSpace, MethodBindingTarget target,
  std::vector<MethodArgumentDescription> inputs, std::vector<MethodArgumentDescription> outputs,
  MethodCallSource::CallHandler handler) noexcept;

template<typename... In, typename... Out, typename Handler>
MethodCallSource::CallHandler method_call_handler(AddressSpace& addressSpace, const Inputs<In...>& inputs,
  const Outputs<Out...>& /*outputs*/, Handler handler)
{
  return MethodAdapter<std::tuple<In...>, std::tuple<Out...>>{
    std::move(handler), inputs, addressSpace.logger()};
}

}  // namespace detail

/// @endcond

/// Adds a Method to the address space in one call.
///
/// Creates the Method node under @p parent (BrowseName, DisplayName, `Executable = true`, the reference
/// from the parent and its inverse), creates the `InputArguments` and `OutputArguments` Properties that
/// are not empty from @p inputs and @p outputs, and installs @p handler, which is either form a
/// @ref MethodAdapter takes. The published signature and the decoding come from the same description,
/// so they cannot disagree. A DataType of another namespace is resolved against the namespace array; an
/// unregistered one fails with `Bad_InvalidState` naming the URI. A namespace whose nodes do not accept
/// call handlers fails with `Bad_NotSupported`. On a failure the nodes created so far are deleted.
/// The Method is answered with the code its MethodCallSource answered the handler's install with, a Good
/// subcode or an Uncertain code included. A creation or lookup the namespace answers Uncertain is not acted
/// on: it fails with `Bad_InternalError` (`LookupAnswerUncertain`) with the Uncertain code as its cause.
/// The `_async` suffix is how creating the Method completes; the handler may be of either form.
///
/// @param addressSpace The address space.
/// @param parent       The Object the Method belongs to.
/// @param browseName   The Method's BrowseName (its DisplayName is the name).
/// @param inputs       The input arguments (@ref ua::inputs).
/// @param outputs      The output arguments (@ref ua::outputs).
/// @param handler      The handler.
/// @param done         Receives the Method, or an @ref ErrorDetail. Runs on an unspecified thread; never
///                     throws. With a null callback the Method is still added and a failure is logged.
/// @param config       The Method's NodeId, Description and parent reference.
/// @ingroup address_space
template<typename... In, typename... Out, typename Handler>
void add_method_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
  Inputs<In...> inputs, Outputs<Out...> outputs, Handler handler,
  std::function<void(Result<MethodAccessor>)> done, const MethodConfig& config = {}) noexcept
{
  auto callHandler = detail::method_call_handler(addressSpace, inputs, outputs, std::move(handler));
  detail::add_method_async(std::move(addressSpace),
    parent,
    browseName,
    detail::describe_arguments(inputs.args),
    detail::describe_arguments(outputs.args),
    std::move(callHandler),
    config,
    std::move(done));
}

/// Adds a Method to the address space in one call, blocking until it is added. As @ref add_method_async.
///
/// @param addressSpace The address space.
/// @param parent       The Object the Method belongs to.
/// @param browseName   The Method's BrowseName.
/// @param inputs       The input arguments.
/// @param outputs      The output arguments.
/// @param handler      The handler, of either form.
/// @param config       The Method's NodeId, Description and parent reference.
/// @return The Method, or an @ref ErrorDetail, which is `Bad_WouldBlock` on a thread of the address
///         space's executor (use @ref add_method_async there). Never throws.
/// @ingroup address_space
template<typename... In, typename... Out, typename Handler>
Result<MethodAccessor> try_add_method_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, Inputs<In...> inputs, Outputs<Out...> outputs, Handler handler,
  const MethodConfig& config = {}) noexcept
{
  try
  {
    auto callHandler = detail::method_call_handler(addressSpace, inputs, outputs, std::move(handler));
    return detail::try_add_method_sync(std::move(addressSpace),
      parent,
      browseName,
      detail::describe_arguments(inputs.args),
      detail::describe_arguments(outputs.args),
      std::move(callHandler),
      config);
  }
  catch (...)
  {
    return Result<MethodAccessor>{ua::exception_to_status_code(std::current_exception())};
  }
}

/// Adds a Method to the address space in one call, blocking until it is added. As @ref add_method_async.
/// A Good subcode on the answer is not returned; try_add_method_sync() returns it.
///
/// @param addressSpace The address space.
/// @param parent       The Object the Method belongs to.
/// @param browseName   The Method's BrowseName.
/// @param inputs       The input arguments.
/// @param outputs      The output arguments.
/// @param handler      The handler, of either form.
/// @param config       The Method's NodeId, Description and parent reference.
/// @return The Method.
/// @throws UaException with the failure, including `Bad_WouldBlock` on a thread of the address space's
///         executor.
/// @ingroup address_space
template<typename... In, typename... Out, typename Handler>
MethodAccessor add_method_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, Inputs<In...> inputs, Outputs<Out...> outputs, Handler handler,
  const MethodConfig& config = {})
{
  return ua::detail::good_value(try_add_method_sync(std::move(addressSpace),
    parent,
    browseName,
    std::move(inputs),
    std::move(outputs),
    std::move(handler),
    config));
}

/// Installs a typed handler on an existing Method node.
///
/// Before installing, reads the node's `InputArguments` and `OutputArguments` Properties (an absent one
/// has no arguments) and compares their count, names, DataType and ValueRank with @p inputs and
/// @p outputs. A mismatch fails with `Bad_InvalidArgument` and an @ref ErrorDetail whose code says what
/// differs (`MethodArgumentCountMismatch`, `MethodArgumentNameMismatch`, `MethodArgumentTypeMismatch`)
/// and whose context gives the argument's index (`operation.index`), name (`field.name`) and the
/// expected and actual value (`type.expected`, `type.actual` for a DataType or ValueRank). It creates no
/// nodes. For a Method declared on an ObjectType, a call that names the type's Method with an instance
/// as the Object reaches the handler with the instance as @ref MethodCall::object_id. A namespace whose
/// nodes do not accept call handlers fails with `Bad_NotSupported`. The outcome is the code the Method's
/// MethodCallSource answered the install with, whatever it is: a Good subcode, an Uncertain code or a Bad
/// code with its @ref ErrorDetail. A lookup or Property read the namespace answers Uncertain is not acted
/// on: it fails with `Bad_InternalError` (`LookupAnswerUncertain` or `ReadAnswerUncertain`) with the
/// Uncertain code as its cause.
///
/// @param addressSpace The address space.
/// @param methodId     The Method node.
/// @param inputs       The input arguments the node must declare.
/// @param outputs      The output arguments the node must declare.
/// @param handler      The handler, of either form.
/// @param done         Receives the outcome. Runs on an unspecified thread; never throws.
/// @ingroup address_space
template<typename... In, typename... Out, typename Handler>
void bind_method_async(AddressSpace addressSpace, const NodeId& methodId, Inputs<In...> inputs,
  Outputs<Out...> outputs, Handler handler, std::function<void(VoidResult)> done) noexcept
{
  auto callHandler = detail::method_call_handler(addressSpace, inputs, outputs, std::move(handler));
  detail::bind_method_async(std::move(addressSpace),
    detail::MethodBindingTarget{methodId, std::nullopt},
    detail::describe_arguments(inputs.args),
    detail::describe_arguments(outputs.args),
    std::move(callHandler),
    std::move(done));
}

/// Installs a typed handler on the Method named @p methodBrowseName under @p objectId. As the overload
/// that names the Method node.
/// @param addressSpace     The address space.
/// @param objectId         The Object the Method belongs to.
/// @param methodBrowseName The Method's BrowseName under @p objectId.
/// @param inputs           The input arguments the node must declare.
/// @param outputs          The output arguments the node must declare.
/// @param handler          The handler, of either form.
/// @param done             Receives the outcome. Runs on an unspecified thread; never throws.
/// @ingroup address_space
template<typename... In, typename... Out, typename Handler>
void bind_method_async(AddressSpace addressSpace, const NodeId& objectId,
  const QualifiedName& methodBrowseName, Inputs<In...> inputs, Outputs<Out...> outputs, Handler handler,
  std::function<void(VoidResult)> done) noexcept
{
  auto callHandler = detail::method_call_handler(addressSpace, inputs, outputs, std::move(handler));
  detail::bind_method_async(std::move(addressSpace),
    detail::MethodBindingTarget{objectId, methodBrowseName},
    detail::describe_arguments(inputs.args),
    detail::describe_arguments(outputs.args),
    std::move(callHandler),
    std::move(done));
}

/// Installs a typed handler on an existing Method node, blocking until complete. As @ref bind_method_async.
/// @param addressSpace The address space.
/// @param methodId     The Method node.
/// @param inputs       The input arguments the node must declare.
/// @param outputs      The output arguments the node must declare.
/// @param handler      The handler, of either form.
/// @return Success, or an @ref ErrorDetail, which is `Bad_WouldBlock` on a thread of the address space's
///         executor. Never throws.
/// @ingroup address_space
template<typename... In, typename... Out, typename Handler>
VoidResult try_bind_method_sync(AddressSpace addressSpace, const NodeId& methodId, Inputs<In...> inputs,
  Outputs<Out...> outputs, Handler handler) noexcept
{
  try
  {
    auto callHandler = detail::method_call_handler(addressSpace, inputs, outputs, std::move(handler));
    return detail::try_bind_method_sync(std::move(addressSpace),
      detail::MethodBindingTarget{methodId, std::nullopt},
      detail::describe_arguments(inputs.args),
      detail::describe_arguments(outputs.args),
      std::move(callHandler));
  }
  catch (...)
  {
    return VoidResult{ua::exception_to_status_code(std::current_exception())};
  }
}

/// Installs a typed handler on the Method named @p methodBrowseName under @p objectId, blocking until
/// complete. As @ref bind_method_async.
/// @param addressSpace     The address space.
/// @param objectId         The Object the Method belongs to.
/// @param methodBrowseName The Method's BrowseName under @p objectId.
/// @param inputs           The input arguments the node must declare.
/// @param outputs          The output arguments the node must declare.
/// @param handler          The handler, of either form.
/// @return Success, or an @ref ErrorDetail. Never throws.
/// @ingroup address_space
template<typename... In, typename... Out, typename Handler>
VoidResult try_bind_method_sync(AddressSpace addressSpace, const NodeId& objectId,
  const QualifiedName& methodBrowseName, Inputs<In...> inputs, Outputs<Out...> outputs,
  Handler handler) noexcept
{
  try
  {
    auto callHandler = detail::method_call_handler(addressSpace, inputs, outputs, std::move(handler));
    return detail::try_bind_method_sync(std::move(addressSpace),
      detail::MethodBindingTarget{objectId, methodBrowseName},
      detail::describe_arguments(inputs.args),
      detail::describe_arguments(outputs.args),
      std::move(callHandler));
  }
  catch (...)
  {
    return VoidResult{ua::exception_to_status_code(std::current_exception())};
  }
}

/// Installs a typed handler on an existing Method node, blocking until complete.
/// @param addressSpace The address space.
/// @param methodId     The Method node.
/// @param inputs       The input arguments the node must declare.
/// @param outputs      The output arguments the node must declare.
/// @param handler      The handler, of either form.
/// @throws UaException with the failure.
/// @ingroup address_space
template<typename... In, typename... Out, typename Handler>
void bind_method_sync(AddressSpace addressSpace, const NodeId& methodId, Inputs<In...> inputs,
  Outputs<Out...> outputs, Handler handler)
{
  (void)try_bind_method_sync(
    std::move(addressSpace), methodId, std::move(inputs), std::move(outputs), std::move(handler))
    .value();
}

/// Installs a typed handler on the Method named @p methodBrowseName under @p objectId, blocking until
/// complete.
/// @param addressSpace     The address space.
/// @param objectId         The Object the Method belongs to.
/// @param methodBrowseName The Method's BrowseName under @p objectId.
/// @param inputs           The input arguments the node must declare.
/// @param outputs          The output arguments the node must declare.
/// @param handler          The handler, of either form.
/// @throws UaException with the failure.
/// @ingroup address_space
template<typename... In, typename... Out, typename Handler>
void bind_method_sync(AddressSpace addressSpace, const NodeId& objectId,
  const QualifiedName& methodBrowseName, Inputs<In...> inputs, Outputs<Out...> outputs, Handler handler)
{
  (void)try_bind_method_sync(std::move(addressSpace),
    objectId,
    methodBrowseName,
    std::move(inputs),
    std::move(outputs),
    std::move(handler))
    .value();
}

}  // namespace ua

#endif  // UA_ADD_METHOD_H
