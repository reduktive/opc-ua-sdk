// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// add_method and bind_method (public API review 2026-10, item 8b sections 9.6 and 9.7): the address-space
// work behind the templates in ua_add_method.h, which build the argument descriptions and the adapter.

#include "ua_add_method.h"

#include "ua_access_level_type.h"
#include "ua_argument.h"
#include "ua_attribute_id.h"
#include "ua_attribute_wire.h"
#include "ua_callback_safety.h"
#include "ua_datatype_id.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_guid.h"
#include "ua_instance_utils.h"
#include "ua_namespace_array.h"
#include "ua_namespace_route.h"
#include "ua_ref_structure.h"
#include "ua_referencetype_id.h"
#include "ua_self_owning_operation.h"
#include "ua_sync_wait.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_variabletype_id.h"

#include <boost/asio/strand.hpp>

#include <array>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ua::detail
{

namespace
{

constexpr std::string_view inputArgumentsName{"InputArguments"};
constexpr std::string_view outputArgumentsName{"OutputArguments"};

/// The DataType of @p argument in the server's namespace indexes (D-20).
Result<NodeId> resolve_data_type(AddressSpace& addressSpace, const MethodArgumentDescription& argument)
{
  const ExpandedNodeId& dataType = argument.dataType;
  if (dataType.namespace_uri().empty())
  {
    return Result<NodeId>{dataType.node_id()};
  }
  try
  {
    NodeId resolved = dataType.node_id();
    resolved.namespace_index() = addressSpace.namespace_array().get_namespace_index(dataType.namespace_uri());
    return Result<NodeId>{std::move(resolved)};
  }
  catch (const UaException& exception)
  {
    if (exception.status() != Status::BadOutOfRange)
    {
      throw;
    }
  }
  return Result<NodeId>{StatusCode{Status::BadInvalidState,
    ErrorDetail::build("MethodArgumentNamespaceNotRegistered",
      "An argument's DataType belongs to a namespace that is not registered",
      "add_method")
      .context(ContextKeys::namespaceUri, std::string{dataType.namespace_uri()})
      .context(ContextKeys::argumentName, argument.name)}};
}

/// The Argument structures that describe @p arguments, as a Property publishes them.
Result<std::vector<Argument>> resolve_arguments(
  AddressSpace& addressSpace, const std::vector<MethodArgumentDescription>& arguments)
{
  std::vector<Argument> resolved;
  resolved.reserve(arguments.size());
  for (const auto& described : arguments)
  {
    auto dataType = resolve_data_type(addressSpace, described);
    if (!dataType.is_good())
    {
      return Result<std::vector<Argument>>{dataType.status_code(), dataType.shared_detail()};
    }
    Argument argumentDefinition;
    argumentDefinition.name() = described.name;
    argumentDefinition.description() = described.description;
    argumentDefinition.data_type() = std::move(dataType).value();
    argumentDefinition.value_rank() = described.valueRank;
    argumentDefinition.array_dimensions() = described.arrayDimensions;
    resolved.push_back(std::move(argumentDefinition));
  }
  return Result<std::vector<Argument>>{std::move(resolved)};
}

/// The value of an InputArguments or OutputArguments Property.
Variant arguments_value(const std::vector<Argument>& arguments)
{
  Array<RefStructure<Structure>> elements;
  for (const auto& argumentDefinition : arguments)
  {
    const unique_ptr<Structure> copy = std::make_unique<Argument>(argumentDefinition);
    elements.payload().emplace_back(copy);
  }
  return Variant{std::move(elements)};
}

/// The Argument structures a Property's value holds, or nothing when it holds something else.
std::optional<std::vector<Argument>> declared_arguments(const Variant& value)
{
  const auto* elements = value.try_as<Array<RefStructure<Structure>>>();
  if (elements == nullptr)
  {
    return std::nullopt;
  }
  std::vector<Argument> declared;
  for (const auto& element : elements->payload())
  {
    const auto* argumentDefinition = dynamic_cast<const Argument*>(element.get());
    if (argumentDefinition == nullptr)
    {
      return std::nullopt;
    }
    declared.push_back(*argumentDefinition);
  }
  return declared;
}

/// Compares what a Method node declares in one Property with what a handler describes (section 9.7).
VoidResult compare_arguments(
  std::string_view property, const std::vector<Argument>& declared, const std::vector<Argument>& described)
{
  if (declared.size() != described.size())
  {
    return VoidResult{StatusCode{Status::BadInvalidArgument,
      ErrorDetail::build("MethodArgumentCountMismatch",
        "The Method node declares a different number of arguments than the handler describes",
        "bind_method")
        .context(ContextKeys::nodeBrowseName, std::string{property})
        .context(ContextKeys::sizeExpected, described.size())
        .context(ContextKeys::sizeActual, declared.size())}};
  }
  for (std::size_t index = 0; index < declared.size(); ++index)
  {
    const Argument& onNode = declared[index];
    const Argument& inCode = described[index];
    if (onNode.name() != inCode.name())
    {
      return VoidResult{StatusCode{Status::BadInvalidArgument,
        ErrorDetail::build("MethodArgumentNameMismatch",
          "An argument of the Method node has a different name than the handler describes",
          "bind_method")
          .context(ContextKeys::nodeBrowseName, std::string{property})
          .context(ContextKeys::operationIndex, index)
          .context(ContextKeys::expected, std::string{inCode.name()})
          .context(ContextKeys::actual, std::string{onNode.name()})}};
    }
    if (onNode.data_type() != inCode.data_type())
    {
      return VoidResult{StatusCode{Status::BadInvalidArgument,
        ErrorDetail::build("MethodArgumentTypeMismatch",
          "An argument of the Method node has a different DataType than the handler describes",
          "bind_method")
          .context(ContextKeys::nodeBrowseName, std::string{property})
          .context(ContextKeys::operationIndex, index)
          .context(ContextKeys::fieldName, std::string{onNode.name()})
          .context(ContextKeys::typeExpected, to_string(inCode.data_type()))
          .context(ContextKeys::typeActual, to_string(onNode.data_type()))}};
    }
    if (onNode.value_rank() != inCode.value_rank())
    {
      return VoidResult{StatusCode{Status::BadInvalidArgument,
        ErrorDetail::build("MethodArgumentTypeMismatch",
          "An argument of the Method node has a different ValueRank than the handler describes",
          "bind_method")
          .context(ContextKeys::nodeBrowseName, std::string{property})
          .context(ContextKeys::operationIndex, index)
          .context(ContextKeys::fieldName, std::string{onNode.name()})
          .context(ContextKeys::expected, std::to_string(inCode.value_rank()))
          .context(ContextKeys::actual, std::to_string(onNode.value_rank()))}};
    }
  }
  return VoidResult{};
}

/// Installs @p handler on @p method and answers the code the Method's MethodCallSource answered the install
/// with, whatever it is (a Good subcode, an Uncertain or a Bad code with its ErrorDetail), or says why it
/// cannot be installed.
VoidResult install_handler(const MethodAccessor& method, MethodCallSource::CallHandler handler)
{
  auto* source = method->method_call_source();
  if (source == nullptr)
  {
    return VoidResult{StatusCode{Status::BadNotSupported,
      ErrorDetail::build(
        "MethodCallsNotSupported", "The namespace's Method nodes do not accept call handlers", "add_method")
        .context(ContextKeys::nodeId, to_string(method.get_node_id()))}};
  }
  return VoidResult{source->set_call_handler(std::move(handler))};
}

/// The common steps of the two operations: one address-space call each, awaited on the operation's strand.
///
/// The address space is held weakly and locked only inside a step's initiation, so the operation - which
/// every completion it hands out owns - never keeps it alive across a suspension (ua_namespace.h,
/// Ownership). A step whose address space has gone is answered `address_space_gone`.
template<typename Operation>
class MethodSteps : public ua::async::SelfOwningOperation<Operation>
{
protected:
  explicit MethodSteps(const AddressSpace& addressSpace)
    : ua::async::SelfOwningOperation<Operation>(
        boost::asio::make_strand(addressSpace.executor()), addressSpace.logger()),
      mAddressSpace(addressSpace.weak())
  {}

  static StatusCode gone()
  {
    return ua::detail::address_space_gone("add_method");
  }

  /// @ref resolve_arguments with the address space locked for the synchronous call only.
  Result<std::vector<Argument>> resolve(const std::vector<MethodArgumentDescription>& arguments)
  {
    auto addressSpace = mAddressSpace.lock();
    if (!addressSpace)
    {
      return Result<std::vector<Argument>>{gone()};
    }
    return resolve_arguments(*addressSpace, arguments);
  }

  auto find_node(NodeId nodeId)
  {
    return this->template await_step<NodeAccessorResult>(
      [this, nodeId = std::move(nodeId)](auto completion) mutable
      {
        if (auto addressSpace = mAddressSpace.lock())
          addressSpace->find_node_async(nodeId, std::move(completion));
        else
          completion(NodeAccessorResult{gone()});
      });
  }

  /// @param accessor Borrowed for the call only - the initiate runs synchronously, inside await_ready.
  auto add_reference(NodeAccessor& accessor, NodeId type, NodeId target, bool isForward)
  {
    return this->template await_step<VoidResult>(
      [&accessor, type = std::move(type), target = std::move(target), isForward](auto completion) mutable
      {
        accessor.add_reference_if_not_present_async(
          type, target, isForward, ReferenceHalves::Both, std::move(completion));
      });
  }

  WeakAddressSpace mAddressSpace;
};

class AddMethodOperation final : public MethodSteps<AddMethodOperation>
{
public:
  static void start(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    std::vector<MethodArgumentDescription> inputs, std::vector<MethodArgumentDescription> outputs,
    MethodCallSource::CallHandler handler, MethodConfig config,
    std::function<void(Result<MethodAccessor>)> done)
  {
    launch(std::make_shared<AddMethodOperation>(std::move(addressSpace),
      std::move(parent),
      std::move(browseName),
      std::move(inputs),
      std::move(outputs),
      std::move(handler),
      std::move(config),
      std::move(done)));
  }

  AddMethodOperation(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    std::vector<MethodArgumentDescription> inputs, std::vector<MethodArgumentDescription> outputs,
    MethodCallSource::CallHandler handler, MethodConfig config,
    std::function<void(Result<MethodAccessor>)> done)
    : MethodSteps<AddMethodOperation>(std::move(addressSpace)), mParent(std::move(parent)),
      mBrowseName(std::move(browseName)), mInputs(std::move(inputs)), mOutputs(std::move(outputs)),
      mHandler(std::move(handler)), mConfig(std::move(config)), mDone(std::move(done))
  {}

private:
  friend class ua::async::SelfOwningOperation<AddMethodOperation>;

  auto create_method(NodeId nodeId, InitialAttributes attributes)
  {
    return await_step<Result<MethodAccessor>>(
      [this, nodeId = std::move(nodeId), attributes = std::move(attributes)](auto completion) mutable
      {
        if (auto addressSpace = mAddressSpace.lock())
        {
          addressSpace->create_async<MethodAccessor>(
            nodeId, NodeClass::Method, std::move(attributes), std::move(completion));
        }
        else
        {
          completion(Result<MethodAccessor>{gone()});
        }
      });
  }

  auto create_property(NodeId nodeId, InitialAttributes attributes)
  {
    return await_step<Result<VariableAccessor>>(
      [this, nodeId = std::move(nodeId), attributes = std::move(attributes)](auto completion) mutable
      {
        if (auto addressSpace = mAddressSpace.lock())
        {
          addressSpace->create_async<VariableAccessor>(
            nodeId, NodeClass::Variable, std::move(attributes), std::move(completion));
        }
        else
        {
          completion(Result<VariableAccessor>{gone()});
        }
      });
  }

  /// @param property Borrowed for the call only - the initiate runs synchronously, inside await_ready.
  auto write_value(VariableAccessor& property, DataValue value)
  {
    return await_step<VoidResult>([&property, value = std::move(value)](auto completion) mutable
      { property.write_value_async(std::move(value), std::move(completion)); });
  }

  /// Deletes @p nodeId, the Method or a Property this operation created, with what it holds.
  auto delete_method(NodeId nodeId)
  {
    return await_step<VoidResult>(
      [this, nodeId = std::move(nodeId)](auto completion) mutable
      {
        if (auto addressSpace = mAddressSpace.lock())
          addressSpace->delete_node_async(nodeId, true, ReferenceHalves::Both, std::move(completion));
        else
          completion(VoidResult{gone()});
      });
  }

  /// The Method node's NodeId: the caller's, or a GUID in the parent's namespace (namespace 1 for a
  /// parent in namespace 0, which a server's own nodes may not use, OPC 10000-5 4.1).
  NodeId method_node_id() const
  {
    if (mConfig.nodeId)
    {
      return *mConfig.nodeId;
    }
    uint16_t namespaceIndex = mParent.namespace_index();
    if (namespaceIndex == 0)
    {
      namespaceIndex = 1;
    }
    return NodeId{namespaceIndex, Guid::create_and_generate()};
  }

  /// Whether @p referenceType is symmetric: then the Method's half of the parent reference is forward
  /// too (OPC 10000-3 5.3.2). A type that cannot be resolved is taken as asymmetric, which every
  /// hierarchical type is.
  ua::async::Task<bool> is_symmetric(NodeId referenceType)
  {
    auto found = co_await find_node(std::move(referenceType));
    if (found.is_good())
    {
      if (auto typed = found.value().as<ReferenceTypeAccessor>())
      {
        co_return typed->get_symmetric();
      }
    }
    co_return false;
  }

  ua::async::Task<> run()
  {
    std::optional<NodeId> created;
    // A Property the namespace holds that is not yet linked to the Method, so that the Method's deletion
    // would not remove it.
    std::optional<NodeId> unlinkedProperty;
    StatusCode failure{Status::Good};
    try
    {
      do
      {
        auto resolvedInputs = resolve(mInputs);
        if (!resolvedInputs.is_good())
        {
          failure = resolvedInputs.status_code();
          break;
        }
        auto resolvedOutputs = resolve(mOutputs);
        if (!resolvedOutputs.is_good())
        {
          failure = resolvedOutputs.status_code();
          break;
        }

        const NodeId methodId = method_node_id();
        InitialAttributes attributes;
        attributes.emplace_back(AttributeId::BrowseName, attribute_wire::browse_name(mBrowseName));
        attributes.emplace_back(
          AttributeId::DisplayName, attribute_wire::display_name(LocalizedText{mBrowseName.name()}));
        if (mConfig.description)
        {
          attributes.emplace_back(
            AttributeId::Description, attribute_wire::description(*mConfig.description));
        }
        attributes.emplace_back(AttributeId::Executable, attribute_wire::executable(true));
        auto method = co_await create_method(methodId, std::move(attributes));
        // A Node the namespace holds is removed again if the Method is not completed, an Uncertain answer's
        // too; the SDK builds on the Method it creates, so it does not act on an Uncertain answer.
        if (method.has_value())
        {
          created = methodId;
        }
        if (!method.is_good())
        {
          failure = ::ua::detail::lookup_failure(methodId, method.status_code(), "add_method");
          break;
        }
        MethodAccessor methodNode = std::move(method).value();

        auto parent = co_await find_node(mParent);
        if (!parent.is_good())
        {
          failure = ::ua::detail::lookup_failure(mParent, parent.status_code(), "add_method");
          break;
        }
        NodeAccessor parentNode = std::move(parent).value();
        if (auto linked = co_await add_reference(parentNode, mConfig.parentReferenceType, methodId, true);
            linked.is_bad())
        {
          failure = linked.status_code();
          break;
        }
        const bool symmetric = co_await is_symmetric(mConfig.parentReferenceType);
        if (auto mirrored =
              co_await add_reference(methodNode, mConfig.parentReferenceType, mParent, symmetric);
            mirrored.is_bad())
        {
          failure = mirrored.status_code();
          break;
        }

        const std::array<std::pair<std::string_view, const std::vector<Argument>*>, 2> properties{
          {{inputArgumentsName, &resolvedInputs.value()}, {outputArgumentsName, &resolvedOutputs.value()}}};
        for (const auto& [name, arguments] : properties)
        {
          if (failure.is_bad())
          {
            break;
          }
          if (arguments->empty())
          {
            continue;
          }
          const NodeId propertyId{methodId.namespace_index(), Guid::create_and_generate()};
          InitialAttributes propertyAttributes;
          propertyAttributes.emplace_back(
            AttributeId::BrowseName, attribute_wire::browse_name(QualifiedName{0, std::string{name}}));
          propertyAttributes.emplace_back(
            AttributeId::DisplayName, attribute_wire::display_name(LocalizedText{"", std::string{name}}));
          propertyAttributes.emplace_back(
            AttributeId::DataType, attribute_wire::data_type(NodeId{DataTypeId::Argument}));
          propertyAttributes.emplace_back(AttributeId::ValueRank, attribute_wire::value_rank(ValueRank{1}));
          propertyAttributes.emplace_back(AttributeId::ArrayDimensions,
            attribute_wire::array_dimensions(
              std::vector<uint32_t>{static_cast<uint32_t>(arguments->size())}));
          propertyAttributes.emplace_back(AttributeId::AccessLevel,
            attribute_wire::access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead}));
          auto property = co_await create_property(propertyId, std::move(propertyAttributes));
          // As for the Method: a Property the namespace holds is removed again, an Uncertain answer's too.
          if (property.has_value())
          {
            unlinkedProperty = propertyId;
          }
          if (!property.is_good())
          {
            failure = ::ua::detail::lookup_failure(propertyId, property.status_code(), "add_method");
            break;
          }
          VariableAccessor propertyNode = std::move(property).value();
          if (auto typed = co_await add_reference(propertyNode,
                NodeId{ReferenceTypeId::HasTypeDefinition},
                NodeId{VariableTypeId::PropertyType},
                true);
              typed.is_bad())
          {
            failure = typed.status_code();
            break;
          }
          if (auto owned =
                co_await add_reference(methodNode, NodeId{ReferenceTypeId::HasProperty}, propertyId, true);
              owned.is_bad())
          {
            failure = owned.status_code();
            break;
          }
          // Linked: the Method's deletion removes it.
          unlinkedProperty.reset();
          if (auto mirror =
                co_await add_reference(propertyNode, NodeId{ReferenceTypeId::HasProperty}, methodId, false);
              mirror.is_bad())
          {
            failure = mirror.status_code();
            break;
          }
          if (auto written = co_await write_value(propertyNode, DataValue{arguments_value(*arguments)});
              written.is_bad())
          {
            failure = written.status_code();
            break;
          }
        }
        if (failure.is_bad())
        {
          break;
        }

        auto installed = install_handler(methodNode, std::move(mHandler));
        if (installed.is_bad())
        {
          failure = installed.status_code();
          break;
        }
        // The install's code reaches the caller: a Good subcode, or an Uncertain code with the Method.
        answer(Result<MethodAccessor>{std::move(methodNode), installed.status_code()});
        co_return;
      }
      while (false);

      // Nothing half-made is left behind: the Method node goes, with its Properties, and so does a Property
      // not yet linked to it.
      if (unlinkedProperty)
      {
        (void)co_await delete_method(*unlinkedProperty);
      }
      if (created)
      {
        (void)co_await delete_method(*created);
      }
      fail(failure, failure.shared_detail());
    }
    catch (const ua::async::Abandoned&)
    {
      fail(StatusCode{Status::BadOperationAbandoned}, nullptr);
    }
    catch (...)
    {
      const StatusCode thrown = ua::exception_to_status_code(std::current_exception());
      fail(thrown, thrown.shared_detail());
    }
  }

  void fail_to_start(StatusCode status)
  {
    fail(status, status.shared_detail());
  }

  void fail(StatusCode status, std::shared_ptr<const ErrorDetail> detail)
  {
    answer(Result<MethodAccessor>{status, std::move(detail)});
  }

  /// Fires once.
  void answer(Result<MethodAccessor> result)
  {
    if (auto done = std::exchange(mDone, nullptr))
    {
      done(std::move(result));
    }
  }

  NodeId mParent;
  QualifiedName mBrowseName;
  std::vector<MethodArgumentDescription> mInputs;
  std::vector<MethodArgumentDescription> mOutputs;
  MethodCallSource::CallHandler mHandler;
  MethodConfig mConfig;
  std::function<void(Result<MethodAccessor>)> mDone;
};

class BindMethodOperation final : public MethodSteps<BindMethodOperation>
{
public:
  static void start(AddressSpace addressSpace, MethodBindingTarget target,
    std::vector<MethodArgumentDescription> inputs, std::vector<MethodArgumentDescription> outputs,
    MethodCallSource::CallHandler handler, std::function<void(VoidResult)> done)
  {
    launch(std::make_shared<BindMethodOperation>(std::move(addressSpace),
      std::move(target),
      std::move(inputs),
      std::move(outputs),
      std::move(handler),
      std::move(done)));
  }

  BindMethodOperation(AddressSpace addressSpace, MethodBindingTarget target,
    std::vector<MethodArgumentDescription> inputs, std::vector<MethodArgumentDescription> outputs,
    MethodCallSource::CallHandler handler, std::function<void(VoidResult)> done)
    : MethodSteps<BindMethodOperation>(std::move(addressSpace)), mTarget(std::move(target)),
      mInputs(std::move(inputs)), mOutputs(std::move(outputs)), mHandler(std::move(handler)),
      mDone(std::move(done))
  {}

private:
  friend class ua::async::SelfOwningOperation<BindMethodOperation>;

  auto find_method_child(NodeId object, QualifiedName browseName)
  {
    return await_step<MethodAccessorResult>(
      [this, object = std::move(object), browseName = std::move(browseName)](auto completion) mutable
      {
        if (auto addressSpace = mAddressSpace.lock())
        {
          instance_utils::find_child_method_accessor_by_browse_name_async(std::move(*addressSpace),
            object,
            NodeId{ReferenceTypeId::HasComponent},
            browseName,
            std::move(completion));
        }
        else
        {
          completion(MethodAccessorResult{gone()});
        }
      });
  }

  auto find_property(NodeId method, std::string_view name)
  {
    return await_step<VariableAccessorResult>(
      [this, method = std::move(method), name = std::string{name}](auto completion) mutable
      {
        if (auto addressSpace = mAddressSpace.lock())
        {
          instance_utils::find_child_variable_accessor_by_browse_name_async(std::move(*addressSpace),
            method,
            NodeId{ReferenceTypeId::HasProperty},
            QualifiedName{0, name},
            std::move(completion));
        }
        else
        {
          completion(VariableAccessorResult{gone()});
        }
      });
  }

  auto read_value(NodeId variable)
  {
    return await_step<DataValueResult>(
      [this, variable = std::move(variable)](auto completion) mutable
      {
        if (auto addressSpace = mAddressSpace.lock())
          instance_utils::read_variable_data_value_async(
            std::move(*addressSpace), variable, std::move(completion));
        else
          completion(DataValueResult{gone()});
      });
  }

  /// What the Method node declares in one Property: no arguments when the Property is absent.
  ua::async::Task<Result<std::vector<Argument>>> read_declared(NodeId method, std::string_view name)
  {
    // The binding compares what the Property declares, so it does not act on an Uncertain answer.
    auto property = co_await find_property(method, name);
    if (!property.is_good())
    {
      if (property.status_code().as_status() == Status::BadNodeIdUnknown)
      {
        co_return Result<std::vector<Argument>>{std::vector<Argument>{}};
      }
      co_return Result<std::vector<Argument>>{
        ::ua::detail::lookup_failure(method, property.status_code(), "bind_method")};
    }
    auto value = co_await read_value(property.value().get_node_id());
    if (!value.is_good())
    {
      co_return Result<std::vector<Argument>>{::ua::detail::read_failure(value.status_code(), "bind_method")};
    }
    auto declared = declared_arguments(value.value().value());
    if (!declared)
    {
      co_return Result<std::vector<Argument>>{StatusCode{Status::BadInvalidArgument,
        ErrorDetail::build("MethodArgumentPropertyInvalid",
          "A Method node's argument Property does not hold an array of Argument",
          "bind_method")
          .context(ContextKeys::nodeBrowseName, std::string{name})
          .context(ContextKeys::nodeId, to_string(method))}};
    }
    co_return Result<std::vector<Argument>>{std::move(*declared)};
  }

  ua::async::Task<> run()
  {
    try
    {
      auto resolvedInputs = resolve(mInputs);
      if (!resolvedInputs.is_good())
      {
        answer(VoidResult{resolvedInputs.status_code()});
        co_return;
      }
      auto resolvedOutputs = resolve(mOutputs);
      if (!resolvedOutputs.is_good())
      {
        answer(VoidResult{resolvedOutputs.status_code()});
        co_return;
      }

      std::optional<MethodAccessor> method;
      if (mTarget.methodBrowseName)
      {
        auto found = co_await find_method_child(mTarget.node, *mTarget.methodBrowseName);
        if (!found.is_good())
        {
          answer(VoidResult{::ua::detail::lookup_failure(mTarget.node, found.status_code(), "bind_method")});
          co_return;
        }
        method.emplace(std::move(found).value());
      }
      else
      {
        auto found = co_await find_node(mTarget.node);
        if (!found.is_good())
        {
          answer(VoidResult{::ua::detail::lookup_failure(mTarget.node, found.status_code(), "bind_method")});
          co_return;
        }
        auto typed = found.value().as<MethodAccessor>();
        if (!typed)
        {
          answer(VoidResult{StatusCode{Status::BadNodeClassInvalid,
            ErrorDetail::build(
              "MethodBindingNotAMethod", "The node to bind a handler to is not a Method", "bind_method")
              .context(ContextKeys::nodeId, to_string(mTarget.node))}});
          co_return;
        }
        method.emplace(std::move(*typed));
      }

      const NodeId methodId = method->get_node_id();
      auto declaredInputs = co_await read_declared(methodId, inputArgumentsName);
      if (!declaredInputs.is_good())
      {
        answer(VoidResult{declaredInputs.status_code()});
        co_return;
      }
      if (auto compared =
            compare_arguments(inputArgumentsName, declaredInputs.value(), resolvedInputs.value());
          compared.is_bad())
      {
        answer(std::move(compared));
        co_return;
      }
      auto declaredOutputs = co_await read_declared(methodId, outputArgumentsName);
      if (!declaredOutputs.is_good())
      {
        answer(VoidResult{declaredOutputs.status_code()});
        co_return;
      }
      if (auto compared =
            compare_arguments(outputArgumentsName, declaredOutputs.value(), resolvedOutputs.value());
          compared.is_bad())
      {
        answer(std::move(compared));
        co_return;
      }

      answer(install_handler(*method, std::move(mHandler)));
    }
    catch (const ua::async::Abandoned&)
    {
      answer(VoidResult{StatusCode{Status::BadOperationAbandoned}});
    }
    catch (...)
    {
      answer(VoidResult{ua::exception_to_status_code(std::current_exception())});
    }
  }

  void fail_to_start(StatusCode status)
  {
    answer(VoidResult{std::move(status)});
  }

  /// Fires once.
  void answer(VoidResult result)
  {
    if (auto done = std::exchange(mDone, nullptr))
    {
      done(std::move(result));
    }
  }

  MethodBindingTarget mTarget;
  std::vector<MethodArgumentDescription> mInputs;
  std::vector<MethodArgumentDescription> mOutputs;
  MethodCallSource::CallHandler mHandler;
  std::function<void(VoidResult)> mDone;
};

}  // namespace

void add_method_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  std::vector<MethodArgumentDescription> inputs, std::vector<MethodArgumentDescription> outputs,
  MethodCallSource::CallHandler handler, MethodConfig config,
  std::function<void(Result<MethodAccessor>)> done) noexcept
{
  // A caller that passes no callback still has the Method added; a failure is logged instead.
  done = ua::detail::completion_or_log(std::move(done), addressSpace.logger(), "add_method_async");
  try
  {
    AddMethodOperation::start(std::move(addressSpace),
      std::move(parent),
      std::move(browseName),
      std::move(inputs),
      std::move(outputs),
      std::move(handler),
      std::move(config),
      done);
  }
  catch (...)
  {
    done(Result<MethodAccessor>{ua::exception_to_status_code(std::current_exception())});
  }
}

Result<MethodAccessor> try_add_method_sync(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  std::vector<MethodArgumentDescription> inputs, std::vector<MethodArgumentDescription> outputs,
  MethodCallSource::CallHandler handler, MethodConfig config) noexcept
{
  const auto executor = addressSpace.executor();
  return ua::async::detail::blocking_call<Result<MethodAccessor>>(executor,
    [&](std::function<void(Result<MethodAccessor>)> complete)
    {
      add_method_async(std::move(addressSpace),
        std::move(parent),
        std::move(browseName),
        std::move(inputs),
        std::move(outputs),
        std::move(handler),
        std::move(config),
        std::move(complete));
    });
}

void bind_method_async(AddressSpace addressSpace, MethodBindingTarget target,
  std::vector<MethodArgumentDescription> inputs, std::vector<MethodArgumentDescription> outputs,
  MethodCallSource::CallHandler handler, std::function<void(VoidResult)> done) noexcept
{
  // A caller that passes no callback still has the Method bound; a failure is logged instead.
  done = ua::detail::completion_or_log(std::move(done), addressSpace.logger(), "bind_method_async");
  try
  {
    BindMethodOperation::start(std::move(addressSpace),
      std::move(target),
      std::move(inputs),
      std::move(outputs),
      std::move(handler),
      done);
  }
  catch (...)
  {
    done(VoidResult{ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult try_bind_method_sync(AddressSpace addressSpace, MethodBindingTarget target,
  std::vector<MethodArgumentDescription> inputs, std::vector<MethodArgumentDescription> outputs,
  MethodCallSource::CallHandler handler) noexcept
{
  const auto executor = addressSpace.executor();
  return ua::async::detail::blocking_call<VoidResult>(executor,
    [&](std::function<void(VoidResult)> complete)
    {
      bind_method_async(std::move(addressSpace),
        std::move(target),
        std::move(inputs),
        std::move(outputs),
        std::move(handler),
        std::move(complete));
    });
}

}  // namespace ua::detail
