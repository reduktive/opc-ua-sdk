// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_external_guard_linker.h"

#include "ua_attribute_id.h"
#include "ua_callback_safety.h"
#include "ua_content_filter.h"
#include "ua_error_detail.h"
#include "ua_instance_utils.h"
#include "ua_namespace_route.h"
#include "ua_node_accessor_route.h"
#include "ua_node_utilities.h"
#include "ua_on_strand.h"
#include "ua_read_value_id.h"
#include "ua_referencetype_id.h"
#include "ua_self_owning_operation.h"
#include "ua_simple_attribute_operand.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_variabletype_id.h"

#include <boost/asio/strand.hpp>

#include <algorithm>
#include <exception>
#include <memory>
#include <optional>
#include <vector>
#include <string>
#include <string_view>
#include <utility>

namespace ua::instantiation_detail
{
namespace
{

struct ExternalLink
{
  NodeId machineInstanceId;
  NodeId variableInstanceId;
  NodeId referenceTypeId;

  bool operator==(const ExternalLink&) const = default;
};

std::string browse_path_text(const Array<QualifiedName>& browsePath)
{
  std::string text;
  for (const auto& element : browsePath)
  {
    if (!text.empty())
      text += '/';
    text += to_string(element);
  }
  return text;
}

/// The ErrorDetail source of the linking's own answers.
constexpr std::string_view linkerSource{"ExternalGuardVariableLinker"};

StatusCode expression_value_type_mismatch(const NodeId& expressionId)
{
  return StatusCode{Status::BadTypeMismatch,
    ErrorDetail::build("ExpressionGuardValueTypeMismatch",
      "ExpressionGuard Expression does not contain a ContentFilter",
      "ExternalGuardVariableLinker")
      .context(ContextKeys::nodeId, expressionId)
      .context(ContextKeys::expected, "ContentFilter")};
}

StatusCode external_target_missing(const NodeId& machineId, const SimpleAttributeOperand& operand)
{
  return StatusCode{Status::BadConfigurationError,
    ErrorDetail::build("ExternalGuardVariableNotInstantiated",
      "ExpressionGuard external Variable does not resolve in the instantiated owner subtree",
      "ExternalGuardVariableLinker")
      .context(ContextKeys::nodeId, machineId)
      .context(ContextKeys::typeId, operand.type_definition_id())
      .context(ContextKeys::fieldName, browse_path_text(operand.browse_path()))};
}

StatusCode external_target_ambiguous(const NodeId& machineId, const SimpleAttributeOperand& operand)
{
  return StatusCode{Status::BadConfigurationError,
    ErrorDetail::build("ExternalGuardVariableAmbiguous",
      "ExpressionGuard external Variable resolves to more than one instantiated node",
      "ExternalGuardVariableLinker")
      .context(ContextKeys::nodeId, machineId)
      .context(ContextKeys::typeId, operand.type_definition_id())
      .context(ContextKeys::fieldName, browse_path_text(operand.browse_path()))};
}

/// Finds ExpressionGuardVariables reachable from a freshly instantiated subtree and links each
/// machine instance to the guard variable its expression names.
///
/// Four nested walks, all of them plain loops now: every instantiated candidate object, every
/// machine type in its supertype chain, every component of those types, and every HasGuard target of
/// those components. The guards that turn out to be ExpressionGuardVariableType have their
/// Expression read and its operands resolved into links, which a final pass applies in both
/// directions.
///
/// Every step is fatal on failure - unlike the instantiation walk this runs after, there is no
/// best-effort step here. The linking acts on every lookup, References read and Value read it makes, so an
/// Uncertain answer to one, with or without its data, is not acted on: it answers `Bad_InternalError` with
/// the ErrorDetail code `LookupAnswerUncertain`, `ReferencesAnswerUncertain` or `ReadAnswerUncertain`, whose
/// cause is the Uncertain code. A Reference addition answered Bad ends the linking with that answer; one
/// answered Uncertain ends it with `Bad_InternalError` (`AnswerUncertain`, the Uncertain code as its cause),
/// so the instantiation that runs the linking fails and removes what it created.
class ExternalGuardVariableLinkOperation final
  : public ua::async::SelfOwningOperation<ExternalGuardVariableLinkOperation>
{
public:
  static void start(AddressSpace addressSpace, DepthBudget budget,
    std::shared_ptr<const InstantiationContext> context, std::function<void(VoidResult)> completion)
  {
    launch(std::make_shared<ExternalGuardVariableLinkOperation>(
      std::move(addressSpace), budget, std::move(context), std::move(completion)));
  }

  ExternalGuardVariableLinkOperation(AddressSpace addressSpace, DepthBudget budget,
    std::shared_ptr<const InstantiationContext> context, std::function<void(VoidResult)> completion)
    : ua::async::SelfOwningOperation<ExternalGuardVariableLinkOperation>(
        boost::asio::make_strand(addressSpace.executor()), addressSpace.logger()),
      mAddressSpace(addressSpace.weak()), mBudget(budget), mContext(std::move(context)),
      mCompletion(std::move(completion))
  {}

private:
  friend class ua::async::SelfOwningOperation<ExternalGuardVariableLinkOperation>;

  // Declared ahead of the bodies that co_await them: an `auto` return type has to be deduced before
  // a caller can name it.
  auto find_node(NodeId nodeId)
  {
    return await_step<NodeAccessorResult>(
      [this, nodeId = std::move(nodeId)](auto completion) mutable
      {
        if (auto addressSpace = mAddressSpace.lock())
          addressSpace->find_node_async(nodeId, std::move(completion));
        else
          completion(NodeAccessorResult{ua::detail::address_space_gone("ExternalGuardVariableLinker")});
      });
  }

  /// @param node Borrowed for the call only - the initiate runs synchronously, inside await_ready.
  auto get_references(NodeAccessor& node)
  {
    return await_step<NodeAccessor::ReferencesResult>(
      [this, &node](auto completion) mutable
      {
        if (auto addressSpace = mAddressSpace.lock())
          ua::detail::NodeAccessorRoute::read_all_references(node, std::move(completion), mAddressSpace);
        else
          completion(
            NodeAccessor::ReferencesResult{ua::detail::address_space_gone("ExternalGuardVariableLinker")});
      });
  }

  auto get_super_type(NodeAccessor type)
  {
    return await_step<node_utils::OptionalNodeAccessorResult>(
      [this, type = std::move(type)](auto completion) mutable
      {
        if (auto addressSpace = mAddressSpace.lock())
          node_utils::get_super_type_async(*addressSpace, std::move(type), std::move(completion));
        else
          completion(node_utils::OptionalNodeAccessorResult{
            ua::detail::address_space_gone("ExternalGuardVariableLinker")});
      });
  }

  auto find_expression_property(NodeId guardId)
  {
    return await_step<VariableAccessorResult>(
      [this, guardId = std::move(guardId)](auto completion) mutable
      {
        if (auto addressSpace = mAddressSpace.lock())
          instance_utils::find_child_variable_accessor_by_browse_name_async(*addressSpace,
            guardId,
            NodeId{ReferenceTypeId::HasProperty},
            QualifiedName{0, "Expression"},
            std::move(completion));
        else
          completion(VariableAccessorResult{ua::detail::address_space_gone("ExternalGuardVariableLinker")});
      });
  }

  auto read_expression(VariableAccessor& expression)
  {
    ReadValueId readValueId;
    readValueId.node_id() = expression.get_node_id();
    readValueId.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    return await_step<DataValueResult>(
      [this, &expression, readValueId = std::move(readValueId)](auto completion) mutable
      {
        // Guard-expression resolution during instantiation: no Session involved.
        if (auto addressSpace = mAddressSpace.lock())
          expression.read_value_async(Duration{}, false, readValueId, nullptr, std::move(completion));
        else
          completion(DataValueResult{ua::detail::address_space_gone("ExternalGuardVariableLinker")});
      });
  }

  auto add_reference(NodeAccessor& node, NodeId type, NodeId target, bool isForward)
  {
    return await_step<VoidResult>(
      [this, &node, type = std::move(type), target = std::move(target), isForward](auto completion) mutable
      {
        if (auto addressSpace = mAddressSpace.lock())
          ua::detail::NodeAccessorRoute::add_reference_if_not_present(
            node, std::move(type), std::move(target), isForward, std::move(completion), mAddressSpace);
        else
          completion(VoidResult{ua::detail::address_space_gone("ExternalGuardVariableLinker")});
      });
  }

  ua::async::Task<> run()
  {
    try
    {
      for (size_t candidateIndex = 0; candidateIndex < mContext->nodes().size(); ++candidateIndex)
      {
        const auto candidate = mContext->nodes()[candidateIndex];
        if (candidate.nodeClass != NodeClass::Object || !candidate.typeDefinitionId ||
            candidate.parentInstanceId.is_null())
        {
          continue;
        }
        if (!co_await collect_guards_for(candidate))
        {
          co_return;  // already answered
        }
      }

      if (!co_await apply_links())
      {
        co_return;
      }
      finish(VoidResult{});
    }
    catch (const ua::async::Abandoned&)
    {
      finish(VoidResult{StatusCode{Status::BadOperationAbandoned}});
    }
    catch (...)
    {
      finish(VoidResult{ua::exception_to_status_code(std::current_exception())});
    }
  }

  /// Walks one candidate's type and every supertype of it, gathering the HasGuard targets of their
  /// components, then inspects each guard.
  /// @return false when the operation has already answered with a failure.
  ua::async::Task<bool> collect_guards_for(const InstantiatedNodeBinding& candidate)
  {
    std::vector<NodeId> machineTypeQueue{*candidate.typeDefinitionId};
    std::vector<NodeId> visitedMachineTypes;
    std::vector<NodeId> guardIds;

    while (!machineTypeQueue.empty())
    {
      auto machineType = std::move(machineTypeQueue.back());
      machineTypeQueue.pop_back();
      if (std::find(visitedMachineTypes.begin(), visitedMachineTypes.end(), machineType) !=
          visitedMachineTypes.end())
      {
        continue;
      }
      visitedMachineTypes.push_back(machineType);
      mBudget.consume();

      auto typeResult = co_await find_node(machineType);
      if (!typeResult.is_good())
      {
        refuse(ua::detail::lookup_failure(machineType, typeResult.status_code(), linkerSource));
        co_return false;
      }
      auto typeNode = std::move(typeResult).value();

      auto typeReferences = co_await get_references(typeNode);
      if (!typeReferences.is_good())
      {
        refuse(ua::detail::references_failure(typeReferences.status_code(), linkerSource));
        co_return false;
      }

      std::vector<NodeId> componentIds;
      for (const auto& reference : typeReferences.value())
      {
        if (reference.is_remote() || !reference.target_id().is_local())
        {
          continue;
        }
        if (!reference.is_forward() && reference.type_id() == NodeId{ReferenceTypeId::HasSubtype})
        {
          machineTypeQueue.push_back(reference.target_id().node_id());
          continue;
        }
        if (reference.is_forward() && (reference.type_id() == NodeId{ReferenceTypeId::HasComponent} ||
                                        reference.type_id() == NodeId{ReferenceTypeId::HasOrderedComponent}))
        {
          componentIds.push_back(reference.target_id().node_id());
        }
      }

      for (const auto& componentId : componentIds)
      {
        mBudget.consume();
        auto componentResult = co_await find_node(componentId);
        if (!componentResult.is_good())
        {
          refuse(ua::detail::lookup_failure(componentId, componentResult.status_code(), linkerSource));
          co_return false;
        }
        auto component = std::move(componentResult).value();

        auto componentReferences = co_await get_references(component);
        if (!componentReferences.is_good())
        {
          refuse(ua::detail::references_failure(componentReferences.status_code(), linkerSource));
          co_return false;
        }
        for (const auto& reference : componentReferences.value())
        {
          if (!reference.is_forward() || reference.is_remote() || !reference.target_id().is_local() ||
              reference.type_id() != NodeId{ReferenceTypeId::HasGuard})
          {
            continue;
          }
          const auto& guardId = reference.target_id().node_id();
          if (std::find(guardIds.begin(), guardIds.end(), guardId) == guardIds.end())
          {
            guardIds.push_back(guardId);
          }
        }
      }
    }

    for (const auto& guardId : guardIds)
    {
      if (!co_await inspect_guard(candidate, guardId))
      {
        co_return false;
      }
    }
    co_return true;
  }

  /// Reads one guard's Expression, if it is an ExpressionGuardVariableType, and turns its operands
  /// into pending links. A guard with no type definition, or whose supertype chain never reaches
  /// ExpressionGuardVariableType, is skipped.
  /// @return false when the operation has already answered with a failure.
  ua::async::Task<bool> inspect_guard(const InstantiatedNodeBinding& candidate, const NodeId& guardId)
  {
    mBudget.consume();
    auto guardResult = co_await find_node(guardId);
    if (!guardResult.is_good())
    {
      refuse(ua::detail::lookup_failure(guardId, guardResult.status_code(), linkerSource));
      co_return false;
    }
    auto guard = std::move(guardResult).value();

    auto guardReferences = co_await get_references(guard);
    if (!guardReferences.is_good())
    {
      refuse(ua::detail::references_failure(guardReferences.status_code(), linkerSource));
      co_return false;
    }

    std::optional<NodeId> typeDefinition;
    for (const auto& reference : guardReferences.value())
    {
      if (reference.is_forward() && !reference.is_remote() && reference.target_id().is_local() &&
          reference.type_id() == NodeId{ReferenceTypeId::HasTypeDefinition})
      {
        typeDefinition = reference.target_id().node_id();
        break;
      }
    }
    if (!typeDefinition)
    {
      co_return true;
    }

    mBudget.consume();
    auto typeResult = co_await find_node(*typeDefinition);
    if (!typeResult.is_good())
    {
      refuse(ua::detail::lookup_failure(*typeDefinition, typeResult.status_code(), linkerSource));
      co_return false;
    }
    auto type = std::move(typeResult).value();

    // Walk up the supertype chain until ExpressionGuardVariableType is reached, or the chain ends.
    while (type.get_node_id() != NodeId{VariableTypeId::ExpressionGuardVariableType})
    {
      mBudget.consume();
      auto superResult = co_await get_super_type(type);
      if (!superResult.is_good())
      {
        // The supertype is a References read of the type and a lookup of its target, which answers one code.
        refuse(ua::detail::lookup_failure(type.get_node_id(), superResult.status_code(), linkerSource));
        co_return false;
      }
      auto& superType = superResult.value();
      if (!superType)
      {
        co_return true;  // not an expression guard
      }
      type = std::move(superType.value());
    }

    auto expressionResult = co_await find_expression_property(guard.get_node_id());
    if (!expressionResult.is_good())
    {
      refuse(
        ua::detail::answer_failure(expressionResult.status_code(), "LookupAnswerUncertain", linkerSource));
      co_return false;
    }
    auto expression = std::move(expressionResult).value();

    auto valueResult = co_await read_expression(expression);
    if (!valueResult.is_good())
    {
      refuse(ua::detail::read_failure(valueResult.status_code(), linkerSource));
      co_return false;
    }
    const auto& expressionStatus = valueResult.value().status();
    if (expressionStatus && !expressionStatus.value().is_good())
    {
      refuse(ua::detail::read_failure(expressionStatus.value(), linkerSource));
      co_return false;
    }
    const auto* filter = valueResult.value().value().try_as<ContentFilter>();
    if (filter == nullptr)
    {
      finish(VoidResult{expression_value_type_mismatch(expression.get_node_id())});
      co_return false;
    }

    for (const auto& element : filter->elements())
    {
      for (const auto& operand : element.filter_operands())
      {
        const auto* simple = dynamic_cast<const SimpleAttributeOperand*>(operand.get());
        if (simple == nullptr)
        {
          continue;
        }
        if (auto failure = consider_operand(candidate, *simple))
        {
          finish(VoidResult{std::move(*failure)});
          co_return false;
        }
      }
    }
    co_return true;
  }

  /// Applies every collected link in both directions.
  /// @return false when the operation has already answered with a failure.
  ua::async::Task<bool> apply_links()
  {
    for (const auto& link : mLinks)
    {
      mBudget.consume();
      auto sourceResult = co_await find_node(link.machineInstanceId);
      if (!sourceResult.is_good())
      {
        refuse(ua::detail::lookup_failure(link.machineInstanceId, sourceResult.status_code(), linkerSource));
        co_return false;
      }
      auto source = std::move(sourceResult).value();

      auto forward = co_await add_reference(source, link.referenceTypeId, link.variableInstanceId, true);
      if (!forward.is_good())
      {
        refuse(ua::detail::answer_failure(forward.status_code(), "AnswerUncertain", linkerSource));
        co_return false;
      }

      mBudget.consume();
      auto targetResult = co_await find_node(link.variableInstanceId);
      if (!targetResult.is_good())
      {
        refuse(ua::detail::lookup_failure(link.variableInstanceId, targetResult.status_code(), linkerSource));
        co_return false;
      }
      auto target = std::move(targetResult).value();

      auto inverse = co_await add_reference(target, link.referenceTypeId, link.machineInstanceId, false);
      if (!inverse.is_good())
      {
        refuse(ua::detail::answer_failure(inverse.status_code(), "AnswerUncertain", linkerSource));
        co_return false;
      }
    }
    co_return true;
  }

  void fail_to_start(StatusCode status)
  {
    finish(VoidResult{status, status.shared_detail()});
  }

  /// Answers @p refused: a step's Bad answer, or the refusal the refusal helpers build for an Uncertain one.
  void refuse(const StatusCode& refused)
  {
    finish(VoidResult{refused});
  }

  /// Fires once: a body that failed a step and then unwound must not answer twice.
  void finish(VoidResult result)
  {
    if (auto completion = std::exchange(mCompletion, nullptr))
    {
      ua::detail::invoke_user_callback(mLogger, completion, std::move(result));
    }
  }

  /// Resolves an operand's browse path against the instances this instantiation recorded.
  ///
  /// Takes the candidate explicitly: it used to be the `mCandidate` member, which existed only
  /// because the flow had nowhere else to keep per-candidate state between callbacks.
  std::vector<const InstantiatedNodeBinding*> resolve_operand_targets(
    const InstantiatedNodeBinding& candidate, const SimpleAttributeOperand& operand) const
  {
    std::vector<NodeId> startInstances;
    for (const auto& type : mContext->types())
    {
      if (type.typeDefinitionId != operand.type_definition_id() ||
          !is_within(type.instanceId, candidate.parentInstanceId))
      {
        continue;
      }
      if (std::find(startInstances.begin(), startInstances.end(), type.instanceId) == startInstances.end())
      {
        startInstances.push_back(type.instanceId);
      }
    }

    std::vector<const InstantiatedNodeBinding*> targets;
    for (const auto& startInstance : startInstances)
    {
      NodeId current = startInstance;
      const InstantiatedNodeBinding* terminal = nullptr;
      bool complete = true;
      for (const auto& browseName : operand.browse_path())
      {
        std::vector<const InstantiatedNodeBinding*> matches;
        for (const auto& binding : mContext->nodes())
        {
          if (binding.parentInstanceId == current && binding.browseName == browseName)
            matches.push_back(&binding);
        }
        if (matches.size() != 1U)
        {
          complete = false;
          break;
        }
        terminal = matches.front();
        current = terminal->instanceId;
      }
      if (complete && terminal != nullptr && terminal->nodeClass == NodeClass::Variable &&
          std::find_if(targets.begin(),
            targets.end(),
            [terminal](const InstantiatedNodeBinding* existing)
            { return existing->instanceId == terminal->instanceId; }) == targets.end())
      {
        targets.push_back(terminal);
      }
    }
    return targets;
  }

  /// Records a link for one operand, or reports why it cannot be linked.
  std::optional<StatusCode> consider_operand(
    const InstantiatedNodeBinding& candidate, const SimpleAttributeOperand& operand)
  {
    if (operand.type_definition_id().is_null() || operand.browse_path().empty())
      return std::nullopt;

    bool externalTypeExists{false};
    for (const auto& type : mContext->types())
    {
      externalTypeExists = externalTypeExists || (type.typeDefinitionId == operand.type_definition_id() &&
                                                   is_within(type.instanceId, candidate.parentInstanceId));
    }
    if (!externalTypeExists)
      return std::nullopt;

    auto targets = resolve_operand_targets(candidate, operand);
    if (targets.empty())
      return external_target_missing(candidate.instanceId, operand);
    if (targets.size() != 1U)
      return external_target_ambiguous(candidate.instanceId, operand);

    const auto& target = *targets.front();
    if (is_within(target.instanceId, candidate.instanceId))
      return std::nullopt;

    const ExternalLink link{candidate.instanceId, target.instanceId, target.parentReferenceType};
    if (std::find(mLinks.begin(), mLinks.end(), link) == mLinks.end())
      mLinks.push_back(link);
    return std::nullopt;
  }

  bool is_within(const NodeId& instanceId, const NodeId& ancestorId) const
  {
    NodeId current = instanceId;
    for (size_t depth = 0; depth <= mContext->nodes().size(); ++depth)
    {
      if (current == ancestorId)
        return true;
      const auto binding = std::find_if(mContext->nodes().begin(),
        mContext->nodes().end(),
        [&current](const InstantiatedNodeBinding& candidate) { return candidate.instanceId == current; });
      if (binding == mContext->nodes().end())
        return false;
      current = binding->parentInstanceId;
    }
    return false;
  }

  WeakAddressSpace mAddressSpace;
  DepthBudget mBudget;
  std::shared_ptr<const InstantiationContext> mContext;
  std::function<void(VoidResult)> mCompletion;

  std::vector<ExternalLink> mLinks;
};
}  // namespace

void InstantiationContext::record_type(NodeId typeDefinitionId, NodeId instanceId)
{
  const InstantiatedTypeBinding binding{std::move(typeDefinitionId), std::move(instanceId)};
  if (std::find(mTypes.begin(), mTypes.end(), binding) == mTypes.end())
    mTypes.push_back(binding);
}

void InstantiationContext::record_node(InstantiatedNodeBinding binding)
{
  const auto existing = std::find_if(mNodes.begin(),
    mNodes.end(),
    [&binding](const InstantiatedNodeBinding& candidate)
    { return candidate.instanceId == binding.instanceId; });
  if (existing == mNodes.end())
  {
    if (binding.typeDefinitionId)
      record_type(*binding.typeDefinitionId, binding.instanceId);
    mNodes.push_back(std::move(binding));
  }
}

const std::vector<InstantiatedTypeBinding>& InstantiationContext::types() const noexcept
{
  return mTypes;
}

const std::vector<InstantiatedNodeBinding>& InstantiationContext::nodes() const noexcept
{
  return mNodes;
}

bool InstantiationContext::created(const NodeId& node) const noexcept
{
  return std::any_of(mNodes.begin(),
    mNodes.end(),
    [&node](const InstantiatedNodeBinding& binding) { return binding.instanceId == node; });
}

const std::shared_ptr<node_utils::RefTypeCache>& InstantiationContext::reference_type_cache() const noexcept
{
  return mReferenceTypeCache;
}

void InstantiationContext::plan_node(PlannedNode node)
{
  mPlannedIds.insert(node.creation.nodeId);
  mPlannedNodes.push_back(std::move(node));
}

void InstantiationContext::plan_half(PlannedHalf half)
{
  mPlannedHalves.push_back(std::move(half));
}

void InstantiationContext::plan_link(
  const NodeId& parent, const NodeId& referenceType, const NodeId& child, const QualifiedName& browseName)
{
  mPlannedHalves.push_back(
    PlannedHalf{ReferenceChange{parent, referenceType, ExpandedNodeId{child}, true, planned(parent)}, false});
  mPlannedHalves.push_back(
    PlannedHalf{ReferenceChange{child, referenceType, ExpandedNodeId{parent}, false, planned(child)}, true});
  mPlannedChildren[parent].emplace_back(browseName, child);
}

bool InstantiationContext::planned(const NodeId& node) const noexcept
{
  return mPlannedIds.contains(node);
}

std::optional<NodeId> InstantiationContext::planned_child(
  const NodeId& parent, const QualifiedName& browseName) const
{
  const auto children = mPlannedChildren.find(parent);
  if (children == mPlannedChildren.end())
  {
    return std::nullopt;
  }
  for (const auto& [name, child] : children->second)
  {
    if (name == browseName)
    {
      return child;
    }
  }
  return std::nullopt;
}

std::vector<NodeId> InstantiationContext::planned_link_types(const NodeId& parent, const NodeId& child) const
{
  std::vector<NodeId> referenceTypes;
  for (const auto& half : mPlannedHalves)
  {
    if (half.change.isForward && half.change.source == parent && half.change.target.is_local() &&
        half.change.target.node_id() == child)
    {
      referenceTypes.push_back(half.change.referenceType);
    }
  }
  return referenceTypes;
}

const std::vector<PlannedNode>& InstantiationContext::planned_nodes() const noexcept
{
  return mPlannedNodes;
}

const std::vector<PlannedHalf>& InstantiationContext::planned_halves() const noexcept
{
  return mPlannedHalves;
}

void wire_external_guard_variables_async(AddressSpace addressSpace, DepthBudget budget,
  std::shared_ptr<const InstantiationContext> context, std::function<void(VoidResult)> completion) noexcept
{
  Logger logger;
  try
  {
    logger = addressSpace.logger();
    if (!context)
    {
      ua::detail::invoke_user_callback(logger,
        completion,
        VoidResult{StatusCode{Status::BadInvalidArgument,
          ErrorDetail::build("MissingInstantiationContext",
            "External Guard Variable linker requires an instantiation context",
            "ExternalGuardVariableLinker")}});
      return;
    }
    // launch() posts the body, which is what the explicit post here used to provide.
    // Keep the entry's answer state until operation construction and launch have succeeded.
    ExternalGuardVariableLinkOperation::start(addressSpace, budget, context, completion);
  }
  catch (...)
  {
    ua::detail::invoke_user_callback(
      logger, completion, VoidResult{ua::exception_to_status_code(std::current_exception())});
  }
}

}  // namespace ua::instantiation_detail
