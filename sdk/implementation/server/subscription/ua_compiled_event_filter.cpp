// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_compiled_event_filter.h"

#include "ua_built_in_type_id.h"
#include "ua_binary_codec.h"
#include "ua_byte_string.h"
#include "ua_data_value.h"
#include "ua_encoding_limits.h"
#include "ua_attribute_id.h"
#include "ua_attribute_operand.h"
#include "ua_date_time.h"
#include "ua_element_operand.h"
#include "ua_error_detail.h"
#include "ua_event_type_model.h"
#include "ua_expanded_node_id.h"
#include "ua_filter_operator.h"
#include "ua_guid.h"
#include "ua_literal_operand.h"
#include "ua_localized_text.h"
#include "ua_null_stream.h"
#include "ua_objecttype_id.h"
#include "ua_qualified_name.h"
#include "ua_simple_attribute_operand.h"
#include "ua_status_code.h"
#include "ua_to_string.h"

#include "fmt/format.h"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstring>
#include <limits>
#include <ranges>

namespace ua::server
{

namespace
{

// --- Compile helpers ---

/// Expected operand counts for each supported operator.
/// Returns {min, max}. Returns {0, 0} for unsupported operators.
std::pair<uint32_t, uint32_t> expected_operand_count(FilterOperator op)
{
  switch (op)
  {
  case FilterOperator::IsNull:
  case FilterOperator::Not:
  case FilterOperator::OfType:
    return {1, 1};
  case FilterOperator::Equals:
  case FilterOperator::GreaterThan:
  case FilterOperator::LessThan:
  case FilterOperator::GreaterThanOrEqual:
  case FilterOperator::LessThanOrEqual:
  case FilterOperator::Like:
  case FilterOperator::And:
  case FilterOperator::Or:
  case FilterOperator::BitwiseAnd:
  case FilterOperator::BitwiseOr:
    return {2, 2};
  case FilterOperator::Between:
    return {3, 3};
  case FilterOperator::InList:
    return {2, std::numeric_limits<uint32_t>::max()};
  case FilterOperator::Cast:
    return {2, 2};
  // Disallowed in EventFilter where clause (SVR-EVT-FLT-019)
  case FilterOperator::InView:
  case FilterOperator::RelatedTo:
  default:
    return {0, 0};
  }
}

/// Check for cycles in element references (SVR-EVT-CF-001).
/// Returns true if acyclic.
bool is_acyclic(const std::vector<CompiledFilterElement>& elements)
{
  auto count = numeric_cast<uint32_t>(elements.size());
  // visited[i] == 0: unvisited, 1: in-progress, 2: done
  std::vector<uint8_t> state(count, 0);

  // DFS from each unvisited node
  for (uint32_t start = 0; start < count; ++start)
  {
    if (state[start] == 2)
      continue;

    // Iterative DFS using a stack
    std::vector<uint32_t> stack{start};
    while (!stack.empty())
    {
      auto idx = stack.back();
      if (idx >= count)
      {
        stack.pop_back();
        continue;
      }

      if (state[idx] == 2)
      {
        stack.pop_back();
        continue;
      }

      if (state[idx] == 1)
      {
        // Finishing this node
        state[idx] = 2;
        stack.pop_back();
        continue;
      }

      state[idx] = 1;  // Mark in-progress

      for (const auto& operand : elements[idx].operands)
      {
        if (auto* elemRef = std::get_if<uint32_t>(&operand))
        {
          if (*elemRef >= count)
            continue;
          if (state[*elemRef] == 1)
            return false;  // Cycle detected
          if (state[*elemRef] == 0)
            stack.push_back(*elemRef);
        }
      }
    }
  }
  return true;
}

/// Validate a single select clause.
StatusCode validate_select_clause(const SimpleAttributeOperand& clause)
{
  // An empty browse path is valid (Part 4 7.4.4.5): the operand refers to the instance of the
  // typeDefinitionId itself rather than a child field. Combined with attributeId == NodeId this is how
  // a Client selects the ConditionId (the NodeId of the ConditionType instance the event is about).
  const auto& browsePath = clause.browse_path();

  // Validate typeDefinitionId: must be BaseEventType or a subtype.
  // At compile time we can only check it's not obviously wrong.
  const auto& typeDefId = clause.type_definition_id();
  if (!typeDefId.is_null())
  {
    // Must be a numeric NodeId in namespace 0 to be a standard ObjectTypeId.
    // We allow any NodeId - type hierarchy checking is deferred to runtime.
  }

  // Validate browse path elements are not null (SVR-EVT-FLT-005)
  for (size_t i = 0; i < browsePath.size(); ++i)
  {
    if (browsePath[i].name().empty())
      return StatusCode{Status::BadBrowseNameInvalid};
  }

  // Part 9 5.2: TrueState and FalseState are TwoStateVariableType metadata, not Event fields. A
  // nested occurrence under a standard ConditionType select path therefore can never be selected.
  if (browsePath.size() >= 2 && typeDefId.namespace_index() == 0)
  {
    const auto& terminalName = browsePath[browsePath.size() - 1].name();
    if (terminalName == String{"TrueState"} || terminalName == String{"FalseState"})
      return StatusCode{Status::BadFilterOperandInvalid};
  }

  // Validate AttributeId
  auto attrId = clause.attribute_id();
  if (attrId == 0)
    attrId = utils::to_underlying(AttributeId::Value);  // Default

  // Part 4 section 7.22.3 requires Value on Variables and NodeId on Objects. This SDK additionally
  // supports the static RolePermissions Attribute so the Part 18 authorization surface cannot be
  // bypassed through Event field selection.
  if (attrId != utils::to_underlying(AttributeId::Value) &&
      attrId != utils::to_underlying(AttributeId::NodeId) &&
      attrId != utils::to_underlying(AttributeId::RolePermissions))
  {
    return StatusCode{Status::BadAttributeIdInvalid};
  }

  // An empty browsePath selects the event instance node itself, which is an Object. Per Part 4
  // 7.22.3 a Server is only required to support the NodeId Attribute for Object Nodes, so the
  // Value Attribute can never be returned for the event node -> Bad_AttributeIdInvalid (Table 149:
  // "the node specified by the browse path will never allow the given AttributeId to be returned").
  // This holds for every possible Event, so it is a valid compile-time select-clause error.
  if (browsePath.empty() && attrId != utils::to_underlying(AttributeId::NodeId))
  {
    return StatusCode{Status::BadAttributeIdInvalid};
  }

  return StatusCode{Status::Good};
}

/// Compile a single filter operand.
/// Returns the compiled operand and a status code.
std::pair<CompiledOperand, StatusCode> compile_operand(
  const RefStructure<Structure>& operandRef, uint32_t elementCount)
{
  const auto* ptr = operandRef.get();
  if (!ptr)
    return {Variant{}, StatusCode{Status::BadFilterOperandInvalid}};

  if (const auto* elem = dynamic_cast<const ElementOperand*>(ptr))
  {
    auto idx = elem->index();
    if (idx >= elementCount)
      return {Variant{}, StatusCode{Status::BadFilterElementInvalid}};
    return {idx, StatusCode{Status::Good}};
  }

  if (const auto* lit = dynamic_cast<const LiteralOperand*>(ptr))
  {
    return {lit->value(), StatusCode{Status::Good}};
  }

  if (const auto* sao = dynamic_cast<const SimpleAttributeOperand*>(ptr))
  {
    ResolvedSelectClause resolved;
    const auto& browsePath = sao->browse_path();
    resolved.browsePath.reserve(browsePath.size());
    for (size_t i = 0; i < browsePath.size(); ++i)
      resolved.browsePath.push_back(browsePath[i]);

    resolved.attributeId = sao->attribute_id();
    if (resolved.attributeId == 0)
      resolved.attributeId = utils::to_underlying(AttributeId::Value);

    resolved.typeDefinitionId = sao->type_definition_id();

    resolved.validationStatus = StatusCode{Status::Good};
    return {std::move(resolved), StatusCode{Status::Good}};
  }

  // AttributeOperand is disallowed in EventFilter where clause (SVR-EVT-FLT-021)
  if (dynamic_cast<const AttributeOperand*>(ptr))
    return {Variant{}, StatusCode{Status::BadFilterOperandInvalid}};

  return {Variant{}, StatusCode{Status::BadFilterOperandInvalid}};
}

}  // namespace

// --- CompiledEventFilter ---

CompiledEventFilterResult CompiledEventFilter::compile(const EventFilter& filter,
  EventFilterCompileLimits limits, std::span<const StatusCode> selectClauseModelStatuses,
  std::span<const std::optional<NodeAccessor>> selectClauseDeclarations)
{
  CompiledEventFilterResult result;
  result.overallStatus = StatusCode{Status::Good};

  auto& filterResult = result.filterResult;

  // --- Validate select clauses ---
  const auto& selectClauses = filter.select_clauses();
  if (selectClauses.empty())
  {
    // SVR-EVT-FLT-003: at least one valid clause required
    result.overallStatus = StatusCode{Status::BadMonitoredItemFilterInvalid};
    return result;
  }

  // SVR-EVT-CAP-001: enforce MaxSelectClauseParameters
  if (limits.maxSelectClauses > 0 && selectClauses.size() > limits.maxSelectClauses)
  {
    result.overallStatus = StatusCode{Status::BadMonitoredItemFilterInvalid};
    return result;
  }

  // SVR-EVT-CAP-002: enforce MaxWhereClauseParameters on the element count.
  if (limits.maxWhereClauseElements > 0 &&
      filter.where_clause().elements().size() > limits.maxWhereClauseElements)
  {
    result.overallStatus = StatusCode{Status::BadMonitoredItemFilterInvalid};
    return result;
  }

  // SVR-EVT-CAP-002b: bound the TOTAL number of where-clause operands (summed across every element), not
  // just the element count. Per OPC 10000-4 MaxWhereClauseParameters bounds the where-clause operands;
  // an operator with unbounded operand arity (e.g. InList, whose expected_operand_count max is
  // UINT32_MAX) otherwise lets one small CreateMonitoredItems install a filter costing millions of
  // per-event comparisons on the subscription strand (post-auth CPU-amplification DoS). Reject before
  // the compile loop allocates, so the cost is paid neither in compilation nor in per-event evaluation.
  if (limits.maxWhereClauseElements > 0)
  {
    uint64_t totalOperands = 0;
    for (const auto& element : filter.where_clause().elements())
    {
      totalOperands += element.filter_operands().size();
    }
    if (totalOperands > limits.maxWhereClauseElements)
    {
      result.overallStatus = StatusCode{Status::BadMonitoredItemFilterInvalid};
      return result;
    }
  }

  // SVR-EVT-CAP-002c: bound the TOTAL byte size of where-clause string-literal operands. `Like` is
  // O(text x pattern) per event and And/Or do NOT short-circuit (all operands pre-resolved), so a long
  // pattern literal (bounded only by mMaxStringLength, up to 1 MB) repeated across elements multiplies
  // per-event CPU on the subscription strand - an authenticated slow-burn DoS the operand-COUNT cap
  // (SVR-EVT-CAP-002b) does not bound. Reject before the compile loop so the cost is paid neither in
  // compilation nor per-event evaluation.
  if (limits.maxWhereClauseOperandBytes > 0)
  {
    uint64_t totalLiteralBytes = 0;
    for (const auto& element : filter.where_clause().elements())
    {
      for (const auto& operandRef : element.filter_operands())
      {
        if (const auto* lit = dynamic_cast<const LiteralOperand*>(operandRef.get()))
        {
          if (lit->value().is_string())
            totalLiteralBytes += static_cast<std::string_view>(lit->value().as<String>()).size();
        }
      }
    }
    if (totalLiteralBytes > limits.maxWhereClauseOperandBytes)
    {
      result.overallStatus = StatusCode{Status::BadMonitoredItemFilterInvalid};
      return result;
    }
  }

  auto compiledFilter = std::make_unique<CompiledEventFilter>();
  compiledFilter->mSelectClauses.reserve(selectClauses.size());

  auto& selectResults = filterResult.select_clause_results();
  bool hasValidSelectClause = false;

  for (size_t i = 0; i < selectClauses.size(); ++i)
  {
    const auto& clause = selectClauses[i];
    auto status = validate_select_clause(clause);
    if (status.is_good() && i < selectClauseModelStatuses.size() && selectClauseModelStatuses[i].is_bad())
    {
      status = selectClauseModelStatuses[i];
    }
    selectResults.push_back(status);

    ResolvedSelectClause resolved;
    const auto& browsePath = clause.browse_path();
    resolved.browsePath.reserve(browsePath.size());
    for (size_t j = 0; j < browsePath.size(); ++j)
      resolved.browsePath.push_back(browsePath[j]);

    resolved.attributeId = clause.attribute_id();
    if (resolved.attributeId == 0)
      resolved.attributeId = utils::to_underlying(AttributeId::Value);

    resolved.typeDefinitionId = clause.type_definition_id();

    resolved.validationStatus = status;
    if (i < selectClauseDeclarations.size())
      resolved.declarationAccessor = selectClauseDeclarations[i];
    compiledFilter->mSelectClauses.push_back(std::move(resolved));

    if (status.is_good())
      hasValidSelectClause = true;
  }

  if (!hasValidSelectClause)
  {
    const auto firstFailure = std::find_if(
      selectResults.begin(), selectResults.end(), [](const StatusCode& status) { return status.is_bad(); });
    if (firstFailure == selectResults.end())
    {
      result.overallStatus = StatusCode{Status::BadMonitoredItemFilterInvalid};
    }
    else
    {
      result.overallStatus = StatusCode{Status::BadMonitoredItemFilterInvalid,
        ErrorDetail::build("MonitoredItemFilterInvalid",
          "Every EventFilter select clause failed validation",
          "CompiledEventFilter")
          .cause(*firstFailure)};
    }
    return result;
  }

  // --- Validate and compile where clause ---
  const auto& whereClause = filter.where_clause();
  const auto& elements = whereClause.elements();
  auto elementCount = numeric_cast<uint32_t>(elements.size());

  auto& whereResult = filterResult.where_clause_result();

  for (uint32_t i = 0; i < elementCount; ++i)
  {
    const auto& element = elements[i];
    auto op = element.filter_operator();

    ContentFilterElementResult elemResult;

    // Check if operator is allowed (SVR-EVT-FLT-019)
    auto [minOps, maxOps] = expected_operand_count(op);
    if (minOps == 0 && maxOps == 0)
    {
      elemResult.status_code() = StatusCode{Status::BadFilterOperatorUnsupported};
      whereResult.element_results().push_back(std::move(elemResult));
      continue;
    }

    // Check operand count (SVR-EVT-CF-002)
    const auto& operands = element.filter_operands();
    auto opCount = numeric_cast<uint32_t>(operands.size());
    if (opCount < minOps || opCount > maxOps)
    {
      elemResult.status_code() = StatusCode{Status::BadFilterOperandCountMismatch};
      whereResult.element_results().push_back(std::move(elemResult));
      continue;
    }

    CompiledFilterElement compiled;
    compiled.op = op;
    bool elementValid = true;

    for (uint32_t j = 0; j < opCount; ++j)
    {
      auto [compiledOp, opStatus] = compile_operand(operands[j], elementCount);
      elemResult.operand_status_codes().push_back(opStatus);

      if (opStatus.is_bad())
        elementValid = false;

      compiled.operands.push_back(std::move(compiledOp));
    }

    elemResult.status_code() =
      elementValid ? StatusCode{Status::Good} : StatusCode{Status::BadFilterOperandInvalid};

    whereResult.element_results().push_back(std::move(elemResult));
    compiledFilter->mWhereElements.push_back(std::move(compiled));
  }

  // Check for cycles (SVR-EVT-CF-001)
  if (!compiledFilter->mWhereElements.empty() && !is_acyclic(compiledFilter->mWhereElements))
  {
    result.overallStatus = StatusCode{Status::BadMonitoredItemFilterInvalid};
    return result;
  }

  // Check if any where clause element had errors
  const auto& elemResults = whereResult.element_results();
  for (size_t i = 0; i < elemResults.size(); ++i)
  {
    if (elemResults[i].status_code().is_bad())
    {
      result.overallStatus = StatusCode{Status::BadMonitoredItemFilterInvalid};
      return result;
    }
  }

  result.filter = std::move(compiledFilter);
  return result;
}

namespace
{

/// OPC 10000-9 section 4.5: RefreshStartEventType, RefreshEndEventType and RefreshRequiredEventType "ignore
/// the Event content filtering associated with a Subscription and will always be delivered to the Client".
/// The select clauses still shape what is delivered.
bool ignores_where_clause(const BaseEvent& event)
{
  return event.eventType == NodeId{ObjectTypeId::RefreshStartEventType} ||
         event.eventType == NodeId{ObjectTypeId::RefreshEndEventType} ||
         event.eventType == NodeId{ObjectTypeId::RefreshRequiredEventType};
}

}  // namespace

bool CompiledEventFilter::evaluate(const BaseEvent& event) const
{
  if (mWhereElements.empty() || ignores_where_clause(event))
    return true;  // an empty where clause passes every event; a refresh event ignores it

  // Evaluate starting from element 0 (the root)
  ElementResults memo{mWhereElements.size()};
  auto result = evaluate_element(event, 0, memo);

  // The result should be a boolean. Null or non-boolean means the event does not pass.
  if (result.empty() || !result.is_boolean())
    return false;

  return result.as<bool>();
}

std::vector<CompiledEventFilter::AuthorizationSubject> CompiledEventFilter::authorization_subjects(
  const BaseEvent& event,
  const std::shared_ptr<const event_type_model::DeclarationsResult>& declarationModel) const
{
  std::vector<AuthorizationSubject> subjects;
  const auto append = [&subjects](AuthorizationSubject subject)
  {
    const auto duplicate = std::ranges::find_if(subjects,
      [&subject](const AuthorizationSubject& candidate)
      { return candidate.nodeId == subject.nodeId && candidate.operation == subject.operation; });
    if (duplicate == subjects.end())
      subjects.push_back(std::move(subject));
  };

  for (const auto& clause : mSelectClauses)
  {
    if (is_inviolate_field(clause))
      continue;
    if (auto nodeId = authorization_subject(event, clause, declarationModel))
    {
      const auto attribute = utils::from_underlying<AttributeId>(clause.attributeId);
      append(AuthorizationSubject{std::move(*nodeId), AccessControl::attribute_read_operation(attribute)});
    }
  }

  for (const auto& element : mWhereElements)
  {
    for (const auto& operand : element.operands)
    {
      const auto* clause = std::get_if<ResolvedSelectClause>(&operand);
      if (!clause || is_inviolate_field(*clause))
        continue;
      if (auto nodeId = authorization_subject(event, *clause, declarationModel))
      {
        const auto attribute = utils::from_underlying<AttributeId>(clause->attributeId);
        append(AuthorizationSubject{std::move(*nodeId), AccessControl::attribute_read_operation(attribute)});
      }
    }
  }
  return subjects;
}

bool CompiledEventFilter::evaluate_authorized(const BaseEvent& event,
  const std::shared_ptr<const event_type_model::DeclarationsResult>& declarationModel,
  std::span<const AccessControl::Verdict> verdicts) const
{
  if (mWhereElements.empty() || ignores_where_clause(event))
    return true;

  ElementResults memo{mWhereElements.size()};
  auto result = evaluate_element_authorized(event, 0, memo, declarationModel, verdicts);
  return !result.empty() && result.is_boolean() && result.as<bool>();
}

bool CompiledEventFilter::operand_applies_to_event(const BaseEvent& event, const NodeId& typeDefinitionId)
{
  // Table 133: a null typeDefinitionId or BaseEventType means the browsePath is evaluated without
  // considering the typeDefinitionId, so the operand always applies.
  if (typeDefinitionId.is_null() || typeDefinitionId == NodeId{ObjectTypeId::BaseEventType})
    return true;

  // The operand applies iff the event is of typeDefinitionId or a subtype - i.e. typeDefinitionId is
  // in the event's supertype chain. The EventBus resolves and attaches that chain (from the address
  // space HasSubtype graph) before any monitored item evaluates the filter, so this branch is taken
  // for every dispatched event.
  if (const auto& chain = event.eventTypeHierarchy)
  {
    for (const NodeId& ancestor : *chain)
    {
      if (ancestor == typeDefinitionId)
        return true;
    }
    return false;
  }

  // No resolved chain - the event was evaluated off the EventBus (e.g. a direct unit-test call). The
  // type restriction cannot be evaluated here; applying it would risk dropping a requested field on a
  // check we could not actually perform, so the operand applies.
  return true;
}

Variant CompiledEventFilter::resolve_select_field(const BaseEvent& event, const ResolvedSelectClause& clause)
{
  // SVR-EVT-FLT-009: clauses that failed validation project/evaluate as null.
  if (clause.validationStatus.is_bad())
    return Variant{};

  // Table 133: the operand only applies to instances of its typeDefinitionId or a subtype; otherwise
  // the field is null for this event.
  if (!operand_applies_to_event(event, clause.typeDefinitionId))
    return Variant{};

  // Part 4 7.7.4.5 Table 133: "If this list [browsePath] is empty the Node is the instance of the
  // TypeDefinition." The attributeId then selects which attribute of that instance node to read. An
  // event is transient and has no node of its own, so the only instance it references is its Condition;
  // hence empty browsePath + attributeId == NodeId yields the Condition's NodeId - the ConditionId.
  // This is a general operand rule, not a ConditionId-specific case, so it must hold wherever the
  // operand appears: select-clause projection AND where-clause evaluation (e.g. InList(ConditionId,
  // [...])). Keeping it in one shared helper guarantees both paths resolve the operand identically.
  if (clause.browsePath.empty() && clause.attributeId == utils::to_underlying(AttributeId::NodeId))
  {
    if (event.conditionNodeId.has_value())
      return Variant{*event.conditionNodeId};
    return Variant{};
  }

  auto field = event.resolve_field(clause.browsePath);
  if (clause.attributeId == utils::to_underlying(AttributeId::Value))
  {
    if (const auto* dataValue = field.try_as<DataValue>())
    {
      const auto& fieldStatus = dataValue->status();
      if (fieldStatus.has_value() && !fieldStatus.value().is_good())
        return Variant{fieldStatus.value()};
      return dataValue->value();
    }
  }
  return field;
}

bool CompiledEventFilter::is_inviolate_field(const ResolvedSelectClause& clause) noexcept
{
  return clause.browsePath.size() == 1 && clause.browsePath.front().namespace_index() == 0 &&
         (clause.browsePath.front().name() == "EventId" || clause.browsePath.front().name() == "EventType" ||
           clause.browsePath.front().name() == "ReceiveTime");
}

std::optional<NodeId> CompiledEventFilter::authorization_subject(const BaseEvent& event,
  const ResolvedSelectClause& clause,
  const std::shared_ptr<const event_type_model::DeclarationsResult>& declarationModel)
{
  if (clause.validationStatus.is_bad() || !operand_applies_to_event(event, clause.typeDefinitionId) ||
      !declarationModel || !declarationModel->is_good())
  {
    return std::nullopt;
  }

  if (clause.browsePath.empty() && clause.attributeId == utils::to_underlying(AttributeId::NodeId))
  {
    if (!clause.typeDefinitionId.is_null())
      return clause.typeDefinitionId;
    return std::nullopt;
  }

  const auto& declarations = declarationModel->value();
  const auto declaration = std::ranges::find_if(declarations,
    [&clause](const event_type_model::Declaration& candidate)
    { return candidate.browsePath == clause.browsePath; });
  if (declaration != declarations.end())
    return declaration->nodeId;

  // A successfully resolved concrete model and no declaration proves that an empty field is absent
  // for this EventType. A raw value without its required declaration is deliberately not assigned a
  // guessed subject; projection/evaluation then fails closed.
  return std::nullopt;
}

const AccessControl::Verdict* CompiledEventFilter::associated_verdict(
  const AuthorizationSubject& subject, std::span<const AccessControl::Verdict> verdicts) noexcept
{
  const auto found = std::ranges::find_if(verdicts,
    [&subject](const AccessControl::Verdict& verdict)
    { return verdict.subject == subject.nodeId && verdict.operation == subject.operation; });
  return found == verdicts.end() ? nullptr : &*found;
}

const AccessControl::Item* CompiledEventFilter::associated_item(
  const AuthorizationSubject& subject, std::span<const AccessControl::Item> items) noexcept
{
  const auto found = std::ranges::find_if(items,
    [&subject](const AccessControl::Item& item)
    {
      try
      {
        return item.node.get_node_id() == subject.nodeId && item.operation == subject.operation;
      }
      catch (...)
      {
        return false;
      }
    });
  return found == items.end() ? nullptr : &*found;
}

EventFieldList CompiledEventFilter::project_authorized(const BaseEvent& event, uint32_t clientHandle,
  const std::shared_ptr<const event_type_model::DeclarationsResult>& declarationModel,
  const SessionAccessControl& accessControl, std::span<const AccessControl::Item> resolvedItems,
  std::span<const AccessControl::Verdict> verdicts, uint32_t maxResponseMessageSize) const
{
  EventFieldList fieldList;
  fieldList.client_handle() = clientHandle;
  auto& fields = fieldList.event_fields();
  fields.reserve(mSelectClauses.size());

  StatusCode declarationStatus{Status::Good};
  if (!declarationModel)
  {
    declarationStatus = StatusCode{Status::BadInvalidState,
      ErrorDetail::build("EventFieldDeclarationModelMissing",
        "The concrete EventType declaration model was not supplied",
        "CompiledEventFilter")};
  }
  else if (!declarationModel->is_good())
  {
    declarationStatus = declarationModel->status_code();
  }

  for (const auto& clause : mSelectClauses)
  {
    auto field = resolve_select_field(event, clause);
    if (is_inviolate_field(clause) || clause.validationStatus.is_bad())
    {
      fields.push_back(std::move(field));
      continue;
    }
    if (!declarationStatus.is_good())
    {
      fields.emplace_back(StatusCode{Status::BadUserAccessDenied,
        ErrorDetail::build("EventFieldDeclarationModelUnavailable",
          "The concrete EventType declaration model could not be resolved for authorization",
          "CompiledEventFilter")
          .cause(declarationStatus)});
      continue;
    }

    const auto nodeId = authorization_subject(event, clause, declarationModel);
    if (!nodeId)
    {
      if (field.empty())
      {
        fields.push_back(std::move(field));
      }
      else
      {
        fields.emplace_back(StatusCode{Status::BadUserAccessDenied,
          ErrorDetail::build("EventFieldDeclarationUnavailable",
            "The Event field declaration could not be resolved for authorization",
            "CompiledEventFilter")});
      }
      continue;
    }

    const auto attribute = utils::from_underlying<AttributeId>(clause.attributeId);
    const AuthorizationSubject subject{*nodeId, AccessControl::attribute_read_operation(attribute)};
    const auto* verdict = associated_verdict(subject, verdicts);
    if (!verdict || !verdict->permitted)
    {
      StatusCode cause{Status::BadUserAccessDenied,
        ErrorDetail::build("EventFieldAuthorizationVerdictMissing",
          "The Event field has no permitted associated authorization verdict",
          "CompiledEventFilter")};
      if (verdict && verdict->cause.is_bad())
      {
        cause = verdict->cause.as_status() == Status::BadUserAccessDenied
                  ? verdict->cause
                  : StatusCode{Status::BadUserAccessDenied,
                      ErrorDetail::build("EventFieldReadDenied",
                        "The current Session user may not read the selected Event field",
                        "CompiledEventFilter")
                        .cause(verdict->cause)};
      }
      fields.emplace_back(std::move(cause));
      continue;
    }

    if (attribute == AttributeId::RolePermissions || attribute == AttributeId::UserRolePermissions ||
        attribute == AttributeId::UserAccessLevel || attribute == AttributeId::UserWriteMask ||
        attribute == AttributeId::UserExecutable)
    {
      const auto* item = associated_item(subject, resolvedItems);
      if (!item)
      {
        fields.emplace_back(StatusCode{Status::BadUserAccessDenied,
          ErrorDetail::build("EventFieldAuthorizationSubjectMissing",
            "The authorized Event field does not retain its resolved node subject",
            "CompiledEventFilter")});
        continue;
      }
      auto projected = accessControl.make_client_attribute_value(
        item->node, attribute, DataValue{std::move(field), StatusCode{Status::Good}}, *verdict);
      const auto& projectionStatus = projected.status();
      // A bad projection is non-fatal to other fields; its status is returned in this field.
      if (projectionStatus && projectionStatus.value().is_bad())
        fields.emplace_back(projectionStatus.value());
      else
        fields.push_back(std::move(projected.value()));
      continue;
    }

    fields.push_back(std::move(field));
  }
  enforce_encoding_limit(fieldList, maxResponseMessageSize);
  return fieldList;
}

std::shared_ptr<const CompiledEventFilter> CompiledEventFilter::retained_copy() const
{
  auto retained = std::make_shared<CompiledEventFilter>(*this);
  for (auto& clause : retained->mSelectClauses)
    clause.declarationAccessor.reset();
  for (auto& element : retained->mWhereElements)
  {
    for (auto& operand : element.operands)
    {
      if (auto* clause = std::get_if<ResolvedSelectClause>(&operand))
        clause->declarationAccessor.reset();
    }
  }
  return retained;
}

EventFieldList CompiledEventFilter::project(const BaseEvent& event, uint32_t clientHandle) const
{
  return project(event, clientHandle, 0);
}

EventFieldList CompiledEventFilter::project(
  const BaseEvent& event, uint32_t clientHandle, uint32_t maxResponseMessageSize) const
{
  EventFieldList fieldList;
  fieldList.client_handle() = clientHandle;
  auto& fields = fieldList.event_fields();
  fields.reserve(mSelectClauses.size());
  for (const auto& clause : mSelectClauses)
    fields.push_back(resolve_select_field(event, clause));
  enforce_encoding_limit(fieldList, maxResponseMessageSize);
  return fieldList;
}

void CompiledEventFilter::enforce_encoding_limit(EventFieldList& fieldList, uint32_t maxResponseMessageSize)
{
  if (maxResponseMessageSize == 0)
    return;

  for (auto& field : fieldList.event_fields())
  {
    NullStream countingStream;
    UaBinaryEncoder encoder{CodecNamespaceContext{}, countingStream};
    encoder.encode(EncodingLimits{}.stack_depth(), field);
    if (countingStream.get_position() > maxResponseMessageSize)
      field = Variant{StatusCode{Status::BadEncodingLimitsExceeded}};
  }
}

Variant CompiledEventFilter::evaluate_element(
  const BaseEvent& event, uint32_t elementIndex, ElementResults& memo) const
{
  if (elementIndex >= mWhereElements.size())
    return Variant{};  // SVR-EVT-FLT-017: null on error

  if (memo.results[elementIndex])
    return *memo.results[elementIndex];  // a second ElementOperand naming this element
  if (memo.inProgress[elementIndex])
    return Variant{};  // Cycle protection

  memo.inProgress[elementIndex] = true;

  const auto& element = mWhereElements[elementIndex];

  // Resolve all operands
  std::vector<Variant> resolvedOperands;
  resolvedOperands.reserve(element.operands.size());
  for (const auto& operand : element.operands)
  {
    resolvedOperands.push_back(resolve_operand(event, operand, elementIndex, memo));
  }

  // Apply the operator
  auto result = apply_operator(element.op, resolvedOperands, event);
  memo.inProgress[elementIndex] = false;
  memo.results[elementIndex] = result;
  return result;
}

Variant CompiledEventFilter::evaluate_element_authorized(const BaseEvent& event, uint32_t elementIndex,
  ElementResults& memo, const std::shared_ptr<const event_type_model::DeclarationsResult>& declarationModel,
  std::span<const AccessControl::Verdict> verdicts) const
{
  if (elementIndex >= mWhereElements.size() || memo.inProgress[elementIndex])
    return Variant{};
  if (memo.results[elementIndex])
    return *memo.results[elementIndex];

  memo.inProgress[elementIndex] = true;
  const auto& element = mWhereElements[elementIndex];
  std::vector<Variant> resolvedOperands;
  resolvedOperands.reserve(element.operands.size());
  for (const auto& operand : element.operands)
  {
    resolvedOperands.push_back(
      resolve_operand_authorized(event, operand, elementIndex, memo, declarationModel, verdicts));
  }
  auto result = apply_operator(element.op, resolvedOperands, event);
  memo.inProgress[elementIndex] = false;
  memo.results[elementIndex] = result;
  return result;
}

Variant CompiledEventFilter::resolve_operand(const BaseEvent& event, const CompiledOperand& operand,
  uint32_t /*current_element*/, ElementResults& memo) const
{
  if (const auto* elementRef = std::get_if<uint32_t>(&operand))
  {
    return evaluate_element(event, *elementRef, memo);
  }

  if (const auto* selectClause = std::get_if<ResolvedSelectClause>(&operand))
  {
    return resolve_select_field(event, *selectClause);
  }

  if (const auto* literal = std::get_if<Variant>(&operand))
  {
    return *literal;
  }

  return Variant{};
}

Variant CompiledEventFilter::resolve_operand_authorized(const BaseEvent& event,
  const CompiledOperand& operand, uint32_t /*currentElement*/, ElementResults& memo,
  const std::shared_ptr<const event_type_model::DeclarationsResult>& declarationModel,
  std::span<const AccessControl::Verdict> verdicts) const
{
  if (const auto* elementRef = std::get_if<uint32_t>(&operand))
  {
    return evaluate_element_authorized(event, *elementRef, memo, declarationModel, verdicts);
  }

  if (const auto* clause = std::get_if<ResolvedSelectClause>(&operand))
  {
    auto field = resolve_select_field(event, *clause);
    if (is_inviolate_field(*clause))
      return field;
    const auto nodeId = authorization_subject(event, *clause, declarationModel);
    if (!nodeId)
      return Variant{};
    const auto attribute = utils::from_underlying<AttributeId>(clause->attributeId);
    const AuthorizationSubject subject{*nodeId, AccessControl::attribute_read_operation(attribute)};
    const auto* verdict = associated_verdict(subject, verdicts);
    if (!verdict || !verdict->permitted)
      return Variant{};
    return field;
  }

  if (const auto* literal = std::get_if<Variant>(&operand))
    return *literal;
  return Variant{};
}

Variant CompiledEventFilter::apply_operator(
  FilterOperator op, std::span<const Variant> operands, const BaseEvent& event)
{
  // SVR-EVT-FLT-017: any error -> null. We use try/catch as a safety net.
  try
  {
    switch (op)
    {
    case FilterOperator::Equals:
    {
      if (operands.size() < 2 || operands[0].empty() || operands[1].empty())
        return Variant{};
      return Variant{operands[0] == operands[1]};
    }

    case FilterOperator::IsNull:
    {
      if (operands.empty())
        return Variant{};
      return Variant{operands[0].empty()};
    }

    case FilterOperator::Not:
    {
      if (operands.empty() || operands[0].empty() || !operands[0].is_boolean())
        return Variant{};
      return Variant{!operands[0].as<bool>()};
    }

    case FilterOperator::And:
    {
      if (operands.size() < 2)
        return Variant{};

      // Three-valued logic: null AND false = false, null AND true = null
      const bool lhsNull = operands[0].empty() || !operands[0].is_boolean();
      const bool rhsNull = operands[1].empty() || !operands[1].is_boolean();

      if (lhsNull && rhsNull)
        return Variant{};

      if (lhsNull)
        return operands[1].as<bool>() ? Variant{} : Variant{false};
      if (rhsNull)
        return operands[0].as<bool>() ? Variant{} : Variant{false};

      return Variant{operands[0].as<bool>() && operands[1].as<bool>()};
    }

    case FilterOperator::Or:
    {
      if (operands.size() < 2)
        return Variant{};

      // Three-valued logic: null OR true = true, null OR false = null
      const bool lhsNull = operands[0].empty() || !operands[0].is_boolean();
      const bool rhsNull = operands[1].empty() || !operands[1].is_boolean();

      if (lhsNull && rhsNull)
        return Variant{};

      if (lhsNull)
        return operands[1].as<bool>() ? Variant{true} : Variant{};
      if (rhsNull)
        return operands[0].as<bool>() ? Variant{true} : Variant{};

      return Variant{operands[0].as<bool>() || operands[1].as<bool>()};
    }

    case FilterOperator::GreaterThan:
    {
      if (operands.size() < 2)
        return Variant{};
      auto cmp = compare_variants(operands[0], operands[1]);
      if (!cmp)
        return Variant{};
      return Variant{*cmp > 0};
    }

    case FilterOperator::LessThan:
    {
      if (operands.size() < 2)
        return Variant{};
      auto cmp = compare_variants(operands[0], operands[1]);
      if (!cmp)
        return Variant{};
      return Variant{*cmp < 0};
    }

    case FilterOperator::GreaterThanOrEqual:
    {
      if (operands.size() < 2)
        return Variant{};
      auto cmp = compare_variants(operands[0], operands[1]);
      if (!cmp)
        return Variant{};
      return Variant{*cmp >= 0};
    }

    case FilterOperator::LessThanOrEqual:
    {
      if (operands.size() < 2)
        return Variant{};
      auto cmp = compare_variants(operands[0], operands[1]);
      if (!cmp)
        return Variant{};
      return Variant{*cmp <= 0};
    }

    case FilterOperator::Like:
    {
      if (operands.size() < 2)
        return Variant{};
      // Spec: returns FALSE (not NULL) if operands cannot resolve to strings.
      if (!operands[0].is_string() || !operands[1].is_string())
        return Variant{false};
      auto text = static_cast<std::string_view>(operands[0].as<String>());
      auto pattern = static_cast<std::string_view>(operands[1].as<String>());
      return Variant{match_like(text, pattern)};
    }

    case FilterOperator::Between:
    {
      if (operands.size() < 3)
        return Variant{};
      auto cmpLow = compare_variants(operands[0], operands[1]);
      auto cmpHigh = compare_variants(operands[0], operands[2]);
      if (!cmpLow || !cmpHigh)
        return Variant{};
      return Variant{*cmpLow >= 0 && *cmpHigh <= 0};
    }

    case FilterOperator::InList:
    {
      if (operands.size() < 2 || operands[0].empty())
        return Variant{};
      for (size_t i = 1; i < operands.size(); ++i)
      {
        if (!operands[i].empty() && operands[0] == operands[i])
          return Variant{true};
      }
      return Variant{false};
    }

    case FilterOperator::OfType:
    {
      if (operands.empty() || operands[0].empty())
        return Variant{};

      // Operand must resolve to a NodeId (SVR-EVT-FLT-023/024)
      if (!operands[0].is_node_id())
        return Variant{false};

      return Variant{is_of_type(event, operands[0].as<NodeId>())};
    }

    case FilterOperator::Cast:
    {
      if (operands.size() < 2 || operands[0].empty() || operands[1].empty())
        return Variant{};
      if (!operands[1].is_node_id())
        return Variant{};
      const auto& targetTypeId = operands[1].as<NodeId>();
      if (targetTypeId.namespace_index() != 0 || !targetTypeId.identifier().is_numeric())
        return Variant{};
      auto targetBuiltIn = static_cast<BuiltInTypeId>(targetTypeId.identifier().get_numeric());
      return cast_variant(operands[0], targetBuiltIn);
    }

    case FilterOperator::BitwiseAnd:
    {
      if (operands.size() < 2)
        return Variant{};
      auto lhs = to_double(operands[0]);
      auto rhs = to_double(operands[1]);
      if (!lhs || !rhs)
        return Variant{};
      return Variant{numeric_cast<int64_t>(*lhs) & numeric_cast<int64_t>(*rhs)};
    }

    case FilterOperator::BitwiseOr:
    {
      if (operands.size() < 2)
        return Variant{};
      auto lhs = to_double(operands[0]);
      auto rhs = to_double(operands[1]);
      if (!lhs || !rhs)
        return Variant{};
      return Variant{numeric_cast<int64_t>(*lhs) | numeric_cast<int64_t>(*rhs)};
    }

    default:
      return Variant{};
    }
  }
  catch (...)
  {
    // SVR-EVT-FLT-017: null on any error
    return Variant{};
  }
}

std::optional<int> CompiledEventFilter::compare_variants(const Variant& lhs, const Variant& rhs)
{
  if (lhs.empty() || rhs.empty())
    return std::nullopt;

  // Numeric comparison
  auto lhsNum = to_double(lhs);
  auto rhsNum = to_double(rhs);
  if (lhsNum && rhsNum)
  {
    if (*lhsNum < *rhsNum)
      return -1;
    if (*lhsNum > *rhsNum)
      return 1;
    return 0;
  }

  // String comparison
  if (lhs.is_string() && rhs.is_string())
  {
    auto lhsView = static_cast<std::string_view>(lhs.as<String>());
    auto rhsView = static_cast<std::string_view>(rhs.as<String>());
    return lhsView.compare(rhsView);
  }

  // DateTime comparison
  if (lhs.is_date_time() && rhs.is_date_time())
  {
    const auto& lhsDt = lhs.as<DateTime>();
    const auto& rhsDt = rhs.as<DateTime>();
    if (lhsDt < rhsDt)
      return -1;
    if (rhsDt < lhsDt)
      return 1;
    return 0;
  }

  // NodeId equality only (no ordering)
  if (lhs.is_node_id() && rhs.is_node_id())
  {
    return (lhs.as<NodeId>() == rhs.as<NodeId>()) ? 0 : std::optional<int>{std::nullopt};
  }

  return std::nullopt;
}

std::optional<double> CompiledEventFilter::to_double(const Variant& variant)
{
  if (variant.empty())
    return std::nullopt;

  if (variant.is_boolean())
    return variant.as<bool>() ? 1.0 : 0.0;
  if (variant.is_int8())
    return static_cast<double>(variant.as<int8_t>());
  if (variant.is_uint8())
    return static_cast<double>(variant.as<uint8_t>());
  if (variant.is_int16())
    return static_cast<double>(variant.as<int16_t>());
  if (variant.is_uint16())
    return static_cast<double>(variant.as<uint16_t>());
  if (variant.is_int32())
    return static_cast<double>(variant.as<int32_t>());
  if (variant.is_uint32())
    return static_cast<double>(variant.as<uint32_t>());
  if (variant.is_int64())
    return static_cast<double>(variant.as<int64_t>());
  if (variant.is_uint64())
    return static_cast<double>(variant.as<uint64_t>());
  if (variant.is_float())
    return static_cast<double>(variant.as<float>());
  if (variant.is_double())
    return variant.as<double>();

  return std::nullopt;
}

bool CompiledEventFilter::is_of_type(const BaseEvent& event, const NodeId& typeId)
{
  // EventFilter OfType subtype matching (Part 4 7.7.3): the event matches if
  // `type_id` is its EventType or any supertype. The authoritative hierarchy is
  // the server's address-space HasSubtype graph; the EventBus resolves each
  // event's supertype chain at dispatch and attaches it as event_type_hierarchy.
  // Here we do a pure synchronous membership test - no address-space access on
  // the subscription strand.
  if (const auto& chain = event.eventTypeHierarchy)
  {
    for (const NodeId& ancestor : *chain)
    {
      if (ancestor == typeId)
        return true;
    }
    return false;
  }

  // No resolved chain (event not dispatched through the EventBus - e.g. a direct
  // unit-test evaluation): fall back to an exact EventType match.
  return event.eventType == typeId;
}

// --- Like pattern matching (OPC UA Part 4, Table 124) ---

namespace
{

/// Parse a [...] character class from the pattern starting after the opening '['.
/// Returns true if 'ch' is in the set, and advances 'pi' past the closing ']'.
/// On malformed input (no closing ']'), returns false with pi at pattern end.
bool match_char_class(char ch, std::string_view pattern, size_t& pi)
{
  bool negated = false;
  if (pi < pattern.size() && pattern[pi] == '^')
  {
    negated = true;
    ++pi;
  }

  bool found = false;
  // We need to handle at least one character before looking for ']' as closing.
  bool first = true;

  while (pi < pattern.size() && (first || pattern[pi] != ']'))
  {
    first = false;
    const char lo = pattern[pi];
    ++pi;

    // Check for range: lo '-' hi
    if (pi + 1 < pattern.size() && pattern[pi] == '-' && pattern[pi + 1] != ']')
    {
      const char hi = pattern[pi + 1];
      pi += 2;
      if (ch >= lo && ch <= hi)
        found = true;
    }
    else
    {
      if (ch == lo)
        found = true;
    }
  }

  // Skip closing ']'
  if (pi < pattern.size() && pattern[pi] == ']')
    ++pi;

  return negated ? !found : found;
}

}  // namespace

bool CompiledEventFilter::match_like(std::string_view text, std::string_view pattern)
{
  // Iterative two-pointer approach with '%' restart tracking.
  size_t ti = 0;
  size_t pi = 0;
  size_t starPi = std::string_view::npos;  // pattern index after last '%'
  size_t starTi = 0;  // text index to retry from on backtrack

  while (ti < text.size())
  {
    if (pi < pattern.size() && pattern[pi] == '%')
    {
      // Record restart point and skip consecutive '%'.
      while (pi < pattern.size() && pattern[pi] == '%')
        ++pi;
      if (pi == pattern.size())
        return true;  // Trailing '%' matches everything.
      starPi = pi;
      starTi = ti;
      continue;
    }

    if (pi < pattern.size())
    {
      bool matched = false;

      if (pattern[pi] == '_')
      {
        // Match any single character.
        matched = true;
        ++pi;
      }
      else if (pattern[pi] == '\\' && pi + 1 < pattern.size())
      {
        // Escaped character - match literal.
        matched = (text[ti] == pattern[pi + 1]);
        pi += 2;
      }
      else if (pattern[pi] == '[')
      {
        // Character class.
        size_t classPi = pi + 1;
        matched = match_char_class(text[ti], pattern, classPi);
        // Advance past the class regardless of the match outcome (a mismatch still
        // advances so the backtrack reset starts from the correct position).
        pi = classPi;
      }
      else
      {
        // Literal character.
        matched = (text[ti] == pattern[pi]);
        if (matched)
          ++pi;
      }

      if (matched)
      {
        ++ti;
        continue;
      }
    }

    // Mismatch - backtrack to last '%' if available.
    if (starPi != std::string_view::npos)
    {
      pi = starPi;
      ++starTi;
      ti = starTi;
      continue;
    }

    return false;
  }

  // Text exhausted - skip trailing '%' in pattern.
  while (pi < pattern.size() && pattern[pi] == '%')
    ++pi;

  return pi == pattern.size();
}

// --- Cast operator (OPC UA Part 4, Table 125) ---

namespace
{

/// Extract a numeric value as int64_t from a Variant. Returns nullopt if not numeric.
std::optional<int64_t> to_int64(const Variant& v)
{
  if (v.is_boolean())
    return v.as<bool>() ? 1 : 0;
  if (v.is_int8())
    return v.as<int8_t>();
  if (v.is_uint8())
    return v.as<uint8_t>();
  if (v.is_int16())
    return v.as<int16_t>();
  if (v.is_uint16())
    return v.as<uint16_t>();
  if (v.is_int32())
    return v.as<int32_t>();
  if (v.is_uint32())
    return v.as<uint32_t>();
  if (v.is_int64())
    return v.as<int64_t>();
  if (v.is_uint64())
  {
    auto val = v.as<uint64_t>();
    if (val > numeric_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
      return std::nullopt;
    return numeric_cast<int64_t>(val);
  }
  return std::nullopt;
}

/// Round a double using OPC UA spec rule: "add 0.5 and truncate."
/// Example: 3.7 -> 3.7+0.5=4.2 -> trunc -> 4. -3.7 -> -3.7+0.5=-3.2 -> trunc -> -3.
double ua_round_to_int(double val)
{
  return std::trunc(val + 0.5);
}

/// Cast a numeric source (int64 or double) to a target integer type with range check.
/// Returns empty Variant on out-of-range or negative-to-unsigned.
template<typename T>
Variant cast_to_integer(const Variant& source)
{
  // Try integer extraction first.
  auto asInt = to_int64(source);
  if (asInt)
  {
    const int64_t v = *asInt;
    if constexpr (std::is_unsigned_v<T>)
    {
      if (v < 0)
        return Variant{};
    }
    // For uint64_t, any non-negative int64 fits. For other types, range-check normally.
    if constexpr (std::is_same_v<T, uint64_t>)
    {
      return Variant{numeric_cast<uint64_t>(v)};
    }
    else
    {
      if (v < numeric_cast<int64_t>(std::numeric_limits<T>::min()) ||
          v > numeric_cast<int64_t>(std::numeric_limits<T>::max()))
        return Variant{};
      return Variant{static_cast<T>(v)};
    }
  }

  // Float/double source - apply OPC UA rounding.
  if (source.is_float() || source.is_double())
  {
    const double d = source.is_float() ? static_cast<double>(source.as<float>()) : source.as<double>();
    if (std::isnan(d) || std::isinf(d))
      return Variant{};
    const double rounded = ua_round_to_int(d);
    if constexpr (std::is_unsigned_v<T>)
    {
      if (rounded < 0.0)
        return Variant{};
    }
    if (rounded < static_cast<double>(std::numeric_limits<T>::min()) ||
        rounded > static_cast<double>(std::numeric_limits<T>::max()))
      return Variant{};
    return Variant{static_cast<T>(rounded)};
  }

  return Variant{};
}

/// Parse a string as a numeric type. Returns empty Variant on failure.
template<typename T>
Variant parse_string_to_numeric(std::string_view str)
{
  if constexpr (std::is_floating_point_v<T>)
  {
    // Use from_chars for floats where available, otherwise stod/stof.
    T result{};
    auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), result);
    if (ec != std::errc{} || ptr != str.data() + str.size())
      return Variant{};
    return Variant{result};
  }
  else
  {
    // Integer parse.
    // First try parsing as integer directly.
    T result{};
    auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), result);
    if (ec != std::errc{} || ptr != str.data() + str.size())
      return Variant{};
    return Variant{result};
  }
}

/// Check if the source Variant is a numeric or boolean type.
/// String sources are handled separately (parsed via from_chars) before this check.
bool is_numeric_or_boolean(const Variant& source)
{
  return source.is_boolean() || source.is_int8() || source.is_uint8() || source.is_int16() ||
         source.is_uint16() || source.is_int32() || source.is_uint32() || source.is_int64() ||
         source.is_uint64() || source.is_float() || source.is_double();
}

/// Convert source to boolean per Table 125.
Variant cast_to_boolean(const Variant& source)
{
  // Numeric -> bool: non-zero = true, zero = false.
  auto asInt = to_int64(source);
  if (asInt)
    return Variant{*asInt != 0};
  if (source.is_float())
    return Variant{source.as<float>() != 0.0f};
  if (source.is_double())
    return Variant{source.as<double>() != 0.0};

  // String -> bool: "true"/"1" -> true, "false"/"0" -> false (case-insensitive).
  if (source.is_string())
  {
    auto sv = static_cast<std::string_view>(source.as<String>());
    // Case-insensitive comparison.
    auto iequal = [](std::string_view a, std::string_view b)
    {
      if (a.size() != b.size())
        return false;
      for (size_t i = 0; i < a.size(); ++i)
      {
        if (std::tolower(numeric_cast<unsigned char>(a[i])) !=
            std::tolower(numeric_cast<unsigned char>(b[i])))
          return false;
      }
      return true;
    };
    if (iequal(sv, "true") || sv == "1")
      return Variant{true};
    if (iequal(sv, "false") || sv == "0")
      return Variant{false};
    return Variant{};  // Invalid string.
  }

  return Variant{};
}

/// Convert source to String per Table 125.
Variant cast_to_string(const Variant& source)
{
  // Boolean -> "1" or "0".
  if (source.is_boolean())
    return Variant{String{source.as<bool>() ? "1" : "0"}};

  // uint64 must be handled before to_int64 (which rejects values > INT64_MAX).
  if (source.is_uint64())
    return Variant{String{std::to_string(source.as<uint64_t>())}};

  // Other integer types -> string (booleans already returned above, so to_int64's bool case
  // is unreachable here).
  auto asInt = to_int64(source);
  if (asInt)
    return Variant{String{std::to_string(*asInt)}};

  if (source.is_float())
    return Variant{String{fmt::format("{}", source.as<float>())}};
  if (source.is_double())
    return Variant{String{fmt::format("{}", source.as<double>())}};

  if (source.is_date_time())
    return Variant{String{source.as<DateTime>().as_iso_string()}};

  if (source.is_node_id())
    return Variant{String{source.as<NodeId>().as_definition()}};

  if (source.is_expanded_node_id())
    return Variant{String{source.as<ExpandedNodeId>().as_definition()}};

  if (source.is_guid())
    return Variant{String{source.as<Guid>().as_string()}};

  if (source.is_localized_text())
    return Variant{String{source.as<LocalizedText>().text()}};

  if (source.is_qualified_name())
    return Variant{String{source.as<QualifiedName>().name()}};

  return Variant{};
}

}  // namespace

Variant CompiledEventFilter::cast_variant(const Variant& source, BuiltInTypeId target)
{
  if (source.empty())
    return Variant{};

  // Identity cast - return the original value if types match.
  if (source.get_built_in_type() == target)
    return Variant{source};

  switch (target)
  {
  case BuiltInTypeId::Boolean:
    return cast_to_boolean(source);

  case BuiltInTypeId::SByte:
  {
    if (source.is_string())
      return parse_string_to_numeric<int8_t>(static_cast<std::string_view>(source.as<String>()));
    if (is_numeric_or_boolean(source))
      return cast_to_integer<int8_t>(source);
    return Variant{};
  }

  case BuiltInTypeId::Byte:
  {
    if (source.is_string())
      return parse_string_to_numeric<uint8_t>(static_cast<std::string_view>(source.as<String>()));
    if (is_numeric_or_boolean(source))
      return cast_to_integer<uint8_t>(source);
    return Variant{};
  }

  case BuiltInTypeId::Int16:
  {
    if (source.is_string())
      return parse_string_to_numeric<int16_t>(static_cast<std::string_view>(source.as<String>()));
    if (source.is_status_code())
      return Variant{numeric_cast<int16_t>(source.as<StatusCode>().as_uint32() >> 16)};
    if (is_numeric_or_boolean(source))
      return cast_to_integer<int16_t>(source);
    return Variant{};
  }

  case BuiltInTypeId::UInt16:
  {
    if (source.is_string())
      return parse_string_to_numeric<uint16_t>(static_cast<std::string_view>(source.as<String>()));
    if (source.is_status_code())
      return Variant{numeric_cast<uint16_t>(source.as<StatusCode>().as_uint32() >> 16)};
    if (is_numeric_or_boolean(source))
      return cast_to_integer<uint16_t>(source);
    return Variant{};
  }

  case BuiltInTypeId::Int32:
  {
    if (source.is_string())
      return parse_string_to_numeric<int32_t>(static_cast<std::string_view>(source.as<String>()));
    if (source.is_status_code())
      return Variant{numeric_cast<int32_t>(source.as<StatusCode>().as_uint32())};
    if (is_numeric_or_boolean(source))
      return cast_to_integer<int32_t>(source);
    return Variant{};
  }

  case BuiltInTypeId::UInt32:
  {
    if (source.is_string())
      return parse_string_to_numeric<uint32_t>(static_cast<std::string_view>(source.as<String>()));
    if (source.is_status_code())
      return Variant{source.as<StatusCode>().as_uint32()};
    if (is_numeric_or_boolean(source))
      return cast_to_integer<uint32_t>(source);
    return Variant{};
  }

  case BuiltInTypeId::Int64:
  {
    if (source.is_string())
      return parse_string_to_numeric<int64_t>(static_cast<std::string_view>(source.as<String>()));
    if (source.is_status_code())
      return Variant{numeric_cast<int64_t>(source.as<StatusCode>().as_uint32())};
    if (is_numeric_or_boolean(source))
      return cast_to_integer<int64_t>(source);
    return Variant{};
  }

  case BuiltInTypeId::UInt64:
  {
    if (source.is_string())
      return parse_string_to_numeric<uint64_t>(static_cast<std::string_view>(source.as<String>()));
    if (source.is_status_code())
      return Variant{numeric_cast<uint64_t>(source.as<StatusCode>().as_uint32())};
    if (is_numeric_or_boolean(source))
      return cast_to_integer<uint64_t>(source);
    return Variant{};
  }

  case BuiltInTypeId::Float:
  {
    if (source.is_string())
      return parse_string_to_numeric<float>(static_cast<std::string_view>(source.as<String>()));
    if (source.is_double())
      return Variant{static_cast<float>(source.as<double>())};
    // All integer/bool types -> float via int64.
    auto asInt = to_int64(source);
    if (asInt)
      return Variant{static_cast<float>(*asInt)};
    return Variant{};
  }

  case BuiltInTypeId::Double:
  {
    if (source.is_string())
      return parse_string_to_numeric<double>(static_cast<std::string_view>(source.as<String>()));
    if (source.is_float())
      return Variant{static_cast<double>(source.as<float>())};
    auto asInt = to_int64(source);
    if (asInt)
      return Variant{static_cast<double>(*asInt)};
    // uint64 may overflow int64 but still fits in double.
    if (source.is_uint64())
      return Variant{static_cast<double>(source.as<uint64_t>())};
    return Variant{};
  }

  case BuiltInTypeId::String:
    return cast_to_string(source);

  case BuiltInTypeId::DateTime:
  {
    if (source.is_string())
    {
      auto dt = DateTime::parse(static_cast<std::string_view>(source.as<String>()));
      return Variant{dt};
    }
    return Variant{};
  }

  case BuiltInTypeId::Guid:
  {
    if (source.is_string())
    {
      const Guid g = Guid::parse(static_cast<std::string_view>(source.as<String>()));
      return Variant{g};
    }
    if (source.is_byte_string())
    {
      const auto& bs = source.as<ByteString>();
      if (bs.size() != Guid::length)
        return Variant{};
      Guid g;
      g.from_ua_binary(static_cast<span<const byte>>(bs));
      return Variant{g};
    }
    return Variant{};
  }

  case BuiltInTypeId::ByteString:
  {
    if (source.is_guid())
    {
      auto bytes = source.as<Guid>().as_ua_binary();
      return Variant{ByteString{span<const byte>{bytes.data(), bytes.size()}}};
    }
    return Variant{};
  }

  case BuiltInTypeId::NodeId:
  {
    if (source.is_string())
    {
      NodeId nid = NodeId::parse(static_cast<std::string_view>(source.as<String>()));
      return Variant{std::move(nid)};
    }
    if (source.is_expanded_node_id())
    {
      // ExpandedNodeId -> NodeId: only if no server index and no namespace URI.
      const auto& eni = source.as<ExpandedNodeId>();
      return Variant{NodeId{eni.node_id()}};
    }
    return Variant{};
  }

  case BuiltInTypeId::ExpandedNodeId:
  {
    if (source.is_string())
    {
      ExpandedNodeId eni = ExpandedNodeId::parse(static_cast<std::string_view>(source.as<String>()));
      return Variant{std::move(eni)};
    }
    if (source.is_node_id())
    {
      return Variant{ExpandedNodeId{source.as<NodeId>()}};
    }
    return Variant{};
  }

  case BuiltInTypeId::StatusCode:
  {
    if (source.is_uint32())
      return Variant{StatusCode{source.as<uint32_t>()}};
    if (source.is_int32())
      return Variant{StatusCode{numeric_cast<uint32_t>(source.as<int32_t>())}};
    if (source.is_uint16())
      return Variant{StatusCode{numeric_cast<uint32_t>(source.as<uint16_t>()) << 16}};
    if (source.is_int16())
      return Variant{StatusCode{numeric_cast<uint32_t>(numeric_cast<uint16_t>(source.as<int16_t>())) << 16}};
    return Variant{};
  }

  case BuiltInTypeId::LocalizedText:
  {
    if (source.is_string())
      return Variant{LocalizedText{String{source.as<String>()}}};
    if (source.is_qualified_name())
      return Variant{LocalizedText{String{source.as<QualifiedName>().name()}}};
    return Variant{};
  }

  case BuiltInTypeId::QualifiedName:
  {
    if (source.is_string())
      return Variant{QualifiedName{static_cast<std::string_view>(source.as<String>())}};
    return Variant{};
  }

  default:
    return Variant{};
  }
}

}  // namespace ua::server
