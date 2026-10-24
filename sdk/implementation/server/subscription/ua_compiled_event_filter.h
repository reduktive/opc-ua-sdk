// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_COMPILED_EVENT_FILTER_H
#define UA_COMPILED_EVENT_FILTER_H

#include "ua_access_control.h"
#include "ua_base_event.h"
#include "ua_content_filter_result.h"
#include "ua_event_field_list.h"
#include "ua_event_filter.h"
#include "ua_event_filter_result.h"
#include "ua_event_type_model.h"
#include "ua_node_id.h"
#include "ua_node_accessor.h"
#include "ua_qualified_name.h"
#include "ua_status_code.h"
#include "ua_built_in_type_id.h"
#include "ua_variant.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <variant>
#include <vector>

namespace ua::server
{

namespace event_type_model
{
struct Declaration;
}

/// A pre-resolved select clause from an EventFilter.
/// Created at compile time, used at runtime for field projection.
struct ResolvedSelectClause
{
  std::vector<QualifiedName> browsePath;
  uint32_t attributeId{0};  // AttributeId::Value by default
  NodeId typeDefinitionId;  // Restricts the operand to instances of this type or a subtype (Part 4 7.7.4.5)
  StatusCode validationStatus;
  std::optional<NodeAccessor> declarationAccessor;
};

/// A compiled operand within a where clause element.
using CompiledOperand = std::variant<uint32_t,  // ElementOperand - index into the elements vector
  ResolvedSelectClause,  // SimpleAttributeOperand - pre-resolved field reference
  Variant  // LiteralOperand - literal value
  >;

/// A compiled where clause element.
struct CompiledFilterElement
{
  FilterOperator op{};
  std::vector<CompiledOperand> operands;
};

/// Outcome of compiling an EventFilter.
struct CompiledEventFilterResult
{
  std::unique_ptr<class CompiledEventFilter> filter;
  EventFilterResult filterResult;  // Per-clause status codes for the client
  StatusCode overallStatus;  // Good or Bad_MonitoredItemFilterInvalid
};

/// Optional limits for EventFilter compilation (SVR-EVT-CAP-001/002).
struct EventFilterCompileLimits
{
  uint32_t maxSelectClauses{0};  // 0 = unlimited
  uint32_t maxWhereClauseElements{0};  // 0 = unlimited
  uint32_t maxWhereClauseOperandBytes{0};  // total string-literal operand bytes; 0 = unlimited
};

/// An EventFilter that has been validated and compiled for efficient runtime evaluation.
///
/// Created at CreateMonitoredItems time. Logically immutable after construction.
/// Pure logic: it has no async operations, strand state, I/O or mutable authorization cache.
class CompiledEventFilter
{
public:
  /// One node/operation pair that must cross the Event head's asynchronous authorization barrier.
  struct AuthorizationSubject
  {
    NodeId nodeId;
    AccessOperation operation{AccessOperation::Browse};
  };

  /// Compile and validate an EventFilter.
  /// Returns the compiled filter plus per-clause validation results.
  /// The address space is not needed for basic compilation - type hierarchy
  /// checks (OfType) are deferred to runtime evaluation.
  static CompiledEventFilterResult compile(const EventFilter& filter, EventFilterCompileLimits limits = {},
    std::span<const StatusCode> selectClauseModelStatuses = {},
    std::span<const std::optional<NodeAccessor>> selectClauseDeclarations = {});

  /// Evaluate the where clause against an event.
  /// Returns true if the event passes the filter (should be delivered).
  /// An empty where clause passes all events, and the three refresh event types (RefreshStart,
  /// RefreshEnd, RefreshRequired) ignore the where clause (OPC 10000-9 section 4.5).
  bool evaluate(const BaseEvent& event) const;

  /// Project select clause fields from an event into an EventFieldList.
  EventFieldList project(const BaseEvent& event, uint32_t clientHandle) const;
  EventFieldList project(
    const BaseEvent& event, uint32_t clientHandle, uint32_t maxResponseMessageSize) const;

  /// True for EventId, EventType and ReceiveTime: fields every receiver of an Event may read, which
  /// field authorization never withholds. HistoryRead applies the same rule to archived Events.
  static bool is_inviolate_field(const ResolvedSelectClause& clause) noexcept;

  /// Returns every non-inviolate select and where subject required by this concrete Event.
  ///
  /// The returned pairs are stable, deduplicated in clause-discovery order and contain no node
  /// handles. The Subscription resolves them together with SourceNode and EventTypeId before one
  /// asynchronous authorization batch. A good concrete model that proves a type-dependent selected
  /// field absent contributes no subject.
  std::vector<AuthorizationSubject> authorization_subjects(const BaseEvent& event,
    const std::shared_ptr<const event_type_model::DeclarationsResult>& declarationModel) const;

  /// Evaluate the where clause from a completed Event-head authorization view.
  ///
  /// As @ref evaluate, the three refresh event types ignore the where clause.
  /// A denied, failed or unassociated SimpleAttributeOperand resolves to null before its operator is
  /// evaluated. This function performs no access-control call, I/O or scheduling.
  bool evaluate_authorized(const BaseEvent& event,
    const std::shared_ptr<const event_type_model::DeclarationsResult>& declarationModel,
    std::span<const AccessControl::Verdict> verdicts) const;

  /// Project selected fields from the completed Event-head authorization view.
  ///
  /// The resolved items retain NodeAccessor handles needed by identity-derived Attribute projection;
  /// verdict association is by NodeId and AccessOperation, not vector position. This function performs
  /// no access-control acquisition, I/O or scheduling.
  EventFieldList project_authorized(const BaseEvent& event, uint32_t clientHandle,
    const std::shared_ptr<const event_type_model::DeclarationsResult>& declarationModel,
    const SessionAccessControl& accessControl, std::span<const AccessControl::Item> resolvedItems,
    std::span<const AccessControl::Verdict> verdicts, uint32_t maxResponseMessageSize = 0) const;

  /// Clone the immutable filter for a retransmission sidecar without retaining NodeAccessor handles.
  /// Republish resolves every stable NodeId afresh from its retained declaration model.
  std::shared_ptr<const CompiledEventFilter> retained_copy() const;

  const std::vector<ResolvedSelectClause>& select_clauses() const
  {
    return mSelectClauses;
  }

private:
  friend struct CompiledEventFilterResult;
  friend struct CompiledEventFilterTestAccess;

  static void enforce_encoding_limit(EventFieldList& fieldList, uint32_t maxResponseMessageSize);

  std::vector<ResolvedSelectClause> mSelectClauses;
  std::vector<CompiledFilterElement> mWhereElements;

  /// Each where-clause element's result for one event, computed once: an element that two ElementOperands
  /// reference answers both with the same value. `inProgress` guards the recursion path; compile already
  /// refuses cycles, so it only fires on a filter that bypassed compile.
  struct ElementResults
  {
    explicit ElementResults(std::size_t count) : results(count), inProgress(count, false)
    {}

    std::vector<std::optional<Variant>> results;
    std::vector<bool> inProgress;
  };

  /// Evaluate a single where clause element.
  /// Returns the result as a Variant (typically bool or null).
  Variant evaluate_element(const BaseEvent& event, uint32_t elementIndex, ElementResults& memo) const;

  Variant evaluate_element_authorized(const BaseEvent& event, uint32_t elementIndex, ElementResults& memo,
    const std::shared_ptr<const event_type_model::DeclarationsResult>& declarationModel,
    std::span<const AccessControl::Verdict> verdicts) const;

  /// Resolve an operand value for where clause evaluation.
  Variant resolve_operand(const BaseEvent& event, const CompiledOperand& operand, uint32_t currentElement,
    ElementResults& memo) const;

  Variant resolve_operand_authorized(const BaseEvent& event, const CompiledOperand& operand,
    uint32_t currentElement, ElementResults& memo,
    const std::shared_ptr<const event_type_model::DeclarationsResult>& declarationModel,
    std::span<const AccessControl::Verdict> verdicts) const;

  /// Resolve a single SimpleAttributeOperand field value from an event. Applies the
  /// empty-browse-path + NodeId-attribute -> ConditionId rule (Part 4 7.7.4.5) so both
  /// select-clause projection and where-clause evaluation treat the ConditionId operand
  /// identically. Returns null for clauses that failed validation or whose typeDefinitionId
  /// does not apply to the event (see operand_applies_to_event).
  static Variant resolve_select_field(const BaseEvent& event, const ResolvedSelectClause& clause);

  static std::optional<NodeId> authorization_subject(const BaseEvent& event,
    const ResolvedSelectClause& clause,
    const std::shared_ptr<const event_type_model::DeclarationsResult>& declarationModel);
  static const AccessControl::Verdict* associated_verdict(
    const AuthorizationSubject& subject, std::span<const AccessControl::Verdict> verdicts) noexcept;
  static const AccessControl::Item* associated_item(
    const AuthorizationSubject& subject, std::span<const AccessControl::Item> items) noexcept;

  /// Part 4 7.7.4.5 Table 133: a SimpleAttributeOperand applies only to instances of its
  /// typeDefinitionId or a subtype. A null typeDefinitionId or BaseEventType means "ignore the
  /// typeDefinitionId" (the latter is Table 133's explicit carve-out) and always applies. Otherwise
  /// the answer is "typeDefinitionId is in the event's supertype chain" - which the EventBus resolves
  /// and attaches before any filter sees the event. If the chain is absent (a hand-built event
  /// evaluated off the EventBus) the restriction cannot be evaluated, so the operand applies rather
  /// than fabricate a false non-match that would drop a requested field.
  static bool operand_applies_to_event(const BaseEvent& event, const NodeId& typeDefinitionId);

  /// Apply a filter operator to its resolved operand values.
  static Variant apply_operator(FilterOperator op, std::span<const Variant> operands, const BaseEvent& event);

  /// Compare two Variant values. Returns <0, 0, or >0.
  /// Returns nullopt if the types are incomparable.
  static std::optional<int> compare_variants(const Variant& lhs, const Variant& rhs);

  /// Extract a double from a numeric Variant. Returns nullopt if not numeric.
  static std::optional<double> to_double(const Variant& variant);

  /// Check if an event type is equal to or a subtype of the given type.
  /// For now uses a simple check against the event's event_type field.
  static bool is_of_type(const BaseEvent& event, const NodeId& typeId);

  /// OPC UA Like pattern matching (Table 124). Case sensitive.
  /// Supports: % (any string), _ (single char), \ (escape), [set], [^set], [range].
  static bool match_like(std::string_view text, std::string_view pattern);

  /// Cast a Variant to a target built-in type per Table 125.
  /// Returns empty Variant on any error or impossible conversion.
  static Variant cast_variant(const Variant& source, BuiltInTypeId target);
};

}  // namespace ua::server

#endif  // !UA_COMPILED_EVENT_FILTER_H
