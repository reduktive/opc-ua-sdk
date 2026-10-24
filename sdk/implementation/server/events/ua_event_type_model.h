// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_EVENT_TYPE_MODEL_H
#define UA_EVENT_TYPE_MODEL_H

#include "ua_address_space.h"
#include "ua_event_filter.h"
#include "ua_node_class.h"
#include "ua_node_accessor.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_request_info.h"
#include "ua_result.h"

#include <functional>
#include <optional>
#include <vector>

namespace ua::server::event_type_model
{

/// One InstanceDeclaration exposed by an EventType, including its complete path from that type.
struct Declaration
{
  std::vector<QualifiedName> browsePath;
  NodeId nodeId;
  std::optional<NodeAccessor> accessor;
  NodeClass nodeClass{NodeClass::Unspecified};
  bool mandatory{false};
  NodeId dataType;
};

using Declarations = std::vector<Declaration>;
using DeclarationsResult = Result<Declarations>;
using CollectCallback = std::function<void(DeclarationsResult)>;

struct SelectClauseModel
{
  StatusCode status;
  std::optional<NodeAccessor> declarationAccessor;
};

using SelectClauseModels = std::vector<SelectClauseModel>;
using SelectClauseModelsResult = Result<SelectClauseModels>;
using ResolveSelectClauseModelsCallback = std::function<void(SelectClauseModelsResult)>;

using SelectClauseStatuses = std::vector<StatusCode>;
using SelectClauseStatusesResult = Result<SelectClauseStatuses>;
using ValidateSelectClausesCallback = std::function<void(SelectClauseStatusesResult)>;

/// Collect every InstanceDeclaration of @p eventType, including inherited and nested declarations.
///
/// The walk is callback-canonical and follows forward Aggregate references (including application-
/// defined subtypes) from the named ObjectType and each of its supertypes through BaseEventType.
/// Every failure remains attached to the returned StatusCode as ErrorDetail. The walk of the batched
/// resolution below, for this one type and the server's own `RequestInfo`. The callback is invoked
/// exactly once, after this call returns; inline only when the walk could not be started.
void collect_declarations_async(
  AddressSpace addressSpace, NodeId eventType, CollectCallback onComplete) noexcept;

/// Resolve every SimpleAttributeOperand BrowsePath against the live EventType model.
///
/// Each Good entry retains the final InstanceDeclaration accessor when the path is known for the
/// declared type. A Good entry with no accessor is type-dependent and is resolved from the concrete
/// emitted EventType metadata at delivery. One filter of the batched form below, for the server's
/// own `RequestInfo`.
void resolve_select_clause_models_async(
  AddressSpace addressSpace, EventFilter filter, ResolveSelectClauseModelsCallback onComplete) noexcept;

/// The select-clause models of each of @p filters, for the request @p request serves (NR-28 rule 3).
///
/// Every distinct typeDefinitionId the filters name is collected once, the types walked together: their
/// supertypes a level per round, then their InstanceDeclarations a depth per round, each round one batched
/// lookup and one References read per namespace (types: Both directions, hinted {HasSubtype, Aggregates};
/// declarations: Forward, hinted {Aggregates, HasModellingRule}; resume tokens followed under
/// `ua::detail::maxEmptyReferencePages`). An application ReferenceType is classified against Aggregates once
/// per request, when a walk first meets it. A Node is looked up and read once per request however many
/// types reach it, and each type's declarations are composed from those facts as @ref
/// collect_declarations_async composes them: the same order, BrowsePath deduplication, bounds and
/// ErrorDetail. A Node that fails to look up or read fails each type whose walk reaches it, and only those.
/// Each filter's clauses are then resolved as the single form resolves them; a clause with an empty
/// BrowsePath takes its type's accessor from that type's lookup. @p onComplete receives one answer per
/// filter, in order, once, after this call returns; inline only when the resolution could not be started.
void resolve_select_clause_models_async(AddressSpace addressSpace, RequestInfo request,
  std::vector<EventFilter> filters,
  std::function<void(std::vector<SelectClauseModelsResult>)> onComplete) noexcept;

/// Validate every SimpleAttributeOperand BrowsePath against the live EventType model.
///
/// The returned vector is parallel to EventFilter::select_clauses(). A Good entry means every
/// resolved InstanceDeclaration in that path is an Object or Variable; a bad entry is the exact
/// clause failure and carries its ErrorDetail on the StatusCode.
void validate_select_clauses_async(
  AddressSpace addressSpace, EventFilter filter, ValidateSelectClausesCallback onComplete) noexcept;

}  // namespace ua::server::event_type_model

#endif  // UA_EVENT_TYPE_MODEL_H
