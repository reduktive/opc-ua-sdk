// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_sync_wait.h"
#include "ua_state_machine_access.h"

#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_browse_description.h"
#include "ua_browse_direction.h"
#include "ua_browse_next_request.h"
#include "ua_browse_next_response.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_result_mask.h"
#include "ua_call_method_request.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_client_answer_status.h"
#include "ua_connection_ops.h"
#include "ua_content_filter.h"
#include "ua_content_filter_element.h"
#include "ua_continuation_point.h"
#include "ua_browse_drain_guard.h"
#include "ua_error_detail.h"
#include "ua_event_filter.h"
#include "ua_event_subscriber.h"
#include "ua_event_subscriber_impl.h"
#include "ua_filter_operator.h"
#include "ua_literal_operand.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_qualified_name.h"
#include "ua_browse_path.h"
#include "ua_localized_text.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_ref_structure.h"
#include "ua_reference_description.h"
#include "ua_referencetype_id.h"
#include "ua_relative_path.h"
#include "ua_relative_path_element.h"
#include "ua_simple_attribute_operand.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"
#include "ua_state_machine_access_state.h"
#include "ua_status.h"
#include "ua_structure.h"

#include <boost/asio/post.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include "ua_on_strand.h"

namespace ua::client
{

namespace
{

// Source tags for the manufactured boundary failures (the design specification, CL-DIAG-002/-015).
constexpr std::string_view connClosedSource = "client.tier2.state_machine.connection_closed";
constexpr std::string_view constructionSource = "client.tier2.state_machine.construction";
constexpr std::string_view currentStateSource = "client.tier2.state_machine.current_state";
constexpr std::string_view lastTransitionSource = "client.tier2.state_machine.last_transition";
constexpr std::string_view lastTransitionAbsentSource =
  "client.tier2.state_machine.last_transition_not_present";
constexpr std::string_view currentStateIsSource = "client.tier2.state_machine.current_state_is";
constexpr std::string_view topologySource = "client.tier2.state_machine.topology";
constexpr std::string_view methodResolutionSource = "client.tier2.state_machine.method_resolution";
constexpr std::string_view executableSource = "client.tier2.state_machine.executable";
constexpr std::string_view notExecutableSource = "client.tier2.state_machine.method_not_executable";
constexpr std::string_view stateMismatchSource = "client.tier2.state_machine.state_method_mismatch";
constexpr std::string_view methodCallSource = "client.tier2.state_machine.method_call";
constexpr std::string_view subscribeTransitionsSource = "client.tier2.state_machine.subscribe_transitions";

constexpr std::uint32_t valueAttribute = static_cast<std::uint32_t>(ua::AttributeId::Value);
constexpr std::uint32_t executableAttribute = static_cast<std::uint32_t>(ua::AttributeId::Executable);
constexpr std::uint32_t browseNameAttribute = static_cast<std::uint32_t>(ua::AttributeId::BrowseName);
constexpr std::uint32_t displayNameAttribute = static_cast<std::uint32_t>(ua::AttributeId::DisplayName);
constexpr std::size_t maximumStateTypeDepth = 64U;

/// Posts @p result to @p executor for a callback (callbacks always run on the executor); inline when no
/// executor is set (a moved-from handle's inert path).
template<typename Result>
void deliver(
  const boost::asio::any_io_executor& executor, std::function<void(Result)> callback, Result result)
{
  if (!executor)
  {
    callback(std::move(result));
    return;
  }
  boost::asio::post(executor,
    ua::async::guarded(ua::Logger{},
      [callback = std::move(callback), result = std::move(result)]() mutable
      { callback(std::move(result)); }));
}

// ---- one-level paged browse (mirrors the DataAccess paged-browse pattern) ----

/// The children accumulated from a one-level Browse (across all continuation pages).
using ReferenceList = std::vector<ua::ReferenceDescription>;

/// Builds a one-level forward Browse of @p nodeId along @p referenceType (subtypes included), requesting the
/// BrowseName result mask (the only field the SM child match needs).
ua::BrowseRequest make_reference_browse(
  const ua::NodeId& nodeId, ua::ReferenceTypeId referenceType, ua::BrowseDirection direction)
{
  ua::BrowseDescription browseDescription;
  browseDescription.node_id() = nodeId;
  browseDescription.browse_direction() = direction;
  browseDescription.reference_type_id() = ua::NodeId{std::uint16_t{0}, referenceType};
  browseDescription.include_subtypes() = true;
  browseDescription.result_mask() = static_cast<std::uint32_t>(ua::BrowseResultMask::BrowseName);
  ua::BrowseRequest browse;
  browse.nodes_to_browse().push_back(std::move(browseDescription));
  return browse;
}

/// Builds a continuing (non-release) BrowseNext for @p continuationPoint.
ua::BrowseNextRequest make_browse_next(const ua::ContinuationPoint& continuationPoint)
{
  ua::BrowseNextRequest request;
  request.release_continuation_points() = false;
  request.continuation_points().push_back(continuationPoint);
  return request;
}

/// Drains the remaining continuation pages via BrowseNext, appending into @p accumulated, until the server
/// returns an empty continuation point. @p interface is held strong across the page walk.
void drain_children(std::shared_ptr<ua::client::detail::WireOps> lockedWireOps,
  std::shared_ptr<ReferenceList> accumulated, ua::ContinuationPoint continuationPoint, std::string source,
  std::function<void(ua::Result<ReferenceList>)> done,
  std::shared_ptr<ua::client::detail::BrowseDrainGuard> guard = {})
{
  if (!guard)
  {
    guard = std::make_shared<ua::client::detail::BrowseDrainGuard>(
      source, ua::client::detail::BrowseDrainLimits{}, accumulated->size());
  }
  auto* lockedWireOpsRaw = lockedWireOps.get();
  lockedWireOpsRaw->browse_next_async(make_browse_next(continuationPoint),
    [lockedWireOps = std::move(lockedWireOps),
      accumulated = std::move(accumulated),
      source = std::move(source),
      done = std::move(done),
      guard](ua::Result<ua::BrowseNextResponse> response) mutable
    {
      // The SDK resolves the machine from these References itself, so only a Good answer is used: an
      // Uncertain one (to the service, its ServiceResult or the page) is refused (ReferencesAnswerUncertain).
      if (response.is_uncertain())
      {
        done(ua::Result<ReferenceList>{ua::client::detail::uncertain_answer_refused(
          response.status_code(), "ReferencesAnswerUncertain", source)});
        return;
      }
      if (!response.has_value())
      {
        done(ua::Result<ReferenceList>{response.status_code(),
          ua::make_error_detail("StateMachineBrowseNextFailed",
            "a BrowseNext continuing a state-machine child Browse failed",
            source,
            response.shared_detail())});
        return;
      }
      // Facade flatten: the wire funnel returns the BrowseNextResponse verbatim; a bad
      // ResponseHeader.serviceResult is a service-level failure the facade surfaces as bad, preserving the
      // exact service status + ErrorDetail. Without this an empty results[] masks the fault as
      // Bad_UnexpectedError (empty-results branch below).
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        done(ua::Result<ReferenceList>{serviceResult,
          ua::make_error_detail("StateMachineBrowseNextServiceFault",
            "a BrowseNext continuing a state-machine child Browse returned a service-level fault",
            source,
            serviceResult)});
        return;
      }
      if (serviceResult.is_uncertain())
      {
        done(ua::Result<ReferenceList>{
          ua::client::detail::uncertain_answer_refused(serviceResult, "ReferencesAnswerUncertain", source)});
        return;
      }
      const auto& results = response.value().results();
      if (results.empty())
      {
        done(ua::Result<ReferenceList>{ua::Status::BadUnexpectedError,
          ua::make_error_detail("StateMachineBrowseNextEmpty",
            "the server returned a Good BrowseNext response with no result",
            source)});
        return;
      }
      const ua::BrowseResult& browseResult = results[0];
      if (browseResult.status_code().is_bad())
      {
        done(ua::Result<ReferenceList>{browseResult.status_code(),
          ua::make_error_detail("StateMachineBrowseNextBad",
            "a BrowseNext continuing a state-machine child Browse returned a Bad per-node status",
            source)});
        return;
      }
      if (browseResult.status_code().is_uncertain())
      {
        done(ua::Result<ReferenceList>{ua::client::detail::uncertain_answer_refused(
          browseResult.status_code(), "ReferencesAnswerUncertain", source)});
        return;
      }
      // CL-VIEW-005: the page is admitted before its references are kept; a self-loop or an exhausted
      // budget ends the drain (a budget refusal releases the server's continuation point best-effort).
      if (auto admitted = guard->admit_page(browseResult); admitted.is_bad())
      {
        ua::client::detail::release_continuation_point_best_effort(
          *lockedWireOps, browseResult.continuation_point());
        done(ua::Result<ReferenceList>{admitted.status_code(), admitted.shared_detail()});
        return;
      }
      for (const auto& reference : browseResult.references())
      {
        accumulated->push_back(reference);
      }
      if (!browseResult.continuation_point().empty())
      {
        drain_children(std::move(lockedWireOps),
          std::move(accumulated),
          browseResult.continuation_point(),
          std::move(source),
          std::move(done),
          guard);
        return;
      }
      done(ua::Result<ReferenceList>{std::move(*accumulated)});
    });
}

/// Browses @p nodeId one level along @p referenceType and accumulates EVERY child reference across all
/// continuation pages. Delivers the full reference list (or a Bad Result chaining the wire detail under
/// @p source). @p interface is held strong for the whole page walk.
void browse_references(std::shared_ptr<ua::client::detail::WireOps> lockedWireOps, ua::NodeId nodeId,
  ua::ReferenceTypeId referenceType, ua::BrowseDirection direction, std::string source,
  std::function<void(ua::Result<ReferenceList>)> done)
{
  auto* lockedWireOpsRaw = lockedWireOps.get();
  lockedWireOpsRaw->browse_async(make_reference_browse(nodeId, referenceType, direction),
    [lockedWireOps = std::move(lockedWireOps), source = std::move(source), done = std::move(done)](
      ua::Result<ua::BrowseResponse> response) mutable
    {
      // The SDK resolves the machine from these References itself, so only a Good answer is used: an
      // Uncertain one (to the service, its ServiceResult or the page) is refused (ReferencesAnswerUncertain).
      if (response.is_uncertain())
      {
        done(ua::Result<ReferenceList>{ua::client::detail::uncertain_answer_refused(
          response.status_code(), "ReferencesAnswerUncertain", source)});
        return;
      }
      if (!response.has_value())
      {
        done(ua::Result<ReferenceList>{response.status_code(),
          ua::make_error_detail("StateMachineBrowseFailed",
            "a state-machine child Browse failed",
            source,
            response.shared_detail())});
        return;
      }
      // Facade flatten: the wire funnel returns the BrowseResponse verbatim; a bad
      // ResponseHeader.serviceResult is a service-level failure the facade surfaces as bad, preserving the
      // exact service status + ErrorDetail. Without this an empty results[] masks the fault as
      // Bad_UnexpectedError (empty-results branch below).
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        done(ua::Result<ReferenceList>{serviceResult,
          ua::make_error_detail("StateMachineBrowseServiceFault",
            "a state-machine child Browse returned a service-level fault",
            source,
            serviceResult)});
        return;
      }
      if (serviceResult.is_uncertain())
      {
        done(ua::Result<ReferenceList>{
          ua::client::detail::uncertain_answer_refused(serviceResult, "ReferencesAnswerUncertain", source)});
        return;
      }
      const auto& results = response.value().results();
      if (results.empty())
      {
        done(ua::Result<ReferenceList>{ua::Status::BadUnexpectedError,
          ua::make_error_detail(
            "StateMachineBrowseEmpty", "the server returned a Good Browse response with no result", source)});
        return;
      }
      const ua::BrowseResult& browseResult = results[0];
      if (browseResult.status_code().is_bad())
      {
        done(ua::Result<ReferenceList>{browseResult.status_code(),
          ua::make_error_detail(
            "StateMachineBrowseBad", "a state-machine child Browse returned a Bad per-node status", source)});
        return;
      }
      if (browseResult.status_code().is_uncertain())
      {
        done(ua::Result<ReferenceList>{ua::client::detail::uncertain_answer_refused(
          browseResult.status_code(), "ReferencesAnswerUncertain", source)});
        return;
      }
      auto accumulated = std::make_shared<ReferenceList>();
      for (const auto& reference : browseResult.references())
      {
        accumulated->push_back(reference);
      }
      if (!browseResult.continuation_point().empty())
      {
        drain_children(std::move(lockedWireOps),
          std::move(accumulated),
          browseResult.continuation_point(),
          std::move(source),
          std::move(done));
        return;
      }
      done(ua::Result<ReferenceList>{std::move(*accumulated)});
    });
}

void browse_children(std::shared_ptr<ua::client::detail::WireOps> lockedWireOps, ua::NodeId nodeId,
  ua::ReferenceTypeId referenceType, std::string source, std::function<void(ua::Result<ReferenceList>)> done)
{
  browse_references(std::move(lockedWireOps),
    std::move(nodeId),
    referenceType,
    ua::BrowseDirection::Forward,
    std::move(source),
    std::move(done));
}

/// @return The (local) NodeId of the ns0 @p ns0Name child in @p references, or `nullopt` when absent.
std::optional<ua::NodeId> find_child(const ReferenceList& references, std::string_view ns0Name)
{
  for (const auto& reference : references)
  {
    const ua::QualifiedName& browseName = reference.browse_name();
    if (browseName.namespace_index() != 0)
    {
      continue;
    }
    if (static_cast<std::string_view>(browseName.name()) == ns0Name)
    {
      return reference.node_id().node_id();  // ExpandedNodeId -> local NodeId
    }
  }
  return std::nullopt;
}

/// @return The local NodeId of the child whose BrowseName exactly equals @p browseName.
std::optional<ua::NodeId> find_child(const ReferenceList& references, const ua::QualifiedName& browseName)
{
  for (const auto& reference : references)
  {
    if (reference.browse_name() == browseName)
    {
      return reference.node_id().node_id();
    }
  }
  return std::nullopt;
}

/// @return A single-node Read of @p nodeId's @p attribute Attribute.
ua::ReadValueId make_attribute_read_value(const ua::NodeId& nodeId, std::uint32_t attribute)
{
  ua::ReadValueId readValue;
  readValue.node_id() = nodeId;
  readValue.attribute_id() = attribute;
  return readValue;
}

// ---- finite-state identity normalization (CL-SM-006) ----

using StateIdentityResult = ua::Result<ua::NodeId>;

/// Walks the owning finite-state-machine ObjectType's inverse HasSubtype chain. At each parent it looks for
/// the replicated State/Transition Object with the same BrowseName (Part 16 section 4.4.18). The last match
/// is the Object where the identity was first defined, which is the NodeId required by Part 16 sections
/// 4.4.6/4.4.7. Missing parent/matching-state References are a normal root/new-state stop, not an error.
void walk_state_identity_to_origin(std::shared_ptr<ua::client::detail::WireOps> lockedWireOps,
  ua::NodeId currentIdentity, ua::NodeId ownerType, ua::QualifiedName browseName,
  std::vector<ua::NodeId> visitedOwners, std::size_t depth, std::string source,
  std::function<void(StateIdentityResult)> done)
{
  if (depth >= maximumStateTypeDepth)
  {
    done(StateIdentityResult{ua::Status::BadUnexpectedError,
      ua::make_error_detail("StateMachineIdentityDepthExceeded",
        "the finite-state-machine type hierarchy exceeded the identity resolution depth limit",
        source)});
    return;
  }
  for (const auto& visited : visitedOwners)
  {
    if (visited == ownerType)
    {
      done(StateIdentityResult{ua::Status::BadUnexpectedError,
        ua::make_error_detail("StateMachineIdentityTypeCycle",
          "the finite-state-machine ObjectType hierarchy contains a HasSubtype cycle",
          source)});
      return;
    }
  }
  visitedOwners.push_back(ownerType);

  auto wireOpsForParentChildren = lockedWireOps;
  browse_references(std::move(lockedWireOps),
    ownerType,
    ua::ReferenceTypeId::HasSubtype,
    ua::BrowseDirection::Inverse,
    source,
    [wireOpsForParentChildren = std::move(wireOpsForParentChildren),
      currentIdentity = std::move(currentIdentity),
      browseName = std::move(browseName),
      visitedOwners = std::move(visitedOwners),
      depth,
      source = std::move(source),
      done = std::move(done)](ua::Result<ReferenceList> parents) mutable
    {
      if (!parents.is_good())
      {
        done(StateIdentityResult{parents.status_code(), parents.shared_detail()});
        return;
      }
      if (parents.value().empty())
      {
        done(StateIdentityResult{std::move(currentIdentity)});
        return;
      }

      const ua::NodeId parentType = parents.value().front().node_id().node_id();
      auto wireOpsForRecursion = wireOpsForParentChildren;
      browse_references(std::move(wireOpsForParentChildren),
        parentType,
        ua::ReferenceTypeId::HasComponent,
        ua::BrowseDirection::Forward,
        source,
        [wireOpsForRecursion = std::move(wireOpsForRecursion),
          currentIdentity = std::move(currentIdentity),
          parentType,
          browseName = std::move(browseName),
          visitedOwners = std::move(visitedOwners),
          depth,
          source = std::move(source),
          done = std::move(done)](ua::Result<ReferenceList> parentComponents) mutable
        {
          if (!parentComponents.is_good())
          {
            done(StateIdentityResult{parentComponents.status_code(), parentComponents.shared_detail()});
            return;
          }
          auto parentIdentity = find_child(parentComponents.value(), browseName);
          if (!parentIdentity)
          {
            done(StateIdentityResult{std::move(currentIdentity)});
            return;
          }
          walk_state_identity_to_origin(std::move(wireOpsForRecursion),
            std::move(*parentIdentity),
            parentType,
            std::move(browseName),
            std::move(visitedOwners),
            depth + 1U,
            std::move(source),
            std::move(done));
        });
    });
}

/// Resolves a State/Transition Object NodeId to the first definition in its finite-state-machine ObjectType
/// hierarchy. A Node with no inverse HasComponent owner is returned unchanged (it is not a replicated
/// State/Transition declaration).
void normalize_state_identity(std::shared_ptr<ua::client::detail::WireOps> lockedWireOps, ua::NodeId identity,
  std::string source, std::function<void(StateIdentityResult)> done)
{
  ua::ReadRequest read;
  read.nodes_to_read().push_back(make_attribute_read_value(identity, browseNameAttribute));
  auto wireOpsForOwner = lockedWireOps;
  lockedWireOps->read_async(std::move(read),
    [wireOpsForOwner = std::move(wireOpsForOwner),
      identity = std::move(identity),
      source = std::move(source),
      done = std::move(done)](ua::Result<ua::ReadResponse> response) mutable
    {
      // The SDK walks the type hierarchy from this BrowseName itself, so only a Good answer is used: an
      // Uncertain one (to the service, its ServiceResult or the value) is refused (ReadAnswerUncertain).
      if (response.is_uncertain())
      {
        done(StateIdentityResult{ua::client::detail::uncertain_answer_refused(
          response.status_code(), "ReadAnswerUncertain", source)});
        return;
      }
      if (!response.has_value())
      {
        done(StateIdentityResult{response.status_code(),
          ua::make_error_detail("StateMachineIdentityBrowseNameReadFailed",
            "the Read of a State or Transition Object's BrowseName failed",
            source,
            response.shared_detail())});
        return;
      }
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        done(StateIdentityResult{serviceResult,
          ua::make_error_detail("StateMachineIdentityBrowseNameServiceFault",
            "the Read of a State or Transition Object's BrowseName returned a service-level fault",
            source,
            serviceResult)});
        return;
      }
      if (serviceResult.is_uncertain())
      {
        done(StateIdentityResult{
          ua::client::detail::uncertain_answer_refused(serviceResult, "ReadAnswerUncertain", source)});
        return;
      }
      auto& values = response.value().results();
      if (values.size() != 1U)
      {
        done(StateIdentityResult{ua::Status::BadUnexpectedError,
          ua::make_error_detail("StateMachineIdentityBrowseNameReadCountMismatch",
            "the BrowseName Read returned a result count different from the one ReadValueId sent",
            source)});
        return;
      }
      const ua::StatusCode valueStatus = values[0].status().value_or(ua::StatusCode{});
      if (valueStatus.is_uncertain())
      {
        done(StateIdentityResult{
          ua::client::detail::uncertain_answer_refused(valueStatus, "ReadAnswerUncertain", source)});
        return;
      }
      if (valueStatus.is_bad())
      {
        // Base StateMachineType permits application-defined Id NodeIds that need not identify a
        // browsable State Object. Bad_NodeIdUnknown therefore means "opaque identity": retain the
        // NodeId and let exact comparison decide. Transport/service failures and malformed readable
        // Objects remain hard errors.
        if (valueStatus.as_status() == ua::Status::BadNodeIdUnknown)
        {
          done(StateIdentityResult{std::move(identity)});
          return;
        }
        done(StateIdentityResult{valueStatus,
          ua::make_error_detail("StateMachineIdentityBrowseNameReadBad",
            "the State or Transition Object's BrowseName Read returned a Bad value status",
            source,
            valueStatus)});
        return;
      }
      auto decodedBrowseName = values[0].value().to<ua::QualifiedName>();
      if (!decodedBrowseName.is_good())
      {
        done(StateIdentityResult{decodedBrowseName.status_code(),
          ua::make_error_detail("StateMachineIdentityBrowseNameDecode",
            "the State or Transition Object's BrowseName did not decode to a QualifiedName",
            source,
            decodedBrowseName.shared_detail())});
        return;
      }
      ua::QualifiedName browseName = std::move(decodedBrowseName).value();

      auto wireOpsForWalk = wireOpsForOwner;
      browse_references(std::move(wireOpsForOwner),
        identity,
        ua::ReferenceTypeId::HasComponent,
        ua::BrowseDirection::Inverse,
        source,
        [wireOpsForWalk = std::move(wireOpsForWalk),
          identity = std::move(identity),
          browseName = std::move(browseName),
          source = std::move(source),
          done = std::move(done)](ua::Result<ReferenceList> owners) mutable
        {
          if (!owners.is_good())
          {
            done(StateIdentityResult{owners.status_code(), owners.shared_detail()});
            return;
          }
          if (owners.value().empty())
          {
            done(StateIdentityResult{std::move(identity)});
            return;
          }
          walk_state_identity_to_origin(std::move(wireOpsForWalk),
            std::move(identity),
            owners.value().front().node_id().node_id(),
            std::move(browseName),
            {},
            0U,
            std::move(source),
            std::move(done));
        });
    });
}

// ---- base (StateMachineType) resolution ----

/// Resolves the base child node ids (CurrentState + its Id  -  both Mandatory; LastTransition + its
/// Id/TransitionTime  -  Optional) onto @p state, then hands the machine's `HasComponent` reference list to
/// @p done (the program level reuses it to resolve the method nodes). @p interface is held strong for the
/// chain.
void resolve_base(std::shared_ptr<ua::client::detail::WireOps> lockedWireOps,
  std::shared_ptr<ua::client::detail::StateMachineHandleState> state, std::string source,
  std::function<void(ua::Result<std::shared_ptr<ReferenceList>>)> done)
{
  using CompsResult = ua::Result<std::shared_ptr<ReferenceList>>;
  const ua::NodeId machineId = state->machineId;
  auto wireOpsForChildren = lockedWireOps;
  browse_children(std::move(lockedWireOps),
    machineId,
    ua::ReferenceTypeId::HasComponent,
    source,
    [wireOpsForChildren = std::move(wireOpsForChildren),
      state = std::move(state),
      source,
      done = std::move(done)](ua::Result<ReferenceList> components) mutable
    {
      if (!components.is_good())
      {
        done(CompsResult{components.status_code(), components.shared_detail()});
        return;
      }
      auto comps = std::make_shared<ReferenceList>(std::move(components).value());
      auto currentState = find_child(*comps, "CurrentState");
      if (!currentState)
      {
        done(CompsResult{ua::Status::BadNotFound,
          ua::make_error_detail("StateMachineNoCurrentState",
            "the state machine has no Mandatory CurrentState component",
            source)});
        return;
      }
      state->currentStateNodeId = *currentState;
      state->lastTransitionNodeId = find_child(*comps, "LastTransition");  // Optional

      // Browse CurrentState one level (HasProperty) for its Mandatory Id Property.
      auto wireOpsForLastTransition = wireOpsForChildren;
      browse_children(std::move(wireOpsForChildren),
        *currentState,
        ua::ReferenceTypeId::HasProperty,
        source,
        [wireOpsForLastTransition = std::move(wireOpsForLastTransition),
          state,
          comps,
          source,
          done = std::move(done)](ua::Result<ReferenceList> currentStateProps) mutable
        {
          if (!currentStateProps.is_good())
          {
            done(CompsResult{currentStateProps.status_code(), currentStateProps.shared_detail()});
            return;
          }
          auto id = find_child(currentStateProps.value(), "Id");
          if (!id)
          {
            done(CompsResult{ua::Status::BadNotFound,
              ua::make_error_detail("StateMachineNoCurrentStateId",
                "the CurrentState variable has no Mandatory Id Property",
                source)});
            return;
          }
          state->currentStateIdNodeId = *id;

          if (!state->lastTransitionNodeId)
          {
            done(CompsResult{std::move(comps)});  // no LastTransition: base resolution complete
            return;
          }
          // Browse LastTransition one level (HasProperty) for its Id + TransitionTime Properties.
          const ua::NodeId lastTransition = *state->lastTransitionNodeId;
          browse_children(std::move(wireOpsForLastTransition),
            lastTransition,
            ua::ReferenceTypeId::HasProperty,
            source,
            [state, comps, source, done = std::move(done)](
              ua::Result<ReferenceList> lastTransitionProps) mutable
            {
              if (!lastTransitionProps.is_good())
              {
                done(CompsResult{lastTransitionProps.status_code(), lastTransitionProps.shared_detail()});
                return;
              }
              state->lastTransitionIdNodeId = find_child(lastTransitionProps.value(), "Id");
              state->lastTransitionTimeNodeId = find_child(lastTransitionProps.value(), "TransitionTime");
              done(CompsResult{std::move(comps)});
            });
        });
    });
}

// ---- finite (FiniteStateMachineType) topology resolution ----

/// The resolved topology snapshot + the Property node ids used to re-resolve it.
struct Topology
{
  std::vector<AvailableState> states;
  std::vector<AvailableTransition> transitions;
  std::optional<ua::NodeId> statesNodeId;
  std::optional<ua::NodeId> transitionsNodeId;
  /// Whether each array's Value was read Good. A published array whose Value is Bad leaves its list empty
  /// without being an array the server publishes empty.
  bool statesRead = false;
  bool transitionsRead = false;

  /// Cleared by any best-effort enrichment step that degraded, so the caller can tell an optional field left
  /// empty by the server from one left empty by a lookup this SDK could not complete.
  bool enrichmentComplete = true;
};

/// Records a failed best-effort enrichment step: the topology keeps its NodeIds and stays Good, and the
/// caller learns through @ref TopologyProvenance::enrichmentComplete that some optional fields are empty
/// because the SDK could not resolve them rather than because the server does not publish them.
void report_enrichment_degraded(
  const ua::Logger& logger, Topology& topology, std::string_view step, ua::StatusCode status)
{
  topology.enrichmentComplete = false;
  logger.warning({{"step", step}, {"status", fmt::format("0x{:08x}", status.as_uint32())}},
    "State-machine topology enrichment step failed; the NodeIds are intact and the optional metadata it "
    "would have filled is left empty");
}

/// Decodes the `AvailableStates` Property Value (an array of state Object NodeIds) into @ref AvailableState
/// entries. These are topology Object NodeIds; CL-SM-006 identity normalization is performed on demand by
/// current_state_is_async, so topology decoding itself needs no per-state metadata read. A Bad value status
/// gives an empty list: a Bad value has no usable value.
std::vector<AvailableState> decode_states(const ua::DataValue& value)
{
  std::vector<AvailableState> out;
  const auto& valueStatus = value.status();
  if (valueStatus && valueStatus.value().is_bad())
  {
    return out;
  }
  if (auto ids = value.value().to_vector<ua::NodeId>(); ids.is_good())
  {
    for (auto& id : ids.value())
    {
      AvailableState entry;
      entry.stateId = std::move(id);
      out.push_back(std::move(entry));
    }
  }
  return out;
}

/// Decodes the `AvailableTransitions` Property Value (an array of transition Object NodeIds) into
/// @ref AvailableTransition entries. A Bad value status gives an empty list: a Bad value has no usable value.
std::vector<AvailableTransition> decode_transitions(const ua::DataValue& value)
{
  std::vector<AvailableTransition> out;
  const auto& valueStatus = value.status();
  if (valueStatus && valueStatus.value().is_bad())
  {
    return out;
  }
  if (auto ids = value.value().to_vector<ua::NodeId>(); ids.is_good())
  {
    for (auto& id : ids.value())
    {
      AvailableTransition entry;
      entry.transitionId = std::move(id);
      out.push_back(std::move(entry));
    }
  }
  return out;
}

/// Fills in each entry's DisplayName, its StateNumber / TransitionNumber, and each transition's FromState /
/// ToState targets (OPC 10000-16 4.4.2/4.4.4: `StateType` has a Mandatory `StateNumber` Property,
/// `TransitionType` a Mandatory `TransitionNumber`, and a transition names its endpoints through the
/// `FromState` / `ToState` ReferenceTypes).
///
/// Without the endpoints a transition list is a list of opaque NodeIds: a caller can see THAT transitions
/// exist but not what graph they form. The number is what the standard state machines are keyed by, and the
/// name is what an operator sees.
///
/// Costs three batched round-trips for the WHOLE topology regardless of its size (one Browse carrying every
/// transition's FromState and ToState, one TranslateBrowsePaths for every Number Property, one Read), and
/// the result is cached with the topology. Enrichment is BEST-EFFORT: a failure leaves the ids - the part
/// the caller's contract is built on - intact and Good, with the optional fields empty, because a topology
/// that fails wholesale because a DisplayName could not be read would be a worse answer than a partial one.
///
/// A step that fails clears @ref Topology::enrichmentComplete and logs through @p logger (see
/// @ref report_enrichment_degraded), so a partial result is reported as one.
void enrich_topology(std::shared_ptr<ua::client::detail::WireOps> lockedWireOps, Topology topology,
  std::string source, ua::Logger logger, std::function<void(ua::Result<Topology>)> done);

/// Resolves the `AvailableStates` / `AvailableTransitions` topology: browses the machine one level
/// (HasComponent), matches the two Variables, and batch-Reads their NodeId-array Values. Absent
/// Variables yield an empty topology (Good). @p interface is held strong for the chain; @p done is invoked
/// inline (the caller delivers on the executor).
///
/// The reference type is **HasComponent**, per OPC 10000-16's FiniteStateMachineType definition:
///
///     HasComponent  Variable  AvailableStates       NodeId[]  BaseDataVariableType  Optional
///     HasComponent  Variable  AvailableTransitions  NodeId[]  BaseDataVariableType  Optional
///
/// Both Variables are Optional, so "not found" is a legitimate outcome and an empty topology is Good. Which
/// of the two was found is carried on @ref Topology::statesNodeId / @ref Topology::transitionsNodeId and
/// published as @ref TopologyProvenance, so an empty topology stays distinguishable from a failed lookup.
void resolve_topology(std::shared_ptr<ua::client::detail::WireOps> lockedWireOps, ua::NodeId machineId,
  std::string source, ua::Logger logger, std::function<void(ua::Result<Topology>)> done)
{
  auto wireOpsForRead = lockedWireOps;
  browse_children(std::move(lockedWireOps),
    machineId,
    ua::ReferenceTypeId::HasComponent,
    source,
    [wireOpsForRead = std::move(wireOpsForRead), source, logger = std::move(logger), done = std::move(done)](
      ua::Result<ReferenceList> props) mutable
    {
      if (!props.is_good())
      {
        done(ua::Result<Topology>{props.status_code(), props.shared_detail()});
        return;
      }
      Topology topology;
      topology.statesNodeId = find_child(props.value(), "AvailableStates");
      topology.transitionsNodeId = find_child(props.value(), "AvailableTransitions");
      if (!topology.statesNodeId && !topology.transitionsNodeId)
      {
        done(ua::Result<Topology>{std::move(topology)});  // no finite topology declared: empty (Good)
        return;
      }
      // Build a batched Read of the present Property Values in a fixed order [states, transitions].
      ua::ReadRequest read;
      const bool haveStates = topology.statesNodeId.has_value();
      const bool haveTransitions = topology.transitionsNodeId.has_value();
      if (haveStates)
      {
        read.nodes_to_read().push_back(make_attribute_read_value(*topology.statesNodeId, valueAttribute));
      }
      if (haveTransitions)
      {
        read.nodes_to_read().push_back(
          make_attribute_read_value(*topology.transitionsNodeId, valueAttribute));
      }
      auto wireOpsForEnrich = wireOpsForRead;
      wireOpsForRead->read_async(std::move(read),
        [topology = std::move(topology),
          haveStates,
          haveTransitions,
          source,
          logger = std::move(logger),
          wireOpsForEnrich = std::move(wireOpsForEnrich),
          done = std::move(done)](ua::Result<ua::ReadResponse> response) mutable
        {
          // The handle keeps the topology as its own state, so only a Good answer is used: an Uncertain one
          // (to the service, its ServiceResult or either value) is refused (ReadAnswerUncertain), and a value
          // whose status is Bad fails the resolution with that status.
          if (response.is_uncertain())
          {
            done(ua::Result<Topology>{ua::client::detail::uncertain_answer_refused(
              response.status_code(), "ReadAnswerUncertain", source)});
            return;
          }
          if (!response.has_value())
          {
            done(ua::Result<Topology>{response.status_code(),
              ua::make_error_detail("StateMachineTopologyReadFailed",
                "the batched Read of the AvailableStates / AvailableTransitions Values failed",
                source,
                response.shared_detail())});
            return;
          }
          // Facade flatten: the wire funnel returns the ReadResponse verbatim; a bad
          // ResponseHeader.serviceResult is a service-level failure the facade surfaces as bad, preserving
          // the exact service status + ErrorDetail. Without this an empty results[] masks the fault as
          // Bad_UnexpectedError (count-mismatch branch below).
          const ua::StatusCode serviceResult = response.value().response_header().service_result();
          if (serviceResult.is_bad())
          {
            done(ua::Result<Topology>{serviceResult,
              ua::make_error_detail("StateMachineTopologyServiceFault",
                "the batched Read of the AvailableStates / AvailableTransitions Values returned a "
                "service-level fault",
                source,
                serviceResult)});
            return;
          }
          if (serviceResult.is_uncertain())
          {
            done(ua::Result<Topology>{
              ua::client::detail::uncertain_answer_refused(serviceResult, "ReadAnswerUncertain", source)});
            return;
          }
          auto& values = response.value().results();
          const std::size_t expected =
            static_cast<std::size_t>(haveStates ? 1 : 0) + static_cast<std::size_t>(haveTransitions ? 1 : 0);
          if (values.size() != expected)
          {
            done(ua::Result<Topology>{ua::Status::BadUnexpectedError,
              ua::make_error_detail("StateMachineTopologyReadCountMismatch",
                "the topology Read returned a result count different from the number of ReadValueIds sent",
                source,
                response.shared_detail())});
            return;
          }
          for (const auto& value : values)
          {
            const ua::StatusCode valueStatus = value.status().value_or(ua::StatusCode{ua::Status::Good});
            if (valueStatus.is_uncertain())
            {
              done(ua::Result<Topology>{
                ua::client::detail::uncertain_answer_refused(valueStatus, "ReadAnswerUncertain", source)});
              return;
            }
          }
          // Both Properties are Optional (OPC 10000-16 4.4.2): a Bad value leaves its list empty
          // (decode_states / decode_transitions) and the topology is still built.
          std::size_t index = 0;
          const auto readGood = [](const ua::DataValue& value)
          {
            return value.status().value_or(ua::StatusCode{ua::Status::Good}).is_good();
          };
          if (haveStates)
          {
            topology.statesRead = readGood(values[index]);
            topology.states = decode_states(values[index++]);
          }
          if (haveTransitions)
          {
            topology.transitionsRead = readGood(values[index]);
            topology.transitions = decode_transitions(values[index++]);
          }
          enrich_topology(std::move(wireOpsForEnrich),
            std::move(topology),
            std::move(source),
            std::move(logger),
            std::move(done));
        });
    });
}

/// Builds the single-element RelativePath `/<HasProperty>ns0:<propertyName>` used to locate a state's or
/// transition's Number Property in one TranslateBrowsePaths call.
ua::BrowsePath make_number_browse_path(const ua::NodeId& startNode, std::string_view propertyName)
{
  ua::RelativePathElement element;
  element.reference_type_id() =
    ua::NodeId{std::uint16_t{0}, static_cast<std::uint32_t>(ua::ReferenceTypeId::HasProperty)};
  element.is_inverse() = false;
  element.include_subtypes() = false;
  element.target_name() = ua::QualifiedName{0, std::string{propertyName}};

  ua::BrowsePath path;
  path.starting_node() = startNode;
  path.relative_path().elements().push_back(std::move(element));
  return path;
}

void enrich_topology(std::shared_ptr<ua::client::detail::WireOps> lockedWireOps, Topology topology,
  std::string source, ua::Logger logger, std::function<void(ua::Result<Topology>)> done)
{
  if (topology.states.empty() && topology.transitions.empty())
  {
    done(ua::Result<Topology>{std::move(topology)});
    return;
  }

  // Step 1 - every transition's FromState and ToState in ONE Browse: 2 descriptions per transition, in a
  // fixed order the response is read back positionally.
  ua::BrowseRequest browse;
  for (const auto& transition : topology.transitions)
  {
    for (const auto referenceType : {ua::ReferenceTypeId::FromState, ua::ReferenceTypeId::ToState})
    {
      ua::BrowseDescription browseDescription;
      browseDescription.node_id() = transition.transitionId;
      browseDescription.browse_direction() = ua::BrowseDirection::Forward;
      browseDescription.reference_type_id() =
        ua::NodeId{std::uint16_t{0}, static_cast<std::uint32_t>(referenceType)};
      browseDescription.include_subtypes() = false;
      browse.nodes_to_browse().push_back(std::move(browseDescription));
    }
  }

  auto finishNamesAndNumbers = [lockedWireOps, source, logger, done](Topology enriched) mutable
  {
    // Step 2 - the DisplayName of every state and transition, then their Number Properties. The Numbers
    // need their Property NodeIds first, which one TranslateBrowsePaths resolves for all of them at once.
    ua::TranslateBrowsePathsToNodeIdsRequest translate;
    for (const auto& state : enriched.states)
    {
      translate.browse_paths().push_back(make_number_browse_path(state.stateId, "StateNumber"));
    }
    for (const auto& transition : enriched.transitions)
    {
      translate.browse_paths().push_back(
        make_number_browse_path(transition.transitionId, "TransitionNumber"));
    }

    lockedWireOps->translate_browse_paths_async(std::move(translate),
      [lockedWireOps, source, logger, enriched = std::move(enriched), done](
        ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse> translated) mutable
      {
        // The Number Properties are Mandatory on StateType / TransitionType, but a server that does not
        // publish them is not a reason to fail the topology: keep the ids and leave the numbers empty.
        std::vector<std::optional<ua::NodeId>> numberNodes(
          enriched.states.size() + enriched.transitions.size(), std::nullopt);
        // The SDK keeps what it resolves here, so only a Good answer is used.
        if (translated.is_good() && translated.value().response_header().service_result().is_good())
        {
          const auto& results = translated.value().results();
          for (std::size_t i = 0; i < results.size() && i < numberNodes.size(); ++i)
          {
            if (results[i].status_code().is_good() && !results[i].targets().empty())
            {
              numberNodes[i] = results[i].targets()[0].target_id().node_id();
            }
          }
        }
        else
        {
          // Every Number is now unresolvable, not just one: the whole TranslateBrowsePaths failed.
          report_enrichment_degraded(logger,
            enriched,
            "translate_number_properties",
            !translated.is_good() ? translated.status_code()
                                  : translated.value().response_header().service_result());
        }

        // One Read carrying every DisplayName followed by every resolved Number Value, in that order.
        ua::ReadRequest read;
        for (const auto& state : enriched.states)
        {
          read.nodes_to_read().push_back(make_attribute_read_value(state.stateId, displayNameAttribute));
        }
        for (const auto& transition : enriched.transitions)
        {
          read.nodes_to_read().push_back(
            make_attribute_read_value(transition.transitionId, displayNameAttribute));
        }
        std::vector<std::size_t> numberReadIndex(numberNodes.size(), 0);
        for (std::size_t i = 0; i < numberNodes.size(); ++i)
        {
          if (numberNodes[i].has_value())
          {
            numberReadIndex[i] = read.nodes_to_read().size();
            read.nodes_to_read().push_back(make_attribute_read_value(*numberNodes[i], valueAttribute));
          }
        }

        lockedWireOps->read_async(std::move(read),
          [enriched = std::move(enriched),
            numberNodes = std::move(numberNodes),
            numberReadIndex = std::move(numberReadIndex),
            logger,
            done](ua::Result<ua::ReadResponse> response) mutable
          {
            // The SDK keeps the names and numbers with the topology, so only a Good answer, and a value read
            // Good, is used.
            if (!response.is_good() || !response.value().response_header().service_result().is_good())
            {
              // ids stand; every name and number stays empty
              report_enrichment_degraded(logger,
                enriched,
                "read_names_and_numbers",
                !response.is_good() ? response.status_code()
                                    : response.value().response_header().service_result());
              done(ua::Result<Topology>{std::move(enriched)});
              return;
            }
            const auto& values = response.value().results();
            const std::size_t entryCount = enriched.states.size() + enriched.transitions.size();
            for (std::size_t i = 0; i < entryCount && i < values.size(); ++i)
            {
              if (!values[i].status().value_or(ua::StatusCode{ua::Status::Good}).is_good())
              {
                continue;
              }
              auto name = values[i].value().to<ua::LocalizedText>();
              if (!name.is_good())
              {
                continue;
              }
              if (i < enriched.states.size())
              {
                enriched.states[i].name = std::move(name).value();
              }
              else
              {
                enriched.transitions[i - enriched.states.size()].name = std::move(name).value();
              }
            }
            for (std::size_t i = 0; i < numberNodes.size(); ++i)
            {
              if (!numberNodes[i].has_value() || numberReadIndex[i] >= values.size())
              {
                continue;
              }
              const auto& value = values[numberReadIndex[i]];
              if (!value.status().value_or(ua::StatusCode{ua::Status::Good}).is_good())
              {
                continue;
              }
              auto number = value.value().to<std::uint32_t>();
              if (!number.is_good())
              {
                continue;
              }
              if (i < enriched.states.size())
              {
                enriched.states[i].number = number.value();
              }
              else
              {
                enriched.transitions[i - enriched.states.size()].number = number.value();
              }
            }
            done(ua::Result<Topology>{std::move(enriched)});
          });
      });
  };

  if (browse.nodes_to_browse().empty())
  {
    finishNamesAndNumbers(std::move(topology));  // states only: nothing to walk
    return;
  }

  lockedWireOps->browse_async(std::move(browse),
    [topology = std::move(topology), logger, finishNamesAndNumbers](
      ua::Result<ua::BrowseResponse> response) mutable
    {
      // The SDK keeps the endpoints with the topology, so only a Good answer is used.
      if (!response.is_good() || !response.value().response_header().service_result().is_good())
      {
        // Without the endpoints the transition list is a graph with no edges: kept, not failed.
        report_enrichment_degraded(logger,
          topology,
          "browse_transition_endpoints",
          !response.is_good() ? response.status_code() : response.value().response_header().service_result());
      }
      else
      {
        const auto& results = response.value().results();
        for (std::size_t i = 0; i < topology.transitions.size(); ++i)
        {
          const std::size_t fromIndex = i * 2;
          const std::size_t toIndex = fromIndex + 1;
          if (fromIndex < results.size() && results[fromIndex].status_code().is_good() &&
              !results[fromIndex].references().empty())
          {
            topology.transitions[i].fromStateId = results[fromIndex].references()[0].node_id().node_id();
          }
          if (toIndex < results.size() && results[toIndex].status_code().is_good() &&
              !results[toIndex].references().empty())
          {
            topology.transitions[i].toStateId = results[toIndex].references()[0].node_id().node_id();
          }
        }
      }
      finishNamesAndNumbers(std::move(topology));
    });
}

// ---- program (ProgramStateMachineType) method + state matrix ----

/// The standard Part-10 program states (matched by the well-known ns0 state-Object NodeId).
enum class ProgramState
{
  Ready,
  Running,
  Suspended,
  Halted,
  Unknown,
};

/// Maps a `CurrentState.Id` NodeId to a @ref ProgramState via the well-known ns0 state ids. Per CL-SM-006 the
/// server reuses these NodeIds for a compliant `ProgramStateMachineType` (or subtype); an unrecognised id
/// maps to @ref ProgramState::Unknown, which the matrix treats as a mismatch (the `skip_local_state_check`
/// override exists for exactly that custom-subtype case).
ProgramState program_state_of(const ua::NodeId& stateId)
{
  const auto wellKnown = [&](ua::ObjectId id)
  {
    return stateId == ua::NodeId{std::uint16_t{0}, static_cast<std::uint32_t>(id)};
  };
  if (wellKnown(ua::ObjectId::ProgramStateMachineType_Ready))
    return ProgramState::Ready;
  if (wellKnown(ua::ObjectId::ProgramStateMachineType_Running))
    return ProgramState::Running;
  if (wellKnown(ua::ObjectId::ProgramStateMachineType_Suspended))
    return ProgramState::Suspended;
  if (wellKnown(ua::ObjectId::ProgramStateMachineType_Halted))
    return ProgramState::Halted;
  return ProgramState::Unknown;
}

/// The ns0 method BrowseName the @p method resolves to. `Stop` is a non-Part-10 convenience aliased onto the
/// `Halt` method (Part 10 has no Stop cause; "stop a running/suspended program" == Halt it).
std::string_view method_browse_name(ProgramMethod method)
{
  switch (method)
  {
  case ProgramMethod::Start:
    return "Start";
  case ProgramMethod::Suspend:
    return "Suspend";
  case ProgramMethod::Resume:
    return "Resume";
  case ProgramMethod::Reset:
    return "Reset";
  case ProgramMethod::Halt:
  case ProgramMethod::Stop:
    return "Halt";
  }
  return "Halt";
}

/// The local state-method matrix (CL-SM-009, Part 10 section 6.6.3): whether @p method is a valid cause FROM
/// @p state. `Stop` (non-standard) is valid from {Running, Suspended}  -  a running/suspended program can be
/// stopped (== Halt-from-active).
bool matrix_allows(ProgramMethod method, ProgramState state)
{
  switch (method)
  {
  case ProgramMethod::Start:
    return state == ProgramState::Ready;
  case ProgramMethod::Suspend:
    return state == ProgramState::Running;
  case ProgramMethod::Resume:
    return state == ProgramState::Suspended;
  case ProgramMethod::Reset:
    // Part 10 ProgramStateMachineType (section 6.6.3): Reset is a valid cause from Halted, Running, or
    // Suspended (the HaltedToReady / RunningToReady / SuspendedToReady transitions), not from Halted alone.
    return state == ProgramState::Halted || state == ProgramState::Running ||
           state == ProgramState::Suspended;
  case ProgramMethod::Halt:
    return state == ProgramState::Ready || state == ProgramState::Running || state == ProgramState::Suspended;
  case ProgramMethod::Stop:
    return state == ProgramState::Running || state == ProgramState::Suspended;
  }
  return false;
}

// ---- StateVariable / TransitionVariable decoders ----

/// The two DataValues of a StateVariable read as one @ref StateVariable. Its statusCode is the CurrentState
/// quality and the Id Property's combined (@ref ua::detail::combined_status, the CurrentState's code answered
/// when both carry one of the same severity), so an Uncertain or Bad Id is not hidden behind a Good
/// CurrentState; a value whose own status is Bad is not decoded.
StateVariable decode_current_state(const ua::DataValue& stateValue, const ua::DataValue& idValue)
{
  StateVariable out;
  const auto& stateStatus = stateValue.status();
  // CL-SM-002 - the CurrentState quality is surfaced verbatim (Bad_StateNotActive etc.) when the Id's is
  // Good.
  out.statusCode = ua::detail::combined_status(idValue.status().value_or(ua::StatusCode{ua::Status::Good}),
    stateStatus.value_or(ua::StatusCode{ua::Status::Good}));
  if ((!stateStatus || !stateStatus->is_bad()))
  {
    if (auto name = stateValue.value().to<ua::LocalizedText>(); name.is_good())
    {
      out.name = name.value();
    }
  }
  out.sourceTimestamp = stateValue.source_timestamp();
  const auto& idStatus = idValue.status();
  if ((!idStatus || !idStatus->is_bad()))
  {
    if (auto id = idValue.value().to<ua::NodeId>(); id.is_good())
    {
      out.id = id.value();
    }
  }
  return out;
}

/// Atomically publishes @p topology onto @p finite (client design section 8.18.2): the state / transition
/// snapshots are wrapped in immutable `shared_ptr<const vector<...>>` and stored through the atomics so a
/// concurrent synchronous accessor never tears; the refresh Property node ids are updated for the next
/// re-resolve.
void publish_topology(ua::client::detail::FiniteStateMachineHandleState& finite, Topology topology)
{
  finite.availableStates.store(
    std::make_shared<const std::vector<AvailableState>>(std::move(topology.states)));
  finite.availableTransitions.store(
    std::make_shared<const std::vector<AvailableTransition>>(std::move(topology.transitions)));
  finite.availableStatesNodeId = topology.statesNodeId;
  finite.availableTransitionsNodeId = topology.transitionsNodeId;
  finite.provenance.store(std::make_shared<const TopologyProvenance>(
    TopologyProvenance{topology.statesNodeId.has_value() && topology.statesRead,
      topology.transitionsNodeId.has_value() && topology.transitionsRead,
      topology.enrichmentComplete}));
}

// ---- CL-SM-010/011 TransitionEvent subscription: filter build + notification decode ----

/// Builds one `TransitionEventType` SelectClause for the Value attribute at @p browsePath (a chain of ns0
/// BrowseNames, e.g. {"Transition", "Id"}).
ua::SimpleAttributeOperand transition_select_clause(std::initializer_list<std::string_view> browsePath)
{
  ua::SimpleAttributeOperand operand;
  operand.type_definition_id() = ua::NodeId{ua::ObjectTypeId::TransitionEventType};
  for (const std::string_view segment : browsePath)
  {
    operand.browse_path().push_back(ua::QualifiedName{std::uint16_t{0}, std::string{segment}});
  }
  operand.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::Value);
  return operand;
}

/// Builds the `OfType(TransitionEventType)` WhereClause element (a single `OfType` operator over a
/// `LiteralOperand` carrying the type NodeId).
ua::ContentFilterElement of_type_transition_event_element()
{
  ua::LiteralOperand operand;
  operand.value() = ua::Variant{ua::NodeId{ua::ObjectTypeId::TransitionEventType}};
  ua::ContentFilterElement element;
  element.filter_operator() = ua::FilterOperator::OfType;
  element.filter_operands().push_back(
    ua::RefStructure<ua::Structure>{std::make_unique<ua::LiteralOperand>(std::move(operand))});
  return element;
}

/// The CL-SM-010 TransitionEvent `EventFilter`: OfType(TransitionEventType) WhereClause + SelectClauses for
/// `Transition` / `FromState` / `ToState` and each one's `Id` Property. The base BaseEventType mandatories
/// (incl. `Time`) are prepended by the event backbone (`EventSubscriber::subscribe_async`)  -  this filter
/// carries only the transition-specific fields.
ua::EventFilter build_transition_event_filter()
{
  ua::EventFilter filter;
  filter.select_clauses().push_back(transition_select_clause({"Transition"}));
  filter.select_clauses().push_back(transition_select_clause({"Transition", "Id"}));
  filter.select_clauses().push_back(transition_select_clause({"FromState"}));
  filter.select_clauses().push_back(transition_select_clause({"FromState", "Id"}));
  filter.select_clauses().push_back(transition_select_clause({"ToState"}));
  filter.select_clauses().push_back(transition_select_clause({"ToState", "Id"}));
  filter.where_clause().elements().push_back(of_type_transition_event_element());
  return filter;
}

/// Finds the selected event-field value whose BrowsePath equals @p browsePath (positional decode against the
/// composite filter's SelectClauses, via the parallel `fieldPaths` metadata  -  robust to the base
/// mandatories the backbone prepends). Returns `nullopt` when no field matches / the field is null.
std::optional<ua::Variant> field_by_path(
  const ua::client::EventNotification& event, std::initializer_list<std::string_view> browsePath)
{
  for (std::size_t i = 0; i < event.fieldPaths.size() && i < event.fields.size(); ++i)
  {
    const auto& path = event.fieldPaths[i];
    if (path.size() != browsePath.size())
    {
      continue;
    }
    bool matches = true;
    std::size_t segment = 0;
    for (const std::string_view expected : browsePath)
    {
      if (static_cast<std::string_view>(path[segment].name()) != expected)
      {
        matches = false;
        break;
      }
      ++segment;
    }
    if (matches)
    {
      return event.fields[i];
    }
  }
  return std::nullopt;
}

/// Decodes a demux-matched @ref ua::client::EventNotification into a @ref TransitionEventNotification
/// (CL-SM-010): `sourceNode` is the decoded BaseEventType field; the transition-specific fields come from the
/// positional selected fields by their BrowsePath.
TransitionEventNotification decode_transition_event(const ua::client::EventNotification& event)
{
  TransitionEventNotification out;
  out.sourceNode = event.sourceNode;
  if (const auto time = event.field_as<ua::DateTime>("Time"); time.is_good())
  {
    out.time = time.value();
  }
  if (const auto name = field_by_path(event, {"Transition"}))
  {
    if (const auto decoded = name->to<ua::LocalizedText>(); decoded.is_good())
    {
      out.transitionName = decoded.value();
    }
  }
  if (const auto id = field_by_path(event, {"Transition", "Id"}))
  {
    if (const auto decoded = id->to<ua::NodeId>(); decoded.is_good())
    {
      out.transitionId = decoded.value();
    }
  }
  if (const auto id = field_by_path(event, {"FromState", "Id"}))
  {
    if (const auto decoded = id->to<ua::NodeId>(); decoded.is_good())
    {
      out.fromStateId = decoded.value();
    }
  }
  if (const auto id = field_by_path(event, {"ToState", "Id"}))
  {
    if (const auto decoded = id->to<ua::NodeId>(); decoded.is_good())
    {
      out.toStateId = decoded.value();
    }
  }
  return out;
}

}  // namespace

// ============================================================================
// StateMachineAccessor
// ============================================================================

StateMachineAccessor::StateMachineAccessor(std::weak_ptr<detail::WireOps> wireOps,
  std::weak_ptr<detail::SupportOps> supportOps, boost::asio::any_io_executor executor, ua::Logger logger)
  : mWireOps(std::move(wireOps)), mSupportOps(std::move(supportOps)), mExecutor(std::move(executor)),
    mLogger(std::move(logger))
{}

void StateMachineAccessor::state_machine_async(
  ua::NodeId machineId, std::function<void(StateMachineHandleResult)> callback) noexcept
{
  auto lockedWireOps = mWireOps.lock();
  auto support = mSupportOps.lock();
  auto executor = mExecutor;
  if (!lockedWireOps || !support)
  {
    deliver<StateMachineHandleResult>(executor,
      std::move(callback),
      StateMachineHandleResult{ua::Status::BadConnectionClosed,
        ua::make_error_detail("StateMachineConnectionGone",
          "the Connection was dropped before the state-machine handle could be built",
          std::string{connClosedSource})});
    return;
  }
  auto state = std::make_shared<detail::StateMachineHandleState>();
  state->wireOps = mWireOps;
  state->supportOps = mSupportOps;
  state->executor = executor;
  state->logger = mLogger;
  state->machineId = std::move(machineId);
  resolve_base(std::move(lockedWireOps),
    state,
    std::string{constructionSource},
    [state, executor, callback = std::move(callback)](
      ua::Result<std::shared_ptr<ReferenceList>> comps) mutable
    {
      if (!comps.is_good())
      {
        deliver<StateMachineHandleResult>(executor,
          std::move(callback),
          StateMachineHandleResult{comps.status_code(), comps.shared_detail()});
        return;
      }
      deliver<StateMachineHandleResult>(
        executor, std::move(callback), StateMachineHandleResult{StateMachineHandle{std::move(state)}});
    });
}

void StateMachineAccessor::finite_state_machine_async(
  ua::NodeId machineId, std::function<void(FiniteStateMachineHandleResult)> callback) noexcept
{
  auto lockedWireOps = mWireOps.lock();
  auto support = mSupportOps.lock();
  auto executor = mExecutor;
  if (!lockedWireOps || !support)
  {
    deliver<FiniteStateMachineHandleResult>(executor,
      std::move(callback),
      FiniteStateMachineHandleResult{ua::Status::BadConnectionClosed,
        ua::make_error_detail("StateMachineConnectionGone",
          "the Connection was dropped before the finite-state-machine handle could be built",
          std::string{connClosedSource})});
    return;
  }
  auto state = std::make_shared<detail::FiniteStateMachineHandleState>();
  state->wireOps = mWireOps;
  state->supportOps = mSupportOps;
  state->executor = executor;
  state->logger = mLogger;
  state->machineId = std::move(machineId);
  const ua::NodeId machine = state->machineId;
  resolve_base(lockedWireOps,
    state,
    std::string{constructionSource},
    [lockedWireOps, state, machine, executor, callback = std::move(callback)](
      ua::Result<std::shared_ptr<ReferenceList>> comps) mutable
    {
      if (!comps.is_good())
      {
        deliver<FiniteStateMachineHandleResult>(executor,
          std::move(callback),
          FiniteStateMachineHandleResult{comps.status_code(), comps.shared_detail()});
        return;
      }
      resolve_topology(std::move(lockedWireOps),
        machine,
        std::string{topologySource},
        state->logger,
        [state, executor, callback = std::move(callback)](ua::Result<Topology> topology) mutable
        {
          if (!topology.is_good())
          {
            deliver<FiniteStateMachineHandleResult>(executor,
              std::move(callback),
              FiniteStateMachineHandleResult{topology.status_code(), topology.shared_detail()});
            return;
          }
          publish_topology(*state, std::move(topology.value()));
          deliver<FiniteStateMachineHandleResult>(executor,
            std::move(callback),
            FiniteStateMachineHandleResult{FiniteStateMachineHandle{std::move(state)}});
        });
    });
}

void StateMachineAccessor::program_state_machine_async(
  ua::NodeId machineId, std::function<void(ProgramStateMachineHandleResult)> callback) noexcept
{
  auto lockedWireOps = mWireOps.lock();
  auto support = mSupportOps.lock();
  auto executor = mExecutor;
  if (!lockedWireOps || !support)
  {
    deliver<ProgramStateMachineHandleResult>(executor,
      std::move(callback),
      ProgramStateMachineHandleResult{ua::Status::BadConnectionClosed,
        ua::make_error_detail("StateMachineConnectionGone",
          "the Connection was dropped before the program-state-machine handle could be built",
          std::string{connClosedSource})});
    return;
  }
  auto state = std::make_shared<detail::ProgramStateMachineHandleState>();
  state->wireOps = mWireOps;
  state->supportOps = mSupportOps;
  state->executor = executor;
  state->logger = mLogger;
  state->machineId = std::move(machineId);
  const ua::NodeId machine = state->machineId;
  resolve_base(lockedWireOps,
    state,
    std::string{constructionSource},
    [lockedWireOps, state, machine, executor, callback = std::move(callback)](
      ua::Result<std::shared_ptr<ReferenceList>> comps) mutable
    {
      if (!comps.is_good())
      {
        deliver<ProgramStateMachineHandleResult>(executor,
          std::move(callback),
          ProgramStateMachineHandleResult{comps.status_code(), comps.shared_detail()});
        return;
      }
      // Resolve the standard method nodes from the machine's HasComponent references (reused from
      // resolve_base  -  the methods are HasComponent children alongside CurrentState / LastTransition).
      for (std::string_view name : {"Start", "Suspend", "Resume", "Halt", "Reset"})
      {
        if (auto methodNode = find_child(*comps.value(), name))
        {
          state->methodNodeIds.emplace(std::string{name}, *methodNode);
        }
      }
      resolve_topology(std::move(lockedWireOps),
        machine,
        std::string{topologySource},
        state->logger,
        [state, executor, callback = std::move(callback)](ua::Result<Topology> topology) mutable
        {
          if (!topology.is_good())
          {
            deliver<ProgramStateMachineHandleResult>(executor,
              std::move(callback),
              ProgramStateMachineHandleResult{topology.status_code(), topology.shared_detail()});
            return;
          }
          publish_topology(*state, std::move(topology.value()));
          deliver<ProgramStateMachineHandleResult>(executor,
            std::move(callback),
            ProgramStateMachineHandleResult{ProgramStateMachineHandle{std::move(state)}});
        });
    });
}

void StateMachineAccessor::subscribe_transitions_async(ua::NodeId machineId,
  TransitionEventCallback onTransition,
  std::function<void(ua::client::MonitoredItemResult)> callback) noexcept
{
  using R = ua::client::MonitoredItemResult;
  auto support = mSupportOps.lock();
  auto executor = mExecutor;
  // Reach the section 8.13 event backbone through the SupportOps interface. A gone Connection (or a
  // subscriber that is not available) is a gone interface -> Bad_ConnectionClosed on the executor.
  std::shared_ptr<detail::EventSubscriberImpl> subscriber = support ? support->event_subscriber() : nullptr;
  if (!subscriber)
  {
    deliver<R>(executor,
      std::move(callback),
      R{ua::Status::BadConnectionClosed,
        ua::make_error_detail("StateMachineConnectionGone",
          "the Connection was dropped before the TransitionEvent subscription could be created",
          std::string{subscribeTransitionsSource})});
    return;
  }

  // CL-SM-011 demux: the wrapper's event callback CLOSURE captures machineId at subscribe time and delivers
  // only events whose sourceNode == machineId (the returned unified MonitoredItem carries no machine id).
  // DEFERRED (section 3.1 W-2): the CL-SM-011 `includeSubMachines=true` opt-in (also delivering a machine's
  // sub-state-machine transitions) is NOT implemented  -  this is the strict same-machine demux only. A later
  // slice adds the opt-in param + the sub-machine-id set predicate (the citation here covers the strict
  // half).
  auto onEvent = [machineId, onTransition = std::move(onTransition)](
                   ua::client::EventNotification event) mutable
  {
    if (event.sourceNode != machineId)
    {
      return;  // CL-SM-011  -  a TransitionEvent for a different machine is filtered out
    }
    onTransition(decode_transition_event(event));
  };

  // CL-SM-010: OfType(TransitionEventType) + Transition/FromState/ToState (+ Id) SelectClauses, ridden
  // through EventSubscriber::subscribe_async (the section 8.13 filter-carrying entry; subscribe_to_type_async
  // offers no interface for the extra SelectClauses). The backbone prepends the BaseEventType mandatories.
  ua::client::EventSubscription subscription;
  subscription.filter = build_transition_event_filter();

  // The subscribe completion (and every event notification) is delivered on the executor by the subscriber,
  // so the SubscribeResult -> MonitoredItemResult forward runs on the executor already; no re-post needed.
  subscriber->subscribe_async(std::move(subscription),
    std::move(onEvent),
    [callback = std::move(callback)](ua::client::SubscribeResult result) mutable
    { callback(std::move(result)); });
}

// ============================================================================
// StateMachineHandle
// ============================================================================

void StateMachineHandle::current_state_async(std::function<void(StateVariableResult)> callback) noexcept
{
  if (!mState)
  {
    callback(StateVariableResult{ua::Status::BadInvalidState,
      ua::make_error_detail("StateMachineMovedFrom",
        "current_state issued on a moved-from StateMachineHandle",
        std::string{currentStateSource})});
    return;
  }
  auto lockedWireOps = mState->wireOps.lock();
  if (!lockedWireOps)
  {
    deliver<StateVariableResult>(mState->executor,
      std::move(callback),
      StateVariableResult{ua::Status::BadConnectionClosed,
        ua::make_error_detail("StateMachineConnectionGone",
          "the Connection was dropped before the CurrentState read could be issued",
          std::string{connClosedSource})});
    return;
  }
  auto executor = mState->executor;
  std::weak_ptr<detail::StateMachineHandleState> weak = mState;
  ua::ReadRequest read;
  read.nodes_to_read().push_back(make_attribute_read_value(mState->currentStateNodeId, valueAttribute));
  read.nodes_to_read().push_back(make_attribute_read_value(mState->currentStateIdNodeId, valueAttribute));
  lockedWireOps->read_async(std::move(read),
    [weak, executor, callback = std::move(callback)](ua::Result<ua::ReadResponse> response) mutable
    {
      if (!weak.lock())
      {
        return;  // handle dropped mid-flight: bail (UAF guard, section 9.8.3)
      }
      if (!response.has_value())
      {
        deliver<StateVariableResult>(executor,
          std::move(callback),
          StateVariableResult{response.status_code(),
            ua::make_error_detail("StateMachineCurrentStateReadFailed",
              "the batched Read of CurrentState + CurrentState.Id failed",
              std::string{currentStateSource},
              response.shared_detail())});
        return;
      }
      // Facade flatten: the wire funnel returns the ReadResponse verbatim; a bad ResponseHeader.serviceResult
      // is a service-level failure the facade surfaces as bad, preserving the exact service status +
      // ErrorDetail. Without this an empty results[] masks the fault as Bad_UnexpectedError (count-mismatch
      // branch below).
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        deliver<StateVariableResult>(executor,
          std::move(callback),
          StateVariableResult{serviceResult,
            ua::make_error_detail("StateMachineCurrentStateServiceFault",
              "the CurrentState Read returned a service-level fault",
              std::string{currentStateSource},
              serviceResult)});
        return;
      }
      const auto& values = response.value().results();
      if (values.size() != 2)
      {
        deliver<StateVariableResult>(executor,
          std::move(callback),
          StateVariableResult{ua::Status::BadUnexpectedError,
            ua::make_error_detail("StateMachineCurrentStateReadCountMismatch",
              "the CurrentState Read did not return exactly two DataValues",
              std::string{currentStateSource})});
        return;
      }
      // CL-SM-002  -  the read succeeded; a Bad CurrentState quality is surfaced in StateVariable.statusCode
      // and the outer Result keeps the read's own code (a Good subcode or an Uncertain ServiceResult).
      deliver<StateVariableResult>(executor,
        std::move(callback),
        ua::detail::held(decode_current_state(values[0], values[1]),
          ua::detail::combined_status(response.status_code(), serviceResult)));
    });
}

void StateMachineHandle::last_transition_async(
  std::function<void(TransitionVariableResult)> callback) noexcept
{
  if (!mState)
  {
    callback(TransitionVariableResult{ua::Status::BadInvalidState,
      ua::make_error_detail("StateMachineMovedFrom",
        "last_transition issued on a moved-from StateMachineHandle",
        std::string{lastTransitionSource})});
    return;
  }
  const auto& lastTransitionNode = mState->lastTransitionNodeId;
  if (!lastTransitionNode)
  {
    // CL-SM-004  -  LastTransition is Optional on StateMachineType; absent -> Bad_NotFound.
    deliver<TransitionVariableResult>(mState->executor,
      std::move(callback),
      TransitionVariableResult{ua::Status::BadNotFound,
        ua::make_error_detail("StateMachineNoLastTransition",
          "the state machine does not expose the Optional LastTransition variable",
          std::string{lastTransitionAbsentSource})});
    return;
  }
  auto lockedWireOps = mState->wireOps.lock();
  if (!lockedWireOps)
  {
    deliver<TransitionVariableResult>(mState->executor,
      std::move(callback),
      TransitionVariableResult{ua::Status::BadConnectionClosed,
        ua::make_error_detail("StateMachineConnectionGone",
          "the Connection was dropped before the LastTransition read could be issued",
          std::string{connClosedSource})});
    return;
  }
  auto executor = mState->executor;
  std::weak_ptr<detail::StateMachineHandleState> weak = mState;
  // Read LastTransition.Value plus (when present) its Id + TransitionTime Property Values, in a fixed order.
  ua::ReadRequest read;
  read.nodes_to_read().push_back(make_attribute_read_value(lastTransitionNode.value(), valueAttribute));
  const auto& transitionId = mState->lastTransitionIdNodeId;
  const auto& transitionTime = mState->lastTransitionTimeNodeId;
  const bool haveId = transitionId.has_value();
  const bool haveTime = transitionTime.has_value();
  if (haveId)
  {
    read.nodes_to_read().push_back(make_attribute_read_value(transitionId.value(), valueAttribute));
  }
  if (haveTime)
  {
    read.nodes_to_read().push_back(make_attribute_read_value(transitionTime.value(), valueAttribute));
  }
  lockedWireOps->read_async(std::move(read),
    [weak, executor, haveId, haveTime, callback = std::move(callback)](
      ua::Result<ua::ReadResponse> response) mutable
    {
      if (!weak.lock())
      {
        return;  // handle dropped mid-flight: bail (UAF guard, section 9.8.3)
      }
      if (!response.has_value())
      {
        deliver<TransitionVariableResult>(executor,
          std::move(callback),
          TransitionVariableResult{response.status_code(),
            ua::make_error_detail("StateMachineLastTransitionReadFailed",
              "the Read of LastTransition + its Properties failed",
              std::string{lastTransitionSource},
              response.shared_detail())});
        return;
      }
      // Facade flatten: the wire funnel returns the ReadResponse verbatim; a bad ResponseHeader.serviceResult
      // is a service-level failure the facade surfaces as bad, preserving the exact service status +
      // ErrorDetail. Without this an empty results[] masks the fault as Bad_UnexpectedError (count-mismatch
      // branch below).
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        deliver<TransitionVariableResult>(executor,
          std::move(callback),
          TransitionVariableResult{serviceResult,
            ua::make_error_detail("StateMachineLastTransitionServiceFault",
              "the Read of LastTransition + its Properties returned a service-level fault",
              std::string{lastTransitionSource},
              serviceResult)});
        return;
      }
      auto& values = response.value().results();
      const std::size_t expected =
        1U + static_cast<std::size_t>(haveId ? 1 : 0) + static_cast<std::size_t>(haveTime ? 1 : 0);
      if (values.size() != expected)
      {
        deliver<TransitionVariableResult>(executor,
          std::move(callback),
          TransitionVariableResult{ua::Status::BadUnexpectedError,
            ua::make_error_detail("StateMachineLastTransitionReadCountMismatch",
              "the LastTransition Read returned a result count different from the number of ReadValueIds "
              "sent",
              std::string{lastTransitionSource})});
        return;
      }
      // The transition comes with the Read's code: the ServiceResult, LastTransition's status and the status
      // of each optional Id / TransitionTime Property that is not Bad, combined
      // (ua::detail::combined_status). A Bad Property leaves its field unset (TransitionTime then comes from
      // LastTransition's SourceTimestamp, CL-SM-004). A Bad code, or a LastTransition that is not Good and
      // has no value, is answered without a transition.
      const auto statusOf = [](const ua::DataValue& value)
      {
        return value.status().value_or(ua::StatusCode{ua::Status::Good});
      };
      ua::StatusCode answered = ua::detail::combined_status(response.status_code(), serviceResult);
      answered = ua::detail::combined_status(answered, statusOf(values[0]));
      for (std::size_t property = 1; property < values.size(); ++property)
      {
        if (!statusOf(values[property]).is_bad())
        {
          answered = ua::detail::combined_status(answered, statusOf(values[property]));
        }
      }
      if (answered.is_bad() || (!answered.is_good() && values[0].value().empty()))
      {
        deliver<TransitionVariableResult>(executor, std::move(callback), TransitionVariableResult{answered});
        return;
      }
      TransitionVariable out;
      if (auto name = values[0].value().to<ua::LocalizedText>(); name.is_good())
      {
        out.name = name.value();
      }
      out.transitionTime =
        values[0].source_timestamp();  // default; overridden by the TransitionTime Property
      std::size_t index = 1;
      if (haveId)
      {
        auto id = values[index].value().to<ua::NodeId>();
        if (!statusOf(values[index]).is_bad() && id.is_good())
        {
          out.id = id.value();
        }
        ++index;
      }
      if (haveTime)
      {
        auto time = values[index].value().to<ua::DateTime>();
        if (!statusOf(values[index]).is_bad() && time.is_good())
        {
          out.transitionTime = time.value();  // CL-SM-004  -  the authoritative TransitionTime Property
        }
        ++index;
      }
      deliver<TransitionVariableResult>(
        executor, std::move(callback), ua::detail::held(std::move(out), answered));
    });
}

void StateMachineHandle::current_state_is_async(
  ua::NodeId expectedStateId, std::function<void(ua::Result<bool>)> callback) noexcept
{
  using R = ua::Result<bool>;
  if (!mState)
  {
    callback(R{ua::Status::BadInvalidState,
      ua::make_error_detail("StateMachineMovedFrom",
        "current_state_is issued on a moved-from StateMachineHandle",
        std::string{currentStateIsSource})});
    return;
  }
  auto lockedWireOps = mState->wireOps.lock();
  if (!lockedWireOps)
  {
    deliver<R>(mState->executor,
      std::move(callback),
      R{ua::Status::BadConnectionClosed,
        ua::make_error_detail("StateMachineConnectionGone",
          "the Connection was dropped before the CurrentState.Id read could be issued",
          std::string{connClosedSource})});
    return;
  }
  auto executor = mState->executor;
  std::weak_ptr<detail::StateMachineHandleState> weak = mState;
  ua::ReadRequest read;
  read.nodes_to_read().push_back(make_attribute_read_value(mState->currentStateIdNodeId, valueAttribute));
  lockedWireOps->read_async(std::move(read),
    [weak, executor, expectedStateId = std::move(expectedStateId), callback = std::move(callback)](
      ua::Result<ua::ReadResponse> response) mutable
    {
      if (!weak.lock())
      {
        return;  // handle dropped mid-flight: bail (UAF guard, section 9.8.3)
      }
      if (!response.has_value())
      {
        deliver<R>(executor,
          std::move(callback),
          R{response.status_code(),
            ua::make_error_detail("StateMachineCurrentStateIdReadFailed",
              "the Read of CurrentState.Id failed",
              std::string{currentStateIsSource},
              response.shared_detail())});
        return;
      }
      // Facade flatten: the wire funnel returns the ReadResponse verbatim; a bad ResponseHeader.serviceResult
      // is a service-level failure the facade surfaces as bad, preserving the exact service status +
      // ErrorDetail. Without this an empty results[] masks the fault as Bad_UnexpectedError (empty-results
      // branch below).
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        deliver<R>(executor,
          std::move(callback),
          R{serviceResult,
            ua::make_error_detail("StateMachineCurrentStateIdServiceFault",
              "the Read of CurrentState.Id returned a service-level fault",
              std::string{currentStateIsSource},
              serviceResult)});
        return;
      }
      auto& values = response.value().results();
      if (values.empty())
      {
        deliver<R>(executor,
          std::move(callback),
          R{ua::Status::BadUnexpectedError,
            ua::make_error_detail("StateMachineCurrentStateIdReadEmpty",
              "the server returned a Good Read response with no result",
              std::string{currentStateIsSource})});
        return;
      }
      // The answer comes with the Read's code: the ServiceResult and the Id's status combined
      // (ua::detail::combined_status). A Bad code, or one that is not Good on a null Id, is answered without
      // a value; the identity walks below decide internally and use only Good answers.
      const ua::StatusCode answered =
        ua::detail::combined_status(ua::detail::combined_status(response.status_code(), serviceResult),
          values[0].status().value_or(ua::StatusCode{ua::Status::Good}));
      if (answered.is_bad())
      {
        deliver<R>(executor,
          std::move(callback),
          R{answered,
            ua::make_error_detail("StateMachineCurrentStateIdReadBad",
              "the Read of CurrentState.Id returned a Bad value status",
              std::string{currentStateIsSource},
              answered)});
        return;
      }
      if (!answered.is_good() && values[0].value().empty())
      {
        deliver<R>(executor, std::move(callback), R{answered});
        return;
      }
      auto currentId = values[0].value().to<ua::NodeId>();
      if (!currentId.is_good())
      {
        if (values[0].value().empty())
        {
          // An empty / null CurrentState.Id Value is the server's valid "no active state" answer (Part 5):
          // the machine simply is not in the expected state -> Good/false, not a decode error. Only a Value
          // that holds a genuinely non-NodeId type is an undecodable Bad.
          deliver<R>(executor, std::move(callback), ua::detail::held(false, answered));
          return;
        }
        deliver<R>(executor,
          std::move(callback),
          R{currentId.status_code(),
            ua::make_error_detail("StateMachineCurrentStateIdDecode",
              "the CurrentState.Id Value did not decode to a NodeId",
              std::string{currentStateIsSource},
              currentId.shared_detail())});
        return;
      }
      // The common compliant case needs no additional wire work: CurrentState.Id already equals the
      // supertype-origin NodeId supplied by the caller.
      if (currentId.value() == expectedStateId)
      {
        deliver<R>(executor, std::move(callback), ua::detail::held(true, answered));
        return;
      }

      // CL-SM-006: a caller may hold the replicated State Object on a subtype while CurrentState.Id names
      // the Object where the state was first defined. Resolve BOTH identities through their owning
      // ObjectType's inverse HasSubtype chain, matching the mandated same BrowseName replica at each parent
      // (Part 16 sections 4.4.6 and 4.4.18), then compare the origins.
      auto state = weak.lock();
      if (!state)
      {
        return;
      }
      auto identityWireOps = state->wireOps.lock();
      if (!identityWireOps)
      {
        deliver<R>(executor,
          std::move(callback),
          R{ua::Status::BadConnectionClosed,
            ua::make_error_detail("StateMachineConnectionGone",
              "the Connection was dropped before state identity resolution could be issued",
              std::string{connClosedSource})});
        return;
      }
      auto wireOpsForExpected = identityWireOps;
      normalize_state_identity(std::move(identityWireOps),
        std::move(currentId).value(),
        std::string{currentStateIsSource},
        [weak,
          wireOpsForExpected = std::move(wireOpsForExpected),
          executor,
          answered,
          expectedStateId = std::move(expectedStateId),
          callback = std::move(callback)](StateIdentityResult currentOrigin) mutable
        {
          if (!weak.lock())
          {
            return;
          }
          if (!currentOrigin.is_good())
          {
            deliver<R>(executor,
              std::move(callback),
              R{currentOrigin.status_code(),
                ua::make_error_detail("StateMachineCurrentIdentityResolveFailed",
                  "resolving CurrentState.Id to its first type-hierarchy definition failed",
                  std::string{currentStateIsSource},
                  currentOrigin.shared_detail())});
            return;
          }
          const ua::NodeId normalizedCurrent = std::move(currentOrigin).value();
          normalize_state_identity(std::move(wireOpsForExpected),
            std::move(expectedStateId),
            std::string{currentStateIsSource},
            [weak, executor, answered, normalizedCurrent, callback = std::move(callback)](
              StateIdentityResult expectedOrigin) mutable
            {
              if (!weak.lock())
              {
                return;
              }
              if (!expectedOrigin.is_good())
              {
                deliver<R>(executor,
                  std::move(callback),
                  R{expectedOrigin.status_code(),
                    ua::make_error_detail("StateMachineExpectedIdentityResolveFailed",
                      "resolving the expected State Id to its first type-hierarchy definition failed",
                      std::string{currentStateIsSource},
                      expectedOrigin.shared_detail())});
                return;
              }
              deliver<R>(executor,
                std::move(callback),
                ua::detail::held(normalizedCurrent == expectedOrigin.value(), answered));
            });
        });
    });
}

ua::NodeId StateMachineHandle::machine_id() const noexcept
{
  return mState ? mState->machineId : ua::NodeId{};
}

// ============================================================================
// FiniteStateMachineHandle
// ============================================================================

FiniteStateMachineHandle::FiniteStateMachineHandle(
  std::shared_ptr<detail::FiniteStateMachineHandleState> state)
  : StateMachineHandle(std::move(state))
{}

detail::FiniteStateMachineHandleState* FiniteStateMachineHandle::finite_state() const noexcept
{
  // The concrete object is always at least a FiniteStateMachineHandleState (guaranteed by the factory /
  // test-access ctors), so the down-cast is sound; a sentinel handle has a null state.
  return static_cast<detail::FiniteStateMachineHandleState*>(mState.get());
}

std::vector<AvailableState> FiniteStateMachineHandle::available_states() const noexcept
{
  auto* state = finite_state();
  if (!state)
  {
    return {};
  }
  // Atomically load the published snapshot then copy its (immutable) pointee: a concurrent refresh only
  // ever swaps the pointer, so the reader is never torn (client design section 8.18.2).
  return *state->availableStates.load();
}

std::vector<AvailableTransition> FiniteStateMachineHandle::available_transitions() const noexcept
{
  auto* state = finite_state();
  if (!state)
  {
    return {};
  }
  return *state->availableTransitions.load();
}

TopologyProvenance FiniteStateMachineHandle::topology_provenance() const noexcept
{
  auto* state = finite_state();
  if (!state)
  {
    return {};  // a sentinel published nothing
  }
  return *state->provenance.load();
}

void FiniteStateMachineHandle::refresh_topology_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  auto* state = finite_state();
  if (!state)
  {
    callback(ua::VoidResult{ua::Status::BadInvalidState,
      ua::make_error_detail("StateMachineMovedFrom",
        "refresh_topology issued on a moved-from FiniteStateMachineHandle",
        std::string{topologySource})});
    return;
  }
  auto lockedWireOps = state->wireOps.lock();
  if (!lockedWireOps)
  {
    deliver<ua::VoidResult>(state->executor,
      std::move(callback),
      ua::VoidResult{ua::Status::BadConnectionClosed,
        ua::make_error_detail("StateMachineConnectionGone",
          "the Connection was dropped before the topology could be refreshed",
          std::string{connClosedSource})});
    return;
  }
  auto executor = state->executor;
  // Weak-capture the finite state via its base shared_ptr so a dropped handle bails cleanly (section 9.8.3).
  std::weak_ptr<detail::StateMachineHandleState> weak = mState;
  resolve_topology(std::move(lockedWireOps),
    state->machineId,
    std::string{topologySource},
    state->logger,
    [weak, executor, callback = std::move(callback)](ua::Result<Topology> topology) mutable
    {
      auto locked = weak.lock();
      if (!locked)
      {
        return;  // handle dropped mid-flight: bail (UAF guard, section 9.8.3)
      }
      if (!topology.is_good())
      {
        deliver<ua::VoidResult>(
          executor, std::move(callback), ua::VoidResult{topology.status_code(), topology.shared_detail()});
        return;
      }
      // The live object is a FiniteStateMachineHandleState (or subtype); atomically publish the fresh
      // snapshot so every copy of the handle observes the refresh without tearing against a concurrent
      // accessor.
      auto* finite = static_cast<detail::FiniteStateMachineHandleState*>(locked.get());
      publish_topology(*finite, std::move(topology.value()));
      deliver<ua::VoidResult>(executor, std::move(callback), ua::VoidResult{});
    });
}

// ============================================================================
// ProgramStateMachineHandle
// ============================================================================

ProgramStateMachineHandle::ProgramStateMachineHandle(
  std::shared_ptr<detail::ProgramStateMachineHandleState> state, bool skipLocalStateCheck)
  : FiniteStateMachineHandle(std::move(state)), mSkipLocalStateCheck(skipLocalStateCheck)
{}

detail::ProgramStateMachineHandleState* ProgramStateMachineHandle::program_state() const noexcept
{
  return static_cast<detail::ProgramStateMachineHandleState*>(mState.get());
}

ProgramStateMachineHandle ProgramStateMachineHandle::skip_local_state_check() const noexcept
{
  // Returns a copy that shares the same resolution but flips the per-handle bypass flag (CL-SM-009). The flag
  // is per-handle, not stored in the shared state, so the original handle's behaviour is unchanged.
  ProgramStateMachineHandle copy{*this};
  copy.mSkipLocalStateCheck = true;
  return copy;
}

namespace
{

/// Reads the @p methodNode `Executable` Attribute over @p interface and delivers the decoded boolean inline
/// (the caller delivers on the executor). Used by both `can_invoke_async` and `invoke_async`'s pre-flight.
void read_executable(const std::shared_ptr<ua::client::detail::WireOps>& lockedWireOps,
  const ua::NodeId& methodNode, std::function<void(ua::Result<bool>)> done)
{
  ua::ReadRequest read;
  read.nodes_to_read().push_back(make_attribute_read_value(methodNode, executableAttribute));
  lockedWireOps->read_async(std::move(read),
    [done = std::move(done)](ua::Result<ua::ReadResponse> response) mutable
    {
      if (!response.has_value())
      {
        done(ua::Result<bool>{response.status_code(),
          ua::make_error_detail("StateMachineExecutableReadFailed",
            "the Read of the method's Executable Attribute failed",
            std::string{executableSource},
            response.shared_detail())});
        return;
      }
      // Facade flatten: the wire funnel returns the ReadResponse verbatim; a bad ResponseHeader.serviceResult
      // is a service-level failure the facade surfaces as bad, preserving the exact service status +
      // ErrorDetail. Without this an empty results[] masks the fault as Bad_UnexpectedError (empty-results
      // branch below).
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        done(ua::Result<bool>{serviceResult,
          ua::make_error_detail("StateMachineExecutableServiceFault",
            "the Read of the method's Executable Attribute returned a service-level fault",
            std::string{executableSource},
            serviceResult)});
        return;
      }
      auto& values = response.value().results();
      if (values.empty())
      {
        done(ua::Result<bool>{ua::Status::BadUnexpectedError,
          ua::make_error_detail("StateMachineExecutableReadEmpty",
            "the server returned a Good Read response with no result for the Executable Attribute",
            std::string{executableSource})});
        return;
      }
      // The flag comes with the Read's code: the ServiceResult and the Attribute's status combined
      // (ua::detail::combined_status). A Bad code, or one that is not Good on a null value, is answered
      // without a flag.
      const ua::StatusCode answered =
        ua::detail::combined_status(ua::detail::combined_status(response.status_code(), serviceResult),
          values[0].status().value_or(ua::StatusCode{ua::Status::Good}));
      if (answered.is_bad())
      {
        done(ua::Result<bool>{answered,
          ua::make_error_detail("StateMachineExecutableReadBad",
            "the Read of the method's Executable Attribute returned a Bad value status",
            std::string{executableSource},
            answered)});
        return;
      }
      if (!answered.is_good() && values[0].value().empty())
      {
        done(ua::Result<bool>{answered});
        return;
      }
      auto executable = values[0].value().to<bool>();
      if (!executable.is_good())
      {
        done(ua::Result<bool>{executable.status_code(),
          ua::make_error_detail("StateMachineExecutableDecode",
            "the method's Executable Attribute did not decode to a Boolean",
            std::string{executableSource},
            executable.shared_detail())});
        return;
      }
      done(ua::detail::held(executable.value(), answered));
    });
}

/// Issues the wire `Call` for @p method (object = @p machineId, method = @p methodNode) with @p args verbatim
/// and delivers the server `CallMethodResult` verbatim on @p executor (a Bad per-call status chains beneath
/// the method-call source). @p state is weak-captured for the UAF bail.
void do_method_call(const std::shared_ptr<ua::client::detail::WireOps>& lockedWireOps,
  std::weak_ptr<ua::client::detail::StateMachineHandleState> weak, boost::asio::any_io_executor executor,
  const ua::NodeId& machineId, const ua::NodeId& methodNode, std::vector<ua::Variant> args,
  std::function<void(ua::Result<ua::CallMethodResult>)> callback)
{
  using R = ua::Result<ua::CallMethodResult>;
  ua::CallMethodRequest methodRequest;
  methodRequest.object_id() = machineId;
  methodRequest.method_id() = methodNode;
  for (auto& arg : args)
  {
    methodRequest.input_arguments().push_back(std::move(arg));  // CL-SM-008  -  caller's args verbatim
  }
  ua::CallRequest request;
  request.methods_to_call().push_back(std::move(methodRequest));
  lockedWireOps->call_async(std::move(request),
    [weak, executor, callback = std::move(callback)](ua::Result<ua::CallResponse> response) mutable
    {
      if (!weak.lock())
      {
        return;  // handle dropped mid-flight: bail (UAF guard, section 9.8.3)
      }
      if (!response.has_value())
      {
        deliver<R>(executor,
          std::move(callback),
          R{response.status_code(),
            ua::make_error_detail("StateMachineCallFailed",
              "the method Call service failed",
              std::string{methodCallSource},
              response.shared_detail())});
        return;
      }
      // Facade flatten: the wire funnel returns the CallResponse verbatim; a bad ResponseHeader.serviceResult
      // is a service-level failure the facade surfaces as bad, preserving the exact service status +
      // ErrorDetail. Without this an empty results[] masks the fault as Bad_UnexpectedError (empty-results
      // branch below).
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        deliver<R>(executor,
          std::move(callback),
          R{serviceResult,
            ua::make_error_detail("StateMachineCallServiceFault",
              "the Call service returned a service fault",
              std::string{methodCallSource},
              serviceResult)});
        return;
      }
      const auto& results = response.value().results();
      if (results.empty())
      {
        deliver<R>(executor,
          std::move(callback),
          R{ua::Status::BadUnexpectedError,
            ua::make_error_detail("StateMachineCallEmpty",
              "the server returned a Good Call response with no result",
              std::string{methodCallSource})});
        return;
      }
      ua::CallMethodResult result = results[0];
      if (result.status_code().is_bad())
      {
        // CL-SM-008  -  surface the server's per-call status verbatim (e.g. Bad_ArgumentsMissing), tagged
        // with the method-call source and chaining any server detail.
        deliver<R>(executor,
          std::move(callback),
          R{result.status_code(),
            ua::make_error_detail("StateMachineCallRejected",
              "the server rejected the method Call",
              std::string{methodCallSource},
              response.shared_detail())});
        return;
      }
      // The CallMethodResult comes with the Call's code: the ServiceResult and the Method's statusCode
      // combined (ua::detail::combined_status), so a Good subcode or an Uncertain code reaches the caller on
      // the Result as well as in the CallMethodResult.
      const ua::StatusCode answered = ua::detail::combined_status(
        ua::detail::combined_status(response.status_code(), serviceResult), result.status_code());
      deliver<R>(executor, std::move(callback), ua::detail::held(std::move(result), answered));
    });
}

}  // namespace

void ProgramStateMachineHandle::can_invoke_async(
  ProgramMethod method, std::function<void(ua::Result<bool>)> callback) noexcept
{
  using R = ua::Result<bool>;
  auto* state = program_state();
  if (!state)
  {
    callback(R{ua::Status::BadInvalidState,
      ua::make_error_detail("StateMachineMovedFrom",
        "can_invoke issued on a moved-from ProgramStateMachineHandle",
        std::string{executableSource})});
    return;
  }
  auto lockedWireOps = state->wireOps.lock();
  if (!lockedWireOps)
  {
    deliver<R>(state->executor,
      std::move(callback),
      R{ua::Status::BadConnectionClosed,
        ua::make_error_detail("StateMachineConnectionGone",
          "the Connection was dropped before the Executable read could be issued",
          std::string{connClosedSource})});
    return;
  }
  auto methodNodeIt = state->methodNodeIds.find(std::string{method_browse_name(method)});
  if (methodNodeIt == state->methodNodeIds.end())
  {
    deliver<R>(state->executor,
      std::move(callback),
      R{ua::Status::BadNotFound,
        ua::make_error_detail("StateMachineMethodNotResolved",
          "the program state machine does not expose the requested method",
          std::string{methodResolutionSource})});
    return;
  }
  auto executor = state->executor;
  std::weak_ptr<detail::StateMachineHandleState> weak = mState;
  read_executable(lockedWireOps,
    methodNodeIt->second,
    [weak, executor, callback = std::move(callback)](R executable) mutable
    {
      if (!weak.lock())
      {
        return;  // handle dropped mid-flight: bail (UAF guard, section 9.8.3)
      }
      deliver<R>(executor, std::move(callback), std::move(executable));
    });
}

void ProgramStateMachineHandle::invoke_async(ProgramMethod method, std::vector<ua::Variant> args,
  std::function<void(ua::Result<ua::CallMethodResult>)> callback) noexcept
{
  using R = ua::Result<ua::CallMethodResult>;
  auto* state = program_state();
  if (!state)
  {
    callback(R{ua::Status::BadInvalidState,
      ua::make_error_detail("StateMachineMovedFrom",
        "invoke issued on a moved-from ProgramStateMachineHandle",
        std::string{methodCallSource})});
    return;
  }
  auto lockedWireOps = state->wireOps.lock();
  if (!lockedWireOps)
  {
    deliver<R>(state->executor,
      std::move(callback),
      R{ua::Status::BadConnectionClosed,
        ua::make_error_detail("StateMachineConnectionGone",
          "the Connection was dropped before the method could be invoked",
          std::string{connClosedSource})});
    return;
  }
  auto methodNodeIt = state->methodNodeIds.find(std::string{method_browse_name(method)});
  if (methodNodeIt == state->methodNodeIds.end())
  {
    deliver<R>(state->executor,
      std::move(callback),
      R{ua::Status::BadNotFound,
        ua::make_error_detail("StateMachineMethodNotResolved",
          "the program state machine does not expose the requested method",
          std::string{methodResolutionSource})});
    return;
  }
  const ua::NodeId methodNode = methodNodeIt->second;
  const ua::NodeId machineId = state->machineId;
  const ua::NodeId currentStateIdNodeId = state->currentStateIdNodeId;
  auto executor = state->executor;
  const bool skipCheck = mSkipLocalStateCheck;
  std::weak_ptr<detail::StateMachineHandleState> weak = mState;

  // Step 1 (CL-SM-007): Read the method's Executable Attribute; false -> Bad_NotExecutable, no wire Call.
  read_executable(lockedWireOps,
    methodNode,
    [lockedWireOps,
      weak,
      executor,
      method,
      args = std::move(args),
      methodNode,
      machineId,
      currentStateIdNodeId,
      skipCheck,
      callback = std::move(callback)](ua::Result<bool> executable) mutable
    {
      auto locked = weak.lock();
      if (!locked)
      {
        return;  // handle dropped mid-flight: bail (UAF guard, section 9.8.3)
      }
      // The SDK decides whether to Call from the flag, so only a Good answer is used: an Uncertain one is
      // refused (ReadAnswerUncertain), a Bad one is passed on.
      if (!executable.is_good())
      {
        deliver<R>(executor,
          std::move(callback),
          R{ua::client::detail::answer_refused(
            executable.status_code(), "ReadAnswerUncertain", executableSource)});
        return;
      }
      if (!executable.value())
      {
        deliver<R>(executor,
          std::move(callback),
          R{ua::Status::BadNotExecutable,
            ua::make_error_detail("StateMachineMethodNotExecutable",
              "the method's Executable Attribute is false; the Call was not issued",
              std::string{notExecutableSource})});
        return;
      }
      if (skipCheck)
      {
        // CL-SM-009 override: bypass the local matrix and Call directly.
        do_method_call(
          lockedWireOps, weak, executor, machineId, methodNode, std::move(args), std::move(callback));
        return;
      }
      // Step 2 (CL-SM-009): Read CurrentState.Id, map to a ProgramState, and check the local matrix.
      ua::ReadRequest stateRead;
      stateRead.nodes_to_read().push_back(make_attribute_read_value(currentStateIdNodeId, valueAttribute));
      lockedWireOps->read_async(std::move(stateRead),
        [lockedWireOps,
          weak,
          executor,
          method,
          args = std::move(args),
          methodNode,
          machineId,
          callback = std::move(callback)](ua::Result<ua::ReadResponse> stateResponse) mutable
        {
          if (!weak.lock())
          {
            return;  // handle dropped mid-flight: bail (UAF guard, section 9.8.3)
          }
          // The SDK decides whether to Call from CurrentState.Id, so only a Good answer is used: an Uncertain
          // one (to the service, its ServiceResult or the value) is refused (ReadAnswerUncertain).
          if (stateResponse.is_uncertain())
          {
            deliver<R>(executor,
              std::move(callback),
              R{ua::client::detail::uncertain_answer_refused(
                stateResponse.status_code(), "ReadAnswerUncertain", stateMismatchSource)});
            return;
          }
          if (!stateResponse.has_value())
          {
            deliver<R>(executor,
              std::move(callback),
              R{stateResponse.status_code(),
                ua::make_error_detail("StateMachineCurrentStateIdReadFailed",
                  "the Read of CurrentState.Id for the matrix check failed",
                  std::string{stateMismatchSource},
                  stateResponse.shared_detail())});
            return;
          }
          // Facade flatten: the wire funnel returns the ReadResponse verbatim; a bad
          // ResponseHeader.serviceResult is a service-level failure the facade surfaces as bad, preserving
          // the exact service status + ErrorDetail. Without this an empty results[] masks the fault as
          // Bad_UnexpectedError (empty-results branch below).
          const ua::StatusCode serviceResult = stateResponse.value().response_header().service_result();
          if (serviceResult.is_bad())
          {
            deliver<R>(executor,
              std::move(callback),
              R{serviceResult,
                ua::make_error_detail("StateMachineCurrentStateIdReadServiceFault",
                  "the CurrentState.Id Read returned a service-level fault",
                  std::string{stateMismatchSource},
                  serviceResult)});
            return;
          }
          if (serviceResult.is_uncertain())
          {
            deliver<R>(executor,
              std::move(callback),
              R{ua::client::detail::uncertain_answer_refused(
                serviceResult, "ReadAnswerUncertain", stateMismatchSource)});
            return;
          }
          auto& values = stateResponse.value().results();
          if (values.empty())
          {
            deliver<R>(executor,
              std::move(callback),
              R{ua::Status::BadUnexpectedError,
                ua::make_error_detail("StateMachineCurrentStateIdReadEmpty",
                  "the CurrentState.Id Read returned a Good response with no result",
                  std::string{stateMismatchSource})});
            return;
          }
          const ua::StatusCode idStatus = values[0].status().value_or(ua::StatusCode{ua::Status::Good});
          if (idStatus.is_uncertain())
          {
            deliver<R>(executor,
              std::move(callback),
              R{ua::client::detail::uncertain_answer_refused(
                idStatus, "ReadAnswerUncertain", stateMismatchSource)});
            return;
          }
          // A Bad CurrentState.Id holds no state, which the matrix treats as Unknown (a mismatch).
          const auto currentId = values[0].value().to<ua::NodeId>();
          const ProgramState current = idStatus.is_good() && currentId.is_good()
                                         ? program_state_of(currentId.value())
                                         : ProgramState::Unknown;
          if (!matrix_allows(method, current))
          {
            // CL-SM-009  -  not a valid cause FROM the current state; no wire Call.
            deliver<R>(executor,
              std::move(callback),
              R{ua::Status::BadInvalidState,
                ua::make_error_detail("StateMachineStateMethodMismatch",
                  "the method is not a valid transition cause from the machine's current state",
                  std::string{stateMismatchSource})});
            return;
          }
          // Step 3: matrix satisfied -> Call.
          do_method_call(
            lockedWireOps, weak, executor, machineId, methodNode, std::move(args), std::move(callback));
        });
    });
}

// ============================================================================
// Blocking wrappers
//
// One blocking_call per asynchronous operation, the shape every tier-2 facade uses
// (ua_sync_wait.h): the throwing form returns the value of a Good `try_*_sync(...)` result
// (ua::detail::good_value) and throws otherwise, and the non-throwing form arms the existing `*_async`. No
// operation is reimplemented here.
//
// Each blocks the calling thread until the completion runs; called from the executor thread that
// would run it, each refuses with Bad_WouldBlock before starting anything.
// ============================================================================

StateVariable StateMachineHandle::current_state_sync()
{
  return ua::detail::good_value(try_current_state_sync());
}

ua::Result<StateVariable> StateMachineHandle::try_current_state_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<StateVariable>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this](auto completion) mutable { current_state_async(std::move(completion)); });
}

TransitionVariable StateMachineHandle::last_transition_sync()
{
  return ua::detail::good_value(try_last_transition_sync());
}

ua::Result<TransitionVariable> StateMachineHandle::try_last_transition_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<TransitionVariable>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this](auto completion) mutable { last_transition_async(std::move(completion)); });
}

bool StateMachineHandle::current_state_is_sync(ua::NodeId expectedStateId)
{
  return ua::detail::good_value(try_current_state_is_sync(std::move(expectedStateId)));
}

ua::Result<bool> StateMachineHandle::try_current_state_is_sync(ua::NodeId expectedStateId) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<bool>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this, expectedStateId = std::move(expectedStateId)](auto completion) mutable
    { current_state_is_async(std::move(expectedStateId), std::move(completion)); });
}

void FiniteStateMachineHandle::refresh_topology_sync()
{
  try_refresh_topology_sync().value();
}

ua::VoidResult FiniteStateMachineHandle::try_refresh_topology_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this](auto completion) mutable { refresh_topology_async(std::move(completion)); });
}

bool ProgramStateMachineHandle::can_invoke_sync(ProgramMethod method)
{
  return ua::detail::good_value(try_can_invoke_sync(std::move(method)));
}

ua::Result<bool> ProgramStateMachineHandle::try_can_invoke_sync(ProgramMethod method) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<bool>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this, method = std::move(method)](auto completion) mutable
    { can_invoke_async(std::move(method), std::move(completion)); });
}

ua::CallMethodResult ProgramStateMachineHandle::invoke_sync(
  ProgramMethod method, std::vector<ua::Variant> args)
{
  return ua::detail::good_value(try_invoke_sync(std::move(method), std::move(args)));
}

ua::Result<ua::CallMethodResult> ProgramStateMachineHandle::try_invoke_sync(
  ProgramMethod method, std::vector<ua::Variant> args) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::CallMethodResult>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this, method = std::move(method), args = std::move(args)](auto completion) mutable
    { invoke_async(std::move(method), std::move(args), std::move(completion)); });
}

StateMachineHandle StateMachineAccessor::state_machine_sync(ua::NodeId machineId)
{
  return ua::detail::good_value(try_state_machine_sync(std::move(machineId)));
}

ua::Result<StateMachineHandle> StateMachineAccessor::try_state_machine_sync(ua::NodeId machineId) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<StateMachineHandle>>(mExecutor,
    [this, machineId = std::move(machineId)](auto completion) mutable
    { state_machine_async(std::move(machineId), std::move(completion)); });
}

FiniteStateMachineHandle StateMachineAccessor::finite_state_machine_sync(ua::NodeId machineId)
{
  return ua::detail::good_value(try_finite_state_machine_sync(std::move(machineId)));
}

ua::Result<FiniteStateMachineHandle> StateMachineAccessor::try_finite_state_machine_sync(
  ua::NodeId machineId) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<FiniteStateMachineHandle>>(mExecutor,
    [this, machineId = std::move(machineId)](auto completion) mutable
    { finite_state_machine_async(std::move(machineId), std::move(completion)); });
}

ProgramStateMachineHandle StateMachineAccessor::program_state_machine_sync(ua::NodeId machineId)
{
  return ua::detail::good_value(try_program_state_machine_sync(std::move(machineId)));
}

ua::Result<ProgramStateMachineHandle> StateMachineAccessor::try_program_state_machine_sync(
  ua::NodeId machineId) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ProgramStateMachineHandle>>(mExecutor,
    [this, machineId = std::move(machineId)](auto completion) mutable
    { program_state_machine_async(std::move(machineId), std::move(completion)); });
}

ua::client::MonitoredItem StateMachineAccessor::subscribe_transitions_sync(
  ua::NodeId machineId, TransitionEventCallback onTransition)
{
  return ua::detail::good_value(
    try_subscribe_transitions_sync(std::move(machineId), std::move(onTransition)));
}

ua::Result<ua::client::MonitoredItem> StateMachineAccessor::try_subscribe_transitions_sync(
  ua::NodeId machineId, TransitionEventCallback onTransition) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::client::MonitoredItem>>(mExecutor,
    [this, machineId = std::move(machineId), onTransition = std::move(onTransition)](auto completion) mutable
    { subscribe_transitions_async(std::move(machineId), std::move(onTransition), std::move(completion)); });
}

}  // namespace ua::client
