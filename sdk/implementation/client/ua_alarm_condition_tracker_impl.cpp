// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Implementation of the no-own-strand @ref ua::client::detail::AlarmConditionTrackerImpl (client
///        design section 8.8): condition-map maintenance, the ConditionRefresh demultiplexer (collect-until-
///        RefreshEnd; re-entrant  to  Bad_RefreshInProgress), and the typed method wrappers.

#include "ua_alarm_condition_tracker_impl.h"

#include "ua_attribute_id.h"
#include "ua_browse_path.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_callback_safety.h"
#include "ua_client_answer_status.h"
#include "ua_client_observers.h"  // DataIntegrityKind (CL-AC-023/025)
#include "ua_connection_ops.h"
#include "ua_content_filter_element.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_filter_operator.h"
#include "ua_literal_operand.h"
#include "ua_localized_text.h"
#include "ua_method_id.h"
#include "ua_objecttype_id.h"
#include "ua_observer_sink.h"  // ObserverSink::fire_data_integrity_warning (CL-AC-023/025)
#include "ua_on_strand.h"
#include "ua_qualified_name.h"
#include "ua_read_request.h"
#include "ua_read_value_id.h"
#include "ua_referencetype_id.h"
#include "ua_relative_path_element.h"
#include "ua_simple_attribute_operand.h"
#include "ua_status.h"
#include "ua_to_result.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"

#include <boost/asio/post.hpp>

#include <fmt/format.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <string>
#include <string_view>
#include <utility>

namespace ua::client::detail
{

namespace
{

using ua::Result;
using ua::Status;
using ua::StatusCode;
using ua::VoidResult;

constexpr std::size_t alarmMetricNodeCount = 11;

ua::RelativePathElement metric_path_element(
  std::string_view name, ua::ReferenceTypeId referenceType = ua::ReferenceTypeId::HasComponent)
{
  ua::RelativePathElement element;
  element.reference_type_id() = ua::NodeId{referenceType};
  element.include_subtypes() = false;
  element.target_name() = ua::QualifiedName{0, name};
  return element;
}

ua::BrowsePath metric_browse_path(
  const ua::NodeId& object, std::initializer_list<ua::RelativePathElement> elements)
{
  ua::BrowsePath path;
  path.starting_node() = object;
  for (const auto& element : elements)
  {
    path.relative_path().elements().push_back(element);
  }
  return path;
}

ua::TranslateBrowsePathsToNodeIdsRequest build_metric_paths(const ua::NodeId& object)
{
  ua::TranslateBrowsePathsToNodeIdsRequest request;
  for (const std::string_view name : {"AlarmCount",
         "StartTime",
         "MaximumActiveState",
         "MaximumUnAck",
         "CurrentAlarmRate",
         "MaximumAlarmRate",
         "MaximumReAlarmCount",
         "AverageAlarmRate"})
  {
    request.browse_paths().push_back(metric_browse_path(object, {metric_path_element(name)}));
  }
  for (const std::string_view name : {"CurrentAlarmRate", "MaximumAlarmRate", "AverageAlarmRate"})
  {
    request.browse_paths().push_back(metric_browse_path(
      object, {metric_path_element(name), metric_path_element("Rate", ua::ReferenceTypeId::HasProperty)}));
  }
  return request;
}

ua::TranslateBrowsePathsToNodeIdsRequest build_metric_reset_path(const ua::NodeId& object)
{
  ua::TranslateBrowsePathsToNodeIdsRequest request;
  request.browse_paths().push_back(metric_browse_path(object, {metric_path_element("Reset")}));
  return request;
}

ua::TranslateBrowsePathsToNodeIdsRequest build_condition_property_path(
  const ua::NodeId& condition, const ua::QualifiedName& property)
{
  ua::RelativePathElement element;
  element.reference_type_id() = ua::NodeId{ua::ReferenceTypeId::HierarchicalReferences};
  element.include_subtypes() = true;
  element.target_name() = property;
  ua::TranslateBrowsePathsToNodeIdsRequest request;
  request.browse_paths().push_back(metric_browse_path(condition, {element}));
  return request;
}

/// The first Uncertain code of a TranslateBrowsePaths answer: the service's, its ServiceResult's or one
/// path's; plain Good when no part of the answer is Uncertain.
///
/// @param response The TranslateBrowsePaths answer.
/// @return The Uncertain code, or Good.
StatusCode uncertain_translation(const Result<ua::TranslateBrowsePathsToNodeIdsResponse>& response)
{
  if (!response.has_value())
  {
    return response.is_uncertain() ? response.status_code() : StatusCode{Status::Good};
  }
  const StatusCode serviceResult = response.value().response_header().service_result();
  if (serviceResult.is_uncertain())
  {
    return serviceResult;
  }
  for (const auto& result : response.value().results())
  {
    if (result.status_code().is_uncertain())
    {
      return result.status_code();
    }
  }
  return StatusCode{Status::Good};
}

/// The status a lookup the tracker acts on fails with when the TranslateBrowsePaths answer is not Good: an
/// Uncertain part (the service, its ServiceResult or one path) is refused with `ReferencesAnswerUncertain`, a
/// Bad service answer or ServiceResult is passed on. Plain Good otherwise; a Good subcode is consumed by the
/// lookup.
///
/// @param response The TranslateBrowsePaths answer.
/// @param source   The ErrorDetail source of a refusal.
/// @return The status to fail with, or Good.
StatusCode translation_refusal(
  const Result<ua::TranslateBrowsePathsToNodeIdsResponse>& response, std::string_view source)
{
  if (const StatusCode uncertain = uncertain_translation(response); uncertain.is_uncertain())
  {
    return uncertain_answer_refused(uncertain, "ReferencesAnswerUncertain", source);
  }
  if (!response.has_value())
  {
    return response.status_code();
  }
  const StatusCode serviceResult = response.value().response_header().service_result();
  if (serviceResult.is_bad())
  {
    return serviceResult;
  }
  return StatusCode{Status::Good};
}

// The tracker reads the Property this lookup finds, so only a Good answer is used (translation_refusal).
Result<ua::NodeId> resolved_condition_property(Result<ua::TranslateBrowsePathsToNodeIdsResponse> response)
{
  const StatusCode refusal = translation_refusal(response, "client.tier2.alarm_tracker.read_property");
  if (!refusal.is_good())
  {
    return Result<ua::NodeId>{refusal};
  }
  const auto& results = response.value().results();
  if (results.size() != 1)
  {
    return Result<ua::NodeId>{StatusCode{Status::BadUnexpectedError},
      ua::make_error_detail("AlarmPropertyResolutionCount",
        "TranslateBrowsePaths returned an unexpected result count for an Alarm property",
        "client.tier2.alarm_tracker.read_property")};
  }
  const auto& result = results[0];
  if (result.status_code().is_bad())
  {
    return Result<ua::NodeId>{result.status_code()};
  }
  if (result.targets().empty())
  {
    return Result<ua::NodeId>{StatusCode{Status::BadNoMatch},
      ua::make_error_detail("AlarmPropertyResolutionNoTarget",
        "the Alarm property browse path resolved to no target",
        "client.tier2.alarm_tracker.read_property")};
  }
  const auto& target = result.targets()[0].target_id();
  if (!target.is_local() || !target.namespace_uri().empty() || target.node_id().is_null())
  {
    return Result<ua::NodeId>{StatusCode{Status::BadNoMatch},
      ua::make_error_detail("AlarmPropertyResolutionNonLocal",
        "the Alarm property browse path did not resolve to a local node",
        "client.tier2.alarm_tracker.read_property")};
  }
  return Result<ua::NodeId>{target.node_id()};
}

// The tracker reads or calls the nodes this lookup finds, so only a Good answer is used
// (translation_refusal).
Result<std::vector<ua::NodeId>> resolved_metric_nodes(
  Result<ua::TranslateBrowsePathsToNodeIdsResponse> response, std::size_t expected)
{
  const StatusCode refusal = translation_refusal(response, "client.tier2.alarm_metrics.resolve");
  if (!refusal.is_good())
  {
    return Result<std::vector<ua::NodeId>>{refusal};
  }
  const auto& results = response.value().results();
  if (results.size() != expected)
  {
    return Result<std::vector<ua::NodeId>>{StatusCode{Status::BadUnexpectedError},
      ua::make_error_detail("AlarmMetricsResolutionCount",
        "TranslateBrowsePaths returned an unexpected result count for AlarmMetrics",
        "client.tier2.alarm_metrics.resolve")};
  }
  std::vector<ua::NodeId> nodes;
  nodes.reserve(expected);
  for (const auto& result : results)
  {
    if (result.status_code().is_bad())
    {
      return Result<std::vector<ua::NodeId>>{result.status_code()};
    }
    if (result.targets().empty())
    {
      return Result<std::vector<ua::NodeId>>{StatusCode{Status::BadNoMatch},
        ua::make_error_detail("AlarmMetricsResolutionNoTarget",
          "an AlarmMetrics browse path resolved to no target",
          "client.tier2.alarm_metrics.resolve")};
    }
    const auto& target = result.targets()[0].target_id();
    if (!target.is_local() || !target.namespace_uri().empty() || target.node_id().is_null())
    {
      return Result<std::vector<ua::NodeId>>{StatusCode{Status::BadNoMatch},
        ua::make_error_detail("AlarmMetricsResolutionNonLocal",
          "an AlarmMetrics browse path did not resolve to a local node",
          "client.tier2.alarm_metrics.resolve")};
    }
    nodes.push_back(target.node_id());
  }
  return Result<std::vector<ua::NodeId>>{std::move(nodes)};
}

// Flatten a Call response into a VoidResult, preserving ErrorDetail (section 8.8.6  -  the wrapper is the
// source tag). The result is the ServiceResult and the Method's statusCode combined
// (ua::detail::combined_status), so a Good subcode or an Uncertain code the server answers reaches the
// caller.
VoidResult flatten_call(Result<ua::CallResponse> result)
{
  if (!result.has_value())
  {
    return VoidResult{result.status_code(), result.shared_detail()};
  }
  const auto& response = result.value();
  const auto serviceResult = response.response_header().service_result();
  if (serviceResult.is_bad())
  {
    return VoidResult{serviceResult};
  }
  if (response.results().size() == 0)
  {
    // No per-method result (e.g. a permissive fake): the ServiceResult is the answer.
    return VoidResult{serviceResult};
  }
  return VoidResult{ua::detail::combined_status(serviceResult, response.results()[0].status_code())};
}

// Encode a comment per CL-AC-020: nullopt  to  NULL (empty) LocalizedText; Some  to  literal.
ua::Variant encode_comment(const std::optional<ua::LocalizedText>& comment)
{
  return ua::Variant{comment.value_or(ua::LocalizedText{})};
}

// Read a TwoStateVariable's Boolean from the spec-shaped two-segment path `[<State>, "Id"]` (Part 9): the
// single-segment `<State>` node's Value is the human-readable LocalizedText display name, NOT the Boolean the
// tracker reads. Decode is by-PATH via the additive EventNotification::field({...}) overload, so it is robust
// under composite-filter widening (a fixed positional slot would silently mis-decode as other hooks' select
// clauses shift the field order).
std::optional<bool> two_state_id(const EventNotification& event, std::string_view stateName)
{
  if (const auto field = event.field({stateName, "Id"}))
  {
    if (const auto decoded = field->to<bool>(); decoded.is_good())
    {
      return decoded.value();
    }
  }
  return std::nullopt;
}

// Read the ConditionId (CL-AC-002): the condition instance's OWN NodeId, carried by the EMPTY-browse-path
// SimpleAttributeOperand with attributeId == NodeId (Part 4 Table 133). It has no browse-name node, so it is
// found by its empty fieldPath, not by name  -  the single-segment `field("ConditionId")` never matched a
// spec-shaped server (there is no ConditionId child node), which is why distinct trunk conditions collapsed
// onto {null, empty}. Decode is best-effort: only accepted when it decodes to a NodeId.
std::optional<ua::NodeId> condition_id_from_empty_path(const EventNotification& event)
{
  for (std::size_t i = 0; i < event.fieldPaths.size() && i < event.fields.size(); ++i)
  {
    if (const auto& conditionField = event.fields[i];
        event.fieldPaths[i].empty() && conditionField.has_value())
    {
      if (const auto decoded = conditionField.value().to<ua::NodeId>(); decoded.is_good())
      {
        return decoded.value();
      }
    }
  }
  return std::nullopt;
}

// The tracker's hook: forwards the subscriber's on-strand feed to the tracker (weak). Every method is called
// ON the subscriber/tracker strand, so it forwards directly (no re-post).
class TrackerHookImpl : public EventTrackerHook
{
public:
  explicit TrackerHookImpl(std::weak_ptr<AlarmConditionTrackerImpl> tracker) : mTracker(std::move(tracker))
  {}

  void on_event(const EventNotification& notification) override
  {
    if (auto tracker = mTracker.lock())
    {
      tracker->handle_event_on_strand(notification);
    }
  }

  ua::EventFilter filter_contribution() const override
  {
    if (auto tracker = mTracker.lock())
    {
      return tracker->filter_contribution_on_strand();
    }
    return ua::EventFilter{};
  }

  void on_refresh_start_event(const EventNotification& notification) override
  {
    if (auto tracker = mTracker.lock())
    {
      tracker->handle_refresh_start_on_strand(notification);
    }
  }

  void on_refresh_end_event(const EventNotification& notification) override
  {
    if (auto tracker = mTracker.lock())
    {
      tracker->handle_refresh_end_on_strand(notification);
    }
  }

  void on_refresh_required_event(const EventNotification& notification) override
  {
    if (auto tracker = mTracker.lock())
    {
      tracker->handle_refresh_required_on_strand(notification);
    }
  }

  void on_first_event_after_attach() override
  {
    if (auto tracker = mTracker.lock())
    {
      tracker->handle_first_event_after_attach_on_strand();
    }
  }

  void on_backbone_recovered(BackboneRecoveryReason reason) override
  {
    if (auto tracker = mTracker.lock())
    {
      tracker->handle_backbone_recovered_on_strand(reason);
    }
  }

  void on_backbone_subscription_changed(std::uint32_t subscriptionId, std::uint32_t monitoredItemId) override
  {
    if (auto tracker = mTracker.lock())
    {
      tracker->set_backbone_ids(subscriptionId, monitoredItemId);
    }
  }

private:
  std::weak_ptr<AlarmConditionTrackerImpl> mTracker;
};

/// Reports a field that ARRIVED but did not convert to the type this decoder expects.
///
/// The decoder's shape - `if (field) { if (converted.is_good()) ... }` - makes "the server did not
/// send it" and "the server sent it as another type" indistinguishable: both leave the default, log
/// nothing, and set no status. A wrong expected type therefore fails on every event from every server
/// and reads exactly like a field the server does not publish.
///
/// This is deliberately a log line rather than a hard failure: a non-conforming peer must not break a
/// tracker that is otherwise working, but it must not be silent either.
void report_field_type_mismatch(
  const ua::Logger& logger, std::string_view field, std::string_view expectedType, const ua::Variant& actual)
{
  UA_UNUSED(actual);
  logger.warning({{"field", field}, {"expected_type", expectedType}},
    "Condition event field did not decode to the expected type; the value was ignored");
}

// Decode a condition event into a TrackedCondition. The datum for each field is read from the browse PATH the
// server carries it at (CL-AC-002/024/025): a TwoStateVariable's Boolean at `[<State>, "Id"]`, the
// ExclusiveLimit state at `["LimitState", "CurrentState"]`, and the ConditionId via the empty-browse-path
// NodeId operand. Every read is by-PATH (never by absolute slot index), so it stays correct under
// composite-filter widening (the subscriber merges multiple hooks' SelectClauses, shifting the tracker's
// field positions). Real leaf values whose node Value IS the datum (ConditionName, Retain, the four limit
// doubles, MaxTimeShelved) stay single-segment.
//
// The logger is the caller's: a type mismatch belongs in the log of the tracker whose event it is.
TrackedCondition decode_condition(const EventNotification& event, const ua::Logger& logger)
{
  TrackedCondition tc;
  tc.conditionTypeId = event.eventTypeId;
  tc.lastEventId = event.eventId;
  tc.severity = event.severity;
  tc.message = event.message;
  tc.time = event.time;
  tc.receiveTime = event.receiveTime;
  tc.sourceNode = event.sourceNode;
  tc.sourceName = event.sourceName;

  if (const auto conditionId = condition_id_from_empty_path(event))
  {
    tc.key.conditionId = *conditionId;
  }
  if (const auto branchId = event.field("BranchId"))
  {
    // OPC 10000-9: BranchId is a NodeId Property, Mandatory on ConditionType. A NULL NodeId is the
    // trunk. Asking for the wrong type here failed on every event from every server and, because a
    // failed conversion is indistinguishable from an absent field (see report_field_type_mismatch),
    // read exactly like "this server does not use branches" - which is a legitimate, common state.
    if (const auto decoded = branchId->to<ua::NodeId>(); decoded.is_good())
    {
      tc.key.branchId = decoded.value();
    }
    else
    {
      report_field_type_mismatch(logger, "BranchId", "NodeId", *branchId);
    }
  }
  if (const auto conditionName = event.field("ConditionName"))
  {
    if (const auto decoded = conditionName->to<ua::LocalizedText>(); decoded.is_good())
    {
      tc.conditionName = decoded.value();
    }
  }
  if (const auto conditionClassId = event.field("ConditionClassId"))
  {
    if (const auto decoded = conditionClassId->to<ua::NodeId>(); decoded.is_good())
    {
      tc.conditionClassId = decoded.value();
    }
  }
  if (const auto conditionClassName = event.field("ConditionClassName"))
  {
    if (const auto decoded = conditionClassName->to<ua::LocalizedText>(); decoded.is_good())
    {
      tc.conditionClassName = decoded.value();
    }
  }
  if (const auto retain = event.field("Retain"))
  {
    if (const auto decoded = retain->to<bool>(); decoded.is_good())
    {
      tc.retain = decoded.value();
    }
  }
  if (const auto enabled = two_state_id(event, "EnabledState"))
  {
    tc.enabledState.id = enabled;
  }
  if (const auto acked = two_state_id(event, "AckedState"))
  {
    TwoStateValue value;
    value.id = acked;
    tc.ackedState = value;
  }
  if (const auto confirmed = two_state_id(event, "ConfirmedState"))
  {
    TwoStateValue value;
    value.id = confirmed;
    tc.confirmedState = value;
  }
  if (const auto active = two_state_id(event, "ActiveState"))
  {
    TwoStateValue value;
    value.id = active;
    tc.activeState = value;
  }

  // ---- Limit-alarm fields, decoded BY-NAME and surfaced VERBATIM (CL-AC-023/024/025) ----
  // Decode is by-name (event.field), NOT positional, so these additive fields never disturb the base
  // decode above. An absent field leaves the member nullopt; a present one is surfaced exactly as received
  // (the tracker never corrects or drops an inconsistent value  -  it only additionally ADVISES).
  const auto decodeLimit = [&event](std::string_view name) -> std::optional<double>
  {
    if (const auto field = event.field(name))
    {
      if (const auto decoded = field->to<double>(); decoded.is_good())
      {
        return decoded.value();
      }
    }
    return std::nullopt;
  };
  tc.highHighLimit = decodeLimit("HighHighLimit");
  tc.highLimit = decodeLimit("HighLimit");
  tc.lowLimit = decodeLimit("LowLimit");
  tc.lowLowLimit = decodeLimit("LowLowLimit");
  tc.maxTimeShelved = decodeLimit("MaxTimeShelved");  // Double property; drives the timed_shelve pre-flight

  const auto decodeDuration = [&event](std::string_view name) -> std::optional<ua::Duration>
  {
    if (const auto field = event.field(name))
    {
      if (const auto decoded = field->to<ua::Duration>(); decoded.is_good())
      {
        return decoded.value();
      }
    }
    return std::nullopt;
  };
  const auto decodeBool = [&event](std::string_view name) -> std::optional<bool>
  {
    if (const auto field = event.field(name))
    {
      if (const auto decoded = field->to<bool>(); decoded.is_good())
      {
        return decoded.value();
      }
    }
    return std::nullopt;
  };
  tc.reAlarmTime = decodeDuration("ReAlarmTime");
  tc.onDelay = decodeDuration("OnDelay");
  tc.offDelay = decodeDuration("OffDelay");
  tc.audibleEnabled = decodeBool("AudibleEnabled");
  tc.firstInGroupFlag = decodeBool("FirstInGroupFlag");
  if (const auto field = event.field("ReAlarmRepeatCount"))
  {
    if (const auto decoded = field->to<std::int16_t>(); decoded.is_good())
    {
      tc.reAlarmRepeatCount = decoded.value();
    }
  }
  if (const auto field = event.field("AudibleSound"))
  {
    if (const auto decoded = field->to<ua::AudioDataType>(); decoded.is_good())
    {
      tc.audibleSound = decoded.value();
    }
  }
  if (const auto field = event.field("FirstInGroup"))
  {
    if (const auto decoded = field->to<ua::NodeId>(); decoded.is_good())
    {
      tc.firstInGroup = decoded.value();
    }
  }

  const auto decodeState = [&event](std::string_view name) -> std::optional<TwoStateValue>
  {
    if (const auto id = two_state_id(event, name))
    {
      TwoStateValue value;
      value.id = id;
      return value;
    }
    return std::nullopt;
  };
  tc.highHighState = decodeState("HighHighState");
  tc.highState = decodeState("HighState");
  tc.lowState = decodeState("LowState");
  tc.lowLowState = decodeState("LowLowState");

  // ExclusiveLimit CurrentState (CL-AC-024): the spec-shaped ExclusiveLimitStateMachine current state is at
  // the two-segment path ["LimitState", "CurrentState"] (a StateVariable's Value), not the single-segment
  // state-machine object node.
  if (const auto limitState = event.field({"LimitState", "CurrentState"}))
  {
    if (const auto decoded = limitState->to<ua::LocalizedText>(); decoded.is_good())
    {
      tc.exclusiveLimitState = decoded.value();
    }
  }

  // ---- Optional AlarmConditionType sub-states (CL-AC-016) ----
  // Each TwoStateVariable Boolean is read by-PATH from `[<State>, "Id"]` (same rule as the mandatory states);
  // `SuppressedOrShelved` is a plain single-segment Boolean; `ShelvingState.CurrentState` is a StateVariable
  // LocalizedText at the two-segment path. Absent  to  nullopt (distinct from a present `false`).
  tc.suppressedState = decodeState("SuppressedState");
  tc.outOfServiceState = decodeState("OutOfServiceState");
  tc.silenceState = decodeState("SilenceState");
  tc.latchedState = decodeState("LatchedState");
  if (const auto suppressedOrShelved = event.field("SuppressedOrShelved"))
  {
    if (const auto decoded = suppressedOrShelved->to<bool>(); decoded.is_good())
    {
      tc.suppressedOrShelved = decoded.value();
    }
  }
  if (const auto shelvingState = event.field({"ShelvingState", "CurrentState"}))
  {
    if (const auto decoded = shelvingState->to<ua::LocalizedText>(); decoded.is_good())
    {
      tc.shelvingState = decoded.value();
    }
  }

  // ---- Discrete / OffNormal / Discrepancy subtype payload (CL-AC-021) ----
  // EventType selects the typed union. The exact EventType remains separately surfaced; this classification
  // only supplies the inherited subtype property view. Mandatory server properties remain optional here so
  // a malformed/incomplete event is observable as absence rather than a fabricated default value.
  const auto decodeNodeId = [&event](std::string_view name) -> std::optional<ua::NodeId>
  {
    if (const auto field = event.field(name))
    {
      if (const auto decoded = field->to<ua::NodeId>(); decoded.is_good())
      {
        return decoded.value();
      }
    }
    return std::nullopt;
  };
  const ua::NodeId discrepancyType{ua::ObjectTypeId::DiscrepancyAlarmType};
  const ua::NodeId discreteType{ua::ObjectTypeId::DiscreteAlarmType};
  const bool offNormalFamily =
    tc.conditionTypeId == ua::NodeId{ua::ObjectTypeId::OffNormalAlarmType} ||
    tc.conditionTypeId == ua::NodeId{ua::ObjectTypeId::TripAlarmType} ||
    tc.conditionTypeId == ua::NodeId{ua::ObjectTypeId::SystemOffNormalAlarmType} ||
    tc.conditionTypeId == ua::NodeId{ua::ObjectTypeId::CertificateExpirationAlarmType};
  if (tc.conditionTypeId == discrepancyType)
  {
    DiscrepancyAlarmInfo info;
    info.targetValueNode = decodeNodeId("TargetValueNode");
    info.expectedTime = decodeDuration("ExpectedTime");
    info.tolerance = decodeLimit("Tolerance");
    tc.subtypeInfo = std::move(info);
  }
  else if (offNormalFamily)
  {
    tc.subtypeInfo = OffNormalAlarmInfo{decodeNodeId("NormalState")};
  }
  else if (tc.conditionTypeId == discreteType)
  {
    tc.subtypeInfo = DiscreteAlarmInfo{};
  }
  return tc;
}

// A single-segment SelectClause (the leaf's Value attribute) against an explicit typeDefinitionId  -  the
// type that DECLARES the field. `SuppressedOrShelved` (CL-AC-016) is declared on AlarmConditionType, so it
// selects with AlarmConditionType as the operand's type; the ConditionType leaves keep ConditionType.
ua::SimpleAttributeOperand make_condition_clause(ua::NodeId typeDefinitionId, std::string_view browseName)
{
  ua::SimpleAttributeOperand operand;
  operand.type_definition_id() = std::move(typeDefinitionId);
  operand.browse_path().push_back(ua::QualifiedName{0, std::string{browseName}});
  operand.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::Value);
  return operand;
}

// A single-segment SelectClause for a leaf declared by ConditionType.
ua::SimpleAttributeOperand make_condition_clause(std::string_view browseName)
{
  return make_condition_clause(ua::NodeId{ua::ObjectTypeId::ConditionType}, browseName);
}

ua::SimpleAttributeOperand make_condition_node_clause(
  ua::NodeId typeDefinitionId, std::string_view browseName)
{
  ua::SimpleAttributeOperand operand;
  operand.type_definition_id() = std::move(typeDefinitionId);
  operand.browse_path().push_back(ua::QualifiedName{0, std::string{browseName}});
  operand.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::NodeId);
  return operand;
}

// A MULTI-segment SelectClause (Part 9) against an explicit typeDefinitionId  -  the type that DECLARES the
// field. The AlarmConditionType sub-states (CL-AC-016 Suppressed/OutOfService/Silence/Latched /Id and
// ShelvingState/CurrentState) are declared on AlarmConditionType, so they select with AlarmConditionType;
// the ConditionType/AcknowledgeableConditionType states keep ConditionType. The server resolves the browse
// path against the concrete condition instance either way.
ua::SimpleAttributeOperand make_condition_clause(
  ua::NodeId typeDefinitionId, std::initializer_list<std::string_view> browsePath)
{
  ua::SimpleAttributeOperand operand;
  operand.type_definition_id() = std::move(typeDefinitionId);
  for (const std::string_view segment : browsePath)
  {
    operand.browse_path().push_back(ua::QualifiedName{0, std::string{segment}});
  }
  operand.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::Value);
  return operand;
}

// The ConditionId operand (CL-AC-002): an EMPTY browse path with attributeId == NodeId selects the condition
// instance's OWN NodeId (Part 4 Table 133). This is what distinguishes distinct trunk conditions, which
// otherwise collapse onto {null, empty}.
ua::SimpleAttributeOperand make_condition_id_clause()
{
  ua::SimpleAttributeOperand operand;
  operand.type_definition_id() = ua::NodeId{ua::ObjectTypeId::ConditionType};
  // no browse path  -  the instance node itself
  operand.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::NodeId);
  return operand;
}

// Render an optional limit threshold for the human-readable advisory message ("absent" when not carried).
std::string render_limit(const std::optional<double>& limit)
{
  return limit.has_value() ? fmt::format("{}", *limit) : std::string{"absent"};
}

// Render an optional NonExclusive limit state as active / inactive / absent for the advisory message.
std::string render_state(const std::optional<TwoStateValue>& state)
{
  if (!state.has_value())
  {
    return "absent";
  }
  return state->id == true ? "active" : "inactive";
}

}  // namespace

bool limit_inequality(const TrackedCondition& condition) noexcept
{
  // Project the PRESENT limits in canonical ascending order and require the projection is non-decreasing
  // (lowLow <= low <= high <= highHigh over whichever limits the event carried). An inversion between any two
  // consecutive present limits is a server-side data-integrity violation (CL-AC-023). Absent limits impose no
  // constraint. A NaN limit is treated as ABSENT for ordering: a NaN never advises on its own (every IEEE
  // comparison against it is false), and  -  critically  -  it must NOT advance `previous`, otherwise a NaN
  // sandwiched between two inverted real limits (e.g. lowLow=10, low=NaN, high=5) would sever the transitive
  // comparison chain and MASK the real 10 > 5 inversion (section 3.1 finding). Skipping NaN keeps `previous`
  // on the last real value so surrounding inversions are still detected.
  std::optional<double> previous;
  for (const std::optional<double>& limit :
    {condition.lowLowLimit, condition.lowLimit, condition.highLimit, condition.highHighLimit})
  {
    if (!limit.has_value() || std::isnan(*limit))
    {
      continue;
    }
    if (previous.has_value() && *previous > *limit)
    {
      return true;
    }
    previous = limit;
  }
  return false;
}

bool non_exclusive_cross_group(const TrackedCondition& condition) noexcept
{
  // CL-AC-025: a high-group state (HighState | HighHighState) AND a low-group state (LowState | LowLowState)
  // active simultaneously is an impossible cross-group state. Within-group concurrency (High+HighHigh or
  // Low+LowLow) is LEGAL and must NOT advise. A state is "active" iff its TwoStateValue.id == true.
  const auto active = [](const std::optional<TwoStateValue>& state)
  {
    return state.has_value() && state->id == true;
  };
  const bool highGroupActive = active(condition.highState) || active(condition.highHighState);
  const bool lowGroupActive = active(condition.lowState) || active(condition.lowLowState);
  return highGroupActive && lowGroupActive;
}

std::shared_ptr<AlarmConditionTrackerImpl> AlarmConditionTrackerImpl::create(
  boost::asio::strand<boost::asio::any_io_executor> strand, boost::asio::any_io_executor executor,
  std::weak_ptr<EventSubscriberImpl> subscriber, std::weak_ptr<WireOps> wireOps, ua::Logger logger,
  AlarmConditionTrackerPolicy policy, std::weak_ptr<ObserverSink> observerSink)
{
  return std::shared_ptr<AlarmConditionTrackerImpl>(new AlarmConditionTrackerImpl(std::move(strand),
    std::move(executor),
    std::move(subscriber),
    std::move(wireOps),
    std::move(logger),
    policy,
    std::move(observerSink)));
}

AlarmConditionTrackerImpl::AlarmConditionTrackerImpl(boost::asio::strand<boost::asio::any_io_executor> strand,
  boost::asio::any_io_executor executor, std::weak_ptr<EventSubscriberImpl> subscriber,
  std::weak_ptr<WireOps> wireOps, ua::Logger logger, AlarmConditionTrackerPolicy policy,
  std::weak_ptr<ObserverSink> observerSink)
  : mStrand(std::move(strand)), mExecutor(std::move(executor)), mSubscriber(std::move(subscriber)),
    mWireOps(std::move(wireOps)), mLogger(std::move(logger)), mPolicy(policy),
    mObserverSink(std::move(observerSink)), mUseRefresh2(policy.preferConditionRefresh2)
{
  refresh_info_snapshot();
}

void AlarmConditionTrackerImpl::start_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  try
  {
    if (!callback)
    {
      // The caller supplied no completion, so the operation result is not needed.
      callback = [](VoidResult) {
      };
    }
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      std::move(callback),
      VoidResult{StatusCode{Status::BadConnectionClosed}},
      [](AlarmConditionTrackerImpl& self, std::function<void(VoidResult)> completion)
      {
        self.mTrackerHook = std::make_shared<TrackerHookImpl>(self.weak_from_this());
        auto subscriber = self.mSubscriber.lock();
        if (!subscriber)
        {
          self.deliver_void(std::move(completion), VoidResult{StatusCode{Status::BadConnectionClosed}});
          return;
        }
        subscriber->attach_tracker_async(self.mTrackerHook, std::move(completion));
      })();
  }
  catch (...)
  {
    ::ua::detail::invoke_user_callback(
      mLogger, callback, VoidResult{exception_to_status_code(std::current_exception())});
  }
}

void AlarmConditionTrackerImpl::close_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  try
  {
    if (!callback)
    {
      // The caller supplied no completion, so the operation result is not needed.
      callback = [](VoidResult) {
      };
    }
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      std::move(callback),
      VoidResult{},
      [](AlarmConditionTrackerImpl& self, std::function<void(VoidResult)> completion)
      {
        self.mClosing = true;
        self.mTrackerHook.reset();  // the subscriber's weak entry expires on next iteration
        self.mTrackedConditions.clear();
        self.mActiveRefreshWindows.clear();
        self.mSeenRefreshEndEventIds.clear();
        if (self.mPendingRefreshCallback)
        {
          auto pending = std::move(self.mPendingRefreshCallback);
          self.mPendingRefreshCallback = nullptr;
          self.deliver_void(std::move(pending), VoidResult{StatusCode{Status::BadConnectionClosed}});
        }
        self.mRefreshInProgress = false;
        self.mRefreshTriggerStatus = StatusCode{Status::Good};
        self.refresh_info_snapshot();
        self.deliver_void(std::move(completion), VoidResult{});
      })();
  }
  catch (...)
  {
    ::ua::detail::invoke_user_callback(
      mLogger, callback, VoidResult{exception_to_status_code(std::current_exception())});
  }
}

// ---- Observers ----

void AlarmConditionTrackerImpl::on_condition_added_async(
  ConditionAddedCb cb, std::function<void(ua::VoidResult)> callback) noexcept
{
  try
  {
    if (!callback)
    {
      // The caller supplied no completion, so the operation result is not needed.
      callback = [](VoidResult) {
      };
    }
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      std::move(callback),
      VoidResult{StatusCode{Status::BadConnectionClosed}},
      [cb = std::move(cb)](
        AlarmConditionTrackerImpl& self, std::function<void(VoidResult)> completion) mutable
      {
        self.mAddedObservers.push_back(std::move(cb));
        self.deliver_void(std::move(completion), VoidResult{});
      })();
  }
  catch (...)
  {
    ::ua::detail::invoke_user_callback(
      mLogger, callback, VoidResult{exception_to_status_code(std::current_exception())});
  }
}

void AlarmConditionTrackerImpl::on_condition_changed_async(
  ConditionChangedCb cb, std::function<void(ua::VoidResult)> callback) noexcept
{
  try
  {
    if (!callback)
    {
      // The caller supplied no completion, so the operation result is not needed.
      callback = [](VoidResult) {
      };
    }
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      std::move(callback),
      VoidResult{StatusCode{Status::BadConnectionClosed}},
      [cb = std::move(cb)](
        AlarmConditionTrackerImpl& self, std::function<void(VoidResult)> completion) mutable
      {
        self.mChangedObservers.push_back(std::move(cb));
        self.deliver_void(std::move(completion), VoidResult{});
      })();
  }
  catch (...)
  {
    ::ua::detail::invoke_user_callback(
      mLogger, callback, VoidResult{exception_to_status_code(std::current_exception())});
  }
}

void AlarmConditionTrackerImpl::on_condition_removed_async(
  ConditionRemovedCb cb, std::function<void(ua::VoidResult)> callback) noexcept
{
  try
  {
    if (!callback)
    {
      // The caller supplied no completion, so the operation result is not needed.
      callback = [](VoidResult) {
      };
    }
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      std::move(callback),
      VoidResult{StatusCode{Status::BadConnectionClosed}},
      [cb = std::move(cb)](
        AlarmConditionTrackerImpl& self, std::function<void(VoidResult)> completion) mutable
      {
        self.mRemovedObservers.push_back(std::move(cb));
        self.deliver_void(std::move(completion), VoidResult{});
      })();
  }
  catch (...)
  {
    ::ua::detail::invoke_user_callback(
      mLogger, callback, VoidResult{exception_to_status_code(std::current_exception())});
  }
}

// ---- Snapshot reads ----

void AlarmConditionTrackerImpl::list_conditions_async(
  std::function<void(ua::Result<std::vector<TrackedCondition>>)> callback) noexcept
{
  try
  {
    if (!callback)
    {
      // The caller supplied no completion, so the operation result is not needed.
      callback = [](Result<std::vector<TrackedCondition>>) {
      };
    }
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      std::move(callback),
      Result<std::vector<TrackedCondition>>{StatusCode{Status::BadConnectionClosed}},
      [](AlarmConditionTrackerImpl& self,
        std::function<void(Result<std::vector<TrackedCondition>>)>
          completion) mutable
      {
        std::vector<TrackedCondition> snapshot = self.mTrackedConditions;
        boost::asio::post(self.mExecutor,
          ua::async::guarded(self.mLogger,
            [completion = std::move(completion), snapshot = std::move(snapshot)]() mutable
            { completion(Result<std::vector<TrackedCondition>>{std::move(snapshot)}); }));
      })();
  }
  catch (...)
  {
    ::ua::detail::invoke_user_callback(mLogger,
      callback,
      Result<std::vector<TrackedCondition>>{exception_to_status_code(std::current_exception())});
  }
}

void AlarmConditionTrackerImpl::get_condition_async(
  TrackedKey key, std::function<void(ua::Result<TrackedCondition>)> callback) noexcept
{
  try
  {
    if (!callback)
    {
      // The caller supplied no completion, so the operation result is not needed.
      callback = [](Result<TrackedCondition>) {
      };
    }
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      std::move(callback),
      Result<TrackedCondition>{StatusCode{Status::BadConnectionClosed}},
      [key = std::move(key)](
        AlarmConditionTrackerImpl& self, std::function<void(Result<TrackedCondition>)> completion) mutable
      {
        const TrackedCondition* found = self.find(key);
        Result<TrackedCondition> result = found
                                            ? Result<TrackedCondition>{*found}
                                            : Result<TrackedCondition>{StatusCode{Status::BadNodeIdUnknown},
                                                ua::make_error_detail("BadNodeIdUnknown",
                                                  "no tracked condition for the key",
                                                  "client.tier2.alarm_tracker.unknown_branch")};
        boost::asio::post(self.mExecutor,
          ua::async::guarded(self.mLogger,
            [completion = std::move(completion), result = std::move(result)]() mutable
            { completion(std::move(result)); }));
      })();
  }
  catch (...)
  {
    ::ua::detail::invoke_user_callback(
      mLogger, callback, Result<TrackedCondition>{exception_to_status_code(std::current_exception())});
  }
}

// ---- Refresh ----

void AlarmConditionTrackerImpl::refresh_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  try
  {
    if (!callback)
    {
      // The caller supplied no completion, so the operation result is not needed.
      callback = [](VoidResult) {
      };
    }
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      std::move(callback),
      VoidResult{StatusCode{Status::BadConnectionClosed}},
      [](AlarmConditionTrackerImpl& self, std::function<void(VoidResult)> completion) mutable
      {
        if (self.mClosing)
        {
          self.deliver_void(std::move(completion), VoidResult{StatusCode{Status::BadConnectionClosed}});
          return;
        }
        // Re-entrancy (section 9.6.7): a client refresh already awaiting its RefreshEnd rejects a second one.
        if (self.mRefreshInProgress)
        {
          self.deliver_void(std::move(completion),
            VoidResult{StatusCode{Status::BadRefreshInProgress},
              ua::make_error_detail("BadRefreshInProgress",
                "a ConditionRefresh is already in progress (awaiting RefreshEnd)",
                "client.tier2.alarm_tracker.refresh")});
          return;
        }
        self.mRefreshInProgress = true;
        self.mPendingRefreshCallback = std::move(completion);
        self.issue_refresh();
      })();
  }
  catch (...)
  {
    ::ua::detail::invoke_user_callback(
      mLogger, callback, VoidResult{exception_to_status_code(std::current_exception())});
  }
}

void AlarmConditionTrackerImpl::on_redundancy_switch_recovered_async(ua::RedundancySupport mode) noexcept
{
  try
  {
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [mode](AlarmConditionTrackerImpl& self) { self.handle_redundancy_switch_recovered_on_strand(mode); })();
  }
  catch (...)
  {
    ua::async::detail::report_guarded_exception(mLogger, "alarm tracker redundancy recovery");
  }
}

void AlarmConditionTrackerImpl::read_alarm_metrics_async(
  ua::NodeId metricsObject, std::function<void(Result<AlarmMetricsSnapshot>)> callback) noexcept
{
  try
  {
    if (!callback)
    {
      // The caller supplied no completion, so the operation result is not needed.
      callback = [](Result<AlarmMetricsSnapshot>) {
      };
    }
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      std::move(callback),
      Result<AlarmMetricsSnapshot>{StatusCode{Status::BadConnectionClosed}},
      [metricsObject = std::move(metricsObject)](
        AlarmConditionTrackerImpl& self, std::function<void(Result<AlarmMetricsSnapshot>)> completion) mutable
      {
        auto wire = self.mWireOps.lock();
        if (!wire)
        {
          completion(Result<AlarmMetricsSnapshot>{StatusCode{Status::BadConnectionClosed}});
          return;
        }
        // The public view is owed exactly one completion even if its owning Connection closes mid-read.
        // Keep the tracker alive only for this bounded translate->read chain.
        wire->translate_browse_paths_async(build_metric_paths(metricsObject),
          ua::async::post_owning(&self,
            self.mStrand,
            self.mLogger,
            [done = std::move(completion)](AlarmConditionTrackerImpl& tracker,
              Result<ua::TranslateBrowsePathsToNodeIdsResponse>
                translated) mutable
            {
              auto nodes = resolved_metric_nodes(std::move(translated), alarmMetricNodeCount);
              if (!nodes.is_good())
              {
                done(Result<AlarmMetricsSnapshot>{nodes.status_code()});
                return;
              }
              ua::ReadRequest request;
              for (const auto& node : nodes.value())
              {
                ua::ReadValueId value;
                value.node_id() = node;
                value.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::Value);
                request.nodes_to_read().push_back(std::move(value));
              }
              auto wireOps = tracker.mWireOps.lock();
              if (!wireOps)
              {
                done(Result<AlarmMetricsSnapshot>{StatusCode{Status::BadConnectionClosed}});
                return;
              }
              wireOps->read_async(std::move(request),
                ua::async::post_owning(&tracker,
                  tracker.mStrand,
                  tracker.mLogger,
                  [finish = std::move(done)](
                    AlarmConditionTrackerImpl&, Result<ua::ReadResponse> readResult) mutable
                  {
                    if (!readResult.has_value())
                    {
                      finish(
                        Result<AlarmMetricsSnapshot>{readResult.status_code(), readResult.shared_detail()});
                      return;
                    }
                    const StatusCode serviceResult = readResult.value().response_header().service_result();
                    if (serviceResult.is_bad())
                    {
                      finish(Result<AlarmMetricsSnapshot>{serviceResult});
                      return;
                    }
                    const auto& values = readResult.value().results();
                    if (values.size() != alarmMetricNodeCount)
                    {
                      finish(Result<AlarmMetricsSnapshot>{StatusCode{Status::BadUnexpectedError},
                        ua::make_error_detail("AlarmMetricsReadCount",
                          "Read returned an unexpected result count for AlarmMetrics",
                          "client.tier2.alarm_metrics.read")});
                      return;
                    }
                    // The snapshot carries the Read's code: the ServiceResult and every value's status
                    // combined (ua::detail::combined_status). A Bad value fails the read; a value that is not
                    // Good and carries no value is answered with the code and no snapshot.
                    StatusCode answered =
                      ua::detail::combined_status(readResult.status_code(), serviceResult);
                    for (const auto& value : values)
                    {
                      const StatusCode status = value.status().value_or(StatusCode{Status::Good});
                      if (status.is_bad())
                      {
                        finish(Result<AlarmMetricsSnapshot>{status});
                        return;
                      }
                      answered = ua::detail::combined_status(answered, status);
                      if (!status.is_good() && value.value().empty())
                      {
                        finish(Result<AlarmMetricsSnapshot>{answered});
                        return;
                      }
                    }
                    const auto alarmCount = values[0].value().to<std::uint32_t>();
                    const auto startTime = values[1].value().to<ua::DateTime>();
                    const auto maximumActive = values[2].value().to<ua::Duration>();
                    const auto maximumUnAck = values[3].value().to<ua::Duration>();
                    const auto currentRate = values[4].value().to<double>();
                    const auto maximumRate = values[5].value().to<double>();
                    const auto maximumReAlarm = values[6].value().to<std::uint32_t>();
                    const auto averageRate = values[7].value().to<double>();
                    const auto currentMinutes = values[8].value().to<std::uint16_t>();
                    const auto maximumMinutes = values[9].value().to<std::uint16_t>();
                    const auto averageMinutes = values[10].value().to<std::uint16_t>();
                    if (alarmCount.is_bad() || startTime.is_bad() || maximumActive.is_bad() ||
                        maximumUnAck.is_bad() || currentRate.is_bad() || maximumRate.is_bad() ||
                        maximumReAlarm.is_bad() || averageRate.is_bad() || currentMinutes.is_bad() ||
                        maximumMinutes.is_bad() || averageMinutes.is_bad())
                    {
                      finish(Result<AlarmMetricsSnapshot>{StatusCode{Status::BadDecodingError},
                        ua::make_error_detail("AlarmMetricsTypeMismatch",
                          "an AlarmMetrics value did not match its mandatory data type",
                          "client.tier2.alarm_metrics.read")});
                      return;
                    }
                    AlarmMetricsSnapshot snapshot;
                    snapshot.alarmCount = alarmCount.value();
                    snapshot.startTime = startTime.value();
                    snapshot.maximumActiveState = maximumActive.value();
                    snapshot.maximumUnAck = maximumUnAck.value();
                    snapshot.currentAlarmRate = {currentRate.value(), currentMinutes.value()};
                    snapshot.maximumAlarmRate = {maximumRate.value(), maximumMinutes.value()};
                    snapshot.maximumReAlarmCount = maximumReAlarm.value();
                    snapshot.averageAlarmRate = {averageRate.value(), averageMinutes.value()};
                    finish(ua::detail::held(std::move(snapshot), answered));
                  }));
            }));
      })();
  }
  catch (...)
  {
    ::ua::detail::invoke_user_callback(
      mLogger, callback, Result<AlarmMetricsSnapshot>{exception_to_status_code(std::current_exception())});
  }
}

void AlarmConditionTrackerImpl::read_property_async(
  TrackedKey key, ua::QualifiedName property, std::function<void(Result<ua::Variant>)> callback) noexcept
{
  try
  {
    if (!callback)
    {
      // The caller supplied no completion, so the operation result is not needed.
      callback = [](Result<ua::Variant>) {
      };
    }
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      std::move(callback),
      Result<ua::Variant>{StatusCode{Status::BadConnectionClosed}},
      [key = std::move(key), property = std::move(property)](
        AlarmConditionTrackerImpl& self, std::function<void(Result<ua::Variant>)> completion) mutable
      {
        auto wire = self.mWireOps.lock();
        if (!wire)
        {
          completion(Result<ua::Variant>{StatusCode{Status::BadConnectionClosed}});
          return;
        }
        wire->translate_browse_paths_async(build_condition_property_path(key.conditionId, property),
          ua::async::post_owning(&self,
            self.mStrand,
            self.mLogger,
            [done = std::move(completion)](AlarmConditionTrackerImpl& tracker,
              Result<ua::TranslateBrowsePathsToNodeIdsResponse>
                translated) mutable
            {
              auto propertyNode = resolved_condition_property(std::move(translated));
              if (!propertyNode.is_good())
              {
                done(Result<ua::Variant>{propertyNode.status_code(), propertyNode.shared_detail()});
                return;
              }
              ua::ReadValueId value;
              value.node_id() = propertyNode.value();
              value.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::Value);
              ua::ReadRequest request;
              request.nodes_to_read().push_back(std::move(value));
              auto wireOps = tracker.mWireOps.lock();
              if (!wireOps)
              {
                done(Result<ua::Variant>{StatusCode{Status::BadConnectionClosed}});
                return;
              }
              wireOps->read_async(std::move(request),
                ua::async::post_owning(&tracker,
                  tracker.mStrand,
                  tracker.mLogger,
                  [finish = std::move(done)](
                    AlarmConditionTrackerImpl&, Result<ua::ReadResponse> readResult) mutable
                  {
                    if (!readResult.has_value())
                    {
                      finish(Result<ua::Variant>{readResult.status_code(), readResult.shared_detail()});
                      return;
                    }
                    const StatusCode serviceResult = readResult.value().response_header().service_result();
                    if (serviceResult.is_bad())
                    {
                      finish(Result<ua::Variant>{serviceResult});
                      return;
                    }
                    const auto& values = readResult.value().results();
                    if (values.size() != 1)
                    {
                      finish(Result<ua::Variant>{StatusCode{Status::BadUnexpectedError},
                        ua::make_error_detail("AlarmPropertyReadCount",
                          "Read returned an unexpected result count for an Alarm property",
                          "client.tier2.alarm_tracker.read_property")});
                      return;
                    }
                    // The value with the Read's code: the ServiceResult and the value's status combined
                    // (ua::detail::combined_status). A Bad code, or a code that is not Good on a null value,
                    // is answered without a value.
                    const StatusCode answered = ua::detail::combined_status(
                      ua::detail::combined_status(readResult.status_code(), serviceResult),
                      values[0].status().value_or(StatusCode{Status::Good}));
                    if (answered.is_bad() || (!answered.is_good() && values[0].value().empty()))
                    {
                      finish(Result<ua::Variant>{answered});
                      return;
                    }
                    finish(ua::detail::held(values[0].value(), answered));
                  }));
            }));
      })();
  }
  catch (...)
  {
    ::ua::detail::invoke_user_callback(
      mLogger, callback, Result<ua::Variant>{exception_to_status_code(std::current_exception())});
  }
}

void AlarmConditionTrackerImpl::reset_alarm_metrics_async(
  ua::NodeId metricsObject, std::function<void(VoidResult)> callback) noexcept
{
  try
  {
    if (!callback)
    {
      // The caller supplied no completion, so the operation result is not needed.
      callback = [](VoidResult) {
      };
    }
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      std::move(callback),
      VoidResult{StatusCode{Status::BadConnectionClosed}},
      [metricsObject = std::move(metricsObject)](
        AlarmConditionTrackerImpl& self, std::function<void(VoidResult)> completion) mutable
      {
        auto wire = self.mWireOps.lock();
        if (!wire)
        {
          completion(VoidResult{StatusCode{Status::BadConnectionClosed}});
          return;
        }
        // Reset likewise owes its public completion across the bounded translate->Call chain.
        auto resetPath = build_metric_reset_path(metricsObject);
        wire->translate_browse_paths_async(std::move(resetPath),
          ua::async::post_owning(&self,
            self.mStrand,
            self.mLogger,
            [metricsObject = std::move(metricsObject), done = std::move(completion)](
              AlarmConditionTrackerImpl& tracker,
              Result<ua::TranslateBrowsePathsToNodeIdsResponse>
                translated) mutable
            {
              auto nodes = resolved_metric_nodes(std::move(translated), 1);
              if (!nodes.is_good())
              {
                done(VoidResult{nodes.status_code()});
                return;
              }
              auto wireOps = tracker.mWireOps.lock();
              if (!wireOps)
              {
                done(VoidResult{StatusCode{Status::BadConnectionClosed}});
                return;
              }
              ua::CallMethodRequest method;
              method.object_id() = std::move(metricsObject);
              method.method_id() = nodes.value()[0];
              ua::CallRequest request;
              request.methods_to_call().push_back(std::move(method));
              wireOps->call_async(std::move(request),
                ua::async::post_owning(&tracker,
                  tracker.mStrand,
                  tracker.mLogger,
                  [finish = std::move(done)](
                    AlarmConditionTrackerImpl&, Result<ua::CallResponse> result) mutable
                  { finish(flatten_call(std::move(result))); }));
            }));
      })();
  }
  catch (...)
  {
    ::ua::detail::invoke_user_callback(
      mLogger, callback, VoidResult{exception_to_status_code(std::current_exception())});
  }
}

void AlarmConditionTrackerImpl::issue_refresh()
{
  // ConditionRefresh: ObjectId = ConditionType, MethodId = ConditionType.ConditionRefresh (CL-AC-011). The
  // Call response Good only confirms the trigger; the window closes on RefreshEnd (collect-until-RefreshEnd).
  auto wire = mWireOps.lock();
  if (!wire)
  {
    // Connection gone before the trigger could be sent: no window will open, so return the machine to Idle
    // (independent of whether a user callback is pending  -  internal triggers have none; section 8.8.4).
    fail_refresh_and_reset(VoidResult{StatusCode{Status::BadConnectionClosed},
      ua::make_error_detail("BadConnectionClosed",
        "ConditionRefresh trigger: Connection gone",
        "client.tier2.alarm_tracker.refresh")});
    return;
  }
  const std::uint32_t refreshMethod =
    mUseRefresh2 ? static_cast<std::uint32_t>(ua::MethodId::ConditionType_ConditionRefresh2)
                 : static_cast<std::uint32_t>(ua::MethodId::ConditionType_ConditionRefresh);

  // OPC 10000-9 Table 20: ConditionRefresh([in] IntegerId SubscriptionId) - ONE mandatory argument.
  // This used to send none, so a conforming server refused the call and the tracker then waited
  // forever for a RefreshEnd that could never arrive (a Good here only confirms the trigger). Our own
  // server answers Bad_ArgumentsMissing, because it registers MethodAdapter<std::tuple<uint32_t>>,
  // which validates arity.
  if (mBackboneSubscriptionId == 0)
  {
    fail_refresh_and_reset(VoidResult{StatusCode{Status::BadInvalidState},
      ua::make_error_detail("NoBackboneSubscription",
        "ConditionRefresh needs the SubscriptionId of the backbone carrying this tracker's event "
        "MonitoredItems; the tracker is not attached to one yet",
        "client.tier2.alarm_tracker.refresh")});
    return;
  }

  ua::CallMethodRequest method;
  method.object_id() = ua::NodeId{ua::ObjectTypeId::ConditionType};
  method.method_id() = ua::NodeId{refreshMethod};
  method.input_arguments().push_back(ua::Variant{mBackboneSubscriptionId});
  if (mUseRefresh2)
  {
    // Table 23: ConditionRefresh2 scopes the replay to ONE MonitoredItem, so it takes a second
    // mandatory argument. Sending it with only the SubscriptionId fails the same way the legacy
    // method did with none.
    method.input_arguments().push_back(ua::Variant{mBackboneMonitoredItemId});
  }

  ua::CallRequest request;
  request.methods_to_call().push_back(std::move(method));

  wire->call_async(std::move(request),
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [](AlarmConditionTrackerImpl& self, Result<ua::CallResponse> result) mutable
      {
        const bool answered = result.has_value();
        const VoidResult outcome = flatten_call(std::move(result));
        if (answered && !outcome.is_bad())
        {
          // A Good or an Uncertain answer only CONFIRMS the trigger (Uncertain: the server ran the Method,
          // partly successfully)  -  keep mRefreshInProgress set; the callback fires when the matching
          // RefreshEnd arrives (collect-until-RefreshEnd), with this code, so a Good subcode or an Uncertain
          // code the server answered the trigger with reaches the caller.
          self.mRefreshTriggerStatus = outcome.status_code();
          return;
        }
        if (outcome.is_uncertain())
        {
          // An Uncertain answer without a CallResponse does not say the Method ran, so the tracker does not
          // wait for a RefreshEnd on it: the trigger is refused.
          self.fail_refresh_and_reset(VoidResult{ua::client::detail::answer_refused(
            outcome.status_code(), "ServiceAnswerUncertain", "client.tier2.alarm_tracker.refresh")});
          return;
        }
        // CL-AC-012 (section 8.8.5 rows 9103/9169): a ConditionRefresh2 rejected with Bad_MethodInvalid
        // latches mUseRefresh2=false PERMANENTLY and transparently RETRIES as legacy ConditionRefresh on the
        // same subscription  -  it does NOT complete the pending callback nor wedge the machine. Once already
        // on the legacy method (mUseRefresh2 == false) a Bad_MethodInvalid is a genuine failure and
        // terminates.
        if (self.mUseRefresh2 && outcome.status_code().as_status() == Status::BadMethodInvalid)
        {
          self.mUseRefresh2 = false;
          self.refresh_info_snapshot();
          self.issue_refresh();  // transparent legacy retry (counts as the next trigger)
          return;
        }
        // Any other (Bad) answer returns the machine to Idle (F1) and propagates to a pending user callback.
        self.fail_refresh_and_reset(outcome);
      }));
}

void AlarmConditionTrackerImpl::fail_refresh_and_reset(ua::VoidResult outcome)
{
  // A refresh TRIGGER failed (Call Bad, an Uncertain Call answer without a response refused, or Connection
  // gone): no RefreshStart/RefreshEnd window will open, so
  // the state machine MUST return to Idle regardless of whether a user callback is pending. The three
  // INTERNAL triggers (first-event-after-attach CL-AC-003, RefreshRequired-while-idle CL-AC-007, and the
  // follow-on re-issue) set mRefreshInProgress with NO user callback; gating the reset on a pending callback
  // (the F1 defect) wedged the machine permanently  -  every subsequent refresh_async then returned
  // Bad_RefreshInProgress. section 8.8.4: a Bad trigger returns to Idle.
  mRefreshInProgress = false;
  mRefreshTriggerStatus = StatusCode{Status::Good};
  if (mPendingRefreshCallback)
  {
    auto pending = std::move(mPendingRefreshCallback);
    mPendingRefreshCallback = nullptr;
    deliver_void(std::move(pending), outcome);
  }
  else
  {
    // Internal trigger  -  no user callback to carry the code. Log at the wire boundary before it is lost.
    mLogger.warning({{"status", fmt::format("0x{:08x}", outcome.status_code().as_uint32())}},
      "alarm tracker internal ConditionRefresh trigger was not confirmed");
  }
  // Honour a queued follow-on (CL-AC-007): the failed trigger may have shadowed a RefreshRequired arrival.
  if (mPendingFollowOnRefresh && !mClosing)
  {
    mPendingFollowOnRefresh = false;
    mRefreshInProgress = true;  // an internal (no user callback) follow-on refresh
    issue_refresh();
  }
  refresh_info_snapshot();
}

void AlarmConditionTrackerImpl::refresh_windows_maybe_complete()
{
  if (!mActiveRefreshWindows.empty())
  {
    // A RefreshEnd closed ONE of several overlapping windows (CL-AC-004). The refresh has not completed, but
    // the window set shrank  -  republish the observability snapshot so a consumer polling info() sees the
    // decremented openRefreshWindowCount (every other mutating on-strand path already refreshes it; without
    // this the count would appear stuck at its peak until the LAST window closed).
    refresh_info_snapshot();
    return;
  }
  if (mRefreshInProgress && mPendingRefreshCallback)
  {
    auto pending = std::move(mPendingRefreshCallback);
    mPendingRefreshCallback = nullptr;
    mRefreshInProgress = false;
    deliver_void(std::move(pending), VoidResult{mRefreshTriggerStatus});
  }
  else
  {
    mRefreshInProgress = false;
  }
  mRefreshTriggerStatus = StatusCode{Status::Good};
  if (mPendingFollowOnRefresh && !mClosing)
  {
    mPendingFollowOnRefresh = false;
    mRefreshInProgress = true;  // an internal (no user callback) follow-on refresh
    issue_refresh();
  }
  refresh_info_snapshot();
}

// ---- Method wrappers ----

void AlarmConditionTrackerImpl::acknowledge_async(TrackedKey key, std::optional<ua::ByteString> eventId,
  std::optional<ua::LocalizedText> comment, std::function<void(ua::VoidResult)> callback) noexcept
{
  try
  {
    if (!callback)
    {
      // The caller supplied no completion, so the operation result is not needed.
      callback = [](VoidResult) {
      };
    }
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      std::move(callback),
      VoidResult{StatusCode{Status::BadConnectionClosed}},
      [key = std::move(key), eventId = std::move(eventId), comment = std::move(comment)](
        AlarmConditionTrackerImpl& self, std::function<void(VoidResult)> completion) mutable
      {
        const TrackedCondition* tc = self.find(key);
        // CL-AC-010: local short-circuit when the branch is already acknowledged (no explicit-EventId
        // override  -  an explicit EventId may target a historical branch the tracker has no state for).
        if (!eventId.has_value() && tc && tc->ackedState && tc->ackedState->id == true)
        {
          self.deliver_void(std::move(completion),
            VoidResult{StatusCode{Status::BadConditionBranchAlreadyAcked},
              ua::make_error_detail("BadConditionBranchAlreadyAcked",
                "condition branch already acknowledged",
                "client.tier2.alarm_tracker.short_circuit_acked")});
          return;
        }
        if (!eventId.has_value() && tc == nullptr)
        {
          self.deliver_void(std::move(completion),
            VoidResult{StatusCode{Status::BadNodeIdUnknown},
              ua::make_error_detail("BadNodeIdUnknown",
                "acknowledge of an unknown branch without an explicit EventId",
                "client.tier2.alarm_tracker.unknown_branch")});
          return;
        }
        ua::ByteString effectiveEventId = eventId.value_or(tc ? tc->lastEventId : ua::ByteString{});
        std::vector<ua::Variant> inputs{ua::Variant{effectiveEventId}, encode_comment(comment)};
        self.call_condition_method(key,
          static_cast<std::uint32_t>(ua::MethodId::AcknowledgeableConditionType_Acknowledge),
          std::move(inputs),
          std::move(completion));
      })();
  }
  catch (...)
  {
    ::ua::detail::invoke_user_callback(
      mLogger, callback, VoidResult{exception_to_status_code(std::current_exception())});
  }
}

void AlarmConditionTrackerImpl::confirm_async(TrackedKey key, std::optional<ua::ByteString> eventId,
  std::optional<ua::LocalizedText> comment, std::function<void(ua::VoidResult)> callback) noexcept
{
  try
  {
    if (!callback)
    {
      // The caller supplied no completion, so the operation result is not needed.
      callback = [](VoidResult) {
      };
    }
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      std::move(callback),
      VoidResult{StatusCode{Status::BadConnectionClosed}},
      [key = std::move(key), eventId = std::move(eventId), comment = std::move(comment)](
        AlarmConditionTrackerImpl& self, std::function<void(VoidResult)> completion) mutable
      {
        const TrackedCondition* tc = self.find(key);
        if (!eventId.has_value() && tc && tc->confirmedState && tc->confirmedState->id == true)
        {
          self.deliver_void(std::move(completion),
            VoidResult{StatusCode{Status::BadConditionBranchAlreadyConfirmed},
              ua::make_error_detail("BadConditionBranchAlreadyConfirmed",
                "condition branch already confirmed",
                "client.tier2.alarm_tracker.short_circuit_confirmed")});
          return;
        }
        if (!eventId.has_value() && tc == nullptr)
        {
          self.deliver_void(std::move(completion),
            VoidResult{StatusCode{Status::BadNodeIdUnknown},
              ua::make_error_detail("BadNodeIdUnknown",
                "confirm of an unknown branch without an explicit EventId",
                "client.tier2.alarm_tracker.unknown_branch")});
          return;
        }
        ua::ByteString effectiveEventId = eventId.value_or(tc ? tc->lastEventId : ua::ByteString{});
        std::vector<ua::Variant> inputs{ua::Variant{effectiveEventId}, encode_comment(comment)};
        self.call_condition_method(key,
          static_cast<std::uint32_t>(ua::MethodId::AcknowledgeableConditionType_Confirm),
          std::move(inputs),
          std::move(completion));
      })();
  }
  catch (...)
  {
    ::ua::detail::invoke_user_callback(
      mLogger, callback, VoidResult{exception_to_status_code(std::current_exception())});
  }
}

void AlarmConditionTrackerImpl::add_comment_async(TrackedKey key, ua::ByteString eventId,
  std::optional<ua::LocalizedText> comment, std::function<void(ua::VoidResult)> callback) noexcept
{
  try
  {
    if (!callback)
    {
      // The caller supplied no completion, so the operation result is not needed.
      callback = [](VoidResult) {
      };
    }
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      std::move(callback),
      VoidResult{StatusCode{Status::BadConnectionClosed}},
      [key = std::move(key), eventId = std::move(eventId), comment = std::move(comment)](
        AlarmConditionTrackerImpl& self, std::function<void(VoidResult)> completion) mutable
      {
        std::vector<ua::Variant> inputs{ua::Variant{eventId}, encode_comment(comment)};
        self.call_condition_method(key,
          static_cast<std::uint32_t>(ua::MethodId::ConditionType_AddComment),
          std::move(inputs),
          std::move(completion));
      })();
  }
  catch (...)
  {
    ::ua::detail::invoke_user_callback(
      mLogger, callback, VoidResult{exception_to_status_code(std::current_exception())});
  }
}

void AlarmConditionTrackerImpl::enable_async(
  TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept
{
  try
  {
    if (!callback)
    {
      // The caller supplied no completion, so the operation result is not needed.
      callback = [](VoidResult) {
      };
    }
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      std::move(callback),
      VoidResult{StatusCode{Status::BadConnectionClosed}},
      [key = std::move(key)](
        AlarmConditionTrackerImpl& self, std::function<void(VoidResult)> completion) mutable
      {
        self.call_condition_method(
          key, static_cast<std::uint32_t>(ua::MethodId::ConditionType_Enable), {}, std::move(completion));
      })();
  }
  catch (...)
  {
    ::ua::detail::invoke_user_callback(
      mLogger, callback, VoidResult{exception_to_status_code(std::current_exception())});
  }
}

void AlarmConditionTrackerImpl::disable_async(
  TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept
{
  try
  {
    if (!callback)
    {
      // The caller supplied no completion, so the operation result is not needed.
      callback = [](VoidResult) {
      };
    }
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      std::move(callback),
      VoidResult{StatusCode{Status::BadConnectionClosed}},
      [key = std::move(key)](
        AlarmConditionTrackerImpl& self, std::function<void(VoidResult)> completion) mutable
      {
        self.call_condition_method(
          key, static_cast<std::uint32_t>(ua::MethodId::ConditionType_Disable), {}, std::move(completion));
      })();
  }
  catch (...)
  {
    ::ua::detail::invoke_user_callback(
      mLogger, callback, VoidResult{exception_to_status_code(std::current_exception())});
  }
}

void AlarmConditionTrackerImpl::silence_async(
  TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept
{
  try
  {
    if (!callback)
    {
      // The caller supplied no completion, so the operation result is not needed.
      callback = [](VoidResult) {
      };
    }
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      std::move(callback),
      VoidResult{StatusCode{Status::BadConnectionClosed}},
      [key = std::move(key)](
        AlarmConditionTrackerImpl& self, std::function<void(VoidResult)> completion) mutable
      {
        self.call_condition_method(key,
          static_cast<std::uint32_t>(ua::MethodId::AlarmConditionType_Silence),
          {},
          std::move(completion));
      })();
  }
  catch (...)
  {
    ::ua::detail::invoke_user_callback(
      mLogger, callback, VoidResult{exception_to_status_code(std::current_exception())});
  }
}

void AlarmConditionTrackerImpl::suppress_async(
  TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept
{
  try
  {
    if (!callback)
    {
      // The caller supplied no completion, so the operation result is not needed.
      callback = [](VoidResult) {
      };
    }
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      std::move(callback),
      VoidResult{StatusCode{Status::BadConnectionClosed}},
      [key = std::move(key)](
        AlarmConditionTrackerImpl& self, std::function<void(VoidResult)> completion) mutable
      {
        self.call_condition_method(key,
          static_cast<std::uint32_t>(ua::MethodId::AlarmConditionType_Suppress),
          {},
          std::move(completion));
      })();
  }
  catch (...)
  {
    ::ua::detail::invoke_user_callback(
      mLogger, callback, VoidResult{exception_to_status_code(std::current_exception())});
  }
}

void AlarmConditionTrackerImpl::unsuppress_async(
  TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept
{
  try
  {
    if (!callback)
    {
      // The caller supplied no completion, so the operation result is not needed.
      callback = [](VoidResult) {
      };
    }
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      std::move(callback),
      VoidResult{StatusCode{Status::BadConnectionClosed}},
      [key = std::move(key)](
        AlarmConditionTrackerImpl& self, std::function<void(VoidResult)> completion) mutable
      {
        self.call_condition_method(key,
          static_cast<std::uint32_t>(ua::MethodId::AlarmConditionType_Unsuppress),
          {},
          std::move(completion));
      })();
  }
  catch (...)
  {
    ::ua::detail::invoke_user_callback(
      mLogger, callback, VoidResult{exception_to_status_code(std::current_exception())});
  }
}

void AlarmConditionTrackerImpl::timed_shelve_async(
  TrackedKey key, ua::Duration shelvingTime, std::function<void(ua::VoidResult)> callback) noexcept
{
  try
  {
    if (!callback)
    {
      // The caller supplied no completion, so the operation result is not needed.
      callback = [](VoidResult) {
      };
    }
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      std::move(callback),
      VoidResult{StatusCode{Status::BadConnectionClosed}},
      [key = std::move(key), shelvingTime](
        AlarmConditionTrackerImpl& self, std::function<void(VoidResult)> completion) mutable
      {
        // Local pre-flight (mirrors the CL-AC-010 ack/confirm short-circuit on tracked state): when the
        // tracked MaxTimeShelved is KNOWN and the requested ShelvingTime exceeds it, refuse locally with
        // Bad_ShelvingTimeOutOfRange  -  the server would reject it anyway (OPC 10000-9 ShelvedStateMachine).
        // A null/unknown MaxTimeShelved (or a NaN) proceeds unconditionally: the server stays the authority.
        const TrackedCondition* tc = self.find(key);
        if (tc && tc->maxTimeShelved && shelvingTime > *tc->maxTimeShelved)
        {
          self.deliver_void(std::move(completion),
            VoidResult{StatusCode{Status::BadShelvingTimeOutOfRange},
              ua::make_error_detail("BadShelvingTimeOutOfRange",
                "requested ShelvingTime exceeds the condition's MaxTimeShelved",
                "client.tier2.alarm_tracker.short_circuit_max_time_shelved")});
          return;
        }
        std::vector<ua::Variant> inputs{ua::Variant{shelvingTime}};
        self.call_shelving_method(key,
          "TimedShelve",
          static_cast<std::uint32_t>(ua::MethodId::ShelvedStateMachineType_TimedShelve),
          std::move(inputs),
          std::move(completion));
      })();
  }
  catch (...)
  {
    ::ua::detail::invoke_user_callback(
      mLogger, callback, VoidResult{exception_to_status_code(std::current_exception())});
  }
}

void AlarmConditionTrackerImpl::one_shot_shelve_async(
  TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept
{
  try
  {
    if (!callback)
    {
      // The caller supplied no completion, so the operation result is not needed.
      callback = [](VoidResult) {
      };
    }
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      std::move(callback),
      VoidResult{StatusCode{Status::BadConnectionClosed}},
      [key = std::move(key)](
        AlarmConditionTrackerImpl& self, std::function<void(VoidResult)> completion) mutable
      {
        self.call_shelving_method(key,
          "OneShotShelve",
          static_cast<std::uint32_t>(ua::MethodId::ShelvedStateMachineType_OneShotShelve),
          {},
          std::move(completion));
      })();
  }
  catch (...)
  {
    ::ua::detail::invoke_user_callback(
      mLogger, callback, VoidResult{exception_to_status_code(std::current_exception())});
  }
}

void AlarmConditionTrackerImpl::unshelve_async(
  TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept
{
  try
  {
    if (!callback)
    {
      // The caller supplied no completion, so the operation result is not needed.
      callback = [](VoidResult) {
      };
    }
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      std::move(callback),
      VoidResult{StatusCode{Status::BadConnectionClosed}},
      [key = std::move(key)](
        AlarmConditionTrackerImpl& self, std::function<void(VoidResult)> completion) mutable
      {
        self.call_shelving_method(key,
          "Unshelve",
          static_cast<std::uint32_t>(ua::MethodId::ShelvedStateMachineType_Unshelve),
          {},
          std::move(completion));
      })();
  }
  catch (...)
  {
    ::ua::detail::invoke_user_callback(
      mLogger, callback, VoidResult{exception_to_status_code(std::current_exception())});
  }
}

namespace
{

/// The single-element RelativePath `/<HasComponent>ns0:<name>` - the reference the ShelvingState object
/// and its Methods hang off (OPC 10000-9 Table 42 / Table 73 both declare them HasComponent).
ua::BrowsePath make_component_path(const ua::NodeId& startNode, std::string_view name)
{
  ua::RelativePathElement element;
  element.reference_type_id() =
    ua::NodeId{std::uint16_t{0}, static_cast<std::uint32_t>(ua::ReferenceTypeId::HasComponent)};
  element.is_inverse() = false;
  element.include_subtypes() = false;
  element.target_name() = ua::QualifiedName{0, std::string{name}};

  ua::BrowsePath path;
  path.starting_node() = startNode;
  path.relative_path().elements().push_back(std::move(element));
  return path;
}

/// The first target of translate result @p index, or nullopt when the Server resolved nothing there.
std::optional<ua::NodeId> translated_target(
  const ua::TranslateBrowsePathsToNodeIdsResponse& response, std::size_t index)
{
  const auto& results = response.results();
  if (index >= results.size() || results[index].status_code().is_bad() || results[index].targets().empty())
  {
    return std::nullopt;
  }
  return results[index].targets()[0].target_id().node_id();
}

}  // namespace

void AlarmConditionTrackerImpl::issue_resolved_call(ua::NodeId objectId, ua::NodeId methodId,
  std::vector<ua::Variant> inputs, std::function<void(ua::VoidResult)> callback)
{
  auto wire = mWireOps.lock();
  if (!wire)
  {
    deliver_void(std::move(callback),
      VoidResult{StatusCode{Status::BadConnectionClosed},
        ua::make_error_detail("BadConnectionClosed",
          "condition method call: Connection gone",
          "client.tier2.alarm_tracker.method")});
    return;
  }
  ua::CallMethodRequest method;
  method.object_id() = std::move(objectId);
  method.method_id() = std::move(methodId);
  for (auto& input : inputs)
  {
    method.input_arguments().push_back(std::move(input));
  }
  ua::CallRequest request;
  request.methods_to_call().push_back(std::move(method));
  wire->call_async(std::move(request),
    [callback = std::move(callback)](Result<ua::CallResponse> result) mutable
    { callback(flatten_call(std::move(result))); });
}

void AlarmConditionTrackerImpl::call_shelving_method(const TrackedKey& key, std::string_view methodName,
  std::uint32_t wellKnownMethodId, std::vector<ua::Variant> inputs,
  std::function<void(ua::VoidResult)> callback)
{
  const auto cached = mShelvingNodes.find(key.conditionId);
  if (cached != mShelvingNodes.end())
  {
    const auto method = cached->second.methodIds.find(std::string{methodName});
    if (method != cached->second.methodIds.end())
    {
      issue_resolved_call(
        cached->second.shelvingStateId, method->second, std::move(inputs), std::move(callback));
      return;
    }
  }

  auto wire = mWireOps.lock();
  if (!wire)
  {
    deliver_void(std::move(callback),
      VoidResult{StatusCode{Status::BadConnectionClosed},
        ua::make_error_detail("BadConnectionClosed",
          "shelving method call: Connection gone",
          "client.tier2.alarm_tracker.method")});
    return;
  }

  // Both hops in one request: [0] the ShelvingState object, [1] the Method on it.
  ua::TranslateBrowsePathsToNodeIdsRequest translate;
  translate.browse_paths().push_back(make_component_path(key.conditionId, "ShelvingState"));
  ua::BrowsePath methodPath = make_component_path(key.conditionId, "ShelvingState");
  ua::RelativePathElement methodElement;
  methodElement.reference_type_id() =
    ua::NodeId{std::uint16_t{0}, static_cast<std::uint32_t>(ua::ReferenceTypeId::HasComponent)};
  methodElement.is_inverse() = false;
  methodElement.include_subtypes() = false;
  methodElement.target_name() = ua::QualifiedName{0, std::string{methodName}};
  methodPath.relative_path().elements().push_back(std::move(methodElement));
  translate.browse_paths().push_back(std::move(methodPath));

  wire->translate_browse_paths_async(std::move(translate),
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [self = weak_from_this(),
        conditionId = key.conditionId,
        methodName = std::string{methodName},
        wellKnownMethodId,
        inputs = std::move(inputs),
        callback = std::move(callback)](AlarmConditionTrackerImpl& tracker,
        Result<ua::TranslateBrowsePathsToNodeIdsResponse>
          translated) mutable
      {
        static_cast<void>(self);
        // The tracker calls the Method this lookup finds, so an Uncertain answer (the service, its
        // ServiceResult or either path) is refused (ReferencesAnswerUncertain). A Bad one means the Server
        // does not expose the ShelvingState, and the call falls back to the ConditionId form below.
        if (const StatusCode uncertain = uncertain_translation(translated); uncertain.is_uncertain())
        {
          tracker.deliver_void(std::move(callback),
            VoidResult{uncertain_answer_refused(
              uncertain, "ReferencesAnswerUncertain", "client.tier2.alarm_tracker.method")});
          return;
        }
        std::optional<ua::NodeId> shelvingStateId;
        std::optional<ua::NodeId> methodId;
        if (translated.is_good() && translated.value().response_header().service_result().is_good())
        {
          shelvingStateId = translated_target(translated.value(), 0);
          methodId = translated_target(translated.value(), 1);
        }

        if (shelvingStateId.has_value() && methodId.has_value())
        {
          auto& entry = tracker.mShelvingNodes[conditionId];
          entry.shelvingStateId = *shelvingStateId;
          entry.methodIds[methodName] = *methodId;
          tracker.issue_resolved_call(*shelvingStateId, *methodId, std::move(inputs), std::move(callback));
          return;
        }

        // The Server does not expose this Condition's ShelvingState. 5.8.17 provides for exactly that:
        // ConditionId as the ObjectId with the well-known Method node.
        tracker.mLogger.debug({{"method", methodName}},
          "condition exposes no ShelvingState child; addressing the shelving method by ConditionId");
        tracker.issue_resolved_call(
          conditionId, ua::NodeId{wellKnownMethodId}, std::move(inputs), std::move(callback));
      }));
}

void AlarmConditionTrackerImpl::call_condition_method(const TrackedKey& key, std::uint32_t methodId,
  std::vector<ua::Variant> inputs, std::function<void(ua::VoidResult)> callback)
{
  auto wire = mWireOps.lock();
  if (!wire)
  {
    deliver_void(std::move(callback),
      VoidResult{StatusCode{Status::BadConnectionClosed},
        ua::make_error_detail("BadConnectionClosed",
          "condition method call: Connection gone",
          "client.tier2.alarm_tracker.method")});
    return;
  }
  ua::CallMethodRequest method;
  method.object_id() = key.conditionId;  // CL-AC-009: ObjectId = ConditionId, never the Type node
  method.method_id() = ua::NodeId{methodId};
  for (auto& input : inputs)
  {
    method.input_arguments().push_back(std::move(input));
  }
  ua::CallRequest request;
  request.methods_to_call().push_back(std::move(method));

  // The Call completion already runs on the executor (WireOps contract) and touches no strand state  -
  // flatten and deliver directly.
  wire->call_async(std::move(request),
    [callback = std::move(callback)](Result<ua::CallResponse> result) mutable
    { callback(flatten_call(std::move(result))); });
}

// ---- Hook feed (on strand) ----

void AlarmConditionTrackerImpl::handle_event_on_strand(const EventNotification& notification)
{
  TrackedCondition decoded = decode_condition(notification, mLogger);
  TrackedKey key = decoded.key;

  // CL-AC-005 (section 8.8.3): within an OPEN refresh window, a replayed event MUST NOT regress a branch that
  // a later LIVE event already advanced. A refresh replay carries the server's ORIGINAL (older) ReceiveTime;
  // if the tracked entry's ReceiveTime is strictly newer, the stale replay is dropped (advisory) instead of
  // overwriting the live state. Outside any window (no replay in flight) last-arrived semantics are
  // unchanged. The guard applies before the Retain handling too, so a stale Retain=False replay cannot
  // remove a branch a newer live Retain=True event kept active.
  if (!mActiveRefreshWindows.empty())
  {
    if (const TrackedCondition* live = find(key); live != nullptr && live->receiveTime > decoded.receiveTime)
    {
      mLogger.warning({{"source", "client.tier2.alarm_tracker.refresh_replay_skipped_for_newer_live"}},
        "dropping a refresh-replay event older than the tracked live branch state (CL-AC-005)");
      return;
    }
  }

  // CL-AC-023 / CL-AC-025: advise on a detected server-side data-integrity violation in the raw event. The
  // raw values are still surfaced verbatim below (never refused/coerced/dropped)  -  this only ADVISES.
  detect_and_advise_data_integrity(decoded);

  if (!decoded.retain)
  {
    // CL-AC-006: Retain=False removes the branch and fires condition_removed.
    const auto it = std::find_if(mTrackedConditions.begin(),
      mTrackedConditions.end(),
      [&key](const TrackedCondition& tc) { return tc.key == key; });
    if (it != mTrackedConditions.end())
    {
      mTrackedConditions.erase(it);
      for (const auto& observer : mRemovedObservers)
      {
        boost::asio::post(
          mExecutor, ua::async::guarded(mLogger, [observer, key]() mutable { observer(key); }));
      }
    }
    refresh_info_snapshot();
    return;
  }

  TrackedCondition* existing = find(key);
  if (existing == nullptr)
  {
    // cache-then-observer (CL-EVT-003): the entry is inserted into the map BEFORE the observer fires, so a
    // consumer that re-reads the tracker in its callback sees the new condition.
    mTrackedConditions.push_back(decoded);
    const TrackedCondition inserted = mTrackedConditions.back();
    for (const auto& observer : mAddedObservers)
    {
      boost::asio::post(
        mExecutor, ua::async::guarded(mLogger, [observer, inserted]() mutable { observer(inserted); }));
    }
  }
  else
  {
    *existing = decoded;
    const TrackedCondition changed = *existing;
    for (const auto& observer : mChangedObservers)
    {
      boost::asio::post(
        mExecutor, ua::async::guarded(mLogger, [observer, changed]() mutable { observer(changed); }));
    }
  }
  refresh_info_snapshot();
}

void AlarmConditionTrackerImpl::detect_and_advise_data_integrity(const TrackedCondition& condition)
{
  // Runs ON the strand. Each positive detection ADVISES twice: (1) a source-tagged advisory log (always,
  // even if the sink is gone), and (2) the AlarmObserver::on_data_integrity_warning hook via the WEAK
  // ObserverSink (locked per fire; skipped if expired). The ErrorDetail is NEVER discarded  -  it carries the
  // source tag (symbolic id + producing component) and the offending values (highest-priority rule).
  if (limit_inequality(condition))
  {
    const std::string summary = fmt::format(
      "limit inequality: the ordering invariant lowLow<=low<=high<=highHigh is violated "
      "(lowLow={}, low={}, high={}, highHigh={})",
      render_limit(condition.lowLowLimit),
      render_limit(condition.lowLimit),
      render_limit(condition.highLimit),
      render_limit(condition.highHighLimit));
    mLogger.warning({{"source", "client.tier2.alarm_tracker.limit_inequality"}},
      "alarm data-integrity advisory: {}",
      summary);
    if (auto sink = mObserverSink.lock())
    {
      sink->fire_data_integrity_warning(condition.key,
        DataIntegrityKind::LimitInequality,
        ua::ErrorDetail::build("LimitInequalityViolated",
          "Alarm limit values violate their ordering invariant",
          "client.tier2.alarm_tracker.limit_inequality")
          .context(ua::ContextKeys::errorMessage, summary));
    }
  }

  if (non_exclusive_cross_group(condition))
  {
    const std::string summary = fmt::format(
      "non-exclusive cross-group concurrency: a high-group AND a low-group limit state are simultaneously "
      "active (high={}, highHigh={}, low={}, lowLow={})",
      render_state(condition.highState),
      render_state(condition.highHighState),
      render_state(condition.lowState),
      render_state(condition.lowLowState));
    mLogger.warning({{"source", "client.tier2.alarm_tracker.non_exclusive_cross_group"}},
      "alarm data-integrity advisory: {}",
      summary);
    if (auto sink = mObserverSink.lock())
    {
      sink->fire_data_integrity_warning(condition.key,
        DataIntegrityKind::NonExclusiveCrossGroup,
        ua::ErrorDetail::build("NonExclusiveLimitCrossGroup",
          "Non-exclusive alarm limit states are simultaneously active across opposing groups",
          "client.tier2.alarm_tracker.non_exclusive_cross_group")
          .context(ua::ContextKeys::errorMessage, summary));
    }
  }
}

void AlarmConditionTrackerImpl::handle_refresh_start_on_strand(const EventNotification& notification)
{
  // CL-AC-004: window membership keys on the RefreshStart EventId (dedup tolerated).
  if (std::find(mActiveRefreshWindows.begin(), mActiveRefreshWindows.end(), notification.eventId) ==
      mActiveRefreshWindows.end())
  {
    mActiveRefreshWindows.push_back(notification.eventId);
  }
  refresh_info_snapshot();
}

void AlarmConditionTrackerImpl::handle_refresh_end_on_strand(const EventNotification& notification)
{
  // A RefreshEnd's EventId is NOT a correlation key back to the RefreshStart. OPC 10000-9 5.5.7 issues two
  // separate Event instances - step 1 a RefreshStartEventType, step 4 a RefreshEndEventType - and says only
  // that the copies WITHIN each set share an EventId ("Each of the Event copies shall contain the same
  // EventId"), never that the start and the end share one. Two distinct events have two distinct EventIds.
  //
  // So looking the RefreshEnd's EventId up among the open RefreshStart EventIds, as this did, can never
  // match against a conforming server: the window stayed open forever, mRefreshInProgress stayed latched,
  // and every later refresh_async returned Bad_RefreshInProgress for the life of the tracker. The unit tests
  // missed it because each of them posts the end with the same EventId constant as the start, which is a
  // shape no server produces.
  //
  // The pairing that IS available is positional. A Subscription's refreshes complete in the order they were
  // started, so a RefreshEnd closes the OLDEST open window. The EventId still earns its keep, one step down:
  // it collapses the copies queued into each Notifier MonitoredItem so that one refresh closes one window.
  if (std::find(mSeenRefreshEndEventIds.begin(), mSeenRefreshEndEventIds.end(), notification.eventId) !=
      mSeenRefreshEndEventIds.end())
  {
    return;  // another Notifier's copy of a RefreshEnd already counted
  }
  mSeenRefreshEndEventIds.push_back(notification.eventId);
  if (mSeenRefreshEndEventIds.size() > sRefreshEndLedgerLimit)
  {
    mSeenRefreshEndEventIds.pop_front();
  }
  if (!mActiveRefreshWindows.empty())
  {
    mActiveRefreshWindows.erase(mActiveRefreshWindows.begin());
  }
  refresh_windows_maybe_complete();
}

void AlarmConditionTrackerImpl::handle_refresh_required_on_strand(const EventNotification& /*notification*/)
{
  // CL-AC-007: signal the observer that the server asked for a resync  -  the observer wants to know
  // regardless of the issue decision below. Best-effort weak-lock; RefreshRequired is attacker-influenceable,
  // so this never throws out of the on-strand handler (the reverse-connect no-throw-in-handler lesson). A
  // server that spams RefreshRequired yields one fire each  -  coalescing is the batched EV1-D1 follow-up
  // (AC007-D2). The refresh ISSUE decision (the in-progress/window gate) is unchanged: it already collapses a
  // double-issue.
  if (auto sink = mObserverSink.lock())
  {
    sink->fire_refresh_required(mTrackedConditions.size());
  }
  // CL-AC-007: a RefreshRequired while a window is open queues a follow-on; otherwise refresh now.
  if (!mActiveRefreshWindows.empty() || mRefreshInProgress)
  {
    mPendingFollowOnRefresh = true;
    // Republish the observability snapshot: pendingFollowOnRefresh is a cross-strand info() field, so a
    // consumer polling info() must see the queued follow-on (every other mutating on-strand path refreshes).
    refresh_info_snapshot();
    return;
  }
  if (!mClosing)
  {
    mRefreshInProgress = true;  // internal refresh (no user callback)
    issue_refresh();
  }
}

void AlarmConditionTrackerImpl::handle_first_event_after_attach_on_strand()
{
  // CL-AC-003: schedule the initial refresh once the backbone MI queue is wired (no user callback).
  if (mClosing || mRefreshInProgress)
  {
    return;
  }
  mRefreshInProgress = true;
  issue_refresh();
}

void AlarmConditionTrackerImpl::set_backbone_ids(std::uint32_t subscriptionId, std::uint32_t monitoredItemId)
{
  mBackboneSubscriptionId = subscriptionId;
  mBackboneMonitoredItemId = monitoredItemId;
}

void AlarmConditionTrackerImpl::handle_backbone_recovered_on_strand(BackboneRecoveryReason reason)
{
  // CL-AC-003 (AC003-D1a) / Finding 2 (R4): the backbone's old refresh windows can never complete  -  a
  // session-CHANGED reconnect recreated the backbone MonitoredItem on a NEW session (no Republish for the old
  // windows), OR a reactive Republish drain lost messages (a dropped RefreshEnd). Reset the dead refresh
  // state  -  otherwise the machine wedges (mRefreshInProgress stuck) and every future refresh_async returns
  // Bad_RefreshInProgress forever. Runs ON the strand (called by the subscriber's on_reconnect_recovered
  // dispatch on the shared strand). Best-effort; never throws.
  if (mClosing)
  {
    return;
  }
  // Deliver any in-flight USER refresh callback its reset status  -  the ErrorDetail is NEVER discarded (the
  // highest-priority rule); it carries the source tag so the loss is observable at the boundary. NOT
  // fail_refresh_and_reset: that auto-issues a queued follow-on, but here the backbone is not yet delivering,
  // so we must NOT fire a ConditionRefresh  -  the re-armed first-event path re-issues once it is. The reason
  // selects an ACCURATE status+message (a steady-state event-loss resync did NOT close the session, so
  // Bad_SessionClosed would mislead  -  R4); both prose strings are literals (prose-purity gate).
  if (mPendingRefreshCallback)
  {
    auto pending = std::move(mPendingRefreshCallback);
    mPendingRefreshCallback = nullptr;
    VoidResult resetResult =
      (reason == BackboneRecoveryReason::EventLossDetected)
        ? VoidResult{StatusCode{Status::BadSequenceNumberUnknown},
            ua::make_error_detail("BadSequenceNumberUnknown",
              "ConditionRefresh abandoned: event loss detected; condition state re-syncs",
              "client.tier2.alarm_tracker.event_loss_reset")}
        : VoidResult{StatusCode{Status::BadSessionClosed},
            ua::make_error_detail("BadSessionClosed",
              "ConditionRefresh abandoned: the session was re-established; state re-syncs on recovery",
              "client.tier2.alarm_tracker.reconnect_reset")};
    deliver_void(std::move(pending), std::move(resetResult));
  }
  mActiveRefreshWindows.clear();
  mSeenRefreshEndEventIds.clear();
  mRefreshInProgress = false;
  mRefreshTriggerStatus = StatusCode{Status::Good};
  mPendingFollowOnRefresh = false;
  refresh_info_snapshot();
}

void AlarmConditionTrackerImpl::handle_redundancy_switch_recovered_on_strand(ua::RedundancySupport mode)
{
  const bool requiresRefresh = mode == ua::RedundancySupport::Cold || mode == ua::RedundancySupport::Warm;
  if (mClosing || !requiresRefresh || !mPolicy.refreshOnRedundancySwitch)
  {
    return;
  }

  // Cold/Warm servers do not share live event state. Any pending refresh belongs to the former server and
  // can never authoritatively complete on this one; fail its user completion with a source-tagged detail
  // before resetting the state machine. Internal refreshes have no callback to lose.
  if (mPendingRefreshCallback)
  {
    auto pending = std::move(mPendingRefreshCallback);
    mPendingRefreshCallback = nullptr;
    deliver_void(std::move(pending),
      VoidResult{StatusCode{Status::BadSessionClosed},
        ua::make_error_detail("BadSessionClosed",
          "ConditionRefresh abandoned: a cold or warm redundant server became active",
          "client.tier2.alarm_tracker.redundancy_switch")});
  }

  // Never carry ConditionIds, BranchIds, EventIds, or refresh windows across a Cold/Warm server boundary.
  mTrackedConditions.clear();
  mActiveRefreshWindows.clear();
  mSeenRefreshEndEventIds.clear();
  mPendingFollowOnRefresh = false;
  mRefreshInProgress = true;
  mRefreshTriggerStatus = StatusCode{Status::Good};
  refresh_info_snapshot();
  issue_refresh();
}

ua::EventFilter AlarmConditionTrackerImpl::filter_contribution_on_strand() const
{
  ua::EventFilter filter;

  // CL-AC-002: the ConditionId via the empty-path NodeId operand (the instance's own NodeId).
  filter.select_clauses().push_back(make_condition_id_clause());

  // Every operand names the EventType that DECLARES its path. A conforming server validates each
  // SimpleAttributeOperand against that type before projecting an Event; using ConditionType for a subtype
  // field makes the clause invalid and projects null even when the concrete Event carries the field.
  const ua::NodeId conditionType{ua::ObjectTypeId::ConditionType};
  for (const std::string_view name :
    {"BranchId", "Retain", "ConditionName", "ConditionClassId", "ConditionClassName"})
  {
    filter.select_clauses().push_back(make_condition_clause(name));
  }

  const ua::NodeId acknowledgeableType{ua::ObjectTypeId::AcknowledgeableConditionType};
  const ua::NodeId alarmType{ua::ObjectTypeId::AlarmConditionType};
  const ua::NodeId limitType{ua::ObjectTypeId::LimitAlarmType};
  const ua::NodeId exclusiveLimitType{ua::ObjectTypeId::ExclusiveLimitAlarmType};
  const ua::NodeId nonExclusiveLimitType{ua::ObjectTypeId::NonExclusiveLimitAlarmType};

  for (const std::string_view name : {"HighHighLimit", "HighLimit", "LowLimit", "LowLowLimit"})
  {
    filter.select_clauses().push_back(make_condition_clause(limitType, name));
  }

  // TwoStateVariable Booleans live at [<State>, "Id"], not at the state object's display Value.
  filter.select_clauses().push_back(make_condition_clause(conditionType, {"EnabledState", "Id"}));
  for (const std::string_view state : {"AckedState", "ConfirmedState"})
  {
    filter.select_clauses().push_back(make_condition_clause(acknowledgeableType, {state, "Id"}));
  }
  filter.select_clauses().push_back(make_condition_clause(alarmType, {"ActiveState", "Id"}));
  for (const std::string_view state : {"HighHighState", "HighState", "LowState", "LowLowState"})
  {
    filter.select_clauses().push_back(make_condition_clause(nonExclusiveLimitType, {state, "Id"}));
  }
  filter.select_clauses().push_back(
    make_condition_clause(exclusiveLimitType, {"LimitState", "CurrentState"}));

  // Optional AlarmConditionType sub-states (CL-AC-016): the Suppressed/OutOfService/Silence/Latched
  // TwoStateVariable Booleans at [<State>, "Id"] and the ShelvingState current state at
  // ["ShelvingState", "CurrentState"], all declared on AlarmConditionType (its typeDefinitionId), plus the
  // aggregate SuppressedOrShelved single-segment Boolean. A server that does not model an optional sub-state
  // simply returns nothing for that clause (decode  to  nullopt).
  for (const std::string_view state :
    {"SuppressedState", "OutOfServiceState", "SilenceState", "LatchedState"})
  {
    filter.select_clauses().push_back(make_condition_clause(alarmType, {state, "Id"}));
  }
  filter.select_clauses().push_back(make_condition_clause(alarmType, {"ShelvingState", "CurrentState"}));
  filter.select_clauses().push_back(make_condition_clause(alarmType, "SuppressedOrShelved"));

  // CL-AC-022 optional AlarmConditionType properties. FirstInGroup is an Object, so its NodeId attribute is
  // selected; the remaining Variables/Properties expose their Value attribute.
  for (const std::string_view property : {"ReAlarmTime",
         "ReAlarmRepeatCount",
         "OnDelay",
         "OffDelay",
         "AudibleEnabled",
         "AudibleSound",
         "FirstInGroupFlag",
         "MaxTimeShelved"})
  {
    filter.select_clauses().push_back(make_condition_clause(alarmType, property));
  }
  filter.select_clauses().push_back(make_condition_node_clause(alarmType, "FirstInGroup"));

  // CL-AC-021: subtype properties must be requested against the type that declares them. A composite
  // ConditionType operand would not reliably resolve a subtype-only child on a conforming server.
  filter.select_clauses().push_back(
    make_condition_clause(ua::NodeId{ua::ObjectTypeId::OffNormalAlarmType}, "NormalState"));
  const ua::NodeId discrepancyType{ua::ObjectTypeId::DiscrepancyAlarmType};
  for (const std::string_view property : {"TargetValueNode", "ExpectedTime", "Tolerance"})
  {
    filter.select_clauses().push_back(make_condition_clause(discrepancyType, property));
  }

  // WhereClause OfType(ConditionType): built by the subscriber's composite accumulator (extract_of_types).
  ua::LiteralOperand operand;
  operand.value() = ua::Variant{ua::NodeId{ua::ObjectTypeId::ConditionType}};
  ua::ContentFilterElement element;
  element.filter_operator() = ua::FilterOperator::OfType;
  element.filter_operands().push_back(
    ua::RefStructure<ua::Structure>{std::make_unique<ua::LiteralOperand>(std::move(operand))});
  filter.where_clause().elements().push_back(std::move(element));
  return filter;
}

// ---- Helpers ----

TrackedCondition* AlarmConditionTrackerImpl::find(const TrackedKey& key)
{
  const auto it = std::find_if(mTrackedConditions.begin(),
    mTrackedConditions.end(),
    [&key](const TrackedCondition& tc) { return tc.key == key; });
  return it == mTrackedConditions.end() ? nullptr : &*it;
}

const TrackedCondition* AlarmConditionTrackerImpl::find(const TrackedKey& key) const
{
  const auto it = std::find_if(mTrackedConditions.begin(),
    mTrackedConditions.end(),
    [&key](const TrackedCondition& tc) { return tc.key == key; });
  return it == mTrackedConditions.end() ? nullptr : &*it;
}

void AlarmConditionTrackerImpl::deliver_void(
  std::function<void(ua::VoidResult)> callback, ua::VoidResult result)
{
  if (!callback)
  {
    return;
  }
  boost::asio::post(mExecutor,
    ua::async::guarded(mLogger, [callback = std::move(callback), result]() mutable { callback(result); }));
}

std::shared_ptr<const AlarmConditionTrackerInfo> AlarmConditionTrackerImpl::info() const noexcept
{
  return mInfoSnapshot.load();
}

void AlarmConditionTrackerImpl::refresh_info_snapshot()
{
  auto trackerInfo = std::make_shared<AlarmConditionTrackerInfo>();
  trackerInfo->trackedConditionCount = mTrackedConditions.size();
  trackerInfo->openRefreshWindowCount = mActiveRefreshWindows.size();
  trackerInfo->pendingFollowOnRefresh = mPendingFollowOnRefresh;
  trackerInfo->useRefresh2 = mUseRefresh2;
  mInfoSnapshot.store(std::move(trackerInfo));
}

}  // namespace ua::client::detail
