// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// *** THIS FILE IS GENERATED - DO NOT EDIT ***

#include "ua_objecttype_id.h"
#include "ua_data_value.h"

#include <memory>

#include "ua_condition_payload.h"
#include "ua_acknowledgeable_condition_payload.h"
#include "ua_alarm_condition_payload.h"
#include "ua_limit_alarm_payload.h"
#include "ua_non_exclusive_limit_alarm_payload.h"
#include "ua_non_exclusive_level_alarm_payload.h"
#include "ua_non_exclusive_rate_of_change_alarm_payload.h"
#include "ua_non_exclusive_deviation_alarm_payload.h"
#include "ua_discrete_alarm_payload.h"
#include "ua_off_normal_alarm_payload.h"
#include "ua_trip_alarm_payload.h"
#include "ua_audit_event_payload.h"
#include "ua_audit_update_method_event_payload.h"
#include "ua_audit_condition_event_payload.h"
#include "ua_audit_condition_shelving_event_payload.h"
#include "ua_progress_event_payload.h"
#include "ua_system_event_payload.h"
#include "ua_system_status_change_event_payload.h"
#include "ua_system_off_normal_alarm_payload.h"
#include "ua_audit_update_state_event_payload.h"
#include "ua_audit_program_transition_event_payload.h"
#include "ua_trust_list_updated_audit_event_payload.h"
#include "ua_certificate_updated_audit_event_payload.h"
#include "ua_certificate_expiration_alarm_payload.h"
#include "ua_audit_condition_reset_event_payload.h"
#include "ua_pub_sub_status_event_payload.h"
#include "ua_configuration_updated_audit_event_payload.h"
#include "ua_pub_sub_transport_limits_exceed_event_payload.h"
#include "ua_pub_sub_communication_failure_event_payload.h"
#include "ua_discrepancy_alarm_payload.h"
#include "ua_audit_condition_suppression_event_payload.h"
#include "ua_audit_condition_silence_event_payload.h"
#include "ua_audit_condition_out_of_service_event_payload.h"
#include "ua_role_mapping_rule_changed_audit_event_payload.h"
#include "ua_key_credential_audit_event_payload.h"
#include "ua_key_credential_updated_audit_event_payload.h"
#include "ua_key_credential_deleted_audit_event_payload.h"
#include "ua_instrument_diagnostic_alarm_payload.h"
#include "ua_system_diagnostic_alarm_payload.h"
#include "ua_audit_update_event_payload.h"
#include "ua_audit_history_update_event_payload.h"
#include "ua_audit_history_annotation_update_event_payload.h"
#include "ua_trust_list_out_of_date_alarm_payload.h"
#include "ua_base_log_event_payload.h"
#include "ua_log_overflow_event_payload.h"
#include "ua_audit_security_event_payload.h"
#include "ua_audit_channel_event_payload.h"
#include "ua_audit_open_secure_channel_event_payload.h"
#include "ua_audit_session_event_payload.h"
#include "ua_audit_create_session_event_payload.h"
#include "ua_audit_activate_session_event_payload.h"
#include "ua_audit_cancel_event_payload.h"
#include "ua_audit_certificate_event_payload.h"
#include "ua_audit_certificate_data_mismatch_event_payload.h"
#include "ua_audit_certificate_expired_event_payload.h"
#include "ua_audit_certificate_invalid_event_payload.h"
#include "ua_audit_certificate_untrusted_event_payload.h"
#include "ua_audit_certificate_revoked_event_payload.h"
#include "ua_audit_certificate_mismatch_event_payload.h"
#include "ua_audit_node_management_event_payload.h"
#include "ua_audit_add_nodes_event_payload.h"
#include "ua_audit_delete_nodes_event_payload.h"
#include "ua_audit_add_references_event_payload.h"
#include "ua_audit_delete_references_event_payload.h"
#include "ua_audit_write_update_event_payload.h"
#include "ua_device_failure_event_payload.h"
#include "ua_base_model_change_event_payload.h"
#include "ua_general_model_change_event_payload.h"
#include "ua_transition_event_payload.h"
#include "ua_audit_client_event_payload.h"
#include "ua_program_transition_event_payload.h"
#include "ua_audit_client_update_method_result_event_payload.h"
#include "ua_semantic_change_event_payload.h"
#include "ua_audit_url_mismatch_event_payload.h"
#include "ua_refresh_start_event_payload.h"
#include "ua_refresh_end_event_payload.h"
#include "ua_refresh_required_event_payload.h"
#include "ua_audit_condition_enable_event_payload.h"
#include "ua_audit_condition_comment_event_payload.h"
#include "ua_dialog_condition_payload.h"
#include "ua_audit_history_event_update_event_payload.h"
#include "ua_audit_history_value_update_event_payload.h"
#include "ua_audit_history_delete_event_payload.h"
#include "ua_audit_history_raw_modify_delete_event_payload.h"
#include "ua_audit_history_at_time_delete_event_payload.h"
#include "ua_audit_history_event_delete_event_payload.h"
#include "ua_event_queue_overflow_event_payload.h"
#include "ua_trust_list_update_requested_audit_event_payload.h"
#include "ua_certificate_update_requested_audit_event_payload.h"
#include "ua_audit_history_configuration_change_event_payload.h"
#include "ua_audit_history_bulk_insert_event_payload.h"
#include "ua_program_transition_audit_event_payload.h"
#include "ua_audit_condition_respond_event_payload.h"
#include "ua_audit_condition_acknowledge_event_payload.h"
#include "ua_audit_condition_confirm_event_payload.h"
#include "ua_exclusive_limit_alarm_payload.h"
#include "ua_exclusive_level_alarm_payload.h"
#include "ua_exclusive_rate_of_change_alarm_payload.h"
#include "ua_exclusive_deviation_alarm_payload.h"

namespace ua
{

ConditionPayload::ConditionPayload()
{
  eventType = NodeId{ObjectTypeId::ConditionType};
}

std::unique_ptr<BaseEvent> ConditionPayload::clone() const
{
  return std::make_unique<ConditionPayload>(*this);
}

Variant ConditionPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = BaseEvent::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "ConditionClassId")
      return Variant{conditionClassId};
    if (name == "ConditionClassName")
      return Variant{conditionClassName};
    if (name == "ConditionSubClassId" && conditionSubClassId)
      return Variant{conditionSubClassId.value()};
    if (name == "ConditionSubClassName" && conditionSubClassName)
      return Variant{conditionSubClassName.value()};
    if (name == "ConditionName")
      return Variant{conditionName};
    if (name == "BranchId")
      return Variant{branchId};
    if (name == "Retain")
      return Variant{retain};
    if (name == "SupportsFilteredRetain")
      return Variant{supportsFilteredRetain};
    if (name == "ClientUserId")
      return Variant{clientUserId};
    if (name == "EnabledState")
      return Variant{enabledState.currentState};
    if (name == "Quality")
      return quality.value;
    if (name == "LastSeverity")
      return lastSeverity.value;
    if (name == "Comment")
      return comment.value;
  }

  if (browse_path.size() == 2 && browse_path[0].namespace_index() == 0 &&
      browse_path[1].namespace_index() == 0)
  {
    const auto parent = static_cast<std::string_view>(browse_path[0].name());
    const auto child = static_cast<std::string_view>(browse_path[1].name());
    if (parent == "EnabledState")
    {
      if (child == "Id")
        return Variant{enabledState.id};
      if (child == "TransitionTime")
        return Variant{enabledState.transitionTime};
      if (child == "CurrentState")
        return Variant{enabledState.currentState};
    }
    if (parent == "Quality")
    {
      if (child == "SourceTimestamp")
        return Variant{quality.sourceTimestamp};
    }
    if (parent == "LastSeverity")
    {
      if (child == "SourceTimestamp")
        return Variant{lastSeverity.sourceTimestamp};
    }
    if (parent == "Comment")
    {
      if (child == "SourceTimestamp")
        return Variant{comment.sourceTimestamp};
    }
  }

  return Variant{};
}

AcknowledgeableConditionPayload::AcknowledgeableConditionPayload()
{
  eventType = NodeId{ObjectTypeId::AcknowledgeableConditionType};
}

std::unique_ptr<BaseEvent> AcknowledgeableConditionPayload::clone() const
{
  return std::make_unique<AcknowledgeableConditionPayload>(*this);
}

Variant AcknowledgeableConditionPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = ConditionPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "AckedState")
      return Variant{ackedState.currentState};
    if (name == "ConfirmedState" && confirmedState.has_value())
      return Variant{confirmedState.value().currentState};
  }

  if (browse_path.size() == 2 && browse_path[0].namespace_index() == 0 &&
      browse_path[1].namespace_index() == 0)
  {
    const auto parent = static_cast<std::string_view>(browse_path[0].name());
    const auto child = static_cast<std::string_view>(browse_path[1].name());
    if (parent == "AckedState")
    {
      if (child == "Id")
        return Variant{ackedState.id};
      if (child == "TransitionTime")
        return Variant{ackedState.transitionTime};
      if (child == "CurrentState")
        return Variant{ackedState.currentState};
    }
    if (parent == "ConfirmedState" && confirmedState.has_value())
    {
      if (child == "Id")
        return Variant{confirmedState.value().id};
      if (child == "TransitionTime")
        return Variant{confirmedState.value().transitionTime};
      if (child == "CurrentState")
        return Variant{confirmedState.value().currentState};
    }
  }

  return Variant{};
}

AlarmConditionPayload::AlarmConditionPayload()
{
  eventType = NodeId{ObjectTypeId::AlarmConditionType};
}

std::unique_ptr<BaseEvent> AlarmConditionPayload::clone() const
{
  return std::make_unique<AlarmConditionPayload>(*this);
}

Variant AlarmConditionPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AcknowledgeableConditionPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "InputNode")
      return Variant{inputNode};
    if (name == "SuppressedOrShelved")
      return Variant{suppressedOrShelved};
    if (name == "MaxTimeShelved" && maxTimeShelved)
      return Variant{maxTimeShelved.value()};
    if (name == "AudibleEnabled" && audibleEnabled)
      return Variant{audibleEnabled.value()};
    if (name == "OnDelay" && onDelay)
      return Variant{onDelay.value()};
    if (name == "OffDelay" && offDelay)
      return Variant{offDelay.value()};
    if (name == "ReAlarmTime" && reAlarmTime)
      return Variant{reAlarmTime.value()};
    if (name == "ActiveState")
      return Variant{activeState.currentState};
    if (name == "SuppressedState" && suppressedState.has_value())
      return Variant{suppressedState.value().currentState};
    if (name == "OutOfServiceState" && outOfServiceState.has_value())
      return Variant{outOfServiceState.value().currentState};
    if (name == "ShelvingState" && shelvingState.has_value())
      return Variant{shelvingState.value().currentState};
    if (name == "SilenceState" && silenceState.has_value())
      return Variant{silenceState.value().currentState};
    if (name == "LatchedState" && latchedState.has_value())
      return Variant{latchedState.value().currentState};
  }

  if (browse_path.size() == 2 && browse_path[0].namespace_index() == 0 &&
      browse_path[1].namespace_index() == 0)
  {
    const auto parent = static_cast<std::string_view>(browse_path[0].name());
    const auto child = static_cast<std::string_view>(browse_path[1].name());
    if (parent == "ActiveState")
    {
      if (child == "Id")
        return Variant{activeState.id};
      if (child == "TransitionTime")
        return Variant{activeState.transitionTime};
      if (child == "CurrentState")
        return Variant{activeState.currentState};
    }
    if (parent == "SuppressedState" && suppressedState.has_value())
    {
      if (child == "Id")
        return Variant{suppressedState.value().id};
      if (child == "TransitionTime")
        return Variant{suppressedState.value().transitionTime};
      if (child == "CurrentState")
        return Variant{suppressedState.value().currentState};
    }
    if (parent == "OutOfServiceState" && outOfServiceState.has_value())
    {
      if (child == "Id")
        return Variant{outOfServiceState.value().id};
      if (child == "TransitionTime")
        return Variant{outOfServiceState.value().transitionTime};
      if (child == "CurrentState")
        return Variant{outOfServiceState.value().currentState};
    }
    if (parent == "ShelvingState" && shelvingState.has_value())
    {
      if (child == "CurrentState")
        return Variant{shelvingState.value().currentState};
      if (child == "UnshelveTime")
        return Variant{shelvingState.value().unshelveTime};
    }
    if (parent == "SilenceState" && silenceState.has_value())
    {
      if (child == "Id")
        return Variant{silenceState.value().id};
      if (child == "TransitionTime")
        return Variant{silenceState.value().transitionTime};
      if (child == "CurrentState")
        return Variant{silenceState.value().currentState};
    }
    if (parent == "LatchedState" && latchedState.has_value())
    {
      if (child == "Id")
        return Variant{latchedState.value().id};
      if (child == "TransitionTime")
        return Variant{latchedState.value().transitionTime};
      if (child == "CurrentState")
        return Variant{latchedState.value().currentState};
    }
  }

  if (browse_path.size() == 3 && browse_path[0].namespace_index() == 0 &&
      browse_path[1].namespace_index() == 0 && browse_path[2].namespace_index() == 0)
  {
    const auto a = static_cast<std::string_view>(browse_path[0].name());
    const auto b = static_cast<std::string_view>(browse_path[1].name());
    const auto c = static_cast<std::string_view>(browse_path[2].name());
    if (a == "ShelvingState" && b == "CurrentState" && c == "Id" && shelvingState.has_value())
      return Variant{shelvingState.value().id};
  }

  return Variant{};
}

LimitAlarmPayload::LimitAlarmPayload()
{
  eventType = NodeId{ObjectTypeId::LimitAlarmType};
}

std::unique_ptr<BaseEvent> LimitAlarmPayload::clone() const
{
  return std::make_unique<LimitAlarmPayload>(*this);
}

Variant LimitAlarmPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AlarmConditionPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "HighHighLimit" && highHighLimit)
      return Variant{highHighLimit.value()};
    if (name == "HighLimit" && highLimit)
      return Variant{highLimit.value()};
    if (name == "LowLimit" && lowLimit)
      return Variant{lowLimit.value()};
    if (name == "LowLowLimit" && lowLowLimit)
      return Variant{lowLowLimit.value()};
    if (name == "BaseHighHighLimit" && baseHighHighLimit)
      return Variant{baseHighHighLimit.value()};
    if (name == "BaseHighLimit" && baseHighLimit)
      return Variant{baseHighLimit.value()};
    if (name == "BaseLowLimit" && baseLowLimit)
      return Variant{baseLowLimit.value()};
    if (name == "BaseLowLowLimit" && baseLowLowLimit)
      return Variant{baseLowLowLimit.value()};
    if (name == "SeverityHighHigh" && severityHighHigh)
      return Variant{severityHighHigh.value()};
    if (name == "SeverityHigh" && severityHigh)
      return Variant{severityHigh.value()};
    if (name == "SeverityLow" && severityLow)
      return Variant{severityLow.value()};
    if (name == "SeverityLowLow" && severityLowLow)
      return Variant{severityLowLow.value()};
    if (name == "HighHighDeadband" && highHighDeadband)
      return Variant{highHighDeadband.value()};
    if (name == "HighDeadband" && highDeadband)
      return Variant{highDeadband.value()};
    if (name == "LowDeadband" && lowDeadband)
      return Variant{lowDeadband.value()};
    if (name == "LowLowDeadband" && lowLowDeadband)
      return Variant{lowLowDeadband.value()};
  }

  return Variant{};
}

NonExclusiveLimitAlarmPayload::NonExclusiveLimitAlarmPayload()
{
  eventType = NodeId{ObjectTypeId::NonExclusiveLimitAlarmType};
}

std::unique_ptr<BaseEvent> NonExclusiveLimitAlarmPayload::clone() const
{
  return std::make_unique<NonExclusiveLimitAlarmPayload>(*this);
}

Variant NonExclusiveLimitAlarmPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = LimitAlarmPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "HighHighState" && highHighState.has_value())
      return Variant{highHighState.value().currentState};
    if (name == "HighState" && highState.has_value())
      return Variant{highState.value().currentState};
    if (name == "LowState" && lowState.has_value())
      return Variant{lowState.value().currentState};
    if (name == "LowLowState" && lowLowState.has_value())
      return Variant{lowLowState.value().currentState};
  }

  if (browse_path.size() == 2 && browse_path[0].namespace_index() == 0 &&
      browse_path[1].namespace_index() == 0)
  {
    const auto parent = static_cast<std::string_view>(browse_path[0].name());
    const auto child = static_cast<std::string_view>(browse_path[1].name());
    if (parent == "HighHighState" && highHighState.has_value())
    {
      if (child == "Id")
        return Variant{highHighState.value().id};
      if (child == "TransitionTime")
        return Variant{highHighState.value().transitionTime};
      if (child == "CurrentState")
        return Variant{highHighState.value().currentState};
    }
    if (parent == "HighState" && highState.has_value())
    {
      if (child == "Id")
        return Variant{highState.value().id};
      if (child == "TransitionTime")
        return Variant{highState.value().transitionTime};
      if (child == "CurrentState")
        return Variant{highState.value().currentState};
    }
    if (parent == "LowState" && lowState.has_value())
    {
      if (child == "Id")
        return Variant{lowState.value().id};
      if (child == "TransitionTime")
        return Variant{lowState.value().transitionTime};
      if (child == "CurrentState")
        return Variant{lowState.value().currentState};
    }
    if (parent == "LowLowState" && lowLowState.has_value())
    {
      if (child == "Id")
        return Variant{lowLowState.value().id};
      if (child == "TransitionTime")
        return Variant{lowLowState.value().transitionTime};
      if (child == "CurrentState")
        return Variant{lowLowState.value().currentState};
    }
  }

  return Variant{};
}

NonExclusiveLevelAlarmPayload::NonExclusiveLevelAlarmPayload()
{
  eventType = NodeId{ObjectTypeId::NonExclusiveLevelAlarmType};
}

std::unique_ptr<BaseEvent> NonExclusiveLevelAlarmPayload::clone() const
{
  return std::make_unique<NonExclusiveLevelAlarmPayload>(*this);
}

Variant NonExclusiveLevelAlarmPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = NonExclusiveLimitAlarmPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

NonExclusiveRateOfChangeAlarmPayload::NonExclusiveRateOfChangeAlarmPayload()
{
  eventType = NodeId{ObjectTypeId::NonExclusiveRateOfChangeAlarmType};
}

std::unique_ptr<BaseEvent> NonExclusiveRateOfChangeAlarmPayload::clone() const
{
  return std::make_unique<NonExclusiveRateOfChangeAlarmPayload>(*this);
}

Variant NonExclusiveRateOfChangeAlarmPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = NonExclusiveLimitAlarmPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "EngineeringUnits" && engineeringUnits)
      return Variant{engineeringUnits.value()};
  }

  return Variant{};
}

NonExclusiveDeviationAlarmPayload::NonExclusiveDeviationAlarmPayload()
{
  eventType = NodeId{ObjectTypeId::NonExclusiveDeviationAlarmType};
}

std::unique_ptr<BaseEvent> NonExclusiveDeviationAlarmPayload::clone() const
{
  return std::make_unique<NonExclusiveDeviationAlarmPayload>(*this);
}

Variant NonExclusiveDeviationAlarmPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = NonExclusiveLimitAlarmPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "SetpointNode")
      return Variant{setpointNode};
    if (name == "BaseSetpointNode" && baseSetpointNode)
      return Variant{baseSetpointNode.value()};
  }

  return Variant{};
}

DiscreteAlarmPayload::DiscreteAlarmPayload()
{
  eventType = NodeId{ObjectTypeId::DiscreteAlarmType};
}

std::unique_ptr<BaseEvent> DiscreteAlarmPayload::clone() const
{
  return std::make_unique<DiscreteAlarmPayload>(*this);
}

Variant DiscreteAlarmPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AlarmConditionPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

OffNormalAlarmPayload::OffNormalAlarmPayload()
{
  eventType = NodeId{ObjectTypeId::OffNormalAlarmType};
}

std::unique_ptr<BaseEvent> OffNormalAlarmPayload::clone() const
{
  return std::make_unique<OffNormalAlarmPayload>(*this);
}

Variant OffNormalAlarmPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = DiscreteAlarmPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "NormalState")
      return Variant{normalState};
  }

  return Variant{};
}

TripAlarmPayload::TripAlarmPayload()
{
  eventType = NodeId{ObjectTypeId::TripAlarmType};
}

std::unique_ptr<BaseEvent> TripAlarmPayload::clone() const
{
  return std::make_unique<TripAlarmPayload>(*this);
}

Variant TripAlarmPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = OffNormalAlarmPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

AuditEventPayload::AuditEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditEventType};
}

std::unique_ptr<BaseEvent> AuditEventPayload::clone() const
{
  return std::make_unique<AuditEventPayload>(*this);
}

Variant AuditEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = BaseEvent::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "ActionTimeStamp")
      return Variant{actionTimeStamp};
    if (name == "Status")
      return Variant{status};
    if (name == "ServerId")
      return Variant{serverId};
    if (name == "ClientAuditEntryId")
      return Variant{clientAuditEntryId};
    if (name == "ClientUserId")
      return Variant{clientUserId};
    if (name == "ClientApplicationUri" && clientApplicationUri)
      return Variant{clientApplicationUri.value()};
  }

  return Variant{};
}

AuditUpdateMethodEventPayload::AuditUpdateMethodEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditUpdateMethodEventType};
}

std::unique_ptr<BaseEvent> AuditUpdateMethodEventPayload::clone() const
{
  return std::make_unique<AuditUpdateMethodEventPayload>(*this);
}

Variant AuditUpdateMethodEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "MethodId")
      return Variant{methodId};
    if (name == "StatusCodeId" && statusCodeId)
      return Variant{statusCodeId.value()};
    if (name == "InputArguments")
      return Variant{inputArguments};
    if (name == "OutputArguments" && outputArguments)
      return Variant{outputArguments.value()};
  }

  return Variant{};
}

AuditConditionEventPayload::AuditConditionEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditConditionEventType};
}

std::unique_ptr<BaseEvent> AuditConditionEventPayload::clone() const
{
  return std::make_unique<AuditConditionEventPayload>(*this);
}

Variant AuditConditionEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditUpdateMethodEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

AuditConditionShelvingEventPayload::AuditConditionShelvingEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditConditionShelvingEventType};
}

std::unique_ptr<BaseEvent> AuditConditionShelvingEventPayload::clone() const
{
  return std::make_unique<AuditConditionShelvingEventPayload>(*this);
}

Variant AuditConditionShelvingEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditConditionEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "ShelvingTime" && shelvingTime)
      return Variant{shelvingTime.value()};
  }

  return Variant{};
}

ProgressEventPayload::ProgressEventPayload()
{
  eventType = NodeId{ObjectTypeId::ProgressEventType};
}

std::unique_ptr<BaseEvent> ProgressEventPayload::clone() const
{
  return std::make_unique<ProgressEventPayload>(*this);
}

Variant ProgressEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = BaseEvent::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "Context")
      return Variant{context};
    if (name == "Progress")
      return Variant{progress};
  }

  return Variant{};
}

SystemEventPayload::SystemEventPayload()
{
  eventType = NodeId{ObjectTypeId::SystemEventType};
}

std::unique_ptr<BaseEvent> SystemEventPayload::clone() const
{
  return std::make_unique<SystemEventPayload>(*this);
}

Variant SystemEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = BaseEvent::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

SystemStatusChangeEventPayload::SystemStatusChangeEventPayload()
{
  eventType = NodeId{ObjectTypeId::SystemStatusChangeEventType};
}

std::unique_ptr<BaseEvent> SystemStatusChangeEventPayload::clone() const
{
  return std::make_unique<SystemStatusChangeEventPayload>(*this);
}

Variant SystemStatusChangeEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = SystemEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "SystemState")
      return Variant{systemState};
  }

  return Variant{};
}

SystemOffNormalAlarmPayload::SystemOffNormalAlarmPayload()
{
  eventType = NodeId{ObjectTypeId::SystemOffNormalAlarmType};
}

std::unique_ptr<BaseEvent> SystemOffNormalAlarmPayload::clone() const
{
  return std::make_unique<SystemOffNormalAlarmPayload>(*this);
}

Variant SystemOffNormalAlarmPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = OffNormalAlarmPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

AuditUpdateStateEventPayload::AuditUpdateStateEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditUpdateStateEventType};
}

std::unique_ptr<BaseEvent> AuditUpdateStateEventPayload::clone() const
{
  return std::make_unique<AuditUpdateStateEventPayload>(*this);
}

Variant AuditUpdateStateEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditUpdateMethodEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "OldStateId")
      return Variant{oldStateId};
    if (name == "NewStateId")
      return Variant{newStateId};
  }

  return Variant{};
}

AuditProgramTransitionEventPayload::AuditProgramTransitionEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditProgramTransitionEventType};
}

std::unique_ptr<BaseEvent> AuditProgramTransitionEventPayload::clone() const
{
  return std::make_unique<AuditProgramTransitionEventPayload>(*this);
}

Variant AuditProgramTransitionEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditUpdateStateEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "TransitionNumber")
      return Variant{transitionNumber};
  }

  return Variant{};
}

TrustListUpdatedAuditEventPayload::TrustListUpdatedAuditEventPayload()
{
  eventType = NodeId{ObjectTypeId::TrustListUpdatedAuditEventType};
}

std::unique_ptr<BaseEvent> TrustListUpdatedAuditEventPayload::clone() const
{
  return std::make_unique<TrustListUpdatedAuditEventPayload>(*this);
}

Variant TrustListUpdatedAuditEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditUpdateMethodEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "TrustListId")
      return Variant{trustListId};
  }

  return Variant{};
}

CertificateUpdatedAuditEventPayload::CertificateUpdatedAuditEventPayload()
{
  eventType = NodeId{ObjectTypeId::CertificateUpdatedAuditEventType};
}

std::unique_ptr<BaseEvent> CertificateUpdatedAuditEventPayload::clone() const
{
  return std::make_unique<CertificateUpdatedAuditEventPayload>(*this);
}

Variant CertificateUpdatedAuditEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditUpdateMethodEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "CertificateGroup")
      return Variant{certificateGroup};
    if (name == "CertificateType")
      return Variant{certificateType};
  }

  return Variant{};
}

CertificateExpirationAlarmPayload::CertificateExpirationAlarmPayload()
{
  eventType = NodeId{ObjectTypeId::CertificateExpirationAlarmType};
}

std::unique_ptr<BaseEvent> CertificateExpirationAlarmPayload::clone() const
{
  return std::make_unique<CertificateExpirationAlarmPayload>(*this);
}

Variant CertificateExpirationAlarmPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = SystemOffNormalAlarmPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "ExpirationDate")
      return Variant{expirationDate};
    if (name == "ExpirationLimit" && expirationLimit)
      return Variant{expirationLimit.value()};
    if (name == "CertificateType")
      return Variant{certificateType};
    if (name == "Certificate")
      return Variant{certificate};
  }

  return Variant{};
}

AuditConditionResetEventPayload::AuditConditionResetEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditConditionResetEventType};
}

std::unique_ptr<BaseEvent> AuditConditionResetEventPayload::clone() const
{
  return std::make_unique<AuditConditionResetEventPayload>(*this);
}

Variant AuditConditionResetEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditConditionEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

PubSubStatusEventPayload::PubSubStatusEventPayload()
{
  eventType = NodeId{ObjectTypeId::PubSubStatusEventType};
}

std::unique_ptr<BaseEvent> PubSubStatusEventPayload::clone() const
{
  return std::make_unique<PubSubStatusEventPayload>(*this);
}

Variant PubSubStatusEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = SystemEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "ConnectionId")
      return Variant{connectionId};
    if (name == "GroupId")
      return Variant{groupId};
    if (name == "State")
      return Variant{state};
  }

  return Variant{};
}

ConfigurationUpdatedAuditEventPayload::ConfigurationUpdatedAuditEventPayload()
{
  eventType = NodeId{ObjectTypeId::ConfigurationUpdatedAuditEventType};
}

std::unique_ptr<BaseEvent> ConfigurationUpdatedAuditEventPayload::clone() const
{
  return std::make_unique<ConfigurationUpdatedAuditEventPayload>(*this);
}

Variant ConfigurationUpdatedAuditEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "OldVersion")
      return Variant{oldVersion};
    if (name == "NewVersion")
      return Variant{newVersion};
  }

  return Variant{};
}

PubSubTransportLimitsExceedEventPayload::PubSubTransportLimitsExceedEventPayload()
{
  eventType = NodeId{ObjectTypeId::PubSubTransportLimitsExceedEventType};
}

std::unique_ptr<BaseEvent> PubSubTransportLimitsExceedEventPayload::clone() const
{
  return std::make_unique<PubSubTransportLimitsExceedEventPayload>(*this);
}

Variant PubSubTransportLimitsExceedEventPayload::resolve_field(
  std::span<const QualifiedName> browse_path) const
{
  auto result = PubSubStatusEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "Actual")
      return Variant{actual};
    if (name == "Maximum")
      return Variant{maximum};
  }

  return Variant{};
}

PubSubCommunicationFailureEventPayload::PubSubCommunicationFailureEventPayload()
{
  eventType = NodeId{ObjectTypeId::PubSubCommunicationFailureEventType};
}

std::unique_ptr<BaseEvent> PubSubCommunicationFailureEventPayload::clone() const
{
  return std::make_unique<PubSubCommunicationFailureEventPayload>(*this);
}

Variant PubSubCommunicationFailureEventPayload::resolve_field(
  std::span<const QualifiedName> browse_path) const
{
  auto result = PubSubStatusEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "Error")
      return Variant{error};
  }

  return Variant{};
}

DiscrepancyAlarmPayload::DiscrepancyAlarmPayload()
{
  eventType = NodeId{ObjectTypeId::DiscrepancyAlarmType};
}

std::unique_ptr<BaseEvent> DiscrepancyAlarmPayload::clone() const
{
  return std::make_unique<DiscrepancyAlarmPayload>(*this);
}

Variant DiscrepancyAlarmPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AlarmConditionPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "TargetValueNode")
      return Variant{targetValueNode};
    if (name == "ExpectedTime")
      return Variant{expectedTime};
    if (name == "Tolerance" && tolerance)
      return Variant{tolerance.value()};
  }

  return Variant{};
}

AuditConditionSuppressionEventPayload::AuditConditionSuppressionEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditConditionSuppressionEventType};
}

std::unique_ptr<BaseEvent> AuditConditionSuppressionEventPayload::clone() const
{
  return std::make_unique<AuditConditionSuppressionEventPayload>(*this);
}

Variant AuditConditionSuppressionEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditConditionEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

AuditConditionSilenceEventPayload::AuditConditionSilenceEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditConditionSilenceEventType};
}

std::unique_ptr<BaseEvent> AuditConditionSilenceEventPayload::clone() const
{
  return std::make_unique<AuditConditionSilenceEventPayload>(*this);
}

Variant AuditConditionSilenceEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditConditionEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

AuditConditionOutOfServiceEventPayload::AuditConditionOutOfServiceEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditConditionOutOfServiceEventType};
}

std::unique_ptr<BaseEvent> AuditConditionOutOfServiceEventPayload::clone() const
{
  return std::make_unique<AuditConditionOutOfServiceEventPayload>(*this);
}

Variant AuditConditionOutOfServiceEventPayload::resolve_field(
  std::span<const QualifiedName> browse_path) const
{
  auto result = AuditConditionEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

RoleMappingRuleChangedAuditEventPayload::RoleMappingRuleChangedAuditEventPayload()
{
  eventType = NodeId{ObjectTypeId::RoleMappingRuleChangedAuditEventType};
}

std::unique_ptr<BaseEvent> RoleMappingRuleChangedAuditEventPayload::clone() const
{
  return std::make_unique<RoleMappingRuleChangedAuditEventPayload>(*this);
}

Variant RoleMappingRuleChangedAuditEventPayload::resolve_field(
  std::span<const QualifiedName> browse_path) const
{
  auto result = AuditUpdateMethodEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

KeyCredentialAuditEventPayload::KeyCredentialAuditEventPayload()
{
  eventType = NodeId{ObjectTypeId::KeyCredentialAuditEventType};
}

std::unique_ptr<BaseEvent> KeyCredentialAuditEventPayload::clone() const
{
  return std::make_unique<KeyCredentialAuditEventPayload>(*this);
}

Variant KeyCredentialAuditEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditUpdateMethodEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "ResourceUri")
      return Variant{resourceUri};
  }

  return Variant{};
}

KeyCredentialUpdatedAuditEventPayload::KeyCredentialUpdatedAuditEventPayload()
{
  eventType = NodeId{ObjectTypeId::KeyCredentialUpdatedAuditEventType};
}

std::unique_ptr<BaseEvent> KeyCredentialUpdatedAuditEventPayload::clone() const
{
  return std::make_unique<KeyCredentialUpdatedAuditEventPayload>(*this);
}

Variant KeyCredentialUpdatedAuditEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = KeyCredentialAuditEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

KeyCredentialDeletedAuditEventPayload::KeyCredentialDeletedAuditEventPayload()
{
  eventType = NodeId{ObjectTypeId::KeyCredentialDeletedAuditEventType};
}

std::unique_ptr<BaseEvent> KeyCredentialDeletedAuditEventPayload::clone() const
{
  return std::make_unique<KeyCredentialDeletedAuditEventPayload>(*this);
}

Variant KeyCredentialDeletedAuditEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = KeyCredentialAuditEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

InstrumentDiagnosticAlarmPayload::InstrumentDiagnosticAlarmPayload()
{
  eventType = NodeId{ObjectTypeId::InstrumentDiagnosticAlarmType};
}

std::unique_ptr<BaseEvent> InstrumentDiagnosticAlarmPayload::clone() const
{
  return std::make_unique<InstrumentDiagnosticAlarmPayload>(*this);
}

Variant InstrumentDiagnosticAlarmPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = OffNormalAlarmPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

SystemDiagnosticAlarmPayload::SystemDiagnosticAlarmPayload()
{
  eventType = NodeId{ObjectTypeId::SystemDiagnosticAlarmType};
}

std::unique_ptr<BaseEvent> SystemDiagnosticAlarmPayload::clone() const
{
  return std::make_unique<SystemDiagnosticAlarmPayload>(*this);
}

Variant SystemDiagnosticAlarmPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = OffNormalAlarmPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

AuditUpdateEventPayload::AuditUpdateEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditUpdateEventType};
}

std::unique_ptr<BaseEvent> AuditUpdateEventPayload::clone() const
{
  return std::make_unique<AuditUpdateEventPayload>(*this);
}

Variant AuditUpdateEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

AuditHistoryUpdateEventPayload::AuditHistoryUpdateEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditHistoryUpdateEventType};
}

std::unique_ptr<BaseEvent> AuditHistoryUpdateEventPayload::clone() const
{
  return std::make_unique<AuditHistoryUpdateEventPayload>(*this);
}

Variant AuditHistoryUpdateEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditUpdateEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "ParameterDataTypeId")
      return Variant{parameterDataTypeId};
  }

  return Variant{};
}

AuditHistoryAnnotationUpdateEventPayload::AuditHistoryAnnotationUpdateEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditHistoryAnnotationUpdateEventType};
}

std::unique_ptr<BaseEvent> AuditHistoryAnnotationUpdateEventPayload::clone() const
{
  return std::make_unique<AuditHistoryAnnotationUpdateEventPayload>(*this);
}

Variant AuditHistoryAnnotationUpdateEventPayload::resolve_field(
  std::span<const QualifiedName> browse_path) const
{
  auto result = AuditHistoryUpdateEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "PerformInsertReplace")
      return Variant{performInsertReplace};
    if (name == "NewValues")
      return Variant{newValues};
    if (name == "OldValues")
      return Variant{oldValues};
  }

  return Variant{};
}

TrustListOutOfDateAlarmPayload::TrustListOutOfDateAlarmPayload()
{
  eventType = NodeId{ObjectTypeId::TrustListOutOfDateAlarmType};
}

std::unique_ptr<BaseEvent> TrustListOutOfDateAlarmPayload::clone() const
{
  return std::make_unique<TrustListOutOfDateAlarmPayload>(*this);
}

Variant TrustListOutOfDateAlarmPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = SystemOffNormalAlarmPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "TrustListId")
      return Variant{trustListId};
    if (name == "LastUpdateTime")
      return Variant{lastUpdateTime};
    if (name == "UpdateFrequency")
      return Variant{updateFrequency};
  }

  return Variant{};
}

BaseLogEventPayload::BaseLogEventPayload()
{
  eventType = NodeId{ObjectTypeId::BaseLogEventType};
}

std::unique_ptr<BaseEvent> BaseLogEventPayload::clone() const
{
  return std::make_unique<BaseLogEventPayload>(*this);
}

Variant BaseLogEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = BaseEvent::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "ConditionClassId")
      return Variant{conditionClassId};
    if (name == "ConditionClassName")
      return Variant{conditionClassName};
    if (name == "ErrorCode" && errorCode)
      return Variant{errorCode.value()};
    if (name == "ErrorCodeNode" && errorCodeNode)
      return Variant{errorCodeNode.value()};
  }

  return Variant{};
}

LogOverflowEventPayload::LogOverflowEventPayload()
{
  eventType = NodeId{ObjectTypeId::LogOverflowEventType};
}

std::unique_ptr<BaseEvent> LogOverflowEventPayload::clone() const
{
  return std::make_unique<LogOverflowEventPayload>(*this);
}

Variant LogOverflowEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = BaseEvent::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

AuditSecurityEventPayload::AuditSecurityEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditSecurityEventType};
}

std::unique_ptr<BaseEvent> AuditSecurityEventPayload::clone() const
{
  return std::make_unique<AuditSecurityEventPayload>(*this);
}

Variant AuditSecurityEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "StatusCodeId" && statusCodeId)
      return Variant{statusCodeId.value()};
  }

  return Variant{};
}

AuditChannelEventPayload::AuditChannelEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditChannelEventType};
}

std::unique_ptr<BaseEvent> AuditChannelEventPayload::clone() const
{
  return std::make_unique<AuditChannelEventPayload>(*this);
}

Variant AuditChannelEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditSecurityEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "SecureChannelId")
      return Variant{secureChannelId};
  }

  return Variant{};
}

AuditOpenSecureChannelEventPayload::AuditOpenSecureChannelEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditOpenSecureChannelEventType};
}

std::unique_ptr<BaseEvent> AuditOpenSecureChannelEventPayload::clone() const
{
  return std::make_unique<AuditOpenSecureChannelEventPayload>(*this);
}

Variant AuditOpenSecureChannelEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditChannelEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "ClientCertificate")
      return Variant{clientCertificate};
    if (name == "ClientCertificateThumbprint")
      return Variant{clientCertificateThumbprint};
    if (name == "RequestType")
      return Variant{requestType};
    if (name == "SecurityPolicyUri")
      return Variant{securityPolicyUri};
    if (name == "SecurityMode")
      return Variant{securityMode};
    if (name == "RequestedLifetime")
      return Variant{requestedLifetime};
    if (name == "CertificateErrorEventId" && certificateErrorEventId)
      return Variant{certificateErrorEventId.value()};
  }

  return Variant{};
}

AuditSessionEventPayload::AuditSessionEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditSessionEventType};
}

std::unique_ptr<BaseEvent> AuditSessionEventPayload::clone() const
{
  return std::make_unique<AuditSessionEventPayload>(*this);
}

Variant AuditSessionEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditSecurityEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "SessionId")
      return Variant{sessionId};
  }

  return Variant{};
}

AuditCreateSessionEventPayload::AuditCreateSessionEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditCreateSessionEventType};
}

std::unique_ptr<BaseEvent> AuditCreateSessionEventPayload::clone() const
{
  return std::make_unique<AuditCreateSessionEventPayload>(*this);
}

Variant AuditCreateSessionEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditSessionEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "SecureChannelId")
      return Variant{secureChannelId};
    if (name == "ClientCertificate")
      return Variant{clientCertificate};
    if (name == "ClientCertificateThumbprint")
      return Variant{clientCertificateThumbprint};
    if (name == "RevisedSessionTimeout")
      return Variant{revisedSessionTimeout};
  }

  return Variant{};
}

AuditActivateSessionEventPayload::AuditActivateSessionEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditActivateSessionEventType};
}

std::unique_ptr<BaseEvent> AuditActivateSessionEventPayload::clone() const
{
  return std::make_unique<AuditActivateSessionEventPayload>(*this);
}

Variant AuditActivateSessionEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditSessionEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "ClientSoftwareCertificates")
      return Variant{clientSoftwareCertificates};
    if (name == "UserIdentityToken")
      return Variant{userIdentityToken};
    if (name == "SecureChannelId")
      return Variant{secureChannelId};
    if (name == "CurrentRoleIds" && currentRoleIds)
      return Variant{currentRoleIds.value()};
  }

  return Variant{};
}

AuditCancelEventPayload::AuditCancelEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditCancelEventType};
}

std::unique_ptr<BaseEvent> AuditCancelEventPayload::clone() const
{
  return std::make_unique<AuditCancelEventPayload>(*this);
}

Variant AuditCancelEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditSessionEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "RequestHandle")
      return Variant{requestHandle};
  }

  return Variant{};
}

AuditCertificateEventPayload::AuditCertificateEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditCertificateEventType};
}

std::unique_ptr<BaseEvent> AuditCertificateEventPayload::clone() const
{
  return std::make_unique<AuditCertificateEventPayload>(*this);
}

Variant AuditCertificateEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditSecurityEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "Certificate")
      return Variant{certificate};
  }

  return Variant{};
}

AuditCertificateDataMismatchEventPayload::AuditCertificateDataMismatchEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditCertificateDataMismatchEventType};
}

std::unique_ptr<BaseEvent> AuditCertificateDataMismatchEventPayload::clone() const
{
  return std::make_unique<AuditCertificateDataMismatchEventPayload>(*this);
}

Variant AuditCertificateDataMismatchEventPayload::resolve_field(
  std::span<const QualifiedName> browse_path) const
{
  auto result = AuditCertificateEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "InvalidHostname")
      return Variant{invalidHostname};
    if (name == "InvalidUri")
      return Variant{invalidUri};
  }

  return Variant{};
}

AuditCertificateExpiredEventPayload::AuditCertificateExpiredEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditCertificateExpiredEventType};
}

std::unique_ptr<BaseEvent> AuditCertificateExpiredEventPayload::clone() const
{
  return std::make_unique<AuditCertificateExpiredEventPayload>(*this);
}

Variant AuditCertificateExpiredEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditCertificateEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

AuditCertificateInvalidEventPayload::AuditCertificateInvalidEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditCertificateInvalidEventType};
}

std::unique_ptr<BaseEvent> AuditCertificateInvalidEventPayload::clone() const
{
  return std::make_unique<AuditCertificateInvalidEventPayload>(*this);
}

Variant AuditCertificateInvalidEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditCertificateEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

AuditCertificateUntrustedEventPayload::AuditCertificateUntrustedEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditCertificateUntrustedEventType};
}

std::unique_ptr<BaseEvent> AuditCertificateUntrustedEventPayload::clone() const
{
  return std::make_unique<AuditCertificateUntrustedEventPayload>(*this);
}

Variant AuditCertificateUntrustedEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditCertificateEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

AuditCertificateRevokedEventPayload::AuditCertificateRevokedEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditCertificateRevokedEventType};
}

std::unique_ptr<BaseEvent> AuditCertificateRevokedEventPayload::clone() const
{
  return std::make_unique<AuditCertificateRevokedEventPayload>(*this);
}

Variant AuditCertificateRevokedEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditCertificateEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

AuditCertificateMismatchEventPayload::AuditCertificateMismatchEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditCertificateMismatchEventType};
}

std::unique_ptr<BaseEvent> AuditCertificateMismatchEventPayload::clone() const
{
  return std::make_unique<AuditCertificateMismatchEventPayload>(*this);
}

Variant AuditCertificateMismatchEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditCertificateEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

AuditNodeManagementEventPayload::AuditNodeManagementEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditNodeManagementEventType};
}

std::unique_ptr<BaseEvent> AuditNodeManagementEventPayload::clone() const
{
  return std::make_unique<AuditNodeManagementEventPayload>(*this);
}

Variant AuditNodeManagementEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

AuditAddNodesEventPayload::AuditAddNodesEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditAddNodesEventType};
}

std::unique_ptr<BaseEvent> AuditAddNodesEventPayload::clone() const
{
  return std::make_unique<AuditAddNodesEventPayload>(*this);
}

Variant AuditAddNodesEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditNodeManagementEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "NodesToAdd")
      return Variant{nodesToAdd};
  }

  return Variant{};
}

AuditDeleteNodesEventPayload::AuditDeleteNodesEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditDeleteNodesEventType};
}

std::unique_ptr<BaseEvent> AuditDeleteNodesEventPayload::clone() const
{
  return std::make_unique<AuditDeleteNodesEventPayload>(*this);
}

Variant AuditDeleteNodesEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditNodeManagementEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "NodesToDelete")
      return Variant{nodesToDelete};
  }

  return Variant{};
}

AuditAddReferencesEventPayload::AuditAddReferencesEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditAddReferencesEventType};
}

std::unique_ptr<BaseEvent> AuditAddReferencesEventPayload::clone() const
{
  return std::make_unique<AuditAddReferencesEventPayload>(*this);
}

Variant AuditAddReferencesEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditNodeManagementEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "ReferencesToAdd")
      return Variant{referencesToAdd};
  }

  return Variant{};
}

AuditDeleteReferencesEventPayload::AuditDeleteReferencesEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditDeleteReferencesEventType};
}

std::unique_ptr<BaseEvent> AuditDeleteReferencesEventPayload::clone() const
{
  return std::make_unique<AuditDeleteReferencesEventPayload>(*this);
}

Variant AuditDeleteReferencesEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditNodeManagementEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "ReferencesToDelete")
      return Variant{referencesToDelete};
  }

  return Variant{};
}

AuditWriteUpdateEventPayload::AuditWriteUpdateEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditWriteUpdateEventType};
}

std::unique_ptr<BaseEvent> AuditWriteUpdateEventPayload::clone() const
{
  return std::make_unique<AuditWriteUpdateEventPayload>(*this);
}

Variant AuditWriteUpdateEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditUpdateEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "AttributeId")
      return Variant{attributeId};
    if (name == "IndexRange")
      return Variant{indexRange};
    if (name == "OldValue")
      return Variant{oldValue};
    if (name == "NewValue")
      return Variant{newValue};
  }

  return Variant{};
}

DeviceFailureEventPayload::DeviceFailureEventPayload()
{
  eventType = NodeId{ObjectTypeId::DeviceFailureEventType};
}

std::unique_ptr<BaseEvent> DeviceFailureEventPayload::clone() const
{
  return std::make_unique<DeviceFailureEventPayload>(*this);
}

Variant DeviceFailureEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = SystemEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

BaseModelChangeEventPayload::BaseModelChangeEventPayload()
{
  eventType = NodeId{ObjectTypeId::BaseModelChangeEventType};
}

std::unique_ptr<BaseEvent> BaseModelChangeEventPayload::clone() const
{
  return std::make_unique<BaseModelChangeEventPayload>(*this);
}

Variant BaseModelChangeEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = BaseEvent::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

GeneralModelChangeEventPayload::GeneralModelChangeEventPayload()
{
  eventType = NodeId{ObjectTypeId::GeneralModelChangeEventType};
}

std::unique_ptr<BaseEvent> GeneralModelChangeEventPayload::clone() const
{
  return std::make_unique<GeneralModelChangeEventPayload>(*this);
}

Variant GeneralModelChangeEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = BaseModelChangeEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "Changes")
      return Variant{changes};
  }

  return Variant{};
}

TransitionEventPayload::TransitionEventPayload()
{
  eventType = NodeId{ObjectTypeId::TransitionEventType};
}

std::unique_ptr<BaseEvent> TransitionEventPayload::clone() const
{
  return std::make_unique<TransitionEventPayload>(*this);
}

Variant TransitionEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = BaseEvent::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

AuditClientEventPayload::AuditClientEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditClientEventType};
}

std::unique_ptr<BaseEvent> AuditClientEventPayload::clone() const
{
  return std::make_unique<AuditClientEventPayload>(*this);
}

Variant AuditClientEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "ServerUri")
      return Variant{serverUri};
  }

  return Variant{};
}

ProgramTransitionEventPayload::ProgramTransitionEventPayload()
{
  eventType = NodeId{ObjectTypeId::ProgramTransitionEventType};
}

std::unique_ptr<BaseEvent> ProgramTransitionEventPayload::clone() const
{
  return std::make_unique<ProgramTransitionEventPayload>(*this);
}

Variant ProgramTransitionEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = TransitionEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

AuditClientUpdateMethodResultEventPayload::AuditClientUpdateMethodResultEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditClientUpdateMethodResultEventType};
}

std::unique_ptr<BaseEvent> AuditClientUpdateMethodResultEventPayload::clone() const
{
  return std::make_unique<AuditClientUpdateMethodResultEventPayload>(*this);
}

Variant AuditClientUpdateMethodResultEventPayload::resolve_field(
  std::span<const QualifiedName> browse_path) const
{
  auto result = AuditClientEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "ObjectId")
      return Variant{objectId};
    if (name == "MethodId")
      return Variant{methodId};
    if (name == "StatusCodeId")
      return Variant{statusCodeId};
    if (name == "InputArguments")
      return Variant{inputArguments};
    if (name == "OutputArguments")
      return Variant{outputArguments};
  }

  return Variant{};
}

SemanticChangeEventPayload::SemanticChangeEventPayload()
{
  eventType = NodeId{ObjectTypeId::SemanticChangeEventType};
}

std::unique_ptr<BaseEvent> SemanticChangeEventPayload::clone() const
{
  return std::make_unique<SemanticChangeEventPayload>(*this);
}

Variant SemanticChangeEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = BaseEvent::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "Changes")
      return Variant{changes};
  }

  return Variant{};
}

AuditUrlMismatchEventPayload::AuditUrlMismatchEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditUrlMismatchEventType};
}

std::unique_ptr<BaseEvent> AuditUrlMismatchEventPayload::clone() const
{
  return std::make_unique<AuditUrlMismatchEventPayload>(*this);
}

Variant AuditUrlMismatchEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditCreateSessionEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "EndpointUrl")
      return Variant{endpointUrl};
  }

  return Variant{};
}

RefreshStartEventPayload::RefreshStartEventPayload()
{
  eventType = NodeId{ObjectTypeId::RefreshStartEventType};
}

std::unique_ptr<BaseEvent> RefreshStartEventPayload::clone() const
{
  return std::make_unique<RefreshStartEventPayload>(*this);
}

Variant RefreshStartEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = SystemEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

RefreshEndEventPayload::RefreshEndEventPayload()
{
  eventType = NodeId{ObjectTypeId::RefreshEndEventType};
}

std::unique_ptr<BaseEvent> RefreshEndEventPayload::clone() const
{
  return std::make_unique<RefreshEndEventPayload>(*this);
}

Variant RefreshEndEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = SystemEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

RefreshRequiredEventPayload::RefreshRequiredEventPayload()
{
  eventType = NodeId{ObjectTypeId::RefreshRequiredEventType};
}

std::unique_ptr<BaseEvent> RefreshRequiredEventPayload::clone() const
{
  return std::make_unique<RefreshRequiredEventPayload>(*this);
}

Variant RefreshRequiredEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = SystemEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

AuditConditionEnableEventPayload::AuditConditionEnableEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditConditionEnableEventType};
}

std::unique_ptr<BaseEvent> AuditConditionEnableEventPayload::clone() const
{
  return std::make_unique<AuditConditionEnableEventPayload>(*this);
}

Variant AuditConditionEnableEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditConditionEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

AuditConditionCommentEventPayload::AuditConditionCommentEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditConditionCommentEventType};
}

std::unique_ptr<BaseEvent> AuditConditionCommentEventPayload::clone() const
{
  return std::make_unique<AuditConditionCommentEventPayload>(*this);
}

Variant AuditConditionCommentEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditConditionEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "ConditionEventId")
      return Variant{conditionEventId};
    if (name == "Comment")
      return Variant{comment};
  }

  return Variant{};
}

DialogConditionPayload::DialogConditionPayload()
{
  eventType = NodeId{ObjectTypeId::DialogConditionType};
}

std::unique_ptr<BaseEvent> DialogConditionPayload::clone() const
{
  return std::make_unique<DialogConditionPayload>(*this);
}

Variant DialogConditionPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = ConditionPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "Prompt")
      return Variant{prompt};
    if (name == "ResponseOptionSet")
      return Variant{responseOptionSet};
    if (name == "DefaultResponse")
      return Variant{defaultResponse};
    if (name == "OkResponse")
      return Variant{okResponse};
    if (name == "CancelResponse")
      return Variant{cancelResponse};
    if (name == "LastResponse")
      return Variant{lastResponse};
    if (name == "DialogState")
      return Variant{dialogState.currentState};
  }

  if (browse_path.size() == 2 && browse_path[0].namespace_index() == 0 &&
      browse_path[1].namespace_index() == 0)
  {
    const auto parent = static_cast<std::string_view>(browse_path[0].name());
    const auto child = static_cast<std::string_view>(browse_path[1].name());
    if (parent == "DialogState")
    {
      if (child == "Id")
        return Variant{dialogState.id};
      if (child == "TransitionTime")
        return Variant{dialogState.transitionTime};
      if (child == "CurrentState")
        return Variant{dialogState.currentState};
    }
  }

  return Variant{};
}

AuditHistoryEventUpdateEventPayload::AuditHistoryEventUpdateEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditHistoryEventUpdateEventType};
}

std::unique_ptr<BaseEvent> AuditHistoryEventUpdateEventPayload::clone() const
{
  return std::make_unique<AuditHistoryEventUpdateEventPayload>(*this);
}

Variant AuditHistoryEventUpdateEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditHistoryUpdateEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "UpdatedNode")
      return Variant{updatedNode};
    if (name == "PerformInsertReplace")
      return Variant{performInsertReplace};
    if (name == "Filter")
      return Variant{filter};
    if (name == "NewValues")
      return Variant{newValues};
    if (name == "OldValues")
      return Variant{oldValues};
  }

  return Variant{};
}

AuditHistoryValueUpdateEventPayload::AuditHistoryValueUpdateEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditHistoryValueUpdateEventType};
}

std::unique_ptr<BaseEvent> AuditHistoryValueUpdateEventPayload::clone() const
{
  return std::make_unique<AuditHistoryValueUpdateEventPayload>(*this);
}

Variant AuditHistoryValueUpdateEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditHistoryUpdateEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "UpdatedNode")
      return Variant{updatedNode};
    if (name == "PerformInsertReplace")
      return Variant{performInsertReplace};
    if (name == "NewValues")
      return Variant{newValues};
    if (name == "OldValues")
      return Variant{oldValues};
  }

  return Variant{};
}

AuditHistoryDeleteEventPayload::AuditHistoryDeleteEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditHistoryDeleteEventType};
}

std::unique_ptr<BaseEvent> AuditHistoryDeleteEventPayload::clone() const
{
  return std::make_unique<AuditHistoryDeleteEventPayload>(*this);
}

Variant AuditHistoryDeleteEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditHistoryUpdateEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "UpdatedNode")
      return Variant{updatedNode};
  }

  return Variant{};
}

AuditHistoryRawModifyDeleteEventPayload::AuditHistoryRawModifyDeleteEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditHistoryRawModifyDeleteEventType};
}

std::unique_ptr<BaseEvent> AuditHistoryRawModifyDeleteEventPayload::clone() const
{
  return std::make_unique<AuditHistoryRawModifyDeleteEventPayload>(*this);
}

Variant AuditHistoryRawModifyDeleteEventPayload::resolve_field(
  std::span<const QualifiedName> browse_path) const
{
  auto result = AuditHistoryDeleteEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "IsDeleteModified")
      return Variant{isDeleteModified};
    if (name == "StartTime")
      return Variant{startTime};
    if (name == "EndTime")
      return Variant{endTime};
    if (name == "OldValues")
      return Variant{oldValues};
  }

  return Variant{};
}

AuditHistoryAtTimeDeleteEventPayload::AuditHistoryAtTimeDeleteEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditHistoryAtTimeDeleteEventType};
}

std::unique_ptr<BaseEvent> AuditHistoryAtTimeDeleteEventPayload::clone() const
{
  return std::make_unique<AuditHistoryAtTimeDeleteEventPayload>(*this);
}

Variant AuditHistoryAtTimeDeleteEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditHistoryDeleteEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "ReqTimes")
      return Variant{reqTimes};
    if (name == "OldValues")
      return Variant{oldValues};
  }

  return Variant{};
}

AuditHistoryEventDeleteEventPayload::AuditHistoryEventDeleteEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditHistoryEventDeleteEventType};
}

std::unique_ptr<BaseEvent> AuditHistoryEventDeleteEventPayload::clone() const
{
  return std::make_unique<AuditHistoryEventDeleteEventPayload>(*this);
}

Variant AuditHistoryEventDeleteEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditHistoryDeleteEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "EventIds")
      return Variant{eventIds};
    if (name == "OldValues")
      return Variant{oldValues};
  }

  return Variant{};
}

EventQueueOverflowEventPayload::EventQueueOverflowEventPayload()
{
  eventType = NodeId{ObjectTypeId::EventQueueOverflowEventType};
}

std::unique_ptr<BaseEvent> EventQueueOverflowEventPayload::clone() const
{
  return std::make_unique<EventQueueOverflowEventPayload>(*this);
}

Variant EventQueueOverflowEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = BaseEvent::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

TrustListUpdateRequestedAuditEventPayload::TrustListUpdateRequestedAuditEventPayload()
{
  eventType = NodeId{ObjectTypeId::TrustListUpdateRequestedAuditEventType};
}

std::unique_ptr<BaseEvent> TrustListUpdateRequestedAuditEventPayload::clone() const
{
  return std::make_unique<TrustListUpdateRequestedAuditEventPayload>(*this);
}

Variant TrustListUpdateRequestedAuditEventPayload::resolve_field(
  std::span<const QualifiedName> browse_path) const
{
  auto result = AuditUpdateMethodEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

CertificateUpdateRequestedAuditEventPayload::CertificateUpdateRequestedAuditEventPayload()
{
  eventType = NodeId{ObjectTypeId::CertificateUpdateRequestedAuditEventType};
}

std::unique_ptr<BaseEvent> CertificateUpdateRequestedAuditEventPayload::clone() const
{
  return std::make_unique<CertificateUpdateRequestedAuditEventPayload>(*this);
}

Variant CertificateUpdateRequestedAuditEventPayload::resolve_field(
  std::span<const QualifiedName> browse_path) const
{
  auto result = AuditUpdateMethodEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

AuditHistoryConfigurationChangeEventPayload::AuditHistoryConfigurationChangeEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditHistoryConfigurationChangeEventType};
}

std::unique_ptr<BaseEvent> AuditHistoryConfigurationChangeEventPayload::clone() const
{
  return std::make_unique<AuditHistoryConfigurationChangeEventPayload>(*this);
}

Variant AuditHistoryConfigurationChangeEventPayload::resolve_field(
  std::span<const QualifiedName> browse_path) const
{
  auto result = AuditEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

AuditHistoryBulkInsertEventPayload::AuditHistoryBulkInsertEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditHistoryBulkInsertEventType};
}

std::unique_ptr<BaseEvent> AuditHistoryBulkInsertEventPayload::clone() const
{
  return std::make_unique<AuditHistoryBulkInsertEventPayload>(*this);
}

Variant AuditHistoryBulkInsertEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "UpdatedNode")
      return Variant{updatedNode};
    if (name == "StartTime")
      return Variant{startTime};
    if (name == "EndTime")
      return Variant{endTime};
  }

  return Variant{};
}

ProgramTransitionAuditEventPayload::ProgramTransitionAuditEventPayload()
{
  eventType = NodeId{ObjectTypeId::ProgramTransitionAuditEventType};
}

std::unique_ptr<BaseEvent> ProgramTransitionAuditEventPayload::clone() const
{
  return std::make_unique<ProgramTransitionAuditEventPayload>(*this);
}

Variant ProgramTransitionAuditEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditUpdateStateEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

AuditConditionRespondEventPayload::AuditConditionRespondEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditConditionRespondEventType};
}

std::unique_ptr<BaseEvent> AuditConditionRespondEventPayload::clone() const
{
  return std::make_unique<AuditConditionRespondEventPayload>(*this);
}

Variant AuditConditionRespondEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditConditionEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "SelectedResponse")
      return Variant{selectedResponse};
  }

  return Variant{};
}

AuditConditionAcknowledgeEventPayload::AuditConditionAcknowledgeEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditConditionAcknowledgeEventType};
}

std::unique_ptr<BaseEvent> AuditConditionAcknowledgeEventPayload::clone() const
{
  return std::make_unique<AuditConditionAcknowledgeEventPayload>(*this);
}

Variant AuditConditionAcknowledgeEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditConditionEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "ConditionEventId")
      return Variant{conditionEventId};
    if (name == "Comment")
      return Variant{comment};
  }

  return Variant{};
}

AuditConditionConfirmEventPayload::AuditConditionConfirmEventPayload()
{
  eventType = NodeId{ObjectTypeId::AuditConditionConfirmEventType};
}

std::unique_ptr<BaseEvent> AuditConditionConfirmEventPayload::clone() const
{
  return std::make_unique<AuditConditionConfirmEventPayload>(*this);
}

Variant AuditConditionConfirmEventPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = AuditConditionEventPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "ConditionEventId")
      return Variant{conditionEventId};
    if (name == "Comment")
      return Variant{comment};
  }

  return Variant{};
}

ExclusiveLimitAlarmPayload::ExclusiveLimitAlarmPayload()
{
  eventType = NodeId{ObjectTypeId::ExclusiveLimitAlarmType};
}

std::unique_ptr<BaseEvent> ExclusiveLimitAlarmPayload::clone() const
{
  return std::make_unique<ExclusiveLimitAlarmPayload>(*this);
}

Variant ExclusiveLimitAlarmPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = LimitAlarmPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "LimitState")
      return Variant{limitState.currentState};
  }

  if (browse_path.size() == 2 && browse_path[0].namespace_index() == 0 &&
      browse_path[1].namespace_index() == 0)
  {
    const auto parent = static_cast<std::string_view>(browse_path[0].name());
    const auto child = static_cast<std::string_view>(browse_path[1].name());
    if (parent == "LimitState")
    {
      if (child == "CurrentState")
        return Variant{limitState.currentState};
    }
  }

  if (browse_path.size() == 3 && browse_path[0].namespace_index() == 0 &&
      browse_path[1].namespace_index() == 0 && browse_path[2].namespace_index() == 0)
  {
    const auto a = static_cast<std::string_view>(browse_path[0].name());
    const auto b = static_cast<std::string_view>(browse_path[1].name());
    const auto c = static_cast<std::string_view>(browse_path[2].name());
    if (a == "LimitState" && b == "CurrentState" && c == "Id")
      return Variant{limitState.id};
  }

  return Variant{};
}

ExclusiveLevelAlarmPayload::ExclusiveLevelAlarmPayload()
{
  eventType = NodeId{ObjectTypeId::ExclusiveLevelAlarmType};
}

std::unique_ptr<BaseEvent> ExclusiveLevelAlarmPayload::clone() const
{
  return std::make_unique<ExclusiveLevelAlarmPayload>(*this);
}

Variant ExclusiveLevelAlarmPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = ExclusiveLimitAlarmPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  return Variant{};
}

ExclusiveRateOfChangeAlarmPayload::ExclusiveRateOfChangeAlarmPayload()
{
  eventType = NodeId{ObjectTypeId::ExclusiveRateOfChangeAlarmType};
}

std::unique_ptr<BaseEvent> ExclusiveRateOfChangeAlarmPayload::clone() const
{
  return std::make_unique<ExclusiveRateOfChangeAlarmPayload>(*this);
}

Variant ExclusiveRateOfChangeAlarmPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = ExclusiveLimitAlarmPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "EngineeringUnits" && engineeringUnits)
      return Variant{engineeringUnits.value()};
  }

  return Variant{};
}

ExclusiveDeviationAlarmPayload::ExclusiveDeviationAlarmPayload()
{
  eventType = NodeId{ObjectTypeId::ExclusiveDeviationAlarmType};
}

std::unique_ptr<BaseEvent> ExclusiveDeviationAlarmPayload::clone() const
{
  return std::make_unique<ExclusiveDeviationAlarmPayload>(*this);
}

Variant ExclusiveDeviationAlarmPayload::resolve_field(std::span<const QualifiedName> browse_path) const
{
  auto result = ExclusiveLimitAlarmPayload::resolve_field(browse_path);
  if (!result.empty())
    return result;

  if (browse_path.size() == 1 && browse_path[0].namespace_index() == 0)
  {
    const auto name = static_cast<std::string_view>(browse_path[0].name());
    if (name == "SetpointNode")
      return Variant{setpointNode};
    if (name == "BaseSetpointNode" && baseSetpointNode)
      return Variant{baseSetpointNode.value()};
  }

  return Variant{};
}

}  // namespace ua
