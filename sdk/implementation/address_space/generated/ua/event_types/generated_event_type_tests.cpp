// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_base_event.h"
#include "ua_objecttype_id.h"
#include "ua_qualified_name.h"
#include "ua_variant.h"
#include "ua_data_value.h"

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

using namespace ua;

TEST(GeneratedEventTypeTests, ConditionPayload_Construction)
{
  ConditionPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::ConditionType});
}

TEST(GeneratedEventTypeTests, ConditionPayload_ResolveOwnFields)
{
  ConditionPayload event;
  auto sentinel_condition_class_id = NodeId{1, 42};
  event.conditionClassId = sentinel_condition_class_id;
  const QualifiedName path_condition_class_id[]{QualifiedName{0, "ConditionClassId"}};
  auto result_condition_class_id = event.resolve_field(path_condition_class_id);
  ASSERT_FALSE(result_condition_class_id.empty()) << "ConditionClassId resolved to empty";
  EXPECT_EQ(result_condition_class_id.as<NodeId>(), sentinel_condition_class_id);
  auto sentinel_condition_class_name = LocalizedText{"en", "test"};
  event.conditionClassName = sentinel_condition_class_name;
  const QualifiedName path_condition_class_name[]{QualifiedName{0, "ConditionClassName"}};
  auto result_condition_class_name = event.resolve_field(path_condition_class_name);
  ASSERT_FALSE(result_condition_class_name.empty()) << "ConditionClassName resolved to empty";
  EXPECT_EQ(result_condition_class_name.as<LocalizedText>(), sentinel_condition_class_name);
  auto sentinel_condition_name = String{"test"};
  event.conditionName = sentinel_condition_name;
  const QualifiedName path_condition_name[]{QualifiedName{0, "ConditionName"}};
  auto result_condition_name = event.resolve_field(path_condition_name);
  ASSERT_FALSE(result_condition_name.empty()) << "ConditionName resolved to empty";
  EXPECT_EQ(result_condition_name.as<String>(), sentinel_condition_name);
  auto sentinel_branch_id = NodeId{1, 42};
  event.branchId = sentinel_branch_id;
  const QualifiedName path_branch_id[]{QualifiedName{0, "BranchId"}};
  auto result_branch_id = event.resolve_field(path_branch_id);
  ASSERT_FALSE(result_branch_id.empty()) << "BranchId resolved to empty";
  EXPECT_EQ(result_branch_id.as<NodeId>(), sentinel_branch_id);
  auto sentinel_retain = true;
  event.retain = sentinel_retain;
  const QualifiedName path_retain[]{QualifiedName{0, "Retain"}};
  auto result_retain = event.resolve_field(path_retain);
  ASSERT_FALSE(result_retain.empty()) << "Retain resolved to empty";
  EXPECT_EQ(result_retain.as<bool>(), sentinel_retain);
  auto sentinel_supports_filtered_retain = true;
  event.supportsFilteredRetain = sentinel_supports_filtered_retain;
  const QualifiedName path_supports_filtered_retain[]{QualifiedName{0, "SupportsFilteredRetain"}};
  auto result_supports_filtered_retain = event.resolve_field(path_supports_filtered_retain);
  ASSERT_FALSE(result_supports_filtered_retain.empty()) << "SupportsFilteredRetain resolved to empty";
  EXPECT_EQ(result_supports_filtered_retain.as<bool>(), sentinel_supports_filtered_retain);
  auto sentinel_enabled_state = TwoStateVariableState{true, LocalizedText{"", "Active"}, DateTime::now()};
  event.enabledState = sentinel_enabled_state;
  const QualifiedName path_enabled_state[]{QualifiedName{0, "EnabledState"}};
  auto result_enabled_state = event.resolve_field(path_enabled_state);
  ASSERT_FALSE(result_enabled_state.empty()) << "EnabledState resolved to empty";
  EXPECT_EQ(result_enabled_state.as<LocalizedText>(), sentinel_enabled_state.currentState);
  auto sentinel_quality = ConditionVariableState{Variant{42}, DateTime::now()};
  event.quality = sentinel_quality;
  const QualifiedName path_quality[]{QualifiedName{0, "Quality"}};
  auto result_quality = event.resolve_field(path_quality);
  ASSERT_FALSE(result_quality.empty()) << "Quality resolved to empty";
  auto sentinel_last_severity = ConditionVariableState{Variant{42}, DateTime::now()};
  event.lastSeverity = sentinel_last_severity;
  const QualifiedName path_last_severity[]{QualifiedName{0, "LastSeverity"}};
  auto result_last_severity = event.resolve_field(path_last_severity);
  ASSERT_FALSE(result_last_severity.empty()) << "LastSeverity resolved to empty";
  auto sentinel_comment = ConditionVariableState{Variant{42}, DateTime::now()};
  event.comment = sentinel_comment;
  const QualifiedName path_comment[]{QualifiedName{0, "Comment"}};
  auto result_comment = event.resolve_field(path_comment);
  ASSERT_FALSE(result_comment.empty()) << "Comment resolved to empty";
  auto sentinel_client_user_id = String{"test"};
  event.clientUserId = sentinel_client_user_id;
  const QualifiedName path_client_user_id[]{QualifiedName{0, "ClientUserId"}};
  auto result_client_user_id = event.resolve_field(path_client_user_id);
  ASSERT_FALSE(result_client_user_id.empty()) << "ClientUserId resolved to empty";
  EXPECT_EQ(result_client_user_id.as<String>(), sentinel_client_user_id);
}

TEST(GeneratedEventTypeTests, ConditionPayload_OptionalFields_Unset)
{
  ConditionPayload event;
  const QualifiedName path_condition_sub_class_id[]{QualifiedName{0, "ConditionSubClassId"}};
  EXPECT_TRUE(event.resolve_field(path_condition_sub_class_id).empty())
    << "ConditionSubClassId unexpectedly resolved while unset";
  const QualifiedName path_condition_sub_class_name[]{QualifiedName{0, "ConditionSubClassName"}};
  EXPECT_TRUE(event.resolve_field(path_condition_sub_class_name).empty())
    << "ConditionSubClassName unexpectedly resolved while unset";
}

TEST(GeneratedEventTypeTests, ConditionPayload_OptionalFields_Set)
{
  ConditionPayload event;
  auto sentinel_condition_sub_class_id = Array<NodeId>{NodeId{1, 42}};
  event.conditionSubClassId = sentinel_condition_sub_class_id;
  const QualifiedName path_condition_sub_class_id[]{QualifiedName{0, "ConditionSubClassId"}};
  auto result_condition_sub_class_id = event.resolve_field(path_condition_sub_class_id);
  ASSERT_FALSE(result_condition_sub_class_id.empty())
    << "ConditionSubClassId resolved to empty after being set";
  EXPECT_EQ(result_condition_sub_class_id.as<Array<NodeId>>(), sentinel_condition_sub_class_id);
  auto sentinel_condition_sub_class_name = Array<LocalizedText>{LocalizedText{"en", "test"}};
  event.conditionSubClassName = sentinel_condition_sub_class_name;
  const QualifiedName path_condition_sub_class_name[]{QualifiedName{0, "ConditionSubClassName"}};
  auto result_condition_sub_class_name = event.resolve_field(path_condition_sub_class_name);
  ASSERT_FALSE(result_condition_sub_class_name.empty())
    << "ConditionSubClassName resolved to empty after being set";
  EXPECT_EQ(result_condition_sub_class_name.as<Array<LocalizedText>>(), sentinel_condition_sub_class_name);
}

TEST(GeneratedEventTypeTests, ConditionPayload_CompoundSubFields)
{
  ConditionPayload event;
  auto sentinel_enabled_state = TwoStateVariableState{true, LocalizedText{"", "Active"}, DateTime::now()};
  event.enabledState = sentinel_enabled_state;
  const QualifiedName path_enabled_state_id[]{QualifiedName{0, "EnabledState"}, QualifiedName{0, "Id"}};
  auto result_enabled_state_id = event.resolve_field(path_enabled_state_id);
  ASSERT_FALSE(result_enabled_state_id.empty()) << "EnabledState.Id resolved to empty";
  EXPECT_EQ(result_enabled_state_id.as<bool>(), sentinel_enabled_state.id);
  const QualifiedName path_enabled_state_transition_time[]{
    QualifiedName{0, "EnabledState"}, QualifiedName{0, "TransitionTime"}};
  auto result_enabled_state_transition_time = event.resolve_field(path_enabled_state_transition_time);
  ASSERT_FALSE(result_enabled_state_transition_time.empty())
    << "EnabledState.TransitionTime resolved to empty";
  EXPECT_EQ(result_enabled_state_transition_time.as<DateTime>(), sentinel_enabled_state.transitionTime);
  const QualifiedName path_enabled_state_current_state[]{
    QualifiedName{0, "EnabledState"}, QualifiedName{0, "CurrentState"}};
  auto result_enabled_state_current_state = event.resolve_field(path_enabled_state_current_state);
  ASSERT_FALSE(result_enabled_state_current_state.empty()) << "EnabledState.CurrentState resolved to empty";
  EXPECT_EQ(result_enabled_state_current_state.as<LocalizedText>(), sentinel_enabled_state.currentState);
  auto sentinel_quality = ConditionVariableState{Variant{42}, DateTime::now()};
  event.quality = sentinel_quality;
  const QualifiedName path_quality_source_timestamp[]{
    QualifiedName{0, "Quality"}, QualifiedName{0, "SourceTimestamp"}};
  auto result_quality_source_timestamp = event.resolve_field(path_quality_source_timestamp);
  ASSERT_FALSE(result_quality_source_timestamp.empty()) << "Quality.SourceTimestamp resolved to empty";
  EXPECT_EQ(result_quality_source_timestamp.as<DateTime>(), sentinel_quality.sourceTimestamp);
  auto sentinel_last_severity = ConditionVariableState{Variant{42}, DateTime::now()};
  event.lastSeverity = sentinel_last_severity;
  const QualifiedName path_last_severity_source_timestamp[]{
    QualifiedName{0, "LastSeverity"}, QualifiedName{0, "SourceTimestamp"}};
  auto result_last_severity_source_timestamp = event.resolve_field(path_last_severity_source_timestamp);
  ASSERT_FALSE(result_last_severity_source_timestamp.empty())
    << "LastSeverity.SourceTimestamp resolved to empty";
  EXPECT_EQ(result_last_severity_source_timestamp.as<DateTime>(), sentinel_last_severity.sourceTimestamp);
  auto sentinel_comment = ConditionVariableState{Variant{42}, DateTime::now()};
  event.comment = sentinel_comment;
  const QualifiedName path_comment_source_timestamp[]{
    QualifiedName{0, "Comment"}, QualifiedName{0, "SourceTimestamp"}};
  auto result_comment_source_timestamp = event.resolve_field(path_comment_source_timestamp);
  ASSERT_FALSE(result_comment_source_timestamp.empty()) << "Comment.SourceTimestamp resolved to empty";
  EXPECT_EQ(result_comment_source_timestamp.as<DateTime>(), sentinel_comment.sourceTimestamp);
}

TEST(GeneratedEventTypeTests, ConditionPayload_Clone)
{
  ConditionPayload event;
  event.severity = 511;
  auto sentinel_clone_condition_class_id = NodeId{1, 42};
  event.conditionClassId = sentinel_clone_condition_class_id;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<ConditionPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->conditionClassId, sentinel_clone_condition_class_id);
}

TEST(GeneratedEventTypeTests, ConditionPayload_ParentDelegation)
{
  ConditionPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AcknowledgeableConditionPayload_Construction)
{
  AcknowledgeableConditionPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AcknowledgeableConditionType});
}

TEST(GeneratedEventTypeTests, AcknowledgeableConditionPayload_ResolveOwnFields)
{
  AcknowledgeableConditionPayload event;
  auto sentinel_acked_state = TwoStateVariableState{true, LocalizedText{"", "Active"}, DateTime::now()};
  event.ackedState = sentinel_acked_state;
  const QualifiedName path_acked_state[]{QualifiedName{0, "AckedState"}};
  auto result_acked_state = event.resolve_field(path_acked_state);
  ASSERT_FALSE(result_acked_state.empty()) << "AckedState resolved to empty";
  EXPECT_EQ(result_acked_state.as<LocalizedText>(), sentinel_acked_state.currentState);
}

TEST(GeneratedEventTypeTests, AcknowledgeableConditionPayload_OptionalFields_Unset)
{
  AcknowledgeableConditionPayload event;
  const QualifiedName path_confirmed_state[]{QualifiedName{0, "ConfirmedState"}};
  EXPECT_TRUE(event.resolve_field(path_confirmed_state).empty())
    << "ConfirmedState unexpectedly resolved while unset";
}

TEST(GeneratedEventTypeTests, AcknowledgeableConditionPayload_OptionalFields_Set)
{
  AcknowledgeableConditionPayload event;
  auto sentinel_confirmed_state = TwoStateVariableState{true, LocalizedText{"", "Active"}, DateTime::now()};
  event.confirmedState = sentinel_confirmed_state;
  const QualifiedName path_confirmed_state[]{QualifiedName{0, "ConfirmedState"}};
  auto result_confirmed_state = event.resolve_field(path_confirmed_state);
  ASSERT_FALSE(result_confirmed_state.empty()) << "ConfirmedState resolved to empty after being set";
  EXPECT_EQ(result_confirmed_state.as<LocalizedText>(), sentinel_confirmed_state.currentState);
}

TEST(GeneratedEventTypeTests, AcknowledgeableConditionPayload_CompoundSubFields)
{
  AcknowledgeableConditionPayload event;
  auto sentinel_acked_state = TwoStateVariableState{true, LocalizedText{"", "Active"}, DateTime::now()};
  event.ackedState = sentinel_acked_state;
  const QualifiedName path_acked_state_id[]{QualifiedName{0, "AckedState"}, QualifiedName{0, "Id"}};
  auto result_acked_state_id = event.resolve_field(path_acked_state_id);
  ASSERT_FALSE(result_acked_state_id.empty()) << "AckedState.Id resolved to empty";
  EXPECT_EQ(result_acked_state_id.as<bool>(), sentinel_acked_state.id);
  const QualifiedName path_acked_state_transition_time[]{
    QualifiedName{0, "AckedState"}, QualifiedName{0, "TransitionTime"}};
  auto result_acked_state_transition_time = event.resolve_field(path_acked_state_transition_time);
  ASSERT_FALSE(result_acked_state_transition_time.empty()) << "AckedState.TransitionTime resolved to empty";
  EXPECT_EQ(result_acked_state_transition_time.as<DateTime>(), sentinel_acked_state.transitionTime);
  const QualifiedName path_acked_state_current_state[]{
    QualifiedName{0, "AckedState"}, QualifiedName{0, "CurrentState"}};
  auto result_acked_state_current_state = event.resolve_field(path_acked_state_current_state);
  ASSERT_FALSE(result_acked_state_current_state.empty()) << "AckedState.CurrentState resolved to empty";
  EXPECT_EQ(result_acked_state_current_state.as<LocalizedText>(), sentinel_acked_state.currentState);
}

TEST(GeneratedEventTypeTests, AcknowledgeableConditionPayload_OptionalCompoundSubFields)
{
  AcknowledgeableConditionPayload event;
  auto sentinel_confirmed_state = TwoStateVariableState{true, LocalizedText{"", "Active"}, DateTime::now()};
  event.confirmedState = sentinel_confirmed_state;
  const QualifiedName path_confirmed_state_id[]{QualifiedName{0, "ConfirmedState"}, QualifiedName{0, "Id"}};
  auto result_confirmed_state_id = event.resolve_field(path_confirmed_state_id);
  ASSERT_FALSE(result_confirmed_state_id.empty()) << "ConfirmedState.Id resolved to empty after being set";
  EXPECT_EQ(result_confirmed_state_id.as<bool>(), sentinel_confirmed_state.id);
  const QualifiedName path_confirmed_state_transition_time[]{
    QualifiedName{0, "ConfirmedState"}, QualifiedName{0, "TransitionTime"}};
  auto result_confirmed_state_transition_time = event.resolve_field(path_confirmed_state_transition_time);
  ASSERT_FALSE(result_confirmed_state_transition_time.empty())
    << "ConfirmedState.TransitionTime resolved to empty after being set";
  EXPECT_EQ(result_confirmed_state_transition_time.as<DateTime>(), sentinel_confirmed_state.transitionTime);
  const QualifiedName path_confirmed_state_current_state[]{
    QualifiedName{0, "ConfirmedState"}, QualifiedName{0, "CurrentState"}};
  auto result_confirmed_state_current_state = event.resolve_field(path_confirmed_state_current_state);
  ASSERT_FALSE(result_confirmed_state_current_state.empty())
    << "ConfirmedState.CurrentState resolved to empty after being set";
  EXPECT_EQ(result_confirmed_state_current_state.as<LocalizedText>(), sentinel_confirmed_state.currentState);
}

TEST(GeneratedEventTypeTests, AcknowledgeableConditionPayload_Clone)
{
  AcknowledgeableConditionPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AcknowledgeableConditionPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AcknowledgeableConditionPayload_ParentDelegation)
{
  AcknowledgeableConditionPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AlarmConditionPayload_Construction)
{
  AlarmConditionPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AlarmConditionType});
}

TEST(GeneratedEventTypeTests, AlarmConditionPayload_ResolveOwnFields)
{
  AlarmConditionPayload event;
  auto sentinel_active_state = TwoStateVariableState{true, LocalizedText{"", "Active"}, DateTime::now()};
  event.activeState = sentinel_active_state;
  const QualifiedName path_active_state[]{QualifiedName{0, "ActiveState"}};
  auto result_active_state = event.resolve_field(path_active_state);
  ASSERT_FALSE(result_active_state.empty()) << "ActiveState resolved to empty";
  EXPECT_EQ(result_active_state.as<LocalizedText>(), sentinel_active_state.currentState);
  auto sentinel_input_node = NodeId{1, 42};
  event.inputNode = sentinel_input_node;
  const QualifiedName path_input_node[]{QualifiedName{0, "InputNode"}};
  auto result_input_node = event.resolve_field(path_input_node);
  ASSERT_FALSE(result_input_node.empty()) << "InputNode resolved to empty";
  EXPECT_EQ(result_input_node.as<NodeId>(), sentinel_input_node);
  auto sentinel_suppressed_or_shelved = true;
  event.suppressedOrShelved = sentinel_suppressed_or_shelved;
  const QualifiedName path_suppressed_or_shelved[]{QualifiedName{0, "SuppressedOrShelved"}};
  auto result_suppressed_or_shelved = event.resolve_field(path_suppressed_or_shelved);
  ASSERT_FALSE(result_suppressed_or_shelved.empty()) << "SuppressedOrShelved resolved to empty";
  EXPECT_EQ(result_suppressed_or_shelved.as<bool>(), sentinel_suppressed_or_shelved);
}

TEST(GeneratedEventTypeTests, AlarmConditionPayload_OptionalFields_Unset)
{
  AlarmConditionPayload event;
  const QualifiedName path_suppressed_state[]{QualifiedName{0, "SuppressedState"}};
  EXPECT_TRUE(event.resolve_field(path_suppressed_state).empty())
    << "SuppressedState unexpectedly resolved while unset";
  const QualifiedName path_out_of_service_state[]{QualifiedName{0, "OutOfServiceState"}};
  EXPECT_TRUE(event.resolve_field(path_out_of_service_state).empty())
    << "OutOfServiceState unexpectedly resolved while unset";
  const QualifiedName path_shelving_state[]{QualifiedName{0, "ShelvingState"}};
  EXPECT_TRUE(event.resolve_field(path_shelving_state).empty())
    << "ShelvingState unexpectedly resolved while unset";
  const QualifiedName path_max_time_shelved[]{QualifiedName{0, "MaxTimeShelved"}};
  EXPECT_TRUE(event.resolve_field(path_max_time_shelved).empty())
    << "MaxTimeShelved unexpectedly resolved while unset";
  const QualifiedName path_audible_enabled[]{QualifiedName{0, "AudibleEnabled"}};
  EXPECT_TRUE(event.resolve_field(path_audible_enabled).empty())
    << "AudibleEnabled unexpectedly resolved while unset";
  const QualifiedName path_silence_state[]{QualifiedName{0, "SilenceState"}};
  EXPECT_TRUE(event.resolve_field(path_silence_state).empty())
    << "SilenceState unexpectedly resolved while unset";
  const QualifiedName path_on_delay[]{QualifiedName{0, "OnDelay"}};
  EXPECT_TRUE(event.resolve_field(path_on_delay).empty()) << "OnDelay unexpectedly resolved while unset";
  const QualifiedName path_off_delay[]{QualifiedName{0, "OffDelay"}};
  EXPECT_TRUE(event.resolve_field(path_off_delay).empty()) << "OffDelay unexpectedly resolved while unset";
  const QualifiedName path_latched_state[]{QualifiedName{0, "LatchedState"}};
  EXPECT_TRUE(event.resolve_field(path_latched_state).empty())
    << "LatchedState unexpectedly resolved while unset";
  const QualifiedName path_re_alarm_time[]{QualifiedName{0, "ReAlarmTime"}};
  EXPECT_TRUE(event.resolve_field(path_re_alarm_time).empty())
    << "ReAlarmTime unexpectedly resolved while unset";
}

TEST(GeneratedEventTypeTests, AlarmConditionPayload_OptionalFields_Set)
{
  AlarmConditionPayload event;
  auto sentinel_suppressed_state = TwoStateVariableState{true, LocalizedText{"", "Active"}, DateTime::now()};
  event.suppressedState = sentinel_suppressed_state;
  const QualifiedName path_suppressed_state[]{QualifiedName{0, "SuppressedState"}};
  auto result_suppressed_state = event.resolve_field(path_suppressed_state);
  ASSERT_FALSE(result_suppressed_state.empty()) << "SuppressedState resolved to empty after being set";
  EXPECT_EQ(result_suppressed_state.as<LocalizedText>(), sentinel_suppressed_state.currentState);
  auto sentinel_out_of_service_state =
    TwoStateVariableState{true, LocalizedText{"", "Active"}, DateTime::now()};
  event.outOfServiceState = sentinel_out_of_service_state;
  const QualifiedName path_out_of_service_state[]{QualifiedName{0, "OutOfServiceState"}};
  auto result_out_of_service_state = event.resolve_field(path_out_of_service_state);
  ASSERT_FALSE(result_out_of_service_state.empty()) << "OutOfServiceState resolved to empty after being set";
  EXPECT_EQ(result_out_of_service_state.as<LocalizedText>(), sentinel_out_of_service_state.currentState);
  auto sentinel_shelving_state =
    ShelvedStateVariableState{LocalizedText{"", "OneShotShelved"}, NodeId{0, 2930u}, 1000.0};
  event.shelvingState = sentinel_shelving_state;
  const QualifiedName path_shelving_state[]{QualifiedName{0, "ShelvingState"}};
  auto result_shelving_state = event.resolve_field(path_shelving_state);
  ASSERT_FALSE(result_shelving_state.empty()) << "ShelvingState resolved to empty after being set";
  EXPECT_EQ(result_shelving_state.as<LocalizedText>(), sentinel_shelving_state.currentState);
  auto sentinel_max_time_shelved = Variant{42};
  event.maxTimeShelved = sentinel_max_time_shelved;
  const QualifiedName path_max_time_shelved[]{QualifiedName{0, "MaxTimeShelved"}};
  auto result_max_time_shelved = event.resolve_field(path_max_time_shelved);
  ASSERT_FALSE(result_max_time_shelved.empty()) << "MaxTimeShelved resolved to empty after being set";
  auto sentinel_audible_enabled = true;
  event.audibleEnabled = sentinel_audible_enabled;
  const QualifiedName path_audible_enabled[]{QualifiedName{0, "AudibleEnabled"}};
  auto result_audible_enabled = event.resolve_field(path_audible_enabled);
  ASSERT_FALSE(result_audible_enabled.empty()) << "AudibleEnabled resolved to empty after being set";
  EXPECT_EQ(result_audible_enabled.as<bool>(), sentinel_audible_enabled);
  auto sentinel_silence_state = TwoStateVariableState{true, LocalizedText{"", "Active"}, DateTime::now()};
  event.silenceState = sentinel_silence_state;
  const QualifiedName path_silence_state[]{QualifiedName{0, "SilenceState"}};
  auto result_silence_state = event.resolve_field(path_silence_state);
  ASSERT_FALSE(result_silence_state.empty()) << "SilenceState resolved to empty after being set";
  EXPECT_EQ(result_silence_state.as<LocalizedText>(), sentinel_silence_state.currentState);
  auto sentinel_on_delay = Variant{42};
  event.onDelay = sentinel_on_delay;
  const QualifiedName path_on_delay[]{QualifiedName{0, "OnDelay"}};
  auto result_on_delay = event.resolve_field(path_on_delay);
  ASSERT_FALSE(result_on_delay.empty()) << "OnDelay resolved to empty after being set";
  auto sentinel_off_delay = Variant{42};
  event.offDelay = sentinel_off_delay;
  const QualifiedName path_off_delay[]{QualifiedName{0, "OffDelay"}};
  auto result_off_delay = event.resolve_field(path_off_delay);
  ASSERT_FALSE(result_off_delay.empty()) << "OffDelay resolved to empty after being set";
  auto sentinel_latched_state = TwoStateVariableState{true, LocalizedText{"", "Active"}, DateTime::now()};
  event.latchedState = sentinel_latched_state;
  const QualifiedName path_latched_state[]{QualifiedName{0, "LatchedState"}};
  auto result_latched_state = event.resolve_field(path_latched_state);
  ASSERT_FALSE(result_latched_state.empty()) << "LatchedState resolved to empty after being set";
  EXPECT_EQ(result_latched_state.as<LocalizedText>(), sentinel_latched_state.currentState);
  auto sentinel_re_alarm_time = Variant{42};
  event.reAlarmTime = sentinel_re_alarm_time;
  const QualifiedName path_re_alarm_time[]{QualifiedName{0, "ReAlarmTime"}};
  auto result_re_alarm_time = event.resolve_field(path_re_alarm_time);
  ASSERT_FALSE(result_re_alarm_time.empty()) << "ReAlarmTime resolved to empty after being set";
}

TEST(GeneratedEventTypeTests, AlarmConditionPayload_CompoundSubFields)
{
  AlarmConditionPayload event;
  auto sentinel_active_state = TwoStateVariableState{true, LocalizedText{"", "Active"}, DateTime::now()};
  event.activeState = sentinel_active_state;
  const QualifiedName path_active_state_id[]{QualifiedName{0, "ActiveState"}, QualifiedName{0, "Id"}};
  auto result_active_state_id = event.resolve_field(path_active_state_id);
  ASSERT_FALSE(result_active_state_id.empty()) << "ActiveState.Id resolved to empty";
  EXPECT_EQ(result_active_state_id.as<bool>(), sentinel_active_state.id);
  const QualifiedName path_active_state_transition_time[]{
    QualifiedName{0, "ActiveState"}, QualifiedName{0, "TransitionTime"}};
  auto result_active_state_transition_time = event.resolve_field(path_active_state_transition_time);
  ASSERT_FALSE(result_active_state_transition_time.empty()) << "ActiveState.TransitionTime resolved to empty";
  EXPECT_EQ(result_active_state_transition_time.as<DateTime>(), sentinel_active_state.transitionTime);
  const QualifiedName path_active_state_current_state[]{
    QualifiedName{0, "ActiveState"}, QualifiedName{0, "CurrentState"}};
  auto result_active_state_current_state = event.resolve_field(path_active_state_current_state);
  ASSERT_FALSE(result_active_state_current_state.empty()) << "ActiveState.CurrentState resolved to empty";
  EXPECT_EQ(result_active_state_current_state.as<LocalizedText>(), sentinel_active_state.currentState);
}

TEST(GeneratedEventTypeTests, AlarmConditionPayload_OptionalCompoundSubFields)
{
  AlarmConditionPayload event;
  auto sentinel_suppressed_state = TwoStateVariableState{true, LocalizedText{"", "Active"}, DateTime::now()};
  event.suppressedState = sentinel_suppressed_state;
  const QualifiedName path_suppressed_state_id[]{QualifiedName{0, "SuppressedState"}, QualifiedName{0, "Id"}};
  auto result_suppressed_state_id = event.resolve_field(path_suppressed_state_id);
  ASSERT_FALSE(result_suppressed_state_id.empty()) << "SuppressedState.Id resolved to empty after being set";
  EXPECT_EQ(result_suppressed_state_id.as<bool>(), sentinel_suppressed_state.id);
  const QualifiedName path_suppressed_state_transition_time[]{
    QualifiedName{0, "SuppressedState"}, QualifiedName{0, "TransitionTime"}};
  auto result_suppressed_state_transition_time = event.resolve_field(path_suppressed_state_transition_time);
  ASSERT_FALSE(result_suppressed_state_transition_time.empty())
    << "SuppressedState.TransitionTime resolved to empty after being set";
  EXPECT_EQ(result_suppressed_state_transition_time.as<DateTime>(), sentinel_suppressed_state.transitionTime);
  const QualifiedName path_suppressed_state_current_state[]{
    QualifiedName{0, "SuppressedState"}, QualifiedName{0, "CurrentState"}};
  auto result_suppressed_state_current_state = event.resolve_field(path_suppressed_state_current_state);
  ASSERT_FALSE(result_suppressed_state_current_state.empty())
    << "SuppressedState.CurrentState resolved to empty after being set";
  EXPECT_EQ(
    result_suppressed_state_current_state.as<LocalizedText>(), sentinel_suppressed_state.currentState);
  auto sentinel_out_of_service_state =
    TwoStateVariableState{true, LocalizedText{"", "Active"}, DateTime::now()};
  event.outOfServiceState = sentinel_out_of_service_state;
  const QualifiedName path_out_of_service_state_id[]{
    QualifiedName{0, "OutOfServiceState"}, QualifiedName{0, "Id"}};
  auto result_out_of_service_state_id = event.resolve_field(path_out_of_service_state_id);
  ASSERT_FALSE(result_out_of_service_state_id.empty())
    << "OutOfServiceState.Id resolved to empty after being set";
  EXPECT_EQ(result_out_of_service_state_id.as<bool>(), sentinel_out_of_service_state.id);
  const QualifiedName path_out_of_service_state_transition_time[]{
    QualifiedName{0, "OutOfServiceState"}, QualifiedName{0, "TransitionTime"}};
  auto result_out_of_service_state_transition_time =
    event.resolve_field(path_out_of_service_state_transition_time);
  ASSERT_FALSE(result_out_of_service_state_transition_time.empty())
    << "OutOfServiceState.TransitionTime resolved to empty after being set";
  EXPECT_EQ(
    result_out_of_service_state_transition_time.as<DateTime>(), sentinel_out_of_service_state.transitionTime);
  const QualifiedName path_out_of_service_state_current_state[]{
    QualifiedName{0, "OutOfServiceState"}, QualifiedName{0, "CurrentState"}};
  auto result_out_of_service_state_current_state =
    event.resolve_field(path_out_of_service_state_current_state);
  ASSERT_FALSE(result_out_of_service_state_current_state.empty())
    << "OutOfServiceState.CurrentState resolved to empty after being set";
  EXPECT_EQ(result_out_of_service_state_current_state.as<LocalizedText>(),
    sentinel_out_of_service_state.currentState);
  auto sentinel_shelving_state =
    ShelvedStateVariableState{LocalizedText{"", "OneShotShelved"}, NodeId{0, 2930u}, 1000.0};
  event.shelvingState = sentinel_shelving_state;
  const QualifiedName path_shelving_state_current_state[]{
    QualifiedName{0, "ShelvingState"}, QualifiedName{0, "CurrentState"}};
  auto result_shelving_state_current_state = event.resolve_field(path_shelving_state_current_state);
  ASSERT_FALSE(result_shelving_state_current_state.empty())
    << "ShelvingState.CurrentState resolved to empty after being set";
  EXPECT_EQ(result_shelving_state_current_state.as<LocalizedText>(), sentinel_shelving_state.currentState);
  const QualifiedName path_shelving_state_unshelve_time[]{
    QualifiedName{0, "ShelvingState"}, QualifiedName{0, "UnshelveTime"}};
  auto result_shelving_state_unshelve_time = event.resolve_field(path_shelving_state_unshelve_time);
  ASSERT_FALSE(result_shelving_state_unshelve_time.empty())
    << "ShelvingState.UnshelveTime resolved to empty after being set";
  EXPECT_EQ(result_shelving_state_unshelve_time.as<double>(), sentinel_shelving_state.unshelveTime);
  auto sentinel_silence_state = TwoStateVariableState{true, LocalizedText{"", "Active"}, DateTime::now()};
  event.silenceState = sentinel_silence_state;
  const QualifiedName path_silence_state_id[]{QualifiedName{0, "SilenceState"}, QualifiedName{0, "Id"}};
  auto result_silence_state_id = event.resolve_field(path_silence_state_id);
  ASSERT_FALSE(result_silence_state_id.empty()) << "SilenceState.Id resolved to empty after being set";
  EXPECT_EQ(result_silence_state_id.as<bool>(), sentinel_silence_state.id);
  const QualifiedName path_silence_state_transition_time[]{
    QualifiedName{0, "SilenceState"}, QualifiedName{0, "TransitionTime"}};
  auto result_silence_state_transition_time = event.resolve_field(path_silence_state_transition_time);
  ASSERT_FALSE(result_silence_state_transition_time.empty())
    << "SilenceState.TransitionTime resolved to empty after being set";
  EXPECT_EQ(result_silence_state_transition_time.as<DateTime>(), sentinel_silence_state.transitionTime);
  const QualifiedName path_silence_state_current_state[]{
    QualifiedName{0, "SilenceState"}, QualifiedName{0, "CurrentState"}};
  auto result_silence_state_current_state = event.resolve_field(path_silence_state_current_state);
  ASSERT_FALSE(result_silence_state_current_state.empty())
    << "SilenceState.CurrentState resolved to empty after being set";
  EXPECT_EQ(result_silence_state_current_state.as<LocalizedText>(), sentinel_silence_state.currentState);
  auto sentinel_latched_state = TwoStateVariableState{true, LocalizedText{"", "Active"}, DateTime::now()};
  event.latchedState = sentinel_latched_state;
  const QualifiedName path_latched_state_id[]{QualifiedName{0, "LatchedState"}, QualifiedName{0, "Id"}};
  auto result_latched_state_id = event.resolve_field(path_latched_state_id);
  ASSERT_FALSE(result_latched_state_id.empty()) << "LatchedState.Id resolved to empty after being set";
  EXPECT_EQ(result_latched_state_id.as<bool>(), sentinel_latched_state.id);
  const QualifiedName path_latched_state_transition_time[]{
    QualifiedName{0, "LatchedState"}, QualifiedName{0, "TransitionTime"}};
  auto result_latched_state_transition_time = event.resolve_field(path_latched_state_transition_time);
  ASSERT_FALSE(result_latched_state_transition_time.empty())
    << "LatchedState.TransitionTime resolved to empty after being set";
  EXPECT_EQ(result_latched_state_transition_time.as<DateTime>(), sentinel_latched_state.transitionTime);
  const QualifiedName path_latched_state_current_state[]{
    QualifiedName{0, "LatchedState"}, QualifiedName{0, "CurrentState"}};
  auto result_latched_state_current_state = event.resolve_field(path_latched_state_current_state);
  ASSERT_FALSE(result_latched_state_current_state.empty())
    << "LatchedState.CurrentState resolved to empty after being set";
  EXPECT_EQ(result_latched_state_current_state.as<LocalizedText>(), sentinel_latched_state.currentState);
}

TEST(GeneratedEventTypeTests, AlarmConditionPayload_Clone)
{
  AlarmConditionPayload event;
  event.severity = 511;
  auto sentinel_clone_input_node = NodeId{1, 42};
  event.inputNode = sentinel_clone_input_node;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AlarmConditionPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->inputNode, sentinel_clone_input_node);
}

TEST(GeneratedEventTypeTests, AlarmConditionPayload_ParentDelegation)
{
  AlarmConditionPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, LimitAlarmPayload_Construction)
{
  LimitAlarmPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::LimitAlarmType});
}

TEST(GeneratedEventTypeTests, LimitAlarmPayload_OptionalFields_Unset)
{
  LimitAlarmPayload event;
  const QualifiedName path_high_high_limit[]{QualifiedName{0, "HighHighLimit"}};
  EXPECT_TRUE(event.resolve_field(path_high_high_limit).empty())
    << "HighHighLimit unexpectedly resolved while unset";
  const QualifiedName path_high_limit[]{QualifiedName{0, "HighLimit"}};
  EXPECT_TRUE(event.resolve_field(path_high_limit).empty()) << "HighLimit unexpectedly resolved while unset";
  const QualifiedName path_low_limit[]{QualifiedName{0, "LowLimit"}};
  EXPECT_TRUE(event.resolve_field(path_low_limit).empty()) << "LowLimit unexpectedly resolved while unset";
  const QualifiedName path_low_low_limit[]{QualifiedName{0, "LowLowLimit"}};
  EXPECT_TRUE(event.resolve_field(path_low_low_limit).empty())
    << "LowLowLimit unexpectedly resolved while unset";
  const QualifiedName path_base_high_high_limit[]{QualifiedName{0, "BaseHighHighLimit"}};
  EXPECT_TRUE(event.resolve_field(path_base_high_high_limit).empty())
    << "BaseHighHighLimit unexpectedly resolved while unset";
  const QualifiedName path_base_high_limit[]{QualifiedName{0, "BaseHighLimit"}};
  EXPECT_TRUE(event.resolve_field(path_base_high_limit).empty())
    << "BaseHighLimit unexpectedly resolved while unset";
  const QualifiedName path_base_low_limit[]{QualifiedName{0, "BaseLowLimit"}};
  EXPECT_TRUE(event.resolve_field(path_base_low_limit).empty())
    << "BaseLowLimit unexpectedly resolved while unset";
  const QualifiedName path_base_low_low_limit[]{QualifiedName{0, "BaseLowLowLimit"}};
  EXPECT_TRUE(event.resolve_field(path_base_low_low_limit).empty())
    << "BaseLowLowLimit unexpectedly resolved while unset";
  const QualifiedName path_severity_high_high[]{QualifiedName{0, "SeverityHighHigh"}};
  EXPECT_TRUE(event.resolve_field(path_severity_high_high).empty())
    << "SeverityHighHigh unexpectedly resolved while unset";
  const QualifiedName path_severity_high[]{QualifiedName{0, "SeverityHigh"}};
  EXPECT_TRUE(event.resolve_field(path_severity_high).empty())
    << "SeverityHigh unexpectedly resolved while unset";
  const QualifiedName path_severity_low[]{QualifiedName{0, "SeverityLow"}};
  EXPECT_TRUE(event.resolve_field(path_severity_low).empty())
    << "SeverityLow unexpectedly resolved while unset";
  const QualifiedName path_severity_low_low[]{QualifiedName{0, "SeverityLowLow"}};
  EXPECT_TRUE(event.resolve_field(path_severity_low_low).empty())
    << "SeverityLowLow unexpectedly resolved while unset";
  const QualifiedName path_high_high_deadband[]{QualifiedName{0, "HighHighDeadband"}};
  EXPECT_TRUE(event.resolve_field(path_high_high_deadband).empty())
    << "HighHighDeadband unexpectedly resolved while unset";
  const QualifiedName path_high_deadband[]{QualifiedName{0, "HighDeadband"}};
  EXPECT_TRUE(event.resolve_field(path_high_deadband).empty())
    << "HighDeadband unexpectedly resolved while unset";
  const QualifiedName path_low_deadband[]{QualifiedName{0, "LowDeadband"}};
  EXPECT_TRUE(event.resolve_field(path_low_deadband).empty())
    << "LowDeadband unexpectedly resolved while unset";
  const QualifiedName path_low_low_deadband[]{QualifiedName{0, "LowLowDeadband"}};
  EXPECT_TRUE(event.resolve_field(path_low_low_deadband).empty())
    << "LowLowDeadband unexpectedly resolved while unset";
}

TEST(GeneratedEventTypeTests, LimitAlarmPayload_OptionalFields_Set)
{
  LimitAlarmPayload event;
  auto sentinel_high_high_limit = 3.14;
  event.highHighLimit = sentinel_high_high_limit;
  const QualifiedName path_high_high_limit[]{QualifiedName{0, "HighHighLimit"}};
  auto result_high_high_limit = event.resolve_field(path_high_high_limit);
  ASSERT_FALSE(result_high_high_limit.empty()) << "HighHighLimit resolved to empty after being set";
  EXPECT_EQ(result_high_high_limit.as<double>(), sentinel_high_high_limit);
  auto sentinel_high_limit = 3.14;
  event.highLimit = sentinel_high_limit;
  const QualifiedName path_high_limit[]{QualifiedName{0, "HighLimit"}};
  auto result_high_limit = event.resolve_field(path_high_limit);
  ASSERT_FALSE(result_high_limit.empty()) << "HighLimit resolved to empty after being set";
  EXPECT_EQ(result_high_limit.as<double>(), sentinel_high_limit);
  auto sentinel_low_limit = 3.14;
  event.lowLimit = sentinel_low_limit;
  const QualifiedName path_low_limit[]{QualifiedName{0, "LowLimit"}};
  auto result_low_limit = event.resolve_field(path_low_limit);
  ASSERT_FALSE(result_low_limit.empty()) << "LowLimit resolved to empty after being set";
  EXPECT_EQ(result_low_limit.as<double>(), sentinel_low_limit);
  auto sentinel_low_low_limit = 3.14;
  event.lowLowLimit = sentinel_low_low_limit;
  const QualifiedName path_low_low_limit[]{QualifiedName{0, "LowLowLimit"}};
  auto result_low_low_limit = event.resolve_field(path_low_low_limit);
  ASSERT_FALSE(result_low_low_limit.empty()) << "LowLowLimit resolved to empty after being set";
  EXPECT_EQ(result_low_low_limit.as<double>(), sentinel_low_low_limit);
  auto sentinel_base_high_high_limit = 3.14;
  event.baseHighHighLimit = sentinel_base_high_high_limit;
  const QualifiedName path_base_high_high_limit[]{QualifiedName{0, "BaseHighHighLimit"}};
  auto result_base_high_high_limit = event.resolve_field(path_base_high_high_limit);
  ASSERT_FALSE(result_base_high_high_limit.empty()) << "BaseHighHighLimit resolved to empty after being set";
  EXPECT_EQ(result_base_high_high_limit.as<double>(), sentinel_base_high_high_limit);
  auto sentinel_base_high_limit = 3.14;
  event.baseHighLimit = sentinel_base_high_limit;
  const QualifiedName path_base_high_limit[]{QualifiedName{0, "BaseHighLimit"}};
  auto result_base_high_limit = event.resolve_field(path_base_high_limit);
  ASSERT_FALSE(result_base_high_limit.empty()) << "BaseHighLimit resolved to empty after being set";
  EXPECT_EQ(result_base_high_limit.as<double>(), sentinel_base_high_limit);
  auto sentinel_base_low_limit = 3.14;
  event.baseLowLimit = sentinel_base_low_limit;
  const QualifiedName path_base_low_limit[]{QualifiedName{0, "BaseLowLimit"}};
  auto result_base_low_limit = event.resolve_field(path_base_low_limit);
  ASSERT_FALSE(result_base_low_limit.empty()) << "BaseLowLimit resolved to empty after being set";
  EXPECT_EQ(result_base_low_limit.as<double>(), sentinel_base_low_limit);
  auto sentinel_base_low_low_limit = 3.14;
  event.baseLowLowLimit = sentinel_base_low_low_limit;
  const QualifiedName path_base_low_low_limit[]{QualifiedName{0, "BaseLowLowLimit"}};
  auto result_base_low_low_limit = event.resolve_field(path_base_low_low_limit);
  ASSERT_FALSE(result_base_low_low_limit.empty()) << "BaseLowLowLimit resolved to empty after being set";
  EXPECT_EQ(result_base_low_low_limit.as<double>(), sentinel_base_low_low_limit);
  auto sentinel_severity_high_high = 100;
  event.severityHighHigh = sentinel_severity_high_high;
  const QualifiedName path_severity_high_high[]{QualifiedName{0, "SeverityHighHigh"}};
  auto result_severity_high_high = event.resolve_field(path_severity_high_high);
  ASSERT_FALSE(result_severity_high_high.empty()) << "SeverityHighHigh resolved to empty after being set";
  EXPECT_EQ(result_severity_high_high.as<uint16_t>(), sentinel_severity_high_high);
  auto sentinel_severity_high = 100;
  event.severityHigh = sentinel_severity_high;
  const QualifiedName path_severity_high[]{QualifiedName{0, "SeverityHigh"}};
  auto result_severity_high = event.resolve_field(path_severity_high);
  ASSERT_FALSE(result_severity_high.empty()) << "SeverityHigh resolved to empty after being set";
  EXPECT_EQ(result_severity_high.as<uint16_t>(), sentinel_severity_high);
  auto sentinel_severity_low = 100;
  event.severityLow = sentinel_severity_low;
  const QualifiedName path_severity_low[]{QualifiedName{0, "SeverityLow"}};
  auto result_severity_low = event.resolve_field(path_severity_low);
  ASSERT_FALSE(result_severity_low.empty()) << "SeverityLow resolved to empty after being set";
  EXPECT_EQ(result_severity_low.as<uint16_t>(), sentinel_severity_low);
  auto sentinel_severity_low_low = 100;
  event.severityLowLow = sentinel_severity_low_low;
  const QualifiedName path_severity_low_low[]{QualifiedName{0, "SeverityLowLow"}};
  auto result_severity_low_low = event.resolve_field(path_severity_low_low);
  ASSERT_FALSE(result_severity_low_low.empty()) << "SeverityLowLow resolved to empty after being set";
  EXPECT_EQ(result_severity_low_low.as<uint16_t>(), sentinel_severity_low_low);
  auto sentinel_high_high_deadband = 3.14;
  event.highHighDeadband = sentinel_high_high_deadband;
  const QualifiedName path_high_high_deadband[]{QualifiedName{0, "HighHighDeadband"}};
  auto result_high_high_deadband = event.resolve_field(path_high_high_deadband);
  ASSERT_FALSE(result_high_high_deadband.empty()) << "HighHighDeadband resolved to empty after being set";
  EXPECT_EQ(result_high_high_deadband.as<double>(), sentinel_high_high_deadband);
  auto sentinel_high_deadband = 3.14;
  event.highDeadband = sentinel_high_deadband;
  const QualifiedName path_high_deadband[]{QualifiedName{0, "HighDeadband"}};
  auto result_high_deadband = event.resolve_field(path_high_deadband);
  ASSERT_FALSE(result_high_deadband.empty()) << "HighDeadband resolved to empty after being set";
  EXPECT_EQ(result_high_deadband.as<double>(), sentinel_high_deadband);
  auto sentinel_low_deadband = 3.14;
  event.lowDeadband = sentinel_low_deadband;
  const QualifiedName path_low_deadband[]{QualifiedName{0, "LowDeadband"}};
  auto result_low_deadband = event.resolve_field(path_low_deadband);
  ASSERT_FALSE(result_low_deadband.empty()) << "LowDeadband resolved to empty after being set";
  EXPECT_EQ(result_low_deadband.as<double>(), sentinel_low_deadband);
  auto sentinel_low_low_deadband = 3.14;
  event.lowLowDeadband = sentinel_low_low_deadband;
  const QualifiedName path_low_low_deadband[]{QualifiedName{0, "LowLowDeadband"}};
  auto result_low_low_deadband = event.resolve_field(path_low_low_deadband);
  ASSERT_FALSE(result_low_low_deadband.empty()) << "LowLowDeadband resolved to empty after being set";
  EXPECT_EQ(result_low_low_deadband.as<double>(), sentinel_low_low_deadband);
}

TEST(GeneratedEventTypeTests, LimitAlarmPayload_Clone)
{
  LimitAlarmPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<LimitAlarmPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, LimitAlarmPayload_ParentDelegation)
{
  LimitAlarmPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, NonExclusiveLimitAlarmPayload_Construction)
{
  NonExclusiveLimitAlarmPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::NonExclusiveLimitAlarmType});
}

TEST(GeneratedEventTypeTests, NonExclusiveLimitAlarmPayload_OptionalFields_Unset)
{
  NonExclusiveLimitAlarmPayload event;
  const QualifiedName path_high_high_state[]{QualifiedName{0, "HighHighState"}};
  EXPECT_TRUE(event.resolve_field(path_high_high_state).empty())
    << "HighHighState unexpectedly resolved while unset";
  const QualifiedName path_high_state[]{QualifiedName{0, "HighState"}};
  EXPECT_TRUE(event.resolve_field(path_high_state).empty()) << "HighState unexpectedly resolved while unset";
  const QualifiedName path_low_state[]{QualifiedName{0, "LowState"}};
  EXPECT_TRUE(event.resolve_field(path_low_state).empty()) << "LowState unexpectedly resolved while unset";
  const QualifiedName path_low_low_state[]{QualifiedName{0, "LowLowState"}};
  EXPECT_TRUE(event.resolve_field(path_low_low_state).empty())
    << "LowLowState unexpectedly resolved while unset";
}

TEST(GeneratedEventTypeTests, NonExclusiveLimitAlarmPayload_OptionalFields_Set)
{
  NonExclusiveLimitAlarmPayload event;
  auto sentinel_high_high_state = TwoStateVariableState{true, LocalizedText{"", "Active"}, DateTime::now()};
  event.highHighState = sentinel_high_high_state;
  const QualifiedName path_high_high_state[]{QualifiedName{0, "HighHighState"}};
  auto result_high_high_state = event.resolve_field(path_high_high_state);
  ASSERT_FALSE(result_high_high_state.empty()) << "HighHighState resolved to empty after being set";
  EXPECT_EQ(result_high_high_state.as<LocalizedText>(), sentinel_high_high_state.currentState);
  auto sentinel_high_state = TwoStateVariableState{true, LocalizedText{"", "Active"}, DateTime::now()};
  event.highState = sentinel_high_state;
  const QualifiedName path_high_state[]{QualifiedName{0, "HighState"}};
  auto result_high_state = event.resolve_field(path_high_state);
  ASSERT_FALSE(result_high_state.empty()) << "HighState resolved to empty after being set";
  EXPECT_EQ(result_high_state.as<LocalizedText>(), sentinel_high_state.currentState);
  auto sentinel_low_state = TwoStateVariableState{true, LocalizedText{"", "Active"}, DateTime::now()};
  event.lowState = sentinel_low_state;
  const QualifiedName path_low_state[]{QualifiedName{0, "LowState"}};
  auto result_low_state = event.resolve_field(path_low_state);
  ASSERT_FALSE(result_low_state.empty()) << "LowState resolved to empty after being set";
  EXPECT_EQ(result_low_state.as<LocalizedText>(), sentinel_low_state.currentState);
  auto sentinel_low_low_state = TwoStateVariableState{true, LocalizedText{"", "Active"}, DateTime::now()};
  event.lowLowState = sentinel_low_low_state;
  const QualifiedName path_low_low_state[]{QualifiedName{0, "LowLowState"}};
  auto result_low_low_state = event.resolve_field(path_low_low_state);
  ASSERT_FALSE(result_low_low_state.empty()) << "LowLowState resolved to empty after being set";
  EXPECT_EQ(result_low_low_state.as<LocalizedText>(), sentinel_low_low_state.currentState);
}

TEST(GeneratedEventTypeTests, NonExclusiveLimitAlarmPayload_OptionalCompoundSubFields)
{
  NonExclusiveLimitAlarmPayload event;
  auto sentinel_high_high_state = TwoStateVariableState{true, LocalizedText{"", "Active"}, DateTime::now()};
  event.highHighState = sentinel_high_high_state;
  const QualifiedName path_high_high_state_id[]{QualifiedName{0, "HighHighState"}, QualifiedName{0, "Id"}};
  auto result_high_high_state_id = event.resolve_field(path_high_high_state_id);
  ASSERT_FALSE(result_high_high_state_id.empty()) << "HighHighState.Id resolved to empty after being set";
  EXPECT_EQ(result_high_high_state_id.as<bool>(), sentinel_high_high_state.id);
  const QualifiedName path_high_high_state_transition_time[]{
    QualifiedName{0, "HighHighState"}, QualifiedName{0, "TransitionTime"}};
  auto result_high_high_state_transition_time = event.resolve_field(path_high_high_state_transition_time);
  ASSERT_FALSE(result_high_high_state_transition_time.empty())
    << "HighHighState.TransitionTime resolved to empty after being set";
  EXPECT_EQ(result_high_high_state_transition_time.as<DateTime>(), sentinel_high_high_state.transitionTime);
  const QualifiedName path_high_high_state_current_state[]{
    QualifiedName{0, "HighHighState"}, QualifiedName{0, "CurrentState"}};
  auto result_high_high_state_current_state = event.resolve_field(path_high_high_state_current_state);
  ASSERT_FALSE(result_high_high_state_current_state.empty())
    << "HighHighState.CurrentState resolved to empty after being set";
  EXPECT_EQ(result_high_high_state_current_state.as<LocalizedText>(), sentinel_high_high_state.currentState);
  auto sentinel_high_state = TwoStateVariableState{true, LocalizedText{"", "Active"}, DateTime::now()};
  event.highState = sentinel_high_state;
  const QualifiedName path_high_state_id[]{QualifiedName{0, "HighState"}, QualifiedName{0, "Id"}};
  auto result_high_state_id = event.resolve_field(path_high_state_id);
  ASSERT_FALSE(result_high_state_id.empty()) << "HighState.Id resolved to empty after being set";
  EXPECT_EQ(result_high_state_id.as<bool>(), sentinel_high_state.id);
  const QualifiedName path_high_state_transition_time[]{
    QualifiedName{0, "HighState"}, QualifiedName{0, "TransitionTime"}};
  auto result_high_state_transition_time = event.resolve_field(path_high_state_transition_time);
  ASSERT_FALSE(result_high_state_transition_time.empty())
    << "HighState.TransitionTime resolved to empty after being set";
  EXPECT_EQ(result_high_state_transition_time.as<DateTime>(), sentinel_high_state.transitionTime);
  const QualifiedName path_high_state_current_state[]{
    QualifiedName{0, "HighState"}, QualifiedName{0, "CurrentState"}};
  auto result_high_state_current_state = event.resolve_field(path_high_state_current_state);
  ASSERT_FALSE(result_high_state_current_state.empty())
    << "HighState.CurrentState resolved to empty after being set";
  EXPECT_EQ(result_high_state_current_state.as<LocalizedText>(), sentinel_high_state.currentState);
  auto sentinel_low_state = TwoStateVariableState{true, LocalizedText{"", "Active"}, DateTime::now()};
  event.lowState = sentinel_low_state;
  const QualifiedName path_low_state_id[]{QualifiedName{0, "LowState"}, QualifiedName{0, "Id"}};
  auto result_low_state_id = event.resolve_field(path_low_state_id);
  ASSERT_FALSE(result_low_state_id.empty()) << "LowState.Id resolved to empty after being set";
  EXPECT_EQ(result_low_state_id.as<bool>(), sentinel_low_state.id);
  const QualifiedName path_low_state_transition_time[]{
    QualifiedName{0, "LowState"}, QualifiedName{0, "TransitionTime"}};
  auto result_low_state_transition_time = event.resolve_field(path_low_state_transition_time);
  ASSERT_FALSE(result_low_state_transition_time.empty())
    << "LowState.TransitionTime resolved to empty after being set";
  EXPECT_EQ(result_low_state_transition_time.as<DateTime>(), sentinel_low_state.transitionTime);
  const QualifiedName path_low_state_current_state[]{
    QualifiedName{0, "LowState"}, QualifiedName{0, "CurrentState"}};
  auto result_low_state_current_state = event.resolve_field(path_low_state_current_state);
  ASSERT_FALSE(result_low_state_current_state.empty())
    << "LowState.CurrentState resolved to empty after being set";
  EXPECT_EQ(result_low_state_current_state.as<LocalizedText>(), sentinel_low_state.currentState);
  auto sentinel_low_low_state = TwoStateVariableState{true, LocalizedText{"", "Active"}, DateTime::now()};
  event.lowLowState = sentinel_low_low_state;
  const QualifiedName path_low_low_state_id[]{QualifiedName{0, "LowLowState"}, QualifiedName{0, "Id"}};
  auto result_low_low_state_id = event.resolve_field(path_low_low_state_id);
  ASSERT_FALSE(result_low_low_state_id.empty()) << "LowLowState.Id resolved to empty after being set";
  EXPECT_EQ(result_low_low_state_id.as<bool>(), sentinel_low_low_state.id);
  const QualifiedName path_low_low_state_transition_time[]{
    QualifiedName{0, "LowLowState"}, QualifiedName{0, "TransitionTime"}};
  auto result_low_low_state_transition_time = event.resolve_field(path_low_low_state_transition_time);
  ASSERT_FALSE(result_low_low_state_transition_time.empty())
    << "LowLowState.TransitionTime resolved to empty after being set";
  EXPECT_EQ(result_low_low_state_transition_time.as<DateTime>(), sentinel_low_low_state.transitionTime);
  const QualifiedName path_low_low_state_current_state[]{
    QualifiedName{0, "LowLowState"}, QualifiedName{0, "CurrentState"}};
  auto result_low_low_state_current_state = event.resolve_field(path_low_low_state_current_state);
  ASSERT_FALSE(result_low_low_state_current_state.empty())
    << "LowLowState.CurrentState resolved to empty after being set";
  EXPECT_EQ(result_low_low_state_current_state.as<LocalizedText>(), sentinel_low_low_state.currentState);
}

TEST(GeneratedEventTypeTests, NonExclusiveLimitAlarmPayload_Clone)
{
  NonExclusiveLimitAlarmPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<NonExclusiveLimitAlarmPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, NonExclusiveLimitAlarmPayload_ParentDelegation)
{
  NonExclusiveLimitAlarmPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, NonExclusiveLevelAlarmPayload_Construction)
{
  NonExclusiveLevelAlarmPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::NonExclusiveLevelAlarmType});
}

TEST(GeneratedEventTypeTests, NonExclusiveLevelAlarmPayload_Clone)
{
  NonExclusiveLevelAlarmPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<NonExclusiveLevelAlarmPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, NonExclusiveLevelAlarmPayload_ParentDelegation)
{
  NonExclusiveLevelAlarmPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, NonExclusiveRateOfChangeAlarmPayload_Construction)
{
  NonExclusiveRateOfChangeAlarmPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::NonExclusiveRateOfChangeAlarmType});
}

TEST(GeneratedEventTypeTests, NonExclusiveRateOfChangeAlarmPayload_OptionalFields_Unset)
{
  NonExclusiveRateOfChangeAlarmPayload event;
  const QualifiedName path_engineering_units[]{QualifiedName{0, "EngineeringUnits"}};
  EXPECT_TRUE(event.resolve_field(path_engineering_units).empty())
    << "EngineeringUnits unexpectedly resolved while unset";
}

TEST(GeneratedEventTypeTests, NonExclusiveRateOfChangeAlarmPayload_OptionalFields_Set)
{
  NonExclusiveRateOfChangeAlarmPayload event;
  auto sentinel_engineering_units = Variant{42};
  event.engineeringUnits = sentinel_engineering_units;
  const QualifiedName path_engineering_units[]{QualifiedName{0, "EngineeringUnits"}};
  auto result_engineering_units = event.resolve_field(path_engineering_units);
  ASSERT_FALSE(result_engineering_units.empty()) << "EngineeringUnits resolved to empty after being set";
}

TEST(GeneratedEventTypeTests, NonExclusiveRateOfChangeAlarmPayload_Clone)
{
  NonExclusiveRateOfChangeAlarmPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<NonExclusiveRateOfChangeAlarmPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, NonExclusiveRateOfChangeAlarmPayload_ParentDelegation)
{
  NonExclusiveRateOfChangeAlarmPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, NonExclusiveDeviationAlarmPayload_Construction)
{
  NonExclusiveDeviationAlarmPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::NonExclusiveDeviationAlarmType});
}

TEST(GeneratedEventTypeTests, NonExclusiveDeviationAlarmPayload_ResolveOwnFields)
{
  NonExclusiveDeviationAlarmPayload event;
  auto sentinel_setpoint_node = NodeId{1, 42};
  event.setpointNode = sentinel_setpoint_node;
  const QualifiedName path_setpoint_node[]{QualifiedName{0, "SetpointNode"}};
  auto result_setpoint_node = event.resolve_field(path_setpoint_node);
  ASSERT_FALSE(result_setpoint_node.empty()) << "SetpointNode resolved to empty";
  EXPECT_EQ(result_setpoint_node.as<NodeId>(), sentinel_setpoint_node);
}

TEST(GeneratedEventTypeTests, NonExclusiveDeviationAlarmPayload_OptionalFields_Unset)
{
  NonExclusiveDeviationAlarmPayload event;
  const QualifiedName path_base_setpoint_node[]{QualifiedName{0, "BaseSetpointNode"}};
  EXPECT_TRUE(event.resolve_field(path_base_setpoint_node).empty())
    << "BaseSetpointNode unexpectedly resolved while unset";
}

TEST(GeneratedEventTypeTests, NonExclusiveDeviationAlarmPayload_OptionalFields_Set)
{
  NonExclusiveDeviationAlarmPayload event;
  auto sentinel_base_setpoint_node = NodeId{1, 42};
  event.baseSetpointNode = sentinel_base_setpoint_node;
  const QualifiedName path_base_setpoint_node[]{QualifiedName{0, "BaseSetpointNode"}};
  auto result_base_setpoint_node = event.resolve_field(path_base_setpoint_node);
  ASSERT_FALSE(result_base_setpoint_node.empty()) << "BaseSetpointNode resolved to empty after being set";
  EXPECT_EQ(result_base_setpoint_node.as<NodeId>(), sentinel_base_setpoint_node);
}

TEST(GeneratedEventTypeTests, NonExclusiveDeviationAlarmPayload_Clone)
{
  NonExclusiveDeviationAlarmPayload event;
  event.severity = 511;
  auto sentinel_clone_setpoint_node = NodeId{1, 42};
  event.setpointNode = sentinel_clone_setpoint_node;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<NonExclusiveDeviationAlarmPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->setpointNode, sentinel_clone_setpoint_node);
}

TEST(GeneratedEventTypeTests, NonExclusiveDeviationAlarmPayload_ParentDelegation)
{
  NonExclusiveDeviationAlarmPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, DiscreteAlarmPayload_Construction)
{
  DiscreteAlarmPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::DiscreteAlarmType});
}

TEST(GeneratedEventTypeTests, DiscreteAlarmPayload_Clone)
{
  DiscreteAlarmPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<DiscreteAlarmPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, DiscreteAlarmPayload_ParentDelegation)
{
  DiscreteAlarmPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, OffNormalAlarmPayload_Construction)
{
  OffNormalAlarmPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::OffNormalAlarmType});
}

TEST(GeneratedEventTypeTests, OffNormalAlarmPayload_ResolveOwnFields)
{
  OffNormalAlarmPayload event;
  auto sentinel_normal_state = NodeId{1, 42};
  event.normalState = sentinel_normal_state;
  const QualifiedName path_normal_state[]{QualifiedName{0, "NormalState"}};
  auto result_normal_state = event.resolve_field(path_normal_state);
  ASSERT_FALSE(result_normal_state.empty()) << "NormalState resolved to empty";
  EXPECT_EQ(result_normal_state.as<NodeId>(), sentinel_normal_state);
}

TEST(GeneratedEventTypeTests, OffNormalAlarmPayload_Clone)
{
  OffNormalAlarmPayload event;
  event.severity = 511;
  auto sentinel_clone_normal_state = NodeId{1, 42};
  event.normalState = sentinel_clone_normal_state;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<OffNormalAlarmPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->normalState, sentinel_clone_normal_state);
}

TEST(GeneratedEventTypeTests, OffNormalAlarmPayload_ParentDelegation)
{
  OffNormalAlarmPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, TripAlarmPayload_Construction)
{
  TripAlarmPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::TripAlarmType});
}

TEST(GeneratedEventTypeTests, TripAlarmPayload_Clone)
{
  TripAlarmPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<TripAlarmPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, TripAlarmPayload_ParentDelegation)
{
  TripAlarmPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditEventPayload_Construction)
{
  AuditEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditEventType});
}

TEST(GeneratedEventTypeTests, AuditEventPayload_ResolveOwnFields)
{
  AuditEventPayload event;
  auto sentinel_action_time_stamp = Variant{42};
  event.actionTimeStamp = sentinel_action_time_stamp;
  const QualifiedName path_action_time_stamp[]{QualifiedName{0, "ActionTimeStamp"}};
  auto result_action_time_stamp = event.resolve_field(path_action_time_stamp);
  ASSERT_FALSE(result_action_time_stamp.empty()) << "ActionTimeStamp resolved to empty";
  auto sentinel_status = true;
  event.status = sentinel_status;
  const QualifiedName path_status[]{QualifiedName{0, "Status"}};
  auto result_status = event.resolve_field(path_status);
  ASSERT_FALSE(result_status.empty()) << "Status resolved to empty";
  EXPECT_EQ(result_status.as<bool>(), sentinel_status);
  auto sentinel_server_id = String{"test"};
  event.serverId = sentinel_server_id;
  const QualifiedName path_server_id[]{QualifiedName{0, "ServerId"}};
  auto result_server_id = event.resolve_field(path_server_id);
  ASSERT_FALSE(result_server_id.empty()) << "ServerId resolved to empty";
  EXPECT_EQ(result_server_id.as<String>(), sentinel_server_id);
  auto sentinel_client_audit_entry_id = String{"test"};
  event.clientAuditEntryId = sentinel_client_audit_entry_id;
  const QualifiedName path_client_audit_entry_id[]{QualifiedName{0, "ClientAuditEntryId"}};
  auto result_client_audit_entry_id = event.resolve_field(path_client_audit_entry_id);
  ASSERT_FALSE(result_client_audit_entry_id.empty()) << "ClientAuditEntryId resolved to empty";
  EXPECT_EQ(result_client_audit_entry_id.as<String>(), sentinel_client_audit_entry_id);
  auto sentinel_client_user_id = String{"test"};
  event.clientUserId = sentinel_client_user_id;
  const QualifiedName path_client_user_id[]{QualifiedName{0, "ClientUserId"}};
  auto result_client_user_id = event.resolve_field(path_client_user_id);
  ASSERT_FALSE(result_client_user_id.empty()) << "ClientUserId resolved to empty";
  EXPECT_EQ(result_client_user_id.as<String>(), sentinel_client_user_id);
}

TEST(GeneratedEventTypeTests, AuditEventPayload_OptionalFields_Unset)
{
  AuditEventPayload event;
  const QualifiedName path_client_application_uri[]{QualifiedName{0, "ClientApplicationUri"}};
  EXPECT_TRUE(event.resolve_field(path_client_application_uri).empty())
    << "ClientApplicationUri unexpectedly resolved while unset";
}

TEST(GeneratedEventTypeTests, AuditEventPayload_OptionalFields_Set)
{
  AuditEventPayload event;
  auto sentinel_client_application_uri = String{"test"};
  event.clientApplicationUri = sentinel_client_application_uri;
  const QualifiedName path_client_application_uri[]{QualifiedName{0, "ClientApplicationUri"}};
  auto result_client_application_uri = event.resolve_field(path_client_application_uri);
  ASSERT_FALSE(result_client_application_uri.empty())
    << "ClientApplicationUri resolved to empty after being set";
  EXPECT_EQ(result_client_application_uri.as<String>(), sentinel_client_application_uri);
}

TEST(GeneratedEventTypeTests, AuditEventPayload_Clone)
{
  AuditEventPayload event;
  event.severity = 511;
  auto sentinel_clone_action_time_stamp = Variant{42};
  event.actionTimeStamp = sentinel_clone_action_time_stamp;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AuditEventPayload_ParentDelegation)
{
  AuditEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditUpdateMethodEventPayload_Construction)
{
  AuditUpdateMethodEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditUpdateMethodEventType});
}

TEST(GeneratedEventTypeTests, AuditUpdateMethodEventPayload_ResolveOwnFields)
{
  AuditUpdateMethodEventPayload event;
  auto sentinel_method_id = NodeId{1, 42};
  event.methodId = sentinel_method_id;
  const QualifiedName path_method_id[]{QualifiedName{0, "MethodId"}};
  auto result_method_id = event.resolve_field(path_method_id);
  ASSERT_FALSE(result_method_id.empty()) << "MethodId resolved to empty";
  EXPECT_EQ(result_method_id.as<NodeId>(), sentinel_method_id);
  auto sentinel_input_arguments = Variant{42};
  event.inputArguments = sentinel_input_arguments;
  const QualifiedName path_input_arguments[]{QualifiedName{0, "InputArguments"}};
  auto result_input_arguments = event.resolve_field(path_input_arguments);
  ASSERT_FALSE(result_input_arguments.empty()) << "InputArguments resolved to empty";
}

TEST(GeneratedEventTypeTests, AuditUpdateMethodEventPayload_OptionalFields_Unset)
{
  AuditUpdateMethodEventPayload event;
  const QualifiedName path_status_code_id[]{QualifiedName{0, "StatusCodeId"}};
  EXPECT_TRUE(event.resolve_field(path_status_code_id).empty())
    << "StatusCodeId unexpectedly resolved while unset";
  const QualifiedName path_output_arguments[]{QualifiedName{0, "OutputArguments"}};
  EXPECT_TRUE(event.resolve_field(path_output_arguments).empty())
    << "OutputArguments unexpectedly resolved while unset";
}

TEST(GeneratedEventTypeTests, AuditUpdateMethodEventPayload_OptionalFields_Set)
{
  AuditUpdateMethodEventPayload event;
  auto sentinel_status_code_id = StatusCode{};
  event.statusCodeId = sentinel_status_code_id;
  const QualifiedName path_status_code_id[]{QualifiedName{0, "StatusCodeId"}};
  auto result_status_code_id = event.resolve_field(path_status_code_id);
  ASSERT_FALSE(result_status_code_id.empty()) << "StatusCodeId resolved to empty after being set";
  EXPECT_EQ(result_status_code_id.as<StatusCode>(), sentinel_status_code_id);
  auto sentinel_output_arguments = Variant{42};
  event.outputArguments = sentinel_output_arguments;
  const QualifiedName path_output_arguments[]{QualifiedName{0, "OutputArguments"}};
  auto result_output_arguments = event.resolve_field(path_output_arguments);
  ASSERT_FALSE(result_output_arguments.empty()) << "OutputArguments resolved to empty after being set";
}

TEST(GeneratedEventTypeTests, AuditUpdateMethodEventPayload_Clone)
{
  AuditUpdateMethodEventPayload event;
  event.severity = 511;
  auto sentinel_clone_method_id = NodeId{1, 42};
  event.methodId = sentinel_clone_method_id;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditUpdateMethodEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->methodId, sentinel_clone_method_id);
}

TEST(GeneratedEventTypeTests, AuditUpdateMethodEventPayload_ParentDelegation)
{
  AuditUpdateMethodEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditConditionEventPayload_Construction)
{
  AuditConditionEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditConditionEventType});
}

TEST(GeneratedEventTypeTests, AuditConditionEventPayload_Clone)
{
  AuditConditionEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditConditionEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AuditConditionEventPayload_ParentDelegation)
{
  AuditConditionEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditConditionShelvingEventPayload_Construction)
{
  AuditConditionShelvingEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditConditionShelvingEventType});
}

TEST(GeneratedEventTypeTests, AuditConditionShelvingEventPayload_OptionalFields_Unset)
{
  AuditConditionShelvingEventPayload event;
  const QualifiedName path_shelving_time[]{QualifiedName{0, "ShelvingTime"}};
  EXPECT_TRUE(event.resolve_field(path_shelving_time).empty())
    << "ShelvingTime unexpectedly resolved while unset";
}

TEST(GeneratedEventTypeTests, AuditConditionShelvingEventPayload_OptionalFields_Set)
{
  AuditConditionShelvingEventPayload event;
  auto sentinel_shelving_time = Variant{42};
  event.shelvingTime = sentinel_shelving_time;
  const QualifiedName path_shelving_time[]{QualifiedName{0, "ShelvingTime"}};
  auto result_shelving_time = event.resolve_field(path_shelving_time);
  ASSERT_FALSE(result_shelving_time.empty()) << "ShelvingTime resolved to empty after being set";
}

TEST(GeneratedEventTypeTests, AuditConditionShelvingEventPayload_Clone)
{
  AuditConditionShelvingEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditConditionShelvingEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AuditConditionShelvingEventPayload_ParentDelegation)
{
  AuditConditionShelvingEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, ProgressEventPayload_Construction)
{
  ProgressEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::ProgressEventType});
}

TEST(GeneratedEventTypeTests, ProgressEventPayload_ResolveOwnFields)
{
  ProgressEventPayload event;
  auto sentinel_context = Variant{42};
  event.context = sentinel_context;
  const QualifiedName path_context[]{QualifiedName{0, "Context"}};
  auto result_context = event.resolve_field(path_context);
  ASSERT_FALSE(result_context.empty()) << "Context resolved to empty";
  auto sentinel_progress = 100;
  event.progress = sentinel_progress;
  const QualifiedName path_progress[]{QualifiedName{0, "Progress"}};
  auto result_progress = event.resolve_field(path_progress);
  ASSERT_FALSE(result_progress.empty()) << "Progress resolved to empty";
  EXPECT_EQ(result_progress.as<uint16_t>(), sentinel_progress);
}

TEST(GeneratedEventTypeTests, ProgressEventPayload_Clone)
{
  ProgressEventPayload event;
  event.severity = 511;
  auto sentinel_clone_context = Variant{42};
  event.context = sentinel_clone_context;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<ProgressEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, ProgressEventPayload_ParentDelegation)
{
  ProgressEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, SystemEventPayload_Construction)
{
  SystemEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::SystemEventType});
}

TEST(GeneratedEventTypeTests, SystemEventPayload_Clone)
{
  SystemEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<SystemEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, SystemEventPayload_ParentDelegation)
{
  SystemEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, SystemStatusChangeEventPayload_Construction)
{
  SystemStatusChangeEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::SystemStatusChangeEventType});
}

TEST(GeneratedEventTypeTests, SystemStatusChangeEventPayload_ResolveOwnFields)
{
  SystemStatusChangeEventPayload event;
  auto sentinel_system_state = Variant{42};
  event.systemState = sentinel_system_state;
  const QualifiedName path_system_state[]{QualifiedName{0, "SystemState"}};
  auto result_system_state = event.resolve_field(path_system_state);
  ASSERT_FALSE(result_system_state.empty()) << "SystemState resolved to empty";
}

TEST(GeneratedEventTypeTests, SystemStatusChangeEventPayload_Clone)
{
  SystemStatusChangeEventPayload event;
  event.severity = 511;
  auto sentinel_clone_system_state = Variant{42};
  event.systemState = sentinel_clone_system_state;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<SystemStatusChangeEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, SystemStatusChangeEventPayload_ParentDelegation)
{
  SystemStatusChangeEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, SystemOffNormalAlarmPayload_Construction)
{
  SystemOffNormalAlarmPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::SystemOffNormalAlarmType});
}

TEST(GeneratedEventTypeTests, SystemOffNormalAlarmPayload_Clone)
{
  SystemOffNormalAlarmPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<SystemOffNormalAlarmPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, SystemOffNormalAlarmPayload_ParentDelegation)
{
  SystemOffNormalAlarmPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditUpdateStateEventPayload_Construction)
{
  AuditUpdateStateEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditUpdateStateEventType});
}

TEST(GeneratedEventTypeTests, AuditUpdateStateEventPayload_ResolveOwnFields)
{
  AuditUpdateStateEventPayload event;
  auto sentinel_old_state_id = Variant{42};
  event.oldStateId = sentinel_old_state_id;
  const QualifiedName path_old_state_id[]{QualifiedName{0, "OldStateId"}};
  auto result_old_state_id = event.resolve_field(path_old_state_id);
  ASSERT_FALSE(result_old_state_id.empty()) << "OldStateId resolved to empty";
  auto sentinel_new_state_id = Variant{42};
  event.newStateId = sentinel_new_state_id;
  const QualifiedName path_new_state_id[]{QualifiedName{0, "NewStateId"}};
  auto result_new_state_id = event.resolve_field(path_new_state_id);
  ASSERT_FALSE(result_new_state_id.empty()) << "NewStateId resolved to empty";
}

TEST(GeneratedEventTypeTests, AuditUpdateStateEventPayload_Clone)
{
  AuditUpdateStateEventPayload event;
  event.severity = 511;
  auto sentinel_clone_old_state_id = Variant{42};
  event.oldStateId = sentinel_clone_old_state_id;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditUpdateStateEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AuditUpdateStateEventPayload_ParentDelegation)
{
  AuditUpdateStateEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditProgramTransitionEventPayload_Construction)
{
  AuditProgramTransitionEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditProgramTransitionEventType});
}

TEST(GeneratedEventTypeTests, AuditProgramTransitionEventPayload_ResolveOwnFields)
{
  AuditProgramTransitionEventPayload event;
  auto sentinel_transition_number = 12345;
  event.transitionNumber = sentinel_transition_number;
  const QualifiedName path_transition_number[]{QualifiedName{0, "TransitionNumber"}};
  auto result_transition_number = event.resolve_field(path_transition_number);
  ASSERT_FALSE(result_transition_number.empty()) << "TransitionNumber resolved to empty";
  EXPECT_EQ(result_transition_number.as<uint32_t>(), sentinel_transition_number);
}

TEST(GeneratedEventTypeTests, AuditProgramTransitionEventPayload_Clone)
{
  AuditProgramTransitionEventPayload event;
  event.severity = 511;
  auto sentinel_clone_transition_number = 12345;
  event.transitionNumber = sentinel_clone_transition_number;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditProgramTransitionEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->transitionNumber, sentinel_clone_transition_number);
}

TEST(GeneratedEventTypeTests, AuditProgramTransitionEventPayload_ParentDelegation)
{
  AuditProgramTransitionEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, TrustListUpdatedAuditEventPayload_Construction)
{
  TrustListUpdatedAuditEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::TrustListUpdatedAuditEventType});
}

TEST(GeneratedEventTypeTests, TrustListUpdatedAuditEventPayload_ResolveOwnFields)
{
  TrustListUpdatedAuditEventPayload event;
  auto sentinel_trust_list_id = NodeId{1, 42};
  event.trustListId = sentinel_trust_list_id;
  const QualifiedName path_trust_list_id[]{QualifiedName{0, "TrustListId"}};
  auto result_trust_list_id = event.resolve_field(path_trust_list_id);
  ASSERT_FALSE(result_trust_list_id.empty()) << "TrustListId resolved to empty";
  EXPECT_EQ(result_trust_list_id.as<NodeId>(), sentinel_trust_list_id);
}

TEST(GeneratedEventTypeTests, TrustListUpdatedAuditEventPayload_Clone)
{
  TrustListUpdatedAuditEventPayload event;
  event.severity = 511;
  auto sentinel_clone_trust_list_id = NodeId{1, 42};
  event.trustListId = sentinel_clone_trust_list_id;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<TrustListUpdatedAuditEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->trustListId, sentinel_clone_trust_list_id);
}

TEST(GeneratedEventTypeTests, TrustListUpdatedAuditEventPayload_ParentDelegation)
{
  TrustListUpdatedAuditEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, CertificateUpdatedAuditEventPayload_Construction)
{
  CertificateUpdatedAuditEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::CertificateUpdatedAuditEventType});
}

TEST(GeneratedEventTypeTests, CertificateUpdatedAuditEventPayload_ResolveOwnFields)
{
  CertificateUpdatedAuditEventPayload event;
  auto sentinel_certificate_group = NodeId{1, 42};
  event.certificateGroup = sentinel_certificate_group;
  const QualifiedName path_certificate_group[]{QualifiedName{0, "CertificateGroup"}};
  auto result_certificate_group = event.resolve_field(path_certificate_group);
  ASSERT_FALSE(result_certificate_group.empty()) << "CertificateGroup resolved to empty";
  EXPECT_EQ(result_certificate_group.as<NodeId>(), sentinel_certificate_group);
  auto sentinel_certificate_type = NodeId{1, 42};
  event.certificateType = sentinel_certificate_type;
  const QualifiedName path_certificate_type[]{QualifiedName{0, "CertificateType"}};
  auto result_certificate_type = event.resolve_field(path_certificate_type);
  ASSERT_FALSE(result_certificate_type.empty()) << "CertificateType resolved to empty";
  EXPECT_EQ(result_certificate_type.as<NodeId>(), sentinel_certificate_type);
}

TEST(GeneratedEventTypeTests, CertificateUpdatedAuditEventPayload_Clone)
{
  CertificateUpdatedAuditEventPayload event;
  event.severity = 511;
  auto sentinel_clone_certificate_group = NodeId{1, 42};
  event.certificateGroup = sentinel_clone_certificate_group;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<CertificateUpdatedAuditEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->certificateGroup, sentinel_clone_certificate_group);
}

TEST(GeneratedEventTypeTests, CertificateUpdatedAuditEventPayload_ParentDelegation)
{
  CertificateUpdatedAuditEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, CertificateExpirationAlarmPayload_Construction)
{
  CertificateExpirationAlarmPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::CertificateExpirationAlarmType});
}

TEST(GeneratedEventTypeTests, CertificateExpirationAlarmPayload_ResolveOwnFields)
{
  CertificateExpirationAlarmPayload event;
  auto sentinel_expiration_date = DateTime::now();
  event.expirationDate = sentinel_expiration_date;
  const QualifiedName path_expiration_date[]{QualifiedName{0, "ExpirationDate"}};
  auto result_expiration_date = event.resolve_field(path_expiration_date);
  ASSERT_FALSE(result_expiration_date.empty()) << "ExpirationDate resolved to empty";
  EXPECT_EQ(result_expiration_date.as<DateTime>(), sentinel_expiration_date);
  auto sentinel_certificate_type = NodeId{1, 42};
  event.certificateType = sentinel_certificate_type;
  const QualifiedName path_certificate_type[]{QualifiedName{0, "CertificateType"}};
  auto result_certificate_type = event.resolve_field(path_certificate_type);
  ASSERT_FALSE(result_certificate_type.empty()) << "CertificateType resolved to empty";
  EXPECT_EQ(result_certificate_type.as<NodeId>(), sentinel_certificate_type);
  auto sentinel_certificate = ByteString{std::vector<std::byte>{std::byte{1}}};
  event.certificate = sentinel_certificate;
  const QualifiedName path_certificate[]{QualifiedName{0, "Certificate"}};
  auto result_certificate = event.resolve_field(path_certificate);
  ASSERT_FALSE(result_certificate.empty()) << "Certificate resolved to empty";
  EXPECT_EQ(result_certificate.as<ByteString>(), sentinel_certificate);
}

TEST(GeneratedEventTypeTests, CertificateExpirationAlarmPayload_OptionalFields_Unset)
{
  CertificateExpirationAlarmPayload event;
  const QualifiedName path_expiration_limit[]{QualifiedName{0, "ExpirationLimit"}};
  EXPECT_TRUE(event.resolve_field(path_expiration_limit).empty())
    << "ExpirationLimit unexpectedly resolved while unset";
}

TEST(GeneratedEventTypeTests, CertificateExpirationAlarmPayload_OptionalFields_Set)
{
  CertificateExpirationAlarmPayload event;
  auto sentinel_expiration_limit = Variant{42};
  event.expirationLimit = sentinel_expiration_limit;
  const QualifiedName path_expiration_limit[]{QualifiedName{0, "ExpirationLimit"}};
  auto result_expiration_limit = event.resolve_field(path_expiration_limit);
  ASSERT_FALSE(result_expiration_limit.empty()) << "ExpirationLimit resolved to empty after being set";
}

TEST(GeneratedEventTypeTests, CertificateExpirationAlarmPayload_Clone)
{
  CertificateExpirationAlarmPayload event;
  event.severity = 511;
  auto sentinel_clone_expiration_date = DateTime::now();
  event.expirationDate = sentinel_clone_expiration_date;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<CertificateExpirationAlarmPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->expirationDate, sentinel_clone_expiration_date);
}

TEST(GeneratedEventTypeTests, CertificateExpirationAlarmPayload_ParentDelegation)
{
  CertificateExpirationAlarmPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditConditionResetEventPayload_Construction)
{
  AuditConditionResetEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditConditionResetEventType});
}

TEST(GeneratedEventTypeTests, AuditConditionResetEventPayload_Clone)
{
  AuditConditionResetEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditConditionResetEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AuditConditionResetEventPayload_ParentDelegation)
{
  AuditConditionResetEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, PubSubStatusEventPayload_Construction)
{
  PubSubStatusEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::PubSubStatusEventType});
}

TEST(GeneratedEventTypeTests, PubSubStatusEventPayload_ResolveOwnFields)
{
  PubSubStatusEventPayload event;
  auto sentinel_connection_id = NodeId{1, 42};
  event.connectionId = sentinel_connection_id;
  const QualifiedName path_connection_id[]{QualifiedName{0, "ConnectionId"}};
  auto result_connection_id = event.resolve_field(path_connection_id);
  ASSERT_FALSE(result_connection_id.empty()) << "ConnectionId resolved to empty";
  EXPECT_EQ(result_connection_id.as<NodeId>(), sentinel_connection_id);
  auto sentinel_group_id = NodeId{1, 42};
  event.groupId = sentinel_group_id;
  const QualifiedName path_group_id[]{QualifiedName{0, "GroupId"}};
  auto result_group_id = event.resolve_field(path_group_id);
  ASSERT_FALSE(result_group_id.empty()) << "GroupId resolved to empty";
  EXPECT_EQ(result_group_id.as<NodeId>(), sentinel_group_id);
  auto sentinel_state = Variant{42};
  event.state = sentinel_state;
  const QualifiedName path_state[]{QualifiedName{0, "State"}};
  auto result_state = event.resolve_field(path_state);
  ASSERT_FALSE(result_state.empty()) << "State resolved to empty";
}

TEST(GeneratedEventTypeTests, PubSubStatusEventPayload_Clone)
{
  PubSubStatusEventPayload event;
  event.severity = 511;
  auto sentinel_clone_connection_id = NodeId{1, 42};
  event.connectionId = sentinel_clone_connection_id;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<PubSubStatusEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->connectionId, sentinel_clone_connection_id);
}

TEST(GeneratedEventTypeTests, PubSubStatusEventPayload_ParentDelegation)
{
  PubSubStatusEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, ConfigurationUpdatedAuditEventPayload_Construction)
{
  ConfigurationUpdatedAuditEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::ConfigurationUpdatedAuditEventType});
}

TEST(GeneratedEventTypeTests, ConfigurationUpdatedAuditEventPayload_ResolveOwnFields)
{
  ConfigurationUpdatedAuditEventPayload event;
  auto sentinel_old_version = Variant{42};
  event.oldVersion = sentinel_old_version;
  const QualifiedName path_old_version[]{QualifiedName{0, "OldVersion"}};
  auto result_old_version = event.resolve_field(path_old_version);
  ASSERT_FALSE(result_old_version.empty()) << "OldVersion resolved to empty";
  auto sentinel_new_version = Variant{42};
  event.newVersion = sentinel_new_version;
  const QualifiedName path_new_version[]{QualifiedName{0, "NewVersion"}};
  auto result_new_version = event.resolve_field(path_new_version);
  ASSERT_FALSE(result_new_version.empty()) << "NewVersion resolved to empty";
}

TEST(GeneratedEventTypeTests, ConfigurationUpdatedAuditEventPayload_Clone)
{
  ConfigurationUpdatedAuditEventPayload event;
  event.severity = 511;
  auto sentinel_clone_old_version = Variant{42};
  event.oldVersion = sentinel_clone_old_version;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<ConfigurationUpdatedAuditEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, ConfigurationUpdatedAuditEventPayload_ParentDelegation)
{
  ConfigurationUpdatedAuditEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, PubSubTransportLimitsExceedEventPayload_Construction)
{
  PubSubTransportLimitsExceedEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::PubSubTransportLimitsExceedEventType});
}

TEST(GeneratedEventTypeTests, PubSubTransportLimitsExceedEventPayload_ResolveOwnFields)
{
  PubSubTransportLimitsExceedEventPayload event;
  auto sentinel_actual = 12345;
  event.actual = sentinel_actual;
  const QualifiedName path_actual[]{QualifiedName{0, "Actual"}};
  auto result_actual = event.resolve_field(path_actual);
  ASSERT_FALSE(result_actual.empty()) << "Actual resolved to empty";
  EXPECT_EQ(result_actual.as<uint32_t>(), sentinel_actual);
  auto sentinel_maximum = 12345;
  event.maximum = sentinel_maximum;
  const QualifiedName path_maximum[]{QualifiedName{0, "Maximum"}};
  auto result_maximum = event.resolve_field(path_maximum);
  ASSERT_FALSE(result_maximum.empty()) << "Maximum resolved to empty";
  EXPECT_EQ(result_maximum.as<uint32_t>(), sentinel_maximum);
}

TEST(GeneratedEventTypeTests, PubSubTransportLimitsExceedEventPayload_Clone)
{
  PubSubTransportLimitsExceedEventPayload event;
  event.severity = 511;
  auto sentinel_clone_actual = 12345;
  event.actual = sentinel_clone_actual;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<PubSubTransportLimitsExceedEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->actual, sentinel_clone_actual);
}

TEST(GeneratedEventTypeTests, PubSubTransportLimitsExceedEventPayload_ParentDelegation)
{
  PubSubTransportLimitsExceedEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, PubSubCommunicationFailureEventPayload_Construction)
{
  PubSubCommunicationFailureEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::PubSubCommunicationFailureEventType});
}

TEST(GeneratedEventTypeTests, PubSubCommunicationFailureEventPayload_ResolveOwnFields)
{
  PubSubCommunicationFailureEventPayload event;
  auto sentinel_error = StatusCode{};
  event.error = sentinel_error;
  const QualifiedName path_error[]{QualifiedName{0, "Error"}};
  auto result_error = event.resolve_field(path_error);
  ASSERT_FALSE(result_error.empty()) << "Error resolved to empty";
  EXPECT_EQ(result_error.as<StatusCode>(), sentinel_error);
}

TEST(GeneratedEventTypeTests, PubSubCommunicationFailureEventPayload_Clone)
{
  PubSubCommunicationFailureEventPayload event;
  event.severity = 511;
  auto sentinel_clone_error = StatusCode{};
  event.error = sentinel_clone_error;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<PubSubCommunicationFailureEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->error, sentinel_clone_error);
}

TEST(GeneratedEventTypeTests, PubSubCommunicationFailureEventPayload_ParentDelegation)
{
  PubSubCommunicationFailureEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, DiscrepancyAlarmPayload_Construction)
{
  DiscrepancyAlarmPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::DiscrepancyAlarmType});
}

TEST(GeneratedEventTypeTests, DiscrepancyAlarmPayload_ResolveOwnFields)
{
  DiscrepancyAlarmPayload event;
  auto sentinel_target_value_node = NodeId{1, 42};
  event.targetValueNode = sentinel_target_value_node;
  const QualifiedName path_target_value_node[]{QualifiedName{0, "TargetValueNode"}};
  auto result_target_value_node = event.resolve_field(path_target_value_node);
  ASSERT_FALSE(result_target_value_node.empty()) << "TargetValueNode resolved to empty";
  EXPECT_EQ(result_target_value_node.as<NodeId>(), sentinel_target_value_node);
  auto sentinel_expected_time = Variant{42};
  event.expectedTime = sentinel_expected_time;
  const QualifiedName path_expected_time[]{QualifiedName{0, "ExpectedTime"}};
  auto result_expected_time = event.resolve_field(path_expected_time);
  ASSERT_FALSE(result_expected_time.empty()) << "ExpectedTime resolved to empty";
}

TEST(GeneratedEventTypeTests, DiscrepancyAlarmPayload_OptionalFields_Unset)
{
  DiscrepancyAlarmPayload event;
  const QualifiedName path_tolerance[]{QualifiedName{0, "Tolerance"}};
  EXPECT_TRUE(event.resolve_field(path_tolerance).empty()) << "Tolerance unexpectedly resolved while unset";
}

TEST(GeneratedEventTypeTests, DiscrepancyAlarmPayload_OptionalFields_Set)
{
  DiscrepancyAlarmPayload event;
  auto sentinel_tolerance = 3.14;
  event.tolerance = sentinel_tolerance;
  const QualifiedName path_tolerance[]{QualifiedName{0, "Tolerance"}};
  auto result_tolerance = event.resolve_field(path_tolerance);
  ASSERT_FALSE(result_tolerance.empty()) << "Tolerance resolved to empty after being set";
  EXPECT_EQ(result_tolerance.as<double>(), sentinel_tolerance);
}

TEST(GeneratedEventTypeTests, DiscrepancyAlarmPayload_Clone)
{
  DiscrepancyAlarmPayload event;
  event.severity = 511;
  auto sentinel_clone_target_value_node = NodeId{1, 42};
  event.targetValueNode = sentinel_clone_target_value_node;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<DiscrepancyAlarmPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->targetValueNode, sentinel_clone_target_value_node);
}

TEST(GeneratedEventTypeTests, DiscrepancyAlarmPayload_ParentDelegation)
{
  DiscrepancyAlarmPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditConditionSuppressionEventPayload_Construction)
{
  AuditConditionSuppressionEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditConditionSuppressionEventType});
}

TEST(GeneratedEventTypeTests, AuditConditionSuppressionEventPayload_Clone)
{
  AuditConditionSuppressionEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditConditionSuppressionEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AuditConditionSuppressionEventPayload_ParentDelegation)
{
  AuditConditionSuppressionEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditConditionSilenceEventPayload_Construction)
{
  AuditConditionSilenceEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditConditionSilenceEventType});
}

TEST(GeneratedEventTypeTests, AuditConditionSilenceEventPayload_Clone)
{
  AuditConditionSilenceEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditConditionSilenceEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AuditConditionSilenceEventPayload_ParentDelegation)
{
  AuditConditionSilenceEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditConditionOutOfServiceEventPayload_Construction)
{
  AuditConditionOutOfServiceEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditConditionOutOfServiceEventType});
}

TEST(GeneratedEventTypeTests, AuditConditionOutOfServiceEventPayload_Clone)
{
  AuditConditionOutOfServiceEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditConditionOutOfServiceEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AuditConditionOutOfServiceEventPayload_ParentDelegation)
{
  AuditConditionOutOfServiceEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, RoleMappingRuleChangedAuditEventPayload_Construction)
{
  RoleMappingRuleChangedAuditEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::RoleMappingRuleChangedAuditEventType});
}

TEST(GeneratedEventTypeTests, RoleMappingRuleChangedAuditEventPayload_Clone)
{
  RoleMappingRuleChangedAuditEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<RoleMappingRuleChangedAuditEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, RoleMappingRuleChangedAuditEventPayload_ParentDelegation)
{
  RoleMappingRuleChangedAuditEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, KeyCredentialAuditEventPayload_Construction)
{
  KeyCredentialAuditEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::KeyCredentialAuditEventType});
}

TEST(GeneratedEventTypeTests, KeyCredentialAuditEventPayload_ResolveOwnFields)
{
  KeyCredentialAuditEventPayload event;
  auto sentinel_resource_uri = String{"test"};
  event.resourceUri = sentinel_resource_uri;
  const QualifiedName path_resource_uri[]{QualifiedName{0, "ResourceUri"}};
  auto result_resource_uri = event.resolve_field(path_resource_uri);
  ASSERT_FALSE(result_resource_uri.empty()) << "ResourceUri resolved to empty";
  EXPECT_EQ(result_resource_uri.as<String>(), sentinel_resource_uri);
}

TEST(GeneratedEventTypeTests, KeyCredentialAuditEventPayload_Clone)
{
  KeyCredentialAuditEventPayload event;
  event.severity = 511;
  auto sentinel_clone_resource_uri = String{"test"};
  event.resourceUri = sentinel_clone_resource_uri;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<KeyCredentialAuditEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->resourceUri, sentinel_clone_resource_uri);
}

TEST(GeneratedEventTypeTests, KeyCredentialAuditEventPayload_ParentDelegation)
{
  KeyCredentialAuditEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, KeyCredentialUpdatedAuditEventPayload_Construction)
{
  KeyCredentialUpdatedAuditEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::KeyCredentialUpdatedAuditEventType});
}

TEST(GeneratedEventTypeTests, KeyCredentialUpdatedAuditEventPayload_Clone)
{
  KeyCredentialUpdatedAuditEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<KeyCredentialUpdatedAuditEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, KeyCredentialUpdatedAuditEventPayload_ParentDelegation)
{
  KeyCredentialUpdatedAuditEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, KeyCredentialDeletedAuditEventPayload_Construction)
{
  KeyCredentialDeletedAuditEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::KeyCredentialDeletedAuditEventType});
}

TEST(GeneratedEventTypeTests, KeyCredentialDeletedAuditEventPayload_Clone)
{
  KeyCredentialDeletedAuditEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<KeyCredentialDeletedAuditEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, KeyCredentialDeletedAuditEventPayload_ParentDelegation)
{
  KeyCredentialDeletedAuditEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, InstrumentDiagnosticAlarmPayload_Construction)
{
  InstrumentDiagnosticAlarmPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::InstrumentDiagnosticAlarmType});
}

TEST(GeneratedEventTypeTests, InstrumentDiagnosticAlarmPayload_Clone)
{
  InstrumentDiagnosticAlarmPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<InstrumentDiagnosticAlarmPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, InstrumentDiagnosticAlarmPayload_ParentDelegation)
{
  InstrumentDiagnosticAlarmPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, SystemDiagnosticAlarmPayload_Construction)
{
  SystemDiagnosticAlarmPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::SystemDiagnosticAlarmType});
}

TEST(GeneratedEventTypeTests, SystemDiagnosticAlarmPayload_Clone)
{
  SystemDiagnosticAlarmPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<SystemDiagnosticAlarmPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, SystemDiagnosticAlarmPayload_ParentDelegation)
{
  SystemDiagnosticAlarmPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditUpdateEventPayload_Construction)
{
  AuditUpdateEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditUpdateEventType});
}

TEST(GeneratedEventTypeTests, AuditUpdateEventPayload_Clone)
{
  AuditUpdateEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditUpdateEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AuditUpdateEventPayload_ParentDelegation)
{
  AuditUpdateEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditHistoryUpdateEventPayload_Construction)
{
  AuditHistoryUpdateEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditHistoryUpdateEventType});
}

TEST(GeneratedEventTypeTests, AuditHistoryUpdateEventPayload_ResolveOwnFields)
{
  AuditHistoryUpdateEventPayload event;
  auto sentinel_parameter_data_type_id = NodeId{1, 42};
  event.parameterDataTypeId = sentinel_parameter_data_type_id;
  const QualifiedName path_parameter_data_type_id[]{QualifiedName{0, "ParameterDataTypeId"}};
  auto result_parameter_data_type_id = event.resolve_field(path_parameter_data_type_id);
  ASSERT_FALSE(result_parameter_data_type_id.empty()) << "ParameterDataTypeId resolved to empty";
  EXPECT_EQ(result_parameter_data_type_id.as<NodeId>(), sentinel_parameter_data_type_id);
}

TEST(GeneratedEventTypeTests, AuditHistoryUpdateEventPayload_Clone)
{
  AuditHistoryUpdateEventPayload event;
  event.severity = 511;
  auto sentinel_clone_parameter_data_type_id = NodeId{1, 42};
  event.parameterDataTypeId = sentinel_clone_parameter_data_type_id;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditHistoryUpdateEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->parameterDataTypeId, sentinel_clone_parameter_data_type_id);
}

TEST(GeneratedEventTypeTests, AuditHistoryUpdateEventPayload_ParentDelegation)
{
  AuditHistoryUpdateEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditHistoryAnnotationUpdateEventPayload_Construction)
{
  AuditHistoryAnnotationUpdateEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditHistoryAnnotationUpdateEventType});
}

TEST(GeneratedEventTypeTests, AuditHistoryAnnotationUpdateEventPayload_ResolveOwnFields)
{
  AuditHistoryAnnotationUpdateEventPayload event;
  auto sentinel_perform_insert_replace = Variant{42};
  event.performInsertReplace = sentinel_perform_insert_replace;
  const QualifiedName path_perform_insert_replace[]{QualifiedName{0, "PerformInsertReplace"}};
  auto result_perform_insert_replace = event.resolve_field(path_perform_insert_replace);
  ASSERT_FALSE(result_perform_insert_replace.empty()) << "PerformInsertReplace resolved to empty";
  auto sentinel_new_values = Variant{42};
  event.newValues = sentinel_new_values;
  const QualifiedName path_new_values[]{QualifiedName{0, "NewValues"}};
  auto result_new_values = event.resolve_field(path_new_values);
  ASSERT_FALSE(result_new_values.empty()) << "NewValues resolved to empty";
  auto sentinel_old_values = Variant{42};
  event.oldValues = sentinel_old_values;
  const QualifiedName path_old_values[]{QualifiedName{0, "OldValues"}};
  auto result_old_values = event.resolve_field(path_old_values);
  ASSERT_FALSE(result_old_values.empty()) << "OldValues resolved to empty";
}

TEST(GeneratedEventTypeTests, AuditHistoryAnnotationUpdateEventPayload_Clone)
{
  AuditHistoryAnnotationUpdateEventPayload event;
  event.severity = 511;
  auto sentinel_clone_perform_insert_replace = Variant{42};
  event.performInsertReplace = sentinel_clone_perform_insert_replace;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditHistoryAnnotationUpdateEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AuditHistoryAnnotationUpdateEventPayload_ParentDelegation)
{
  AuditHistoryAnnotationUpdateEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, TrustListOutOfDateAlarmPayload_Construction)
{
  TrustListOutOfDateAlarmPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::TrustListOutOfDateAlarmType});
}

TEST(GeneratedEventTypeTests, TrustListOutOfDateAlarmPayload_ResolveOwnFields)
{
  TrustListOutOfDateAlarmPayload event;
  auto sentinel_trust_list_id = NodeId{1, 42};
  event.trustListId = sentinel_trust_list_id;
  const QualifiedName path_trust_list_id[]{QualifiedName{0, "TrustListId"}};
  auto result_trust_list_id = event.resolve_field(path_trust_list_id);
  ASSERT_FALSE(result_trust_list_id.empty()) << "TrustListId resolved to empty";
  EXPECT_EQ(result_trust_list_id.as<NodeId>(), sentinel_trust_list_id);
  auto sentinel_last_update_time = Variant{42};
  event.lastUpdateTime = sentinel_last_update_time;
  const QualifiedName path_last_update_time[]{QualifiedName{0, "LastUpdateTime"}};
  auto result_last_update_time = event.resolve_field(path_last_update_time);
  ASSERT_FALSE(result_last_update_time.empty()) << "LastUpdateTime resolved to empty";
  auto sentinel_update_frequency = Variant{42};
  event.updateFrequency = sentinel_update_frequency;
  const QualifiedName path_update_frequency[]{QualifiedName{0, "UpdateFrequency"}};
  auto result_update_frequency = event.resolve_field(path_update_frequency);
  ASSERT_FALSE(result_update_frequency.empty()) << "UpdateFrequency resolved to empty";
}

TEST(GeneratedEventTypeTests, TrustListOutOfDateAlarmPayload_Clone)
{
  TrustListOutOfDateAlarmPayload event;
  event.severity = 511;
  auto sentinel_clone_trust_list_id = NodeId{1, 42};
  event.trustListId = sentinel_clone_trust_list_id;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<TrustListOutOfDateAlarmPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->trustListId, sentinel_clone_trust_list_id);
}

TEST(GeneratedEventTypeTests, TrustListOutOfDateAlarmPayload_ParentDelegation)
{
  TrustListOutOfDateAlarmPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, BaseLogEventPayload_Construction)
{
  BaseLogEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::BaseLogEventType});
}

TEST(GeneratedEventTypeTests, BaseLogEventPayload_ResolveOwnFields)
{
  BaseLogEventPayload event;
  auto sentinel_condition_class_id = NodeId{1, 42};
  event.conditionClassId = sentinel_condition_class_id;
  const QualifiedName path_condition_class_id[]{QualifiedName{0, "ConditionClassId"}};
  auto result_condition_class_id = event.resolve_field(path_condition_class_id);
  ASSERT_FALSE(result_condition_class_id.empty()) << "ConditionClassId resolved to empty";
  EXPECT_EQ(result_condition_class_id.as<NodeId>(), sentinel_condition_class_id);
  auto sentinel_condition_class_name = LocalizedText{"en", "test"};
  event.conditionClassName = sentinel_condition_class_name;
  const QualifiedName path_condition_class_name[]{QualifiedName{0, "ConditionClassName"}};
  auto result_condition_class_name = event.resolve_field(path_condition_class_name);
  ASSERT_FALSE(result_condition_class_name.empty()) << "ConditionClassName resolved to empty";
  EXPECT_EQ(result_condition_class_name.as<LocalizedText>(), sentinel_condition_class_name);
}

TEST(GeneratedEventTypeTests, BaseLogEventPayload_OptionalFields_Unset)
{
  BaseLogEventPayload event;
  const QualifiedName path_error_code[]{QualifiedName{0, "ErrorCode"}};
  EXPECT_TRUE(event.resolve_field(path_error_code).empty()) << "ErrorCode unexpectedly resolved while unset";
  const QualifiedName path_error_code_node[]{QualifiedName{0, "ErrorCodeNode"}};
  EXPECT_TRUE(event.resolve_field(path_error_code_node).empty())
    << "ErrorCodeNode unexpectedly resolved while unset";
}

TEST(GeneratedEventTypeTests, BaseLogEventPayload_OptionalFields_Set)
{
  BaseLogEventPayload event;
  auto sentinel_error_code = StatusCode{};
  event.errorCode = sentinel_error_code;
  const QualifiedName path_error_code[]{QualifiedName{0, "ErrorCode"}};
  auto result_error_code = event.resolve_field(path_error_code);
  ASSERT_FALSE(result_error_code.empty()) << "ErrorCode resolved to empty after being set";
  EXPECT_EQ(result_error_code.as<StatusCode>(), sentinel_error_code);
  auto sentinel_error_code_node = NodeId{1, 42};
  event.errorCodeNode = sentinel_error_code_node;
  const QualifiedName path_error_code_node[]{QualifiedName{0, "ErrorCodeNode"}};
  auto result_error_code_node = event.resolve_field(path_error_code_node);
  ASSERT_FALSE(result_error_code_node.empty()) << "ErrorCodeNode resolved to empty after being set";
  EXPECT_EQ(result_error_code_node.as<NodeId>(), sentinel_error_code_node);
}

TEST(GeneratedEventTypeTests, BaseLogEventPayload_Clone)
{
  BaseLogEventPayload event;
  event.severity = 511;
  auto sentinel_clone_condition_class_id = NodeId{1, 42};
  event.conditionClassId = sentinel_clone_condition_class_id;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<BaseLogEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->conditionClassId, sentinel_clone_condition_class_id);
}

TEST(GeneratedEventTypeTests, BaseLogEventPayload_ParentDelegation)
{
  BaseLogEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, LogOverflowEventPayload_Construction)
{
  LogOverflowEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::LogOverflowEventType});
}

TEST(GeneratedEventTypeTests, LogOverflowEventPayload_Clone)
{
  LogOverflowEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<LogOverflowEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, LogOverflowEventPayload_ParentDelegation)
{
  LogOverflowEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditSecurityEventPayload_Construction)
{
  AuditSecurityEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditSecurityEventType});
}

TEST(GeneratedEventTypeTests, AuditSecurityEventPayload_OptionalFields_Unset)
{
  AuditSecurityEventPayload event;
  const QualifiedName path_status_code_id[]{QualifiedName{0, "StatusCodeId"}};
  EXPECT_TRUE(event.resolve_field(path_status_code_id).empty())
    << "StatusCodeId unexpectedly resolved while unset";
}

TEST(GeneratedEventTypeTests, AuditSecurityEventPayload_OptionalFields_Set)
{
  AuditSecurityEventPayload event;
  auto sentinel_status_code_id = StatusCode{};
  event.statusCodeId = sentinel_status_code_id;
  const QualifiedName path_status_code_id[]{QualifiedName{0, "StatusCodeId"}};
  auto result_status_code_id = event.resolve_field(path_status_code_id);
  ASSERT_FALSE(result_status_code_id.empty()) << "StatusCodeId resolved to empty after being set";
  EXPECT_EQ(result_status_code_id.as<StatusCode>(), sentinel_status_code_id);
}

TEST(GeneratedEventTypeTests, AuditSecurityEventPayload_Clone)
{
  AuditSecurityEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditSecurityEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AuditSecurityEventPayload_ParentDelegation)
{
  AuditSecurityEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditChannelEventPayload_Construction)
{
  AuditChannelEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditChannelEventType});
}

TEST(GeneratedEventTypeTests, AuditChannelEventPayload_ResolveOwnFields)
{
  AuditChannelEventPayload event;
  auto sentinel_secure_channel_id = String{"test"};
  event.secureChannelId = sentinel_secure_channel_id;
  const QualifiedName path_secure_channel_id[]{QualifiedName{0, "SecureChannelId"}};
  auto result_secure_channel_id = event.resolve_field(path_secure_channel_id);
  ASSERT_FALSE(result_secure_channel_id.empty()) << "SecureChannelId resolved to empty";
  EXPECT_EQ(result_secure_channel_id.as<String>(), sentinel_secure_channel_id);
}

TEST(GeneratedEventTypeTests, AuditChannelEventPayload_Clone)
{
  AuditChannelEventPayload event;
  event.severity = 511;
  auto sentinel_clone_secure_channel_id = String{"test"};
  event.secureChannelId = sentinel_clone_secure_channel_id;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditChannelEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->secureChannelId, sentinel_clone_secure_channel_id);
}

TEST(GeneratedEventTypeTests, AuditChannelEventPayload_ParentDelegation)
{
  AuditChannelEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditOpenSecureChannelEventPayload_Construction)
{
  AuditOpenSecureChannelEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditOpenSecureChannelEventType});
}

TEST(GeneratedEventTypeTests, AuditOpenSecureChannelEventPayload_ResolveOwnFields)
{
  AuditOpenSecureChannelEventPayload event;
  auto sentinel_client_certificate = ByteString{std::vector<std::byte>{std::byte{1}}};
  event.clientCertificate = sentinel_client_certificate;
  const QualifiedName path_client_certificate[]{QualifiedName{0, "ClientCertificate"}};
  auto result_client_certificate = event.resolve_field(path_client_certificate);
  ASSERT_FALSE(result_client_certificate.empty()) << "ClientCertificate resolved to empty";
  EXPECT_EQ(result_client_certificate.as<ByteString>(), sentinel_client_certificate);
  auto sentinel_client_certificate_thumbprint = String{"test"};
  event.clientCertificateThumbprint = sentinel_client_certificate_thumbprint;
  const QualifiedName path_client_certificate_thumbprint[]{QualifiedName{0, "ClientCertificateThumbprint"}};
  auto result_client_certificate_thumbprint = event.resolve_field(path_client_certificate_thumbprint);
  ASSERT_FALSE(result_client_certificate_thumbprint.empty())
    << "ClientCertificateThumbprint resolved to empty";
  EXPECT_EQ(result_client_certificate_thumbprint.as<String>(), sentinel_client_certificate_thumbprint);
  auto sentinel_request_type = Variant{42};
  event.requestType = sentinel_request_type;
  const QualifiedName path_request_type[]{QualifiedName{0, "RequestType"}};
  auto result_request_type = event.resolve_field(path_request_type);
  ASSERT_FALSE(result_request_type.empty()) << "RequestType resolved to empty";
  auto sentinel_security_policy_uri = String{"test"};
  event.securityPolicyUri = sentinel_security_policy_uri;
  const QualifiedName path_security_policy_uri[]{QualifiedName{0, "SecurityPolicyUri"}};
  auto result_security_policy_uri = event.resolve_field(path_security_policy_uri);
  ASSERT_FALSE(result_security_policy_uri.empty()) << "SecurityPolicyUri resolved to empty";
  EXPECT_EQ(result_security_policy_uri.as<String>(), sentinel_security_policy_uri);
  auto sentinel_security_mode = Variant{42};
  event.securityMode = sentinel_security_mode;
  const QualifiedName path_security_mode[]{QualifiedName{0, "SecurityMode"}};
  auto result_security_mode = event.resolve_field(path_security_mode);
  ASSERT_FALSE(result_security_mode.empty()) << "SecurityMode resolved to empty";
  auto sentinel_requested_lifetime = Variant{42};
  event.requestedLifetime = sentinel_requested_lifetime;
  const QualifiedName path_requested_lifetime[]{QualifiedName{0, "RequestedLifetime"}};
  auto result_requested_lifetime = event.resolve_field(path_requested_lifetime);
  ASSERT_FALSE(result_requested_lifetime.empty()) << "RequestedLifetime resolved to empty";
}

TEST(GeneratedEventTypeTests, AuditOpenSecureChannelEventPayload_OptionalFields_Unset)
{
  AuditOpenSecureChannelEventPayload event;
  const QualifiedName path_certificate_error_event_id[]{QualifiedName{0, "CertificateErrorEventId"}};
  EXPECT_TRUE(event.resolve_field(path_certificate_error_event_id).empty())
    << "CertificateErrorEventId unexpectedly resolved while unset";
}

TEST(GeneratedEventTypeTests, AuditOpenSecureChannelEventPayload_OptionalFields_Set)
{
  AuditOpenSecureChannelEventPayload event;
  auto sentinel_certificate_error_event_id = ByteString{std::vector<std::byte>{std::byte{1}}};
  event.certificateErrorEventId = sentinel_certificate_error_event_id;
  const QualifiedName path_certificate_error_event_id[]{QualifiedName{0, "CertificateErrorEventId"}};
  auto result_certificate_error_event_id = event.resolve_field(path_certificate_error_event_id);
  ASSERT_FALSE(result_certificate_error_event_id.empty())
    << "CertificateErrorEventId resolved to empty after being set";
  EXPECT_EQ(result_certificate_error_event_id.as<ByteString>(), sentinel_certificate_error_event_id);
}

TEST(GeneratedEventTypeTests, AuditOpenSecureChannelEventPayload_Clone)
{
  AuditOpenSecureChannelEventPayload event;
  event.severity = 511;
  auto sentinel_clone_client_certificate = ByteString{std::vector<std::byte>{std::byte{1}}};
  event.clientCertificate = sentinel_clone_client_certificate;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditOpenSecureChannelEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->clientCertificate, sentinel_clone_client_certificate);
}

TEST(GeneratedEventTypeTests, AuditOpenSecureChannelEventPayload_ParentDelegation)
{
  AuditOpenSecureChannelEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditSessionEventPayload_Construction)
{
  AuditSessionEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditSessionEventType});
}

TEST(GeneratedEventTypeTests, AuditSessionEventPayload_ResolveOwnFields)
{
  AuditSessionEventPayload event;
  auto sentinel_session_id = NodeId{1, 42};
  event.sessionId = sentinel_session_id;
  const QualifiedName path_session_id[]{QualifiedName{0, "SessionId"}};
  auto result_session_id = event.resolve_field(path_session_id);
  ASSERT_FALSE(result_session_id.empty()) << "SessionId resolved to empty";
  EXPECT_EQ(result_session_id.as<NodeId>(), sentinel_session_id);
}

TEST(GeneratedEventTypeTests, AuditSessionEventPayload_Clone)
{
  AuditSessionEventPayload event;
  event.severity = 511;
  auto sentinel_clone_session_id = NodeId{1, 42};
  event.sessionId = sentinel_clone_session_id;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditSessionEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->sessionId, sentinel_clone_session_id);
}

TEST(GeneratedEventTypeTests, AuditSessionEventPayload_ParentDelegation)
{
  AuditSessionEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditCreateSessionEventPayload_Construction)
{
  AuditCreateSessionEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditCreateSessionEventType});
}

TEST(GeneratedEventTypeTests, AuditCreateSessionEventPayload_ResolveOwnFields)
{
  AuditCreateSessionEventPayload event;
  auto sentinel_secure_channel_id = String{"test"};
  event.secureChannelId = sentinel_secure_channel_id;
  const QualifiedName path_secure_channel_id[]{QualifiedName{0, "SecureChannelId"}};
  auto result_secure_channel_id = event.resolve_field(path_secure_channel_id);
  ASSERT_FALSE(result_secure_channel_id.empty()) << "SecureChannelId resolved to empty";
  EXPECT_EQ(result_secure_channel_id.as<String>(), sentinel_secure_channel_id);
  auto sentinel_client_certificate = ByteString{std::vector<std::byte>{std::byte{1}}};
  event.clientCertificate = sentinel_client_certificate;
  const QualifiedName path_client_certificate[]{QualifiedName{0, "ClientCertificate"}};
  auto result_client_certificate = event.resolve_field(path_client_certificate);
  ASSERT_FALSE(result_client_certificate.empty()) << "ClientCertificate resolved to empty";
  EXPECT_EQ(result_client_certificate.as<ByteString>(), sentinel_client_certificate);
  auto sentinel_client_certificate_thumbprint = String{"test"};
  event.clientCertificateThumbprint = sentinel_client_certificate_thumbprint;
  const QualifiedName path_client_certificate_thumbprint[]{QualifiedName{0, "ClientCertificateThumbprint"}};
  auto result_client_certificate_thumbprint = event.resolve_field(path_client_certificate_thumbprint);
  ASSERT_FALSE(result_client_certificate_thumbprint.empty())
    << "ClientCertificateThumbprint resolved to empty";
  EXPECT_EQ(result_client_certificate_thumbprint.as<String>(), sentinel_client_certificate_thumbprint);
  auto sentinel_revised_session_timeout = Variant{42};
  event.revisedSessionTimeout = sentinel_revised_session_timeout;
  const QualifiedName path_revised_session_timeout[]{QualifiedName{0, "RevisedSessionTimeout"}};
  auto result_revised_session_timeout = event.resolve_field(path_revised_session_timeout);
  ASSERT_FALSE(result_revised_session_timeout.empty()) << "RevisedSessionTimeout resolved to empty";
}

TEST(GeneratedEventTypeTests, AuditCreateSessionEventPayload_Clone)
{
  AuditCreateSessionEventPayload event;
  event.severity = 511;
  auto sentinel_clone_secure_channel_id = String{"test"};
  event.secureChannelId = sentinel_clone_secure_channel_id;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditCreateSessionEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->secureChannelId, sentinel_clone_secure_channel_id);
}

TEST(GeneratedEventTypeTests, AuditCreateSessionEventPayload_ParentDelegation)
{
  AuditCreateSessionEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditActivateSessionEventPayload_Construction)
{
  AuditActivateSessionEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditActivateSessionEventType});
}

TEST(GeneratedEventTypeTests, AuditActivateSessionEventPayload_ResolveOwnFields)
{
  AuditActivateSessionEventPayload event;
  auto sentinel_client_software_certificates = Variant{42};
  event.clientSoftwareCertificates = sentinel_client_software_certificates;
  const QualifiedName path_client_software_certificates[]{QualifiedName{0, "ClientSoftwareCertificates"}};
  auto result_client_software_certificates = event.resolve_field(path_client_software_certificates);
  ASSERT_FALSE(result_client_software_certificates.empty()) << "ClientSoftwareCertificates resolved to empty";
  auto sentinel_user_identity_token = Variant{42};
  event.userIdentityToken = sentinel_user_identity_token;
  const QualifiedName path_user_identity_token[]{QualifiedName{0, "UserIdentityToken"}};
  auto result_user_identity_token = event.resolve_field(path_user_identity_token);
  ASSERT_FALSE(result_user_identity_token.empty()) << "UserIdentityToken resolved to empty";
  auto sentinel_secure_channel_id = String{"test"};
  event.secureChannelId = sentinel_secure_channel_id;
  const QualifiedName path_secure_channel_id[]{QualifiedName{0, "SecureChannelId"}};
  auto result_secure_channel_id = event.resolve_field(path_secure_channel_id);
  ASSERT_FALSE(result_secure_channel_id.empty()) << "SecureChannelId resolved to empty";
  EXPECT_EQ(result_secure_channel_id.as<String>(), sentinel_secure_channel_id);
}

TEST(GeneratedEventTypeTests, AuditActivateSessionEventPayload_OptionalFields_Unset)
{
  AuditActivateSessionEventPayload event;
  const QualifiedName path_current_role_ids[]{QualifiedName{0, "CurrentRoleIds"}};
  EXPECT_TRUE(event.resolve_field(path_current_role_ids).empty())
    << "CurrentRoleIds unexpectedly resolved while unset";
}

TEST(GeneratedEventTypeTests, AuditActivateSessionEventPayload_OptionalFields_Set)
{
  AuditActivateSessionEventPayload event;
  auto sentinel_current_role_ids = Array<NodeId>{NodeId{1, 42}};
  event.currentRoleIds = sentinel_current_role_ids;
  const QualifiedName path_current_role_ids[]{QualifiedName{0, "CurrentRoleIds"}};
  auto result_current_role_ids = event.resolve_field(path_current_role_ids);
  ASSERT_FALSE(result_current_role_ids.empty()) << "CurrentRoleIds resolved to empty after being set";
  EXPECT_EQ(result_current_role_ids.as<Array<NodeId>>(), sentinel_current_role_ids);
}

TEST(GeneratedEventTypeTests, AuditActivateSessionEventPayload_Clone)
{
  AuditActivateSessionEventPayload event;
  event.severity = 511;
  auto sentinel_clone_client_software_certificates = Variant{42};
  event.clientSoftwareCertificates = sentinel_clone_client_software_certificates;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditActivateSessionEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AuditActivateSessionEventPayload_ParentDelegation)
{
  AuditActivateSessionEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditCancelEventPayload_Construction)
{
  AuditCancelEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditCancelEventType});
}

TEST(GeneratedEventTypeTests, AuditCancelEventPayload_ResolveOwnFields)
{
  AuditCancelEventPayload event;
  auto sentinel_request_handle = 12345;
  event.requestHandle = sentinel_request_handle;
  const QualifiedName path_request_handle[]{QualifiedName{0, "RequestHandle"}};
  auto result_request_handle = event.resolve_field(path_request_handle);
  ASSERT_FALSE(result_request_handle.empty()) << "RequestHandle resolved to empty";
  EXPECT_EQ(result_request_handle.as<uint32_t>(), sentinel_request_handle);
}

TEST(GeneratedEventTypeTests, AuditCancelEventPayload_Clone)
{
  AuditCancelEventPayload event;
  event.severity = 511;
  auto sentinel_clone_request_handle = 12345;
  event.requestHandle = sentinel_clone_request_handle;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditCancelEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->requestHandle, sentinel_clone_request_handle);
}

TEST(GeneratedEventTypeTests, AuditCancelEventPayload_ParentDelegation)
{
  AuditCancelEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditCertificateEventPayload_Construction)
{
  AuditCertificateEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditCertificateEventType});
}

TEST(GeneratedEventTypeTests, AuditCertificateEventPayload_ResolveOwnFields)
{
  AuditCertificateEventPayload event;
  auto sentinel_certificate = ByteString{std::vector<std::byte>{std::byte{1}}};
  event.certificate = sentinel_certificate;
  const QualifiedName path_certificate[]{QualifiedName{0, "Certificate"}};
  auto result_certificate = event.resolve_field(path_certificate);
  ASSERT_FALSE(result_certificate.empty()) << "Certificate resolved to empty";
  EXPECT_EQ(result_certificate.as<ByteString>(), sentinel_certificate);
}

TEST(GeneratedEventTypeTests, AuditCertificateEventPayload_Clone)
{
  AuditCertificateEventPayload event;
  event.severity = 511;
  auto sentinel_clone_certificate = ByteString{std::vector<std::byte>{std::byte{1}}};
  event.certificate = sentinel_clone_certificate;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditCertificateEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->certificate, sentinel_clone_certificate);
}

TEST(GeneratedEventTypeTests, AuditCertificateEventPayload_ParentDelegation)
{
  AuditCertificateEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditCertificateDataMismatchEventPayload_Construction)
{
  AuditCertificateDataMismatchEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditCertificateDataMismatchEventType});
}

TEST(GeneratedEventTypeTests, AuditCertificateDataMismatchEventPayload_ResolveOwnFields)
{
  AuditCertificateDataMismatchEventPayload event;
  auto sentinel_invalid_hostname = String{"test"};
  event.invalidHostname = sentinel_invalid_hostname;
  const QualifiedName path_invalid_hostname[]{QualifiedName{0, "InvalidHostname"}};
  auto result_invalid_hostname = event.resolve_field(path_invalid_hostname);
  ASSERT_FALSE(result_invalid_hostname.empty()) << "InvalidHostname resolved to empty";
  EXPECT_EQ(result_invalid_hostname.as<String>(), sentinel_invalid_hostname);
  auto sentinel_invalid_uri = String{"test"};
  event.invalidUri = sentinel_invalid_uri;
  const QualifiedName path_invalid_uri[]{QualifiedName{0, "InvalidUri"}};
  auto result_invalid_uri = event.resolve_field(path_invalid_uri);
  ASSERT_FALSE(result_invalid_uri.empty()) << "InvalidUri resolved to empty";
  EXPECT_EQ(result_invalid_uri.as<String>(), sentinel_invalid_uri);
}

TEST(GeneratedEventTypeTests, AuditCertificateDataMismatchEventPayload_Clone)
{
  AuditCertificateDataMismatchEventPayload event;
  event.severity = 511;
  auto sentinel_clone_invalid_hostname = String{"test"};
  event.invalidHostname = sentinel_clone_invalid_hostname;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditCertificateDataMismatchEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->invalidHostname, sentinel_clone_invalid_hostname);
}

TEST(GeneratedEventTypeTests, AuditCertificateDataMismatchEventPayload_ParentDelegation)
{
  AuditCertificateDataMismatchEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditCertificateExpiredEventPayload_Construction)
{
  AuditCertificateExpiredEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditCertificateExpiredEventType});
}

TEST(GeneratedEventTypeTests, AuditCertificateExpiredEventPayload_Clone)
{
  AuditCertificateExpiredEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditCertificateExpiredEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AuditCertificateExpiredEventPayload_ParentDelegation)
{
  AuditCertificateExpiredEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditCertificateInvalidEventPayload_Construction)
{
  AuditCertificateInvalidEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditCertificateInvalidEventType});
}

TEST(GeneratedEventTypeTests, AuditCertificateInvalidEventPayload_Clone)
{
  AuditCertificateInvalidEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditCertificateInvalidEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AuditCertificateInvalidEventPayload_ParentDelegation)
{
  AuditCertificateInvalidEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditCertificateUntrustedEventPayload_Construction)
{
  AuditCertificateUntrustedEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditCertificateUntrustedEventType});
}

TEST(GeneratedEventTypeTests, AuditCertificateUntrustedEventPayload_Clone)
{
  AuditCertificateUntrustedEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditCertificateUntrustedEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AuditCertificateUntrustedEventPayload_ParentDelegation)
{
  AuditCertificateUntrustedEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditCertificateRevokedEventPayload_Construction)
{
  AuditCertificateRevokedEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditCertificateRevokedEventType});
}

TEST(GeneratedEventTypeTests, AuditCertificateRevokedEventPayload_Clone)
{
  AuditCertificateRevokedEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditCertificateRevokedEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AuditCertificateRevokedEventPayload_ParentDelegation)
{
  AuditCertificateRevokedEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditCertificateMismatchEventPayload_Construction)
{
  AuditCertificateMismatchEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditCertificateMismatchEventType});
}

TEST(GeneratedEventTypeTests, AuditCertificateMismatchEventPayload_Clone)
{
  AuditCertificateMismatchEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditCertificateMismatchEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AuditCertificateMismatchEventPayload_ParentDelegation)
{
  AuditCertificateMismatchEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditNodeManagementEventPayload_Construction)
{
  AuditNodeManagementEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditNodeManagementEventType});
}

TEST(GeneratedEventTypeTests, AuditNodeManagementEventPayload_Clone)
{
  AuditNodeManagementEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditNodeManagementEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AuditNodeManagementEventPayload_ParentDelegation)
{
  AuditNodeManagementEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditAddNodesEventPayload_Construction)
{
  AuditAddNodesEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditAddNodesEventType});
}

TEST(GeneratedEventTypeTests, AuditAddNodesEventPayload_ResolveOwnFields)
{
  AuditAddNodesEventPayload event;
  auto sentinel_nodes_to_add = Variant{42};
  event.nodesToAdd = sentinel_nodes_to_add;
  const QualifiedName path_nodes_to_add[]{QualifiedName{0, "NodesToAdd"}};
  auto result_nodes_to_add = event.resolve_field(path_nodes_to_add);
  ASSERT_FALSE(result_nodes_to_add.empty()) << "NodesToAdd resolved to empty";
}

TEST(GeneratedEventTypeTests, AuditAddNodesEventPayload_Clone)
{
  AuditAddNodesEventPayload event;
  event.severity = 511;
  auto sentinel_clone_nodes_to_add = Variant{42};
  event.nodesToAdd = sentinel_clone_nodes_to_add;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditAddNodesEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AuditAddNodesEventPayload_ParentDelegation)
{
  AuditAddNodesEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditDeleteNodesEventPayload_Construction)
{
  AuditDeleteNodesEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditDeleteNodesEventType});
}

TEST(GeneratedEventTypeTests, AuditDeleteNodesEventPayload_ResolveOwnFields)
{
  AuditDeleteNodesEventPayload event;
  auto sentinel_nodes_to_delete = Variant{42};
  event.nodesToDelete = sentinel_nodes_to_delete;
  const QualifiedName path_nodes_to_delete[]{QualifiedName{0, "NodesToDelete"}};
  auto result_nodes_to_delete = event.resolve_field(path_nodes_to_delete);
  ASSERT_FALSE(result_nodes_to_delete.empty()) << "NodesToDelete resolved to empty";
}

TEST(GeneratedEventTypeTests, AuditDeleteNodesEventPayload_Clone)
{
  AuditDeleteNodesEventPayload event;
  event.severity = 511;
  auto sentinel_clone_nodes_to_delete = Variant{42};
  event.nodesToDelete = sentinel_clone_nodes_to_delete;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditDeleteNodesEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AuditDeleteNodesEventPayload_ParentDelegation)
{
  AuditDeleteNodesEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditAddReferencesEventPayload_Construction)
{
  AuditAddReferencesEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditAddReferencesEventType});
}

TEST(GeneratedEventTypeTests, AuditAddReferencesEventPayload_ResolveOwnFields)
{
  AuditAddReferencesEventPayload event;
  auto sentinel_references_to_add = Variant{42};
  event.referencesToAdd = sentinel_references_to_add;
  const QualifiedName path_references_to_add[]{QualifiedName{0, "ReferencesToAdd"}};
  auto result_references_to_add = event.resolve_field(path_references_to_add);
  ASSERT_FALSE(result_references_to_add.empty()) << "ReferencesToAdd resolved to empty";
}

TEST(GeneratedEventTypeTests, AuditAddReferencesEventPayload_Clone)
{
  AuditAddReferencesEventPayload event;
  event.severity = 511;
  auto sentinel_clone_references_to_add = Variant{42};
  event.referencesToAdd = sentinel_clone_references_to_add;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditAddReferencesEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AuditAddReferencesEventPayload_ParentDelegation)
{
  AuditAddReferencesEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditDeleteReferencesEventPayload_Construction)
{
  AuditDeleteReferencesEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditDeleteReferencesEventType});
}

TEST(GeneratedEventTypeTests, AuditDeleteReferencesEventPayload_ResolveOwnFields)
{
  AuditDeleteReferencesEventPayload event;
  auto sentinel_references_to_delete = Variant{42};
  event.referencesToDelete = sentinel_references_to_delete;
  const QualifiedName path_references_to_delete[]{QualifiedName{0, "ReferencesToDelete"}};
  auto result_references_to_delete = event.resolve_field(path_references_to_delete);
  ASSERT_FALSE(result_references_to_delete.empty()) << "ReferencesToDelete resolved to empty";
}

TEST(GeneratedEventTypeTests, AuditDeleteReferencesEventPayload_Clone)
{
  AuditDeleteReferencesEventPayload event;
  event.severity = 511;
  auto sentinel_clone_references_to_delete = Variant{42};
  event.referencesToDelete = sentinel_clone_references_to_delete;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditDeleteReferencesEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AuditDeleteReferencesEventPayload_ParentDelegation)
{
  AuditDeleteReferencesEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditWriteUpdateEventPayload_Construction)
{
  AuditWriteUpdateEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditWriteUpdateEventType});
}

TEST(GeneratedEventTypeTests, AuditWriteUpdateEventPayload_ResolveOwnFields)
{
  AuditWriteUpdateEventPayload event;
  auto sentinel_attribute_id = 12345;
  event.attributeId = sentinel_attribute_id;
  const QualifiedName path_attribute_id[]{QualifiedName{0, "AttributeId"}};
  auto result_attribute_id = event.resolve_field(path_attribute_id);
  ASSERT_FALSE(result_attribute_id.empty()) << "AttributeId resolved to empty";
  EXPECT_EQ(result_attribute_id.as<uint32_t>(), sentinel_attribute_id);
  auto sentinel_index_range = Variant{42};
  event.indexRange = sentinel_index_range;
  const QualifiedName path_index_range[]{QualifiedName{0, "IndexRange"}};
  auto result_index_range = event.resolve_field(path_index_range);
  ASSERT_FALSE(result_index_range.empty()) << "IndexRange resolved to empty";
  auto sentinel_old_value = Variant{42};
  event.oldValue = sentinel_old_value;
  const QualifiedName path_old_value[]{QualifiedName{0, "OldValue"}};
  auto result_old_value = event.resolve_field(path_old_value);
  ASSERT_FALSE(result_old_value.empty()) << "OldValue resolved to empty";
  auto sentinel_new_value = Variant{42};
  event.newValue = sentinel_new_value;
  const QualifiedName path_new_value[]{QualifiedName{0, "NewValue"}};
  auto result_new_value = event.resolve_field(path_new_value);
  ASSERT_FALSE(result_new_value.empty()) << "NewValue resolved to empty";
}

TEST(GeneratedEventTypeTests, AuditWriteUpdateEventPayload_Clone)
{
  AuditWriteUpdateEventPayload event;
  event.severity = 511;
  auto sentinel_clone_attribute_id = 12345;
  event.attributeId = sentinel_clone_attribute_id;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditWriteUpdateEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->attributeId, sentinel_clone_attribute_id);
}

TEST(GeneratedEventTypeTests, AuditWriteUpdateEventPayload_ParentDelegation)
{
  AuditWriteUpdateEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, DeviceFailureEventPayload_Construction)
{
  DeviceFailureEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::DeviceFailureEventType});
}

TEST(GeneratedEventTypeTests, DeviceFailureEventPayload_Clone)
{
  DeviceFailureEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<DeviceFailureEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, DeviceFailureEventPayload_ParentDelegation)
{
  DeviceFailureEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, BaseModelChangeEventPayload_Construction)
{
  BaseModelChangeEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::BaseModelChangeEventType});
}

TEST(GeneratedEventTypeTests, BaseModelChangeEventPayload_Clone)
{
  BaseModelChangeEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<BaseModelChangeEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, BaseModelChangeEventPayload_ParentDelegation)
{
  BaseModelChangeEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, GeneralModelChangeEventPayload_Construction)
{
  GeneralModelChangeEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::GeneralModelChangeEventType});
}

TEST(GeneratedEventTypeTests, GeneralModelChangeEventPayload_ResolveOwnFields)
{
  GeneralModelChangeEventPayload event;
  auto sentinel_changes = Variant{42};
  event.changes = sentinel_changes;
  const QualifiedName path_changes[]{QualifiedName{0, "Changes"}};
  auto result_changes = event.resolve_field(path_changes);
  ASSERT_FALSE(result_changes.empty()) << "Changes resolved to empty";
}

TEST(GeneratedEventTypeTests, GeneralModelChangeEventPayload_Clone)
{
  GeneralModelChangeEventPayload event;
  event.severity = 511;
  auto sentinel_clone_changes = Variant{42};
  event.changes = sentinel_clone_changes;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<GeneralModelChangeEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, GeneralModelChangeEventPayload_ParentDelegation)
{
  GeneralModelChangeEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, TransitionEventPayload_Construction)
{
  TransitionEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::TransitionEventType});
}

TEST(GeneratedEventTypeTests, TransitionEventPayload_Clone)
{
  TransitionEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<TransitionEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, TransitionEventPayload_ParentDelegation)
{
  TransitionEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditClientEventPayload_Construction)
{
  AuditClientEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditClientEventType});
}

TEST(GeneratedEventTypeTests, AuditClientEventPayload_ResolveOwnFields)
{
  AuditClientEventPayload event;
  auto sentinel_server_uri = Variant{42};
  event.serverUri = sentinel_server_uri;
  const QualifiedName path_server_uri[]{QualifiedName{0, "ServerUri"}};
  auto result_server_uri = event.resolve_field(path_server_uri);
  ASSERT_FALSE(result_server_uri.empty()) << "ServerUri resolved to empty";
}

TEST(GeneratedEventTypeTests, AuditClientEventPayload_Clone)
{
  AuditClientEventPayload event;
  event.severity = 511;
  auto sentinel_clone_server_uri = Variant{42};
  event.serverUri = sentinel_clone_server_uri;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditClientEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AuditClientEventPayload_ParentDelegation)
{
  AuditClientEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, ProgramTransitionEventPayload_Construction)
{
  ProgramTransitionEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::ProgramTransitionEventType});
}

TEST(GeneratedEventTypeTests, ProgramTransitionEventPayload_Clone)
{
  ProgramTransitionEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<ProgramTransitionEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, ProgramTransitionEventPayload_ParentDelegation)
{
  ProgramTransitionEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditClientUpdateMethodResultEventPayload_Construction)
{
  AuditClientUpdateMethodResultEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditClientUpdateMethodResultEventType});
}

TEST(GeneratedEventTypeTests, AuditClientUpdateMethodResultEventPayload_ResolveOwnFields)
{
  AuditClientUpdateMethodResultEventPayload event;
  auto sentinel_object_id = Variant{42};
  event.objectId = sentinel_object_id;
  const QualifiedName path_object_id[]{QualifiedName{0, "ObjectId"}};
  auto result_object_id = event.resolve_field(path_object_id);
  ASSERT_FALSE(result_object_id.empty()) << "ObjectId resolved to empty";
  auto sentinel_method_id = Variant{42};
  event.methodId = sentinel_method_id;
  const QualifiedName path_method_id[]{QualifiedName{0, "MethodId"}};
  auto result_method_id = event.resolve_field(path_method_id);
  ASSERT_FALSE(result_method_id.empty()) << "MethodId resolved to empty";
  auto sentinel_status_code_id = StatusCode{};
  event.statusCodeId = sentinel_status_code_id;
  const QualifiedName path_status_code_id[]{QualifiedName{0, "StatusCodeId"}};
  auto result_status_code_id = event.resolve_field(path_status_code_id);
  ASSERT_FALSE(result_status_code_id.empty()) << "StatusCodeId resolved to empty";
  EXPECT_EQ(result_status_code_id.as<StatusCode>(), sentinel_status_code_id);
  auto sentinel_input_arguments = Variant{42};
  event.inputArguments = sentinel_input_arguments;
  const QualifiedName path_input_arguments[]{QualifiedName{0, "InputArguments"}};
  auto result_input_arguments = event.resolve_field(path_input_arguments);
  ASSERT_FALSE(result_input_arguments.empty()) << "InputArguments resolved to empty";
  auto sentinel_output_arguments = Variant{42};
  event.outputArguments = sentinel_output_arguments;
  const QualifiedName path_output_arguments[]{QualifiedName{0, "OutputArguments"}};
  auto result_output_arguments = event.resolve_field(path_output_arguments);
  ASSERT_FALSE(result_output_arguments.empty()) << "OutputArguments resolved to empty";
}

TEST(GeneratedEventTypeTests, AuditClientUpdateMethodResultEventPayload_Clone)
{
  AuditClientUpdateMethodResultEventPayload event;
  event.severity = 511;
  auto sentinel_clone_object_id = Variant{42};
  event.objectId = sentinel_clone_object_id;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditClientUpdateMethodResultEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AuditClientUpdateMethodResultEventPayload_ParentDelegation)
{
  AuditClientUpdateMethodResultEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, SemanticChangeEventPayload_Construction)
{
  SemanticChangeEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::SemanticChangeEventType});
}

TEST(GeneratedEventTypeTests, SemanticChangeEventPayload_ResolveOwnFields)
{
  SemanticChangeEventPayload event;
  auto sentinel_changes = Variant{42};
  event.changes = sentinel_changes;
  const QualifiedName path_changes[]{QualifiedName{0, "Changes"}};
  auto result_changes = event.resolve_field(path_changes);
  ASSERT_FALSE(result_changes.empty()) << "Changes resolved to empty";
}

TEST(GeneratedEventTypeTests, SemanticChangeEventPayload_Clone)
{
  SemanticChangeEventPayload event;
  event.severity = 511;
  auto sentinel_clone_changes = Variant{42};
  event.changes = sentinel_clone_changes;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<SemanticChangeEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, SemanticChangeEventPayload_ParentDelegation)
{
  SemanticChangeEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditUrlMismatchEventPayload_Construction)
{
  AuditUrlMismatchEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditUrlMismatchEventType});
}

TEST(GeneratedEventTypeTests, AuditUrlMismatchEventPayload_ResolveOwnFields)
{
  AuditUrlMismatchEventPayload event;
  auto sentinel_endpoint_url = String{"test"};
  event.endpointUrl = sentinel_endpoint_url;
  const QualifiedName path_endpoint_url[]{QualifiedName{0, "EndpointUrl"}};
  auto result_endpoint_url = event.resolve_field(path_endpoint_url);
  ASSERT_FALSE(result_endpoint_url.empty()) << "EndpointUrl resolved to empty";
  EXPECT_EQ(result_endpoint_url.as<String>(), sentinel_endpoint_url);
}

TEST(GeneratedEventTypeTests, AuditUrlMismatchEventPayload_Clone)
{
  AuditUrlMismatchEventPayload event;
  event.severity = 511;
  auto sentinel_clone_endpoint_url = String{"test"};
  event.endpointUrl = sentinel_clone_endpoint_url;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditUrlMismatchEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->endpointUrl, sentinel_clone_endpoint_url);
}

TEST(GeneratedEventTypeTests, AuditUrlMismatchEventPayload_ParentDelegation)
{
  AuditUrlMismatchEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, RefreshStartEventPayload_Construction)
{
  RefreshStartEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::RefreshStartEventType});
}

TEST(GeneratedEventTypeTests, RefreshStartEventPayload_Clone)
{
  RefreshStartEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<RefreshStartEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, RefreshStartEventPayload_ParentDelegation)
{
  RefreshStartEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, RefreshEndEventPayload_Construction)
{
  RefreshEndEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::RefreshEndEventType});
}

TEST(GeneratedEventTypeTests, RefreshEndEventPayload_Clone)
{
  RefreshEndEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<RefreshEndEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, RefreshEndEventPayload_ParentDelegation)
{
  RefreshEndEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, RefreshRequiredEventPayload_Construction)
{
  RefreshRequiredEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::RefreshRequiredEventType});
}

TEST(GeneratedEventTypeTests, RefreshRequiredEventPayload_Clone)
{
  RefreshRequiredEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<RefreshRequiredEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, RefreshRequiredEventPayload_ParentDelegation)
{
  RefreshRequiredEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditConditionEnableEventPayload_Construction)
{
  AuditConditionEnableEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditConditionEnableEventType});
}

TEST(GeneratedEventTypeTests, AuditConditionEnableEventPayload_Clone)
{
  AuditConditionEnableEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditConditionEnableEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AuditConditionEnableEventPayload_ParentDelegation)
{
  AuditConditionEnableEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditConditionCommentEventPayload_Construction)
{
  AuditConditionCommentEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditConditionCommentEventType});
}

TEST(GeneratedEventTypeTests, AuditConditionCommentEventPayload_ResolveOwnFields)
{
  AuditConditionCommentEventPayload event;
  auto sentinel_condition_event_id = ByteString{std::vector<std::byte>{std::byte{1}}};
  event.conditionEventId = sentinel_condition_event_id;
  const QualifiedName path_condition_event_id[]{QualifiedName{0, "ConditionEventId"}};
  auto result_condition_event_id = event.resolve_field(path_condition_event_id);
  ASSERT_FALSE(result_condition_event_id.empty()) << "ConditionEventId resolved to empty";
  EXPECT_EQ(result_condition_event_id.as<ByteString>(), sentinel_condition_event_id);
  auto sentinel_comment = LocalizedText{"en", "test"};
  event.comment = sentinel_comment;
  const QualifiedName path_comment[]{QualifiedName{0, "Comment"}};
  auto result_comment = event.resolve_field(path_comment);
  ASSERT_FALSE(result_comment.empty()) << "Comment resolved to empty";
  EXPECT_EQ(result_comment.as<LocalizedText>(), sentinel_comment);
}

TEST(GeneratedEventTypeTests, AuditConditionCommentEventPayload_Clone)
{
  AuditConditionCommentEventPayload event;
  event.severity = 511;
  auto sentinel_clone_condition_event_id = ByteString{std::vector<std::byte>{std::byte{1}}};
  event.conditionEventId = sentinel_clone_condition_event_id;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditConditionCommentEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->conditionEventId, sentinel_clone_condition_event_id);
}

TEST(GeneratedEventTypeTests, AuditConditionCommentEventPayload_ParentDelegation)
{
  AuditConditionCommentEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, DialogConditionPayload_Construction)
{
  DialogConditionPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::DialogConditionType});
}

TEST(GeneratedEventTypeTests, DialogConditionPayload_ResolveOwnFields)
{
  DialogConditionPayload event;
  auto sentinel_dialog_state = TwoStateVariableState{true, LocalizedText{"", "Active"}, DateTime::now()};
  event.dialogState = sentinel_dialog_state;
  const QualifiedName path_dialog_state[]{QualifiedName{0, "DialogState"}};
  auto result_dialog_state = event.resolve_field(path_dialog_state);
  ASSERT_FALSE(result_dialog_state.empty()) << "DialogState resolved to empty";
  EXPECT_EQ(result_dialog_state.as<LocalizedText>(), sentinel_dialog_state.currentState);
  auto sentinel_prompt = LocalizedText{"en", "test"};
  event.prompt = sentinel_prompt;
  const QualifiedName path_prompt[]{QualifiedName{0, "Prompt"}};
  auto result_prompt = event.resolve_field(path_prompt);
  ASSERT_FALSE(result_prompt.empty()) << "Prompt resolved to empty";
  EXPECT_EQ(result_prompt.as<LocalizedText>(), sentinel_prompt);
  auto sentinel_response_option_set = Array<LocalizedText>{LocalizedText{"en", "test"}};
  event.responseOptionSet = sentinel_response_option_set;
  const QualifiedName path_response_option_set[]{QualifiedName{0, "ResponseOptionSet"}};
  auto result_response_option_set = event.resolve_field(path_response_option_set);
  ASSERT_FALSE(result_response_option_set.empty()) << "ResponseOptionSet resolved to empty";
  EXPECT_EQ(result_response_option_set.as<Array<LocalizedText>>(), sentinel_response_option_set);
  auto sentinel_default_response = 12345;
  event.defaultResponse = sentinel_default_response;
  const QualifiedName path_default_response[]{QualifiedName{0, "DefaultResponse"}};
  auto result_default_response = event.resolve_field(path_default_response);
  ASSERT_FALSE(result_default_response.empty()) << "DefaultResponse resolved to empty";
  EXPECT_EQ(result_default_response.as<int32_t>(), sentinel_default_response);
  auto sentinel_ok_response = 12345;
  event.okResponse = sentinel_ok_response;
  const QualifiedName path_ok_response[]{QualifiedName{0, "OkResponse"}};
  auto result_ok_response = event.resolve_field(path_ok_response);
  ASSERT_FALSE(result_ok_response.empty()) << "OkResponse resolved to empty";
  EXPECT_EQ(result_ok_response.as<int32_t>(), sentinel_ok_response);
  auto sentinel_cancel_response = 12345;
  event.cancelResponse = sentinel_cancel_response;
  const QualifiedName path_cancel_response[]{QualifiedName{0, "CancelResponse"}};
  auto result_cancel_response = event.resolve_field(path_cancel_response);
  ASSERT_FALSE(result_cancel_response.empty()) << "CancelResponse resolved to empty";
  EXPECT_EQ(result_cancel_response.as<int32_t>(), sentinel_cancel_response);
  auto sentinel_last_response = 12345;
  event.lastResponse = sentinel_last_response;
  const QualifiedName path_last_response[]{QualifiedName{0, "LastResponse"}};
  auto result_last_response = event.resolve_field(path_last_response);
  ASSERT_FALSE(result_last_response.empty()) << "LastResponse resolved to empty";
  EXPECT_EQ(result_last_response.as<int32_t>(), sentinel_last_response);
}

TEST(GeneratedEventTypeTests, DialogConditionPayload_CompoundSubFields)
{
  DialogConditionPayload event;
  auto sentinel_dialog_state = TwoStateVariableState{true, LocalizedText{"", "Active"}, DateTime::now()};
  event.dialogState = sentinel_dialog_state;
  const QualifiedName path_dialog_state_id[]{QualifiedName{0, "DialogState"}, QualifiedName{0, "Id"}};
  auto result_dialog_state_id = event.resolve_field(path_dialog_state_id);
  ASSERT_FALSE(result_dialog_state_id.empty()) << "DialogState.Id resolved to empty";
  EXPECT_EQ(result_dialog_state_id.as<bool>(), sentinel_dialog_state.id);
  const QualifiedName path_dialog_state_transition_time[]{
    QualifiedName{0, "DialogState"}, QualifiedName{0, "TransitionTime"}};
  auto result_dialog_state_transition_time = event.resolve_field(path_dialog_state_transition_time);
  ASSERT_FALSE(result_dialog_state_transition_time.empty()) << "DialogState.TransitionTime resolved to empty";
  EXPECT_EQ(result_dialog_state_transition_time.as<DateTime>(), sentinel_dialog_state.transitionTime);
  const QualifiedName path_dialog_state_current_state[]{
    QualifiedName{0, "DialogState"}, QualifiedName{0, "CurrentState"}};
  auto result_dialog_state_current_state = event.resolve_field(path_dialog_state_current_state);
  ASSERT_FALSE(result_dialog_state_current_state.empty()) << "DialogState.CurrentState resolved to empty";
  EXPECT_EQ(result_dialog_state_current_state.as<LocalizedText>(), sentinel_dialog_state.currentState);
}

TEST(GeneratedEventTypeTests, DialogConditionPayload_Clone)
{
  DialogConditionPayload event;
  event.severity = 511;
  auto sentinel_clone_prompt = LocalizedText{"en", "test"};
  event.prompt = sentinel_clone_prompt;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<DialogConditionPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->prompt, sentinel_clone_prompt);
}

TEST(GeneratedEventTypeTests, DialogConditionPayload_ParentDelegation)
{
  DialogConditionPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditHistoryEventUpdateEventPayload_Construction)
{
  AuditHistoryEventUpdateEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditHistoryEventUpdateEventType});
}

TEST(GeneratedEventTypeTests, AuditHistoryEventUpdateEventPayload_ResolveOwnFields)
{
  AuditHistoryEventUpdateEventPayload event;
  auto sentinel_updated_node = NodeId{1, 42};
  event.updatedNode = sentinel_updated_node;
  const QualifiedName path_updated_node[]{QualifiedName{0, "UpdatedNode"}};
  auto result_updated_node = event.resolve_field(path_updated_node);
  ASSERT_FALSE(result_updated_node.empty()) << "UpdatedNode resolved to empty";
  EXPECT_EQ(result_updated_node.as<NodeId>(), sentinel_updated_node);
  auto sentinel_perform_insert_replace = Variant{42};
  event.performInsertReplace = sentinel_perform_insert_replace;
  const QualifiedName path_perform_insert_replace[]{QualifiedName{0, "PerformInsertReplace"}};
  auto result_perform_insert_replace = event.resolve_field(path_perform_insert_replace);
  ASSERT_FALSE(result_perform_insert_replace.empty()) << "PerformInsertReplace resolved to empty";
  auto sentinel_filter = Variant{42};
  event.filter = sentinel_filter;
  const QualifiedName path_filter[]{QualifiedName{0, "Filter"}};
  auto result_filter = event.resolve_field(path_filter);
  ASSERT_FALSE(result_filter.empty()) << "Filter resolved to empty";
  auto sentinel_new_values = Variant{42};
  event.newValues = sentinel_new_values;
  const QualifiedName path_new_values[]{QualifiedName{0, "NewValues"}};
  auto result_new_values = event.resolve_field(path_new_values);
  ASSERT_FALSE(result_new_values.empty()) << "NewValues resolved to empty";
  auto sentinel_old_values = Variant{42};
  event.oldValues = sentinel_old_values;
  const QualifiedName path_old_values[]{QualifiedName{0, "OldValues"}};
  auto result_old_values = event.resolve_field(path_old_values);
  ASSERT_FALSE(result_old_values.empty()) << "OldValues resolved to empty";
}

TEST(GeneratedEventTypeTests, AuditHistoryEventUpdateEventPayload_Clone)
{
  AuditHistoryEventUpdateEventPayload event;
  event.severity = 511;
  auto sentinel_clone_updated_node = NodeId{1, 42};
  event.updatedNode = sentinel_clone_updated_node;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditHistoryEventUpdateEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->updatedNode, sentinel_clone_updated_node);
}

TEST(GeneratedEventTypeTests, AuditHistoryEventUpdateEventPayload_ParentDelegation)
{
  AuditHistoryEventUpdateEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditHistoryValueUpdateEventPayload_Construction)
{
  AuditHistoryValueUpdateEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditHistoryValueUpdateEventType});
}

TEST(GeneratedEventTypeTests, AuditHistoryValueUpdateEventPayload_ResolveOwnFields)
{
  AuditHistoryValueUpdateEventPayload event;
  auto sentinel_updated_node = NodeId{1, 42};
  event.updatedNode = sentinel_updated_node;
  const QualifiedName path_updated_node[]{QualifiedName{0, "UpdatedNode"}};
  auto result_updated_node = event.resolve_field(path_updated_node);
  ASSERT_FALSE(result_updated_node.empty()) << "UpdatedNode resolved to empty";
  EXPECT_EQ(result_updated_node.as<NodeId>(), sentinel_updated_node);
  auto sentinel_perform_insert_replace = Variant{42};
  event.performInsertReplace = sentinel_perform_insert_replace;
  const QualifiedName path_perform_insert_replace[]{QualifiedName{0, "PerformInsertReplace"}};
  auto result_perform_insert_replace = event.resolve_field(path_perform_insert_replace);
  ASSERT_FALSE(result_perform_insert_replace.empty()) << "PerformInsertReplace resolved to empty";
  auto sentinel_new_values = Variant{42};
  event.newValues = sentinel_new_values;
  const QualifiedName path_new_values[]{QualifiedName{0, "NewValues"}};
  auto result_new_values = event.resolve_field(path_new_values);
  ASSERT_FALSE(result_new_values.empty()) << "NewValues resolved to empty";
  auto sentinel_old_values = Variant{42};
  event.oldValues = sentinel_old_values;
  const QualifiedName path_old_values[]{QualifiedName{0, "OldValues"}};
  auto result_old_values = event.resolve_field(path_old_values);
  ASSERT_FALSE(result_old_values.empty()) << "OldValues resolved to empty";
}

TEST(GeneratedEventTypeTests, AuditHistoryValueUpdateEventPayload_Clone)
{
  AuditHistoryValueUpdateEventPayload event;
  event.severity = 511;
  auto sentinel_clone_updated_node = NodeId{1, 42};
  event.updatedNode = sentinel_clone_updated_node;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditHistoryValueUpdateEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->updatedNode, sentinel_clone_updated_node);
}

TEST(GeneratedEventTypeTests, AuditHistoryValueUpdateEventPayload_ParentDelegation)
{
  AuditHistoryValueUpdateEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditHistoryDeleteEventPayload_Construction)
{
  AuditHistoryDeleteEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditHistoryDeleteEventType});
}

TEST(GeneratedEventTypeTests, AuditHistoryDeleteEventPayload_ResolveOwnFields)
{
  AuditHistoryDeleteEventPayload event;
  auto sentinel_updated_node = NodeId{1, 42};
  event.updatedNode = sentinel_updated_node;
  const QualifiedName path_updated_node[]{QualifiedName{0, "UpdatedNode"}};
  auto result_updated_node = event.resolve_field(path_updated_node);
  ASSERT_FALSE(result_updated_node.empty()) << "UpdatedNode resolved to empty";
  EXPECT_EQ(result_updated_node.as<NodeId>(), sentinel_updated_node);
}

TEST(GeneratedEventTypeTests, AuditHistoryDeleteEventPayload_Clone)
{
  AuditHistoryDeleteEventPayload event;
  event.severity = 511;
  auto sentinel_clone_updated_node = NodeId{1, 42};
  event.updatedNode = sentinel_clone_updated_node;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditHistoryDeleteEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->updatedNode, sentinel_clone_updated_node);
}

TEST(GeneratedEventTypeTests, AuditHistoryDeleteEventPayload_ParentDelegation)
{
  AuditHistoryDeleteEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditHistoryRawModifyDeleteEventPayload_Construction)
{
  AuditHistoryRawModifyDeleteEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditHistoryRawModifyDeleteEventType});
}

TEST(GeneratedEventTypeTests, AuditHistoryRawModifyDeleteEventPayload_ResolveOwnFields)
{
  AuditHistoryRawModifyDeleteEventPayload event;
  auto sentinel_is_delete_modified = true;
  event.isDeleteModified = sentinel_is_delete_modified;
  const QualifiedName path_is_delete_modified[]{QualifiedName{0, "IsDeleteModified"}};
  auto result_is_delete_modified = event.resolve_field(path_is_delete_modified);
  ASSERT_FALSE(result_is_delete_modified.empty()) << "IsDeleteModified resolved to empty";
  EXPECT_EQ(result_is_delete_modified.as<bool>(), sentinel_is_delete_modified);
  auto sentinel_start_time = Variant{42};
  event.startTime = sentinel_start_time;
  const QualifiedName path_start_time[]{QualifiedName{0, "StartTime"}};
  auto result_start_time = event.resolve_field(path_start_time);
  ASSERT_FALSE(result_start_time.empty()) << "StartTime resolved to empty";
  auto sentinel_end_time = Variant{42};
  event.endTime = sentinel_end_time;
  const QualifiedName path_end_time[]{QualifiedName{0, "EndTime"}};
  auto result_end_time = event.resolve_field(path_end_time);
  ASSERT_FALSE(result_end_time.empty()) << "EndTime resolved to empty";
  auto sentinel_old_values = Variant{42};
  event.oldValues = sentinel_old_values;
  const QualifiedName path_old_values[]{QualifiedName{0, "OldValues"}};
  auto result_old_values = event.resolve_field(path_old_values);
  ASSERT_FALSE(result_old_values.empty()) << "OldValues resolved to empty";
}

TEST(GeneratedEventTypeTests, AuditHistoryRawModifyDeleteEventPayload_Clone)
{
  AuditHistoryRawModifyDeleteEventPayload event;
  event.severity = 511;
  auto sentinel_clone_is_delete_modified = true;
  event.isDeleteModified = sentinel_clone_is_delete_modified;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditHistoryRawModifyDeleteEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->isDeleteModified, sentinel_clone_is_delete_modified);
}

TEST(GeneratedEventTypeTests, AuditHistoryRawModifyDeleteEventPayload_ParentDelegation)
{
  AuditHistoryRawModifyDeleteEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditHistoryAtTimeDeleteEventPayload_Construction)
{
  AuditHistoryAtTimeDeleteEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditHistoryAtTimeDeleteEventType});
}

TEST(GeneratedEventTypeTests, AuditHistoryAtTimeDeleteEventPayload_ResolveOwnFields)
{
  AuditHistoryAtTimeDeleteEventPayload event;
  auto sentinel_req_times = Variant{42};
  event.reqTimes = sentinel_req_times;
  const QualifiedName path_req_times[]{QualifiedName{0, "ReqTimes"}};
  auto result_req_times = event.resolve_field(path_req_times);
  ASSERT_FALSE(result_req_times.empty()) << "ReqTimes resolved to empty";
  auto sentinel_old_values = Variant{42};
  event.oldValues = sentinel_old_values;
  const QualifiedName path_old_values[]{QualifiedName{0, "OldValues"}};
  auto result_old_values = event.resolve_field(path_old_values);
  ASSERT_FALSE(result_old_values.empty()) << "OldValues resolved to empty";
}

TEST(GeneratedEventTypeTests, AuditHistoryAtTimeDeleteEventPayload_Clone)
{
  AuditHistoryAtTimeDeleteEventPayload event;
  event.severity = 511;
  auto sentinel_clone_req_times = Variant{42};
  event.reqTimes = sentinel_clone_req_times;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditHistoryAtTimeDeleteEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AuditHistoryAtTimeDeleteEventPayload_ParentDelegation)
{
  AuditHistoryAtTimeDeleteEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditHistoryEventDeleteEventPayload_Construction)
{
  AuditHistoryEventDeleteEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditHistoryEventDeleteEventType});
}

TEST(GeneratedEventTypeTests, AuditHistoryEventDeleteEventPayload_ResolveOwnFields)
{
  AuditHistoryEventDeleteEventPayload event;
  auto sentinel_event_ids = Array<ByteString>{ByteString{std::vector<std::byte>{std::byte{1}}}};
  event.eventIds = sentinel_event_ids;
  const QualifiedName path_event_ids[]{QualifiedName{0, "EventIds"}};
  auto result_event_ids = event.resolve_field(path_event_ids);
  ASSERT_FALSE(result_event_ids.empty()) << "EventIds resolved to empty";
  EXPECT_EQ(result_event_ids.as<Array<ByteString>>(), sentinel_event_ids);
  auto sentinel_old_values = Variant{42};
  event.oldValues = sentinel_old_values;
  const QualifiedName path_old_values[]{QualifiedName{0, "OldValues"}};
  auto result_old_values = event.resolve_field(path_old_values);
  ASSERT_FALSE(result_old_values.empty()) << "OldValues resolved to empty";
}

TEST(GeneratedEventTypeTests, AuditHistoryEventDeleteEventPayload_Clone)
{
  AuditHistoryEventDeleteEventPayload event;
  event.severity = 511;
  auto sentinel_clone_event_ids = Array<ByteString>{ByteString{std::vector<std::byte>{std::byte{1}}}};
  event.eventIds = sentinel_clone_event_ids;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditHistoryEventDeleteEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->eventIds, sentinel_clone_event_ids);
}

TEST(GeneratedEventTypeTests, AuditHistoryEventDeleteEventPayload_ParentDelegation)
{
  AuditHistoryEventDeleteEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, EventQueueOverflowEventPayload_Construction)
{
  EventQueueOverflowEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::EventQueueOverflowEventType});
}

TEST(GeneratedEventTypeTests, EventQueueOverflowEventPayload_Clone)
{
  EventQueueOverflowEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<EventQueueOverflowEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, EventQueueOverflowEventPayload_ParentDelegation)
{
  EventQueueOverflowEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, TrustListUpdateRequestedAuditEventPayload_Construction)
{
  TrustListUpdateRequestedAuditEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::TrustListUpdateRequestedAuditEventType});
}

TEST(GeneratedEventTypeTests, TrustListUpdateRequestedAuditEventPayload_Clone)
{
  TrustListUpdateRequestedAuditEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<TrustListUpdateRequestedAuditEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, TrustListUpdateRequestedAuditEventPayload_ParentDelegation)
{
  TrustListUpdateRequestedAuditEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, CertificateUpdateRequestedAuditEventPayload_Construction)
{
  CertificateUpdateRequestedAuditEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::CertificateUpdateRequestedAuditEventType});
}

TEST(GeneratedEventTypeTests, CertificateUpdateRequestedAuditEventPayload_Clone)
{
  CertificateUpdateRequestedAuditEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<CertificateUpdateRequestedAuditEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, CertificateUpdateRequestedAuditEventPayload_ParentDelegation)
{
  CertificateUpdateRequestedAuditEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditHistoryConfigurationChangeEventPayload_Construction)
{
  AuditHistoryConfigurationChangeEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditHistoryConfigurationChangeEventType});
}

TEST(GeneratedEventTypeTests, AuditHistoryConfigurationChangeEventPayload_Clone)
{
  AuditHistoryConfigurationChangeEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditHistoryConfigurationChangeEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, AuditHistoryConfigurationChangeEventPayload_ParentDelegation)
{
  AuditHistoryConfigurationChangeEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditHistoryBulkInsertEventPayload_Construction)
{
  AuditHistoryBulkInsertEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditHistoryBulkInsertEventType});
}

TEST(GeneratedEventTypeTests, AuditHistoryBulkInsertEventPayload_ResolveOwnFields)
{
  AuditHistoryBulkInsertEventPayload event;
  auto sentinel_updated_node = NodeId{1, 42};
  event.updatedNode = sentinel_updated_node;
  const QualifiedName path_updated_node[]{QualifiedName{0, "UpdatedNode"}};
  auto result_updated_node = event.resolve_field(path_updated_node);
  ASSERT_FALSE(result_updated_node.empty()) << "UpdatedNode resolved to empty";
  EXPECT_EQ(result_updated_node.as<NodeId>(), sentinel_updated_node);
  auto sentinel_start_time = Variant{42};
  event.startTime = sentinel_start_time;
  const QualifiedName path_start_time[]{QualifiedName{0, "StartTime"}};
  auto result_start_time = event.resolve_field(path_start_time);
  ASSERT_FALSE(result_start_time.empty()) << "StartTime resolved to empty";
  auto sentinel_end_time = Variant{42};
  event.endTime = sentinel_end_time;
  const QualifiedName path_end_time[]{QualifiedName{0, "EndTime"}};
  auto result_end_time = event.resolve_field(path_end_time);
  ASSERT_FALSE(result_end_time.empty()) << "EndTime resolved to empty";
}

TEST(GeneratedEventTypeTests, AuditHistoryBulkInsertEventPayload_Clone)
{
  AuditHistoryBulkInsertEventPayload event;
  event.severity = 511;
  auto sentinel_clone_updated_node = NodeId{1, 42};
  event.updatedNode = sentinel_clone_updated_node;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditHistoryBulkInsertEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->updatedNode, sentinel_clone_updated_node);
}

TEST(GeneratedEventTypeTests, AuditHistoryBulkInsertEventPayload_ParentDelegation)
{
  AuditHistoryBulkInsertEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, ProgramTransitionAuditEventPayload_Construction)
{
  ProgramTransitionAuditEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::ProgramTransitionAuditEventType});
}

TEST(GeneratedEventTypeTests, ProgramTransitionAuditEventPayload_Clone)
{
  ProgramTransitionAuditEventPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<ProgramTransitionAuditEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, ProgramTransitionAuditEventPayload_ParentDelegation)
{
  ProgramTransitionAuditEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditConditionRespondEventPayload_Construction)
{
  AuditConditionRespondEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditConditionRespondEventType});
}

TEST(GeneratedEventTypeTests, AuditConditionRespondEventPayload_ResolveOwnFields)
{
  AuditConditionRespondEventPayload event;
  auto sentinel_selected_response = 12345;
  event.selectedResponse = sentinel_selected_response;
  const QualifiedName path_selected_response[]{QualifiedName{0, "SelectedResponse"}};
  auto result_selected_response = event.resolve_field(path_selected_response);
  ASSERT_FALSE(result_selected_response.empty()) << "SelectedResponse resolved to empty";
  EXPECT_EQ(result_selected_response.as<uint32_t>(), sentinel_selected_response);
}

TEST(GeneratedEventTypeTests, AuditConditionRespondEventPayload_Clone)
{
  AuditConditionRespondEventPayload event;
  event.severity = 511;
  auto sentinel_clone_selected_response = 12345;
  event.selectedResponse = sentinel_clone_selected_response;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditConditionRespondEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->selectedResponse, sentinel_clone_selected_response);
}

TEST(GeneratedEventTypeTests, AuditConditionRespondEventPayload_ParentDelegation)
{
  AuditConditionRespondEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditConditionAcknowledgeEventPayload_Construction)
{
  AuditConditionAcknowledgeEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditConditionAcknowledgeEventType});
}

TEST(GeneratedEventTypeTests, AuditConditionAcknowledgeEventPayload_ResolveOwnFields)
{
  AuditConditionAcknowledgeEventPayload event;
  auto sentinel_condition_event_id = ByteString{std::vector<std::byte>{std::byte{1}}};
  event.conditionEventId = sentinel_condition_event_id;
  const QualifiedName path_condition_event_id[]{QualifiedName{0, "ConditionEventId"}};
  auto result_condition_event_id = event.resolve_field(path_condition_event_id);
  ASSERT_FALSE(result_condition_event_id.empty()) << "ConditionEventId resolved to empty";
  EXPECT_EQ(result_condition_event_id.as<ByteString>(), sentinel_condition_event_id);
  auto sentinel_comment = LocalizedText{"en", "test"};
  event.comment = sentinel_comment;
  const QualifiedName path_comment[]{QualifiedName{0, "Comment"}};
  auto result_comment = event.resolve_field(path_comment);
  ASSERT_FALSE(result_comment.empty()) << "Comment resolved to empty";
  EXPECT_EQ(result_comment.as<LocalizedText>(), sentinel_comment);
}

TEST(GeneratedEventTypeTests, AuditConditionAcknowledgeEventPayload_Clone)
{
  AuditConditionAcknowledgeEventPayload event;
  event.severity = 511;
  auto sentinel_clone_condition_event_id = ByteString{std::vector<std::byte>{std::byte{1}}};
  event.conditionEventId = sentinel_clone_condition_event_id;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditConditionAcknowledgeEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->conditionEventId, sentinel_clone_condition_event_id);
}

TEST(GeneratedEventTypeTests, AuditConditionAcknowledgeEventPayload_ParentDelegation)
{
  AuditConditionAcknowledgeEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, AuditConditionConfirmEventPayload_Construction)
{
  AuditConditionConfirmEventPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::AuditConditionConfirmEventType});
}

TEST(GeneratedEventTypeTests, AuditConditionConfirmEventPayload_ResolveOwnFields)
{
  AuditConditionConfirmEventPayload event;
  auto sentinel_condition_event_id = ByteString{std::vector<std::byte>{std::byte{1}}};
  event.conditionEventId = sentinel_condition_event_id;
  const QualifiedName path_condition_event_id[]{QualifiedName{0, "ConditionEventId"}};
  auto result_condition_event_id = event.resolve_field(path_condition_event_id);
  ASSERT_FALSE(result_condition_event_id.empty()) << "ConditionEventId resolved to empty";
  EXPECT_EQ(result_condition_event_id.as<ByteString>(), sentinel_condition_event_id);
  auto sentinel_comment = LocalizedText{"en", "test"};
  event.comment = sentinel_comment;
  const QualifiedName path_comment[]{QualifiedName{0, "Comment"}};
  auto result_comment = event.resolve_field(path_comment);
  ASSERT_FALSE(result_comment.empty()) << "Comment resolved to empty";
  EXPECT_EQ(result_comment.as<LocalizedText>(), sentinel_comment);
}

TEST(GeneratedEventTypeTests, AuditConditionConfirmEventPayload_Clone)
{
  AuditConditionConfirmEventPayload event;
  event.severity = 511;
  auto sentinel_clone_condition_event_id = ByteString{std::vector<std::byte>{std::byte{1}}};
  event.conditionEventId = sentinel_clone_condition_event_id;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<AuditConditionConfirmEventPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->conditionEventId, sentinel_clone_condition_event_id);
}

TEST(GeneratedEventTypeTests, AuditConditionConfirmEventPayload_ParentDelegation)
{
  AuditConditionConfirmEventPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, ExclusiveLimitAlarmPayload_Construction)
{
  ExclusiveLimitAlarmPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::ExclusiveLimitAlarmType});
}

TEST(GeneratedEventTypeTests, ExclusiveLimitAlarmPayload_ResolveOwnFields)
{
  ExclusiveLimitAlarmPayload event;
  auto sentinel_limit_state = FiniteStateVariableState{LocalizedText{"", "High"}, NodeId{0, 9331u}};
  event.limitState = sentinel_limit_state;
  const QualifiedName path_limit_state[]{QualifiedName{0, "LimitState"}};
  auto result_limit_state = event.resolve_field(path_limit_state);
  ASSERT_FALSE(result_limit_state.empty()) << "LimitState resolved to empty";
  EXPECT_EQ(result_limit_state.as<LocalizedText>(), sentinel_limit_state.currentState);
}

TEST(GeneratedEventTypeTests, ExclusiveLimitAlarmPayload_CompoundSubFields)
{
  ExclusiveLimitAlarmPayload event;
  auto sentinel_limit_state = FiniteStateVariableState{LocalizedText{"", "High"}, NodeId{0, 9331u}};
  event.limitState = sentinel_limit_state;
  const QualifiedName path_limit_state_current_state[]{
    QualifiedName{0, "LimitState"}, QualifiedName{0, "CurrentState"}};
  auto result_limit_state_current_state = event.resolve_field(path_limit_state_current_state);
  ASSERT_FALSE(result_limit_state_current_state.empty()) << "LimitState.CurrentState resolved to empty";
  EXPECT_EQ(result_limit_state_current_state.as<LocalizedText>(), sentinel_limit_state.currentState);
}

TEST(GeneratedEventTypeTests, ExclusiveLimitAlarmPayload_Clone)
{
  ExclusiveLimitAlarmPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<ExclusiveLimitAlarmPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, ExclusiveLimitAlarmPayload_ParentDelegation)
{
  ExclusiveLimitAlarmPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, ExclusiveLevelAlarmPayload_Construction)
{
  ExclusiveLevelAlarmPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::ExclusiveLevelAlarmType});
}

TEST(GeneratedEventTypeTests, ExclusiveLevelAlarmPayload_Clone)
{
  ExclusiveLevelAlarmPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<ExclusiveLevelAlarmPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, ExclusiveLevelAlarmPayload_ParentDelegation)
{
  ExclusiveLevelAlarmPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, ExclusiveRateOfChangeAlarmPayload_Construction)
{
  ExclusiveRateOfChangeAlarmPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::ExclusiveRateOfChangeAlarmType});
}

TEST(GeneratedEventTypeTests, ExclusiveRateOfChangeAlarmPayload_OptionalFields_Unset)
{
  ExclusiveRateOfChangeAlarmPayload event;
  const QualifiedName path_engineering_units[]{QualifiedName{0, "EngineeringUnits"}};
  EXPECT_TRUE(event.resolve_field(path_engineering_units).empty())
    << "EngineeringUnits unexpectedly resolved while unset";
}

TEST(GeneratedEventTypeTests, ExclusiveRateOfChangeAlarmPayload_OptionalFields_Set)
{
  ExclusiveRateOfChangeAlarmPayload event;
  auto sentinel_engineering_units = Variant{42};
  event.engineeringUnits = sentinel_engineering_units;
  const QualifiedName path_engineering_units[]{QualifiedName{0, "EngineeringUnits"}};
  auto result_engineering_units = event.resolve_field(path_engineering_units);
  ASSERT_FALSE(result_engineering_units.empty()) << "EngineeringUnits resolved to empty after being set";
}

TEST(GeneratedEventTypeTests, ExclusiveRateOfChangeAlarmPayload_Clone)
{
  ExclusiveRateOfChangeAlarmPayload event;
  event.severity = 511;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<ExclusiveRateOfChangeAlarmPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
}

TEST(GeneratedEventTypeTests, ExclusiveRateOfChangeAlarmPayload_ParentDelegation)
{
  ExclusiveRateOfChangeAlarmPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}

TEST(GeneratedEventTypeTests, ExclusiveDeviationAlarmPayload_Construction)
{
  ExclusiveDeviationAlarmPayload event;
  EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::ExclusiveDeviationAlarmType});
}

TEST(GeneratedEventTypeTests, ExclusiveDeviationAlarmPayload_ResolveOwnFields)
{
  ExclusiveDeviationAlarmPayload event;
  auto sentinel_setpoint_node = NodeId{1, 42};
  event.setpointNode = sentinel_setpoint_node;
  const QualifiedName path_setpoint_node[]{QualifiedName{0, "SetpointNode"}};
  auto result_setpoint_node = event.resolve_field(path_setpoint_node);
  ASSERT_FALSE(result_setpoint_node.empty()) << "SetpointNode resolved to empty";
  EXPECT_EQ(result_setpoint_node.as<NodeId>(), sentinel_setpoint_node);
}

TEST(GeneratedEventTypeTests, ExclusiveDeviationAlarmPayload_OptionalFields_Unset)
{
  ExclusiveDeviationAlarmPayload event;
  const QualifiedName path_base_setpoint_node[]{QualifiedName{0, "BaseSetpointNode"}};
  EXPECT_TRUE(event.resolve_field(path_base_setpoint_node).empty())
    << "BaseSetpointNode unexpectedly resolved while unset";
}

TEST(GeneratedEventTypeTests, ExclusiveDeviationAlarmPayload_OptionalFields_Set)
{
  ExclusiveDeviationAlarmPayload event;
  auto sentinel_base_setpoint_node = NodeId{1, 42};
  event.baseSetpointNode = sentinel_base_setpoint_node;
  const QualifiedName path_base_setpoint_node[]{QualifiedName{0, "BaseSetpointNode"}};
  auto result_base_setpoint_node = event.resolve_field(path_base_setpoint_node);
  ASSERT_FALSE(result_base_setpoint_node.empty()) << "BaseSetpointNode resolved to empty after being set";
  EXPECT_EQ(result_base_setpoint_node.as<NodeId>(), sentinel_base_setpoint_node);
}

TEST(GeneratedEventTypeTests, ExclusiveDeviationAlarmPayload_Clone)
{
  ExclusiveDeviationAlarmPayload event;
  event.severity = 511;
  auto sentinel_clone_setpoint_node = NodeId{1, 42};
  event.setpointNode = sentinel_clone_setpoint_node;
  auto cloned = event.clone();
  ASSERT_NE(cloned, nullptr);
  auto* casted = dynamic_cast<ExclusiveDeviationAlarmPayload*>(cloned.get());
  ASSERT_NE(casted, nullptr) << "clone returned wrong dynamic type";
  EXPECT_EQ(casted->eventType, event.eventType);
  EXPECT_EQ(casted->severity, event.severity);
  EXPECT_EQ(casted->setpointNode, sentinel_clone_setpoint_node);
}

TEST(GeneratedEventTypeTests, ExclusiveDeviationAlarmPayload_ParentDelegation)
{
  ExclusiveDeviationAlarmPayload event;
  event.severity = 500;
  const QualifiedName severityPath[]{QualifiedName{0, "Severity"}};
  auto result = event.resolve_field(severityPath);
  EXPECT_FALSE(result.empty());
  auto val = result.as<uint16_t>();
  EXPECT_EQ(val, 500);
}
