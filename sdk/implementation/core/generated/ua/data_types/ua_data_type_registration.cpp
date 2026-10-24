// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_data_type_registration.h"
#include "ua_structure_factory.h"

#include "ua_key_value_pair.h"
#include "ua_additional_parameters_type.h"
#include "ua_ephemeral_key_type.h"
#include "ua_endpoint_type.h"
#include "ua_bit_field_definition.h"
#include "ua_rational_number.h"
#include "ua_three_d_vector.h"
#include "ua_three_d_cartesian_coordinates.h"
#include "ua_three_d_orientation.h"
#include "ua_three_d_frame.h"
#include "ua_identity_mapping_rule_type.h"
#include "ua_currency_unit_type.h"
#include "ua_annotation_data_type.h"
#include "ua_linear_conversion_data_type.h"
#include "ua_quantity_dimension.h"
#include "ua_trust_list_data_type.h"
#include "ua_certificate_group_data_type.h"
#include "ua_configuration_update_target_type.h"
#include "ua_transaction_error_type.h"
#include "ua_application_configuration_data_type.h"
#include "ua_application_identity_data_type.h"
#include "ua_endpoint_data_type.h"
#include "ua_server_endpoint_data_type.h"
#include "ua_security_settings_data_type.h"
#include "ua_user_token_settings_data_type.h"
#include "ua_service_certificate_data_type.h"
#include "ua_authorization_service_configuration_data_type.h"
#include "ua_structure_description.h"
#include "ua_enum_description.h"
#include "ua_simple_type_description.h"
#include "ua_ua_binary_file_data_type.h"
#include "ua_portable_qualified_name.h"
#include "ua_portable_node_id.h"
#include "ua_unsigned_rational_number.h"
#include "ua_alias_name_data_type.h"
#include "ua_user_management_data_type.h"
#include "ua_priority_mapping_entry_type.h"
#include "ua_lldp_management_address_tx_port_type.h"
#include "ua_lldp_management_address_type.h"
#include "ua_lldp_tlv_type.h"
#include "ua_reference_description_data_type.h"
#include "ua_reference_list_entry_data_type.h"
#include "ua_log_record.h"
#include "ua_log_records_data_type.h"
#include "ua_span_context_data_type.h"
#include "ua_trace_context_data_type.h"
#include "ua_name_value_pair.h"
#include "ua_role_permission_type.h"
#include "ua_structure_field.h"
#include "ua_structure_definition.h"
#include "ua_enum_definition.h"
#include "ua_argument.h"
#include "ua_enum_value_type.h"
#include "ua_enum_field.h"
#include "ua_time_zone_data_type.h"
#include "ua_application_description.h"
#include "ua_server_on_network.h"
#include "ua_user_token_policy.h"
#include "ua_endpoint_description.h"
#include "ua_registered_server.h"
#include "ua_discovery_configuration.h"
#include "ua_mdns_discovery_configuration.h"
#include "ua_signed_software_certificate.h"
#include "ua_anonymous_identity_token.h"
#include "ua_user_name_identity_token.h"
#include "ua_x509_identity_token.h"
#include "ua_issued_identity_token.h"
#include "ua_add_nodes_item.h"
#include "ua_add_references_item.h"
#include "ua_delete_nodes_item.h"
#include "ua_delete_references_item.h"
#include "ua_relative_path_element.h"
#include "ua_relative_path.h"
#include "ua_endpoint_configuration.h"
#include "ua_content_filter_element.h"
#include "ua_content_filter.h"
#include "ua_element_operand.h"
#include "ua_literal_operand.h"
#include "ua_attribute_operand.h"
#include "ua_simple_attribute_operand.h"
#include "ua_modification_info.h"
#include "ua_history_event.h"
#include "ua_history_modified_event.h"
#include "ua_monitoring_filter.h"
#include "ua_event_filter.h"
#include "ua_aggregate_configuration.h"
#include "ua_history_event_field_list.h"
#include "ua_build_info.h"
#include "ua_redundant_server_data_type.h"
#include "ua_endpoint_url_list_data_type.h"
#include "ua_network_group_data_type.h"
#include "ua_sampling_interval_diagnostics_data_type.h"
#include "ua_server_diagnostics_summary_data_type.h"
#include "ua_server_status_data_type.h"
#include "ua_session_diagnostics_data_type.h"
#include "ua_session_security_diagnostics_data_type.h"
#include "ua_service_counter_data_type.h"
#include "ua_status_result.h"
#include "ua_subscription_diagnostics_data_type.h"
#include "ua_model_change_structure_data_type.h"
#include "ua_semantic_change_structure_data_type.h"
#include "ua_range.h"
#include "ua_eu_information.h"
#include "ua_complex_number_type.h"
#include "ua_double_complex_number_type.h"
#include "ua_axis_information.h"
#include "ua_xv_type.h"
#include "ua_program_diagnostic_data_type.h"
#include "ua_program_diagnostic2_data_type.h"
#include "ua_annotation.h"
#include "ua_reference_node.h"
#include "ua_request_header.h"
#include "ua_response_header.h"
#include "ua_service_fault.h"
#include "ua_sessionless_invoke_request_type.h"
#include "ua_sessionless_invoke_response_type.h"
#include "ua_find_servers_request.h"
#include "ua_find_servers_response.h"
#include "ua_find_servers_on_network_request.h"
#include "ua_find_servers_on_network_response.h"
#include "ua_get_endpoints_request.h"
#include "ua_get_endpoints_response.h"
#include "ua_register_server_request.h"
#include "ua_register_server_response.h"
#include "ua_register_server2_request.h"
#include "ua_register_server2_response.h"
#include "ua_channel_security_token.h"
#include "ua_open_secure_channel_request.h"
#include "ua_open_secure_channel_response.h"
#include "ua_close_secure_channel_request.h"
#include "ua_close_secure_channel_response.h"
#include "ua_signature_data.h"
#include "ua_create_session_request.h"
#include "ua_create_session_response.h"
#include "ua_activate_session_request.h"
#include "ua_activate_session_response.h"
#include "ua_close_session_request.h"
#include "ua_close_session_response.h"
#include "ua_cancel_request.h"
#include "ua_cancel_response.h"
#include "ua_node_attributes.h"
#include "ua_object_attributes.h"
#include "ua_variable_attributes.h"
#include "ua_method_attributes.h"
#include "ua_object_type_attributes.h"
#include "ua_variable_type_attributes.h"
#include "ua_reference_type_attributes.h"
#include "ua_data_type_attributes.h"
#include "ua_view_attributes.h"
#include "ua_generic_attribute_value.h"
#include "ua_generic_attributes.h"
#include "ua_add_nodes_result.h"
#include "ua_add_nodes_request.h"
#include "ua_add_nodes_response.h"
#include "ua_add_references_request.h"
#include "ua_add_references_response.h"
#include "ua_delete_nodes_request.h"
#include "ua_delete_nodes_response.h"
#include "ua_delete_references_request.h"
#include "ua_delete_references_response.h"
#include "ua_view_description.h"
#include "ua_browse_description.h"
#include "ua_reference_description.h"
#include "ua_browse_result.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_next_request.h"
#include "ua_browse_next_response.h"
#include "ua_browse_path.h"
#include "ua_browse_path_target.h"
#include "ua_browse_path_result.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"
#include "ua_register_nodes_request.h"
#include "ua_register_nodes_response.h"
#include "ua_unregister_nodes_request.h"
#include "ua_unregister_nodes_response.h"
#include "ua_query_data_description.h"
#include "ua_node_type_description.h"
#include "ua_query_data_set.h"
#include "ua_node_reference.h"
#include "ua_content_filter_element_result.h"
#include "ua_content_filter_result.h"
#include "ua_parsing_result.h"
#include "ua_query_first_request.h"
#include "ua_query_first_response.h"
#include "ua_query_next_request.h"
#include "ua_query_next_response.h"
#include "ua_read_value_id.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_history_read_value_id.h"
#include "ua_history_read_result.h"
#include "ua_read_event_details.h"
#include "ua_read_event_details2.h"
#include "ua_sort_rule_element.h"
#include "ua_read_event_details_sorted.h"
#include "ua_read_raw_modified_details.h"
#include "ua_read_processed_details.h"
#include "ua_read_at_time_details.h"
#include "ua_read_annotation_data_details.h"
#include "ua_history_data.h"
#include "ua_history_modified_data.h"
#include "ua_history_read_request.h"
#include "ua_history_read_response.h"
#include "ua_write_value.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_update_data_details.h"
#include "ua_update_structure_data_details.h"
#include "ua_update_event_details.h"
#include "ua_delete_raw_modified_details.h"
#include "ua_delete_at_time_details.h"
#include "ua_delete_event_details.h"
#include "ua_history_update_result.h"
#include "ua_history_update_request.h"
#include "ua_history_update_response.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_data_change_filter.h"
#include "ua_aggregate_filter.h"
#include "ua_monitoring_filter_result.h"
#include "ua_event_filter_result.h"
#include "ua_aggregate_filter_result.h"
#include "ua_monitoring_parameters.h"
#include "ua_monitored_item_create_request.h"
#include "ua_monitored_item_create_result.h"
#include "ua_create_monitored_items_request.h"
#include "ua_create_monitored_items_response.h"
#include "ua_monitored_item_modify_request.h"
#include "ua_monitored_item_modify_result.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_modify_monitored_items_response.h"
#include "ua_set_monitoring_mode_request.h"
#include "ua_set_monitoring_mode_response.h"
#include "ua_set_triggering_request.h"
#include "ua_set_triggering_response.h"
#include "ua_delete_monitored_items_request.h"
#include "ua_delete_monitored_items_response.h"
#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_modify_subscription_request.h"
#include "ua_modify_subscription_response.h"
#include "ua_set_publishing_mode_request.h"
#include "ua_set_publishing_mode_response.h"
#include "ua_notification_message.h"
#include "ua_notification_data.h"
#include "ua_data_change_notification.h"
#include "ua_monitored_item_notification.h"
#include "ua_event_notification_list.h"
#include "ua_event_field_list.h"
#include "ua_status_change_notification.h"
#include "ua_subscription_acknowledgement.h"
#include "ua_publish_request.h"
#include "ua_publish_response.h"
#include "ua_republish_request.h"
#include "ua_republish_response.h"
#include "ua_transfer_result.h"
#include "ua_transfer_subscriptions_request.h"
#include "ua_transfer_subscriptions_response.h"
#include "ua_delete_subscriptions_request.h"
#include "ua_delete_subscriptions_response.h"

namespace ua
{

void register_ua_core_data_types_with_factory(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  KeyValuePair::register_type(ns, uaBinaryFactory, xmlFactory);
  AdditionalParametersType::register_type(ns, uaBinaryFactory, xmlFactory);
  EphemeralKeyType::register_type(ns, uaBinaryFactory, xmlFactory);
  EndpointType::register_type(ns, uaBinaryFactory, xmlFactory);
  BitFieldDefinition::register_type(ns, uaBinaryFactory, xmlFactory);
  RationalNumber::register_type(ns, uaBinaryFactory, xmlFactory);
  ThreeDVector::register_type(ns, uaBinaryFactory, xmlFactory);
  ThreeDCartesianCoordinates::register_type(ns, uaBinaryFactory, xmlFactory);
  ThreeDOrientation::register_type(ns, uaBinaryFactory, xmlFactory);
  ThreeDFrame::register_type(ns, uaBinaryFactory, xmlFactory);
  IdentityMappingRuleType::register_type(ns, uaBinaryFactory, xmlFactory);
  CurrencyUnitType::register_type(ns, uaBinaryFactory, xmlFactory);
  ConfigurationUpdateTargetType::register_type(ns, uaBinaryFactory, xmlFactory);
  TransactionErrorType::register_type(ns, uaBinaryFactory, xmlFactory);
  ApplicationConfigurationDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  ApplicationIdentityDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  EndpointDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  ServerEndpointDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  SecuritySettingsDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  UserTokenSettingsDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  ServiceCertificateDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  AuthorizationServiceConfigurationDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  StructureDescription::register_type(ns, uaBinaryFactory, xmlFactory);
  EnumDescription::register_type(ns, uaBinaryFactory, xmlFactory);
  SimpleTypeDescription::register_type(ns, uaBinaryFactory, xmlFactory);
  UABinaryFileDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  PortableQualifiedName::register_type(ns, uaBinaryFactory, xmlFactory);
  PortableNodeId::register_type(ns, uaBinaryFactory, xmlFactory);
  UnsignedRationalNumber::register_type(ns, uaBinaryFactory, xmlFactory);
  AliasNameDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  UserManagementDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  ReferenceDescriptionDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  ReferenceListEntryDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  RolePermissionType::register_type(ns, uaBinaryFactory, xmlFactory);
  StructureField::register_type(ns, uaBinaryFactory, xmlFactory);
  StructureDefinition::register_type(ns, uaBinaryFactory, xmlFactory);
  EnumDefinition::register_type(ns, uaBinaryFactory, xmlFactory);
  Argument::register_type(ns, uaBinaryFactory, xmlFactory);
  EnumValueType::register_type(ns, uaBinaryFactory, xmlFactory);
  EnumField::register_type(ns, uaBinaryFactory, xmlFactory);
  TimeZoneDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  ApplicationDescription::register_type(ns, uaBinaryFactory, xmlFactory);
  ServerOnNetwork::register_type(ns, uaBinaryFactory, xmlFactory);
  UserTokenPolicy::register_type(ns, uaBinaryFactory, xmlFactory);
  EndpointDescription::register_type(ns, uaBinaryFactory, xmlFactory);
  RegisteredServer::register_type(ns, uaBinaryFactory, xmlFactory);
  DiscoveryConfiguration::register_type(ns, uaBinaryFactory, xmlFactory);
  MdnsDiscoveryConfiguration::register_type(ns, uaBinaryFactory, xmlFactory);
  RelativePathElement::register_type(ns, uaBinaryFactory, xmlFactory);
  RelativePath::register_type(ns, uaBinaryFactory, xmlFactory);
  EndpointConfiguration::register_type(ns, uaBinaryFactory, xmlFactory);
  ContentFilterElement::register_type(ns, uaBinaryFactory, xmlFactory);
  ContentFilter::register_type(ns, uaBinaryFactory, xmlFactory);
  ElementOperand::register_type(ns, uaBinaryFactory, xmlFactory);
  LiteralOperand::register_type(ns, uaBinaryFactory, xmlFactory);
  AttributeOperand::register_type(ns, uaBinaryFactory, xmlFactory);
  SimpleAttributeOperand::register_type(ns, uaBinaryFactory, xmlFactory);
  ModificationInfo::register_type(ns, uaBinaryFactory, xmlFactory);
  HistoryEvent::register_type(ns, uaBinaryFactory, xmlFactory);
  HistoryModifiedEvent::register_type(ns, uaBinaryFactory, xmlFactory);
  MonitoringFilter::register_type(ns, uaBinaryFactory, xmlFactory);
  EventFilter::register_type(ns, uaBinaryFactory, xmlFactory);
  AggregateConfiguration::register_type(ns, uaBinaryFactory, xmlFactory);
  HistoryEventFieldList::register_type(ns, uaBinaryFactory, xmlFactory);
  BuildInfo::register_type(ns, uaBinaryFactory, xmlFactory);
  RedundantServerDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  EndpointUrlListDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  NetworkGroupDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  SamplingIntervalDiagnosticsDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  ServerDiagnosticsSummaryDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  ServerStatusDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  SessionDiagnosticsDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  SessionSecurityDiagnosticsDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  ServiceCounterDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  StatusResult::register_type(ns, uaBinaryFactory, xmlFactory);
  SubscriptionDiagnosticsDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  ModelChangeStructureDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  SemanticChangeStructureDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  Range::register_type(ns, uaBinaryFactory, xmlFactory);
  EUInformation::register_type(ns, uaBinaryFactory, xmlFactory);
  ProgramDiagnosticDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  ProgramDiagnostic2DataType::register_type(ns, uaBinaryFactory, xmlFactory);
  Annotation::register_type(ns, uaBinaryFactory, xmlFactory);
  ReferenceNode::register_type(ns, uaBinaryFactory, xmlFactory);
  RequestHeader::register_type(ns, uaBinaryFactory, xmlFactory);
  ResponseHeader::register_type(ns, uaBinaryFactory, xmlFactory);
  ServiceFault::register_type(ns, uaBinaryFactory, xmlFactory);
  SessionlessInvokeRequestType::register_type(ns, uaBinaryFactory, xmlFactory);
  SessionlessInvokeResponseType::register_type(ns, uaBinaryFactory, xmlFactory);
  FindServersRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  FindServersResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  FindServersOnNetworkRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  FindServersOnNetworkResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  GetEndpointsRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  GetEndpointsResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  RegisterServerRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  RegisterServerResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  RegisterServer2Request::register_type(ns, uaBinaryFactory, xmlFactory);
  RegisterServer2Response::register_type(ns, uaBinaryFactory, xmlFactory);
  ChannelSecurityToken::register_type(ns, uaBinaryFactory, xmlFactory);
  OpenSecureChannelRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  OpenSecureChannelResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  CloseSecureChannelRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  CloseSecureChannelResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  SignatureData::register_type(ns, uaBinaryFactory, xmlFactory);
  CreateSessionRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  CreateSessionResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  ActivateSessionRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  ActivateSessionResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  CloseSessionRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  CloseSessionResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  CancelRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  CancelResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  NodeAttributes::register_type(ns, uaBinaryFactory, xmlFactory);
  ObjectAttributes::register_type(ns, uaBinaryFactory, xmlFactory);
  VariableAttributes::register_type(ns, uaBinaryFactory, xmlFactory);
  MethodAttributes::register_type(ns, uaBinaryFactory, xmlFactory);
  ObjectTypeAttributes::register_type(ns, uaBinaryFactory, xmlFactory);
  VariableTypeAttributes::register_type(ns, uaBinaryFactory, xmlFactory);
  ReferenceTypeAttributes::register_type(ns, uaBinaryFactory, xmlFactory);
  DataTypeAttributes::register_type(ns, uaBinaryFactory, xmlFactory);
  ViewAttributes::register_type(ns, uaBinaryFactory, xmlFactory);
  GenericAttributeValue::register_type(ns, uaBinaryFactory, xmlFactory);
  GenericAttributes::register_type(ns, uaBinaryFactory, xmlFactory);
  AddNodesResult::register_type(ns, uaBinaryFactory, xmlFactory);
  AddNodesRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  AddNodesResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  AddReferencesRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  AddReferencesResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  DeleteNodesRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  DeleteNodesResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  DeleteReferencesRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  DeleteReferencesResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  ViewDescription::register_type(ns, uaBinaryFactory, xmlFactory);
  BrowseDescription::register_type(ns, uaBinaryFactory, xmlFactory);
  ReferenceDescription::register_type(ns, uaBinaryFactory, xmlFactory);
  BrowseResult::register_type(ns, uaBinaryFactory, xmlFactory);
  BrowseRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  BrowseResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  BrowseNextRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  BrowseNextResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  BrowsePath::register_type(ns, uaBinaryFactory, xmlFactory);
  BrowsePathTarget::register_type(ns, uaBinaryFactory, xmlFactory);
  BrowsePathResult::register_type(ns, uaBinaryFactory, xmlFactory);
  TranslateBrowsePathsToNodeIdsRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  TranslateBrowsePathsToNodeIdsResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  RegisterNodesRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  RegisterNodesResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  UnregisterNodesRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  UnregisterNodesResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  QueryDataDescription::register_type(ns, uaBinaryFactory, xmlFactory);
  NodeTypeDescription::register_type(ns, uaBinaryFactory, xmlFactory);
  QueryDataSet::register_type(ns, uaBinaryFactory, xmlFactory);
  NodeReference::register_type(ns, uaBinaryFactory, xmlFactory);
  ContentFilterElementResult::register_type(ns, uaBinaryFactory, xmlFactory);
  ContentFilterResult::register_type(ns, uaBinaryFactory, xmlFactory);
  ParsingResult::register_type(ns, uaBinaryFactory, xmlFactory);
  QueryFirstRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  QueryFirstResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  QueryNextRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  QueryNextResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  ReadValueId::register_type(ns, uaBinaryFactory, xmlFactory);
  ReadRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  ReadResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  HistoryReadValueId::register_type(ns, uaBinaryFactory, xmlFactory);
  HistoryReadResult::register_type(ns, uaBinaryFactory, xmlFactory);
  ReadEventDetails::register_type(ns, uaBinaryFactory, xmlFactory);
  ReadEventDetails2::register_type(ns, uaBinaryFactory, xmlFactory);
  SortRuleElement::register_type(ns, uaBinaryFactory, xmlFactory);
  ReadEventDetailsSorted::register_type(ns, uaBinaryFactory, xmlFactory);
  ReadRawModifiedDetails::register_type(ns, uaBinaryFactory, xmlFactory);
  ReadProcessedDetails::register_type(ns, uaBinaryFactory, xmlFactory);
  ReadAtTimeDetails::register_type(ns, uaBinaryFactory, xmlFactory);
  ReadAnnotationDataDetails::register_type(ns, uaBinaryFactory, xmlFactory);
  HistoryData::register_type(ns, uaBinaryFactory, xmlFactory);
  HistoryModifiedData::register_type(ns, uaBinaryFactory, xmlFactory);
  HistoryReadRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  HistoryReadResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  WriteValue::register_type(ns, uaBinaryFactory, xmlFactory);
  WriteRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  WriteResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  UpdateDataDetails::register_type(ns, uaBinaryFactory, xmlFactory);
  UpdateStructureDataDetails::register_type(ns, uaBinaryFactory, xmlFactory);
  UpdateEventDetails::register_type(ns, uaBinaryFactory, xmlFactory);
  DeleteRawModifiedDetails::register_type(ns, uaBinaryFactory, xmlFactory);
  DeleteAtTimeDetails::register_type(ns, uaBinaryFactory, xmlFactory);
  DeleteEventDetails::register_type(ns, uaBinaryFactory, xmlFactory);
  HistoryUpdateResult::register_type(ns, uaBinaryFactory, xmlFactory);
  HistoryUpdateRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  HistoryUpdateResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  CallMethodRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  CallMethodResult::register_type(ns, uaBinaryFactory, xmlFactory);
  CallRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  CallResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  DataChangeFilter::register_type(ns, uaBinaryFactory, xmlFactory);
  AggregateFilter::register_type(ns, uaBinaryFactory, xmlFactory);
  MonitoringFilterResult::register_type(ns, uaBinaryFactory, xmlFactory);
  EventFilterResult::register_type(ns, uaBinaryFactory, xmlFactory);
  AggregateFilterResult::register_type(ns, uaBinaryFactory, xmlFactory);
  MonitoringParameters::register_type(ns, uaBinaryFactory, xmlFactory);
  MonitoredItemCreateRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  MonitoredItemCreateResult::register_type(ns, uaBinaryFactory, xmlFactory);
  CreateMonitoredItemsRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  CreateMonitoredItemsResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  MonitoredItemModifyRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  MonitoredItemModifyResult::register_type(ns, uaBinaryFactory, xmlFactory);
  ModifyMonitoredItemsRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  ModifyMonitoredItemsResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  SetMonitoringModeRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  SetMonitoringModeResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  SetTriggeringRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  SetTriggeringResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  DeleteMonitoredItemsRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  DeleteMonitoredItemsResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  CreateSubscriptionRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  CreateSubscriptionResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  ModifySubscriptionRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  ModifySubscriptionResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  SetPublishingModeRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  SetPublishingModeResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  NotificationMessage::register_type(ns, uaBinaryFactory, xmlFactory);
  NotificationData::register_type(ns, uaBinaryFactory, xmlFactory);
  DataChangeNotification::register_type(ns, uaBinaryFactory, xmlFactory);
  MonitoredItemNotification::register_type(ns, uaBinaryFactory, xmlFactory);
  EventNotificationList::register_type(ns, uaBinaryFactory, xmlFactory);
  EventFieldList::register_type(ns, uaBinaryFactory, xmlFactory);
  StatusChangeNotification::register_type(ns, uaBinaryFactory, xmlFactory);
  SubscriptionAcknowledgement::register_type(ns, uaBinaryFactory, xmlFactory);
  PublishRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  PublishResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  RepublishRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  RepublishResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  TransferResult::register_type(ns, uaBinaryFactory, xmlFactory);
  TransferSubscriptionsRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  TransferSubscriptionsResponse::register_type(ns, uaBinaryFactory, xmlFactory);
  DeleteSubscriptionsRequest::register_type(ns, uaBinaryFactory, xmlFactory);
  DeleteSubscriptionsResponse::register_type(ns, uaBinaryFactory, xmlFactory);
}

void register_ua_data_access_data_types_with_factory(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  AnnotationDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  LinearConversionDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  QuantityDimension::register_type(ns, uaBinaryFactory, xmlFactory);
  ComplexNumberType::register_type(ns, uaBinaryFactory, xmlFactory);
  DoubleComplexNumberType::register_type(ns, uaBinaryFactory, xmlFactory);
  AxisInformation::register_type(ns, uaBinaryFactory, xmlFactory);
  XVType::register_type(ns, uaBinaryFactory, xmlFactory);
}

void register_ua_auditing_data_types_with_factory(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  SignedSoftwareCertificate::register_type(ns, uaBinaryFactory, xmlFactory);
  AnonymousIdentityToken::register_type(ns, uaBinaryFactory, xmlFactory);
  UserNameIdentityToken::register_type(ns, uaBinaryFactory, xmlFactory);
  X509IdentityToken::register_type(ns, uaBinaryFactory, xmlFactory);
  IssuedIdentityToken::register_type(ns, uaBinaryFactory, xmlFactory);
  AddNodesItem::register_type(ns, uaBinaryFactory, xmlFactory);
  AddReferencesItem::register_type(ns, uaBinaryFactory, xmlFactory);
  DeleteNodesItem::register_type(ns, uaBinaryFactory, xmlFactory);
  DeleteReferencesItem::register_type(ns, uaBinaryFactory, xmlFactory);
}

void register_ua_certificates_data_types_with_factory(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  TrustListDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  CertificateGroupDataType::register_type(ns, uaBinaryFactory, xmlFactory);
}

void register_ua_network_mgmt_data_types_with_factory(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  PriorityMappingEntryType::register_type(ns, uaBinaryFactory, xmlFactory);
  LldpManagementAddressTxPortType::register_type(ns, uaBinaryFactory, xmlFactory);
  LldpManagementAddressType::register_type(ns, uaBinaryFactory, xmlFactory);
  LldpTlvType::register_type(ns, uaBinaryFactory, xmlFactory);
}

void register_ua_diagnostics_data_types_with_factory(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  LogRecord::register_type(ns, uaBinaryFactory, xmlFactory);
  LogRecordsDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  SpanContextDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  TraceContextDataType::register_type(ns, uaBinaryFactory, xmlFactory);
  NameValuePair::register_type(ns, uaBinaryFactory, xmlFactory);
}

void register_ua_data_types_with_factory(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  register_ua_core_data_types_with_factory(ns, uaBinaryFactory, xmlFactory);
  register_ua_data_access_data_types_with_factory(ns, uaBinaryFactory, xmlFactory);
  register_ua_auditing_data_types_with_factory(ns, uaBinaryFactory, xmlFactory);
  register_ua_certificates_data_types_with_factory(ns, uaBinaryFactory, xmlFactory);
  register_ua_network_mgmt_data_types_with_factory(ns, uaBinaryFactory, xmlFactory);
  register_ua_diagnostics_data_types_with_factory(ns, uaBinaryFactory, xmlFactory);
}

}  // namespace ua
