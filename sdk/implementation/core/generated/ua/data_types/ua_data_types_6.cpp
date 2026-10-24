// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_structure_factory.h"
#include "ua_binary_codec.h"
#include "ua_xml_codec.h"
#include "ua_uri_array.h"
#include "ua_to_string.h"
#include "ua_utilities.h"

#include "ua_key_value_pair.h"
#include "ua_additional_parameters_type.h"
#include "ua_ephemeral_key_type.h"
#include "ua_endpoint_type.h"
#include "ua_bit_field_definition.h"
#include "ua_rational_number.h"
#include "ua_vector.h"
#include "ua_three_d_vector.h"
#include "ua_cartesian_coordinates.h"
#include "ua_three_d_cartesian_coordinates.h"
#include "ua_orientation.h"
#include "ua_three_d_orientation.h"
#include "ua_frame.h"
#include "ua_three_d_frame.h"
#include "ua_identity_mapping_rule_type.h"
#include "ua_currency_unit_type.h"
#include "ua_annotation_data_type.h"
#include "ua_linear_conversion_data_type.h"
#include "ua_quantity_dimension.h"
#include "ua_trust_list_data_type.h"
#include "ua_base_configuration_data_type.h"
#include "ua_base_configuration_record_data_type.h"
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
#include "ua_data_type_schema_header.h"
#include "ua_data_type_description.h"
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
#include "ua_data_type_definition.h"
#include "ua_structure_field.h"
#include "ua_structure_definition.h"
#include "ua_enum_definition.h"
#include "ua_argument.h"
#include "ua_enum_value_type.h"
#include "ua_enum_field.h"
#include "ua_option_set.h"
#include "ua_time_zone_data_type.h"
#include "ua_application_description.h"
#include "ua_server_on_network.h"
#include "ua_user_token_policy.h"
#include "ua_endpoint_description.h"
#include "ua_registered_server.h"
#include "ua_discovery_configuration.h"
#include "ua_mdns_discovery_configuration.h"
#include "ua_signed_software_certificate.h"
#include "ua_user_identity_token.h"
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
#include "ua_filter_operand.h"
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
#include "ua_history_read_details.h"
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
#include "ua_history_update_details.h"
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

bool Vector::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId Vector::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId Vector::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String Vector::type_name() const
{
  return typeName;
}

void Vector::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);
}

void Vector::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  UA_UNUSED(limit);
  UA_UNUSED(ns);
  UA_UNUSED(encoder);
}

void Vector::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);
}

BuiltInTypeId Vector::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::IdentityMappingRuleType
{
namespace
{
void encode(StackDepth limit, const ua::IdentityMappingRuleType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, utils::as_int32(value.criteria_type()));
  encoder.encode(limit, value.criteria());
}

void encode(StackDepth limit, const ua::IdentityMappingRuleType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "CriteriaType", utils::as_int32(value.criteria_type()));
  encoder.encode(limit, "Criteria", value.criteria());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::IdentityMappingRuleType& value)
{
  int32_t enumVal{};
  decoder.decode(limit, enumVal);
  value.criteria_type() = utils::from_underlying<IdentityCriteriaType>(enumVal);
  decoder.decode(limit, value.criteria());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::IdentityMappingRuleType& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "CriteriaType", true, enumVal);
  value.criteria_type() = utils::from_underlying<IdentityCriteriaType>(enumVal);
  decoder.decode(limit, "Criteria", true, value.criteria());
}
}  // namespace
}  // namespace detail::IdentityMappingRuleType

namespace detail::IdentityMappingRuleType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::IdentityMappingRuleType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::IdentityMappingRuleType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::IdentityMappingRuleType

namespace detail::IdentityMappingRuleType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::IdentityMappingRuleType>();
}
}  // namespace
}  // namespace detail::IdentityMappingRuleType

bool IdentityMappingRuleType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId IdentityMappingRuleType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId IdentityMappingRuleType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String IdentityMappingRuleType::type_name() const
{
  return typeName;
}

void IdentityMappingRuleType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::IdentityMappingRuleType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::IdentityMappingRuleType::encode(limit, *this, *xml);
  }
}

void IdentityMappingRuleType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::IdentityMappingRuleType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::IdentityMappingRuleType::encode_id(limit, ns, *xml);
  }
}

void IdentityMappingRuleType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::IdentityMappingRuleType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::IdentityMappingRuleType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> IdentityMappingRuleType::clone() const
{
  return make_unique<IdentityMappingRuleType>(*this);
}

void IdentityMappingRuleType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "criteria_type=" + ua::to_string(utils::as_int32(criteria_type()));
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "criteria=" + ua::to_string(criteria());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "criteria_type=" + ua::to_string(utils::as_int32(criteria_type()));
  if (!output.empty())
  {
    output += ", ";
  }
  output += "criteria=" + ua::to_string(criteria());
}

std::string IdentityMappingRuleType::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void IdentityMappingRuleType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::IdentityMappingRuleType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::IdentityMappingRuleType::create);
  }
}

IdentityCriteriaType& IdentityMappingRuleType::criteria_type()
{
  return mCriteriaType;
}

const IdentityCriteriaType& IdentityMappingRuleType::criteria_type() const
{
  return mCriteriaType;
}

String& IdentityMappingRuleType::criteria()
{
  return mCriteria;
}

const String& IdentityMappingRuleType::criteria() const
{
  return mCriteria;
}

BuiltInTypeId IdentityMappingRuleType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::CertificateGroupDataType
{
namespace
{
void encode(StackDepth limit, const ua::CertificateGroupDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.purpose());
  encoder.encode(limit, value.certificate_types());
  encoder.encode(limit, value.is_certificate_assigned());
  encoder.encode(limit, value.validation_options().as_underlying_type());
}

void encode(StackDepth limit, const ua::CertificateGroupDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Purpose", value.purpose());
  encoder.encode(limit, "CertificateTypes", value.certificate_types());
  encoder.encode(limit, "IsCertificateAssigned", value.is_certificate_assigned());
  encoder.encode(limit, "ValidationOptions", value.validation_options().as_underlying_type());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::CertificateGroupDataType& value)
{
  decoder.decode(limit, value.purpose());
  decoder.decode(limit, value.certificate_types());
  decoder.decode(limit, value.is_certificate_assigned());
  {
    TrustListValidationOptions::UnderlyingType val{};
    decoder.decode(limit, val);
    value.validation_options().from_underlying_type(val);
  }
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::CertificateGroupDataType& value)
{
  decoder.decode(limit, "Purpose", true, value.purpose());
  decoder.decode(limit, "CertificateTypes", true, value.certificate_types());
  decoder.decode(limit, "IsCertificateAssigned", true, value.is_certificate_assigned());
  {
    TrustListValidationOptions::UnderlyingType val{};
    decoder.decode(limit, "ValidationOptions", true, val);
    value.validation_options().from_underlying_type(val);
  }
}
}  // namespace
}  // namespace detail::CertificateGroupDataType

namespace detail::CertificateGroupDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::CertificateGroupDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::CertificateGroupDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::CertificateGroupDataType

namespace detail::CertificateGroupDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::CertificateGroupDataType>();
}
}  // namespace
}  // namespace detail::CertificateGroupDataType

bool CertificateGroupDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return BaseConfigurationRecordDataType::is_of_type(ns, dataTypeId);
}

NodeId CertificateGroupDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId CertificateGroupDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String CertificateGroupDataType::type_name() const
{
  return typeName;
}

void CertificateGroupDataType::encode(StackDepth limit, Encoder& encoder) const
{

  BaseConfigurationRecordDataType::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CertificateGroupDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CertificateGroupDataType::encode(limit, *this, *xml);
  }
}

void CertificateGroupDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CertificateGroupDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CertificateGroupDataType::encode_id(limit, ns, *xml);
  }
}

void CertificateGroupDataType::decode(StackDepth limit, Decoder& decoder)
{

  BaseConfigurationRecordDataType::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::CertificateGroupDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::CertificateGroupDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> CertificateGroupDataType::clone() const
{
  return make_unique<CertificateGroupDataType>(*this);
}

void CertificateGroupDataType::append_fields(std::string& output, int indent) const
{
  BaseConfigurationRecordDataType::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "purpose=" + ua::to_string(purpose());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "certificate_types=" + ua::to_string(certificate_types());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "is_certificate_assigned=" + ua::to_string(is_certificate_assigned());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "validation_options=" + ua::to_string(validation_options().as_underlying_type());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "purpose=" + ua::to_string(purpose());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "certificate_types=" + ua::to_string(certificate_types());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "is_certificate_assigned=" + ua::to_string(is_certificate_assigned());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "validation_options=" + ua::to_string(validation_options().as_underlying_type());
}

std::string CertificateGroupDataType::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void CertificateGroupDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::CertificateGroupDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::CertificateGroupDataType::create);
  }
}

NodeId& CertificateGroupDataType::purpose()
{
  return mPurpose;
}

const NodeId& CertificateGroupDataType::purpose() const
{
  return mPurpose;
}

Array<NodeId>& CertificateGroupDataType::certificate_types()
{
  return mCertificateTypes;
}

const Array<NodeId>& CertificateGroupDataType::certificate_types() const
{
  return mCertificateTypes;
}

Array<bool>& CertificateGroupDataType::is_certificate_assigned()
{
  return mIsCertificateAssigned;
}

const Array<bool>& CertificateGroupDataType::is_certificate_assigned() const
{
  return mIsCertificateAssigned;
}

TrustListValidationOptions& CertificateGroupDataType::validation_options()
{
  return mValidationOptions;
}

const TrustListValidationOptions& CertificateGroupDataType::validation_options() const
{
  return mValidationOptions;
}

BuiltInTypeId CertificateGroupDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::UserTokenSettingsDataType
{
namespace
{
void encode(StackDepth limit, const ua::UserTokenSettingsDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, utils::as_int32(value.token_type()));
  encoder.encode(limit, value.issued_token_type());
  encoder.encode(limit, value.issuer_endpoint_url());
  encoder.encode(limit, value.security_policy_uri());
  encoder.encode(limit, value.certificate_group_name());
  encoder.encode(limit, value.authorization_service_name());
}

void encode(StackDepth limit, const ua::UserTokenSettingsDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "TokenType", utils::as_int32(value.token_type()));
  encoder.encode(limit, "IssuedTokenType", value.issued_token_type());
  encoder.encode(limit, "IssuerEndpointUrl", value.issuer_endpoint_url());
  encoder.encode(limit, "SecurityPolicyUri", value.security_policy_uri());
  encoder.encode(limit, "CertificateGroupName", value.certificate_group_name());
  encoder.encode(limit, "AuthorizationServiceName", value.authorization_service_name());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::UserTokenSettingsDataType& value)
{
  int32_t enumVal{};
  decoder.decode(limit, enumVal);
  value.token_type() = utils::from_underlying<UserTokenType>(enumVal);
  decoder.decode(limit, value.issued_token_type());
  decoder.decode(limit, value.issuer_endpoint_url());
  decoder.decode(limit, value.security_policy_uri());
  decoder.decode(limit, value.certificate_group_name());
  decoder.decode(limit, value.authorization_service_name());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::UserTokenSettingsDataType& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "TokenType", true, enumVal);
  value.token_type() = utils::from_underlying<UserTokenType>(enumVal);
  decoder.decode(limit, "IssuedTokenType", true, value.issued_token_type());
  decoder.decode(limit, "IssuerEndpointUrl", true, value.issuer_endpoint_url());
  decoder.decode(limit, "SecurityPolicyUri", true, value.security_policy_uri());
  decoder.decode(limit, "CertificateGroupName", true, value.certificate_group_name());
  decoder.decode(limit, "AuthorizationServiceName", true, value.authorization_service_name());
}
}  // namespace
}  // namespace detail::UserTokenSettingsDataType

namespace detail::UserTokenSettingsDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::UserTokenSettingsDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::UserTokenSettingsDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::UserTokenSettingsDataType

namespace detail::UserTokenSettingsDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::UserTokenSettingsDataType>();
}
}  // namespace
}  // namespace detail::UserTokenSettingsDataType

bool UserTokenSettingsDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return BaseConfigurationRecordDataType::is_of_type(ns, dataTypeId);
}

NodeId UserTokenSettingsDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId UserTokenSettingsDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String UserTokenSettingsDataType::type_name() const
{
  return typeName;
}

void UserTokenSettingsDataType::encode(StackDepth limit, Encoder& encoder) const
{

  BaseConfigurationRecordDataType::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::UserTokenSettingsDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::UserTokenSettingsDataType::encode(limit, *this, *xml);
  }
}

void UserTokenSettingsDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::UserTokenSettingsDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::UserTokenSettingsDataType::encode_id(limit, ns, *xml);
  }
}

void UserTokenSettingsDataType::decode(StackDepth limit, Decoder& decoder)
{

  BaseConfigurationRecordDataType::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::UserTokenSettingsDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::UserTokenSettingsDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> UserTokenSettingsDataType::clone() const
{
  return make_unique<UserTokenSettingsDataType>(*this);
}

void UserTokenSettingsDataType::append_fields(std::string& output, int indent) const
{
  BaseConfigurationRecordDataType::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "token_type=" + ua::to_string(utils::as_int32(token_type()));
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "issued_token_type=" + ua::to_string(issued_token_type());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "issuer_endpoint_url=" + ua::to_string(issuer_endpoint_url());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "security_policy_uri=" + ua::to_string(security_policy_uri());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "certificate_group_name=" + ua::to_string(certificate_group_name());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "authorization_service_name=" + ua::to_string(authorization_service_name());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "token_type=" + ua::to_string(utils::as_int32(token_type()));
  if (!output.empty())
  {
    output += ", ";
  }
  output += "issued_token_type=" + ua::to_string(issued_token_type());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "issuer_endpoint_url=" + ua::to_string(issuer_endpoint_url());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "security_policy_uri=" + ua::to_string(security_policy_uri());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "certificate_group_name=" + ua::to_string(certificate_group_name());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "authorization_service_name=" + ua::to_string(authorization_service_name());
}

std::string UserTokenSettingsDataType::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void UserTokenSettingsDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::UserTokenSettingsDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::UserTokenSettingsDataType::create);
  }
}

UserTokenType& UserTokenSettingsDataType::token_type()
{
  return mTokenType;
}

const UserTokenType& UserTokenSettingsDataType::token_type() const
{
  return mTokenType;
}

String& UserTokenSettingsDataType::issued_token_type()
{
  return mIssuedTokenType;
}

const String& UserTokenSettingsDataType::issued_token_type() const
{
  return mIssuedTokenType;
}

String& UserTokenSettingsDataType::issuer_endpoint_url()
{
  return mIssuerEndpointUrl;
}

const String& UserTokenSettingsDataType::issuer_endpoint_url() const
{
  return mIssuerEndpointUrl;
}

String& UserTokenSettingsDataType::security_policy_uri()
{
  return mSecurityPolicyUri;
}

const String& UserTokenSettingsDataType::security_policy_uri() const
{
  return mSecurityPolicyUri;
}

String& UserTokenSettingsDataType::certificate_group_name()
{
  return mCertificateGroupName;
}

const String& UserTokenSettingsDataType::certificate_group_name() const
{
  return mCertificateGroupName;
}

String& UserTokenSettingsDataType::authorization_service_name()
{
  return mAuthorizationServiceName;
}

const String& UserTokenSettingsDataType::authorization_service_name() const
{
  return mAuthorizationServiceName;
}

BuiltInTypeId UserTokenSettingsDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::UABinaryFileDataType
{
namespace
{
void encode(StackDepth limit, const ua::UABinaryFileDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.schema_location());
  encoder.encode(limit, value.file_header());
  encoder.encode(limit, value.body());
}

void encode(StackDepth limit, const ua::UABinaryFileDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "SchemaLocation", value.schema_location());
  encoder.encode(limit, "FileHeader", value.file_header());
  encoder.encode(limit, "Body", value.body());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::UABinaryFileDataType& value)
{
  decoder.decode(limit, value.schema_location());
  decoder.decode(limit, value.file_header());
  decoder.decode(limit, value.body());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::UABinaryFileDataType& value)
{
  decoder.decode(limit, "SchemaLocation", true, value.schema_location());
  decoder.decode(limit, "FileHeader", true, value.file_header());
  decoder.decode(limit, "Body", true, value.body());
}
}  // namespace
}  // namespace detail::UABinaryFileDataType

namespace detail::UABinaryFileDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::UABinaryFileDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::UABinaryFileDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::UABinaryFileDataType

namespace detail::UABinaryFileDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::UABinaryFileDataType>();
}
}  // namespace
}  // namespace detail::UABinaryFileDataType

bool UABinaryFileDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return DataTypeSchemaHeader::is_of_type(ns, dataTypeId);
}

NodeId UABinaryFileDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId UABinaryFileDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String UABinaryFileDataType::type_name() const
{
  return typeName;
}

void UABinaryFileDataType::encode(StackDepth limit, Encoder& encoder) const
{

  DataTypeSchemaHeader::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::UABinaryFileDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::UABinaryFileDataType::encode(limit, *this, *xml);
  }
}

void UABinaryFileDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::UABinaryFileDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::UABinaryFileDataType::encode_id(limit, ns, *xml);
  }
}

void UABinaryFileDataType::decode(StackDepth limit, Decoder& decoder)
{

  DataTypeSchemaHeader::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::UABinaryFileDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::UABinaryFileDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> UABinaryFileDataType::clone() const
{
  return make_unique<UABinaryFileDataType>(*this);
}

void UABinaryFileDataType::append_fields(std::string& output, int indent) const
{
  DataTypeSchemaHeader::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "schema_location=" + ua::to_string(schema_location());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "file_header=" + ua::to_string(file_header());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "body=" + ua::to_string(body());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "schema_location=" + ua::to_string(schema_location());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "file_header=" + ua::to_string(file_header());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "body=" + ua::to_string(body());
}

std::string UABinaryFileDataType::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void UABinaryFileDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::UABinaryFileDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::UABinaryFileDataType::create);
  }
}

String& UABinaryFileDataType::schema_location()
{
  return mSchemaLocation;
}

const String& UABinaryFileDataType::schema_location() const
{
  return mSchemaLocation;
}

Array<KeyValuePair>& UABinaryFileDataType::file_header()
{
  return mFileHeader;
}

const Array<KeyValuePair>& UABinaryFileDataType::file_header() const
{
  return mFileHeader;
}

Variant& UABinaryFileDataType::body()
{
  return mBody;
}

const Variant& UABinaryFileDataType::body() const
{
  return mBody;
}

BuiltInTypeId UABinaryFileDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::LldpManagementAddressType
{
namespace
{
void encode(StackDepth limit, const ua::LldpManagementAddressType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.address_subtype());
  encoder.encode(limit, value.address());
  encoder.encode(limit, utils::as_int32(value.if_subtype()));
  encoder.encode(limit, value.if_id());
}

void encode(StackDepth limit, const ua::LldpManagementAddressType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "AddressSubtype", value.address_subtype());
  encoder.encode(limit, "Address", value.address());
  encoder.encode(limit, "IfSubtype", utils::as_int32(value.if_subtype()));
  encoder.encode(limit, "IfId", value.if_id());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::LldpManagementAddressType& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.address_subtype());
  decoder.decode(limit, value.address());
  decoder.decode(limit, enumVal);
  value.if_subtype() = utils::from_underlying<ManAddrIfSubtype>(enumVal);
  decoder.decode(limit, value.if_id());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::LldpManagementAddressType& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "AddressSubtype", true, value.address_subtype());
  decoder.decode(limit, "Address", true, value.address());
  decoder.decode(limit, "IfSubtype", true, enumVal);
  value.if_subtype() = utils::from_underlying<ManAddrIfSubtype>(enumVal);
  decoder.decode(limit, "IfId", true, value.if_id());
}
}  // namespace
}  // namespace detail::LldpManagementAddressType

namespace detail::LldpManagementAddressType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::LldpManagementAddressType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::LldpManagementAddressType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::LldpManagementAddressType

namespace detail::LldpManagementAddressType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::LldpManagementAddressType>();
}
}  // namespace
}  // namespace detail::LldpManagementAddressType

bool LldpManagementAddressType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId LldpManagementAddressType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId LldpManagementAddressType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String LldpManagementAddressType::type_name() const
{
  return typeName;
}

void LldpManagementAddressType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::LldpManagementAddressType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::LldpManagementAddressType::encode(limit, *this, *xml);
  }
}

void LldpManagementAddressType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::LldpManagementAddressType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::LldpManagementAddressType::encode_id(limit, ns, *xml);
  }
}

void LldpManagementAddressType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::LldpManagementAddressType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::LldpManagementAddressType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> LldpManagementAddressType::clone() const
{
  return make_unique<LldpManagementAddressType>(*this);
}

void LldpManagementAddressType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "address_subtype=" + ua::to_string(address_subtype());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "address=" + ua::to_string(address());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "if_subtype=" + ua::to_string(utils::as_int32(if_subtype()));
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "if_id=" + ua::to_string(if_id());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "address_subtype=" + ua::to_string(address_subtype());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "address=" + ua::to_string(address());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "if_subtype=" + ua::to_string(utils::as_int32(if_subtype()));
  if (!output.empty())
  {
    output += ", ";
  }
  output += "if_id=" + ua::to_string(if_id());
}

std::string LldpManagementAddressType::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void LldpManagementAddressType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::LldpManagementAddressType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::LldpManagementAddressType::create);
  }
}

uint32_t& LldpManagementAddressType::address_subtype()
{
  return mAddressSubtype;
}

const uint32_t& LldpManagementAddressType::address_subtype() const
{
  return mAddressSubtype;
}

String& LldpManagementAddressType::address()
{
  return mAddress;
}

const String& LldpManagementAddressType::address() const
{
  return mAddress;
}

ManAddrIfSubtype& LldpManagementAddressType::if_subtype()
{
  return mIfSubtype;
}

const ManAddrIfSubtype& LldpManagementAddressType::if_subtype() const
{
  return mIfSubtype;
}

uint32_t& LldpManagementAddressType::if_id()
{
  return mIfId;
}

const uint32_t& LldpManagementAddressType::if_id() const
{
  return mIfId;
}

BuiltInTypeId LldpManagementAddressType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::NameValuePair
{
namespace
{
void encode(StackDepth limit, const ua::NameValuePair& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.name());
  encoder.encode(limit, value.value());
}

void encode(StackDepth limit, const ua::NameValuePair& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Name", value.name());
  encoder.encode(limit, "Value", value.value());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::NameValuePair& value)
{
  decoder.decode(limit, value.name());
  decoder.decode(limit, value.value());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::NameValuePair& value)
{
  decoder.decode(limit, "Name", true, value.name());
  decoder.decode(limit, "Value", true, value.value());
}
}  // namespace
}  // namespace detail::NameValuePair

namespace detail::NameValuePair
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::NameValuePair::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::NameValuePair::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::NameValuePair

namespace detail::NameValuePair
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::NameValuePair>();
}
}  // namespace
}  // namespace detail::NameValuePair

bool NameValuePair::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId NameValuePair::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId NameValuePair::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String NameValuePair::type_name() const
{
  return typeName;
}

void NameValuePair::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::NameValuePair::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::NameValuePair::encode(limit, *this, *xml);
  }
}

void NameValuePair::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::NameValuePair::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::NameValuePair::encode_id(limit, ns, *xml);
  }
}

void NameValuePair::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::NameValuePair::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::NameValuePair::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> NameValuePair::clone() const
{
  return make_unique<NameValuePair>(*this);
}

void NameValuePair::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "name=" + ua::to_string(name());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "value=" + ua::to_string(value());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "name=" + ua::to_string(name());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "value=" + ua::to_string(value());
}

std::string NameValuePair::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void NameValuePair::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::NameValuePair::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::NameValuePair::create);
  }
}

String& NameValuePair::name()
{
  return mName;
}

const String& NameValuePair::name() const
{
  return mName;
}

Variant& NameValuePair::value()
{
  return mValue;
}

const Variant& NameValuePair::value() const
{
  return mValue;
}

BuiltInTypeId NameValuePair::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::EnumField
{
namespace
{
void encode(StackDepth limit, const ua::EnumField& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.name());
}

void encode(StackDepth limit, const ua::EnumField& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Name", value.name());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::EnumField& value)
{
  decoder.decode(limit, value.name());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::EnumField& value)
{
  decoder.decode(limit, "Name", true, value.name());
}
}  // namespace
}  // namespace detail::EnumField

namespace detail::EnumField
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::EnumField::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::EnumField::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::EnumField

namespace detail::EnumField
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::EnumField>();
}
}  // namespace
}  // namespace detail::EnumField

bool EnumField::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return EnumValueType::is_of_type(ns, dataTypeId);
}

NodeId EnumField::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId EnumField::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String EnumField::type_name() const
{
  return typeName;
}

void EnumField::encode(StackDepth limit, Encoder& encoder) const
{

  EnumValueType::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EnumField::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EnumField::encode(limit, *this, *xml);
  }
}

void EnumField::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EnumField::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EnumField::encode_id(limit, ns, *xml);
  }
}

void EnumField::decode(StackDepth limit, Decoder& decoder)
{

  EnumValueType::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::EnumField::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::EnumField::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> EnumField::clone() const
{
  return make_unique<EnumField>(*this);
}

void EnumField::append_fields(std::string& output, int indent) const
{
  EnumValueType::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "name=" + ua::to_string(name());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "name=" + ua::to_string(name());
}

std::string EnumField::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void EnumField::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::EnumField::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::EnumField::create);
  }
}

String& EnumField::name()
{
  return mName;
}

const String& EnumField::name() const
{
  return mName;
}

BuiltInTypeId EnumField::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::DiscoveryConfiguration
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::DiscoveryConfiguration::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::DiscoveryConfiguration::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::DiscoveryConfiguration

namespace detail::DiscoveryConfiguration
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::DiscoveryConfiguration>();
}
}  // namespace
}  // namespace detail::DiscoveryConfiguration

bool DiscoveryConfiguration::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId DiscoveryConfiguration::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId DiscoveryConfiguration::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String DiscoveryConfiguration::type_name() const
{
  return typeName;
}

void DiscoveryConfiguration::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);
}

void DiscoveryConfiguration::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DiscoveryConfiguration::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DiscoveryConfiguration::encode_id(limit, ns, *xml);
  }
}

void DiscoveryConfiguration::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);
}

unique_ptr<Structure> DiscoveryConfiguration::clone() const
{
  return make_unique<DiscoveryConfiguration>(*this);
}

std::string DiscoveryConfiguration::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void DiscoveryConfiguration::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::DiscoveryConfiguration::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::DiscoveryConfiguration::create);
  }
}

BuiltInTypeId DiscoveryConfiguration::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::AddNodesItem
{
namespace
{
void encode(StackDepth limit, const ua::AddNodesItem& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.parent_node_id());
  encoder.encode(limit, value.reference_type_id());
  encoder.encode(limit, value.requested_new_node_id());
  encoder.encode(limit, value.browse_name());
  encoder.encode(limit, utils::as_int32(value.node_class()));
  encoder.encode(limit, value.node_attributes().get());
  encoder.encode(limit, value.type_definition());
}

void encode(StackDepth limit, const ua::AddNodesItem& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ParentNodeId", value.parent_node_id());
  encoder.encode(limit, "ReferenceTypeId", value.reference_type_id());
  encoder.encode(limit, "RequestedNewNodeId", value.requested_new_node_id());
  encoder.encode(limit, "BrowseName", value.browse_name());
  encoder.encode(limit, "NodeClass", utils::as_int32(value.node_class()));
  encoder.encode(limit, "NodeAttributes", value.node_attributes().get());
  encoder.encode(limit, "TypeDefinition", value.type_definition());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::AddNodesItem& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.parent_node_id());
  decoder.decode(limit, value.reference_type_id());
  decoder.decode(limit, value.requested_new_node_id());
  decoder.decode(limit, value.browse_name());
  decoder.decode(limit, enumVal);
  value.node_class() = utils::from_underlying<NodeClass>(enumVal);
  decoder.decode(limit, value.node_attributes().inner_unique_ptr());
  decoder.decode(limit, value.type_definition());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::AddNodesItem& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "ParentNodeId", true, value.parent_node_id());
  decoder.decode(limit, "ReferenceTypeId", true, value.reference_type_id());
  decoder.decode(limit, "RequestedNewNodeId", true, value.requested_new_node_id());
  decoder.decode(limit, "BrowseName", true, value.browse_name());
  decoder.decode(limit, "NodeClass", true, enumVal);
  value.node_class() = utils::from_underlying<NodeClass>(enumVal);
  decoder.decode(limit, "NodeAttributes", true, value.node_attributes().inner_unique_ptr());
  decoder.decode(limit, "TypeDefinition", true, value.type_definition());
}
}  // namespace
}  // namespace detail::AddNodesItem

namespace detail::AddNodesItem
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::AddNodesItem::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::AddNodesItem::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::AddNodesItem

namespace detail::AddNodesItem
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::AddNodesItem>();
}
}  // namespace
}  // namespace detail::AddNodesItem

bool AddNodesItem::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId AddNodesItem::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId AddNodesItem::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String AddNodesItem::type_name() const
{
  return typeName;
}

void AddNodesItem::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AddNodesItem::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AddNodesItem::encode(limit, *this, *xml);
  }
}

void AddNodesItem::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AddNodesItem::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AddNodesItem::encode_id(limit, ns, *xml);
  }
}

void AddNodesItem::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::AddNodesItem::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::AddNodesItem::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> AddNodesItem::clone() const
{
  return make_unique<AddNodesItem>(*this);
}

void AddNodesItem::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "parent_node_id=" + ua::to_string(parent_node_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "reference_type_id=" + ua::to_string(reference_type_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "requested_new_node_id=" + ua::to_string(requested_new_node_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "browse_name=" + ua::to_string(browse_name());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "node_class=" + ua::to_string(utils::as_int32(node_class()));
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "node_attributes=" + (node_attributes() ? node_attributes()->to_string(indent) : "null");
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "type_definition=" + ua::to_string(type_definition());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "parent_node_id=" + ua::to_string(parent_node_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "reference_type_id=" + ua::to_string(reference_type_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "requested_new_node_id=" + ua::to_string(requested_new_node_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "browse_name=" + ua::to_string(browse_name());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "node_class=" + ua::to_string(utils::as_int32(node_class()));
  if (!output.empty())
  {
    output += ", ";
  }
  output += "node_attributes=" + (node_attributes() ? node_attributes()->to_string(0) : "null");
  if (!output.empty())
  {
    output += ", ";
  }
  output += "type_definition=" + ua::to_string(type_definition());
}

std::string AddNodesItem::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void AddNodesItem::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::AddNodesItem::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::AddNodesItem::create);
  }
}

ExpandedNodeId& AddNodesItem::parent_node_id()
{
  return mParentNodeId;
}

const ExpandedNodeId& AddNodesItem::parent_node_id() const
{
  return mParentNodeId;
}

NodeId& AddNodesItem::reference_type_id()
{
  return mReferenceTypeId;
}

const NodeId& AddNodesItem::reference_type_id() const
{
  return mReferenceTypeId;
}

ExpandedNodeId& AddNodesItem::requested_new_node_id()
{
  return mRequestedNewNodeId;
}

const ExpandedNodeId& AddNodesItem::requested_new_node_id() const
{
  return mRequestedNewNodeId;
}

QualifiedName& AddNodesItem::browse_name()
{
  return mBrowseName;
}

const QualifiedName& AddNodesItem::browse_name() const
{
  return mBrowseName;
}

NodeClass& AddNodesItem::node_class()
{
  return mNodeClass;
}

const NodeClass& AddNodesItem::node_class() const
{
  return mNodeClass;
}

RefStructure<Structure>& AddNodesItem::node_attributes()
{
  return mNodeAttributes;
}

const RefStructure<Structure>& AddNodesItem::node_attributes() const
{
  return mNodeAttributes;
}

ExpandedNodeId& AddNodesItem::type_definition()
{
  return mTypeDefinition;
}

const ExpandedNodeId& AddNodesItem::type_definition() const
{
  return mTypeDefinition;
}

BuiltInTypeId AddNodesItem::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ContentFilter
{
namespace
{
void encode(StackDepth limit, const ua::ContentFilter& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.elements());
}

void encode(StackDepth limit, const ua::ContentFilter& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Elements", value.elements());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ContentFilter& value)
{
  decoder.decode(limit, value.elements());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ContentFilter& value)
{
  decoder.decode(limit, "Elements", true, value.elements());
}
}  // namespace
}  // namespace detail::ContentFilter

namespace detail::ContentFilter
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ContentFilter::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ContentFilter::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ContentFilter

namespace detail::ContentFilter
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ContentFilter>();
}
}  // namespace
}  // namespace detail::ContentFilter

bool ContentFilter::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ContentFilter::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ContentFilter::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ContentFilter::type_name() const
{
  return typeName;
}

void ContentFilter::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ContentFilter::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ContentFilter::encode(limit, *this, *xml);
  }
}

void ContentFilter::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ContentFilter::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ContentFilter::encode_id(limit, ns, *xml);
  }
}

void ContentFilter::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ContentFilter::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ContentFilter::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ContentFilter::clone() const
{
  return make_unique<ContentFilter>(*this);
}

void ContentFilter::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "elements=" + ua::to_string(elements());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "elements=" + ua::to_string(elements());
}

std::string ContentFilter::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void ContentFilter::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ContentFilter::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ContentFilter::create);
  }
}

Array<ContentFilterElement>& ContentFilter::elements()
{
  return mElements;
}

const Array<ContentFilterElement>& ContentFilter::elements() const
{
  return mElements;
}

BuiltInTypeId ContentFilter::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::HistoryModifiedEvent
{
namespace
{
void encode(StackDepth limit, const ua::HistoryModifiedEvent& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.modification_infos());
}

void encode(StackDepth limit, const ua::HistoryModifiedEvent& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ModificationInfos", value.modification_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::HistoryModifiedEvent& value)
{
  decoder.decode(limit, value.modification_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::HistoryModifiedEvent& value)
{
  decoder.decode(limit, "ModificationInfos", true, value.modification_infos());
}
}  // namespace
}  // namespace detail::HistoryModifiedEvent

namespace detail::HistoryModifiedEvent
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::HistoryModifiedEvent::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::HistoryModifiedEvent::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::HistoryModifiedEvent

namespace detail::HistoryModifiedEvent
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::HistoryModifiedEvent>();
}
}  // namespace
}  // namespace detail::HistoryModifiedEvent

bool HistoryModifiedEvent::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return HistoryEvent::is_of_type(ns, dataTypeId);
}

NodeId HistoryModifiedEvent::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId HistoryModifiedEvent::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String HistoryModifiedEvent::type_name() const
{
  return typeName;
}

void HistoryModifiedEvent::encode(StackDepth limit, Encoder& encoder) const
{

  HistoryEvent::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::HistoryModifiedEvent::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::HistoryModifiedEvent::encode(limit, *this, *xml);
  }
}

void HistoryModifiedEvent::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::HistoryModifiedEvent::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::HistoryModifiedEvent::encode_id(limit, ns, *xml);
  }
}

void HistoryModifiedEvent::decode(StackDepth limit, Decoder& decoder)
{

  HistoryEvent::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::HistoryModifiedEvent::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::HistoryModifiedEvent::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> HistoryModifiedEvent::clone() const
{
  return make_unique<HistoryModifiedEvent>(*this);
}

void HistoryModifiedEvent::append_fields(std::string& output, int indent) const
{
  HistoryEvent::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "modification_infos=" + ua::to_string(modification_infos());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "modification_infos=" + ua::to_string(modification_infos());
}

std::string HistoryModifiedEvent::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void HistoryModifiedEvent::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::HistoryModifiedEvent::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::HistoryModifiedEvent::create);
  }
}

Array<ModificationInfo>& HistoryModifiedEvent::modification_infos()
{
  return mModificationInfos;
}

const Array<ModificationInfo>& HistoryModifiedEvent::modification_infos() const
{
  return mModificationInfos;
}

BuiltInTypeId HistoryModifiedEvent::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::NetworkGroupDataType
{
namespace
{
void encode(StackDepth limit, const ua::NetworkGroupDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.server_uri());
  encoder.encode(limit, value.network_paths());
}

void encode(StackDepth limit, const ua::NetworkGroupDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ServerUri", value.server_uri());
  encoder.encode(limit, "NetworkPaths", value.network_paths());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::NetworkGroupDataType& value)
{
  decoder.decode(limit, value.server_uri());
  decoder.decode(limit, value.network_paths());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::NetworkGroupDataType& value)
{
  decoder.decode(limit, "ServerUri", true, value.server_uri());
  decoder.decode(limit, "NetworkPaths", true, value.network_paths());
}
}  // namespace
}  // namespace detail::NetworkGroupDataType

namespace detail::NetworkGroupDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::NetworkGroupDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::NetworkGroupDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::NetworkGroupDataType

namespace detail::NetworkGroupDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::NetworkGroupDataType>();
}
}  // namespace
}  // namespace detail::NetworkGroupDataType

bool NetworkGroupDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId NetworkGroupDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId NetworkGroupDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String NetworkGroupDataType::type_name() const
{
  return typeName;
}

void NetworkGroupDataType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::NetworkGroupDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::NetworkGroupDataType::encode(limit, *this, *xml);
  }
}

void NetworkGroupDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::NetworkGroupDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::NetworkGroupDataType::encode_id(limit, ns, *xml);
  }
}

void NetworkGroupDataType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::NetworkGroupDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::NetworkGroupDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> NetworkGroupDataType::clone() const
{
  return make_unique<NetworkGroupDataType>(*this);
}

void NetworkGroupDataType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "server_uri=" + ua::to_string(server_uri());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "network_paths=" + ua::to_string(network_paths());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "server_uri=" + ua::to_string(server_uri());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "network_paths=" + ua::to_string(network_paths());
}

std::string NetworkGroupDataType::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void NetworkGroupDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::NetworkGroupDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::NetworkGroupDataType::create);
  }
}

String& NetworkGroupDataType::server_uri()
{
  return mServerUri;
}

const String& NetworkGroupDataType::server_uri() const
{
  return mServerUri;
}

Array<EndpointUrlListDataType>& NetworkGroupDataType::network_paths()
{
  return mNetworkPaths;
}

const Array<EndpointUrlListDataType>& NetworkGroupDataType::network_paths() const
{
  return mNetworkPaths;
}

BuiltInTypeId NetworkGroupDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::SubscriptionDiagnosticsDataType
{
namespace
{
void encode(StackDepth limit, const ua::SubscriptionDiagnosticsDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.session_id());
  encoder.encode(limit, value.subscription_id());
  encoder.encode(limit, value.priority());
  encoder.encode(limit, value.publishing_interval());
  encoder.encode(limit, value.max_keep_alive_count());
  encoder.encode(limit, value.max_lifetime_count());
  encoder.encode(limit, value.max_notifications_per_publish());
  encoder.encode(limit, value.publishing_enabled());
  encoder.encode(limit, value.modify_count());
  encoder.encode(limit, value.enable_count());
  encoder.encode(limit, value.disable_count());
  encoder.encode(limit, value.republish_request_count());
  encoder.encode(limit, value.republish_message_request_count());
  encoder.encode(limit, value.republish_message_count());
  encoder.encode(limit, value.transfer_request_count());
  encoder.encode(limit, value.transferred_to_alt_client_count());
  encoder.encode(limit, value.transferred_to_same_client_count());
  encoder.encode(limit, value.publish_request_count());
  encoder.encode(limit, value.data_change_notifications_count());
  encoder.encode(limit, value.event_notifications_count());
  encoder.encode(limit, value.notifications_count());
  encoder.encode(limit, value.late_publish_request_count());
  encoder.encode(limit, value.current_keep_alive_count());
  encoder.encode(limit, value.current_lifetime_count());
  encoder.encode(limit, value.unacknowledged_message_count());
  encoder.encode(limit, value.discarded_message_count());
  encoder.encode(limit, value.monitored_item_count());
  encoder.encode(limit, value.disabled_monitored_item_count());
  encoder.encode(limit, value.monitoring_queue_overflow_count());
  encoder.encode(limit, value.next_sequence_number());
  encoder.encode(limit, value.event_queue_overflow_count());
}

void encode(StackDepth limit, const ua::SubscriptionDiagnosticsDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "SessionId", value.session_id());
  encoder.encode(limit, "SubscriptionId", value.subscription_id());
  encoder.encode(limit, "Priority", value.priority());
  encoder.encode(limit, "PublishingInterval", value.publishing_interval());
  encoder.encode(limit, "MaxKeepAliveCount", value.max_keep_alive_count());
  encoder.encode(limit, "MaxLifetimeCount", value.max_lifetime_count());
  encoder.encode(limit, "MaxNotificationsPerPublish", value.max_notifications_per_publish());
  encoder.encode(limit, "PublishingEnabled", value.publishing_enabled());
  encoder.encode(limit, "ModifyCount", value.modify_count());
  encoder.encode(limit, "EnableCount", value.enable_count());
  encoder.encode(limit, "DisableCount", value.disable_count());
  encoder.encode(limit, "RepublishRequestCount", value.republish_request_count());
  encoder.encode(limit, "RepublishMessageRequestCount", value.republish_message_request_count());
  encoder.encode(limit, "RepublishMessageCount", value.republish_message_count());
  encoder.encode(limit, "TransferRequestCount", value.transfer_request_count());
  encoder.encode(limit, "TransferredToAltClientCount", value.transferred_to_alt_client_count());
  encoder.encode(limit, "TransferredToSameClientCount", value.transferred_to_same_client_count());
  encoder.encode(limit, "PublishRequestCount", value.publish_request_count());
  encoder.encode(limit, "DataChangeNotificationsCount", value.data_change_notifications_count());
  encoder.encode(limit, "EventNotificationsCount", value.event_notifications_count());
  encoder.encode(limit, "NotificationsCount", value.notifications_count());
  encoder.encode(limit, "LatePublishRequestCount", value.late_publish_request_count());
  encoder.encode(limit, "CurrentKeepAliveCount", value.current_keep_alive_count());
  encoder.encode(limit, "CurrentLifetimeCount", value.current_lifetime_count());
  encoder.encode(limit, "UnacknowledgedMessageCount", value.unacknowledged_message_count());
  encoder.encode(limit, "DiscardedMessageCount", value.discarded_message_count());
  encoder.encode(limit, "MonitoredItemCount", value.monitored_item_count());
  encoder.encode(limit, "DisabledMonitoredItemCount", value.disabled_monitored_item_count());
  encoder.encode(limit, "MonitoringQueueOverflowCount", value.monitoring_queue_overflow_count());
  encoder.encode(limit, "NextSequenceNumber", value.next_sequence_number());
  encoder.encode(limit, "EventQueueOverflowCount", value.event_queue_overflow_count());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::SubscriptionDiagnosticsDataType& value)
{
  decoder.decode(limit, value.session_id());
  decoder.decode(limit, value.subscription_id());
  decoder.decode(limit, value.priority());
  decoder.decode(limit, value.publishing_interval());
  decoder.decode(limit, value.max_keep_alive_count());
  decoder.decode(limit, value.max_lifetime_count());
  decoder.decode(limit, value.max_notifications_per_publish());
  decoder.decode(limit, value.publishing_enabled());
  decoder.decode(limit, value.modify_count());
  decoder.decode(limit, value.enable_count());
  decoder.decode(limit, value.disable_count());
  decoder.decode(limit, value.republish_request_count());
  decoder.decode(limit, value.republish_message_request_count());
  decoder.decode(limit, value.republish_message_count());
  decoder.decode(limit, value.transfer_request_count());
  decoder.decode(limit, value.transferred_to_alt_client_count());
  decoder.decode(limit, value.transferred_to_same_client_count());
  decoder.decode(limit, value.publish_request_count());
  decoder.decode(limit, value.data_change_notifications_count());
  decoder.decode(limit, value.event_notifications_count());
  decoder.decode(limit, value.notifications_count());
  decoder.decode(limit, value.late_publish_request_count());
  decoder.decode(limit, value.current_keep_alive_count());
  decoder.decode(limit, value.current_lifetime_count());
  decoder.decode(limit, value.unacknowledged_message_count());
  decoder.decode(limit, value.discarded_message_count());
  decoder.decode(limit, value.monitored_item_count());
  decoder.decode(limit, value.disabled_monitored_item_count());
  decoder.decode(limit, value.monitoring_queue_overflow_count());
  decoder.decode(limit, value.next_sequence_number());
  decoder.decode(limit, value.event_queue_overflow_count());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::SubscriptionDiagnosticsDataType& value)
{
  decoder.decode(limit, "SessionId", true, value.session_id());
  decoder.decode(limit, "SubscriptionId", true, value.subscription_id());
  decoder.decode(limit, "Priority", true, value.priority());
  decoder.decode(limit, "PublishingInterval", true, value.publishing_interval());
  decoder.decode(limit, "MaxKeepAliveCount", true, value.max_keep_alive_count());
  decoder.decode(limit, "MaxLifetimeCount", true, value.max_lifetime_count());
  decoder.decode(limit, "MaxNotificationsPerPublish", true, value.max_notifications_per_publish());
  decoder.decode(limit, "PublishingEnabled", true, value.publishing_enabled());
  decoder.decode(limit, "ModifyCount", true, value.modify_count());
  decoder.decode(limit, "EnableCount", true, value.enable_count());
  decoder.decode(limit, "DisableCount", true, value.disable_count());
  decoder.decode(limit, "RepublishRequestCount", true, value.republish_request_count());
  decoder.decode(limit, "RepublishMessageRequestCount", true, value.republish_message_request_count());
  decoder.decode(limit, "RepublishMessageCount", true, value.republish_message_count());
  decoder.decode(limit, "TransferRequestCount", true, value.transfer_request_count());
  decoder.decode(limit, "TransferredToAltClientCount", true, value.transferred_to_alt_client_count());
  decoder.decode(limit, "TransferredToSameClientCount", true, value.transferred_to_same_client_count());
  decoder.decode(limit, "PublishRequestCount", true, value.publish_request_count());
  decoder.decode(limit, "DataChangeNotificationsCount", true, value.data_change_notifications_count());
  decoder.decode(limit, "EventNotificationsCount", true, value.event_notifications_count());
  decoder.decode(limit, "NotificationsCount", true, value.notifications_count());
  decoder.decode(limit, "LatePublishRequestCount", true, value.late_publish_request_count());
  decoder.decode(limit, "CurrentKeepAliveCount", true, value.current_keep_alive_count());
  decoder.decode(limit, "CurrentLifetimeCount", true, value.current_lifetime_count());
  decoder.decode(limit, "UnacknowledgedMessageCount", true, value.unacknowledged_message_count());
  decoder.decode(limit, "DiscardedMessageCount", true, value.discarded_message_count());
  decoder.decode(limit, "MonitoredItemCount", true, value.monitored_item_count());
  decoder.decode(limit, "DisabledMonitoredItemCount", true, value.disabled_monitored_item_count());
  decoder.decode(limit, "MonitoringQueueOverflowCount", true, value.monitoring_queue_overflow_count());
  decoder.decode(limit, "NextSequenceNumber", true, value.next_sequence_number());
  decoder.decode(limit, "EventQueueOverflowCount", true, value.event_queue_overflow_count());
}
}  // namespace
}  // namespace detail::SubscriptionDiagnosticsDataType

namespace detail::SubscriptionDiagnosticsDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::SubscriptionDiagnosticsDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::SubscriptionDiagnosticsDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::SubscriptionDiagnosticsDataType

namespace detail::SubscriptionDiagnosticsDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::SubscriptionDiagnosticsDataType>();
}
}  // namespace
}  // namespace detail::SubscriptionDiagnosticsDataType

bool SubscriptionDiagnosticsDataType::is_of_type(
  const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId SubscriptionDiagnosticsDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId SubscriptionDiagnosticsDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String SubscriptionDiagnosticsDataType::type_name() const
{
  return typeName;
}

void SubscriptionDiagnosticsDataType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SubscriptionDiagnosticsDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SubscriptionDiagnosticsDataType::encode(limit, *this, *xml);
  }
}

void SubscriptionDiagnosticsDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SubscriptionDiagnosticsDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SubscriptionDiagnosticsDataType::encode_id(limit, ns, *xml);
  }
}

void SubscriptionDiagnosticsDataType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::SubscriptionDiagnosticsDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::SubscriptionDiagnosticsDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> SubscriptionDiagnosticsDataType::clone() const
{
  return make_unique<SubscriptionDiagnosticsDataType>(*this);
}

void SubscriptionDiagnosticsDataType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "session_id=" + ua::to_string(session_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "subscription_id=" + ua::to_string(subscription_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "priority=" + ua::to_string(priority());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "publishing_interval=" + ua::to_string(publishing_interval());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "max_keep_alive_count=" + ua::to_string(max_keep_alive_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "max_lifetime_count=" + ua::to_string(max_lifetime_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "max_notifications_per_publish=" + ua::to_string(max_notifications_per_publish());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "publishing_enabled=" + ua::to_string(publishing_enabled());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "modify_count=" + ua::to_string(modify_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "enable_count=" + ua::to_string(enable_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "disable_count=" + ua::to_string(disable_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "republish_request_count=" + ua::to_string(republish_request_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "republish_message_request_count=" + ua::to_string(republish_message_request_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "republish_message_count=" + ua::to_string(republish_message_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "transfer_request_count=" + ua::to_string(transfer_request_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "transferred_to_alt_client_count=" + ua::to_string(transferred_to_alt_client_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "transferred_to_same_client_count=" + ua::to_string(transferred_to_same_client_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "publish_request_count=" + ua::to_string(publish_request_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "data_change_notifications_count=" + ua::to_string(data_change_notifications_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "event_notifications_count=" + ua::to_string(event_notifications_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "notifications_count=" + ua::to_string(notifications_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "late_publish_request_count=" + ua::to_string(late_publish_request_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "current_keep_alive_count=" + ua::to_string(current_keep_alive_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "current_lifetime_count=" + ua::to_string(current_lifetime_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "unacknowledged_message_count=" + ua::to_string(unacknowledged_message_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "discarded_message_count=" + ua::to_string(discarded_message_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "monitored_item_count=" + ua::to_string(monitored_item_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "disabled_monitored_item_count=" + ua::to_string(disabled_monitored_item_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "monitoring_queue_overflow_count=" + ua::to_string(monitoring_queue_overflow_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "next_sequence_number=" + ua::to_string(next_sequence_number());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "event_queue_overflow_count=" + ua::to_string(event_queue_overflow_count());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "session_id=" + ua::to_string(session_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "subscription_id=" + ua::to_string(subscription_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "priority=" + ua::to_string(priority());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "publishing_interval=" + ua::to_string(publishing_interval());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "max_keep_alive_count=" + ua::to_string(max_keep_alive_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "max_lifetime_count=" + ua::to_string(max_lifetime_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "max_notifications_per_publish=" + ua::to_string(max_notifications_per_publish());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "publishing_enabled=" + ua::to_string(publishing_enabled());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "modify_count=" + ua::to_string(modify_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "enable_count=" + ua::to_string(enable_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "disable_count=" + ua::to_string(disable_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "republish_request_count=" + ua::to_string(republish_request_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "republish_message_request_count=" + ua::to_string(republish_message_request_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "republish_message_count=" + ua::to_string(republish_message_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "transfer_request_count=" + ua::to_string(transfer_request_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "transferred_to_alt_client_count=" + ua::to_string(transferred_to_alt_client_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "transferred_to_same_client_count=" + ua::to_string(transferred_to_same_client_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "publish_request_count=" + ua::to_string(publish_request_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "data_change_notifications_count=" + ua::to_string(data_change_notifications_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "event_notifications_count=" + ua::to_string(event_notifications_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "notifications_count=" + ua::to_string(notifications_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "late_publish_request_count=" + ua::to_string(late_publish_request_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "current_keep_alive_count=" + ua::to_string(current_keep_alive_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "current_lifetime_count=" + ua::to_string(current_lifetime_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "unacknowledged_message_count=" + ua::to_string(unacknowledged_message_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "discarded_message_count=" + ua::to_string(discarded_message_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "monitored_item_count=" + ua::to_string(monitored_item_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "disabled_monitored_item_count=" + ua::to_string(disabled_monitored_item_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "monitoring_queue_overflow_count=" + ua::to_string(monitoring_queue_overflow_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "next_sequence_number=" + ua::to_string(next_sequence_number());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "event_queue_overflow_count=" + ua::to_string(event_queue_overflow_count());
}

std::string SubscriptionDiagnosticsDataType::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void SubscriptionDiagnosticsDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::SubscriptionDiagnosticsDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::SubscriptionDiagnosticsDataType::create);
  }
}

NodeId& SubscriptionDiagnosticsDataType::session_id()
{
  return mSessionId;
}

const NodeId& SubscriptionDiagnosticsDataType::session_id() const
{
  return mSessionId;
}

uint32_t& SubscriptionDiagnosticsDataType::subscription_id()
{
  return mSubscriptionId;
}

const uint32_t& SubscriptionDiagnosticsDataType::subscription_id() const
{
  return mSubscriptionId;
}

uint8_t& SubscriptionDiagnosticsDataType::priority()
{
  return mPriority;
}

const uint8_t& SubscriptionDiagnosticsDataType::priority() const
{
  return mPriority;
}

Duration& SubscriptionDiagnosticsDataType::publishing_interval()
{
  return mPublishingInterval;
}

const Duration& SubscriptionDiagnosticsDataType::publishing_interval() const
{
  return mPublishingInterval;
}

uint32_t& SubscriptionDiagnosticsDataType::max_keep_alive_count()
{
  return mMaxKeepAliveCount;
}

const uint32_t& SubscriptionDiagnosticsDataType::max_keep_alive_count() const
{
  return mMaxKeepAliveCount;
}

uint32_t& SubscriptionDiagnosticsDataType::max_lifetime_count()
{
  return mMaxLifetimeCount;
}

const uint32_t& SubscriptionDiagnosticsDataType::max_lifetime_count() const
{
  return mMaxLifetimeCount;
}

uint32_t& SubscriptionDiagnosticsDataType::max_notifications_per_publish()
{
  return mMaxNotificationsPerPublish;
}

const uint32_t& SubscriptionDiagnosticsDataType::max_notifications_per_publish() const
{
  return mMaxNotificationsPerPublish;
}

bool& SubscriptionDiagnosticsDataType::publishing_enabled()
{
  return mPublishingEnabled;
}

const bool& SubscriptionDiagnosticsDataType::publishing_enabled() const
{
  return mPublishingEnabled;
}

uint32_t& SubscriptionDiagnosticsDataType::modify_count()
{
  return mModifyCount;
}

const uint32_t& SubscriptionDiagnosticsDataType::modify_count() const
{
  return mModifyCount;
}

uint32_t& SubscriptionDiagnosticsDataType::enable_count()
{
  return mEnableCount;
}

const uint32_t& SubscriptionDiagnosticsDataType::enable_count() const
{
  return mEnableCount;
}

uint32_t& SubscriptionDiagnosticsDataType::disable_count()
{
  return mDisableCount;
}

const uint32_t& SubscriptionDiagnosticsDataType::disable_count() const
{
  return mDisableCount;
}

uint32_t& SubscriptionDiagnosticsDataType::republish_request_count()
{
  return mRepublishRequestCount;
}

const uint32_t& SubscriptionDiagnosticsDataType::republish_request_count() const
{
  return mRepublishRequestCount;
}

uint32_t& SubscriptionDiagnosticsDataType::republish_message_request_count()
{
  return mRepublishMessageRequestCount;
}

const uint32_t& SubscriptionDiagnosticsDataType::republish_message_request_count() const
{
  return mRepublishMessageRequestCount;
}

uint32_t& SubscriptionDiagnosticsDataType::republish_message_count()
{
  return mRepublishMessageCount;
}

const uint32_t& SubscriptionDiagnosticsDataType::republish_message_count() const
{
  return mRepublishMessageCount;
}

uint32_t& SubscriptionDiagnosticsDataType::transfer_request_count()
{
  return mTransferRequestCount;
}

const uint32_t& SubscriptionDiagnosticsDataType::transfer_request_count() const
{
  return mTransferRequestCount;
}

uint32_t& SubscriptionDiagnosticsDataType::transferred_to_alt_client_count()
{
  return mTransferredToAltClientCount;
}

const uint32_t& SubscriptionDiagnosticsDataType::transferred_to_alt_client_count() const
{
  return mTransferredToAltClientCount;
}

uint32_t& SubscriptionDiagnosticsDataType::transferred_to_same_client_count()
{
  return mTransferredToSameClientCount;
}

const uint32_t& SubscriptionDiagnosticsDataType::transferred_to_same_client_count() const
{
  return mTransferredToSameClientCount;
}

uint32_t& SubscriptionDiagnosticsDataType::publish_request_count()
{
  return mPublishRequestCount;
}

const uint32_t& SubscriptionDiagnosticsDataType::publish_request_count() const
{
  return mPublishRequestCount;
}

uint32_t& SubscriptionDiagnosticsDataType::data_change_notifications_count()
{
  return mDataChangeNotificationsCount;
}

const uint32_t& SubscriptionDiagnosticsDataType::data_change_notifications_count() const
{
  return mDataChangeNotificationsCount;
}

uint32_t& SubscriptionDiagnosticsDataType::event_notifications_count()
{
  return mEventNotificationsCount;
}

const uint32_t& SubscriptionDiagnosticsDataType::event_notifications_count() const
{
  return mEventNotificationsCount;
}

uint32_t& SubscriptionDiagnosticsDataType::notifications_count()
{
  return mNotificationsCount;
}

const uint32_t& SubscriptionDiagnosticsDataType::notifications_count() const
{
  return mNotificationsCount;
}

uint32_t& SubscriptionDiagnosticsDataType::late_publish_request_count()
{
  return mLatePublishRequestCount;
}

const uint32_t& SubscriptionDiagnosticsDataType::late_publish_request_count() const
{
  return mLatePublishRequestCount;
}

uint32_t& SubscriptionDiagnosticsDataType::current_keep_alive_count()
{
  return mCurrentKeepAliveCount;
}

const uint32_t& SubscriptionDiagnosticsDataType::current_keep_alive_count() const
{
  return mCurrentKeepAliveCount;
}

uint32_t& SubscriptionDiagnosticsDataType::current_lifetime_count()
{
  return mCurrentLifetimeCount;
}

const uint32_t& SubscriptionDiagnosticsDataType::current_lifetime_count() const
{
  return mCurrentLifetimeCount;
}

uint32_t& SubscriptionDiagnosticsDataType::unacknowledged_message_count()
{
  return mUnacknowledgedMessageCount;
}

const uint32_t& SubscriptionDiagnosticsDataType::unacknowledged_message_count() const
{
  return mUnacknowledgedMessageCount;
}

uint32_t& SubscriptionDiagnosticsDataType::discarded_message_count()
{
  return mDiscardedMessageCount;
}

const uint32_t& SubscriptionDiagnosticsDataType::discarded_message_count() const
{
  return mDiscardedMessageCount;
}

uint32_t& SubscriptionDiagnosticsDataType::monitored_item_count()
{
  return mMonitoredItemCount;
}

const uint32_t& SubscriptionDiagnosticsDataType::monitored_item_count() const
{
  return mMonitoredItemCount;
}

uint32_t& SubscriptionDiagnosticsDataType::disabled_monitored_item_count()
{
  return mDisabledMonitoredItemCount;
}

const uint32_t& SubscriptionDiagnosticsDataType::disabled_monitored_item_count() const
{
  return mDisabledMonitoredItemCount;
}

uint32_t& SubscriptionDiagnosticsDataType::monitoring_queue_overflow_count()
{
  return mMonitoringQueueOverflowCount;
}

const uint32_t& SubscriptionDiagnosticsDataType::monitoring_queue_overflow_count() const
{
  return mMonitoringQueueOverflowCount;
}

uint32_t& SubscriptionDiagnosticsDataType::next_sequence_number()
{
  return mNextSequenceNumber;
}

const uint32_t& SubscriptionDiagnosticsDataType::next_sequence_number() const
{
  return mNextSequenceNumber;
}

uint32_t& SubscriptionDiagnosticsDataType::event_queue_overflow_count()
{
  return mEventQueueOverflowCount;
}

const uint32_t& SubscriptionDiagnosticsDataType::event_queue_overflow_count() const
{
  return mEventQueueOverflowCount;
}

BuiltInTypeId SubscriptionDiagnosticsDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::XVType
{
namespace
{
void encode(StackDepth limit, const ua::XVType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.x());
  encoder.encode(limit, value.value());
}

void encode(StackDepth limit, const ua::XVType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "X", value.x());
  encoder.encode(limit, "Value", value.value());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::XVType& value)
{
  decoder.decode(limit, value.x());
  decoder.decode(limit, value.value());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::XVType& value)
{
  decoder.decode(limit, "X", true, value.x());
  decoder.decode(limit, "Value", true, value.value());
}
}  // namespace
}  // namespace detail::XVType

namespace detail::XVType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::XVType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::XVType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::XVType

namespace detail::XVType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::XVType>();
}
}  // namespace
}  // namespace detail::XVType

bool XVType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId XVType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId XVType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String XVType::type_name() const
{
  return typeName;
}

void XVType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::XVType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::XVType::encode(limit, *this, *xml);
  }
}

void XVType::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::XVType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::XVType::encode_id(limit, ns, *xml);
  }
}

void XVType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::XVType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::XVType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> XVType::clone() const
{
  return make_unique<XVType>(*this);
}

void XVType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "x=" + ua::to_string(x());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "value=" + ua::to_string(value());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "x=" + ua::to_string(x());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "value=" + ua::to_string(value());
}

std::string XVType::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void XVType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::XVType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::XVType::create);
  }
}

double& XVType::x()
{
  return mX;
}

const double& XVType::x() const
{
  return mX;
}

float& XVType::value()
{
  return mValue;
}

const float& XVType::value() const
{
  return mValue;
}

BuiltInTypeId XVType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::SessionlessInvokeRequestType
{
namespace
{
void encode(StackDepth limit, const ua::SessionlessInvokeRequestType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.uris_version());
  encoder.encode(limit, value.namespace_uris());
  encoder.encode(limit, value.server_uris());
  encoder.encode(limit, value.locale_ids());
  encoder.encode(limit, value.service_id());
}

void encode(StackDepth limit, const ua::SessionlessInvokeRequestType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "UrisVersion", value.uris_version());
  encoder.encode(limit, "NamespaceUris", value.namespace_uris());
  encoder.encode(limit, "ServerUris", value.server_uris());
  encoder.encode(limit, "LocaleIds", value.locale_ids());
  encoder.encode(limit, "ServiceId", value.service_id());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::SessionlessInvokeRequestType& value)
{
  decoder.decode(limit, value.uris_version());
  decoder.decode(limit, value.namespace_uris());
  decoder.decode(limit, value.server_uris());
  decoder.decode(limit, value.locale_ids());
  decoder.decode(limit, value.service_id());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::SessionlessInvokeRequestType& value)
{
  decoder.decode(limit, "UrisVersion", true, value.uris_version());
  decoder.decode(limit, "NamespaceUris", true, value.namespace_uris());
  decoder.decode(limit, "ServerUris", true, value.server_uris());
  decoder.decode(limit, "LocaleIds", true, value.locale_ids());
  decoder.decode(limit, "ServiceId", true, value.service_id());
}
}  // namespace
}  // namespace detail::SessionlessInvokeRequestType

namespace detail::SessionlessInvokeRequestType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::SessionlessInvokeRequestType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::SessionlessInvokeRequestType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::SessionlessInvokeRequestType

namespace detail::SessionlessInvokeRequestType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::SessionlessInvokeRequestType>();
}
}  // namespace
}  // namespace detail::SessionlessInvokeRequestType

bool SessionlessInvokeRequestType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId SessionlessInvokeRequestType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId SessionlessInvokeRequestType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String SessionlessInvokeRequestType::type_name() const
{
  return typeName;
}

void SessionlessInvokeRequestType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SessionlessInvokeRequestType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SessionlessInvokeRequestType::encode(limit, *this, *xml);
  }
}

void SessionlessInvokeRequestType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SessionlessInvokeRequestType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SessionlessInvokeRequestType::encode_id(limit, ns, *xml);
  }
}

void SessionlessInvokeRequestType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::SessionlessInvokeRequestType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::SessionlessInvokeRequestType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> SessionlessInvokeRequestType::clone() const
{
  return make_unique<SessionlessInvokeRequestType>(*this);
}

void SessionlessInvokeRequestType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "uris_version=" + ua::to_string(uris_version());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "namespace_uris=" + ua::to_string(namespace_uris());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "server_uris=" + ua::to_string(server_uris());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "locale_ids=" + ua::to_string(locale_ids());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "service_id=" + ua::to_string(service_id());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "uris_version=" + ua::to_string(uris_version());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "namespace_uris=" + ua::to_string(namespace_uris());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "server_uris=" + ua::to_string(server_uris());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "locale_ids=" + ua::to_string(locale_ids());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "service_id=" + ua::to_string(service_id());
}

std::string SessionlessInvokeRequestType::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void SessionlessInvokeRequestType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::SessionlessInvokeRequestType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::SessionlessInvokeRequestType::create);
  }
}

VersionTime& SessionlessInvokeRequestType::uris_version()
{
  return mUrisVersion;
}

const VersionTime& SessionlessInvokeRequestType::uris_version() const
{
  return mUrisVersion;
}

Array<String>& SessionlessInvokeRequestType::namespace_uris()
{
  return mNamespaceUris;
}

const Array<String>& SessionlessInvokeRequestType::namespace_uris() const
{
  return mNamespaceUris;
}

Array<String>& SessionlessInvokeRequestType::server_uris()
{
  return mServerUris;
}

const Array<String>& SessionlessInvokeRequestType::server_uris() const
{
  return mServerUris;
}

Array<LocaleId>& SessionlessInvokeRequestType::locale_ids()
{
  return mLocaleIds;
}

const Array<LocaleId>& SessionlessInvokeRequestType::locale_ids() const
{
  return mLocaleIds;
}

uint32_t& SessionlessInvokeRequestType::service_id()
{
  return mServiceId;
}

const uint32_t& SessionlessInvokeRequestType::service_id() const
{
  return mServiceId;
}

BuiltInTypeId SessionlessInvokeRequestType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::RegisterServerRequest
{
namespace
{
void encode(StackDepth limit, const ua::RegisterServerRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.server());
}

void encode(StackDepth limit, const ua::RegisterServerRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "Server", value.server());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::RegisterServerRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.server());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::RegisterServerRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "Server", true, value.server());
}
}  // namespace
}  // namespace detail::RegisterServerRequest

namespace detail::RegisterServerRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::RegisterServerRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::RegisterServerRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::RegisterServerRequest

namespace detail::RegisterServerRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::RegisterServerRequest>();
}
}  // namespace
}  // namespace detail::RegisterServerRequest

bool RegisterServerRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId RegisterServerRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId RegisterServerRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String RegisterServerRequest::type_name() const
{
  return typeName;
}

void RegisterServerRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RegisterServerRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RegisterServerRequest::encode(limit, *this, *xml);
  }
}

void RegisterServerRequest::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RegisterServerRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RegisterServerRequest::encode_id(limit, ns, *xml);
  }
}

void RegisterServerRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::RegisterServerRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::RegisterServerRequest::decode(limit, *xml, *this);
  }
}

void RegisterServerRequest::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  mServer.resolve(locales);
}

unique_ptr<Structure> RegisterServerRequest::clone() const
{
  return make_unique<RegisterServerRequest>(*this);
}

void RegisterServerRequest::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "request_header=" + ua::to_string(request_header());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "server=" + ua::to_string(server());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "request_header=" + ua::to_string(request_header());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "server=" + ua::to_string(server());
}

std::string RegisterServerRequest::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void RegisterServerRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::RegisterServerRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::RegisterServerRequest::create);
  }
}

RequestHeader& RegisterServerRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& RegisterServerRequest::request_header() const
{
  return mRequestHeader;
}

RegisteredServer& RegisterServerRequest::server()
{
  return mServer;
}

const RegisteredServer& RegisterServerRequest::server() const
{
  return mServer;
}

BuiltInTypeId RegisterServerRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::CloseSecureChannelResponse
{
namespace
{
void encode(StackDepth limit, const ua::CloseSecureChannelResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
}

void encode(StackDepth limit, const ua::CloseSecureChannelResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::CloseSecureChannelResponse& value)
{
  decoder.decode(limit, value.response_header());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::CloseSecureChannelResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
}
}  // namespace
}  // namespace detail::CloseSecureChannelResponse

namespace detail::CloseSecureChannelResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::CloseSecureChannelResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::CloseSecureChannelResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::CloseSecureChannelResponse

namespace detail::CloseSecureChannelResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::CloseSecureChannelResponse>();
}
}  // namespace
}  // namespace detail::CloseSecureChannelResponse

bool CloseSecureChannelResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId CloseSecureChannelResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId CloseSecureChannelResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String CloseSecureChannelResponse::type_name() const
{
  return typeName;
}

void CloseSecureChannelResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CloseSecureChannelResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CloseSecureChannelResponse::encode(limit, *this, *xml);
  }
}

void CloseSecureChannelResponse::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CloseSecureChannelResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CloseSecureChannelResponse::encode_id(limit, ns, *xml);
  }
}

void CloseSecureChannelResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::CloseSecureChannelResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::CloseSecureChannelResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> CloseSecureChannelResponse::clone() const
{
  return make_unique<CloseSecureChannelResponse>(*this);
}

void CloseSecureChannelResponse::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "response_header=" + ua::to_string(response_header());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "response_header=" + ua::to_string(response_header());
}

std::string CloseSecureChannelResponse::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void CloseSecureChannelResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::CloseSecureChannelResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::CloseSecureChannelResponse::create);
  }
}

ResponseHeader& CloseSecureChannelResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& CloseSecureChannelResponse::response_header() const
{
  return mResponseHeader;
}

BuiltInTypeId CloseSecureChannelResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::CancelRequest
{
namespace
{
void encode(StackDepth limit, const ua::CancelRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.request_handle());
}

void encode(StackDepth limit, const ua::CancelRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "RequestHandle", value.request_handle());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::CancelRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.request_handle());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::CancelRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "RequestHandle", true, value.request_handle());
}
}  // namespace
}  // namespace detail::CancelRequest

namespace detail::CancelRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::CancelRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::CancelRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::CancelRequest

namespace detail::CancelRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::CancelRequest>();
}
}  // namespace
}  // namespace detail::CancelRequest

bool CancelRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId CancelRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId CancelRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String CancelRequest::type_name() const
{
  return typeName;
}

void CancelRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CancelRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CancelRequest::encode(limit, *this, *xml);
  }
}

void CancelRequest::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CancelRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CancelRequest::encode_id(limit, ns, *xml);
  }
}

void CancelRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::CancelRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::CancelRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> CancelRequest::clone() const
{
  return make_unique<CancelRequest>(*this);
}

void CancelRequest::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "request_header=" + ua::to_string(request_header());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "request_handle=" + ua::to_string(request_handle());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "request_header=" + ua::to_string(request_header());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "request_handle=" + ua::to_string(request_handle());
}

std::string CancelRequest::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void CancelRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::CancelRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::CancelRequest::create);
  }
}

RequestHeader& CancelRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& CancelRequest::request_header() const
{
  return mRequestHeader;
}

IntegerId& CancelRequest::request_handle()
{
  return mRequestHandle;
}

const IntegerId& CancelRequest::request_handle() const
{
  return mRequestHandle;
}

BuiltInTypeId CancelRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ReferenceTypeAttributes
{
namespace
{
void encode(StackDepth limit, const ua::ReferenceTypeAttributes& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.is_abstract());
  encoder.encode(limit, value.symmetric());
  encoder.encode(limit, value.inverse_name());
}

void encode(StackDepth limit, const ua::ReferenceTypeAttributes& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "IsAbstract", value.is_abstract());
  encoder.encode(limit, "Symmetric", value.symmetric());
  encoder.encode(limit, "InverseName", value.inverse_name());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ReferenceTypeAttributes& value)
{
  decoder.decode(limit, value.is_abstract());
  decoder.decode(limit, value.symmetric());
  decoder.decode(limit, value.inverse_name());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ReferenceTypeAttributes& value)
{
  decoder.decode(limit, "IsAbstract", true, value.is_abstract());
  decoder.decode(limit, "Symmetric", true, value.symmetric());
  decoder.decode(limit, "InverseName", true, value.inverse_name());
}
}  // namespace
}  // namespace detail::ReferenceTypeAttributes

namespace detail::ReferenceTypeAttributes
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ReferenceTypeAttributes::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ReferenceTypeAttributes::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ReferenceTypeAttributes

namespace detail::ReferenceTypeAttributes
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ReferenceTypeAttributes>();
}
}  // namespace
}  // namespace detail::ReferenceTypeAttributes

bool ReferenceTypeAttributes::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return NodeAttributes::is_of_type(ns, dataTypeId);
}

NodeId ReferenceTypeAttributes::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ReferenceTypeAttributes::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ReferenceTypeAttributes::type_name() const
{
  return typeName;
}

void ReferenceTypeAttributes::encode(StackDepth limit, Encoder& encoder) const
{

  NodeAttributes::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReferenceTypeAttributes::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReferenceTypeAttributes::encode(limit, *this, *xml);
  }
}

void ReferenceTypeAttributes::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReferenceTypeAttributes::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReferenceTypeAttributes::encode_id(limit, ns, *xml);
  }
}

void ReferenceTypeAttributes::decode(StackDepth limit, Decoder& decoder)
{

  NodeAttributes::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ReferenceTypeAttributes::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ReferenceTypeAttributes::decode(limit, *xml, *this);
  }
}

void ReferenceTypeAttributes::resolve(span<const LocaleId> locales)
{
  NodeAttributes::resolve(locales);
  mInverseName = mInverseName.resolve(locales);
}

unique_ptr<Structure> ReferenceTypeAttributes::clone() const
{
  return make_unique<ReferenceTypeAttributes>(*this);
}

void ReferenceTypeAttributes::append_fields(std::string& output, int indent) const
{
  NodeAttributes::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "is_abstract=" + ua::to_string(is_abstract());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "symmetric=" + ua::to_string(symmetric());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "inverse_name=" + ua::to_string(inverse_name());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "is_abstract=" + ua::to_string(is_abstract());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "symmetric=" + ua::to_string(symmetric());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "inverse_name=" + ua::to_string(inverse_name());
}

std::string ReferenceTypeAttributes::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void ReferenceTypeAttributes::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ReferenceTypeAttributes::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ReferenceTypeAttributes::create);
  }
}

bool& ReferenceTypeAttributes::is_abstract()
{
  return mIsAbstract;
}

const bool& ReferenceTypeAttributes::is_abstract() const
{
  return mIsAbstract;
}

bool& ReferenceTypeAttributes::symmetric()
{
  return mSymmetric;
}

const bool& ReferenceTypeAttributes::symmetric() const
{
  return mSymmetric;
}

LocalizedText& ReferenceTypeAttributes::inverse_name()
{
  return mInverseName;
}

const LocalizedText& ReferenceTypeAttributes::inverse_name() const
{
  return mInverseName;
}

BuiltInTypeId ReferenceTypeAttributes::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::AddReferencesRequest
{
namespace
{
void encode(StackDepth limit, const ua::AddReferencesRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.references_to_add());
}

void encode(StackDepth limit, const ua::AddReferencesRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "ReferencesToAdd", value.references_to_add());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::AddReferencesRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.references_to_add());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::AddReferencesRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "ReferencesToAdd", true, value.references_to_add());
}
}  // namespace
}  // namespace detail::AddReferencesRequest

namespace detail::AddReferencesRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::AddReferencesRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::AddReferencesRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::AddReferencesRequest

namespace detail::AddReferencesRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::AddReferencesRequest>();
}
}  // namespace
}  // namespace detail::AddReferencesRequest

bool AddReferencesRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId AddReferencesRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId AddReferencesRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String AddReferencesRequest::type_name() const
{
  return typeName;
}

void AddReferencesRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AddReferencesRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AddReferencesRequest::encode(limit, *this, *xml);
  }
}

void AddReferencesRequest::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AddReferencesRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AddReferencesRequest::encode_id(limit, ns, *xml);
  }
}

void AddReferencesRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::AddReferencesRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::AddReferencesRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> AddReferencesRequest::clone() const
{
  return make_unique<AddReferencesRequest>(*this);
}

void AddReferencesRequest::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "request_header=" + ua::to_string(request_header());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "references_to_add=" + ua::to_string(references_to_add());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "request_header=" + ua::to_string(request_header());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "references_to_add=" + ua::to_string(references_to_add());
}

std::string AddReferencesRequest::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void AddReferencesRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::AddReferencesRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::AddReferencesRequest::create);
  }
}

RequestHeader& AddReferencesRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& AddReferencesRequest::request_header() const
{
  return mRequestHeader;
}

Array<AddReferencesItem>& AddReferencesRequest::references_to_add()
{
  return mReferencesToAdd;
}

const Array<AddReferencesItem>& AddReferencesRequest::references_to_add() const
{
  return mReferencesToAdd;
}

BuiltInTypeId AddReferencesRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ReferenceDescription
{
namespace
{
void encode(StackDepth limit, const ua::ReferenceDescription& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.reference_type_id());
  encoder.encode(limit, value.is_forward());
  encoder.encode(limit, value.node_id());
  encoder.encode(limit, value.browse_name());
  encoder.encode(limit, value.display_name());
  encoder.encode(limit, utils::as_int32(value.node_class()));
  encoder.encode(limit, value.type_definition());
}

void encode(StackDepth limit, const ua::ReferenceDescription& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ReferenceTypeId", value.reference_type_id());
  encoder.encode(limit, "IsForward", value.is_forward());
  encoder.encode(limit, "NodeId", value.node_id());
  encoder.encode(limit, "BrowseName", value.browse_name());
  encoder.encode(limit, "DisplayName", value.display_name());
  encoder.encode(limit, "NodeClass", utils::as_int32(value.node_class()));
  encoder.encode(limit, "TypeDefinition", value.type_definition());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ReferenceDescription& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.reference_type_id());
  decoder.decode(limit, value.is_forward());
  decoder.decode(limit, value.node_id());
  decoder.decode(limit, value.browse_name());
  decoder.decode(limit, value.display_name());
  decoder.decode(limit, enumVal);
  value.node_class() = utils::from_underlying<NodeClass>(enumVal);
  decoder.decode(limit, value.type_definition());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ReferenceDescription& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "ReferenceTypeId", true, value.reference_type_id());
  decoder.decode(limit, "IsForward", true, value.is_forward());
  decoder.decode(limit, "NodeId", true, value.node_id());
  decoder.decode(limit, "BrowseName", true, value.browse_name());
  decoder.decode(limit, "DisplayName", true, value.display_name());
  decoder.decode(limit, "NodeClass", true, enumVal);
  value.node_class() = utils::from_underlying<NodeClass>(enumVal);
  decoder.decode(limit, "TypeDefinition", true, value.type_definition());
}
}  // namespace
}  // namespace detail::ReferenceDescription

namespace detail::ReferenceDescription
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ReferenceDescription::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ReferenceDescription::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ReferenceDescription

namespace detail::ReferenceDescription
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ReferenceDescription>();
}
}  // namespace
}  // namespace detail::ReferenceDescription

bool ReferenceDescription::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ReferenceDescription::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ReferenceDescription::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ReferenceDescription::type_name() const
{
  return typeName;
}

void ReferenceDescription::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReferenceDescription::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReferenceDescription::encode(limit, *this, *xml);
  }
}

void ReferenceDescription::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReferenceDescription::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReferenceDescription::encode_id(limit, ns, *xml);
  }
}

void ReferenceDescription::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ReferenceDescription::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ReferenceDescription::decode(limit, *xml, *this);
  }
}

void ReferenceDescription::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  mDisplayName = mDisplayName.resolve(locales);
}

unique_ptr<Structure> ReferenceDescription::clone() const
{
  return make_unique<ReferenceDescription>(*this);
}

void ReferenceDescription::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "reference_type_id=" + ua::to_string(reference_type_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "is_forward=" + ua::to_string(is_forward());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "node_id=" + ua::to_string(node_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "browse_name=" + ua::to_string(browse_name());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "display_name=" + ua::to_string(display_name());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "node_class=" + ua::to_string(utils::as_int32(node_class()));
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "type_definition=" + ua::to_string(type_definition());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "reference_type_id=" + ua::to_string(reference_type_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "is_forward=" + ua::to_string(is_forward());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "node_id=" + ua::to_string(node_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "browse_name=" + ua::to_string(browse_name());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "display_name=" + ua::to_string(display_name());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "node_class=" + ua::to_string(utils::as_int32(node_class()));
  if (!output.empty())
  {
    output += ", ";
  }
  output += "type_definition=" + ua::to_string(type_definition());
}

std::string ReferenceDescription::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void ReferenceDescription::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ReferenceDescription::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ReferenceDescription::create);
  }
}

NodeId& ReferenceDescription::reference_type_id()
{
  return mReferenceTypeId;
}

const NodeId& ReferenceDescription::reference_type_id() const
{
  return mReferenceTypeId;
}

bool& ReferenceDescription::is_forward()
{
  return mIsForward;
}

const bool& ReferenceDescription::is_forward() const
{
  return mIsForward;
}

ExpandedNodeId& ReferenceDescription::node_id()
{
  return mNodeId;
}

const ExpandedNodeId& ReferenceDescription::node_id() const
{
  return mNodeId;
}

QualifiedName& ReferenceDescription::browse_name()
{
  return mBrowseName;
}

const QualifiedName& ReferenceDescription::browse_name() const
{
  return mBrowseName;
}

LocalizedText& ReferenceDescription::display_name()
{
  return mDisplayName;
}

const LocalizedText& ReferenceDescription::display_name() const
{
  return mDisplayName;
}

NodeClass& ReferenceDescription::node_class()
{
  return mNodeClass;
}

const NodeClass& ReferenceDescription::node_class() const
{
  return mNodeClass;
}

ExpandedNodeId& ReferenceDescription::type_definition()
{
  return mTypeDefinition;
}

const ExpandedNodeId& ReferenceDescription::type_definition() const
{
  return mTypeDefinition;
}

BuiltInTypeId ReferenceDescription::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::BrowsePathResult
{
namespace
{
void encode(StackDepth limit, const ua::BrowsePathResult& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.status_code());
  encoder.encode(limit, value.targets());
}

void encode(StackDepth limit, const ua::BrowsePathResult& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "StatusCode", value.status_code());
  encoder.encode(limit, "Targets", value.targets());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::BrowsePathResult& value)
{
  decoder.decode(limit, value.status_code());
  decoder.decode(limit, value.targets());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::BrowsePathResult& value)
{
  decoder.decode(limit, "StatusCode", true, value.status_code());
  decoder.decode(limit, "Targets", true, value.targets());
}
}  // namespace
}  // namespace detail::BrowsePathResult

namespace detail::BrowsePathResult
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::BrowsePathResult::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::BrowsePathResult::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::BrowsePathResult

namespace detail::BrowsePathResult
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::BrowsePathResult>();
}
}  // namespace
}  // namespace detail::BrowsePathResult

bool BrowsePathResult::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId BrowsePathResult::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId BrowsePathResult::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String BrowsePathResult::type_name() const
{
  return typeName;
}

void BrowsePathResult::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::BrowsePathResult::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::BrowsePathResult::encode(limit, *this, *xml);
  }
}

void BrowsePathResult::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::BrowsePathResult::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::BrowsePathResult::encode_id(limit, ns, *xml);
  }
}

void BrowsePathResult::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::BrowsePathResult::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::BrowsePathResult::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> BrowsePathResult::clone() const
{
  return make_unique<BrowsePathResult>(*this);
}

void BrowsePathResult::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "status_code=" + ua::to_string(status_code());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "targets=" + ua::to_string(targets());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "status_code=" + ua::to_string(status_code());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "targets=" + ua::to_string(targets());
}

std::string BrowsePathResult::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void BrowsePathResult::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::BrowsePathResult::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::BrowsePathResult::create);
  }
}

StatusCode& BrowsePathResult::status_code()
{
  return mStatusCode;
}

const StatusCode& BrowsePathResult::status_code() const
{
  return mStatusCode;
}

Array<BrowsePathTarget>& BrowsePathResult::targets()
{
  return mTargets;
}

const Array<BrowsePathTarget>& BrowsePathResult::targets() const
{
  return mTargets;
}

BuiltInTypeId BrowsePathResult::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::NodeTypeDescription
{
namespace
{
void encode(StackDepth limit, const ua::NodeTypeDescription& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.type_definition_node());
  encoder.encode(limit, value.include_sub_types());
  encoder.encode(limit, value.data_to_return());
}

void encode(StackDepth limit, const ua::NodeTypeDescription& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "TypeDefinitionNode", value.type_definition_node());
  encoder.encode(limit, "IncludeSubTypes", value.include_sub_types());
  encoder.encode(limit, "DataToReturn", value.data_to_return());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::NodeTypeDescription& value)
{
  decoder.decode(limit, value.type_definition_node());
  decoder.decode(limit, value.include_sub_types());
  decoder.decode(limit, value.data_to_return());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::NodeTypeDescription& value)
{
  decoder.decode(limit, "TypeDefinitionNode", true, value.type_definition_node());
  decoder.decode(limit, "IncludeSubTypes", true, value.include_sub_types());
  decoder.decode(limit, "DataToReturn", true, value.data_to_return());
}
}  // namespace
}  // namespace detail::NodeTypeDescription

namespace detail::NodeTypeDescription
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::NodeTypeDescription::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::NodeTypeDescription::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::NodeTypeDescription

namespace detail::NodeTypeDescription
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::NodeTypeDescription>();
}
}  // namespace
}  // namespace detail::NodeTypeDescription

bool NodeTypeDescription::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId NodeTypeDescription::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId NodeTypeDescription::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String NodeTypeDescription::type_name() const
{
  return typeName;
}

void NodeTypeDescription::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::NodeTypeDescription::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::NodeTypeDescription::encode(limit, *this, *xml);
  }
}

void NodeTypeDescription::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::NodeTypeDescription::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::NodeTypeDescription::encode_id(limit, ns, *xml);
  }
}

void NodeTypeDescription::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::NodeTypeDescription::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::NodeTypeDescription::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> NodeTypeDescription::clone() const
{
  return make_unique<NodeTypeDescription>(*this);
}

void NodeTypeDescription::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "type_definition_node=" + ua::to_string(type_definition_node());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "include_sub_types=" + ua::to_string(include_sub_types());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "data_to_return=" + ua::to_string(data_to_return());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "type_definition_node=" + ua::to_string(type_definition_node());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "include_sub_types=" + ua::to_string(include_sub_types());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "data_to_return=" + ua::to_string(data_to_return());
}

std::string NodeTypeDescription::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void NodeTypeDescription::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::NodeTypeDescription::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::NodeTypeDescription::create);
  }
}

ExpandedNodeId& NodeTypeDescription::type_definition_node()
{
  return mTypeDefinitionNode;
}

const ExpandedNodeId& NodeTypeDescription::type_definition_node() const
{
  return mTypeDefinitionNode;
}

bool& NodeTypeDescription::include_sub_types()
{
  return mIncludeSubTypes;
}

const bool& NodeTypeDescription::include_sub_types() const
{
  return mIncludeSubTypes;
}

Array<QueryDataDescription>& NodeTypeDescription::data_to_return()
{
  return mDataToReturn;
}

const Array<QueryDataDescription>& NodeTypeDescription::data_to_return() const
{
  return mDataToReturn;
}

BuiltInTypeId NodeTypeDescription::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::QueryNextRequest
{
namespace
{
void encode(StackDepth limit, const ua::QueryNextRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.release_continuation_point());
  encoder.encode(limit, value.continuation_point());
}

void encode(StackDepth limit, const ua::QueryNextRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "ReleaseContinuationPoint", value.release_continuation_point());
  encoder.encode(limit, "ContinuationPoint", value.continuation_point());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::QueryNextRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.release_continuation_point());
  decoder.decode(limit, value.continuation_point());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::QueryNextRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "ReleaseContinuationPoint", true, value.release_continuation_point());
  decoder.decode(limit, "ContinuationPoint", true, value.continuation_point());
}
}  // namespace
}  // namespace detail::QueryNextRequest

namespace detail::QueryNextRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::QueryNextRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::QueryNextRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::QueryNextRequest

namespace detail::QueryNextRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::QueryNextRequest>();
}
}  // namespace
}  // namespace detail::QueryNextRequest

bool QueryNextRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId QueryNextRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId QueryNextRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String QueryNextRequest::type_name() const
{
  return typeName;
}

void QueryNextRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::QueryNextRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::QueryNextRequest::encode(limit, *this, *xml);
  }
}

void QueryNextRequest::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::QueryNextRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::QueryNextRequest::encode_id(limit, ns, *xml);
  }
}

void QueryNextRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::QueryNextRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::QueryNextRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> QueryNextRequest::clone() const
{
  return make_unique<QueryNextRequest>(*this);
}

void QueryNextRequest::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "request_header=" + ua::to_string(request_header());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "release_continuation_point=" + ua::to_string(release_continuation_point());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "continuation_point=" + ua::to_string(continuation_point());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "request_header=" + ua::to_string(request_header());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "release_continuation_point=" + ua::to_string(release_continuation_point());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "continuation_point=" + ua::to_string(continuation_point());
}

std::string QueryNextRequest::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void QueryNextRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::QueryNextRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::QueryNextRequest::create);
  }
}

RequestHeader& QueryNextRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& QueryNextRequest::request_header() const
{
  return mRequestHeader;
}

bool& QueryNextRequest::release_continuation_point()
{
  return mReleaseContinuationPoint;
}

const bool& QueryNextRequest::release_continuation_point() const
{
  return mReleaseContinuationPoint;
}

ContinuationPoint& QueryNextRequest::continuation_point()
{
  return mContinuationPoint;
}

const ContinuationPoint& QueryNextRequest::continuation_point() const
{
  return mContinuationPoint;
}

BuiltInTypeId QueryNextRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ReadEventDetails
{
namespace
{
void encode(StackDepth limit, const ua::ReadEventDetails& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.num_values_per_node());
  encoder.encode(limit, value.start_time());
  encoder.encode(limit, value.end_time());
  encoder.encode(limit, value.filter());
}

void encode(StackDepth limit, const ua::ReadEventDetails& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "NumValuesPerNode", value.num_values_per_node());
  encoder.encode(limit, "StartTime", value.start_time());
  encoder.encode(limit, "EndTime", value.end_time());
  encoder.encode(limit, "Filter", value.filter());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ReadEventDetails& value)
{
  decoder.decode(limit, value.num_values_per_node());
  decoder.decode(limit, value.start_time());
  decoder.decode(limit, value.end_time());
  decoder.decode(limit, value.filter());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ReadEventDetails& value)
{
  decoder.decode(limit, "NumValuesPerNode", true, value.num_values_per_node());
  decoder.decode(limit, "StartTime", true, value.start_time());
  decoder.decode(limit, "EndTime", true, value.end_time());
  decoder.decode(limit, "Filter", true, value.filter());
}
}  // namespace
}  // namespace detail::ReadEventDetails

namespace detail::ReadEventDetails
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ReadEventDetails::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ReadEventDetails::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ReadEventDetails

namespace detail::ReadEventDetails
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ReadEventDetails>();
}
}  // namespace
}  // namespace detail::ReadEventDetails

bool ReadEventDetails::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return HistoryReadDetails::is_of_type(ns, dataTypeId);
}

NodeId ReadEventDetails::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ReadEventDetails::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ReadEventDetails::type_name() const
{
  return typeName;
}

void ReadEventDetails::encode(StackDepth limit, Encoder& encoder) const
{

  HistoryReadDetails::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReadEventDetails::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReadEventDetails::encode(limit, *this, *xml);
  }
}

void ReadEventDetails::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReadEventDetails::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReadEventDetails::encode_id(limit, ns, *xml);
  }
}

void ReadEventDetails::decode(StackDepth limit, Decoder& decoder)
{

  HistoryReadDetails::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ReadEventDetails::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ReadEventDetails::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ReadEventDetails::clone() const
{
  return make_unique<ReadEventDetails>(*this);
}

void ReadEventDetails::append_fields(std::string& output, int indent) const
{
  HistoryReadDetails::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "num_values_per_node=" + ua::to_string(num_values_per_node());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "start_time=" + ua::to_string(start_time());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "end_time=" + ua::to_string(end_time());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "filter=" + ua::to_string(filter());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "num_values_per_node=" + ua::to_string(num_values_per_node());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "start_time=" + ua::to_string(start_time());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "end_time=" + ua::to_string(end_time());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "filter=" + ua::to_string(filter());
}

std::string ReadEventDetails::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void ReadEventDetails::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ReadEventDetails::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ReadEventDetails::create);
  }
}

Counter& ReadEventDetails::num_values_per_node()
{
  return mNumValuesPerNode;
}

const Counter& ReadEventDetails::num_values_per_node() const
{
  return mNumValuesPerNode;
}

UtcTime& ReadEventDetails::start_time()
{
  return mStartTime;
}

const UtcTime& ReadEventDetails::start_time() const
{
  return mStartTime;
}

UtcTime& ReadEventDetails::end_time()
{
  return mEndTime;
}

const UtcTime& ReadEventDetails::end_time() const
{
  return mEndTime;
}

EventFilter& ReadEventDetails::filter()
{
  return mFilter;
}

const EventFilter& ReadEventDetails::filter() const
{
  return mFilter;
}

BuiltInTypeId ReadEventDetails::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::HistoryData
{
namespace
{
void encode(StackDepth limit, const ua::HistoryData& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.data_values());
}

void encode(StackDepth limit, const ua::HistoryData& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "DataValues", value.data_values());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::HistoryData& value)
{
  decoder.decode(limit, value.data_values());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::HistoryData& value)
{
  decoder.decode(limit, "DataValues", true, value.data_values());
}
}  // namespace
}  // namespace detail::HistoryData

namespace detail::HistoryData
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::HistoryData::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::HistoryData::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::HistoryData

namespace detail::HistoryData
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::HistoryData>();
}
}  // namespace
}  // namespace detail::HistoryData

bool HistoryData::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId HistoryData::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId HistoryData::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String HistoryData::type_name() const
{
  return typeName;
}

void HistoryData::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::HistoryData::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::HistoryData::encode(limit, *this, *xml);
  }
}

void HistoryData::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::HistoryData::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::HistoryData::encode_id(limit, ns, *xml);
  }
}

void HistoryData::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::HistoryData::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::HistoryData::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> HistoryData::clone() const
{
  return make_unique<HistoryData>(*this);
}

void HistoryData::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "data_values=" + ua::to_string(data_values());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "data_values=" + ua::to_string(data_values());
}

std::string HistoryData::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void HistoryData::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::HistoryData::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::HistoryData::create);
  }
}

Array<DataValue>& HistoryData::data_values()
{
  return mDataValues;
}

const Array<DataValue>& HistoryData::data_values() const
{
  return mDataValues;
}

BuiltInTypeId HistoryData::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::UpdateDataDetails
{
namespace
{
void encode(StackDepth limit, const ua::UpdateDataDetails& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.node_id());
  encoder.encode(limit, utils::as_int32(value.perform_insert_replace()));
  encoder.encode(limit, value.update_values());
}

void encode(StackDepth limit, const ua::UpdateDataDetails& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "NodeId", value.node_id());
  encoder.encode(limit, "PerformInsertReplace", utils::as_int32(value.perform_insert_replace()));
  encoder.encode(limit, "UpdateValues", value.update_values());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::UpdateDataDetails& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.node_id());
  decoder.decode(limit, enumVal);
  value.perform_insert_replace() = utils::from_underlying<PerformUpdateType>(enumVal);
  decoder.decode(limit, value.update_values());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::UpdateDataDetails& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "NodeId", true, value.node_id());
  decoder.decode(limit, "PerformInsertReplace", true, enumVal);
  value.perform_insert_replace() = utils::from_underlying<PerformUpdateType>(enumVal);
  decoder.decode(limit, "UpdateValues", true, value.update_values());
}
}  // namespace
}  // namespace detail::UpdateDataDetails

namespace detail::UpdateDataDetails
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::UpdateDataDetails::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::UpdateDataDetails::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::UpdateDataDetails

namespace detail::UpdateDataDetails
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::UpdateDataDetails>();
}
}  // namespace
}  // namespace detail::UpdateDataDetails

bool UpdateDataDetails::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return HistoryUpdateDetails::is_of_type(ns, dataTypeId);
}

NodeId UpdateDataDetails::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId UpdateDataDetails::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String UpdateDataDetails::type_name() const
{
  return typeName;
}

void UpdateDataDetails::encode(StackDepth limit, Encoder& encoder) const
{

  HistoryUpdateDetails::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::UpdateDataDetails::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::UpdateDataDetails::encode(limit, *this, *xml);
  }
}

void UpdateDataDetails::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::UpdateDataDetails::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::UpdateDataDetails::encode_id(limit, ns, *xml);
  }
}

void UpdateDataDetails::decode(StackDepth limit, Decoder& decoder)
{

  HistoryUpdateDetails::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::UpdateDataDetails::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::UpdateDataDetails::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> UpdateDataDetails::clone() const
{
  return make_unique<UpdateDataDetails>(*this);
}

void UpdateDataDetails::append_fields(std::string& output, int indent) const
{
  HistoryUpdateDetails::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "node_id=" + ua::to_string(node_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "perform_insert_replace=" + ua::to_string(utils::as_int32(perform_insert_replace()));
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "update_values=" + ua::to_string(update_values());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "node_id=" + ua::to_string(node_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "perform_insert_replace=" + ua::to_string(utils::as_int32(perform_insert_replace()));
  if (!output.empty())
  {
    output += ", ";
  }
  output += "update_values=" + ua::to_string(update_values());
}

std::string UpdateDataDetails::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void UpdateDataDetails::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::UpdateDataDetails::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::UpdateDataDetails::create);
  }
}

NodeId& UpdateDataDetails::node_id()
{
  return mNodeId;
}

const NodeId& UpdateDataDetails::node_id() const
{
  return mNodeId;
}

PerformUpdateType& UpdateDataDetails::perform_insert_replace()
{
  return mPerformInsertReplace;
}

const PerformUpdateType& UpdateDataDetails::perform_insert_replace() const
{
  return mPerformInsertReplace;
}

Array<DataValue>& UpdateDataDetails::update_values()
{
  return mUpdateValues;
}

const Array<DataValue>& UpdateDataDetails::update_values() const
{
  return mUpdateValues;
}

BuiltInTypeId UpdateDataDetails::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::HistoryUpdateResponse
{
namespace
{
void encode(StackDepth limit, const ua::HistoryUpdateResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.results());
  encoder.encode(limit, value.diagnostic_infos());
}

void encode(StackDepth limit, const ua::HistoryUpdateResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "Results", value.results());
  encoder.encode(limit, "DiagnosticInfos", value.diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::HistoryUpdateResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.results());
  decoder.decode(limit, value.diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::HistoryUpdateResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "Results", true, value.results());
  decoder.decode(limit, "DiagnosticInfos", true, value.diagnostic_infos());
}
}  // namespace
}  // namespace detail::HistoryUpdateResponse

namespace detail::HistoryUpdateResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::HistoryUpdateResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::HistoryUpdateResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::HistoryUpdateResponse

namespace detail::HistoryUpdateResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::HistoryUpdateResponse>();
}
}  // namespace
}  // namespace detail::HistoryUpdateResponse

bool HistoryUpdateResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId HistoryUpdateResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId HistoryUpdateResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String HistoryUpdateResponse::type_name() const
{
  return typeName;
}

void HistoryUpdateResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::HistoryUpdateResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::HistoryUpdateResponse::encode(limit, *this, *xml);
  }
}

void HistoryUpdateResponse::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::HistoryUpdateResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::HistoryUpdateResponse::encode_id(limit, ns, *xml);
  }
}

void HistoryUpdateResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::HistoryUpdateResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::HistoryUpdateResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> HistoryUpdateResponse::clone() const
{
  return make_unique<HistoryUpdateResponse>(*this);
}

void HistoryUpdateResponse::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "response_header=" + ua::to_string(response_header());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "results=" + ua::to_string(results());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "diagnostic_infos=" + ua::to_string(diagnostic_infos());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "response_header=" + ua::to_string(response_header());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "results=" + ua::to_string(results());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "diagnostic_infos=" + ua::to_string(diagnostic_infos());
}

std::string HistoryUpdateResponse::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void HistoryUpdateResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::HistoryUpdateResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::HistoryUpdateResponse::create);
  }
}

ResponseHeader& HistoryUpdateResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& HistoryUpdateResponse::response_header() const
{
  return mResponseHeader;
}

Array<HistoryUpdateResult>& HistoryUpdateResponse::results()
{
  return mResults;
}

const Array<HistoryUpdateResult>& HistoryUpdateResponse::results() const
{
  return mResults;
}

Array<DiagnosticInfo>& HistoryUpdateResponse::diagnostic_infos()
{
  return mDiagnosticInfos;
}

const Array<DiagnosticInfo>& HistoryUpdateResponse::diagnostic_infos() const
{
  return mDiagnosticInfos;
}

BuiltInTypeId HistoryUpdateResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::EventFilterResult
{
namespace
{
void encode(StackDepth limit, const ua::EventFilterResult& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.select_clause_results());
  encoder.encode(limit, value.select_clause_diagnostic_infos());
  encoder.encode(limit, value.where_clause_result());
}

void encode(StackDepth limit, const ua::EventFilterResult& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "SelectClauseResults", value.select_clause_results());
  encoder.encode(limit, "SelectClauseDiagnosticInfos", value.select_clause_diagnostic_infos());
  encoder.encode(limit, "WhereClauseResult", value.where_clause_result());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::EventFilterResult& value)
{
  decoder.decode(limit, value.select_clause_results());
  decoder.decode(limit, value.select_clause_diagnostic_infos());
  decoder.decode(limit, value.where_clause_result());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::EventFilterResult& value)
{
  decoder.decode(limit, "SelectClauseResults", true, value.select_clause_results());
  decoder.decode(limit, "SelectClauseDiagnosticInfos", true, value.select_clause_diagnostic_infos());
  decoder.decode(limit, "WhereClauseResult", true, value.where_clause_result());
}
}  // namespace
}  // namespace detail::EventFilterResult

namespace detail::EventFilterResult
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::EventFilterResult::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::EventFilterResult::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::EventFilterResult

namespace detail::EventFilterResult
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::EventFilterResult>();
}
}  // namespace
}  // namespace detail::EventFilterResult

bool EventFilterResult::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return MonitoringFilterResult::is_of_type(ns, dataTypeId);
}

NodeId EventFilterResult::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId EventFilterResult::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String EventFilterResult::type_name() const
{
  return typeName;
}

void EventFilterResult::encode(StackDepth limit, Encoder& encoder) const
{

  MonitoringFilterResult::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EventFilterResult::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EventFilterResult::encode(limit, *this, *xml);
  }
}

void EventFilterResult::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EventFilterResult::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EventFilterResult::encode_id(limit, ns, *xml);
  }
}

void EventFilterResult::decode(StackDepth limit, Decoder& decoder)
{

  MonitoringFilterResult::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::EventFilterResult::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::EventFilterResult::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> EventFilterResult::clone() const
{
  return make_unique<EventFilterResult>(*this);
}

void EventFilterResult::append_fields(std::string& output, int indent) const
{
  MonitoringFilterResult::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "select_clause_results=" + ua::to_string(select_clause_results());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "select_clause_diagnostic_infos=" + ua::to_string(select_clause_diagnostic_infos());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "where_clause_result=" + ua::to_string(where_clause_result());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "select_clause_results=" + ua::to_string(select_clause_results());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "select_clause_diagnostic_infos=" + ua::to_string(select_clause_diagnostic_infos());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "where_clause_result=" + ua::to_string(where_clause_result());
}

std::string EventFilterResult::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void EventFilterResult::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::EventFilterResult::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::EventFilterResult::create);
  }
}

Array<StatusCode>& EventFilterResult::select_clause_results()
{
  return mSelectClauseResults;
}

const Array<StatusCode>& EventFilterResult::select_clause_results() const
{
  return mSelectClauseResults;
}

Array<DiagnosticInfo>& EventFilterResult::select_clause_diagnostic_infos()
{
  return mSelectClauseDiagnosticInfos;
}

const Array<DiagnosticInfo>& EventFilterResult::select_clause_diagnostic_infos() const
{
  return mSelectClauseDiagnosticInfos;
}

ContentFilterResult& EventFilterResult::where_clause_result()
{
  return mWhereClauseResult;
}

const ContentFilterResult& EventFilterResult::where_clause_result() const
{
  return mWhereClauseResult;
}

BuiltInTypeId EventFilterResult::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::MonitoredItemModifyResult
{
namespace
{
void encode(StackDepth limit, const ua::MonitoredItemModifyResult& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.status_code());
  encoder.encode(limit, value.revised_sampling_interval());
  encoder.encode(limit, value.revised_queue_size());
  encoder.encode(limit, value.filter_result().get());
}

void encode(StackDepth limit, const ua::MonitoredItemModifyResult& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "StatusCode", value.status_code());
  encoder.encode(limit, "RevisedSamplingInterval", value.revised_sampling_interval());
  encoder.encode(limit, "RevisedQueueSize", value.revised_queue_size());
  encoder.encode(limit, "FilterResult", value.filter_result().get());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::MonitoredItemModifyResult& value)
{
  decoder.decode(limit, value.status_code());
  decoder.decode(limit, value.revised_sampling_interval());
  decoder.decode(limit, value.revised_queue_size());
  decoder.decode(limit, value.filter_result().inner_unique_ptr());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::MonitoredItemModifyResult& value)
{
  decoder.decode(limit, "StatusCode", true, value.status_code());
  decoder.decode(limit, "RevisedSamplingInterval", true, value.revised_sampling_interval());
  decoder.decode(limit, "RevisedQueueSize", true, value.revised_queue_size());
  decoder.decode(limit, "FilterResult", true, value.filter_result().inner_unique_ptr());
}
}  // namespace
}  // namespace detail::MonitoredItemModifyResult

namespace detail::MonitoredItemModifyResult
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::MonitoredItemModifyResult::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::MonitoredItemModifyResult::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::MonitoredItemModifyResult

namespace detail::MonitoredItemModifyResult
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::MonitoredItemModifyResult>();
}
}  // namespace
}  // namespace detail::MonitoredItemModifyResult

bool MonitoredItemModifyResult::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId MonitoredItemModifyResult::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId MonitoredItemModifyResult::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String MonitoredItemModifyResult::type_name() const
{
  return typeName;
}

void MonitoredItemModifyResult::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::MonitoredItemModifyResult::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::MonitoredItemModifyResult::encode(limit, *this, *xml);
  }
}

void MonitoredItemModifyResult::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::MonitoredItemModifyResult::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::MonitoredItemModifyResult::encode_id(limit, ns, *xml);
  }
}

void MonitoredItemModifyResult::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::MonitoredItemModifyResult::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::MonitoredItemModifyResult::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> MonitoredItemModifyResult::clone() const
{
  return make_unique<MonitoredItemModifyResult>(*this);
}

void MonitoredItemModifyResult::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "status_code=" + ua::to_string(status_code());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "revised_sampling_interval=" + ua::to_string(revised_sampling_interval());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "revised_queue_size=" + ua::to_string(revised_queue_size());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "filter_result=" + (filter_result() ? filter_result()->to_string(indent) : "null");
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "status_code=" + ua::to_string(status_code());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "revised_sampling_interval=" + ua::to_string(revised_sampling_interval());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "revised_queue_size=" + ua::to_string(revised_queue_size());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "filter_result=" + (filter_result() ? filter_result()->to_string(0) : "null");
}

std::string MonitoredItemModifyResult::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void MonitoredItemModifyResult::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::MonitoredItemModifyResult::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::MonitoredItemModifyResult::create);
  }
}

StatusCode& MonitoredItemModifyResult::status_code()
{
  return mStatusCode;
}

const StatusCode& MonitoredItemModifyResult::status_code() const
{
  return mStatusCode;
}

Duration& MonitoredItemModifyResult::revised_sampling_interval()
{
  return mRevisedSamplingInterval;
}

const Duration& MonitoredItemModifyResult::revised_sampling_interval() const
{
  return mRevisedSamplingInterval;
}

Counter& MonitoredItemModifyResult::revised_queue_size()
{
  return mRevisedQueueSize;
}

const Counter& MonitoredItemModifyResult::revised_queue_size() const
{
  return mRevisedQueueSize;
}

RefStructure<Structure>& MonitoredItemModifyResult::filter_result()
{
  return mFilterResult;
}

const RefStructure<Structure>& MonitoredItemModifyResult::filter_result() const
{
  return mFilterResult;
}

BuiltInTypeId MonitoredItemModifyResult::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::DeleteMonitoredItemsResponse
{
namespace
{
void encode(StackDepth limit, const ua::DeleteMonitoredItemsResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.results());
  encoder.encode(limit, value.diagnostic_infos());
}

void encode(StackDepth limit, const ua::DeleteMonitoredItemsResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "Results", value.results());
  encoder.encode(limit, "DiagnosticInfos", value.diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::DeleteMonitoredItemsResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.results());
  decoder.decode(limit, value.diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::DeleteMonitoredItemsResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "Results", true, value.results());
  decoder.decode(limit, "DiagnosticInfos", true, value.diagnostic_infos());
}
}  // namespace
}  // namespace detail::DeleteMonitoredItemsResponse

namespace detail::DeleteMonitoredItemsResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::DeleteMonitoredItemsResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::DeleteMonitoredItemsResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::DeleteMonitoredItemsResponse

namespace detail::DeleteMonitoredItemsResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::DeleteMonitoredItemsResponse>();
}
}  // namespace
}  // namespace detail::DeleteMonitoredItemsResponse

bool DeleteMonitoredItemsResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId DeleteMonitoredItemsResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId DeleteMonitoredItemsResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String DeleteMonitoredItemsResponse::type_name() const
{
  return typeName;
}

void DeleteMonitoredItemsResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DeleteMonitoredItemsResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DeleteMonitoredItemsResponse::encode(limit, *this, *xml);
  }
}

void DeleteMonitoredItemsResponse::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DeleteMonitoredItemsResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DeleteMonitoredItemsResponse::encode_id(limit, ns, *xml);
  }
}

void DeleteMonitoredItemsResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::DeleteMonitoredItemsResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::DeleteMonitoredItemsResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> DeleteMonitoredItemsResponse::clone() const
{
  return make_unique<DeleteMonitoredItemsResponse>(*this);
}

void DeleteMonitoredItemsResponse::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "response_header=" + ua::to_string(response_header());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "results=" + ua::to_string(results());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "diagnostic_infos=" + ua::to_string(diagnostic_infos());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "response_header=" + ua::to_string(response_header());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "results=" + ua::to_string(results());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "diagnostic_infos=" + ua::to_string(diagnostic_infos());
}

std::string DeleteMonitoredItemsResponse::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void DeleteMonitoredItemsResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::DeleteMonitoredItemsResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::DeleteMonitoredItemsResponse::create);
  }
}

ResponseHeader& DeleteMonitoredItemsResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& DeleteMonitoredItemsResponse::response_header() const
{
  return mResponseHeader;
}

Array<StatusCode>& DeleteMonitoredItemsResponse::results()
{
  return mResults;
}

const Array<StatusCode>& DeleteMonitoredItemsResponse::results() const
{
  return mResults;
}

Array<DiagnosticInfo>& DeleteMonitoredItemsResponse::diagnostic_infos()
{
  return mDiagnosticInfos;
}

const Array<DiagnosticInfo>& DeleteMonitoredItemsResponse::diagnostic_infos() const
{
  return mDiagnosticInfos;
}

BuiltInTypeId DeleteMonitoredItemsResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::NotificationData
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::NotificationData::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::NotificationData::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::NotificationData

namespace detail::NotificationData
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::NotificationData>();
}
}  // namespace
}  // namespace detail::NotificationData

bool NotificationData::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId NotificationData::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId NotificationData::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String NotificationData::type_name() const
{
  return typeName;
}

void NotificationData::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);
}

void NotificationData::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::NotificationData::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::NotificationData::encode_id(limit, ns, *xml);
  }
}

void NotificationData::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);
}

unique_ptr<Structure> NotificationData::clone() const
{
  return make_unique<NotificationData>(*this);
}

std::string NotificationData::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void NotificationData::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::NotificationData::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::NotificationData::create);
  }
}

BuiltInTypeId NotificationData::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::PublishResponse
{
namespace
{
void encode(StackDepth limit, const ua::PublishResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.subscription_id());
  encoder.encode(limit, value.available_sequence_numbers());
  encoder.encode(limit, value.more_notifications());
  encoder.encode(limit, value.notification_message());
  encoder.encode(limit, value.results());
  encoder.encode(limit, value.diagnostic_infos());
}

void encode(StackDepth limit, const ua::PublishResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "SubscriptionId", value.subscription_id());
  encoder.encode(limit, "AvailableSequenceNumbers", value.available_sequence_numbers());
  encoder.encode(limit, "MoreNotifications", value.more_notifications());
  encoder.encode(limit, "NotificationMessage", value.notification_message());
  encoder.encode(limit, "Results", value.results());
  encoder.encode(limit, "DiagnosticInfos", value.diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::PublishResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.subscription_id());
  decoder.decode(limit, value.available_sequence_numbers());
  decoder.decode(limit, value.more_notifications());
  decoder.decode(limit, value.notification_message());
  decoder.decode(limit, value.results());
  decoder.decode(limit, value.diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::PublishResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "SubscriptionId", true, value.subscription_id());
  decoder.decode(limit, "AvailableSequenceNumbers", true, value.available_sequence_numbers());
  decoder.decode(limit, "MoreNotifications", true, value.more_notifications());
  decoder.decode(limit, "NotificationMessage", true, value.notification_message());
  decoder.decode(limit, "Results", true, value.results());
  decoder.decode(limit, "DiagnosticInfos", true, value.diagnostic_infos());
}
}  // namespace
}  // namespace detail::PublishResponse

namespace detail::PublishResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::PublishResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::PublishResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::PublishResponse

namespace detail::PublishResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::PublishResponse>();
}
}  // namespace
}  // namespace detail::PublishResponse

bool PublishResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId PublishResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId PublishResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String PublishResponse::type_name() const
{
  return typeName;
}

void PublishResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::PublishResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::PublishResponse::encode(limit, *this, *xml);
  }
}

void PublishResponse::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::PublishResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::PublishResponse::encode_id(limit, ns, *xml);
  }
}

void PublishResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::PublishResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::PublishResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> PublishResponse::clone() const
{
  return make_unique<PublishResponse>(*this);
}

void PublishResponse::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "response_header=" + ua::to_string(response_header());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "subscription_id=" + ua::to_string(subscription_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "available_sequence_numbers=" + ua::to_string(available_sequence_numbers());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "more_notifications=" + ua::to_string(more_notifications());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "notification_message=" + ua::to_string(notification_message());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "results=" + ua::to_string(results());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "diagnostic_infos=" + ua::to_string(diagnostic_infos());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "response_header=" + ua::to_string(response_header());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "subscription_id=" + ua::to_string(subscription_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "available_sequence_numbers=" + ua::to_string(available_sequence_numbers());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "more_notifications=" + ua::to_string(more_notifications());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "notification_message=" + ua::to_string(notification_message());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "results=" + ua::to_string(results());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "diagnostic_infos=" + ua::to_string(diagnostic_infos());
}

std::string PublishResponse::to_string(int indent) const
{
  if (indent > 0)
  {
    std::string renderedFields;
    append_fields(renderedFields, indent + 2);
    if (renderedFields.empty())
    {
      return std::string(typeName) + "{}";
    }
    std::string pad(numeric_cast<size_t>(indent), ' ');
    return std::string(typeName) + "{\n" + renderedFields + "\n" + pad + "}";
  }
  std::string renderedFields;
  append_fields(renderedFields);
  return std::string(typeName) + "{" + renderedFields + "}";
}

void PublishResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::PublishResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::PublishResponse::create);
  }
}

ResponseHeader& PublishResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& PublishResponse::response_header() const
{
  return mResponseHeader;
}

IntegerId& PublishResponse::subscription_id()
{
  return mSubscriptionId;
}

const IntegerId& PublishResponse::subscription_id() const
{
  return mSubscriptionId;
}

Array<Counter>& PublishResponse::available_sequence_numbers()
{
  return mAvailableSequenceNumbers;
}

const Array<Counter>& PublishResponse::available_sequence_numbers() const
{
  return mAvailableSequenceNumbers;
}

bool& PublishResponse::more_notifications()
{
  return mMoreNotifications;
}

const bool& PublishResponse::more_notifications() const
{
  return mMoreNotifications;
}

NotificationMessage& PublishResponse::notification_message()
{
  return mNotificationMessage;
}

const NotificationMessage& PublishResponse::notification_message() const
{
  return mNotificationMessage;
}

Array<StatusCode>& PublishResponse::results()
{
  return mResults;
}

const Array<StatusCode>& PublishResponse::results() const
{
  return mResults;
}

Array<DiagnosticInfo>& PublishResponse::diagnostic_infos()
{
  return mDiagnosticInfos;
}

const Array<DiagnosticInfo>& PublishResponse::diagnostic_infos() const
{
  return mDiagnosticInfos;
}

BuiltInTypeId PublishResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

}  // namespace ua
