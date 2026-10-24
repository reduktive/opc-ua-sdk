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

namespace detail::KeyValuePair
{
namespace
{
void encode(StackDepth limit, const ua::KeyValuePair& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.key());
  encoder.encode(limit, value.value());
}

void encode(StackDepth limit, const ua::KeyValuePair& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Key", value.key());
  encoder.encode(limit, "Value", value.value());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::KeyValuePair& value)
{
  decoder.decode(limit, value.key());
  decoder.decode(limit, value.value());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::KeyValuePair& value)
{
  decoder.decode(limit, "Key", true, value.key());
  decoder.decode(limit, "Value", true, value.value());
}
}  // namespace
}  // namespace detail::KeyValuePair

namespace detail::KeyValuePair
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::KeyValuePair::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::KeyValuePair::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::KeyValuePair

namespace detail::KeyValuePair
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::KeyValuePair>();
}
}  // namespace
}  // namespace detail::KeyValuePair

bool KeyValuePair::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId KeyValuePair::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId KeyValuePair::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String KeyValuePair::type_name() const
{
  return typeName;
}

void KeyValuePair::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::KeyValuePair::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::KeyValuePair::encode(limit, *this, *xml);
  }
}

void KeyValuePair::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::KeyValuePair::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::KeyValuePair::encode_id(limit, ns, *xml);
  }
}

void KeyValuePair::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::KeyValuePair::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::KeyValuePair::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> KeyValuePair::clone() const
{
  return make_unique<KeyValuePair>(*this);
}

void KeyValuePair::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "key=" + ua::to_string(key());
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
  output += "key=" + ua::to_string(key());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "value=" + ua::to_string(value());
}

std::string KeyValuePair::to_string(int indent) const
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

void KeyValuePair::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::KeyValuePair::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::KeyValuePair::create);
  }
}

QualifiedName& KeyValuePair::key()
{
  return mKey;
}

const QualifiedName& KeyValuePair::key() const
{
  return mKey;
}

Variant& KeyValuePair::value()
{
  return mValue;
}

const Variant& KeyValuePair::value() const
{
  return mValue;
}

BuiltInTypeId KeyValuePair::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

bool CartesianCoordinates::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId CartesianCoordinates::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId CartesianCoordinates::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String CartesianCoordinates::type_name() const
{
  return typeName;
}

void CartesianCoordinates::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);
}

void CartesianCoordinates::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  UA_UNUSED(limit);
  UA_UNUSED(ns);
  UA_UNUSED(encoder);
}

void CartesianCoordinates::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);
}

BuiltInTypeId CartesianCoordinates::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::AnnotationDataType
{
namespace
{
void encode(StackDepth limit, const ua::AnnotationDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.annotation());
  encoder.encode(limit, value.discipline());
  encoder.encode(limit, value.uri());
}

void encode(StackDepth limit, const ua::AnnotationDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Annotation", value.annotation());
  encoder.encode(limit, "Discipline", value.discipline());
  encoder.encode(limit, "Uri", value.uri());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::AnnotationDataType& value)
{
  decoder.decode(limit, value.annotation());
  decoder.decode(limit, value.discipline());
  decoder.decode(limit, value.uri());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::AnnotationDataType& value)
{
  decoder.decode(limit, "Annotation", true, value.annotation());
  decoder.decode(limit, "Discipline", true, value.discipline());
  decoder.decode(limit, "Uri", true, value.uri());
}
}  // namespace
}  // namespace detail::AnnotationDataType

namespace detail::AnnotationDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::AnnotationDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::AnnotationDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::AnnotationDataType

namespace detail::AnnotationDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::AnnotationDataType>();
}
}  // namespace
}  // namespace detail::AnnotationDataType

bool AnnotationDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId AnnotationDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId AnnotationDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String AnnotationDataType::type_name() const
{
  return typeName;
}

void AnnotationDataType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AnnotationDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AnnotationDataType::encode(limit, *this, *xml);
  }
}

void AnnotationDataType::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AnnotationDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AnnotationDataType::encode_id(limit, ns, *xml);
  }
}

void AnnotationDataType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::AnnotationDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::AnnotationDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> AnnotationDataType::clone() const
{
  return make_unique<AnnotationDataType>(*this);
}

void AnnotationDataType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "annotation=" + ua::to_string(annotation());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "discipline=" + ua::to_string(discipline());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "uri=" + ua::to_string(uri());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "annotation=" + ua::to_string(annotation());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "discipline=" + ua::to_string(discipline());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "uri=" + ua::to_string(uri());
}

std::string AnnotationDataType::to_string(int indent) const
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

void AnnotationDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::AnnotationDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::AnnotationDataType::create);
  }
}

String& AnnotationDataType::annotation()
{
  return mAnnotation;
}

const String& AnnotationDataType::annotation() const
{
  return mAnnotation;
}

String& AnnotationDataType::discipline()
{
  return mDiscipline;
}

const String& AnnotationDataType::discipline() const
{
  return mDiscipline;
}

String& AnnotationDataType::uri()
{
  return mUri;
}

const String& AnnotationDataType::uri() const
{
  return mUri;
}

BuiltInTypeId AnnotationDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::TransactionErrorType
{
namespace
{
void encode(StackDepth limit, const ua::TransactionErrorType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.target_id());
  encoder.encode(limit, value.error());
  encoder.encode(limit, value.message());
}

void encode(StackDepth limit, const ua::TransactionErrorType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "TargetId", value.target_id());
  encoder.encode(limit, "Error", value.error());
  encoder.encode(limit, "Message", value.message());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::TransactionErrorType& value)
{
  decoder.decode(limit, value.target_id());
  decoder.decode(limit, value.error());
  decoder.decode(limit, value.message());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::TransactionErrorType& value)
{
  decoder.decode(limit, "TargetId", true, value.target_id());
  decoder.decode(limit, "Error", true, value.error());
  decoder.decode(limit, "Message", true, value.message());
}
}  // namespace
}  // namespace detail::TransactionErrorType

namespace detail::TransactionErrorType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::TransactionErrorType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::TransactionErrorType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::TransactionErrorType

namespace detail::TransactionErrorType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::TransactionErrorType>();
}
}  // namespace
}  // namespace detail::TransactionErrorType

bool TransactionErrorType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId TransactionErrorType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId TransactionErrorType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String TransactionErrorType::type_name() const
{
  return typeName;
}

void TransactionErrorType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::TransactionErrorType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::TransactionErrorType::encode(limit, *this, *xml);
  }
}

void TransactionErrorType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::TransactionErrorType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::TransactionErrorType::encode_id(limit, ns, *xml);
  }
}

void TransactionErrorType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::TransactionErrorType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::TransactionErrorType::decode(limit, *xml, *this);
  }
}

void TransactionErrorType::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  mMessage = mMessage.resolve(locales);
}

unique_ptr<Structure> TransactionErrorType::clone() const
{
  return make_unique<TransactionErrorType>(*this);
}

void TransactionErrorType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "target_id=" + ua::to_string(target_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "error=" + ua::to_string(error());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "message=" + ua::to_string(message());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "target_id=" + ua::to_string(target_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "error=" + ua::to_string(error());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "message=" + ua::to_string(message());
}

std::string TransactionErrorType::to_string(int indent) const
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

void TransactionErrorType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::TransactionErrorType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::TransactionErrorType::create);
  }
}

NodeId& TransactionErrorType::target_id()
{
  return mTargetId;
}

const NodeId& TransactionErrorType::target_id() const
{
  return mTargetId;
}

StatusCode& TransactionErrorType::error()
{
  return mError;
}

const StatusCode& TransactionErrorType::error() const
{
  return mError;
}

LocalizedText& TransactionErrorType::message()
{
  return mMessage;
}

const LocalizedText& TransactionErrorType::message() const
{
  return mMessage;
}

BuiltInTypeId TransactionErrorType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::AuthorizationServiceConfigurationDataType
{
namespace
{
void encode(
  StackDepth limit, const ua::AuthorizationServiceConfigurationDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.service_uri());
  encoder.encode(limit, value.service_certificates());
  encoder.encode(limit, value.issuer_endpoint_settings());
}

void encode(StackDepth limit, const ua::AuthorizationServiceConfigurationDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ServiceUri", value.service_uri());
  encoder.encode(limit, "ServiceCertificates", value.service_certificates());
  encoder.encode(limit, "IssuerEndpointSettings", value.issuer_endpoint_settings());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::AuthorizationServiceConfigurationDataType& value)
{
  decoder.decode(limit, value.service_uri());
  decoder.decode(limit, value.service_certificates());
  decoder.decode(limit, value.issuer_endpoint_settings());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::AuthorizationServiceConfigurationDataType& value)
{
  decoder.decode(limit, "ServiceUri", true, value.service_uri());
  decoder.decode(limit, "ServiceCertificates", true, value.service_certificates());
  decoder.decode(limit, "IssuerEndpointSettings", true, value.issuer_endpoint_settings());
}
}  // namespace
}  // namespace detail::AuthorizationServiceConfigurationDataType

namespace detail::AuthorizationServiceConfigurationDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::AuthorizationServiceConfigurationDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(
    limit, "TypeId", NodeId{ua::AuthorizationServiceConfigurationDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::AuthorizationServiceConfigurationDataType

namespace detail::AuthorizationServiceConfigurationDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::AuthorizationServiceConfigurationDataType>();
}
}  // namespace
}  // namespace detail::AuthorizationServiceConfigurationDataType

bool AuthorizationServiceConfigurationDataType::is_of_type(
  const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return BaseConfigurationRecordDataType::is_of_type(ns, dataTypeId);
}

NodeId AuthorizationServiceConfigurationDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId AuthorizationServiceConfigurationDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String AuthorizationServiceConfigurationDataType::type_name() const
{
  return typeName;
}

void AuthorizationServiceConfigurationDataType::encode(StackDepth limit, Encoder& encoder) const
{

  BaseConfigurationRecordDataType::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AuthorizationServiceConfigurationDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AuthorizationServiceConfigurationDataType::encode(limit, *this, *xml);
  }
}

void AuthorizationServiceConfigurationDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AuthorizationServiceConfigurationDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AuthorizationServiceConfigurationDataType::encode_id(limit, ns, *xml);
  }
}

void AuthorizationServiceConfigurationDataType::decode(StackDepth limit, Decoder& decoder)
{

  BaseConfigurationRecordDataType::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::AuthorizationServiceConfigurationDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::AuthorizationServiceConfigurationDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> AuthorizationServiceConfigurationDataType::clone() const
{
  return make_unique<AuthorizationServiceConfigurationDataType>(*this);
}

void AuthorizationServiceConfigurationDataType::append_fields(std::string& output, int indent) const
{
  BaseConfigurationRecordDataType::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "service_uri=" + ua::to_string(service_uri());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "service_certificates=" + ua::to_string(service_certificates());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "issuer_endpoint_settings=" + ua::to_string(issuer_endpoint_settings());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "service_uri=" + ua::to_string(service_uri());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "service_certificates=" + ua::to_string(service_certificates());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "issuer_endpoint_settings=" + ua::to_string(issuer_endpoint_settings());
}

std::string AuthorizationServiceConfigurationDataType::to_string(int indent) const
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

void AuthorizationServiceConfigurationDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::AuthorizationServiceConfigurationDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(
      NodeId(defaultXmlEncodingId), detail::AuthorizationServiceConfigurationDataType::create);
  }
}

UriString& AuthorizationServiceConfigurationDataType::service_uri()
{
  return mServiceUri;
}

const UriString& AuthorizationServiceConfigurationDataType::service_uri() const
{
  return mServiceUri;
}

Array<ServiceCertificateDataType>& AuthorizationServiceConfigurationDataType::service_certificates()
{
  return mServiceCertificates;
}

const Array<ServiceCertificateDataType>&
  AuthorizationServiceConfigurationDataType::service_certificates() const
{
  return mServiceCertificates;
}

String& AuthorizationServiceConfigurationDataType::issuer_endpoint_settings()
{
  return mIssuerEndpointSettings;
}

const String& AuthorizationServiceConfigurationDataType::issuer_endpoint_settings() const
{
  return mIssuerEndpointSettings;
}

BuiltInTypeId AuthorizationServiceConfigurationDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::PortableNodeId
{
namespace
{
void encode(StackDepth limit, const ua::PortableNodeId& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.namespace_uri());
  encoder.encode(limit,
    [&]
    {
      auto identifier = value.identifier();
      identifier.namespace_index() = 0;
      return identifier;
    }());
}

void encode(StackDepth limit, const ua::PortableNodeId& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "NamespaceUri", value.namespace_uri());
  encoder.encode(limit,
    "Identifier",
    [&]
    {
      auto identifier = value.identifier();
      identifier.namespace_index() = 0;
      return identifier;
    }());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::PortableNodeId& value)
{
  decoder.decode(limit, value.namespace_uri());
  decoder.decode(limit, value.identifier());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::PortableNodeId& value)
{
  decoder.decode(limit, "NamespaceUri", true, value.namespace_uri());
  decoder.decode(limit, "Identifier", true, value.identifier());
}
}  // namespace
}  // namespace detail::PortableNodeId

namespace detail::PortableNodeId
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::PortableNodeId::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::PortableNodeId::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::PortableNodeId

namespace detail::PortableNodeId
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::PortableNodeId>();
}
}  // namespace
}  // namespace detail::PortableNodeId

bool PortableNodeId::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId PortableNodeId::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId PortableNodeId::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String PortableNodeId::type_name() const
{
  return typeName;
}

void PortableNodeId::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::PortableNodeId::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::PortableNodeId::encode(limit, *this, *xml);
  }
}

void PortableNodeId::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::PortableNodeId::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::PortableNodeId::encode_id(limit, ns, *xml);
  }
}

void PortableNodeId::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::PortableNodeId::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::PortableNodeId::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> PortableNodeId::clone() const
{
  return make_unique<PortableNodeId>(*this);
}

void PortableNodeId::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "namespace_uri=" + ua::to_string(namespace_uri());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "identifier=" + ua::to_string(identifier());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "namespace_uri=" + ua::to_string(namespace_uri());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "identifier=" + ua::to_string(identifier());
}

std::string PortableNodeId::to_string(int indent) const
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

void PortableNodeId::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::PortableNodeId::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::PortableNodeId::create);
  }
}

String& PortableNodeId::namespace_uri()
{
  return mNamespaceUri;
}

const String& PortableNodeId::namespace_uri() const
{
  return mNamespaceUri;
}

NodeId& PortableNodeId::identifier()
{
  mIdentifier.namespace_index() = 0;
  return mIdentifier;
}

const NodeId& PortableNodeId::identifier() const
{
  mIdentifier.namespace_index() = 0;
  return mIdentifier;
}

BuiltInTypeId PortableNodeId::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ReferenceDescriptionDataType
{
namespace
{
void encode(StackDepth limit, const ua::ReferenceDescriptionDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.source_node());
  encoder.encode(limit, value.reference_type());
  encoder.encode(limit, value.is_forward());
  encoder.encode(limit, value.target_node());
}

void encode(StackDepth limit, const ua::ReferenceDescriptionDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "SourceNode", value.source_node());
  encoder.encode(limit, "ReferenceType", value.reference_type());
  encoder.encode(limit, "IsForward", value.is_forward());
  encoder.encode(limit, "TargetNode", value.target_node());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ReferenceDescriptionDataType& value)
{
  decoder.decode(limit, value.source_node());
  decoder.decode(limit, value.reference_type());
  decoder.decode(limit, value.is_forward());
  decoder.decode(limit, value.target_node());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ReferenceDescriptionDataType& value)
{
  decoder.decode(limit, "SourceNode", true, value.source_node());
  decoder.decode(limit, "ReferenceType", true, value.reference_type());
  decoder.decode(limit, "IsForward", true, value.is_forward());
  decoder.decode(limit, "TargetNode", true, value.target_node());
}
}  // namespace
}  // namespace detail::ReferenceDescriptionDataType

namespace detail::ReferenceDescriptionDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ReferenceDescriptionDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ReferenceDescriptionDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ReferenceDescriptionDataType

namespace detail::ReferenceDescriptionDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ReferenceDescriptionDataType>();
}
}  // namespace
}  // namespace detail::ReferenceDescriptionDataType

bool ReferenceDescriptionDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ReferenceDescriptionDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ReferenceDescriptionDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ReferenceDescriptionDataType::type_name() const
{
  return typeName;
}

void ReferenceDescriptionDataType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReferenceDescriptionDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReferenceDescriptionDataType::encode(limit, *this, *xml);
  }
}

void ReferenceDescriptionDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReferenceDescriptionDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReferenceDescriptionDataType::encode_id(limit, ns, *xml);
  }
}

void ReferenceDescriptionDataType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ReferenceDescriptionDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ReferenceDescriptionDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ReferenceDescriptionDataType::clone() const
{
  return make_unique<ReferenceDescriptionDataType>(*this);
}

void ReferenceDescriptionDataType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "source_node=" + ua::to_string(source_node());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "reference_type=" + ua::to_string(reference_type());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "is_forward=" + ua::to_string(is_forward());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "target_node=" + ua::to_string(target_node());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "source_node=" + ua::to_string(source_node());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "reference_type=" + ua::to_string(reference_type());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "is_forward=" + ua::to_string(is_forward());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "target_node=" + ua::to_string(target_node());
}

std::string ReferenceDescriptionDataType::to_string(int indent) const
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

void ReferenceDescriptionDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::ReferenceDescriptionDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ReferenceDescriptionDataType::create);
  }
}

NodeId& ReferenceDescriptionDataType::source_node()
{
  return mSourceNode;
}

const NodeId& ReferenceDescriptionDataType::source_node() const
{
  return mSourceNode;
}

NodeId& ReferenceDescriptionDataType::reference_type()
{
  return mReferenceType;
}

const NodeId& ReferenceDescriptionDataType::reference_type() const
{
  return mReferenceType;
}

bool& ReferenceDescriptionDataType::is_forward()
{
  return mIsForward;
}

const bool& ReferenceDescriptionDataType::is_forward() const
{
  return mIsForward;
}

ExpandedNodeId& ReferenceDescriptionDataType::target_node()
{
  return mTargetNode;
}

const ExpandedNodeId& ReferenceDescriptionDataType::target_node() const
{
  return mTargetNode;
}

BuiltInTypeId ReferenceDescriptionDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

bool DataTypeDefinition::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId DataTypeDefinition::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId DataTypeDefinition::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String DataTypeDefinition::type_name() const
{
  return typeName;
}

void DataTypeDefinition::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);
}

void DataTypeDefinition::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  UA_UNUSED(limit);
  UA_UNUSED(ns);
  UA_UNUSED(encoder);
}

void DataTypeDefinition::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);
}

BuiltInTypeId DataTypeDefinition::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::TimeZoneDataType
{
namespace
{
void encode(StackDepth limit, const ua::TimeZoneDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.offset());
  encoder.encode(limit, value.daylight_saving_in_offset());
}

void encode(StackDepth limit, const ua::TimeZoneDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Offset", value.offset());
  encoder.encode(limit, "DaylightSavingInOffset", value.daylight_saving_in_offset());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::TimeZoneDataType& value)
{
  decoder.decode(limit, value.offset());
  decoder.decode(limit, value.daylight_saving_in_offset());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::TimeZoneDataType& value)
{
  decoder.decode(limit, "Offset", true, value.offset());
  decoder.decode(limit, "DaylightSavingInOffset", true, value.daylight_saving_in_offset());
}
}  // namespace
}  // namespace detail::TimeZoneDataType

namespace detail::TimeZoneDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::TimeZoneDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::TimeZoneDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::TimeZoneDataType

namespace detail::TimeZoneDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::TimeZoneDataType>();
}
}  // namespace
}  // namespace detail::TimeZoneDataType

bool TimeZoneDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId TimeZoneDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId TimeZoneDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String TimeZoneDataType::type_name() const
{
  return typeName;
}

void TimeZoneDataType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::TimeZoneDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::TimeZoneDataType::encode(limit, *this, *xml);
  }
}

void TimeZoneDataType::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::TimeZoneDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::TimeZoneDataType::encode_id(limit, ns, *xml);
  }
}

void TimeZoneDataType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::TimeZoneDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::TimeZoneDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> TimeZoneDataType::clone() const
{
  return make_unique<TimeZoneDataType>(*this);
}

void TimeZoneDataType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "offset=" + ua::to_string(offset());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "daylight_saving_in_offset=" + ua::to_string(daylight_saving_in_offset());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "offset=" + ua::to_string(offset());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "daylight_saving_in_offset=" + ua::to_string(daylight_saving_in_offset());
}

std::string TimeZoneDataType::to_string(int indent) const
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

void TimeZoneDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::TimeZoneDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::TimeZoneDataType::create);
  }
}

int16_t& TimeZoneDataType::offset()
{
  return mOffset;
}

const int16_t& TimeZoneDataType::offset() const
{
  return mOffset;
}

bool& TimeZoneDataType::daylight_saving_in_offset()
{
  return mDaylightSavingInOffset;
}

const bool& TimeZoneDataType::daylight_saving_in_offset() const
{
  return mDaylightSavingInOffset;
}

BuiltInTypeId TimeZoneDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::SignedSoftwareCertificate
{
namespace
{
void encode(StackDepth limit, const ua::SignedSoftwareCertificate& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.certificate_data());
  encoder.encode(limit, value.signature());
}

void encode(StackDepth limit, const ua::SignedSoftwareCertificate& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "CertificateData", value.certificate_data());
  encoder.encode(limit, "Signature", value.signature());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::SignedSoftwareCertificate& value)
{
  decoder.decode(limit, value.certificate_data());
  decoder.decode(limit, value.signature());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::SignedSoftwareCertificate& value)
{
  decoder.decode(limit, "CertificateData", true, value.certificate_data());
  decoder.decode(limit, "Signature", true, value.signature());
}
}  // namespace
}  // namespace detail::SignedSoftwareCertificate

namespace detail::SignedSoftwareCertificate
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::SignedSoftwareCertificate::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::SignedSoftwareCertificate::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::SignedSoftwareCertificate

namespace detail::SignedSoftwareCertificate
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::SignedSoftwareCertificate>();
}
}  // namespace
}  // namespace detail::SignedSoftwareCertificate

bool SignedSoftwareCertificate::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId SignedSoftwareCertificate::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId SignedSoftwareCertificate::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String SignedSoftwareCertificate::type_name() const
{
  return typeName;
}

void SignedSoftwareCertificate::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SignedSoftwareCertificate::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SignedSoftwareCertificate::encode(limit, *this, *xml);
  }
}

void SignedSoftwareCertificate::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SignedSoftwareCertificate::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SignedSoftwareCertificate::encode_id(limit, ns, *xml);
  }
}

void SignedSoftwareCertificate::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::SignedSoftwareCertificate::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::SignedSoftwareCertificate::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> SignedSoftwareCertificate::clone() const
{
  return make_unique<SignedSoftwareCertificate>(*this);
}

void SignedSoftwareCertificate::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "certificate_data=" + ua::to_string(certificate_data());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "signature=" + ua::to_string(signature());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "certificate_data=" + ua::to_string(certificate_data());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "signature=" + ua::to_string(signature());
}

std::string SignedSoftwareCertificate::to_string(int indent) const
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

void SignedSoftwareCertificate::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::SignedSoftwareCertificate::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::SignedSoftwareCertificate::create);
  }
}

ByteString& SignedSoftwareCertificate::certificate_data()
{
  return mCertificateData;
}

const ByteString& SignedSoftwareCertificate::certificate_data() const
{
  return mCertificateData;
}

ByteString& SignedSoftwareCertificate::signature()
{
  return mSignature;
}

const ByteString& SignedSoftwareCertificate::signature() const
{
  return mSignature;
}

BuiltInTypeId SignedSoftwareCertificate::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::DeleteNodesItem
{
namespace
{
void encode(StackDepth limit, const ua::DeleteNodesItem& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.node_id());
  encoder.encode(limit, value.delete_target_references());
}

void encode(StackDepth limit, const ua::DeleteNodesItem& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "NodeId", value.node_id());
  encoder.encode(limit, "DeleteTargetReferences", value.delete_target_references());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::DeleteNodesItem& value)
{
  decoder.decode(limit, value.node_id());
  decoder.decode(limit, value.delete_target_references());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::DeleteNodesItem& value)
{
  decoder.decode(limit, "NodeId", true, value.node_id());
  decoder.decode(limit, "DeleteTargetReferences", true, value.delete_target_references());
}
}  // namespace
}  // namespace detail::DeleteNodesItem

namespace detail::DeleteNodesItem
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::DeleteNodesItem::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::DeleteNodesItem::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::DeleteNodesItem

namespace detail::DeleteNodesItem
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::DeleteNodesItem>();
}
}  // namespace
}  // namespace detail::DeleteNodesItem

bool DeleteNodesItem::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId DeleteNodesItem::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId DeleteNodesItem::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String DeleteNodesItem::type_name() const
{
  return typeName;
}

void DeleteNodesItem::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DeleteNodesItem::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DeleteNodesItem::encode(limit, *this, *xml);
  }
}

void DeleteNodesItem::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DeleteNodesItem::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DeleteNodesItem::encode_id(limit, ns, *xml);
  }
}

void DeleteNodesItem::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::DeleteNodesItem::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::DeleteNodesItem::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> DeleteNodesItem::clone() const
{
  return make_unique<DeleteNodesItem>(*this);
}

void DeleteNodesItem::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
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
    output += pad + "delete_target_references=" + ua::to_string(delete_target_references());
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
  output += "delete_target_references=" + ua::to_string(delete_target_references());
}

std::string DeleteNodesItem::to_string(int indent) const
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

void DeleteNodesItem::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::DeleteNodesItem::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::DeleteNodesItem::create);
  }
}

NodeId& DeleteNodesItem::node_id()
{
  return mNodeId;
}

const NodeId& DeleteNodesItem::node_id() const
{
  return mNodeId;
}

bool& DeleteNodesItem::delete_target_references()
{
  return mDeleteTargetReferences;
}

const bool& DeleteNodesItem::delete_target_references() const
{
  return mDeleteTargetReferences;
}

BuiltInTypeId DeleteNodesItem::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ElementOperand
{
namespace
{
void encode(StackDepth limit, const ua::ElementOperand& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.index());
}

void encode(StackDepth limit, const ua::ElementOperand& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Index", value.index());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ElementOperand& value)
{
  decoder.decode(limit, value.index());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ElementOperand& value)
{
  decoder.decode(limit, "Index", true, value.index());
}
}  // namespace
}  // namespace detail::ElementOperand

namespace detail::ElementOperand
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ElementOperand::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ElementOperand::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ElementOperand

namespace detail::ElementOperand
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ElementOperand>();
}
}  // namespace
}  // namespace detail::ElementOperand

bool ElementOperand::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return FilterOperand::is_of_type(ns, dataTypeId);
}

NodeId ElementOperand::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ElementOperand::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ElementOperand::type_name() const
{
  return typeName;
}

void ElementOperand::encode(StackDepth limit, Encoder& encoder) const
{

  FilterOperand::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ElementOperand::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ElementOperand::encode(limit, *this, *xml);
  }
}

void ElementOperand::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ElementOperand::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ElementOperand::encode_id(limit, ns, *xml);
  }
}

void ElementOperand::decode(StackDepth limit, Decoder& decoder)
{

  FilterOperand::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ElementOperand::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ElementOperand::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ElementOperand::clone() const
{
  return make_unique<ElementOperand>(*this);
}

void ElementOperand::append_fields(std::string& output, int indent) const
{
  FilterOperand::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "index=" + ua::to_string(index());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "index=" + ua::to_string(index());
}

std::string ElementOperand::to_string(int indent) const
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

void ElementOperand::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ElementOperand::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ElementOperand::create);
  }
}

uint32_t& ElementOperand::index()
{
  return mIndex;
}

const uint32_t& ElementOperand::index() const
{
  return mIndex;
}

BuiltInTypeId ElementOperand::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::EventFilter
{
namespace
{
void encode(StackDepth limit, const ua::EventFilter& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.select_clauses());
  encoder.encode(limit, value.where_clause());
}

void encode(StackDepth limit, const ua::EventFilter& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "SelectClauses", value.select_clauses());
  encoder.encode(limit, "WhereClause", value.where_clause());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::EventFilter& value)
{
  decoder.decode(limit, value.select_clauses());
  decoder.decode(limit, value.where_clause());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::EventFilter& value)
{
  decoder.decode(limit, "SelectClauses", true, value.select_clauses());
  decoder.decode(limit, "WhereClause", true, value.where_clause());
}
}  // namespace
}  // namespace detail::EventFilter

namespace detail::EventFilter
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::EventFilter::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::EventFilter::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::EventFilter

namespace detail::EventFilter
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::EventFilter>();
}
}  // namespace
}  // namespace detail::EventFilter

bool EventFilter::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return MonitoringFilter::is_of_type(ns, dataTypeId);
}

NodeId EventFilter::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId EventFilter::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String EventFilter::type_name() const
{
  return typeName;
}

void EventFilter::encode(StackDepth limit, Encoder& encoder) const
{

  MonitoringFilter::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EventFilter::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EventFilter::encode(limit, *this, *xml);
  }
}

void EventFilter::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EventFilter::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EventFilter::encode_id(limit, ns, *xml);
  }
}

void EventFilter::decode(StackDepth limit, Decoder& decoder)
{

  MonitoringFilter::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::EventFilter::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::EventFilter::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> EventFilter::clone() const
{
  return make_unique<EventFilter>(*this);
}

void EventFilter::append_fields(std::string& output, int indent) const
{
  MonitoringFilter::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "select_clauses=" + ua::to_string(select_clauses());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "where_clause=" + ua::to_string(where_clause());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "select_clauses=" + ua::to_string(select_clauses());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "where_clause=" + ua::to_string(where_clause());
}

std::string EventFilter::to_string(int indent) const
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

void EventFilter::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::EventFilter::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::EventFilter::create);
  }
}

Array<SimpleAttributeOperand>& EventFilter::select_clauses()
{
  return mSelectClauses;
}

const Array<SimpleAttributeOperand>& EventFilter::select_clauses() const
{
  return mSelectClauses;
}

ContentFilter& EventFilter::where_clause()
{
  return mWhereClause;
}

const ContentFilter& EventFilter::where_clause() const
{
  return mWhereClause;
}

BuiltInTypeId EventFilter::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ServerDiagnosticsSummaryDataType
{
namespace
{
void encode(StackDepth limit, const ua::ServerDiagnosticsSummaryDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.server_view_count());
  encoder.encode(limit, value.current_session_count());
  encoder.encode(limit, value.cumulated_session_count());
  encoder.encode(limit, value.security_rejected_session_count());
  encoder.encode(limit, value.rejected_session_count());
  encoder.encode(limit, value.session_timeout_count());
  encoder.encode(limit, value.session_abort_count());
  encoder.encode(limit, value.current_subscription_count());
  encoder.encode(limit, value.cumulated_subscription_count());
  encoder.encode(limit, value.publishing_interval_count());
  encoder.encode(limit, value.security_rejected_requests_count());
  encoder.encode(limit, value.rejected_requests_count());
}

void encode(StackDepth limit, const ua::ServerDiagnosticsSummaryDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ServerViewCount", value.server_view_count());
  encoder.encode(limit, "CurrentSessionCount", value.current_session_count());
  encoder.encode(limit, "CumulatedSessionCount", value.cumulated_session_count());
  encoder.encode(limit, "SecurityRejectedSessionCount", value.security_rejected_session_count());
  encoder.encode(limit, "RejectedSessionCount", value.rejected_session_count());
  encoder.encode(limit, "SessionTimeoutCount", value.session_timeout_count());
  encoder.encode(limit, "SessionAbortCount", value.session_abort_count());
  encoder.encode(limit, "CurrentSubscriptionCount", value.current_subscription_count());
  encoder.encode(limit, "CumulatedSubscriptionCount", value.cumulated_subscription_count());
  encoder.encode(limit, "PublishingIntervalCount", value.publishing_interval_count());
  encoder.encode(limit, "SecurityRejectedRequestsCount", value.security_rejected_requests_count());
  encoder.encode(limit, "RejectedRequestsCount", value.rejected_requests_count());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ServerDiagnosticsSummaryDataType& value)
{
  decoder.decode(limit, value.server_view_count());
  decoder.decode(limit, value.current_session_count());
  decoder.decode(limit, value.cumulated_session_count());
  decoder.decode(limit, value.security_rejected_session_count());
  decoder.decode(limit, value.rejected_session_count());
  decoder.decode(limit, value.session_timeout_count());
  decoder.decode(limit, value.session_abort_count());
  decoder.decode(limit, value.current_subscription_count());
  decoder.decode(limit, value.cumulated_subscription_count());
  decoder.decode(limit, value.publishing_interval_count());
  decoder.decode(limit, value.security_rejected_requests_count());
  decoder.decode(limit, value.rejected_requests_count());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ServerDiagnosticsSummaryDataType& value)
{
  decoder.decode(limit, "ServerViewCount", true, value.server_view_count());
  decoder.decode(limit, "CurrentSessionCount", true, value.current_session_count());
  decoder.decode(limit, "CumulatedSessionCount", true, value.cumulated_session_count());
  decoder.decode(limit, "SecurityRejectedSessionCount", true, value.security_rejected_session_count());
  decoder.decode(limit, "RejectedSessionCount", true, value.rejected_session_count());
  decoder.decode(limit, "SessionTimeoutCount", true, value.session_timeout_count());
  decoder.decode(limit, "SessionAbortCount", true, value.session_abort_count());
  decoder.decode(limit, "CurrentSubscriptionCount", true, value.current_subscription_count());
  decoder.decode(limit, "CumulatedSubscriptionCount", true, value.cumulated_subscription_count());
  decoder.decode(limit, "PublishingIntervalCount", true, value.publishing_interval_count());
  decoder.decode(limit, "SecurityRejectedRequestsCount", true, value.security_rejected_requests_count());
  decoder.decode(limit, "RejectedRequestsCount", true, value.rejected_requests_count());
}
}  // namespace
}  // namespace detail::ServerDiagnosticsSummaryDataType

namespace detail::ServerDiagnosticsSummaryDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ServerDiagnosticsSummaryDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ServerDiagnosticsSummaryDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ServerDiagnosticsSummaryDataType

namespace detail::ServerDiagnosticsSummaryDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ServerDiagnosticsSummaryDataType>();
}
}  // namespace
}  // namespace detail::ServerDiagnosticsSummaryDataType

bool ServerDiagnosticsSummaryDataType::is_of_type(
  const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ServerDiagnosticsSummaryDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ServerDiagnosticsSummaryDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ServerDiagnosticsSummaryDataType::type_name() const
{
  return typeName;
}

void ServerDiagnosticsSummaryDataType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ServerDiagnosticsSummaryDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ServerDiagnosticsSummaryDataType::encode(limit, *this, *xml);
  }
}

void ServerDiagnosticsSummaryDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ServerDiagnosticsSummaryDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ServerDiagnosticsSummaryDataType::encode_id(limit, ns, *xml);
  }
}

void ServerDiagnosticsSummaryDataType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ServerDiagnosticsSummaryDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ServerDiagnosticsSummaryDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ServerDiagnosticsSummaryDataType::clone() const
{
  return make_unique<ServerDiagnosticsSummaryDataType>(*this);
}

void ServerDiagnosticsSummaryDataType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "server_view_count=" + ua::to_string(server_view_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "current_session_count=" + ua::to_string(current_session_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "cumulated_session_count=" + ua::to_string(cumulated_session_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "security_rejected_session_count=" + ua::to_string(security_rejected_session_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "rejected_session_count=" + ua::to_string(rejected_session_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "session_timeout_count=" + ua::to_string(session_timeout_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "session_abort_count=" + ua::to_string(session_abort_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "current_subscription_count=" + ua::to_string(current_subscription_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "cumulated_subscription_count=" + ua::to_string(cumulated_subscription_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "publishing_interval_count=" + ua::to_string(publishing_interval_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "security_rejected_requests_count=" + ua::to_string(security_rejected_requests_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "rejected_requests_count=" + ua::to_string(rejected_requests_count());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "server_view_count=" + ua::to_string(server_view_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "current_session_count=" + ua::to_string(current_session_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "cumulated_session_count=" + ua::to_string(cumulated_session_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "security_rejected_session_count=" + ua::to_string(security_rejected_session_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "rejected_session_count=" + ua::to_string(rejected_session_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "session_timeout_count=" + ua::to_string(session_timeout_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "session_abort_count=" + ua::to_string(session_abort_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "current_subscription_count=" + ua::to_string(current_subscription_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "cumulated_subscription_count=" + ua::to_string(cumulated_subscription_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "publishing_interval_count=" + ua::to_string(publishing_interval_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "security_rejected_requests_count=" + ua::to_string(security_rejected_requests_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "rejected_requests_count=" + ua::to_string(rejected_requests_count());
}

std::string ServerDiagnosticsSummaryDataType::to_string(int indent) const
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

void ServerDiagnosticsSummaryDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::ServerDiagnosticsSummaryDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ServerDiagnosticsSummaryDataType::create);
  }
}

uint32_t& ServerDiagnosticsSummaryDataType::server_view_count()
{
  return mServerViewCount;
}

const uint32_t& ServerDiagnosticsSummaryDataType::server_view_count() const
{
  return mServerViewCount;
}

uint32_t& ServerDiagnosticsSummaryDataType::current_session_count()
{
  return mCurrentSessionCount;
}

const uint32_t& ServerDiagnosticsSummaryDataType::current_session_count() const
{
  return mCurrentSessionCount;
}

uint32_t& ServerDiagnosticsSummaryDataType::cumulated_session_count()
{
  return mCumulatedSessionCount;
}

const uint32_t& ServerDiagnosticsSummaryDataType::cumulated_session_count() const
{
  return mCumulatedSessionCount;
}

uint32_t& ServerDiagnosticsSummaryDataType::security_rejected_session_count()
{
  return mSecurityRejectedSessionCount;
}

const uint32_t& ServerDiagnosticsSummaryDataType::security_rejected_session_count() const
{
  return mSecurityRejectedSessionCount;
}

uint32_t& ServerDiagnosticsSummaryDataType::rejected_session_count()
{
  return mRejectedSessionCount;
}

const uint32_t& ServerDiagnosticsSummaryDataType::rejected_session_count() const
{
  return mRejectedSessionCount;
}

uint32_t& ServerDiagnosticsSummaryDataType::session_timeout_count()
{
  return mSessionTimeoutCount;
}

const uint32_t& ServerDiagnosticsSummaryDataType::session_timeout_count() const
{
  return mSessionTimeoutCount;
}

uint32_t& ServerDiagnosticsSummaryDataType::session_abort_count()
{
  return mSessionAbortCount;
}

const uint32_t& ServerDiagnosticsSummaryDataType::session_abort_count() const
{
  return mSessionAbortCount;
}

uint32_t& ServerDiagnosticsSummaryDataType::current_subscription_count()
{
  return mCurrentSubscriptionCount;
}

const uint32_t& ServerDiagnosticsSummaryDataType::current_subscription_count() const
{
  return mCurrentSubscriptionCount;
}

uint32_t& ServerDiagnosticsSummaryDataType::cumulated_subscription_count()
{
  return mCumulatedSubscriptionCount;
}

const uint32_t& ServerDiagnosticsSummaryDataType::cumulated_subscription_count() const
{
  return mCumulatedSubscriptionCount;
}

uint32_t& ServerDiagnosticsSummaryDataType::publishing_interval_count()
{
  return mPublishingIntervalCount;
}

const uint32_t& ServerDiagnosticsSummaryDataType::publishing_interval_count() const
{
  return mPublishingIntervalCount;
}

uint32_t& ServerDiagnosticsSummaryDataType::security_rejected_requests_count()
{
  return mSecurityRejectedRequestsCount;
}

const uint32_t& ServerDiagnosticsSummaryDataType::security_rejected_requests_count() const
{
  return mSecurityRejectedRequestsCount;
}

uint32_t& ServerDiagnosticsSummaryDataType::rejected_requests_count()
{
  return mRejectedRequestsCount;
}

const uint32_t& ServerDiagnosticsSummaryDataType::rejected_requests_count() const
{
  return mRejectedRequestsCount;
}

BuiltInTypeId ServerDiagnosticsSummaryDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::SemanticChangeStructureDataType
{
namespace
{
void encode(StackDepth limit, const ua::SemanticChangeStructureDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.affected());
  encoder.encode(limit, value.affected_type());
}

void encode(StackDepth limit, const ua::SemanticChangeStructureDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Affected", value.affected());
  encoder.encode(limit, "AffectedType", value.affected_type());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::SemanticChangeStructureDataType& value)
{
  decoder.decode(limit, value.affected());
  decoder.decode(limit, value.affected_type());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::SemanticChangeStructureDataType& value)
{
  decoder.decode(limit, "Affected", true, value.affected());
  decoder.decode(limit, "AffectedType", true, value.affected_type());
}
}  // namespace
}  // namespace detail::SemanticChangeStructureDataType

namespace detail::SemanticChangeStructureDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::SemanticChangeStructureDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::SemanticChangeStructureDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::SemanticChangeStructureDataType

namespace detail::SemanticChangeStructureDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::SemanticChangeStructureDataType>();
}
}  // namespace
}  // namespace detail::SemanticChangeStructureDataType

bool SemanticChangeStructureDataType::is_of_type(
  const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId SemanticChangeStructureDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId SemanticChangeStructureDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String SemanticChangeStructureDataType::type_name() const
{
  return typeName;
}

void SemanticChangeStructureDataType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SemanticChangeStructureDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SemanticChangeStructureDataType::encode(limit, *this, *xml);
  }
}

void SemanticChangeStructureDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SemanticChangeStructureDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SemanticChangeStructureDataType::encode_id(limit, ns, *xml);
  }
}

void SemanticChangeStructureDataType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::SemanticChangeStructureDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::SemanticChangeStructureDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> SemanticChangeStructureDataType::clone() const
{
  return make_unique<SemanticChangeStructureDataType>(*this);
}

void SemanticChangeStructureDataType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "affected=" + ua::to_string(affected());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "affected_type=" + ua::to_string(affected_type());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "affected=" + ua::to_string(affected());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "affected_type=" + ua::to_string(affected_type());
}

std::string SemanticChangeStructureDataType::to_string(int indent) const
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

void SemanticChangeStructureDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::SemanticChangeStructureDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::SemanticChangeStructureDataType::create);
  }
}

NodeId& SemanticChangeStructureDataType::affected()
{
  return mAffected;
}

const NodeId& SemanticChangeStructureDataType::affected() const
{
  return mAffected;
}

NodeId& SemanticChangeStructureDataType::affected_type()
{
  return mAffectedType;
}

const NodeId& SemanticChangeStructureDataType::affected_type() const
{
  return mAffectedType;
}

BuiltInTypeId SemanticChangeStructureDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ProgramDiagnostic2DataType
{
namespace
{
void encode(StackDepth limit, const ua::ProgramDiagnostic2DataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.create_session_id());
  encoder.encode(limit, value.create_client_name());
  encoder.encode(limit, value.invocation_creation_time());
  encoder.encode(limit, value.last_transition_time());
  encoder.encode(limit, value.last_method_call());
  encoder.encode(limit, value.last_method_session_id());
  encoder.encode(limit, value.last_method_input_arguments());
  encoder.encode(limit, value.last_method_output_arguments());
  encoder.encode(limit, value.last_method_input_values());
  encoder.encode(limit, value.last_method_output_values());
  encoder.encode(limit, value.last_method_call_time());
  encoder.encode(limit, value.last_method_return_status());
}

void encode(StackDepth limit, const ua::ProgramDiagnostic2DataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "CreateSessionId", value.create_session_id());
  encoder.encode(limit, "CreateClientName", value.create_client_name());
  encoder.encode(limit, "InvocationCreationTime", value.invocation_creation_time());
  encoder.encode(limit, "LastTransitionTime", value.last_transition_time());
  encoder.encode(limit, "LastMethodCall", value.last_method_call());
  encoder.encode(limit, "LastMethodSessionId", value.last_method_session_id());
  encoder.encode(limit, "LastMethodInputArguments", value.last_method_input_arguments());
  encoder.encode(limit, "LastMethodOutputArguments", value.last_method_output_arguments());
  encoder.encode(limit, "LastMethodInputValues", value.last_method_input_values());
  encoder.encode(limit, "LastMethodOutputValues", value.last_method_output_values());
  encoder.encode(limit, "LastMethodCallTime", value.last_method_call_time());
  encoder.encode(limit, "LastMethodReturnStatus", value.last_method_return_status());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ProgramDiagnostic2DataType& value)
{
  decoder.decode(limit, value.create_session_id());
  decoder.decode(limit, value.create_client_name());
  decoder.decode(limit, value.invocation_creation_time());
  decoder.decode(limit, value.last_transition_time());
  decoder.decode(limit, value.last_method_call());
  decoder.decode(limit, value.last_method_session_id());
  decoder.decode(limit, value.last_method_input_arguments());
  decoder.decode(limit, value.last_method_output_arguments());
  decoder.decode(limit, value.last_method_input_values());
  decoder.decode(limit, value.last_method_output_values());
  decoder.decode(limit, value.last_method_call_time());
  decoder.decode(limit, value.last_method_return_status());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ProgramDiagnostic2DataType& value)
{
  decoder.decode(limit, "CreateSessionId", true, value.create_session_id());
  decoder.decode(limit, "CreateClientName", true, value.create_client_name());
  decoder.decode(limit, "InvocationCreationTime", true, value.invocation_creation_time());
  decoder.decode(limit, "LastTransitionTime", true, value.last_transition_time());
  decoder.decode(limit, "LastMethodCall", true, value.last_method_call());
  decoder.decode(limit, "LastMethodSessionId", true, value.last_method_session_id());
  decoder.decode(limit, "LastMethodInputArguments", true, value.last_method_input_arguments());
  decoder.decode(limit, "LastMethodOutputArguments", true, value.last_method_output_arguments());
  decoder.decode(limit, "LastMethodInputValues", true, value.last_method_input_values());
  decoder.decode(limit, "LastMethodOutputValues", true, value.last_method_output_values());
  decoder.decode(limit, "LastMethodCallTime", true, value.last_method_call_time());
  decoder.decode(limit, "LastMethodReturnStatus", true, value.last_method_return_status());
}
}  // namespace
}  // namespace detail::ProgramDiagnostic2DataType

namespace detail::ProgramDiagnostic2DataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ProgramDiagnostic2DataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ProgramDiagnostic2DataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ProgramDiagnostic2DataType

namespace detail::ProgramDiagnostic2DataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ProgramDiagnostic2DataType>();
}
}  // namespace
}  // namespace detail::ProgramDiagnostic2DataType

bool ProgramDiagnostic2DataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ProgramDiagnostic2DataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ProgramDiagnostic2DataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ProgramDiagnostic2DataType::type_name() const
{
  return typeName;
}

void ProgramDiagnostic2DataType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ProgramDiagnostic2DataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ProgramDiagnostic2DataType::encode(limit, *this, *xml);
  }
}

void ProgramDiagnostic2DataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ProgramDiagnostic2DataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ProgramDiagnostic2DataType::encode_id(limit, ns, *xml);
  }
}

void ProgramDiagnostic2DataType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ProgramDiagnostic2DataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ProgramDiagnostic2DataType::decode(limit, *xml, *this);
  }
}

void ProgramDiagnostic2DataType::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  for (size_t i = 0; i < mLastMethodInputArguments.size(); ++i)
  {
    mLastMethodInputArguments[i].resolve(locales);
  }
  for (size_t i = 0; i < mLastMethodOutputArguments.size(); ++i)
  {
    mLastMethodOutputArguments[i].resolve(locales);
  }
}

unique_ptr<Structure> ProgramDiagnostic2DataType::clone() const
{
  return make_unique<ProgramDiagnostic2DataType>(*this);
}

void ProgramDiagnostic2DataType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "create_session_id=" + ua::to_string(create_session_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "create_client_name=" + ua::to_string(create_client_name());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "invocation_creation_time=" + ua::to_string(invocation_creation_time());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "last_transition_time=" + ua::to_string(last_transition_time());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "last_method_call=" + ua::to_string(last_method_call());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "last_method_session_id=" + ua::to_string(last_method_session_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "last_method_input_arguments=" + ua::to_string(last_method_input_arguments());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "last_method_output_arguments=" + ua::to_string(last_method_output_arguments());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "last_method_input_values=" + ua::to_string(last_method_input_values());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "last_method_output_values=" + ua::to_string(last_method_output_values());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "last_method_call_time=" + ua::to_string(last_method_call_time());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "last_method_return_status=" + ua::to_string(last_method_return_status());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "create_session_id=" + ua::to_string(create_session_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "create_client_name=" + ua::to_string(create_client_name());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "invocation_creation_time=" + ua::to_string(invocation_creation_time());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "last_transition_time=" + ua::to_string(last_transition_time());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "last_method_call=" + ua::to_string(last_method_call());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "last_method_session_id=" + ua::to_string(last_method_session_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "last_method_input_arguments=" + ua::to_string(last_method_input_arguments());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "last_method_output_arguments=" + ua::to_string(last_method_output_arguments());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "last_method_input_values=" + ua::to_string(last_method_input_values());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "last_method_output_values=" + ua::to_string(last_method_output_values());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "last_method_call_time=" + ua::to_string(last_method_call_time());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "last_method_return_status=" + ua::to_string(last_method_return_status());
}

std::string ProgramDiagnostic2DataType::to_string(int indent) const
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

void ProgramDiagnostic2DataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::ProgramDiagnostic2DataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ProgramDiagnostic2DataType::create);
  }
}

NodeId& ProgramDiagnostic2DataType::create_session_id()
{
  return mCreateSessionId;
}

const NodeId& ProgramDiagnostic2DataType::create_session_id() const
{
  return mCreateSessionId;
}

String& ProgramDiagnostic2DataType::create_client_name()
{
  return mCreateClientName;
}

const String& ProgramDiagnostic2DataType::create_client_name() const
{
  return mCreateClientName;
}

UtcTime& ProgramDiagnostic2DataType::invocation_creation_time()
{
  return mInvocationCreationTime;
}

const UtcTime& ProgramDiagnostic2DataType::invocation_creation_time() const
{
  return mInvocationCreationTime;
}

UtcTime& ProgramDiagnostic2DataType::last_transition_time()
{
  return mLastTransitionTime;
}

const UtcTime& ProgramDiagnostic2DataType::last_transition_time() const
{
  return mLastTransitionTime;
}

String& ProgramDiagnostic2DataType::last_method_call()
{
  return mLastMethodCall;
}

const String& ProgramDiagnostic2DataType::last_method_call() const
{
  return mLastMethodCall;
}

NodeId& ProgramDiagnostic2DataType::last_method_session_id()
{
  return mLastMethodSessionId;
}

const NodeId& ProgramDiagnostic2DataType::last_method_session_id() const
{
  return mLastMethodSessionId;
}

Array<Argument>& ProgramDiagnostic2DataType::last_method_input_arguments()
{
  return mLastMethodInputArguments;
}

const Array<Argument>& ProgramDiagnostic2DataType::last_method_input_arguments() const
{
  return mLastMethodInputArguments;
}

Array<Argument>& ProgramDiagnostic2DataType::last_method_output_arguments()
{
  return mLastMethodOutputArguments;
}

const Array<Argument>& ProgramDiagnostic2DataType::last_method_output_arguments() const
{
  return mLastMethodOutputArguments;
}

Array<Variant>& ProgramDiagnostic2DataType::last_method_input_values()
{
  return mLastMethodInputValues;
}

const Array<Variant>& ProgramDiagnostic2DataType::last_method_input_values() const
{
  return mLastMethodInputValues;
}

Array<Variant>& ProgramDiagnostic2DataType::last_method_output_values()
{
  return mLastMethodOutputValues;
}

const Array<Variant>& ProgramDiagnostic2DataType::last_method_output_values() const
{
  return mLastMethodOutputValues;
}

UtcTime& ProgramDiagnostic2DataType::last_method_call_time()
{
  return mLastMethodCallTime;
}

const UtcTime& ProgramDiagnostic2DataType::last_method_call_time() const
{
  return mLastMethodCallTime;
}

StatusCode& ProgramDiagnostic2DataType::last_method_return_status()
{
  return mLastMethodReturnStatus;
}

const StatusCode& ProgramDiagnostic2DataType::last_method_return_status() const
{
  return mLastMethodReturnStatus;
}

BuiltInTypeId ProgramDiagnostic2DataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::FindServersRequest
{
namespace
{
void encode(StackDepth limit, const ua::FindServersRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.endpoint_url());
  encoder.encode(limit, value.locale_ids());
  encoder.encode(limit, value.server_uris());
}

void encode(StackDepth limit, const ua::FindServersRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "EndpointUrl", value.endpoint_url());
  encoder.encode(limit, "LocaleIds", value.locale_ids());
  encoder.encode(limit, "ServerUris", value.server_uris());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::FindServersRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.endpoint_url());
  decoder.decode(limit, value.locale_ids());
  decoder.decode(limit, value.server_uris());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::FindServersRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "EndpointUrl", true, value.endpoint_url());
  decoder.decode(limit, "LocaleIds", true, value.locale_ids());
  decoder.decode(limit, "ServerUris", true, value.server_uris());
}
}  // namespace
}  // namespace detail::FindServersRequest

namespace detail::FindServersRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::FindServersRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::FindServersRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::FindServersRequest

namespace detail::FindServersRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::FindServersRequest>();
}
}  // namespace
}  // namespace detail::FindServersRequest

bool FindServersRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId FindServersRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId FindServersRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String FindServersRequest::type_name() const
{
  return typeName;
}

void FindServersRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::FindServersRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::FindServersRequest::encode(limit, *this, *xml);
  }
}

void FindServersRequest::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::FindServersRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::FindServersRequest::encode_id(limit, ns, *xml);
  }
}

void FindServersRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::FindServersRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::FindServersRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> FindServersRequest::clone() const
{
  return make_unique<FindServersRequest>(*this);
}

void FindServersRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "endpoint_url=" + ua::to_string(endpoint_url());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "locale_ids=" + ua::to_string(locale_ids());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "server_uris=" + ua::to_string(server_uris());
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
  output += "endpoint_url=" + ua::to_string(endpoint_url());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "locale_ids=" + ua::to_string(locale_ids());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "server_uris=" + ua::to_string(server_uris());
}

std::string FindServersRequest::to_string(int indent) const
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

void FindServersRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::FindServersRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::FindServersRequest::create);
  }
}

RequestHeader& FindServersRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& FindServersRequest::request_header() const
{
  return mRequestHeader;
}

String& FindServersRequest::endpoint_url()
{
  return mEndpointUrl;
}

const String& FindServersRequest::endpoint_url() const
{
  return mEndpointUrl;
}

Array<LocaleId>& FindServersRequest::locale_ids()
{
  return mLocaleIds;
}

const Array<LocaleId>& FindServersRequest::locale_ids() const
{
  return mLocaleIds;
}

Array<String>& FindServersRequest::server_uris()
{
  return mServerUris;
}

const Array<String>& FindServersRequest::server_uris() const
{
  return mServerUris;
}

BuiltInTypeId FindServersRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::RegisterServer2Request
{
namespace
{
void encode(StackDepth limit, const ua::RegisterServer2Request& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.server());
  encoder.encode(limit, value.discovery_configuration());
}

void encode(StackDepth limit, const ua::RegisterServer2Request& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "Server", value.server());
  encoder.encode(limit, "DiscoveryConfiguration", value.discovery_configuration());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::RegisterServer2Request& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.server());
  decoder.decode(limit, value.discovery_configuration());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::RegisterServer2Request& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "Server", true, value.server());
  decoder.decode(limit, "DiscoveryConfiguration", true, value.discovery_configuration());
}
}  // namespace
}  // namespace detail::RegisterServer2Request

namespace detail::RegisterServer2Request
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::RegisterServer2Request::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::RegisterServer2Request::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::RegisterServer2Request

namespace detail::RegisterServer2Request
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::RegisterServer2Request>();
}
}  // namespace
}  // namespace detail::RegisterServer2Request

bool RegisterServer2Request::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId RegisterServer2Request::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId RegisterServer2Request::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String RegisterServer2Request::type_name() const
{
  return typeName;
}

void RegisterServer2Request::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RegisterServer2Request::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RegisterServer2Request::encode(limit, *this, *xml);
  }
}

void RegisterServer2Request::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RegisterServer2Request::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RegisterServer2Request::encode_id(limit, ns, *xml);
  }
}

void RegisterServer2Request::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::RegisterServer2Request::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::RegisterServer2Request::decode(limit, *xml, *this);
  }
}

void RegisterServer2Request::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  mServer.resolve(locales);
}

unique_ptr<Structure> RegisterServer2Request::clone() const
{
  return make_unique<RegisterServer2Request>(*this);
}

void RegisterServer2Request::append_fields(std::string& output, int indent) const
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
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "discovery_configuration=" + ua::to_string(discovery_configuration(), indent);
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
  if (!output.empty())
  {
    output += ", ";
  }
  output += "discovery_configuration=" + ua::to_string(discovery_configuration());
}

std::string RegisterServer2Request::to_string(int indent) const
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

void RegisterServer2Request::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::RegisterServer2Request::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::RegisterServer2Request::create);
  }
}

RequestHeader& RegisterServer2Request::request_header()
{
  return mRequestHeader;
}

const RequestHeader& RegisterServer2Request::request_header() const
{
  return mRequestHeader;
}

RegisteredServer& RegisterServer2Request::server()
{
  return mServer;
}

const RegisteredServer& RegisterServer2Request::server() const
{
  return mServer;
}

Array<RefStructure<Structure>>& RegisterServer2Request::discovery_configuration()
{
  return mDiscoveryConfiguration;
}

const Array<RefStructure<Structure>>& RegisterServer2Request::discovery_configuration() const
{
  return mDiscoveryConfiguration;
}

BuiltInTypeId RegisterServer2Request::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::CreateSessionRequest
{
namespace
{
void encode(StackDepth limit, const ua::CreateSessionRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.client_description());
  encoder.encode(limit, value.server_uri());
  encoder.encode(limit, value.endpoint_url());
  encoder.encode(limit, value.session_name());
  encoder.encode(limit, value.client_nonce());
  encoder.encode(limit, value.client_certificate());
  encoder.encode(limit, value.requested_session_timeout());
  encoder.encode(limit, value.max_response_message_size());
}

void encode(StackDepth limit, const ua::CreateSessionRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "ClientDescription", value.client_description());
  encoder.encode(limit, "ServerUri", value.server_uri());
  encoder.encode(limit, "EndpointUrl", value.endpoint_url());
  encoder.encode(limit, "SessionName", value.session_name());
  encoder.encode(limit, "ClientNonce", value.client_nonce());
  encoder.encode(limit, "ClientCertificate", value.client_certificate());
  encoder.encode(limit, "RequestedSessionTimeout", value.requested_session_timeout());
  encoder.encode(limit, "MaxResponseMessageSize", value.max_response_message_size());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::CreateSessionRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.client_description());
  decoder.decode(limit, value.server_uri());
  decoder.decode(limit, value.endpoint_url());
  decoder.decode(limit, value.session_name());
  decoder.decode(limit, value.client_nonce());
  decoder.decode(limit, value.client_certificate());
  decoder.decode(limit, value.requested_session_timeout());
  decoder.decode(limit, value.max_response_message_size());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::CreateSessionRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "ClientDescription", true, value.client_description());
  decoder.decode(limit, "ServerUri", true, value.server_uri());
  decoder.decode(limit, "EndpointUrl", true, value.endpoint_url());
  decoder.decode(limit, "SessionName", true, value.session_name());
  decoder.decode(limit, "ClientNonce", true, value.client_nonce());
  decoder.decode(limit, "ClientCertificate", true, value.client_certificate());
  decoder.decode(limit, "RequestedSessionTimeout", true, value.requested_session_timeout());
  decoder.decode(limit, "MaxResponseMessageSize", true, value.max_response_message_size());
}
}  // namespace
}  // namespace detail::CreateSessionRequest

namespace detail::CreateSessionRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::CreateSessionRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::CreateSessionRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::CreateSessionRequest

namespace detail::CreateSessionRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::CreateSessionRequest>();
}
}  // namespace
}  // namespace detail::CreateSessionRequest

bool CreateSessionRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId CreateSessionRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId CreateSessionRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String CreateSessionRequest::type_name() const
{
  return typeName;
}

void CreateSessionRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CreateSessionRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CreateSessionRequest::encode(limit, *this, *xml);
  }
}

void CreateSessionRequest::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CreateSessionRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CreateSessionRequest::encode_id(limit, ns, *xml);
  }
}

void CreateSessionRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::CreateSessionRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::CreateSessionRequest::decode(limit, *xml, *this);
  }
}

void CreateSessionRequest::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  mClientDescription.resolve(locales);
}

unique_ptr<Structure> CreateSessionRequest::clone() const
{
  return make_unique<CreateSessionRequest>(*this);
}

void CreateSessionRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "client_description=" + ua::to_string(client_description());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "server_uri=" + ua::to_string(server_uri());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "endpoint_url=" + ua::to_string(endpoint_url());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "session_name=" + ua::to_string(session_name());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "client_nonce=" + ua::to_string(client_nonce());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "client_certificate=" + ua::to_string(client_certificate());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "requested_session_timeout=" + ua::to_string(requested_session_timeout());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "max_response_message_size=" + ua::to_string(max_response_message_size());
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
  output += "client_description=" + ua::to_string(client_description());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "server_uri=" + ua::to_string(server_uri());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "endpoint_url=" + ua::to_string(endpoint_url());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "session_name=" + ua::to_string(session_name());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "client_nonce=" + ua::to_string(client_nonce());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "client_certificate=" + ua::to_string(client_certificate());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "requested_session_timeout=" + ua::to_string(requested_session_timeout());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "max_response_message_size=" + ua::to_string(max_response_message_size());
}

std::string CreateSessionRequest::to_string(int indent) const
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

void CreateSessionRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::CreateSessionRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::CreateSessionRequest::create);
  }
}

RequestHeader& CreateSessionRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& CreateSessionRequest::request_header() const
{
  return mRequestHeader;
}

ApplicationDescription& CreateSessionRequest::client_description()
{
  return mClientDescription;
}

const ApplicationDescription& CreateSessionRequest::client_description() const
{
  return mClientDescription;
}

String& CreateSessionRequest::server_uri()
{
  return mServerUri;
}

const String& CreateSessionRequest::server_uri() const
{
  return mServerUri;
}

String& CreateSessionRequest::endpoint_url()
{
  return mEndpointUrl;
}

const String& CreateSessionRequest::endpoint_url() const
{
  return mEndpointUrl;
}

String& CreateSessionRequest::session_name()
{
  return mSessionName;
}

const String& CreateSessionRequest::session_name() const
{
  return mSessionName;
}

ByteString& CreateSessionRequest::client_nonce()
{
  return mClientNonce;
}

const ByteString& CreateSessionRequest::client_nonce() const
{
  return mClientNonce;
}

ApplicationInstanceCertificate& CreateSessionRequest::client_certificate()
{
  return mClientCertificate;
}

const ApplicationInstanceCertificate& CreateSessionRequest::client_certificate() const
{
  return mClientCertificate;
}

Duration& CreateSessionRequest::requested_session_timeout()
{
  return mRequestedSessionTimeout;
}

const Duration& CreateSessionRequest::requested_session_timeout() const
{
  return mRequestedSessionTimeout;
}

uint32_t& CreateSessionRequest::max_response_message_size()
{
  return mMaxResponseMessageSize;
}

const uint32_t& CreateSessionRequest::max_response_message_size() const
{
  return mMaxResponseMessageSize;
}

BuiltInTypeId CreateSessionRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::NodeAttributes
{
namespace
{
void encode(StackDepth limit, const ua::NodeAttributes& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.specified_attributes());
  encoder.encode(limit, value.display_name());
  encoder.encode(limit, value.description());
  encoder.encode(limit, value.write_mask());
  encoder.encode(limit, value.user_write_mask());
}

void encode(StackDepth limit, const ua::NodeAttributes& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "SpecifiedAttributes", value.specified_attributes());
  encoder.encode(limit, "DisplayName", value.display_name());
  encoder.encode(limit, "Description", value.description());
  encoder.encode(limit, "WriteMask", value.write_mask());
  encoder.encode(limit, "UserWriteMask", value.user_write_mask());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::NodeAttributes& value)
{
  decoder.decode(limit, value.specified_attributes());
  decoder.decode(limit, value.display_name());
  decoder.decode(limit, value.description());
  decoder.decode(limit, value.write_mask());
  decoder.decode(limit, value.user_write_mask());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::NodeAttributes& value)
{
  decoder.decode(limit, "SpecifiedAttributes", true, value.specified_attributes());
  decoder.decode(limit, "DisplayName", true, value.display_name());
  decoder.decode(limit, "Description", true, value.description());
  decoder.decode(limit, "WriteMask", true, value.write_mask());
  decoder.decode(limit, "UserWriteMask", true, value.user_write_mask());
}
}  // namespace
}  // namespace detail::NodeAttributes

namespace detail::NodeAttributes
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::NodeAttributes::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::NodeAttributes::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::NodeAttributes

namespace detail::NodeAttributes
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::NodeAttributes>();
}
}  // namespace
}  // namespace detail::NodeAttributes

bool NodeAttributes::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId NodeAttributes::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId NodeAttributes::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String NodeAttributes::type_name() const
{
  return typeName;
}

void NodeAttributes::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::NodeAttributes::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::NodeAttributes::encode(limit, *this, *xml);
  }
}

void NodeAttributes::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::NodeAttributes::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::NodeAttributes::encode_id(limit, ns, *xml);
  }
}

void NodeAttributes::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::NodeAttributes::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::NodeAttributes::decode(limit, *xml, *this);
  }
}

void NodeAttributes::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  mDisplayName = mDisplayName.resolve(locales);
  mDescription = mDescription.resolve(locales);
}

unique_ptr<Structure> NodeAttributes::clone() const
{
  return make_unique<NodeAttributes>(*this);
}

void NodeAttributes::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "specified_attributes=" + ua::to_string(specified_attributes());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "display_name=" + ua::to_string(display_name());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "description=" + ua::to_string(description());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "write_mask=" + ua::to_string(write_mask());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "user_write_mask=" + ua::to_string(user_write_mask());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "specified_attributes=" + ua::to_string(specified_attributes());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "display_name=" + ua::to_string(display_name());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "description=" + ua::to_string(description());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "write_mask=" + ua::to_string(write_mask());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "user_write_mask=" + ua::to_string(user_write_mask());
}

std::string NodeAttributes::to_string(int indent) const
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

void NodeAttributes::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::NodeAttributes::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::NodeAttributes::create);
  }
}

uint32_t& NodeAttributes::specified_attributes()
{
  return mSpecifiedAttributes;
}

const uint32_t& NodeAttributes::specified_attributes() const
{
  return mSpecifiedAttributes;
}

LocalizedText& NodeAttributes::display_name()
{
  return mDisplayName;
}

const LocalizedText& NodeAttributes::display_name() const
{
  return mDisplayName;
}

LocalizedText& NodeAttributes::description()
{
  return mDescription;
}

const LocalizedText& NodeAttributes::description() const
{
  return mDescription;
}

uint32_t& NodeAttributes::write_mask()
{
  return mWriteMask;
}

const uint32_t& NodeAttributes::write_mask() const
{
  return mWriteMask;
}

uint32_t& NodeAttributes::user_write_mask()
{
  return mUserWriteMask;
}

const uint32_t& NodeAttributes::user_write_mask() const
{
  return mUserWriteMask;
}

BuiltInTypeId NodeAttributes::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ViewAttributes
{
namespace
{
void encode(StackDepth limit, const ua::ViewAttributes& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.contains_no_loops());
  encoder.encode(limit, value.event_notifier());
}

void encode(StackDepth limit, const ua::ViewAttributes& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ContainsNoLoops", value.contains_no_loops());
  encoder.encode(limit, "EventNotifier", value.event_notifier());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ViewAttributes& value)
{
  decoder.decode(limit, value.contains_no_loops());
  decoder.decode(limit, value.event_notifier());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ViewAttributes& value)
{
  decoder.decode(limit, "ContainsNoLoops", true, value.contains_no_loops());
  decoder.decode(limit, "EventNotifier", true, value.event_notifier());
}
}  // namespace
}  // namespace detail::ViewAttributes

namespace detail::ViewAttributes
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ViewAttributes::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ViewAttributes::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ViewAttributes

namespace detail::ViewAttributes
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ViewAttributes>();
}
}  // namespace
}  // namespace detail::ViewAttributes

bool ViewAttributes::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return NodeAttributes::is_of_type(ns, dataTypeId);
}

NodeId ViewAttributes::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ViewAttributes::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ViewAttributes::type_name() const
{
  return typeName;
}

void ViewAttributes::encode(StackDepth limit, Encoder& encoder) const
{

  NodeAttributes::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ViewAttributes::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ViewAttributes::encode(limit, *this, *xml);
  }
}

void ViewAttributes::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ViewAttributes::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ViewAttributes::encode_id(limit, ns, *xml);
  }
}

void ViewAttributes::decode(StackDepth limit, Decoder& decoder)
{

  NodeAttributes::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ViewAttributes::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ViewAttributes::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ViewAttributes::clone() const
{
  return make_unique<ViewAttributes>(*this);
}

void ViewAttributes::append_fields(std::string& output, int indent) const
{
  NodeAttributes::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "contains_no_loops=" + ua::to_string(contains_no_loops());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "event_notifier=" + ua::to_string(event_notifier());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "contains_no_loops=" + ua::to_string(contains_no_loops());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "event_notifier=" + ua::to_string(event_notifier());
}

std::string ViewAttributes::to_string(int indent) const
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

void ViewAttributes::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ViewAttributes::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ViewAttributes::create);
  }
}

bool& ViewAttributes::contains_no_loops()
{
  return mContainsNoLoops;
}

const bool& ViewAttributes::contains_no_loops() const
{
  return mContainsNoLoops;
}

uint8_t& ViewAttributes::event_notifier()
{
  return mEventNotifier;
}

const uint8_t& ViewAttributes::event_notifier() const
{
  return mEventNotifier;
}

BuiltInTypeId ViewAttributes::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::DeleteNodesRequest
{
namespace
{
void encode(StackDepth limit, const ua::DeleteNodesRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.nodes_to_delete());
}

void encode(StackDepth limit, const ua::DeleteNodesRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "NodesToDelete", value.nodes_to_delete());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::DeleteNodesRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.nodes_to_delete());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::DeleteNodesRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "NodesToDelete", true, value.nodes_to_delete());
}
}  // namespace
}  // namespace detail::DeleteNodesRequest

namespace detail::DeleteNodesRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::DeleteNodesRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::DeleteNodesRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::DeleteNodesRequest

namespace detail::DeleteNodesRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::DeleteNodesRequest>();
}
}  // namespace
}  // namespace detail::DeleteNodesRequest

bool DeleteNodesRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId DeleteNodesRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId DeleteNodesRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String DeleteNodesRequest::type_name() const
{
  return typeName;
}

void DeleteNodesRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DeleteNodesRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DeleteNodesRequest::encode(limit, *this, *xml);
  }
}

void DeleteNodesRequest::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DeleteNodesRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DeleteNodesRequest::encode_id(limit, ns, *xml);
  }
}

void DeleteNodesRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::DeleteNodesRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::DeleteNodesRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> DeleteNodesRequest::clone() const
{
  return make_unique<DeleteNodesRequest>(*this);
}

void DeleteNodesRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "nodes_to_delete=" + ua::to_string(nodes_to_delete());
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
  output += "nodes_to_delete=" + ua::to_string(nodes_to_delete());
}

std::string DeleteNodesRequest::to_string(int indent) const
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

void DeleteNodesRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::DeleteNodesRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::DeleteNodesRequest::create);
  }
}

RequestHeader& DeleteNodesRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& DeleteNodesRequest::request_header() const
{
  return mRequestHeader;
}

Array<DeleteNodesItem>& DeleteNodesRequest::nodes_to_delete()
{
  return mNodesToDelete;
}

const Array<DeleteNodesItem>& DeleteNodesRequest::nodes_to_delete() const
{
  return mNodesToDelete;
}

BuiltInTypeId DeleteNodesRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::BrowseRequest
{
namespace
{
void encode(StackDepth limit, const ua::BrowseRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.view());
  encoder.encode(limit, value.requested_max_references_per_node());
  encoder.encode(limit, value.nodes_to_browse());
}

void encode(StackDepth limit, const ua::BrowseRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "View", value.view());
  encoder.encode(limit, "RequestedMaxReferencesPerNode", value.requested_max_references_per_node());
  encoder.encode(limit, "NodesToBrowse", value.nodes_to_browse());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::BrowseRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.view());
  decoder.decode(limit, value.requested_max_references_per_node());
  decoder.decode(limit, value.nodes_to_browse());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::BrowseRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "View", true, value.view());
  decoder.decode(limit, "RequestedMaxReferencesPerNode", true, value.requested_max_references_per_node());
  decoder.decode(limit, "NodesToBrowse", true, value.nodes_to_browse());
}
}  // namespace
}  // namespace detail::BrowseRequest

namespace detail::BrowseRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::BrowseRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::BrowseRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::BrowseRequest

namespace detail::BrowseRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::BrowseRequest>();
}
}  // namespace
}  // namespace detail::BrowseRequest

bool BrowseRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId BrowseRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId BrowseRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String BrowseRequest::type_name() const
{
  return typeName;
}

void BrowseRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::BrowseRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::BrowseRequest::encode(limit, *this, *xml);
  }
}

void BrowseRequest::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::BrowseRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::BrowseRequest::encode_id(limit, ns, *xml);
  }
}

void BrowseRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::BrowseRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::BrowseRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> BrowseRequest::clone() const
{
  return make_unique<BrowseRequest>(*this);
}

void BrowseRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "view=" + ua::to_string(view());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "requested_max_references_per_node=" + ua::to_string(requested_max_references_per_node());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "nodes_to_browse=" + ua::to_string(nodes_to_browse());
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
  output += "view=" + ua::to_string(view());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "requested_max_references_per_node=" + ua::to_string(requested_max_references_per_node());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "nodes_to_browse=" + ua::to_string(nodes_to_browse());
}

std::string BrowseRequest::to_string(int indent) const
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

void BrowseRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::BrowseRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::BrowseRequest::create);
  }
}

RequestHeader& BrowseRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& BrowseRequest::request_header() const
{
  return mRequestHeader;
}

ViewDescription& BrowseRequest::view()
{
  return mView;
}

const ViewDescription& BrowseRequest::view() const
{
  return mView;
}

Counter& BrowseRequest::requested_max_references_per_node()
{
  return mRequestedMaxReferencesPerNode;
}

const Counter& BrowseRequest::requested_max_references_per_node() const
{
  return mRequestedMaxReferencesPerNode;
}

Array<BrowseDescription>& BrowseRequest::nodes_to_browse()
{
  return mNodesToBrowse;
}

const Array<BrowseDescription>& BrowseRequest::nodes_to_browse() const
{
  return mNodesToBrowse;
}

BuiltInTypeId BrowseRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::TranslateBrowsePathsToNodeIdsResponse
{
namespace
{
void encode(
  StackDepth limit, const ua::TranslateBrowsePathsToNodeIdsResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.results());
  encoder.encode(limit, value.diagnostic_infos());
}

void encode(StackDepth limit, const ua::TranslateBrowsePathsToNodeIdsResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "Results", value.results());
  encoder.encode(limit, "DiagnosticInfos", value.diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::TranslateBrowsePathsToNodeIdsResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.results());
  decoder.decode(limit, value.diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::TranslateBrowsePathsToNodeIdsResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "Results", true, value.results());
  decoder.decode(limit, "DiagnosticInfos", true, value.diagnostic_infos());
}
}  // namespace
}  // namespace detail::TranslateBrowsePathsToNodeIdsResponse

namespace detail::TranslateBrowsePathsToNodeIdsResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::TranslateBrowsePathsToNodeIdsResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::TranslateBrowsePathsToNodeIdsResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::TranslateBrowsePathsToNodeIdsResponse

namespace detail::TranslateBrowsePathsToNodeIdsResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::TranslateBrowsePathsToNodeIdsResponse>();
}
}  // namespace
}  // namespace detail::TranslateBrowsePathsToNodeIdsResponse

bool TranslateBrowsePathsToNodeIdsResponse::is_of_type(
  const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId TranslateBrowsePathsToNodeIdsResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId TranslateBrowsePathsToNodeIdsResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String TranslateBrowsePathsToNodeIdsResponse::type_name() const
{
  return typeName;
}

void TranslateBrowsePathsToNodeIdsResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::TranslateBrowsePathsToNodeIdsResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::TranslateBrowsePathsToNodeIdsResponse::encode(limit, *this, *xml);
  }
}

void TranslateBrowsePathsToNodeIdsResponse::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::TranslateBrowsePathsToNodeIdsResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::TranslateBrowsePathsToNodeIdsResponse::encode_id(limit, ns, *xml);
  }
}

void TranslateBrowsePathsToNodeIdsResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::TranslateBrowsePathsToNodeIdsResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::TranslateBrowsePathsToNodeIdsResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> TranslateBrowsePathsToNodeIdsResponse::clone() const
{
  return make_unique<TranslateBrowsePathsToNodeIdsResponse>(*this);
}

void TranslateBrowsePathsToNodeIdsResponse::append_fields(std::string& output, int indent) const
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

std::string TranslateBrowsePathsToNodeIdsResponse::to_string(int indent) const
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

void TranslateBrowsePathsToNodeIdsResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::TranslateBrowsePathsToNodeIdsResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(
      NodeId(defaultXmlEncodingId), detail::TranslateBrowsePathsToNodeIdsResponse::create);
  }
}

ResponseHeader& TranslateBrowsePathsToNodeIdsResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& TranslateBrowsePathsToNodeIdsResponse::response_header() const
{
  return mResponseHeader;
}

Array<BrowsePathResult>& TranslateBrowsePathsToNodeIdsResponse::results()
{
  return mResults;
}

const Array<BrowsePathResult>& TranslateBrowsePathsToNodeIdsResponse::results() const
{
  return mResults;
}

Array<DiagnosticInfo>& TranslateBrowsePathsToNodeIdsResponse::diagnostic_infos()
{
  return mDiagnosticInfos;
}

const Array<DiagnosticInfo>& TranslateBrowsePathsToNodeIdsResponse::diagnostic_infos() const
{
  return mDiagnosticInfos;
}

BuiltInTypeId TranslateBrowsePathsToNodeIdsResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::NodeReference
{
namespace
{
void encode(StackDepth limit, const ua::NodeReference& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.node_id());
  encoder.encode(limit, value.reference_type_id());
  encoder.encode(limit, value.is_forward());
  encoder.encode(limit, value.referenced_node_ids());
}

void encode(StackDepth limit, const ua::NodeReference& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "NodeId", value.node_id());
  encoder.encode(limit, "ReferenceTypeId", value.reference_type_id());
  encoder.encode(limit, "IsForward", value.is_forward());
  encoder.encode(limit, "ReferencedNodeIds", value.referenced_node_ids());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::NodeReference& value)
{
  decoder.decode(limit, value.node_id());
  decoder.decode(limit, value.reference_type_id());
  decoder.decode(limit, value.is_forward());
  decoder.decode(limit, value.referenced_node_ids());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::NodeReference& value)
{
  decoder.decode(limit, "NodeId", true, value.node_id());
  decoder.decode(limit, "ReferenceTypeId", true, value.reference_type_id());
  decoder.decode(limit, "IsForward", true, value.is_forward());
  decoder.decode(limit, "ReferencedNodeIds", true, value.referenced_node_ids());
}
}  // namespace
}  // namespace detail::NodeReference

namespace detail::NodeReference
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::NodeReference::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::NodeReference::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::NodeReference

namespace detail::NodeReference
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::NodeReference>();
}
}  // namespace
}  // namespace detail::NodeReference

bool NodeReference::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId NodeReference::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId NodeReference::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String NodeReference::type_name() const
{
  return typeName;
}

void NodeReference::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::NodeReference::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::NodeReference::encode(limit, *this, *xml);
  }
}

void NodeReference::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::NodeReference::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::NodeReference::encode_id(limit, ns, *xml);
  }
}

void NodeReference::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::NodeReference::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::NodeReference::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> NodeReference::clone() const
{
  return make_unique<NodeReference>(*this);
}

void NodeReference::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
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
    output += pad + "referenced_node_ids=" + ua::to_string(referenced_node_ids());
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
  output += "referenced_node_ids=" + ua::to_string(referenced_node_ids());
}

std::string NodeReference::to_string(int indent) const
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

void NodeReference::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::NodeReference::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::NodeReference::create);
  }
}

NodeId& NodeReference::node_id()
{
  return mNodeId;
}

const NodeId& NodeReference::node_id() const
{
  return mNodeId;
}

NodeId& NodeReference::reference_type_id()
{
  return mReferenceTypeId;
}

const NodeId& NodeReference::reference_type_id() const
{
  return mReferenceTypeId;
}

bool& NodeReference::is_forward()
{
  return mIsForward;
}

const bool& NodeReference::is_forward() const
{
  return mIsForward;
}

Array<NodeId>& NodeReference::referenced_node_ids()
{
  return mReferencedNodeIds;
}

const Array<NodeId>& NodeReference::referenced_node_ids() const
{
  return mReferencedNodeIds;
}

BuiltInTypeId NodeReference::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ReadValueId
{
namespace
{
void encode(StackDepth limit, const ua::ReadValueId& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.node_id());
  encoder.encode(limit, value.attribute_id());
  encoder.encode(limit, value.index_range());
  encoder.encode(limit, value.data_encoding());
}

void encode(StackDepth limit, const ua::ReadValueId& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "NodeId", value.node_id());
  encoder.encode(limit, "AttributeId", value.attribute_id());
  encoder.encode(limit, "IndexRange", value.index_range());
  encoder.encode(limit, "DataEncoding", value.data_encoding());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ReadValueId& value)
{
  decoder.decode(limit, value.node_id());
  decoder.decode(limit, value.attribute_id());
  decoder.decode(limit, value.index_range());
  decoder.decode(limit, value.data_encoding());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ReadValueId& value)
{
  decoder.decode(limit, "NodeId", true, value.node_id());
  decoder.decode(limit, "AttributeId", true, value.attribute_id());
  decoder.decode(limit, "IndexRange", true, value.index_range());
  decoder.decode(limit, "DataEncoding", true, value.data_encoding());
}
}  // namespace
}  // namespace detail::ReadValueId

namespace detail::ReadValueId
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ReadValueId::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ReadValueId::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ReadValueId

namespace detail::ReadValueId
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ReadValueId>();
}
}  // namespace
}  // namespace detail::ReadValueId

bool ReadValueId::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ReadValueId::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ReadValueId::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ReadValueId::type_name() const
{
  return typeName;
}

void ReadValueId::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReadValueId::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReadValueId::encode(limit, *this, *xml);
  }
}

void ReadValueId::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReadValueId::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReadValueId::encode_id(limit, ns, *xml);
  }
}

void ReadValueId::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ReadValueId::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ReadValueId::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ReadValueId::clone() const
{
  return make_unique<ReadValueId>(*this);
}

void ReadValueId::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
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
    output += pad + "attribute_id=" + ua::to_string(attribute_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "index_range=" + ua::to_string(index_range());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "data_encoding=" + ua::to_string(data_encoding());
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
  output += "attribute_id=" + ua::to_string(attribute_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "index_range=" + ua::to_string(index_range());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "data_encoding=" + ua::to_string(data_encoding());
}

std::string ReadValueId::to_string(int indent) const
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

void ReadValueId::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ReadValueId::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ReadValueId::create);
  }
}

NodeId& ReadValueId::node_id()
{
  return mNodeId;
}

const NodeId& ReadValueId::node_id() const
{
  return mNodeId;
}

IntegerId& ReadValueId::attribute_id()
{
  return mAttributeId;
}

const IntegerId& ReadValueId::attribute_id() const
{
  return mAttributeId;
}

NumericRange& ReadValueId::index_range()
{
  return mIndexRange;
}

const NumericRange& ReadValueId::index_range() const
{
  return mIndexRange;
}

QualifiedName& ReadValueId::data_encoding()
{
  return mDataEncoding;
}

const QualifiedName& ReadValueId::data_encoding() const
{
  return mDataEncoding;
}

BuiltInTypeId ReadValueId::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::SortRuleElement
{
namespace
{
void encode(StackDepth limit, const ua::SortRuleElement& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, utils::as_int32(value.sort_order()));
  encoder.encode(limit, value.event_field());
}

void encode(StackDepth limit, const ua::SortRuleElement& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "SortOrder", utils::as_int32(value.sort_order()));
  encoder.encode(limit, "EventField", value.event_field());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::SortRuleElement& value)
{
  int32_t enumVal{};
  decoder.decode(limit, enumVal);
  value.sort_order() = utils::from_underlying<SortOrderType>(enumVal);
  decoder.decode(limit, value.event_field());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::SortRuleElement& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "SortOrder", true, enumVal);
  value.sort_order() = utils::from_underlying<SortOrderType>(enumVal);
  decoder.decode(limit, "EventField", true, value.event_field());
}
}  // namespace
}  // namespace detail::SortRuleElement

namespace detail::SortRuleElement
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::SortRuleElement::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::SortRuleElement::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::SortRuleElement

namespace detail::SortRuleElement
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::SortRuleElement>();
}
}  // namespace
}  // namespace detail::SortRuleElement

bool SortRuleElement::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId SortRuleElement::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId SortRuleElement::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String SortRuleElement::type_name() const
{
  return typeName;
}

void SortRuleElement::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SortRuleElement::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SortRuleElement::encode(limit, *this, *xml);
  }
}

void SortRuleElement::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SortRuleElement::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SortRuleElement::encode_id(limit, ns, *xml);
  }
}

void SortRuleElement::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::SortRuleElement::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::SortRuleElement::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> SortRuleElement::clone() const
{
  return make_unique<SortRuleElement>(*this);
}

void SortRuleElement::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "sort_order=" + ua::to_string(utils::as_int32(sort_order()));
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "event_field=" + ua::to_string(event_field());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "sort_order=" + ua::to_string(utils::as_int32(sort_order()));
  if (!output.empty())
  {
    output += ", ";
  }
  output += "event_field=" + ua::to_string(event_field());
}

std::string SortRuleElement::to_string(int indent) const
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

void SortRuleElement::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::SortRuleElement::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::SortRuleElement::create);
  }
}

SortOrderType& SortRuleElement::sort_order()
{
  return mSortOrder;
}

const SortOrderType& SortRuleElement::sort_order() const
{
  return mSortOrder;
}

SimpleAttributeOperand& SortRuleElement::event_field()
{
  return mEventField;
}

const SimpleAttributeOperand& SortRuleElement::event_field() const
{
  return mEventField;
}

BuiltInTypeId SortRuleElement::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::HistoryReadRequest
{
namespace
{
void encode(StackDepth limit, const ua::HistoryReadRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.history_read_details().get());
  encoder.encode(limit, utils::as_int32(value.timestamps_to_return()));
  encoder.encode(limit, value.release_continuation_points());
  encoder.encode(limit, value.nodes_to_read());
}

void encode(StackDepth limit, const ua::HistoryReadRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "HistoryReadDetails", value.history_read_details().get());
  encoder.encode(limit, "TimestampsToReturn", utils::as_int32(value.timestamps_to_return()));
  encoder.encode(limit, "ReleaseContinuationPoints", value.release_continuation_points());
  encoder.encode(limit, "NodesToRead", value.nodes_to_read());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::HistoryReadRequest& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.history_read_details().inner_unique_ptr());
  decoder.decode(limit, enumVal);
  value.timestamps_to_return() = utils::from_underlying<TimestampsToReturn>(enumVal);
  decoder.decode(limit, value.release_continuation_points());
  decoder.decode(limit, value.nodes_to_read());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::HistoryReadRequest& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "HistoryReadDetails", true, value.history_read_details().inner_unique_ptr());
  decoder.decode(limit, "TimestampsToReturn", true, enumVal);
  value.timestamps_to_return() = utils::from_underlying<TimestampsToReturn>(enumVal);
  decoder.decode(limit, "ReleaseContinuationPoints", true, value.release_continuation_points());
  decoder.decode(limit, "NodesToRead", true, value.nodes_to_read());
}
}  // namespace
}  // namespace detail::HistoryReadRequest

namespace detail::HistoryReadRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::HistoryReadRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::HistoryReadRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::HistoryReadRequest

namespace detail::HistoryReadRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::HistoryReadRequest>();
}
}  // namespace
}  // namespace detail::HistoryReadRequest

bool HistoryReadRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId HistoryReadRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId HistoryReadRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String HistoryReadRequest::type_name() const
{
  return typeName;
}

void HistoryReadRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::HistoryReadRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::HistoryReadRequest::encode(limit, *this, *xml);
  }
}

void HistoryReadRequest::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::HistoryReadRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::HistoryReadRequest::encode_id(limit, ns, *xml);
  }
}

void HistoryReadRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::HistoryReadRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::HistoryReadRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> HistoryReadRequest::clone() const
{
  return make_unique<HistoryReadRequest>(*this);
}

void HistoryReadRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "history_read_details=" +
              (history_read_details() ? history_read_details()->to_string(indent) : "null");
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "timestamps_to_return=" + ua::to_string(utils::as_int32(timestamps_to_return()));
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "release_continuation_points=" + ua::to_string(release_continuation_points());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "nodes_to_read=" + ua::to_string(nodes_to_read());
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
  output +=
    "history_read_details=" + (history_read_details() ? history_read_details()->to_string(0) : "null");
  if (!output.empty())
  {
    output += ", ";
  }
  output += "timestamps_to_return=" + ua::to_string(utils::as_int32(timestamps_to_return()));
  if (!output.empty())
  {
    output += ", ";
  }
  output += "release_continuation_points=" + ua::to_string(release_continuation_points());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "nodes_to_read=" + ua::to_string(nodes_to_read());
}

std::string HistoryReadRequest::to_string(int indent) const
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

void HistoryReadRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::HistoryReadRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::HistoryReadRequest::create);
  }
}

RequestHeader& HistoryReadRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& HistoryReadRequest::request_header() const
{
  return mRequestHeader;
}

RefStructure<Structure>& HistoryReadRequest::history_read_details()
{
  return mHistoryReadDetails;
}

const RefStructure<Structure>& HistoryReadRequest::history_read_details() const
{
  return mHistoryReadDetails;
}

TimestampsToReturn& HistoryReadRequest::timestamps_to_return()
{
  return mTimestampsToReturn;
}

const TimestampsToReturn& HistoryReadRequest::timestamps_to_return() const
{
  return mTimestampsToReturn;
}

bool& HistoryReadRequest::release_continuation_points()
{
  return mReleaseContinuationPoints;
}

const bool& HistoryReadRequest::release_continuation_points() const
{
  return mReleaseContinuationPoints;
}

Array<HistoryReadValueId>& HistoryReadRequest::nodes_to_read()
{
  return mNodesToRead;
}

const Array<HistoryReadValueId>& HistoryReadRequest::nodes_to_read() const
{
  return mNodesToRead;
}

BuiltInTypeId HistoryReadRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::UpdateEventDetails
{
namespace
{
void encode(StackDepth limit, const ua::UpdateEventDetails& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.node_id());
  encoder.encode(limit, utils::as_int32(value.perform_insert_replace()));
  encoder.encode(limit, value.filter());
  encoder.encode(limit, value.event_data());
}

void encode(StackDepth limit, const ua::UpdateEventDetails& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "NodeId", value.node_id());
  encoder.encode(limit, "PerformInsertReplace", utils::as_int32(value.perform_insert_replace()));
  encoder.encode(limit, "Filter", value.filter());
  encoder.encode(limit, "EventData", value.event_data());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::UpdateEventDetails& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.node_id());
  decoder.decode(limit, enumVal);
  value.perform_insert_replace() = utils::from_underlying<PerformUpdateType>(enumVal);
  decoder.decode(limit, value.filter());
  decoder.decode(limit, value.event_data());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::UpdateEventDetails& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "NodeId", true, value.node_id());
  decoder.decode(limit, "PerformInsertReplace", true, enumVal);
  value.perform_insert_replace() = utils::from_underlying<PerformUpdateType>(enumVal);
  decoder.decode(limit, "Filter", true, value.filter());
  decoder.decode(limit, "EventData", true, value.event_data());
}
}  // namespace
}  // namespace detail::UpdateEventDetails

namespace detail::UpdateEventDetails
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::UpdateEventDetails::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::UpdateEventDetails::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::UpdateEventDetails

namespace detail::UpdateEventDetails
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::UpdateEventDetails>();
}
}  // namespace
}  // namespace detail::UpdateEventDetails

bool UpdateEventDetails::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return HistoryUpdateDetails::is_of_type(ns, dataTypeId);
}

NodeId UpdateEventDetails::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId UpdateEventDetails::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String UpdateEventDetails::type_name() const
{
  return typeName;
}

void UpdateEventDetails::encode(StackDepth limit, Encoder& encoder) const
{

  HistoryUpdateDetails::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::UpdateEventDetails::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::UpdateEventDetails::encode(limit, *this, *xml);
  }
}

void UpdateEventDetails::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::UpdateEventDetails::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::UpdateEventDetails::encode_id(limit, ns, *xml);
  }
}

void UpdateEventDetails::decode(StackDepth limit, Decoder& decoder)
{

  HistoryUpdateDetails::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::UpdateEventDetails::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::UpdateEventDetails::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> UpdateEventDetails::clone() const
{
  return make_unique<UpdateEventDetails>(*this);
}

void UpdateEventDetails::append_fields(std::string& output, int indent) const
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
    output += pad + "filter=" + ua::to_string(filter());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "event_data=" + ua::to_string(event_data());
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
  output += "filter=" + ua::to_string(filter());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "event_data=" + ua::to_string(event_data());
}

std::string UpdateEventDetails::to_string(int indent) const
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

void UpdateEventDetails::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::UpdateEventDetails::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::UpdateEventDetails::create);
  }
}

NodeId& UpdateEventDetails::node_id()
{
  return mNodeId;
}

const NodeId& UpdateEventDetails::node_id() const
{
  return mNodeId;
}

PerformUpdateType& UpdateEventDetails::perform_insert_replace()
{
  return mPerformInsertReplace;
}

const PerformUpdateType& UpdateEventDetails::perform_insert_replace() const
{
  return mPerformInsertReplace;
}

EventFilter& UpdateEventDetails::filter()
{
  return mFilter;
}

const EventFilter& UpdateEventDetails::filter() const
{
  return mFilter;
}

Array<HistoryEventFieldList>& UpdateEventDetails::event_data()
{
  return mEventData;
}

const Array<HistoryEventFieldList>& UpdateEventDetails::event_data() const
{
  return mEventData;
}

BuiltInTypeId UpdateEventDetails::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::CallMethodResult
{
namespace
{
void encode(StackDepth limit, const ua::CallMethodResult& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.status_code());
  encoder.encode(limit, value.input_argument_results());
  encoder.encode(limit, value.input_argument_diagnostic_infos());
  encoder.encode(limit, value.output_arguments());
}

void encode(StackDepth limit, const ua::CallMethodResult& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "StatusCode", value.status_code());
  encoder.encode(limit, "InputArgumentResults", value.input_argument_results());
  encoder.encode(limit, "InputArgumentDiagnosticInfos", value.input_argument_diagnostic_infos());
  encoder.encode(limit, "OutputArguments", value.output_arguments());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::CallMethodResult& value)
{
  decoder.decode(limit, value.status_code());
  decoder.decode(limit, value.input_argument_results());
  decoder.decode(limit, value.input_argument_diagnostic_infos());
  decoder.decode(limit, value.output_arguments());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::CallMethodResult& value)
{
  decoder.decode(limit, "StatusCode", true, value.status_code());
  decoder.decode(limit, "InputArgumentResults", true, value.input_argument_results());
  decoder.decode(limit, "InputArgumentDiagnosticInfos", true, value.input_argument_diagnostic_infos());
  decoder.decode(limit, "OutputArguments", true, value.output_arguments());
}
}  // namespace
}  // namespace detail::CallMethodResult

namespace detail::CallMethodResult
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::CallMethodResult::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::CallMethodResult::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::CallMethodResult

namespace detail::CallMethodResult
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::CallMethodResult>();
}
}  // namespace
}  // namespace detail::CallMethodResult

bool CallMethodResult::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId CallMethodResult::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId CallMethodResult::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String CallMethodResult::type_name() const
{
  return typeName;
}

void CallMethodResult::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CallMethodResult::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CallMethodResult::encode(limit, *this, *xml);
  }
}

void CallMethodResult::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CallMethodResult::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CallMethodResult::encode_id(limit, ns, *xml);
  }
}

void CallMethodResult::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::CallMethodResult::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::CallMethodResult::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> CallMethodResult::clone() const
{
  return make_unique<CallMethodResult>(*this);
}

void CallMethodResult::append_fields(std::string& output, int indent) const
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
    output += pad + "input_argument_results=" + ua::to_string(input_argument_results());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "input_argument_diagnostic_infos=" + ua::to_string(input_argument_diagnostic_infos());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "output_arguments=" + ua::to_string(output_arguments());
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
  output += "input_argument_results=" + ua::to_string(input_argument_results());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "input_argument_diagnostic_infos=" + ua::to_string(input_argument_diagnostic_infos());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "output_arguments=" + ua::to_string(output_arguments());
}

std::string CallMethodResult::to_string(int indent) const
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

void CallMethodResult::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::CallMethodResult::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::CallMethodResult::create);
  }
}

StatusCode& CallMethodResult::status_code()
{
  return mStatusCode;
}

const StatusCode& CallMethodResult::status_code() const
{
  return mStatusCode;
}

Array<StatusCode>& CallMethodResult::input_argument_results()
{
  return mInputArgumentResults;
}

const Array<StatusCode>& CallMethodResult::input_argument_results() const
{
  return mInputArgumentResults;
}

Array<DiagnosticInfo>& CallMethodResult::input_argument_diagnostic_infos()
{
  return mInputArgumentDiagnosticInfos;
}

const Array<DiagnosticInfo>& CallMethodResult::input_argument_diagnostic_infos() const
{
  return mInputArgumentDiagnosticInfos;
}

Array<Variant>& CallMethodResult::output_arguments()
{
  return mOutputArguments;
}

const Array<Variant>& CallMethodResult::output_arguments() const
{
  return mOutputArguments;
}

BuiltInTypeId CallMethodResult::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::MonitoringParameters
{
namespace
{
void encode(StackDepth limit, const ua::MonitoringParameters& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.client_handle());
  encoder.encode(limit, value.sampling_interval());
  encoder.encode(limit, value.filter().get());
  encoder.encode(limit, value.queue_size());
  encoder.encode(limit, value.discard_oldest());
}

void encode(StackDepth limit, const ua::MonitoringParameters& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ClientHandle", value.client_handle());
  encoder.encode(limit, "SamplingInterval", value.sampling_interval());
  encoder.encode(limit, "Filter", value.filter().get());
  encoder.encode(limit, "QueueSize", value.queue_size());
  encoder.encode(limit, "DiscardOldest", value.discard_oldest());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::MonitoringParameters& value)
{
  decoder.decode(limit, value.client_handle());
  decoder.decode(limit, value.sampling_interval());
  decoder.decode(limit, value.filter().inner_unique_ptr());
  decoder.decode(limit, value.queue_size());
  decoder.decode(limit, value.discard_oldest());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::MonitoringParameters& value)
{
  decoder.decode(limit, "ClientHandle", true, value.client_handle());
  decoder.decode(limit, "SamplingInterval", true, value.sampling_interval());
  decoder.decode(limit, "Filter", true, value.filter().inner_unique_ptr());
  decoder.decode(limit, "QueueSize", true, value.queue_size());
  decoder.decode(limit, "DiscardOldest", true, value.discard_oldest());
}
}  // namespace
}  // namespace detail::MonitoringParameters

namespace detail::MonitoringParameters
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::MonitoringParameters::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::MonitoringParameters::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::MonitoringParameters

namespace detail::MonitoringParameters
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::MonitoringParameters>();
}
}  // namespace
}  // namespace detail::MonitoringParameters

bool MonitoringParameters::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId MonitoringParameters::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId MonitoringParameters::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String MonitoringParameters::type_name() const
{
  return typeName;
}

void MonitoringParameters::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::MonitoringParameters::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::MonitoringParameters::encode(limit, *this, *xml);
  }
}

void MonitoringParameters::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::MonitoringParameters::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::MonitoringParameters::encode_id(limit, ns, *xml);
  }
}

void MonitoringParameters::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::MonitoringParameters::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::MonitoringParameters::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> MonitoringParameters::clone() const
{
  return make_unique<MonitoringParameters>(*this);
}

void MonitoringParameters::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "client_handle=" + ua::to_string(client_handle());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "sampling_interval=" + ua::to_string(sampling_interval());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "filter=" + (filter() ? filter()->to_string(indent) : "null");
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "queue_size=" + ua::to_string(queue_size());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "discard_oldest=" + ua::to_string(discard_oldest());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "client_handle=" + ua::to_string(client_handle());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "sampling_interval=" + ua::to_string(sampling_interval());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "filter=" + (filter() ? filter()->to_string(0) : "null");
  if (!output.empty())
  {
    output += ", ";
  }
  output += "queue_size=" + ua::to_string(queue_size());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "discard_oldest=" + ua::to_string(discard_oldest());
}

std::string MonitoringParameters::to_string(int indent) const
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

void MonitoringParameters::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::MonitoringParameters::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::MonitoringParameters::create);
  }
}

IntegerId& MonitoringParameters::client_handle()
{
  return mClientHandle;
}

const IntegerId& MonitoringParameters::client_handle() const
{
  return mClientHandle;
}

Duration& MonitoringParameters::sampling_interval()
{
  return mSamplingInterval;
}

const Duration& MonitoringParameters::sampling_interval() const
{
  return mSamplingInterval;
}

RefStructure<Structure>& MonitoringParameters::filter()
{
  return mFilter;
}

const RefStructure<Structure>& MonitoringParameters::filter() const
{
  return mFilter;
}

Counter& MonitoringParameters::queue_size()
{
  return mQueueSize;
}

const Counter& MonitoringParameters::queue_size() const
{
  return mQueueSize;
}

bool& MonitoringParameters::discard_oldest()
{
  return mDiscardOldest;
}

const bool& MonitoringParameters::discard_oldest() const
{
  return mDiscardOldest;
}

BuiltInTypeId MonitoringParameters::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ModifyMonitoredItemsResponse
{
namespace
{
void encode(StackDepth limit, const ua::ModifyMonitoredItemsResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.results());
  encoder.encode(limit, value.diagnostic_infos());
}

void encode(StackDepth limit, const ua::ModifyMonitoredItemsResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "Results", value.results());
  encoder.encode(limit, "DiagnosticInfos", value.diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ModifyMonitoredItemsResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.results());
  decoder.decode(limit, value.diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ModifyMonitoredItemsResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "Results", true, value.results());
  decoder.decode(limit, "DiagnosticInfos", true, value.diagnostic_infos());
}
}  // namespace
}  // namespace detail::ModifyMonitoredItemsResponse

namespace detail::ModifyMonitoredItemsResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ModifyMonitoredItemsResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ModifyMonitoredItemsResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ModifyMonitoredItemsResponse

namespace detail::ModifyMonitoredItemsResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ModifyMonitoredItemsResponse>();
}
}  // namespace
}  // namespace detail::ModifyMonitoredItemsResponse

bool ModifyMonitoredItemsResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ModifyMonitoredItemsResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ModifyMonitoredItemsResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ModifyMonitoredItemsResponse::type_name() const
{
  return typeName;
}

void ModifyMonitoredItemsResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ModifyMonitoredItemsResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ModifyMonitoredItemsResponse::encode(limit, *this, *xml);
  }
}

void ModifyMonitoredItemsResponse::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ModifyMonitoredItemsResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ModifyMonitoredItemsResponse::encode_id(limit, ns, *xml);
  }
}

void ModifyMonitoredItemsResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ModifyMonitoredItemsResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ModifyMonitoredItemsResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ModifyMonitoredItemsResponse::clone() const
{
  return make_unique<ModifyMonitoredItemsResponse>(*this);
}

void ModifyMonitoredItemsResponse::append_fields(std::string& output, int indent) const
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

std::string ModifyMonitoredItemsResponse::to_string(int indent) const
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

void ModifyMonitoredItemsResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::ModifyMonitoredItemsResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ModifyMonitoredItemsResponse::create);
  }
}

ResponseHeader& ModifyMonitoredItemsResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& ModifyMonitoredItemsResponse::response_header() const
{
  return mResponseHeader;
}

Array<MonitoredItemModifyResult>& ModifyMonitoredItemsResponse::results()
{
  return mResults;
}

const Array<MonitoredItemModifyResult>& ModifyMonitoredItemsResponse::results() const
{
  return mResults;
}

Array<DiagnosticInfo>& ModifyMonitoredItemsResponse::diagnostic_infos()
{
  return mDiagnosticInfos;
}

const Array<DiagnosticInfo>& ModifyMonitoredItemsResponse::diagnostic_infos() const
{
  return mDiagnosticInfos;
}

BuiltInTypeId ModifyMonitoredItemsResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::CreateSubscriptionResponse
{
namespace
{
void encode(StackDepth limit, const ua::CreateSubscriptionResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.subscription_id());
  encoder.encode(limit, value.revised_publishing_interval());
  encoder.encode(limit, value.revised_lifetime_count());
  encoder.encode(limit, value.revised_max_keep_alive_count());
}

void encode(StackDepth limit, const ua::CreateSubscriptionResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "SubscriptionId", value.subscription_id());
  encoder.encode(limit, "RevisedPublishingInterval", value.revised_publishing_interval());
  encoder.encode(limit, "RevisedLifetimeCount", value.revised_lifetime_count());
  encoder.encode(limit, "RevisedMaxKeepAliveCount", value.revised_max_keep_alive_count());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::CreateSubscriptionResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.subscription_id());
  decoder.decode(limit, value.revised_publishing_interval());
  decoder.decode(limit, value.revised_lifetime_count());
  decoder.decode(limit, value.revised_max_keep_alive_count());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::CreateSubscriptionResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "SubscriptionId", true, value.subscription_id());
  decoder.decode(limit, "RevisedPublishingInterval", true, value.revised_publishing_interval());
  decoder.decode(limit, "RevisedLifetimeCount", true, value.revised_lifetime_count());
  decoder.decode(limit, "RevisedMaxKeepAliveCount", true, value.revised_max_keep_alive_count());
}
}  // namespace
}  // namespace detail::CreateSubscriptionResponse

namespace detail::CreateSubscriptionResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::CreateSubscriptionResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::CreateSubscriptionResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::CreateSubscriptionResponse

namespace detail::CreateSubscriptionResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::CreateSubscriptionResponse>();
}
}  // namespace
}  // namespace detail::CreateSubscriptionResponse

bool CreateSubscriptionResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId CreateSubscriptionResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId CreateSubscriptionResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String CreateSubscriptionResponse::type_name() const
{
  return typeName;
}

void CreateSubscriptionResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CreateSubscriptionResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CreateSubscriptionResponse::encode(limit, *this, *xml);
  }
}

void CreateSubscriptionResponse::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CreateSubscriptionResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CreateSubscriptionResponse::encode_id(limit, ns, *xml);
  }
}

void CreateSubscriptionResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::CreateSubscriptionResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::CreateSubscriptionResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> CreateSubscriptionResponse::clone() const
{
  return make_unique<CreateSubscriptionResponse>(*this);
}

void CreateSubscriptionResponse::append_fields(std::string& output, int indent) const
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
    output += pad + "revised_publishing_interval=" + ua::to_string(revised_publishing_interval());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "revised_lifetime_count=" + ua::to_string(revised_lifetime_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "revised_max_keep_alive_count=" + ua::to_string(revised_max_keep_alive_count());
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
  output += "revised_publishing_interval=" + ua::to_string(revised_publishing_interval());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "revised_lifetime_count=" + ua::to_string(revised_lifetime_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "revised_max_keep_alive_count=" + ua::to_string(revised_max_keep_alive_count());
}

std::string CreateSubscriptionResponse::to_string(int indent) const
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

void CreateSubscriptionResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::CreateSubscriptionResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::CreateSubscriptionResponse::create);
  }
}

ResponseHeader& CreateSubscriptionResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& CreateSubscriptionResponse::response_header() const
{
  return mResponseHeader;
}

IntegerId& CreateSubscriptionResponse::subscription_id()
{
  return mSubscriptionId;
}

const IntegerId& CreateSubscriptionResponse::subscription_id() const
{
  return mSubscriptionId;
}

Duration& CreateSubscriptionResponse::revised_publishing_interval()
{
  return mRevisedPublishingInterval;
}

const Duration& CreateSubscriptionResponse::revised_publishing_interval() const
{
  return mRevisedPublishingInterval;
}

Counter& CreateSubscriptionResponse::revised_lifetime_count()
{
  return mRevisedLifetimeCount;
}

const Counter& CreateSubscriptionResponse::revised_lifetime_count() const
{
  return mRevisedLifetimeCount;
}

Counter& CreateSubscriptionResponse::revised_max_keep_alive_count()
{
  return mRevisedMaxKeepAliveCount;
}

const Counter& CreateSubscriptionResponse::revised_max_keep_alive_count() const
{
  return mRevisedMaxKeepAliveCount;
}

BuiltInTypeId CreateSubscriptionResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::MonitoredItemNotification
{
namespace
{
void encode(StackDepth limit, const ua::MonitoredItemNotification& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.client_handle());
  encoder.encode(limit, value.value());
}

void encode(StackDepth limit, const ua::MonitoredItemNotification& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ClientHandle", value.client_handle());
  encoder.encode(limit, "Value", value.value());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::MonitoredItemNotification& value)
{
  decoder.decode(limit, value.client_handle());
  decoder.decode(limit, value.value());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::MonitoredItemNotification& value)
{
  decoder.decode(limit, "ClientHandle", true, value.client_handle());
  decoder.decode(limit, "Value", true, value.value());
}
}  // namespace
}  // namespace detail::MonitoredItemNotification

namespace detail::MonitoredItemNotification
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::MonitoredItemNotification::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::MonitoredItemNotification::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::MonitoredItemNotification

namespace detail::MonitoredItemNotification
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::MonitoredItemNotification>();
}
}  // namespace
}  // namespace detail::MonitoredItemNotification

bool MonitoredItemNotification::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId MonitoredItemNotification::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId MonitoredItemNotification::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String MonitoredItemNotification::type_name() const
{
  return typeName;
}

void MonitoredItemNotification::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::MonitoredItemNotification::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::MonitoredItemNotification::encode(limit, *this, *xml);
  }
}

void MonitoredItemNotification::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::MonitoredItemNotification::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::MonitoredItemNotification::encode_id(limit, ns, *xml);
  }
}

void MonitoredItemNotification::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::MonitoredItemNotification::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::MonitoredItemNotification::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> MonitoredItemNotification::clone() const
{
  return make_unique<MonitoredItemNotification>(*this);
}

void MonitoredItemNotification::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "client_handle=" + ua::to_string(client_handle());
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
  output += "client_handle=" + ua::to_string(client_handle());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "value=" + ua::to_string(value());
}

std::string MonitoredItemNotification::to_string(int indent) const
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

void MonitoredItemNotification::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::MonitoredItemNotification::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::MonitoredItemNotification::create);
  }
}

IntegerId& MonitoredItemNotification::client_handle()
{
  return mClientHandle;
}

const IntegerId& MonitoredItemNotification::client_handle() const
{
  return mClientHandle;
}

DataValue& MonitoredItemNotification::value()
{
  return mValue;
}

const DataValue& MonitoredItemNotification::value() const
{
  return mValue;
}

BuiltInTypeId MonitoredItemNotification::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::RepublishResponse
{
namespace
{
void encode(StackDepth limit, const ua::RepublishResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.notification_message());
}

void encode(StackDepth limit, const ua::RepublishResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "NotificationMessage", value.notification_message());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::RepublishResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.notification_message());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::RepublishResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "NotificationMessage", true, value.notification_message());
}
}  // namespace
}  // namespace detail::RepublishResponse

namespace detail::RepublishResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::RepublishResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::RepublishResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::RepublishResponse

namespace detail::RepublishResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::RepublishResponse>();
}
}  // namespace
}  // namespace detail::RepublishResponse

bool RepublishResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId RepublishResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId RepublishResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String RepublishResponse::type_name() const
{
  return typeName;
}

void RepublishResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RepublishResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RepublishResponse::encode(limit, *this, *xml);
  }
}

void RepublishResponse::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RepublishResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RepublishResponse::encode_id(limit, ns, *xml);
  }
}

void RepublishResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::RepublishResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::RepublishResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> RepublishResponse::clone() const
{
  return make_unique<RepublishResponse>(*this);
}

void RepublishResponse::append_fields(std::string& output, int indent) const
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
    output += pad + "notification_message=" + ua::to_string(notification_message());
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
  output += "notification_message=" + ua::to_string(notification_message());
}

std::string RepublishResponse::to_string(int indent) const
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

void RepublishResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::RepublishResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::RepublishResponse::create);
  }
}

ResponseHeader& RepublishResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& RepublishResponse::response_header() const
{
  return mResponseHeader;
}

NotificationMessage& RepublishResponse::notification_message()
{
  return mNotificationMessage;
}

const NotificationMessage& RepublishResponse::notification_message() const
{
  return mNotificationMessage;
}

BuiltInTypeId RepublishResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

}  // namespace ua
