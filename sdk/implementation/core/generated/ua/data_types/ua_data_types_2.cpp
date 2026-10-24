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

namespace detail::EphemeralKeyType
{
namespace
{
void encode(StackDepth limit, const ua::EphemeralKeyType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.public_key());
  encoder.encode(limit, value.signature());
}

void encode(StackDepth limit, const ua::EphemeralKeyType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "PublicKey", value.public_key());
  encoder.encode(limit, "Signature", value.signature());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::EphemeralKeyType& value)
{
  decoder.decode(limit, value.public_key());
  decoder.decode(limit, value.signature());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::EphemeralKeyType& value)
{
  decoder.decode(limit, "PublicKey", true, value.public_key());
  decoder.decode(limit, "Signature", true, value.signature());
}
}  // namespace
}  // namespace detail::EphemeralKeyType

namespace detail::EphemeralKeyType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::EphemeralKeyType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::EphemeralKeyType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::EphemeralKeyType

namespace detail::EphemeralKeyType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::EphemeralKeyType>();
}
}  // namespace
}  // namespace detail::EphemeralKeyType

bool EphemeralKeyType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId EphemeralKeyType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId EphemeralKeyType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String EphemeralKeyType::type_name() const
{
  return typeName;
}

void EphemeralKeyType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EphemeralKeyType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EphemeralKeyType::encode(limit, *this, *xml);
  }
}

void EphemeralKeyType::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EphemeralKeyType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EphemeralKeyType::encode_id(limit, ns, *xml);
  }
}

void EphemeralKeyType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::EphemeralKeyType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::EphemeralKeyType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> EphemeralKeyType::clone() const
{
  return make_unique<EphemeralKeyType>(*this);
}

void EphemeralKeyType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "public_key=" + ua::to_string(public_key());
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
  output += "public_key=" + ua::to_string(public_key());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "signature=" + ua::to_string(signature());
}

std::string EphemeralKeyType::to_string(int indent) const
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

void EphemeralKeyType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::EphemeralKeyType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::EphemeralKeyType::create);
  }
}

ByteString& EphemeralKeyType::public_key()
{
  return mPublicKey;
}

const ByteString& EphemeralKeyType::public_key() const
{
  return mPublicKey;
}

ByteString& EphemeralKeyType::signature()
{
  return mSignature;
}

const ByteString& EphemeralKeyType::signature() const
{
  return mSignature;
}

BuiltInTypeId EphemeralKeyType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

bool Orientation::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId Orientation::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId Orientation::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String Orientation::type_name() const
{
  return typeName;
}

void Orientation::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);
}

void Orientation::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  UA_UNUSED(limit);
  UA_UNUSED(ns);
  UA_UNUSED(encoder);
}

void Orientation::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);
}

BuiltInTypeId Orientation::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::QuantityDimension
{
namespace
{
void encode(StackDepth limit, const ua::QuantityDimension& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.mass_exponent());
  encoder.encode(limit, value.length_exponent());
  encoder.encode(limit, value.time_exponent());
  encoder.encode(limit, value.electric_current_exponent());
  encoder.encode(limit, value.amount_of_substance_exponent());
  encoder.encode(limit, value.luminous_intensity_exponent());
  encoder.encode(limit, value.absolute_temperature_exponent());
  encoder.encode(limit, value.dimensionless_exponent());
}

void encode(StackDepth limit, const ua::QuantityDimension& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "MassExponent", value.mass_exponent());
  encoder.encode(limit, "LengthExponent", value.length_exponent());
  encoder.encode(limit, "TimeExponent", value.time_exponent());
  encoder.encode(limit, "ElectricCurrentExponent", value.electric_current_exponent());
  encoder.encode(limit, "AmountOfSubstanceExponent", value.amount_of_substance_exponent());
  encoder.encode(limit, "LuminousIntensityExponent", value.luminous_intensity_exponent());
  encoder.encode(limit, "AbsoluteTemperatureExponent", value.absolute_temperature_exponent());
  encoder.encode(limit, "DimensionlessExponent", value.dimensionless_exponent());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::QuantityDimension& value)
{
  decoder.decode(limit, value.mass_exponent());
  decoder.decode(limit, value.length_exponent());
  decoder.decode(limit, value.time_exponent());
  decoder.decode(limit, value.electric_current_exponent());
  decoder.decode(limit, value.amount_of_substance_exponent());
  decoder.decode(limit, value.luminous_intensity_exponent());
  decoder.decode(limit, value.absolute_temperature_exponent());
  decoder.decode(limit, value.dimensionless_exponent());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::QuantityDimension& value)
{
  decoder.decode(limit, "MassExponent", true, value.mass_exponent());
  decoder.decode(limit, "LengthExponent", true, value.length_exponent());
  decoder.decode(limit, "TimeExponent", true, value.time_exponent());
  decoder.decode(limit, "ElectricCurrentExponent", true, value.electric_current_exponent());
  decoder.decode(limit, "AmountOfSubstanceExponent", true, value.amount_of_substance_exponent());
  decoder.decode(limit, "LuminousIntensityExponent", true, value.luminous_intensity_exponent());
  decoder.decode(limit, "AbsoluteTemperatureExponent", true, value.absolute_temperature_exponent());
  decoder.decode(limit, "DimensionlessExponent", true, value.dimensionless_exponent());
}
}  // namespace
}  // namespace detail::QuantityDimension

namespace detail::QuantityDimension
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::QuantityDimension::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::QuantityDimension::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::QuantityDimension

namespace detail::QuantityDimension
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::QuantityDimension>();
}
}  // namespace
}  // namespace detail::QuantityDimension

bool QuantityDimension::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId QuantityDimension::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId QuantityDimension::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String QuantityDimension::type_name() const
{
  return typeName;
}

void QuantityDimension::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::QuantityDimension::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::QuantityDimension::encode(limit, *this, *xml);
  }
}

void QuantityDimension::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::QuantityDimension::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::QuantityDimension::encode_id(limit, ns, *xml);
  }
}

void QuantityDimension::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::QuantityDimension::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::QuantityDimension::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> QuantityDimension::clone() const
{
  return make_unique<QuantityDimension>(*this);
}

void QuantityDimension::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "mass_exponent=" + ua::to_string(mass_exponent());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "length_exponent=" + ua::to_string(length_exponent());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "time_exponent=" + ua::to_string(time_exponent());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "electric_current_exponent=" + ua::to_string(electric_current_exponent());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "amount_of_substance_exponent=" + ua::to_string(amount_of_substance_exponent());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "luminous_intensity_exponent=" + ua::to_string(luminous_intensity_exponent());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "absolute_temperature_exponent=" + ua::to_string(absolute_temperature_exponent());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "dimensionless_exponent=" + ua::to_string(dimensionless_exponent());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "mass_exponent=" + ua::to_string(mass_exponent());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "length_exponent=" + ua::to_string(length_exponent());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "time_exponent=" + ua::to_string(time_exponent());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "electric_current_exponent=" + ua::to_string(electric_current_exponent());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "amount_of_substance_exponent=" + ua::to_string(amount_of_substance_exponent());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "luminous_intensity_exponent=" + ua::to_string(luminous_intensity_exponent());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "absolute_temperature_exponent=" + ua::to_string(absolute_temperature_exponent());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "dimensionless_exponent=" + ua::to_string(dimensionless_exponent());
}

std::string QuantityDimension::to_string(int indent) const
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

void QuantityDimension::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::QuantityDimension::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::QuantityDimension::create);
  }
}

int8_t& QuantityDimension::mass_exponent()
{
  return mMassExponent;
}

const int8_t& QuantityDimension::mass_exponent() const
{
  return mMassExponent;
}

int8_t& QuantityDimension::length_exponent()
{
  return mLengthExponent;
}

const int8_t& QuantityDimension::length_exponent() const
{
  return mLengthExponent;
}

int8_t& QuantityDimension::time_exponent()
{
  return mTimeExponent;
}

const int8_t& QuantityDimension::time_exponent() const
{
  return mTimeExponent;
}

int8_t& QuantityDimension::electric_current_exponent()
{
  return mElectricCurrentExponent;
}

const int8_t& QuantityDimension::electric_current_exponent() const
{
  return mElectricCurrentExponent;
}

int8_t& QuantityDimension::amount_of_substance_exponent()
{
  return mAmountOfSubstanceExponent;
}

const int8_t& QuantityDimension::amount_of_substance_exponent() const
{
  return mAmountOfSubstanceExponent;
}

int8_t& QuantityDimension::luminous_intensity_exponent()
{
  return mLuminousIntensityExponent;
}

const int8_t& QuantityDimension::luminous_intensity_exponent() const
{
  return mLuminousIntensityExponent;
}

int8_t& QuantityDimension::absolute_temperature_exponent()
{
  return mAbsoluteTemperatureExponent;
}

const int8_t& QuantityDimension::absolute_temperature_exponent() const
{
  return mAbsoluteTemperatureExponent;
}

int8_t& QuantityDimension::dimensionless_exponent()
{
  return mDimensionlessExponent;
}

const int8_t& QuantityDimension::dimensionless_exponent() const
{
  return mDimensionlessExponent;
}

BuiltInTypeId QuantityDimension::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ApplicationIdentityDataType
{
namespace
{
void encode(StackDepth limit, const ua::ApplicationIdentityDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.application_uri());
  encoder.encode(limit, value.application_names());
  encoder.encode(limit, value.additional_servers());
}

void encode(StackDepth limit, const ua::ApplicationIdentityDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ApplicationUri", value.application_uri());
  encoder.encode(limit, "ApplicationNames", value.application_names());
  encoder.encode(limit, "AdditionalServers", value.additional_servers());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ApplicationIdentityDataType& value)
{
  decoder.decode(limit, value.application_uri());
  decoder.decode(limit, value.application_names());
  decoder.decode(limit, value.additional_servers());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ApplicationIdentityDataType& value)
{
  decoder.decode(limit, "ApplicationUri", true, value.application_uri());
  decoder.decode(limit, "ApplicationNames", true, value.application_names());
  decoder.decode(limit, "AdditionalServers", true, value.additional_servers());
}
}  // namespace
}  // namespace detail::ApplicationIdentityDataType

namespace detail::ApplicationIdentityDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ApplicationIdentityDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ApplicationIdentityDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ApplicationIdentityDataType

namespace detail::ApplicationIdentityDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ApplicationIdentityDataType>();
}
}  // namespace
}  // namespace detail::ApplicationIdentityDataType

bool ApplicationIdentityDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return BaseConfigurationRecordDataType::is_of_type(ns, dataTypeId);
}

NodeId ApplicationIdentityDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ApplicationIdentityDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ApplicationIdentityDataType::type_name() const
{
  return typeName;
}

void ApplicationIdentityDataType::encode(StackDepth limit, Encoder& encoder) const
{

  BaseConfigurationRecordDataType::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ApplicationIdentityDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ApplicationIdentityDataType::encode(limit, *this, *xml);
  }
}

void ApplicationIdentityDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ApplicationIdentityDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ApplicationIdentityDataType::encode_id(limit, ns, *xml);
  }
}

void ApplicationIdentityDataType::decode(StackDepth limit, Decoder& decoder)
{

  BaseConfigurationRecordDataType::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ApplicationIdentityDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ApplicationIdentityDataType::decode(limit, *xml, *this);
  }
}

void ApplicationIdentityDataType::resolve(span<const LocaleId> locales)
{
  BaseConfigurationRecordDataType::resolve(locales);
  for (size_t i = 0; i < mApplicationNames.size(); ++i)
  {
    mApplicationNames[i] = mApplicationNames[i].resolve(locales);
  }
  for (size_t i = 0; i < mAdditionalServers.size(); ++i)
  {
    mAdditionalServers[i].resolve(locales);
  }
}

unique_ptr<Structure> ApplicationIdentityDataType::clone() const
{
  return make_unique<ApplicationIdentityDataType>(*this);
}

void ApplicationIdentityDataType::append_fields(std::string& output, int indent) const
{
  BaseConfigurationRecordDataType::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "application_uri=" + ua::to_string(application_uri());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "application_names=" + ua::to_string(application_names());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "additional_servers=" + ua::to_string(additional_servers());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "application_uri=" + ua::to_string(application_uri());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "application_names=" + ua::to_string(application_names());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "additional_servers=" + ua::to_string(additional_servers());
}

std::string ApplicationIdentityDataType::to_string(int indent) const
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

void ApplicationIdentityDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::ApplicationIdentityDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ApplicationIdentityDataType::create);
  }
}

UriString& ApplicationIdentityDataType::application_uri()
{
  return mApplicationUri;
}

const UriString& ApplicationIdentityDataType::application_uri() const
{
  return mApplicationUri;
}

Array<LocalizedText>& ApplicationIdentityDataType::application_names()
{
  return mApplicationNames;
}

const Array<LocalizedText>& ApplicationIdentityDataType::application_names() const
{
  return mApplicationNames;
}

Array<ApplicationDescription>& ApplicationIdentityDataType::additional_servers()
{
  return mAdditionalServers;
}

const Array<ApplicationDescription>& ApplicationIdentityDataType::additional_servers() const
{
  return mAdditionalServers;
}

BuiltInTypeId ApplicationIdentityDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::DataTypeDescription
{
namespace
{
void encode(StackDepth limit, const ua::DataTypeDescription& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.data_type_id());
  encoder.encode(limit, value.name());
}

void encode(StackDepth limit, const ua::DataTypeDescription& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "DataTypeId", value.data_type_id());
  encoder.encode(limit, "Name", value.name());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::DataTypeDescription& value)
{
  decoder.decode(limit, value.data_type_id());
  decoder.decode(limit, value.name());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::DataTypeDescription& value)
{
  decoder.decode(limit, "DataTypeId", true, value.data_type_id());
  decoder.decode(limit, "Name", true, value.name());
}
}  // namespace
}  // namespace detail::DataTypeDescription

bool DataTypeDescription::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId DataTypeDescription::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId DataTypeDescription::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String DataTypeDescription::type_name() const
{
  return typeName;
}

void DataTypeDescription::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DataTypeDescription::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DataTypeDescription::encode(limit, *this, *xml);
  }
}

void DataTypeDescription::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  UA_UNUSED(limit);
  UA_UNUSED(ns);
  UA_UNUSED(encoder);
}

void DataTypeDescription::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::DataTypeDescription::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::DataTypeDescription::decode(limit, *xml, *this);
  }
}

void DataTypeDescription::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "data_type_id=" + ua::to_string(data_type_id());
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
  output += "data_type_id=" + ua::to_string(data_type_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "name=" + ua::to_string(name());
}

NodeId& DataTypeDescription::data_type_id()
{
  return mDataTypeId;
}

const NodeId& DataTypeDescription::data_type_id() const
{
  return mDataTypeId;
}

QualifiedName& DataTypeDescription::name()
{
  return mName;
}

const QualifiedName& DataTypeDescription::name() const
{
  return mName;
}

BuiltInTypeId DataTypeDescription::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::AliasNameDataType
{
namespace
{
void encode(StackDepth limit, const ua::AliasNameDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.alias_name());
  encoder.encode(limit, value.referenced_nodes());
}

void encode(StackDepth limit, const ua::AliasNameDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "AliasName", value.alias_name());
  encoder.encode(limit, "ReferencedNodes", value.referenced_nodes());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::AliasNameDataType& value)
{
  decoder.decode(limit, value.alias_name());
  decoder.decode(limit, value.referenced_nodes());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::AliasNameDataType& value)
{
  decoder.decode(limit, "AliasName", true, value.alias_name());
  decoder.decode(limit, "ReferencedNodes", true, value.referenced_nodes());
}
}  // namespace
}  // namespace detail::AliasNameDataType

namespace detail::AliasNameDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::AliasNameDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::AliasNameDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::AliasNameDataType

namespace detail::AliasNameDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::AliasNameDataType>();
}
}  // namespace
}  // namespace detail::AliasNameDataType

bool AliasNameDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId AliasNameDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId AliasNameDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String AliasNameDataType::type_name() const
{
  return typeName;
}

void AliasNameDataType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AliasNameDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AliasNameDataType::encode(limit, *this, *xml);
  }
}

void AliasNameDataType::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AliasNameDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AliasNameDataType::encode_id(limit, ns, *xml);
  }
}

void AliasNameDataType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::AliasNameDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::AliasNameDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> AliasNameDataType::clone() const
{
  return make_unique<AliasNameDataType>(*this);
}

void AliasNameDataType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "alias_name=" + ua::to_string(alias_name());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "referenced_nodes=" + ua::to_string(referenced_nodes());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "alias_name=" + ua::to_string(alias_name());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "referenced_nodes=" + ua::to_string(referenced_nodes());
}

std::string AliasNameDataType::to_string(int indent) const
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

void AliasNameDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::AliasNameDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::AliasNameDataType::create);
  }
}

QualifiedName& AliasNameDataType::alias_name()
{
  return mAliasName;
}

const QualifiedName& AliasNameDataType::alias_name() const
{
  return mAliasName;
}

Array<ExpandedNodeId>& AliasNameDataType::referenced_nodes()
{
  return mReferencedNodes;
}

const Array<ExpandedNodeId>& AliasNameDataType::referenced_nodes() const
{
  return mReferencedNodes;
}

BuiltInTypeId AliasNameDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::LogRecord
{
namespace
{
void encode(StackDepth limit, const ua::LogRecord& value, UaBinaryEncoder& encoder)
{
  uint32_t encodingMask = 0;
  if (value.event_type().has_value())
    encodingMask |= (1u << 0);
  if (value.source_node().has_value())
    encodingMask |= (1u << 1);
  if (value.source_name().has_value())
    encodingMask |= (1u << 2);
  if (value.trace_context().has_value())
    encodingMask |= (1u << 3);
  if (value.additional_data().has_value())
    encodingMask |= (1u << 4);
  encoder.encode(limit, encodingMask);
  encoder.encode(limit, value.time());
  encoder.encode(limit, value.severity());
  if (const auto& optField = value.event_type(); optField.has_value())
  {
    encoder.encode(limit, (*optField));
  }
  if (const auto& optField = value.source_node(); optField.has_value())
  {
    encoder.encode(limit, (*optField));
  }
  if (const auto& optField = value.source_name(); optField.has_value())
  {
    encoder.encode(limit, (*optField));
  }
  encoder.encode(limit, value.message());
  if (const auto& optField = value.trace_context(); optField.has_value())
  {
    encoder.encode(limit, (*optField));
  }
  if (const auto& optField = value.additional_data(); optField.has_value())
  {
    encoder.encode(limit, (*optField));
  }
}

void encode(StackDepth limit, const ua::LogRecord& value, XmlEncoder& encoder)
{
  uint32_t encodingMask = 0;
  if (value.event_type().has_value())
    encodingMask |= (1u << 0);
  if (value.source_node().has_value())
    encodingMask |= (1u << 1);
  if (value.source_name().has_value())
    encodingMask |= (1u << 2);
  if (value.trace_context().has_value())
    encodingMask |= (1u << 3);
  if (value.additional_data().has_value())
    encodingMask |= (1u << 4);
  encoder.encode(limit, "EncodingMask", encodingMask);
  encoder.encode(limit, "Time", value.time());
  encoder.encode(limit, "Severity", value.severity());
  if (const auto& optField = value.event_type(); optField.has_value())
  {
    encoder.encode(limit, "EventType", (*optField));
  }
  if (const auto& optField = value.source_node(); optField.has_value())
  {
    encoder.encode(limit, "SourceNode", (*optField));
  }
  if (const auto& optField = value.source_name(); optField.has_value())
  {
    encoder.encode(limit, "SourceName", (*optField));
  }
  encoder.encode(limit, "Message", value.message());
  if (const auto& optField = value.trace_context(); optField.has_value())
  {
    encoder.encode(limit, "TraceContext", (*optField));
  }
  if (const auto& optField = value.additional_data(); optField.has_value())
  {
    encoder.encode(limit, "AdditionalData", (*optField));
  }
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::LogRecord& value)
{
  uint32_t encodingMask{};
  decoder.decode(limit, encodingMask);
  if ((encodingMask & ~0x1fu) != 0)
    throw UaException(Status::BadDecodingError);
  decoder.decode(limit, value.time());
  decoder.decode(limit, value.severity());
  if (encodingMask & (1u << 0))
  {
    auto& optField = value.event_type();
    optField.emplace();
    decoder.decode(limit, (*optField));
  }
  if (encodingMask & (1u << 1))
  {
    auto& optField = value.source_node();
    optField.emplace();
    decoder.decode(limit, (*optField));
  }
  if (encodingMask & (1u << 2))
  {
    auto& optField = value.source_name();
    optField.emplace();
    decoder.decode(limit, (*optField));
  }
  decoder.decode(limit, value.message());
  if (encodingMask & (1u << 3))
  {
    auto& optField = value.trace_context();
    optField.emplace();
    decoder.decode(limit, (*optField));
  }
  if (encodingMask & (1u << 4))
  {
    auto& optField = value.additional_data();
    optField.emplace();
    decoder.decode(limit, (*optField));
  }
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::LogRecord& value)
{
  uint32_t encodingMask{};
  decoder.decode(limit, "EncodingMask", true, encodingMask);
  if ((encodingMask & ~0x1fu) != 0)
    throw UaException(Status::BadDecodingError);
  decoder.decode(limit, "Time", true, value.time());
  decoder.decode(limit, "Severity", true, value.severity());
  if (encodingMask & (1u << 0))
  {
    auto& optField = value.event_type();
    optField.emplace();
    decoder.decode(limit, "EventType", true, (*optField));
  }
  if (encodingMask & (1u << 1))
  {
    auto& optField = value.source_node();
    optField.emplace();
    decoder.decode(limit, "SourceNode", true, (*optField));
  }
  if (encodingMask & (1u << 2))
  {
    auto& optField = value.source_name();
    optField.emplace();
    decoder.decode(limit, "SourceName", true, (*optField));
  }
  decoder.decode(limit, "Message", true, value.message());
  if (encodingMask & (1u << 3))
  {
    auto& optField = value.trace_context();
    optField.emplace();
    decoder.decode(limit, "TraceContext", true, (*optField));
  }
  if (encodingMask & (1u << 4))
  {
    auto& optField = value.additional_data();
    optField.emplace();
    decoder.decode(limit, "AdditionalData", true, (*optField));
  }
}
}  // namespace
}  // namespace detail::LogRecord

namespace detail::LogRecord
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::LogRecord::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::LogRecord::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::LogRecord

namespace detail::LogRecord
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::LogRecord>();
}
}  // namespace
}  // namespace detail::LogRecord

bool LogRecord::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId LogRecord::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId LogRecord::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String LogRecord::type_name() const
{
  return typeName;
}

void LogRecord::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::LogRecord::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::LogRecord::encode(limit, *this, *xml);
  }
}

void LogRecord::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::LogRecord::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::LogRecord::encode_id(limit, ns, *xml);
  }
}

void LogRecord::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::LogRecord::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::LogRecord::decode(limit, *xml, *this);
  }
}

void LogRecord::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  mMessage = mMessage.resolve(locales);
}

unique_ptr<Structure> LogRecord::clone() const
{
  return make_unique<LogRecord>(*this);
}

void LogRecord::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "time=" + ua::to_string(time());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "severity=" + ua::to_string(severity());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "event_type=" + [&]
    {
      const auto& o = event_type();
      return o.has_value() ? ua::to_string(*o) : "null";
    }();
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "source_node=" + [&]
    {
      const auto& o = source_node();
      return o.has_value() ? ua::to_string(*o) : "null";
    }();
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "source_name=" + [&]
    {
      const auto& o = source_name();
      return o.has_value() ? ua::to_string(*o) : "null";
    }();
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "message=" + ua::to_string(message());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "trace_context=" + [&]
    {
      const auto& o = trace_context();
      return o.has_value() ? ua::to_string(*o) : "null";
    }();
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "additional_data=" + [&]
    {
      const auto& o = additional_data();
      return o.has_value() ? ua::to_string(*o) : "null";
    }();
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "time=" + ua::to_string(time());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "severity=" + ua::to_string(severity());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "event_type=" + [&]
  {
    const auto& o = event_type();
    return o.has_value() ? ua::to_string(*o) : "null";
  }();
  if (!output.empty())
  {
    output += ", ";
  }
  output += "source_node=" + [&]
  {
    const auto& o = source_node();
    return o.has_value() ? ua::to_string(*o) : "null";
  }();
  if (!output.empty())
  {
    output += ", ";
  }
  output += "source_name=" + [&]
  {
    const auto& o = source_name();
    return o.has_value() ? ua::to_string(*o) : "null";
  }();
  if (!output.empty())
  {
    output += ", ";
  }
  output += "message=" + ua::to_string(message());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "trace_context=" + [&]
  {
    const auto& o = trace_context();
    return o.has_value() ? ua::to_string(*o) : "null";
  }();
  if (!output.empty())
  {
    output += ", ";
  }
  output += "additional_data=" + [&]
  {
    const auto& o = additional_data();
    return o.has_value() ? ua::to_string(*o) : "null";
  }();
}

std::string LogRecord::to_string(int indent) const
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

void LogRecord::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::LogRecord::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::LogRecord::create);
  }
}

DateTime& LogRecord::time()
{
  return mTime;
}

const DateTime& LogRecord::time() const
{
  return mTime;
}

uint16_t& LogRecord::severity()
{
  return mSeverity;
}

const uint16_t& LogRecord::severity() const
{
  return mSeverity;
}

optional<NodeId>& LogRecord::event_type()
{
  return mEventType;
}

const optional<NodeId>& LogRecord::event_type() const
{
  return mEventType;
}

optional<NodeId>& LogRecord::source_node()
{
  return mSourceNode;
}

const optional<NodeId>& LogRecord::source_node() const
{
  return mSourceNode;
}

optional<String>& LogRecord::source_name()
{
  return mSourceName;
}

const optional<String>& LogRecord::source_name() const
{
  return mSourceName;
}

LocalizedText& LogRecord::message()
{
  return mMessage;
}

const LocalizedText& LogRecord::message() const
{
  return mMessage;
}

optional<TraceContextDataType>& LogRecord::trace_context()
{
  return mTraceContext;
}

const optional<TraceContextDataType>& LogRecord::trace_context() const
{
  return mTraceContext;
}

optional<Array<NameValuePair>>& LogRecord::additional_data()
{
  return mAdditionalData;
}

const optional<Array<NameValuePair>>& LogRecord::additional_data() const
{
  return mAdditionalData;
}

BuiltInTypeId LogRecord::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::StructureDefinition
{
namespace
{
void encode(StackDepth limit, const ua::StructureDefinition& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.default_encoding_id());
  encoder.encode(limit, value.base_data_type());
  encoder.encode(limit, utils::as_int32(value.structure_type()));
  encoder.encode(limit, value.fields());
}

void encode(StackDepth limit, const ua::StructureDefinition& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "DefaultEncodingId", value.default_encoding_id());
  encoder.encode(limit, "BaseDataType", value.base_data_type());
  encoder.encode(limit, "StructureType", utils::as_int32(value.structure_type()));
  encoder.encode(limit, "Fields", value.fields());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::StructureDefinition& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.default_encoding_id());
  decoder.decode(limit, value.base_data_type());
  decoder.decode(limit, enumVal);
  value.structure_type() = utils::from_underlying<StructureType>(enumVal);
  decoder.decode(limit, value.fields());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::StructureDefinition& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "DefaultEncodingId", true, value.default_encoding_id());
  decoder.decode(limit, "BaseDataType", true, value.base_data_type());
  decoder.decode(limit, "StructureType", true, enumVal);
  value.structure_type() = utils::from_underlying<StructureType>(enumVal);
  decoder.decode(limit, "Fields", true, value.fields());
}
}  // namespace
}  // namespace detail::StructureDefinition

namespace detail::StructureDefinition
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::StructureDefinition::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::StructureDefinition::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::StructureDefinition

namespace detail::StructureDefinition
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::StructureDefinition>();
}
}  // namespace
}  // namespace detail::StructureDefinition

bool StructureDefinition::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return DataTypeDefinition::is_of_type(ns, dataTypeId);
}

NodeId StructureDefinition::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId StructureDefinition::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String StructureDefinition::type_name() const
{
  return typeName;
}

void StructureDefinition::encode(StackDepth limit, Encoder& encoder) const
{

  DataTypeDefinition::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::StructureDefinition::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::StructureDefinition::encode(limit, *this, *xml);
  }
}

void StructureDefinition::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::StructureDefinition::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::StructureDefinition::encode_id(limit, ns, *xml);
  }
}

void StructureDefinition::decode(StackDepth limit, Decoder& decoder)
{

  DataTypeDefinition::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::StructureDefinition::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::StructureDefinition::decode(limit, *xml, *this);
  }
}

void StructureDefinition::resolve(span<const LocaleId> locales)
{
  DataTypeDefinition::resolve(locales);
  for (size_t i = 0; i < mFields.size(); ++i)
  {
    mFields[i].resolve(locales);
  }
}

unique_ptr<Structure> StructureDefinition::clone() const
{
  return make_unique<StructureDefinition>(*this);
}

void StructureDefinition::append_fields(std::string& output, int indent) const
{
  DataTypeDefinition::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "default_encoding_id=" + ua::to_string(default_encoding_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "base_data_type=" + ua::to_string(base_data_type());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "structure_type=" + ua::to_string(utils::as_int32(structure_type()));
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "fields=" + ua::to_string(fields());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "default_encoding_id=" + ua::to_string(default_encoding_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "base_data_type=" + ua::to_string(base_data_type());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "structure_type=" + ua::to_string(utils::as_int32(structure_type()));
  if (!output.empty())
  {
    output += ", ";
  }
  output += "fields=" + ua::to_string(fields());
}

std::string StructureDefinition::to_string(int indent) const
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

void StructureDefinition::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::StructureDefinition::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::StructureDefinition::create);
  }
}

NodeId& StructureDefinition::default_encoding_id()
{
  return mDefaultEncodingId;
}

const NodeId& StructureDefinition::default_encoding_id() const
{
  return mDefaultEncodingId;
}

NodeId& StructureDefinition::base_data_type()
{
  return mBaseDataType;
}

const NodeId& StructureDefinition::base_data_type() const
{
  return mBaseDataType;
}

StructureType& StructureDefinition::structure_type()
{
  return mStructureType;
}

const StructureType& StructureDefinition::structure_type() const
{
  return mStructureType;
}

Array<StructureField>& StructureDefinition::fields()
{
  return mFields;
}

const Array<StructureField>& StructureDefinition::fields() const
{
  return mFields;
}

BuiltInTypeId StructureDefinition::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ServerOnNetwork
{
namespace
{
void encode(StackDepth limit, const ua::ServerOnNetwork& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.record_id());
  encoder.encode(limit, value.server_name());
  encoder.encode(limit, value.discovery_url());
  encoder.encode(limit, value.server_capabilities());
}

void encode(StackDepth limit, const ua::ServerOnNetwork& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RecordId", value.record_id());
  encoder.encode(limit, "ServerName", value.server_name());
  encoder.encode(limit, "DiscoveryUrl", value.discovery_url());
  encoder.encode(limit, "ServerCapabilities", value.server_capabilities());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ServerOnNetwork& value)
{
  decoder.decode(limit, value.record_id());
  decoder.decode(limit, value.server_name());
  decoder.decode(limit, value.discovery_url());
  decoder.decode(limit, value.server_capabilities());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ServerOnNetwork& value)
{
  decoder.decode(limit, "RecordId", true, value.record_id());
  decoder.decode(limit, "ServerName", true, value.server_name());
  decoder.decode(limit, "DiscoveryUrl", true, value.discovery_url());
  decoder.decode(limit, "ServerCapabilities", true, value.server_capabilities());
}
}  // namespace
}  // namespace detail::ServerOnNetwork

namespace detail::ServerOnNetwork
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ServerOnNetwork::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ServerOnNetwork::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ServerOnNetwork

namespace detail::ServerOnNetwork
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ServerOnNetwork>();
}
}  // namespace
}  // namespace detail::ServerOnNetwork

bool ServerOnNetwork::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ServerOnNetwork::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ServerOnNetwork::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ServerOnNetwork::type_name() const
{
  return typeName;
}

void ServerOnNetwork::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ServerOnNetwork::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ServerOnNetwork::encode(limit, *this, *xml);
  }
}

void ServerOnNetwork::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ServerOnNetwork::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ServerOnNetwork::encode_id(limit, ns, *xml);
  }
}

void ServerOnNetwork::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ServerOnNetwork::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ServerOnNetwork::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ServerOnNetwork::clone() const
{
  return make_unique<ServerOnNetwork>(*this);
}

void ServerOnNetwork::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "record_id=" + ua::to_string(record_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "server_name=" + ua::to_string(server_name());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "discovery_url=" + ua::to_string(discovery_url());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "server_capabilities=" + ua::to_string(server_capabilities());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "record_id=" + ua::to_string(record_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "server_name=" + ua::to_string(server_name());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "discovery_url=" + ua::to_string(discovery_url());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "server_capabilities=" + ua::to_string(server_capabilities());
}

std::string ServerOnNetwork::to_string(int indent) const
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

void ServerOnNetwork::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ServerOnNetwork::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ServerOnNetwork::create);
  }
}

uint32_t& ServerOnNetwork::record_id()
{
  return mRecordId;
}

const uint32_t& ServerOnNetwork::record_id() const
{
  return mRecordId;
}

String& ServerOnNetwork::server_name()
{
  return mServerName;
}

const String& ServerOnNetwork::server_name() const
{
  return mServerName;
}

String& ServerOnNetwork::discovery_url()
{
  return mDiscoveryUrl;
}

const String& ServerOnNetwork::discovery_url() const
{
  return mDiscoveryUrl;
}

Array<String>& ServerOnNetwork::server_capabilities()
{
  return mServerCapabilities;
}

const Array<String>& ServerOnNetwork::server_capabilities() const
{
  return mServerCapabilities;
}

BuiltInTypeId ServerOnNetwork::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::AnonymousIdentityToken
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::AnonymousIdentityToken::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::AnonymousIdentityToken::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::AnonymousIdentityToken

namespace detail::AnonymousIdentityToken
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::AnonymousIdentityToken>();
}
}  // namespace
}  // namespace detail::AnonymousIdentityToken

bool AnonymousIdentityToken::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return UserIdentityToken::is_of_type(ns, dataTypeId);
}

NodeId AnonymousIdentityToken::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId AnonymousIdentityToken::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String AnonymousIdentityToken::type_name() const
{
  return typeName;
}

void AnonymousIdentityToken::encode(StackDepth limit, Encoder& encoder) const
{

  UserIdentityToken::encode(limit, encoder);
}

void AnonymousIdentityToken::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AnonymousIdentityToken::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AnonymousIdentityToken::encode_id(limit, ns, *xml);
  }
}

void AnonymousIdentityToken::decode(StackDepth limit, Decoder& decoder)
{

  UserIdentityToken::decode(limit, decoder);
}

unique_ptr<Structure> AnonymousIdentityToken::clone() const
{
  return make_unique<AnonymousIdentityToken>(*this);
}

std::string AnonymousIdentityToken::to_string(int indent) const
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

void AnonymousIdentityToken::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::AnonymousIdentityToken::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::AnonymousIdentityToken::create);
  }
}

BuiltInTypeId AnonymousIdentityToken::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::RelativePathElement
{
namespace
{
void encode(StackDepth limit, const ua::RelativePathElement& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.reference_type_id());
  encoder.encode(limit, value.is_inverse());
  encoder.encode(limit, value.include_subtypes());
  encoder.encode(limit, value.target_name());
}

void encode(StackDepth limit, const ua::RelativePathElement& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ReferenceTypeId", value.reference_type_id());
  encoder.encode(limit, "IsInverse", value.is_inverse());
  encoder.encode(limit, "IncludeSubtypes", value.include_subtypes());
  encoder.encode(limit, "TargetName", value.target_name());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::RelativePathElement& value)
{
  decoder.decode(limit, value.reference_type_id());
  decoder.decode(limit, value.is_inverse());
  decoder.decode(limit, value.include_subtypes());
  decoder.decode(limit, value.target_name());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::RelativePathElement& value)
{
  decoder.decode(limit, "ReferenceTypeId", true, value.reference_type_id());
  decoder.decode(limit, "IsInverse", true, value.is_inverse());
  decoder.decode(limit, "IncludeSubtypes", true, value.include_subtypes());
  decoder.decode(limit, "TargetName", true, value.target_name());
}
}  // namespace
}  // namespace detail::RelativePathElement

namespace detail::RelativePathElement
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::RelativePathElement::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::RelativePathElement::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::RelativePathElement

namespace detail::RelativePathElement
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::RelativePathElement>();
}
}  // namespace
}  // namespace detail::RelativePathElement

bool RelativePathElement::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId RelativePathElement::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId RelativePathElement::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String RelativePathElement::type_name() const
{
  return typeName;
}

void RelativePathElement::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RelativePathElement::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RelativePathElement::encode(limit, *this, *xml);
  }
}

void RelativePathElement::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RelativePathElement::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RelativePathElement::encode_id(limit, ns, *xml);
  }
}

void RelativePathElement::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::RelativePathElement::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::RelativePathElement::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> RelativePathElement::clone() const
{
  return make_unique<RelativePathElement>(*this);
}

void RelativePathElement::append_fields(std::string& output, int indent) const
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
    output += pad + "is_inverse=" + ua::to_string(is_inverse());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "include_subtypes=" + ua::to_string(include_subtypes());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "target_name=" + ua::to_string(target_name());
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
  output += "is_inverse=" + ua::to_string(is_inverse());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "include_subtypes=" + ua::to_string(include_subtypes());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "target_name=" + ua::to_string(target_name());
}

std::string RelativePathElement::to_string(int indent) const
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

void RelativePathElement::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::RelativePathElement::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::RelativePathElement::create);
  }
}

NodeId& RelativePathElement::reference_type_id()
{
  return mReferenceTypeId;
}

const NodeId& RelativePathElement::reference_type_id() const
{
  return mReferenceTypeId;
}

bool& RelativePathElement::is_inverse()
{
  return mIsInverse;
}

const bool& RelativePathElement::is_inverse() const
{
  return mIsInverse;
}

bool& RelativePathElement::include_subtypes()
{
  return mIncludeSubtypes;
}

const bool& RelativePathElement::include_subtypes() const
{
  return mIncludeSubtypes;
}

QualifiedName& RelativePathElement::target_name()
{
  return mTargetName;
}

const QualifiedName& RelativePathElement::target_name() const
{
  return mTargetName;
}

BuiltInTypeId RelativePathElement::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::AttributeOperand
{
namespace
{
void encode(StackDepth limit, const ua::AttributeOperand& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.node_id());
  encoder.encode(limit, value.alias());
  encoder.encode(limit, value.browse_path());
  encoder.encode(limit, value.attribute_id());
  encoder.encode(limit, value.index_range());
}

void encode(StackDepth limit, const ua::AttributeOperand& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "NodeId", value.node_id());
  encoder.encode(limit, "Alias", value.alias());
  encoder.encode(limit, "BrowsePath", value.browse_path());
  encoder.encode(limit, "AttributeId", value.attribute_id());
  encoder.encode(limit, "IndexRange", value.index_range());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::AttributeOperand& value)
{
  decoder.decode(limit, value.node_id());
  decoder.decode(limit, value.alias());
  decoder.decode(limit, value.browse_path());
  decoder.decode(limit, value.attribute_id());
  decoder.decode(limit, value.index_range());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::AttributeOperand& value)
{
  decoder.decode(limit, "NodeId", true, value.node_id());
  decoder.decode(limit, "Alias", true, value.alias());
  decoder.decode(limit, "BrowsePath", true, value.browse_path());
  decoder.decode(limit, "AttributeId", true, value.attribute_id());
  decoder.decode(limit, "IndexRange", true, value.index_range());
}
}  // namespace
}  // namespace detail::AttributeOperand

namespace detail::AttributeOperand
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::AttributeOperand::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::AttributeOperand::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::AttributeOperand

namespace detail::AttributeOperand
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::AttributeOperand>();
}
}  // namespace
}  // namespace detail::AttributeOperand

bool AttributeOperand::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return FilterOperand::is_of_type(ns, dataTypeId);
}

NodeId AttributeOperand::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId AttributeOperand::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String AttributeOperand::type_name() const
{
  return typeName;
}

void AttributeOperand::encode(StackDepth limit, Encoder& encoder) const
{

  FilterOperand::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AttributeOperand::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AttributeOperand::encode(limit, *this, *xml);
  }
}

void AttributeOperand::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AttributeOperand::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AttributeOperand::encode_id(limit, ns, *xml);
  }
}

void AttributeOperand::decode(StackDepth limit, Decoder& decoder)
{

  FilterOperand::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::AttributeOperand::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::AttributeOperand::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> AttributeOperand::clone() const
{
  return make_unique<AttributeOperand>(*this);
}

void AttributeOperand::append_fields(std::string& output, int indent) const
{
  FilterOperand::append_fields(output, indent);
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
    output += pad + "alias=" + ua::to_string(alias());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "browse_path=" + ua::to_string(browse_path());
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
  output += "alias=" + ua::to_string(alias());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "browse_path=" + ua::to_string(browse_path());
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
}

std::string AttributeOperand::to_string(int indent) const
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

void AttributeOperand::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::AttributeOperand::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::AttributeOperand::create);
  }
}

NodeId& AttributeOperand::node_id()
{
  return mNodeId;
}

const NodeId& AttributeOperand::node_id() const
{
  return mNodeId;
}

String& AttributeOperand::alias()
{
  return mAlias;
}

const String& AttributeOperand::alias() const
{
  return mAlias;
}

RelativePath& AttributeOperand::browse_path()
{
  return mBrowsePath;
}

const RelativePath& AttributeOperand::browse_path() const
{
  return mBrowsePath;
}

IntegerId& AttributeOperand::attribute_id()
{
  return mAttributeId;
}

const IntegerId& AttributeOperand::attribute_id() const
{
  return mAttributeId;
}

NumericRange& AttributeOperand::index_range()
{
  return mIndexRange;
}

const NumericRange& AttributeOperand::index_range() const
{
  return mIndexRange;
}

BuiltInTypeId AttributeOperand::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::HistoryEventFieldList
{
namespace
{
void encode(StackDepth limit, const ua::HistoryEventFieldList& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.event_fields());
}

void encode(StackDepth limit, const ua::HistoryEventFieldList& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "EventFields", value.event_fields());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::HistoryEventFieldList& value)
{
  decoder.decode(limit, value.event_fields());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::HistoryEventFieldList& value)
{
  decoder.decode(limit, "EventFields", true, value.event_fields());
}
}  // namespace
}  // namespace detail::HistoryEventFieldList

namespace detail::HistoryEventFieldList
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::HistoryEventFieldList::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::HistoryEventFieldList::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::HistoryEventFieldList

namespace detail::HistoryEventFieldList
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::HistoryEventFieldList>();
}
}  // namespace
}  // namespace detail::HistoryEventFieldList

bool HistoryEventFieldList::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId HistoryEventFieldList::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId HistoryEventFieldList::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String HistoryEventFieldList::type_name() const
{
  return typeName;
}

void HistoryEventFieldList::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::HistoryEventFieldList::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::HistoryEventFieldList::encode(limit, *this, *xml);
  }
}

void HistoryEventFieldList::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::HistoryEventFieldList::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::HistoryEventFieldList::encode_id(limit, ns, *xml);
  }
}

void HistoryEventFieldList::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::HistoryEventFieldList::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::HistoryEventFieldList::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> HistoryEventFieldList::clone() const
{
  return make_unique<HistoryEventFieldList>(*this);
}

void HistoryEventFieldList::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "event_fields=" + ua::to_string(event_fields());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "event_fields=" + ua::to_string(event_fields());
}

std::string HistoryEventFieldList::to_string(int indent) const
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

void HistoryEventFieldList::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::HistoryEventFieldList::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::HistoryEventFieldList::create);
  }
}

Array<Variant>& HistoryEventFieldList::event_fields()
{
  return mEventFields;
}

const Array<Variant>& HistoryEventFieldList::event_fields() const
{
  return mEventFields;
}

BuiltInTypeId HistoryEventFieldList::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::SessionDiagnosticsDataType
{
namespace
{
void encode(StackDepth limit, const ua::SessionDiagnosticsDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.session_id());
  encoder.encode(limit, value.session_name());
  encoder.encode(limit, value.client_description());
  encoder.encode(limit, value.server_uri());
  encoder.encode(limit, value.endpoint_url());
  encoder.encode(limit, value.locale_ids());
  encoder.encode(limit, value.actual_session_timeout());
  encoder.encode(limit, value.max_response_message_size());
  encoder.encode(limit, value.client_connection_time());
  encoder.encode(limit, value.client_last_contact_time());
  encoder.encode(limit, value.current_subscriptions_count());
  encoder.encode(limit, value.current_monitored_items_count());
  encoder.encode(limit, value.current_publish_requests_in_queue());
  encoder.encode(limit, value.total_request_count());
  encoder.encode(limit, value.unauthorized_request_count());
  encoder.encode(limit, value.read_count());
  encoder.encode(limit, value.history_read_count());
  encoder.encode(limit, value.write_count());
  encoder.encode(limit, value.history_update_count());
  encoder.encode(limit, value.call_count());
  encoder.encode(limit, value.create_monitored_items_count());
  encoder.encode(limit, value.modify_monitored_items_count());
  encoder.encode(limit, value.set_monitoring_mode_count());
  encoder.encode(limit, value.set_triggering_count());
  encoder.encode(limit, value.delete_monitored_items_count());
  encoder.encode(limit, value.create_subscription_count());
  encoder.encode(limit, value.modify_subscription_count());
  encoder.encode(limit, value.set_publishing_mode_count());
  encoder.encode(limit, value.publish_count());
  encoder.encode(limit, value.republish_count());
  encoder.encode(limit, value.transfer_subscriptions_count());
  encoder.encode(limit, value.delete_subscriptions_count());
  encoder.encode(limit, value.add_nodes_count());
  encoder.encode(limit, value.add_references_count());
  encoder.encode(limit, value.delete_nodes_count());
  encoder.encode(limit, value.delete_references_count());
  encoder.encode(limit, value.browse_count());
  encoder.encode(limit, value.browse_next_count());
  encoder.encode(limit, value.translate_browse_paths_to_node_ids_count());
  encoder.encode(limit, value.query_first_count());
  encoder.encode(limit, value.query_next_count());
  encoder.encode(limit, value.register_nodes_count());
  encoder.encode(limit, value.unregister_nodes_count());
}

void encode(StackDepth limit, const ua::SessionDiagnosticsDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "SessionId", value.session_id());
  encoder.encode(limit, "SessionName", value.session_name());
  encoder.encode(limit, "ClientDescription", value.client_description());
  encoder.encode(limit, "ServerUri", value.server_uri());
  encoder.encode(limit, "EndpointUrl", value.endpoint_url());
  encoder.encode(limit, "LocaleIds", value.locale_ids());
  encoder.encode(limit, "ActualSessionTimeout", value.actual_session_timeout());
  encoder.encode(limit, "MaxResponseMessageSize", value.max_response_message_size());
  encoder.encode(limit, "ClientConnectionTime", value.client_connection_time());
  encoder.encode(limit, "ClientLastContactTime", value.client_last_contact_time());
  encoder.encode(limit, "CurrentSubscriptionsCount", value.current_subscriptions_count());
  encoder.encode(limit, "CurrentMonitoredItemsCount", value.current_monitored_items_count());
  encoder.encode(limit, "CurrentPublishRequestsInQueue", value.current_publish_requests_in_queue());
  encoder.encode(limit, "TotalRequestCount", value.total_request_count());
  encoder.encode(limit, "UnauthorizedRequestCount", value.unauthorized_request_count());
  encoder.encode(limit, "ReadCount", value.read_count());
  encoder.encode(limit, "HistoryReadCount", value.history_read_count());
  encoder.encode(limit, "WriteCount", value.write_count());
  encoder.encode(limit, "HistoryUpdateCount", value.history_update_count());
  encoder.encode(limit, "CallCount", value.call_count());
  encoder.encode(limit, "CreateMonitoredItemsCount", value.create_monitored_items_count());
  encoder.encode(limit, "ModifyMonitoredItemsCount", value.modify_monitored_items_count());
  encoder.encode(limit, "SetMonitoringModeCount", value.set_monitoring_mode_count());
  encoder.encode(limit, "SetTriggeringCount", value.set_triggering_count());
  encoder.encode(limit, "DeleteMonitoredItemsCount", value.delete_monitored_items_count());
  encoder.encode(limit, "CreateSubscriptionCount", value.create_subscription_count());
  encoder.encode(limit, "ModifySubscriptionCount", value.modify_subscription_count());
  encoder.encode(limit, "SetPublishingModeCount", value.set_publishing_mode_count());
  encoder.encode(limit, "PublishCount", value.publish_count());
  encoder.encode(limit, "RepublishCount", value.republish_count());
  encoder.encode(limit, "TransferSubscriptionsCount", value.transfer_subscriptions_count());
  encoder.encode(limit, "DeleteSubscriptionsCount", value.delete_subscriptions_count());
  encoder.encode(limit, "AddNodesCount", value.add_nodes_count());
  encoder.encode(limit, "AddReferencesCount", value.add_references_count());
  encoder.encode(limit, "DeleteNodesCount", value.delete_nodes_count());
  encoder.encode(limit, "DeleteReferencesCount", value.delete_references_count());
  encoder.encode(limit, "BrowseCount", value.browse_count());
  encoder.encode(limit, "BrowseNextCount", value.browse_next_count());
  encoder.encode(
    limit, "TranslateBrowsePathsToNodeIdsCount", value.translate_browse_paths_to_node_ids_count());
  encoder.encode(limit, "QueryFirstCount", value.query_first_count());
  encoder.encode(limit, "QueryNextCount", value.query_next_count());
  encoder.encode(limit, "RegisterNodesCount", value.register_nodes_count());
  encoder.encode(limit, "UnregisterNodesCount", value.unregister_nodes_count());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::SessionDiagnosticsDataType& value)
{
  decoder.decode(limit, value.session_id());
  decoder.decode(limit, value.session_name());
  decoder.decode(limit, value.client_description());
  decoder.decode(limit, value.server_uri());
  decoder.decode(limit, value.endpoint_url());
  decoder.decode(limit, value.locale_ids());
  decoder.decode(limit, value.actual_session_timeout());
  decoder.decode(limit, value.max_response_message_size());
  decoder.decode(limit, value.client_connection_time());
  decoder.decode(limit, value.client_last_contact_time());
  decoder.decode(limit, value.current_subscriptions_count());
  decoder.decode(limit, value.current_monitored_items_count());
  decoder.decode(limit, value.current_publish_requests_in_queue());
  decoder.decode(limit, value.total_request_count());
  decoder.decode(limit, value.unauthorized_request_count());
  decoder.decode(limit, value.read_count());
  decoder.decode(limit, value.history_read_count());
  decoder.decode(limit, value.write_count());
  decoder.decode(limit, value.history_update_count());
  decoder.decode(limit, value.call_count());
  decoder.decode(limit, value.create_monitored_items_count());
  decoder.decode(limit, value.modify_monitored_items_count());
  decoder.decode(limit, value.set_monitoring_mode_count());
  decoder.decode(limit, value.set_triggering_count());
  decoder.decode(limit, value.delete_monitored_items_count());
  decoder.decode(limit, value.create_subscription_count());
  decoder.decode(limit, value.modify_subscription_count());
  decoder.decode(limit, value.set_publishing_mode_count());
  decoder.decode(limit, value.publish_count());
  decoder.decode(limit, value.republish_count());
  decoder.decode(limit, value.transfer_subscriptions_count());
  decoder.decode(limit, value.delete_subscriptions_count());
  decoder.decode(limit, value.add_nodes_count());
  decoder.decode(limit, value.add_references_count());
  decoder.decode(limit, value.delete_nodes_count());
  decoder.decode(limit, value.delete_references_count());
  decoder.decode(limit, value.browse_count());
  decoder.decode(limit, value.browse_next_count());
  decoder.decode(limit, value.translate_browse_paths_to_node_ids_count());
  decoder.decode(limit, value.query_first_count());
  decoder.decode(limit, value.query_next_count());
  decoder.decode(limit, value.register_nodes_count());
  decoder.decode(limit, value.unregister_nodes_count());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::SessionDiagnosticsDataType& value)
{
  decoder.decode(limit, "SessionId", true, value.session_id());
  decoder.decode(limit, "SessionName", true, value.session_name());
  decoder.decode(limit, "ClientDescription", true, value.client_description());
  decoder.decode(limit, "ServerUri", true, value.server_uri());
  decoder.decode(limit, "EndpointUrl", true, value.endpoint_url());
  decoder.decode(limit, "LocaleIds", true, value.locale_ids());
  decoder.decode(limit, "ActualSessionTimeout", true, value.actual_session_timeout());
  decoder.decode(limit, "MaxResponseMessageSize", true, value.max_response_message_size());
  decoder.decode(limit, "ClientConnectionTime", true, value.client_connection_time());
  decoder.decode(limit, "ClientLastContactTime", true, value.client_last_contact_time());
  decoder.decode(limit, "CurrentSubscriptionsCount", true, value.current_subscriptions_count());
  decoder.decode(limit, "CurrentMonitoredItemsCount", true, value.current_monitored_items_count());
  decoder.decode(limit, "CurrentPublishRequestsInQueue", true, value.current_publish_requests_in_queue());
  decoder.decode(limit, "TotalRequestCount", true, value.total_request_count());
  decoder.decode(limit, "UnauthorizedRequestCount", true, value.unauthorized_request_count());
  decoder.decode(limit, "ReadCount", true, value.read_count());
  decoder.decode(limit, "HistoryReadCount", true, value.history_read_count());
  decoder.decode(limit, "WriteCount", true, value.write_count());
  decoder.decode(limit, "HistoryUpdateCount", true, value.history_update_count());
  decoder.decode(limit, "CallCount", true, value.call_count());
  decoder.decode(limit, "CreateMonitoredItemsCount", true, value.create_monitored_items_count());
  decoder.decode(limit, "ModifyMonitoredItemsCount", true, value.modify_monitored_items_count());
  decoder.decode(limit, "SetMonitoringModeCount", true, value.set_monitoring_mode_count());
  decoder.decode(limit, "SetTriggeringCount", true, value.set_triggering_count());
  decoder.decode(limit, "DeleteMonitoredItemsCount", true, value.delete_monitored_items_count());
  decoder.decode(limit, "CreateSubscriptionCount", true, value.create_subscription_count());
  decoder.decode(limit, "ModifySubscriptionCount", true, value.modify_subscription_count());
  decoder.decode(limit, "SetPublishingModeCount", true, value.set_publishing_mode_count());
  decoder.decode(limit, "PublishCount", true, value.publish_count());
  decoder.decode(limit, "RepublishCount", true, value.republish_count());
  decoder.decode(limit, "TransferSubscriptionsCount", true, value.transfer_subscriptions_count());
  decoder.decode(limit, "DeleteSubscriptionsCount", true, value.delete_subscriptions_count());
  decoder.decode(limit, "AddNodesCount", true, value.add_nodes_count());
  decoder.decode(limit, "AddReferencesCount", true, value.add_references_count());
  decoder.decode(limit, "DeleteNodesCount", true, value.delete_nodes_count());
  decoder.decode(limit, "DeleteReferencesCount", true, value.delete_references_count());
  decoder.decode(limit, "BrowseCount", true, value.browse_count());
  decoder.decode(limit, "BrowseNextCount", true, value.browse_next_count());
  decoder.decode(
    limit, "TranslateBrowsePathsToNodeIdsCount", true, value.translate_browse_paths_to_node_ids_count());
  decoder.decode(limit, "QueryFirstCount", true, value.query_first_count());
  decoder.decode(limit, "QueryNextCount", true, value.query_next_count());
  decoder.decode(limit, "RegisterNodesCount", true, value.register_nodes_count());
  decoder.decode(limit, "UnregisterNodesCount", true, value.unregister_nodes_count());
}
}  // namespace
}  // namespace detail::SessionDiagnosticsDataType

namespace detail::SessionDiagnosticsDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::SessionDiagnosticsDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::SessionDiagnosticsDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::SessionDiagnosticsDataType

namespace detail::SessionDiagnosticsDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::SessionDiagnosticsDataType>();
}
}  // namespace
}  // namespace detail::SessionDiagnosticsDataType

bool SessionDiagnosticsDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId SessionDiagnosticsDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId SessionDiagnosticsDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String SessionDiagnosticsDataType::type_name() const
{
  return typeName;
}

void SessionDiagnosticsDataType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SessionDiagnosticsDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SessionDiagnosticsDataType::encode(limit, *this, *xml);
  }
}

void SessionDiagnosticsDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SessionDiagnosticsDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SessionDiagnosticsDataType::encode_id(limit, ns, *xml);
  }
}

void SessionDiagnosticsDataType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::SessionDiagnosticsDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::SessionDiagnosticsDataType::decode(limit, *xml, *this);
  }
}

void SessionDiagnosticsDataType::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  mClientDescription.resolve(locales);
}

unique_ptr<Structure> SessionDiagnosticsDataType::clone() const
{
  return make_unique<SessionDiagnosticsDataType>(*this);
}

void SessionDiagnosticsDataType::append_fields(std::string& output, int indent) const
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
    output += pad + "session_name=" + ua::to_string(session_name());
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
    output += pad + "locale_ids=" + ua::to_string(locale_ids());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "actual_session_timeout=" + ua::to_string(actual_session_timeout());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "max_response_message_size=" + ua::to_string(max_response_message_size());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "client_connection_time=" + ua::to_string(client_connection_time());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "client_last_contact_time=" + ua::to_string(client_last_contact_time());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "current_subscriptions_count=" + ua::to_string(current_subscriptions_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "current_monitored_items_count=" + ua::to_string(current_monitored_items_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "current_publish_requests_in_queue=" + ua::to_string(current_publish_requests_in_queue());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "total_request_count=" + ua::to_string(total_request_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "unauthorized_request_count=" + ua::to_string(unauthorized_request_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "read_count=" + ua::to_string(read_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "history_read_count=" + ua::to_string(history_read_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "write_count=" + ua::to_string(write_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "history_update_count=" + ua::to_string(history_update_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "call_count=" + ua::to_string(call_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "create_monitored_items_count=" + ua::to_string(create_monitored_items_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "modify_monitored_items_count=" + ua::to_string(modify_monitored_items_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "set_monitoring_mode_count=" + ua::to_string(set_monitoring_mode_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "set_triggering_count=" + ua::to_string(set_triggering_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "delete_monitored_items_count=" + ua::to_string(delete_monitored_items_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "create_subscription_count=" + ua::to_string(create_subscription_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "modify_subscription_count=" + ua::to_string(modify_subscription_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "set_publishing_mode_count=" + ua::to_string(set_publishing_mode_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "publish_count=" + ua::to_string(publish_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "republish_count=" + ua::to_string(republish_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "transfer_subscriptions_count=" + ua::to_string(transfer_subscriptions_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "delete_subscriptions_count=" + ua::to_string(delete_subscriptions_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "add_nodes_count=" + ua::to_string(add_nodes_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "add_references_count=" + ua::to_string(add_references_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "delete_nodes_count=" + ua::to_string(delete_nodes_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "delete_references_count=" + ua::to_string(delete_references_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "browse_count=" + ua::to_string(browse_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "browse_next_count=" + ua::to_string(browse_next_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "translate_browse_paths_to_node_ids_count=" +
              ua::to_string(translate_browse_paths_to_node_ids_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "query_first_count=" + ua::to_string(query_first_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "query_next_count=" + ua::to_string(query_next_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "register_nodes_count=" + ua::to_string(register_nodes_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "unregister_nodes_count=" + ua::to_string(unregister_nodes_count());
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
  output += "session_name=" + ua::to_string(session_name());
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
  output += "locale_ids=" + ua::to_string(locale_ids());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "actual_session_timeout=" + ua::to_string(actual_session_timeout());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "max_response_message_size=" + ua::to_string(max_response_message_size());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "client_connection_time=" + ua::to_string(client_connection_time());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "client_last_contact_time=" + ua::to_string(client_last_contact_time());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "current_subscriptions_count=" + ua::to_string(current_subscriptions_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "current_monitored_items_count=" + ua::to_string(current_monitored_items_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "current_publish_requests_in_queue=" + ua::to_string(current_publish_requests_in_queue());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "total_request_count=" + ua::to_string(total_request_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "unauthorized_request_count=" + ua::to_string(unauthorized_request_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "read_count=" + ua::to_string(read_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "history_read_count=" + ua::to_string(history_read_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "write_count=" + ua::to_string(write_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "history_update_count=" + ua::to_string(history_update_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "call_count=" + ua::to_string(call_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "create_monitored_items_count=" + ua::to_string(create_monitored_items_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "modify_monitored_items_count=" + ua::to_string(modify_monitored_items_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "set_monitoring_mode_count=" + ua::to_string(set_monitoring_mode_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "set_triggering_count=" + ua::to_string(set_triggering_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "delete_monitored_items_count=" + ua::to_string(delete_monitored_items_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "create_subscription_count=" + ua::to_string(create_subscription_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "modify_subscription_count=" + ua::to_string(modify_subscription_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "set_publishing_mode_count=" + ua::to_string(set_publishing_mode_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "publish_count=" + ua::to_string(publish_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "republish_count=" + ua::to_string(republish_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "transfer_subscriptions_count=" + ua::to_string(transfer_subscriptions_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "delete_subscriptions_count=" + ua::to_string(delete_subscriptions_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "add_nodes_count=" + ua::to_string(add_nodes_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "add_references_count=" + ua::to_string(add_references_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "delete_nodes_count=" + ua::to_string(delete_nodes_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "delete_references_count=" + ua::to_string(delete_references_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "browse_count=" + ua::to_string(browse_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "browse_next_count=" + ua::to_string(browse_next_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output +=
    "translate_browse_paths_to_node_ids_count=" + ua::to_string(translate_browse_paths_to_node_ids_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "query_first_count=" + ua::to_string(query_first_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "query_next_count=" + ua::to_string(query_next_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "register_nodes_count=" + ua::to_string(register_nodes_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "unregister_nodes_count=" + ua::to_string(unregister_nodes_count());
}

std::string SessionDiagnosticsDataType::to_string(int indent) const
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

void SessionDiagnosticsDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::SessionDiagnosticsDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::SessionDiagnosticsDataType::create);
  }
}

NodeId& SessionDiagnosticsDataType::session_id()
{
  return mSessionId;
}

const NodeId& SessionDiagnosticsDataType::session_id() const
{
  return mSessionId;
}

String& SessionDiagnosticsDataType::session_name()
{
  return mSessionName;
}

const String& SessionDiagnosticsDataType::session_name() const
{
  return mSessionName;
}

ApplicationDescription& SessionDiagnosticsDataType::client_description()
{
  return mClientDescription;
}

const ApplicationDescription& SessionDiagnosticsDataType::client_description() const
{
  return mClientDescription;
}

String& SessionDiagnosticsDataType::server_uri()
{
  return mServerUri;
}

const String& SessionDiagnosticsDataType::server_uri() const
{
  return mServerUri;
}

String& SessionDiagnosticsDataType::endpoint_url()
{
  return mEndpointUrl;
}

const String& SessionDiagnosticsDataType::endpoint_url() const
{
  return mEndpointUrl;
}

Array<LocaleId>& SessionDiagnosticsDataType::locale_ids()
{
  return mLocaleIds;
}

const Array<LocaleId>& SessionDiagnosticsDataType::locale_ids() const
{
  return mLocaleIds;
}

Duration& SessionDiagnosticsDataType::actual_session_timeout()
{
  return mActualSessionTimeout;
}

const Duration& SessionDiagnosticsDataType::actual_session_timeout() const
{
  return mActualSessionTimeout;
}

uint32_t& SessionDiagnosticsDataType::max_response_message_size()
{
  return mMaxResponseMessageSize;
}

const uint32_t& SessionDiagnosticsDataType::max_response_message_size() const
{
  return mMaxResponseMessageSize;
}

UtcTime& SessionDiagnosticsDataType::client_connection_time()
{
  return mClientConnectionTime;
}

const UtcTime& SessionDiagnosticsDataType::client_connection_time() const
{
  return mClientConnectionTime;
}

UtcTime& SessionDiagnosticsDataType::client_last_contact_time()
{
  return mClientLastContactTime;
}

const UtcTime& SessionDiagnosticsDataType::client_last_contact_time() const
{
  return mClientLastContactTime;
}

uint32_t& SessionDiagnosticsDataType::current_subscriptions_count()
{
  return mCurrentSubscriptionsCount;
}

const uint32_t& SessionDiagnosticsDataType::current_subscriptions_count() const
{
  return mCurrentSubscriptionsCount;
}

uint32_t& SessionDiagnosticsDataType::current_monitored_items_count()
{
  return mCurrentMonitoredItemsCount;
}

const uint32_t& SessionDiagnosticsDataType::current_monitored_items_count() const
{
  return mCurrentMonitoredItemsCount;
}

uint32_t& SessionDiagnosticsDataType::current_publish_requests_in_queue()
{
  return mCurrentPublishRequestsInQueue;
}

const uint32_t& SessionDiagnosticsDataType::current_publish_requests_in_queue() const
{
  return mCurrentPublishRequestsInQueue;
}

ServiceCounterDataType& SessionDiagnosticsDataType::total_request_count()
{
  return mTotalRequestCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::total_request_count() const
{
  return mTotalRequestCount;
}

uint32_t& SessionDiagnosticsDataType::unauthorized_request_count()
{
  return mUnauthorizedRequestCount;
}

const uint32_t& SessionDiagnosticsDataType::unauthorized_request_count() const
{
  return mUnauthorizedRequestCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::read_count()
{
  return mReadCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::read_count() const
{
  return mReadCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::history_read_count()
{
  return mHistoryReadCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::history_read_count() const
{
  return mHistoryReadCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::write_count()
{
  return mWriteCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::write_count() const
{
  return mWriteCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::history_update_count()
{
  return mHistoryUpdateCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::history_update_count() const
{
  return mHistoryUpdateCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::call_count()
{
  return mCallCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::call_count() const
{
  return mCallCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::create_monitored_items_count()
{
  return mCreateMonitoredItemsCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::create_monitored_items_count() const
{
  return mCreateMonitoredItemsCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::modify_monitored_items_count()
{
  return mModifyMonitoredItemsCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::modify_monitored_items_count() const
{
  return mModifyMonitoredItemsCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::set_monitoring_mode_count()
{
  return mSetMonitoringModeCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::set_monitoring_mode_count() const
{
  return mSetMonitoringModeCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::set_triggering_count()
{
  return mSetTriggeringCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::set_triggering_count() const
{
  return mSetTriggeringCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::delete_monitored_items_count()
{
  return mDeleteMonitoredItemsCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::delete_monitored_items_count() const
{
  return mDeleteMonitoredItemsCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::create_subscription_count()
{
  return mCreateSubscriptionCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::create_subscription_count() const
{
  return mCreateSubscriptionCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::modify_subscription_count()
{
  return mModifySubscriptionCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::modify_subscription_count() const
{
  return mModifySubscriptionCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::set_publishing_mode_count()
{
  return mSetPublishingModeCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::set_publishing_mode_count() const
{
  return mSetPublishingModeCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::publish_count()
{
  return mPublishCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::publish_count() const
{
  return mPublishCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::republish_count()
{
  return mRepublishCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::republish_count() const
{
  return mRepublishCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::transfer_subscriptions_count()
{
  return mTransferSubscriptionsCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::transfer_subscriptions_count() const
{
  return mTransferSubscriptionsCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::delete_subscriptions_count()
{
  return mDeleteSubscriptionsCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::delete_subscriptions_count() const
{
  return mDeleteSubscriptionsCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::add_nodes_count()
{
  return mAddNodesCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::add_nodes_count() const
{
  return mAddNodesCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::add_references_count()
{
  return mAddReferencesCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::add_references_count() const
{
  return mAddReferencesCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::delete_nodes_count()
{
  return mDeleteNodesCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::delete_nodes_count() const
{
  return mDeleteNodesCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::delete_references_count()
{
  return mDeleteReferencesCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::delete_references_count() const
{
  return mDeleteReferencesCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::browse_count()
{
  return mBrowseCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::browse_count() const
{
  return mBrowseCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::browse_next_count()
{
  return mBrowseNextCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::browse_next_count() const
{
  return mBrowseNextCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::translate_browse_paths_to_node_ids_count()
{
  return mTranslateBrowsePathsToNodeIdsCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::translate_browse_paths_to_node_ids_count() const
{
  return mTranslateBrowsePathsToNodeIdsCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::query_first_count()
{
  return mQueryFirstCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::query_first_count() const
{
  return mQueryFirstCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::query_next_count()
{
  return mQueryNextCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::query_next_count() const
{
  return mQueryNextCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::register_nodes_count()
{
  return mRegisterNodesCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::register_nodes_count() const
{
  return mRegisterNodesCount;
}

ServiceCounterDataType& SessionDiagnosticsDataType::unregister_nodes_count()
{
  return mUnregisterNodesCount;
}

const ServiceCounterDataType& SessionDiagnosticsDataType::unregister_nodes_count() const
{
  return mUnregisterNodesCount;
}

BuiltInTypeId SessionDiagnosticsDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::EUInformation
{
namespace
{
void encode(StackDepth limit, const ua::EUInformation& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.namespace_uri());
  encoder.encode(limit, value.unit_id());
  encoder.encode(limit, value.display_name());
  encoder.encode(limit, value.description());
}

void encode(StackDepth limit, const ua::EUInformation& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "NamespaceUri", value.namespace_uri());
  encoder.encode(limit, "UnitId", value.unit_id());
  encoder.encode(limit, "DisplayName", value.display_name());
  encoder.encode(limit, "Description", value.description());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::EUInformation& value)
{
  decoder.decode(limit, value.namespace_uri());
  decoder.decode(limit, value.unit_id());
  decoder.decode(limit, value.display_name());
  decoder.decode(limit, value.description());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::EUInformation& value)
{
  decoder.decode(limit, "NamespaceUri", true, value.namespace_uri());
  decoder.decode(limit, "UnitId", true, value.unit_id());
  decoder.decode(limit, "DisplayName", true, value.display_name());
  decoder.decode(limit, "Description", true, value.description());
}
}  // namespace
}  // namespace detail::EUInformation

namespace detail::EUInformation
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::EUInformation::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::EUInformation::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::EUInformation

namespace detail::EUInformation
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::EUInformation>();
}
}  // namespace
}  // namespace detail::EUInformation

bool EUInformation::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId EUInformation::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId EUInformation::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String EUInformation::type_name() const
{
  return typeName;
}

void EUInformation::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EUInformation::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EUInformation::encode(limit, *this, *xml);
  }
}

void EUInformation::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EUInformation::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EUInformation::encode_id(limit, ns, *xml);
  }
}

void EUInformation::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::EUInformation::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::EUInformation::decode(limit, *xml, *this);
  }
}

void EUInformation::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  mDisplayName = mDisplayName.resolve(locales);
  mDescription = mDescription.resolve(locales);
}

unique_ptr<Structure> EUInformation::clone() const
{
  return make_unique<EUInformation>(*this);
}

void EUInformation::append_fields(std::string& output, int indent) const
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
    output += pad + "unit_id=" + ua::to_string(unit_id());
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
  output += "unit_id=" + ua::to_string(unit_id());
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
}

std::string EUInformation::to_string(int indent) const
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

void EUInformation::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::EUInformation::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::EUInformation::create);
  }
}

String& EUInformation::namespace_uri()
{
  return mNamespaceUri;
}

const String& EUInformation::namespace_uri() const
{
  return mNamespaceUri;
}

int32_t& EUInformation::unit_id()
{
  return mUnitId;
}

const int32_t& EUInformation::unit_id() const
{
  return mUnitId;
}

LocalizedText& EUInformation::display_name()
{
  return mDisplayName;
}

const LocalizedText& EUInformation::display_name() const
{
  return mDisplayName;
}

LocalizedText& EUInformation::description()
{
  return mDescription;
}

const LocalizedText& EUInformation::description() const
{
  return mDescription;
}

BuiltInTypeId EUInformation::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ReferenceNode
{
namespace
{
void encode(StackDepth limit, const ua::ReferenceNode& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.reference_type_id());
  encoder.encode(limit, value.is_inverse());
  encoder.encode(limit, value.target_id());
}

void encode(StackDepth limit, const ua::ReferenceNode& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ReferenceTypeId", value.reference_type_id());
  encoder.encode(limit, "IsInverse", value.is_inverse());
  encoder.encode(limit, "TargetId", value.target_id());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ReferenceNode& value)
{
  decoder.decode(limit, value.reference_type_id());
  decoder.decode(limit, value.is_inverse());
  decoder.decode(limit, value.target_id());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ReferenceNode& value)
{
  decoder.decode(limit, "ReferenceTypeId", true, value.reference_type_id());
  decoder.decode(limit, "IsInverse", true, value.is_inverse());
  decoder.decode(limit, "TargetId", true, value.target_id());
}
}  // namespace
}  // namespace detail::ReferenceNode

namespace detail::ReferenceNode
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ReferenceNode::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ReferenceNode::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ReferenceNode

namespace detail::ReferenceNode
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ReferenceNode>();
}
}  // namespace
}  // namespace detail::ReferenceNode

bool ReferenceNode::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ReferenceNode::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ReferenceNode::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ReferenceNode::type_name() const
{
  return typeName;
}

void ReferenceNode::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReferenceNode::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReferenceNode::encode(limit, *this, *xml);
  }
}

void ReferenceNode::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReferenceNode::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReferenceNode::encode_id(limit, ns, *xml);
  }
}

void ReferenceNode::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ReferenceNode::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ReferenceNode::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ReferenceNode::clone() const
{
  return make_unique<ReferenceNode>(*this);
}

void ReferenceNode::append_fields(std::string& output, int indent) const
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
    output += pad + "is_inverse=" + ua::to_string(is_inverse());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "target_id=" + ua::to_string(target_id());
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
  output += "is_inverse=" + ua::to_string(is_inverse());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "target_id=" + ua::to_string(target_id());
}

std::string ReferenceNode::to_string(int indent) const
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

void ReferenceNode::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ReferenceNode::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ReferenceNode::create);
  }
}

NodeId& ReferenceNode::reference_type_id()
{
  return mReferenceTypeId;
}

const NodeId& ReferenceNode::reference_type_id() const
{
  return mReferenceTypeId;
}

bool& ReferenceNode::is_inverse()
{
  return mIsInverse;
}

const bool& ReferenceNode::is_inverse() const
{
  return mIsInverse;
}

ExpandedNodeId& ReferenceNode::target_id()
{
  return mTargetId;
}

const ExpandedNodeId& ReferenceNode::target_id() const
{
  return mTargetId;
}

BuiltInTypeId ReferenceNode::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::FindServersOnNetworkRequest
{
namespace
{
void encode(StackDepth limit, const ua::FindServersOnNetworkRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.starting_record_id());
  encoder.encode(limit, value.max_records_to_return());
  encoder.encode(limit, value.server_capability_filter());
}

void encode(StackDepth limit, const ua::FindServersOnNetworkRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "StartingRecordId", value.starting_record_id());
  encoder.encode(limit, "MaxRecordsToReturn", value.max_records_to_return());
  encoder.encode(limit, "ServerCapabilityFilter", value.server_capability_filter());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::FindServersOnNetworkRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.starting_record_id());
  decoder.decode(limit, value.max_records_to_return());
  decoder.decode(limit, value.server_capability_filter());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::FindServersOnNetworkRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "StartingRecordId", true, value.starting_record_id());
  decoder.decode(limit, "MaxRecordsToReturn", true, value.max_records_to_return());
  decoder.decode(limit, "ServerCapabilityFilter", true, value.server_capability_filter());
}
}  // namespace
}  // namespace detail::FindServersOnNetworkRequest

namespace detail::FindServersOnNetworkRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::FindServersOnNetworkRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::FindServersOnNetworkRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::FindServersOnNetworkRequest

namespace detail::FindServersOnNetworkRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::FindServersOnNetworkRequest>();
}
}  // namespace
}  // namespace detail::FindServersOnNetworkRequest

bool FindServersOnNetworkRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId FindServersOnNetworkRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId FindServersOnNetworkRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String FindServersOnNetworkRequest::type_name() const
{
  return typeName;
}

void FindServersOnNetworkRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::FindServersOnNetworkRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::FindServersOnNetworkRequest::encode(limit, *this, *xml);
  }
}

void FindServersOnNetworkRequest::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::FindServersOnNetworkRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::FindServersOnNetworkRequest::encode_id(limit, ns, *xml);
  }
}

void FindServersOnNetworkRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::FindServersOnNetworkRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::FindServersOnNetworkRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> FindServersOnNetworkRequest::clone() const
{
  return make_unique<FindServersOnNetworkRequest>(*this);
}

void FindServersOnNetworkRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "starting_record_id=" + ua::to_string(starting_record_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "max_records_to_return=" + ua::to_string(max_records_to_return());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "server_capability_filter=" + ua::to_string(server_capability_filter());
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
  output += "starting_record_id=" + ua::to_string(starting_record_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "max_records_to_return=" + ua::to_string(max_records_to_return());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "server_capability_filter=" + ua::to_string(server_capability_filter());
}

std::string FindServersOnNetworkRequest::to_string(int indent) const
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

void FindServersOnNetworkRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::FindServersOnNetworkRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::FindServersOnNetworkRequest::create);
  }
}

RequestHeader& FindServersOnNetworkRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& FindServersOnNetworkRequest::request_header() const
{
  return mRequestHeader;
}

Counter& FindServersOnNetworkRequest::starting_record_id()
{
  return mStartingRecordId;
}

const Counter& FindServersOnNetworkRequest::starting_record_id() const
{
  return mStartingRecordId;
}

uint32_t& FindServersOnNetworkRequest::max_records_to_return()
{
  return mMaxRecordsToReturn;
}

const uint32_t& FindServersOnNetworkRequest::max_records_to_return() const
{
  return mMaxRecordsToReturn;
}

Array<String>& FindServersOnNetworkRequest::server_capability_filter()
{
  return mServerCapabilityFilter;
}

const Array<String>& FindServersOnNetworkRequest::server_capability_filter() const
{
  return mServerCapabilityFilter;
}

BuiltInTypeId FindServersOnNetworkRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ChannelSecurityToken
{
namespace
{
void encode(StackDepth limit, const ua::ChannelSecurityToken& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.channel_id());
  encoder.encode(limit, value.token_id());
  encoder.encode(limit, value.created_at());
  encoder.encode(limit, value.revised_lifetime());
}

void encode(StackDepth limit, const ua::ChannelSecurityToken& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ChannelId", value.channel_id());
  encoder.encode(limit, "TokenId", value.token_id());
  encoder.encode(limit, "CreatedAt", value.created_at());
  encoder.encode(limit, "RevisedLifetime", value.revised_lifetime());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ChannelSecurityToken& value)
{
  decoder.decode(limit, value.channel_id());
  decoder.decode(limit, value.token_id());
  decoder.decode(limit, value.created_at());
  decoder.decode(limit, value.revised_lifetime());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ChannelSecurityToken& value)
{
  decoder.decode(limit, "ChannelId", true, value.channel_id());
  decoder.decode(limit, "TokenId", true, value.token_id());
  decoder.decode(limit, "CreatedAt", true, value.created_at());
  decoder.decode(limit, "RevisedLifetime", true, value.revised_lifetime());
}
}  // namespace
}  // namespace detail::ChannelSecurityToken

namespace detail::ChannelSecurityToken
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ChannelSecurityToken::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ChannelSecurityToken::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ChannelSecurityToken

namespace detail::ChannelSecurityToken
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ChannelSecurityToken>();
}
}  // namespace
}  // namespace detail::ChannelSecurityToken

bool ChannelSecurityToken::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ChannelSecurityToken::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ChannelSecurityToken::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ChannelSecurityToken::type_name() const
{
  return typeName;
}

void ChannelSecurityToken::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ChannelSecurityToken::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ChannelSecurityToken::encode(limit, *this, *xml);
  }
}

void ChannelSecurityToken::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ChannelSecurityToken::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ChannelSecurityToken::encode_id(limit, ns, *xml);
  }
}

void ChannelSecurityToken::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ChannelSecurityToken::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ChannelSecurityToken::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ChannelSecurityToken::clone() const
{
  return make_unique<ChannelSecurityToken>(*this);
}

void ChannelSecurityToken::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "channel_id=" + ua::to_string(channel_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "token_id=" + ua::to_string(token_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "created_at=" + ua::to_string(created_at());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "revised_lifetime=" + ua::to_string(revised_lifetime());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "channel_id=" + ua::to_string(channel_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "token_id=" + ua::to_string(token_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "created_at=" + ua::to_string(created_at());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "revised_lifetime=" + ua::to_string(revised_lifetime());
}

std::string ChannelSecurityToken::to_string(int indent) const
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

void ChannelSecurityToken::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ChannelSecurityToken::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ChannelSecurityToken::create);
  }
}

uint32_t& ChannelSecurityToken::channel_id()
{
  return mChannelId;
}

const uint32_t& ChannelSecurityToken::channel_id() const
{
  return mChannelId;
}

uint32_t& ChannelSecurityToken::token_id()
{
  return mTokenId;
}

const uint32_t& ChannelSecurityToken::token_id() const
{
  return mTokenId;
}

UtcTime& ChannelSecurityToken::created_at()
{
  return mCreatedAt;
}

const UtcTime& ChannelSecurityToken::created_at() const
{
  return mCreatedAt;
}

uint32_t& ChannelSecurityToken::revised_lifetime()
{
  return mRevisedLifetime;
}

const uint32_t& ChannelSecurityToken::revised_lifetime() const
{
  return mRevisedLifetime;
}

BuiltInTypeId ChannelSecurityToken::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ActivateSessionRequest
{
namespace
{
void encode(StackDepth limit, const ua::ActivateSessionRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.client_signature());
  encoder.encode(limit, value.client_software_certificates());
  encoder.encode(limit, value.locale_ids());
  encoder.encode(limit, value.user_identity_token().get());
  encoder.encode(limit, value.user_token_signature());
}

void encode(StackDepth limit, const ua::ActivateSessionRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "ClientSignature", value.client_signature());
  encoder.encode(limit, "ClientSoftwareCertificates", value.client_software_certificates());
  encoder.encode(limit, "LocaleIds", value.locale_ids());
  encoder.encode(limit, "UserIdentityToken", value.user_identity_token().get());
  encoder.encode(limit, "UserTokenSignature", value.user_token_signature());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ActivateSessionRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.client_signature());
  decoder.decode(limit, value.client_software_certificates());
  decoder.decode(limit, value.locale_ids());
  decoder.decode(limit, value.user_identity_token().inner_unique_ptr());
  decoder.decode(limit, value.user_token_signature());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ActivateSessionRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "ClientSignature", true, value.client_signature());
  decoder.decode(limit, "ClientSoftwareCertificates", true, value.client_software_certificates());
  decoder.decode(limit, "LocaleIds", true, value.locale_ids());
  decoder.decode(limit, "UserIdentityToken", true, value.user_identity_token().inner_unique_ptr());
  decoder.decode(limit, "UserTokenSignature", true, value.user_token_signature());
}
}  // namespace
}  // namespace detail::ActivateSessionRequest

namespace detail::ActivateSessionRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ActivateSessionRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ActivateSessionRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ActivateSessionRequest

namespace detail::ActivateSessionRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ActivateSessionRequest>();
}
}  // namespace
}  // namespace detail::ActivateSessionRequest

bool ActivateSessionRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ActivateSessionRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ActivateSessionRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ActivateSessionRequest::type_name() const
{
  return typeName;
}

void ActivateSessionRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ActivateSessionRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ActivateSessionRequest::encode(limit, *this, *xml);
  }
}

void ActivateSessionRequest::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ActivateSessionRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ActivateSessionRequest::encode_id(limit, ns, *xml);
  }
}

void ActivateSessionRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ActivateSessionRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ActivateSessionRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ActivateSessionRequest::clone() const
{
  return make_unique<ActivateSessionRequest>(*this);
}

void ActivateSessionRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "client_signature=" + ua::to_string(client_signature());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "client_software_certificates=" + ua::to_string(client_software_certificates());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "locale_ids=" + ua::to_string(locale_ids());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "user_identity_token=" +
              (user_identity_token() ? user_identity_token()->to_string(indent) : "null");
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "user_token_signature=" + ua::to_string(user_token_signature());
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
  output += "client_signature=" + ua::to_string(client_signature());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "client_software_certificates=" + ua::to_string(client_software_certificates());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "locale_ids=" + ua::to_string(locale_ids());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "user_identity_token=" + (user_identity_token() ? user_identity_token()->to_string(0) : "null");
  if (!output.empty())
  {
    output += ", ";
  }
  output += "user_token_signature=" + ua::to_string(user_token_signature());
}

std::string ActivateSessionRequest::to_string(int indent) const
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

void ActivateSessionRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ActivateSessionRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ActivateSessionRequest::create);
  }
}

RequestHeader& ActivateSessionRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& ActivateSessionRequest::request_header() const
{
  return mRequestHeader;
}

SignatureData& ActivateSessionRequest::client_signature()
{
  return mClientSignature;
}

const SignatureData& ActivateSessionRequest::client_signature() const
{
  return mClientSignature;
}

Array<SignedSoftwareCertificate>& ActivateSessionRequest::client_software_certificates()
{
  return mClientSoftwareCertificates;
}

const Array<SignedSoftwareCertificate>& ActivateSessionRequest::client_software_certificates() const
{
  return mClientSoftwareCertificates;
}

Array<LocaleId>& ActivateSessionRequest::locale_ids()
{
  return mLocaleIds;
}

const Array<LocaleId>& ActivateSessionRequest::locale_ids() const
{
  return mLocaleIds;
}

RefStructure<Structure>& ActivateSessionRequest::user_identity_token()
{
  return mUserIdentityToken;
}

const RefStructure<Structure>& ActivateSessionRequest::user_identity_token() const
{
  return mUserIdentityToken;
}

SignatureData& ActivateSessionRequest::user_token_signature()
{
  return mUserTokenSignature;
}

const SignatureData& ActivateSessionRequest::user_token_signature() const
{
  return mUserTokenSignature;
}

BuiltInTypeId ActivateSessionRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::VariableAttributes
{
namespace
{
void encode(StackDepth limit, const ua::VariableAttributes& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.value());
  encoder.encode(limit, value.data_type());
  encoder.encode(limit, value.value_rank());
  encoder.encode(limit, value.array_dimensions());
  encoder.encode(limit, value.access_level());
  encoder.encode(limit, value.user_access_level());
  encoder.encode(limit, value.minimum_sampling_interval());
  encoder.encode(limit, value.historizing());
}

void encode(StackDepth limit, const ua::VariableAttributes& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Value", value.value());
  encoder.encode(limit, "DataType", value.data_type());
  encoder.encode(limit, "ValueRank", value.value_rank());
  encoder.encode(limit, "ArrayDimensions", value.array_dimensions());
  encoder.encode(limit, "AccessLevel", value.access_level());
  encoder.encode(limit, "UserAccessLevel", value.user_access_level());
  encoder.encode(limit, "MinimumSamplingInterval", value.minimum_sampling_interval());
  encoder.encode(limit, "Historizing", value.historizing());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::VariableAttributes& value)
{
  decoder.decode(limit, value.value());
  decoder.decode(limit, value.data_type());
  decoder.decode(limit, value.value_rank());
  decoder.decode(limit, value.array_dimensions());
  decoder.decode(limit, value.access_level());
  decoder.decode(limit, value.user_access_level());
  decoder.decode(limit, value.minimum_sampling_interval());
  decoder.decode(limit, value.historizing());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::VariableAttributes& value)
{
  decoder.decode(limit, "Value", true, value.value());
  decoder.decode(limit, "DataType", true, value.data_type());
  decoder.decode(limit, "ValueRank", true, value.value_rank());
  decoder.decode(limit, "ArrayDimensions", true, value.array_dimensions());
  decoder.decode(limit, "AccessLevel", true, value.access_level());
  decoder.decode(limit, "UserAccessLevel", true, value.user_access_level());
  decoder.decode(limit, "MinimumSamplingInterval", true, value.minimum_sampling_interval());
  decoder.decode(limit, "Historizing", true, value.historizing());
}
}  // namespace
}  // namespace detail::VariableAttributes

namespace detail::VariableAttributes
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::VariableAttributes::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::VariableAttributes::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::VariableAttributes

namespace detail::VariableAttributes
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::VariableAttributes>();
}
}  // namespace
}  // namespace detail::VariableAttributes

bool VariableAttributes::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return NodeAttributes::is_of_type(ns, dataTypeId);
}

NodeId VariableAttributes::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId VariableAttributes::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String VariableAttributes::type_name() const
{
  return typeName;
}

void VariableAttributes::encode(StackDepth limit, Encoder& encoder) const
{

  NodeAttributes::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::VariableAttributes::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::VariableAttributes::encode(limit, *this, *xml);
  }
}

void VariableAttributes::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::VariableAttributes::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::VariableAttributes::encode_id(limit, ns, *xml);
  }
}

void VariableAttributes::decode(StackDepth limit, Decoder& decoder)
{

  NodeAttributes::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::VariableAttributes::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::VariableAttributes::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> VariableAttributes::clone() const
{
  return make_unique<VariableAttributes>(*this);
}

void VariableAttributes::append_fields(std::string& output, int indent) const
{
  NodeAttributes::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "value=" + ua::to_string(value());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "data_type=" + ua::to_string(data_type());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "value_rank=" + ua::to_string(value_rank());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "array_dimensions=" + ua::to_string(array_dimensions());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "access_level=" + ua::to_string(access_level());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "user_access_level=" + ua::to_string(user_access_level());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "minimum_sampling_interval=" + ua::to_string(minimum_sampling_interval());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "historizing=" + ua::to_string(historizing());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "value=" + ua::to_string(value());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "data_type=" + ua::to_string(data_type());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "value_rank=" + ua::to_string(value_rank());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "array_dimensions=" + ua::to_string(array_dimensions());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "access_level=" + ua::to_string(access_level());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "user_access_level=" + ua::to_string(user_access_level());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "minimum_sampling_interval=" + ua::to_string(minimum_sampling_interval());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "historizing=" + ua::to_string(historizing());
}

std::string VariableAttributes::to_string(int indent) const
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

void VariableAttributes::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::VariableAttributes::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::VariableAttributes::create);
  }
}

Variant& VariableAttributes::value()
{
  return mValue;
}

const Variant& VariableAttributes::value() const
{
  return mValue;
}

NodeId& VariableAttributes::data_type()
{
  return mDataType;
}

const NodeId& VariableAttributes::data_type() const
{
  return mDataType;
}

int32_t& VariableAttributes::value_rank()
{
  return mValueRank;
}

const int32_t& VariableAttributes::value_rank() const
{
  return mValueRank;
}

Array<uint32_t>& VariableAttributes::array_dimensions()
{
  return mArrayDimensions;
}

const Array<uint32_t>& VariableAttributes::array_dimensions() const
{
  return mArrayDimensions;
}

uint8_t& VariableAttributes::access_level()
{
  return mAccessLevel;
}

const uint8_t& VariableAttributes::access_level() const
{
  return mAccessLevel;
}

uint8_t& VariableAttributes::user_access_level()
{
  return mUserAccessLevel;
}

const uint8_t& VariableAttributes::user_access_level() const
{
  return mUserAccessLevel;
}

Duration& VariableAttributes::minimum_sampling_interval()
{
  return mMinimumSamplingInterval;
}

const Duration& VariableAttributes::minimum_sampling_interval() const
{
  return mMinimumSamplingInterval;
}

bool& VariableAttributes::historizing()
{
  return mHistorizing;
}

const bool& VariableAttributes::historizing() const
{
  return mHistorizing;
}

BuiltInTypeId VariableAttributes::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::GenericAttributes
{
namespace
{
void encode(StackDepth limit, const ua::GenericAttributes& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.attribute_values());
}

void encode(StackDepth limit, const ua::GenericAttributes& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "AttributeValues", value.attribute_values());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::GenericAttributes& value)
{
  decoder.decode(limit, value.attribute_values());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::GenericAttributes& value)
{
  decoder.decode(limit, "AttributeValues", true, value.attribute_values());
}
}  // namespace
}  // namespace detail::GenericAttributes

namespace detail::GenericAttributes
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::GenericAttributes::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::GenericAttributes::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::GenericAttributes

namespace detail::GenericAttributes
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::GenericAttributes>();
}
}  // namespace
}  // namespace detail::GenericAttributes

bool GenericAttributes::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return NodeAttributes::is_of_type(ns, dataTypeId);
}

NodeId GenericAttributes::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId GenericAttributes::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String GenericAttributes::type_name() const
{
  return typeName;
}

void GenericAttributes::encode(StackDepth limit, Encoder& encoder) const
{

  NodeAttributes::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::GenericAttributes::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::GenericAttributes::encode(limit, *this, *xml);
  }
}

void GenericAttributes::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::GenericAttributes::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::GenericAttributes::encode_id(limit, ns, *xml);
  }
}

void GenericAttributes::decode(StackDepth limit, Decoder& decoder)
{

  NodeAttributes::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::GenericAttributes::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::GenericAttributes::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> GenericAttributes::clone() const
{
  return make_unique<GenericAttributes>(*this);
}

void GenericAttributes::append_fields(std::string& output, int indent) const
{
  NodeAttributes::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "attribute_values=" + ua::to_string(attribute_values());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "attribute_values=" + ua::to_string(attribute_values());
}

std::string GenericAttributes::to_string(int indent) const
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

void GenericAttributes::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::GenericAttributes::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::GenericAttributes::create);
  }
}

Array<GenericAttributeValue>& GenericAttributes::attribute_values()
{
  return mAttributeValues;
}

const Array<GenericAttributeValue>& GenericAttributes::attribute_values() const
{
  return mAttributeValues;
}

BuiltInTypeId GenericAttributes::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::DeleteReferencesRequest
{
namespace
{
void encode(StackDepth limit, const ua::DeleteReferencesRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.references_to_delete());
}

void encode(StackDepth limit, const ua::DeleteReferencesRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "ReferencesToDelete", value.references_to_delete());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::DeleteReferencesRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.references_to_delete());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::DeleteReferencesRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "ReferencesToDelete", true, value.references_to_delete());
}
}  // namespace
}  // namespace detail::DeleteReferencesRequest

namespace detail::DeleteReferencesRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::DeleteReferencesRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::DeleteReferencesRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::DeleteReferencesRequest

namespace detail::DeleteReferencesRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::DeleteReferencesRequest>();
}
}  // namespace
}  // namespace detail::DeleteReferencesRequest

bool DeleteReferencesRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId DeleteReferencesRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId DeleteReferencesRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String DeleteReferencesRequest::type_name() const
{
  return typeName;
}

void DeleteReferencesRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DeleteReferencesRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DeleteReferencesRequest::encode(limit, *this, *xml);
  }
}

void DeleteReferencesRequest::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DeleteReferencesRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DeleteReferencesRequest::encode_id(limit, ns, *xml);
  }
}

void DeleteReferencesRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::DeleteReferencesRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::DeleteReferencesRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> DeleteReferencesRequest::clone() const
{
  return make_unique<DeleteReferencesRequest>(*this);
}

void DeleteReferencesRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "references_to_delete=" + ua::to_string(references_to_delete());
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
  output += "references_to_delete=" + ua::to_string(references_to_delete());
}

std::string DeleteReferencesRequest::to_string(int indent) const
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

void DeleteReferencesRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::DeleteReferencesRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::DeleteReferencesRequest::create);
  }
}

RequestHeader& DeleteReferencesRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& DeleteReferencesRequest::request_header() const
{
  return mRequestHeader;
}

Array<DeleteReferencesItem>& DeleteReferencesRequest::references_to_delete()
{
  return mReferencesToDelete;
}

const Array<DeleteReferencesItem>& DeleteReferencesRequest::references_to_delete() const
{
  return mReferencesToDelete;
}

BuiltInTypeId DeleteReferencesRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::BrowseNextRequest
{
namespace
{
void encode(StackDepth limit, const ua::BrowseNextRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.release_continuation_points());
  encoder.encode(limit, value.continuation_points());
}

void encode(StackDepth limit, const ua::BrowseNextRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "ReleaseContinuationPoints", value.release_continuation_points());
  encoder.encode(limit, "ContinuationPoints", value.continuation_points());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::BrowseNextRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.release_continuation_points());
  decoder.decode(limit, value.continuation_points());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::BrowseNextRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "ReleaseContinuationPoints", true, value.release_continuation_points());
  decoder.decode(limit, "ContinuationPoints", true, value.continuation_points());
}
}  // namespace
}  // namespace detail::BrowseNextRequest

namespace detail::BrowseNextRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::BrowseNextRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::BrowseNextRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::BrowseNextRequest

namespace detail::BrowseNextRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::BrowseNextRequest>();
}
}  // namespace
}  // namespace detail::BrowseNextRequest

bool BrowseNextRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId BrowseNextRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId BrowseNextRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String BrowseNextRequest::type_name() const
{
  return typeName;
}

void BrowseNextRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::BrowseNextRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::BrowseNextRequest::encode(limit, *this, *xml);
  }
}

void BrowseNextRequest::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::BrowseNextRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::BrowseNextRequest::encode_id(limit, ns, *xml);
  }
}

void BrowseNextRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::BrowseNextRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::BrowseNextRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> BrowseNextRequest::clone() const
{
  return make_unique<BrowseNextRequest>(*this);
}

void BrowseNextRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "release_continuation_points=" + ua::to_string(release_continuation_points());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "continuation_points=" + ua::to_string(continuation_points());
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
  output += "release_continuation_points=" + ua::to_string(release_continuation_points());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "continuation_points=" + ua::to_string(continuation_points());
}

std::string BrowseNextRequest::to_string(int indent) const
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

void BrowseNextRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::BrowseNextRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::BrowseNextRequest::create);
  }
}

RequestHeader& BrowseNextRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& BrowseNextRequest::request_header() const
{
  return mRequestHeader;
}

bool& BrowseNextRequest::release_continuation_points()
{
  return mReleaseContinuationPoints;
}

const bool& BrowseNextRequest::release_continuation_points() const
{
  return mReleaseContinuationPoints;
}

Array<ContinuationPoint>& BrowseNextRequest::continuation_points()
{
  return mContinuationPoints;
}

const Array<ContinuationPoint>& BrowseNextRequest::continuation_points() const
{
  return mContinuationPoints;
}

BuiltInTypeId BrowseNextRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::RegisterNodesResponse
{
namespace
{
void encode(StackDepth limit, const ua::RegisterNodesResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.registered_node_ids());
}

void encode(StackDepth limit, const ua::RegisterNodesResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "RegisteredNodeIds", value.registered_node_ids());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::RegisterNodesResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.registered_node_ids());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::RegisterNodesResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "RegisteredNodeIds", true, value.registered_node_ids());
}
}  // namespace
}  // namespace detail::RegisterNodesResponse

namespace detail::RegisterNodesResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::RegisterNodesResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::RegisterNodesResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::RegisterNodesResponse

namespace detail::RegisterNodesResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::RegisterNodesResponse>();
}
}  // namespace
}  // namespace detail::RegisterNodesResponse

bool RegisterNodesResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId RegisterNodesResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId RegisterNodesResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String RegisterNodesResponse::type_name() const
{
  return typeName;
}

void RegisterNodesResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RegisterNodesResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RegisterNodesResponse::encode(limit, *this, *xml);
  }
}

void RegisterNodesResponse::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RegisterNodesResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RegisterNodesResponse::encode_id(limit, ns, *xml);
  }
}

void RegisterNodesResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::RegisterNodesResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::RegisterNodesResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> RegisterNodesResponse::clone() const
{
  return make_unique<RegisterNodesResponse>(*this);
}

void RegisterNodesResponse::append_fields(std::string& output, int indent) const
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
    output += pad + "registered_node_ids=" + ua::to_string(registered_node_ids());
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
  output += "registered_node_ids=" + ua::to_string(registered_node_ids());
}

std::string RegisterNodesResponse::to_string(int indent) const
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

void RegisterNodesResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::RegisterNodesResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::RegisterNodesResponse::create);
  }
}

ResponseHeader& RegisterNodesResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& RegisterNodesResponse::response_header() const
{
  return mResponseHeader;
}

Array<NodeId>& RegisterNodesResponse::registered_node_ids()
{
  return mRegisteredNodeIds;
}

const Array<NodeId>& RegisterNodesResponse::registered_node_ids() const
{
  return mRegisteredNodeIds;
}

BuiltInTypeId RegisterNodesResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ContentFilterResult
{
namespace
{
void encode(StackDepth limit, const ua::ContentFilterResult& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.element_results());
  encoder.encode(limit, value.element_diagnostic_infos());
}

void encode(StackDepth limit, const ua::ContentFilterResult& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ElementResults", value.element_results());
  encoder.encode(limit, "ElementDiagnosticInfos", value.element_diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ContentFilterResult& value)
{
  decoder.decode(limit, value.element_results());
  decoder.decode(limit, value.element_diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ContentFilterResult& value)
{
  decoder.decode(limit, "ElementResults", true, value.element_results());
  decoder.decode(limit, "ElementDiagnosticInfos", true, value.element_diagnostic_infos());
}
}  // namespace
}  // namespace detail::ContentFilterResult

namespace detail::ContentFilterResult
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ContentFilterResult::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ContentFilterResult::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ContentFilterResult

namespace detail::ContentFilterResult
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ContentFilterResult>();
}
}  // namespace
}  // namespace detail::ContentFilterResult

bool ContentFilterResult::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ContentFilterResult::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ContentFilterResult::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ContentFilterResult::type_name() const
{
  return typeName;
}

void ContentFilterResult::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ContentFilterResult::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ContentFilterResult::encode(limit, *this, *xml);
  }
}

void ContentFilterResult::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ContentFilterResult::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ContentFilterResult::encode_id(limit, ns, *xml);
  }
}

void ContentFilterResult::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ContentFilterResult::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ContentFilterResult::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ContentFilterResult::clone() const
{
  return make_unique<ContentFilterResult>(*this);
}

void ContentFilterResult::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "element_results=" + ua::to_string(element_results());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "element_diagnostic_infos=" + ua::to_string(element_diagnostic_infos());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "element_results=" + ua::to_string(element_results());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "element_diagnostic_infos=" + ua::to_string(element_diagnostic_infos());
}

std::string ContentFilterResult::to_string(int indent) const
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

void ContentFilterResult::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ContentFilterResult::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ContentFilterResult::create);
  }
}

Array<ContentFilterElementResult>& ContentFilterResult::element_results()
{
  return mElementResults;
}

const Array<ContentFilterElementResult>& ContentFilterResult::element_results() const
{
  return mElementResults;
}

Array<DiagnosticInfo>& ContentFilterResult::element_diagnostic_infos()
{
  return mElementDiagnosticInfos;
}

const Array<DiagnosticInfo>& ContentFilterResult::element_diagnostic_infos() const
{
  return mElementDiagnosticInfos;
}

BuiltInTypeId ContentFilterResult::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ReadResponse
{
namespace
{
void encode(StackDepth limit, const ua::ReadResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.results());
  encoder.encode(limit, value.diagnostic_infos());
}

void encode(StackDepth limit, const ua::ReadResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "Results", value.results());
  encoder.encode(limit, "DiagnosticInfos", value.diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ReadResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.results());
  decoder.decode(limit, value.diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ReadResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "Results", true, value.results());
  decoder.decode(limit, "DiagnosticInfos", true, value.diagnostic_infos());
}
}  // namespace
}  // namespace detail::ReadResponse

namespace detail::ReadResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ReadResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ReadResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ReadResponse

namespace detail::ReadResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ReadResponse>();
}
}  // namespace
}  // namespace detail::ReadResponse

bool ReadResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ReadResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ReadResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ReadResponse::type_name() const
{
  return typeName;
}

void ReadResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReadResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReadResponse::encode(limit, *this, *xml);
  }
}

void ReadResponse::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReadResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReadResponse::encode_id(limit, ns, *xml);
  }
}

void ReadResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ReadResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ReadResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ReadResponse::clone() const
{
  return make_unique<ReadResponse>(*this);
}

void ReadResponse::append_fields(std::string& output, int indent) const
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

std::string ReadResponse::to_string(int indent) const
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

void ReadResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ReadResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ReadResponse::create);
  }
}

ResponseHeader& ReadResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& ReadResponse::response_header() const
{
  return mResponseHeader;
}

Array<DataValue>& ReadResponse::results()
{
  return mResults;
}

const Array<DataValue>& ReadResponse::results() const
{
  return mResults;
}

Array<DiagnosticInfo>& ReadResponse::diagnostic_infos()
{
  return mDiagnosticInfos;
}

const Array<DiagnosticInfo>& ReadResponse::diagnostic_infos() const
{
  return mDiagnosticInfos;
}

BuiltInTypeId ReadResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ReadRawModifiedDetails
{
namespace
{
void encode(StackDepth limit, const ua::ReadRawModifiedDetails& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.is_read_modified());
  encoder.encode(limit, value.start_time());
  encoder.encode(limit, value.end_time());
  encoder.encode(limit, value.num_values_per_node());
  encoder.encode(limit, value.return_bounds());
}

void encode(StackDepth limit, const ua::ReadRawModifiedDetails& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "IsReadModified", value.is_read_modified());
  encoder.encode(limit, "StartTime", value.start_time());
  encoder.encode(limit, "EndTime", value.end_time());
  encoder.encode(limit, "NumValuesPerNode", value.num_values_per_node());
  encoder.encode(limit, "ReturnBounds", value.return_bounds());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ReadRawModifiedDetails& value)
{
  decoder.decode(limit, value.is_read_modified());
  decoder.decode(limit, value.start_time());
  decoder.decode(limit, value.end_time());
  decoder.decode(limit, value.num_values_per_node());
  decoder.decode(limit, value.return_bounds());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ReadRawModifiedDetails& value)
{
  decoder.decode(limit, "IsReadModified", true, value.is_read_modified());
  decoder.decode(limit, "StartTime", true, value.start_time());
  decoder.decode(limit, "EndTime", true, value.end_time());
  decoder.decode(limit, "NumValuesPerNode", true, value.num_values_per_node());
  decoder.decode(limit, "ReturnBounds", true, value.return_bounds());
}
}  // namespace
}  // namespace detail::ReadRawModifiedDetails

namespace detail::ReadRawModifiedDetails
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ReadRawModifiedDetails::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ReadRawModifiedDetails::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ReadRawModifiedDetails

namespace detail::ReadRawModifiedDetails
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ReadRawModifiedDetails>();
}
}  // namespace
}  // namespace detail::ReadRawModifiedDetails

bool ReadRawModifiedDetails::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return HistoryReadDetails::is_of_type(ns, dataTypeId);
}

NodeId ReadRawModifiedDetails::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ReadRawModifiedDetails::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ReadRawModifiedDetails::type_name() const
{
  return typeName;
}

void ReadRawModifiedDetails::encode(StackDepth limit, Encoder& encoder) const
{

  HistoryReadDetails::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReadRawModifiedDetails::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReadRawModifiedDetails::encode(limit, *this, *xml);
  }
}

void ReadRawModifiedDetails::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReadRawModifiedDetails::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReadRawModifiedDetails::encode_id(limit, ns, *xml);
  }
}

void ReadRawModifiedDetails::decode(StackDepth limit, Decoder& decoder)
{

  HistoryReadDetails::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ReadRawModifiedDetails::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ReadRawModifiedDetails::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ReadRawModifiedDetails::clone() const
{
  return make_unique<ReadRawModifiedDetails>(*this);
}

void ReadRawModifiedDetails::append_fields(std::string& output, int indent) const
{
  HistoryReadDetails::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "is_read_modified=" + ua::to_string(is_read_modified());
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
    output += pad + "num_values_per_node=" + ua::to_string(num_values_per_node());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "return_bounds=" + ua::to_string(return_bounds());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "is_read_modified=" + ua::to_string(is_read_modified());
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
  output += "num_values_per_node=" + ua::to_string(num_values_per_node());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "return_bounds=" + ua::to_string(return_bounds());
}

std::string ReadRawModifiedDetails::to_string(int indent) const
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

void ReadRawModifiedDetails::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ReadRawModifiedDetails::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ReadRawModifiedDetails::create);
  }
}

bool& ReadRawModifiedDetails::is_read_modified()
{
  return mIsReadModified;
}

const bool& ReadRawModifiedDetails::is_read_modified() const
{
  return mIsReadModified;
}

UtcTime& ReadRawModifiedDetails::start_time()
{
  return mStartTime;
}

const UtcTime& ReadRawModifiedDetails::start_time() const
{
  return mStartTime;
}

UtcTime& ReadRawModifiedDetails::end_time()
{
  return mEndTime;
}

const UtcTime& ReadRawModifiedDetails::end_time() const
{
  return mEndTime;
}

Counter& ReadRawModifiedDetails::num_values_per_node()
{
  return mNumValuesPerNode;
}

const Counter& ReadRawModifiedDetails::num_values_per_node() const
{
  return mNumValuesPerNode;
}

bool& ReadRawModifiedDetails::return_bounds()
{
  return mReturnBounds;
}

const bool& ReadRawModifiedDetails::return_bounds() const
{
  return mReturnBounds;
}

BuiltInTypeId ReadRawModifiedDetails::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::WriteValue
{
namespace
{
void encode(StackDepth limit, const ua::WriteValue& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.node_id());
  encoder.encode(limit, value.attribute_id());
  encoder.encode(limit, value.index_range());
  encoder.encode(limit, value.value());
}

void encode(StackDepth limit, const ua::WriteValue& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "NodeId", value.node_id());
  encoder.encode(limit, "AttributeId", value.attribute_id());
  encoder.encode(limit, "IndexRange", value.index_range());
  encoder.encode(limit, "Value", value.value());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::WriteValue& value)
{
  decoder.decode(limit, value.node_id());
  decoder.decode(limit, value.attribute_id());
  decoder.decode(limit, value.index_range());
  decoder.decode(limit, value.value());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::WriteValue& value)
{
  decoder.decode(limit, "NodeId", true, value.node_id());
  decoder.decode(limit, "AttributeId", true, value.attribute_id());
  decoder.decode(limit, "IndexRange", true, value.index_range());
  decoder.decode(limit, "Value", true, value.value());
}
}  // namespace
}  // namespace detail::WriteValue

namespace detail::WriteValue
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::WriteValue::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::WriteValue::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::WriteValue

namespace detail::WriteValue
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::WriteValue>();
}
}  // namespace
}  // namespace detail::WriteValue

bool WriteValue::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId WriteValue::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId WriteValue::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String WriteValue::type_name() const
{
  return typeName;
}

void WriteValue::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::WriteValue::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::WriteValue::encode(limit, *this, *xml);
  }
}

void WriteValue::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::WriteValue::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::WriteValue::encode_id(limit, ns, *xml);
  }
}

void WriteValue::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::WriteValue::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::WriteValue::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> WriteValue::clone() const
{
  return make_unique<WriteValue>(*this);
}

void WriteValue::append_fields(std::string& output, int indent) const
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
    output += pad + "value=" + ua::to_string(value());
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
  output += "value=" + ua::to_string(value());
}

std::string WriteValue::to_string(int indent) const
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

void WriteValue::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::WriteValue::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::WriteValue::create);
  }
}

NodeId& WriteValue::node_id()
{
  return mNodeId;
}

const NodeId& WriteValue::node_id() const
{
  return mNodeId;
}

IntegerId& WriteValue::attribute_id()
{
  return mAttributeId;
}

const IntegerId& WriteValue::attribute_id() const
{
  return mAttributeId;
}

NumericRange& WriteValue::index_range()
{
  return mIndexRange;
}

const NumericRange& WriteValue::index_range() const
{
  return mIndexRange;
}

DataValue& WriteValue::value()
{
  return mValue;
}

const DataValue& WriteValue::value() const
{
  return mValue;
}

BuiltInTypeId WriteValue::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::DeleteAtTimeDetails
{
namespace
{
void encode(StackDepth limit, const ua::DeleteAtTimeDetails& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.node_id());
  encoder.encode(limit, value.req_times());
}

void encode(StackDepth limit, const ua::DeleteAtTimeDetails& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "NodeId", value.node_id());
  encoder.encode(limit, "ReqTimes", value.req_times());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::DeleteAtTimeDetails& value)
{
  decoder.decode(limit, value.node_id());
  decoder.decode(limit, value.req_times());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::DeleteAtTimeDetails& value)
{
  decoder.decode(limit, "NodeId", true, value.node_id());
  decoder.decode(limit, "ReqTimes", true, value.req_times());
}
}  // namespace
}  // namespace detail::DeleteAtTimeDetails

namespace detail::DeleteAtTimeDetails
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::DeleteAtTimeDetails::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::DeleteAtTimeDetails::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::DeleteAtTimeDetails

namespace detail::DeleteAtTimeDetails
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::DeleteAtTimeDetails>();
}
}  // namespace
}  // namespace detail::DeleteAtTimeDetails

bool DeleteAtTimeDetails::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return HistoryUpdateDetails::is_of_type(ns, dataTypeId);
}

NodeId DeleteAtTimeDetails::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId DeleteAtTimeDetails::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String DeleteAtTimeDetails::type_name() const
{
  return typeName;
}

void DeleteAtTimeDetails::encode(StackDepth limit, Encoder& encoder) const
{

  HistoryUpdateDetails::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DeleteAtTimeDetails::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DeleteAtTimeDetails::encode(limit, *this, *xml);
  }
}

void DeleteAtTimeDetails::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DeleteAtTimeDetails::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DeleteAtTimeDetails::encode_id(limit, ns, *xml);
  }
}

void DeleteAtTimeDetails::decode(StackDepth limit, Decoder& decoder)
{

  HistoryUpdateDetails::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::DeleteAtTimeDetails::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::DeleteAtTimeDetails::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> DeleteAtTimeDetails::clone() const
{
  return make_unique<DeleteAtTimeDetails>(*this);
}

void DeleteAtTimeDetails::append_fields(std::string& output, int indent) const
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
    output += pad + "req_times=" + ua::to_string(req_times());
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
  output += "req_times=" + ua::to_string(req_times());
}

std::string DeleteAtTimeDetails::to_string(int indent) const
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

void DeleteAtTimeDetails::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::DeleteAtTimeDetails::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::DeleteAtTimeDetails::create);
  }
}

NodeId& DeleteAtTimeDetails::node_id()
{
  return mNodeId;
}

const NodeId& DeleteAtTimeDetails::node_id() const
{
  return mNodeId;
}

Array<UtcTime>& DeleteAtTimeDetails::req_times()
{
  return mReqTimes;
}

const Array<UtcTime>& DeleteAtTimeDetails::req_times() const
{
  return mReqTimes;
}

BuiltInTypeId DeleteAtTimeDetails::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::CallResponse
{
namespace
{
void encode(StackDepth limit, const ua::CallResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.results());
  encoder.encode(limit, value.diagnostic_infos());
}

void encode(StackDepth limit, const ua::CallResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "Results", value.results());
  encoder.encode(limit, "DiagnosticInfos", value.diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::CallResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.results());
  decoder.decode(limit, value.diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::CallResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "Results", true, value.results());
  decoder.decode(limit, "DiagnosticInfos", true, value.diagnostic_infos());
}
}  // namespace
}  // namespace detail::CallResponse

namespace detail::CallResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::CallResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::CallResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::CallResponse

namespace detail::CallResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::CallResponse>();
}
}  // namespace
}  // namespace detail::CallResponse

bool CallResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId CallResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId CallResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String CallResponse::type_name() const
{
  return typeName;
}

void CallResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CallResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CallResponse::encode(limit, *this, *xml);
  }
}

void CallResponse::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CallResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CallResponse::encode_id(limit, ns, *xml);
  }
}

void CallResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::CallResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::CallResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> CallResponse::clone() const
{
  return make_unique<CallResponse>(*this);
}

void CallResponse::append_fields(std::string& output, int indent) const
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

std::string CallResponse::to_string(int indent) const
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

void CallResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::CallResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::CallResponse::create);
  }
}

ResponseHeader& CallResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& CallResponse::response_header() const
{
  return mResponseHeader;
}

Array<CallMethodResult>& CallResponse::results()
{
  return mResults;
}

const Array<CallMethodResult>& CallResponse::results() const
{
  return mResults;
}

Array<DiagnosticInfo>& CallResponse::diagnostic_infos()
{
  return mDiagnosticInfos;
}

const Array<DiagnosticInfo>& CallResponse::diagnostic_infos() const
{
  return mDiagnosticInfos;
}

BuiltInTypeId CallResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::MonitoredItemCreateResult
{
namespace
{
void encode(StackDepth limit, const ua::MonitoredItemCreateResult& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.status_code());
  encoder.encode(limit, value.monitored_item_id());
  encoder.encode(limit, value.revised_sampling_interval());
  encoder.encode(limit, value.revised_queue_size());
  encoder.encode(limit, value.filter_result().get());
}

void encode(StackDepth limit, const ua::MonitoredItemCreateResult& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "StatusCode", value.status_code());
  encoder.encode(limit, "MonitoredItemId", value.monitored_item_id());
  encoder.encode(limit, "RevisedSamplingInterval", value.revised_sampling_interval());
  encoder.encode(limit, "RevisedQueueSize", value.revised_queue_size());
  encoder.encode(limit, "FilterResult", value.filter_result().get());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::MonitoredItemCreateResult& value)
{
  decoder.decode(limit, value.status_code());
  decoder.decode(limit, value.monitored_item_id());
  decoder.decode(limit, value.revised_sampling_interval());
  decoder.decode(limit, value.revised_queue_size());
  decoder.decode(limit, value.filter_result().inner_unique_ptr());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::MonitoredItemCreateResult& value)
{
  decoder.decode(limit, "StatusCode", true, value.status_code());
  decoder.decode(limit, "MonitoredItemId", true, value.monitored_item_id());
  decoder.decode(limit, "RevisedSamplingInterval", true, value.revised_sampling_interval());
  decoder.decode(limit, "RevisedQueueSize", true, value.revised_queue_size());
  decoder.decode(limit, "FilterResult", true, value.filter_result().inner_unique_ptr());
}
}  // namespace
}  // namespace detail::MonitoredItemCreateResult

namespace detail::MonitoredItemCreateResult
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::MonitoredItemCreateResult::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::MonitoredItemCreateResult::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::MonitoredItemCreateResult

namespace detail::MonitoredItemCreateResult
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::MonitoredItemCreateResult>();
}
}  // namespace
}  // namespace detail::MonitoredItemCreateResult

bool MonitoredItemCreateResult::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId MonitoredItemCreateResult::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId MonitoredItemCreateResult::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String MonitoredItemCreateResult::type_name() const
{
  return typeName;
}

void MonitoredItemCreateResult::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::MonitoredItemCreateResult::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::MonitoredItemCreateResult::encode(limit, *this, *xml);
  }
}

void MonitoredItemCreateResult::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::MonitoredItemCreateResult::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::MonitoredItemCreateResult::encode_id(limit, ns, *xml);
  }
}

void MonitoredItemCreateResult::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::MonitoredItemCreateResult::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::MonitoredItemCreateResult::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> MonitoredItemCreateResult::clone() const
{
  return make_unique<MonitoredItemCreateResult>(*this);
}

void MonitoredItemCreateResult::append_fields(std::string& output, int indent) const
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
    output += pad + "monitored_item_id=" + ua::to_string(monitored_item_id());
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
  output += "monitored_item_id=" + ua::to_string(monitored_item_id());
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

std::string MonitoredItemCreateResult::to_string(int indent) const
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

void MonitoredItemCreateResult::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::MonitoredItemCreateResult::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::MonitoredItemCreateResult::create);
  }
}

StatusCode& MonitoredItemCreateResult::status_code()
{
  return mStatusCode;
}

const StatusCode& MonitoredItemCreateResult::status_code() const
{
  return mStatusCode;
}

IntegerId& MonitoredItemCreateResult::monitored_item_id()
{
  return mMonitoredItemId;
}

const IntegerId& MonitoredItemCreateResult::monitored_item_id() const
{
  return mMonitoredItemId;
}

Duration& MonitoredItemCreateResult::revised_sampling_interval()
{
  return mRevisedSamplingInterval;
}

const Duration& MonitoredItemCreateResult::revised_sampling_interval() const
{
  return mRevisedSamplingInterval;
}

Counter& MonitoredItemCreateResult::revised_queue_size()
{
  return mRevisedQueueSize;
}

const Counter& MonitoredItemCreateResult::revised_queue_size() const
{
  return mRevisedQueueSize;
}

RefStructure<Structure>& MonitoredItemCreateResult::filter_result()
{
  return mFilterResult;
}

const RefStructure<Structure>& MonitoredItemCreateResult::filter_result() const
{
  return mFilterResult;
}

BuiltInTypeId MonitoredItemCreateResult::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::SetMonitoringModeResponse
{
namespace
{
void encode(StackDepth limit, const ua::SetMonitoringModeResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.results());
  encoder.encode(limit, value.diagnostic_infos());
}

void encode(StackDepth limit, const ua::SetMonitoringModeResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "Results", value.results());
  encoder.encode(limit, "DiagnosticInfos", value.diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::SetMonitoringModeResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.results());
  decoder.decode(limit, value.diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::SetMonitoringModeResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "Results", true, value.results());
  decoder.decode(limit, "DiagnosticInfos", true, value.diagnostic_infos());
}
}  // namespace
}  // namespace detail::SetMonitoringModeResponse

namespace detail::SetMonitoringModeResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::SetMonitoringModeResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::SetMonitoringModeResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::SetMonitoringModeResponse

namespace detail::SetMonitoringModeResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::SetMonitoringModeResponse>();
}
}  // namespace
}  // namespace detail::SetMonitoringModeResponse

bool SetMonitoringModeResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId SetMonitoringModeResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId SetMonitoringModeResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String SetMonitoringModeResponse::type_name() const
{
  return typeName;
}

void SetMonitoringModeResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SetMonitoringModeResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SetMonitoringModeResponse::encode(limit, *this, *xml);
  }
}

void SetMonitoringModeResponse::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SetMonitoringModeResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SetMonitoringModeResponse::encode_id(limit, ns, *xml);
  }
}

void SetMonitoringModeResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::SetMonitoringModeResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::SetMonitoringModeResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> SetMonitoringModeResponse::clone() const
{
  return make_unique<SetMonitoringModeResponse>(*this);
}

void SetMonitoringModeResponse::append_fields(std::string& output, int indent) const
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

std::string SetMonitoringModeResponse::to_string(int indent) const
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

void SetMonitoringModeResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::SetMonitoringModeResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::SetMonitoringModeResponse::create);
  }
}

ResponseHeader& SetMonitoringModeResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& SetMonitoringModeResponse::response_header() const
{
  return mResponseHeader;
}

Array<StatusCode>& SetMonitoringModeResponse::results()
{
  return mResults;
}

const Array<StatusCode>& SetMonitoringModeResponse::results() const
{
  return mResults;
}

Array<DiagnosticInfo>& SetMonitoringModeResponse::diagnostic_infos()
{
  return mDiagnosticInfos;
}

const Array<DiagnosticInfo>& SetMonitoringModeResponse::diagnostic_infos() const
{
  return mDiagnosticInfos;
}

BuiltInTypeId SetMonitoringModeResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ModifySubscriptionResponse
{
namespace
{
void encode(StackDepth limit, const ua::ModifySubscriptionResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.revised_publishing_interval());
  encoder.encode(limit, value.revised_lifetime_count());
  encoder.encode(limit, value.revised_max_keep_alive_count());
}

void encode(StackDepth limit, const ua::ModifySubscriptionResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "RevisedPublishingInterval", value.revised_publishing_interval());
  encoder.encode(limit, "RevisedLifetimeCount", value.revised_lifetime_count());
  encoder.encode(limit, "RevisedMaxKeepAliveCount", value.revised_max_keep_alive_count());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ModifySubscriptionResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.revised_publishing_interval());
  decoder.decode(limit, value.revised_lifetime_count());
  decoder.decode(limit, value.revised_max_keep_alive_count());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ModifySubscriptionResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "RevisedPublishingInterval", true, value.revised_publishing_interval());
  decoder.decode(limit, "RevisedLifetimeCount", true, value.revised_lifetime_count());
  decoder.decode(limit, "RevisedMaxKeepAliveCount", true, value.revised_max_keep_alive_count());
}
}  // namespace
}  // namespace detail::ModifySubscriptionResponse

namespace detail::ModifySubscriptionResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ModifySubscriptionResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ModifySubscriptionResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ModifySubscriptionResponse

namespace detail::ModifySubscriptionResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ModifySubscriptionResponse>();
}
}  // namespace
}  // namespace detail::ModifySubscriptionResponse

bool ModifySubscriptionResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ModifySubscriptionResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ModifySubscriptionResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ModifySubscriptionResponse::type_name() const
{
  return typeName;
}

void ModifySubscriptionResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ModifySubscriptionResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ModifySubscriptionResponse::encode(limit, *this, *xml);
  }
}

void ModifySubscriptionResponse::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ModifySubscriptionResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ModifySubscriptionResponse::encode_id(limit, ns, *xml);
  }
}

void ModifySubscriptionResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ModifySubscriptionResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ModifySubscriptionResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ModifySubscriptionResponse::clone() const
{
  return make_unique<ModifySubscriptionResponse>(*this);
}

void ModifySubscriptionResponse::append_fields(std::string& output, int indent) const
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

std::string ModifySubscriptionResponse::to_string(int indent) const
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

void ModifySubscriptionResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::ModifySubscriptionResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ModifySubscriptionResponse::create);
  }
}

ResponseHeader& ModifySubscriptionResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& ModifySubscriptionResponse::response_header() const
{
  return mResponseHeader;
}

Duration& ModifySubscriptionResponse::revised_publishing_interval()
{
  return mRevisedPublishingInterval;
}

const Duration& ModifySubscriptionResponse::revised_publishing_interval() const
{
  return mRevisedPublishingInterval;
}

Counter& ModifySubscriptionResponse::revised_lifetime_count()
{
  return mRevisedLifetimeCount;
}

const Counter& ModifySubscriptionResponse::revised_lifetime_count() const
{
  return mRevisedLifetimeCount;
}

Counter& ModifySubscriptionResponse::revised_max_keep_alive_count()
{
  return mRevisedMaxKeepAliveCount;
}

const Counter& ModifySubscriptionResponse::revised_max_keep_alive_count() const
{
  return mRevisedMaxKeepAliveCount;
}

BuiltInTypeId ModifySubscriptionResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::EventFieldList
{
namespace
{
void encode(StackDepth limit, const ua::EventFieldList& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.client_handle());
  encoder.encode(limit, value.event_fields());
}

void encode(StackDepth limit, const ua::EventFieldList& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ClientHandle", value.client_handle());
  encoder.encode(limit, "EventFields", value.event_fields());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::EventFieldList& value)
{
  decoder.decode(limit, value.client_handle());
  decoder.decode(limit, value.event_fields());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::EventFieldList& value)
{
  decoder.decode(limit, "ClientHandle", true, value.client_handle());
  decoder.decode(limit, "EventFields", true, value.event_fields());
}
}  // namespace
}  // namespace detail::EventFieldList

namespace detail::EventFieldList
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::EventFieldList::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::EventFieldList::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::EventFieldList

namespace detail::EventFieldList
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::EventFieldList>();
}
}  // namespace
}  // namespace detail::EventFieldList

bool EventFieldList::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId EventFieldList::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId EventFieldList::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String EventFieldList::type_name() const
{
  return typeName;
}

void EventFieldList::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EventFieldList::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EventFieldList::encode(limit, *this, *xml);
  }
}

void EventFieldList::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EventFieldList::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EventFieldList::encode_id(limit, ns, *xml);
  }
}

void EventFieldList::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::EventFieldList::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::EventFieldList::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> EventFieldList::clone() const
{
  return make_unique<EventFieldList>(*this);
}

void EventFieldList::append_fields(std::string& output, int indent) const
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
    output += pad + "event_fields=" + ua::to_string(event_fields());
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
  output += "event_fields=" + ua::to_string(event_fields());
}

std::string EventFieldList::to_string(int indent) const
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

void EventFieldList::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::EventFieldList::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::EventFieldList::create);
  }
}

IntegerId& EventFieldList::client_handle()
{
  return mClientHandle;
}

const IntegerId& EventFieldList::client_handle() const
{
  return mClientHandle;
}

Array<Variant>& EventFieldList::event_fields()
{
  return mEventFields;
}

const Array<Variant>& EventFieldList::event_fields() const
{
  return mEventFields;
}

BuiltInTypeId EventFieldList::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::TransferSubscriptionsRequest
{
namespace
{
void encode(StackDepth limit, const ua::TransferSubscriptionsRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.subscription_ids());
  encoder.encode(limit, value.send_initial_values());
}

void encode(StackDepth limit, const ua::TransferSubscriptionsRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "SubscriptionIds", value.subscription_ids());
  encoder.encode(limit, "SendInitialValues", value.send_initial_values());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::TransferSubscriptionsRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.subscription_ids());
  decoder.decode(limit, value.send_initial_values());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::TransferSubscriptionsRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "SubscriptionIds", true, value.subscription_ids());
  decoder.decode(limit, "SendInitialValues", true, value.send_initial_values());
}
}  // namespace
}  // namespace detail::TransferSubscriptionsRequest

namespace detail::TransferSubscriptionsRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::TransferSubscriptionsRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::TransferSubscriptionsRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::TransferSubscriptionsRequest

namespace detail::TransferSubscriptionsRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::TransferSubscriptionsRequest>();
}
}  // namespace
}  // namespace detail::TransferSubscriptionsRequest

bool TransferSubscriptionsRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId TransferSubscriptionsRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId TransferSubscriptionsRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String TransferSubscriptionsRequest::type_name() const
{
  return typeName;
}

void TransferSubscriptionsRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::TransferSubscriptionsRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::TransferSubscriptionsRequest::encode(limit, *this, *xml);
  }
}

void TransferSubscriptionsRequest::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::TransferSubscriptionsRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::TransferSubscriptionsRequest::encode_id(limit, ns, *xml);
  }
}

void TransferSubscriptionsRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::TransferSubscriptionsRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::TransferSubscriptionsRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> TransferSubscriptionsRequest::clone() const
{
  return make_unique<TransferSubscriptionsRequest>(*this);
}

void TransferSubscriptionsRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "subscription_ids=" + ua::to_string(subscription_ids());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "send_initial_values=" + ua::to_string(send_initial_values());
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
  output += "subscription_ids=" + ua::to_string(subscription_ids());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "send_initial_values=" + ua::to_string(send_initial_values());
}

std::string TransferSubscriptionsRequest::to_string(int indent) const
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

void TransferSubscriptionsRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::TransferSubscriptionsRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::TransferSubscriptionsRequest::create);
  }
}

RequestHeader& TransferSubscriptionsRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& TransferSubscriptionsRequest::request_header() const
{
  return mRequestHeader;
}

Array<IntegerId>& TransferSubscriptionsRequest::subscription_ids()
{
  return mSubscriptionIds;
}

const Array<IntegerId>& TransferSubscriptionsRequest::subscription_ids() const
{
  return mSubscriptionIds;
}

bool& TransferSubscriptionsRequest::send_initial_values()
{
  return mSendInitialValues;
}

const bool& TransferSubscriptionsRequest::send_initial_values() const
{
  return mSendInitialValues;
}

BuiltInTypeId TransferSubscriptionsRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

}  // namespace ua
