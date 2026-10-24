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

namespace detail::BitFieldDefinition
{
namespace
{
void encode(StackDepth limit, const ua::BitFieldDefinition& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.name());
  encoder.encode(limit, value.description());
  encoder.encode(limit, value.reserved());
  encoder.encode(limit, value.starting_bit_position());
  encoder.encode(limit, value.ending_bit_position());
}

void encode(StackDepth limit, const ua::BitFieldDefinition& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Name", value.name());
  encoder.encode(limit, "Description", value.description());
  encoder.encode(limit, "Reserved", value.reserved());
  encoder.encode(limit, "StartingBitPosition", value.starting_bit_position());
  encoder.encode(limit, "EndingBitPosition", value.ending_bit_position());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::BitFieldDefinition& value)
{
  decoder.decode(limit, value.name());
  decoder.decode(limit, value.description());
  decoder.decode(limit, value.reserved());
  decoder.decode(limit, value.starting_bit_position());
  decoder.decode(limit, value.ending_bit_position());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::BitFieldDefinition& value)
{
  decoder.decode(limit, "Name", true, value.name());
  decoder.decode(limit, "Description", true, value.description());
  decoder.decode(limit, "Reserved", true, value.reserved());
  decoder.decode(limit, "StartingBitPosition", true, value.starting_bit_position());
  decoder.decode(limit, "EndingBitPosition", true, value.ending_bit_position());
}
}  // namespace
}  // namespace detail::BitFieldDefinition

namespace detail::BitFieldDefinition
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::BitFieldDefinition::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::BitFieldDefinition::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::BitFieldDefinition

namespace detail::BitFieldDefinition
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::BitFieldDefinition>();
}
}  // namespace
}  // namespace detail::BitFieldDefinition

bool BitFieldDefinition::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId BitFieldDefinition::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId BitFieldDefinition::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String BitFieldDefinition::type_name() const
{
  return typeName;
}

void BitFieldDefinition::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::BitFieldDefinition::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::BitFieldDefinition::encode(limit, *this, *xml);
  }
}

void BitFieldDefinition::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::BitFieldDefinition::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::BitFieldDefinition::encode_id(limit, ns, *xml);
  }
}

void BitFieldDefinition::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::BitFieldDefinition::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::BitFieldDefinition::decode(limit, *xml, *this);
  }
}

void BitFieldDefinition::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  mDescription = mDescription.resolve(locales);
}

unique_ptr<Structure> BitFieldDefinition::clone() const
{
  return make_unique<BitFieldDefinition>(*this);
}

void BitFieldDefinition::append_fields(std::string& output, int indent) const
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
    output += pad + "description=" + ua::to_string(description());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "reserved=" + ua::to_string(reserved());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "starting_bit_position=" + ua::to_string(starting_bit_position());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "ending_bit_position=" + ua::to_string(ending_bit_position());
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
  output += "description=" + ua::to_string(description());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "reserved=" + ua::to_string(reserved());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "starting_bit_position=" + ua::to_string(starting_bit_position());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "ending_bit_position=" + ua::to_string(ending_bit_position());
}

std::string BitFieldDefinition::to_string(int indent) const
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

void BitFieldDefinition::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::BitFieldDefinition::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::BitFieldDefinition::create);
  }
}

String& BitFieldDefinition::name()
{
  return mName;
}

const String& BitFieldDefinition::name() const
{
  return mName;
}

LocalizedText& BitFieldDefinition::description()
{
  return mDescription;
}

const LocalizedText& BitFieldDefinition::description() const
{
  return mDescription;
}

bool& BitFieldDefinition::reserved()
{
  return mReserved;
}

const bool& BitFieldDefinition::reserved() const
{
  return mReserved;
}

uint32_t& BitFieldDefinition::starting_bit_position()
{
  return mStartingBitPosition;
}

const uint32_t& BitFieldDefinition::starting_bit_position() const
{
  return mStartingBitPosition;
}

uint32_t& BitFieldDefinition::ending_bit_position()
{
  return mEndingBitPosition;
}

const uint32_t& BitFieldDefinition::ending_bit_position() const
{
  return mEndingBitPosition;
}

BuiltInTypeId BitFieldDefinition::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

bool Frame::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId Frame::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId Frame::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String Frame::type_name() const
{
  return typeName;
}

void Frame::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);
}

void Frame::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  UA_UNUSED(limit);
  UA_UNUSED(ns);
  UA_UNUSED(encoder);
}

void Frame::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);
}

BuiltInTypeId Frame::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::BaseConfigurationDataType
{
namespace
{
void encode(StackDepth limit, const ua::BaseConfigurationDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.configuration_version());
  encoder.encode(limit, value.configuration_properties());
}

void encode(StackDepth limit, const ua::BaseConfigurationDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ConfigurationVersion", value.configuration_version());
  encoder.encode(limit, "ConfigurationProperties", value.configuration_properties());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::BaseConfigurationDataType& value)
{
  decoder.decode(limit, value.configuration_version());
  decoder.decode(limit, value.configuration_properties());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::BaseConfigurationDataType& value)
{
  decoder.decode(limit, "ConfigurationVersion", true, value.configuration_version());
  decoder.decode(limit, "ConfigurationProperties", true, value.configuration_properties());
}
}  // namespace
}  // namespace detail::BaseConfigurationDataType

bool BaseConfigurationDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId BaseConfigurationDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId BaseConfigurationDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String BaseConfigurationDataType::type_name() const
{
  return typeName;
}

void BaseConfigurationDataType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::BaseConfigurationDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::BaseConfigurationDataType::encode(limit, *this, *xml);
  }
}

void BaseConfigurationDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  UA_UNUSED(limit);
  UA_UNUSED(ns);
  UA_UNUSED(encoder);
}

void BaseConfigurationDataType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::BaseConfigurationDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::BaseConfigurationDataType::decode(limit, *xml, *this);
  }
}

void BaseConfigurationDataType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "configuration_version=" + ua::to_string(configuration_version());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "configuration_properties=" + ua::to_string(configuration_properties());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "configuration_version=" + ua::to_string(configuration_version());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "configuration_properties=" + ua::to_string(configuration_properties());
}

VersionTime& BaseConfigurationDataType::configuration_version()
{
  return mConfigurationVersion;
}

const VersionTime& BaseConfigurationDataType::configuration_version() const
{
  return mConfigurationVersion;
}

Array<KeyValuePair>& BaseConfigurationDataType::configuration_properties()
{
  return mConfigurationProperties;
}

const Array<KeyValuePair>& BaseConfigurationDataType::configuration_properties() const
{
  return mConfigurationProperties;
}

BuiltInTypeId BaseConfigurationDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ServerEndpointDataType
{
namespace
{
void encode(StackDepth limit, const ua::ServerEndpointDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.endpoint_urls());
  encoder.encode(limit, value.security_setting_names());
  encoder.encode(limit, value.transport_profile_uri());
  encoder.encode(limit, value.user_token_setting_names());
  encoder.encode(limit, value.reverse_connect_urls());
}

void encode(StackDepth limit, const ua::ServerEndpointDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "EndpointUrls", value.endpoint_urls());
  encoder.encode(limit, "SecuritySettingNames", value.security_setting_names());
  encoder.encode(limit, "TransportProfileUri", value.transport_profile_uri());
  encoder.encode(limit, "UserTokenSettingNames", value.user_token_setting_names());
  encoder.encode(limit, "ReverseConnectUrls", value.reverse_connect_urls());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ServerEndpointDataType& value)
{
  decoder.decode(limit, value.endpoint_urls());
  decoder.decode(limit, value.security_setting_names());
  decoder.decode(limit, value.transport_profile_uri());
  decoder.decode(limit, value.user_token_setting_names());
  decoder.decode(limit, value.reverse_connect_urls());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ServerEndpointDataType& value)
{
  decoder.decode(limit, "EndpointUrls", true, value.endpoint_urls());
  decoder.decode(limit, "SecuritySettingNames", true, value.security_setting_names());
  decoder.decode(limit, "TransportProfileUri", true, value.transport_profile_uri());
  decoder.decode(limit, "UserTokenSettingNames", true, value.user_token_setting_names());
  decoder.decode(limit, "ReverseConnectUrls", true, value.reverse_connect_urls());
}
}  // namespace
}  // namespace detail::ServerEndpointDataType

namespace detail::ServerEndpointDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ServerEndpointDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ServerEndpointDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ServerEndpointDataType

namespace detail::ServerEndpointDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ServerEndpointDataType>();
}
}  // namespace
}  // namespace detail::ServerEndpointDataType

bool ServerEndpointDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return EndpointDataType::is_of_type(ns, dataTypeId);
}

NodeId ServerEndpointDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ServerEndpointDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ServerEndpointDataType::type_name() const
{
  return typeName;
}

void ServerEndpointDataType::encode(StackDepth limit, Encoder& encoder) const
{

  EndpointDataType::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ServerEndpointDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ServerEndpointDataType::encode(limit, *this, *xml);
  }
}

void ServerEndpointDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ServerEndpointDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ServerEndpointDataType::encode_id(limit, ns, *xml);
  }
}

void ServerEndpointDataType::decode(StackDepth limit, Decoder& decoder)
{

  EndpointDataType::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ServerEndpointDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ServerEndpointDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ServerEndpointDataType::clone() const
{
  return make_unique<ServerEndpointDataType>(*this);
}

void ServerEndpointDataType::append_fields(std::string& output, int indent) const
{
  EndpointDataType::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "endpoint_urls=" + ua::to_string(endpoint_urls());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "security_setting_names=" + ua::to_string(security_setting_names());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "transport_profile_uri=" + ua::to_string(transport_profile_uri());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "user_token_setting_names=" + ua::to_string(user_token_setting_names());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "reverse_connect_urls=" + ua::to_string(reverse_connect_urls());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "endpoint_urls=" + ua::to_string(endpoint_urls());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "security_setting_names=" + ua::to_string(security_setting_names());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "transport_profile_uri=" + ua::to_string(transport_profile_uri());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "user_token_setting_names=" + ua::to_string(user_token_setting_names());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "reverse_connect_urls=" + ua::to_string(reverse_connect_urls());
}

std::string ServerEndpointDataType::to_string(int indent) const
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

void ServerEndpointDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ServerEndpointDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ServerEndpointDataType::create);
  }
}

Array<UriString>& ServerEndpointDataType::endpoint_urls()
{
  return mEndpointUrls;
}

const Array<UriString>& ServerEndpointDataType::endpoint_urls() const
{
  return mEndpointUrls;
}

Array<String>& ServerEndpointDataType::security_setting_names()
{
  return mSecuritySettingNames;
}

const Array<String>& ServerEndpointDataType::security_setting_names() const
{
  return mSecuritySettingNames;
}

UriString& ServerEndpointDataType::transport_profile_uri()
{
  return mTransportProfileUri;
}

const UriString& ServerEndpointDataType::transport_profile_uri() const
{
  return mTransportProfileUri;
}

Array<String>& ServerEndpointDataType::user_token_setting_names()
{
  return mUserTokenSettingNames;
}

const Array<String>& ServerEndpointDataType::user_token_setting_names() const
{
  return mUserTokenSettingNames;
}

Array<String>& ServerEndpointDataType::reverse_connect_urls()
{
  return mReverseConnectUrls;
}

const Array<String>& ServerEndpointDataType::reverse_connect_urls() const
{
  return mReverseConnectUrls;
}

BuiltInTypeId ServerEndpointDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::EnumDescription
{
namespace
{
void encode(StackDepth limit, const ua::EnumDescription& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.enum_definition());
  encoder.encode(limit, value.built_in_type());
}

void encode(StackDepth limit, const ua::EnumDescription& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "EnumDefinition", value.enum_definition());
  encoder.encode(limit, "BuiltInType", value.built_in_type());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::EnumDescription& value)
{
  decoder.decode(limit, value.enum_definition());
  decoder.decode(limit, value.built_in_type());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::EnumDescription& value)
{
  decoder.decode(limit, "EnumDefinition", true, value.enum_definition());
  decoder.decode(limit, "BuiltInType", true, value.built_in_type());
}
}  // namespace
}  // namespace detail::EnumDescription

namespace detail::EnumDescription
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::EnumDescription::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::EnumDescription::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::EnumDescription

namespace detail::EnumDescription
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::EnumDescription>();
}
}  // namespace
}  // namespace detail::EnumDescription

bool EnumDescription::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return DataTypeDescription::is_of_type(ns, dataTypeId);
}

NodeId EnumDescription::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId EnumDescription::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String EnumDescription::type_name() const
{
  return typeName;
}

void EnumDescription::encode(StackDepth limit, Encoder& encoder) const
{

  DataTypeDescription::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EnumDescription::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EnumDescription::encode(limit, *this, *xml);
  }
}

void EnumDescription::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EnumDescription::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EnumDescription::encode_id(limit, ns, *xml);
  }
}

void EnumDescription::decode(StackDepth limit, Decoder& decoder)
{

  DataTypeDescription::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::EnumDescription::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::EnumDescription::decode(limit, *xml, *this);
  }
}

void EnumDescription::resolve(span<const LocaleId> locales)
{
  DataTypeDescription::resolve(locales);
  mEnumDefinition.resolve(locales);
}

unique_ptr<Structure> EnumDescription::clone() const
{
  return make_unique<EnumDescription>(*this);
}

void EnumDescription::append_fields(std::string& output, int indent) const
{
  DataTypeDescription::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "enum_definition=" + ua::to_string(enum_definition());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "built_in_type=" + ua::to_string(built_in_type());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "enum_definition=" + ua::to_string(enum_definition());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "built_in_type=" + ua::to_string(built_in_type());
}

std::string EnumDescription::to_string(int indent) const
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

void EnumDescription::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::EnumDescription::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::EnumDescription::create);
  }
}

EnumDefinition& EnumDescription::enum_definition()
{
  return mEnumDefinition;
}

const EnumDefinition& EnumDescription::enum_definition() const
{
  return mEnumDefinition;
}

uint8_t& EnumDescription::built_in_type()
{
  return mBuiltInType;
}

const uint8_t& EnumDescription::built_in_type() const
{
  return mBuiltInType;
}

BuiltInTypeId EnumDescription::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::PriorityMappingEntryType
{
namespace
{
void encode(StackDepth limit, const ua::PriorityMappingEntryType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.mapping_uri());
  encoder.encode(limit, value.priority_label());
  encoder.encode(limit, value.priority_value_pcp());
  encoder.encode(limit, value.priority_value_dscp());
}

void encode(StackDepth limit, const ua::PriorityMappingEntryType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "MappingUri", value.mapping_uri());
  encoder.encode(limit, "PriorityLabel", value.priority_label());
  encoder.encode(limit, "PriorityValue_PCP", value.priority_value_pcp());
  encoder.encode(limit, "PriorityValue_DSCP", value.priority_value_dscp());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::PriorityMappingEntryType& value)
{
  decoder.decode(limit, value.mapping_uri());
  decoder.decode(limit, value.priority_label());
  decoder.decode(limit, value.priority_value_pcp());
  decoder.decode(limit, value.priority_value_dscp());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::PriorityMappingEntryType& value)
{
  decoder.decode(limit, "MappingUri", true, value.mapping_uri());
  decoder.decode(limit, "PriorityLabel", true, value.priority_label());
  decoder.decode(limit, "PriorityValue_PCP", true, value.priority_value_pcp());
  decoder.decode(limit, "PriorityValue_DSCP", true, value.priority_value_dscp());
}
}  // namespace
}  // namespace detail::PriorityMappingEntryType

namespace detail::PriorityMappingEntryType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::PriorityMappingEntryType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::PriorityMappingEntryType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::PriorityMappingEntryType

namespace detail::PriorityMappingEntryType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::PriorityMappingEntryType>();
}
}  // namespace
}  // namespace detail::PriorityMappingEntryType

bool PriorityMappingEntryType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId PriorityMappingEntryType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId PriorityMappingEntryType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String PriorityMappingEntryType::type_name() const
{
  return typeName;
}

void PriorityMappingEntryType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::PriorityMappingEntryType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::PriorityMappingEntryType::encode(limit, *this, *xml);
  }
}

void PriorityMappingEntryType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::PriorityMappingEntryType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::PriorityMappingEntryType::encode_id(limit, ns, *xml);
  }
}

void PriorityMappingEntryType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::PriorityMappingEntryType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::PriorityMappingEntryType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> PriorityMappingEntryType::clone() const
{
  return make_unique<PriorityMappingEntryType>(*this);
}

void PriorityMappingEntryType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "mapping_uri=" + ua::to_string(mapping_uri());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "priority_label=" + ua::to_string(priority_label());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "priority_value_pcp=" + ua::to_string(priority_value_pcp());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "priority_value_dscp=" + ua::to_string(priority_value_dscp());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "mapping_uri=" + ua::to_string(mapping_uri());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "priority_label=" + ua::to_string(priority_label());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "priority_value_pcp=" + ua::to_string(priority_value_pcp());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "priority_value_dscp=" + ua::to_string(priority_value_dscp());
}

std::string PriorityMappingEntryType::to_string(int indent) const
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

void PriorityMappingEntryType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::PriorityMappingEntryType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::PriorityMappingEntryType::create);
  }
}

String& PriorityMappingEntryType::mapping_uri()
{
  return mMappingUri;
}

const String& PriorityMappingEntryType::mapping_uri() const
{
  return mMappingUri;
}

String& PriorityMappingEntryType::priority_label()
{
  return mPriorityLabel;
}

const String& PriorityMappingEntryType::priority_label() const
{
  return mPriorityLabel;
}

uint8_t& PriorityMappingEntryType::priority_value_pcp()
{
  return mPriorityValue_PCP;
}

const uint8_t& PriorityMappingEntryType::priority_value_pcp() const
{
  return mPriorityValue_PCP;
}

uint32_t& PriorityMappingEntryType::priority_value_dscp()
{
  return mPriorityValue_DSCP;
}

const uint32_t& PriorityMappingEntryType::priority_value_dscp() const
{
  return mPriorityValue_DSCP;
}

BuiltInTypeId PriorityMappingEntryType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::SpanContextDataType
{
namespace
{
void encode(StackDepth limit, const ua::SpanContextDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.trace_id());
  encoder.encode(limit, value.span_id());
}

void encode(StackDepth limit, const ua::SpanContextDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "TraceId", value.trace_id());
  encoder.encode(limit, "SpanId", value.span_id());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::SpanContextDataType& value)
{
  decoder.decode(limit, value.trace_id());
  decoder.decode(limit, value.span_id());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::SpanContextDataType& value)
{
  decoder.decode(limit, "TraceId", true, value.trace_id());
  decoder.decode(limit, "SpanId", true, value.span_id());
}
}  // namespace
}  // namespace detail::SpanContextDataType

namespace detail::SpanContextDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::SpanContextDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::SpanContextDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::SpanContextDataType

namespace detail::SpanContextDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::SpanContextDataType>();
}
}  // namespace
}  // namespace detail::SpanContextDataType

bool SpanContextDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId SpanContextDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId SpanContextDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String SpanContextDataType::type_name() const
{
  return typeName;
}

void SpanContextDataType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SpanContextDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SpanContextDataType::encode(limit, *this, *xml);
  }
}

void SpanContextDataType::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SpanContextDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SpanContextDataType::encode_id(limit, ns, *xml);
  }
}

void SpanContextDataType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::SpanContextDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::SpanContextDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> SpanContextDataType::clone() const
{
  return make_unique<SpanContextDataType>(*this);
}

void SpanContextDataType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "trace_id=" + ua::to_string(trace_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "span_id=" + ua::to_string(span_id());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "trace_id=" + ua::to_string(trace_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "span_id=" + ua::to_string(span_id());
}

std::string SpanContextDataType::to_string(int indent) const
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

void SpanContextDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::SpanContextDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::SpanContextDataType::create);
  }
}

Guid& SpanContextDataType::trace_id()
{
  return mTraceId;
}

const Guid& SpanContextDataType::trace_id() const
{
  return mTraceId;
}

uint64_t& SpanContextDataType::span_id()
{
  return mSpanId;
}

const uint64_t& SpanContextDataType::span_id() const
{
  return mSpanId;
}

BuiltInTypeId SpanContextDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::Argument
{
namespace
{
void encode(StackDepth limit, const ua::Argument& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.name());
  encoder.encode(limit, value.data_type());
  encoder.encode(limit, value.value_rank());
  encoder.encode(limit, value.array_dimensions());
  encoder.encode(limit, value.description());
}

void encode(StackDepth limit, const ua::Argument& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Name", value.name());
  encoder.encode(limit, "DataType", value.data_type());
  encoder.encode(limit, "ValueRank", value.value_rank());
  encoder.encode(limit, "ArrayDimensions", value.array_dimensions());
  encoder.encode(limit, "Description", value.description());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::Argument& value)
{
  decoder.decode(limit, value.name());
  decoder.decode(limit, value.data_type());
  decoder.decode(limit, value.value_rank());
  decoder.decode(limit, value.array_dimensions());
  decoder.decode(limit, value.description());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::Argument& value)
{
  decoder.decode(limit, "Name", true, value.name());
  decoder.decode(limit, "DataType", true, value.data_type());
  decoder.decode(limit, "ValueRank", true, value.value_rank());
  decoder.decode(limit, "ArrayDimensions", true, value.array_dimensions());
  decoder.decode(limit, "Description", true, value.description());
}
}  // namespace
}  // namespace detail::Argument

namespace detail::Argument
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::Argument::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::Argument::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::Argument

namespace detail::Argument
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::Argument>();
}
}  // namespace
}  // namespace detail::Argument

bool Argument::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId Argument::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId Argument::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String Argument::type_name() const
{
  return typeName;
}

void Argument::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::Argument::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::Argument::encode(limit, *this, *xml);
  }
}

void Argument::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::Argument::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::Argument::encode_id(limit, ns, *xml);
  }
}

void Argument::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::Argument::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::Argument::decode(limit, *xml, *this);
  }
}

void Argument::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  mDescription = mDescription.resolve(locales);
}

unique_ptr<Structure> Argument::clone() const
{
  return make_unique<Argument>(*this);
}

void Argument::append_fields(std::string& output, int indent) const
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
    output += pad + "description=" + ua::to_string(description());
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
  output += "description=" + ua::to_string(description());
}

std::string Argument::to_string(int indent) const
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

void Argument::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::Argument::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::Argument::create);
  }
}

String& Argument::name()
{
  return mName;
}

const String& Argument::name() const
{
  return mName;
}

NodeId& Argument::data_type()
{
  return mDataType;
}

const NodeId& Argument::data_type() const
{
  return mDataType;
}

int32_t& Argument::value_rank()
{
  return mValueRank;
}

const int32_t& Argument::value_rank() const
{
  return mValueRank;
}

Array<uint32_t>& Argument::array_dimensions()
{
  return mArrayDimensions;
}

const Array<uint32_t>& Argument::array_dimensions() const
{
  return mArrayDimensions;
}

LocalizedText& Argument::description()
{
  return mDescription;
}

const LocalizedText& Argument::description() const
{
  return mDescription;
}

BuiltInTypeId Argument::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::EndpointDescription
{
namespace
{
void encode(StackDepth limit, const ua::EndpointDescription& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.endpoint_url());
  encoder.encode(limit, value.server());
  encoder.encode(limit, value.server_certificate());
  encoder.encode(limit, utils::as_int32(value.security_mode()));
  encoder.encode(limit, value.security_policy_uri());
  encoder.encode(limit, value.user_identity_tokens());
  encoder.encode(limit, value.transport_profile_uri());
  encoder.encode(limit, value.security_level());
}

void encode(StackDepth limit, const ua::EndpointDescription& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "EndpointUrl", value.endpoint_url());
  encoder.encode(limit, "Server", value.server());
  encoder.encode(limit, "ServerCertificate", value.server_certificate());
  encoder.encode(limit, "SecurityMode", utils::as_int32(value.security_mode()));
  encoder.encode(limit, "SecurityPolicyUri", value.security_policy_uri());
  encoder.encode(limit, "UserIdentityTokens", value.user_identity_tokens());
  encoder.encode(limit, "TransportProfileUri", value.transport_profile_uri());
  encoder.encode(limit, "SecurityLevel", value.security_level());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::EndpointDescription& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.endpoint_url());
  decoder.decode(limit, value.server());
  decoder.decode(limit, value.server_certificate());
  decoder.decode(limit, enumVal);
  value.security_mode() = utils::from_underlying<MessageSecurityMode>(enumVal);
  decoder.decode(limit, value.security_policy_uri());
  decoder.decode(limit, value.user_identity_tokens());
  decoder.decode(limit, value.transport_profile_uri());
  decoder.decode(limit, value.security_level());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::EndpointDescription& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "EndpointUrl", true, value.endpoint_url());
  decoder.decode(limit, "Server", true, value.server());
  decoder.decode(limit, "ServerCertificate", true, value.server_certificate());
  decoder.decode(limit, "SecurityMode", true, enumVal);
  value.security_mode() = utils::from_underlying<MessageSecurityMode>(enumVal);
  decoder.decode(limit, "SecurityPolicyUri", true, value.security_policy_uri());
  decoder.decode(limit, "UserIdentityTokens", true, value.user_identity_tokens());
  decoder.decode(limit, "TransportProfileUri", true, value.transport_profile_uri());
  decoder.decode(limit, "SecurityLevel", true, value.security_level());
}
}  // namespace
}  // namespace detail::EndpointDescription

namespace detail::EndpointDescription
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::EndpointDescription::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::EndpointDescription::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::EndpointDescription

namespace detail::EndpointDescription
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::EndpointDescription>();
}
}  // namespace
}  // namespace detail::EndpointDescription

bool EndpointDescription::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId EndpointDescription::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId EndpointDescription::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String EndpointDescription::type_name() const
{
  return typeName;
}

void EndpointDescription::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EndpointDescription::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EndpointDescription::encode(limit, *this, *xml);
  }
}

void EndpointDescription::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EndpointDescription::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EndpointDescription::encode_id(limit, ns, *xml);
  }
}

void EndpointDescription::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::EndpointDescription::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::EndpointDescription::decode(limit, *xml, *this);
  }
}

void EndpointDescription::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  mServer.resolve(locales);
}

unique_ptr<Structure> EndpointDescription::clone() const
{
  return make_unique<EndpointDescription>(*this);
}

void EndpointDescription::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "endpoint_url=" + ua::to_string(endpoint_url());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "server=" + ua::to_string(server());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "server_certificate=" + ua::to_string(server_certificate());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "security_mode=" + ua::to_string(utils::as_int32(security_mode()));
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "security_policy_uri=" + ua::to_string(security_policy_uri());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "user_identity_tokens=" + ua::to_string(user_identity_tokens());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "transport_profile_uri=" + ua::to_string(transport_profile_uri());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "security_level=" + ua::to_string(security_level());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "endpoint_url=" + ua::to_string(endpoint_url());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "server=" + ua::to_string(server());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "server_certificate=" + ua::to_string(server_certificate());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "security_mode=" + ua::to_string(utils::as_int32(security_mode()));
  if (!output.empty())
  {
    output += ", ";
  }
  output += "security_policy_uri=" + ua::to_string(security_policy_uri());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "user_identity_tokens=" + ua::to_string(user_identity_tokens());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "transport_profile_uri=" + ua::to_string(transport_profile_uri());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "security_level=" + ua::to_string(security_level());
}

std::string EndpointDescription::to_string(int indent) const
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

void EndpointDescription::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::EndpointDescription::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::EndpointDescription::create);
  }
}

String& EndpointDescription::endpoint_url()
{
  return mEndpointUrl;
}

const String& EndpointDescription::endpoint_url() const
{
  return mEndpointUrl;
}

ApplicationDescription& EndpointDescription::server()
{
  return mServer;
}

const ApplicationDescription& EndpointDescription::server() const
{
  return mServer;
}

ApplicationInstanceCertificate& EndpointDescription::server_certificate()
{
  return mServerCertificate;
}

const ApplicationInstanceCertificate& EndpointDescription::server_certificate() const
{
  return mServerCertificate;
}

MessageSecurityMode& EndpointDescription::security_mode()
{
  return mSecurityMode;
}

const MessageSecurityMode& EndpointDescription::security_mode() const
{
  return mSecurityMode;
}

String& EndpointDescription::security_policy_uri()
{
  return mSecurityPolicyUri;
}

const String& EndpointDescription::security_policy_uri() const
{
  return mSecurityPolicyUri;
}

Array<UserTokenPolicy>& EndpointDescription::user_identity_tokens()
{
  return mUserIdentityTokens;
}

const Array<UserTokenPolicy>& EndpointDescription::user_identity_tokens() const
{
  return mUserIdentityTokens;
}

String& EndpointDescription::transport_profile_uri()
{
  return mTransportProfileUri;
}

const String& EndpointDescription::transport_profile_uri() const
{
  return mTransportProfileUri;
}

uint8_t& EndpointDescription::security_level()
{
  return mSecurityLevel;
}

const uint8_t& EndpointDescription::security_level() const
{
  return mSecurityLevel;
}

BuiltInTypeId EndpointDescription::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::X509IdentityToken
{
namespace
{
void encode(StackDepth limit, const ua::X509IdentityToken& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.certificate_data());
}

void encode(StackDepth limit, const ua::X509IdentityToken& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "CertificateData", value.certificate_data());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::X509IdentityToken& value)
{
  decoder.decode(limit, value.certificate_data());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::X509IdentityToken& value)
{
  decoder.decode(limit, "CertificateData", true, value.certificate_data());
}
}  // namespace
}  // namespace detail::X509IdentityToken

namespace detail::X509IdentityToken
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::X509IdentityToken::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::X509IdentityToken::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::X509IdentityToken

namespace detail::X509IdentityToken
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::X509IdentityToken>();
}
}  // namespace
}  // namespace detail::X509IdentityToken

bool X509IdentityToken::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return UserIdentityToken::is_of_type(ns, dataTypeId);
}

NodeId X509IdentityToken::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId X509IdentityToken::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String X509IdentityToken::type_name() const
{
  return typeName;
}

void X509IdentityToken::encode(StackDepth limit, Encoder& encoder) const
{

  UserIdentityToken::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::X509IdentityToken::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::X509IdentityToken::encode(limit, *this, *xml);
  }
}

void X509IdentityToken::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::X509IdentityToken::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::X509IdentityToken::encode_id(limit, ns, *xml);
  }
}

void X509IdentityToken::decode(StackDepth limit, Decoder& decoder)
{

  UserIdentityToken::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::X509IdentityToken::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::X509IdentityToken::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> X509IdentityToken::clone() const
{
  return make_unique<X509IdentityToken>(*this);
}

void X509IdentityToken::append_fields(std::string& output, int indent) const
{
  UserIdentityToken::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "certificate_data=" + ua::to_string(certificate_data());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "certificate_data=" + ua::to_string(certificate_data());
}

std::string X509IdentityToken::to_string(int indent) const
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

void X509IdentityToken::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::X509IdentityToken::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::X509IdentityToken::create);
  }
}

ByteString& X509IdentityToken::certificate_data()
{
  return mCertificateData;
}

const ByteString& X509IdentityToken::certificate_data() const
{
  return mCertificateData;
}

BuiltInTypeId X509IdentityToken::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::EndpointConfiguration
{
namespace
{
void encode(StackDepth limit, const ua::EndpointConfiguration& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.operation_timeout());
  encoder.encode(limit, value.use_binary_encoding());
  encoder.encode(limit, value.max_string_length());
  encoder.encode(limit, value.max_byte_string_length());
  encoder.encode(limit, value.max_array_length());
  encoder.encode(limit, value.max_message_size());
  encoder.encode(limit, value.max_buffer_size());
  encoder.encode(limit, value.channel_lifetime());
  encoder.encode(limit, value.security_token_lifetime());
}

void encode(StackDepth limit, const ua::EndpointConfiguration& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "OperationTimeout", value.operation_timeout());
  encoder.encode(limit, "UseBinaryEncoding", value.use_binary_encoding());
  encoder.encode(limit, "MaxStringLength", value.max_string_length());
  encoder.encode(limit, "MaxByteStringLength", value.max_byte_string_length());
  encoder.encode(limit, "MaxArrayLength", value.max_array_length());
  encoder.encode(limit, "MaxMessageSize", value.max_message_size());
  encoder.encode(limit, "MaxBufferSize", value.max_buffer_size());
  encoder.encode(limit, "ChannelLifetime", value.channel_lifetime());
  encoder.encode(limit, "SecurityTokenLifetime", value.security_token_lifetime());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::EndpointConfiguration& value)
{
  decoder.decode(limit, value.operation_timeout());
  decoder.decode(limit, value.use_binary_encoding());
  decoder.decode(limit, value.max_string_length());
  decoder.decode(limit, value.max_byte_string_length());
  decoder.decode(limit, value.max_array_length());
  decoder.decode(limit, value.max_message_size());
  decoder.decode(limit, value.max_buffer_size());
  decoder.decode(limit, value.channel_lifetime());
  decoder.decode(limit, value.security_token_lifetime());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::EndpointConfiguration& value)
{
  decoder.decode(limit, "OperationTimeout", true, value.operation_timeout());
  decoder.decode(limit, "UseBinaryEncoding", true, value.use_binary_encoding());
  decoder.decode(limit, "MaxStringLength", true, value.max_string_length());
  decoder.decode(limit, "MaxByteStringLength", true, value.max_byte_string_length());
  decoder.decode(limit, "MaxArrayLength", true, value.max_array_length());
  decoder.decode(limit, "MaxMessageSize", true, value.max_message_size());
  decoder.decode(limit, "MaxBufferSize", true, value.max_buffer_size());
  decoder.decode(limit, "ChannelLifetime", true, value.channel_lifetime());
  decoder.decode(limit, "SecurityTokenLifetime", true, value.security_token_lifetime());
}
}  // namespace
}  // namespace detail::EndpointConfiguration

namespace detail::EndpointConfiguration
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::EndpointConfiguration::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::EndpointConfiguration::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::EndpointConfiguration

namespace detail::EndpointConfiguration
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::EndpointConfiguration>();
}
}  // namespace
}  // namespace detail::EndpointConfiguration

bool EndpointConfiguration::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId EndpointConfiguration::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId EndpointConfiguration::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String EndpointConfiguration::type_name() const
{
  return typeName;
}

void EndpointConfiguration::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EndpointConfiguration::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EndpointConfiguration::encode(limit, *this, *xml);
  }
}

void EndpointConfiguration::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EndpointConfiguration::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EndpointConfiguration::encode_id(limit, ns, *xml);
  }
}

void EndpointConfiguration::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::EndpointConfiguration::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::EndpointConfiguration::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> EndpointConfiguration::clone() const
{
  return make_unique<EndpointConfiguration>(*this);
}

void EndpointConfiguration::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "operation_timeout=" + ua::to_string(operation_timeout());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "use_binary_encoding=" + ua::to_string(use_binary_encoding());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "max_string_length=" + ua::to_string(max_string_length());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "max_byte_string_length=" + ua::to_string(max_byte_string_length());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "max_array_length=" + ua::to_string(max_array_length());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "max_message_size=" + ua::to_string(max_message_size());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "max_buffer_size=" + ua::to_string(max_buffer_size());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "channel_lifetime=" + ua::to_string(channel_lifetime());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "security_token_lifetime=" + ua::to_string(security_token_lifetime());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "operation_timeout=" + ua::to_string(operation_timeout());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "use_binary_encoding=" + ua::to_string(use_binary_encoding());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "max_string_length=" + ua::to_string(max_string_length());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "max_byte_string_length=" + ua::to_string(max_byte_string_length());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "max_array_length=" + ua::to_string(max_array_length());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "max_message_size=" + ua::to_string(max_message_size());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "max_buffer_size=" + ua::to_string(max_buffer_size());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "channel_lifetime=" + ua::to_string(channel_lifetime());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "security_token_lifetime=" + ua::to_string(security_token_lifetime());
}

std::string EndpointConfiguration::to_string(int indent) const
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

void EndpointConfiguration::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::EndpointConfiguration::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::EndpointConfiguration::create);
  }
}

int32_t& EndpointConfiguration::operation_timeout()
{
  return mOperationTimeout;
}

const int32_t& EndpointConfiguration::operation_timeout() const
{
  return mOperationTimeout;
}

bool& EndpointConfiguration::use_binary_encoding()
{
  return mUseBinaryEncoding;
}

const bool& EndpointConfiguration::use_binary_encoding() const
{
  return mUseBinaryEncoding;
}

int32_t& EndpointConfiguration::max_string_length()
{
  return mMaxStringLength;
}

const int32_t& EndpointConfiguration::max_string_length() const
{
  return mMaxStringLength;
}

int32_t& EndpointConfiguration::max_byte_string_length()
{
  return mMaxByteStringLength;
}

const int32_t& EndpointConfiguration::max_byte_string_length() const
{
  return mMaxByteStringLength;
}

int32_t& EndpointConfiguration::max_array_length()
{
  return mMaxArrayLength;
}

const int32_t& EndpointConfiguration::max_array_length() const
{
  return mMaxArrayLength;
}

int32_t& EndpointConfiguration::max_message_size()
{
  return mMaxMessageSize;
}

const int32_t& EndpointConfiguration::max_message_size() const
{
  return mMaxMessageSize;
}

int32_t& EndpointConfiguration::max_buffer_size()
{
  return mMaxBufferSize;
}

const int32_t& EndpointConfiguration::max_buffer_size() const
{
  return mMaxBufferSize;
}

int32_t& EndpointConfiguration::channel_lifetime()
{
  return mChannelLifetime;
}

const int32_t& EndpointConfiguration::channel_lifetime() const
{
  return mChannelLifetime;
}

int32_t& EndpointConfiguration::security_token_lifetime()
{
  return mSecurityTokenLifetime;
}

const int32_t& EndpointConfiguration::security_token_lifetime() const
{
  return mSecurityTokenLifetime;
}

BuiltInTypeId EndpointConfiguration::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ModificationInfo
{
namespace
{
void encode(StackDepth limit, const ua::ModificationInfo& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.modification_time());
  encoder.encode(limit, utils::as_int32(value.update_type()));
  encoder.encode(limit, value.user_name());
}

void encode(StackDepth limit, const ua::ModificationInfo& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ModificationTime", value.modification_time());
  encoder.encode(limit, "UpdateType", utils::as_int32(value.update_type()));
  encoder.encode(limit, "UserName", value.user_name());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ModificationInfo& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.modification_time());
  decoder.decode(limit, enumVal);
  value.update_type() = utils::from_underlying<HistoryUpdateType>(enumVal);
  decoder.decode(limit, value.user_name());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ModificationInfo& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "ModificationTime", true, value.modification_time());
  decoder.decode(limit, "UpdateType", true, enumVal);
  value.update_type() = utils::from_underlying<HistoryUpdateType>(enumVal);
  decoder.decode(limit, "UserName", true, value.user_name());
}
}  // namespace
}  // namespace detail::ModificationInfo

namespace detail::ModificationInfo
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ModificationInfo::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ModificationInfo::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ModificationInfo

namespace detail::ModificationInfo
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ModificationInfo>();
}
}  // namespace
}  // namespace detail::ModificationInfo

bool ModificationInfo::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ModificationInfo::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ModificationInfo::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ModificationInfo::type_name() const
{
  return typeName;
}

void ModificationInfo::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ModificationInfo::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ModificationInfo::encode(limit, *this, *xml);
  }
}

void ModificationInfo::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ModificationInfo::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ModificationInfo::encode_id(limit, ns, *xml);
  }
}

void ModificationInfo::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ModificationInfo::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ModificationInfo::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ModificationInfo::clone() const
{
  return make_unique<ModificationInfo>(*this);
}

void ModificationInfo::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "modification_time=" + ua::to_string(modification_time());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "update_type=" + ua::to_string(utils::as_int32(update_type()));
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "user_name=" + ua::to_string(user_name());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "modification_time=" + ua::to_string(modification_time());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "update_type=" + ua::to_string(utils::as_int32(update_type()));
  if (!output.empty())
  {
    output += ", ";
  }
  output += "user_name=" + ua::to_string(user_name());
}

std::string ModificationInfo::to_string(int indent) const
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

void ModificationInfo::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ModificationInfo::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ModificationInfo::create);
  }
}

UtcTime& ModificationInfo::modification_time()
{
  return mModificationTime;
}

const UtcTime& ModificationInfo::modification_time() const
{
  return mModificationTime;
}

HistoryUpdateType& ModificationInfo::update_type()
{
  return mUpdateType;
}

const HistoryUpdateType& ModificationInfo::update_type() const
{
  return mUpdateType;
}

String& ModificationInfo::user_name()
{
  return mUserName;
}

const String& ModificationInfo::user_name() const
{
  return mUserName;
}

BuiltInTypeId ModificationInfo::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::RedundantServerDataType
{
namespace
{
void encode(StackDepth limit, const ua::RedundantServerDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.server_id());
  encoder.encode(limit, value.service_level());
  encoder.encode(limit, utils::as_int32(value.server_state()));
}

void encode(StackDepth limit, const ua::RedundantServerDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ServerId", value.server_id());
  encoder.encode(limit, "ServiceLevel", value.service_level());
  encoder.encode(limit, "ServerState", utils::as_int32(value.server_state()));
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::RedundantServerDataType& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.server_id());
  decoder.decode(limit, value.service_level());
  decoder.decode(limit, enumVal);
  value.server_state() = utils::from_underlying<ServerState>(enumVal);
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::RedundantServerDataType& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "ServerId", true, value.server_id());
  decoder.decode(limit, "ServiceLevel", true, value.service_level());
  decoder.decode(limit, "ServerState", true, enumVal);
  value.server_state() = utils::from_underlying<ServerState>(enumVal);
}
}  // namespace
}  // namespace detail::RedundantServerDataType

namespace detail::RedundantServerDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::RedundantServerDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::RedundantServerDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::RedundantServerDataType

namespace detail::RedundantServerDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::RedundantServerDataType>();
}
}  // namespace
}  // namespace detail::RedundantServerDataType

bool RedundantServerDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId RedundantServerDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId RedundantServerDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String RedundantServerDataType::type_name() const
{
  return typeName;
}

void RedundantServerDataType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RedundantServerDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RedundantServerDataType::encode(limit, *this, *xml);
  }
}

void RedundantServerDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RedundantServerDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RedundantServerDataType::encode_id(limit, ns, *xml);
  }
}

void RedundantServerDataType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::RedundantServerDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::RedundantServerDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> RedundantServerDataType::clone() const
{
  return make_unique<RedundantServerDataType>(*this);
}

void RedundantServerDataType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "server_id=" + ua::to_string(server_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "service_level=" + ua::to_string(service_level());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "server_state=" + ua::to_string(utils::as_int32(server_state()));
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "server_id=" + ua::to_string(server_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "service_level=" + ua::to_string(service_level());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "server_state=" + ua::to_string(utils::as_int32(server_state()));
}

std::string RedundantServerDataType::to_string(int indent) const
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

void RedundantServerDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::RedundantServerDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::RedundantServerDataType::create);
  }
}

String& RedundantServerDataType::server_id()
{
  return mServerId;
}

const String& RedundantServerDataType::server_id() const
{
  return mServerId;
}

uint8_t& RedundantServerDataType::service_level()
{
  return mServiceLevel;
}

const uint8_t& RedundantServerDataType::service_level() const
{
  return mServiceLevel;
}

ServerState& RedundantServerDataType::server_state()
{
  return mServerState;
}

const ServerState& RedundantServerDataType::server_state() const
{
  return mServerState;
}

BuiltInTypeId RedundantServerDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ServiceCounterDataType
{
namespace
{
void encode(StackDepth limit, const ua::ServiceCounterDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.total_count());
  encoder.encode(limit, value.error_count());
}

void encode(StackDepth limit, const ua::ServiceCounterDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "TotalCount", value.total_count());
  encoder.encode(limit, "ErrorCount", value.error_count());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ServiceCounterDataType& value)
{
  decoder.decode(limit, value.total_count());
  decoder.decode(limit, value.error_count());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ServiceCounterDataType& value)
{
  decoder.decode(limit, "TotalCount", true, value.total_count());
  decoder.decode(limit, "ErrorCount", true, value.error_count());
}
}  // namespace
}  // namespace detail::ServiceCounterDataType

namespace detail::ServiceCounterDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ServiceCounterDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ServiceCounterDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ServiceCounterDataType

namespace detail::ServiceCounterDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ServiceCounterDataType>();
}
}  // namespace
}  // namespace detail::ServiceCounterDataType

bool ServiceCounterDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ServiceCounterDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ServiceCounterDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ServiceCounterDataType::type_name() const
{
  return typeName;
}

void ServiceCounterDataType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ServiceCounterDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ServiceCounterDataType::encode(limit, *this, *xml);
  }
}

void ServiceCounterDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ServiceCounterDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ServiceCounterDataType::encode_id(limit, ns, *xml);
  }
}

void ServiceCounterDataType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ServiceCounterDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ServiceCounterDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ServiceCounterDataType::clone() const
{
  return make_unique<ServiceCounterDataType>(*this);
}

void ServiceCounterDataType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "total_count=" + ua::to_string(total_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "error_count=" + ua::to_string(error_count());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "total_count=" + ua::to_string(total_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "error_count=" + ua::to_string(error_count());
}

std::string ServiceCounterDataType::to_string(int indent) const
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

void ServiceCounterDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ServiceCounterDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ServiceCounterDataType::create);
  }
}

uint32_t& ServiceCounterDataType::total_count()
{
  return mTotalCount;
}

const uint32_t& ServiceCounterDataType::total_count() const
{
  return mTotalCount;
}

uint32_t& ServiceCounterDataType::error_count()
{
  return mErrorCount;
}

const uint32_t& ServiceCounterDataType::error_count() const
{
  return mErrorCount;
}

BuiltInTypeId ServiceCounterDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::DoubleComplexNumberType
{
namespace
{
void encode(StackDepth limit, const ua::DoubleComplexNumberType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.real());
  encoder.encode(limit, value.imaginary());
}

void encode(StackDepth limit, const ua::DoubleComplexNumberType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Real", value.real());
  encoder.encode(limit, "Imaginary", value.imaginary());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::DoubleComplexNumberType& value)
{
  decoder.decode(limit, value.real());
  decoder.decode(limit, value.imaginary());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::DoubleComplexNumberType& value)
{
  decoder.decode(limit, "Real", true, value.real());
  decoder.decode(limit, "Imaginary", true, value.imaginary());
}
}  // namespace
}  // namespace detail::DoubleComplexNumberType

namespace detail::DoubleComplexNumberType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::DoubleComplexNumberType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::DoubleComplexNumberType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::DoubleComplexNumberType

namespace detail::DoubleComplexNumberType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::DoubleComplexNumberType>();
}
}  // namespace
}  // namespace detail::DoubleComplexNumberType

bool DoubleComplexNumberType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId DoubleComplexNumberType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId DoubleComplexNumberType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String DoubleComplexNumberType::type_name() const
{
  return typeName;
}

void DoubleComplexNumberType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DoubleComplexNumberType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DoubleComplexNumberType::encode(limit, *this, *xml);
  }
}

void DoubleComplexNumberType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DoubleComplexNumberType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DoubleComplexNumberType::encode_id(limit, ns, *xml);
  }
}

void DoubleComplexNumberType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::DoubleComplexNumberType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::DoubleComplexNumberType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> DoubleComplexNumberType::clone() const
{
  return make_unique<DoubleComplexNumberType>(*this);
}

void DoubleComplexNumberType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "real=" + ua::to_string(real());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "imaginary=" + ua::to_string(imaginary());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "real=" + ua::to_string(real());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "imaginary=" + ua::to_string(imaginary());
}

std::string DoubleComplexNumberType::to_string(int indent) const
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

void DoubleComplexNumberType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::DoubleComplexNumberType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::DoubleComplexNumberType::create);
  }
}

double& DoubleComplexNumberType::real()
{
  return mReal;
}

const double& DoubleComplexNumberType::real() const
{
  return mReal;
}

double& DoubleComplexNumberType::imaginary()
{
  return mImaginary;
}

const double& DoubleComplexNumberType::imaginary() const
{
  return mImaginary;
}

BuiltInTypeId DoubleComplexNumberType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ResponseHeader
{
namespace
{
void encode(StackDepth limit, const ua::ResponseHeader& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.timestamp());
  encoder.encode(limit, value.request_handle());
  encoder.encode(limit, value.service_result());
  encoder.encode(limit, value.service_diagnostics());
  encoder.encode(limit, value.string_table());
  encoder.encode(limit, value.additional_header().get());
}

void encode(StackDepth limit, const ua::ResponseHeader& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Timestamp", value.timestamp());
  encoder.encode(limit, "RequestHandle", value.request_handle());
  encoder.encode(limit, "ServiceResult", value.service_result());
  encoder.encode(limit, "ServiceDiagnostics", value.service_diagnostics());
  encoder.encode(limit, "StringTable", value.string_table());
  encoder.encode(limit, "AdditionalHeader", value.additional_header().get());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ResponseHeader& value)
{
  decoder.decode(limit, value.timestamp());
  decoder.decode(limit, value.request_handle());
  decoder.decode(limit, value.service_result());
  decoder.decode(limit, value.service_diagnostics());
  decoder.decode(limit, value.string_table());
  decoder.decode(limit, value.additional_header().inner_unique_ptr());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ResponseHeader& value)
{
  decoder.decode(limit, "Timestamp", true, value.timestamp());
  decoder.decode(limit, "RequestHandle", true, value.request_handle());
  decoder.decode(limit, "ServiceResult", true, value.service_result());
  decoder.decode(limit, "ServiceDiagnostics", true, value.service_diagnostics());
  decoder.decode(limit, "StringTable", true, value.string_table());
  decoder.decode(limit, "AdditionalHeader", true, value.additional_header().inner_unique_ptr());
}
}  // namespace
}  // namespace detail::ResponseHeader

namespace detail::ResponseHeader
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ResponseHeader::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ResponseHeader::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ResponseHeader

namespace detail::ResponseHeader
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ResponseHeader>();
}
}  // namespace
}  // namespace detail::ResponseHeader

bool ResponseHeader::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ResponseHeader::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ResponseHeader::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ResponseHeader::type_name() const
{
  return typeName;
}

void ResponseHeader::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ResponseHeader::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ResponseHeader::encode(limit, *this, *xml);
  }
}

void ResponseHeader::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ResponseHeader::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ResponseHeader::encode_id(limit, ns, *xml);
  }
}

void ResponseHeader::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ResponseHeader::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ResponseHeader::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ResponseHeader::clone() const
{
  return make_unique<ResponseHeader>(*this);
}

void ResponseHeader::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "timestamp=" + ua::to_string(timestamp());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "request_handle=" + ua::to_string(request_handle());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "service_result=" + ua::to_string(service_result());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "service_diagnostics=" + ua::to_string(service_diagnostics());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "string_table=" + ua::to_string(string_table());
    if (!output.empty())
    {
      output += ",\n";
    }
    output +=
      pad + "additional_header=" + (additional_header() ? additional_header()->to_string(indent) : "null");
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "timestamp=" + ua::to_string(timestamp());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "request_handle=" + ua::to_string(request_handle());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "service_result=" + ua::to_string(service_result());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "service_diagnostics=" + ua::to_string(service_diagnostics());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "string_table=" + ua::to_string(string_table());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "additional_header=" + (additional_header() ? additional_header()->to_string(0) : "null");
}

std::string ResponseHeader::to_string(int indent) const
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

void ResponseHeader::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ResponseHeader::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ResponseHeader::create);
  }
}

UtcTime& ResponseHeader::timestamp()
{
  return mTimestamp;
}

const UtcTime& ResponseHeader::timestamp() const
{
  return mTimestamp;
}

IntegerId& ResponseHeader::request_handle()
{
  return mRequestHandle;
}

const IntegerId& ResponseHeader::request_handle() const
{
  return mRequestHandle;
}

StatusCode& ResponseHeader::service_result()
{
  return mServiceResult;
}

const StatusCode& ResponseHeader::service_result() const
{
  return mServiceResult;
}

DiagnosticInfo& ResponseHeader::service_diagnostics()
{
  return mServiceDiagnostics;
}

const DiagnosticInfo& ResponseHeader::service_diagnostics() const
{
  return mServiceDiagnostics;
}

Array<String>& ResponseHeader::string_table()
{
  return mStringTable;
}

const Array<String>& ResponseHeader::string_table() const
{
  return mStringTable;
}

RefStructure<Structure>& ResponseHeader::additional_header()
{
  return mAdditionalHeader;
}

const RefStructure<Structure>& ResponseHeader::additional_header() const
{
  return mAdditionalHeader;
}

BuiltInTypeId ResponseHeader::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::GetEndpointsRequest
{
namespace
{
void encode(StackDepth limit, const ua::GetEndpointsRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.endpoint_url());
  encoder.encode(limit, value.locale_ids());
  encoder.encode(limit, value.profile_uris());
}

void encode(StackDepth limit, const ua::GetEndpointsRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "EndpointUrl", value.endpoint_url());
  encoder.encode(limit, "LocaleIds", value.locale_ids());
  encoder.encode(limit, "ProfileUris", value.profile_uris());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::GetEndpointsRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.endpoint_url());
  decoder.decode(limit, value.locale_ids());
  decoder.decode(limit, value.profile_uris());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::GetEndpointsRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "EndpointUrl", true, value.endpoint_url());
  decoder.decode(limit, "LocaleIds", true, value.locale_ids());
  decoder.decode(limit, "ProfileUris", true, value.profile_uris());
}
}  // namespace
}  // namespace detail::GetEndpointsRequest

namespace detail::GetEndpointsRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::GetEndpointsRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::GetEndpointsRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::GetEndpointsRequest

namespace detail::GetEndpointsRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::GetEndpointsRequest>();
}
}  // namespace
}  // namespace detail::GetEndpointsRequest

bool GetEndpointsRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId GetEndpointsRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId GetEndpointsRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String GetEndpointsRequest::type_name() const
{
  return typeName;
}

void GetEndpointsRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::GetEndpointsRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::GetEndpointsRequest::encode(limit, *this, *xml);
  }
}

void GetEndpointsRequest::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::GetEndpointsRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::GetEndpointsRequest::encode_id(limit, ns, *xml);
  }
}

void GetEndpointsRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::GetEndpointsRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::GetEndpointsRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> GetEndpointsRequest::clone() const
{
  return make_unique<GetEndpointsRequest>(*this);
}

void GetEndpointsRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "profile_uris=" + ua::to_string(profile_uris());
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
  output += "profile_uris=" + ua::to_string(profile_uris());
}

std::string GetEndpointsRequest::to_string(int indent) const
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

void GetEndpointsRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::GetEndpointsRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::GetEndpointsRequest::create);
  }
}

RequestHeader& GetEndpointsRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& GetEndpointsRequest::request_header() const
{
  return mRequestHeader;
}

String& GetEndpointsRequest::endpoint_url()
{
  return mEndpointUrl;
}

const String& GetEndpointsRequest::endpoint_url() const
{
  return mEndpointUrl;
}

Array<LocaleId>& GetEndpointsRequest::locale_ids()
{
  return mLocaleIds;
}

const Array<LocaleId>& GetEndpointsRequest::locale_ids() const
{
  return mLocaleIds;
}

Array<String>& GetEndpointsRequest::profile_uris()
{
  return mProfileUris;
}

const Array<String>& GetEndpointsRequest::profile_uris() const
{
  return mProfileUris;
}

BuiltInTypeId GetEndpointsRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::OpenSecureChannelResponse
{
namespace
{
void encode(StackDepth limit, const ua::OpenSecureChannelResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.server_protocol_version());
  encoder.encode(limit, value.security_token());
  encoder.encode(limit, value.server_nonce());
}

void encode(StackDepth limit, const ua::OpenSecureChannelResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "ServerProtocolVersion", value.server_protocol_version());
  encoder.encode(limit, "SecurityToken", value.security_token());
  encoder.encode(limit, "ServerNonce", value.server_nonce());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::OpenSecureChannelResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.server_protocol_version());
  decoder.decode(limit, value.security_token());
  decoder.decode(limit, value.server_nonce());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::OpenSecureChannelResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "ServerProtocolVersion", true, value.server_protocol_version());
  decoder.decode(limit, "SecurityToken", true, value.security_token());
  decoder.decode(limit, "ServerNonce", true, value.server_nonce());
}
}  // namespace
}  // namespace detail::OpenSecureChannelResponse

namespace detail::OpenSecureChannelResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::OpenSecureChannelResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::OpenSecureChannelResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::OpenSecureChannelResponse

namespace detail::OpenSecureChannelResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::OpenSecureChannelResponse>();
}
}  // namespace
}  // namespace detail::OpenSecureChannelResponse

bool OpenSecureChannelResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId OpenSecureChannelResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId OpenSecureChannelResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String OpenSecureChannelResponse::type_name() const
{
  return typeName;
}

void OpenSecureChannelResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::OpenSecureChannelResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::OpenSecureChannelResponse::encode(limit, *this, *xml);
  }
}

void OpenSecureChannelResponse::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::OpenSecureChannelResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::OpenSecureChannelResponse::encode_id(limit, ns, *xml);
  }
}

void OpenSecureChannelResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::OpenSecureChannelResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::OpenSecureChannelResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> OpenSecureChannelResponse::clone() const
{
  return make_unique<OpenSecureChannelResponse>(*this);
}

void OpenSecureChannelResponse::append_fields(std::string& output, int indent) const
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
    output += pad + "server_protocol_version=" + ua::to_string(server_protocol_version());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "security_token=" + ua::to_string(security_token());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "server_nonce=" + ua::to_string(server_nonce());
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
  output += "server_protocol_version=" + ua::to_string(server_protocol_version());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "security_token=" + ua::to_string(security_token());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "server_nonce=" + ua::to_string(server_nonce());
}

std::string OpenSecureChannelResponse::to_string(int indent) const
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

void OpenSecureChannelResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::OpenSecureChannelResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::OpenSecureChannelResponse::create);
  }
}

ResponseHeader& OpenSecureChannelResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& OpenSecureChannelResponse::response_header() const
{
  return mResponseHeader;
}

uint32_t& OpenSecureChannelResponse::server_protocol_version()
{
  return mServerProtocolVersion;
}

const uint32_t& OpenSecureChannelResponse::server_protocol_version() const
{
  return mServerProtocolVersion;
}

ChannelSecurityToken& OpenSecureChannelResponse::security_token()
{
  return mSecurityToken;
}

const ChannelSecurityToken& OpenSecureChannelResponse::security_token() const
{
  return mSecurityToken;
}

ByteString& OpenSecureChannelResponse::server_nonce()
{
  return mServerNonce;
}

const ByteString& OpenSecureChannelResponse::server_nonce() const
{
  return mServerNonce;
}

BuiltInTypeId OpenSecureChannelResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::CloseSessionRequest
{
namespace
{
void encode(StackDepth limit, const ua::CloseSessionRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.delete_subscriptions());
}

void encode(StackDepth limit, const ua::CloseSessionRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "DeleteSubscriptions", value.delete_subscriptions());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::CloseSessionRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.delete_subscriptions());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::CloseSessionRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "DeleteSubscriptions", true, value.delete_subscriptions());
}
}  // namespace
}  // namespace detail::CloseSessionRequest

namespace detail::CloseSessionRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::CloseSessionRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::CloseSessionRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::CloseSessionRequest

namespace detail::CloseSessionRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::CloseSessionRequest>();
}
}  // namespace
}  // namespace detail::CloseSessionRequest

bool CloseSessionRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId CloseSessionRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId CloseSessionRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String CloseSessionRequest::type_name() const
{
  return typeName;
}

void CloseSessionRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CloseSessionRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CloseSessionRequest::encode(limit, *this, *xml);
  }
}

void CloseSessionRequest::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CloseSessionRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CloseSessionRequest::encode_id(limit, ns, *xml);
  }
}

void CloseSessionRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::CloseSessionRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::CloseSessionRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> CloseSessionRequest::clone() const
{
  return make_unique<CloseSessionRequest>(*this);
}

void CloseSessionRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "delete_subscriptions=" + ua::to_string(delete_subscriptions());
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
  output += "delete_subscriptions=" + ua::to_string(delete_subscriptions());
}

std::string CloseSessionRequest::to_string(int indent) const
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

void CloseSessionRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::CloseSessionRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::CloseSessionRequest::create);
  }
}

RequestHeader& CloseSessionRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& CloseSessionRequest::request_header() const
{
  return mRequestHeader;
}

bool& CloseSessionRequest::delete_subscriptions()
{
  return mDeleteSubscriptions;
}

const bool& CloseSessionRequest::delete_subscriptions() const
{
  return mDeleteSubscriptions;
}

BuiltInTypeId CloseSessionRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ObjectTypeAttributes
{
namespace
{
void encode(StackDepth limit, const ua::ObjectTypeAttributes& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.is_abstract());
}

void encode(StackDepth limit, const ua::ObjectTypeAttributes& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "IsAbstract", value.is_abstract());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ObjectTypeAttributes& value)
{
  decoder.decode(limit, value.is_abstract());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ObjectTypeAttributes& value)
{
  decoder.decode(limit, "IsAbstract", true, value.is_abstract());
}
}  // namespace
}  // namespace detail::ObjectTypeAttributes

namespace detail::ObjectTypeAttributes
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ObjectTypeAttributes::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ObjectTypeAttributes::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ObjectTypeAttributes

namespace detail::ObjectTypeAttributes
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ObjectTypeAttributes>();
}
}  // namespace
}  // namespace detail::ObjectTypeAttributes

bool ObjectTypeAttributes::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return NodeAttributes::is_of_type(ns, dataTypeId);
}

NodeId ObjectTypeAttributes::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ObjectTypeAttributes::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ObjectTypeAttributes::type_name() const
{
  return typeName;
}

void ObjectTypeAttributes::encode(StackDepth limit, Encoder& encoder) const
{

  NodeAttributes::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ObjectTypeAttributes::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ObjectTypeAttributes::encode(limit, *this, *xml);
  }
}

void ObjectTypeAttributes::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ObjectTypeAttributes::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ObjectTypeAttributes::encode_id(limit, ns, *xml);
  }
}

void ObjectTypeAttributes::decode(StackDepth limit, Decoder& decoder)
{

  NodeAttributes::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ObjectTypeAttributes::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ObjectTypeAttributes::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ObjectTypeAttributes::clone() const
{
  return make_unique<ObjectTypeAttributes>(*this);
}

void ObjectTypeAttributes::append_fields(std::string& output, int indent) const
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
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "is_abstract=" + ua::to_string(is_abstract());
}

std::string ObjectTypeAttributes::to_string(int indent) const
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

void ObjectTypeAttributes::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ObjectTypeAttributes::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ObjectTypeAttributes::create);
  }
}

bool& ObjectTypeAttributes::is_abstract()
{
  return mIsAbstract;
}

const bool& ObjectTypeAttributes::is_abstract() const
{
  return mIsAbstract;
}

BuiltInTypeId ObjectTypeAttributes::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::AddNodesRequest
{
namespace
{
void encode(StackDepth limit, const ua::AddNodesRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.nodes_to_add());
}

void encode(StackDepth limit, const ua::AddNodesRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "NodesToAdd", value.nodes_to_add());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::AddNodesRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.nodes_to_add());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::AddNodesRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "NodesToAdd", true, value.nodes_to_add());
}
}  // namespace
}  // namespace detail::AddNodesRequest

namespace detail::AddNodesRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::AddNodesRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::AddNodesRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::AddNodesRequest

namespace detail::AddNodesRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::AddNodesRequest>();
}
}  // namespace
}  // namespace detail::AddNodesRequest

bool AddNodesRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId AddNodesRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId AddNodesRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String AddNodesRequest::type_name() const
{
  return typeName;
}

void AddNodesRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AddNodesRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AddNodesRequest::encode(limit, *this, *xml);
  }
}

void AddNodesRequest::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AddNodesRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AddNodesRequest::encode_id(limit, ns, *xml);
  }
}

void AddNodesRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::AddNodesRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::AddNodesRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> AddNodesRequest::clone() const
{
  return make_unique<AddNodesRequest>(*this);
}

void AddNodesRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "nodes_to_add=" + ua::to_string(nodes_to_add());
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
  output += "nodes_to_add=" + ua::to_string(nodes_to_add());
}

std::string AddNodesRequest::to_string(int indent) const
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

void AddNodesRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::AddNodesRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::AddNodesRequest::create);
  }
}

RequestHeader& AddNodesRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& AddNodesRequest::request_header() const
{
  return mRequestHeader;
}

Array<AddNodesItem>& AddNodesRequest::nodes_to_add()
{
  return mNodesToAdd;
}

const Array<AddNodesItem>& AddNodesRequest::nodes_to_add() const
{
  return mNodesToAdd;
}

BuiltInTypeId AddNodesRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ViewDescription
{
namespace
{
void encode(StackDepth limit, const ua::ViewDescription& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.view_id());
  encoder.encode(limit, value.timestamp());
  encoder.encode(limit, value.view_version());
}

void encode(StackDepth limit, const ua::ViewDescription& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ViewId", value.view_id());
  encoder.encode(limit, "Timestamp", value.timestamp());
  encoder.encode(limit, "ViewVersion", value.view_version());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ViewDescription& value)
{
  decoder.decode(limit, value.view_id());
  decoder.decode(limit, value.timestamp());
  decoder.decode(limit, value.view_version());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ViewDescription& value)
{
  decoder.decode(limit, "ViewId", true, value.view_id());
  decoder.decode(limit, "Timestamp", true, value.timestamp());
  decoder.decode(limit, "ViewVersion", true, value.view_version());
}
}  // namespace
}  // namespace detail::ViewDescription

namespace detail::ViewDescription
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ViewDescription::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ViewDescription::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ViewDescription

namespace detail::ViewDescription
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ViewDescription>();
}
}  // namespace
}  // namespace detail::ViewDescription

bool ViewDescription::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ViewDescription::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ViewDescription::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ViewDescription::type_name() const
{
  return typeName;
}

void ViewDescription::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ViewDescription::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ViewDescription::encode(limit, *this, *xml);
  }
}

void ViewDescription::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ViewDescription::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ViewDescription::encode_id(limit, ns, *xml);
  }
}

void ViewDescription::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ViewDescription::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ViewDescription::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ViewDescription::clone() const
{
  return make_unique<ViewDescription>(*this);
}

void ViewDescription::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "view_id=" + ua::to_string(view_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "timestamp=" + ua::to_string(timestamp());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "view_version=" + ua::to_string(view_version());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "view_id=" + ua::to_string(view_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "timestamp=" + ua::to_string(timestamp());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "view_version=" + ua::to_string(view_version());
}

std::string ViewDescription::to_string(int indent) const
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

void ViewDescription::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ViewDescription::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ViewDescription::create);
  }
}

NodeId& ViewDescription::view_id()
{
  return mViewId;
}

const NodeId& ViewDescription::view_id() const
{
  return mViewId;
}

UtcTime& ViewDescription::timestamp()
{
  return mTimestamp;
}

const UtcTime& ViewDescription::timestamp() const
{
  return mTimestamp;
}

uint32_t& ViewDescription::view_version()
{
  return mViewVersion;
}

const uint32_t& ViewDescription::view_version() const
{
  return mViewVersion;
}

BuiltInTypeId ViewDescription::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::BrowsePath
{
namespace
{
void encode(StackDepth limit, const ua::BrowsePath& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.starting_node());
  encoder.encode(limit, value.relative_path());
}

void encode(StackDepth limit, const ua::BrowsePath& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "StartingNode", value.starting_node());
  encoder.encode(limit, "RelativePath", value.relative_path());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::BrowsePath& value)
{
  decoder.decode(limit, value.starting_node());
  decoder.decode(limit, value.relative_path());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::BrowsePath& value)
{
  decoder.decode(limit, "StartingNode", true, value.starting_node());
  decoder.decode(limit, "RelativePath", true, value.relative_path());
}
}  // namespace
}  // namespace detail::BrowsePath

namespace detail::BrowsePath
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::BrowsePath::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::BrowsePath::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::BrowsePath

namespace detail::BrowsePath
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::BrowsePath>();
}
}  // namespace
}  // namespace detail::BrowsePath

bool BrowsePath::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId BrowsePath::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId BrowsePath::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String BrowsePath::type_name() const
{
  return typeName;
}

void BrowsePath::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::BrowsePath::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::BrowsePath::encode(limit, *this, *xml);
  }
}

void BrowsePath::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::BrowsePath::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::BrowsePath::encode_id(limit, ns, *xml);
  }
}

void BrowsePath::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::BrowsePath::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::BrowsePath::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> BrowsePath::clone() const
{
  return make_unique<BrowsePath>(*this);
}

void BrowsePath::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "starting_node=" + ua::to_string(starting_node());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "relative_path=" + ua::to_string(relative_path());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "starting_node=" + ua::to_string(starting_node());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "relative_path=" + ua::to_string(relative_path());
}

std::string BrowsePath::to_string(int indent) const
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

void BrowsePath::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::BrowsePath::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::BrowsePath::create);
  }
}

NodeId& BrowsePath::starting_node()
{
  return mStartingNode;
}

const NodeId& BrowsePath::starting_node() const
{
  return mStartingNode;
}

RelativePath& BrowsePath::relative_path()
{
  return mRelativePath;
}

const RelativePath& BrowsePath::relative_path() const
{
  return mRelativePath;
}

BuiltInTypeId BrowsePath::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::UnregisterNodesResponse
{
namespace
{
void encode(StackDepth limit, const ua::UnregisterNodesResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
}

void encode(StackDepth limit, const ua::UnregisterNodesResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::UnregisterNodesResponse& value)
{
  decoder.decode(limit, value.response_header());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::UnregisterNodesResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
}
}  // namespace
}  // namespace detail::UnregisterNodesResponse

namespace detail::UnregisterNodesResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::UnregisterNodesResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::UnregisterNodesResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::UnregisterNodesResponse

namespace detail::UnregisterNodesResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::UnregisterNodesResponse>();
}
}  // namespace
}  // namespace detail::UnregisterNodesResponse

bool UnregisterNodesResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId UnregisterNodesResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId UnregisterNodesResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String UnregisterNodesResponse::type_name() const
{
  return typeName;
}

void UnregisterNodesResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::UnregisterNodesResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::UnregisterNodesResponse::encode(limit, *this, *xml);
  }
}

void UnregisterNodesResponse::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::UnregisterNodesResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::UnregisterNodesResponse::encode_id(limit, ns, *xml);
  }
}

void UnregisterNodesResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::UnregisterNodesResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::UnregisterNodesResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> UnregisterNodesResponse::clone() const
{
  return make_unique<UnregisterNodesResponse>(*this);
}

void UnregisterNodesResponse::append_fields(std::string& output, int indent) const
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

std::string UnregisterNodesResponse::to_string(int indent) const
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

void UnregisterNodesResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::UnregisterNodesResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::UnregisterNodesResponse::create);
  }
}

ResponseHeader& UnregisterNodesResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& UnregisterNodesResponse::response_header() const
{
  return mResponseHeader;
}

BuiltInTypeId UnregisterNodesResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::QueryFirstRequest
{
namespace
{
void encode(StackDepth limit, const ua::QueryFirstRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.view());
  encoder.encode(limit, value.node_types());
  encoder.encode(limit, value.filter());
  encoder.encode(limit, value.max_data_sets_to_return());
  encoder.encode(limit, value.max_references_to_return());
}

void encode(StackDepth limit, const ua::QueryFirstRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "View", value.view());
  encoder.encode(limit, "NodeTypes", value.node_types());
  encoder.encode(limit, "Filter", value.filter());
  encoder.encode(limit, "MaxDataSetsToReturn", value.max_data_sets_to_return());
  encoder.encode(limit, "MaxReferencesToReturn", value.max_references_to_return());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::QueryFirstRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.view());
  decoder.decode(limit, value.node_types());
  decoder.decode(limit, value.filter());
  decoder.decode(limit, value.max_data_sets_to_return());
  decoder.decode(limit, value.max_references_to_return());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::QueryFirstRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "View", true, value.view());
  decoder.decode(limit, "NodeTypes", true, value.node_types());
  decoder.decode(limit, "Filter", true, value.filter());
  decoder.decode(limit, "MaxDataSetsToReturn", true, value.max_data_sets_to_return());
  decoder.decode(limit, "MaxReferencesToReturn", true, value.max_references_to_return());
}
}  // namespace
}  // namespace detail::QueryFirstRequest

namespace detail::QueryFirstRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::QueryFirstRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::QueryFirstRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::QueryFirstRequest

namespace detail::QueryFirstRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::QueryFirstRequest>();
}
}  // namespace
}  // namespace detail::QueryFirstRequest

bool QueryFirstRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId QueryFirstRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId QueryFirstRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String QueryFirstRequest::type_name() const
{
  return typeName;
}

void QueryFirstRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::QueryFirstRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::QueryFirstRequest::encode(limit, *this, *xml);
  }
}

void QueryFirstRequest::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::QueryFirstRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::QueryFirstRequest::encode_id(limit, ns, *xml);
  }
}

void QueryFirstRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::QueryFirstRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::QueryFirstRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> QueryFirstRequest::clone() const
{
  return make_unique<QueryFirstRequest>(*this);
}

void QueryFirstRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "node_types=" + ua::to_string(node_types());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "filter=" + ua::to_string(filter());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "max_data_sets_to_return=" + ua::to_string(max_data_sets_to_return());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "max_references_to_return=" + ua::to_string(max_references_to_return());
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
  output += "node_types=" + ua::to_string(node_types());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "filter=" + ua::to_string(filter());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "max_data_sets_to_return=" + ua::to_string(max_data_sets_to_return());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "max_references_to_return=" + ua::to_string(max_references_to_return());
}

std::string QueryFirstRequest::to_string(int indent) const
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

void QueryFirstRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::QueryFirstRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::QueryFirstRequest::create);
  }
}

RequestHeader& QueryFirstRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& QueryFirstRequest::request_header() const
{
  return mRequestHeader;
}

ViewDescription& QueryFirstRequest::view()
{
  return mView;
}

const ViewDescription& QueryFirstRequest::view() const
{
  return mView;
}

Array<NodeTypeDescription>& QueryFirstRequest::node_types()
{
  return mNodeTypes;
}

const Array<NodeTypeDescription>& QueryFirstRequest::node_types() const
{
  return mNodeTypes;
}

ContentFilter& QueryFirstRequest::filter()
{
  return mFilter;
}

const ContentFilter& QueryFirstRequest::filter() const
{
  return mFilter;
}

Counter& QueryFirstRequest::max_data_sets_to_return()
{
  return mMaxDataSetsToReturn;
}

const Counter& QueryFirstRequest::max_data_sets_to_return() const
{
  return mMaxDataSetsToReturn;
}

Counter& QueryFirstRequest::max_references_to_return()
{
  return mMaxReferencesToReturn;
}

const Counter& QueryFirstRequest::max_references_to_return() const
{
  return mMaxReferencesToReturn;
}

BuiltInTypeId QueryFirstRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::HistoryReadResult
{
namespace
{
void encode(StackDepth limit, const ua::HistoryReadResult& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.status_code());
  encoder.encode(limit, value.continuation_point());
  encoder.encode(limit, value.history_data().get());
}

void encode(StackDepth limit, const ua::HistoryReadResult& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "StatusCode", value.status_code());
  encoder.encode(limit, "ContinuationPoint", value.continuation_point());
  encoder.encode(limit, "HistoryData", value.history_data().get());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::HistoryReadResult& value)
{
  decoder.decode(limit, value.status_code());
  decoder.decode(limit, value.continuation_point());
  decoder.decode(limit, value.history_data().inner_unique_ptr());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::HistoryReadResult& value)
{
  decoder.decode(limit, "StatusCode", true, value.status_code());
  decoder.decode(limit, "ContinuationPoint", true, value.continuation_point());
  decoder.decode(limit, "HistoryData", true, value.history_data().inner_unique_ptr());
}
}  // namespace
}  // namespace detail::HistoryReadResult

namespace detail::HistoryReadResult
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::HistoryReadResult::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::HistoryReadResult::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::HistoryReadResult

namespace detail::HistoryReadResult
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::HistoryReadResult>();
}
}  // namespace
}  // namespace detail::HistoryReadResult

bool HistoryReadResult::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId HistoryReadResult::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId HistoryReadResult::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String HistoryReadResult::type_name() const
{
  return typeName;
}

void HistoryReadResult::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::HistoryReadResult::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::HistoryReadResult::encode(limit, *this, *xml);
  }
}

void HistoryReadResult::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::HistoryReadResult::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::HistoryReadResult::encode_id(limit, ns, *xml);
  }
}

void HistoryReadResult::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::HistoryReadResult::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::HistoryReadResult::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> HistoryReadResult::clone() const
{
  return make_unique<HistoryReadResult>(*this);
}

void HistoryReadResult::append_fields(std::string& output, int indent) const
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
    output += pad + "continuation_point=" + ua::to_string(continuation_point());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "history_data=" + (history_data() ? history_data()->to_string(indent) : "null");
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
  output += "continuation_point=" + ua::to_string(continuation_point());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "history_data=" + (history_data() ? history_data()->to_string(0) : "null");
}

std::string HistoryReadResult::to_string(int indent) const
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

void HistoryReadResult::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::HistoryReadResult::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::HistoryReadResult::create);
  }
}

StatusCode& HistoryReadResult::status_code()
{
  return mStatusCode;
}

const StatusCode& HistoryReadResult::status_code() const
{
  return mStatusCode;
}

ContinuationPoint& HistoryReadResult::continuation_point()
{
  return mContinuationPoint;
}

const ContinuationPoint& HistoryReadResult::continuation_point() const
{
  return mContinuationPoint;
}

RefStructure<Structure>& HistoryReadResult::history_data()
{
  return mHistoryData;
}

const RefStructure<Structure>& HistoryReadResult::history_data() const
{
  return mHistoryData;
}

BuiltInTypeId HistoryReadResult::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ReadAtTimeDetails
{
namespace
{
void encode(StackDepth limit, const ua::ReadAtTimeDetails& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.req_times());
  encoder.encode(limit, value.use_simple_bounds());
}

void encode(StackDepth limit, const ua::ReadAtTimeDetails& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ReqTimes", value.req_times());
  encoder.encode(limit, "UseSimpleBounds", value.use_simple_bounds());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ReadAtTimeDetails& value)
{
  decoder.decode(limit, value.req_times());
  decoder.decode(limit, value.use_simple_bounds());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ReadAtTimeDetails& value)
{
  decoder.decode(limit, "ReqTimes", true, value.req_times());
  decoder.decode(limit, "UseSimpleBounds", true, value.use_simple_bounds());
}
}  // namespace
}  // namespace detail::ReadAtTimeDetails

namespace detail::ReadAtTimeDetails
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ReadAtTimeDetails::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ReadAtTimeDetails::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ReadAtTimeDetails

namespace detail::ReadAtTimeDetails
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ReadAtTimeDetails>();
}
}  // namespace
}  // namespace detail::ReadAtTimeDetails

bool ReadAtTimeDetails::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return HistoryReadDetails::is_of_type(ns, dataTypeId);
}

NodeId ReadAtTimeDetails::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ReadAtTimeDetails::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ReadAtTimeDetails::type_name() const
{
  return typeName;
}

void ReadAtTimeDetails::encode(StackDepth limit, Encoder& encoder) const
{

  HistoryReadDetails::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReadAtTimeDetails::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReadAtTimeDetails::encode(limit, *this, *xml);
  }
}

void ReadAtTimeDetails::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReadAtTimeDetails::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReadAtTimeDetails::encode_id(limit, ns, *xml);
  }
}

void ReadAtTimeDetails::decode(StackDepth limit, Decoder& decoder)
{

  HistoryReadDetails::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ReadAtTimeDetails::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ReadAtTimeDetails::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ReadAtTimeDetails::clone() const
{
  return make_unique<ReadAtTimeDetails>(*this);
}

void ReadAtTimeDetails::append_fields(std::string& output, int indent) const
{
  HistoryReadDetails::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "req_times=" + ua::to_string(req_times());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "use_simple_bounds=" + ua::to_string(use_simple_bounds());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "req_times=" + ua::to_string(req_times());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "use_simple_bounds=" + ua::to_string(use_simple_bounds());
}

std::string ReadAtTimeDetails::to_string(int indent) const
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

void ReadAtTimeDetails::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ReadAtTimeDetails::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ReadAtTimeDetails::create);
  }
}

Array<UtcTime>& ReadAtTimeDetails::req_times()
{
  return mReqTimes;
}

const Array<UtcTime>& ReadAtTimeDetails::req_times() const
{
  return mReqTimes;
}

bool& ReadAtTimeDetails::use_simple_bounds()
{
  return mUseSimpleBounds;
}

const bool& ReadAtTimeDetails::use_simple_bounds() const
{
  return mUseSimpleBounds;
}

BuiltInTypeId ReadAtTimeDetails::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::WriteResponse
{
namespace
{
void encode(StackDepth limit, const ua::WriteResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.results());
  encoder.encode(limit, value.diagnostic_infos());
}

void encode(StackDepth limit, const ua::WriteResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "Results", value.results());
  encoder.encode(limit, "DiagnosticInfos", value.diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::WriteResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.results());
  decoder.decode(limit, value.diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::WriteResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "Results", true, value.results());
  decoder.decode(limit, "DiagnosticInfos", true, value.diagnostic_infos());
}
}  // namespace
}  // namespace detail::WriteResponse

namespace detail::WriteResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::WriteResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::WriteResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::WriteResponse

namespace detail::WriteResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::WriteResponse>();
}
}  // namespace
}  // namespace detail::WriteResponse

bool WriteResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId WriteResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId WriteResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String WriteResponse::type_name() const
{
  return typeName;
}

void WriteResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::WriteResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::WriteResponse::encode(limit, *this, *xml);
  }
}

void WriteResponse::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::WriteResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::WriteResponse::encode_id(limit, ns, *xml);
  }
}

void WriteResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::WriteResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::WriteResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> WriteResponse::clone() const
{
  return make_unique<WriteResponse>(*this);
}

void WriteResponse::append_fields(std::string& output, int indent) const
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

std::string WriteResponse::to_string(int indent) const
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

void WriteResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::WriteResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::WriteResponse::create);
  }
}

ResponseHeader& WriteResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& WriteResponse::response_header() const
{
  return mResponseHeader;
}

Array<StatusCode>& WriteResponse::results()
{
  return mResults;
}

const Array<StatusCode>& WriteResponse::results() const
{
  return mResults;
}

Array<DiagnosticInfo>& WriteResponse::diagnostic_infos()
{
  return mDiagnosticInfos;
}

const Array<DiagnosticInfo>& WriteResponse::diagnostic_infos() const
{
  return mDiagnosticInfos;
}

BuiltInTypeId WriteResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::HistoryUpdateResult
{
namespace
{
void encode(StackDepth limit, const ua::HistoryUpdateResult& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.status_code());
  encoder.encode(limit, value.operation_results());
  encoder.encode(limit, value.diagnostic_infos());
}

void encode(StackDepth limit, const ua::HistoryUpdateResult& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "StatusCode", value.status_code());
  encoder.encode(limit, "OperationResults", value.operation_results());
  encoder.encode(limit, "DiagnosticInfos", value.diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::HistoryUpdateResult& value)
{
  decoder.decode(limit, value.status_code());
  decoder.decode(limit, value.operation_results());
  decoder.decode(limit, value.diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::HistoryUpdateResult& value)
{
  decoder.decode(limit, "StatusCode", true, value.status_code());
  decoder.decode(limit, "OperationResults", true, value.operation_results());
  decoder.decode(limit, "DiagnosticInfos", true, value.diagnostic_infos());
}
}  // namespace
}  // namespace detail::HistoryUpdateResult

namespace detail::HistoryUpdateResult
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::HistoryUpdateResult::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::HistoryUpdateResult::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::HistoryUpdateResult

namespace detail::HistoryUpdateResult
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::HistoryUpdateResult>();
}
}  // namespace
}  // namespace detail::HistoryUpdateResult

bool HistoryUpdateResult::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId HistoryUpdateResult::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId HistoryUpdateResult::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String HistoryUpdateResult::type_name() const
{
  return typeName;
}

void HistoryUpdateResult::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::HistoryUpdateResult::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::HistoryUpdateResult::encode(limit, *this, *xml);
  }
}

void HistoryUpdateResult::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::HistoryUpdateResult::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::HistoryUpdateResult::encode_id(limit, ns, *xml);
  }
}

void HistoryUpdateResult::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::HistoryUpdateResult::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::HistoryUpdateResult::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> HistoryUpdateResult::clone() const
{
  return make_unique<HistoryUpdateResult>(*this);
}

void HistoryUpdateResult::append_fields(std::string& output, int indent) const
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
    output += pad + "operation_results=" + ua::to_string(operation_results());
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
  output += "status_code=" + ua::to_string(status_code());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "operation_results=" + ua::to_string(operation_results());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "diagnostic_infos=" + ua::to_string(diagnostic_infos());
}

std::string HistoryUpdateResult::to_string(int indent) const
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

void HistoryUpdateResult::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::HistoryUpdateResult::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::HistoryUpdateResult::create);
  }
}

StatusCode& HistoryUpdateResult::status_code()
{
  return mStatusCode;
}

const StatusCode& HistoryUpdateResult::status_code() const
{
  return mStatusCode;
}

Array<StatusCode>& HistoryUpdateResult::operation_results()
{
  return mOperationResults;
}

const Array<StatusCode>& HistoryUpdateResult::operation_results() const
{
  return mOperationResults;
}

Array<DiagnosticInfo>& HistoryUpdateResult::diagnostic_infos()
{
  return mDiagnosticInfos;
}

const Array<DiagnosticInfo>& HistoryUpdateResult::diagnostic_infos() const
{
  return mDiagnosticInfos;
}

BuiltInTypeId HistoryUpdateResult::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::AggregateFilter
{
namespace
{
void encode(StackDepth limit, const ua::AggregateFilter& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.start_time());
  encoder.encode(limit, value.aggregate_type());
  encoder.encode(limit, value.processing_interval());
  encoder.encode(limit, value.aggregate_configuration());
}

void encode(StackDepth limit, const ua::AggregateFilter& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "StartTime", value.start_time());
  encoder.encode(limit, "AggregateType", value.aggregate_type());
  encoder.encode(limit, "ProcessingInterval", value.processing_interval());
  encoder.encode(limit, "AggregateConfiguration", value.aggregate_configuration());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::AggregateFilter& value)
{
  decoder.decode(limit, value.start_time());
  decoder.decode(limit, value.aggregate_type());
  decoder.decode(limit, value.processing_interval());
  decoder.decode(limit, value.aggregate_configuration());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::AggregateFilter& value)
{
  decoder.decode(limit, "StartTime", true, value.start_time());
  decoder.decode(limit, "AggregateType", true, value.aggregate_type());
  decoder.decode(limit, "ProcessingInterval", true, value.processing_interval());
  decoder.decode(limit, "AggregateConfiguration", true, value.aggregate_configuration());
}
}  // namespace
}  // namespace detail::AggregateFilter

namespace detail::AggregateFilter
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::AggregateFilter::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::AggregateFilter::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::AggregateFilter

namespace detail::AggregateFilter
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::AggregateFilter>();
}
}  // namespace
}  // namespace detail::AggregateFilter

bool AggregateFilter::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return MonitoringFilter::is_of_type(ns, dataTypeId);
}

NodeId AggregateFilter::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId AggregateFilter::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String AggregateFilter::type_name() const
{
  return typeName;
}

void AggregateFilter::encode(StackDepth limit, Encoder& encoder) const
{

  MonitoringFilter::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AggregateFilter::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AggregateFilter::encode(limit, *this, *xml);
  }
}

void AggregateFilter::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AggregateFilter::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AggregateFilter::encode_id(limit, ns, *xml);
  }
}

void AggregateFilter::decode(StackDepth limit, Decoder& decoder)
{

  MonitoringFilter::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::AggregateFilter::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::AggregateFilter::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> AggregateFilter::clone() const
{
  return make_unique<AggregateFilter>(*this);
}

void AggregateFilter::append_fields(std::string& output, int indent) const
{
  MonitoringFilter::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "start_time=" + ua::to_string(start_time());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "aggregate_type=" + ua::to_string(aggregate_type());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "processing_interval=" + ua::to_string(processing_interval());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "aggregate_configuration=" + ua::to_string(aggregate_configuration());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "start_time=" + ua::to_string(start_time());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "aggregate_type=" + ua::to_string(aggregate_type());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "processing_interval=" + ua::to_string(processing_interval());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "aggregate_configuration=" + ua::to_string(aggregate_configuration());
}

std::string AggregateFilter::to_string(int indent) const
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

void AggregateFilter::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::AggregateFilter::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::AggregateFilter::create);
  }
}

UtcTime& AggregateFilter::start_time()
{
  return mStartTime;
}

const UtcTime& AggregateFilter::start_time() const
{
  return mStartTime;
}

NodeId& AggregateFilter::aggregate_type()
{
  return mAggregateType;
}

const NodeId& AggregateFilter::aggregate_type() const
{
  return mAggregateType;
}

Duration& AggregateFilter::processing_interval()
{
  return mProcessingInterval;
}

const Duration& AggregateFilter::processing_interval() const
{
  return mProcessingInterval;
}

AggregateConfiguration& AggregateFilter::aggregate_configuration()
{
  return mAggregateConfiguration;
}

const AggregateConfiguration& AggregateFilter::aggregate_configuration() const
{
  return mAggregateConfiguration;
}

BuiltInTypeId AggregateFilter::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::CreateMonitoredItemsResponse
{
namespace
{
void encode(StackDepth limit, const ua::CreateMonitoredItemsResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.results());
  encoder.encode(limit, value.diagnostic_infos());
}

void encode(StackDepth limit, const ua::CreateMonitoredItemsResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "Results", value.results());
  encoder.encode(limit, "DiagnosticInfos", value.diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::CreateMonitoredItemsResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.results());
  decoder.decode(limit, value.diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::CreateMonitoredItemsResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "Results", true, value.results());
  decoder.decode(limit, "DiagnosticInfos", true, value.diagnostic_infos());
}
}  // namespace
}  // namespace detail::CreateMonitoredItemsResponse

namespace detail::CreateMonitoredItemsResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::CreateMonitoredItemsResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::CreateMonitoredItemsResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::CreateMonitoredItemsResponse

namespace detail::CreateMonitoredItemsResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::CreateMonitoredItemsResponse>();
}
}  // namespace
}  // namespace detail::CreateMonitoredItemsResponse

bool CreateMonitoredItemsResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId CreateMonitoredItemsResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId CreateMonitoredItemsResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String CreateMonitoredItemsResponse::type_name() const
{
  return typeName;
}

void CreateMonitoredItemsResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CreateMonitoredItemsResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CreateMonitoredItemsResponse::encode(limit, *this, *xml);
  }
}

void CreateMonitoredItemsResponse::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CreateMonitoredItemsResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CreateMonitoredItemsResponse::encode_id(limit, ns, *xml);
  }
}

void CreateMonitoredItemsResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::CreateMonitoredItemsResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::CreateMonitoredItemsResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> CreateMonitoredItemsResponse::clone() const
{
  return make_unique<CreateMonitoredItemsResponse>(*this);
}

void CreateMonitoredItemsResponse::append_fields(std::string& output, int indent) const
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

std::string CreateMonitoredItemsResponse::to_string(int indent) const
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

void CreateMonitoredItemsResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::CreateMonitoredItemsResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::CreateMonitoredItemsResponse::create);
  }
}

ResponseHeader& CreateMonitoredItemsResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& CreateMonitoredItemsResponse::response_header() const
{
  return mResponseHeader;
}

Array<MonitoredItemCreateResult>& CreateMonitoredItemsResponse::results()
{
  return mResults;
}

const Array<MonitoredItemCreateResult>& CreateMonitoredItemsResponse::results() const
{
  return mResults;
}

Array<DiagnosticInfo>& CreateMonitoredItemsResponse::diagnostic_infos()
{
  return mDiagnosticInfos;
}

const Array<DiagnosticInfo>& CreateMonitoredItemsResponse::diagnostic_infos() const
{
  return mDiagnosticInfos;
}

BuiltInTypeId CreateMonitoredItemsResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::SetTriggeringResponse
{
namespace
{
void encode(StackDepth limit, const ua::SetTriggeringResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.add_results());
  encoder.encode(limit, value.add_diagnostic_infos());
  encoder.encode(limit, value.remove_results());
  encoder.encode(limit, value.remove_diagnostic_infos());
}

void encode(StackDepth limit, const ua::SetTriggeringResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "AddResults", value.add_results());
  encoder.encode(limit, "AddDiagnosticInfos", value.add_diagnostic_infos());
  encoder.encode(limit, "RemoveResults", value.remove_results());
  encoder.encode(limit, "RemoveDiagnosticInfos", value.remove_diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::SetTriggeringResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.add_results());
  decoder.decode(limit, value.add_diagnostic_infos());
  decoder.decode(limit, value.remove_results());
  decoder.decode(limit, value.remove_diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::SetTriggeringResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "AddResults", true, value.add_results());
  decoder.decode(limit, "AddDiagnosticInfos", true, value.add_diagnostic_infos());
  decoder.decode(limit, "RemoveResults", true, value.remove_results());
  decoder.decode(limit, "RemoveDiagnosticInfos", true, value.remove_diagnostic_infos());
}
}  // namespace
}  // namespace detail::SetTriggeringResponse

namespace detail::SetTriggeringResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::SetTriggeringResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::SetTriggeringResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::SetTriggeringResponse

namespace detail::SetTriggeringResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::SetTriggeringResponse>();
}
}  // namespace
}  // namespace detail::SetTriggeringResponse

bool SetTriggeringResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId SetTriggeringResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId SetTriggeringResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String SetTriggeringResponse::type_name() const
{
  return typeName;
}

void SetTriggeringResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SetTriggeringResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SetTriggeringResponse::encode(limit, *this, *xml);
  }
}

void SetTriggeringResponse::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SetTriggeringResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SetTriggeringResponse::encode_id(limit, ns, *xml);
  }
}

void SetTriggeringResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::SetTriggeringResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::SetTriggeringResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> SetTriggeringResponse::clone() const
{
  return make_unique<SetTriggeringResponse>(*this);
}

void SetTriggeringResponse::append_fields(std::string& output, int indent) const
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
    output += pad + "add_results=" + ua::to_string(add_results());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "add_diagnostic_infos=" + ua::to_string(add_diagnostic_infos());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "remove_results=" + ua::to_string(remove_results());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "remove_diagnostic_infos=" + ua::to_string(remove_diagnostic_infos());
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
  output += "add_results=" + ua::to_string(add_results());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "add_diagnostic_infos=" + ua::to_string(add_diagnostic_infos());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "remove_results=" + ua::to_string(remove_results());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "remove_diagnostic_infos=" + ua::to_string(remove_diagnostic_infos());
}

std::string SetTriggeringResponse::to_string(int indent) const
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

void SetTriggeringResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::SetTriggeringResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::SetTriggeringResponse::create);
  }
}

ResponseHeader& SetTriggeringResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& SetTriggeringResponse::response_header() const
{
  return mResponseHeader;
}

Array<StatusCode>& SetTriggeringResponse::add_results()
{
  return mAddResults;
}

const Array<StatusCode>& SetTriggeringResponse::add_results() const
{
  return mAddResults;
}

Array<DiagnosticInfo>& SetTriggeringResponse::add_diagnostic_infos()
{
  return mAddDiagnosticInfos;
}

const Array<DiagnosticInfo>& SetTriggeringResponse::add_diagnostic_infos() const
{
  return mAddDiagnosticInfos;
}

Array<StatusCode>& SetTriggeringResponse::remove_results()
{
  return mRemoveResults;
}

const Array<StatusCode>& SetTriggeringResponse::remove_results() const
{
  return mRemoveResults;
}

Array<DiagnosticInfo>& SetTriggeringResponse::remove_diagnostic_infos()
{
  return mRemoveDiagnosticInfos;
}

const Array<DiagnosticInfo>& SetTriggeringResponse::remove_diagnostic_infos() const
{
  return mRemoveDiagnosticInfos;
}

BuiltInTypeId SetTriggeringResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::SetPublishingModeResponse
{
namespace
{
void encode(StackDepth limit, const ua::SetPublishingModeResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.results());
  encoder.encode(limit, value.diagnostic_infos());
}

void encode(StackDepth limit, const ua::SetPublishingModeResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "Results", value.results());
  encoder.encode(limit, "DiagnosticInfos", value.diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::SetPublishingModeResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.results());
  decoder.decode(limit, value.diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::SetPublishingModeResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "Results", true, value.results());
  decoder.decode(limit, "DiagnosticInfos", true, value.diagnostic_infos());
}
}  // namespace
}  // namespace detail::SetPublishingModeResponse

namespace detail::SetPublishingModeResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::SetPublishingModeResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::SetPublishingModeResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::SetPublishingModeResponse

namespace detail::SetPublishingModeResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::SetPublishingModeResponse>();
}
}  // namespace
}  // namespace detail::SetPublishingModeResponse

bool SetPublishingModeResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId SetPublishingModeResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId SetPublishingModeResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String SetPublishingModeResponse::type_name() const
{
  return typeName;
}

void SetPublishingModeResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SetPublishingModeResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SetPublishingModeResponse::encode(limit, *this, *xml);
  }
}

void SetPublishingModeResponse::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SetPublishingModeResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SetPublishingModeResponse::encode_id(limit, ns, *xml);
  }
}

void SetPublishingModeResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::SetPublishingModeResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::SetPublishingModeResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> SetPublishingModeResponse::clone() const
{
  return make_unique<SetPublishingModeResponse>(*this);
}

void SetPublishingModeResponse::append_fields(std::string& output, int indent) const
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

std::string SetPublishingModeResponse::to_string(int indent) const
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

void SetPublishingModeResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::SetPublishingModeResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::SetPublishingModeResponse::create);
  }
}

ResponseHeader& SetPublishingModeResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& SetPublishingModeResponse::response_header() const
{
  return mResponseHeader;
}

Array<StatusCode>& SetPublishingModeResponse::results()
{
  return mResults;
}

const Array<StatusCode>& SetPublishingModeResponse::results() const
{
  return mResults;
}

Array<DiagnosticInfo>& SetPublishingModeResponse::diagnostic_infos()
{
  return mDiagnosticInfos;
}

const Array<DiagnosticInfo>& SetPublishingModeResponse::diagnostic_infos() const
{
  return mDiagnosticInfos;
}

BuiltInTypeId SetPublishingModeResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::SubscriptionAcknowledgement
{
namespace
{
void encode(StackDepth limit, const ua::SubscriptionAcknowledgement& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.subscription_id());
  encoder.encode(limit, value.sequence_number());
}

void encode(StackDepth limit, const ua::SubscriptionAcknowledgement& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "SubscriptionId", value.subscription_id());
  encoder.encode(limit, "SequenceNumber", value.sequence_number());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::SubscriptionAcknowledgement& value)
{
  decoder.decode(limit, value.subscription_id());
  decoder.decode(limit, value.sequence_number());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::SubscriptionAcknowledgement& value)
{
  decoder.decode(limit, "SubscriptionId", true, value.subscription_id());
  decoder.decode(limit, "SequenceNumber", true, value.sequence_number());
}
}  // namespace
}  // namespace detail::SubscriptionAcknowledgement

namespace detail::SubscriptionAcknowledgement
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::SubscriptionAcknowledgement::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::SubscriptionAcknowledgement::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::SubscriptionAcknowledgement

namespace detail::SubscriptionAcknowledgement
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::SubscriptionAcknowledgement>();
}
}  // namespace
}  // namespace detail::SubscriptionAcknowledgement

bool SubscriptionAcknowledgement::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId SubscriptionAcknowledgement::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId SubscriptionAcknowledgement::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String SubscriptionAcknowledgement::type_name() const
{
  return typeName;
}

void SubscriptionAcknowledgement::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SubscriptionAcknowledgement::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SubscriptionAcknowledgement::encode(limit, *this, *xml);
  }
}

void SubscriptionAcknowledgement::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SubscriptionAcknowledgement::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SubscriptionAcknowledgement::encode_id(limit, ns, *xml);
  }
}

void SubscriptionAcknowledgement::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::SubscriptionAcknowledgement::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::SubscriptionAcknowledgement::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> SubscriptionAcknowledgement::clone() const
{
  return make_unique<SubscriptionAcknowledgement>(*this);
}

void SubscriptionAcknowledgement::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "subscription_id=" + ua::to_string(subscription_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "sequence_number=" + ua::to_string(sequence_number());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "subscription_id=" + ua::to_string(subscription_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "sequence_number=" + ua::to_string(sequence_number());
}

std::string SubscriptionAcknowledgement::to_string(int indent) const
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

void SubscriptionAcknowledgement::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::SubscriptionAcknowledgement::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::SubscriptionAcknowledgement::create);
  }
}

IntegerId& SubscriptionAcknowledgement::subscription_id()
{
  return mSubscriptionId;
}

const IntegerId& SubscriptionAcknowledgement::subscription_id() const
{
  return mSubscriptionId;
}

Counter& SubscriptionAcknowledgement::sequence_number()
{
  return mSequenceNumber;
}

const Counter& SubscriptionAcknowledgement::sequence_number() const
{
  return mSequenceNumber;
}

BuiltInTypeId SubscriptionAcknowledgement::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::DeleteSubscriptionsRequest
{
namespace
{
void encode(StackDepth limit, const ua::DeleteSubscriptionsRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.subscription_ids());
}

void encode(StackDepth limit, const ua::DeleteSubscriptionsRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "SubscriptionIds", value.subscription_ids());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::DeleteSubscriptionsRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.subscription_ids());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::DeleteSubscriptionsRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "SubscriptionIds", true, value.subscription_ids());
}
}  // namespace
}  // namespace detail::DeleteSubscriptionsRequest

namespace detail::DeleteSubscriptionsRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::DeleteSubscriptionsRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::DeleteSubscriptionsRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::DeleteSubscriptionsRequest

namespace detail::DeleteSubscriptionsRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::DeleteSubscriptionsRequest>();
}
}  // namespace
}  // namespace detail::DeleteSubscriptionsRequest

bool DeleteSubscriptionsRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId DeleteSubscriptionsRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId DeleteSubscriptionsRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String DeleteSubscriptionsRequest::type_name() const
{
  return typeName;
}

void DeleteSubscriptionsRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DeleteSubscriptionsRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DeleteSubscriptionsRequest::encode(limit, *this, *xml);
  }
}

void DeleteSubscriptionsRequest::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DeleteSubscriptionsRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DeleteSubscriptionsRequest::encode_id(limit, ns, *xml);
  }
}

void DeleteSubscriptionsRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::DeleteSubscriptionsRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::DeleteSubscriptionsRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> DeleteSubscriptionsRequest::clone() const
{
  return make_unique<DeleteSubscriptionsRequest>(*this);
}

void DeleteSubscriptionsRequest::append_fields(std::string& output, int indent) const
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
}

std::string DeleteSubscriptionsRequest::to_string(int indent) const
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

void DeleteSubscriptionsRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::DeleteSubscriptionsRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::DeleteSubscriptionsRequest::create);
  }
}

RequestHeader& DeleteSubscriptionsRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& DeleteSubscriptionsRequest::request_header() const
{
  return mRequestHeader;
}

Array<IntegerId>& DeleteSubscriptionsRequest::subscription_ids()
{
  return mSubscriptionIds;
}

const Array<IntegerId>& DeleteSubscriptionsRequest::subscription_ids() const
{
  return mSubscriptionIds;
}

BuiltInTypeId DeleteSubscriptionsRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

}  // namespace ua
