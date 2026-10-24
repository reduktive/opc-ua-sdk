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

namespace detail::AdditionalParametersType
{
namespace
{
void encode(StackDepth limit, const ua::AdditionalParametersType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.parameters());
}

void encode(StackDepth limit, const ua::AdditionalParametersType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Parameters", value.parameters());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::AdditionalParametersType& value)
{
  decoder.decode(limit, value.parameters());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::AdditionalParametersType& value)
{
  decoder.decode(limit, "Parameters", true, value.parameters());
}
}  // namespace
}  // namespace detail::AdditionalParametersType

namespace detail::AdditionalParametersType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::AdditionalParametersType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::AdditionalParametersType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::AdditionalParametersType

namespace detail::AdditionalParametersType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::AdditionalParametersType>();
}
}  // namespace
}  // namespace detail::AdditionalParametersType

bool AdditionalParametersType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId AdditionalParametersType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId AdditionalParametersType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String AdditionalParametersType::type_name() const
{
  return typeName;
}

void AdditionalParametersType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AdditionalParametersType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AdditionalParametersType::encode(limit, *this, *xml);
  }
}

void AdditionalParametersType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AdditionalParametersType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AdditionalParametersType::encode_id(limit, ns, *xml);
  }
}

void AdditionalParametersType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::AdditionalParametersType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::AdditionalParametersType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> AdditionalParametersType::clone() const
{
  return make_unique<AdditionalParametersType>(*this);
}

void AdditionalParametersType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "parameters=" + ua::to_string(parameters());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "parameters=" + ua::to_string(parameters());
}

std::string AdditionalParametersType::to_string(int indent) const
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

void AdditionalParametersType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::AdditionalParametersType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::AdditionalParametersType::create);
  }
}

Array<KeyValuePair>& AdditionalParametersType::parameters()
{
  return mParameters;
}

const Array<KeyValuePair>& AdditionalParametersType::parameters() const
{
  return mParameters;
}

BuiltInTypeId AdditionalParametersType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ThreeDCartesianCoordinates
{
namespace
{
void encode(StackDepth limit, const ua::ThreeDCartesianCoordinates& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.x());
  encoder.encode(limit, value.y());
  encoder.encode(limit, value.z());
}

void encode(StackDepth limit, const ua::ThreeDCartesianCoordinates& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "X", value.x());
  encoder.encode(limit, "Y", value.y());
  encoder.encode(limit, "Z", value.z());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ThreeDCartesianCoordinates& value)
{
  decoder.decode(limit, value.x());
  decoder.decode(limit, value.y());
  decoder.decode(limit, value.z());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ThreeDCartesianCoordinates& value)
{
  decoder.decode(limit, "X", true, value.x());
  decoder.decode(limit, "Y", true, value.y());
  decoder.decode(limit, "Z", true, value.z());
}
}  // namespace
}  // namespace detail::ThreeDCartesianCoordinates

namespace detail::ThreeDCartesianCoordinates
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ThreeDCartesianCoordinates::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ThreeDCartesianCoordinates::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ThreeDCartesianCoordinates

namespace detail::ThreeDCartesianCoordinates
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ThreeDCartesianCoordinates>();
}
}  // namespace
}  // namespace detail::ThreeDCartesianCoordinates

bool ThreeDCartesianCoordinates::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return CartesianCoordinates::is_of_type(ns, dataTypeId);
}

NodeId ThreeDCartesianCoordinates::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ThreeDCartesianCoordinates::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ThreeDCartesianCoordinates::type_name() const
{
  return typeName;
}

void ThreeDCartesianCoordinates::encode(StackDepth limit, Encoder& encoder) const
{

  CartesianCoordinates::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ThreeDCartesianCoordinates::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ThreeDCartesianCoordinates::encode(limit, *this, *xml);
  }
}

void ThreeDCartesianCoordinates::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ThreeDCartesianCoordinates::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ThreeDCartesianCoordinates::encode_id(limit, ns, *xml);
  }
}

void ThreeDCartesianCoordinates::decode(StackDepth limit, Decoder& decoder)
{

  CartesianCoordinates::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ThreeDCartesianCoordinates::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ThreeDCartesianCoordinates::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ThreeDCartesianCoordinates::clone() const
{
  return make_unique<ThreeDCartesianCoordinates>(*this);
}

void ThreeDCartesianCoordinates::append_fields(std::string& output, int indent) const
{
  CartesianCoordinates::append_fields(output, indent);
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
    output += pad + "y=" + ua::to_string(y());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "z=" + ua::to_string(z());
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
  output += "y=" + ua::to_string(y());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "z=" + ua::to_string(z());
}

std::string ThreeDCartesianCoordinates::to_string(int indent) const
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

void ThreeDCartesianCoordinates::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::ThreeDCartesianCoordinates::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ThreeDCartesianCoordinates::create);
  }
}

double& ThreeDCartesianCoordinates::x()
{
  return mX;
}

const double& ThreeDCartesianCoordinates::x() const
{
  return mX;
}

double& ThreeDCartesianCoordinates::y()
{
  return mY;
}

const double& ThreeDCartesianCoordinates::y() const
{
  return mY;
}

double& ThreeDCartesianCoordinates::z()
{
  return mZ;
}

const double& ThreeDCartesianCoordinates::z() const
{
  return mZ;
}

BuiltInTypeId ThreeDCartesianCoordinates::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::LinearConversionDataType
{
namespace
{
void encode(StackDepth limit, const ua::LinearConversionDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.initial_addend());
  encoder.encode(limit, value.multiplicand());
  encoder.encode(limit, value.divisor());
  encoder.encode(limit, value.final_addend());
}

void encode(StackDepth limit, const ua::LinearConversionDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "InitialAddend", value.initial_addend());
  encoder.encode(limit, "Multiplicand", value.multiplicand());
  encoder.encode(limit, "Divisor", value.divisor());
  encoder.encode(limit, "FinalAddend", value.final_addend());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::LinearConversionDataType& value)
{
  decoder.decode(limit, value.initial_addend());
  decoder.decode(limit, value.multiplicand());
  decoder.decode(limit, value.divisor());
  decoder.decode(limit, value.final_addend());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::LinearConversionDataType& value)
{
  decoder.decode(limit, "InitialAddend", true, value.initial_addend());
  decoder.decode(limit, "Multiplicand", true, value.multiplicand());
  decoder.decode(limit, "Divisor", true, value.divisor());
  decoder.decode(limit, "FinalAddend", true, value.final_addend());
}
}  // namespace
}  // namespace detail::LinearConversionDataType

namespace detail::LinearConversionDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::LinearConversionDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::LinearConversionDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::LinearConversionDataType

namespace detail::LinearConversionDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::LinearConversionDataType>();
}
}  // namespace
}  // namespace detail::LinearConversionDataType

bool LinearConversionDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId LinearConversionDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId LinearConversionDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String LinearConversionDataType::type_name() const
{
  return typeName;
}

void LinearConversionDataType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::LinearConversionDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::LinearConversionDataType::encode(limit, *this, *xml);
  }
}

void LinearConversionDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::LinearConversionDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::LinearConversionDataType::encode_id(limit, ns, *xml);
  }
}

void LinearConversionDataType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::LinearConversionDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::LinearConversionDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> LinearConversionDataType::clone() const
{
  return make_unique<LinearConversionDataType>(*this);
}

void LinearConversionDataType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "initial_addend=" + ua::to_string(initial_addend());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "multiplicand=" + ua::to_string(multiplicand());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "divisor=" + ua::to_string(divisor());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "final_addend=" + ua::to_string(final_addend());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "initial_addend=" + ua::to_string(initial_addend());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "multiplicand=" + ua::to_string(multiplicand());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "divisor=" + ua::to_string(divisor());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "final_addend=" + ua::to_string(final_addend());
}

std::string LinearConversionDataType::to_string(int indent) const
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

void LinearConversionDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::LinearConversionDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::LinearConversionDataType::create);
  }
}

float& LinearConversionDataType::initial_addend()
{
  return mInitialAddend;
}

const float& LinearConversionDataType::initial_addend() const
{
  return mInitialAddend;
}

float& LinearConversionDataType::multiplicand()
{
  return mMultiplicand;
}

const float& LinearConversionDataType::multiplicand() const
{
  return mMultiplicand;
}

float& LinearConversionDataType::divisor()
{
  return mDivisor;
}

const float& LinearConversionDataType::divisor() const
{
  return mDivisor;
}

float& LinearConversionDataType::final_addend()
{
  return mFinalAddend;
}

const float& LinearConversionDataType::final_addend() const
{
  return mFinalAddend;
}

BuiltInTypeId LinearConversionDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ApplicationConfigurationDataType
{
namespace
{
void encode(StackDepth limit, const ua::ApplicationConfigurationDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.application_identity());
  encoder.encode(limit, value.certificate_groups());
  encoder.encode(limit, value.server_endpoints());
  encoder.encode(limit, value.client_endpoints());
  encoder.encode(limit, value.security_settings());
  encoder.encode(limit, value.user_token_settings());
  encoder.encode(limit, value.authorization_services());
}

void encode(StackDepth limit, const ua::ApplicationConfigurationDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ApplicationIdentity", value.application_identity());
  encoder.encode(limit, "CertificateGroups", value.certificate_groups());
  encoder.encode(limit, "ServerEndpoints", value.server_endpoints());
  encoder.encode(limit, "ClientEndpoints", value.client_endpoints());
  encoder.encode(limit, "SecuritySettings", value.security_settings());
  encoder.encode(limit, "UserTokenSettings", value.user_token_settings());
  encoder.encode(limit, "AuthorizationServices", value.authorization_services());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ApplicationConfigurationDataType& value)
{
  decoder.decode(limit, value.application_identity());
  decoder.decode(limit, value.certificate_groups());
  decoder.decode(limit, value.server_endpoints());
  decoder.decode(limit, value.client_endpoints());
  decoder.decode(limit, value.security_settings());
  decoder.decode(limit, value.user_token_settings());
  decoder.decode(limit, value.authorization_services());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ApplicationConfigurationDataType& value)
{
  decoder.decode(limit, "ApplicationIdentity", true, value.application_identity());
  decoder.decode(limit, "CertificateGroups", true, value.certificate_groups());
  decoder.decode(limit, "ServerEndpoints", true, value.server_endpoints());
  decoder.decode(limit, "ClientEndpoints", true, value.client_endpoints());
  decoder.decode(limit, "SecuritySettings", true, value.security_settings());
  decoder.decode(limit, "UserTokenSettings", true, value.user_token_settings());
  decoder.decode(limit, "AuthorizationServices", true, value.authorization_services());
}
}  // namespace
}  // namespace detail::ApplicationConfigurationDataType

namespace detail::ApplicationConfigurationDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ApplicationConfigurationDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ApplicationConfigurationDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ApplicationConfigurationDataType

namespace detail::ApplicationConfigurationDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ApplicationConfigurationDataType>();
}
}  // namespace
}  // namespace detail::ApplicationConfigurationDataType

bool ApplicationConfigurationDataType::is_of_type(
  const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return BaseConfigurationDataType::is_of_type(ns, dataTypeId);
}

NodeId ApplicationConfigurationDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ApplicationConfigurationDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ApplicationConfigurationDataType::type_name() const
{
  return typeName;
}

void ApplicationConfigurationDataType::encode(StackDepth limit, Encoder& encoder) const
{

  BaseConfigurationDataType::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ApplicationConfigurationDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ApplicationConfigurationDataType::encode(limit, *this, *xml);
  }
}

void ApplicationConfigurationDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ApplicationConfigurationDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ApplicationConfigurationDataType::encode_id(limit, ns, *xml);
  }
}

void ApplicationConfigurationDataType::decode(StackDepth limit, Decoder& decoder)
{

  BaseConfigurationDataType::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ApplicationConfigurationDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ApplicationConfigurationDataType::decode(limit, *xml, *this);
  }
}

void ApplicationConfigurationDataType::resolve(span<const LocaleId> locales)
{
  BaseConfigurationDataType::resolve(locales);
  mApplicationIdentity.resolve(locales);
}

unique_ptr<Structure> ApplicationConfigurationDataType::clone() const
{
  return make_unique<ApplicationConfigurationDataType>(*this);
}

void ApplicationConfigurationDataType::append_fields(std::string& output, int indent) const
{
  BaseConfigurationDataType::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "application_identity=" + ua::to_string(application_identity());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "certificate_groups=" + ua::to_string(certificate_groups());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "server_endpoints=" + ua::to_string(server_endpoints());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "client_endpoints=" + ua::to_string(client_endpoints());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "security_settings=" + ua::to_string(security_settings());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "user_token_settings=" + ua::to_string(user_token_settings());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "authorization_services=" + ua::to_string(authorization_services());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "application_identity=" + ua::to_string(application_identity());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "certificate_groups=" + ua::to_string(certificate_groups());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "server_endpoints=" + ua::to_string(server_endpoints());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "client_endpoints=" + ua::to_string(client_endpoints());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "security_settings=" + ua::to_string(security_settings());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "user_token_settings=" + ua::to_string(user_token_settings());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "authorization_services=" + ua::to_string(authorization_services());
}

std::string ApplicationConfigurationDataType::to_string(int indent) const
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

void ApplicationConfigurationDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::ApplicationConfigurationDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ApplicationConfigurationDataType::create);
  }
}

ApplicationIdentityDataType& ApplicationConfigurationDataType::application_identity()
{
  return mApplicationIdentity;
}

const ApplicationIdentityDataType& ApplicationConfigurationDataType::application_identity() const
{
  return mApplicationIdentity;
}

Array<CertificateGroupDataType>& ApplicationConfigurationDataType::certificate_groups()
{
  return mCertificateGroups;
}

const Array<CertificateGroupDataType>& ApplicationConfigurationDataType::certificate_groups() const
{
  return mCertificateGroups;
}

Array<ServerEndpointDataType>& ApplicationConfigurationDataType::server_endpoints()
{
  return mServerEndpoints;
}

const Array<ServerEndpointDataType>& ApplicationConfigurationDataType::server_endpoints() const
{
  return mServerEndpoints;
}

Array<EndpointDataType>& ApplicationConfigurationDataType::client_endpoints()
{
  return mClientEndpoints;
}

const Array<EndpointDataType>& ApplicationConfigurationDataType::client_endpoints() const
{
  return mClientEndpoints;
}

Array<SecuritySettingsDataType>& ApplicationConfigurationDataType::security_settings()
{
  return mSecuritySettings;
}

const Array<SecuritySettingsDataType>& ApplicationConfigurationDataType::security_settings() const
{
  return mSecuritySettings;
}

Array<UserTokenSettingsDataType>& ApplicationConfigurationDataType::user_token_settings()
{
  return mUserTokenSettings;
}

const Array<UserTokenSettingsDataType>& ApplicationConfigurationDataType::user_token_settings() const
{
  return mUserTokenSettings;
}

Array<AuthorizationServiceConfigurationDataType>& ApplicationConfigurationDataType::authorization_services()
{
  return mAuthorizationServices;
}

const Array<AuthorizationServiceConfigurationDataType>&
  ApplicationConfigurationDataType::authorization_services() const
{
  return mAuthorizationServices;
}

BuiltInTypeId ApplicationConfigurationDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::DataTypeSchemaHeader
{
namespace
{
void encode(StackDepth limit, const ua::DataTypeSchemaHeader& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.namespaces());
  encoder.encode(limit, value.structure_data_types());
  encoder.encode(limit, value.enum_data_types());
  encoder.encode(limit, value.simple_data_types());
}

void encode(StackDepth limit, const ua::DataTypeSchemaHeader& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Namespaces", value.namespaces());
  encoder.encode(limit, "StructureDataTypes", value.structure_data_types());
  encoder.encode(limit, "EnumDataTypes", value.enum_data_types());
  encoder.encode(limit, "SimpleDataTypes", value.simple_data_types());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::DataTypeSchemaHeader& value)
{
  decoder.decode(limit, value.namespaces());
  decoder.decode(limit, value.structure_data_types());
  decoder.decode(limit, value.enum_data_types());
  decoder.decode(limit, value.simple_data_types());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::DataTypeSchemaHeader& value)
{
  decoder.decode(limit, "Namespaces", true, value.namespaces());
  decoder.decode(limit, "StructureDataTypes", true, value.structure_data_types());
  decoder.decode(limit, "EnumDataTypes", true, value.enum_data_types());
  decoder.decode(limit, "SimpleDataTypes", true, value.simple_data_types());
}
}  // namespace
}  // namespace detail::DataTypeSchemaHeader

bool DataTypeSchemaHeader::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId DataTypeSchemaHeader::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId DataTypeSchemaHeader::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String DataTypeSchemaHeader::type_name() const
{
  return typeName;
}

void DataTypeSchemaHeader::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DataTypeSchemaHeader::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DataTypeSchemaHeader::encode(limit, *this, *xml);
  }
}

void DataTypeSchemaHeader::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  UA_UNUSED(limit);
  UA_UNUSED(ns);
  UA_UNUSED(encoder);
}

void DataTypeSchemaHeader::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::DataTypeSchemaHeader::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::DataTypeSchemaHeader::decode(limit, *xml, *this);
  }
}

void DataTypeSchemaHeader::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  for (size_t i = 0; i < mStructureDataTypes.size(); ++i)
  {
    mStructureDataTypes[i].resolve(locales);
  }
  for (size_t i = 0; i < mEnumDataTypes.size(); ++i)
  {
    mEnumDataTypes[i].resolve(locales);
  }
}

void DataTypeSchemaHeader::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "namespaces=" + ua::to_string(namespaces());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "structure_data_types=" + ua::to_string(structure_data_types());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "enum_data_types=" + ua::to_string(enum_data_types());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "simple_data_types=" + ua::to_string(simple_data_types());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "namespaces=" + ua::to_string(namespaces());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "structure_data_types=" + ua::to_string(structure_data_types());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "enum_data_types=" + ua::to_string(enum_data_types());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "simple_data_types=" + ua::to_string(simple_data_types());
}

Array<String>& DataTypeSchemaHeader::namespaces()
{
  return mNamespaces;
}

const Array<String>& DataTypeSchemaHeader::namespaces() const
{
  return mNamespaces;
}

Array<StructureDescription>& DataTypeSchemaHeader::structure_data_types()
{
  return mStructureDataTypes;
}

const Array<StructureDescription>& DataTypeSchemaHeader::structure_data_types() const
{
  return mStructureDataTypes;
}

Array<EnumDescription>& DataTypeSchemaHeader::enum_data_types()
{
  return mEnumDataTypes;
}

const Array<EnumDescription>& DataTypeSchemaHeader::enum_data_types() const
{
  return mEnumDataTypes;
}

Array<SimpleTypeDescription>& DataTypeSchemaHeader::simple_data_types()
{
  return mSimpleDataTypes;
}

const Array<SimpleTypeDescription>& DataTypeSchemaHeader::simple_data_types() const
{
  return mSimpleDataTypes;
}

BuiltInTypeId DataTypeSchemaHeader::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::UnsignedRationalNumber
{
namespace
{
void encode(StackDepth limit, const ua::UnsignedRationalNumber& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.numerator());
  encoder.encode(limit, value.denominator());
}

void encode(StackDepth limit, const ua::UnsignedRationalNumber& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Numerator", value.numerator());
  encoder.encode(limit, "Denominator", value.denominator());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::UnsignedRationalNumber& value)
{
  decoder.decode(limit, value.numerator());
  decoder.decode(limit, value.denominator());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::UnsignedRationalNumber& value)
{
  decoder.decode(limit, "Numerator", true, value.numerator());
  decoder.decode(limit, "Denominator", true, value.denominator());
}
}  // namespace
}  // namespace detail::UnsignedRationalNumber

namespace detail::UnsignedRationalNumber
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::UnsignedRationalNumber::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::UnsignedRationalNumber::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::UnsignedRationalNumber

namespace detail::UnsignedRationalNumber
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::UnsignedRationalNumber>();
}
}  // namespace
}  // namespace detail::UnsignedRationalNumber

bool UnsignedRationalNumber::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId UnsignedRationalNumber::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId UnsignedRationalNumber::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String UnsignedRationalNumber::type_name() const
{
  return typeName;
}

void UnsignedRationalNumber::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::UnsignedRationalNumber::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::UnsignedRationalNumber::encode(limit, *this, *xml);
  }
}

void UnsignedRationalNumber::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::UnsignedRationalNumber::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::UnsignedRationalNumber::encode_id(limit, ns, *xml);
  }
}

void UnsignedRationalNumber::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::UnsignedRationalNumber::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::UnsignedRationalNumber::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> UnsignedRationalNumber::clone() const
{
  return make_unique<UnsignedRationalNumber>(*this);
}

void UnsignedRationalNumber::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "numerator=" + ua::to_string(numerator());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "denominator=" + ua::to_string(denominator());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "numerator=" + ua::to_string(numerator());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "denominator=" + ua::to_string(denominator());
}

std::string UnsignedRationalNumber::to_string(int indent) const
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

void UnsignedRationalNumber::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::UnsignedRationalNumber::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::UnsignedRationalNumber::create);
  }
}

uint32_t& UnsignedRationalNumber::numerator()
{
  return mNumerator;
}

const uint32_t& UnsignedRationalNumber::numerator() const
{
  return mNumerator;
}

uint32_t& UnsignedRationalNumber::denominator()
{
  return mDenominator;
}

const uint32_t& UnsignedRationalNumber::denominator() const
{
  return mDenominator;
}

BuiltInTypeId UnsignedRationalNumber::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ReferenceListEntryDataType
{
namespace
{
void encode(StackDepth limit, const ua::ReferenceListEntryDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.reference_type());
  encoder.encode(limit, value.is_forward());
  encoder.encode(limit, value.target_node());
}

void encode(StackDepth limit, const ua::ReferenceListEntryDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ReferenceType", value.reference_type());
  encoder.encode(limit, "IsForward", value.is_forward());
  encoder.encode(limit, "TargetNode", value.target_node());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ReferenceListEntryDataType& value)
{
  decoder.decode(limit, value.reference_type());
  decoder.decode(limit, value.is_forward());
  decoder.decode(limit, value.target_node());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ReferenceListEntryDataType& value)
{
  decoder.decode(limit, "ReferenceType", true, value.reference_type());
  decoder.decode(limit, "IsForward", true, value.is_forward());
  decoder.decode(limit, "TargetNode", true, value.target_node());
}
}  // namespace
}  // namespace detail::ReferenceListEntryDataType

namespace detail::ReferenceListEntryDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ReferenceListEntryDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ReferenceListEntryDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ReferenceListEntryDataType

namespace detail::ReferenceListEntryDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ReferenceListEntryDataType>();
}
}  // namespace
}  // namespace detail::ReferenceListEntryDataType

bool ReferenceListEntryDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ReferenceListEntryDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ReferenceListEntryDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ReferenceListEntryDataType::type_name() const
{
  return typeName;
}

void ReferenceListEntryDataType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReferenceListEntryDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReferenceListEntryDataType::encode(limit, *this, *xml);
  }
}

void ReferenceListEntryDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReferenceListEntryDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReferenceListEntryDataType::encode_id(limit, ns, *xml);
  }
}

void ReferenceListEntryDataType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ReferenceListEntryDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ReferenceListEntryDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ReferenceListEntryDataType::clone() const
{
  return make_unique<ReferenceListEntryDataType>(*this);
}

void ReferenceListEntryDataType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
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

std::string ReferenceListEntryDataType::to_string(int indent) const
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

void ReferenceListEntryDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::ReferenceListEntryDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ReferenceListEntryDataType::create);
  }
}

NodeId& ReferenceListEntryDataType::reference_type()
{
  return mReferenceType;
}

const NodeId& ReferenceListEntryDataType::reference_type() const
{
  return mReferenceType;
}

bool& ReferenceListEntryDataType::is_forward()
{
  return mIsForward;
}

const bool& ReferenceListEntryDataType::is_forward() const
{
  return mIsForward;
}

ExpandedNodeId& ReferenceListEntryDataType::target_node()
{
  return mTargetNode;
}

const ExpandedNodeId& ReferenceListEntryDataType::target_node() const
{
  return mTargetNode;
}

BuiltInTypeId ReferenceListEntryDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::StructureField
{
namespace
{
void encode(StackDepth limit, const ua::StructureField& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.name());
  encoder.encode(limit, value.description());
  encoder.encode(limit, value.data_type());
  encoder.encode(limit, value.value_rank());
  encoder.encode(limit, value.array_dimensions());
  encoder.encode(limit, value.max_string_length());
  encoder.encode(limit, value.is_optional());
}

void encode(StackDepth limit, const ua::StructureField& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Name", value.name());
  encoder.encode(limit, "Description", value.description());
  encoder.encode(limit, "DataType", value.data_type());
  encoder.encode(limit, "ValueRank", value.value_rank());
  encoder.encode(limit, "ArrayDimensions", value.array_dimensions());
  encoder.encode(limit, "MaxStringLength", value.max_string_length());
  encoder.encode(limit, "IsOptional", value.is_optional());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::StructureField& value)
{
  decoder.decode(limit, value.name());
  decoder.decode(limit, value.description());
  decoder.decode(limit, value.data_type());
  decoder.decode(limit, value.value_rank());
  decoder.decode(limit, value.array_dimensions());
  decoder.decode(limit, value.max_string_length());
  decoder.decode(limit, value.is_optional());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::StructureField& value)
{
  decoder.decode(limit, "Name", true, value.name());
  decoder.decode(limit, "Description", true, value.description());
  decoder.decode(limit, "DataType", true, value.data_type());
  decoder.decode(limit, "ValueRank", true, value.value_rank());
  decoder.decode(limit, "ArrayDimensions", true, value.array_dimensions());
  decoder.decode(limit, "MaxStringLength", true, value.max_string_length());
  decoder.decode(limit, "IsOptional", true, value.is_optional());
}
}  // namespace
}  // namespace detail::StructureField

namespace detail::StructureField
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::StructureField::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::StructureField::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::StructureField

namespace detail::StructureField
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::StructureField>();
}
}  // namespace
}  // namespace detail::StructureField

bool StructureField::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId StructureField::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId StructureField::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String StructureField::type_name() const
{
  return typeName;
}

void StructureField::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::StructureField::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::StructureField::encode(limit, *this, *xml);
  }
}

void StructureField::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::StructureField::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::StructureField::encode_id(limit, ns, *xml);
  }
}

void StructureField::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::StructureField::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::StructureField::decode(limit, *xml, *this);
  }
}

void StructureField::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  mDescription = mDescription.resolve(locales);
}

unique_ptr<Structure> StructureField::clone() const
{
  return make_unique<StructureField>(*this);
}

void StructureField::append_fields(std::string& output, int indent) const
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
    output += pad + "max_string_length=" + ua::to_string(max_string_length());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "is_optional=" + ua::to_string(is_optional());
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
  output += "max_string_length=" + ua::to_string(max_string_length());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "is_optional=" + ua::to_string(is_optional());
}

std::string StructureField::to_string(int indent) const
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

void StructureField::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::StructureField::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::StructureField::create);
  }
}

String& StructureField::name()
{
  return mName;
}

const String& StructureField::name() const
{
  return mName;
}

LocalizedText& StructureField::description()
{
  return mDescription;
}

const LocalizedText& StructureField::description() const
{
  return mDescription;
}

NodeId& StructureField::data_type()
{
  return mDataType;
}

const NodeId& StructureField::data_type() const
{
  return mDataType;
}

int32_t& StructureField::value_rank()
{
  return mValueRank;
}

const int32_t& StructureField::value_rank() const
{
  return mValueRank;
}

Array<uint32_t>& StructureField::array_dimensions()
{
  return mArrayDimensions;
}

const Array<uint32_t>& StructureField::array_dimensions() const
{
  return mArrayDimensions;
}

uint32_t& StructureField::max_string_length()
{
  return mMaxStringLength;
}

const uint32_t& StructureField::max_string_length() const
{
  return mMaxStringLength;
}

bool& StructureField::is_optional()
{
  return mIsOptional;
}

const bool& StructureField::is_optional() const
{
  return mIsOptional;
}

BuiltInTypeId StructureField::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ApplicationDescription
{
namespace
{
void encode(StackDepth limit, const ua::ApplicationDescription& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.application_uri());
  encoder.encode(limit, value.product_uri());
  encoder.encode(limit, value.application_name());
  encoder.encode(limit, utils::as_int32(value.application_type()));
  encoder.encode(limit, value.gateway_server_uri());
  encoder.encode(limit, value.discovery_profile_uri());
  encoder.encode(limit, value.discovery_urls());
}

void encode(StackDepth limit, const ua::ApplicationDescription& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ApplicationUri", value.application_uri());
  encoder.encode(limit, "ProductUri", value.product_uri());
  encoder.encode(limit, "ApplicationName", value.application_name());
  encoder.encode(limit, "ApplicationType", utils::as_int32(value.application_type()));
  encoder.encode(limit, "GatewayServerUri", value.gateway_server_uri());
  encoder.encode(limit, "DiscoveryProfileUri", value.discovery_profile_uri());
  encoder.encode(limit, "DiscoveryUrls", value.discovery_urls());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ApplicationDescription& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.application_uri());
  decoder.decode(limit, value.product_uri());
  decoder.decode(limit, value.application_name());
  decoder.decode(limit, enumVal);
  value.application_type() = utils::from_underlying<ApplicationType>(enumVal);
  decoder.decode(limit, value.gateway_server_uri());
  decoder.decode(limit, value.discovery_profile_uri());
  decoder.decode(limit, value.discovery_urls());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ApplicationDescription& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "ApplicationUri", true, value.application_uri());
  decoder.decode(limit, "ProductUri", true, value.product_uri());
  decoder.decode(limit, "ApplicationName", true, value.application_name());
  decoder.decode(limit, "ApplicationType", true, enumVal);
  value.application_type() = utils::from_underlying<ApplicationType>(enumVal);
  decoder.decode(limit, "GatewayServerUri", true, value.gateway_server_uri());
  decoder.decode(limit, "DiscoveryProfileUri", true, value.discovery_profile_uri());
  decoder.decode(limit, "DiscoveryUrls", true, value.discovery_urls());
}
}  // namespace
}  // namespace detail::ApplicationDescription

namespace detail::ApplicationDescription
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ApplicationDescription::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ApplicationDescription::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ApplicationDescription

namespace detail::ApplicationDescription
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ApplicationDescription>();
}
}  // namespace
}  // namespace detail::ApplicationDescription

bool ApplicationDescription::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ApplicationDescription::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ApplicationDescription::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ApplicationDescription::type_name() const
{
  return typeName;
}

void ApplicationDescription::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ApplicationDescription::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ApplicationDescription::encode(limit, *this, *xml);
  }
}

void ApplicationDescription::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ApplicationDescription::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ApplicationDescription::encode_id(limit, ns, *xml);
  }
}

void ApplicationDescription::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ApplicationDescription::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ApplicationDescription::decode(limit, *xml, *this);
  }
}

void ApplicationDescription::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  mApplicationName = mApplicationName.resolve(locales);
}

unique_ptr<Structure> ApplicationDescription::clone() const
{
  return make_unique<ApplicationDescription>(*this);
}

void ApplicationDescription::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
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
    output += pad + "product_uri=" + ua::to_string(product_uri());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "application_name=" + ua::to_string(application_name());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "application_type=" + ua::to_string(utils::as_int32(application_type()));
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "gateway_server_uri=" + ua::to_string(gateway_server_uri());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "discovery_profile_uri=" + ua::to_string(discovery_profile_uri());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "discovery_urls=" + ua::to_string(discovery_urls());
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
  output += "product_uri=" + ua::to_string(product_uri());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "application_name=" + ua::to_string(application_name());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "application_type=" + ua::to_string(utils::as_int32(application_type()));
  if (!output.empty())
  {
    output += ", ";
  }
  output += "gateway_server_uri=" + ua::to_string(gateway_server_uri());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "discovery_profile_uri=" + ua::to_string(discovery_profile_uri());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "discovery_urls=" + ua::to_string(discovery_urls());
}

std::string ApplicationDescription::to_string(int indent) const
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

void ApplicationDescription::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ApplicationDescription::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ApplicationDescription::create);
  }
}

String& ApplicationDescription::application_uri()
{
  return mApplicationUri;
}

const String& ApplicationDescription::application_uri() const
{
  return mApplicationUri;
}

String& ApplicationDescription::product_uri()
{
  return mProductUri;
}

const String& ApplicationDescription::product_uri() const
{
  return mProductUri;
}

LocalizedText& ApplicationDescription::application_name()
{
  return mApplicationName;
}

const LocalizedText& ApplicationDescription::application_name() const
{
  return mApplicationName;
}

ApplicationType& ApplicationDescription::application_type()
{
  return mApplicationType;
}

const ApplicationType& ApplicationDescription::application_type() const
{
  return mApplicationType;
}

String& ApplicationDescription::gateway_server_uri()
{
  return mGatewayServerUri;
}

const String& ApplicationDescription::gateway_server_uri() const
{
  return mGatewayServerUri;
}

String& ApplicationDescription::discovery_profile_uri()
{
  return mDiscoveryProfileUri;
}

const String& ApplicationDescription::discovery_profile_uri() const
{
  return mDiscoveryProfileUri;
}

Array<String>& ApplicationDescription::discovery_urls()
{
  return mDiscoveryUrls;
}

const Array<String>& ApplicationDescription::discovery_urls() const
{
  return mDiscoveryUrls;
}

BuiltInTypeId ApplicationDescription::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::UserIdentityToken
{
namespace
{
void encode(StackDepth limit, const ua::UserIdentityToken& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.policy_id());
}

void encode(StackDepth limit, const ua::UserIdentityToken& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "PolicyId", value.policy_id());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::UserIdentityToken& value)
{
  decoder.decode(limit, value.policy_id());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::UserIdentityToken& value)
{
  decoder.decode(limit, "PolicyId", true, value.policy_id());
}
}  // namespace
}  // namespace detail::UserIdentityToken

bool UserIdentityToken::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId UserIdentityToken::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId UserIdentityToken::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String UserIdentityToken::type_name() const
{
  return typeName;
}

void UserIdentityToken::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::UserIdentityToken::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::UserIdentityToken::encode(limit, *this, *xml);
  }
}

void UserIdentityToken::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  UA_UNUSED(limit);
  UA_UNUSED(ns);
  UA_UNUSED(encoder);
}

void UserIdentityToken::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::UserIdentityToken::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::UserIdentityToken::decode(limit, *xml, *this);
  }
}

void UserIdentityToken::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "policy_id=" + ua::to_string(policy_id());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "policy_id=" + ua::to_string(policy_id());
}

String& UserIdentityToken::policy_id()
{
  return mPolicyId;
}

const String& UserIdentityToken::policy_id() const
{
  return mPolicyId;
}

BuiltInTypeId UserIdentityToken::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::DeleteReferencesItem
{
namespace
{
void encode(StackDepth limit, const ua::DeleteReferencesItem& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.source_node_id());
  encoder.encode(limit, value.reference_type_id());
  encoder.encode(limit, value.is_forward());
  encoder.encode(limit, value.target_node_id());
  encoder.encode(limit, value.delete_bidirectional());
}

void encode(StackDepth limit, const ua::DeleteReferencesItem& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "SourceNodeId", value.source_node_id());
  encoder.encode(limit, "ReferenceTypeId", value.reference_type_id());
  encoder.encode(limit, "IsForward", value.is_forward());
  encoder.encode(limit, "TargetNodeId", value.target_node_id());
  encoder.encode(limit, "DeleteBidirectional", value.delete_bidirectional());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::DeleteReferencesItem& value)
{
  decoder.decode(limit, value.source_node_id());
  decoder.decode(limit, value.reference_type_id());
  decoder.decode(limit, value.is_forward());
  decoder.decode(limit, value.target_node_id());
  decoder.decode(limit, value.delete_bidirectional());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::DeleteReferencesItem& value)
{
  decoder.decode(limit, "SourceNodeId", true, value.source_node_id());
  decoder.decode(limit, "ReferenceTypeId", true, value.reference_type_id());
  decoder.decode(limit, "IsForward", true, value.is_forward());
  decoder.decode(limit, "TargetNodeId", true, value.target_node_id());
  decoder.decode(limit, "DeleteBidirectional", true, value.delete_bidirectional());
}
}  // namespace
}  // namespace detail::DeleteReferencesItem

namespace detail::DeleteReferencesItem
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::DeleteReferencesItem::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::DeleteReferencesItem::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::DeleteReferencesItem

namespace detail::DeleteReferencesItem
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::DeleteReferencesItem>();
}
}  // namespace
}  // namespace detail::DeleteReferencesItem

bool DeleteReferencesItem::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId DeleteReferencesItem::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId DeleteReferencesItem::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String DeleteReferencesItem::type_name() const
{
  return typeName;
}

void DeleteReferencesItem::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DeleteReferencesItem::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DeleteReferencesItem::encode(limit, *this, *xml);
  }
}

void DeleteReferencesItem::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DeleteReferencesItem::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DeleteReferencesItem::encode_id(limit, ns, *xml);
  }
}

void DeleteReferencesItem::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::DeleteReferencesItem::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::DeleteReferencesItem::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> DeleteReferencesItem::clone() const
{
  return make_unique<DeleteReferencesItem>(*this);
}

void DeleteReferencesItem::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "source_node_id=" + ua::to_string(source_node_id());
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
    output += pad + "target_node_id=" + ua::to_string(target_node_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "delete_bidirectional=" + ua::to_string(delete_bidirectional());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "source_node_id=" + ua::to_string(source_node_id());
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
  output += "target_node_id=" + ua::to_string(target_node_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "delete_bidirectional=" + ua::to_string(delete_bidirectional());
}

std::string DeleteReferencesItem::to_string(int indent) const
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

void DeleteReferencesItem::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::DeleteReferencesItem::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::DeleteReferencesItem::create);
  }
}

NodeId& DeleteReferencesItem::source_node_id()
{
  return mSourceNodeId;
}

const NodeId& DeleteReferencesItem::source_node_id() const
{
  return mSourceNodeId;
}

NodeId& DeleteReferencesItem::reference_type_id()
{
  return mReferenceTypeId;
}

const NodeId& DeleteReferencesItem::reference_type_id() const
{
  return mReferenceTypeId;
}

bool& DeleteReferencesItem::is_forward()
{
  return mIsForward;
}

const bool& DeleteReferencesItem::is_forward() const
{
  return mIsForward;
}

ExpandedNodeId& DeleteReferencesItem::target_node_id()
{
  return mTargetNodeId;
}

const ExpandedNodeId& DeleteReferencesItem::target_node_id() const
{
  return mTargetNodeId;
}

bool& DeleteReferencesItem::delete_bidirectional()
{
  return mDeleteBidirectional;
}

const bool& DeleteReferencesItem::delete_bidirectional() const
{
  return mDeleteBidirectional;
}

BuiltInTypeId DeleteReferencesItem::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::LiteralOperand
{
namespace
{
void encode(StackDepth limit, const ua::LiteralOperand& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.value());
}

void encode(StackDepth limit, const ua::LiteralOperand& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Value", value.value());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::LiteralOperand& value)
{
  decoder.decode(limit, value.value());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::LiteralOperand& value)
{
  decoder.decode(limit, "Value", true, value.value());
}
}  // namespace
}  // namespace detail::LiteralOperand

namespace detail::LiteralOperand
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::LiteralOperand::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::LiteralOperand::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::LiteralOperand

namespace detail::LiteralOperand
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::LiteralOperand>();
}
}  // namespace
}  // namespace detail::LiteralOperand

bool LiteralOperand::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return FilterOperand::is_of_type(ns, dataTypeId);
}

NodeId LiteralOperand::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId LiteralOperand::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String LiteralOperand::type_name() const
{
  return typeName;
}

void LiteralOperand::encode(StackDepth limit, Encoder& encoder) const
{

  FilterOperand::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::LiteralOperand::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::LiteralOperand::encode(limit, *this, *xml);
  }
}

void LiteralOperand::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::LiteralOperand::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::LiteralOperand::encode_id(limit, ns, *xml);
  }
}

void LiteralOperand::decode(StackDepth limit, Decoder& decoder)
{

  FilterOperand::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::LiteralOperand::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::LiteralOperand::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> LiteralOperand::clone() const
{
  return make_unique<LiteralOperand>(*this);
}

void LiteralOperand::append_fields(std::string& output, int indent) const
{
  FilterOperand::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
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
  output += "value=" + ua::to_string(value());
}

std::string LiteralOperand::to_string(int indent) const
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

void LiteralOperand::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::LiteralOperand::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::LiteralOperand::create);
  }
}

Variant& LiteralOperand::value()
{
  return mValue;
}

const Variant& LiteralOperand::value() const
{
  return mValue;
}

BuiltInTypeId LiteralOperand::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::AggregateConfiguration
{
namespace
{
void encode(StackDepth limit, const ua::AggregateConfiguration& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.use_server_capabilities_defaults());
  encoder.encode(limit, value.treat_uncertain_as_bad());
  encoder.encode(limit, value.percent_data_bad());
  encoder.encode(limit, value.percent_data_good());
  encoder.encode(limit, value.use_sloped_extrapolation());
}

void encode(StackDepth limit, const ua::AggregateConfiguration& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "UseServerCapabilitiesDefaults", value.use_server_capabilities_defaults());
  encoder.encode(limit, "TreatUncertainAsBad", value.treat_uncertain_as_bad());
  encoder.encode(limit, "PercentDataBad", value.percent_data_bad());
  encoder.encode(limit, "PercentDataGood", value.percent_data_good());
  encoder.encode(limit, "UseSlopedExtrapolation", value.use_sloped_extrapolation());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::AggregateConfiguration& value)
{
  decoder.decode(limit, value.use_server_capabilities_defaults());
  decoder.decode(limit, value.treat_uncertain_as_bad());
  decoder.decode(limit, value.percent_data_bad());
  decoder.decode(limit, value.percent_data_good());
  decoder.decode(limit, value.use_sloped_extrapolation());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::AggregateConfiguration& value)
{
  decoder.decode(limit, "UseServerCapabilitiesDefaults", true, value.use_server_capabilities_defaults());
  decoder.decode(limit, "TreatUncertainAsBad", true, value.treat_uncertain_as_bad());
  decoder.decode(limit, "PercentDataBad", true, value.percent_data_bad());
  decoder.decode(limit, "PercentDataGood", true, value.percent_data_good());
  decoder.decode(limit, "UseSlopedExtrapolation", true, value.use_sloped_extrapolation());
}
}  // namespace
}  // namespace detail::AggregateConfiguration

namespace detail::AggregateConfiguration
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::AggregateConfiguration::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::AggregateConfiguration::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::AggregateConfiguration

namespace detail::AggregateConfiguration
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::AggregateConfiguration>();
}
}  // namespace
}  // namespace detail::AggregateConfiguration

bool AggregateConfiguration::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId AggregateConfiguration::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId AggregateConfiguration::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String AggregateConfiguration::type_name() const
{
  return typeName;
}

void AggregateConfiguration::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AggregateConfiguration::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AggregateConfiguration::encode(limit, *this, *xml);
  }
}

void AggregateConfiguration::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AggregateConfiguration::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AggregateConfiguration::encode_id(limit, ns, *xml);
  }
}

void AggregateConfiguration::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::AggregateConfiguration::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::AggregateConfiguration::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> AggregateConfiguration::clone() const
{
  return make_unique<AggregateConfiguration>(*this);
}

void AggregateConfiguration::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "use_server_capabilities_defaults=" + ua::to_string(use_server_capabilities_defaults());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "treat_uncertain_as_bad=" + ua::to_string(treat_uncertain_as_bad());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "percent_data_bad=" + ua::to_string(percent_data_bad());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "percent_data_good=" + ua::to_string(percent_data_good());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "use_sloped_extrapolation=" + ua::to_string(use_sloped_extrapolation());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "use_server_capabilities_defaults=" + ua::to_string(use_server_capabilities_defaults());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "treat_uncertain_as_bad=" + ua::to_string(treat_uncertain_as_bad());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "percent_data_bad=" + ua::to_string(percent_data_bad());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "percent_data_good=" + ua::to_string(percent_data_good());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "use_sloped_extrapolation=" + ua::to_string(use_sloped_extrapolation());
}

std::string AggregateConfiguration::to_string(int indent) const
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

void AggregateConfiguration::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::AggregateConfiguration::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::AggregateConfiguration::create);
  }
}

bool& AggregateConfiguration::use_server_capabilities_defaults()
{
  return mUseServerCapabilitiesDefaults;
}

const bool& AggregateConfiguration::use_server_capabilities_defaults() const
{
  return mUseServerCapabilitiesDefaults;
}

bool& AggregateConfiguration::treat_uncertain_as_bad()
{
  return mTreatUncertainAsBad;
}

const bool& AggregateConfiguration::treat_uncertain_as_bad() const
{
  return mTreatUncertainAsBad;
}

uint8_t& AggregateConfiguration::percent_data_bad()
{
  return mPercentDataBad;
}

const uint8_t& AggregateConfiguration::percent_data_bad() const
{
  return mPercentDataBad;
}

uint8_t& AggregateConfiguration::percent_data_good()
{
  return mPercentDataGood;
}

const uint8_t& AggregateConfiguration::percent_data_good() const
{
  return mPercentDataGood;
}

bool& AggregateConfiguration::use_sloped_extrapolation()
{
  return mUseSlopedExtrapolation;
}

const bool& AggregateConfiguration::use_sloped_extrapolation() const
{
  return mUseSlopedExtrapolation;
}

BuiltInTypeId AggregateConfiguration::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ServerStatusDataType
{
namespace
{
void encode(StackDepth limit, const ua::ServerStatusDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.start_time());
  encoder.encode(limit, value.current_time());
  encoder.encode(limit, utils::as_int32(value.state()));
  encoder.encode(limit, value.build_info());
  encoder.encode(limit, value.seconds_till_shutdown());
  encoder.encode(limit, value.shutdown_reason());
}

void encode(StackDepth limit, const ua::ServerStatusDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "StartTime", value.start_time());
  encoder.encode(limit, "CurrentTime", value.current_time());
  encoder.encode(limit, "State", utils::as_int32(value.state()));
  encoder.encode(limit, "BuildInfo", value.build_info());
  encoder.encode(limit, "SecondsTillShutdown", value.seconds_till_shutdown());
  encoder.encode(limit, "ShutdownReason", value.shutdown_reason());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ServerStatusDataType& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.start_time());
  decoder.decode(limit, value.current_time());
  decoder.decode(limit, enumVal);
  value.state() = utils::from_underlying<ServerState>(enumVal);
  decoder.decode(limit, value.build_info());
  decoder.decode(limit, value.seconds_till_shutdown());
  decoder.decode(limit, value.shutdown_reason());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ServerStatusDataType& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "StartTime", true, value.start_time());
  decoder.decode(limit, "CurrentTime", true, value.current_time());
  decoder.decode(limit, "State", true, enumVal);
  value.state() = utils::from_underlying<ServerState>(enumVal);
  decoder.decode(limit, "BuildInfo", true, value.build_info());
  decoder.decode(limit, "SecondsTillShutdown", true, value.seconds_till_shutdown());
  decoder.decode(limit, "ShutdownReason", true, value.shutdown_reason());
}
}  // namespace
}  // namespace detail::ServerStatusDataType

namespace detail::ServerStatusDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ServerStatusDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ServerStatusDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ServerStatusDataType

namespace detail::ServerStatusDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ServerStatusDataType>();
}
}  // namespace
}  // namespace detail::ServerStatusDataType

bool ServerStatusDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ServerStatusDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ServerStatusDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ServerStatusDataType::type_name() const
{
  return typeName;
}

void ServerStatusDataType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ServerStatusDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ServerStatusDataType::encode(limit, *this, *xml);
  }
}

void ServerStatusDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ServerStatusDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ServerStatusDataType::encode_id(limit, ns, *xml);
  }
}

void ServerStatusDataType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ServerStatusDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ServerStatusDataType::decode(limit, *xml, *this);
  }
}

void ServerStatusDataType::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  mShutdownReason = mShutdownReason.resolve(locales);
}

unique_ptr<Structure> ServerStatusDataType::clone() const
{
  return make_unique<ServerStatusDataType>(*this);
}

void ServerStatusDataType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
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
    output += pad + "current_time=" + ua::to_string(current_time());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "state=" + ua::to_string(utils::as_int32(state()));
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "build_info=" + ua::to_string(build_info());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "seconds_till_shutdown=" + ua::to_string(seconds_till_shutdown());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "shutdown_reason=" + ua::to_string(shutdown_reason());
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
  output += "current_time=" + ua::to_string(current_time());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "state=" + ua::to_string(utils::as_int32(state()));
  if (!output.empty())
  {
    output += ", ";
  }
  output += "build_info=" + ua::to_string(build_info());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "seconds_till_shutdown=" + ua::to_string(seconds_till_shutdown());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "shutdown_reason=" + ua::to_string(shutdown_reason());
}

std::string ServerStatusDataType::to_string(int indent) const
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

void ServerStatusDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ServerStatusDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ServerStatusDataType::create);
  }
}

UtcTime& ServerStatusDataType::start_time()
{
  return mStartTime;
}

const UtcTime& ServerStatusDataType::start_time() const
{
  return mStartTime;
}

UtcTime& ServerStatusDataType::current_time()
{
  return mCurrentTime;
}

const UtcTime& ServerStatusDataType::current_time() const
{
  return mCurrentTime;
}

ServerState& ServerStatusDataType::state()
{
  return mState;
}

const ServerState& ServerStatusDataType::state() const
{
  return mState;
}

BuildInfo& ServerStatusDataType::build_info()
{
  return mBuildInfo;
}

const BuildInfo& ServerStatusDataType::build_info() const
{
  return mBuildInfo;
}

uint32_t& ServerStatusDataType::seconds_till_shutdown()
{
  return mSecondsTillShutdown;
}

const uint32_t& ServerStatusDataType::seconds_till_shutdown() const
{
  return mSecondsTillShutdown;
}

LocalizedText& ServerStatusDataType::shutdown_reason()
{
  return mShutdownReason;
}

const LocalizedText& ServerStatusDataType::shutdown_reason() const
{
  return mShutdownReason;
}

BuiltInTypeId ServerStatusDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::Range
{
namespace
{
void encode(StackDepth limit, const ua::Range& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.low());
  encoder.encode(limit, value.high());
}

void encode(StackDepth limit, const ua::Range& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Low", value.low());
  encoder.encode(limit, "High", value.high());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::Range& value)
{
  decoder.decode(limit, value.low());
  decoder.decode(limit, value.high());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::Range& value)
{
  decoder.decode(limit, "Low", true, value.low());
  decoder.decode(limit, "High", true, value.high());
}
}  // namespace
}  // namespace detail::Range

namespace detail::Range
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::Range::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::Range::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::Range

namespace detail::Range
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::Range>();
}
}  // namespace
}  // namespace detail::Range

bool Range::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId Range::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId Range::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String Range::type_name() const
{
  return typeName;
}

void Range::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::Range::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::Range::encode(limit, *this, *xml);
  }
}

void Range::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::Range::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::Range::encode_id(limit, ns, *xml);
  }
}

void Range::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::Range::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::Range::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> Range::clone() const
{
  return make_unique<Range>(*this);
}

void Range::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "low=" + ua::to_string(low());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "high=" + ua::to_string(high());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "low=" + ua::to_string(low());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "high=" + ua::to_string(high());
}

std::string Range::to_string(int indent) const
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

void Range::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::Range::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::Range::create);
  }
}

double& Range::low()
{
  return mLow;
}

const double& Range::low() const
{
  return mLow;
}

double& Range::high()
{
  return mHigh;
}

const double& Range::high() const
{
  return mHigh;
}

BuiltInTypeId Range::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::Annotation
{
namespace
{
void encode(StackDepth limit, const ua::Annotation& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.message());
  encoder.encode(limit, value.user_name());
  encoder.encode(limit, value.annotation_time());
}

void encode(StackDepth limit, const ua::Annotation& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Message", value.message());
  encoder.encode(limit, "UserName", value.user_name());
  encoder.encode(limit, "AnnotationTime", value.annotation_time());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::Annotation& value)
{
  decoder.decode(limit, value.message());
  decoder.decode(limit, value.user_name());
  decoder.decode(limit, value.annotation_time());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::Annotation& value)
{
  decoder.decode(limit, "Message", true, value.message());
  decoder.decode(limit, "UserName", true, value.user_name());
  decoder.decode(limit, "AnnotationTime", true, value.annotation_time());
}
}  // namespace
}  // namespace detail::Annotation

namespace detail::Annotation
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::Annotation::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::Annotation::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::Annotation

namespace detail::Annotation
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::Annotation>();
}
}  // namespace
}  // namespace detail::Annotation

bool Annotation::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId Annotation::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId Annotation::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String Annotation::type_name() const
{
  return typeName;
}

void Annotation::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::Annotation::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::Annotation::encode(limit, *this, *xml);
  }
}

void Annotation::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::Annotation::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::Annotation::encode_id(limit, ns, *xml);
  }
}

void Annotation::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::Annotation::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::Annotation::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> Annotation::clone() const
{
  return make_unique<Annotation>(*this);
}

void Annotation::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "message=" + ua::to_string(message());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "user_name=" + ua::to_string(user_name());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "annotation_time=" + ua::to_string(annotation_time());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "message=" + ua::to_string(message());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "user_name=" + ua::to_string(user_name());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "annotation_time=" + ua::to_string(annotation_time());
}

std::string Annotation::to_string(int indent) const
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

void Annotation::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::Annotation::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::Annotation::create);
  }
}

String& Annotation::message()
{
  return mMessage;
}

const String& Annotation::message() const
{
  return mMessage;
}

String& Annotation::user_name()
{
  return mUserName;
}

const String& Annotation::user_name() const
{
  return mUserName;
}

UtcTime& Annotation::annotation_time()
{
  return mAnnotationTime;
}

const UtcTime& Annotation::annotation_time() const
{
  return mAnnotationTime;
}

BuiltInTypeId Annotation::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::FindServersResponse
{
namespace
{
void encode(StackDepth limit, const ua::FindServersResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.servers());
}

void encode(StackDepth limit, const ua::FindServersResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "Servers", value.servers());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::FindServersResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.servers());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::FindServersResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "Servers", true, value.servers());
}
}  // namespace
}  // namespace detail::FindServersResponse

namespace detail::FindServersResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::FindServersResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::FindServersResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::FindServersResponse

namespace detail::FindServersResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::FindServersResponse>();
}
}  // namespace
}  // namespace detail::FindServersResponse

bool FindServersResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId FindServersResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId FindServersResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String FindServersResponse::type_name() const
{
  return typeName;
}

void FindServersResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::FindServersResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::FindServersResponse::encode(limit, *this, *xml);
  }
}

void FindServersResponse::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::FindServersResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::FindServersResponse::encode_id(limit, ns, *xml);
  }
}

void FindServersResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::FindServersResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::FindServersResponse::decode(limit, *xml, *this);
  }
}

void FindServersResponse::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  for (size_t i = 0; i < mServers.size(); ++i)
  {
    mServers[i].resolve(locales);
  }
}

unique_ptr<Structure> FindServersResponse::clone() const
{
  return make_unique<FindServersResponse>(*this);
}

void FindServersResponse::append_fields(std::string& output, int indent) const
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
    output += pad + "servers=" + ua::to_string(servers());
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
  output += "servers=" + ua::to_string(servers());
}

std::string FindServersResponse::to_string(int indent) const
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

void FindServersResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::FindServersResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::FindServersResponse::create);
  }
}

ResponseHeader& FindServersResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& FindServersResponse::response_header() const
{
  return mResponseHeader;
}

Array<ApplicationDescription>& FindServersResponse::servers()
{
  return mServers;
}

const Array<ApplicationDescription>& FindServersResponse::servers() const
{
  return mServers;
}

BuiltInTypeId FindServersResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::RegisterServer2Response
{
namespace
{
void encode(StackDepth limit, const ua::RegisterServer2Response& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.configuration_results());
  encoder.encode(limit, value.diagnostic_infos());
}

void encode(StackDepth limit, const ua::RegisterServer2Response& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "ConfigurationResults", value.configuration_results());
  encoder.encode(limit, "DiagnosticInfos", value.diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::RegisterServer2Response& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.configuration_results());
  decoder.decode(limit, value.diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::RegisterServer2Response& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "ConfigurationResults", true, value.configuration_results());
  decoder.decode(limit, "DiagnosticInfos", true, value.diagnostic_infos());
}
}  // namespace
}  // namespace detail::RegisterServer2Response

namespace detail::RegisterServer2Response
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::RegisterServer2Response::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::RegisterServer2Response::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::RegisterServer2Response

namespace detail::RegisterServer2Response
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::RegisterServer2Response>();
}
}  // namespace
}  // namespace detail::RegisterServer2Response

bool RegisterServer2Response::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId RegisterServer2Response::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId RegisterServer2Response::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String RegisterServer2Response::type_name() const
{
  return typeName;
}

void RegisterServer2Response::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RegisterServer2Response::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RegisterServer2Response::encode(limit, *this, *xml);
  }
}

void RegisterServer2Response::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RegisterServer2Response::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RegisterServer2Response::encode_id(limit, ns, *xml);
  }
}

void RegisterServer2Response::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::RegisterServer2Response::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::RegisterServer2Response::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> RegisterServer2Response::clone() const
{
  return make_unique<RegisterServer2Response>(*this);
}

void RegisterServer2Response::append_fields(std::string& output, int indent) const
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
    output += pad + "configuration_results=" + ua::to_string(configuration_results());
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
  output += "configuration_results=" + ua::to_string(configuration_results());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "diagnostic_infos=" + ua::to_string(diagnostic_infos());
}

std::string RegisterServer2Response::to_string(int indent) const
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

void RegisterServer2Response::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::RegisterServer2Response::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::RegisterServer2Response::create);
  }
}

ResponseHeader& RegisterServer2Response::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& RegisterServer2Response::response_header() const
{
  return mResponseHeader;
}

Array<StatusCode>& RegisterServer2Response::configuration_results()
{
  return mConfigurationResults;
}

const Array<StatusCode>& RegisterServer2Response::configuration_results() const
{
  return mConfigurationResults;
}

Array<DiagnosticInfo>& RegisterServer2Response::diagnostic_infos()
{
  return mDiagnosticInfos;
}

const Array<DiagnosticInfo>& RegisterServer2Response::diagnostic_infos() const
{
  return mDiagnosticInfos;
}

BuiltInTypeId RegisterServer2Response::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::CreateSessionResponse
{
namespace
{
void encode(StackDepth limit, const ua::CreateSessionResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.session_id());
  encoder.encode(limit, value.authentication_token());
  encoder.encode(limit, value.revised_session_timeout());
  encoder.encode(limit, value.server_nonce());
  encoder.encode(limit, value.server_certificate());
  encoder.encode(limit, value.server_endpoints());
  encoder.encode(limit, value.server_software_certificates());
  encoder.encode(limit, value.server_signature());
  encoder.encode(limit, value.max_request_message_size());
}

void encode(StackDepth limit, const ua::CreateSessionResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "SessionId", value.session_id());
  encoder.encode(limit, "AuthenticationToken", value.authentication_token());
  encoder.encode(limit, "RevisedSessionTimeout", value.revised_session_timeout());
  encoder.encode(limit, "ServerNonce", value.server_nonce());
  encoder.encode(limit, "ServerCertificate", value.server_certificate());
  encoder.encode(limit, "ServerEndpoints", value.server_endpoints());
  encoder.encode(limit, "ServerSoftwareCertificates", value.server_software_certificates());
  encoder.encode(limit, "ServerSignature", value.server_signature());
  encoder.encode(limit, "MaxRequestMessageSize", value.max_request_message_size());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::CreateSessionResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.session_id());
  decoder.decode(limit, value.authentication_token());
  decoder.decode(limit, value.revised_session_timeout());
  decoder.decode(limit, value.server_nonce());
  decoder.decode(limit, value.server_certificate());
  decoder.decode(limit, value.server_endpoints());
  decoder.decode(limit, value.server_software_certificates());
  decoder.decode(limit, value.server_signature());
  decoder.decode(limit, value.max_request_message_size());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::CreateSessionResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "SessionId", true, value.session_id());
  decoder.decode(limit, "AuthenticationToken", true, value.authentication_token());
  decoder.decode(limit, "RevisedSessionTimeout", true, value.revised_session_timeout());
  decoder.decode(limit, "ServerNonce", true, value.server_nonce());
  decoder.decode(limit, "ServerCertificate", true, value.server_certificate());
  decoder.decode(limit, "ServerEndpoints", true, value.server_endpoints());
  decoder.decode(limit, "ServerSoftwareCertificates", true, value.server_software_certificates());
  decoder.decode(limit, "ServerSignature", true, value.server_signature());
  decoder.decode(limit, "MaxRequestMessageSize", true, value.max_request_message_size());
}
}  // namespace
}  // namespace detail::CreateSessionResponse

namespace detail::CreateSessionResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::CreateSessionResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::CreateSessionResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::CreateSessionResponse

namespace detail::CreateSessionResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::CreateSessionResponse>();
}
}  // namespace
}  // namespace detail::CreateSessionResponse

bool CreateSessionResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId CreateSessionResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId CreateSessionResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String CreateSessionResponse::type_name() const
{
  return typeName;
}

void CreateSessionResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CreateSessionResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CreateSessionResponse::encode(limit, *this, *xml);
  }
}

void CreateSessionResponse::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CreateSessionResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CreateSessionResponse::encode_id(limit, ns, *xml);
  }
}

void CreateSessionResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::CreateSessionResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::CreateSessionResponse::decode(limit, *xml, *this);
  }
}

void CreateSessionResponse::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  for (size_t i = 0; i < mServerEndpoints.size(); ++i)
  {
    mServerEndpoints[i].resolve(locales);
  }
}

unique_ptr<Structure> CreateSessionResponse::clone() const
{
  return make_unique<CreateSessionResponse>(*this);
}

void CreateSessionResponse::append_fields(std::string& output, int indent) const
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
    output += pad + "session_id=" + ua::to_string(session_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "authentication_token=" + ua::to_string(authentication_token());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "revised_session_timeout=" + ua::to_string(revised_session_timeout());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "server_nonce=" + ua::to_string(server_nonce());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "server_certificate=" + ua::to_string(server_certificate());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "server_endpoints=" + ua::to_string(server_endpoints());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "server_software_certificates=" + ua::to_string(server_software_certificates());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "server_signature=" + ua::to_string(server_signature());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "max_request_message_size=" + ua::to_string(max_request_message_size());
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
  output += "session_id=" + ua::to_string(session_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "authentication_token=" + ua::to_string(authentication_token());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "revised_session_timeout=" + ua::to_string(revised_session_timeout());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "server_nonce=" + ua::to_string(server_nonce());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "server_certificate=" + ua::to_string(server_certificate());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "server_endpoints=" + ua::to_string(server_endpoints());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "server_software_certificates=" + ua::to_string(server_software_certificates());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "server_signature=" + ua::to_string(server_signature());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "max_request_message_size=" + ua::to_string(max_request_message_size());
}

std::string CreateSessionResponse::to_string(int indent) const
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

void CreateSessionResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::CreateSessionResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::CreateSessionResponse::create);
  }
}

ResponseHeader& CreateSessionResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& CreateSessionResponse::response_header() const
{
  return mResponseHeader;
}

NodeId& CreateSessionResponse::session_id()
{
  return mSessionId;
}

const NodeId& CreateSessionResponse::session_id() const
{
  return mSessionId;
}

SessionAuthenticationToken& CreateSessionResponse::authentication_token()
{
  return mAuthenticationToken;
}

const SessionAuthenticationToken& CreateSessionResponse::authentication_token() const
{
  return mAuthenticationToken;
}

Duration& CreateSessionResponse::revised_session_timeout()
{
  return mRevisedSessionTimeout;
}

const Duration& CreateSessionResponse::revised_session_timeout() const
{
  return mRevisedSessionTimeout;
}

ByteString& CreateSessionResponse::server_nonce()
{
  return mServerNonce;
}

const ByteString& CreateSessionResponse::server_nonce() const
{
  return mServerNonce;
}

ApplicationInstanceCertificate& CreateSessionResponse::server_certificate()
{
  return mServerCertificate;
}

const ApplicationInstanceCertificate& CreateSessionResponse::server_certificate() const
{
  return mServerCertificate;
}

Array<EndpointDescription>& CreateSessionResponse::server_endpoints()
{
  return mServerEndpoints;
}

const Array<EndpointDescription>& CreateSessionResponse::server_endpoints() const
{
  return mServerEndpoints;
}

Array<SignedSoftwareCertificate>& CreateSessionResponse::server_software_certificates()
{
  return mServerSoftwareCertificates;
}

const Array<SignedSoftwareCertificate>& CreateSessionResponse::server_software_certificates() const
{
  return mServerSoftwareCertificates;
}

SignatureData& CreateSessionResponse::server_signature()
{
  return mServerSignature;
}

const SignatureData& CreateSessionResponse::server_signature() const
{
  return mServerSignature;
}

uint32_t& CreateSessionResponse::max_request_message_size()
{
  return mMaxRequestMessageSize;
}

const uint32_t& CreateSessionResponse::max_request_message_size() const
{
  return mMaxRequestMessageSize;
}

BuiltInTypeId CreateSessionResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ObjectAttributes
{
namespace
{
void encode(StackDepth limit, const ua::ObjectAttributes& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.event_notifier());
}

void encode(StackDepth limit, const ua::ObjectAttributes& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "EventNotifier", value.event_notifier());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ObjectAttributes& value)
{
  decoder.decode(limit, value.event_notifier());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ObjectAttributes& value)
{
  decoder.decode(limit, "EventNotifier", true, value.event_notifier());
}
}  // namespace
}  // namespace detail::ObjectAttributes

namespace detail::ObjectAttributes
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ObjectAttributes::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ObjectAttributes::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ObjectAttributes

namespace detail::ObjectAttributes
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ObjectAttributes>();
}
}  // namespace
}  // namespace detail::ObjectAttributes

bool ObjectAttributes::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return NodeAttributes::is_of_type(ns, dataTypeId);
}

NodeId ObjectAttributes::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ObjectAttributes::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ObjectAttributes::type_name() const
{
  return typeName;
}

void ObjectAttributes::encode(StackDepth limit, Encoder& encoder) const
{

  NodeAttributes::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ObjectAttributes::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ObjectAttributes::encode(limit, *this, *xml);
  }
}

void ObjectAttributes::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ObjectAttributes::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ObjectAttributes::encode_id(limit, ns, *xml);
  }
}

void ObjectAttributes::decode(StackDepth limit, Decoder& decoder)
{

  NodeAttributes::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ObjectAttributes::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ObjectAttributes::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ObjectAttributes::clone() const
{
  return make_unique<ObjectAttributes>(*this);
}

void ObjectAttributes::append_fields(std::string& output, int indent) const
{
  NodeAttributes::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
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
  output += "event_notifier=" + ua::to_string(event_notifier());
}

std::string ObjectAttributes::to_string(int indent) const
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

void ObjectAttributes::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ObjectAttributes::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ObjectAttributes::create);
  }
}

uint8_t& ObjectAttributes::event_notifier()
{
  return mEventNotifier;
}

const uint8_t& ObjectAttributes::event_notifier() const
{
  return mEventNotifier;
}

BuiltInTypeId ObjectAttributes::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::GenericAttributeValue
{
namespace
{
void encode(StackDepth limit, const ua::GenericAttributeValue& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.attribute_id());
  encoder.encode(limit, value.value());
}

void encode(StackDepth limit, const ua::GenericAttributeValue& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "AttributeId", value.attribute_id());
  encoder.encode(limit, "Value", value.value());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::GenericAttributeValue& value)
{
  decoder.decode(limit, value.attribute_id());
  decoder.decode(limit, value.value());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::GenericAttributeValue& value)
{
  decoder.decode(limit, "AttributeId", true, value.attribute_id());
  decoder.decode(limit, "Value", true, value.value());
}
}  // namespace
}  // namespace detail::GenericAttributeValue

namespace detail::GenericAttributeValue
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::GenericAttributeValue::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::GenericAttributeValue::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::GenericAttributeValue

namespace detail::GenericAttributeValue
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::GenericAttributeValue>();
}
}  // namespace
}  // namespace detail::GenericAttributeValue

bool GenericAttributeValue::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId GenericAttributeValue::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId GenericAttributeValue::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String GenericAttributeValue::type_name() const
{
  return typeName;
}

void GenericAttributeValue::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::GenericAttributeValue::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::GenericAttributeValue::encode(limit, *this, *xml);
  }
}

void GenericAttributeValue::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::GenericAttributeValue::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::GenericAttributeValue::encode_id(limit, ns, *xml);
  }
}

void GenericAttributeValue::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::GenericAttributeValue::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::GenericAttributeValue::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> GenericAttributeValue::clone() const
{
  return make_unique<GenericAttributeValue>(*this);
}

void GenericAttributeValue::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "attribute_id=" + ua::to_string(attribute_id());
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
  output += "attribute_id=" + ua::to_string(attribute_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "value=" + ua::to_string(value());
}

std::string GenericAttributeValue::to_string(int indent) const
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

void GenericAttributeValue::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::GenericAttributeValue::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::GenericAttributeValue::create);
  }
}

IntegerId& GenericAttributeValue::attribute_id()
{
  return mAttributeId;
}

const IntegerId& GenericAttributeValue::attribute_id() const
{
  return mAttributeId;
}

Variant& GenericAttributeValue::value()
{
  return mValue;
}

const Variant& GenericAttributeValue::value() const
{
  return mValue;
}

BuiltInTypeId GenericAttributeValue::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::DeleteNodesResponse
{
namespace
{
void encode(StackDepth limit, const ua::DeleteNodesResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.results());
  encoder.encode(limit, value.diagnostic_infos());
}

void encode(StackDepth limit, const ua::DeleteNodesResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "Results", value.results());
  encoder.encode(limit, "DiagnosticInfos", value.diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::DeleteNodesResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.results());
  decoder.decode(limit, value.diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::DeleteNodesResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "Results", true, value.results());
  decoder.decode(limit, "DiagnosticInfos", true, value.diagnostic_infos());
}
}  // namespace
}  // namespace detail::DeleteNodesResponse

namespace detail::DeleteNodesResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::DeleteNodesResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::DeleteNodesResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::DeleteNodesResponse

namespace detail::DeleteNodesResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::DeleteNodesResponse>();
}
}  // namespace
}  // namespace detail::DeleteNodesResponse

bool DeleteNodesResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId DeleteNodesResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId DeleteNodesResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String DeleteNodesResponse::type_name() const
{
  return typeName;
}

void DeleteNodesResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DeleteNodesResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DeleteNodesResponse::encode(limit, *this, *xml);
  }
}

void DeleteNodesResponse::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DeleteNodesResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DeleteNodesResponse::encode_id(limit, ns, *xml);
  }
}

void DeleteNodesResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::DeleteNodesResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::DeleteNodesResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> DeleteNodesResponse::clone() const
{
  return make_unique<DeleteNodesResponse>(*this);
}

void DeleteNodesResponse::append_fields(std::string& output, int indent) const
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

std::string DeleteNodesResponse::to_string(int indent) const
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

void DeleteNodesResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::DeleteNodesResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::DeleteNodesResponse::create);
  }
}

ResponseHeader& DeleteNodesResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& DeleteNodesResponse::response_header() const
{
  return mResponseHeader;
}

Array<StatusCode>& DeleteNodesResponse::results()
{
  return mResults;
}

const Array<StatusCode>& DeleteNodesResponse::results() const
{
  return mResults;
}

Array<DiagnosticInfo>& DeleteNodesResponse::diagnostic_infos()
{
  return mDiagnosticInfos;
}

const Array<DiagnosticInfo>& DeleteNodesResponse::diagnostic_infos() const
{
  return mDiagnosticInfos;
}

BuiltInTypeId DeleteNodesResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::BrowseResponse
{
namespace
{
void encode(StackDepth limit, const ua::BrowseResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.results());
  encoder.encode(limit, value.diagnostic_infos());
}

void encode(StackDepth limit, const ua::BrowseResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "Results", value.results());
  encoder.encode(limit, "DiagnosticInfos", value.diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::BrowseResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.results());
  decoder.decode(limit, value.diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::BrowseResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "Results", true, value.results());
  decoder.decode(limit, "DiagnosticInfos", true, value.diagnostic_infos());
}
}  // namespace
}  // namespace detail::BrowseResponse

namespace detail::BrowseResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::BrowseResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::BrowseResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::BrowseResponse

namespace detail::BrowseResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::BrowseResponse>();
}
}  // namespace
}  // namespace detail::BrowseResponse

bool BrowseResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId BrowseResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId BrowseResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String BrowseResponse::type_name() const
{
  return typeName;
}

void BrowseResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::BrowseResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::BrowseResponse::encode(limit, *this, *xml);
  }
}

void BrowseResponse::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::BrowseResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::BrowseResponse::encode_id(limit, ns, *xml);
  }
}

void BrowseResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::BrowseResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::BrowseResponse::decode(limit, *xml, *this);
  }
}

void BrowseResponse::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  for (size_t i = 0; i < mResults.size(); ++i)
  {
    mResults[i].resolve(locales);
  }
}

unique_ptr<Structure> BrowseResponse::clone() const
{
  return make_unique<BrowseResponse>(*this);
}

void BrowseResponse::append_fields(std::string& output, int indent) const
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

std::string BrowseResponse::to_string(int indent) const
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

void BrowseResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::BrowseResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::BrowseResponse::create);
  }
}

ResponseHeader& BrowseResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& BrowseResponse::response_header() const
{
  return mResponseHeader;
}

Array<BrowseResult>& BrowseResponse::results()
{
  return mResults;
}

const Array<BrowseResult>& BrowseResponse::results() const
{
  return mResults;
}

Array<DiagnosticInfo>& BrowseResponse::diagnostic_infos()
{
  return mDiagnosticInfos;
}

const Array<DiagnosticInfo>& BrowseResponse::diagnostic_infos() const
{
  return mDiagnosticInfos;
}

BuiltInTypeId BrowseResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::RegisterNodesRequest
{
namespace
{
void encode(StackDepth limit, const ua::RegisterNodesRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.nodes_to_register());
}

void encode(StackDepth limit, const ua::RegisterNodesRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "NodesToRegister", value.nodes_to_register());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::RegisterNodesRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.nodes_to_register());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::RegisterNodesRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "NodesToRegister", true, value.nodes_to_register());
}
}  // namespace
}  // namespace detail::RegisterNodesRequest

namespace detail::RegisterNodesRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::RegisterNodesRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::RegisterNodesRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::RegisterNodesRequest

namespace detail::RegisterNodesRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::RegisterNodesRequest>();
}
}  // namespace
}  // namespace detail::RegisterNodesRequest

bool RegisterNodesRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId RegisterNodesRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId RegisterNodesRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String RegisterNodesRequest::type_name() const
{
  return typeName;
}

void RegisterNodesRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RegisterNodesRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RegisterNodesRequest::encode(limit, *this, *xml);
  }
}

void RegisterNodesRequest::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RegisterNodesRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RegisterNodesRequest::encode_id(limit, ns, *xml);
  }
}

void RegisterNodesRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::RegisterNodesRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::RegisterNodesRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> RegisterNodesRequest::clone() const
{
  return make_unique<RegisterNodesRequest>(*this);
}

void RegisterNodesRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "nodes_to_register=" + ua::to_string(nodes_to_register());
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
  output += "nodes_to_register=" + ua::to_string(nodes_to_register());
}

std::string RegisterNodesRequest::to_string(int indent) const
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

void RegisterNodesRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::RegisterNodesRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::RegisterNodesRequest::create);
  }
}

RequestHeader& RegisterNodesRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& RegisterNodesRequest::request_header() const
{
  return mRequestHeader;
}

Array<NodeId>& RegisterNodesRequest::nodes_to_register()
{
  return mNodesToRegister;
}

const Array<NodeId>& RegisterNodesRequest::nodes_to_register() const
{
  return mNodesToRegister;
}

BuiltInTypeId RegisterNodesRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ContentFilterElementResult
{
namespace
{
void encode(StackDepth limit, const ua::ContentFilterElementResult& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.status_code());
  encoder.encode(limit, value.operand_status_codes());
  encoder.encode(limit, value.operand_diagnostic_infos());
}

void encode(StackDepth limit, const ua::ContentFilterElementResult& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "StatusCode", value.status_code());
  encoder.encode(limit, "OperandStatusCodes", value.operand_status_codes());
  encoder.encode(limit, "OperandDiagnosticInfos", value.operand_diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ContentFilterElementResult& value)
{
  decoder.decode(limit, value.status_code());
  decoder.decode(limit, value.operand_status_codes());
  decoder.decode(limit, value.operand_diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ContentFilterElementResult& value)
{
  decoder.decode(limit, "StatusCode", true, value.status_code());
  decoder.decode(limit, "OperandStatusCodes", true, value.operand_status_codes());
  decoder.decode(limit, "OperandDiagnosticInfos", true, value.operand_diagnostic_infos());
}
}  // namespace
}  // namespace detail::ContentFilterElementResult

namespace detail::ContentFilterElementResult
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ContentFilterElementResult::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ContentFilterElementResult::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ContentFilterElementResult

namespace detail::ContentFilterElementResult
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ContentFilterElementResult>();
}
}  // namespace
}  // namespace detail::ContentFilterElementResult

bool ContentFilterElementResult::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ContentFilterElementResult::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ContentFilterElementResult::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ContentFilterElementResult::type_name() const
{
  return typeName;
}

void ContentFilterElementResult::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ContentFilterElementResult::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ContentFilterElementResult::encode(limit, *this, *xml);
  }
}

void ContentFilterElementResult::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ContentFilterElementResult::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ContentFilterElementResult::encode_id(limit, ns, *xml);
  }
}

void ContentFilterElementResult::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ContentFilterElementResult::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ContentFilterElementResult::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ContentFilterElementResult::clone() const
{
  return make_unique<ContentFilterElementResult>(*this);
}

void ContentFilterElementResult::append_fields(std::string& output, int indent) const
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
    output += pad + "operand_status_codes=" + ua::to_string(operand_status_codes());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "operand_diagnostic_infos=" + ua::to_string(operand_diagnostic_infos());
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
  output += "operand_status_codes=" + ua::to_string(operand_status_codes());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "operand_diagnostic_infos=" + ua::to_string(operand_diagnostic_infos());
}

std::string ContentFilterElementResult::to_string(int indent) const
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

void ContentFilterElementResult::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::ContentFilterElementResult::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ContentFilterElementResult::create);
  }
}

StatusCode& ContentFilterElementResult::status_code()
{
  return mStatusCode;
}

const StatusCode& ContentFilterElementResult::status_code() const
{
  return mStatusCode;
}

Array<StatusCode>& ContentFilterElementResult::operand_status_codes()
{
  return mOperandStatusCodes;
}

const Array<StatusCode>& ContentFilterElementResult::operand_status_codes() const
{
  return mOperandStatusCodes;
}

Array<DiagnosticInfo>& ContentFilterElementResult::operand_diagnostic_infos()
{
  return mOperandDiagnosticInfos;
}

const Array<DiagnosticInfo>& ContentFilterElementResult::operand_diagnostic_infos() const
{
  return mOperandDiagnosticInfos;
}

BuiltInTypeId ContentFilterElementResult::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ReadRequest
{
namespace
{
void encode(StackDepth limit, const ua::ReadRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.max_age());
  encoder.encode(limit, utils::as_int32(value.timestamps_to_return()));
  encoder.encode(limit, value.nodes_to_read());
}

void encode(StackDepth limit, const ua::ReadRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "MaxAge", value.max_age());
  encoder.encode(limit, "TimestampsToReturn", utils::as_int32(value.timestamps_to_return()));
  encoder.encode(limit, "NodesToRead", value.nodes_to_read());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ReadRequest& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.max_age());
  decoder.decode(limit, enumVal);
  value.timestamps_to_return() = utils::from_underlying<TimestampsToReturn>(enumVal);
  decoder.decode(limit, value.nodes_to_read());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ReadRequest& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "MaxAge", true, value.max_age());
  decoder.decode(limit, "TimestampsToReturn", true, enumVal);
  value.timestamps_to_return() = utils::from_underlying<TimestampsToReturn>(enumVal);
  decoder.decode(limit, "NodesToRead", true, value.nodes_to_read());
}
}  // namespace
}  // namespace detail::ReadRequest

namespace detail::ReadRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ReadRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ReadRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ReadRequest

namespace detail::ReadRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ReadRequest>();
}
}  // namespace
}  // namespace detail::ReadRequest

bool ReadRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ReadRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ReadRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ReadRequest::type_name() const
{
  return typeName;
}

void ReadRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReadRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReadRequest::encode(limit, *this, *xml);
  }
}

void ReadRequest::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReadRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReadRequest::encode_id(limit, ns, *xml);
  }
}

void ReadRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ReadRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ReadRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ReadRequest::clone() const
{
  return make_unique<ReadRequest>(*this);
}

void ReadRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "max_age=" + ua::to_string(max_age());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "timestamps_to_return=" + ua::to_string(utils::as_int32(timestamps_to_return()));
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
  output += "max_age=" + ua::to_string(max_age());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "timestamps_to_return=" + ua::to_string(utils::as_int32(timestamps_to_return()));
  if (!output.empty())
  {
    output += ", ";
  }
  output += "nodes_to_read=" + ua::to_string(nodes_to_read());
}

std::string ReadRequest::to_string(int indent) const
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

void ReadRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ReadRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ReadRequest::create);
  }
}

RequestHeader& ReadRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& ReadRequest::request_header() const
{
  return mRequestHeader;
}

Duration& ReadRequest::max_age()
{
  return mMaxAge;
}

const Duration& ReadRequest::max_age() const
{
  return mMaxAge;
}

TimestampsToReturn& ReadRequest::timestamps_to_return()
{
  return mTimestampsToReturn;
}

const TimestampsToReturn& ReadRequest::timestamps_to_return() const
{
  return mTimestampsToReturn;
}

Array<ReadValueId>& ReadRequest::nodes_to_read()
{
  return mNodesToRead;
}

const Array<ReadValueId>& ReadRequest::nodes_to_read() const
{
  return mNodesToRead;
}

BuiltInTypeId ReadRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ReadEventDetailsSorted
{
namespace
{
void encode(StackDepth limit, const ua::ReadEventDetailsSorted& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.sort_clause());
}

void encode(StackDepth limit, const ua::ReadEventDetailsSorted& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "SortClause", value.sort_clause());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ReadEventDetailsSorted& value)
{
  decoder.decode(limit, value.sort_clause());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ReadEventDetailsSorted& value)
{
  decoder.decode(limit, "SortClause", true, value.sort_clause());
}
}  // namespace
}  // namespace detail::ReadEventDetailsSorted

namespace detail::ReadEventDetailsSorted
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ReadEventDetailsSorted::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ReadEventDetailsSorted::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ReadEventDetailsSorted

namespace detail::ReadEventDetailsSorted
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ReadEventDetailsSorted>();
}
}  // namespace
}  // namespace detail::ReadEventDetailsSorted

bool ReadEventDetailsSorted::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return ReadEventDetails::is_of_type(ns, dataTypeId);
}

NodeId ReadEventDetailsSorted::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ReadEventDetailsSorted::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ReadEventDetailsSorted::type_name() const
{
  return typeName;
}

void ReadEventDetailsSorted::encode(StackDepth limit, Encoder& encoder) const
{

  ReadEventDetails::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReadEventDetailsSorted::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReadEventDetailsSorted::encode(limit, *this, *xml);
  }
}

void ReadEventDetailsSorted::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReadEventDetailsSorted::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReadEventDetailsSorted::encode_id(limit, ns, *xml);
  }
}

void ReadEventDetailsSorted::decode(StackDepth limit, Decoder& decoder)
{

  ReadEventDetails::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ReadEventDetailsSorted::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ReadEventDetailsSorted::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ReadEventDetailsSorted::clone() const
{
  return make_unique<ReadEventDetailsSorted>(*this);
}

void ReadEventDetailsSorted::append_fields(std::string& output, int indent) const
{
  ReadEventDetails::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "sort_clause=" + ua::to_string(sort_clause());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "sort_clause=" + ua::to_string(sort_clause());
}

std::string ReadEventDetailsSorted::to_string(int indent) const
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

void ReadEventDetailsSorted::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ReadEventDetailsSorted::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ReadEventDetailsSorted::create);
  }
}

Array<SortRuleElement>& ReadEventDetailsSorted::sort_clause()
{
  return mSortClause;
}

const Array<SortRuleElement>& ReadEventDetailsSorted::sort_clause() const
{
  return mSortClause;
}

BuiltInTypeId ReadEventDetailsSorted::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::HistoryReadResponse
{
namespace
{
void encode(StackDepth limit, const ua::HistoryReadResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.results());
  encoder.encode(limit, value.diagnostic_infos());
}

void encode(StackDepth limit, const ua::HistoryReadResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "Results", value.results());
  encoder.encode(limit, "DiagnosticInfos", value.diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::HistoryReadResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.results());
  decoder.decode(limit, value.diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::HistoryReadResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "Results", true, value.results());
  decoder.decode(limit, "DiagnosticInfos", true, value.diagnostic_infos());
}
}  // namespace
}  // namespace detail::HistoryReadResponse

namespace detail::HistoryReadResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::HistoryReadResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::HistoryReadResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::HistoryReadResponse

namespace detail::HistoryReadResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::HistoryReadResponse>();
}
}  // namespace
}  // namespace detail::HistoryReadResponse

bool HistoryReadResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId HistoryReadResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId HistoryReadResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String HistoryReadResponse::type_name() const
{
  return typeName;
}

void HistoryReadResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::HistoryReadResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::HistoryReadResponse::encode(limit, *this, *xml);
  }
}

void HistoryReadResponse::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::HistoryReadResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::HistoryReadResponse::encode_id(limit, ns, *xml);
  }
}

void HistoryReadResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::HistoryReadResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::HistoryReadResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> HistoryReadResponse::clone() const
{
  return make_unique<HistoryReadResponse>(*this);
}

void HistoryReadResponse::append_fields(std::string& output, int indent) const
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

std::string HistoryReadResponse::to_string(int indent) const
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

void HistoryReadResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::HistoryReadResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::HistoryReadResponse::create);
  }
}

ResponseHeader& HistoryReadResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& HistoryReadResponse::response_header() const
{
  return mResponseHeader;
}

Array<HistoryReadResult>& HistoryReadResponse::results()
{
  return mResults;
}

const Array<HistoryReadResult>& HistoryReadResponse::results() const
{
  return mResults;
}

Array<DiagnosticInfo>& HistoryReadResponse::diagnostic_infos()
{
  return mDiagnosticInfos;
}

const Array<DiagnosticInfo>& HistoryReadResponse::diagnostic_infos() const
{
  return mDiagnosticInfos;
}

BuiltInTypeId HistoryReadResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::DeleteRawModifiedDetails
{
namespace
{
void encode(StackDepth limit, const ua::DeleteRawModifiedDetails& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.node_id());
  encoder.encode(limit, value.is_delete_modified());
  encoder.encode(limit, value.start_time());
  encoder.encode(limit, value.end_time());
}

void encode(StackDepth limit, const ua::DeleteRawModifiedDetails& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "NodeId", value.node_id());
  encoder.encode(limit, "IsDeleteModified", value.is_delete_modified());
  encoder.encode(limit, "StartTime", value.start_time());
  encoder.encode(limit, "EndTime", value.end_time());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::DeleteRawModifiedDetails& value)
{
  decoder.decode(limit, value.node_id());
  decoder.decode(limit, value.is_delete_modified());
  decoder.decode(limit, value.start_time());
  decoder.decode(limit, value.end_time());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::DeleteRawModifiedDetails& value)
{
  decoder.decode(limit, "NodeId", true, value.node_id());
  decoder.decode(limit, "IsDeleteModified", true, value.is_delete_modified());
  decoder.decode(limit, "StartTime", true, value.start_time());
  decoder.decode(limit, "EndTime", true, value.end_time());
}
}  // namespace
}  // namespace detail::DeleteRawModifiedDetails

namespace detail::DeleteRawModifiedDetails
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::DeleteRawModifiedDetails::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::DeleteRawModifiedDetails::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::DeleteRawModifiedDetails

namespace detail::DeleteRawModifiedDetails
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::DeleteRawModifiedDetails>();
}
}  // namespace
}  // namespace detail::DeleteRawModifiedDetails

bool DeleteRawModifiedDetails::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return HistoryUpdateDetails::is_of_type(ns, dataTypeId);
}

NodeId DeleteRawModifiedDetails::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId DeleteRawModifiedDetails::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String DeleteRawModifiedDetails::type_name() const
{
  return typeName;
}

void DeleteRawModifiedDetails::encode(StackDepth limit, Encoder& encoder) const
{

  HistoryUpdateDetails::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DeleteRawModifiedDetails::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DeleteRawModifiedDetails::encode(limit, *this, *xml);
  }
}

void DeleteRawModifiedDetails::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DeleteRawModifiedDetails::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DeleteRawModifiedDetails::encode_id(limit, ns, *xml);
  }
}

void DeleteRawModifiedDetails::decode(StackDepth limit, Decoder& decoder)
{

  HistoryUpdateDetails::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::DeleteRawModifiedDetails::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::DeleteRawModifiedDetails::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> DeleteRawModifiedDetails::clone() const
{
  return make_unique<DeleteRawModifiedDetails>(*this);
}

void DeleteRawModifiedDetails::append_fields(std::string& output, int indent) const
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
    output += pad + "is_delete_modified=" + ua::to_string(is_delete_modified());
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
  output += "is_delete_modified=" + ua::to_string(is_delete_modified());
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
}

std::string DeleteRawModifiedDetails::to_string(int indent) const
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

void DeleteRawModifiedDetails::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::DeleteRawModifiedDetails::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::DeleteRawModifiedDetails::create);
  }
}

NodeId& DeleteRawModifiedDetails::node_id()
{
  return mNodeId;
}

const NodeId& DeleteRawModifiedDetails::node_id() const
{
  return mNodeId;
}

bool& DeleteRawModifiedDetails::is_delete_modified()
{
  return mIsDeleteModified;
}

const bool& DeleteRawModifiedDetails::is_delete_modified() const
{
  return mIsDeleteModified;
}

UtcTime& DeleteRawModifiedDetails::start_time()
{
  return mStartTime;
}

const UtcTime& DeleteRawModifiedDetails::start_time() const
{
  return mStartTime;
}

UtcTime& DeleteRawModifiedDetails::end_time()
{
  return mEndTime;
}

const UtcTime& DeleteRawModifiedDetails::end_time() const
{
  return mEndTime;
}

BuiltInTypeId DeleteRawModifiedDetails::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::CallRequest
{
namespace
{
void encode(StackDepth limit, const ua::CallRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.methods_to_call());
}

void encode(StackDepth limit, const ua::CallRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "MethodsToCall", value.methods_to_call());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::CallRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.methods_to_call());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::CallRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "MethodsToCall", true, value.methods_to_call());
}
}  // namespace
}  // namespace detail::CallRequest

namespace detail::CallRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::CallRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::CallRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::CallRequest

namespace detail::CallRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::CallRequest>();
}
}  // namespace
}  // namespace detail::CallRequest

bool CallRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId CallRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId CallRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String CallRequest::type_name() const
{
  return typeName;
}

void CallRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CallRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CallRequest::encode(limit, *this, *xml);
  }
}

void CallRequest::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CallRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CallRequest::encode_id(limit, ns, *xml);
  }
}

void CallRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::CallRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::CallRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> CallRequest::clone() const
{
  return make_unique<CallRequest>(*this);
}

void CallRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "methods_to_call=" + ua::to_string(methods_to_call());
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
  output += "methods_to_call=" + ua::to_string(methods_to_call());
}

std::string CallRequest::to_string(int indent) const
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

void CallRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::CallRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::CallRequest::create);
  }
}

RequestHeader& CallRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& CallRequest::request_header() const
{
  return mRequestHeader;
}

Array<CallMethodRequest>& CallRequest::methods_to_call()
{
  return mMethodsToCall;
}

const Array<CallMethodRequest>& CallRequest::methods_to_call() const
{
  return mMethodsToCall;
}

BuiltInTypeId CallRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::MonitoredItemCreateRequest
{
namespace
{
void encode(StackDepth limit, const ua::MonitoredItemCreateRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.item_to_monitor());
  encoder.encode(limit, utils::as_int32(value.monitoring_mode()));
  encoder.encode(limit, value.requested_parameters());
}

void encode(StackDepth limit, const ua::MonitoredItemCreateRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ItemToMonitor", value.item_to_monitor());
  encoder.encode(limit, "MonitoringMode", utils::as_int32(value.monitoring_mode()));
  encoder.encode(limit, "RequestedParameters", value.requested_parameters());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::MonitoredItemCreateRequest& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.item_to_monitor());
  decoder.decode(limit, enumVal);
  value.monitoring_mode() = utils::from_underlying<MonitoringMode>(enumVal);
  decoder.decode(limit, value.requested_parameters());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::MonitoredItemCreateRequest& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "ItemToMonitor", true, value.item_to_monitor());
  decoder.decode(limit, "MonitoringMode", true, enumVal);
  value.monitoring_mode() = utils::from_underlying<MonitoringMode>(enumVal);
  decoder.decode(limit, "RequestedParameters", true, value.requested_parameters());
}
}  // namespace
}  // namespace detail::MonitoredItemCreateRequest

namespace detail::MonitoredItemCreateRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::MonitoredItemCreateRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::MonitoredItemCreateRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::MonitoredItemCreateRequest

namespace detail::MonitoredItemCreateRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::MonitoredItemCreateRequest>();
}
}  // namespace
}  // namespace detail::MonitoredItemCreateRequest

bool MonitoredItemCreateRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId MonitoredItemCreateRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId MonitoredItemCreateRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String MonitoredItemCreateRequest::type_name() const
{
  return typeName;
}

void MonitoredItemCreateRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::MonitoredItemCreateRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::MonitoredItemCreateRequest::encode(limit, *this, *xml);
  }
}

void MonitoredItemCreateRequest::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::MonitoredItemCreateRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::MonitoredItemCreateRequest::encode_id(limit, ns, *xml);
  }
}

void MonitoredItemCreateRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::MonitoredItemCreateRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::MonitoredItemCreateRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> MonitoredItemCreateRequest::clone() const
{
  return make_unique<MonitoredItemCreateRequest>(*this);
}

void MonitoredItemCreateRequest::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "item_to_monitor=" + ua::to_string(item_to_monitor());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "monitoring_mode=" + ua::to_string(utils::as_int32(monitoring_mode()));
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "requested_parameters=" + ua::to_string(requested_parameters());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "item_to_monitor=" + ua::to_string(item_to_monitor());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "monitoring_mode=" + ua::to_string(utils::as_int32(monitoring_mode()));
  if (!output.empty())
  {
    output += ", ";
  }
  output += "requested_parameters=" + ua::to_string(requested_parameters());
}

std::string MonitoredItemCreateRequest::to_string(int indent) const
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

void MonitoredItemCreateRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::MonitoredItemCreateRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::MonitoredItemCreateRequest::create);
  }
}

ReadValueId& MonitoredItemCreateRequest::item_to_monitor()
{
  return mItemToMonitor;
}

const ReadValueId& MonitoredItemCreateRequest::item_to_monitor() const
{
  return mItemToMonitor;
}

MonitoringMode& MonitoredItemCreateRequest::monitoring_mode()
{
  return mMonitoringMode;
}

const MonitoringMode& MonitoredItemCreateRequest::monitoring_mode() const
{
  return mMonitoringMode;
}

MonitoringParameters& MonitoredItemCreateRequest::requested_parameters()
{
  return mRequestedParameters;
}

const MonitoringParameters& MonitoredItemCreateRequest::requested_parameters() const
{
  return mRequestedParameters;
}

BuiltInTypeId MonitoredItemCreateRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::SetMonitoringModeRequest
{
namespace
{
void encode(StackDepth limit, const ua::SetMonitoringModeRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.subscription_id());
  encoder.encode(limit, utils::as_int32(value.monitoring_mode()));
  encoder.encode(limit, value.monitored_item_ids());
}

void encode(StackDepth limit, const ua::SetMonitoringModeRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "SubscriptionId", value.subscription_id());
  encoder.encode(limit, "MonitoringMode", utils::as_int32(value.monitoring_mode()));
  encoder.encode(limit, "MonitoredItemIds", value.monitored_item_ids());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::SetMonitoringModeRequest& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.subscription_id());
  decoder.decode(limit, enumVal);
  value.monitoring_mode() = utils::from_underlying<MonitoringMode>(enumVal);
  decoder.decode(limit, value.monitored_item_ids());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::SetMonitoringModeRequest& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "SubscriptionId", true, value.subscription_id());
  decoder.decode(limit, "MonitoringMode", true, enumVal);
  value.monitoring_mode() = utils::from_underlying<MonitoringMode>(enumVal);
  decoder.decode(limit, "MonitoredItemIds", true, value.monitored_item_ids());
}
}  // namespace
}  // namespace detail::SetMonitoringModeRequest

namespace detail::SetMonitoringModeRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::SetMonitoringModeRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::SetMonitoringModeRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::SetMonitoringModeRequest

namespace detail::SetMonitoringModeRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::SetMonitoringModeRequest>();
}
}  // namespace
}  // namespace detail::SetMonitoringModeRequest

bool SetMonitoringModeRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId SetMonitoringModeRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId SetMonitoringModeRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String SetMonitoringModeRequest::type_name() const
{
  return typeName;
}

void SetMonitoringModeRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SetMonitoringModeRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SetMonitoringModeRequest::encode(limit, *this, *xml);
  }
}

void SetMonitoringModeRequest::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SetMonitoringModeRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SetMonitoringModeRequest::encode_id(limit, ns, *xml);
  }
}

void SetMonitoringModeRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::SetMonitoringModeRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::SetMonitoringModeRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> SetMonitoringModeRequest::clone() const
{
  return make_unique<SetMonitoringModeRequest>(*this);
}

void SetMonitoringModeRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "subscription_id=" + ua::to_string(subscription_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "monitoring_mode=" + ua::to_string(utils::as_int32(monitoring_mode()));
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "monitored_item_ids=" + ua::to_string(monitored_item_ids());
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
  output += "subscription_id=" + ua::to_string(subscription_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "monitoring_mode=" + ua::to_string(utils::as_int32(monitoring_mode()));
  if (!output.empty())
  {
    output += ", ";
  }
  output += "monitored_item_ids=" + ua::to_string(monitored_item_ids());
}

std::string SetMonitoringModeRequest::to_string(int indent) const
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

void SetMonitoringModeRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::SetMonitoringModeRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::SetMonitoringModeRequest::create);
  }
}

RequestHeader& SetMonitoringModeRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& SetMonitoringModeRequest::request_header() const
{
  return mRequestHeader;
}

IntegerId& SetMonitoringModeRequest::subscription_id()
{
  return mSubscriptionId;
}

const IntegerId& SetMonitoringModeRequest::subscription_id() const
{
  return mSubscriptionId;
}

MonitoringMode& SetMonitoringModeRequest::monitoring_mode()
{
  return mMonitoringMode;
}

const MonitoringMode& SetMonitoringModeRequest::monitoring_mode() const
{
  return mMonitoringMode;
}

Array<IntegerId>& SetMonitoringModeRequest::monitored_item_ids()
{
  return mMonitoredItemIds;
}

const Array<IntegerId>& SetMonitoringModeRequest::monitored_item_ids() const
{
  return mMonitoredItemIds;
}

BuiltInTypeId SetMonitoringModeRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ModifySubscriptionRequest
{
namespace
{
void encode(StackDepth limit, const ua::ModifySubscriptionRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.subscription_id());
  encoder.encode(limit, value.requested_publishing_interval());
  encoder.encode(limit, value.requested_lifetime_count());
  encoder.encode(limit, value.requested_max_keep_alive_count());
  encoder.encode(limit, value.max_notifications_per_publish());
  encoder.encode(limit, value.priority());
}

void encode(StackDepth limit, const ua::ModifySubscriptionRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "SubscriptionId", value.subscription_id());
  encoder.encode(limit, "RequestedPublishingInterval", value.requested_publishing_interval());
  encoder.encode(limit, "RequestedLifetimeCount", value.requested_lifetime_count());
  encoder.encode(limit, "RequestedMaxKeepAliveCount", value.requested_max_keep_alive_count());
  encoder.encode(limit, "MaxNotificationsPerPublish", value.max_notifications_per_publish());
  encoder.encode(limit, "Priority", value.priority());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ModifySubscriptionRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.subscription_id());
  decoder.decode(limit, value.requested_publishing_interval());
  decoder.decode(limit, value.requested_lifetime_count());
  decoder.decode(limit, value.requested_max_keep_alive_count());
  decoder.decode(limit, value.max_notifications_per_publish());
  decoder.decode(limit, value.priority());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ModifySubscriptionRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "SubscriptionId", true, value.subscription_id());
  decoder.decode(limit, "RequestedPublishingInterval", true, value.requested_publishing_interval());
  decoder.decode(limit, "RequestedLifetimeCount", true, value.requested_lifetime_count());
  decoder.decode(limit, "RequestedMaxKeepAliveCount", true, value.requested_max_keep_alive_count());
  decoder.decode(limit, "MaxNotificationsPerPublish", true, value.max_notifications_per_publish());
  decoder.decode(limit, "Priority", true, value.priority());
}
}  // namespace
}  // namespace detail::ModifySubscriptionRequest

namespace detail::ModifySubscriptionRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ModifySubscriptionRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ModifySubscriptionRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ModifySubscriptionRequest

namespace detail::ModifySubscriptionRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ModifySubscriptionRequest>();
}
}  // namespace
}  // namespace detail::ModifySubscriptionRequest

bool ModifySubscriptionRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ModifySubscriptionRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ModifySubscriptionRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ModifySubscriptionRequest::type_name() const
{
  return typeName;
}

void ModifySubscriptionRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ModifySubscriptionRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ModifySubscriptionRequest::encode(limit, *this, *xml);
  }
}

void ModifySubscriptionRequest::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ModifySubscriptionRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ModifySubscriptionRequest::encode_id(limit, ns, *xml);
  }
}

void ModifySubscriptionRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ModifySubscriptionRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ModifySubscriptionRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ModifySubscriptionRequest::clone() const
{
  return make_unique<ModifySubscriptionRequest>(*this);
}

void ModifySubscriptionRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "subscription_id=" + ua::to_string(subscription_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "requested_publishing_interval=" + ua::to_string(requested_publishing_interval());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "requested_lifetime_count=" + ua::to_string(requested_lifetime_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "requested_max_keep_alive_count=" + ua::to_string(requested_max_keep_alive_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "max_notifications_per_publish=" + ua::to_string(max_notifications_per_publish());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "priority=" + ua::to_string(priority());
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
  output += "subscription_id=" + ua::to_string(subscription_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "requested_publishing_interval=" + ua::to_string(requested_publishing_interval());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "requested_lifetime_count=" + ua::to_string(requested_lifetime_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "requested_max_keep_alive_count=" + ua::to_string(requested_max_keep_alive_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "max_notifications_per_publish=" + ua::to_string(max_notifications_per_publish());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "priority=" + ua::to_string(priority());
}

std::string ModifySubscriptionRequest::to_string(int indent) const
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

void ModifySubscriptionRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::ModifySubscriptionRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ModifySubscriptionRequest::create);
  }
}

RequestHeader& ModifySubscriptionRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& ModifySubscriptionRequest::request_header() const
{
  return mRequestHeader;
}

IntegerId& ModifySubscriptionRequest::subscription_id()
{
  return mSubscriptionId;
}

const IntegerId& ModifySubscriptionRequest::subscription_id() const
{
  return mSubscriptionId;
}

Duration& ModifySubscriptionRequest::requested_publishing_interval()
{
  return mRequestedPublishingInterval;
}

const Duration& ModifySubscriptionRequest::requested_publishing_interval() const
{
  return mRequestedPublishingInterval;
}

Counter& ModifySubscriptionRequest::requested_lifetime_count()
{
  return mRequestedLifetimeCount;
}

const Counter& ModifySubscriptionRequest::requested_lifetime_count() const
{
  return mRequestedLifetimeCount;
}

Counter& ModifySubscriptionRequest::requested_max_keep_alive_count()
{
  return mRequestedMaxKeepAliveCount;
}

const Counter& ModifySubscriptionRequest::requested_max_keep_alive_count() const
{
  return mRequestedMaxKeepAliveCount;
}

Counter& ModifySubscriptionRequest::max_notifications_per_publish()
{
  return mMaxNotificationsPerPublish;
}

const Counter& ModifySubscriptionRequest::max_notifications_per_publish() const
{
  return mMaxNotificationsPerPublish;
}

uint8_t& ModifySubscriptionRequest::priority()
{
  return mPriority;
}

const uint8_t& ModifySubscriptionRequest::priority() const
{
  return mPriority;
}

BuiltInTypeId ModifySubscriptionRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::EventNotificationList
{
namespace
{
void encode(StackDepth limit, const ua::EventNotificationList& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.events());
}

void encode(StackDepth limit, const ua::EventNotificationList& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Events", value.events());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::EventNotificationList& value)
{
  decoder.decode(limit, value.events());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::EventNotificationList& value)
{
  decoder.decode(limit, "Events", true, value.events());
}
}  // namespace
}  // namespace detail::EventNotificationList

namespace detail::EventNotificationList
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::EventNotificationList::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::EventNotificationList::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::EventNotificationList

namespace detail::EventNotificationList
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::EventNotificationList>();
}
}  // namespace
}  // namespace detail::EventNotificationList

bool EventNotificationList::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return NotificationData::is_of_type(ns, dataTypeId);
}

NodeId EventNotificationList::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId EventNotificationList::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String EventNotificationList::type_name() const
{
  return typeName;
}

void EventNotificationList::encode(StackDepth limit, Encoder& encoder) const
{

  NotificationData::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EventNotificationList::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EventNotificationList::encode(limit, *this, *xml);
  }
}

void EventNotificationList::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EventNotificationList::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EventNotificationList::encode_id(limit, ns, *xml);
  }
}

void EventNotificationList::decode(StackDepth limit, Decoder& decoder)
{

  NotificationData::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::EventNotificationList::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::EventNotificationList::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> EventNotificationList::clone() const
{
  return make_unique<EventNotificationList>(*this);
}

void EventNotificationList::append_fields(std::string& output, int indent) const
{
  NotificationData::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "events=" + ua::to_string(events());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "events=" + ua::to_string(events());
}

std::string EventNotificationList::to_string(int indent) const
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

void EventNotificationList::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::EventNotificationList::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::EventNotificationList::create);
  }
}

Array<EventFieldList>& EventNotificationList::events()
{
  return mEvents;
}

const Array<EventFieldList>& EventNotificationList::events() const
{
  return mEvents;
}

BuiltInTypeId EventNotificationList::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::TransferResult
{
namespace
{
void encode(StackDepth limit, const ua::TransferResult& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.status_code());
  encoder.encode(limit, value.available_sequence_numbers());
}

void encode(StackDepth limit, const ua::TransferResult& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "StatusCode", value.status_code());
  encoder.encode(limit, "AvailableSequenceNumbers", value.available_sequence_numbers());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::TransferResult& value)
{
  decoder.decode(limit, value.status_code());
  decoder.decode(limit, value.available_sequence_numbers());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::TransferResult& value)
{
  decoder.decode(limit, "StatusCode", true, value.status_code());
  decoder.decode(limit, "AvailableSequenceNumbers", true, value.available_sequence_numbers());
}
}  // namespace
}  // namespace detail::TransferResult

namespace detail::TransferResult
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::TransferResult::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::TransferResult::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::TransferResult

namespace detail::TransferResult
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::TransferResult>();
}
}  // namespace
}  // namespace detail::TransferResult

bool TransferResult::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId TransferResult::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId TransferResult::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String TransferResult::type_name() const
{
  return typeName;
}

void TransferResult::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::TransferResult::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::TransferResult::encode(limit, *this, *xml);
  }
}

void TransferResult::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::TransferResult::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::TransferResult::encode_id(limit, ns, *xml);
  }
}

void TransferResult::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::TransferResult::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::TransferResult::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> TransferResult::clone() const
{
  return make_unique<TransferResult>(*this);
}

void TransferResult::append_fields(std::string& output, int indent) const
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
    output += pad + "available_sequence_numbers=" + ua::to_string(available_sequence_numbers());
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
  output += "available_sequence_numbers=" + ua::to_string(available_sequence_numbers());
}

std::string TransferResult::to_string(int indent) const
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

void TransferResult::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::TransferResult::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::TransferResult::create);
  }
}

StatusCode& TransferResult::status_code()
{
  return mStatusCode;
}

const StatusCode& TransferResult::status_code() const
{
  return mStatusCode;
}

Array<Counter>& TransferResult::available_sequence_numbers()
{
  return mAvailableSequenceNumbers;
}

const Array<Counter>& TransferResult::available_sequence_numbers() const
{
  return mAvailableSequenceNumbers;
}

BuiltInTypeId TransferResult::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

}  // namespace ua
