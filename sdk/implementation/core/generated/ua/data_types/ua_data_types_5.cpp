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

namespace detail::RationalNumber
{
namespace
{
void encode(StackDepth limit, const ua::RationalNumber& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.numerator());
  encoder.encode(limit, value.denominator());
}

void encode(StackDepth limit, const ua::RationalNumber& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Numerator", value.numerator());
  encoder.encode(limit, "Denominator", value.denominator());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::RationalNumber& value)
{
  decoder.decode(limit, value.numerator());
  decoder.decode(limit, value.denominator());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::RationalNumber& value)
{
  decoder.decode(limit, "Numerator", true, value.numerator());
  decoder.decode(limit, "Denominator", true, value.denominator());
}
}  // namespace
}  // namespace detail::RationalNumber

namespace detail::RationalNumber
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::RationalNumber::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::RationalNumber::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::RationalNumber

namespace detail::RationalNumber
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::RationalNumber>();
}
}  // namespace
}  // namespace detail::RationalNumber

bool RationalNumber::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId RationalNumber::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId RationalNumber::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String RationalNumber::type_name() const
{
  return typeName;
}

void RationalNumber::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RationalNumber::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RationalNumber::encode(limit, *this, *xml);
  }
}

void RationalNumber::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RationalNumber::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RationalNumber::encode_id(limit, ns, *xml);
  }
}

void RationalNumber::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::RationalNumber::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::RationalNumber::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> RationalNumber::clone() const
{
  return make_unique<RationalNumber>(*this);
}

void RationalNumber::append_fields(std::string& output, int indent) const
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

std::string RationalNumber::to_string(int indent) const
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

void RationalNumber::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::RationalNumber::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::RationalNumber::create);
  }
}

int32_t& RationalNumber::numerator()
{
  return mNumerator;
}

const int32_t& RationalNumber::numerator() const
{
  return mNumerator;
}

uint32_t& RationalNumber::denominator()
{
  return mDenominator;
}

const uint32_t& RationalNumber::denominator() const
{
  return mDenominator;
}

BuiltInTypeId RationalNumber::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ThreeDFrame
{
namespace
{
void encode(StackDepth limit, const ua::ThreeDFrame& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.cartesian_coordinates());
  encoder.encode(limit, value.orientation());
}

void encode(StackDepth limit, const ua::ThreeDFrame& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "CartesianCoordinates", value.cartesian_coordinates());
  encoder.encode(limit, "Orientation", value.orientation());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ThreeDFrame& value)
{
  decoder.decode(limit, value.cartesian_coordinates());
  decoder.decode(limit, value.orientation());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ThreeDFrame& value)
{
  decoder.decode(limit, "CartesianCoordinates", true, value.cartesian_coordinates());
  decoder.decode(limit, "Orientation", true, value.orientation());
}
}  // namespace
}  // namespace detail::ThreeDFrame

namespace detail::ThreeDFrame
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ThreeDFrame::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ThreeDFrame::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ThreeDFrame

namespace detail::ThreeDFrame
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ThreeDFrame>();
}
}  // namespace
}  // namespace detail::ThreeDFrame

bool ThreeDFrame::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Frame::is_of_type(ns, dataTypeId);
}

NodeId ThreeDFrame::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ThreeDFrame::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ThreeDFrame::type_name() const
{
  return typeName;
}

void ThreeDFrame::encode(StackDepth limit, Encoder& encoder) const
{

  Frame::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ThreeDFrame::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ThreeDFrame::encode(limit, *this, *xml);
  }
}

void ThreeDFrame::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ThreeDFrame::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ThreeDFrame::encode_id(limit, ns, *xml);
  }
}

void ThreeDFrame::decode(StackDepth limit, Decoder& decoder)
{

  Frame::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ThreeDFrame::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ThreeDFrame::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ThreeDFrame::clone() const
{
  return make_unique<ThreeDFrame>(*this);
}

void ThreeDFrame::append_fields(std::string& output, int indent) const
{
  Frame::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "cartesian_coordinates=" + ua::to_string(cartesian_coordinates());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "orientation=" + ua::to_string(orientation());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "cartesian_coordinates=" + ua::to_string(cartesian_coordinates());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "orientation=" + ua::to_string(orientation());
}

std::string ThreeDFrame::to_string(int indent) const
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

void ThreeDFrame::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ThreeDFrame::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ThreeDFrame::create);
  }
}

ThreeDCartesianCoordinates& ThreeDFrame::cartesian_coordinates()
{
  return mCartesianCoordinates;
}

const ThreeDCartesianCoordinates& ThreeDFrame::cartesian_coordinates() const
{
  return mCartesianCoordinates;
}

ThreeDOrientation& ThreeDFrame::orientation()
{
  return mOrientation;
}

const ThreeDOrientation& ThreeDFrame::orientation() const
{
  return mOrientation;
}

BuiltInTypeId ThreeDFrame::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::BaseConfigurationRecordDataType
{
namespace
{
void encode(StackDepth limit, const ua::BaseConfigurationRecordDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.name());
  encoder.encode(limit, value.record_properties());
}

void encode(StackDepth limit, const ua::BaseConfigurationRecordDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Name", value.name());
  encoder.encode(limit, "RecordProperties", value.record_properties());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::BaseConfigurationRecordDataType& value)
{
  decoder.decode(limit, value.name());
  decoder.decode(limit, value.record_properties());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::BaseConfigurationRecordDataType& value)
{
  decoder.decode(limit, "Name", true, value.name());
  decoder.decode(limit, "RecordProperties", true, value.record_properties());
}
}  // namespace
}  // namespace detail::BaseConfigurationRecordDataType

bool BaseConfigurationRecordDataType::is_of_type(
  const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId BaseConfigurationRecordDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId BaseConfigurationRecordDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String BaseConfigurationRecordDataType::type_name() const
{
  return typeName;
}

void BaseConfigurationRecordDataType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::BaseConfigurationRecordDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::BaseConfigurationRecordDataType::encode(limit, *this, *xml);
  }
}

void BaseConfigurationRecordDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  UA_UNUSED(limit);
  UA_UNUSED(ns);
  UA_UNUSED(encoder);
}

void BaseConfigurationRecordDataType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::BaseConfigurationRecordDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::BaseConfigurationRecordDataType::decode(limit, *xml, *this);
  }
}

void BaseConfigurationRecordDataType::append_fields(std::string& output, int indent) const
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
    output += pad + "record_properties=" + ua::to_string(record_properties());
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
  output += "record_properties=" + ua::to_string(record_properties());
}

String& BaseConfigurationRecordDataType::name()
{
  return mName;
}

const String& BaseConfigurationRecordDataType::name() const
{
  return mName;
}

Array<KeyValuePair>& BaseConfigurationRecordDataType::record_properties()
{
  return mRecordProperties;
}

const Array<KeyValuePair>& BaseConfigurationRecordDataType::record_properties() const
{
  return mRecordProperties;
}

BuiltInTypeId BaseConfigurationRecordDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::SecuritySettingsDataType
{
namespace
{
void encode(StackDepth limit, const ua::SecuritySettingsDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.security_modes());
  encoder.encode(limit, value.security_policy_uris());
  encoder.encode(limit, value.certificate_group_name());
}

void encode(StackDepth limit, const ua::SecuritySettingsDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "SecurityModes", value.security_modes());
  encoder.encode(limit, "SecurityPolicyUris", value.security_policy_uris());
  encoder.encode(limit, "CertificateGroupName", value.certificate_group_name());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::SecuritySettingsDataType& value)
{
  decoder.decode(limit, value.security_modes());
  decoder.decode(limit, value.security_policy_uris());
  decoder.decode(limit, value.certificate_group_name());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::SecuritySettingsDataType& value)
{
  decoder.decode(limit, "SecurityModes", true, value.security_modes());
  decoder.decode(limit, "SecurityPolicyUris", true, value.security_policy_uris());
  decoder.decode(limit, "CertificateGroupName", true, value.certificate_group_name());
}
}  // namespace
}  // namespace detail::SecuritySettingsDataType

namespace detail::SecuritySettingsDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::SecuritySettingsDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::SecuritySettingsDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::SecuritySettingsDataType

namespace detail::SecuritySettingsDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::SecuritySettingsDataType>();
}
}  // namespace
}  // namespace detail::SecuritySettingsDataType

bool SecuritySettingsDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return BaseConfigurationRecordDataType::is_of_type(ns, dataTypeId);
}

NodeId SecuritySettingsDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId SecuritySettingsDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String SecuritySettingsDataType::type_name() const
{
  return typeName;
}

void SecuritySettingsDataType::encode(StackDepth limit, Encoder& encoder) const
{

  BaseConfigurationRecordDataType::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SecuritySettingsDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SecuritySettingsDataType::encode(limit, *this, *xml);
  }
}

void SecuritySettingsDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SecuritySettingsDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SecuritySettingsDataType::encode_id(limit, ns, *xml);
  }
}

void SecuritySettingsDataType::decode(StackDepth limit, Decoder& decoder)
{

  BaseConfigurationRecordDataType::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::SecuritySettingsDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::SecuritySettingsDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> SecuritySettingsDataType::clone() const
{
  return make_unique<SecuritySettingsDataType>(*this);
}

void SecuritySettingsDataType::append_fields(std::string& output, int indent) const
{
  BaseConfigurationRecordDataType::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "security_modes=" + ua::to_string(security_modes());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "security_policy_uris=" + ua::to_string(security_policy_uris());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "certificate_group_name=" + ua::to_string(certificate_group_name());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "security_modes=" + ua::to_string(security_modes());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "security_policy_uris=" + ua::to_string(security_policy_uris());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "certificate_group_name=" + ua::to_string(certificate_group_name());
}

std::string SecuritySettingsDataType::to_string(int indent) const
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

void SecuritySettingsDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::SecuritySettingsDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::SecuritySettingsDataType::create);
  }
}

Array<MessageSecurityMode>& SecuritySettingsDataType::security_modes()
{
  return mSecurityModes;
}

const Array<MessageSecurityMode>& SecuritySettingsDataType::security_modes() const
{
  return mSecurityModes;
}

Array<String>& SecuritySettingsDataType::security_policy_uris()
{
  return mSecurityPolicyUris;
}

const Array<String>& SecuritySettingsDataType::security_policy_uris() const
{
  return mSecurityPolicyUris;
}

String& SecuritySettingsDataType::certificate_group_name()
{
  return mCertificateGroupName;
}

const String& SecuritySettingsDataType::certificate_group_name() const
{
  return mCertificateGroupName;
}

BuiltInTypeId SecuritySettingsDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::SimpleTypeDescription
{
namespace
{
void encode(StackDepth limit, const ua::SimpleTypeDescription& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.base_data_type());
  encoder.encode(limit, value.built_in_type());
}

void encode(StackDepth limit, const ua::SimpleTypeDescription& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "BaseDataType", value.base_data_type());
  encoder.encode(limit, "BuiltInType", value.built_in_type());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::SimpleTypeDescription& value)
{
  decoder.decode(limit, value.base_data_type());
  decoder.decode(limit, value.built_in_type());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::SimpleTypeDescription& value)
{
  decoder.decode(limit, "BaseDataType", true, value.base_data_type());
  decoder.decode(limit, "BuiltInType", true, value.built_in_type());
}
}  // namespace
}  // namespace detail::SimpleTypeDescription

namespace detail::SimpleTypeDescription
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::SimpleTypeDescription::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::SimpleTypeDescription::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::SimpleTypeDescription

namespace detail::SimpleTypeDescription
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::SimpleTypeDescription>();
}
}  // namespace
}  // namespace detail::SimpleTypeDescription

bool SimpleTypeDescription::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return DataTypeDescription::is_of_type(ns, dataTypeId);
}

NodeId SimpleTypeDescription::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId SimpleTypeDescription::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String SimpleTypeDescription::type_name() const
{
  return typeName;
}

void SimpleTypeDescription::encode(StackDepth limit, Encoder& encoder) const
{

  DataTypeDescription::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SimpleTypeDescription::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SimpleTypeDescription::encode(limit, *this, *xml);
  }
}

void SimpleTypeDescription::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SimpleTypeDescription::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SimpleTypeDescription::encode_id(limit, ns, *xml);
  }
}

void SimpleTypeDescription::decode(StackDepth limit, Decoder& decoder)
{

  DataTypeDescription::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::SimpleTypeDescription::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::SimpleTypeDescription::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> SimpleTypeDescription::clone() const
{
  return make_unique<SimpleTypeDescription>(*this);
}

void SimpleTypeDescription::append_fields(std::string& output, int indent) const
{
  DataTypeDescription::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "base_data_type=" + ua::to_string(base_data_type());
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
  output += "base_data_type=" + ua::to_string(base_data_type());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "built_in_type=" + ua::to_string(built_in_type());
}

std::string SimpleTypeDescription::to_string(int indent) const
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

void SimpleTypeDescription::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::SimpleTypeDescription::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::SimpleTypeDescription::create);
  }
}

NodeId& SimpleTypeDescription::base_data_type()
{
  return mBaseDataType;
}

const NodeId& SimpleTypeDescription::base_data_type() const
{
  return mBaseDataType;
}

uint8_t& SimpleTypeDescription::built_in_type()
{
  return mBuiltInType;
}

const uint8_t& SimpleTypeDescription::built_in_type() const
{
  return mBuiltInType;
}

BuiltInTypeId SimpleTypeDescription::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::LldpManagementAddressTxPortType
{
namespace
{
void encode(StackDepth limit, const ua::LldpManagementAddressTxPortType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.address_subtype());
  encoder.encode(limit, value.man_address());
  encoder.encode(limit, value.tx_enable());
  encoder.encode(limit, value.addr_len());
  encoder.encode(limit, utils::as_int32(value.if_subtype()));
  encoder.encode(limit, value.if_id());
}

void encode(StackDepth limit, const ua::LldpManagementAddressTxPortType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "AddressSubtype", value.address_subtype());
  encoder.encode(limit, "ManAddress", value.man_address());
  encoder.encode(limit, "TxEnable", value.tx_enable());
  encoder.encode(limit, "AddrLen", value.addr_len());
  encoder.encode(limit, "IfSubtype", utils::as_int32(value.if_subtype()));
  encoder.encode(limit, "IfId", value.if_id());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::LldpManagementAddressTxPortType& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.address_subtype());
  decoder.decode(limit, value.man_address());
  decoder.decode(limit, value.tx_enable());
  decoder.decode(limit, value.addr_len());
  decoder.decode(limit, enumVal);
  value.if_subtype() = utils::from_underlying<ManAddrIfSubtype>(enumVal);
  decoder.decode(limit, value.if_id());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::LldpManagementAddressTxPortType& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "AddressSubtype", true, value.address_subtype());
  decoder.decode(limit, "ManAddress", true, value.man_address());
  decoder.decode(limit, "TxEnable", true, value.tx_enable());
  decoder.decode(limit, "AddrLen", true, value.addr_len());
  decoder.decode(limit, "IfSubtype", true, enumVal);
  value.if_subtype() = utils::from_underlying<ManAddrIfSubtype>(enumVal);
  decoder.decode(limit, "IfId", true, value.if_id());
}
}  // namespace
}  // namespace detail::LldpManagementAddressTxPortType

namespace detail::LldpManagementAddressTxPortType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::LldpManagementAddressTxPortType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::LldpManagementAddressTxPortType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::LldpManagementAddressTxPortType

namespace detail::LldpManagementAddressTxPortType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::LldpManagementAddressTxPortType>();
}
}  // namespace
}  // namespace detail::LldpManagementAddressTxPortType

bool LldpManagementAddressTxPortType::is_of_type(
  const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId LldpManagementAddressTxPortType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId LldpManagementAddressTxPortType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String LldpManagementAddressTxPortType::type_name() const
{
  return typeName;
}

void LldpManagementAddressTxPortType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::LldpManagementAddressTxPortType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::LldpManagementAddressTxPortType::encode(limit, *this, *xml);
  }
}

void LldpManagementAddressTxPortType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::LldpManagementAddressTxPortType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::LldpManagementAddressTxPortType::encode_id(limit, ns, *xml);
  }
}

void LldpManagementAddressTxPortType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::LldpManagementAddressTxPortType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::LldpManagementAddressTxPortType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> LldpManagementAddressTxPortType::clone() const
{
  return make_unique<LldpManagementAddressTxPortType>(*this);
}

void LldpManagementAddressTxPortType::append_fields(std::string& output, int indent) const
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
    output += pad + "man_address=" + ua::to_string(man_address());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "tx_enable=" + ua::to_string(tx_enable());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "addr_len=" + ua::to_string(addr_len());
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
  output += "man_address=" + ua::to_string(man_address());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "tx_enable=" + ua::to_string(tx_enable());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "addr_len=" + ua::to_string(addr_len());
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

std::string LldpManagementAddressTxPortType::to_string(int indent) const
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

void LldpManagementAddressTxPortType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::LldpManagementAddressTxPortType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::LldpManagementAddressTxPortType::create);
  }
}

uint32_t& LldpManagementAddressTxPortType::address_subtype()
{
  return mAddressSubtype;
}

const uint32_t& LldpManagementAddressTxPortType::address_subtype() const
{
  return mAddressSubtype;
}

String& LldpManagementAddressTxPortType::man_address()
{
  return mManAddress;
}

const String& LldpManagementAddressTxPortType::man_address() const
{
  return mManAddress;
}

bool& LldpManagementAddressTxPortType::tx_enable()
{
  return mTxEnable;
}

const bool& LldpManagementAddressTxPortType::tx_enable() const
{
  return mTxEnable;
}

uint32_t& LldpManagementAddressTxPortType::addr_len()
{
  return mAddrLen;
}

const uint32_t& LldpManagementAddressTxPortType::addr_len() const
{
  return mAddrLen;
}

ManAddrIfSubtype& LldpManagementAddressTxPortType::if_subtype()
{
  return mIfSubtype;
}

const ManAddrIfSubtype& LldpManagementAddressTxPortType::if_subtype() const
{
  return mIfSubtype;
}

uint32_t& LldpManagementAddressTxPortType::if_id()
{
  return mIfId;
}

const uint32_t& LldpManagementAddressTxPortType::if_id() const
{
  return mIfId;
}

BuiltInTypeId LldpManagementAddressTxPortType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::TraceContextDataType
{
namespace
{
void encode(StackDepth limit, const ua::TraceContextDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.parent_span_id());
  encoder.encode(limit, value.parent_identifier());
}

void encode(StackDepth limit, const ua::TraceContextDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ParentSpanId", value.parent_span_id());
  encoder.encode(limit, "ParentIdentifier", value.parent_identifier());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::TraceContextDataType& value)
{
  decoder.decode(limit, value.parent_span_id());
  decoder.decode(limit, value.parent_identifier());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::TraceContextDataType& value)
{
  decoder.decode(limit, "ParentSpanId", true, value.parent_span_id());
  decoder.decode(limit, "ParentIdentifier", true, value.parent_identifier());
}
}  // namespace
}  // namespace detail::TraceContextDataType

namespace detail::TraceContextDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::TraceContextDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::TraceContextDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::TraceContextDataType

namespace detail::TraceContextDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::TraceContextDataType>();
}
}  // namespace
}  // namespace detail::TraceContextDataType

bool TraceContextDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return SpanContextDataType::is_of_type(ns, dataTypeId);
}

NodeId TraceContextDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId TraceContextDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String TraceContextDataType::type_name() const
{
  return typeName;
}

void TraceContextDataType::encode(StackDepth limit, Encoder& encoder) const
{

  SpanContextDataType::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::TraceContextDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::TraceContextDataType::encode(limit, *this, *xml);
  }
}

void TraceContextDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::TraceContextDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::TraceContextDataType::encode_id(limit, ns, *xml);
  }
}

void TraceContextDataType::decode(StackDepth limit, Decoder& decoder)
{

  SpanContextDataType::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::TraceContextDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::TraceContextDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> TraceContextDataType::clone() const
{
  return make_unique<TraceContextDataType>(*this);
}

void TraceContextDataType::append_fields(std::string& output, int indent) const
{
  SpanContextDataType::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "parent_span_id=" + ua::to_string(parent_span_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "parent_identifier=" + ua::to_string(parent_identifier());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "parent_span_id=" + ua::to_string(parent_span_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "parent_identifier=" + ua::to_string(parent_identifier());
}

std::string TraceContextDataType::to_string(int indent) const
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

void TraceContextDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::TraceContextDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::TraceContextDataType::create);
  }
}

uint64_t& TraceContextDataType::parent_span_id()
{
  return mParentSpanId;
}

const uint64_t& TraceContextDataType::parent_span_id() const
{
  return mParentSpanId;
}

String& TraceContextDataType::parent_identifier()
{
  return mParentIdentifier;
}

const String& TraceContextDataType::parent_identifier() const
{
  return mParentIdentifier;
}

BuiltInTypeId TraceContextDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::EnumValueType
{
namespace
{
void encode(StackDepth limit, const ua::EnumValueType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.value());
  encoder.encode(limit, value.display_name());
  encoder.encode(limit, value.description());
}

void encode(StackDepth limit, const ua::EnumValueType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Value", value.value());
  encoder.encode(limit, "DisplayName", value.display_name());
  encoder.encode(limit, "Description", value.description());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::EnumValueType& value)
{
  decoder.decode(limit, value.value());
  decoder.decode(limit, value.display_name());
  decoder.decode(limit, value.description());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::EnumValueType& value)
{
  decoder.decode(limit, "Value", true, value.value());
  decoder.decode(limit, "DisplayName", true, value.display_name());
  decoder.decode(limit, "Description", true, value.description());
}
}  // namespace
}  // namespace detail::EnumValueType

namespace detail::EnumValueType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::EnumValueType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::EnumValueType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::EnumValueType

namespace detail::EnumValueType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::EnumValueType>();
}
}  // namespace
}  // namespace detail::EnumValueType

bool EnumValueType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId EnumValueType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId EnumValueType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String EnumValueType::type_name() const
{
  return typeName;
}

void EnumValueType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EnumValueType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EnumValueType::encode(limit, *this, *xml);
  }
}

void EnumValueType::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EnumValueType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EnumValueType::encode_id(limit, ns, *xml);
  }
}

void EnumValueType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::EnumValueType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::EnumValueType::decode(limit, *xml, *this);
  }
}

void EnumValueType::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  mDisplayName = mDisplayName.resolve(locales);
  mDescription = mDescription.resolve(locales);
}

unique_ptr<Structure> EnumValueType::clone() const
{
  return make_unique<EnumValueType>(*this);
}

void EnumValueType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
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
  output += "value=" + ua::to_string(value());
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

std::string EnumValueType::to_string(int indent) const
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

void EnumValueType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::EnumValueType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::EnumValueType::create);
  }
}

int64_t& EnumValueType::value()
{
  return mValue;
}

const int64_t& EnumValueType::value() const
{
  return mValue;
}

LocalizedText& EnumValueType::display_name()
{
  return mDisplayName;
}

const LocalizedText& EnumValueType::display_name() const
{
  return mDisplayName;
}

LocalizedText& EnumValueType::description()
{
  return mDescription;
}

const LocalizedText& EnumValueType::description() const
{
  return mDescription;
}

BuiltInTypeId EnumValueType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::RegisteredServer
{
namespace
{
void encode(StackDepth limit, const ua::RegisteredServer& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.server_uri());
  encoder.encode(limit, value.product_uri());
  encoder.encode(limit, value.server_names());
  encoder.encode(limit, utils::as_int32(value.server_type()));
  encoder.encode(limit, value.gateway_server_uri());
  encoder.encode(limit, value.discovery_urls());
  encoder.encode(limit, value.semaphore_file_path());
  encoder.encode(limit, value.is_online());
}

void encode(StackDepth limit, const ua::RegisteredServer& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ServerUri", value.server_uri());
  encoder.encode(limit, "ProductUri", value.product_uri());
  encoder.encode(limit, "ServerNames", value.server_names());
  encoder.encode(limit, "ServerType", utils::as_int32(value.server_type()));
  encoder.encode(limit, "GatewayServerUri", value.gateway_server_uri());
  encoder.encode(limit, "DiscoveryUrls", value.discovery_urls());
  encoder.encode(limit, "SemaphoreFilePath", value.semaphore_file_path());
  encoder.encode(limit, "IsOnline", value.is_online());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::RegisteredServer& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.server_uri());
  decoder.decode(limit, value.product_uri());
  decoder.decode(limit, value.server_names());
  decoder.decode(limit, enumVal);
  value.server_type() = utils::from_underlying<ApplicationType>(enumVal);
  decoder.decode(limit, value.gateway_server_uri());
  decoder.decode(limit, value.discovery_urls());
  decoder.decode(limit, value.semaphore_file_path());
  decoder.decode(limit, value.is_online());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::RegisteredServer& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "ServerUri", true, value.server_uri());
  decoder.decode(limit, "ProductUri", true, value.product_uri());
  decoder.decode(limit, "ServerNames", true, value.server_names());
  decoder.decode(limit, "ServerType", true, enumVal);
  value.server_type() = utils::from_underlying<ApplicationType>(enumVal);
  decoder.decode(limit, "GatewayServerUri", true, value.gateway_server_uri());
  decoder.decode(limit, "DiscoveryUrls", true, value.discovery_urls());
  decoder.decode(limit, "SemaphoreFilePath", true, value.semaphore_file_path());
  decoder.decode(limit, "IsOnline", true, value.is_online());
}
}  // namespace
}  // namespace detail::RegisteredServer

namespace detail::RegisteredServer
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::RegisteredServer::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::RegisteredServer::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::RegisteredServer

namespace detail::RegisteredServer
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::RegisteredServer>();
}
}  // namespace
}  // namespace detail::RegisteredServer

bool RegisteredServer::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId RegisteredServer::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId RegisteredServer::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String RegisteredServer::type_name() const
{
  return typeName;
}

void RegisteredServer::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RegisteredServer::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RegisteredServer::encode(limit, *this, *xml);
  }
}

void RegisteredServer::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RegisteredServer::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RegisteredServer::encode_id(limit, ns, *xml);
  }
}

void RegisteredServer::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::RegisteredServer::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::RegisteredServer::decode(limit, *xml, *this);
  }
}

void RegisteredServer::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  for (size_t i = 0; i < mServerNames.size(); ++i)
  {
    mServerNames[i] = mServerNames[i].resolve(locales);
  }
}

unique_ptr<Structure> RegisteredServer::clone() const
{
  return make_unique<RegisteredServer>(*this);
}

void RegisteredServer::append_fields(std::string& output, int indent) const
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
    output += pad + "product_uri=" + ua::to_string(product_uri());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "server_names=" + ua::to_string(server_names());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "server_type=" + ua::to_string(utils::as_int32(server_type()));
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "gateway_server_uri=" + ua::to_string(gateway_server_uri());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "discovery_urls=" + ua::to_string(discovery_urls());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "semaphore_file_path=" + ua::to_string(semaphore_file_path());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "is_online=" + ua::to_string(is_online());
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
  output += "product_uri=" + ua::to_string(product_uri());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "server_names=" + ua::to_string(server_names());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "server_type=" + ua::to_string(utils::as_int32(server_type()));
  if (!output.empty())
  {
    output += ", ";
  }
  output += "gateway_server_uri=" + ua::to_string(gateway_server_uri());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "discovery_urls=" + ua::to_string(discovery_urls());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "semaphore_file_path=" + ua::to_string(semaphore_file_path());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "is_online=" + ua::to_string(is_online());
}

std::string RegisteredServer::to_string(int indent) const
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

void RegisteredServer::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::RegisteredServer::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::RegisteredServer::create);
  }
}

String& RegisteredServer::server_uri()
{
  return mServerUri;
}

const String& RegisteredServer::server_uri() const
{
  return mServerUri;
}

String& RegisteredServer::product_uri()
{
  return mProductUri;
}

const String& RegisteredServer::product_uri() const
{
  return mProductUri;
}

Array<LocalizedText>& RegisteredServer::server_names()
{
  return mServerNames;
}

const Array<LocalizedText>& RegisteredServer::server_names() const
{
  return mServerNames;
}

ApplicationType& RegisteredServer::server_type()
{
  return mServerType;
}

const ApplicationType& RegisteredServer::server_type() const
{
  return mServerType;
}

String& RegisteredServer::gateway_server_uri()
{
  return mGatewayServerUri;
}

const String& RegisteredServer::gateway_server_uri() const
{
  return mGatewayServerUri;
}

Array<String>& RegisteredServer::discovery_urls()
{
  return mDiscoveryUrls;
}

const Array<String>& RegisteredServer::discovery_urls() const
{
  return mDiscoveryUrls;
}

String& RegisteredServer::semaphore_file_path()
{
  return mSemaphoreFilePath;
}

const String& RegisteredServer::semaphore_file_path() const
{
  return mSemaphoreFilePath;
}

bool& RegisteredServer::is_online()
{
  return mIsOnline;
}

const bool& RegisteredServer::is_online() const
{
  return mIsOnline;
}

BuiltInTypeId RegisteredServer::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::IssuedIdentityToken
{
namespace
{
void encode(StackDepth limit, const ua::IssuedIdentityToken& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.token_data());
  encoder.encode(limit, value.encryption_algorithm());
}

void encode(StackDepth limit, const ua::IssuedIdentityToken& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "TokenData", value.token_data());
  encoder.encode(limit, "EncryptionAlgorithm", value.encryption_algorithm());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::IssuedIdentityToken& value)
{
  decoder.decode(limit, value.token_data());
  decoder.decode(limit, value.encryption_algorithm());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::IssuedIdentityToken& value)
{
  decoder.decode(limit, "TokenData", true, value.token_data());
  decoder.decode(limit, "EncryptionAlgorithm", true, value.encryption_algorithm());
}
}  // namespace
}  // namespace detail::IssuedIdentityToken

namespace detail::IssuedIdentityToken
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::IssuedIdentityToken::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::IssuedIdentityToken::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::IssuedIdentityToken

namespace detail::IssuedIdentityToken
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::IssuedIdentityToken>();
}
}  // namespace
}  // namespace detail::IssuedIdentityToken

bool IssuedIdentityToken::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return UserIdentityToken::is_of_type(ns, dataTypeId);
}

NodeId IssuedIdentityToken::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId IssuedIdentityToken::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String IssuedIdentityToken::type_name() const
{
  return typeName;
}

void IssuedIdentityToken::encode(StackDepth limit, Encoder& encoder) const
{

  UserIdentityToken::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::IssuedIdentityToken::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::IssuedIdentityToken::encode(limit, *this, *xml);
  }
}

void IssuedIdentityToken::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::IssuedIdentityToken::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::IssuedIdentityToken::encode_id(limit, ns, *xml);
  }
}

void IssuedIdentityToken::decode(StackDepth limit, Decoder& decoder)
{

  UserIdentityToken::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::IssuedIdentityToken::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::IssuedIdentityToken::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> IssuedIdentityToken::clone() const
{
  return make_unique<IssuedIdentityToken>(*this);
}

void IssuedIdentityToken::append_fields(std::string& output, int indent) const
{
  UserIdentityToken::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "token_data=" + ua::to_string(token_data());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "encryption_algorithm=" + ua::to_string(encryption_algorithm());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "token_data=" + ua::to_string(token_data());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "encryption_algorithm=" + ua::to_string(encryption_algorithm());
}

std::string IssuedIdentityToken::to_string(int indent) const
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

void IssuedIdentityToken::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::IssuedIdentityToken::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::IssuedIdentityToken::create);
  }
}

ByteString& IssuedIdentityToken::token_data()
{
  return mTokenData;
}

const ByteString& IssuedIdentityToken::token_data() const
{
  return mTokenData;
}

String& IssuedIdentityToken::encryption_algorithm()
{
  return mEncryptionAlgorithm;
}

const String& IssuedIdentityToken::encryption_algorithm() const
{
  return mEncryptionAlgorithm;
}

BuiltInTypeId IssuedIdentityToken::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ContentFilterElement
{
namespace
{
void encode(StackDepth limit, const ua::ContentFilterElement& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, utils::as_int32(value.filter_operator()));
  encoder.encode(limit, value.filter_operands());
}

void encode(StackDepth limit, const ua::ContentFilterElement& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "FilterOperator", utils::as_int32(value.filter_operator()));
  encoder.encode(limit, "FilterOperands", value.filter_operands());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ContentFilterElement& value)
{
  int32_t enumVal{};
  decoder.decode(limit, enumVal);
  value.filter_operator() = utils::from_underlying<FilterOperator>(enumVal);
  decoder.decode(limit, value.filter_operands());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ContentFilterElement& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "FilterOperator", true, enumVal);
  value.filter_operator() = utils::from_underlying<FilterOperator>(enumVal);
  decoder.decode(limit, "FilterOperands", true, value.filter_operands());
}
}  // namespace
}  // namespace detail::ContentFilterElement

namespace detail::ContentFilterElement
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ContentFilterElement::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ContentFilterElement::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ContentFilterElement

namespace detail::ContentFilterElement
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ContentFilterElement>();
}
}  // namespace
}  // namespace detail::ContentFilterElement

bool ContentFilterElement::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ContentFilterElement::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ContentFilterElement::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ContentFilterElement::type_name() const
{
  return typeName;
}

void ContentFilterElement::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ContentFilterElement::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ContentFilterElement::encode(limit, *this, *xml);
  }
}

void ContentFilterElement::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ContentFilterElement::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ContentFilterElement::encode_id(limit, ns, *xml);
  }
}

void ContentFilterElement::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ContentFilterElement::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ContentFilterElement::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ContentFilterElement::clone() const
{
  return make_unique<ContentFilterElement>(*this);
}

void ContentFilterElement::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "filter_operator=" + ua::to_string(utils::as_int32(filter_operator()));
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "filter_operands=" + ua::to_string(filter_operands(), indent);
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "filter_operator=" + ua::to_string(utils::as_int32(filter_operator()));
  if (!output.empty())
  {
    output += ", ";
  }
  output += "filter_operands=" + ua::to_string(filter_operands());
}

std::string ContentFilterElement::to_string(int indent) const
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

void ContentFilterElement::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ContentFilterElement::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ContentFilterElement::create);
  }
}

FilterOperator& ContentFilterElement::filter_operator()
{
  return mFilterOperator;
}

const FilterOperator& ContentFilterElement::filter_operator() const
{
  return mFilterOperator;
}

Array<RefStructure<Structure>>& ContentFilterElement::filter_operands()
{
  return mFilterOperands;
}

const Array<RefStructure<Structure>>& ContentFilterElement::filter_operands() const
{
  return mFilterOperands;
}

BuiltInTypeId ContentFilterElement::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::HistoryEvent
{
namespace
{
void encode(StackDepth limit, const ua::HistoryEvent& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.events());
}

void encode(StackDepth limit, const ua::HistoryEvent& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Events", value.events());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::HistoryEvent& value)
{
  decoder.decode(limit, value.events());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::HistoryEvent& value)
{
  decoder.decode(limit, "Events", true, value.events());
}
}  // namespace
}  // namespace detail::HistoryEvent

namespace detail::HistoryEvent
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::HistoryEvent::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::HistoryEvent::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::HistoryEvent

namespace detail::HistoryEvent
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::HistoryEvent>();
}
}  // namespace
}  // namespace detail::HistoryEvent

bool HistoryEvent::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId HistoryEvent::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId HistoryEvent::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String HistoryEvent::type_name() const
{
  return typeName;
}

void HistoryEvent::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::HistoryEvent::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::HistoryEvent::encode(limit, *this, *xml);
  }
}

void HistoryEvent::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::HistoryEvent::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::HistoryEvent::encode_id(limit, ns, *xml);
  }
}

void HistoryEvent::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::HistoryEvent::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::HistoryEvent::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> HistoryEvent::clone() const
{
  return make_unique<HistoryEvent>(*this);
}

void HistoryEvent::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
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

std::string HistoryEvent::to_string(int indent) const
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

void HistoryEvent::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::HistoryEvent::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::HistoryEvent::create);
  }
}

Array<HistoryEventFieldList>& HistoryEvent::events()
{
  return mEvents;
}

const Array<HistoryEventFieldList>& HistoryEvent::events() const
{
  return mEvents;
}

BuiltInTypeId HistoryEvent::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::EndpointUrlListDataType
{
namespace
{
void encode(StackDepth limit, const ua::EndpointUrlListDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.endpoint_url_list());
}

void encode(StackDepth limit, const ua::EndpointUrlListDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "EndpointUrlList", value.endpoint_url_list());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::EndpointUrlListDataType& value)
{
  decoder.decode(limit, value.endpoint_url_list());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::EndpointUrlListDataType& value)
{
  decoder.decode(limit, "EndpointUrlList", true, value.endpoint_url_list());
}
}  // namespace
}  // namespace detail::EndpointUrlListDataType

namespace detail::EndpointUrlListDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::EndpointUrlListDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::EndpointUrlListDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::EndpointUrlListDataType

namespace detail::EndpointUrlListDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::EndpointUrlListDataType>();
}
}  // namespace
}  // namespace detail::EndpointUrlListDataType

bool EndpointUrlListDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId EndpointUrlListDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId EndpointUrlListDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String EndpointUrlListDataType::type_name() const
{
  return typeName;
}

void EndpointUrlListDataType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EndpointUrlListDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EndpointUrlListDataType::encode(limit, *this, *xml);
  }
}

void EndpointUrlListDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EndpointUrlListDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EndpointUrlListDataType::encode_id(limit, ns, *xml);
  }
}

void EndpointUrlListDataType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::EndpointUrlListDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::EndpointUrlListDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> EndpointUrlListDataType::clone() const
{
  return make_unique<EndpointUrlListDataType>(*this);
}

void EndpointUrlListDataType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "endpoint_url_list=" + ua::to_string(endpoint_url_list());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "endpoint_url_list=" + ua::to_string(endpoint_url_list());
}

std::string EndpointUrlListDataType::to_string(int indent) const
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

void EndpointUrlListDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::EndpointUrlListDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::EndpointUrlListDataType::create);
  }
}

Array<String>& EndpointUrlListDataType::endpoint_url_list()
{
  return mEndpointUrlList;
}

const Array<String>& EndpointUrlListDataType::endpoint_url_list() const
{
  return mEndpointUrlList;
}

BuiltInTypeId EndpointUrlListDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::StatusResult
{
namespace
{
void encode(StackDepth limit, const ua::StatusResult& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.status_code());
  encoder.encode(limit, value.diagnostic_info());
}

void encode(StackDepth limit, const ua::StatusResult& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "StatusCode", value.status_code());
  encoder.encode(limit, "DiagnosticInfo", value.diagnostic_info());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::StatusResult& value)
{
  decoder.decode(limit, value.status_code());
  decoder.decode(limit, value.diagnostic_info());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::StatusResult& value)
{
  decoder.decode(limit, "StatusCode", true, value.status_code());
  decoder.decode(limit, "DiagnosticInfo", true, value.diagnostic_info());
}
}  // namespace
}  // namespace detail::StatusResult

namespace detail::StatusResult
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::StatusResult::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::StatusResult::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::StatusResult

namespace detail::StatusResult
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::StatusResult>();
}
}  // namespace
}  // namespace detail::StatusResult

bool StatusResult::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId StatusResult::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId StatusResult::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String StatusResult::type_name() const
{
  return typeName;
}

void StatusResult::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::StatusResult::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::StatusResult::encode(limit, *this, *xml);
  }
}

void StatusResult::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::StatusResult::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::StatusResult::encode_id(limit, ns, *xml);
  }
}

void StatusResult::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::StatusResult::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::StatusResult::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> StatusResult::clone() const
{
  return make_unique<StatusResult>(*this);
}

void StatusResult::append_fields(std::string& output, int indent) const
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
    output += pad + "diagnostic_info=" + ua::to_string(diagnostic_info());
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
  output += "diagnostic_info=" + ua::to_string(diagnostic_info());
}

std::string StatusResult::to_string(int indent) const
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

void StatusResult::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::StatusResult::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::StatusResult::create);
  }
}

StatusCode& StatusResult::status_code()
{
  return mStatusCode;
}

const StatusCode& StatusResult::status_code() const
{
  return mStatusCode;
}

DiagnosticInfo& StatusResult::diagnostic_info()
{
  return mDiagnosticInfo;
}

const DiagnosticInfo& StatusResult::diagnostic_info() const
{
  return mDiagnosticInfo;
}

BuiltInTypeId StatusResult::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::AxisInformation
{
namespace
{
void encode(StackDepth limit, const ua::AxisInformation& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.engineering_units());
  encoder.encode(limit, value.eu_range());
  encoder.encode(limit, value.title());
  encoder.encode(limit, utils::as_int32(value.axis_scale_type()));
  encoder.encode(limit, value.axis_steps());
}

void encode(StackDepth limit, const ua::AxisInformation& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "EngineeringUnits", value.engineering_units());
  encoder.encode(limit, "EURange", value.eu_range());
  encoder.encode(limit, "Title", value.title());
  encoder.encode(limit, "AxisScaleType", utils::as_int32(value.axis_scale_type()));
  encoder.encode(limit, "AxisSteps", value.axis_steps());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::AxisInformation& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.engineering_units());
  decoder.decode(limit, value.eu_range());
  decoder.decode(limit, value.title());
  decoder.decode(limit, enumVal);
  value.axis_scale_type() = utils::from_underlying<AxisScaleEnumeration>(enumVal);
  decoder.decode(limit, value.axis_steps());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::AxisInformation& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "EngineeringUnits", true, value.engineering_units());
  decoder.decode(limit, "EURange", true, value.eu_range());
  decoder.decode(limit, "Title", true, value.title());
  decoder.decode(limit, "AxisScaleType", true, enumVal);
  value.axis_scale_type() = utils::from_underlying<AxisScaleEnumeration>(enumVal);
  decoder.decode(limit, "AxisSteps", true, value.axis_steps());
}
}  // namespace
}  // namespace detail::AxisInformation

namespace detail::AxisInformation
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::AxisInformation::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::AxisInformation::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::AxisInformation

namespace detail::AxisInformation
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::AxisInformation>();
}
}  // namespace
}  // namespace detail::AxisInformation

bool AxisInformation::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId AxisInformation::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId AxisInformation::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String AxisInformation::type_name() const
{
  return typeName;
}

void AxisInformation::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AxisInformation::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AxisInformation::encode(limit, *this, *xml);
  }
}

void AxisInformation::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AxisInformation::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AxisInformation::encode_id(limit, ns, *xml);
  }
}

void AxisInformation::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::AxisInformation::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::AxisInformation::decode(limit, *xml, *this);
  }
}

void AxisInformation::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  mEngineeringUnits.resolve(locales);
  mTitle = mTitle.resolve(locales);
}

unique_ptr<Structure> AxisInformation::clone() const
{
  return make_unique<AxisInformation>(*this);
}

void AxisInformation::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "engineering_units=" + ua::to_string(engineering_units());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "eu_range=" + ua::to_string(eu_range());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "title=" + ua::to_string(title());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "axis_scale_type=" + ua::to_string(utils::as_int32(axis_scale_type()));
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "axis_steps=" + ua::to_string(axis_steps());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "engineering_units=" + ua::to_string(engineering_units());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "eu_range=" + ua::to_string(eu_range());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "title=" + ua::to_string(title());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "axis_scale_type=" + ua::to_string(utils::as_int32(axis_scale_type()));
  if (!output.empty())
  {
    output += ", ";
  }
  output += "axis_steps=" + ua::to_string(axis_steps());
}

std::string AxisInformation::to_string(int indent) const
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

void AxisInformation::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::AxisInformation::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::AxisInformation::create);
  }
}

EUInformation& AxisInformation::engineering_units()
{
  return mEngineeringUnits;
}

const EUInformation& AxisInformation::engineering_units() const
{
  return mEngineeringUnits;
}

Range& AxisInformation::eu_range()
{
  return mEURange;
}

const Range& AxisInformation::eu_range() const
{
  return mEURange;
}

LocalizedText& AxisInformation::title()
{
  return mTitle;
}

const LocalizedText& AxisInformation::title() const
{
  return mTitle;
}

AxisScaleEnumeration& AxisInformation::axis_scale_type()
{
  return mAxisScaleType;
}

const AxisScaleEnumeration& AxisInformation::axis_scale_type() const
{
  return mAxisScaleType;
}

Array<double>& AxisInformation::axis_steps()
{
  return mAxisSteps;
}

const Array<double>& AxisInformation::axis_steps() const
{
  return mAxisSteps;
}

BuiltInTypeId AxisInformation::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ServiceFault
{
namespace
{
void encode(StackDepth limit, const ua::ServiceFault& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
}

void encode(StackDepth limit, const ua::ServiceFault& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ServiceFault& value)
{
  decoder.decode(limit, value.response_header());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ServiceFault& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
}
}  // namespace
}  // namespace detail::ServiceFault

namespace detail::ServiceFault
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ServiceFault::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ServiceFault::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ServiceFault

namespace detail::ServiceFault
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ServiceFault>();
}
}  // namespace
}  // namespace detail::ServiceFault

bool ServiceFault::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ServiceFault::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ServiceFault::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ServiceFault::type_name() const
{
  return typeName;
}

void ServiceFault::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ServiceFault::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ServiceFault::encode(limit, *this, *xml);
  }
}

void ServiceFault::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ServiceFault::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ServiceFault::encode_id(limit, ns, *xml);
  }
}

void ServiceFault::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ServiceFault::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ServiceFault::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ServiceFault::clone() const
{
  return make_unique<ServiceFault>(*this);
}

void ServiceFault::append_fields(std::string& output, int indent) const
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

std::string ServiceFault::to_string(int indent) const
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

void ServiceFault::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ServiceFault::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ServiceFault::create);
  }
}

ResponseHeader& ServiceFault::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& ServiceFault::response_header() const
{
  return mResponseHeader;
}

BuiltInTypeId ServiceFault::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::GetEndpointsResponse
{
namespace
{
void encode(StackDepth limit, const ua::GetEndpointsResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.endpoints());
}

void encode(StackDepth limit, const ua::GetEndpointsResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "Endpoints", value.endpoints());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::GetEndpointsResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.endpoints());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::GetEndpointsResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "Endpoints", true, value.endpoints());
}
}  // namespace
}  // namespace detail::GetEndpointsResponse

namespace detail::GetEndpointsResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::GetEndpointsResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::GetEndpointsResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::GetEndpointsResponse

namespace detail::GetEndpointsResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::GetEndpointsResponse>();
}
}  // namespace
}  // namespace detail::GetEndpointsResponse

bool GetEndpointsResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId GetEndpointsResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId GetEndpointsResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String GetEndpointsResponse::type_name() const
{
  return typeName;
}

void GetEndpointsResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::GetEndpointsResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::GetEndpointsResponse::encode(limit, *this, *xml);
  }
}

void GetEndpointsResponse::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::GetEndpointsResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::GetEndpointsResponse::encode_id(limit, ns, *xml);
  }
}

void GetEndpointsResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::GetEndpointsResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::GetEndpointsResponse::decode(limit, *xml, *this);
  }
}

void GetEndpointsResponse::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  for (size_t i = 0; i < mEndpoints.size(); ++i)
  {
    mEndpoints[i].resolve(locales);
  }
}

unique_ptr<Structure> GetEndpointsResponse::clone() const
{
  return make_unique<GetEndpointsResponse>(*this);
}

void GetEndpointsResponse::append_fields(std::string& output, int indent) const
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
    output += pad + "endpoints=" + ua::to_string(endpoints());
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
  output += "endpoints=" + ua::to_string(endpoints());
}

std::string GetEndpointsResponse::to_string(int indent) const
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

void GetEndpointsResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::GetEndpointsResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::GetEndpointsResponse::create);
  }
}

ResponseHeader& GetEndpointsResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& GetEndpointsResponse::response_header() const
{
  return mResponseHeader;
}

Array<EndpointDescription>& GetEndpointsResponse::endpoints()
{
  return mEndpoints;
}

const Array<EndpointDescription>& GetEndpointsResponse::endpoints() const
{
  return mEndpoints;
}

BuiltInTypeId GetEndpointsResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::CloseSecureChannelRequest
{
namespace
{
void encode(StackDepth limit, const ua::CloseSecureChannelRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
}

void encode(StackDepth limit, const ua::CloseSecureChannelRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::CloseSecureChannelRequest& value)
{
  decoder.decode(limit, value.request_header());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::CloseSecureChannelRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
}
}  // namespace
}  // namespace detail::CloseSecureChannelRequest

namespace detail::CloseSecureChannelRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::CloseSecureChannelRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::CloseSecureChannelRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::CloseSecureChannelRequest

namespace detail::CloseSecureChannelRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::CloseSecureChannelRequest>();
}
}  // namespace
}  // namespace detail::CloseSecureChannelRequest

bool CloseSecureChannelRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId CloseSecureChannelRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId CloseSecureChannelRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String CloseSecureChannelRequest::type_name() const
{
  return typeName;
}

void CloseSecureChannelRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CloseSecureChannelRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CloseSecureChannelRequest::encode(limit, *this, *xml);
  }
}

void CloseSecureChannelRequest::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CloseSecureChannelRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CloseSecureChannelRequest::encode_id(limit, ns, *xml);
  }
}

void CloseSecureChannelRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::CloseSecureChannelRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::CloseSecureChannelRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> CloseSecureChannelRequest::clone() const
{
  return make_unique<CloseSecureChannelRequest>(*this);
}

void CloseSecureChannelRequest::append_fields(std::string& output, int indent) const
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
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "request_header=" + ua::to_string(request_header());
}

std::string CloseSecureChannelRequest::to_string(int indent) const
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

void CloseSecureChannelRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::CloseSecureChannelRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::CloseSecureChannelRequest::create);
  }
}

RequestHeader& CloseSecureChannelRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& CloseSecureChannelRequest::request_header() const
{
  return mRequestHeader;
}

BuiltInTypeId CloseSecureChannelRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::CloseSessionResponse
{
namespace
{
void encode(StackDepth limit, const ua::CloseSessionResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
}

void encode(StackDepth limit, const ua::CloseSessionResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::CloseSessionResponse& value)
{
  decoder.decode(limit, value.response_header());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::CloseSessionResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
}
}  // namespace
}  // namespace detail::CloseSessionResponse

namespace detail::CloseSessionResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::CloseSessionResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::CloseSessionResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::CloseSessionResponse

namespace detail::CloseSessionResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::CloseSessionResponse>();
}
}  // namespace
}  // namespace detail::CloseSessionResponse

bool CloseSessionResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId CloseSessionResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId CloseSessionResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String CloseSessionResponse::type_name() const
{
  return typeName;
}

void CloseSessionResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CloseSessionResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CloseSessionResponse::encode(limit, *this, *xml);
  }
}

void CloseSessionResponse::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CloseSessionResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CloseSessionResponse::encode_id(limit, ns, *xml);
  }
}

void CloseSessionResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::CloseSessionResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::CloseSessionResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> CloseSessionResponse::clone() const
{
  return make_unique<CloseSessionResponse>(*this);
}

void CloseSessionResponse::append_fields(std::string& output, int indent) const
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

std::string CloseSessionResponse::to_string(int indent) const
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

void CloseSessionResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::CloseSessionResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::CloseSessionResponse::create);
  }
}

ResponseHeader& CloseSessionResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& CloseSessionResponse::response_header() const
{
  return mResponseHeader;
}

BuiltInTypeId CloseSessionResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::VariableTypeAttributes
{
namespace
{
void encode(StackDepth limit, const ua::VariableTypeAttributes& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.value());
  encoder.encode(limit, value.data_type());
  encoder.encode(limit, value.value_rank());
  encoder.encode(limit, value.array_dimensions());
  encoder.encode(limit, value.is_abstract());
}

void encode(StackDepth limit, const ua::VariableTypeAttributes& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Value", value.value());
  encoder.encode(limit, "DataType", value.data_type());
  encoder.encode(limit, "ValueRank", value.value_rank());
  encoder.encode(limit, "ArrayDimensions", value.array_dimensions());
  encoder.encode(limit, "IsAbstract", value.is_abstract());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::VariableTypeAttributes& value)
{
  decoder.decode(limit, value.value());
  decoder.decode(limit, value.data_type());
  decoder.decode(limit, value.value_rank());
  decoder.decode(limit, value.array_dimensions());
  decoder.decode(limit, value.is_abstract());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::VariableTypeAttributes& value)
{
  decoder.decode(limit, "Value", true, value.value());
  decoder.decode(limit, "DataType", true, value.data_type());
  decoder.decode(limit, "ValueRank", true, value.value_rank());
  decoder.decode(limit, "ArrayDimensions", true, value.array_dimensions());
  decoder.decode(limit, "IsAbstract", true, value.is_abstract());
}
}  // namespace
}  // namespace detail::VariableTypeAttributes

namespace detail::VariableTypeAttributes
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::VariableTypeAttributes::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::VariableTypeAttributes::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::VariableTypeAttributes

namespace detail::VariableTypeAttributes
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::VariableTypeAttributes>();
}
}  // namespace
}  // namespace detail::VariableTypeAttributes

bool VariableTypeAttributes::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return NodeAttributes::is_of_type(ns, dataTypeId);
}

NodeId VariableTypeAttributes::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId VariableTypeAttributes::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String VariableTypeAttributes::type_name() const
{
  return typeName;
}

void VariableTypeAttributes::encode(StackDepth limit, Encoder& encoder) const
{

  NodeAttributes::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::VariableTypeAttributes::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::VariableTypeAttributes::encode(limit, *this, *xml);
  }
}

void VariableTypeAttributes::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::VariableTypeAttributes::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::VariableTypeAttributes::encode_id(limit, ns, *xml);
  }
}

void VariableTypeAttributes::decode(StackDepth limit, Decoder& decoder)
{

  NodeAttributes::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::VariableTypeAttributes::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::VariableTypeAttributes::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> VariableTypeAttributes::clone() const
{
  return make_unique<VariableTypeAttributes>(*this);
}

void VariableTypeAttributes::append_fields(std::string& output, int indent) const
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
    output += pad + "is_abstract=" + ua::to_string(is_abstract());
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
  output += "is_abstract=" + ua::to_string(is_abstract());
}

std::string VariableTypeAttributes::to_string(int indent) const
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

void VariableTypeAttributes::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::VariableTypeAttributes::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::VariableTypeAttributes::create);
  }
}

Variant& VariableTypeAttributes::value()
{
  return mValue;
}

const Variant& VariableTypeAttributes::value() const
{
  return mValue;
}

NodeId& VariableTypeAttributes::data_type()
{
  return mDataType;
}

const NodeId& VariableTypeAttributes::data_type() const
{
  return mDataType;
}

int32_t& VariableTypeAttributes::value_rank()
{
  return mValueRank;
}

const int32_t& VariableTypeAttributes::value_rank() const
{
  return mValueRank;
}

Array<uint32_t>& VariableTypeAttributes::array_dimensions()
{
  return mArrayDimensions;
}

const Array<uint32_t>& VariableTypeAttributes::array_dimensions() const
{
  return mArrayDimensions;
}

bool& VariableTypeAttributes::is_abstract()
{
  return mIsAbstract;
}

const bool& VariableTypeAttributes::is_abstract() const
{
  return mIsAbstract;
}

BuiltInTypeId VariableTypeAttributes::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::AddNodesResponse
{
namespace
{
void encode(StackDepth limit, const ua::AddNodesResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.results());
  encoder.encode(limit, value.diagnostic_infos());
}

void encode(StackDepth limit, const ua::AddNodesResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "Results", value.results());
  encoder.encode(limit, "DiagnosticInfos", value.diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::AddNodesResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.results());
  decoder.decode(limit, value.diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::AddNodesResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "Results", true, value.results());
  decoder.decode(limit, "DiagnosticInfos", true, value.diagnostic_infos());
}
}  // namespace
}  // namespace detail::AddNodesResponse

namespace detail::AddNodesResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::AddNodesResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::AddNodesResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::AddNodesResponse

namespace detail::AddNodesResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::AddNodesResponse>();
}
}  // namespace
}  // namespace detail::AddNodesResponse

bool AddNodesResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId AddNodesResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId AddNodesResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String AddNodesResponse::type_name() const
{
  return typeName;
}

void AddNodesResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AddNodesResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AddNodesResponse::encode(limit, *this, *xml);
  }
}

void AddNodesResponse::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AddNodesResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AddNodesResponse::encode_id(limit, ns, *xml);
  }
}

void AddNodesResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::AddNodesResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::AddNodesResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> AddNodesResponse::clone() const
{
  return make_unique<AddNodesResponse>(*this);
}

void AddNodesResponse::append_fields(std::string& output, int indent) const
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

std::string AddNodesResponse::to_string(int indent) const
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

void AddNodesResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::AddNodesResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::AddNodesResponse::create);
  }
}

ResponseHeader& AddNodesResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& AddNodesResponse::response_header() const
{
  return mResponseHeader;
}

Array<AddNodesResult>& AddNodesResponse::results()
{
  return mResults;
}

const Array<AddNodesResult>& AddNodesResponse::results() const
{
  return mResults;
}

Array<DiagnosticInfo>& AddNodesResponse::diagnostic_infos()
{
  return mDiagnosticInfos;
}

const Array<DiagnosticInfo>& AddNodesResponse::diagnostic_infos() const
{
  return mDiagnosticInfos;
}

BuiltInTypeId AddNodesResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::BrowseDescription
{
namespace
{
void encode(StackDepth limit, const ua::BrowseDescription& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.node_id());
  encoder.encode(limit, utils::as_int32(value.browse_direction()));
  encoder.encode(limit, value.reference_type_id());
  encoder.encode(limit, value.include_subtypes());
  encoder.encode(limit, value.node_class_mask());
  encoder.encode(limit, value.result_mask());
}

void encode(StackDepth limit, const ua::BrowseDescription& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "NodeId", value.node_id());
  encoder.encode(limit, "BrowseDirection", utils::as_int32(value.browse_direction()));
  encoder.encode(limit, "ReferenceTypeId", value.reference_type_id());
  encoder.encode(limit, "IncludeSubtypes", value.include_subtypes());
  encoder.encode(limit, "NodeClassMask", value.node_class_mask());
  encoder.encode(limit, "ResultMask", value.result_mask());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::BrowseDescription& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.node_id());
  decoder.decode(limit, enumVal);
  value.browse_direction() = utils::from_underlying<BrowseDirection>(enumVal);
  decoder.decode(limit, value.reference_type_id());
  decoder.decode(limit, value.include_subtypes());
  decoder.decode(limit, value.node_class_mask());
  decoder.decode(limit, value.result_mask());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::BrowseDescription& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "NodeId", true, value.node_id());
  decoder.decode(limit, "BrowseDirection", true, enumVal);
  value.browse_direction() = utils::from_underlying<BrowseDirection>(enumVal);
  decoder.decode(limit, "ReferenceTypeId", true, value.reference_type_id());
  decoder.decode(limit, "IncludeSubtypes", true, value.include_subtypes());
  decoder.decode(limit, "NodeClassMask", true, value.node_class_mask());
  decoder.decode(limit, "ResultMask", true, value.result_mask());
}
}  // namespace
}  // namespace detail::BrowseDescription

namespace detail::BrowseDescription
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::BrowseDescription::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::BrowseDescription::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::BrowseDescription

namespace detail::BrowseDescription
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::BrowseDescription>();
}
}  // namespace
}  // namespace detail::BrowseDescription

bool BrowseDescription::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId BrowseDescription::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId BrowseDescription::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String BrowseDescription::type_name() const
{
  return typeName;
}

void BrowseDescription::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::BrowseDescription::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::BrowseDescription::encode(limit, *this, *xml);
  }
}

void BrowseDescription::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::BrowseDescription::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::BrowseDescription::encode_id(limit, ns, *xml);
  }
}

void BrowseDescription::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::BrowseDescription::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::BrowseDescription::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> BrowseDescription::clone() const
{
  return make_unique<BrowseDescription>(*this);
}

void BrowseDescription::append_fields(std::string& output, int indent) const
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
    output += pad + "browse_direction=" + ua::to_string(utils::as_int32(browse_direction()));
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "reference_type_id=" + ua::to_string(reference_type_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "include_subtypes=" + ua::to_string(include_subtypes());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "node_class_mask=" + ua::to_string(node_class_mask());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "result_mask=" + ua::to_string(result_mask());
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
  output += "browse_direction=" + ua::to_string(utils::as_int32(browse_direction()));
  if (!output.empty())
  {
    output += ", ";
  }
  output += "reference_type_id=" + ua::to_string(reference_type_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "include_subtypes=" + ua::to_string(include_subtypes());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "node_class_mask=" + ua::to_string(node_class_mask());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "result_mask=" + ua::to_string(result_mask());
}

std::string BrowseDescription::to_string(int indent) const
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

void BrowseDescription::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::BrowseDescription::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::BrowseDescription::create);
  }
}

NodeId& BrowseDescription::node_id()
{
  return mNodeId;
}

const NodeId& BrowseDescription::node_id() const
{
  return mNodeId;
}

BrowseDirection& BrowseDescription::browse_direction()
{
  return mBrowseDirection;
}

const BrowseDirection& BrowseDescription::browse_direction() const
{
  return mBrowseDirection;
}

NodeId& BrowseDescription::reference_type_id()
{
  return mReferenceTypeId;
}

const NodeId& BrowseDescription::reference_type_id() const
{
  return mReferenceTypeId;
}

bool& BrowseDescription::include_subtypes()
{
  return mIncludeSubtypes;
}

const bool& BrowseDescription::include_subtypes() const
{
  return mIncludeSubtypes;
}

uint32_t& BrowseDescription::node_class_mask()
{
  return mNodeClassMask;
}

const uint32_t& BrowseDescription::node_class_mask() const
{
  return mNodeClassMask;
}

uint32_t& BrowseDescription::result_mask()
{
  return mResultMask;
}

const uint32_t& BrowseDescription::result_mask() const
{
  return mResultMask;
}

BuiltInTypeId BrowseDescription::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::BrowsePathTarget
{
namespace
{
void encode(StackDepth limit, const ua::BrowsePathTarget& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.target_id());
  encoder.encode(limit, value.remaining_path_index());
}

void encode(StackDepth limit, const ua::BrowsePathTarget& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "TargetId", value.target_id());
  encoder.encode(limit, "RemainingPathIndex", value.remaining_path_index());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::BrowsePathTarget& value)
{
  decoder.decode(limit, value.target_id());
  decoder.decode(limit, value.remaining_path_index());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::BrowsePathTarget& value)
{
  decoder.decode(limit, "TargetId", true, value.target_id());
  decoder.decode(limit, "RemainingPathIndex", true, value.remaining_path_index());
}
}  // namespace
}  // namespace detail::BrowsePathTarget

namespace detail::BrowsePathTarget
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::BrowsePathTarget::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::BrowsePathTarget::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::BrowsePathTarget

namespace detail::BrowsePathTarget
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::BrowsePathTarget>();
}
}  // namespace
}  // namespace detail::BrowsePathTarget

bool BrowsePathTarget::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId BrowsePathTarget::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId BrowsePathTarget::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String BrowsePathTarget::type_name() const
{
  return typeName;
}

void BrowsePathTarget::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::BrowsePathTarget::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::BrowsePathTarget::encode(limit, *this, *xml);
  }
}

void BrowsePathTarget::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::BrowsePathTarget::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::BrowsePathTarget::encode_id(limit, ns, *xml);
  }
}

void BrowsePathTarget::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::BrowsePathTarget::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::BrowsePathTarget::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> BrowsePathTarget::clone() const
{
  return make_unique<BrowsePathTarget>(*this);
}

void BrowsePathTarget::append_fields(std::string& output, int indent) const
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
    output += pad + "remaining_path_index=" + ua::to_string(remaining_path_index());
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
  output += "remaining_path_index=" + ua::to_string(remaining_path_index());
}

std::string BrowsePathTarget::to_string(int indent) const
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

void BrowsePathTarget::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::BrowsePathTarget::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::BrowsePathTarget::create);
  }
}

ExpandedNodeId& BrowsePathTarget::target_id()
{
  return mTargetId;
}

const ExpandedNodeId& BrowsePathTarget::target_id() const
{
  return mTargetId;
}

Index& BrowsePathTarget::remaining_path_index()
{
  return mRemainingPathIndex;
}

const Index& BrowsePathTarget::remaining_path_index() const
{
  return mRemainingPathIndex;
}

BuiltInTypeId BrowsePathTarget::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::QueryDataDescription
{
namespace
{
void encode(StackDepth limit, const ua::QueryDataDescription& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.relative_path());
  encoder.encode(limit, value.attribute_id());
  encoder.encode(limit, value.index_range());
}

void encode(StackDepth limit, const ua::QueryDataDescription& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RelativePath", value.relative_path());
  encoder.encode(limit, "AttributeId", value.attribute_id());
  encoder.encode(limit, "IndexRange", value.index_range());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::QueryDataDescription& value)
{
  decoder.decode(limit, value.relative_path());
  decoder.decode(limit, value.attribute_id());
  decoder.decode(limit, value.index_range());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::QueryDataDescription& value)
{
  decoder.decode(limit, "RelativePath", true, value.relative_path());
  decoder.decode(limit, "AttributeId", true, value.attribute_id());
  decoder.decode(limit, "IndexRange", true, value.index_range());
}
}  // namespace
}  // namespace detail::QueryDataDescription

namespace detail::QueryDataDescription
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::QueryDataDescription::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::QueryDataDescription::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::QueryDataDescription

namespace detail::QueryDataDescription
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::QueryDataDescription>();
}
}  // namespace
}  // namespace detail::QueryDataDescription

bool QueryDataDescription::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId QueryDataDescription::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId QueryDataDescription::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String QueryDataDescription::type_name() const
{
  return typeName;
}

void QueryDataDescription::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::QueryDataDescription::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::QueryDataDescription::encode(limit, *this, *xml);
  }
}

void QueryDataDescription::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::QueryDataDescription::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::QueryDataDescription::encode_id(limit, ns, *xml);
  }
}

void QueryDataDescription::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::QueryDataDescription::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::QueryDataDescription::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> QueryDataDescription::clone() const
{
  return make_unique<QueryDataDescription>(*this);
}

void QueryDataDescription::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "relative_path=" + ua::to_string(relative_path());
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
  output += "relative_path=" + ua::to_string(relative_path());
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

std::string QueryDataDescription::to_string(int indent) const
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

void QueryDataDescription::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::QueryDataDescription::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::QueryDataDescription::create);
  }
}

RelativePath& QueryDataDescription::relative_path()
{
  return mRelativePath;
}

const RelativePath& QueryDataDescription::relative_path() const
{
  return mRelativePath;
}

IntegerId& QueryDataDescription::attribute_id()
{
  return mAttributeId;
}

const IntegerId& QueryDataDescription::attribute_id() const
{
  return mAttributeId;
}

NumericRange& QueryDataDescription::index_range()
{
  return mIndexRange;
}

const NumericRange& QueryDataDescription::index_range() const
{
  return mIndexRange;
}

BuiltInTypeId QueryDataDescription::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::QueryFirstResponse
{
namespace
{
void encode(StackDepth limit, const ua::QueryFirstResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.query_data_sets());
  encoder.encode(limit, value.continuation_point());
  encoder.encode(limit, value.parsing_results());
  encoder.encode(limit, value.diagnostic_infos());
  encoder.encode(limit, value.filter_result());
}

void encode(StackDepth limit, const ua::QueryFirstResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "QueryDataSets", value.query_data_sets());
  encoder.encode(limit, "ContinuationPoint", value.continuation_point());
  encoder.encode(limit, "ParsingResults", value.parsing_results());
  encoder.encode(limit, "DiagnosticInfos", value.diagnostic_infos());
  encoder.encode(limit, "FilterResult", value.filter_result());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::QueryFirstResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.query_data_sets());
  decoder.decode(limit, value.continuation_point());
  decoder.decode(limit, value.parsing_results());
  decoder.decode(limit, value.diagnostic_infos());
  decoder.decode(limit, value.filter_result());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::QueryFirstResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "QueryDataSets", true, value.query_data_sets());
  decoder.decode(limit, "ContinuationPoint", true, value.continuation_point());
  decoder.decode(limit, "ParsingResults", true, value.parsing_results());
  decoder.decode(limit, "DiagnosticInfos", true, value.diagnostic_infos());
  decoder.decode(limit, "FilterResult", true, value.filter_result());
}
}  // namespace
}  // namespace detail::QueryFirstResponse

namespace detail::QueryFirstResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::QueryFirstResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::QueryFirstResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::QueryFirstResponse

namespace detail::QueryFirstResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::QueryFirstResponse>();
}
}  // namespace
}  // namespace detail::QueryFirstResponse

bool QueryFirstResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId QueryFirstResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId QueryFirstResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String QueryFirstResponse::type_name() const
{
  return typeName;
}

void QueryFirstResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::QueryFirstResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::QueryFirstResponse::encode(limit, *this, *xml);
  }
}

void QueryFirstResponse::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::QueryFirstResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::QueryFirstResponse::encode_id(limit, ns, *xml);
  }
}

void QueryFirstResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::QueryFirstResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::QueryFirstResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> QueryFirstResponse::clone() const
{
  return make_unique<QueryFirstResponse>(*this);
}

void QueryFirstResponse::append_fields(std::string& output, int indent) const
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
    output += pad + "query_data_sets=" + ua::to_string(query_data_sets());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "continuation_point=" + ua::to_string(continuation_point());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "parsing_results=" + ua::to_string(parsing_results());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "diagnostic_infos=" + ua::to_string(diagnostic_infos());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "filter_result=" + ua::to_string(filter_result());
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
  output += "query_data_sets=" + ua::to_string(query_data_sets());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "continuation_point=" + ua::to_string(continuation_point());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "parsing_results=" + ua::to_string(parsing_results());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "diagnostic_infos=" + ua::to_string(diagnostic_infos());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "filter_result=" + ua::to_string(filter_result());
}

std::string QueryFirstResponse::to_string(int indent) const
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

void QueryFirstResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::QueryFirstResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::QueryFirstResponse::create);
  }
}

ResponseHeader& QueryFirstResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& QueryFirstResponse::response_header() const
{
  return mResponseHeader;
}

Array<QueryDataSet>& QueryFirstResponse::query_data_sets()
{
  return mQueryDataSets;
}

const Array<QueryDataSet>& QueryFirstResponse::query_data_sets() const
{
  return mQueryDataSets;
}

ContinuationPoint& QueryFirstResponse::continuation_point()
{
  return mContinuationPoint;
}

const ContinuationPoint& QueryFirstResponse::continuation_point() const
{
  return mContinuationPoint;
}

Array<ParsingResult>& QueryFirstResponse::parsing_results()
{
  return mParsingResults;
}

const Array<ParsingResult>& QueryFirstResponse::parsing_results() const
{
  return mParsingResults;
}

Array<DiagnosticInfo>& QueryFirstResponse::diagnostic_infos()
{
  return mDiagnosticInfos;
}

const Array<DiagnosticInfo>& QueryFirstResponse::diagnostic_infos() const
{
  return mDiagnosticInfos;
}

ContentFilterResult& QueryFirstResponse::filter_result()
{
  return mFilterResult;
}

const ContentFilterResult& QueryFirstResponse::filter_result() const
{
  return mFilterResult;
}

BuiltInTypeId QueryFirstResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

bool HistoryReadDetails::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId HistoryReadDetails::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId HistoryReadDetails::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String HistoryReadDetails::type_name() const
{
  return typeName;
}

void HistoryReadDetails::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);
}

void HistoryReadDetails::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  UA_UNUSED(limit);
  UA_UNUSED(ns);
  UA_UNUSED(encoder);
}

void HistoryReadDetails::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);
}

BuiltInTypeId HistoryReadDetails::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ReadAnnotationDataDetails
{
namespace
{
void encode(StackDepth limit, const ua::ReadAnnotationDataDetails& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.req_times());
}

void encode(StackDepth limit, const ua::ReadAnnotationDataDetails& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ReqTimes", value.req_times());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ReadAnnotationDataDetails& value)
{
  decoder.decode(limit, value.req_times());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ReadAnnotationDataDetails& value)
{
  decoder.decode(limit, "ReqTimes", true, value.req_times());
}
}  // namespace
}  // namespace detail::ReadAnnotationDataDetails

namespace detail::ReadAnnotationDataDetails
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ReadAnnotationDataDetails::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ReadAnnotationDataDetails::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ReadAnnotationDataDetails

namespace detail::ReadAnnotationDataDetails
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ReadAnnotationDataDetails>();
}
}  // namespace
}  // namespace detail::ReadAnnotationDataDetails

bool ReadAnnotationDataDetails::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return HistoryReadDetails::is_of_type(ns, dataTypeId);
}

NodeId ReadAnnotationDataDetails::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ReadAnnotationDataDetails::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ReadAnnotationDataDetails::type_name() const
{
  return typeName;
}

void ReadAnnotationDataDetails::encode(StackDepth limit, Encoder& encoder) const
{

  HistoryReadDetails::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReadAnnotationDataDetails::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReadAnnotationDataDetails::encode(limit, *this, *xml);
  }
}

void ReadAnnotationDataDetails::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReadAnnotationDataDetails::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReadAnnotationDataDetails::encode_id(limit, ns, *xml);
  }
}

void ReadAnnotationDataDetails::decode(StackDepth limit, Decoder& decoder)
{

  HistoryReadDetails::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ReadAnnotationDataDetails::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ReadAnnotationDataDetails::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ReadAnnotationDataDetails::clone() const
{
  return make_unique<ReadAnnotationDataDetails>(*this);
}

void ReadAnnotationDataDetails::append_fields(std::string& output, int indent) const
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
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "req_times=" + ua::to_string(req_times());
}

std::string ReadAnnotationDataDetails::to_string(int indent) const
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

void ReadAnnotationDataDetails::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::ReadAnnotationDataDetails::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ReadAnnotationDataDetails::create);
  }
}

Array<UtcTime>& ReadAnnotationDataDetails::req_times()
{
  return mReqTimes;
}

const Array<UtcTime>& ReadAnnotationDataDetails::req_times() const
{
  return mReqTimes;
}

BuiltInTypeId ReadAnnotationDataDetails::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

bool HistoryUpdateDetails::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId HistoryUpdateDetails::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId HistoryUpdateDetails::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String HistoryUpdateDetails::type_name() const
{
  return typeName;
}

void HistoryUpdateDetails::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);
}

void HistoryUpdateDetails::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  UA_UNUSED(limit);
  UA_UNUSED(ns);
  UA_UNUSED(encoder);
}

void HistoryUpdateDetails::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);
}

BuiltInTypeId HistoryUpdateDetails::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::HistoryUpdateRequest
{
namespace
{
void encode(StackDepth limit, const ua::HistoryUpdateRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.history_update_details());
}

void encode(StackDepth limit, const ua::HistoryUpdateRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "HistoryUpdateDetails", value.history_update_details());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::HistoryUpdateRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.history_update_details());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::HistoryUpdateRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "HistoryUpdateDetails", true, value.history_update_details());
}
}  // namespace
}  // namespace detail::HistoryUpdateRequest

namespace detail::HistoryUpdateRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::HistoryUpdateRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::HistoryUpdateRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::HistoryUpdateRequest

namespace detail::HistoryUpdateRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::HistoryUpdateRequest>();
}
}  // namespace
}  // namespace detail::HistoryUpdateRequest

bool HistoryUpdateRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId HistoryUpdateRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId HistoryUpdateRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String HistoryUpdateRequest::type_name() const
{
  return typeName;
}

void HistoryUpdateRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::HistoryUpdateRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::HistoryUpdateRequest::encode(limit, *this, *xml);
  }
}

void HistoryUpdateRequest::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::HistoryUpdateRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::HistoryUpdateRequest::encode_id(limit, ns, *xml);
  }
}

void HistoryUpdateRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::HistoryUpdateRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::HistoryUpdateRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> HistoryUpdateRequest::clone() const
{
  return make_unique<HistoryUpdateRequest>(*this);
}

void HistoryUpdateRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "history_update_details=" + ua::to_string(history_update_details(), indent);
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
  output += "history_update_details=" + ua::to_string(history_update_details());
}

std::string HistoryUpdateRequest::to_string(int indent) const
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

void HistoryUpdateRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::HistoryUpdateRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::HistoryUpdateRequest::create);
  }
}

RequestHeader& HistoryUpdateRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& HistoryUpdateRequest::request_header() const
{
  return mRequestHeader;
}

Array<RefStructure<Structure>>& HistoryUpdateRequest::history_update_details()
{
  return mHistoryUpdateDetails;
}

const Array<RefStructure<Structure>>& HistoryUpdateRequest::history_update_details() const
{
  return mHistoryUpdateDetails;
}

BuiltInTypeId HistoryUpdateRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::MonitoringFilterResult
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::MonitoringFilterResult::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::MonitoringFilterResult::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::MonitoringFilterResult

namespace detail::MonitoringFilterResult
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::MonitoringFilterResult>();
}
}  // namespace
}  // namespace detail::MonitoringFilterResult

bool MonitoringFilterResult::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId MonitoringFilterResult::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId MonitoringFilterResult::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String MonitoringFilterResult::type_name() const
{
  return typeName;
}

void MonitoringFilterResult::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);
}

void MonitoringFilterResult::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::MonitoringFilterResult::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::MonitoringFilterResult::encode_id(limit, ns, *xml);
  }
}

void MonitoringFilterResult::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);
}

unique_ptr<Structure> MonitoringFilterResult::clone() const
{
  return make_unique<MonitoringFilterResult>(*this);
}

std::string MonitoringFilterResult::to_string(int indent) const
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

void MonitoringFilterResult::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::MonitoringFilterResult::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::MonitoringFilterResult::create);
  }
}

BuiltInTypeId MonitoringFilterResult::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::MonitoredItemModifyRequest
{
namespace
{
void encode(StackDepth limit, const ua::MonitoredItemModifyRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.monitored_item_id());
  encoder.encode(limit, value.requested_parameters());
}

void encode(StackDepth limit, const ua::MonitoredItemModifyRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "MonitoredItemId", value.monitored_item_id());
  encoder.encode(limit, "RequestedParameters", value.requested_parameters());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::MonitoredItemModifyRequest& value)
{
  decoder.decode(limit, value.monitored_item_id());
  decoder.decode(limit, value.requested_parameters());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::MonitoredItemModifyRequest& value)
{
  decoder.decode(limit, "MonitoredItemId", true, value.monitored_item_id());
  decoder.decode(limit, "RequestedParameters", true, value.requested_parameters());
}
}  // namespace
}  // namespace detail::MonitoredItemModifyRequest

namespace detail::MonitoredItemModifyRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::MonitoredItemModifyRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::MonitoredItemModifyRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::MonitoredItemModifyRequest

namespace detail::MonitoredItemModifyRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::MonitoredItemModifyRequest>();
}
}  // namespace
}  // namespace detail::MonitoredItemModifyRequest

bool MonitoredItemModifyRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId MonitoredItemModifyRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId MonitoredItemModifyRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String MonitoredItemModifyRequest::type_name() const
{
  return typeName;
}

void MonitoredItemModifyRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::MonitoredItemModifyRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::MonitoredItemModifyRequest::encode(limit, *this, *xml);
  }
}

void MonitoredItemModifyRequest::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::MonitoredItemModifyRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::MonitoredItemModifyRequest::encode_id(limit, ns, *xml);
  }
}

void MonitoredItemModifyRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::MonitoredItemModifyRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::MonitoredItemModifyRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> MonitoredItemModifyRequest::clone() const
{
  return make_unique<MonitoredItemModifyRequest>(*this);
}

void MonitoredItemModifyRequest::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "monitored_item_id=" + ua::to_string(monitored_item_id());
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
  output += "monitored_item_id=" + ua::to_string(monitored_item_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "requested_parameters=" + ua::to_string(requested_parameters());
}

std::string MonitoredItemModifyRequest::to_string(int indent) const
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

void MonitoredItemModifyRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::MonitoredItemModifyRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::MonitoredItemModifyRequest::create);
  }
}

IntegerId& MonitoredItemModifyRequest::monitored_item_id()
{
  return mMonitoredItemId;
}

const IntegerId& MonitoredItemModifyRequest::monitored_item_id() const
{
  return mMonitoredItemId;
}

MonitoringParameters& MonitoredItemModifyRequest::requested_parameters()
{
  return mRequestedParameters;
}

const MonitoringParameters& MonitoredItemModifyRequest::requested_parameters() const
{
  return mRequestedParameters;
}

BuiltInTypeId MonitoredItemModifyRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::DeleteMonitoredItemsRequest
{
namespace
{
void encode(StackDepth limit, const ua::DeleteMonitoredItemsRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.subscription_id());
  encoder.encode(limit, value.monitored_item_ids());
}

void encode(StackDepth limit, const ua::DeleteMonitoredItemsRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "SubscriptionId", value.subscription_id());
  encoder.encode(limit, "MonitoredItemIds", value.monitored_item_ids());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::DeleteMonitoredItemsRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.subscription_id());
  decoder.decode(limit, value.monitored_item_ids());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::DeleteMonitoredItemsRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "SubscriptionId", true, value.subscription_id());
  decoder.decode(limit, "MonitoredItemIds", true, value.monitored_item_ids());
}
}  // namespace
}  // namespace detail::DeleteMonitoredItemsRequest

namespace detail::DeleteMonitoredItemsRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::DeleteMonitoredItemsRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::DeleteMonitoredItemsRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::DeleteMonitoredItemsRequest

namespace detail::DeleteMonitoredItemsRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::DeleteMonitoredItemsRequest>();
}
}  // namespace
}  // namespace detail::DeleteMonitoredItemsRequest

bool DeleteMonitoredItemsRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId DeleteMonitoredItemsRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId DeleteMonitoredItemsRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String DeleteMonitoredItemsRequest::type_name() const
{
  return typeName;
}

void DeleteMonitoredItemsRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DeleteMonitoredItemsRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DeleteMonitoredItemsRequest::encode(limit, *this, *xml);
  }
}

void DeleteMonitoredItemsRequest::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DeleteMonitoredItemsRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DeleteMonitoredItemsRequest::encode_id(limit, ns, *xml);
  }
}

void DeleteMonitoredItemsRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::DeleteMonitoredItemsRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::DeleteMonitoredItemsRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> DeleteMonitoredItemsRequest::clone() const
{
  return make_unique<DeleteMonitoredItemsRequest>(*this);
}

void DeleteMonitoredItemsRequest::append_fields(std::string& output, int indent) const
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
  output += "monitored_item_ids=" + ua::to_string(monitored_item_ids());
}

std::string DeleteMonitoredItemsRequest::to_string(int indent) const
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

void DeleteMonitoredItemsRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::DeleteMonitoredItemsRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::DeleteMonitoredItemsRequest::create);
  }
}

RequestHeader& DeleteMonitoredItemsRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& DeleteMonitoredItemsRequest::request_header() const
{
  return mRequestHeader;
}

IntegerId& DeleteMonitoredItemsRequest::subscription_id()
{
  return mSubscriptionId;
}

const IntegerId& DeleteMonitoredItemsRequest::subscription_id() const
{
  return mSubscriptionId;
}

Array<IntegerId>& DeleteMonitoredItemsRequest::monitored_item_ids()
{
  return mMonitoredItemIds;
}

const Array<IntegerId>& DeleteMonitoredItemsRequest::monitored_item_ids() const
{
  return mMonitoredItemIds;
}

BuiltInTypeId DeleteMonitoredItemsRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::NotificationMessage
{
namespace
{
void encode(StackDepth limit, const ua::NotificationMessage& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.sequence_number());
  encoder.encode(limit, value.publish_time());
  encoder.encode(limit, value.notification_data());
}

void encode(StackDepth limit, const ua::NotificationMessage& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "SequenceNumber", value.sequence_number());
  encoder.encode(limit, "PublishTime", value.publish_time());
  encoder.encode(limit, "NotificationData", value.notification_data());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::NotificationMessage& value)
{
  decoder.decode(limit, value.sequence_number());
  decoder.decode(limit, value.publish_time());
  decoder.decode(limit, value.notification_data());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::NotificationMessage& value)
{
  decoder.decode(limit, "SequenceNumber", true, value.sequence_number());
  decoder.decode(limit, "PublishTime", true, value.publish_time());
  decoder.decode(limit, "NotificationData", true, value.notification_data());
}
}  // namespace
}  // namespace detail::NotificationMessage

namespace detail::NotificationMessage
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::NotificationMessage::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::NotificationMessage::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::NotificationMessage

namespace detail::NotificationMessage
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::NotificationMessage>();
}
}  // namespace
}  // namespace detail::NotificationMessage

bool NotificationMessage::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId NotificationMessage::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId NotificationMessage::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String NotificationMessage::type_name() const
{
  return typeName;
}

void NotificationMessage::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::NotificationMessage::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::NotificationMessage::encode(limit, *this, *xml);
  }
}

void NotificationMessage::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::NotificationMessage::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::NotificationMessage::encode_id(limit, ns, *xml);
  }
}

void NotificationMessage::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::NotificationMessage::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::NotificationMessage::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> NotificationMessage::clone() const
{
  return make_unique<NotificationMessage>(*this);
}

void NotificationMessage::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "sequence_number=" + ua::to_string(sequence_number());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "publish_time=" + ua::to_string(publish_time());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "notification_data=" + ua::to_string(notification_data(), indent);
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "sequence_number=" + ua::to_string(sequence_number());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "publish_time=" + ua::to_string(publish_time());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "notification_data=" + ua::to_string(notification_data());
}

std::string NotificationMessage::to_string(int indent) const
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

void NotificationMessage::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::NotificationMessage::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::NotificationMessage::create);
  }
}

Counter& NotificationMessage::sequence_number()
{
  return mSequenceNumber;
}

const Counter& NotificationMessage::sequence_number() const
{
  return mSequenceNumber;
}

UtcTime& NotificationMessage::publish_time()
{
  return mPublishTime;
}

const UtcTime& NotificationMessage::publish_time() const
{
  return mPublishTime;
}

Array<RefStructure<Structure>>& NotificationMessage::notification_data()
{
  return mNotificationData;
}

const Array<RefStructure<Structure>>& NotificationMessage::notification_data() const
{
  return mNotificationData;
}

BuiltInTypeId NotificationMessage::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::PublishRequest
{
namespace
{
void encode(StackDepth limit, const ua::PublishRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.subscription_acknowledgements());
}

void encode(StackDepth limit, const ua::PublishRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "SubscriptionAcknowledgements", value.subscription_acknowledgements());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::PublishRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.subscription_acknowledgements());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::PublishRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "SubscriptionAcknowledgements", true, value.subscription_acknowledgements());
}
}  // namespace
}  // namespace detail::PublishRequest

namespace detail::PublishRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::PublishRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::PublishRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::PublishRequest

namespace detail::PublishRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::PublishRequest>();
}
}  // namespace
}  // namespace detail::PublishRequest

bool PublishRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId PublishRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId PublishRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String PublishRequest::type_name() const
{
  return typeName;
}

void PublishRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::PublishRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::PublishRequest::encode(limit, *this, *xml);
  }
}

void PublishRequest::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::PublishRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::PublishRequest::encode_id(limit, ns, *xml);
  }
}

void PublishRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::PublishRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::PublishRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> PublishRequest::clone() const
{
  return make_unique<PublishRequest>(*this);
}

void PublishRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "subscription_acknowledgements=" + ua::to_string(subscription_acknowledgements());
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
  output += "subscription_acknowledgements=" + ua::to_string(subscription_acknowledgements());
}

std::string PublishRequest::to_string(int indent) const
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

void PublishRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::PublishRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::PublishRequest::create);
  }
}

RequestHeader& PublishRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& PublishRequest::request_header() const
{
  return mRequestHeader;
}

Array<SubscriptionAcknowledgement>& PublishRequest::subscription_acknowledgements()
{
  return mSubscriptionAcknowledgements;
}

const Array<SubscriptionAcknowledgement>& PublishRequest::subscription_acknowledgements() const
{
  return mSubscriptionAcknowledgements;
}

BuiltInTypeId PublishRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::DeleteSubscriptionsResponse
{
namespace
{
void encode(StackDepth limit, const ua::DeleteSubscriptionsResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.results());
  encoder.encode(limit, value.diagnostic_infos());
}

void encode(StackDepth limit, const ua::DeleteSubscriptionsResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "Results", value.results());
  encoder.encode(limit, "DiagnosticInfos", value.diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::DeleteSubscriptionsResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.results());
  decoder.decode(limit, value.diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::DeleteSubscriptionsResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "Results", true, value.results());
  decoder.decode(limit, "DiagnosticInfos", true, value.diagnostic_infos());
}
}  // namespace
}  // namespace detail::DeleteSubscriptionsResponse

namespace detail::DeleteSubscriptionsResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::DeleteSubscriptionsResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::DeleteSubscriptionsResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::DeleteSubscriptionsResponse

namespace detail::DeleteSubscriptionsResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::DeleteSubscriptionsResponse>();
}
}  // namespace
}  // namespace detail::DeleteSubscriptionsResponse

bool DeleteSubscriptionsResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId DeleteSubscriptionsResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId DeleteSubscriptionsResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String DeleteSubscriptionsResponse::type_name() const
{
  return typeName;
}

void DeleteSubscriptionsResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DeleteSubscriptionsResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DeleteSubscriptionsResponse::encode(limit, *this, *xml);
  }
}

void DeleteSubscriptionsResponse::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DeleteSubscriptionsResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DeleteSubscriptionsResponse::encode_id(limit, ns, *xml);
  }
}

void DeleteSubscriptionsResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::DeleteSubscriptionsResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::DeleteSubscriptionsResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> DeleteSubscriptionsResponse::clone() const
{
  return make_unique<DeleteSubscriptionsResponse>(*this);
}

void DeleteSubscriptionsResponse::append_fields(std::string& output, int indent) const
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

std::string DeleteSubscriptionsResponse::to_string(int indent) const
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

void DeleteSubscriptionsResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::DeleteSubscriptionsResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::DeleteSubscriptionsResponse::create);
  }
}

ResponseHeader& DeleteSubscriptionsResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& DeleteSubscriptionsResponse::response_header() const
{
  return mResponseHeader;
}

Array<StatusCode>& DeleteSubscriptionsResponse::results()
{
  return mResults;
}

const Array<StatusCode>& DeleteSubscriptionsResponse::results() const
{
  return mResults;
}

Array<DiagnosticInfo>& DeleteSubscriptionsResponse::diagnostic_infos()
{
  return mDiagnosticInfos;
}

const Array<DiagnosticInfo>& DeleteSubscriptionsResponse::diagnostic_infos() const
{
  return mDiagnosticInfos;
}

BuiltInTypeId DeleteSubscriptionsResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

}  // namespace ua
