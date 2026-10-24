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

namespace detail::EndpointType
{
namespace
{
void encode(StackDepth limit, const ua::EndpointType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.endpoint_url());
  encoder.encode(limit, utils::as_int32(value.security_mode()));
  encoder.encode(limit, value.security_policy_uri());
  encoder.encode(limit, value.transport_profile_uri());
}

void encode(StackDepth limit, const ua::EndpointType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "EndpointUrl", value.endpoint_url());
  encoder.encode(limit, "SecurityMode", utils::as_int32(value.security_mode()));
  encoder.encode(limit, "SecurityPolicyUri", value.security_policy_uri());
  encoder.encode(limit, "TransportProfileUri", value.transport_profile_uri());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::EndpointType& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.endpoint_url());
  decoder.decode(limit, enumVal);
  value.security_mode() = utils::from_underlying<MessageSecurityMode>(enumVal);
  decoder.decode(limit, value.security_policy_uri());
  decoder.decode(limit, value.transport_profile_uri());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::EndpointType& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "EndpointUrl", true, value.endpoint_url());
  decoder.decode(limit, "SecurityMode", true, enumVal);
  value.security_mode() = utils::from_underlying<MessageSecurityMode>(enumVal);
  decoder.decode(limit, "SecurityPolicyUri", true, value.security_policy_uri());
  decoder.decode(limit, "TransportProfileUri", true, value.transport_profile_uri());
}
}  // namespace
}  // namespace detail::EndpointType

namespace detail::EndpointType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::EndpointType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::EndpointType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::EndpointType

namespace detail::EndpointType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::EndpointType>();
}
}  // namespace
}  // namespace detail::EndpointType

bool EndpointType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId EndpointType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId EndpointType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String EndpointType::type_name() const
{
  return typeName;
}

void EndpointType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EndpointType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EndpointType::encode(limit, *this, *xml);
  }
}

void EndpointType::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EndpointType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EndpointType::encode_id(limit, ns, *xml);
  }
}

void EndpointType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::EndpointType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::EndpointType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> EndpointType::clone() const
{
  return make_unique<EndpointType>(*this);
}

void EndpointType::append_fields(std::string& output, int indent) const
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
    output += pad + "transport_profile_uri=" + ua::to_string(transport_profile_uri());
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
  output += "transport_profile_uri=" + ua::to_string(transport_profile_uri());
}

std::string EndpointType::to_string(int indent) const
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

void EndpointType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::EndpointType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::EndpointType::create);
  }
}

String& EndpointType::endpoint_url()
{
  return mEndpointUrl;
}

const String& EndpointType::endpoint_url() const
{
  return mEndpointUrl;
}

MessageSecurityMode& EndpointType::security_mode()
{
  return mSecurityMode;
}

const MessageSecurityMode& EndpointType::security_mode() const
{
  return mSecurityMode;
}

String& EndpointType::security_policy_uri()
{
  return mSecurityPolicyUri;
}

const String& EndpointType::security_policy_uri() const
{
  return mSecurityPolicyUri;
}

String& EndpointType::transport_profile_uri()
{
  return mTransportProfileUri;
}

const String& EndpointType::transport_profile_uri() const
{
  return mTransportProfileUri;
}

BuiltInTypeId EndpointType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ThreeDOrientation
{
namespace
{
void encode(StackDepth limit, const ua::ThreeDOrientation& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.a());
  encoder.encode(limit, value.b());
  encoder.encode(limit, value.c());
}

void encode(StackDepth limit, const ua::ThreeDOrientation& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "A", value.a());
  encoder.encode(limit, "B", value.b());
  encoder.encode(limit, "C", value.c());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ThreeDOrientation& value)
{
  decoder.decode(limit, value.a());
  decoder.decode(limit, value.b());
  decoder.decode(limit, value.c());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ThreeDOrientation& value)
{
  decoder.decode(limit, "A", true, value.a());
  decoder.decode(limit, "B", true, value.b());
  decoder.decode(limit, "C", true, value.c());
}
}  // namespace
}  // namespace detail::ThreeDOrientation

namespace detail::ThreeDOrientation
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ThreeDOrientation::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ThreeDOrientation::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ThreeDOrientation

namespace detail::ThreeDOrientation
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ThreeDOrientation>();
}
}  // namespace
}  // namespace detail::ThreeDOrientation

bool ThreeDOrientation::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Orientation::is_of_type(ns, dataTypeId);
}

NodeId ThreeDOrientation::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ThreeDOrientation::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ThreeDOrientation::type_name() const
{
  return typeName;
}

void ThreeDOrientation::encode(StackDepth limit, Encoder& encoder) const
{

  Orientation::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ThreeDOrientation::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ThreeDOrientation::encode(limit, *this, *xml);
  }
}

void ThreeDOrientation::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ThreeDOrientation::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ThreeDOrientation::encode_id(limit, ns, *xml);
  }
}

void ThreeDOrientation::decode(StackDepth limit, Decoder& decoder)
{

  Orientation::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ThreeDOrientation::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ThreeDOrientation::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ThreeDOrientation::clone() const
{
  return make_unique<ThreeDOrientation>(*this);
}

void ThreeDOrientation::append_fields(std::string& output, int indent) const
{
  Orientation::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "a=" + ua::to_string(a());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "b=" + ua::to_string(b());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "c=" + ua::to_string(c());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "a=" + ua::to_string(a());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "b=" + ua::to_string(b());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "c=" + ua::to_string(c());
}

std::string ThreeDOrientation::to_string(int indent) const
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

void ThreeDOrientation::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ThreeDOrientation::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ThreeDOrientation::create);
  }
}

double& ThreeDOrientation::a()
{
  return mA;
}

const double& ThreeDOrientation::a() const
{
  return mA;
}

double& ThreeDOrientation::b()
{
  return mB;
}

const double& ThreeDOrientation::b() const
{
  return mB;
}

double& ThreeDOrientation::c()
{
  return mC;
}

const double& ThreeDOrientation::c() const
{
  return mC;
}

BuiltInTypeId ThreeDOrientation::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::TrustListDataType
{
namespace
{
void encode(StackDepth limit, const ua::TrustListDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.specified_lists());
  encoder.encode(limit, value.trusted_certificates());
  encoder.encode(limit, value.trusted_crls());
  encoder.encode(limit, value.issuer_certificates());
  encoder.encode(limit, value.issuer_crls());
}

void encode(StackDepth limit, const ua::TrustListDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "SpecifiedLists", value.specified_lists());
  encoder.encode(limit, "TrustedCertificates", value.trusted_certificates());
  encoder.encode(limit, "TrustedCrls", value.trusted_crls());
  encoder.encode(limit, "IssuerCertificates", value.issuer_certificates());
  encoder.encode(limit, "IssuerCrls", value.issuer_crls());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::TrustListDataType& value)
{
  decoder.decode(limit, value.specified_lists());
  decoder.decode(limit, value.trusted_certificates());
  decoder.decode(limit, value.trusted_crls());
  decoder.decode(limit, value.issuer_certificates());
  decoder.decode(limit, value.issuer_crls());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::TrustListDataType& value)
{
  decoder.decode(limit, "SpecifiedLists", true, value.specified_lists());
  decoder.decode(limit, "TrustedCertificates", true, value.trusted_certificates());
  decoder.decode(limit, "TrustedCrls", true, value.trusted_crls());
  decoder.decode(limit, "IssuerCertificates", true, value.issuer_certificates());
  decoder.decode(limit, "IssuerCrls", true, value.issuer_crls());
}
}  // namespace
}  // namespace detail::TrustListDataType

namespace detail::TrustListDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::TrustListDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::TrustListDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::TrustListDataType

namespace detail::TrustListDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::TrustListDataType>();
}
}  // namespace
}  // namespace detail::TrustListDataType

bool TrustListDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId TrustListDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId TrustListDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String TrustListDataType::type_name() const
{
  return typeName;
}

void TrustListDataType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::TrustListDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::TrustListDataType::encode(limit, *this, *xml);
  }
}

void TrustListDataType::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::TrustListDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::TrustListDataType::encode_id(limit, ns, *xml);
  }
}

void TrustListDataType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::TrustListDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::TrustListDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> TrustListDataType::clone() const
{
  return make_unique<TrustListDataType>(*this);
}

void TrustListDataType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "specified_lists=" + ua::to_string(specified_lists());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "trusted_certificates=" + ua::to_string(trusted_certificates());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "trusted_crls=" + ua::to_string(trusted_crls());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "issuer_certificates=" + ua::to_string(issuer_certificates());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "issuer_crls=" + ua::to_string(issuer_crls());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "specified_lists=" + ua::to_string(specified_lists());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "trusted_certificates=" + ua::to_string(trusted_certificates());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "trusted_crls=" + ua::to_string(trusted_crls());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "issuer_certificates=" + ua::to_string(issuer_certificates());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "issuer_crls=" + ua::to_string(issuer_crls());
}

std::string TrustListDataType::to_string(int indent) const
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

void TrustListDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::TrustListDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::TrustListDataType::create);
  }
}

uint32_t& TrustListDataType::specified_lists()
{
  return mSpecifiedLists;
}

const uint32_t& TrustListDataType::specified_lists() const
{
  return mSpecifiedLists;
}

Array<ByteString>& TrustListDataType::trusted_certificates()
{
  return mTrustedCertificates;
}

const Array<ByteString>& TrustListDataType::trusted_certificates() const
{
  return mTrustedCertificates;
}

Array<ByteString>& TrustListDataType::trusted_crls()
{
  return mTrustedCrls;
}

const Array<ByteString>& TrustListDataType::trusted_crls() const
{
  return mTrustedCrls;
}

Array<ByteString>& TrustListDataType::issuer_certificates()
{
  return mIssuerCertificates;
}

const Array<ByteString>& TrustListDataType::issuer_certificates() const
{
  return mIssuerCertificates;
}

Array<ByteString>& TrustListDataType::issuer_crls()
{
  return mIssuerCrls;
}

const Array<ByteString>& TrustListDataType::issuer_crls() const
{
  return mIssuerCrls;
}

BuiltInTypeId TrustListDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::EndpointDataType
{
namespace
{
void encode(StackDepth limit, const ua::EndpointDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.discovery_urls());
  encoder.encode(limit, value.network_name());
  encoder.encode(limit, value.port());
}

void encode(StackDepth limit, const ua::EndpointDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "DiscoveryUrls", value.discovery_urls());
  encoder.encode(limit, "NetworkName", value.network_name());
  encoder.encode(limit, "Port", value.port());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::EndpointDataType& value)
{
  decoder.decode(limit, value.discovery_urls());
  decoder.decode(limit, value.network_name());
  decoder.decode(limit, value.port());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::EndpointDataType& value)
{
  decoder.decode(limit, "DiscoveryUrls", true, value.discovery_urls());
  decoder.decode(limit, "NetworkName", true, value.network_name());
  decoder.decode(limit, "Port", true, value.port());
}
}  // namespace
}  // namespace detail::EndpointDataType

namespace detail::EndpointDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::EndpointDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::EndpointDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::EndpointDataType

namespace detail::EndpointDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::EndpointDataType>();
}
}  // namespace
}  // namespace detail::EndpointDataType

bool EndpointDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return BaseConfigurationRecordDataType::is_of_type(ns, dataTypeId);
}

NodeId EndpointDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId EndpointDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String EndpointDataType::type_name() const
{
  return typeName;
}

void EndpointDataType::encode(StackDepth limit, Encoder& encoder) const
{

  BaseConfigurationRecordDataType::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EndpointDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EndpointDataType::encode(limit, *this, *xml);
  }
}

void EndpointDataType::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EndpointDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EndpointDataType::encode_id(limit, ns, *xml);
  }
}

void EndpointDataType::decode(StackDepth limit, Decoder& decoder)
{

  BaseConfigurationRecordDataType::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::EndpointDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::EndpointDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> EndpointDataType::clone() const
{
  return make_unique<EndpointDataType>(*this);
}

void EndpointDataType::append_fields(std::string& output, int indent) const
{
  BaseConfigurationRecordDataType::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "discovery_urls=" + ua::to_string(discovery_urls());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "network_name=" + ua::to_string(network_name());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "port=" + ua::to_string(port());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "discovery_urls=" + ua::to_string(discovery_urls());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "network_name=" + ua::to_string(network_name());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "port=" + ua::to_string(port());
}

std::string EndpointDataType::to_string(int indent) const
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

void EndpointDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::EndpointDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::EndpointDataType::create);
  }
}

Array<UriString>& EndpointDataType::discovery_urls()
{
  return mDiscoveryUrls;
}

const Array<UriString>& EndpointDataType::discovery_urls() const
{
  return mDiscoveryUrls;
}

String& EndpointDataType::network_name()
{
  return mNetworkName;
}

const String& EndpointDataType::network_name() const
{
  return mNetworkName;
}

uint16_t& EndpointDataType::port()
{
  return mPort;
}

const uint16_t& EndpointDataType::port() const
{
  return mPort;
}

BuiltInTypeId EndpointDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::StructureDescription
{
namespace
{
void encode(StackDepth limit, const ua::StructureDescription& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.structure_definition());
}

void encode(StackDepth limit, const ua::StructureDescription& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "StructureDefinition", value.structure_definition());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::StructureDescription& value)
{
  decoder.decode(limit, value.structure_definition());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::StructureDescription& value)
{
  decoder.decode(limit, "StructureDefinition", true, value.structure_definition());
}
}  // namespace
}  // namespace detail::StructureDescription

namespace detail::StructureDescription
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::StructureDescription::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::StructureDescription::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::StructureDescription

namespace detail::StructureDescription
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::StructureDescription>();
}
}  // namespace
}  // namespace detail::StructureDescription

bool StructureDescription::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return DataTypeDescription::is_of_type(ns, dataTypeId);
}

NodeId StructureDescription::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId StructureDescription::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String StructureDescription::type_name() const
{
  return typeName;
}

void StructureDescription::encode(StackDepth limit, Encoder& encoder) const
{

  DataTypeDescription::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::StructureDescription::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::StructureDescription::encode(limit, *this, *xml);
  }
}

void StructureDescription::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::StructureDescription::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::StructureDescription::encode_id(limit, ns, *xml);
  }
}

void StructureDescription::decode(StackDepth limit, Decoder& decoder)
{

  DataTypeDescription::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::StructureDescription::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::StructureDescription::decode(limit, *xml, *this);
  }
}

void StructureDescription::resolve(span<const LocaleId> locales)
{
  DataTypeDescription::resolve(locales);
  mStructureDefinition.resolve(locales);
}

unique_ptr<Structure> StructureDescription::clone() const
{
  return make_unique<StructureDescription>(*this);
}

void StructureDescription::append_fields(std::string& output, int indent) const
{
  DataTypeDescription::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "structure_definition=" + ua::to_string(structure_definition());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "structure_definition=" + ua::to_string(structure_definition());
}

std::string StructureDescription::to_string(int indent) const
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

void StructureDescription::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::StructureDescription::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::StructureDescription::create);
  }
}

StructureDefinition& StructureDescription::structure_definition()
{
  return mStructureDefinition;
}

const StructureDefinition& StructureDescription::structure_definition() const
{
  return mStructureDefinition;
}

BuiltInTypeId StructureDescription::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::UserManagementDataType
{
namespace
{
void encode(StackDepth limit, const ua::UserManagementDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.user_name());
  encoder.encode(limit, value.user_configuration().as_underlying_type());
  encoder.encode(limit, value.description());
}

void encode(StackDepth limit, const ua::UserManagementDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "UserName", value.user_name());
  encoder.encode(limit, "UserConfiguration", value.user_configuration().as_underlying_type());
  encoder.encode(limit, "Description", value.description());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::UserManagementDataType& value)
{
  decoder.decode(limit, value.user_name());
  {
    UserConfigurationMask::UnderlyingType val{};
    decoder.decode(limit, val);
    value.user_configuration().from_underlying_type(val);
  }
  decoder.decode(limit, value.description());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::UserManagementDataType& value)
{
  decoder.decode(limit, "UserName", true, value.user_name());
  {
    UserConfigurationMask::UnderlyingType val{};
    decoder.decode(limit, "UserConfiguration", true, val);
    value.user_configuration().from_underlying_type(val);
  }
  decoder.decode(limit, "Description", true, value.description());
}
}  // namespace
}  // namespace detail::UserManagementDataType

namespace detail::UserManagementDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::UserManagementDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::UserManagementDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::UserManagementDataType

namespace detail::UserManagementDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::UserManagementDataType>();
}
}  // namespace
}  // namespace detail::UserManagementDataType

bool UserManagementDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId UserManagementDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId UserManagementDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String UserManagementDataType::type_name() const
{
  return typeName;
}

void UserManagementDataType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::UserManagementDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::UserManagementDataType::encode(limit, *this, *xml);
  }
}

void UserManagementDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::UserManagementDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::UserManagementDataType::encode_id(limit, ns, *xml);
  }
}

void UserManagementDataType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::UserManagementDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::UserManagementDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> UserManagementDataType::clone() const
{
  return make_unique<UserManagementDataType>(*this);
}

void UserManagementDataType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "user_name=" + ua::to_string(user_name());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "user_configuration=" + ua::to_string(user_configuration().as_underlying_type());
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
  output += "user_name=" + ua::to_string(user_name());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "user_configuration=" + ua::to_string(user_configuration().as_underlying_type());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "description=" + ua::to_string(description());
}

std::string UserManagementDataType::to_string(int indent) const
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

void UserManagementDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::UserManagementDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::UserManagementDataType::create);
  }
}

String& UserManagementDataType::user_name()
{
  return mUserName;
}

const String& UserManagementDataType::user_name() const
{
  return mUserName;
}

UserConfigurationMask& UserManagementDataType::user_configuration()
{
  return mUserConfiguration;
}

const UserConfigurationMask& UserManagementDataType::user_configuration() const
{
  return mUserConfiguration;
}

String& UserManagementDataType::description()
{
  return mDescription;
}

const String& UserManagementDataType::description() const
{
  return mDescription;
}

BuiltInTypeId UserManagementDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::LogRecordsDataType
{
namespace
{
void encode(StackDepth limit, const ua::LogRecordsDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.log_record_array());
}

void encode(StackDepth limit, const ua::LogRecordsDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "LogRecordArray", value.log_record_array());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::LogRecordsDataType& value)
{
  decoder.decode(limit, value.log_record_array());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::LogRecordsDataType& value)
{
  decoder.decode(limit, "LogRecordArray", true, value.log_record_array());
}
}  // namespace
}  // namespace detail::LogRecordsDataType

namespace detail::LogRecordsDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::LogRecordsDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::LogRecordsDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::LogRecordsDataType

namespace detail::LogRecordsDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::LogRecordsDataType>();
}
}  // namespace
}  // namespace detail::LogRecordsDataType

bool LogRecordsDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId LogRecordsDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId LogRecordsDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String LogRecordsDataType::type_name() const
{
  return typeName;
}

void LogRecordsDataType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::LogRecordsDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::LogRecordsDataType::encode(limit, *this, *xml);
  }
}

void LogRecordsDataType::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::LogRecordsDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::LogRecordsDataType::encode_id(limit, ns, *xml);
  }
}

void LogRecordsDataType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::LogRecordsDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::LogRecordsDataType::decode(limit, *xml, *this);
  }
}

void LogRecordsDataType::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  for (size_t i = 0; i < mLogRecordArray.size(); ++i)
  {
    mLogRecordArray[i].resolve(locales);
  }
}

unique_ptr<Structure> LogRecordsDataType::clone() const
{
  return make_unique<LogRecordsDataType>(*this);
}

void LogRecordsDataType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "log_record_array=" + ua::to_string(log_record_array());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "log_record_array=" + ua::to_string(log_record_array());
}

std::string LogRecordsDataType::to_string(int indent) const
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

void LogRecordsDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::LogRecordsDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::LogRecordsDataType::create);
  }
}

Array<LogRecord>& LogRecordsDataType::log_record_array()
{
  return mLogRecordArray;
}

const Array<LogRecord>& LogRecordsDataType::log_record_array() const
{
  return mLogRecordArray;
}

BuiltInTypeId LogRecordsDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::EnumDefinition
{
namespace
{
void encode(StackDepth limit, const ua::EnumDefinition& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.fields());
}

void encode(StackDepth limit, const ua::EnumDefinition& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Fields", value.fields());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::EnumDefinition& value)
{
  decoder.decode(limit, value.fields());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::EnumDefinition& value)
{
  decoder.decode(limit, "Fields", true, value.fields());
}
}  // namespace
}  // namespace detail::EnumDefinition

namespace detail::EnumDefinition
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::EnumDefinition::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::EnumDefinition::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::EnumDefinition

namespace detail::EnumDefinition
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::EnumDefinition>();
}
}  // namespace
}  // namespace detail::EnumDefinition

bool EnumDefinition::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return DataTypeDefinition::is_of_type(ns, dataTypeId);
}

NodeId EnumDefinition::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId EnumDefinition::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String EnumDefinition::type_name() const
{
  return typeName;
}

void EnumDefinition::encode(StackDepth limit, Encoder& encoder) const
{

  DataTypeDefinition::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EnumDefinition::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EnumDefinition::encode(limit, *this, *xml);
  }
}

void EnumDefinition::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::EnumDefinition::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::EnumDefinition::encode_id(limit, ns, *xml);
  }
}

void EnumDefinition::decode(StackDepth limit, Decoder& decoder)
{

  DataTypeDefinition::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::EnumDefinition::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::EnumDefinition::decode(limit, *xml, *this);
  }
}

void EnumDefinition::resolve(span<const LocaleId> locales)
{
  DataTypeDefinition::resolve(locales);
  for (size_t i = 0; i < mFields.size(); ++i)
  {
    mFields[i].resolve(locales);
  }
}

unique_ptr<Structure> EnumDefinition::clone() const
{
  return make_unique<EnumDefinition>(*this);
}

void EnumDefinition::append_fields(std::string& output, int indent) const
{
  DataTypeDefinition::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
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
  output += "fields=" + ua::to_string(fields());
}

std::string EnumDefinition::to_string(int indent) const
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

void EnumDefinition::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::EnumDefinition::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::EnumDefinition::create);
  }
}

Array<EnumField>& EnumDefinition::fields()
{
  return mFields;
}

const Array<EnumField>& EnumDefinition::fields() const
{
  return mFields;
}

BuiltInTypeId EnumDefinition::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::UserTokenPolicy
{
namespace
{
void encode(StackDepth limit, const ua::UserTokenPolicy& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.policy_id());
  encoder.encode(limit, utils::as_int32(value.token_type()));
  encoder.encode(limit, value.issued_token_type());
  encoder.encode(limit, value.issuer_endpoint_url());
  encoder.encode(limit, value.security_policy_uri());
}

void encode(StackDepth limit, const ua::UserTokenPolicy& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "PolicyId", value.policy_id());
  encoder.encode(limit, "TokenType", utils::as_int32(value.token_type()));
  encoder.encode(limit, "IssuedTokenType", value.issued_token_type());
  encoder.encode(limit, "IssuerEndpointUrl", value.issuer_endpoint_url());
  encoder.encode(limit, "SecurityPolicyUri", value.security_policy_uri());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::UserTokenPolicy& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.policy_id());
  decoder.decode(limit, enumVal);
  value.token_type() = utils::from_underlying<UserTokenType>(enumVal);
  decoder.decode(limit, value.issued_token_type());
  decoder.decode(limit, value.issuer_endpoint_url());
  decoder.decode(limit, value.security_policy_uri());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::UserTokenPolicy& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "PolicyId", true, value.policy_id());
  decoder.decode(limit, "TokenType", true, enumVal);
  value.token_type() = utils::from_underlying<UserTokenType>(enumVal);
  decoder.decode(limit, "IssuedTokenType", true, value.issued_token_type());
  decoder.decode(limit, "IssuerEndpointUrl", true, value.issuer_endpoint_url());
  decoder.decode(limit, "SecurityPolicyUri", true, value.security_policy_uri());
}
}  // namespace
}  // namespace detail::UserTokenPolicy

namespace detail::UserTokenPolicy
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::UserTokenPolicy::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::UserTokenPolicy::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::UserTokenPolicy

namespace detail::UserTokenPolicy
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::UserTokenPolicy>();
}
}  // namespace
}  // namespace detail::UserTokenPolicy

bool UserTokenPolicy::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId UserTokenPolicy::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId UserTokenPolicy::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String UserTokenPolicy::type_name() const
{
  return typeName;
}

void UserTokenPolicy::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::UserTokenPolicy::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::UserTokenPolicy::encode(limit, *this, *xml);
  }
}

void UserTokenPolicy::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::UserTokenPolicy::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::UserTokenPolicy::encode_id(limit, ns, *xml);
  }
}

void UserTokenPolicy::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::UserTokenPolicy::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::UserTokenPolicy::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> UserTokenPolicy::clone() const
{
  return make_unique<UserTokenPolicy>(*this);
}

void UserTokenPolicy::append_fields(std::string& output, int indent) const
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
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "policy_id=" + ua::to_string(policy_id());
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
}

std::string UserTokenPolicy::to_string(int indent) const
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

void UserTokenPolicy::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::UserTokenPolicy::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::UserTokenPolicy::create);
  }
}

String& UserTokenPolicy::policy_id()
{
  return mPolicyId;
}

const String& UserTokenPolicy::policy_id() const
{
  return mPolicyId;
}

UserTokenType& UserTokenPolicy::token_type()
{
  return mTokenType;
}

const UserTokenType& UserTokenPolicy::token_type() const
{
  return mTokenType;
}

String& UserTokenPolicy::issued_token_type()
{
  return mIssuedTokenType;
}

const String& UserTokenPolicy::issued_token_type() const
{
  return mIssuedTokenType;
}

String& UserTokenPolicy::issuer_endpoint_url()
{
  return mIssuerEndpointUrl;
}

const String& UserTokenPolicy::issuer_endpoint_url() const
{
  return mIssuerEndpointUrl;
}

String& UserTokenPolicy::security_policy_uri()
{
  return mSecurityPolicyUri;
}

const String& UserTokenPolicy::security_policy_uri() const
{
  return mSecurityPolicyUri;
}

BuiltInTypeId UserTokenPolicy::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::UserNameIdentityToken
{
namespace
{
void encode(StackDepth limit, const ua::UserNameIdentityToken& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.user_name());
  encoder.encode(limit, value.password());
  encoder.encode(limit, value.encryption_algorithm());
}

void encode(StackDepth limit, const ua::UserNameIdentityToken& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "UserName", value.user_name());
  encoder.encode(limit, "Password", value.password());
  encoder.encode(limit, "EncryptionAlgorithm", value.encryption_algorithm());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::UserNameIdentityToken& value)
{
  decoder.decode(limit, value.user_name());
  decoder.decode(limit, value.password());
  decoder.decode(limit, value.encryption_algorithm());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::UserNameIdentityToken& value)
{
  decoder.decode(limit, "UserName", true, value.user_name());
  decoder.decode(limit, "Password", true, value.password());
  decoder.decode(limit, "EncryptionAlgorithm", true, value.encryption_algorithm());
}
}  // namespace
}  // namespace detail::UserNameIdentityToken

namespace detail::UserNameIdentityToken
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::UserNameIdentityToken::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::UserNameIdentityToken::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::UserNameIdentityToken

namespace detail::UserNameIdentityToken
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::UserNameIdentityToken>();
}
}  // namespace
}  // namespace detail::UserNameIdentityToken

bool UserNameIdentityToken::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return UserIdentityToken::is_of_type(ns, dataTypeId);
}

NodeId UserNameIdentityToken::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId UserNameIdentityToken::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String UserNameIdentityToken::type_name() const
{
  return typeName;
}

void UserNameIdentityToken::encode(StackDepth limit, Encoder& encoder) const
{

  UserIdentityToken::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::UserNameIdentityToken::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::UserNameIdentityToken::encode(limit, *this, *xml);
  }
}

void UserNameIdentityToken::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::UserNameIdentityToken::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::UserNameIdentityToken::encode_id(limit, ns, *xml);
  }
}

void UserNameIdentityToken::decode(StackDepth limit, Decoder& decoder)
{

  UserIdentityToken::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::UserNameIdentityToken::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::UserNameIdentityToken::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> UserNameIdentityToken::clone() const
{
  return make_unique<UserNameIdentityToken>(*this);
}

void UserNameIdentityToken::append_fields(std::string& output, int indent) const
{
  UserIdentityToken::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "user_name=" + ua::to_string(user_name());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "password=" + ua::to_string(password());
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
  output += "user_name=" + ua::to_string(user_name());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "password=" + ua::to_string(password());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "encryption_algorithm=" + ua::to_string(encryption_algorithm());
}

std::string UserNameIdentityToken::to_string(int indent) const
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

void UserNameIdentityToken::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::UserNameIdentityToken::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::UserNameIdentityToken::create);
  }
}

String& UserNameIdentityToken::user_name()
{
  return mUserName;
}

const String& UserNameIdentityToken::user_name() const
{
  return mUserName;
}

ByteString& UserNameIdentityToken::password()
{
  return mPassword;
}

const ByteString& UserNameIdentityToken::password() const
{
  return mPassword;
}

String& UserNameIdentityToken::encryption_algorithm()
{
  return mEncryptionAlgorithm;
}

const String& UserNameIdentityToken::encryption_algorithm() const
{
  return mEncryptionAlgorithm;
}

BuiltInTypeId UserNameIdentityToken::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::RelativePath
{
namespace
{
void encode(StackDepth limit, const ua::RelativePath& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.elements());
}

void encode(StackDepth limit, const ua::RelativePath& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Elements", value.elements());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::RelativePath& value)
{
  decoder.decode(limit, value.elements());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::RelativePath& value)
{
  decoder.decode(limit, "Elements", true, value.elements());
}
}  // namespace
}  // namespace detail::RelativePath

namespace detail::RelativePath
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::RelativePath::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::RelativePath::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::RelativePath

namespace detail::RelativePath
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::RelativePath>();
}
}  // namespace
}  // namespace detail::RelativePath

bool RelativePath::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId RelativePath::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId RelativePath::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String RelativePath::type_name() const
{
  return typeName;
}

void RelativePath::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RelativePath::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RelativePath::encode(limit, *this, *xml);
  }
}

void RelativePath::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RelativePath::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RelativePath::encode_id(limit, ns, *xml);
  }
}

void RelativePath::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::RelativePath::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::RelativePath::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> RelativePath::clone() const
{
  return make_unique<RelativePath>(*this);
}

void RelativePath::append_fields(std::string& output, int indent) const
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

std::string RelativePath::to_string(int indent) const
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

void RelativePath::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::RelativePath::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::RelativePath::create);
  }
}

Array<RelativePathElement>& RelativePath::elements()
{
  return mElements;
}

const Array<RelativePathElement>& RelativePath::elements() const
{
  return mElements;
}

BuiltInTypeId RelativePath::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::SimpleAttributeOperand
{
namespace
{
void encode(StackDepth limit, const ua::SimpleAttributeOperand& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.type_definition_id());
  encoder.encode(limit, value.browse_path());
  encoder.encode(limit, value.attribute_id());
  encoder.encode(limit, value.index_range());
}

void encode(StackDepth limit, const ua::SimpleAttributeOperand& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "TypeDefinitionId", value.type_definition_id());
  encoder.encode(limit, "BrowsePath", value.browse_path());
  encoder.encode(limit, "AttributeId", value.attribute_id());
  encoder.encode(limit, "IndexRange", value.index_range());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::SimpleAttributeOperand& value)
{
  decoder.decode(limit, value.type_definition_id());
  decoder.decode(limit, value.browse_path());
  decoder.decode(limit, value.attribute_id());
  decoder.decode(limit, value.index_range());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::SimpleAttributeOperand& value)
{
  decoder.decode(limit, "TypeDefinitionId", true, value.type_definition_id());
  decoder.decode(limit, "BrowsePath", true, value.browse_path());
  decoder.decode(limit, "AttributeId", true, value.attribute_id());
  decoder.decode(limit, "IndexRange", true, value.index_range());
}
}  // namespace
}  // namespace detail::SimpleAttributeOperand

namespace detail::SimpleAttributeOperand
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::SimpleAttributeOperand::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::SimpleAttributeOperand::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::SimpleAttributeOperand

namespace detail::SimpleAttributeOperand
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::SimpleAttributeOperand>();
}
}  // namespace
}  // namespace detail::SimpleAttributeOperand

bool SimpleAttributeOperand::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return FilterOperand::is_of_type(ns, dataTypeId);
}

NodeId SimpleAttributeOperand::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId SimpleAttributeOperand::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String SimpleAttributeOperand::type_name() const
{
  return typeName;
}

void SimpleAttributeOperand::encode(StackDepth limit, Encoder& encoder) const
{

  FilterOperand::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SimpleAttributeOperand::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SimpleAttributeOperand::encode(limit, *this, *xml);
  }
}

void SimpleAttributeOperand::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SimpleAttributeOperand::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SimpleAttributeOperand::encode_id(limit, ns, *xml);
  }
}

void SimpleAttributeOperand::decode(StackDepth limit, Decoder& decoder)
{

  FilterOperand::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::SimpleAttributeOperand::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::SimpleAttributeOperand::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> SimpleAttributeOperand::clone() const
{
  return make_unique<SimpleAttributeOperand>(*this);
}

void SimpleAttributeOperand::append_fields(std::string& output, int indent) const
{
  FilterOperand::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "type_definition_id=" + ua::to_string(type_definition_id());
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
  output += "type_definition_id=" + ua::to_string(type_definition_id());
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

std::string SimpleAttributeOperand::to_string(int indent) const
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

void SimpleAttributeOperand::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::SimpleAttributeOperand::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::SimpleAttributeOperand::create);
  }
}

NodeId& SimpleAttributeOperand::type_definition_id()
{
  return mTypeDefinitionId;
}

const NodeId& SimpleAttributeOperand::type_definition_id() const
{
  return mTypeDefinitionId;
}

Array<QualifiedName>& SimpleAttributeOperand::browse_path()
{
  return mBrowsePath;
}

const Array<QualifiedName>& SimpleAttributeOperand::browse_path() const
{
  return mBrowsePath;
}

IntegerId& SimpleAttributeOperand::attribute_id()
{
  return mAttributeId;
}

const IntegerId& SimpleAttributeOperand::attribute_id() const
{
  return mAttributeId;
}

NumericRange& SimpleAttributeOperand::index_range()
{
  return mIndexRange;
}

const NumericRange& SimpleAttributeOperand::index_range() const
{
  return mIndexRange;
}

BuiltInTypeId SimpleAttributeOperand::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::BuildInfo
{
namespace
{
void encode(StackDepth limit, const ua::BuildInfo& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.product_uri());
  encoder.encode(limit, value.manufacturer_name());
  encoder.encode(limit, value.product_name());
  encoder.encode(limit, value.software_version());
  encoder.encode(limit, value.build_number());
  encoder.encode(limit, value.build_date());
}

void encode(StackDepth limit, const ua::BuildInfo& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ProductUri", value.product_uri());
  encoder.encode(limit, "ManufacturerName", value.manufacturer_name());
  encoder.encode(limit, "ProductName", value.product_name());
  encoder.encode(limit, "SoftwareVersion", value.software_version());
  encoder.encode(limit, "BuildNumber", value.build_number());
  encoder.encode(limit, "BuildDate", value.build_date());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::BuildInfo& value)
{
  decoder.decode(limit, value.product_uri());
  decoder.decode(limit, value.manufacturer_name());
  decoder.decode(limit, value.product_name());
  decoder.decode(limit, value.software_version());
  decoder.decode(limit, value.build_number());
  decoder.decode(limit, value.build_date());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::BuildInfo& value)
{
  decoder.decode(limit, "ProductUri", true, value.product_uri());
  decoder.decode(limit, "ManufacturerName", true, value.manufacturer_name());
  decoder.decode(limit, "ProductName", true, value.product_name());
  decoder.decode(limit, "SoftwareVersion", true, value.software_version());
  decoder.decode(limit, "BuildNumber", true, value.build_number());
  decoder.decode(limit, "BuildDate", true, value.build_date());
}
}  // namespace
}  // namespace detail::BuildInfo

namespace detail::BuildInfo
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::BuildInfo::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::BuildInfo::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::BuildInfo

namespace detail::BuildInfo
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::BuildInfo>();
}
}  // namespace
}  // namespace detail::BuildInfo

bool BuildInfo::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId BuildInfo::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId BuildInfo::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String BuildInfo::type_name() const
{
  return typeName;
}

void BuildInfo::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::BuildInfo::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::BuildInfo::encode(limit, *this, *xml);
  }
}

void BuildInfo::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::BuildInfo::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::BuildInfo::encode_id(limit, ns, *xml);
  }
}

void BuildInfo::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::BuildInfo::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::BuildInfo::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> BuildInfo::clone() const
{
  return make_unique<BuildInfo>(*this);
}

void BuildInfo::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "product_uri=" + ua::to_string(product_uri());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "manufacturer_name=" + ua::to_string(manufacturer_name());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "product_name=" + ua::to_string(product_name());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "software_version=" + ua::to_string(software_version());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "build_number=" + ua::to_string(build_number());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "build_date=" + ua::to_string(build_date());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "product_uri=" + ua::to_string(product_uri());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "manufacturer_name=" + ua::to_string(manufacturer_name());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "product_name=" + ua::to_string(product_name());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "software_version=" + ua::to_string(software_version());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "build_number=" + ua::to_string(build_number());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "build_date=" + ua::to_string(build_date());
}

std::string BuildInfo::to_string(int indent) const
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

void BuildInfo::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::BuildInfo::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::BuildInfo::create);
  }
}

String& BuildInfo::product_uri()
{
  return mProductUri;
}

const String& BuildInfo::product_uri() const
{
  return mProductUri;
}

String& BuildInfo::manufacturer_name()
{
  return mManufacturerName;
}

const String& BuildInfo::manufacturer_name() const
{
  return mManufacturerName;
}

String& BuildInfo::product_name()
{
  return mProductName;
}

const String& BuildInfo::product_name() const
{
  return mProductName;
}

String& BuildInfo::software_version()
{
  return mSoftwareVersion;
}

const String& BuildInfo::software_version() const
{
  return mSoftwareVersion;
}

String& BuildInfo::build_number()
{
  return mBuildNumber;
}

const String& BuildInfo::build_number() const
{
  return mBuildNumber;
}

UtcTime& BuildInfo::build_date()
{
  return mBuildDate;
}

const UtcTime& BuildInfo::build_date() const
{
  return mBuildDate;
}

BuiltInTypeId BuildInfo::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::SessionSecurityDiagnosticsDataType
{
namespace
{
void encode(StackDepth limit, const ua::SessionSecurityDiagnosticsDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.session_id());
  encoder.encode(limit, value.client_user_id_of_session());
  encoder.encode(limit, value.client_user_id_history());
  encoder.encode(limit, value.authentication_mechanism());
  encoder.encode(limit, value.encoding());
  encoder.encode(limit, value.transport_protocol());
  encoder.encode(limit, utils::as_int32(value.security_mode()));
  encoder.encode(limit, value.security_policy_uri());
  encoder.encode(limit, value.client_certificate());
}

void encode(StackDepth limit, const ua::SessionSecurityDiagnosticsDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "SessionId", value.session_id());
  encoder.encode(limit, "ClientUserIdOfSession", value.client_user_id_of_session());
  encoder.encode(limit, "ClientUserIdHistory", value.client_user_id_history());
  encoder.encode(limit, "AuthenticationMechanism", value.authentication_mechanism());
  encoder.encode(limit, "Encoding", value.encoding());
  encoder.encode(limit, "TransportProtocol", value.transport_protocol());
  encoder.encode(limit, "SecurityMode", utils::as_int32(value.security_mode()));
  encoder.encode(limit, "SecurityPolicyUri", value.security_policy_uri());
  encoder.encode(limit, "ClientCertificate", value.client_certificate());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::SessionSecurityDiagnosticsDataType& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.session_id());
  decoder.decode(limit, value.client_user_id_of_session());
  decoder.decode(limit, value.client_user_id_history());
  decoder.decode(limit, value.authentication_mechanism());
  decoder.decode(limit, value.encoding());
  decoder.decode(limit, value.transport_protocol());
  decoder.decode(limit, enumVal);
  value.security_mode() = utils::from_underlying<MessageSecurityMode>(enumVal);
  decoder.decode(limit, value.security_policy_uri());
  decoder.decode(limit, value.client_certificate());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::SessionSecurityDiagnosticsDataType& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "SessionId", true, value.session_id());
  decoder.decode(limit, "ClientUserIdOfSession", true, value.client_user_id_of_session());
  decoder.decode(limit, "ClientUserIdHistory", true, value.client_user_id_history());
  decoder.decode(limit, "AuthenticationMechanism", true, value.authentication_mechanism());
  decoder.decode(limit, "Encoding", true, value.encoding());
  decoder.decode(limit, "TransportProtocol", true, value.transport_protocol());
  decoder.decode(limit, "SecurityMode", true, enumVal);
  value.security_mode() = utils::from_underlying<MessageSecurityMode>(enumVal);
  decoder.decode(limit, "SecurityPolicyUri", true, value.security_policy_uri());
  decoder.decode(limit, "ClientCertificate", true, value.client_certificate());
}
}  // namespace
}  // namespace detail::SessionSecurityDiagnosticsDataType

namespace detail::SessionSecurityDiagnosticsDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::SessionSecurityDiagnosticsDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::SessionSecurityDiagnosticsDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::SessionSecurityDiagnosticsDataType

namespace detail::SessionSecurityDiagnosticsDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::SessionSecurityDiagnosticsDataType>();
}
}  // namespace
}  // namespace detail::SessionSecurityDiagnosticsDataType

bool SessionSecurityDiagnosticsDataType::is_of_type(
  const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId SessionSecurityDiagnosticsDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId SessionSecurityDiagnosticsDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String SessionSecurityDiagnosticsDataType::type_name() const
{
  return typeName;
}

void SessionSecurityDiagnosticsDataType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SessionSecurityDiagnosticsDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SessionSecurityDiagnosticsDataType::encode(limit, *this, *xml);
  }
}

void SessionSecurityDiagnosticsDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SessionSecurityDiagnosticsDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SessionSecurityDiagnosticsDataType::encode_id(limit, ns, *xml);
  }
}

void SessionSecurityDiagnosticsDataType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::SessionSecurityDiagnosticsDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::SessionSecurityDiagnosticsDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> SessionSecurityDiagnosticsDataType::clone() const
{
  return make_unique<SessionSecurityDiagnosticsDataType>(*this);
}

void SessionSecurityDiagnosticsDataType::append_fields(std::string& output, int indent) const
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
    output += pad + "client_user_id_of_session=" + ua::to_string(client_user_id_of_session());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "client_user_id_history=" + ua::to_string(client_user_id_history());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "authentication_mechanism=" + ua::to_string(authentication_mechanism());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "encoding=" + ua::to_string(encoding());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "transport_protocol=" + ua::to_string(transport_protocol());
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
    output += pad + "client_certificate=" + ua::to_string(client_certificate());
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
  output += "client_user_id_of_session=" + ua::to_string(client_user_id_of_session());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "client_user_id_history=" + ua::to_string(client_user_id_history());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "authentication_mechanism=" + ua::to_string(authentication_mechanism());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "encoding=" + ua::to_string(encoding());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "transport_protocol=" + ua::to_string(transport_protocol());
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
  output += "client_certificate=" + ua::to_string(client_certificate());
}

std::string SessionSecurityDiagnosticsDataType::to_string(int indent) const
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

void SessionSecurityDiagnosticsDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::SessionSecurityDiagnosticsDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(
      NodeId(defaultXmlEncodingId), detail::SessionSecurityDiagnosticsDataType::create);
  }
}

NodeId& SessionSecurityDiagnosticsDataType::session_id()
{
  return mSessionId;
}

const NodeId& SessionSecurityDiagnosticsDataType::session_id() const
{
  return mSessionId;
}

String& SessionSecurityDiagnosticsDataType::client_user_id_of_session()
{
  return mClientUserIdOfSession;
}

const String& SessionSecurityDiagnosticsDataType::client_user_id_of_session() const
{
  return mClientUserIdOfSession;
}

Array<String>& SessionSecurityDiagnosticsDataType::client_user_id_history()
{
  return mClientUserIdHistory;
}

const Array<String>& SessionSecurityDiagnosticsDataType::client_user_id_history() const
{
  return mClientUserIdHistory;
}

String& SessionSecurityDiagnosticsDataType::authentication_mechanism()
{
  return mAuthenticationMechanism;
}

const String& SessionSecurityDiagnosticsDataType::authentication_mechanism() const
{
  return mAuthenticationMechanism;
}

String& SessionSecurityDiagnosticsDataType::encoding()
{
  return mEncoding;
}

const String& SessionSecurityDiagnosticsDataType::encoding() const
{
  return mEncoding;
}

String& SessionSecurityDiagnosticsDataType::transport_protocol()
{
  return mTransportProtocol;
}

const String& SessionSecurityDiagnosticsDataType::transport_protocol() const
{
  return mTransportProtocol;
}

MessageSecurityMode& SessionSecurityDiagnosticsDataType::security_mode()
{
  return mSecurityMode;
}

const MessageSecurityMode& SessionSecurityDiagnosticsDataType::security_mode() const
{
  return mSecurityMode;
}

String& SessionSecurityDiagnosticsDataType::security_policy_uri()
{
  return mSecurityPolicyUri;
}

const String& SessionSecurityDiagnosticsDataType::security_policy_uri() const
{
  return mSecurityPolicyUri;
}

ByteString& SessionSecurityDiagnosticsDataType::client_certificate()
{
  return mClientCertificate;
}

const ByteString& SessionSecurityDiagnosticsDataType::client_certificate() const
{
  return mClientCertificate;
}

BuiltInTypeId SessionSecurityDiagnosticsDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ComplexNumberType
{
namespace
{
void encode(StackDepth limit, const ua::ComplexNumberType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.real());
  encoder.encode(limit, value.imaginary());
}

void encode(StackDepth limit, const ua::ComplexNumberType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Real", value.real());
  encoder.encode(limit, "Imaginary", value.imaginary());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ComplexNumberType& value)
{
  decoder.decode(limit, value.real());
  decoder.decode(limit, value.imaginary());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ComplexNumberType& value)
{
  decoder.decode(limit, "Real", true, value.real());
  decoder.decode(limit, "Imaginary", true, value.imaginary());
}
}  // namespace
}  // namespace detail::ComplexNumberType

namespace detail::ComplexNumberType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ComplexNumberType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ComplexNumberType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ComplexNumberType

namespace detail::ComplexNumberType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ComplexNumberType>();
}
}  // namespace
}  // namespace detail::ComplexNumberType

bool ComplexNumberType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ComplexNumberType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ComplexNumberType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ComplexNumberType::type_name() const
{
  return typeName;
}

void ComplexNumberType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ComplexNumberType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ComplexNumberType::encode(limit, *this, *xml);
  }
}

void ComplexNumberType::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ComplexNumberType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ComplexNumberType::encode_id(limit, ns, *xml);
  }
}

void ComplexNumberType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ComplexNumberType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ComplexNumberType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ComplexNumberType::clone() const
{
  return make_unique<ComplexNumberType>(*this);
}

void ComplexNumberType::append_fields(std::string& output, int indent) const
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

std::string ComplexNumberType::to_string(int indent) const
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

void ComplexNumberType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ComplexNumberType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ComplexNumberType::create);
  }
}

float& ComplexNumberType::real()
{
  return mReal;
}

const float& ComplexNumberType::real() const
{
  return mReal;
}

float& ComplexNumberType::imaginary()
{
  return mImaginary;
}

const float& ComplexNumberType::imaginary() const
{
  return mImaginary;
}

BuiltInTypeId ComplexNumberType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::RequestHeader
{
namespace
{
void encode(StackDepth limit, const ua::RequestHeader& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.authentication_token());
  encoder.encode(limit, value.timestamp());
  encoder.encode(limit, value.request_handle());
  encoder.encode(limit, value.return_diagnostics());
  encoder.encode(limit, value.audit_entry_id());
  encoder.encode(limit, value.timeout_hint());
  encoder.encode(limit, value.additional_header().get());
}

void encode(StackDepth limit, const ua::RequestHeader& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "AuthenticationToken", value.authentication_token());
  encoder.encode(limit, "Timestamp", value.timestamp());
  encoder.encode(limit, "RequestHandle", value.request_handle());
  encoder.encode(limit, "ReturnDiagnostics", value.return_diagnostics());
  encoder.encode(limit, "AuditEntryId", value.audit_entry_id());
  encoder.encode(limit, "TimeoutHint", value.timeout_hint());
  encoder.encode(limit, "AdditionalHeader", value.additional_header().get());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::RequestHeader& value)
{
  decoder.decode(limit, value.authentication_token());
  decoder.decode(limit, value.timestamp());
  decoder.decode(limit, value.request_handle());
  decoder.decode(limit, value.return_diagnostics());
  decoder.decode(limit, value.audit_entry_id());
  decoder.decode(limit, value.timeout_hint());
  decoder.decode(limit, value.additional_header().inner_unique_ptr());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::RequestHeader& value)
{
  decoder.decode(limit, "AuthenticationToken", true, value.authentication_token());
  decoder.decode(limit, "Timestamp", true, value.timestamp());
  decoder.decode(limit, "RequestHandle", true, value.request_handle());
  decoder.decode(limit, "ReturnDiagnostics", true, value.return_diagnostics());
  decoder.decode(limit, "AuditEntryId", true, value.audit_entry_id());
  decoder.decode(limit, "TimeoutHint", true, value.timeout_hint());
  decoder.decode(limit, "AdditionalHeader", true, value.additional_header().inner_unique_ptr());
}
}  // namespace
}  // namespace detail::RequestHeader

namespace detail::RequestHeader
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::RequestHeader::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::RequestHeader::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::RequestHeader

namespace detail::RequestHeader
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::RequestHeader>();
}
}  // namespace
}  // namespace detail::RequestHeader

bool RequestHeader::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId RequestHeader::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId RequestHeader::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String RequestHeader::type_name() const
{
  return typeName;
}

void RequestHeader::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RequestHeader::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RequestHeader::encode(limit, *this, *xml);
  }
}

void RequestHeader::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RequestHeader::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RequestHeader::encode_id(limit, ns, *xml);
  }
}

void RequestHeader::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::RequestHeader::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::RequestHeader::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> RequestHeader::clone() const
{
  return make_unique<RequestHeader>(*this);
}

void RequestHeader::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "authentication_token=" + ua::to_string(authentication_token());
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
    output += pad + "return_diagnostics=" + ua::to_string(return_diagnostics());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "audit_entry_id=" + ua::to_string(audit_entry_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "timeout_hint=" + ua::to_string(timeout_hint());
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
  output += "authentication_token=" + ua::to_string(authentication_token());
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
  output += "return_diagnostics=" + ua::to_string(return_diagnostics());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "audit_entry_id=" + ua::to_string(audit_entry_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "timeout_hint=" + ua::to_string(timeout_hint());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "additional_header=" + (additional_header() ? additional_header()->to_string(0) : "null");
}

std::string RequestHeader::to_string(int indent) const
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

void RequestHeader::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::RequestHeader::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::RequestHeader::create);
  }
}

SessionAuthenticationToken& RequestHeader::authentication_token()
{
  return mAuthenticationToken;
}

const SessionAuthenticationToken& RequestHeader::authentication_token() const
{
  return mAuthenticationToken;
}

UtcTime& RequestHeader::timestamp()
{
  return mTimestamp;
}

const UtcTime& RequestHeader::timestamp() const
{
  return mTimestamp;
}

IntegerId& RequestHeader::request_handle()
{
  return mRequestHandle;
}

const IntegerId& RequestHeader::request_handle() const
{
  return mRequestHandle;
}

uint32_t& RequestHeader::return_diagnostics()
{
  return mReturnDiagnostics;
}

const uint32_t& RequestHeader::return_diagnostics() const
{
  return mReturnDiagnostics;
}

String& RequestHeader::audit_entry_id()
{
  return mAuditEntryId;
}

const String& RequestHeader::audit_entry_id() const
{
  return mAuditEntryId;
}

uint32_t& RequestHeader::timeout_hint()
{
  return mTimeoutHint;
}

const uint32_t& RequestHeader::timeout_hint() const
{
  return mTimeoutHint;
}

RefStructure<Structure>& RequestHeader::additional_header()
{
  return mAdditionalHeader;
}

const RefStructure<Structure>& RequestHeader::additional_header() const
{
  return mAdditionalHeader;
}

BuiltInTypeId RequestHeader::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::FindServersOnNetworkResponse
{
namespace
{
void encode(StackDepth limit, const ua::FindServersOnNetworkResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.last_counter_reset_time());
  encoder.encode(limit, value.servers());
}

void encode(StackDepth limit, const ua::FindServersOnNetworkResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "LastCounterResetTime", value.last_counter_reset_time());
  encoder.encode(limit, "Servers", value.servers());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::FindServersOnNetworkResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.last_counter_reset_time());
  decoder.decode(limit, value.servers());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::FindServersOnNetworkResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "LastCounterResetTime", true, value.last_counter_reset_time());
  decoder.decode(limit, "Servers", true, value.servers());
}
}  // namespace
}  // namespace detail::FindServersOnNetworkResponse

namespace detail::FindServersOnNetworkResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::FindServersOnNetworkResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::FindServersOnNetworkResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::FindServersOnNetworkResponse

namespace detail::FindServersOnNetworkResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::FindServersOnNetworkResponse>();
}
}  // namespace
}  // namespace detail::FindServersOnNetworkResponse

bool FindServersOnNetworkResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId FindServersOnNetworkResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId FindServersOnNetworkResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String FindServersOnNetworkResponse::type_name() const
{
  return typeName;
}

void FindServersOnNetworkResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::FindServersOnNetworkResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::FindServersOnNetworkResponse::encode(limit, *this, *xml);
  }
}

void FindServersOnNetworkResponse::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::FindServersOnNetworkResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::FindServersOnNetworkResponse::encode_id(limit, ns, *xml);
  }
}

void FindServersOnNetworkResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::FindServersOnNetworkResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::FindServersOnNetworkResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> FindServersOnNetworkResponse::clone() const
{
  return make_unique<FindServersOnNetworkResponse>(*this);
}

void FindServersOnNetworkResponse::append_fields(std::string& output, int indent) const
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
    output += pad + "last_counter_reset_time=" + ua::to_string(last_counter_reset_time());
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
  output += "last_counter_reset_time=" + ua::to_string(last_counter_reset_time());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "servers=" + ua::to_string(servers());
}

std::string FindServersOnNetworkResponse::to_string(int indent) const
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

void FindServersOnNetworkResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::FindServersOnNetworkResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::FindServersOnNetworkResponse::create);
  }
}

ResponseHeader& FindServersOnNetworkResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& FindServersOnNetworkResponse::response_header() const
{
  return mResponseHeader;
}

UtcTime& FindServersOnNetworkResponse::last_counter_reset_time()
{
  return mLastCounterResetTime;
}

const UtcTime& FindServersOnNetworkResponse::last_counter_reset_time() const
{
  return mLastCounterResetTime;
}

Array<ServerOnNetwork>& FindServersOnNetworkResponse::servers()
{
  return mServers;
}

const Array<ServerOnNetwork>& FindServersOnNetworkResponse::servers() const
{
  return mServers;
}

BuiltInTypeId FindServersOnNetworkResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::OpenSecureChannelRequest
{
namespace
{
void encode(StackDepth limit, const ua::OpenSecureChannelRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.client_protocol_version());
  encoder.encode(limit, utils::as_int32(value.request_type()));
  encoder.encode(limit, utils::as_int32(value.security_mode()));
  encoder.encode(limit, value.client_nonce());
  encoder.encode(limit, value.requested_lifetime());
}

void encode(StackDepth limit, const ua::OpenSecureChannelRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "ClientProtocolVersion", value.client_protocol_version());
  encoder.encode(limit, "RequestType", utils::as_int32(value.request_type()));
  encoder.encode(limit, "SecurityMode", utils::as_int32(value.security_mode()));
  encoder.encode(limit, "ClientNonce", value.client_nonce());
  encoder.encode(limit, "RequestedLifetime", value.requested_lifetime());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::OpenSecureChannelRequest& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.client_protocol_version());
  decoder.decode(limit, enumVal);
  value.request_type() = utils::from_underlying<SecurityTokenRequestType>(enumVal);
  decoder.decode(limit, enumVal);
  value.security_mode() = utils::from_underlying<MessageSecurityMode>(enumVal);
  decoder.decode(limit, value.client_nonce());
  decoder.decode(limit, value.requested_lifetime());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::OpenSecureChannelRequest& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "ClientProtocolVersion", true, value.client_protocol_version());
  decoder.decode(limit, "RequestType", true, enumVal);
  value.request_type() = utils::from_underlying<SecurityTokenRequestType>(enumVal);
  decoder.decode(limit, "SecurityMode", true, enumVal);
  value.security_mode() = utils::from_underlying<MessageSecurityMode>(enumVal);
  decoder.decode(limit, "ClientNonce", true, value.client_nonce());
  decoder.decode(limit, "RequestedLifetime", true, value.requested_lifetime());
}
}  // namespace
}  // namespace detail::OpenSecureChannelRequest

namespace detail::OpenSecureChannelRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::OpenSecureChannelRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::OpenSecureChannelRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::OpenSecureChannelRequest

namespace detail::OpenSecureChannelRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::OpenSecureChannelRequest>();
}
}  // namespace
}  // namespace detail::OpenSecureChannelRequest

bool OpenSecureChannelRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId OpenSecureChannelRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId OpenSecureChannelRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String OpenSecureChannelRequest::type_name() const
{
  return typeName;
}

void OpenSecureChannelRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::OpenSecureChannelRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::OpenSecureChannelRequest::encode(limit, *this, *xml);
  }
}

void OpenSecureChannelRequest::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::OpenSecureChannelRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::OpenSecureChannelRequest::encode_id(limit, ns, *xml);
  }
}

void OpenSecureChannelRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::OpenSecureChannelRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::OpenSecureChannelRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> OpenSecureChannelRequest::clone() const
{
  return make_unique<OpenSecureChannelRequest>(*this);
}

void OpenSecureChannelRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "client_protocol_version=" + ua::to_string(client_protocol_version());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "request_type=" + ua::to_string(utils::as_int32(request_type()));
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "security_mode=" + ua::to_string(utils::as_int32(security_mode()));
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "client_nonce=" + ua::to_string(client_nonce());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "requested_lifetime=" + ua::to_string(requested_lifetime());
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
  output += "client_protocol_version=" + ua::to_string(client_protocol_version());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "request_type=" + ua::to_string(utils::as_int32(request_type()));
  if (!output.empty())
  {
    output += ", ";
  }
  output += "security_mode=" + ua::to_string(utils::as_int32(security_mode()));
  if (!output.empty())
  {
    output += ", ";
  }
  output += "client_nonce=" + ua::to_string(client_nonce());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "requested_lifetime=" + ua::to_string(requested_lifetime());
}

std::string OpenSecureChannelRequest::to_string(int indent) const
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

void OpenSecureChannelRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::OpenSecureChannelRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::OpenSecureChannelRequest::create);
  }
}

RequestHeader& OpenSecureChannelRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& OpenSecureChannelRequest::request_header() const
{
  return mRequestHeader;
}

uint32_t& OpenSecureChannelRequest::client_protocol_version()
{
  return mClientProtocolVersion;
}

const uint32_t& OpenSecureChannelRequest::client_protocol_version() const
{
  return mClientProtocolVersion;
}

SecurityTokenRequestType& OpenSecureChannelRequest::request_type()
{
  return mRequestType;
}

const SecurityTokenRequestType& OpenSecureChannelRequest::request_type() const
{
  return mRequestType;
}

MessageSecurityMode& OpenSecureChannelRequest::security_mode()
{
  return mSecurityMode;
}

const MessageSecurityMode& OpenSecureChannelRequest::security_mode() const
{
  return mSecurityMode;
}

ByteString& OpenSecureChannelRequest::client_nonce()
{
  return mClientNonce;
}

const ByteString& OpenSecureChannelRequest::client_nonce() const
{
  return mClientNonce;
}

uint32_t& OpenSecureChannelRequest::requested_lifetime()
{
  return mRequestedLifetime;
}

const uint32_t& OpenSecureChannelRequest::requested_lifetime() const
{
  return mRequestedLifetime;
}

BuiltInTypeId OpenSecureChannelRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ActivateSessionResponse
{
namespace
{
void encode(StackDepth limit, const ua::ActivateSessionResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.server_nonce());
  encoder.encode(limit, value.results());
  encoder.encode(limit, value.diagnostic_infos());
}

void encode(StackDepth limit, const ua::ActivateSessionResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "ServerNonce", value.server_nonce());
  encoder.encode(limit, "Results", value.results());
  encoder.encode(limit, "DiagnosticInfos", value.diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ActivateSessionResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.server_nonce());
  decoder.decode(limit, value.results());
  decoder.decode(limit, value.diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ActivateSessionResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "ServerNonce", true, value.server_nonce());
  decoder.decode(limit, "Results", true, value.results());
  decoder.decode(limit, "DiagnosticInfos", true, value.diagnostic_infos());
}
}  // namespace
}  // namespace detail::ActivateSessionResponse

namespace detail::ActivateSessionResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ActivateSessionResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ActivateSessionResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ActivateSessionResponse

namespace detail::ActivateSessionResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ActivateSessionResponse>();
}
}  // namespace
}  // namespace detail::ActivateSessionResponse

bool ActivateSessionResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ActivateSessionResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ActivateSessionResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ActivateSessionResponse::type_name() const
{
  return typeName;
}

void ActivateSessionResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ActivateSessionResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ActivateSessionResponse::encode(limit, *this, *xml);
  }
}

void ActivateSessionResponse::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ActivateSessionResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ActivateSessionResponse::encode_id(limit, ns, *xml);
  }
}

void ActivateSessionResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ActivateSessionResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ActivateSessionResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ActivateSessionResponse::clone() const
{
  return make_unique<ActivateSessionResponse>(*this);
}

void ActivateSessionResponse::append_fields(std::string& output, int indent) const
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
    output += pad + "server_nonce=" + ua::to_string(server_nonce());
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
  output += "server_nonce=" + ua::to_string(server_nonce());
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

std::string ActivateSessionResponse::to_string(int indent) const
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

void ActivateSessionResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ActivateSessionResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ActivateSessionResponse::create);
  }
}

ResponseHeader& ActivateSessionResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& ActivateSessionResponse::response_header() const
{
  return mResponseHeader;
}

ByteString& ActivateSessionResponse::server_nonce()
{
  return mServerNonce;
}

const ByteString& ActivateSessionResponse::server_nonce() const
{
  return mServerNonce;
}

Array<StatusCode>& ActivateSessionResponse::results()
{
  return mResults;
}

const Array<StatusCode>& ActivateSessionResponse::results() const
{
  return mResults;
}

Array<DiagnosticInfo>& ActivateSessionResponse::diagnostic_infos()
{
  return mDiagnosticInfos;
}

const Array<DiagnosticInfo>& ActivateSessionResponse::diagnostic_infos() const
{
  return mDiagnosticInfos;
}

BuiltInTypeId ActivateSessionResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::MethodAttributes
{
namespace
{
void encode(StackDepth limit, const ua::MethodAttributes& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.executable());
  encoder.encode(limit, value.user_executable());
}

void encode(StackDepth limit, const ua::MethodAttributes& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Executable", value.executable());
  encoder.encode(limit, "UserExecutable", value.user_executable());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::MethodAttributes& value)
{
  decoder.decode(limit, value.executable());
  decoder.decode(limit, value.user_executable());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::MethodAttributes& value)
{
  decoder.decode(limit, "Executable", true, value.executable());
  decoder.decode(limit, "UserExecutable", true, value.user_executable());
}
}  // namespace
}  // namespace detail::MethodAttributes

namespace detail::MethodAttributes
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::MethodAttributes::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::MethodAttributes::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::MethodAttributes

namespace detail::MethodAttributes
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::MethodAttributes>();
}
}  // namespace
}  // namespace detail::MethodAttributes

bool MethodAttributes::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return NodeAttributes::is_of_type(ns, dataTypeId);
}

NodeId MethodAttributes::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId MethodAttributes::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String MethodAttributes::type_name() const
{
  return typeName;
}

void MethodAttributes::encode(StackDepth limit, Encoder& encoder) const
{

  NodeAttributes::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::MethodAttributes::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::MethodAttributes::encode(limit, *this, *xml);
  }
}

void MethodAttributes::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::MethodAttributes::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::MethodAttributes::encode_id(limit, ns, *xml);
  }
}

void MethodAttributes::decode(StackDepth limit, Decoder& decoder)
{

  NodeAttributes::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::MethodAttributes::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::MethodAttributes::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> MethodAttributes::clone() const
{
  return make_unique<MethodAttributes>(*this);
}

void MethodAttributes::append_fields(std::string& output, int indent) const
{
  NodeAttributes::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "executable=" + ua::to_string(executable());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "user_executable=" + ua::to_string(user_executable());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "executable=" + ua::to_string(executable());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "user_executable=" + ua::to_string(user_executable());
}

std::string MethodAttributes::to_string(int indent) const
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

void MethodAttributes::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::MethodAttributes::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::MethodAttributes::create);
  }
}

bool& MethodAttributes::executable()
{
  return mExecutable;
}

const bool& MethodAttributes::executable() const
{
  return mExecutable;
}

bool& MethodAttributes::user_executable()
{
  return mUserExecutable;
}

const bool& MethodAttributes::user_executable() const
{
  return mUserExecutable;
}

BuiltInTypeId MethodAttributes::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::AddNodesResult
{
namespace
{
void encode(StackDepth limit, const ua::AddNodesResult& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.status_code());
  encoder.encode(limit, value.added_node_id());
}

void encode(StackDepth limit, const ua::AddNodesResult& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "StatusCode", value.status_code());
  encoder.encode(limit, "AddedNodeId", value.added_node_id());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::AddNodesResult& value)
{
  decoder.decode(limit, value.status_code());
  decoder.decode(limit, value.added_node_id());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::AddNodesResult& value)
{
  decoder.decode(limit, "StatusCode", true, value.status_code());
  decoder.decode(limit, "AddedNodeId", true, value.added_node_id());
}
}  // namespace
}  // namespace detail::AddNodesResult

namespace detail::AddNodesResult
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::AddNodesResult::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::AddNodesResult::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::AddNodesResult

namespace detail::AddNodesResult
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::AddNodesResult>();
}
}  // namespace
}  // namespace detail::AddNodesResult

bool AddNodesResult::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId AddNodesResult::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId AddNodesResult::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String AddNodesResult::type_name() const
{
  return typeName;
}

void AddNodesResult::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AddNodesResult::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AddNodesResult::encode(limit, *this, *xml);
  }
}

void AddNodesResult::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AddNodesResult::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AddNodesResult::encode_id(limit, ns, *xml);
  }
}

void AddNodesResult::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::AddNodesResult::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::AddNodesResult::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> AddNodesResult::clone() const
{
  return make_unique<AddNodesResult>(*this);
}

void AddNodesResult::append_fields(std::string& output, int indent) const
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
    output += pad + "added_node_id=" + ua::to_string(added_node_id());
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
  output += "added_node_id=" + ua::to_string(added_node_id());
}

std::string AddNodesResult::to_string(int indent) const
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

void AddNodesResult::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::AddNodesResult::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::AddNodesResult::create);
  }
}

StatusCode& AddNodesResult::status_code()
{
  return mStatusCode;
}

const StatusCode& AddNodesResult::status_code() const
{
  return mStatusCode;
}

NodeId& AddNodesResult::added_node_id()
{
  return mAddedNodeId;
}

const NodeId& AddNodesResult::added_node_id() const
{
  return mAddedNodeId;
}

BuiltInTypeId AddNodesResult::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::DeleteReferencesResponse
{
namespace
{
void encode(StackDepth limit, const ua::DeleteReferencesResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.results());
  encoder.encode(limit, value.diagnostic_infos());
}

void encode(StackDepth limit, const ua::DeleteReferencesResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "Results", value.results());
  encoder.encode(limit, "DiagnosticInfos", value.diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::DeleteReferencesResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.results());
  decoder.decode(limit, value.diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::DeleteReferencesResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "Results", true, value.results());
  decoder.decode(limit, "DiagnosticInfos", true, value.diagnostic_infos());
}
}  // namespace
}  // namespace detail::DeleteReferencesResponse

namespace detail::DeleteReferencesResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::DeleteReferencesResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::DeleteReferencesResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::DeleteReferencesResponse

namespace detail::DeleteReferencesResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::DeleteReferencesResponse>();
}
}  // namespace
}  // namespace detail::DeleteReferencesResponse

bool DeleteReferencesResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId DeleteReferencesResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId DeleteReferencesResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String DeleteReferencesResponse::type_name() const
{
  return typeName;
}

void DeleteReferencesResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DeleteReferencesResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DeleteReferencesResponse::encode(limit, *this, *xml);
  }
}

void DeleteReferencesResponse::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DeleteReferencesResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DeleteReferencesResponse::encode_id(limit, ns, *xml);
  }
}

void DeleteReferencesResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::DeleteReferencesResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::DeleteReferencesResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> DeleteReferencesResponse::clone() const
{
  return make_unique<DeleteReferencesResponse>(*this);
}

void DeleteReferencesResponse::append_fields(std::string& output, int indent) const
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

std::string DeleteReferencesResponse::to_string(int indent) const
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

void DeleteReferencesResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::DeleteReferencesResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::DeleteReferencesResponse::create);
  }
}

ResponseHeader& DeleteReferencesResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& DeleteReferencesResponse::response_header() const
{
  return mResponseHeader;
}

Array<StatusCode>& DeleteReferencesResponse::results()
{
  return mResults;
}

const Array<StatusCode>& DeleteReferencesResponse::results() const
{
  return mResults;
}

Array<DiagnosticInfo>& DeleteReferencesResponse::diagnostic_infos()
{
  return mDiagnosticInfos;
}

const Array<DiagnosticInfo>& DeleteReferencesResponse::diagnostic_infos() const
{
  return mDiagnosticInfos;
}

BuiltInTypeId DeleteReferencesResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::BrowseNextResponse
{
namespace
{
void encode(StackDepth limit, const ua::BrowseNextResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.results());
  encoder.encode(limit, value.diagnostic_infos());
}

void encode(StackDepth limit, const ua::BrowseNextResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "Results", value.results());
  encoder.encode(limit, "DiagnosticInfos", value.diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::BrowseNextResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.results());
  decoder.decode(limit, value.diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::BrowseNextResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "Results", true, value.results());
  decoder.decode(limit, "DiagnosticInfos", true, value.diagnostic_infos());
}
}  // namespace
}  // namespace detail::BrowseNextResponse

namespace detail::BrowseNextResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::BrowseNextResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::BrowseNextResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::BrowseNextResponse

namespace detail::BrowseNextResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::BrowseNextResponse>();
}
}  // namespace
}  // namespace detail::BrowseNextResponse

bool BrowseNextResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId BrowseNextResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId BrowseNextResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String BrowseNextResponse::type_name() const
{
  return typeName;
}

void BrowseNextResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::BrowseNextResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::BrowseNextResponse::encode(limit, *this, *xml);
  }
}

void BrowseNextResponse::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::BrowseNextResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::BrowseNextResponse::encode_id(limit, ns, *xml);
  }
}

void BrowseNextResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::BrowseNextResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::BrowseNextResponse::decode(limit, *xml, *this);
  }
}

void BrowseNextResponse::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  for (size_t i = 0; i < mResults.size(); ++i)
  {
    mResults[i].resolve(locales);
  }
}

unique_ptr<Structure> BrowseNextResponse::clone() const
{
  return make_unique<BrowseNextResponse>(*this);
}

void BrowseNextResponse::append_fields(std::string& output, int indent) const
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

std::string BrowseNextResponse::to_string(int indent) const
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

void BrowseNextResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::BrowseNextResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::BrowseNextResponse::create);
  }
}

ResponseHeader& BrowseNextResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& BrowseNextResponse::response_header() const
{
  return mResponseHeader;
}

Array<BrowseResult>& BrowseNextResponse::results()
{
  return mResults;
}

const Array<BrowseResult>& BrowseNextResponse::results() const
{
  return mResults;
}

Array<DiagnosticInfo>& BrowseNextResponse::diagnostic_infos()
{
  return mDiagnosticInfos;
}

const Array<DiagnosticInfo>& BrowseNextResponse::diagnostic_infos() const
{
  return mDiagnosticInfos;
}

BuiltInTypeId BrowseNextResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::UnregisterNodesRequest
{
namespace
{
void encode(StackDepth limit, const ua::UnregisterNodesRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.nodes_to_unregister());
}

void encode(StackDepth limit, const ua::UnregisterNodesRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "NodesToUnregister", value.nodes_to_unregister());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::UnregisterNodesRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.nodes_to_unregister());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::UnregisterNodesRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "NodesToUnregister", true, value.nodes_to_unregister());
}
}  // namespace
}  // namespace detail::UnregisterNodesRequest

namespace detail::UnregisterNodesRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::UnregisterNodesRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::UnregisterNodesRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::UnregisterNodesRequest

namespace detail::UnregisterNodesRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::UnregisterNodesRequest>();
}
}  // namespace
}  // namespace detail::UnregisterNodesRequest

bool UnregisterNodesRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId UnregisterNodesRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId UnregisterNodesRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String UnregisterNodesRequest::type_name() const
{
  return typeName;
}

void UnregisterNodesRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::UnregisterNodesRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::UnregisterNodesRequest::encode(limit, *this, *xml);
  }
}

void UnregisterNodesRequest::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::UnregisterNodesRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::UnregisterNodesRequest::encode_id(limit, ns, *xml);
  }
}

void UnregisterNodesRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::UnregisterNodesRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::UnregisterNodesRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> UnregisterNodesRequest::clone() const
{
  return make_unique<UnregisterNodesRequest>(*this);
}

void UnregisterNodesRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "nodes_to_unregister=" + ua::to_string(nodes_to_unregister());
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
  output += "nodes_to_unregister=" + ua::to_string(nodes_to_unregister());
}

std::string UnregisterNodesRequest::to_string(int indent) const
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

void UnregisterNodesRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::UnregisterNodesRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::UnregisterNodesRequest::create);
  }
}

RequestHeader& UnregisterNodesRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& UnregisterNodesRequest::request_header() const
{
  return mRequestHeader;
}

Array<NodeId>& UnregisterNodesRequest::nodes_to_unregister()
{
  return mNodesToUnregister;
}

const Array<NodeId>& UnregisterNodesRequest::nodes_to_unregister() const
{
  return mNodesToUnregister;
}

BuiltInTypeId UnregisterNodesRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ParsingResult
{
namespace
{
void encode(StackDepth limit, const ua::ParsingResult& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.status_code());
  encoder.encode(limit, value.data_status_codes());
  encoder.encode(limit, value.data_diagnostic_infos());
}

void encode(StackDepth limit, const ua::ParsingResult& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "StatusCode", value.status_code());
  encoder.encode(limit, "DataStatusCodes", value.data_status_codes());
  encoder.encode(limit, "DataDiagnosticInfos", value.data_diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ParsingResult& value)
{
  decoder.decode(limit, value.status_code());
  decoder.decode(limit, value.data_status_codes());
  decoder.decode(limit, value.data_diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ParsingResult& value)
{
  decoder.decode(limit, "StatusCode", true, value.status_code());
  decoder.decode(limit, "DataStatusCodes", true, value.data_status_codes());
  decoder.decode(limit, "DataDiagnosticInfos", true, value.data_diagnostic_infos());
}
}  // namespace
}  // namespace detail::ParsingResult

namespace detail::ParsingResult
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ParsingResult::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ParsingResult::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ParsingResult

namespace detail::ParsingResult
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ParsingResult>();
}
}  // namespace
}  // namespace detail::ParsingResult

bool ParsingResult::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ParsingResult::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ParsingResult::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ParsingResult::type_name() const
{
  return typeName;
}

void ParsingResult::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ParsingResult::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ParsingResult::encode(limit, *this, *xml);
  }
}

void ParsingResult::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ParsingResult::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ParsingResult::encode_id(limit, ns, *xml);
  }
}

void ParsingResult::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ParsingResult::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ParsingResult::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ParsingResult::clone() const
{
  return make_unique<ParsingResult>(*this);
}

void ParsingResult::append_fields(std::string& output, int indent) const
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
    output += pad + "data_status_codes=" + ua::to_string(data_status_codes());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "data_diagnostic_infos=" + ua::to_string(data_diagnostic_infos());
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
  output += "data_status_codes=" + ua::to_string(data_status_codes());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "data_diagnostic_infos=" + ua::to_string(data_diagnostic_infos());
}

std::string ParsingResult::to_string(int indent) const
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

void ParsingResult::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ParsingResult::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ParsingResult::create);
  }
}

StatusCode& ParsingResult::status_code()
{
  return mStatusCode;
}

const StatusCode& ParsingResult::status_code() const
{
  return mStatusCode;
}

Array<StatusCode>& ParsingResult::data_status_codes()
{
  return mDataStatusCodes;
}

const Array<StatusCode>& ParsingResult::data_status_codes() const
{
  return mDataStatusCodes;
}

Array<DiagnosticInfo>& ParsingResult::data_diagnostic_infos()
{
  return mDataDiagnosticInfos;
}

const Array<DiagnosticInfo>& ParsingResult::data_diagnostic_infos() const
{
  return mDataDiagnosticInfos;
}

BuiltInTypeId ParsingResult::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::HistoryReadValueId
{
namespace
{
void encode(StackDepth limit, const ua::HistoryReadValueId& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.node_id());
  encoder.encode(limit, value.index_range());
  encoder.encode(limit, value.data_encoding());
  encoder.encode(limit, value.continuation_point());
}

void encode(StackDepth limit, const ua::HistoryReadValueId& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "NodeId", value.node_id());
  encoder.encode(limit, "IndexRange", value.index_range());
  encoder.encode(limit, "DataEncoding", value.data_encoding());
  encoder.encode(limit, "ContinuationPoint", value.continuation_point());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::HistoryReadValueId& value)
{
  decoder.decode(limit, value.node_id());
  decoder.decode(limit, value.index_range());
  decoder.decode(limit, value.data_encoding());
  decoder.decode(limit, value.continuation_point());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::HistoryReadValueId& value)
{
  decoder.decode(limit, "NodeId", true, value.node_id());
  decoder.decode(limit, "IndexRange", true, value.index_range());
  decoder.decode(limit, "DataEncoding", true, value.data_encoding());
  decoder.decode(limit, "ContinuationPoint", true, value.continuation_point());
}
}  // namespace
}  // namespace detail::HistoryReadValueId

namespace detail::HistoryReadValueId
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::HistoryReadValueId::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::HistoryReadValueId::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::HistoryReadValueId

namespace detail::HistoryReadValueId
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::HistoryReadValueId>();
}
}  // namespace
}  // namespace detail::HistoryReadValueId

bool HistoryReadValueId::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId HistoryReadValueId::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId HistoryReadValueId::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String HistoryReadValueId::type_name() const
{
  return typeName;
}

void HistoryReadValueId::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::HistoryReadValueId::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::HistoryReadValueId::encode(limit, *this, *xml);
  }
}

void HistoryReadValueId::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::HistoryReadValueId::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::HistoryReadValueId::encode_id(limit, ns, *xml);
  }
}

void HistoryReadValueId::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::HistoryReadValueId::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::HistoryReadValueId::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> HistoryReadValueId::clone() const
{
  return make_unique<HistoryReadValueId>(*this);
}

void HistoryReadValueId::append_fields(std::string& output, int indent) const
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
    output += pad + "index_range=" + ua::to_string(index_range());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "data_encoding=" + ua::to_string(data_encoding());
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
  output += "node_id=" + ua::to_string(node_id());
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
  if (!output.empty())
  {
    output += ", ";
  }
  output += "continuation_point=" + ua::to_string(continuation_point());
}

std::string HistoryReadValueId::to_string(int indent) const
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

void HistoryReadValueId::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::HistoryReadValueId::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::HistoryReadValueId::create);
  }
}

NodeId& HistoryReadValueId::node_id()
{
  return mNodeId;
}

const NodeId& HistoryReadValueId::node_id() const
{
  return mNodeId;
}

NumericRange& HistoryReadValueId::index_range()
{
  return mIndexRange;
}

const NumericRange& HistoryReadValueId::index_range() const
{
  return mIndexRange;
}

QualifiedName& HistoryReadValueId::data_encoding()
{
  return mDataEncoding;
}

const QualifiedName& HistoryReadValueId::data_encoding() const
{
  return mDataEncoding;
}

ContinuationPoint& HistoryReadValueId::continuation_point()
{
  return mContinuationPoint;
}

const ContinuationPoint& HistoryReadValueId::continuation_point() const
{
  return mContinuationPoint;
}

BuiltInTypeId HistoryReadValueId::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ReadProcessedDetails
{
namespace
{
void encode(StackDepth limit, const ua::ReadProcessedDetails& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.start_time());
  encoder.encode(limit, value.end_time());
  encoder.encode(limit, value.processing_interval());
  encoder.encode(limit, value.aggregate_type());
  encoder.encode(limit, value.aggregate_configuration());
}

void encode(StackDepth limit, const ua::ReadProcessedDetails& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "StartTime", value.start_time());
  encoder.encode(limit, "EndTime", value.end_time());
  encoder.encode(limit, "ProcessingInterval", value.processing_interval());
  encoder.encode(limit, "AggregateType", value.aggregate_type());
  encoder.encode(limit, "AggregateConfiguration", value.aggregate_configuration());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ReadProcessedDetails& value)
{
  decoder.decode(limit, value.start_time());
  decoder.decode(limit, value.end_time());
  decoder.decode(limit, value.processing_interval());
  decoder.decode(limit, value.aggregate_type());
  decoder.decode(limit, value.aggregate_configuration());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ReadProcessedDetails& value)
{
  decoder.decode(limit, "StartTime", true, value.start_time());
  decoder.decode(limit, "EndTime", true, value.end_time());
  decoder.decode(limit, "ProcessingInterval", true, value.processing_interval());
  decoder.decode(limit, "AggregateType", true, value.aggregate_type());
  decoder.decode(limit, "AggregateConfiguration", true, value.aggregate_configuration());
}
}  // namespace
}  // namespace detail::ReadProcessedDetails

namespace detail::ReadProcessedDetails
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ReadProcessedDetails::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ReadProcessedDetails::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ReadProcessedDetails

namespace detail::ReadProcessedDetails
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ReadProcessedDetails>();
}
}  // namespace
}  // namespace detail::ReadProcessedDetails

bool ReadProcessedDetails::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return HistoryReadDetails::is_of_type(ns, dataTypeId);
}

NodeId ReadProcessedDetails::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ReadProcessedDetails::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ReadProcessedDetails::type_name() const
{
  return typeName;
}

void ReadProcessedDetails::encode(StackDepth limit, Encoder& encoder) const
{

  HistoryReadDetails::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReadProcessedDetails::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReadProcessedDetails::encode(limit, *this, *xml);
  }
}

void ReadProcessedDetails::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReadProcessedDetails::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReadProcessedDetails::encode_id(limit, ns, *xml);
  }
}

void ReadProcessedDetails::decode(StackDepth limit, Decoder& decoder)
{

  HistoryReadDetails::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ReadProcessedDetails::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ReadProcessedDetails::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ReadProcessedDetails::clone() const
{
  return make_unique<ReadProcessedDetails>(*this);
}

void ReadProcessedDetails::append_fields(std::string& output, int indent) const
{
  HistoryReadDetails::append_fields(output, indent);
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
    output += pad + "end_time=" + ua::to_string(end_time());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "processing_interval=" + ua::to_string(processing_interval());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "aggregate_type=" + ua::to_string(aggregate_type());
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
  output += "end_time=" + ua::to_string(end_time());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "processing_interval=" + ua::to_string(processing_interval());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "aggregate_type=" + ua::to_string(aggregate_type());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "aggregate_configuration=" + ua::to_string(aggregate_configuration());
}

std::string ReadProcessedDetails::to_string(int indent) const
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

void ReadProcessedDetails::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ReadProcessedDetails::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ReadProcessedDetails::create);
  }
}

UtcTime& ReadProcessedDetails::start_time()
{
  return mStartTime;
}

const UtcTime& ReadProcessedDetails::start_time() const
{
  return mStartTime;
}

UtcTime& ReadProcessedDetails::end_time()
{
  return mEndTime;
}

const UtcTime& ReadProcessedDetails::end_time() const
{
  return mEndTime;
}

Duration& ReadProcessedDetails::processing_interval()
{
  return mProcessingInterval;
}

const Duration& ReadProcessedDetails::processing_interval() const
{
  return mProcessingInterval;
}

Array<NodeId>& ReadProcessedDetails::aggregate_type()
{
  return mAggregateType;
}

const Array<NodeId>& ReadProcessedDetails::aggregate_type() const
{
  return mAggregateType;
}

AggregateConfiguration& ReadProcessedDetails::aggregate_configuration()
{
  return mAggregateConfiguration;
}

const AggregateConfiguration& ReadProcessedDetails::aggregate_configuration() const
{
  return mAggregateConfiguration;
}

BuiltInTypeId ReadProcessedDetails::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::WriteRequest
{
namespace
{
void encode(StackDepth limit, const ua::WriteRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.nodes_to_write());
}

void encode(StackDepth limit, const ua::WriteRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "NodesToWrite", value.nodes_to_write());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::WriteRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.nodes_to_write());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::WriteRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "NodesToWrite", true, value.nodes_to_write());
}
}  // namespace
}  // namespace detail::WriteRequest

namespace detail::WriteRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::WriteRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::WriteRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::WriteRequest

namespace detail::WriteRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::WriteRequest>();
}
}  // namespace
}  // namespace detail::WriteRequest

bool WriteRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId WriteRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId WriteRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String WriteRequest::type_name() const
{
  return typeName;
}

void WriteRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::WriteRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::WriteRequest::encode(limit, *this, *xml);
  }
}

void WriteRequest::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::WriteRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::WriteRequest::encode_id(limit, ns, *xml);
  }
}

void WriteRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::WriteRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::WriteRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> WriteRequest::clone() const
{
  return make_unique<WriteRequest>(*this);
}

void WriteRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "nodes_to_write=" + ua::to_string(nodes_to_write());
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
  output += "nodes_to_write=" + ua::to_string(nodes_to_write());
}

std::string WriteRequest::to_string(int indent) const
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

void WriteRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::WriteRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::WriteRequest::create);
  }
}

RequestHeader& WriteRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& WriteRequest::request_header() const
{
  return mRequestHeader;
}

Array<WriteValue>& WriteRequest::nodes_to_write()
{
  return mNodesToWrite;
}

const Array<WriteValue>& WriteRequest::nodes_to_write() const
{
  return mNodesToWrite;
}

BuiltInTypeId WriteRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::DeleteEventDetails
{
namespace
{
void encode(StackDepth limit, const ua::DeleteEventDetails& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.node_id());
  encoder.encode(limit, value.event_ids());
}

void encode(StackDepth limit, const ua::DeleteEventDetails& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "NodeId", value.node_id());
  encoder.encode(limit, "EventIds", value.event_ids());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::DeleteEventDetails& value)
{
  decoder.decode(limit, value.node_id());
  decoder.decode(limit, value.event_ids());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::DeleteEventDetails& value)
{
  decoder.decode(limit, "NodeId", true, value.node_id());
  decoder.decode(limit, "EventIds", true, value.event_ids());
}
}  // namespace
}  // namespace detail::DeleteEventDetails

namespace detail::DeleteEventDetails
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::DeleteEventDetails::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::DeleteEventDetails::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::DeleteEventDetails

namespace detail::DeleteEventDetails
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::DeleteEventDetails>();
}
}  // namespace
}  // namespace detail::DeleteEventDetails

bool DeleteEventDetails::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return HistoryUpdateDetails::is_of_type(ns, dataTypeId);
}

NodeId DeleteEventDetails::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId DeleteEventDetails::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String DeleteEventDetails::type_name() const
{
  return typeName;
}

void DeleteEventDetails::encode(StackDepth limit, Encoder& encoder) const
{

  HistoryUpdateDetails::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DeleteEventDetails::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DeleteEventDetails::encode(limit, *this, *xml);
  }
}

void DeleteEventDetails::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DeleteEventDetails::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DeleteEventDetails::encode_id(limit, ns, *xml);
  }
}

void DeleteEventDetails::decode(StackDepth limit, Decoder& decoder)
{

  HistoryUpdateDetails::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::DeleteEventDetails::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::DeleteEventDetails::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> DeleteEventDetails::clone() const
{
  return make_unique<DeleteEventDetails>(*this);
}

void DeleteEventDetails::append_fields(std::string& output, int indent) const
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
    output += pad + "event_ids=" + ua::to_string(event_ids());
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
  output += "event_ids=" + ua::to_string(event_ids());
}

std::string DeleteEventDetails::to_string(int indent) const
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

void DeleteEventDetails::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::DeleteEventDetails::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::DeleteEventDetails::create);
  }
}

NodeId& DeleteEventDetails::node_id()
{
  return mNodeId;
}

const NodeId& DeleteEventDetails::node_id() const
{
  return mNodeId;
}

Array<ByteString>& DeleteEventDetails::event_ids()
{
  return mEventIds;
}

const Array<ByteString>& DeleteEventDetails::event_ids() const
{
  return mEventIds;
}

BuiltInTypeId DeleteEventDetails::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::DataChangeFilter
{
namespace
{
void encode(StackDepth limit, const ua::DataChangeFilter& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, utils::as_int32(value.trigger()));
  encoder.encode(limit, value.deadband_type());
  encoder.encode(limit, value.deadband_value());
}

void encode(StackDepth limit, const ua::DataChangeFilter& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Trigger", utils::as_int32(value.trigger()));
  encoder.encode(limit, "DeadbandType", value.deadband_type());
  encoder.encode(limit, "DeadbandValue", value.deadband_value());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::DataChangeFilter& value)
{
  int32_t enumVal{};
  decoder.decode(limit, enumVal);
  value.trigger() = utils::from_underlying<DataChangeTrigger>(enumVal);
  decoder.decode(limit, value.deadband_type());
  decoder.decode(limit, value.deadband_value());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::DataChangeFilter& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "Trigger", true, enumVal);
  value.trigger() = utils::from_underlying<DataChangeTrigger>(enumVal);
  decoder.decode(limit, "DeadbandType", true, value.deadband_type());
  decoder.decode(limit, "DeadbandValue", true, value.deadband_value());
}
}  // namespace
}  // namespace detail::DataChangeFilter

namespace detail::DataChangeFilter
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::DataChangeFilter::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::DataChangeFilter::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::DataChangeFilter

namespace detail::DataChangeFilter
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::DataChangeFilter>();
}
}  // namespace
}  // namespace detail::DataChangeFilter

bool DataChangeFilter::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return MonitoringFilter::is_of_type(ns, dataTypeId);
}

NodeId DataChangeFilter::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId DataChangeFilter::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String DataChangeFilter::type_name() const
{
  return typeName;
}

void DataChangeFilter::encode(StackDepth limit, Encoder& encoder) const
{

  MonitoringFilter::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DataChangeFilter::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DataChangeFilter::encode(limit, *this, *xml);
  }
}

void DataChangeFilter::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DataChangeFilter::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DataChangeFilter::encode_id(limit, ns, *xml);
  }
}

void DataChangeFilter::decode(StackDepth limit, Decoder& decoder)
{

  MonitoringFilter::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::DataChangeFilter::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::DataChangeFilter::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> DataChangeFilter::clone() const
{
  return make_unique<DataChangeFilter>(*this);
}

void DataChangeFilter::append_fields(std::string& output, int indent) const
{
  MonitoringFilter::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "trigger=" + ua::to_string(utils::as_int32(trigger()));
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "deadband_type=" + ua::to_string(deadband_type());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "deadband_value=" + ua::to_string(deadband_value());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "trigger=" + ua::to_string(utils::as_int32(trigger()));
  if (!output.empty())
  {
    output += ", ";
  }
  output += "deadband_type=" + ua::to_string(deadband_type());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "deadband_value=" + ua::to_string(deadband_value());
}

std::string DataChangeFilter::to_string(int indent) const
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

void DataChangeFilter::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::DataChangeFilter::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::DataChangeFilter::create);
  }
}

DataChangeTrigger& DataChangeFilter::trigger()
{
  return mTrigger;
}

const DataChangeTrigger& DataChangeFilter::trigger() const
{
  return mTrigger;
}

uint32_t& DataChangeFilter::deadband_type()
{
  return mDeadbandType;
}

const uint32_t& DataChangeFilter::deadband_type() const
{
  return mDeadbandType;
}

double& DataChangeFilter::deadband_value()
{
  return mDeadbandValue;
}

const double& DataChangeFilter::deadband_value() const
{
  return mDeadbandValue;
}

BuiltInTypeId DataChangeFilter::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::CreateMonitoredItemsRequest
{
namespace
{
void encode(StackDepth limit, const ua::CreateMonitoredItemsRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.subscription_id());
  encoder.encode(limit, utils::as_int32(value.timestamps_to_return()));
  encoder.encode(limit, value.items_to_create());
}

void encode(StackDepth limit, const ua::CreateMonitoredItemsRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "SubscriptionId", value.subscription_id());
  encoder.encode(limit, "TimestampsToReturn", utils::as_int32(value.timestamps_to_return()));
  encoder.encode(limit, "ItemsToCreate", value.items_to_create());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::CreateMonitoredItemsRequest& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.subscription_id());
  decoder.decode(limit, enumVal);
  value.timestamps_to_return() = utils::from_underlying<TimestampsToReturn>(enumVal);
  decoder.decode(limit, value.items_to_create());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::CreateMonitoredItemsRequest& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "SubscriptionId", true, value.subscription_id());
  decoder.decode(limit, "TimestampsToReturn", true, enumVal);
  value.timestamps_to_return() = utils::from_underlying<TimestampsToReturn>(enumVal);
  decoder.decode(limit, "ItemsToCreate", true, value.items_to_create());
}
}  // namespace
}  // namespace detail::CreateMonitoredItemsRequest

namespace detail::CreateMonitoredItemsRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::CreateMonitoredItemsRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::CreateMonitoredItemsRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::CreateMonitoredItemsRequest

namespace detail::CreateMonitoredItemsRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::CreateMonitoredItemsRequest>();
}
}  // namespace
}  // namespace detail::CreateMonitoredItemsRequest

bool CreateMonitoredItemsRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId CreateMonitoredItemsRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId CreateMonitoredItemsRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String CreateMonitoredItemsRequest::type_name() const
{
  return typeName;
}

void CreateMonitoredItemsRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CreateMonitoredItemsRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CreateMonitoredItemsRequest::encode(limit, *this, *xml);
  }
}

void CreateMonitoredItemsRequest::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CreateMonitoredItemsRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CreateMonitoredItemsRequest::encode_id(limit, ns, *xml);
  }
}

void CreateMonitoredItemsRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::CreateMonitoredItemsRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::CreateMonitoredItemsRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> CreateMonitoredItemsRequest::clone() const
{
  return make_unique<CreateMonitoredItemsRequest>(*this);
}

void CreateMonitoredItemsRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "timestamps_to_return=" + ua::to_string(utils::as_int32(timestamps_to_return()));
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "items_to_create=" + ua::to_string(items_to_create());
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
  output += "timestamps_to_return=" + ua::to_string(utils::as_int32(timestamps_to_return()));
  if (!output.empty())
  {
    output += ", ";
  }
  output += "items_to_create=" + ua::to_string(items_to_create());
}

std::string CreateMonitoredItemsRequest::to_string(int indent) const
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

void CreateMonitoredItemsRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::CreateMonitoredItemsRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::CreateMonitoredItemsRequest::create);
  }
}

RequestHeader& CreateMonitoredItemsRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& CreateMonitoredItemsRequest::request_header() const
{
  return mRequestHeader;
}

IntegerId& CreateMonitoredItemsRequest::subscription_id()
{
  return mSubscriptionId;
}

const IntegerId& CreateMonitoredItemsRequest::subscription_id() const
{
  return mSubscriptionId;
}

TimestampsToReturn& CreateMonitoredItemsRequest::timestamps_to_return()
{
  return mTimestampsToReturn;
}

const TimestampsToReturn& CreateMonitoredItemsRequest::timestamps_to_return() const
{
  return mTimestampsToReturn;
}

Array<MonitoredItemCreateRequest>& CreateMonitoredItemsRequest::items_to_create()
{
  return mItemsToCreate;
}

const Array<MonitoredItemCreateRequest>& CreateMonitoredItemsRequest::items_to_create() const
{
  return mItemsToCreate;
}

BuiltInTypeId CreateMonitoredItemsRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::SetTriggeringRequest
{
namespace
{
void encode(StackDepth limit, const ua::SetTriggeringRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.subscription_id());
  encoder.encode(limit, value.triggering_item_id());
  encoder.encode(limit, value.links_to_add());
  encoder.encode(limit, value.links_to_remove());
}

void encode(StackDepth limit, const ua::SetTriggeringRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "SubscriptionId", value.subscription_id());
  encoder.encode(limit, "TriggeringItemId", value.triggering_item_id());
  encoder.encode(limit, "LinksToAdd", value.links_to_add());
  encoder.encode(limit, "LinksToRemove", value.links_to_remove());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::SetTriggeringRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.subscription_id());
  decoder.decode(limit, value.triggering_item_id());
  decoder.decode(limit, value.links_to_add());
  decoder.decode(limit, value.links_to_remove());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::SetTriggeringRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "SubscriptionId", true, value.subscription_id());
  decoder.decode(limit, "TriggeringItemId", true, value.triggering_item_id());
  decoder.decode(limit, "LinksToAdd", true, value.links_to_add());
  decoder.decode(limit, "LinksToRemove", true, value.links_to_remove());
}
}  // namespace
}  // namespace detail::SetTriggeringRequest

namespace detail::SetTriggeringRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::SetTriggeringRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::SetTriggeringRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::SetTriggeringRequest

namespace detail::SetTriggeringRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::SetTriggeringRequest>();
}
}  // namespace
}  // namespace detail::SetTriggeringRequest

bool SetTriggeringRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId SetTriggeringRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId SetTriggeringRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String SetTriggeringRequest::type_name() const
{
  return typeName;
}

void SetTriggeringRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SetTriggeringRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SetTriggeringRequest::encode(limit, *this, *xml);
  }
}

void SetTriggeringRequest::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SetTriggeringRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SetTriggeringRequest::encode_id(limit, ns, *xml);
  }
}

void SetTriggeringRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::SetTriggeringRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::SetTriggeringRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> SetTriggeringRequest::clone() const
{
  return make_unique<SetTriggeringRequest>(*this);
}

void SetTriggeringRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "triggering_item_id=" + ua::to_string(triggering_item_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "links_to_add=" + ua::to_string(links_to_add());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "links_to_remove=" + ua::to_string(links_to_remove());
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
  output += "triggering_item_id=" + ua::to_string(triggering_item_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "links_to_add=" + ua::to_string(links_to_add());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "links_to_remove=" + ua::to_string(links_to_remove());
}

std::string SetTriggeringRequest::to_string(int indent) const
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

void SetTriggeringRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::SetTriggeringRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::SetTriggeringRequest::create);
  }
}

RequestHeader& SetTriggeringRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& SetTriggeringRequest::request_header() const
{
  return mRequestHeader;
}

IntegerId& SetTriggeringRequest::subscription_id()
{
  return mSubscriptionId;
}

const IntegerId& SetTriggeringRequest::subscription_id() const
{
  return mSubscriptionId;
}

IntegerId& SetTriggeringRequest::triggering_item_id()
{
  return mTriggeringItemId;
}

const IntegerId& SetTriggeringRequest::triggering_item_id() const
{
  return mTriggeringItemId;
}

Array<IntegerId>& SetTriggeringRequest::links_to_add()
{
  return mLinksToAdd;
}

const Array<IntegerId>& SetTriggeringRequest::links_to_add() const
{
  return mLinksToAdd;
}

Array<IntegerId>& SetTriggeringRequest::links_to_remove()
{
  return mLinksToRemove;
}

const Array<IntegerId>& SetTriggeringRequest::links_to_remove() const
{
  return mLinksToRemove;
}

BuiltInTypeId SetTriggeringRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::SetPublishingModeRequest
{
namespace
{
void encode(StackDepth limit, const ua::SetPublishingModeRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.publishing_enabled());
  encoder.encode(limit, value.subscription_ids());
}

void encode(StackDepth limit, const ua::SetPublishingModeRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "PublishingEnabled", value.publishing_enabled());
  encoder.encode(limit, "SubscriptionIds", value.subscription_ids());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::SetPublishingModeRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.publishing_enabled());
  decoder.decode(limit, value.subscription_ids());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::SetPublishingModeRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "PublishingEnabled", true, value.publishing_enabled());
  decoder.decode(limit, "SubscriptionIds", true, value.subscription_ids());
}
}  // namespace
}  // namespace detail::SetPublishingModeRequest

namespace detail::SetPublishingModeRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::SetPublishingModeRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::SetPublishingModeRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::SetPublishingModeRequest

namespace detail::SetPublishingModeRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::SetPublishingModeRequest>();
}
}  // namespace
}  // namespace detail::SetPublishingModeRequest

bool SetPublishingModeRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId SetPublishingModeRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId SetPublishingModeRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String SetPublishingModeRequest::type_name() const
{
  return typeName;
}

void SetPublishingModeRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SetPublishingModeRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SetPublishingModeRequest::encode(limit, *this, *xml);
  }
}

void SetPublishingModeRequest::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SetPublishingModeRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SetPublishingModeRequest::encode_id(limit, ns, *xml);
  }
}

void SetPublishingModeRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::SetPublishingModeRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::SetPublishingModeRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> SetPublishingModeRequest::clone() const
{
  return make_unique<SetPublishingModeRequest>(*this);
}

void SetPublishingModeRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "publishing_enabled=" + ua::to_string(publishing_enabled());
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
  output += "publishing_enabled=" + ua::to_string(publishing_enabled());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "subscription_ids=" + ua::to_string(subscription_ids());
}

std::string SetPublishingModeRequest::to_string(int indent) const
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

void SetPublishingModeRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::SetPublishingModeRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::SetPublishingModeRequest::create);
  }
}

RequestHeader& SetPublishingModeRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& SetPublishingModeRequest::request_header() const
{
  return mRequestHeader;
}

bool& SetPublishingModeRequest::publishing_enabled()
{
  return mPublishingEnabled;
}

const bool& SetPublishingModeRequest::publishing_enabled() const
{
  return mPublishingEnabled;
}

Array<IntegerId>& SetPublishingModeRequest::subscription_ids()
{
  return mSubscriptionIds;
}

const Array<IntegerId>& SetPublishingModeRequest::subscription_ids() const
{
  return mSubscriptionIds;
}

BuiltInTypeId SetPublishingModeRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::StatusChangeNotification
{
namespace
{
void encode(StackDepth limit, const ua::StatusChangeNotification& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.status());
  encoder.encode(limit, value.diagnostic_info());
}

void encode(StackDepth limit, const ua::StatusChangeNotification& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Status", value.status());
  encoder.encode(limit, "DiagnosticInfo", value.diagnostic_info());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::StatusChangeNotification& value)
{
  decoder.decode(limit, value.status());
  decoder.decode(limit, value.diagnostic_info());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::StatusChangeNotification& value)
{
  decoder.decode(limit, "Status", true, value.status());
  decoder.decode(limit, "DiagnosticInfo", true, value.diagnostic_info());
}
}  // namespace
}  // namespace detail::StatusChangeNotification

namespace detail::StatusChangeNotification
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::StatusChangeNotification::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::StatusChangeNotification::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::StatusChangeNotification

namespace detail::StatusChangeNotification
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::StatusChangeNotification>();
}
}  // namespace
}  // namespace detail::StatusChangeNotification

bool StatusChangeNotification::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return NotificationData::is_of_type(ns, dataTypeId);
}

NodeId StatusChangeNotification::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId StatusChangeNotification::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String StatusChangeNotification::type_name() const
{
  return typeName;
}

void StatusChangeNotification::encode(StackDepth limit, Encoder& encoder) const
{

  NotificationData::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::StatusChangeNotification::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::StatusChangeNotification::encode(limit, *this, *xml);
  }
}

void StatusChangeNotification::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::StatusChangeNotification::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::StatusChangeNotification::encode_id(limit, ns, *xml);
  }
}

void StatusChangeNotification::decode(StackDepth limit, Decoder& decoder)
{

  NotificationData::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::StatusChangeNotification::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::StatusChangeNotification::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> StatusChangeNotification::clone() const
{
  return make_unique<StatusChangeNotification>(*this);
}

void StatusChangeNotification::append_fields(std::string& output, int indent) const
{
  NotificationData::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "status=" + ua::to_string(status());
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
  output += "status=" + ua::to_string(status());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "diagnostic_info=" + ua::to_string(diagnostic_info());
}

std::string StatusChangeNotification::to_string(int indent) const
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

void StatusChangeNotification::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::StatusChangeNotification::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::StatusChangeNotification::create);
  }
}

StatusCode& StatusChangeNotification::status()
{
  return mStatus;
}

const StatusCode& StatusChangeNotification::status() const
{
  return mStatus;
}

DiagnosticInfo& StatusChangeNotification::diagnostic_info()
{
  return mDiagnosticInfo;
}

const DiagnosticInfo& StatusChangeNotification::diagnostic_info() const
{
  return mDiagnosticInfo;
}

BuiltInTypeId StatusChangeNotification::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::TransferSubscriptionsResponse
{
namespace
{
void encode(StackDepth limit, const ua::TransferSubscriptionsResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.results());
  encoder.encode(limit, value.diagnostic_infos());
}

void encode(StackDepth limit, const ua::TransferSubscriptionsResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "Results", value.results());
  encoder.encode(limit, "DiagnosticInfos", value.diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::TransferSubscriptionsResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.results());
  decoder.decode(limit, value.diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::TransferSubscriptionsResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "Results", true, value.results());
  decoder.decode(limit, "DiagnosticInfos", true, value.diagnostic_infos());
}
}  // namespace
}  // namespace detail::TransferSubscriptionsResponse

namespace detail::TransferSubscriptionsResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::TransferSubscriptionsResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::TransferSubscriptionsResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::TransferSubscriptionsResponse

namespace detail::TransferSubscriptionsResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::TransferSubscriptionsResponse>();
}
}  // namespace
}  // namespace detail::TransferSubscriptionsResponse

bool TransferSubscriptionsResponse::is_of_type(
  const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId TransferSubscriptionsResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId TransferSubscriptionsResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String TransferSubscriptionsResponse::type_name() const
{
  return typeName;
}

void TransferSubscriptionsResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::TransferSubscriptionsResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::TransferSubscriptionsResponse::encode(limit, *this, *xml);
  }
}

void TransferSubscriptionsResponse::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::TransferSubscriptionsResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::TransferSubscriptionsResponse::encode_id(limit, ns, *xml);
  }
}

void TransferSubscriptionsResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::TransferSubscriptionsResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::TransferSubscriptionsResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> TransferSubscriptionsResponse::clone() const
{
  return make_unique<TransferSubscriptionsResponse>(*this);
}

void TransferSubscriptionsResponse::append_fields(std::string& output, int indent) const
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

std::string TransferSubscriptionsResponse::to_string(int indent) const
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

void TransferSubscriptionsResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::TransferSubscriptionsResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::TransferSubscriptionsResponse::create);
  }
}

ResponseHeader& TransferSubscriptionsResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& TransferSubscriptionsResponse::response_header() const
{
  return mResponseHeader;
}

Array<TransferResult>& TransferSubscriptionsResponse::results()
{
  return mResults;
}

const Array<TransferResult>& TransferSubscriptionsResponse::results() const
{
  return mResults;
}

Array<DiagnosticInfo>& TransferSubscriptionsResponse::diagnostic_infos()
{
  return mDiagnosticInfos;
}

const Array<DiagnosticInfo>& TransferSubscriptionsResponse::diagnostic_infos() const
{
  return mDiagnosticInfos;
}

BuiltInTypeId TransferSubscriptionsResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

}  // namespace ua
