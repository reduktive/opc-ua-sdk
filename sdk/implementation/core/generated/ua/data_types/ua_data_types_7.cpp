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

namespace detail::ThreeDVector
{
namespace
{
void encode(StackDepth limit, const ua::ThreeDVector& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.x());
  encoder.encode(limit, value.y());
  encoder.encode(limit, value.z());
}

void encode(StackDepth limit, const ua::ThreeDVector& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "X", value.x());
  encoder.encode(limit, "Y", value.y());
  encoder.encode(limit, "Z", value.z());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ThreeDVector& value)
{
  decoder.decode(limit, value.x());
  decoder.decode(limit, value.y());
  decoder.decode(limit, value.z());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ThreeDVector& value)
{
  decoder.decode(limit, "X", true, value.x());
  decoder.decode(limit, "Y", true, value.y());
  decoder.decode(limit, "Z", true, value.z());
}
}  // namespace
}  // namespace detail::ThreeDVector

namespace detail::ThreeDVector
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ThreeDVector::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ThreeDVector::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ThreeDVector

namespace detail::ThreeDVector
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ThreeDVector>();
}
}  // namespace
}  // namespace detail::ThreeDVector

bool ThreeDVector::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Vector::is_of_type(ns, dataTypeId);
}

NodeId ThreeDVector::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ThreeDVector::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ThreeDVector::type_name() const
{
  return typeName;
}

void ThreeDVector::encode(StackDepth limit, Encoder& encoder) const
{

  Vector::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ThreeDVector::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ThreeDVector::encode(limit, *this, *xml);
  }
}

void ThreeDVector::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ThreeDVector::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ThreeDVector::encode_id(limit, ns, *xml);
  }
}

void ThreeDVector::decode(StackDepth limit, Decoder& decoder)
{

  Vector::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ThreeDVector::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ThreeDVector::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ThreeDVector::clone() const
{
  return make_unique<ThreeDVector>(*this);
}

void ThreeDVector::append_fields(std::string& output, int indent) const
{
  Vector::append_fields(output, indent);
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

std::string ThreeDVector::to_string(int indent) const
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

void ThreeDVector::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ThreeDVector::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ThreeDVector::create);
  }
}

double& ThreeDVector::x()
{
  return mX;
}

const double& ThreeDVector::x() const
{
  return mX;
}

double& ThreeDVector::y()
{
  return mY;
}

const double& ThreeDVector::y() const
{
  return mY;
}

double& ThreeDVector::z()
{
  return mZ;
}

const double& ThreeDVector::z() const
{
  return mZ;
}

BuiltInTypeId ThreeDVector::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::CurrencyUnitType
{
namespace
{
void encode(StackDepth limit, const ua::CurrencyUnitType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.numeric_code());
  encoder.encode(limit, value.exponent());
  encoder.encode(limit, value.alphabetic_code());
  encoder.encode(limit, value.currency());
}

void encode(StackDepth limit, const ua::CurrencyUnitType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "NumericCode", value.numeric_code());
  encoder.encode(limit, "Exponent", value.exponent());
  encoder.encode(limit, "AlphabeticCode", value.alphabetic_code());
  encoder.encode(limit, "Currency", value.currency());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::CurrencyUnitType& value)
{
  decoder.decode(limit, value.numeric_code());
  decoder.decode(limit, value.exponent());
  decoder.decode(limit, value.alphabetic_code());
  decoder.decode(limit, value.currency());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::CurrencyUnitType& value)
{
  decoder.decode(limit, "NumericCode", true, value.numeric_code());
  decoder.decode(limit, "Exponent", true, value.exponent());
  decoder.decode(limit, "AlphabeticCode", true, value.alphabetic_code());
  decoder.decode(limit, "Currency", true, value.currency());
}
}  // namespace
}  // namespace detail::CurrencyUnitType

namespace detail::CurrencyUnitType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::CurrencyUnitType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::CurrencyUnitType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::CurrencyUnitType

namespace detail::CurrencyUnitType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::CurrencyUnitType>();
}
}  // namespace
}  // namespace detail::CurrencyUnitType

bool CurrencyUnitType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId CurrencyUnitType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId CurrencyUnitType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String CurrencyUnitType::type_name() const
{
  return typeName;
}

void CurrencyUnitType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CurrencyUnitType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CurrencyUnitType::encode(limit, *this, *xml);
  }
}

void CurrencyUnitType::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CurrencyUnitType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CurrencyUnitType::encode_id(limit, ns, *xml);
  }
}

void CurrencyUnitType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::CurrencyUnitType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::CurrencyUnitType::decode(limit, *xml, *this);
  }
}

void CurrencyUnitType::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  mCurrency = mCurrency.resolve(locales);
}

unique_ptr<Structure> CurrencyUnitType::clone() const
{
  return make_unique<CurrencyUnitType>(*this);
}

void CurrencyUnitType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "numeric_code=" + [&]
    {
      const auto code = numeric_code();
      const auto text = ua::to_string(code);
      if (code >= 0 && code < 10)
        return std::string{"00"} + text;
      if (code >= 10 && code < 100)
        return std::string{"0"} + text;
      return text;
    }();
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "exponent=" + ua::to_string(exponent());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "alphabetic_code=" + ua::to_string(alphabetic_code());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "currency=" + ua::to_string(currency());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "numeric_code=" + [&]
  {
    const auto code = numeric_code();
    const auto text = ua::to_string(code);
    if (code >= 0 && code < 10)
      return std::string{"00"} + text;
    if (code >= 10 && code < 100)
      return std::string{"0"} + text;
    return text;
  }();
  if (!output.empty())
  {
    output += ", ";
  }
  output += "exponent=" + ua::to_string(exponent());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "alphabetic_code=" + ua::to_string(alphabetic_code());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "currency=" + ua::to_string(currency());
}

std::string CurrencyUnitType::to_string(int indent) const
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

void CurrencyUnitType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::CurrencyUnitType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::CurrencyUnitType::create);
  }
}

int16_t& CurrencyUnitType::numeric_code()
{
  return mNumericCode;
}

const int16_t& CurrencyUnitType::numeric_code() const
{
  return mNumericCode;
}

int8_t& CurrencyUnitType::exponent()
{
  return mExponent;
}

const int8_t& CurrencyUnitType::exponent() const
{
  return mExponent;
}

String& CurrencyUnitType::alphabetic_code()
{
  return mAlphabeticCode;
}

const String& CurrencyUnitType::alphabetic_code() const
{
  return mAlphabeticCode;
}

LocalizedText& CurrencyUnitType::currency()
{
  return mCurrency;
}

const LocalizedText& CurrencyUnitType::currency() const
{
  return mCurrency;
}

BuiltInTypeId CurrencyUnitType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ConfigurationUpdateTargetType
{
namespace
{
void encode(StackDepth limit, const ua::ConfigurationUpdateTargetType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.path());
  encoder.encode(limit, utils::as_int32(value.update_type()));
}

void encode(StackDepth limit, const ua::ConfigurationUpdateTargetType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Path", value.path());
  encoder.encode(limit, "UpdateType", utils::as_int32(value.update_type()));
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ConfigurationUpdateTargetType& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.path());
  decoder.decode(limit, enumVal);
  value.update_type() = utils::from_underlying<ConfigurationUpdateType>(enumVal);
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ConfigurationUpdateTargetType& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "Path", true, value.path());
  decoder.decode(limit, "UpdateType", true, enumVal);
  value.update_type() = utils::from_underlying<ConfigurationUpdateType>(enumVal);
}
}  // namespace
}  // namespace detail::ConfigurationUpdateTargetType

namespace detail::ConfigurationUpdateTargetType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ConfigurationUpdateTargetType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ConfigurationUpdateTargetType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ConfigurationUpdateTargetType

namespace detail::ConfigurationUpdateTargetType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ConfigurationUpdateTargetType>();
}
}  // namespace
}  // namespace detail::ConfigurationUpdateTargetType

bool ConfigurationUpdateTargetType::is_of_type(
  const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ConfigurationUpdateTargetType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ConfigurationUpdateTargetType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ConfigurationUpdateTargetType::type_name() const
{
  return typeName;
}

void ConfigurationUpdateTargetType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ConfigurationUpdateTargetType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ConfigurationUpdateTargetType::encode(limit, *this, *xml);
  }
}

void ConfigurationUpdateTargetType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ConfigurationUpdateTargetType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ConfigurationUpdateTargetType::encode_id(limit, ns, *xml);
  }
}

void ConfigurationUpdateTargetType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ConfigurationUpdateTargetType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ConfigurationUpdateTargetType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ConfigurationUpdateTargetType::clone() const
{
  return make_unique<ConfigurationUpdateTargetType>(*this);
}

void ConfigurationUpdateTargetType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "path=" + ua::to_string(path());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "update_type=" + ua::to_string(utils::as_int32(update_type()));
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "path=" + ua::to_string(path());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "update_type=" + ua::to_string(utils::as_int32(update_type()));
}

std::string ConfigurationUpdateTargetType::to_string(int indent) const
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

void ConfigurationUpdateTargetType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::ConfigurationUpdateTargetType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ConfigurationUpdateTargetType::create);
  }
}

String& ConfigurationUpdateTargetType::path()
{
  return mPath;
}

const String& ConfigurationUpdateTargetType::path() const
{
  return mPath;
}

ConfigurationUpdateType& ConfigurationUpdateTargetType::update_type()
{
  return mUpdateType;
}

const ConfigurationUpdateType& ConfigurationUpdateTargetType::update_type() const
{
  return mUpdateType;
}

BuiltInTypeId ConfigurationUpdateTargetType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ServiceCertificateDataType
{
namespace
{
void encode(StackDepth limit, const ua::ServiceCertificateDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.certificate());
  encoder.encode(limit, value.issuers());
  encoder.encode(limit, value.valid_from());
  encoder.encode(limit, value.valid_to());
}

void encode(StackDepth limit, const ua::ServiceCertificateDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Certificate", value.certificate());
  encoder.encode(limit, "Issuers", value.issuers());
  encoder.encode(limit, "ValidFrom", value.valid_from());
  encoder.encode(limit, "ValidTo", value.valid_to());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ServiceCertificateDataType& value)
{
  decoder.decode(limit, value.certificate());
  decoder.decode(limit, value.issuers());
  decoder.decode(limit, value.valid_from());
  decoder.decode(limit, value.valid_to());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ServiceCertificateDataType& value)
{
  decoder.decode(limit, "Certificate", true, value.certificate());
  decoder.decode(limit, "Issuers", true, value.issuers());
  decoder.decode(limit, "ValidFrom", true, value.valid_from());
  decoder.decode(limit, "ValidTo", true, value.valid_to());
}
}  // namespace
}  // namespace detail::ServiceCertificateDataType

namespace detail::ServiceCertificateDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ServiceCertificateDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ServiceCertificateDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ServiceCertificateDataType

namespace detail::ServiceCertificateDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ServiceCertificateDataType>();
}
}  // namespace
}  // namespace detail::ServiceCertificateDataType

bool ServiceCertificateDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ServiceCertificateDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ServiceCertificateDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ServiceCertificateDataType::type_name() const
{
  return typeName;
}

void ServiceCertificateDataType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ServiceCertificateDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ServiceCertificateDataType::encode(limit, *this, *xml);
  }
}

void ServiceCertificateDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ServiceCertificateDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ServiceCertificateDataType::encode_id(limit, ns, *xml);
  }
}

void ServiceCertificateDataType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ServiceCertificateDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ServiceCertificateDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ServiceCertificateDataType::clone() const
{
  return make_unique<ServiceCertificateDataType>(*this);
}

void ServiceCertificateDataType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "certificate=" + ua::to_string(certificate());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "issuers=" + ua::to_string(issuers());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "valid_from=" + ua::to_string(valid_from());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "valid_to=" + ua::to_string(valid_to());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "certificate=" + ua::to_string(certificate());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "issuers=" + ua::to_string(issuers());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "valid_from=" + ua::to_string(valid_from());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "valid_to=" + ua::to_string(valid_to());
}

std::string ServiceCertificateDataType::to_string(int indent) const
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

void ServiceCertificateDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::ServiceCertificateDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ServiceCertificateDataType::create);
  }
}

ByteString& ServiceCertificateDataType::certificate()
{
  return mCertificate;
}

const ByteString& ServiceCertificateDataType::certificate() const
{
  return mCertificate;
}

Array<ByteString>& ServiceCertificateDataType::issuers()
{
  return mIssuers;
}

const Array<ByteString>& ServiceCertificateDataType::issuers() const
{
  return mIssuers;
}

UtcTime& ServiceCertificateDataType::valid_from()
{
  return mValidFrom;
}

const UtcTime& ServiceCertificateDataType::valid_from() const
{
  return mValidFrom;
}

UtcTime& ServiceCertificateDataType::valid_to()
{
  return mValidTo;
}

const UtcTime& ServiceCertificateDataType::valid_to() const
{
  return mValidTo;
}

BuiltInTypeId ServiceCertificateDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::PortableQualifiedName
{
namespace
{
void encode(StackDepth limit, const ua::PortableQualifiedName& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.namespace_uri());
  encoder.encode(limit, value.name());
}

void encode(StackDepth limit, const ua::PortableQualifiedName& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "NamespaceUri", value.namespace_uri());
  encoder.encode(limit, "Name", value.name());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::PortableQualifiedName& value)
{
  decoder.decode(limit, value.namespace_uri());
  decoder.decode(limit, value.name());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::PortableQualifiedName& value)
{
  decoder.decode(limit, "NamespaceUri", true, value.namespace_uri());
  decoder.decode(limit, "Name", true, value.name());
}
}  // namespace
}  // namespace detail::PortableQualifiedName

namespace detail::PortableQualifiedName
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::PortableQualifiedName::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::PortableQualifiedName::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::PortableQualifiedName

namespace detail::PortableQualifiedName
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::PortableQualifiedName>();
}
}  // namespace
}  // namespace detail::PortableQualifiedName

bool PortableQualifiedName::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId PortableQualifiedName::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId PortableQualifiedName::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String PortableQualifiedName::type_name() const
{
  return typeName;
}

void PortableQualifiedName::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::PortableQualifiedName::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::PortableQualifiedName::encode(limit, *this, *xml);
  }
}

void PortableQualifiedName::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::PortableQualifiedName::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::PortableQualifiedName::encode_id(limit, ns, *xml);
  }
}

void PortableQualifiedName::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::PortableQualifiedName::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::PortableQualifiedName::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> PortableQualifiedName::clone() const
{
  return make_unique<PortableQualifiedName>(*this);
}

void PortableQualifiedName::append_fields(std::string& output, int indent) const
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
    output += pad + "name=" + ua::to_string(name());
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
  output += "name=" + ua::to_string(name());
}

std::string PortableQualifiedName::to_string(int indent) const
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

void PortableQualifiedName::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::PortableQualifiedName::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::PortableQualifiedName::create);
  }
}

String& PortableQualifiedName::namespace_uri()
{
  return mNamespaceUri;
}

const String& PortableQualifiedName::namespace_uri() const
{
  return mNamespaceUri;
}

String& PortableQualifiedName::name()
{
  return mName;
}

const String& PortableQualifiedName::name() const
{
  return mName;
}

BuiltInTypeId PortableQualifiedName::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::LldpTlvType
{
namespace
{
void encode(StackDepth limit, const ua::LldpTlvType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.tlv_type());
  encoder.encode(limit, value.tlv_info());
}

void encode(StackDepth limit, const ua::LldpTlvType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "TlvType", value.tlv_type());
  encoder.encode(limit, "TlvInfo", value.tlv_info());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::LldpTlvType& value)
{
  decoder.decode(limit, value.tlv_type());
  decoder.decode(limit, value.tlv_info());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::LldpTlvType& value)
{
  decoder.decode(limit, "TlvType", true, value.tlv_type());
  decoder.decode(limit, "TlvInfo", true, value.tlv_info());
}
}  // namespace
}  // namespace detail::LldpTlvType

namespace detail::LldpTlvType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::LldpTlvType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::LldpTlvType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::LldpTlvType

namespace detail::LldpTlvType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::LldpTlvType>();
}
}  // namespace
}  // namespace detail::LldpTlvType

bool LldpTlvType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId LldpTlvType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId LldpTlvType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String LldpTlvType::type_name() const
{
  return typeName;
}

void LldpTlvType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::LldpTlvType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::LldpTlvType::encode(limit, *this, *xml);
  }
}

void LldpTlvType::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::LldpTlvType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::LldpTlvType::encode_id(limit, ns, *xml);
  }
}

void LldpTlvType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::LldpTlvType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::LldpTlvType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> LldpTlvType::clone() const
{
  return make_unique<LldpTlvType>(*this);
}

void LldpTlvType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "tlv_type=" + ua::to_string(tlv_type());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "tlv_info=" + ua::to_string(tlv_info());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "tlv_type=" + ua::to_string(tlv_type());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "tlv_info=" + ua::to_string(tlv_info());
}

std::string LldpTlvType::to_string(int indent) const
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

void LldpTlvType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::LldpTlvType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::LldpTlvType::create);
  }
}

uint32_t& LldpTlvType::tlv_type()
{
  return mTlvType;
}

const uint32_t& LldpTlvType::tlv_type() const
{
  return mTlvType;
}

ByteString& LldpTlvType::tlv_info()
{
  return mTlvInfo;
}

const ByteString& LldpTlvType::tlv_info() const
{
  return mTlvInfo;
}

BuiltInTypeId LldpTlvType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::RolePermissionType
{
namespace
{
void encode(StackDepth limit, const ua::RolePermissionType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.role_id());
  encoder.encode(limit, value.permissions().as_underlying_type());
}

void encode(StackDepth limit, const ua::RolePermissionType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RoleId", value.role_id());
  encoder.encode(limit, "Permissions", value.permissions().as_underlying_type());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::RolePermissionType& value)
{
  decoder.decode(limit, value.role_id());
  {
    PermissionType::UnderlyingType val{};
    decoder.decode(limit, val);
    value.permissions().from_underlying_type(val);
  }
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::RolePermissionType& value)
{
  decoder.decode(limit, "RoleId", true, value.role_id());
  {
    PermissionType::UnderlyingType val{};
    decoder.decode(limit, "Permissions", true, val);
    value.permissions().from_underlying_type(val);
  }
}
}  // namespace
}  // namespace detail::RolePermissionType

namespace detail::RolePermissionType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::RolePermissionType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::RolePermissionType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::RolePermissionType

namespace detail::RolePermissionType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::RolePermissionType>();
}
}  // namespace
}  // namespace detail::RolePermissionType

bool RolePermissionType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId RolePermissionType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId RolePermissionType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String RolePermissionType::type_name() const
{
  return typeName;
}

void RolePermissionType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RolePermissionType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RolePermissionType::encode(limit, *this, *xml);
  }
}

void RolePermissionType::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RolePermissionType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RolePermissionType::encode_id(limit, ns, *xml);
  }
}

void RolePermissionType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::RolePermissionType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::RolePermissionType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> RolePermissionType::clone() const
{
  return make_unique<RolePermissionType>(*this);
}

void RolePermissionType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "role_id=" + ua::to_string(role_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "permissions=" + ua::to_string(permissions().as_underlying_type());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "role_id=" + ua::to_string(role_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "permissions=" + ua::to_string(permissions().as_underlying_type());
}

std::string RolePermissionType::to_string(int indent) const
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

void RolePermissionType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::RolePermissionType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::RolePermissionType::create);
  }
}

NodeId& RolePermissionType::role_id()
{
  return mRoleId;
}

const NodeId& RolePermissionType::role_id() const
{
  return mRoleId;
}

PermissionType& RolePermissionType::permissions()
{
  return mPermissions;
}

const PermissionType& RolePermissionType::permissions() const
{
  return mPermissions;
}

BuiltInTypeId RolePermissionType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::OptionSet
{
namespace
{
void encode(StackDepth limit, const ua::OptionSet& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.value());
  encoder.encode(limit, value.valid_bits());
}

void encode(StackDepth limit, const ua::OptionSet& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Value", value.value());
  encoder.encode(limit, "ValidBits", value.valid_bits());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::OptionSet& value)
{
  decoder.decode(limit, value.value());
  decoder.decode(limit, value.valid_bits());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::OptionSet& value)
{
  decoder.decode(limit, "Value", true, value.value());
  decoder.decode(limit, "ValidBits", true, value.valid_bits());
}
}  // namespace
}  // namespace detail::OptionSet

bool OptionSet::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId OptionSet::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId OptionSet::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String OptionSet::type_name() const
{
  return typeName;
}

void OptionSet::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::OptionSet::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::OptionSet::encode(limit, *this, *xml);
  }
}

void OptionSet::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  UA_UNUSED(limit);
  UA_UNUSED(ns);
  UA_UNUSED(encoder);
}

void OptionSet::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::OptionSet::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::OptionSet::decode(limit, *xml, *this);
  }
}

void OptionSet::append_fields(std::string& output, int indent) const
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
    output += pad + "valid_bits=" + ua::to_string(valid_bits());
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
  output += "valid_bits=" + ua::to_string(valid_bits());
}

ByteString& OptionSet::value()
{
  return mValue;
}

const ByteString& OptionSet::value() const
{
  return mValue;
}

ByteString& OptionSet::valid_bits()
{
  return mValidBits;
}

const ByteString& OptionSet::valid_bits() const
{
  return mValidBits;
}

BuiltInTypeId OptionSet::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::MdnsDiscoveryConfiguration
{
namespace
{
void encode(StackDepth limit, const ua::MdnsDiscoveryConfiguration& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.mdns_server_name());
  encoder.encode(limit, value.server_capabilities());
}

void encode(StackDepth limit, const ua::MdnsDiscoveryConfiguration& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "MdnsServerName", value.mdns_server_name());
  encoder.encode(limit, "ServerCapabilities", value.server_capabilities());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::MdnsDiscoveryConfiguration& value)
{
  decoder.decode(limit, value.mdns_server_name());
  decoder.decode(limit, value.server_capabilities());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::MdnsDiscoveryConfiguration& value)
{
  decoder.decode(limit, "MdnsServerName", true, value.mdns_server_name());
  decoder.decode(limit, "ServerCapabilities", true, value.server_capabilities());
}
}  // namespace
}  // namespace detail::MdnsDiscoveryConfiguration

namespace detail::MdnsDiscoveryConfiguration
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::MdnsDiscoveryConfiguration::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::MdnsDiscoveryConfiguration::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::MdnsDiscoveryConfiguration

namespace detail::MdnsDiscoveryConfiguration
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::MdnsDiscoveryConfiguration>();
}
}  // namespace
}  // namespace detail::MdnsDiscoveryConfiguration

bool MdnsDiscoveryConfiguration::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return DiscoveryConfiguration::is_of_type(ns, dataTypeId);
}

NodeId MdnsDiscoveryConfiguration::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId MdnsDiscoveryConfiguration::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String MdnsDiscoveryConfiguration::type_name() const
{
  return typeName;
}

void MdnsDiscoveryConfiguration::encode(StackDepth limit, Encoder& encoder) const
{

  DiscoveryConfiguration::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::MdnsDiscoveryConfiguration::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::MdnsDiscoveryConfiguration::encode(limit, *this, *xml);
  }
}

void MdnsDiscoveryConfiguration::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::MdnsDiscoveryConfiguration::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::MdnsDiscoveryConfiguration::encode_id(limit, ns, *xml);
  }
}

void MdnsDiscoveryConfiguration::decode(StackDepth limit, Decoder& decoder)
{

  DiscoveryConfiguration::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::MdnsDiscoveryConfiguration::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::MdnsDiscoveryConfiguration::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> MdnsDiscoveryConfiguration::clone() const
{
  return make_unique<MdnsDiscoveryConfiguration>(*this);
}

void MdnsDiscoveryConfiguration::append_fields(std::string& output, int indent) const
{
  DiscoveryConfiguration::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "mdns_server_name=" + ua::to_string(mdns_server_name());
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
  output += "mdns_server_name=" + ua::to_string(mdns_server_name());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "server_capabilities=" + ua::to_string(server_capabilities());
}

std::string MdnsDiscoveryConfiguration::to_string(int indent) const
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

void MdnsDiscoveryConfiguration::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::MdnsDiscoveryConfiguration::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::MdnsDiscoveryConfiguration::create);
  }
}

String& MdnsDiscoveryConfiguration::mdns_server_name()
{
  return mMdnsServerName;
}

const String& MdnsDiscoveryConfiguration::mdns_server_name() const
{
  return mMdnsServerName;
}

Array<String>& MdnsDiscoveryConfiguration::server_capabilities()
{
  return mServerCapabilities;
}

const Array<String>& MdnsDiscoveryConfiguration::server_capabilities() const
{
  return mServerCapabilities;
}

BuiltInTypeId MdnsDiscoveryConfiguration::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::AddReferencesItem
{
namespace
{
void encode(StackDepth limit, const ua::AddReferencesItem& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.source_node_id());
  encoder.encode(limit, value.reference_type_id());
  encoder.encode(limit, value.is_forward());
  encoder.encode(limit, value.target_server_uri());
  encoder.encode(limit, value.target_node_id());
  encoder.encode(limit, utils::as_int32(value.target_node_class()));
}

void encode(StackDepth limit, const ua::AddReferencesItem& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "SourceNodeId", value.source_node_id());
  encoder.encode(limit, "ReferenceTypeId", value.reference_type_id());
  encoder.encode(limit, "IsForward", value.is_forward());
  encoder.encode(limit, "TargetServerUri", value.target_server_uri());
  encoder.encode(limit, "TargetNodeId", value.target_node_id());
  encoder.encode(limit, "TargetNodeClass", utils::as_int32(value.target_node_class()));
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::AddReferencesItem& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.source_node_id());
  decoder.decode(limit, value.reference_type_id());
  decoder.decode(limit, value.is_forward());
  decoder.decode(limit, value.target_server_uri());
  decoder.decode(limit, value.target_node_id());
  decoder.decode(limit, enumVal);
  value.target_node_class() = utils::from_underlying<NodeClass>(enumVal);
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::AddReferencesItem& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "SourceNodeId", true, value.source_node_id());
  decoder.decode(limit, "ReferenceTypeId", true, value.reference_type_id());
  decoder.decode(limit, "IsForward", true, value.is_forward());
  decoder.decode(limit, "TargetServerUri", true, value.target_server_uri());
  decoder.decode(limit, "TargetNodeId", true, value.target_node_id());
  decoder.decode(limit, "TargetNodeClass", true, enumVal);
  value.target_node_class() = utils::from_underlying<NodeClass>(enumVal);
}
}  // namespace
}  // namespace detail::AddReferencesItem

namespace detail::AddReferencesItem
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::AddReferencesItem::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::AddReferencesItem::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::AddReferencesItem

namespace detail::AddReferencesItem
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::AddReferencesItem>();
}
}  // namespace
}  // namespace detail::AddReferencesItem

bool AddReferencesItem::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId AddReferencesItem::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId AddReferencesItem::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String AddReferencesItem::type_name() const
{
  return typeName;
}

void AddReferencesItem::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AddReferencesItem::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AddReferencesItem::encode(limit, *this, *xml);
  }
}

void AddReferencesItem::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AddReferencesItem::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AddReferencesItem::encode_id(limit, ns, *xml);
  }
}

void AddReferencesItem::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::AddReferencesItem::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::AddReferencesItem::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> AddReferencesItem::clone() const
{
  return make_unique<AddReferencesItem>(*this);
}

void AddReferencesItem::append_fields(std::string& output, int indent) const
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
    output += pad + "target_server_uri=" + ua::to_string(target_server_uri());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "target_node_id=" + ua::to_string(target_node_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "target_node_class=" + ua::to_string(utils::as_int32(target_node_class()));
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
  output += "target_server_uri=" + ua::to_string(target_server_uri());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "target_node_id=" + ua::to_string(target_node_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "target_node_class=" + ua::to_string(utils::as_int32(target_node_class()));
}

std::string AddReferencesItem::to_string(int indent) const
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

void AddReferencesItem::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::AddReferencesItem::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::AddReferencesItem::create);
  }
}

NodeId& AddReferencesItem::source_node_id()
{
  return mSourceNodeId;
}

const NodeId& AddReferencesItem::source_node_id() const
{
  return mSourceNodeId;
}

NodeId& AddReferencesItem::reference_type_id()
{
  return mReferenceTypeId;
}

const NodeId& AddReferencesItem::reference_type_id() const
{
  return mReferenceTypeId;
}

bool& AddReferencesItem::is_forward()
{
  return mIsForward;
}

const bool& AddReferencesItem::is_forward() const
{
  return mIsForward;
}

String& AddReferencesItem::target_server_uri()
{
  return mTargetServerUri;
}

const String& AddReferencesItem::target_server_uri() const
{
  return mTargetServerUri;
}

ExpandedNodeId& AddReferencesItem::target_node_id()
{
  return mTargetNodeId;
}

const ExpandedNodeId& AddReferencesItem::target_node_id() const
{
  return mTargetNodeId;
}

NodeClass& AddReferencesItem::target_node_class()
{
  return mTargetNodeClass;
}

const NodeClass& AddReferencesItem::target_node_class() const
{
  return mTargetNodeClass;
}

BuiltInTypeId AddReferencesItem::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

bool FilterOperand::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId FilterOperand::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId FilterOperand::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String FilterOperand::type_name() const
{
  return typeName;
}

void FilterOperand::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);
}

void FilterOperand::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  UA_UNUSED(limit);
  UA_UNUSED(ns);
  UA_UNUSED(encoder);
}

void FilterOperand::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);
}

BuiltInTypeId FilterOperand::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::MonitoringFilter
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::MonitoringFilter::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::MonitoringFilter::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::MonitoringFilter

namespace detail::MonitoringFilter
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::MonitoringFilter>();
}
}  // namespace
}  // namespace detail::MonitoringFilter

bool MonitoringFilter::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId MonitoringFilter::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId MonitoringFilter::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String MonitoringFilter::type_name() const
{
  return typeName;
}

void MonitoringFilter::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);
}

void MonitoringFilter::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::MonitoringFilter::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::MonitoringFilter::encode_id(limit, ns, *xml);
  }
}

void MonitoringFilter::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);
}

unique_ptr<Structure> MonitoringFilter::clone() const
{
  return make_unique<MonitoringFilter>(*this);
}

std::string MonitoringFilter::to_string(int indent) const
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

void MonitoringFilter::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::MonitoringFilter::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::MonitoringFilter::create);
  }
}

BuiltInTypeId MonitoringFilter::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::SamplingIntervalDiagnosticsDataType
{
namespace
{
void encode(StackDepth limit, const ua::SamplingIntervalDiagnosticsDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.sampling_interval());
  encoder.encode(limit, value.monitored_item_count());
  encoder.encode(limit, value.max_monitored_item_count());
  encoder.encode(limit, value.disabled_monitored_item_count());
}

void encode(StackDepth limit, const ua::SamplingIntervalDiagnosticsDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "SamplingInterval", value.sampling_interval());
  encoder.encode(limit, "MonitoredItemCount", value.monitored_item_count());
  encoder.encode(limit, "MaxMonitoredItemCount", value.max_monitored_item_count());
  encoder.encode(limit, "DisabledMonitoredItemCount", value.disabled_monitored_item_count());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::SamplingIntervalDiagnosticsDataType& value)
{
  decoder.decode(limit, value.sampling_interval());
  decoder.decode(limit, value.monitored_item_count());
  decoder.decode(limit, value.max_monitored_item_count());
  decoder.decode(limit, value.disabled_monitored_item_count());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::SamplingIntervalDiagnosticsDataType& value)
{
  decoder.decode(limit, "SamplingInterval", true, value.sampling_interval());
  decoder.decode(limit, "MonitoredItemCount", true, value.monitored_item_count());
  decoder.decode(limit, "MaxMonitoredItemCount", true, value.max_monitored_item_count());
  decoder.decode(limit, "DisabledMonitoredItemCount", true, value.disabled_monitored_item_count());
}
}  // namespace
}  // namespace detail::SamplingIntervalDiagnosticsDataType

namespace detail::SamplingIntervalDiagnosticsDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::SamplingIntervalDiagnosticsDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::SamplingIntervalDiagnosticsDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::SamplingIntervalDiagnosticsDataType

namespace detail::SamplingIntervalDiagnosticsDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::SamplingIntervalDiagnosticsDataType>();
}
}  // namespace
}  // namespace detail::SamplingIntervalDiagnosticsDataType

bool SamplingIntervalDiagnosticsDataType::is_of_type(
  const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId SamplingIntervalDiagnosticsDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId SamplingIntervalDiagnosticsDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String SamplingIntervalDiagnosticsDataType::type_name() const
{
  return typeName;
}

void SamplingIntervalDiagnosticsDataType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SamplingIntervalDiagnosticsDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SamplingIntervalDiagnosticsDataType::encode(limit, *this, *xml);
  }
}

void SamplingIntervalDiagnosticsDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SamplingIntervalDiagnosticsDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SamplingIntervalDiagnosticsDataType::encode_id(limit, ns, *xml);
  }
}

void SamplingIntervalDiagnosticsDataType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::SamplingIntervalDiagnosticsDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::SamplingIntervalDiagnosticsDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> SamplingIntervalDiagnosticsDataType::clone() const
{
  return make_unique<SamplingIntervalDiagnosticsDataType>(*this);
}

void SamplingIntervalDiagnosticsDataType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "sampling_interval=" + ua::to_string(sampling_interval());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "monitored_item_count=" + ua::to_string(monitored_item_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "max_monitored_item_count=" + ua::to_string(max_monitored_item_count());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "disabled_monitored_item_count=" + ua::to_string(disabled_monitored_item_count());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "sampling_interval=" + ua::to_string(sampling_interval());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "monitored_item_count=" + ua::to_string(monitored_item_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "max_monitored_item_count=" + ua::to_string(max_monitored_item_count());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "disabled_monitored_item_count=" + ua::to_string(disabled_monitored_item_count());
}

std::string SamplingIntervalDiagnosticsDataType::to_string(int indent) const
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

void SamplingIntervalDiagnosticsDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::SamplingIntervalDiagnosticsDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(
      NodeId(defaultXmlEncodingId), detail::SamplingIntervalDiagnosticsDataType::create);
  }
}

Duration& SamplingIntervalDiagnosticsDataType::sampling_interval()
{
  return mSamplingInterval;
}

const Duration& SamplingIntervalDiagnosticsDataType::sampling_interval() const
{
  return mSamplingInterval;
}

uint32_t& SamplingIntervalDiagnosticsDataType::monitored_item_count()
{
  return mMonitoredItemCount;
}

const uint32_t& SamplingIntervalDiagnosticsDataType::monitored_item_count() const
{
  return mMonitoredItemCount;
}

uint32_t& SamplingIntervalDiagnosticsDataType::max_monitored_item_count()
{
  return mMaxMonitoredItemCount;
}

const uint32_t& SamplingIntervalDiagnosticsDataType::max_monitored_item_count() const
{
  return mMaxMonitoredItemCount;
}

uint32_t& SamplingIntervalDiagnosticsDataType::disabled_monitored_item_count()
{
  return mDisabledMonitoredItemCount;
}

const uint32_t& SamplingIntervalDiagnosticsDataType::disabled_monitored_item_count() const
{
  return mDisabledMonitoredItemCount;
}

BuiltInTypeId SamplingIntervalDiagnosticsDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ModelChangeStructureDataType
{
namespace
{
void encode(StackDepth limit, const ua::ModelChangeStructureDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.affected());
  encoder.encode(limit, value.affected_type());
  encoder.encode(limit, value.verb());
}

void encode(StackDepth limit, const ua::ModelChangeStructureDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Affected", value.affected());
  encoder.encode(limit, "AffectedType", value.affected_type());
  encoder.encode(limit, "Verb", value.verb());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ModelChangeStructureDataType& value)
{
  decoder.decode(limit, value.affected());
  decoder.decode(limit, value.affected_type());
  decoder.decode(limit, value.verb());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ModelChangeStructureDataType& value)
{
  decoder.decode(limit, "Affected", true, value.affected());
  decoder.decode(limit, "AffectedType", true, value.affected_type());
  decoder.decode(limit, "Verb", true, value.verb());
}
}  // namespace
}  // namespace detail::ModelChangeStructureDataType

namespace detail::ModelChangeStructureDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ModelChangeStructureDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ModelChangeStructureDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ModelChangeStructureDataType

namespace detail::ModelChangeStructureDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ModelChangeStructureDataType>();
}
}  // namespace
}  // namespace detail::ModelChangeStructureDataType

bool ModelChangeStructureDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ModelChangeStructureDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ModelChangeStructureDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ModelChangeStructureDataType::type_name() const
{
  return typeName;
}

void ModelChangeStructureDataType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ModelChangeStructureDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ModelChangeStructureDataType::encode(limit, *this, *xml);
  }
}

void ModelChangeStructureDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ModelChangeStructureDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ModelChangeStructureDataType::encode_id(limit, ns, *xml);
  }
}

void ModelChangeStructureDataType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ModelChangeStructureDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ModelChangeStructureDataType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ModelChangeStructureDataType::clone() const
{
  return make_unique<ModelChangeStructureDataType>(*this);
}

void ModelChangeStructureDataType::append_fields(std::string& output, int indent) const
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
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "verb=" + ua::to_string(verb());
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
  if (!output.empty())
  {
    output += ", ";
  }
  output += "verb=" + ua::to_string(verb());
}

std::string ModelChangeStructureDataType::to_string(int indent) const
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

void ModelChangeStructureDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::ModelChangeStructureDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ModelChangeStructureDataType::create);
  }
}

NodeId& ModelChangeStructureDataType::affected()
{
  return mAffected;
}

const NodeId& ModelChangeStructureDataType::affected() const
{
  return mAffected;
}

NodeId& ModelChangeStructureDataType::affected_type()
{
  return mAffectedType;
}

const NodeId& ModelChangeStructureDataType::affected_type() const
{
  return mAffectedType;
}

uint8_t& ModelChangeStructureDataType::verb()
{
  return mVerb;
}

const uint8_t& ModelChangeStructureDataType::verb() const
{
  return mVerb;
}

BuiltInTypeId ModelChangeStructureDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ProgramDiagnosticDataType
{
namespace
{
void encode(StackDepth limit, const ua::ProgramDiagnosticDataType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.create_session_id());
  encoder.encode(limit, value.create_client_name());
  encoder.encode(limit, value.invocation_creation_time());
  encoder.encode(limit, value.last_transition_time());
  encoder.encode(limit, value.last_method_call());
  encoder.encode(limit, value.last_method_session_id());
  encoder.encode(limit, value.last_method_input_arguments());
  encoder.encode(limit, value.last_method_output_arguments());
  encoder.encode(limit, value.last_method_call_time());
  encoder.encode(limit, value.last_method_return_status());
}

void encode(StackDepth limit, const ua::ProgramDiagnosticDataType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "CreateSessionId", value.create_session_id());
  encoder.encode(limit, "CreateClientName", value.create_client_name());
  encoder.encode(limit, "InvocationCreationTime", value.invocation_creation_time());
  encoder.encode(limit, "LastTransitionTime", value.last_transition_time());
  encoder.encode(limit, "LastMethodCall", value.last_method_call());
  encoder.encode(limit, "LastMethodSessionId", value.last_method_session_id());
  encoder.encode(limit, "LastMethodInputArguments", value.last_method_input_arguments());
  encoder.encode(limit, "LastMethodOutputArguments", value.last_method_output_arguments());
  encoder.encode(limit, "LastMethodCallTime", value.last_method_call_time());
  encoder.encode(limit, "LastMethodReturnStatus", value.last_method_return_status());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ProgramDiagnosticDataType& value)
{
  decoder.decode(limit, value.create_session_id());
  decoder.decode(limit, value.create_client_name());
  decoder.decode(limit, value.invocation_creation_time());
  decoder.decode(limit, value.last_transition_time());
  decoder.decode(limit, value.last_method_call());
  decoder.decode(limit, value.last_method_session_id());
  decoder.decode(limit, value.last_method_input_arguments());
  decoder.decode(limit, value.last_method_output_arguments());
  decoder.decode(limit, value.last_method_call_time());
  decoder.decode(limit, value.last_method_return_status());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ProgramDiagnosticDataType& value)
{
  decoder.decode(limit, "CreateSessionId", true, value.create_session_id());
  decoder.decode(limit, "CreateClientName", true, value.create_client_name());
  decoder.decode(limit, "InvocationCreationTime", true, value.invocation_creation_time());
  decoder.decode(limit, "LastTransitionTime", true, value.last_transition_time());
  decoder.decode(limit, "LastMethodCall", true, value.last_method_call());
  decoder.decode(limit, "LastMethodSessionId", true, value.last_method_session_id());
  decoder.decode(limit, "LastMethodInputArguments", true, value.last_method_input_arguments());
  decoder.decode(limit, "LastMethodOutputArguments", true, value.last_method_output_arguments());
  decoder.decode(limit, "LastMethodCallTime", true, value.last_method_call_time());
  decoder.decode(limit, "LastMethodReturnStatus", true, value.last_method_return_status());
}
}  // namespace
}  // namespace detail::ProgramDiagnosticDataType

namespace detail::ProgramDiagnosticDataType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ProgramDiagnosticDataType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ProgramDiagnosticDataType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ProgramDiagnosticDataType

namespace detail::ProgramDiagnosticDataType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ProgramDiagnosticDataType>();
}
}  // namespace
}  // namespace detail::ProgramDiagnosticDataType

bool ProgramDiagnosticDataType::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ProgramDiagnosticDataType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ProgramDiagnosticDataType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ProgramDiagnosticDataType::type_name() const
{
  return typeName;
}

void ProgramDiagnosticDataType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ProgramDiagnosticDataType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ProgramDiagnosticDataType::encode(limit, *this, *xml);
  }
}

void ProgramDiagnosticDataType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ProgramDiagnosticDataType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ProgramDiagnosticDataType::encode_id(limit, ns, *xml);
  }
}

void ProgramDiagnosticDataType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ProgramDiagnosticDataType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ProgramDiagnosticDataType::decode(limit, *xml, *this);
  }
}

void ProgramDiagnosticDataType::resolve(span<const LocaleId> locales)
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

unique_ptr<Structure> ProgramDiagnosticDataType::clone() const
{
  return make_unique<ProgramDiagnosticDataType>(*this);
}

void ProgramDiagnosticDataType::append_fields(std::string& output, int indent) const
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
  output += "last_method_call_time=" + ua::to_string(last_method_call_time());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "last_method_return_status=" + ua::to_string(last_method_return_status());
}

std::string ProgramDiagnosticDataType::to_string(int indent) const
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

void ProgramDiagnosticDataType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::ProgramDiagnosticDataType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ProgramDiagnosticDataType::create);
  }
}

NodeId& ProgramDiagnosticDataType::create_session_id()
{
  return mCreateSessionId;
}

const NodeId& ProgramDiagnosticDataType::create_session_id() const
{
  return mCreateSessionId;
}

String& ProgramDiagnosticDataType::create_client_name()
{
  return mCreateClientName;
}

const String& ProgramDiagnosticDataType::create_client_name() const
{
  return mCreateClientName;
}

UtcTime& ProgramDiagnosticDataType::invocation_creation_time()
{
  return mInvocationCreationTime;
}

const UtcTime& ProgramDiagnosticDataType::invocation_creation_time() const
{
  return mInvocationCreationTime;
}

UtcTime& ProgramDiagnosticDataType::last_transition_time()
{
  return mLastTransitionTime;
}

const UtcTime& ProgramDiagnosticDataType::last_transition_time() const
{
  return mLastTransitionTime;
}

String& ProgramDiagnosticDataType::last_method_call()
{
  return mLastMethodCall;
}

const String& ProgramDiagnosticDataType::last_method_call() const
{
  return mLastMethodCall;
}

NodeId& ProgramDiagnosticDataType::last_method_session_id()
{
  return mLastMethodSessionId;
}

const NodeId& ProgramDiagnosticDataType::last_method_session_id() const
{
  return mLastMethodSessionId;
}

Array<Argument>& ProgramDiagnosticDataType::last_method_input_arguments()
{
  return mLastMethodInputArguments;
}

const Array<Argument>& ProgramDiagnosticDataType::last_method_input_arguments() const
{
  return mLastMethodInputArguments;
}

Array<Argument>& ProgramDiagnosticDataType::last_method_output_arguments()
{
  return mLastMethodOutputArguments;
}

const Array<Argument>& ProgramDiagnosticDataType::last_method_output_arguments() const
{
  return mLastMethodOutputArguments;
}

UtcTime& ProgramDiagnosticDataType::last_method_call_time()
{
  return mLastMethodCallTime;
}

const UtcTime& ProgramDiagnosticDataType::last_method_call_time() const
{
  return mLastMethodCallTime;
}

StatusResult& ProgramDiagnosticDataType::last_method_return_status()
{
  return mLastMethodReturnStatus;
}

const StatusResult& ProgramDiagnosticDataType::last_method_return_status() const
{
  return mLastMethodReturnStatus;
}

BuiltInTypeId ProgramDiagnosticDataType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::SessionlessInvokeResponseType
{
namespace
{
void encode(StackDepth limit, const ua::SessionlessInvokeResponseType& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.namespace_uris());
  encoder.encode(limit, value.server_uris());
  encoder.encode(limit, value.service_id());
}

void encode(StackDepth limit, const ua::SessionlessInvokeResponseType& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "NamespaceUris", value.namespace_uris());
  encoder.encode(limit, "ServerUris", value.server_uris());
  encoder.encode(limit, "ServiceId", value.service_id());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::SessionlessInvokeResponseType& value)
{
  decoder.decode(limit, value.namespace_uris());
  decoder.decode(limit, value.server_uris());
  decoder.decode(limit, value.service_id());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::SessionlessInvokeResponseType& value)
{
  decoder.decode(limit, "NamespaceUris", true, value.namespace_uris());
  decoder.decode(limit, "ServerUris", true, value.server_uris());
  decoder.decode(limit, "ServiceId", true, value.service_id());
}
}  // namespace
}  // namespace detail::SessionlessInvokeResponseType

namespace detail::SessionlessInvokeResponseType
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::SessionlessInvokeResponseType::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::SessionlessInvokeResponseType::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::SessionlessInvokeResponseType

namespace detail::SessionlessInvokeResponseType
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::SessionlessInvokeResponseType>();
}
}  // namespace
}  // namespace detail::SessionlessInvokeResponseType

bool SessionlessInvokeResponseType::is_of_type(
  const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId SessionlessInvokeResponseType::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId SessionlessInvokeResponseType::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String SessionlessInvokeResponseType::type_name() const
{
  return typeName;
}

void SessionlessInvokeResponseType::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SessionlessInvokeResponseType::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SessionlessInvokeResponseType::encode(limit, *this, *xml);
  }
}

void SessionlessInvokeResponseType::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SessionlessInvokeResponseType::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SessionlessInvokeResponseType::encode_id(limit, ns, *xml);
  }
}

void SessionlessInvokeResponseType::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::SessionlessInvokeResponseType::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::SessionlessInvokeResponseType::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> SessionlessInvokeResponseType::clone() const
{
  return make_unique<SessionlessInvokeResponseType>(*this);
}

void SessionlessInvokeResponseType::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
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
    output += pad + "service_id=" + ua::to_string(service_id());
    return;
  }
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
  output += "service_id=" + ua::to_string(service_id());
}

std::string SessionlessInvokeResponseType::to_string(int indent) const
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

void SessionlessInvokeResponseType::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::SessionlessInvokeResponseType::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::SessionlessInvokeResponseType::create);
  }
}

Array<String>& SessionlessInvokeResponseType::namespace_uris()
{
  return mNamespaceUris;
}

const Array<String>& SessionlessInvokeResponseType::namespace_uris() const
{
  return mNamespaceUris;
}

Array<String>& SessionlessInvokeResponseType::server_uris()
{
  return mServerUris;
}

const Array<String>& SessionlessInvokeResponseType::server_uris() const
{
  return mServerUris;
}

uint32_t& SessionlessInvokeResponseType::service_id()
{
  return mServiceId;
}

const uint32_t& SessionlessInvokeResponseType::service_id() const
{
  return mServiceId;
}

BuiltInTypeId SessionlessInvokeResponseType::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::RegisterServerResponse
{
namespace
{
void encode(StackDepth limit, const ua::RegisterServerResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
}

void encode(StackDepth limit, const ua::RegisterServerResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::RegisterServerResponse& value)
{
  decoder.decode(limit, value.response_header());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::RegisterServerResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
}
}  // namespace
}  // namespace detail::RegisterServerResponse

namespace detail::RegisterServerResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::RegisterServerResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::RegisterServerResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::RegisterServerResponse

namespace detail::RegisterServerResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::RegisterServerResponse>();
}
}  // namespace
}  // namespace detail::RegisterServerResponse

bool RegisterServerResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId RegisterServerResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId RegisterServerResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String RegisterServerResponse::type_name() const
{
  return typeName;
}

void RegisterServerResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RegisterServerResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RegisterServerResponse::encode(limit, *this, *xml);
  }
}

void RegisterServerResponse::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RegisterServerResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RegisterServerResponse::encode_id(limit, ns, *xml);
  }
}

void RegisterServerResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::RegisterServerResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::RegisterServerResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> RegisterServerResponse::clone() const
{
  return make_unique<RegisterServerResponse>(*this);
}

void RegisterServerResponse::append_fields(std::string& output, int indent) const
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

std::string RegisterServerResponse::to_string(int indent) const
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

void RegisterServerResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::RegisterServerResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::RegisterServerResponse::create);
  }
}

ResponseHeader& RegisterServerResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& RegisterServerResponse::response_header() const
{
  return mResponseHeader;
}

BuiltInTypeId RegisterServerResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::SignatureData
{
namespace
{
void encode(StackDepth limit, const ua::SignatureData& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.algorithm());
  encoder.encode(limit, value.signature());
}

void encode(StackDepth limit, const ua::SignatureData& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "Algorithm", value.algorithm());
  encoder.encode(limit, "Signature", value.signature());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::SignatureData& value)
{
  decoder.decode(limit, value.algorithm());
  decoder.decode(limit, value.signature());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::SignatureData& value)
{
  decoder.decode(limit, "Algorithm", true, value.algorithm());
  decoder.decode(limit, "Signature", true, value.signature());
}
}  // namespace
}  // namespace detail::SignatureData

namespace detail::SignatureData
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::SignatureData::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::SignatureData::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::SignatureData

namespace detail::SignatureData
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::SignatureData>();
}
}  // namespace
}  // namespace detail::SignatureData

bool SignatureData::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId SignatureData::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId SignatureData::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String SignatureData::type_name() const
{
  return typeName;
}

void SignatureData::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SignatureData::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SignatureData::encode(limit, *this, *xml);
  }
}

void SignatureData::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::SignatureData::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::SignatureData::encode_id(limit, ns, *xml);
  }
}

void SignatureData::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::SignatureData::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::SignatureData::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> SignatureData::clone() const
{
  return make_unique<SignatureData>(*this);
}

void SignatureData::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "algorithm=" + ua::to_string(algorithm());
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
  output += "algorithm=" + ua::to_string(algorithm());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "signature=" + ua::to_string(signature());
}

std::string SignatureData::to_string(int indent) const
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

void SignatureData::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::SignatureData::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::SignatureData::create);
  }
}

String& SignatureData::algorithm()
{
  return mAlgorithm;
}

const String& SignatureData::algorithm() const
{
  return mAlgorithm;
}

ByteString& SignatureData::signature()
{
  return mSignature;
}

const ByteString& SignatureData::signature() const
{
  return mSignature;
}

BuiltInTypeId SignatureData::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::CancelResponse
{
namespace
{
void encode(StackDepth limit, const ua::CancelResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.cancel_count());
}

void encode(StackDepth limit, const ua::CancelResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "CancelCount", value.cancel_count());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::CancelResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.cancel_count());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::CancelResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "CancelCount", true, value.cancel_count());
}
}  // namespace
}  // namespace detail::CancelResponse

namespace detail::CancelResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::CancelResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::CancelResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::CancelResponse

namespace detail::CancelResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::CancelResponse>();
}
}  // namespace
}  // namespace detail::CancelResponse

bool CancelResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId CancelResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId CancelResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String CancelResponse::type_name() const
{
  return typeName;
}

void CancelResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CancelResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CancelResponse::encode(limit, *this, *xml);
  }
}

void CancelResponse::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CancelResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CancelResponse::encode_id(limit, ns, *xml);
  }
}

void CancelResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::CancelResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::CancelResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> CancelResponse::clone() const
{
  return make_unique<CancelResponse>(*this);
}

void CancelResponse::append_fields(std::string& output, int indent) const
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
    output += pad + "cancel_count=" + ua::to_string(cancel_count());
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
  output += "cancel_count=" + ua::to_string(cancel_count());
}

std::string CancelResponse::to_string(int indent) const
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

void CancelResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::CancelResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::CancelResponse::create);
  }
}

ResponseHeader& CancelResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& CancelResponse::response_header() const
{
  return mResponseHeader;
}

uint32_t& CancelResponse::cancel_count()
{
  return mCancelCount;
}

const uint32_t& CancelResponse::cancel_count() const
{
  return mCancelCount;
}

BuiltInTypeId CancelResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::DataTypeAttributes
{
namespace
{
void encode(StackDepth limit, const ua::DataTypeAttributes& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.is_abstract());
}

void encode(StackDepth limit, const ua::DataTypeAttributes& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "IsAbstract", value.is_abstract());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::DataTypeAttributes& value)
{
  decoder.decode(limit, value.is_abstract());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::DataTypeAttributes& value)
{
  decoder.decode(limit, "IsAbstract", true, value.is_abstract());
}
}  // namespace
}  // namespace detail::DataTypeAttributes

namespace detail::DataTypeAttributes
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::DataTypeAttributes::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::DataTypeAttributes::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::DataTypeAttributes

namespace detail::DataTypeAttributes
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::DataTypeAttributes>();
}
}  // namespace
}  // namespace detail::DataTypeAttributes

bool DataTypeAttributes::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return NodeAttributes::is_of_type(ns, dataTypeId);
}

NodeId DataTypeAttributes::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId DataTypeAttributes::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String DataTypeAttributes::type_name() const
{
  return typeName;
}

void DataTypeAttributes::encode(StackDepth limit, Encoder& encoder) const
{

  NodeAttributes::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DataTypeAttributes::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DataTypeAttributes::encode(limit, *this, *xml);
  }
}

void DataTypeAttributes::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DataTypeAttributes::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DataTypeAttributes::encode_id(limit, ns, *xml);
  }
}

void DataTypeAttributes::decode(StackDepth limit, Decoder& decoder)
{

  NodeAttributes::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::DataTypeAttributes::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::DataTypeAttributes::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> DataTypeAttributes::clone() const
{
  return make_unique<DataTypeAttributes>(*this);
}

void DataTypeAttributes::append_fields(std::string& output, int indent) const
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

std::string DataTypeAttributes::to_string(int indent) const
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

void DataTypeAttributes::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::DataTypeAttributes::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::DataTypeAttributes::create);
  }
}

bool& DataTypeAttributes::is_abstract()
{
  return mIsAbstract;
}

const bool& DataTypeAttributes::is_abstract() const
{
  return mIsAbstract;
}

BuiltInTypeId DataTypeAttributes::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::AddReferencesResponse
{
namespace
{
void encode(StackDepth limit, const ua::AddReferencesResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.results());
  encoder.encode(limit, value.diagnostic_infos());
}

void encode(StackDepth limit, const ua::AddReferencesResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "Results", value.results());
  encoder.encode(limit, "DiagnosticInfos", value.diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::AddReferencesResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.results());
  decoder.decode(limit, value.diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::AddReferencesResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "Results", true, value.results());
  decoder.decode(limit, "DiagnosticInfos", true, value.diagnostic_infos());
}
}  // namespace
}  // namespace detail::AddReferencesResponse

namespace detail::AddReferencesResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::AddReferencesResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::AddReferencesResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::AddReferencesResponse

namespace detail::AddReferencesResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::AddReferencesResponse>();
}
}  // namespace
}  // namespace detail::AddReferencesResponse

bool AddReferencesResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId AddReferencesResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId AddReferencesResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String AddReferencesResponse::type_name() const
{
  return typeName;
}

void AddReferencesResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AddReferencesResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AddReferencesResponse::encode(limit, *this, *xml);
  }
}

void AddReferencesResponse::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AddReferencesResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AddReferencesResponse::encode_id(limit, ns, *xml);
  }
}

void AddReferencesResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::AddReferencesResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::AddReferencesResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> AddReferencesResponse::clone() const
{
  return make_unique<AddReferencesResponse>(*this);
}

void AddReferencesResponse::append_fields(std::string& output, int indent) const
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

std::string AddReferencesResponse::to_string(int indent) const
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

void AddReferencesResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::AddReferencesResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::AddReferencesResponse::create);
  }
}

ResponseHeader& AddReferencesResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& AddReferencesResponse::response_header() const
{
  return mResponseHeader;
}

Array<StatusCode>& AddReferencesResponse::results()
{
  return mResults;
}

const Array<StatusCode>& AddReferencesResponse::results() const
{
  return mResults;
}

Array<DiagnosticInfo>& AddReferencesResponse::diagnostic_infos()
{
  return mDiagnosticInfos;
}

const Array<DiagnosticInfo>& AddReferencesResponse::diagnostic_infos() const
{
  return mDiagnosticInfos;
}

BuiltInTypeId AddReferencesResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::BrowseResult
{
namespace
{
void encode(StackDepth limit, const ua::BrowseResult& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.status_code());
  encoder.encode(limit, value.continuation_point());
  encoder.encode(limit, value.references());
}

void encode(StackDepth limit, const ua::BrowseResult& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "StatusCode", value.status_code());
  encoder.encode(limit, "ContinuationPoint", value.continuation_point());
  encoder.encode(limit, "References", value.references());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::BrowseResult& value)
{
  decoder.decode(limit, value.status_code());
  decoder.decode(limit, value.continuation_point());
  decoder.decode(limit, value.references());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::BrowseResult& value)
{
  decoder.decode(limit, "StatusCode", true, value.status_code());
  decoder.decode(limit, "ContinuationPoint", true, value.continuation_point());
  decoder.decode(limit, "References", true, value.references());
}
}  // namespace
}  // namespace detail::BrowseResult

namespace detail::BrowseResult
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::BrowseResult::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::BrowseResult::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::BrowseResult

namespace detail::BrowseResult
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::BrowseResult>();
}
}  // namespace
}  // namespace detail::BrowseResult

bool BrowseResult::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId BrowseResult::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId BrowseResult::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String BrowseResult::type_name() const
{
  return typeName;
}

void BrowseResult::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::BrowseResult::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::BrowseResult::encode(limit, *this, *xml);
  }
}

void BrowseResult::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::BrowseResult::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::BrowseResult::encode_id(limit, ns, *xml);
  }
}

void BrowseResult::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::BrowseResult::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::BrowseResult::decode(limit, *xml, *this);
  }
}

void BrowseResult::resolve(span<const LocaleId> locales)
{
  Structure::resolve(locales);
  for (size_t i = 0; i < mReferences.size(); ++i)
  {
    mReferences[i].resolve(locales);
  }
}

unique_ptr<Structure> BrowseResult::clone() const
{
  return make_unique<BrowseResult>(*this);
}

void BrowseResult::append_fields(std::string& output, int indent) const
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
    output += pad + "references=" + ua::to_string(references());
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
  output += "references=" + ua::to_string(references());
}

std::string BrowseResult::to_string(int indent) const
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

void BrowseResult::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::BrowseResult::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::BrowseResult::create);
  }
}

StatusCode& BrowseResult::status_code()
{
  return mStatusCode;
}

const StatusCode& BrowseResult::status_code() const
{
  return mStatusCode;
}

ContinuationPoint& BrowseResult::continuation_point()
{
  return mContinuationPoint;
}

const ContinuationPoint& BrowseResult::continuation_point() const
{
  return mContinuationPoint;
}

Array<ReferenceDescription>& BrowseResult::references()
{
  return mReferences;
}

const Array<ReferenceDescription>& BrowseResult::references() const
{
  return mReferences;
}

BuiltInTypeId BrowseResult::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::TranslateBrowsePathsToNodeIdsRequest
{
namespace
{
void encode(StackDepth limit, const ua::TranslateBrowsePathsToNodeIdsRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.browse_paths());
}

void encode(StackDepth limit, const ua::TranslateBrowsePathsToNodeIdsRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "BrowsePaths", value.browse_paths());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::TranslateBrowsePathsToNodeIdsRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.browse_paths());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::TranslateBrowsePathsToNodeIdsRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "BrowsePaths", true, value.browse_paths());
}
}  // namespace
}  // namespace detail::TranslateBrowsePathsToNodeIdsRequest

namespace detail::TranslateBrowsePathsToNodeIdsRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::TranslateBrowsePathsToNodeIdsRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::TranslateBrowsePathsToNodeIdsRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::TranslateBrowsePathsToNodeIdsRequest

namespace detail::TranslateBrowsePathsToNodeIdsRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::TranslateBrowsePathsToNodeIdsRequest>();
}
}  // namespace
}  // namespace detail::TranslateBrowsePathsToNodeIdsRequest

bool TranslateBrowsePathsToNodeIdsRequest::is_of_type(
  const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId TranslateBrowsePathsToNodeIdsRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId TranslateBrowsePathsToNodeIdsRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String TranslateBrowsePathsToNodeIdsRequest::type_name() const
{
  return typeName;
}

void TranslateBrowsePathsToNodeIdsRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::TranslateBrowsePathsToNodeIdsRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::TranslateBrowsePathsToNodeIdsRequest::encode(limit, *this, *xml);
  }
}

void TranslateBrowsePathsToNodeIdsRequest::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::TranslateBrowsePathsToNodeIdsRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::TranslateBrowsePathsToNodeIdsRequest::encode_id(limit, ns, *xml);
  }
}

void TranslateBrowsePathsToNodeIdsRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::TranslateBrowsePathsToNodeIdsRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::TranslateBrowsePathsToNodeIdsRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> TranslateBrowsePathsToNodeIdsRequest::clone() const
{
  return make_unique<TranslateBrowsePathsToNodeIdsRequest>(*this);
}

void TranslateBrowsePathsToNodeIdsRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "browse_paths=" + ua::to_string(browse_paths());
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
  output += "browse_paths=" + ua::to_string(browse_paths());
}

std::string TranslateBrowsePathsToNodeIdsRequest::to_string(int indent) const
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

void TranslateBrowsePathsToNodeIdsRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::TranslateBrowsePathsToNodeIdsRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(
      NodeId(defaultXmlEncodingId), detail::TranslateBrowsePathsToNodeIdsRequest::create);
  }
}

RequestHeader& TranslateBrowsePathsToNodeIdsRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& TranslateBrowsePathsToNodeIdsRequest::request_header() const
{
  return mRequestHeader;
}

Array<BrowsePath>& TranslateBrowsePathsToNodeIdsRequest::browse_paths()
{
  return mBrowsePaths;
}

const Array<BrowsePath>& TranslateBrowsePathsToNodeIdsRequest::browse_paths() const
{
  return mBrowsePaths;
}

BuiltInTypeId TranslateBrowsePathsToNodeIdsRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::QueryDataSet
{
namespace
{
void encode(StackDepth limit, const ua::QueryDataSet& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.node_id());
  encoder.encode(limit, value.type_definition_node());
  encoder.encode(limit, value.values());
}

void encode(StackDepth limit, const ua::QueryDataSet& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "NodeId", value.node_id());
  encoder.encode(limit, "TypeDefinitionNode", value.type_definition_node());
  encoder.encode(limit, "Values", value.values());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::QueryDataSet& value)
{
  decoder.decode(limit, value.node_id());
  decoder.decode(limit, value.type_definition_node());
  decoder.decode(limit, value.values());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::QueryDataSet& value)
{
  decoder.decode(limit, "NodeId", true, value.node_id());
  decoder.decode(limit, "TypeDefinitionNode", true, value.type_definition_node());
  decoder.decode(limit, "Values", true, value.values());
}
}  // namespace
}  // namespace detail::QueryDataSet

namespace detail::QueryDataSet
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::QueryDataSet::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::QueryDataSet::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::QueryDataSet

namespace detail::QueryDataSet
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::QueryDataSet>();
}
}  // namespace
}  // namespace detail::QueryDataSet

bool QueryDataSet::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId QueryDataSet::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId QueryDataSet::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String QueryDataSet::type_name() const
{
  return typeName;
}

void QueryDataSet::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::QueryDataSet::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::QueryDataSet::encode(limit, *this, *xml);
  }
}

void QueryDataSet::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::QueryDataSet::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::QueryDataSet::encode_id(limit, ns, *xml);
  }
}

void QueryDataSet::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::QueryDataSet::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::QueryDataSet::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> QueryDataSet::clone() const
{
  return make_unique<QueryDataSet>(*this);
}

void QueryDataSet::append_fields(std::string& output, int indent) const
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
    output += pad + "type_definition_node=" + ua::to_string(type_definition_node());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "values=" + ua::to_string(values());
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
  output += "type_definition_node=" + ua::to_string(type_definition_node());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "values=" + ua::to_string(values());
}

std::string QueryDataSet::to_string(int indent) const
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

void QueryDataSet::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::QueryDataSet::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::QueryDataSet::create);
  }
}

ExpandedNodeId& QueryDataSet::node_id()
{
  return mNodeId;
}

const ExpandedNodeId& QueryDataSet::node_id() const
{
  return mNodeId;
}

ExpandedNodeId& QueryDataSet::type_definition_node()
{
  return mTypeDefinitionNode;
}

const ExpandedNodeId& QueryDataSet::type_definition_node() const
{
  return mTypeDefinitionNode;
}

Array<Variant>& QueryDataSet::values()
{
  return mValues;
}

const Array<Variant>& QueryDataSet::values() const
{
  return mValues;
}

BuiltInTypeId QueryDataSet::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::QueryNextResponse
{
namespace
{
void encode(StackDepth limit, const ua::QueryNextResponse& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.response_header());
  encoder.encode(limit, value.query_data_sets());
  encoder.encode(limit, value.revised_continuation_point());
}

void encode(StackDepth limit, const ua::QueryNextResponse& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ResponseHeader", value.response_header());
  encoder.encode(limit, "QueryDataSets", value.query_data_sets());
  encoder.encode(limit, "RevisedContinuationPoint", value.revised_continuation_point());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::QueryNextResponse& value)
{
  decoder.decode(limit, value.response_header());
  decoder.decode(limit, value.query_data_sets());
  decoder.decode(limit, value.revised_continuation_point());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::QueryNextResponse& value)
{
  decoder.decode(limit, "ResponseHeader", true, value.response_header());
  decoder.decode(limit, "QueryDataSets", true, value.query_data_sets());
  decoder.decode(limit, "RevisedContinuationPoint", true, value.revised_continuation_point());
}
}  // namespace
}  // namespace detail::QueryNextResponse

namespace detail::QueryNextResponse
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::QueryNextResponse::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::QueryNextResponse::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::QueryNextResponse

namespace detail::QueryNextResponse
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::QueryNextResponse>();
}
}  // namespace
}  // namespace detail::QueryNextResponse

bool QueryNextResponse::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId QueryNextResponse::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId QueryNextResponse::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String QueryNextResponse::type_name() const
{
  return typeName;
}

void QueryNextResponse::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::QueryNextResponse::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::QueryNextResponse::encode(limit, *this, *xml);
  }
}

void QueryNextResponse::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::QueryNextResponse::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::QueryNextResponse::encode_id(limit, ns, *xml);
  }
}

void QueryNextResponse::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::QueryNextResponse::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::QueryNextResponse::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> QueryNextResponse::clone() const
{
  return make_unique<QueryNextResponse>(*this);
}

void QueryNextResponse::append_fields(std::string& output, int indent) const
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
    output += pad + "revised_continuation_point=" + ua::to_string(revised_continuation_point());
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
  output += "revised_continuation_point=" + ua::to_string(revised_continuation_point());
}

std::string QueryNextResponse::to_string(int indent) const
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

void QueryNextResponse::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::QueryNextResponse::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::QueryNextResponse::create);
  }
}

ResponseHeader& QueryNextResponse::response_header()
{
  return mResponseHeader;
}

const ResponseHeader& QueryNextResponse::response_header() const
{
  return mResponseHeader;
}

Array<QueryDataSet>& QueryNextResponse::query_data_sets()
{
  return mQueryDataSets;
}

const Array<QueryDataSet>& QueryNextResponse::query_data_sets() const
{
  return mQueryDataSets;
}

ContinuationPoint& QueryNextResponse::revised_continuation_point()
{
  return mRevisedContinuationPoint;
}

const ContinuationPoint& QueryNextResponse::revised_continuation_point() const
{
  return mRevisedContinuationPoint;
}

BuiltInTypeId QueryNextResponse::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ReadEventDetails2
{
namespace
{
void encode(StackDepth limit, const ua::ReadEventDetails2& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.read_modified());
}

void encode(StackDepth limit, const ua::ReadEventDetails2& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ReadModified", value.read_modified());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ReadEventDetails2& value)
{
  decoder.decode(limit, value.read_modified());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ReadEventDetails2& value)
{
  decoder.decode(limit, "ReadModified", true, value.read_modified());
}
}  // namespace
}  // namespace detail::ReadEventDetails2

namespace detail::ReadEventDetails2
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ReadEventDetails2::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ReadEventDetails2::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ReadEventDetails2

namespace detail::ReadEventDetails2
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ReadEventDetails2>();
}
}  // namespace
}  // namespace detail::ReadEventDetails2

bool ReadEventDetails2::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return ReadEventDetails::is_of_type(ns, dataTypeId);
}

NodeId ReadEventDetails2::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ReadEventDetails2::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ReadEventDetails2::type_name() const
{
  return typeName;
}

void ReadEventDetails2::encode(StackDepth limit, Encoder& encoder) const
{

  ReadEventDetails::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReadEventDetails2::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReadEventDetails2::encode(limit, *this, *xml);
  }
}

void ReadEventDetails2::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ReadEventDetails2::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ReadEventDetails2::encode_id(limit, ns, *xml);
  }
}

void ReadEventDetails2::decode(StackDepth limit, Decoder& decoder)
{

  ReadEventDetails::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ReadEventDetails2::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ReadEventDetails2::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ReadEventDetails2::clone() const
{
  return make_unique<ReadEventDetails2>(*this);
}

void ReadEventDetails2::append_fields(std::string& output, int indent) const
{
  ReadEventDetails::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "read_modified=" + ua::to_string(read_modified());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "read_modified=" + ua::to_string(read_modified());
}

std::string ReadEventDetails2::to_string(int indent) const
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

void ReadEventDetails2::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::ReadEventDetails2::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ReadEventDetails2::create);
  }
}

bool& ReadEventDetails2::read_modified()
{
  return mReadModified;
}

const bool& ReadEventDetails2::read_modified() const
{
  return mReadModified;
}

BuiltInTypeId ReadEventDetails2::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::HistoryModifiedData
{
namespace
{
void encode(StackDepth limit, const ua::HistoryModifiedData& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.modification_infos());
}

void encode(StackDepth limit, const ua::HistoryModifiedData& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ModificationInfos", value.modification_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::HistoryModifiedData& value)
{
  decoder.decode(limit, value.modification_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::HistoryModifiedData& value)
{
  decoder.decode(limit, "ModificationInfos", true, value.modification_infos());
}
}  // namespace
}  // namespace detail::HistoryModifiedData

namespace detail::HistoryModifiedData
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::HistoryModifiedData::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::HistoryModifiedData::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::HistoryModifiedData

namespace detail::HistoryModifiedData
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::HistoryModifiedData>();
}
}  // namespace
}  // namespace detail::HistoryModifiedData

bool HistoryModifiedData::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return HistoryData::is_of_type(ns, dataTypeId);
}

NodeId HistoryModifiedData::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId HistoryModifiedData::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String HistoryModifiedData::type_name() const
{
  return typeName;
}

void HistoryModifiedData::encode(StackDepth limit, Encoder& encoder) const
{

  HistoryData::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::HistoryModifiedData::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::HistoryModifiedData::encode(limit, *this, *xml);
  }
}

void HistoryModifiedData::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::HistoryModifiedData::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::HistoryModifiedData::encode_id(limit, ns, *xml);
  }
}

void HistoryModifiedData::decode(StackDepth limit, Decoder& decoder)
{

  HistoryData::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::HistoryModifiedData::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::HistoryModifiedData::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> HistoryModifiedData::clone() const
{
  return make_unique<HistoryModifiedData>(*this);
}

void HistoryModifiedData::append_fields(std::string& output, int indent) const
{
  HistoryData::append_fields(output, indent);
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

std::string HistoryModifiedData::to_string(int indent) const
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

void HistoryModifiedData::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::HistoryModifiedData::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::HistoryModifiedData::create);
  }
}

Array<ModificationInfo>& HistoryModifiedData::modification_infos()
{
  return mModificationInfos;
}

const Array<ModificationInfo>& HistoryModifiedData::modification_infos() const
{
  return mModificationInfos;
}

BuiltInTypeId HistoryModifiedData::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::UpdateStructureDataDetails
{
namespace
{
void encode(StackDepth limit, const ua::UpdateStructureDataDetails& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.node_id());
  encoder.encode(limit, utils::as_int32(value.perform_insert_replace()));
  encoder.encode(limit, value.update_values());
}

void encode(StackDepth limit, const ua::UpdateStructureDataDetails& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "NodeId", value.node_id());
  encoder.encode(limit, "PerformInsertReplace", utils::as_int32(value.perform_insert_replace()));
  encoder.encode(limit, "UpdateValues", value.update_values());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::UpdateStructureDataDetails& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.node_id());
  decoder.decode(limit, enumVal);
  value.perform_insert_replace() = utils::from_underlying<PerformUpdateType>(enumVal);
  decoder.decode(limit, value.update_values());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::UpdateStructureDataDetails& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "NodeId", true, value.node_id());
  decoder.decode(limit, "PerformInsertReplace", true, enumVal);
  value.perform_insert_replace() = utils::from_underlying<PerformUpdateType>(enumVal);
  decoder.decode(limit, "UpdateValues", true, value.update_values());
}
}  // namespace
}  // namespace detail::UpdateStructureDataDetails

namespace detail::UpdateStructureDataDetails
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::UpdateStructureDataDetails::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::UpdateStructureDataDetails::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::UpdateStructureDataDetails

namespace detail::UpdateStructureDataDetails
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::UpdateStructureDataDetails>();
}
}  // namespace
}  // namespace detail::UpdateStructureDataDetails

bool UpdateStructureDataDetails::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return HistoryUpdateDetails::is_of_type(ns, dataTypeId);
}

NodeId UpdateStructureDataDetails::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId UpdateStructureDataDetails::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String UpdateStructureDataDetails::type_name() const
{
  return typeName;
}

void UpdateStructureDataDetails::encode(StackDepth limit, Encoder& encoder) const
{

  HistoryUpdateDetails::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::UpdateStructureDataDetails::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::UpdateStructureDataDetails::encode(limit, *this, *xml);
  }
}

void UpdateStructureDataDetails::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::UpdateStructureDataDetails::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::UpdateStructureDataDetails::encode_id(limit, ns, *xml);
  }
}

void UpdateStructureDataDetails::decode(StackDepth limit, Decoder& decoder)
{

  HistoryUpdateDetails::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::UpdateStructureDataDetails::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::UpdateStructureDataDetails::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> UpdateStructureDataDetails::clone() const
{
  return make_unique<UpdateStructureDataDetails>(*this);
}

void UpdateStructureDataDetails::append_fields(std::string& output, int indent) const
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

std::string UpdateStructureDataDetails::to_string(int indent) const
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

void UpdateStructureDataDetails::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::UpdateStructureDataDetails::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::UpdateStructureDataDetails::create);
  }
}

NodeId& UpdateStructureDataDetails::node_id()
{
  return mNodeId;
}

const NodeId& UpdateStructureDataDetails::node_id() const
{
  return mNodeId;
}

PerformUpdateType& UpdateStructureDataDetails::perform_insert_replace()
{
  return mPerformInsertReplace;
}

const PerformUpdateType& UpdateStructureDataDetails::perform_insert_replace() const
{
  return mPerformInsertReplace;
}

Array<DataValue>& UpdateStructureDataDetails::update_values()
{
  return mUpdateValues;
}

const Array<DataValue>& UpdateStructureDataDetails::update_values() const
{
  return mUpdateValues;
}

BuiltInTypeId UpdateStructureDataDetails::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::CallMethodRequest
{
namespace
{
void encode(StackDepth limit, const ua::CallMethodRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.object_id());
  encoder.encode(limit, value.method_id());
  encoder.encode(limit, value.input_arguments());
}

void encode(StackDepth limit, const ua::CallMethodRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "ObjectId", value.object_id());
  encoder.encode(limit, "MethodId", value.method_id());
  encoder.encode(limit, "InputArguments", value.input_arguments());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::CallMethodRequest& value)
{
  decoder.decode(limit, value.object_id());
  decoder.decode(limit, value.method_id());
  decoder.decode(limit, value.input_arguments());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::CallMethodRequest& value)
{
  decoder.decode(limit, "ObjectId", true, value.object_id());
  decoder.decode(limit, "MethodId", true, value.method_id());
  decoder.decode(limit, "InputArguments", true, value.input_arguments());
}
}  // namespace
}  // namespace detail::CallMethodRequest

namespace detail::CallMethodRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::CallMethodRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::CallMethodRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::CallMethodRequest

namespace detail::CallMethodRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::CallMethodRequest>();
}
}  // namespace
}  // namespace detail::CallMethodRequest

bool CallMethodRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId CallMethodRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId CallMethodRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String CallMethodRequest::type_name() const
{
  return typeName;
}

void CallMethodRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CallMethodRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CallMethodRequest::encode(limit, *this, *xml);
  }
}

void CallMethodRequest::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CallMethodRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CallMethodRequest::encode_id(limit, ns, *xml);
  }
}

void CallMethodRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::CallMethodRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::CallMethodRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> CallMethodRequest::clone() const
{
  return make_unique<CallMethodRequest>(*this);
}

void CallMethodRequest::append_fields(std::string& output, int indent) const
{
  Structure::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "object_id=" + ua::to_string(object_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "method_id=" + ua::to_string(method_id());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "input_arguments=" + ua::to_string(input_arguments());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "object_id=" + ua::to_string(object_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "method_id=" + ua::to_string(method_id());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "input_arguments=" + ua::to_string(input_arguments());
}

std::string CallMethodRequest::to_string(int indent) const
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

void CallMethodRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::CallMethodRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::CallMethodRequest::create);
  }
}

NodeId& CallMethodRequest::object_id()
{
  return mObjectId;
}

const NodeId& CallMethodRequest::object_id() const
{
  return mObjectId;
}

NodeId& CallMethodRequest::method_id()
{
  return mMethodId;
}

const NodeId& CallMethodRequest::method_id() const
{
  return mMethodId;
}

Array<Variant>& CallMethodRequest::input_arguments()
{
  return mInputArguments;
}

const Array<Variant>& CallMethodRequest::input_arguments() const
{
  return mInputArguments;
}

BuiltInTypeId CallMethodRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::AggregateFilterResult
{
namespace
{
void encode(StackDepth limit, const ua::AggregateFilterResult& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.revised_start_time());
  encoder.encode(limit, value.revised_processing_interval());
  encoder.encode(limit, value.revised_aggregate_configuration());
}

void encode(StackDepth limit, const ua::AggregateFilterResult& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RevisedStartTime", value.revised_start_time());
  encoder.encode(limit, "RevisedProcessingInterval", value.revised_processing_interval());
  encoder.encode(limit, "RevisedAggregateConfiguration", value.revised_aggregate_configuration());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::AggregateFilterResult& value)
{
  decoder.decode(limit, value.revised_start_time());
  decoder.decode(limit, value.revised_processing_interval());
  decoder.decode(limit, value.revised_aggregate_configuration());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::AggregateFilterResult& value)
{
  decoder.decode(limit, "RevisedStartTime", true, value.revised_start_time());
  decoder.decode(limit, "RevisedProcessingInterval", true, value.revised_processing_interval());
  decoder.decode(limit, "RevisedAggregateConfiguration", true, value.revised_aggregate_configuration());
}
}  // namespace
}  // namespace detail::AggregateFilterResult

namespace detail::AggregateFilterResult
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::AggregateFilterResult::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::AggregateFilterResult::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::AggregateFilterResult

namespace detail::AggregateFilterResult
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::AggregateFilterResult>();
}
}  // namespace
}  // namespace detail::AggregateFilterResult

bool AggregateFilterResult::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return MonitoringFilterResult::is_of_type(ns, dataTypeId);
}

NodeId AggregateFilterResult::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId AggregateFilterResult::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String AggregateFilterResult::type_name() const
{
  return typeName;
}

void AggregateFilterResult::encode(StackDepth limit, Encoder& encoder) const
{

  MonitoringFilterResult::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AggregateFilterResult::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AggregateFilterResult::encode(limit, *this, *xml);
  }
}

void AggregateFilterResult::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::AggregateFilterResult::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::AggregateFilterResult::encode_id(limit, ns, *xml);
  }
}

void AggregateFilterResult::decode(StackDepth limit, Decoder& decoder)
{

  MonitoringFilterResult::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::AggregateFilterResult::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::AggregateFilterResult::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> AggregateFilterResult::clone() const
{
  return make_unique<AggregateFilterResult>(*this);
}

void AggregateFilterResult::append_fields(std::string& output, int indent) const
{
  MonitoringFilterResult::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "revised_start_time=" + ua::to_string(revised_start_time());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "revised_processing_interval=" + ua::to_string(revised_processing_interval());
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "revised_aggregate_configuration=" + ua::to_string(revised_aggregate_configuration());
    return;
  }
  if (!output.empty())
  {
    output += ", ";
  }
  output += "revised_start_time=" + ua::to_string(revised_start_time());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "revised_processing_interval=" + ua::to_string(revised_processing_interval());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "revised_aggregate_configuration=" + ua::to_string(revised_aggregate_configuration());
}

std::string AggregateFilterResult::to_string(int indent) const
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

void AggregateFilterResult::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::AggregateFilterResult::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::AggregateFilterResult::create);
  }
}

UtcTime& AggregateFilterResult::revised_start_time()
{
  return mRevisedStartTime;
}

const UtcTime& AggregateFilterResult::revised_start_time() const
{
  return mRevisedStartTime;
}

Duration& AggregateFilterResult::revised_processing_interval()
{
  return mRevisedProcessingInterval;
}

const Duration& AggregateFilterResult::revised_processing_interval() const
{
  return mRevisedProcessingInterval;
}

AggregateConfiguration& AggregateFilterResult::revised_aggregate_configuration()
{
  return mRevisedAggregateConfiguration;
}

const AggregateConfiguration& AggregateFilterResult::revised_aggregate_configuration() const
{
  return mRevisedAggregateConfiguration;
}

BuiltInTypeId AggregateFilterResult::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::ModifyMonitoredItemsRequest
{
namespace
{
void encode(StackDepth limit, const ua::ModifyMonitoredItemsRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.subscription_id());
  encoder.encode(limit, utils::as_int32(value.timestamps_to_return()));
  encoder.encode(limit, value.items_to_modify());
}

void encode(StackDepth limit, const ua::ModifyMonitoredItemsRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "SubscriptionId", value.subscription_id());
  encoder.encode(limit, "TimestampsToReturn", utils::as_int32(value.timestamps_to_return()));
  encoder.encode(limit, "ItemsToModify", value.items_to_modify());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::ModifyMonitoredItemsRequest& value)
{
  int32_t enumVal{};
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.subscription_id());
  decoder.decode(limit, enumVal);
  value.timestamps_to_return() = utils::from_underlying<TimestampsToReturn>(enumVal);
  decoder.decode(limit, value.items_to_modify());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::ModifyMonitoredItemsRequest& value)
{
  int32_t enumVal{};
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "SubscriptionId", true, value.subscription_id());
  decoder.decode(limit, "TimestampsToReturn", true, enumVal);
  value.timestamps_to_return() = utils::from_underlying<TimestampsToReturn>(enumVal);
  decoder.decode(limit, "ItemsToModify", true, value.items_to_modify());
}
}  // namespace
}  // namespace detail::ModifyMonitoredItemsRequest

namespace detail::ModifyMonitoredItemsRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::ModifyMonitoredItemsRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::ModifyMonitoredItemsRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::ModifyMonitoredItemsRequest

namespace detail::ModifyMonitoredItemsRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::ModifyMonitoredItemsRequest>();
}
}  // namespace
}  // namespace detail::ModifyMonitoredItemsRequest

bool ModifyMonitoredItemsRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId ModifyMonitoredItemsRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId ModifyMonitoredItemsRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String ModifyMonitoredItemsRequest::type_name() const
{
  return typeName;
}

void ModifyMonitoredItemsRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ModifyMonitoredItemsRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ModifyMonitoredItemsRequest::encode(limit, *this, *xml);
  }
}

void ModifyMonitoredItemsRequest::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::ModifyMonitoredItemsRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::ModifyMonitoredItemsRequest::encode_id(limit, ns, *xml);
  }
}

void ModifyMonitoredItemsRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::ModifyMonitoredItemsRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::ModifyMonitoredItemsRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> ModifyMonitoredItemsRequest::clone() const
{
  return make_unique<ModifyMonitoredItemsRequest>(*this);
}

void ModifyMonitoredItemsRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "items_to_modify=" + ua::to_string(items_to_modify());
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
  output += "items_to_modify=" + ua::to_string(items_to_modify());
}

std::string ModifyMonitoredItemsRequest::to_string(int indent) const
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

void ModifyMonitoredItemsRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::ModifyMonitoredItemsRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::ModifyMonitoredItemsRequest::create);
  }
}

RequestHeader& ModifyMonitoredItemsRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& ModifyMonitoredItemsRequest::request_header() const
{
  return mRequestHeader;
}

IntegerId& ModifyMonitoredItemsRequest::subscription_id()
{
  return mSubscriptionId;
}

const IntegerId& ModifyMonitoredItemsRequest::subscription_id() const
{
  return mSubscriptionId;
}

TimestampsToReturn& ModifyMonitoredItemsRequest::timestamps_to_return()
{
  return mTimestampsToReturn;
}

const TimestampsToReturn& ModifyMonitoredItemsRequest::timestamps_to_return() const
{
  return mTimestampsToReturn;
}

Array<MonitoredItemModifyRequest>& ModifyMonitoredItemsRequest::items_to_modify()
{
  return mItemsToModify;
}

const Array<MonitoredItemModifyRequest>& ModifyMonitoredItemsRequest::items_to_modify() const
{
  return mItemsToModify;
}

BuiltInTypeId ModifyMonitoredItemsRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::CreateSubscriptionRequest
{
namespace
{
void encode(StackDepth limit, const ua::CreateSubscriptionRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.requested_publishing_interval());
  encoder.encode(limit, value.requested_lifetime_count());
  encoder.encode(limit, value.requested_max_keep_alive_count());
  encoder.encode(limit, value.max_notifications_per_publish());
  encoder.encode(limit, value.publishing_enabled());
  encoder.encode(limit, value.priority());
}

void encode(StackDepth limit, const ua::CreateSubscriptionRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "RequestedPublishingInterval", value.requested_publishing_interval());
  encoder.encode(limit, "RequestedLifetimeCount", value.requested_lifetime_count());
  encoder.encode(limit, "RequestedMaxKeepAliveCount", value.requested_max_keep_alive_count());
  encoder.encode(limit, "MaxNotificationsPerPublish", value.max_notifications_per_publish());
  encoder.encode(limit, "PublishingEnabled", value.publishing_enabled());
  encoder.encode(limit, "Priority", value.priority());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::CreateSubscriptionRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.requested_publishing_interval());
  decoder.decode(limit, value.requested_lifetime_count());
  decoder.decode(limit, value.requested_max_keep_alive_count());
  decoder.decode(limit, value.max_notifications_per_publish());
  decoder.decode(limit, value.publishing_enabled());
  decoder.decode(limit, value.priority());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::CreateSubscriptionRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "RequestedPublishingInterval", true, value.requested_publishing_interval());
  decoder.decode(limit, "RequestedLifetimeCount", true, value.requested_lifetime_count());
  decoder.decode(limit, "RequestedMaxKeepAliveCount", true, value.requested_max_keep_alive_count());
  decoder.decode(limit, "MaxNotificationsPerPublish", true, value.max_notifications_per_publish());
  decoder.decode(limit, "PublishingEnabled", true, value.publishing_enabled());
  decoder.decode(limit, "Priority", true, value.priority());
}
}  // namespace
}  // namespace detail::CreateSubscriptionRequest

namespace detail::CreateSubscriptionRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::CreateSubscriptionRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::CreateSubscriptionRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::CreateSubscriptionRequest

namespace detail::CreateSubscriptionRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::CreateSubscriptionRequest>();
}
}  // namespace
}  // namespace detail::CreateSubscriptionRequest

bool CreateSubscriptionRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId CreateSubscriptionRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId CreateSubscriptionRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String CreateSubscriptionRequest::type_name() const
{
  return typeName;
}

void CreateSubscriptionRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CreateSubscriptionRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CreateSubscriptionRequest::encode(limit, *this, *xml);
  }
}

void CreateSubscriptionRequest::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::CreateSubscriptionRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::CreateSubscriptionRequest::encode_id(limit, ns, *xml);
  }
}

void CreateSubscriptionRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::CreateSubscriptionRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::CreateSubscriptionRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> CreateSubscriptionRequest::clone() const
{
  return make_unique<CreateSubscriptionRequest>(*this);
}

void CreateSubscriptionRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "publishing_enabled=" + ua::to_string(publishing_enabled());
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
  output += "publishing_enabled=" + ua::to_string(publishing_enabled());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "priority=" + ua::to_string(priority());
}

std::string CreateSubscriptionRequest::to_string(int indent) const
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

void CreateSubscriptionRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(
      NodeId(defaultBinaryEncodingId), detail::CreateSubscriptionRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::CreateSubscriptionRequest::create);
  }
}

RequestHeader& CreateSubscriptionRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& CreateSubscriptionRequest::request_header() const
{
  return mRequestHeader;
}

Duration& CreateSubscriptionRequest::requested_publishing_interval()
{
  return mRequestedPublishingInterval;
}

const Duration& CreateSubscriptionRequest::requested_publishing_interval() const
{
  return mRequestedPublishingInterval;
}

Counter& CreateSubscriptionRequest::requested_lifetime_count()
{
  return mRequestedLifetimeCount;
}

const Counter& CreateSubscriptionRequest::requested_lifetime_count() const
{
  return mRequestedLifetimeCount;
}

Counter& CreateSubscriptionRequest::requested_max_keep_alive_count()
{
  return mRequestedMaxKeepAliveCount;
}

const Counter& CreateSubscriptionRequest::requested_max_keep_alive_count() const
{
  return mRequestedMaxKeepAliveCount;
}

Counter& CreateSubscriptionRequest::max_notifications_per_publish()
{
  return mMaxNotificationsPerPublish;
}

const Counter& CreateSubscriptionRequest::max_notifications_per_publish() const
{
  return mMaxNotificationsPerPublish;
}

bool& CreateSubscriptionRequest::publishing_enabled()
{
  return mPublishingEnabled;
}

const bool& CreateSubscriptionRequest::publishing_enabled() const
{
  return mPublishingEnabled;
}

uint8_t& CreateSubscriptionRequest::priority()
{
  return mPriority;
}

const uint8_t& CreateSubscriptionRequest::priority() const
{
  return mPriority;
}

BuiltInTypeId CreateSubscriptionRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::DataChangeNotification
{
namespace
{
void encode(StackDepth limit, const ua::DataChangeNotification& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.monitored_items());
  encoder.encode(limit, value.diagnostic_infos());
}

void encode(StackDepth limit, const ua::DataChangeNotification& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "MonitoredItems", value.monitored_items());
  encoder.encode(limit, "DiagnosticInfos", value.diagnostic_infos());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::DataChangeNotification& value)
{
  decoder.decode(limit, value.monitored_items());
  decoder.decode(limit, value.diagnostic_infos());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::DataChangeNotification& value)
{
  decoder.decode(limit, "MonitoredItems", true, value.monitored_items());
  decoder.decode(limit, "DiagnosticInfos", true, value.diagnostic_infos());
}
}  // namespace
}  // namespace detail::DataChangeNotification

namespace detail::DataChangeNotification
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::DataChangeNotification::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::DataChangeNotification::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::DataChangeNotification

namespace detail::DataChangeNotification
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::DataChangeNotification>();
}
}  // namespace
}  // namespace detail::DataChangeNotification

bool DataChangeNotification::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return NotificationData::is_of_type(ns, dataTypeId);
}

NodeId DataChangeNotification::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId DataChangeNotification::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String DataChangeNotification::type_name() const
{
  return typeName;
}

void DataChangeNotification::encode(StackDepth limit, Encoder& encoder) const
{

  NotificationData::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DataChangeNotification::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DataChangeNotification::encode(limit, *this, *xml);
  }
}

void DataChangeNotification::encode_id(
  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::DataChangeNotification::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::DataChangeNotification::encode_id(limit, ns, *xml);
  }
}

void DataChangeNotification::decode(StackDepth limit, Decoder& decoder)
{

  NotificationData::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::DataChangeNotification::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::DataChangeNotification::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> DataChangeNotification::clone() const
{
  return make_unique<DataChangeNotification>(*this);
}

void DataChangeNotification::append_fields(std::string& output, int indent) const
{
  NotificationData::append_fields(output, indent);
  if (indent > 0)
  {
    std::string pad(numeric_cast<size_t>(indent), ' ');
    if (!output.empty())
    {
      output += ",\n";
    }
    output += pad + "monitored_items=" + ua::to_string(monitored_items());
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
  output += "monitored_items=" + ua::to_string(monitored_items());
  if (!output.empty())
  {
    output += ", ";
  }
  output += "diagnostic_infos=" + ua::to_string(diagnostic_infos());
}

std::string DataChangeNotification::to_string(int indent) const
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

void DataChangeNotification::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::DataChangeNotification::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::DataChangeNotification::create);
  }
}

Array<MonitoredItemNotification>& DataChangeNotification::monitored_items()
{
  return mMonitoredItems;
}

const Array<MonitoredItemNotification>& DataChangeNotification::monitored_items() const
{
  return mMonitoredItems;
}

Array<DiagnosticInfo>& DataChangeNotification::diagnostic_infos()
{
  return mDiagnosticInfos;
}

const Array<DiagnosticInfo>& DataChangeNotification::diagnostic_infos() const
{
  return mDiagnosticInfos;
}

BuiltInTypeId DataChangeNotification::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

namespace detail::RepublishRequest
{
namespace
{
void encode(StackDepth limit, const ua::RepublishRequest& value, UaBinaryEncoder& encoder)
{
  encoder.encode(limit, value.request_header());
  encoder.encode(limit, value.subscription_id());
  encoder.encode(limit, value.retransmit_sequence_number());
}

void encode(StackDepth limit, const ua::RepublishRequest& value, XmlEncoder& encoder)
{
  encoder.encode(limit, "RequestHeader", value.request_header());
  encoder.encode(limit, "SubscriptionId", value.subscription_id());
  encoder.encode(limit, "RetransmitSequenceNumber", value.retransmit_sequence_number());
}

void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::RepublishRequest& value)
{
  decoder.decode(limit, value.request_header());
  decoder.decode(limit, value.subscription_id());
  decoder.decode(limit, value.retransmit_sequence_number());
}

void decode(StackDepth limit, XmlDecoder& decoder, ua::RepublishRequest& value)
{
  decoder.decode(limit, "RequestHeader", true, value.request_header());
  decoder.decode(limit, "SubscriptionId", true, value.subscription_id());
  decoder.decode(limit, "RetransmitSequenceNumber", true, value.retransmit_sequence_number());
}
}  // namespace
}  // namespace detail::RepublishRequest

namespace detail::RepublishRequest
{
namespace
{
void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, NodeId{ua::RepublishRequest::defaultBinaryEncodingId});
}

void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)
{
  UA_UNUSED(ns);
  encoder.encode(limit, "TypeId", NodeId{ua::RepublishRequest::defaultXmlEncodingId});
}
}  // namespace
}  // namespace detail::RepublishRequest

namespace detail::RepublishRequest
{
namespace
{
unique_ptr<Structure> create()
{
  return make_unique<ua::RepublishRequest>();
}
}  // namespace
}  // namespace detail::RepublishRequest

bool RepublishRequest::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  NodeId myTypeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
  if (dataTypeId == myTypeId)
  {
    return true;
  }

  return Structure::is_of_type(ns, dataTypeId);
}

NodeId RepublishRequest::type_id(const CodecNamespaceContext& ns) const
{
  return NodeId{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)};
}

ExpandedNodeId RepublishRequest::type_id() const
{
  return ExpandedNodeId{NodeId{0, utils::to_underlying(typeId)}, typeNamespaceUri};
}

String RepublishRequest::type_name() const
{
  return typeName;
}

void RepublishRequest::encode(StackDepth limit, Encoder& encoder) const
{

  Structure::encode(limit, encoder);

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RepublishRequest::encode(limit, *this, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RepublishRequest::encode(limit, *this, *xml);
  }
}

void RepublishRequest::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{

  if (auto uaBinary = encoder.get_ua_binary())
  {
    detail::RepublishRequest::encode_id(limit, ns, *uaBinary);
  }
  else if (auto xml = encoder.get_xml())
  {
    detail::RepublishRequest::encode_id(limit, ns, *xml);
  }
}

void RepublishRequest::decode(StackDepth limit, Decoder& decoder)
{

  Structure::decode(limit, decoder);

  if (auto uaBinary = decoder.get_ua_binary())
  {
    detail::RepublishRequest::decode(limit, *uaBinary, *this);
  }
  else if (auto xml = decoder.get_xml())
  {
    detail::RepublishRequest::decode(limit, *xml, *this);
  }
}

unique_ptr<Structure> RepublishRequest::clone() const
{
  return make_unique<RepublishRequest>(*this);
}

void RepublishRequest::append_fields(std::string& output, int indent) const
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
    output += pad + "retransmit_sequence_number=" + ua::to_string(retransmit_sequence_number());
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
  output += "retransmit_sequence_number=" + ua::to_string(retransmit_sequence_number());
}

std::string RepublishRequest::to_string(int indent) const
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

void RepublishRequest::register_type(
  const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)
{
  UA_UNUSED(ns);

  if (uaBinaryFactory)
  {
    uaBinaryFactory->register_type(NodeId(defaultBinaryEncodingId), detail::RepublishRequest::create);
  }
  if (xmlFactory)
  {
    xmlFactory->register_type(NodeId(defaultXmlEncodingId), detail::RepublishRequest::create);
  }
}

RequestHeader& RepublishRequest::request_header()
{
  return mRequestHeader;
}

const RequestHeader& RepublishRequest::request_header() const
{
  return mRequestHeader;
}

IntegerId& RepublishRequest::subscription_id()
{
  return mSubscriptionId;
}

const IntegerId& RepublishRequest::subscription_id() const
{
  return mSubscriptionId;
}

Counter& RepublishRequest::retransmit_sequence_number()
{
  return mRetransmitSequenceNumber;
}

const Counter& RepublishRequest::retransmit_sequence_number() const
{
  return mRetransmitSequenceNumber;
}

BuiltInTypeId RepublishRequest::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

}  // namespace ua
