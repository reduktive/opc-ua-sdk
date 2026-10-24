// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>
#include "ua_data_type_registration.h"
#include "ua_structure.h"
#include "ua_structure_factory.h"
#include "ua_binary_codec.h"
#include "ua_xml_codec.h"
#include "ua_memory_stream.h"
#include "ua_node_id.h"
#include "ua_xml_parser.h"

#include "ua_null_stream.h"

#include "ua_date_time.h"
#include "ua_guid.h"
#include "ua_node_id.h"
#include "ua_expanded_node_id.h"
#include "ua_qualified_name.h"
#include "ua_localized_text.h"
#include "ua_variant.h"
#include "ua_image.h"
#include "ua_naming_rule_type.h"
#include "ua_image_bmp.h"
#include "ua_image_gif.h"
#include "ua_image_jpg.h"
#include "ua_image_png.h"
#include "ua_audio_data_type.h"
#include "ua_uri_string.h"
#include "ua_redundant_server_mode.h"
#include "ua_bit_field_mask_data_type.h"
#include "ua_semantic_version_string.h"
#include "ua_key_value_pair.h"
#include "ua_additional_parameters_type.h"
#include "ua_ephemeral_key_type.h"
#include "ua_endpoint_type.h"
#include "ua_handle.h"
#include "ua_trimmed_string.h"
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
#include "ua_open_file_mode.h"
#include "ua_identity_criteria_type.h"
#include "ua_identity_mapping_rule_type.h"
#include "ua_currency_unit_type.h"
#include "ua_annotation_data_type.h"
#include "ua_linear_conversion_data_type.h"
#include "ua_conversion_limit_enum.h"
#include "ua_quantity_dimension.h"
#include "ua_alarm_mask.h"
#include "ua_trust_list_validation_options.h"
#include "ua_trust_list_masks.h"
#include "ua_trust_list_data_type.h"
#include "ua_base_configuration_data_type.h"
#include "ua_base_configuration_record_data_type.h"
#include "ua_certificate_group_data_type.h"
#include "ua_configuration_update_target_type.h"
#include "ua_configuration_update_type.h"
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
#include "ua_diagnostics_level.h"
#include "ua_pub_sub_diagnostics_counter_classification.h"
#include "ua_alias_name_data_type.h"
#include "ua_password_options_mask.h"
#include "ua_user_configuration_mask.h"
#include "ua_user_management_data_type.h"
#include "ua_encoded_ticket.h"
#include "ua_duplex.h"
#include "ua_interface_admin_status.h"
#include "ua_interface_oper_status.h"
#include "ua_negotiation_status.h"
#include "ua_tsn_failure_code.h"
#include "ua_tsn_stream_state.h"
#include "ua_tsn_talker_status.h"
#include "ua_tsn_listener_status.h"
#include "ua_chassis_id_subtype.h"
#include "ua_port_id_subtype.h"
#include "ua_man_addr_if_subtype.h"
#include "ua_priority_mapping_entry_type.h"
#include "ua_lldp_management_address_tx_port_type.h"
#include "ua_lldp_management_address_type.h"
#include "ua_lldp_tlv_type.h"
#include "ua_lldp_system_capabilities_map.h"
#include "ua_reference_description_data_type.h"
#include "ua_reference_list_entry_data_type.h"
#include "ua_log_record.h"
#include "ua_log_records_data_type.h"
#include "ua_span_context_data_type.h"
#include "ua_trace_context_data_type.h"
#include "ua_name_value_pair.h"
#include "ua_log_record_mask.h"
#include "ua_id_type.h"
#include "ua_node_class.h"
#include "ua_permission_type.h"
#include "ua_access_level_type.h"
#include "ua_access_level_ex_type.h"
#include "ua_event_notifier_type.h"
#include "ua_access_restriction_type.h"
#include "ua_role_permission_type.h"
#include "ua_data_type_definition.h"
#include "ua_structure_type.h"
#include "ua_structure_field.h"
#include "ua_structure_definition.h"
#include "ua_enum_definition.h"
#include "ua_argument.h"
#include "ua_enum_value_type.h"
#include "ua_enum_field.h"
#include "ua_option_set.h"
#include "ua_normalized_string.h"
#include "ua_decimal_string.h"
#include "ua_duration_string.h"
#include "ua_time_string.h"
#include "ua_date_string.h"
#include "ua_duration.h"
#include "ua_utc_time.h"
#include "ua_locale_id.h"
#include "ua_time_zone_data_type.h"
#include "ua_index.h"
#include "ua_integer_id.h"
#include "ua_application_type.h"
#include "ua_application_description.h"
#include "ua_version_time.h"
#include "ua_server_on_network.h"
#include "ua_application_instance_certificate.h"
#include "ua_message_security_mode.h"
#include "ua_user_token_type.h"
#include "ua_user_token_policy.h"
#include "ua_endpoint_description.h"
#include "ua_registered_server.h"
#include "ua_discovery_configuration.h"
#include "ua_mdns_discovery_configuration.h"
#include "ua_security_token_request_type.h"
#include "ua_signed_software_certificate.h"
#include "ua_session_authentication_token.h"
#include "ua_user_identity_token.h"
#include "ua_anonymous_identity_token.h"
#include "ua_user_name_identity_token.h"
#include "ua_x509_identity_token.h"
#include "ua_issued_identity_token.h"
#include "ua_node_attributes_mask.h"
#include "ua_add_nodes_item.h"
#include "ua_add_references_item.h"
#include "ua_delete_nodes_item.h"
#include "ua_delete_references_item.h"
#include "ua_attribute_write_mask.h"
#include "ua_continuation_point.h"
#include "ua_relative_path_element.h"
#include "ua_relative_path.h"
#include "ua_counter.h"
#include "ua_numeric_range.h"
#include "ua_endpoint_configuration.h"
#include "ua_filter_operator.h"
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
#include "ua_history_update_type.h"
#include "ua_perform_update_type.h"
#include "ua_monitoring_filter.h"
#include "ua_event_filter.h"
#include "ua_aggregate_configuration.h"
#include "ua_history_event_field_list.h"
#include "ua_build_info.h"
#include "ua_redundancy_support.h"
#include "ua_server_state.h"
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
#include "ua_axis_scale_enumeration.h"
#include "ua_complex_number_type.h"
#include "ua_double_complex_number_type.h"
#include "ua_axis_information.h"
#include "ua_xv_type.h"
#include "ua_program_diagnostic_data_type.h"
#include "ua_program_diagnostic2_data_type.h"
#include "ua_annotation.h"
#include "ua_exception_deviation_format.h"
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
#include "ua_rsa_encrypted_secret.h"
#include "ua_ecc_encrypted_secret.h"
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
#include "ua_browse_direction.h"
#include "ua_view_description.h"
#include "ua_browse_description.h"
#include "ua_browse_result_mask.h"
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
#include "ua_timestamps_to_return.h"
#include "ua_read_value_id.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_history_read_value_id.h"
#include "ua_history_read_result.h"
#include "ua_history_read_details.h"
#include "ua_read_event_details.h"
#include "ua_read_event_details2.h"
#include "ua_sort_order_type.h"
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
#include "ua_monitoring_mode.h"
#include "ua_data_change_trigger.h"
#include "ua_deadband_type.h"
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
#include "ua_model_change_structure_verb_mask.h"

using namespace ua;

class GeneratedDataTypeTests : public ::testing::Test
{
protected:
  void SetUp() override
  {
    register_ua_data_types_with_factory(nsConfig, &uaBinaryFactory, &xmlFactory);
  }

  NamespaceIndexResolver getNamespaceIndex = [](string_view uri) -> uint16_t
  {
    if (uri == "http://opcfoundation.org/UA/")
    {
      return 0;
    }

    // Deliberately map non-UA namespaces to a non-trivial index to prove that generated code
    // does not assume `ns=0`.
    return 7;
  };

  CodecNamespaceContext nsConfig{getNamespaceIndex};
  StructureFactory uaBinaryFactory;
  StructureFactory xmlFactory;
  NullStream nullStream;

  template<typename T>
  void test_binary_round_trip(const T& val1)
  {
    memory_stream_device::Dynamic device;
    MemoryStream stream(device);
    EncodingLimits encodingLimits{100, 100};
    auto limit = encodingLimits.stack_depth();
    UaBinaryEncoder binaryEncoder(nsConfig, stream);
    Encoder encoder(binaryEncoder);
    val1.encode(limit, encoder);

    stream.seek_from_start(0);
    UaBinaryDecoder binaryDecoder(uaBinaryFactory.resolver(), stream, encodingLimits, nsConfig);
    Decoder decoder(binaryDecoder);
    T val2;
    val2.decode(limit, decoder);
    EXPECT_EQ(val1, val2);
  }

  template<typename T>
  void test_metadata(const T& val)
  {
    EXPECT_FALSE(val.type_name().empty());
    EXPECT_FALSE(val.type_id(nsConfig).is_null());
    EXPECT_FALSE(val.type_id().is_null());
    EXPECT_TRUE(val.is_of_type(nsConfig, NodeId{getNamespaceIndex(T::typeNamespaceUri), T::typeId}));
    EXPECT_EQ(
      val.type_id(nsConfig).namespace_index(), getNamespaceIndex(string_view{val.type_id().namespace_uri()}));
    EXPECT_EQ(val.built_in_type_id(), BuiltInTypeId::ExtensionObject);
  }

  template<typename T>
  void test_clone(const T& val)
  {
    auto cloned = val.clone();
    ASSERT_NE(cloned, nullptr);
    auto casted = dynamic_cast<T*>(cloned.get());
    ASSERT_NE(casted, nullptr);
    EXPECT_EQ(val, *casted);
  }

  template<typename T>
  void test_xml_round_trip(const T& val1)
  {
    memory_stream_device::Dynamic device;
    MemoryStream stream(device);
    EncodingLimits encodingLimits{100, 100};
    auto limit = encodingLimits.stack_depth();
    XmlEncoder xmlEncoder(nsConfig, stream);
    xmlEncoder.encode(limit, "Value", val1);

    auto data = device.get_data();
    std::string xmlString(reinterpret_cast<const char*>(data.data()), data.size());
    // std::cout << "Encoded XML: " << xmlString << std::endl;
    xmlString.push_back('\0');

    auto xmlContext = xml::parse(xmlString.data());
    auto xmlElement = xmlContext.xml_element();
    auto firstChild = xmlElement.get_first_child("Value");
    ASSERT_TRUE(firstChild.has_value());

    XmlDecoder xmlDecoder(xmlFactory, firstChild.value(), encodingLimits);
    T val2;
    xmlDecoder.decode(limit, "", false, val2);
    // EXPECT_EQ(val1, val2);
    if (!(val1 == val2))
    {
      std::cout << "Inequality detected in XML round trip!" << std::endl;
      memory_stream_device::Dynamic device2;
      MemoryStream stream2(device2);
      XmlEncoder xmlEncoder2(nsConfig, stream2);
      xmlEncoder2.encode(limit, "Value", val2);
      auto data2 = device2.get_data();
      std::string xmlString2(reinterpret_cast<const char*>(data2.data()), data2.size());
      std::cout << "Original XML: ";
      for (auto c : xmlString)
        if (c == '\0')
          std::cout << "\\0";
        else
          std::cout << c;
      std::cout << std::endl;
      std::cout << "Round-trip XML: ";
      for (auto c : xmlString2)
        if (c == '\0')
          std::cout << "\\0";
        else
          std::cout << c;
      std::cout << std::endl;
      EXPECT_EQ(val1, val2);
    }
  }

  // Round-trips the value through the polymorphic `Structure*` encode path - the
  // form a structure takes on the wire inside an ExtensionObject. Unlike
  // test_binary_round_trip (which calls encode()/decode() directly on the
  // concrete type and so only writes the body), this drives encode_id() on the
  // encode side and, on the decode side, the StructureFactory create() method
  // registered for the type's binary encoding id - i.e. the real
  // serialise-as-ExtensionObject / resolve-by-id path. The decoded value must
  // equal the original.
  template<typename T>
  void test_extension_object_round_trip(const T& val1)
  {
    memory_stream_device::Dynamic device;
    MemoryStream stream(device);
    EncodingLimits encodingLimits{100, 100};
    auto limit = encodingLimits.stack_depth();
    UaBinaryEncoder binaryEncoder(nsConfig, stream);
    const Structure* base = &val1;
    binaryEncoder.encode(limit, base);

    stream.seek_from_start(0);
    UaBinaryDecoder binaryDecoder(uaBinaryFactory.resolver(), stream, encodingLimits, nsConfig);
    unique_ptr<Structure> decoded;
    binaryDecoder.decode(limit, decoded);
    ASSERT_NE(decoded, nullptr);
    auto* casted = dynamic_cast<T*>(decoded.get());
    ASSERT_NE(casted, nullptr);
    EXPECT_EQ(val1, *casted);
  }

  // Exercises the type's to_string()/append_fields() formatter on a populated
  // value, recursing through nested structures, arrays and optionals. Both
  // layouts are real paths: indent == 0 is the inline form; indent > 0 is the
  // padded multi-line form a parent uses when formatting a nested value (a
  // separate branch of both to_string() and append_fields()). Asserts the
  // formatter runs and emits non-empty, structured output for each.
  template<typename T>
  void test_to_string(const T& val)
  {
    const std::string inlineStr = val.to_string();
    EXPECT_FALSE(inlineStr.empty());
    EXPECT_NE(inlineStr.find('{'), std::string::npos);
    const std::string indentedStr = val.to_string(2);
    EXPECT_FALSE(indentedStr.empty());
    EXPECT_NE(indentedStr.find('{'), std::string::npos);
  }
};

TEST_F(GeneratedDataTypeTests, Image_SimpleType)
{
  Image val1{};
  Image val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, NamingRuleType_Enumeration)
{
  NamingRuleType e{};
  e = NamingRuleType::Mandatory;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Mandatory");
  e = NamingRuleType::Optional;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Optional");
  e = NamingRuleType::Constraint;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Constraint");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<NamingRuleType>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<NamingRuleType>(-9999));
}

TEST_F(GeneratedDataTypeTests, ImageBMP_SimpleType)
{
  ImageBMP val1{};
  ImageBMP val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, ImageGIF_SimpleType)
{
  ImageGIF val1{};
  ImageGIF val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, ImageJPG_SimpleType)
{
  ImageJPG val1{};
  ImageJPG val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, ImagePNG_SimpleType)
{
  ImagePNG val1{};
  ImagePNG val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, AudioDataType_SimpleType)
{
  AudioDataType val1{};
  AudioDataType val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, UriString_SimpleType)
{
  UriString val1{};
  UriString val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, RedundantServerMode_Enumeration)
{
  RedundantServerMode e{};
  e = RedundantServerMode::PrimaryWithBackup;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "PrimaryWithBackup");
  e = RedundantServerMode::PrimaryOnly;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "PrimaryOnly");
  e = RedundantServerMode::BackupReady;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "BackupReady");
  e = RedundantServerMode::BackupNotReady;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "BackupNotReady");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<RedundantServerMode>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<RedundantServerMode>(-9999));
}

TEST_F(GeneratedDataTypeTests, BitFieldMaskDataType_SimpleType)
{
  BitFieldMaskDataType val1{};
  BitFieldMaskDataType val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, SemanticVersionString_SimpleType)
{
  SemanticVersionString val1{};
  SemanticVersionString val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, KeyValuePair_Structure)
{
  KeyValuePair val1;
  val1.key() = QualifiedName{"test"};
  val1.value() = Variant{123};
  const KeyValuePair& const_val = val1;
  val1.key();
  const_val.key();
  val1.value();
  const_val.value();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, AdditionalParametersType_Structure)
{
  AdditionalParametersType val1;
  val1.parameters().resize(2);
  val1.parameters()[0].key() = QualifiedName{"test"};
  val1.parameters()[0].value() = Variant{123};
  const AdditionalParametersType& const_val = val1;
  val1.parameters();
  const_val.parameters();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, EphemeralKeyType_Structure)
{
  EphemeralKeyType val1;
  val1.public_key() = ByteString{1, 2, 3};
  val1.signature() = ByteString{1, 2, 3};
  const EphemeralKeyType& const_val = val1;
  val1.public_key();
  const_val.public_key();
  val1.signature();
  const_val.signature();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, EndpointType_Structure)
{
  EndpointType val1;
  val1.endpoint_url() = "test";
  val1.security_mode() = MessageSecurityMode::Invalid;
  val1.security_policy_uri() = "test";
  val1.transport_profile_uri() = "test";
  const EndpointType& const_val = val1;
  val1.endpoint_url();
  const_val.endpoint_url();
  val1.security_mode();
  const_val.security_mode();
  val1.security_policy_uri();
  const_val.security_policy_uri();
  val1.transport_profile_uri();
  const_val.transport_profile_uri();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, Handle_SimpleType)
{
  Handle val1{};
  Handle val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, TrimmedString_SimpleType)
{
  TrimmedString val1{};
  TrimmedString val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, BitFieldDefinition_Structure)
{
  BitFieldDefinition val1;
  val1.name() = "test";
  val1.description() = LocalizedText{"en", "test"};
  val1.reserved() = true;
  val1.starting_bit_position() = 123456;
  val1.ending_bit_position() = 123456;
  const BitFieldDefinition& const_val = val1;
  val1.name();
  const_val.name();
  val1.description();
  const_val.description();
  val1.reserved();
  const_val.reserved();
  val1.starting_bit_position();
  const_val.starting_bit_position();
  val1.ending_bit_position();
  const_val.ending_bit_position();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, RationalNumber_Structure)
{
  RationalNumber val1;
  val1.numerator() = 123456;
  val1.denominator() = 123456;
  const RationalNumber& const_val = val1;
  val1.numerator();
  const_val.numerator();
  val1.denominator();
  const_val.denominator();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, Vector_AbstractStructure)
{
  // Testing only metadata for abstract structures
  // we cannot instantiate them
}

TEST_F(GeneratedDataTypeTests, ThreeDVector_Structure)
{
  ThreeDVector val1;
  val1.x() = 1.5;
  val1.y() = 1.5;
  val1.z() = 1.5;
  const ThreeDVector& const_val = val1;
  val1.x();
  const_val.x();
  val1.y();
  const_val.y();
  val1.z();
  const_val.z();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, CartesianCoordinates_AbstractStructure)
{
  // Testing only metadata for abstract structures
  // we cannot instantiate them
}

TEST_F(GeneratedDataTypeTests, ThreeDCartesianCoordinates_Structure)
{
  ThreeDCartesianCoordinates val1;
  val1.x() = 1.5;
  val1.y() = 1.5;
  val1.z() = 1.5;
  const ThreeDCartesianCoordinates& const_val = val1;
  val1.x();
  const_val.x();
  val1.y();
  const_val.y();
  val1.z();
  const_val.z();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, Orientation_AbstractStructure)
{
  // Testing only metadata for abstract structures
  // we cannot instantiate them
}

TEST_F(GeneratedDataTypeTests, ThreeDOrientation_Structure)
{
  ThreeDOrientation val1;
  val1.a() = 1.5;
  val1.b() = 1.5;
  val1.c() = 1.5;
  const ThreeDOrientation& const_val = val1;
  val1.a();
  const_val.a();
  val1.b();
  const_val.b();
  val1.c();
  const_val.c();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, Frame_AbstractStructure)
{
  // Testing only metadata for abstract structures
  // we cannot instantiate them
}

TEST_F(GeneratedDataTypeTests, ThreeDFrame_Structure)
{
  ThreeDFrame val1;
  val1.cartesian_coordinates().x() = 1.5;
  val1.cartesian_coordinates().y() = 1.5;
  val1.cartesian_coordinates().z() = 1.5;
  val1.orientation().a() = 1.5;
  val1.orientation().b() = 1.5;
  val1.orientation().c() = 1.5;
  const ThreeDFrame& const_val = val1;
  val1.cartesian_coordinates();
  const_val.cartesian_coordinates();
  val1.orientation();
  const_val.orientation();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, OpenFileMode_Enumeration)
{
  OpenFileMode e{};
  e = OpenFileMode::Read;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Read");
  e = OpenFileMode::Write;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Write");
  e = OpenFileMode::EraseExisting;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "EraseExisting");
  e = OpenFileMode::Append;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Append");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<OpenFileMode>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<OpenFileMode>(-9999));
}

TEST_F(GeneratedDataTypeTests, IdentityCriteriaType_Enumeration)
{
  IdentityCriteriaType e{};
  e = IdentityCriteriaType::UserName;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "UserName");
  e = IdentityCriteriaType::Thumbprint;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Thumbprint");
  e = IdentityCriteriaType::Role;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Role");
  e = IdentityCriteriaType::GroupId;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "GroupId");
  e = IdentityCriteriaType::Anonymous;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Anonymous");
  e = IdentityCriteriaType::AuthenticatedUser;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "AuthenticatedUser");
  e = IdentityCriteriaType::Application;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Application");
  e = IdentityCriteriaType::X509Subject;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "X509Subject");
  e = IdentityCriteriaType::TrustedApplication;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "TrustedApplication");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<IdentityCriteriaType>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<IdentityCriteriaType>(-9999));
}

TEST_F(GeneratedDataTypeTests, IdentityMappingRuleType_Structure)
{
  IdentityMappingRuleType val1;
  val1.criteria_type() = IdentityCriteriaType::UserName;
  val1.criteria() = "test";
  const IdentityMappingRuleType& const_val = val1;
  val1.criteria_type();
  const_val.criteria_type();
  val1.criteria();
  const_val.criteria();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, CurrencyUnitType_Structure)
{
  CurrencyUnitType val1;
  val1.numeric_code() = 12345;
  val1.exponent() = 123;
  val1.alphabetic_code() = "test";
  val1.currency() = LocalizedText{"en", "test"};
  const CurrencyUnitType& const_val = val1;
  val1.numeric_code();
  const_val.numeric_code();
  val1.exponent();
  const_val.exponent();
  val1.alphabetic_code();
  const_val.alphabetic_code();
  val1.currency();
  const_val.currency();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, AnnotationDataType_Structure)
{
  AnnotationDataType val1;
  val1.annotation() = "test";
  val1.discipline() = "test";
  val1.uri() = "test";
  const AnnotationDataType& const_val = val1;
  val1.annotation();
  const_val.annotation();
  val1.discipline();
  const_val.discipline();
  val1.uri();
  const_val.uri();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, LinearConversionDataType_Structure)
{
  LinearConversionDataType val1;
  val1.initial_addend() = 1.5f;
  val1.multiplicand() = 1.5f;
  val1.divisor() = 1.5f;
  val1.final_addend() = 1.5f;
  const LinearConversionDataType& const_val = val1;
  val1.initial_addend();
  const_val.initial_addend();
  val1.multiplicand();
  const_val.multiplicand();
  val1.divisor();
  const_val.divisor();
  val1.final_addend();
  const_val.final_addend();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ConversionLimitEnum_Enumeration)
{
  ConversionLimitEnum e{};
  e = ConversionLimitEnum::NoConversion;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "NoConversion");
  e = ConversionLimitEnum::Limited;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Limited");
  e = ConversionLimitEnum::Unlimited;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Unlimited");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<ConversionLimitEnum>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<ConversionLimitEnum>(-9999));
}

TEST_F(GeneratedDataTypeTests, QuantityDimension_Structure)
{
  QuantityDimension val1;
  val1.mass_exponent() = 123;
  val1.length_exponent() = 123;
  val1.time_exponent() = 123;
  val1.electric_current_exponent() = 123;
  val1.amount_of_substance_exponent() = 123;
  val1.luminous_intensity_exponent() = 123;
  val1.absolute_temperature_exponent() = 123;
  val1.dimensionless_exponent() = 123;
  const QuantityDimension& const_val = val1;
  val1.mass_exponent();
  const_val.mass_exponent();
  val1.length_exponent();
  const_val.length_exponent();
  val1.time_exponent();
  const_val.time_exponent();
  val1.electric_current_exponent();
  const_val.electric_current_exponent();
  val1.amount_of_substance_exponent();
  const_val.amount_of_substance_exponent();
  val1.luminous_intensity_exponent();
  const_val.luminous_intensity_exponent();
  val1.absolute_temperature_exponent();
  const_val.absolute_temperature_exponent();
  val1.dimensionless_exponent();
  const_val.dimensionless_exponent();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, AlarmMask_OptionSet)
{
  AlarmMask o;
  auto default_str = to_string(o);
  EXPECT_NE(default_str.find("AlarmMask"), std::string::npos);
  o.set(AlarmMask::Bit::Active);
  EXPECT_TRUE(o.test(AlarmMask::Bit::Active));
  EXPECT_NE(to_string(o).find("Active"), std::string::npos);
  o.set(AlarmMask::Bit::Unacknowledged);
  EXPECT_TRUE(o.test(AlarmMask::Bit::Unacknowledged));
  EXPECT_NE(to_string(o).find("Unacknowledged"), std::string::npos);
  o.set(AlarmMask::Bit::Unconfirmed);
  EXPECT_TRUE(o.test(AlarmMask::Bit::Unconfirmed));
  EXPECT_NE(to_string(o).find("Unconfirmed"), std::string::npos);
  auto all_set_str = to_string(o);
  EXPECT_NE(all_set_str.find("Active"), std::string::npos);
  EXPECT_NE(all_set_str.find("Unacknowledged"), std::string::npos);
  EXPECT_NE(all_set_str.find("Unconfirmed"), std::string::npos);
  o.reset(AlarmMask::Bit::Active);
  EXPECT_FALSE(o.test(AlarmMask::Bit::Active));
  o.reset(AlarmMask::Bit::Unacknowledged);
  EXPECT_FALSE(o.test(AlarmMask::Bit::Unacknowledged));
  o.reset(AlarmMask::Bit::Unconfirmed);
  EXPECT_FALSE(o.test(AlarmMask::Bit::Unconfirmed));
  auto u = o.as_underlying_type();
  o.from_underlying_type(u);
  EXPECT_EQ(o.as_underlying_type(), u);
}

TEST_F(GeneratedDataTypeTests, TrustListValidationOptions_OptionSet)
{
  TrustListValidationOptions o;
  auto default_str = to_string(o);
  EXPECT_NE(default_str.find("TrustListValidationOptions"), std::string::npos);
  o.set(TrustListValidationOptions::Bit::SuppressCertificateExpired);
  EXPECT_TRUE(o.test(TrustListValidationOptions::Bit::SuppressCertificateExpired));
  EXPECT_NE(to_string(o).find("SuppressCertificateExpired"), std::string::npos);
  o.set(TrustListValidationOptions::Bit::SuppressHostNameInvalid);
  EXPECT_TRUE(o.test(TrustListValidationOptions::Bit::SuppressHostNameInvalid));
  EXPECT_NE(to_string(o).find("SuppressHostNameInvalid"), std::string::npos);
  o.set(TrustListValidationOptions::Bit::SuppressRevocationStatusUnknown);
  EXPECT_TRUE(o.test(TrustListValidationOptions::Bit::SuppressRevocationStatusUnknown));
  EXPECT_NE(to_string(o).find("SuppressRevocationStatusUnknown"), std::string::npos);
  o.set(TrustListValidationOptions::Bit::SuppressIssuerCertificateExpired);
  EXPECT_TRUE(o.test(TrustListValidationOptions::Bit::SuppressIssuerCertificateExpired));
  EXPECT_NE(to_string(o).find("SuppressIssuerCertificateExpired"), std::string::npos);
  o.set(TrustListValidationOptions::Bit::SuppressIssuerRevocationStatusUnknown);
  EXPECT_TRUE(o.test(TrustListValidationOptions::Bit::SuppressIssuerRevocationStatusUnknown));
  EXPECT_NE(to_string(o).find("SuppressIssuerRevocationStatusUnknown"), std::string::npos);
  o.set(TrustListValidationOptions::Bit::CheckRevocationStatusOnline);
  EXPECT_TRUE(o.test(TrustListValidationOptions::Bit::CheckRevocationStatusOnline));
  EXPECT_NE(to_string(o).find("CheckRevocationStatusOnline"), std::string::npos);
  o.set(TrustListValidationOptions::Bit::CheckRevocationStatusOffline);
  EXPECT_TRUE(o.test(TrustListValidationOptions::Bit::CheckRevocationStatusOffline));
  EXPECT_NE(to_string(o).find("CheckRevocationStatusOffline"), std::string::npos);
  auto all_set_str = to_string(o);
  EXPECT_NE(all_set_str.find("SuppressCertificateExpired"), std::string::npos);
  EXPECT_NE(all_set_str.find("SuppressHostNameInvalid"), std::string::npos);
  EXPECT_NE(all_set_str.find("SuppressRevocationStatusUnknown"), std::string::npos);
  EXPECT_NE(all_set_str.find("SuppressIssuerCertificateExpired"), std::string::npos);
  EXPECT_NE(all_set_str.find("SuppressIssuerRevocationStatusUnknown"), std::string::npos);
  EXPECT_NE(all_set_str.find("CheckRevocationStatusOnline"), std::string::npos);
  EXPECT_NE(all_set_str.find("CheckRevocationStatusOffline"), std::string::npos);
  o.reset(TrustListValidationOptions::Bit::SuppressCertificateExpired);
  EXPECT_FALSE(o.test(TrustListValidationOptions::Bit::SuppressCertificateExpired));
  o.reset(TrustListValidationOptions::Bit::SuppressHostNameInvalid);
  EXPECT_FALSE(o.test(TrustListValidationOptions::Bit::SuppressHostNameInvalid));
  o.reset(TrustListValidationOptions::Bit::SuppressRevocationStatusUnknown);
  EXPECT_FALSE(o.test(TrustListValidationOptions::Bit::SuppressRevocationStatusUnknown));
  o.reset(TrustListValidationOptions::Bit::SuppressIssuerCertificateExpired);
  EXPECT_FALSE(o.test(TrustListValidationOptions::Bit::SuppressIssuerCertificateExpired));
  o.reset(TrustListValidationOptions::Bit::SuppressIssuerRevocationStatusUnknown);
  EXPECT_FALSE(o.test(TrustListValidationOptions::Bit::SuppressIssuerRevocationStatusUnknown));
  o.reset(TrustListValidationOptions::Bit::CheckRevocationStatusOnline);
  EXPECT_FALSE(o.test(TrustListValidationOptions::Bit::CheckRevocationStatusOnline));
  o.reset(TrustListValidationOptions::Bit::CheckRevocationStatusOffline);
  EXPECT_FALSE(o.test(TrustListValidationOptions::Bit::CheckRevocationStatusOffline));
  auto u = o.as_underlying_type();
  o.from_underlying_type(u);
  EXPECT_EQ(o.as_underlying_type(), u);
}

TEST_F(GeneratedDataTypeTests, TrustListMasks_Enumeration)
{
  TrustListMasks e{};
  e = TrustListMasks::None;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "None");
  e = TrustListMasks::TrustedCertificates;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "TrustedCertificates");
  e = TrustListMasks::TrustedCrls;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "TrustedCrls");
  e = TrustListMasks::IssuerCertificates;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "IssuerCertificates");
  e = TrustListMasks::IssuerCrls;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "IssuerCrls");
  e = TrustListMasks::All;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "All");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<TrustListMasks>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<TrustListMasks>(-9999));
}

TEST_F(GeneratedDataTypeTests, TrustListDataType_Structure)
{
  TrustListDataType val1;
  val1.specified_lists() = 123456;
  val1.trusted_certificates().resize(2);
  val1.trusted_certificates()[0] = ByteString{1, 2, 3};
  val1.trusted_crls().resize(2);
  val1.trusted_crls()[0] = ByteString{1, 2, 3};
  val1.issuer_certificates().resize(2);
  val1.issuer_certificates()[0] = ByteString{1, 2, 3};
  val1.issuer_crls().resize(2);
  val1.issuer_crls()[0] = ByteString{1, 2, 3};
  const TrustListDataType& const_val = val1;
  val1.specified_lists();
  const_val.specified_lists();
  val1.trusted_certificates();
  const_val.trusted_certificates();
  val1.trusted_crls();
  const_val.trusted_crls();
  val1.issuer_certificates();
  const_val.issuer_certificates();
  val1.issuer_crls();
  const_val.issuer_crls();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, BaseConfigurationDataType_AbstractStructure)
{
  // Testing only metadata for abstract structures
  // we cannot instantiate them
}

TEST_F(GeneratedDataTypeTests, BaseConfigurationRecordDataType_AbstractStructure)
{
  // Testing only metadata for abstract structures
  // we cannot instantiate them
}

TEST_F(GeneratedDataTypeTests, CertificateGroupDataType_Structure)
{
  CertificateGroupDataType val1;
  val1.purpose() = NodeId{1234};
  val1.certificate_types().resize(2);
  val1.certificate_types()[0] = NodeId{1234};
  val1.is_certificate_assigned().resize(2);
  val1.is_certificate_assigned()[0] = true;
  val1.validation_options().set(TrustListValidationOptions::Bit::SuppressCertificateExpired);
  const CertificateGroupDataType& const_val = val1;
  val1.purpose();
  const_val.purpose();
  val1.certificate_types();
  const_val.certificate_types();
  val1.is_certificate_assigned();
  const_val.is_certificate_assigned();
  val1.validation_options();
  const_val.validation_options();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ConfigurationUpdateTargetType_Structure)
{
  ConfigurationUpdateTargetType val1;
  val1.path() = "test";
  val1.update_type() = ConfigurationUpdateType::Insert;
  const ConfigurationUpdateTargetType& const_val = val1;
  val1.path();
  const_val.path();
  val1.update_type();
  const_val.update_type();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ConfigurationUpdateType_Enumeration)
{
  ConfigurationUpdateType e{};
  e = ConfigurationUpdateType::Insert;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Insert");
  e = ConfigurationUpdateType::Replace;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Replace");
  e = ConfigurationUpdateType::InsertOrReplace;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "InsertOrReplace");
  e = ConfigurationUpdateType::Delete;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Delete");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<ConfigurationUpdateType>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<ConfigurationUpdateType>(-9999));
}

TEST_F(GeneratedDataTypeTests, TransactionErrorType_Structure)
{
  TransactionErrorType val1;
  val1.target_id() = NodeId{1234};
  val1.error() = Status::Good;
  val1.message() = LocalizedText{"en", "test"};
  const TransactionErrorType& const_val = val1;
  val1.target_id();
  const_val.target_id();
  val1.error();
  const_val.error();
  val1.message();
  const_val.message();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ApplicationConfigurationDataType_Structure)
{
  ApplicationConfigurationDataType val1;
  val1.application_identity().application_uri() = "test";
  val1.application_identity().application_names().resize(2);
  val1.application_identity().application_names()[0] = LocalizedText{"en", "test"};
  val1.application_identity().additional_servers().resize(2);
  val1.application_identity().additional_servers()[0].application_uri() = "test";
  val1.application_identity().additional_servers()[0].product_uri() = "test";
  val1.application_identity().additional_servers()[0].application_name() = LocalizedText{"en", "test"};
  val1.application_identity().additional_servers()[0].application_type() = ApplicationType::Server;
  val1.application_identity().additional_servers()[0].gateway_server_uri() = "test";
  val1.application_identity().additional_servers()[0].discovery_profile_uri() = "test";
  val1.application_identity().additional_servers()[0].discovery_urls().resize(2);
  val1.application_identity().additional_servers()[0].discovery_urls()[0] = "test";
  val1.certificate_groups().resize(2);
  val1.certificate_groups()[0].purpose() = NodeId{1234};
  val1.certificate_groups()[0].certificate_types().resize(2);
  val1.certificate_groups()[0].certificate_types()[0] = NodeId{1234};
  val1.certificate_groups()[0].is_certificate_assigned().resize(2);
  val1.certificate_groups()[0].is_certificate_assigned()[0] = true;
  val1.certificate_groups()[0].validation_options().set(
    TrustListValidationOptions::Bit::SuppressCertificateExpired);
  val1.server_endpoints().resize(2);
  val1.server_endpoints()[0].endpoint_urls().resize(2);
  val1.server_endpoints()[0].endpoint_urls()[0] = "test";
  val1.server_endpoints()[0].security_setting_names().resize(2);
  val1.server_endpoints()[0].security_setting_names()[0] = "test";
  val1.server_endpoints()[0].transport_profile_uri() = "test";
  val1.server_endpoints()[0].user_token_setting_names().resize(2);
  val1.server_endpoints()[0].user_token_setting_names()[0] = "test";
  val1.server_endpoints()[0].reverse_connect_urls().resize(2);
  val1.server_endpoints()[0].reverse_connect_urls()[0] = "test";
  val1.client_endpoints().resize(2);
  val1.client_endpoints()[0].discovery_urls().resize(2);
  val1.client_endpoints()[0].discovery_urls()[0] = "test";
  val1.client_endpoints()[0].network_name() = "test";
  val1.client_endpoints()[0].port() = 12345;
  val1.security_settings().resize(2);
  val1.security_settings()[0].security_modes().resize(2);
  val1.security_settings()[0].security_modes()[0] = MessageSecurityMode::Invalid;
  val1.security_settings()[0].security_policy_uris().resize(2);
  val1.security_settings()[0].security_policy_uris()[0] = "test";
  val1.security_settings()[0].certificate_group_name() = "test";
  val1.user_token_settings().resize(2);
  val1.user_token_settings()[0].token_type() = UserTokenType::Anonymous;
  val1.user_token_settings()[0].issued_token_type() = "test";
  val1.user_token_settings()[0].issuer_endpoint_url() = "test";
  val1.user_token_settings()[0].security_policy_uri() = "test";
  val1.user_token_settings()[0].certificate_group_name() = "test";
  val1.user_token_settings()[0].authorization_service_name() = "test";
  val1.authorization_services().resize(2);
  val1.authorization_services()[0].service_uri() = "test";
  val1.authorization_services()[0].service_certificates().resize(2);
  val1.authorization_services()[0].service_certificates()[0].certificate() = ByteString{1, 2, 3};
  val1.authorization_services()[0].service_certificates()[0].issuers().resize(2);
  val1.authorization_services()[0].service_certificates()[0].issuers()[0] = ByteString{1, 2, 3};
  val1.authorization_services()[0].service_certificates()[0].valid_from() = DateTime::now();
  val1.authorization_services()[0].service_certificates()[0].valid_to() = DateTime::now();
  val1.authorization_services()[0].issuer_endpoint_settings() = "test";
  const ApplicationConfigurationDataType& const_val = val1;
  val1.application_identity();
  const_val.application_identity();
  val1.certificate_groups();
  const_val.certificate_groups();
  val1.server_endpoints();
  const_val.server_endpoints();
  val1.client_endpoints();
  const_val.client_endpoints();
  val1.security_settings();
  const_val.security_settings();
  val1.user_token_settings();
  const_val.user_token_settings();
  val1.authorization_services();
  const_val.authorization_services();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ApplicationIdentityDataType_Structure)
{
  ApplicationIdentityDataType val1;
  val1.application_uri() = "test";
  val1.application_names().resize(2);
  val1.application_names()[0] = LocalizedText{"en", "test"};
  val1.additional_servers().resize(2);
  val1.additional_servers()[0].application_uri() = "test";
  val1.additional_servers()[0].product_uri() = "test";
  val1.additional_servers()[0].application_name() = LocalizedText{"en", "test"};
  val1.additional_servers()[0].application_type() = ApplicationType::Server;
  val1.additional_servers()[0].gateway_server_uri() = "test";
  val1.additional_servers()[0].discovery_profile_uri() = "test";
  val1.additional_servers()[0].discovery_urls().resize(2);
  val1.additional_servers()[0].discovery_urls()[0] = "test";
  const ApplicationIdentityDataType& const_val = val1;
  val1.application_uri();
  const_val.application_uri();
  val1.application_names();
  const_val.application_names();
  val1.additional_servers();
  const_val.additional_servers();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, EndpointDataType_Structure)
{
  EndpointDataType val1;
  val1.discovery_urls().resize(2);
  val1.discovery_urls()[0] = "test";
  val1.network_name() = "test";
  val1.port() = 12345;
  const EndpointDataType& const_val = val1;
  val1.discovery_urls();
  const_val.discovery_urls();
  val1.network_name();
  const_val.network_name();
  val1.port();
  const_val.port();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ServerEndpointDataType_Structure)
{
  ServerEndpointDataType val1;
  val1.endpoint_urls().resize(2);
  val1.endpoint_urls()[0] = "test";
  val1.security_setting_names().resize(2);
  val1.security_setting_names()[0] = "test";
  val1.transport_profile_uri() = "test";
  val1.user_token_setting_names().resize(2);
  val1.user_token_setting_names()[0] = "test";
  val1.reverse_connect_urls().resize(2);
  val1.reverse_connect_urls()[0] = "test";
  const ServerEndpointDataType& const_val = val1;
  val1.endpoint_urls();
  const_val.endpoint_urls();
  val1.security_setting_names();
  const_val.security_setting_names();
  val1.transport_profile_uri();
  const_val.transport_profile_uri();
  val1.user_token_setting_names();
  const_val.user_token_setting_names();
  val1.reverse_connect_urls();
  const_val.reverse_connect_urls();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, SecuritySettingsDataType_Structure)
{
  SecuritySettingsDataType val1;
  val1.security_modes().resize(2);
  val1.security_modes()[0] = MessageSecurityMode::Invalid;
  val1.security_policy_uris().resize(2);
  val1.security_policy_uris()[0] = "test";
  val1.certificate_group_name() = "test";
  const SecuritySettingsDataType& const_val = val1;
  val1.security_modes();
  const_val.security_modes();
  val1.security_policy_uris();
  const_val.security_policy_uris();
  val1.certificate_group_name();
  const_val.certificate_group_name();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, UserTokenSettingsDataType_Structure)
{
  UserTokenSettingsDataType val1;
  val1.token_type() = UserTokenType::Anonymous;
  val1.issued_token_type() = "test";
  val1.issuer_endpoint_url() = "test";
  val1.security_policy_uri() = "test";
  val1.certificate_group_name() = "test";
  val1.authorization_service_name() = "test";
  const UserTokenSettingsDataType& const_val = val1;
  val1.token_type();
  const_val.token_type();
  val1.issued_token_type();
  const_val.issued_token_type();
  val1.issuer_endpoint_url();
  const_val.issuer_endpoint_url();
  val1.security_policy_uri();
  const_val.security_policy_uri();
  val1.certificate_group_name();
  const_val.certificate_group_name();
  val1.authorization_service_name();
  const_val.authorization_service_name();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ServiceCertificateDataType_Structure)
{
  ServiceCertificateDataType val1;
  val1.certificate() = ByteString{1, 2, 3};
  val1.issuers().resize(2);
  val1.issuers()[0] = ByteString{1, 2, 3};
  val1.valid_from() = DateTime::now();
  val1.valid_to() = DateTime::now();
  const ServiceCertificateDataType& const_val = val1;
  val1.certificate();
  const_val.certificate();
  val1.issuers();
  const_val.issuers();
  val1.valid_from();
  const_val.valid_from();
  val1.valid_to();
  const_val.valid_to();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, AuthorizationServiceConfigurationDataType_Structure)
{
  AuthorizationServiceConfigurationDataType val1;
  val1.service_uri() = "test";
  val1.service_certificates().resize(2);
  val1.service_certificates()[0].certificate() = ByteString{1, 2, 3};
  val1.service_certificates()[0].issuers().resize(2);
  val1.service_certificates()[0].issuers()[0] = ByteString{1, 2, 3};
  val1.service_certificates()[0].valid_from() = DateTime::now();
  val1.service_certificates()[0].valid_to() = DateTime::now();
  val1.issuer_endpoint_settings() = "test";
  const AuthorizationServiceConfigurationDataType& const_val = val1;
  val1.service_uri();
  const_val.service_uri();
  val1.service_certificates();
  const_val.service_certificates();
  val1.issuer_endpoint_settings();
  const_val.issuer_endpoint_settings();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, DataTypeSchemaHeader_AbstractStructure)
{
  // Testing only metadata for abstract structures
  // we cannot instantiate them
}

TEST_F(GeneratedDataTypeTests, DataTypeDescription_AbstractStructure)
{
  // Testing only metadata for abstract structures
  // we cannot instantiate them
}

TEST_F(GeneratedDataTypeTests, StructureDescription_Structure)
{
  StructureDescription val1;
  val1.structure_definition().default_encoding_id() = NodeId{1234};
  val1.structure_definition().base_data_type() = NodeId{1234};
  val1.structure_definition().structure_type() = StructureType::Structure;
  val1.structure_definition().fields().resize(2);
  val1.structure_definition().fields()[0].name() = "test";
  val1.structure_definition().fields()[0].description() = LocalizedText{"en", "test"};
  val1.structure_definition().fields()[0].data_type() = NodeId{1234};
  val1.structure_definition().fields()[0].value_rank() = 123456;
  val1.structure_definition().fields()[0].array_dimensions().resize(2);
  val1.structure_definition().fields()[0].array_dimensions()[0] = 123456;
  val1.structure_definition().fields()[0].max_string_length() = 123456;
  val1.structure_definition().fields()[0].is_optional() = true;
  const StructureDescription& const_val = val1;
  val1.structure_definition();
  const_val.structure_definition();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, EnumDescription_Structure)
{
  EnumDescription val1;
  val1.enum_definition().fields().resize(2);
  val1.enum_definition().fields()[0].name() = "test";
  val1.built_in_type() = 123;
  const EnumDescription& const_val = val1;
  val1.enum_definition();
  const_val.enum_definition();
  val1.built_in_type();
  const_val.built_in_type();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, SimpleTypeDescription_Structure)
{
  SimpleTypeDescription val1;
  val1.base_data_type() = NodeId{1234};
  val1.built_in_type() = 123;
  const SimpleTypeDescription& const_val = val1;
  val1.base_data_type();
  const_val.base_data_type();
  val1.built_in_type();
  const_val.built_in_type();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, UABinaryFileDataType_Structure)
{
  UABinaryFileDataType val1;
  val1.schema_location() = "test";
  val1.file_header().resize(2);
  val1.file_header()[0].key() = QualifiedName{"test"};
  val1.file_header()[0].value() = Variant{123};
  val1.body() = Variant{123};
  const UABinaryFileDataType& const_val = val1;
  val1.schema_location();
  const_val.schema_location();
  val1.file_header();
  const_val.file_header();
  val1.body();
  const_val.body();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, PortableQualifiedName_Structure)
{
  PortableQualifiedName val1;
  val1.namespace_uri() = "test";
  val1.name() = "test";
  const PortableQualifiedName& const_val = val1;
  val1.namespace_uri();
  const_val.namespace_uri();
  val1.name();
  const_val.name();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, PortableNodeId_Structure)
{
  PortableNodeId val1;
  val1.namespace_uri() = "test";
  val1.identifier() = NodeId{1234};
  const PortableNodeId& const_val = val1;
  val1.namespace_uri();
  const_val.namespace_uri();
  val1.identifier();
  const_val.identifier();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, UnsignedRationalNumber_Structure)
{
  UnsignedRationalNumber val1;
  val1.numerator() = 123456;
  val1.denominator() = 123456;
  const UnsignedRationalNumber& const_val = val1;
  val1.numerator();
  const_val.numerator();
  val1.denominator();
  const_val.denominator();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, DiagnosticsLevel_Enumeration)
{
  DiagnosticsLevel e{};
  e = DiagnosticsLevel::Basic;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Basic");
  e = DiagnosticsLevel::Advanced;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Advanced");
  e = DiagnosticsLevel::Info;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Info");
  e = DiagnosticsLevel::Log;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Log");
  e = DiagnosticsLevel::Debug;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Debug");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<DiagnosticsLevel>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<DiagnosticsLevel>(-9999));
}

TEST_F(GeneratedDataTypeTests, PubSubDiagnosticsCounterClassification_Enumeration)
{
  PubSubDiagnosticsCounterClassification e{};
  e = PubSubDiagnosticsCounterClassification::Information;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Information");
  e = PubSubDiagnosticsCounterClassification::Error;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Error");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<PubSubDiagnosticsCounterClassification>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<PubSubDiagnosticsCounterClassification>(-9999));
}

TEST_F(GeneratedDataTypeTests, AliasNameDataType_Structure)
{
  AliasNameDataType val1;
  val1.alias_name() = QualifiedName{"test"};
  val1.referenced_nodes().resize(2);
  val1.referenced_nodes()[0] = ExpandedNodeId{NodeId{1234}};
  const AliasNameDataType& const_val = val1;
  val1.alias_name();
  const_val.alias_name();
  val1.referenced_nodes();
  const_val.referenced_nodes();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, PasswordOptionsMask_OptionSet)
{
  PasswordOptionsMask o;
  auto default_str = to_string(o);
  EXPECT_NE(default_str.find("PasswordOptionsMask"), std::string::npos);
  o.set(PasswordOptionsMask::Bit::SupportInitialPasswordChange);
  EXPECT_TRUE(o.test(PasswordOptionsMask::Bit::SupportInitialPasswordChange));
  EXPECT_NE(to_string(o).find("SupportInitialPasswordChange"), std::string::npos);
  o.set(PasswordOptionsMask::Bit::SupportDisableUser);
  EXPECT_TRUE(o.test(PasswordOptionsMask::Bit::SupportDisableUser));
  EXPECT_NE(to_string(o).find("SupportDisableUser"), std::string::npos);
  o.set(PasswordOptionsMask::Bit::SupportDisableDeleteForUser);
  EXPECT_TRUE(o.test(PasswordOptionsMask::Bit::SupportDisableDeleteForUser));
  EXPECT_NE(to_string(o).find("SupportDisableDeleteForUser"), std::string::npos);
  o.set(PasswordOptionsMask::Bit::SupportNoChangeForUser);
  EXPECT_TRUE(o.test(PasswordOptionsMask::Bit::SupportNoChangeForUser));
  EXPECT_NE(to_string(o).find("SupportNoChangeForUser"), std::string::npos);
  o.set(PasswordOptionsMask::Bit::SupportDescriptionForUser);
  EXPECT_TRUE(o.test(PasswordOptionsMask::Bit::SupportDescriptionForUser));
  EXPECT_NE(to_string(o).find("SupportDescriptionForUser"), std::string::npos);
  o.set(PasswordOptionsMask::Bit::RequiresUpperCaseCharacters);
  EXPECT_TRUE(o.test(PasswordOptionsMask::Bit::RequiresUpperCaseCharacters));
  EXPECT_NE(to_string(o).find("RequiresUpperCaseCharacters"), std::string::npos);
  o.set(PasswordOptionsMask::Bit::RequiresLowerCaseCharacters);
  EXPECT_TRUE(o.test(PasswordOptionsMask::Bit::RequiresLowerCaseCharacters));
  EXPECT_NE(to_string(o).find("RequiresLowerCaseCharacters"), std::string::npos);
  o.set(PasswordOptionsMask::Bit::RequiresDigitCharacters);
  EXPECT_TRUE(o.test(PasswordOptionsMask::Bit::RequiresDigitCharacters));
  EXPECT_NE(to_string(o).find("RequiresDigitCharacters"), std::string::npos);
  o.set(PasswordOptionsMask::Bit::RequiresSpecialCharacters);
  EXPECT_TRUE(o.test(PasswordOptionsMask::Bit::RequiresSpecialCharacters));
  EXPECT_NE(to_string(o).find("RequiresSpecialCharacters"), std::string::npos);
  auto all_set_str = to_string(o);
  EXPECT_NE(all_set_str.find("SupportInitialPasswordChange"), std::string::npos);
  EXPECT_NE(all_set_str.find("SupportDisableUser"), std::string::npos);
  EXPECT_NE(all_set_str.find("SupportDisableDeleteForUser"), std::string::npos);
  EXPECT_NE(all_set_str.find("SupportNoChangeForUser"), std::string::npos);
  EXPECT_NE(all_set_str.find("SupportDescriptionForUser"), std::string::npos);
  EXPECT_NE(all_set_str.find("RequiresUpperCaseCharacters"), std::string::npos);
  EXPECT_NE(all_set_str.find("RequiresLowerCaseCharacters"), std::string::npos);
  EXPECT_NE(all_set_str.find("RequiresDigitCharacters"), std::string::npos);
  EXPECT_NE(all_set_str.find("RequiresSpecialCharacters"), std::string::npos);
  o.reset(PasswordOptionsMask::Bit::SupportInitialPasswordChange);
  EXPECT_FALSE(o.test(PasswordOptionsMask::Bit::SupportInitialPasswordChange));
  o.reset(PasswordOptionsMask::Bit::SupportDisableUser);
  EXPECT_FALSE(o.test(PasswordOptionsMask::Bit::SupportDisableUser));
  o.reset(PasswordOptionsMask::Bit::SupportDisableDeleteForUser);
  EXPECT_FALSE(o.test(PasswordOptionsMask::Bit::SupportDisableDeleteForUser));
  o.reset(PasswordOptionsMask::Bit::SupportNoChangeForUser);
  EXPECT_FALSE(o.test(PasswordOptionsMask::Bit::SupportNoChangeForUser));
  o.reset(PasswordOptionsMask::Bit::SupportDescriptionForUser);
  EXPECT_FALSE(o.test(PasswordOptionsMask::Bit::SupportDescriptionForUser));
  o.reset(PasswordOptionsMask::Bit::RequiresUpperCaseCharacters);
  EXPECT_FALSE(o.test(PasswordOptionsMask::Bit::RequiresUpperCaseCharacters));
  o.reset(PasswordOptionsMask::Bit::RequiresLowerCaseCharacters);
  EXPECT_FALSE(o.test(PasswordOptionsMask::Bit::RequiresLowerCaseCharacters));
  o.reset(PasswordOptionsMask::Bit::RequiresDigitCharacters);
  EXPECT_FALSE(o.test(PasswordOptionsMask::Bit::RequiresDigitCharacters));
  o.reset(PasswordOptionsMask::Bit::RequiresSpecialCharacters);
  EXPECT_FALSE(o.test(PasswordOptionsMask::Bit::RequiresSpecialCharacters));
  auto u = o.as_underlying_type();
  o.from_underlying_type(u);
  EXPECT_EQ(o.as_underlying_type(), u);
}

TEST_F(GeneratedDataTypeTests, UserConfigurationMask_OptionSet)
{
  UserConfigurationMask o;
  auto default_str = to_string(o);
  EXPECT_NE(default_str.find("UserConfigurationMask"), std::string::npos);
  o.set(UserConfigurationMask::Bit::NoDelete);
  EXPECT_TRUE(o.test(UserConfigurationMask::Bit::NoDelete));
  EXPECT_NE(to_string(o).find("NoDelete"), std::string::npos);
  o.set(UserConfigurationMask::Bit::Disabled);
  EXPECT_TRUE(o.test(UserConfigurationMask::Bit::Disabled));
  EXPECT_NE(to_string(o).find("Disabled"), std::string::npos);
  o.set(UserConfigurationMask::Bit::NoChangeByUser);
  EXPECT_TRUE(o.test(UserConfigurationMask::Bit::NoChangeByUser));
  EXPECT_NE(to_string(o).find("NoChangeByUser"), std::string::npos);
  o.set(UserConfigurationMask::Bit::MustChangePassword);
  EXPECT_TRUE(o.test(UserConfigurationMask::Bit::MustChangePassword));
  EXPECT_NE(to_string(o).find("MustChangePassword"), std::string::npos);
  auto all_set_str = to_string(o);
  EXPECT_NE(all_set_str.find("NoDelete"), std::string::npos);
  EXPECT_NE(all_set_str.find("Disabled"), std::string::npos);
  EXPECT_NE(all_set_str.find("NoChangeByUser"), std::string::npos);
  EXPECT_NE(all_set_str.find("MustChangePassword"), std::string::npos);
  o.reset(UserConfigurationMask::Bit::NoDelete);
  EXPECT_FALSE(o.test(UserConfigurationMask::Bit::NoDelete));
  o.reset(UserConfigurationMask::Bit::Disabled);
  EXPECT_FALSE(o.test(UserConfigurationMask::Bit::Disabled));
  o.reset(UserConfigurationMask::Bit::NoChangeByUser);
  EXPECT_FALSE(o.test(UserConfigurationMask::Bit::NoChangeByUser));
  o.reset(UserConfigurationMask::Bit::MustChangePassword);
  EXPECT_FALSE(o.test(UserConfigurationMask::Bit::MustChangePassword));
  auto u = o.as_underlying_type();
  o.from_underlying_type(u);
  EXPECT_EQ(o.as_underlying_type(), u);
}

TEST_F(GeneratedDataTypeTests, UserManagementDataType_Structure)
{
  UserManagementDataType val1;
  val1.user_name() = "test";
  val1.user_configuration().set(UserConfigurationMask::Bit::NoDelete);
  val1.description() = "test";
  const UserManagementDataType& const_val = val1;
  val1.user_name();
  const_val.user_name();
  val1.user_configuration();
  const_val.user_configuration();
  val1.description();
  const_val.description();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, EncodedTicket_SimpleType)
{
  EncodedTicket val1{};
  EncodedTicket val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, Duplex_Enumeration)
{
  Duplex e{};
  e = Duplex::Full;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Full");
  e = Duplex::Half;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Half");
  e = Duplex::Unknown;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Unknown");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<Duplex>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<Duplex>(-9999));
}

TEST_F(GeneratedDataTypeTests, InterfaceAdminStatus_Enumeration)
{
  InterfaceAdminStatus e{};
  e = InterfaceAdminStatus::Up;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Up");
  e = InterfaceAdminStatus::Down;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Down");
  e = InterfaceAdminStatus::Testing;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Testing");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<InterfaceAdminStatus>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<InterfaceAdminStatus>(-9999));
}

TEST_F(GeneratedDataTypeTests, InterfaceOperStatus_Enumeration)
{
  InterfaceOperStatus e{};
  e = InterfaceOperStatus::Up;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Up");
  e = InterfaceOperStatus::Down;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Down");
  e = InterfaceOperStatus::Testing;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Testing");
  e = InterfaceOperStatus::Unknown;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Unknown");
  e = InterfaceOperStatus::Dormant;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Dormant");
  e = InterfaceOperStatus::NotPresent;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "NotPresent");
  e = InterfaceOperStatus::LowerLayerDown;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "LowerLayerDown");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<InterfaceOperStatus>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<InterfaceOperStatus>(-9999));
}

TEST_F(GeneratedDataTypeTests, NegotiationStatus_Enumeration)
{
  NegotiationStatus e{};
  e = NegotiationStatus::InProgress;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "InProgress");
  e = NegotiationStatus::Complete;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Complete");
  e = NegotiationStatus::Failed;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Failed");
  e = NegotiationStatus::Unknown;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Unknown");
  e = NegotiationStatus::NoNegotiation;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "NoNegotiation");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<NegotiationStatus>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<NegotiationStatus>(-9999));
}

TEST_F(GeneratedDataTypeTests, TsnFailureCode_Enumeration)
{
  TsnFailureCode e{};
  e = TsnFailureCode::NoFailure;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "NoFailure");
  e = TsnFailureCode::InsufficientBandwidth;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "InsufficientBandwidth");
  e = TsnFailureCode::InsufficientResources;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "InsufficientResources");
  e = TsnFailureCode::InsufficientTrafficClassBandwidth;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "InsufficientTrafficClassBandwidth");
  e = TsnFailureCode::StreamIdInUse;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "StreamIdInUse");
  e = TsnFailureCode::StreamDestinationAddressInUse;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "StreamDestinationAddressInUse");
  e = TsnFailureCode::StreamPreemptedByHigherRank;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "StreamPreemptedByHigherRank");
  e = TsnFailureCode::LatencyHasChanged;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "LatencyHasChanged");
  e = TsnFailureCode::EgressPortNotAvbCapable;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "EgressPortNotAvbCapable");
  e = TsnFailureCode::UseDifferentDestinationAddress;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "UseDifferentDestinationAddress");
  e = TsnFailureCode::OutOfMsrpResources;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "OutOfMsrpResources");
  e = TsnFailureCode::OutOfMmrpResources;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "OutOfMmrpResources");
  e = TsnFailureCode::CannotStoreDestinationAddress;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "CannotStoreDestinationAddress");
  e = TsnFailureCode::PriorityIsNotAnSrcClass;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "PriorityIsNotAnSrcClass");
  e = TsnFailureCode::MaxFrameSizeTooLarge;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "MaxFrameSizeTooLarge");
  e = TsnFailureCode::MaxFanInPortsLimitReached;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "MaxFanInPortsLimitReached");
  e = TsnFailureCode::FirstValueChangedForStreamId;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "FirstValueChangedForStreamId");
  e = TsnFailureCode::VlanBlockedOnEgress;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "VlanBlockedOnEgress");
  e = TsnFailureCode::VlanTaggingDisabledOnEgress;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "VlanTaggingDisabledOnEgress");
  e = TsnFailureCode::SrClassPriorityMismatch;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "SrClassPriorityMismatch");
  e = TsnFailureCode::FeatureNotPropagated;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "FeatureNotPropagated");
  e = TsnFailureCode::MaxLatencyExceeded;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "MaxLatencyExceeded");
  e = TsnFailureCode::BridgeDoesNotProvideNetworkId;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "BridgeDoesNotProvideNetworkId");
  e = TsnFailureCode::StreamTransformNotSupported;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "StreamTransformNotSupported");
  e = TsnFailureCode::StreamIdTypeNotSupported;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "StreamIdTypeNotSupported");
  e = TsnFailureCode::FeatureNotSupported;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "FeatureNotSupported");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<TsnFailureCode>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<TsnFailureCode>(-9999));
}

TEST_F(GeneratedDataTypeTests, TsnStreamState_Enumeration)
{
  TsnStreamState e{};
  e = TsnStreamState::Disabled;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Disabled");
  e = TsnStreamState::Configuring;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Configuring");
  e = TsnStreamState::Ready;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Ready");
  e = TsnStreamState::Operational;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Operational");
  e = TsnStreamState::Error;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Error");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<TsnStreamState>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<TsnStreamState>(-9999));
}

TEST_F(GeneratedDataTypeTests, TsnTalkerStatus_Enumeration)
{
  TsnTalkerStatus e{};
  e = TsnTalkerStatus::None;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "None");
  e = TsnTalkerStatus::Ready;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Ready");
  e = TsnTalkerStatus::Failed;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Failed");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<TsnTalkerStatus>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<TsnTalkerStatus>(-9999));
}

TEST_F(GeneratedDataTypeTests, TsnListenerStatus_Enumeration)
{
  TsnListenerStatus e{};
  e = TsnListenerStatus::None;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "None");
  e = TsnListenerStatus::Ready;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Ready");
  e = TsnListenerStatus::PartialFailed;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "PartialFailed");
  e = TsnListenerStatus::Failed;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Failed");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<TsnListenerStatus>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<TsnListenerStatus>(-9999));
}

TEST_F(GeneratedDataTypeTests, ChassisIdSubtype_Enumeration)
{
  ChassisIdSubtype e{};
  e = ChassisIdSubtype::ChassisComponent;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "ChassisComponent");
  e = ChassisIdSubtype::InterfaceAlias;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "InterfaceAlias");
  e = ChassisIdSubtype::PortComponent;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "PortComponent");
  e = ChassisIdSubtype::MacAddress;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "MacAddress");
  e = ChassisIdSubtype::NetworkAddress;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "NetworkAddress");
  e = ChassisIdSubtype::InterfaceName;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "InterfaceName");
  e = ChassisIdSubtype::Local;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Local");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<ChassisIdSubtype>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<ChassisIdSubtype>(-9999));
}

TEST_F(GeneratedDataTypeTests, PortIdSubtype_Enumeration)
{
  PortIdSubtype e{};
  e = PortIdSubtype::InterfaceAlias;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "InterfaceAlias");
  e = PortIdSubtype::PortComponent;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "PortComponent");
  e = PortIdSubtype::MacAddress;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "MacAddress");
  e = PortIdSubtype::NetworkAddress;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "NetworkAddress");
  e = PortIdSubtype::InterfaceName;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "InterfaceName");
  e = PortIdSubtype::AgentCircuitId;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "AgentCircuitId");
  e = PortIdSubtype::Local;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Local");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<PortIdSubtype>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<PortIdSubtype>(-9999));
}

TEST_F(GeneratedDataTypeTests, ManAddrIfSubtype_Enumeration)
{
  ManAddrIfSubtype e{};
  e = ManAddrIfSubtype::None;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "None");
  e = ManAddrIfSubtype::Unknown;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Unknown");
  e = ManAddrIfSubtype::PortRef;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "PortRef");
  e = ManAddrIfSubtype::SystemPortNumber;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "SystemPortNumber");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<ManAddrIfSubtype>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<ManAddrIfSubtype>(-9999));
}

TEST_F(GeneratedDataTypeTests, PriorityMappingEntryType_Structure)
{
  PriorityMappingEntryType val1;
  val1.mapping_uri() = "test";
  val1.priority_label() = "test";
  val1.priority_value_pcp() = 123;
  val1.priority_value_dscp() = 123456;
  const PriorityMappingEntryType& const_val = val1;
  val1.mapping_uri();
  const_val.mapping_uri();
  val1.priority_label();
  const_val.priority_label();
  val1.priority_value_pcp();
  const_val.priority_value_pcp();
  val1.priority_value_dscp();
  const_val.priority_value_dscp();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, LldpManagementAddressTxPortType_Structure)
{
  LldpManagementAddressTxPortType val1;
  val1.address_subtype() = 123456;
  val1.man_address() = "test";
  val1.tx_enable() = true;
  val1.addr_len() = 123456;
  val1.if_subtype() = ManAddrIfSubtype::None;
  val1.if_id() = 123456;
  const LldpManagementAddressTxPortType& const_val = val1;
  val1.address_subtype();
  const_val.address_subtype();
  val1.man_address();
  const_val.man_address();
  val1.tx_enable();
  const_val.tx_enable();
  val1.addr_len();
  const_val.addr_len();
  val1.if_subtype();
  const_val.if_subtype();
  val1.if_id();
  const_val.if_id();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, LldpManagementAddressType_Structure)
{
  LldpManagementAddressType val1;
  val1.address_subtype() = 123456;
  val1.address() = "test";
  val1.if_subtype() = ManAddrIfSubtype::None;
  val1.if_id() = 123456;
  const LldpManagementAddressType& const_val = val1;
  val1.address_subtype();
  const_val.address_subtype();
  val1.address();
  const_val.address();
  val1.if_subtype();
  const_val.if_subtype();
  val1.if_id();
  const_val.if_id();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, LldpTlvType_Structure)
{
  LldpTlvType val1;
  val1.tlv_type() = 123456;
  val1.tlv_info() = ByteString{1, 2, 3};
  const LldpTlvType& const_val = val1;
  val1.tlv_type();
  const_val.tlv_type();
  val1.tlv_info();
  const_val.tlv_info();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, LldpSystemCapabilitiesMap_OptionSet)
{
  LldpSystemCapabilitiesMap o;
  auto default_str = to_string(o);
  EXPECT_NE(default_str.find("LldpSystemCapabilitiesMap"), std::string::npos);
  o.set(LldpSystemCapabilitiesMap::Bit::Other);
  EXPECT_TRUE(o.test(LldpSystemCapabilitiesMap::Bit::Other));
  EXPECT_NE(to_string(o).find("Other"), std::string::npos);
  o.set(LldpSystemCapabilitiesMap::Bit::Repeater);
  EXPECT_TRUE(o.test(LldpSystemCapabilitiesMap::Bit::Repeater));
  EXPECT_NE(to_string(o).find("Repeater"), std::string::npos);
  o.set(LldpSystemCapabilitiesMap::Bit::Bridge);
  EXPECT_TRUE(o.test(LldpSystemCapabilitiesMap::Bit::Bridge));
  EXPECT_NE(to_string(o).find("Bridge"), std::string::npos);
  o.set(LldpSystemCapabilitiesMap::Bit::WlanAccessPoint);
  EXPECT_TRUE(o.test(LldpSystemCapabilitiesMap::Bit::WlanAccessPoint));
  EXPECT_NE(to_string(o).find("WlanAccessPoint"), std::string::npos);
  o.set(LldpSystemCapabilitiesMap::Bit::Router);
  EXPECT_TRUE(o.test(LldpSystemCapabilitiesMap::Bit::Router));
  EXPECT_NE(to_string(o).find("Router"), std::string::npos);
  o.set(LldpSystemCapabilitiesMap::Bit::Telephone);
  EXPECT_TRUE(o.test(LldpSystemCapabilitiesMap::Bit::Telephone));
  EXPECT_NE(to_string(o).find("Telephone"), std::string::npos);
  o.set(LldpSystemCapabilitiesMap::Bit::DocsisCableDevice);
  EXPECT_TRUE(o.test(LldpSystemCapabilitiesMap::Bit::DocsisCableDevice));
  EXPECT_NE(to_string(o).find("DocsisCableDevice"), std::string::npos);
  o.set(LldpSystemCapabilitiesMap::Bit::StationOnly);
  EXPECT_TRUE(o.test(LldpSystemCapabilitiesMap::Bit::StationOnly));
  EXPECT_NE(to_string(o).find("StationOnly"), std::string::npos);
  o.set(LldpSystemCapabilitiesMap::Bit::CvlanComponent);
  EXPECT_TRUE(o.test(LldpSystemCapabilitiesMap::Bit::CvlanComponent));
  EXPECT_NE(to_string(o).find("CvlanComponent"), std::string::npos);
  o.set(LldpSystemCapabilitiesMap::Bit::SvlanComponent);
  EXPECT_TRUE(o.test(LldpSystemCapabilitiesMap::Bit::SvlanComponent));
  EXPECT_NE(to_string(o).find("SvlanComponent"), std::string::npos);
  o.set(LldpSystemCapabilitiesMap::Bit::TwoPortMacRelay);
  EXPECT_TRUE(o.test(LldpSystemCapabilitiesMap::Bit::TwoPortMacRelay));
  EXPECT_NE(to_string(o).find("TwoPortMacRelay"), std::string::npos);
  auto all_set_str = to_string(o);
  EXPECT_NE(all_set_str.find("Other"), std::string::npos);
  EXPECT_NE(all_set_str.find("Repeater"), std::string::npos);
  EXPECT_NE(all_set_str.find("Bridge"), std::string::npos);
  EXPECT_NE(all_set_str.find("WlanAccessPoint"), std::string::npos);
  EXPECT_NE(all_set_str.find("Router"), std::string::npos);
  EXPECT_NE(all_set_str.find("Telephone"), std::string::npos);
  EXPECT_NE(all_set_str.find("DocsisCableDevice"), std::string::npos);
  EXPECT_NE(all_set_str.find("StationOnly"), std::string::npos);
  EXPECT_NE(all_set_str.find("CvlanComponent"), std::string::npos);
  EXPECT_NE(all_set_str.find("SvlanComponent"), std::string::npos);
  EXPECT_NE(all_set_str.find("TwoPortMacRelay"), std::string::npos);
  o.reset(LldpSystemCapabilitiesMap::Bit::Other);
  EXPECT_FALSE(o.test(LldpSystemCapabilitiesMap::Bit::Other));
  o.reset(LldpSystemCapabilitiesMap::Bit::Repeater);
  EXPECT_FALSE(o.test(LldpSystemCapabilitiesMap::Bit::Repeater));
  o.reset(LldpSystemCapabilitiesMap::Bit::Bridge);
  EXPECT_FALSE(o.test(LldpSystemCapabilitiesMap::Bit::Bridge));
  o.reset(LldpSystemCapabilitiesMap::Bit::WlanAccessPoint);
  EXPECT_FALSE(o.test(LldpSystemCapabilitiesMap::Bit::WlanAccessPoint));
  o.reset(LldpSystemCapabilitiesMap::Bit::Router);
  EXPECT_FALSE(o.test(LldpSystemCapabilitiesMap::Bit::Router));
  o.reset(LldpSystemCapabilitiesMap::Bit::Telephone);
  EXPECT_FALSE(o.test(LldpSystemCapabilitiesMap::Bit::Telephone));
  o.reset(LldpSystemCapabilitiesMap::Bit::DocsisCableDevice);
  EXPECT_FALSE(o.test(LldpSystemCapabilitiesMap::Bit::DocsisCableDevice));
  o.reset(LldpSystemCapabilitiesMap::Bit::StationOnly);
  EXPECT_FALSE(o.test(LldpSystemCapabilitiesMap::Bit::StationOnly));
  o.reset(LldpSystemCapabilitiesMap::Bit::CvlanComponent);
  EXPECT_FALSE(o.test(LldpSystemCapabilitiesMap::Bit::CvlanComponent));
  o.reset(LldpSystemCapabilitiesMap::Bit::SvlanComponent);
  EXPECT_FALSE(o.test(LldpSystemCapabilitiesMap::Bit::SvlanComponent));
  o.reset(LldpSystemCapabilitiesMap::Bit::TwoPortMacRelay);
  EXPECT_FALSE(o.test(LldpSystemCapabilitiesMap::Bit::TwoPortMacRelay));
  auto u = o.as_underlying_type();
  o.from_underlying_type(u);
  EXPECT_EQ(o.as_underlying_type(), u);
}

TEST_F(GeneratedDataTypeTests, ReferenceDescriptionDataType_Structure)
{
  ReferenceDescriptionDataType val1;
  val1.source_node() = NodeId{1234};
  val1.reference_type() = NodeId{1234};
  val1.is_forward() = true;
  val1.target_node() = ExpandedNodeId{NodeId{1234}};
  const ReferenceDescriptionDataType& const_val = val1;
  val1.source_node();
  const_val.source_node();
  val1.reference_type();
  const_val.reference_type();
  val1.is_forward();
  const_val.is_forward();
  val1.target_node();
  const_val.target_node();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ReferenceListEntryDataType_Structure)
{
  ReferenceListEntryDataType val1;
  val1.reference_type() = NodeId{1234};
  val1.is_forward() = true;
  val1.target_node() = ExpandedNodeId{NodeId{1234}};
  const ReferenceListEntryDataType& const_val = val1;
  val1.reference_type();
  const_val.reference_type();
  val1.is_forward();
  const_val.is_forward();
  val1.target_node();
  const_val.target_node();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, LogRecord_Structure)
{
  LogRecord val1;
  val1.time() = DateTime::now();
  val1.severity() = 12345;
  val1.message() = LocalizedText{"en", "test"};
  const LogRecord& const_val = val1;
  val1.time();
  const_val.time();
  val1.severity();
  const_val.severity();
  val1.event_type();
  const_val.event_type();
  val1.source_node();
  const_val.source_node();
  val1.source_name();
  const_val.source_name();
  val1.message();
  const_val.message();
  val1.trace_context();
  const_val.trace_context();
  val1.additional_data();
  const_val.additional_data();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);

  // Cover the optional-present encoding-mask paths.
  val1.event_type().emplace();
  (*val1.event_type()) = NodeId{1234};
  val1.source_node().emplace();
  (*val1.source_node()) = NodeId{1234};
  val1.source_name().emplace();
  (*val1.source_name()) = "test";
  val1.trace_context().emplace();
  (*val1.trace_context()).parent_span_id() = 1234567;
  (*val1.trace_context()).parent_identifier() = "test";
  val1.additional_data().emplace();
  (*val1.additional_data()).resize(2);
  (*val1.additional_data())[0].name() = "test";
  (*val1.additional_data())[0].value() = Variant{123};
  test_binary_round_trip(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, LogRecordsDataType_Structure)
{
  LogRecordsDataType val1;
  val1.log_record_array().resize(2);
  val1.log_record_array()[0].time() = DateTime::now();
  val1.log_record_array()[0].severity() = 12345;
  val1.log_record_array()[0].message() = LocalizedText{"en", "test"};
  const LogRecordsDataType& const_val = val1;
  val1.log_record_array();
  const_val.log_record_array();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, SpanContextDataType_Structure)
{
  SpanContextDataType val1;
  val1.trace_id() = Guid::create_and_generate();
  val1.span_id() = 1234567;
  const SpanContextDataType& const_val = val1;
  val1.trace_id();
  const_val.trace_id();
  val1.span_id();
  const_val.span_id();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, TraceContextDataType_Structure)
{
  TraceContextDataType val1;
  val1.parent_span_id() = 1234567;
  val1.parent_identifier() = "test";
  const TraceContextDataType& const_val = val1;
  val1.parent_span_id();
  const_val.parent_span_id();
  val1.parent_identifier();
  const_val.parent_identifier();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, NameValuePair_Structure)
{
  NameValuePair val1;
  val1.name() = "test";
  val1.value() = Variant{123};
  const NameValuePair& const_val = val1;
  val1.name();
  const_val.name();
  val1.value();
  const_val.value();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, LogRecordMask_OptionSet)
{
  LogRecordMask o;
  auto default_str = to_string(o);
  EXPECT_NE(default_str.find("LogRecordMask"), std::string::npos);
  o.set(LogRecordMask::Bit::EventType);
  EXPECT_TRUE(o.test(LogRecordMask::Bit::EventType));
  EXPECT_NE(to_string(o).find("EventType"), std::string::npos);
  o.set(LogRecordMask::Bit::SourceNode);
  EXPECT_TRUE(o.test(LogRecordMask::Bit::SourceNode));
  EXPECT_NE(to_string(o).find("SourceNode"), std::string::npos);
  o.set(LogRecordMask::Bit::SourceName);
  EXPECT_TRUE(o.test(LogRecordMask::Bit::SourceName));
  EXPECT_NE(to_string(o).find("SourceName"), std::string::npos);
  o.set(LogRecordMask::Bit::TraceContext);
  EXPECT_TRUE(o.test(LogRecordMask::Bit::TraceContext));
  EXPECT_NE(to_string(o).find("TraceContext"), std::string::npos);
  o.set(LogRecordMask::Bit::AdditionalData);
  EXPECT_TRUE(o.test(LogRecordMask::Bit::AdditionalData));
  EXPECT_NE(to_string(o).find("AdditionalData"), std::string::npos);
  auto all_set_str = to_string(o);
  EXPECT_NE(all_set_str.find("EventType"), std::string::npos);
  EXPECT_NE(all_set_str.find("SourceNode"), std::string::npos);
  EXPECT_NE(all_set_str.find("SourceName"), std::string::npos);
  EXPECT_NE(all_set_str.find("TraceContext"), std::string::npos);
  EXPECT_NE(all_set_str.find("AdditionalData"), std::string::npos);
  o.reset(LogRecordMask::Bit::EventType);
  EXPECT_FALSE(o.test(LogRecordMask::Bit::EventType));
  o.reset(LogRecordMask::Bit::SourceNode);
  EXPECT_FALSE(o.test(LogRecordMask::Bit::SourceNode));
  o.reset(LogRecordMask::Bit::SourceName);
  EXPECT_FALSE(o.test(LogRecordMask::Bit::SourceName));
  o.reset(LogRecordMask::Bit::TraceContext);
  EXPECT_FALSE(o.test(LogRecordMask::Bit::TraceContext));
  o.reset(LogRecordMask::Bit::AdditionalData);
  EXPECT_FALSE(o.test(LogRecordMask::Bit::AdditionalData));
  auto u = o.as_underlying_type();
  o.from_underlying_type(u);
  EXPECT_EQ(o.as_underlying_type(), u);
}

TEST_F(GeneratedDataTypeTests, IdType_Enumeration)
{
  IdType e{};
  e = IdType::Numeric;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Numeric");
  e = IdType::String;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "String");
  e = IdType::Guid;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Guid");
  e = IdType::Opaque;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Opaque");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<IdType>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<IdType>(-9999));
}

TEST_F(GeneratedDataTypeTests, NodeClass_Enumeration)
{
  NodeClass e{};
  e = NodeClass::Unspecified;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Unspecified");
  e = NodeClass::Object;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Object");
  e = NodeClass::Variable;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Variable");
  e = NodeClass::Method;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Method");
  e = NodeClass::ObjectType;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "ObjectType");
  e = NodeClass::VariableType;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "VariableType");
  e = NodeClass::ReferenceType;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "ReferenceType");
  e = NodeClass::DataType;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "DataType");
  e = NodeClass::View;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "View");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<NodeClass>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<NodeClass>(-9999));
}

TEST_F(GeneratedDataTypeTests, PermissionType_OptionSet)
{
  PermissionType o;
  auto default_str = to_string(o);
  EXPECT_NE(default_str.find("PermissionType"), std::string::npos);
  o.set(PermissionType::Bit::Browse);
  EXPECT_TRUE(o.test(PermissionType::Bit::Browse));
  EXPECT_NE(to_string(o).find("Browse"), std::string::npos);
  o.set(PermissionType::Bit::ReadRolePermissions);
  EXPECT_TRUE(o.test(PermissionType::Bit::ReadRolePermissions));
  EXPECT_NE(to_string(o).find("ReadRolePermissions"), std::string::npos);
  o.set(PermissionType::Bit::WriteAttribute);
  EXPECT_TRUE(o.test(PermissionType::Bit::WriteAttribute));
  EXPECT_NE(to_string(o).find("WriteAttribute"), std::string::npos);
  o.set(PermissionType::Bit::WriteRolePermissions);
  EXPECT_TRUE(o.test(PermissionType::Bit::WriteRolePermissions));
  EXPECT_NE(to_string(o).find("WriteRolePermissions"), std::string::npos);
  o.set(PermissionType::Bit::WriteHistorizing);
  EXPECT_TRUE(o.test(PermissionType::Bit::WriteHistorizing));
  EXPECT_NE(to_string(o).find("WriteHistorizing"), std::string::npos);
  o.set(PermissionType::Bit::Read);
  EXPECT_TRUE(o.test(PermissionType::Bit::Read));
  EXPECT_NE(to_string(o).find("Read"), std::string::npos);
  o.set(PermissionType::Bit::Write);
  EXPECT_TRUE(o.test(PermissionType::Bit::Write));
  EXPECT_NE(to_string(o).find("Write"), std::string::npos);
  o.set(PermissionType::Bit::ReadHistory);
  EXPECT_TRUE(o.test(PermissionType::Bit::ReadHistory));
  EXPECT_NE(to_string(o).find("ReadHistory"), std::string::npos);
  o.set(PermissionType::Bit::InsertHistory);
  EXPECT_TRUE(o.test(PermissionType::Bit::InsertHistory));
  EXPECT_NE(to_string(o).find("InsertHistory"), std::string::npos);
  o.set(PermissionType::Bit::ModifyHistory);
  EXPECT_TRUE(o.test(PermissionType::Bit::ModifyHistory));
  EXPECT_NE(to_string(o).find("ModifyHistory"), std::string::npos);
  o.set(PermissionType::Bit::DeleteHistory);
  EXPECT_TRUE(o.test(PermissionType::Bit::DeleteHistory));
  EXPECT_NE(to_string(o).find("DeleteHistory"), std::string::npos);
  o.set(PermissionType::Bit::ReceiveEvents);
  EXPECT_TRUE(o.test(PermissionType::Bit::ReceiveEvents));
  EXPECT_NE(to_string(o).find("ReceiveEvents"), std::string::npos);
  o.set(PermissionType::Bit::Call);
  EXPECT_TRUE(o.test(PermissionType::Bit::Call));
  EXPECT_NE(to_string(o).find("Call"), std::string::npos);
  o.set(PermissionType::Bit::AddReference);
  EXPECT_TRUE(o.test(PermissionType::Bit::AddReference));
  EXPECT_NE(to_string(o).find("AddReference"), std::string::npos);
  o.set(PermissionType::Bit::RemoveReference);
  EXPECT_TRUE(o.test(PermissionType::Bit::RemoveReference));
  EXPECT_NE(to_string(o).find("RemoveReference"), std::string::npos);
  o.set(PermissionType::Bit::DeleteNode);
  EXPECT_TRUE(o.test(PermissionType::Bit::DeleteNode));
  EXPECT_NE(to_string(o).find("DeleteNode"), std::string::npos);
  o.set(PermissionType::Bit::AddNode);
  EXPECT_TRUE(o.test(PermissionType::Bit::AddNode));
  EXPECT_NE(to_string(o).find("AddNode"), std::string::npos);
  auto all_set_str = to_string(o);
  EXPECT_NE(all_set_str.find("Browse"), std::string::npos);
  EXPECT_NE(all_set_str.find("ReadRolePermissions"), std::string::npos);
  EXPECT_NE(all_set_str.find("WriteAttribute"), std::string::npos);
  EXPECT_NE(all_set_str.find("WriteRolePermissions"), std::string::npos);
  EXPECT_NE(all_set_str.find("WriteHistorizing"), std::string::npos);
  EXPECT_NE(all_set_str.find("Read"), std::string::npos);
  EXPECT_NE(all_set_str.find("Write"), std::string::npos);
  EXPECT_NE(all_set_str.find("ReadHistory"), std::string::npos);
  EXPECT_NE(all_set_str.find("InsertHistory"), std::string::npos);
  EXPECT_NE(all_set_str.find("ModifyHistory"), std::string::npos);
  EXPECT_NE(all_set_str.find("DeleteHistory"), std::string::npos);
  EXPECT_NE(all_set_str.find("ReceiveEvents"), std::string::npos);
  EXPECT_NE(all_set_str.find("Call"), std::string::npos);
  EXPECT_NE(all_set_str.find("AddReference"), std::string::npos);
  EXPECT_NE(all_set_str.find("RemoveReference"), std::string::npos);
  EXPECT_NE(all_set_str.find("DeleteNode"), std::string::npos);
  EXPECT_NE(all_set_str.find("AddNode"), std::string::npos);
  o.reset(PermissionType::Bit::Browse);
  EXPECT_FALSE(o.test(PermissionType::Bit::Browse));
  o.reset(PermissionType::Bit::ReadRolePermissions);
  EXPECT_FALSE(o.test(PermissionType::Bit::ReadRolePermissions));
  o.reset(PermissionType::Bit::WriteAttribute);
  EXPECT_FALSE(o.test(PermissionType::Bit::WriteAttribute));
  o.reset(PermissionType::Bit::WriteRolePermissions);
  EXPECT_FALSE(o.test(PermissionType::Bit::WriteRolePermissions));
  o.reset(PermissionType::Bit::WriteHistorizing);
  EXPECT_FALSE(o.test(PermissionType::Bit::WriteHistorizing));
  o.reset(PermissionType::Bit::Read);
  EXPECT_FALSE(o.test(PermissionType::Bit::Read));
  o.reset(PermissionType::Bit::Write);
  EXPECT_FALSE(o.test(PermissionType::Bit::Write));
  o.reset(PermissionType::Bit::ReadHistory);
  EXPECT_FALSE(o.test(PermissionType::Bit::ReadHistory));
  o.reset(PermissionType::Bit::InsertHistory);
  EXPECT_FALSE(o.test(PermissionType::Bit::InsertHistory));
  o.reset(PermissionType::Bit::ModifyHistory);
  EXPECT_FALSE(o.test(PermissionType::Bit::ModifyHistory));
  o.reset(PermissionType::Bit::DeleteHistory);
  EXPECT_FALSE(o.test(PermissionType::Bit::DeleteHistory));
  o.reset(PermissionType::Bit::ReceiveEvents);
  EXPECT_FALSE(o.test(PermissionType::Bit::ReceiveEvents));
  o.reset(PermissionType::Bit::Call);
  EXPECT_FALSE(o.test(PermissionType::Bit::Call));
  o.reset(PermissionType::Bit::AddReference);
  EXPECT_FALSE(o.test(PermissionType::Bit::AddReference));
  o.reset(PermissionType::Bit::RemoveReference);
  EXPECT_FALSE(o.test(PermissionType::Bit::RemoveReference));
  o.reset(PermissionType::Bit::DeleteNode);
  EXPECT_FALSE(o.test(PermissionType::Bit::DeleteNode));
  o.reset(PermissionType::Bit::AddNode);
  EXPECT_FALSE(o.test(PermissionType::Bit::AddNode));
  auto u = o.as_underlying_type();
  o.from_underlying_type(u);
  EXPECT_EQ(o.as_underlying_type(), u);
}

TEST_F(GeneratedDataTypeTests, AccessLevelType_OptionSet)
{
  AccessLevelType o;
  auto default_str = to_string(o);
  EXPECT_NE(default_str.find("AccessLevelType"), std::string::npos);
  o.set(AccessLevelType::Bit::CurrentRead);
  EXPECT_TRUE(o.test(AccessLevelType::Bit::CurrentRead));
  EXPECT_NE(to_string(o).find("CurrentRead"), std::string::npos);
  o.set(AccessLevelType::Bit::CurrentWrite);
  EXPECT_TRUE(o.test(AccessLevelType::Bit::CurrentWrite));
  EXPECT_NE(to_string(o).find("CurrentWrite"), std::string::npos);
  o.set(AccessLevelType::Bit::HistoryRead);
  EXPECT_TRUE(o.test(AccessLevelType::Bit::HistoryRead));
  EXPECT_NE(to_string(o).find("HistoryRead"), std::string::npos);
  o.set(AccessLevelType::Bit::HistoryWrite);
  EXPECT_TRUE(o.test(AccessLevelType::Bit::HistoryWrite));
  EXPECT_NE(to_string(o).find("HistoryWrite"), std::string::npos);
  o.set(AccessLevelType::Bit::SemanticChange);
  EXPECT_TRUE(o.test(AccessLevelType::Bit::SemanticChange));
  EXPECT_NE(to_string(o).find("SemanticChange"), std::string::npos);
  o.set(AccessLevelType::Bit::StatusWrite);
  EXPECT_TRUE(o.test(AccessLevelType::Bit::StatusWrite));
  EXPECT_NE(to_string(o).find("StatusWrite"), std::string::npos);
  o.set(AccessLevelType::Bit::TimestampWrite);
  EXPECT_TRUE(o.test(AccessLevelType::Bit::TimestampWrite));
  EXPECT_NE(to_string(o).find("TimestampWrite"), std::string::npos);
  auto all_set_str = to_string(o);
  EXPECT_NE(all_set_str.find("CurrentRead"), std::string::npos);
  EXPECT_NE(all_set_str.find("CurrentWrite"), std::string::npos);
  EXPECT_NE(all_set_str.find("HistoryRead"), std::string::npos);
  EXPECT_NE(all_set_str.find("HistoryWrite"), std::string::npos);
  EXPECT_NE(all_set_str.find("SemanticChange"), std::string::npos);
  EXPECT_NE(all_set_str.find("StatusWrite"), std::string::npos);
  EXPECT_NE(all_set_str.find("TimestampWrite"), std::string::npos);
  o.reset(AccessLevelType::Bit::CurrentRead);
  EXPECT_FALSE(o.test(AccessLevelType::Bit::CurrentRead));
  o.reset(AccessLevelType::Bit::CurrentWrite);
  EXPECT_FALSE(o.test(AccessLevelType::Bit::CurrentWrite));
  o.reset(AccessLevelType::Bit::HistoryRead);
  EXPECT_FALSE(o.test(AccessLevelType::Bit::HistoryRead));
  o.reset(AccessLevelType::Bit::HistoryWrite);
  EXPECT_FALSE(o.test(AccessLevelType::Bit::HistoryWrite));
  o.reset(AccessLevelType::Bit::SemanticChange);
  EXPECT_FALSE(o.test(AccessLevelType::Bit::SemanticChange));
  o.reset(AccessLevelType::Bit::StatusWrite);
  EXPECT_FALSE(o.test(AccessLevelType::Bit::StatusWrite));
  o.reset(AccessLevelType::Bit::TimestampWrite);
  EXPECT_FALSE(o.test(AccessLevelType::Bit::TimestampWrite));
  auto u = o.as_underlying_type();
  o.from_underlying_type(u);
  EXPECT_EQ(o.as_underlying_type(), u);
}

TEST_F(GeneratedDataTypeTests, AccessLevelExType_OptionSet)
{
  AccessLevelExType o;
  auto default_str = to_string(o);
  EXPECT_NE(default_str.find("AccessLevelExType"), std::string::npos);
  o.set(AccessLevelExType::Bit::CurrentRead);
  EXPECT_TRUE(o.test(AccessLevelExType::Bit::CurrentRead));
  EXPECT_NE(to_string(o).find("CurrentRead"), std::string::npos);
  o.set(AccessLevelExType::Bit::CurrentWrite);
  EXPECT_TRUE(o.test(AccessLevelExType::Bit::CurrentWrite));
  EXPECT_NE(to_string(o).find("CurrentWrite"), std::string::npos);
  o.set(AccessLevelExType::Bit::HistoryRead);
  EXPECT_TRUE(o.test(AccessLevelExType::Bit::HistoryRead));
  EXPECT_NE(to_string(o).find("HistoryRead"), std::string::npos);
  o.set(AccessLevelExType::Bit::HistoryWrite);
  EXPECT_TRUE(o.test(AccessLevelExType::Bit::HistoryWrite));
  EXPECT_NE(to_string(o).find("HistoryWrite"), std::string::npos);
  o.set(AccessLevelExType::Bit::SemanticChange);
  EXPECT_TRUE(o.test(AccessLevelExType::Bit::SemanticChange));
  EXPECT_NE(to_string(o).find("SemanticChange"), std::string::npos);
  o.set(AccessLevelExType::Bit::StatusWrite);
  EXPECT_TRUE(o.test(AccessLevelExType::Bit::StatusWrite));
  EXPECT_NE(to_string(o).find("StatusWrite"), std::string::npos);
  o.set(AccessLevelExType::Bit::TimestampWrite);
  EXPECT_TRUE(o.test(AccessLevelExType::Bit::TimestampWrite));
  EXPECT_NE(to_string(o).find("TimestampWrite"), std::string::npos);
  o.set(AccessLevelExType::Bit::NonatomicRead);
  EXPECT_TRUE(o.test(AccessLevelExType::Bit::NonatomicRead));
  EXPECT_NE(to_string(o).find("NonatomicRead"), std::string::npos);
  o.set(AccessLevelExType::Bit::NonatomicWrite);
  EXPECT_TRUE(o.test(AccessLevelExType::Bit::NonatomicWrite));
  EXPECT_NE(to_string(o).find("NonatomicWrite"), std::string::npos);
  o.set(AccessLevelExType::Bit::WriteFullArrayOnly);
  EXPECT_TRUE(o.test(AccessLevelExType::Bit::WriteFullArrayOnly));
  EXPECT_NE(to_string(o).find("WriteFullArrayOnly"), std::string::npos);
  o.set(AccessLevelExType::Bit::NoSubDataTypes);
  EXPECT_TRUE(o.test(AccessLevelExType::Bit::NoSubDataTypes));
  EXPECT_NE(to_string(o).find("NoSubDataTypes"), std::string::npos);
  o.set(AccessLevelExType::Bit::NonVolatile);
  EXPECT_TRUE(o.test(AccessLevelExType::Bit::NonVolatile));
  EXPECT_NE(to_string(o).find("NonVolatile"), std::string::npos);
  o.set(AccessLevelExType::Bit::Constant);
  EXPECT_TRUE(o.test(AccessLevelExType::Bit::Constant));
  EXPECT_NE(to_string(o).find("Constant"), std::string::npos);
  auto all_set_str = to_string(o);
  EXPECT_NE(all_set_str.find("CurrentRead"), std::string::npos);
  EXPECT_NE(all_set_str.find("CurrentWrite"), std::string::npos);
  EXPECT_NE(all_set_str.find("HistoryRead"), std::string::npos);
  EXPECT_NE(all_set_str.find("HistoryWrite"), std::string::npos);
  EXPECT_NE(all_set_str.find("SemanticChange"), std::string::npos);
  EXPECT_NE(all_set_str.find("StatusWrite"), std::string::npos);
  EXPECT_NE(all_set_str.find("TimestampWrite"), std::string::npos);
  EXPECT_NE(all_set_str.find("NonatomicRead"), std::string::npos);
  EXPECT_NE(all_set_str.find("NonatomicWrite"), std::string::npos);
  EXPECT_NE(all_set_str.find("WriteFullArrayOnly"), std::string::npos);
  EXPECT_NE(all_set_str.find("NoSubDataTypes"), std::string::npos);
  EXPECT_NE(all_set_str.find("NonVolatile"), std::string::npos);
  EXPECT_NE(all_set_str.find("Constant"), std::string::npos);
  o.reset(AccessLevelExType::Bit::CurrentRead);
  EXPECT_FALSE(o.test(AccessLevelExType::Bit::CurrentRead));
  o.reset(AccessLevelExType::Bit::CurrentWrite);
  EXPECT_FALSE(o.test(AccessLevelExType::Bit::CurrentWrite));
  o.reset(AccessLevelExType::Bit::HistoryRead);
  EXPECT_FALSE(o.test(AccessLevelExType::Bit::HistoryRead));
  o.reset(AccessLevelExType::Bit::HistoryWrite);
  EXPECT_FALSE(o.test(AccessLevelExType::Bit::HistoryWrite));
  o.reset(AccessLevelExType::Bit::SemanticChange);
  EXPECT_FALSE(o.test(AccessLevelExType::Bit::SemanticChange));
  o.reset(AccessLevelExType::Bit::StatusWrite);
  EXPECT_FALSE(o.test(AccessLevelExType::Bit::StatusWrite));
  o.reset(AccessLevelExType::Bit::TimestampWrite);
  EXPECT_FALSE(o.test(AccessLevelExType::Bit::TimestampWrite));
  o.reset(AccessLevelExType::Bit::NonatomicRead);
  EXPECT_FALSE(o.test(AccessLevelExType::Bit::NonatomicRead));
  o.reset(AccessLevelExType::Bit::NonatomicWrite);
  EXPECT_FALSE(o.test(AccessLevelExType::Bit::NonatomicWrite));
  o.reset(AccessLevelExType::Bit::WriteFullArrayOnly);
  EXPECT_FALSE(o.test(AccessLevelExType::Bit::WriteFullArrayOnly));
  o.reset(AccessLevelExType::Bit::NoSubDataTypes);
  EXPECT_FALSE(o.test(AccessLevelExType::Bit::NoSubDataTypes));
  o.reset(AccessLevelExType::Bit::NonVolatile);
  EXPECT_FALSE(o.test(AccessLevelExType::Bit::NonVolatile));
  o.reset(AccessLevelExType::Bit::Constant);
  EXPECT_FALSE(o.test(AccessLevelExType::Bit::Constant));
  auto u = o.as_underlying_type();
  o.from_underlying_type(u);
  EXPECT_EQ(o.as_underlying_type(), u);
}

TEST_F(GeneratedDataTypeTests, EventNotifierType_OptionSet)
{
  EventNotifierType o;
  auto default_str = to_string(o);
  EXPECT_NE(default_str.find("EventNotifierType"), std::string::npos);
  o.set(EventNotifierType::Bit::SubscribeToEvents);
  EXPECT_TRUE(o.test(EventNotifierType::Bit::SubscribeToEvents));
  EXPECT_NE(to_string(o).find("SubscribeToEvents"), std::string::npos);
  o.set(EventNotifierType::Bit::HistoryRead);
  EXPECT_TRUE(o.test(EventNotifierType::Bit::HistoryRead));
  EXPECT_NE(to_string(o).find("HistoryRead"), std::string::npos);
  o.set(EventNotifierType::Bit::HistoryWrite);
  EXPECT_TRUE(o.test(EventNotifierType::Bit::HistoryWrite));
  EXPECT_NE(to_string(o).find("HistoryWrite"), std::string::npos);
  auto all_set_str = to_string(o);
  EXPECT_NE(all_set_str.find("SubscribeToEvents"), std::string::npos);
  EXPECT_NE(all_set_str.find("HistoryRead"), std::string::npos);
  EXPECT_NE(all_set_str.find("HistoryWrite"), std::string::npos);
  o.reset(EventNotifierType::Bit::SubscribeToEvents);
  EXPECT_FALSE(o.test(EventNotifierType::Bit::SubscribeToEvents));
  o.reset(EventNotifierType::Bit::HistoryRead);
  EXPECT_FALSE(o.test(EventNotifierType::Bit::HistoryRead));
  o.reset(EventNotifierType::Bit::HistoryWrite);
  EXPECT_FALSE(o.test(EventNotifierType::Bit::HistoryWrite));
  auto u = o.as_underlying_type();
  o.from_underlying_type(u);
  EXPECT_EQ(o.as_underlying_type(), u);
}

TEST_F(GeneratedDataTypeTests, AccessRestrictionType_OptionSet)
{
  AccessRestrictionType o;
  auto default_str = to_string(o);
  EXPECT_NE(default_str.find("AccessRestrictionType"), std::string::npos);
  o.set(AccessRestrictionType::Bit::SigningRequired);
  EXPECT_TRUE(o.test(AccessRestrictionType::Bit::SigningRequired));
  EXPECT_NE(to_string(o).find("SigningRequired"), std::string::npos);
  o.set(AccessRestrictionType::Bit::EncryptionRequired);
  EXPECT_TRUE(o.test(AccessRestrictionType::Bit::EncryptionRequired));
  EXPECT_NE(to_string(o).find("EncryptionRequired"), std::string::npos);
  o.set(AccessRestrictionType::Bit::SessionRequired);
  EXPECT_TRUE(o.test(AccessRestrictionType::Bit::SessionRequired));
  EXPECT_NE(to_string(o).find("SessionRequired"), std::string::npos);
  o.set(AccessRestrictionType::Bit::ApplyRestrictionsToBrowse);
  EXPECT_TRUE(o.test(AccessRestrictionType::Bit::ApplyRestrictionsToBrowse));
  EXPECT_NE(to_string(o).find("ApplyRestrictionsToBrowse"), std::string::npos);
  auto all_set_str = to_string(o);
  EXPECT_NE(all_set_str.find("SigningRequired"), std::string::npos);
  EXPECT_NE(all_set_str.find("EncryptionRequired"), std::string::npos);
  EXPECT_NE(all_set_str.find("SessionRequired"), std::string::npos);
  EXPECT_NE(all_set_str.find("ApplyRestrictionsToBrowse"), std::string::npos);
  o.reset(AccessRestrictionType::Bit::SigningRequired);
  EXPECT_FALSE(o.test(AccessRestrictionType::Bit::SigningRequired));
  o.reset(AccessRestrictionType::Bit::EncryptionRequired);
  EXPECT_FALSE(o.test(AccessRestrictionType::Bit::EncryptionRequired));
  o.reset(AccessRestrictionType::Bit::SessionRequired);
  EXPECT_FALSE(o.test(AccessRestrictionType::Bit::SessionRequired));
  o.reset(AccessRestrictionType::Bit::ApplyRestrictionsToBrowse);
  EXPECT_FALSE(o.test(AccessRestrictionType::Bit::ApplyRestrictionsToBrowse));
  auto u = o.as_underlying_type();
  o.from_underlying_type(u);
  EXPECT_EQ(o.as_underlying_type(), u);
}

TEST_F(GeneratedDataTypeTests, RolePermissionType_Structure)
{
  RolePermissionType val1;
  val1.role_id() = NodeId{1234};
  val1.permissions().set(PermissionType::Bit::Browse);
  const RolePermissionType& const_val = val1;
  val1.role_id();
  const_val.role_id();
  val1.permissions();
  const_val.permissions();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, DataTypeDefinition_AbstractStructure)
{
  // Testing only metadata for abstract structures
  // we cannot instantiate them
}

TEST_F(GeneratedDataTypeTests, StructureType_Enumeration)
{
  StructureType e{};
  e = StructureType::Structure;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Structure");
  e = StructureType::StructureWithOptionalFields;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "StructureWithOptionalFields");
  e = StructureType::Union;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Union");
  e = StructureType::StructureWithSubtypedValues;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "StructureWithSubtypedValues");
  e = StructureType::UnionWithSubtypedValues;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "UnionWithSubtypedValues");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<StructureType>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<StructureType>(-9999));
}

TEST_F(GeneratedDataTypeTests, StructureField_Structure)
{
  StructureField val1;
  val1.name() = "test";
  val1.description() = LocalizedText{"en", "test"};
  val1.data_type() = NodeId{1234};
  val1.value_rank() = 123456;
  val1.array_dimensions().resize(2);
  val1.array_dimensions()[0] = 123456;
  val1.max_string_length() = 123456;
  val1.is_optional() = true;
  const StructureField& const_val = val1;
  val1.name();
  const_val.name();
  val1.description();
  const_val.description();
  val1.data_type();
  const_val.data_type();
  val1.value_rank();
  const_val.value_rank();
  val1.array_dimensions();
  const_val.array_dimensions();
  val1.max_string_length();
  const_val.max_string_length();
  val1.is_optional();
  const_val.is_optional();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, StructureDefinition_Structure)
{
  StructureDefinition val1;
  val1.default_encoding_id() = NodeId{1234};
  val1.base_data_type() = NodeId{1234};
  val1.structure_type() = StructureType::Structure;
  val1.fields().resize(2);
  val1.fields()[0].name() = "test";
  val1.fields()[0].description() = LocalizedText{"en", "test"};
  val1.fields()[0].data_type() = NodeId{1234};
  val1.fields()[0].value_rank() = 123456;
  val1.fields()[0].array_dimensions().resize(2);
  val1.fields()[0].array_dimensions()[0] = 123456;
  val1.fields()[0].max_string_length() = 123456;
  val1.fields()[0].is_optional() = true;
  const StructureDefinition& const_val = val1;
  val1.default_encoding_id();
  const_val.default_encoding_id();
  val1.base_data_type();
  const_val.base_data_type();
  val1.structure_type();
  const_val.structure_type();
  val1.fields();
  const_val.fields();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, EnumDefinition_Structure)
{
  EnumDefinition val1;
  val1.fields().resize(2);
  val1.fields()[0].name() = "test";
  const EnumDefinition& const_val = val1;
  val1.fields();
  const_val.fields();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, Argument_Structure)
{
  Argument val1;
  val1.name() = "test";
  val1.data_type() = NodeId{1234};
  val1.value_rank() = 123456;
  val1.array_dimensions().resize(2);
  val1.array_dimensions()[0] = 123456;
  val1.description() = LocalizedText{"en", "test"};
  const Argument& const_val = val1;
  val1.name();
  const_val.name();
  val1.data_type();
  const_val.data_type();
  val1.value_rank();
  const_val.value_rank();
  val1.array_dimensions();
  const_val.array_dimensions();
  val1.description();
  const_val.description();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, EnumValueType_Structure)
{
  EnumValueType val1;
  val1.value() = 1234567;
  val1.display_name() = LocalizedText{"en", "test"};
  val1.description() = LocalizedText{"en", "test"};
  const EnumValueType& const_val = val1;
  val1.value();
  const_val.value();
  val1.display_name();
  const_val.display_name();
  val1.description();
  const_val.description();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, EnumField_Structure)
{
  EnumField val1;
  val1.name() = "test";
  const EnumField& const_val = val1;
  val1.name();
  const_val.name();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, OptionSet_AbstractStructure)
{
  // Testing only metadata for abstract structures
  // we cannot instantiate them
}

TEST_F(GeneratedDataTypeTests, NormalizedString_SimpleType)
{
  NormalizedString val1{};
  NormalizedString val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, DecimalString_SimpleType)
{
  DecimalString val1{};
  DecimalString val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, DurationString_SimpleType)
{
  DurationString val1{};
  DurationString val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, TimeString_SimpleType)
{
  TimeString val1{};
  TimeString val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, DateString_SimpleType)
{
  DateString val1{};
  DateString val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, Duration_SimpleType)
{
  Duration val1{};
  Duration val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, UtcTime_SimpleType)
{
  UtcTime val1{};
  UtcTime val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, LocaleId_SimpleType)
{
  LocaleId val1{};
  LocaleId val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, TimeZoneDataType_Structure)
{
  TimeZoneDataType val1;
  val1.offset() = 12345;
  val1.daylight_saving_in_offset() = true;
  const TimeZoneDataType& const_val = val1;
  val1.offset();
  const_val.offset();
  val1.daylight_saving_in_offset();
  const_val.daylight_saving_in_offset();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, Index_SimpleType)
{
  Index val1{};
  Index val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, IntegerId_SimpleType)
{
  IntegerId val1{};
  IntegerId val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, ApplicationType_Enumeration)
{
  ApplicationType e{};
  e = ApplicationType::Server;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Server");
  e = ApplicationType::Client;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Client");
  e = ApplicationType::ClientAndServer;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "ClientAndServer");
  e = ApplicationType::DiscoveryServer;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "DiscoveryServer");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<ApplicationType>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<ApplicationType>(-9999));
}

TEST_F(GeneratedDataTypeTests, ApplicationDescription_Structure)
{
  ApplicationDescription val1;
  val1.application_uri() = "test";
  val1.product_uri() = "test";
  val1.application_name() = LocalizedText{"en", "test"};
  val1.application_type() = ApplicationType::Server;
  val1.gateway_server_uri() = "test";
  val1.discovery_profile_uri() = "test";
  val1.discovery_urls().resize(2);
  val1.discovery_urls()[0] = "test";
  const ApplicationDescription& const_val = val1;
  val1.application_uri();
  const_val.application_uri();
  val1.product_uri();
  const_val.product_uri();
  val1.application_name();
  const_val.application_name();
  val1.application_type();
  const_val.application_type();
  val1.gateway_server_uri();
  const_val.gateway_server_uri();
  val1.discovery_profile_uri();
  const_val.discovery_profile_uri();
  val1.discovery_urls();
  const_val.discovery_urls();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, VersionTime_SimpleType)
{
  VersionTime val1{};
  VersionTime val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, ServerOnNetwork_Structure)
{
  ServerOnNetwork val1;
  val1.record_id() = 123456;
  val1.server_name() = "test";
  val1.discovery_url() = "test";
  val1.server_capabilities().resize(2);
  val1.server_capabilities()[0] = "test";
  const ServerOnNetwork& const_val = val1;
  val1.record_id();
  const_val.record_id();
  val1.server_name();
  const_val.server_name();
  val1.discovery_url();
  const_val.discovery_url();
  val1.server_capabilities();
  const_val.server_capabilities();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ApplicationInstanceCertificate_SimpleType)
{
  ApplicationInstanceCertificate val1{};
  ApplicationInstanceCertificate val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, MessageSecurityMode_Enumeration)
{
  MessageSecurityMode e{};
  e = MessageSecurityMode::Invalid;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Invalid");
  e = MessageSecurityMode::None;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "None");
  e = MessageSecurityMode::Sign;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Sign");
  e = MessageSecurityMode::SignAndEncrypt;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "SignAndEncrypt");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<MessageSecurityMode>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<MessageSecurityMode>(-9999));
}

TEST_F(GeneratedDataTypeTests, UserTokenType_Enumeration)
{
  UserTokenType e{};
  e = UserTokenType::Anonymous;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Anonymous");
  e = UserTokenType::UserName;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "UserName");
  e = UserTokenType::Certificate;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Certificate");
  e = UserTokenType::IssuedToken;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "IssuedToken");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<UserTokenType>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<UserTokenType>(-9999));
}

TEST_F(GeneratedDataTypeTests, UserTokenPolicy_Structure)
{
  UserTokenPolicy val1;
  val1.policy_id() = "test";
  val1.token_type() = UserTokenType::Anonymous;
  val1.issued_token_type() = "test";
  val1.issuer_endpoint_url() = "test";
  val1.security_policy_uri() = "test";
  const UserTokenPolicy& const_val = val1;
  val1.policy_id();
  const_val.policy_id();
  val1.token_type();
  const_val.token_type();
  val1.issued_token_type();
  const_val.issued_token_type();
  val1.issuer_endpoint_url();
  const_val.issuer_endpoint_url();
  val1.security_policy_uri();
  const_val.security_policy_uri();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, EndpointDescription_Structure)
{
  EndpointDescription val1;
  val1.endpoint_url() = "test";
  val1.server().application_uri() = "test";
  val1.server().product_uri() = "test";
  val1.server().application_name() = LocalizedText{"en", "test"};
  val1.server().application_type() = ApplicationType::Server;
  val1.server().gateway_server_uri() = "test";
  val1.server().discovery_profile_uri() = "test";
  val1.server().discovery_urls().resize(2);
  val1.server().discovery_urls()[0] = "test";
  val1.server_certificate() = ByteString{1, 2, 3};
  val1.security_mode() = MessageSecurityMode::Invalid;
  val1.security_policy_uri() = "test";
  val1.user_identity_tokens().resize(2);
  val1.user_identity_tokens()[0].policy_id() = "test";
  val1.user_identity_tokens()[0].token_type() = UserTokenType::Anonymous;
  val1.user_identity_tokens()[0].issued_token_type() = "test";
  val1.user_identity_tokens()[0].issuer_endpoint_url() = "test";
  val1.user_identity_tokens()[0].security_policy_uri() = "test";
  val1.transport_profile_uri() = "test";
  val1.security_level() = 123;
  const EndpointDescription& const_val = val1;
  val1.endpoint_url();
  const_val.endpoint_url();
  val1.server();
  const_val.server();
  val1.server_certificate();
  const_val.server_certificate();
  val1.security_mode();
  const_val.security_mode();
  val1.security_policy_uri();
  const_val.security_policy_uri();
  val1.user_identity_tokens();
  const_val.user_identity_tokens();
  val1.transport_profile_uri();
  const_val.transport_profile_uri();
  val1.security_level();
  const_val.security_level();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, RegisteredServer_Structure)
{
  RegisteredServer val1;
  val1.server_uri() = "test";
  val1.product_uri() = "test";
  val1.server_names().resize(2);
  val1.server_names()[0] = LocalizedText{"en", "test"};
  val1.server_type() = ApplicationType::Server;
  val1.gateway_server_uri() = "test";
  val1.discovery_urls().resize(2);
  val1.discovery_urls()[0] = "test";
  val1.semaphore_file_path() = "test";
  val1.is_online() = true;
  const RegisteredServer& const_val = val1;
  val1.server_uri();
  const_val.server_uri();
  val1.product_uri();
  const_val.product_uri();
  val1.server_names();
  const_val.server_names();
  val1.server_type();
  const_val.server_type();
  val1.gateway_server_uri();
  const_val.gateway_server_uri();
  val1.discovery_urls();
  const_val.discovery_urls();
  val1.semaphore_file_path();
  const_val.semaphore_file_path();
  val1.is_online();
  const_val.is_online();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, DiscoveryConfiguration_Structure)
{
  DiscoveryConfiguration val1;
  const DiscoveryConfiguration& const_val = val1;
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, MdnsDiscoveryConfiguration_Structure)
{
  MdnsDiscoveryConfiguration val1;
  val1.mdns_server_name() = "test";
  val1.server_capabilities().resize(2);
  val1.server_capabilities()[0] = "test";
  const MdnsDiscoveryConfiguration& const_val = val1;
  val1.mdns_server_name();
  const_val.mdns_server_name();
  val1.server_capabilities();
  const_val.server_capabilities();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, SecurityTokenRequestType_Enumeration)
{
  SecurityTokenRequestType e{};
  e = SecurityTokenRequestType::Issue;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Issue");
  e = SecurityTokenRequestType::Renew;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Renew");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<SecurityTokenRequestType>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<SecurityTokenRequestType>(-9999));
}

TEST_F(GeneratedDataTypeTests, SignedSoftwareCertificate_Structure)
{
  SignedSoftwareCertificate val1;
  val1.certificate_data() = ByteString{1, 2, 3};
  val1.signature() = ByteString{1, 2, 3};
  const SignedSoftwareCertificate& const_val = val1;
  val1.certificate_data();
  const_val.certificate_data();
  val1.signature();
  const_val.signature();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, SessionAuthenticationToken_SimpleType)
{
  SessionAuthenticationToken val1{};
  SessionAuthenticationToken val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, UserIdentityToken_AbstractStructure)
{
  // Testing only metadata for abstract structures
  // we cannot instantiate them
}

TEST_F(GeneratedDataTypeTests, AnonymousIdentityToken_Structure)
{
  AnonymousIdentityToken val1;
  const AnonymousIdentityToken& const_val = val1;
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, UserNameIdentityToken_Structure)
{
  UserNameIdentityToken val1;
  val1.user_name() = "test";
  val1.password() = ByteString{1, 2, 3};
  val1.encryption_algorithm() = "test";
  const UserNameIdentityToken& const_val = val1;
  val1.user_name();
  const_val.user_name();
  val1.password();
  const_val.password();
  val1.encryption_algorithm();
  const_val.encryption_algorithm();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, X509IdentityToken_Structure)
{
  X509IdentityToken val1;
  val1.certificate_data() = ByteString{1, 2, 3};
  const X509IdentityToken& const_val = val1;
  val1.certificate_data();
  const_val.certificate_data();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, IssuedIdentityToken_Structure)
{
  IssuedIdentityToken val1;
  val1.token_data() = ByteString{1, 2, 3};
  val1.encryption_algorithm() = "test";
  const IssuedIdentityToken& const_val = val1;
  val1.token_data();
  const_val.token_data();
  val1.encryption_algorithm();
  const_val.encryption_algorithm();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, NodeAttributesMask_Enumeration)
{
  NodeAttributesMask e{};
  e = NodeAttributesMask::None;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "None");
  e = NodeAttributesMask::AccessLevel;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "AccessLevel");
  e = NodeAttributesMask::ArrayDimensions;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "ArrayDimensions");
  e = NodeAttributesMask::BrowseName;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "BrowseName");
  e = NodeAttributesMask::ContainsNoLoops;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "ContainsNoLoops");
  e = NodeAttributesMask::DataType;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "DataType");
  e = NodeAttributesMask::Description;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Description");
  e = NodeAttributesMask::DisplayName;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "DisplayName");
  e = NodeAttributesMask::EventNotifier;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "EventNotifier");
  e = NodeAttributesMask::Executable;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Executable");
  e = NodeAttributesMask::Historizing;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Historizing");
  e = NodeAttributesMask::InverseName;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "InverseName");
  e = NodeAttributesMask::IsAbstract;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "IsAbstract");
  e = NodeAttributesMask::MinimumSamplingInterval;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "MinimumSamplingInterval");
  e = NodeAttributesMask::NodeClass;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "NodeClass");
  e = NodeAttributesMask::NodeId;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "NodeId");
  e = NodeAttributesMask::Symmetric;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Symmetric");
  e = NodeAttributesMask::UserAccessLevel;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "UserAccessLevel");
  e = NodeAttributesMask::UserExecutable;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "UserExecutable");
  e = NodeAttributesMask::UserWriteMask;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "UserWriteMask");
  e = NodeAttributesMask::ValueRank;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "ValueRank");
  e = NodeAttributesMask::WriteMask;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "WriteMask");
  e = NodeAttributesMask::Value;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Value");
  e = NodeAttributesMask::DataTypeDefinition;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "DataTypeDefinition");
  e = NodeAttributesMask::RolePermissions;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "RolePermissions");
  e = NodeAttributesMask::AccessRestrictions;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "AccessRestrictions");
  e = NodeAttributesMask::All;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "All");
  e = NodeAttributesMask::BaseNode;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "BaseNode");
  e = NodeAttributesMask::Object;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Object");
  e = NodeAttributesMask::ObjectType;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "ObjectType");
  e = NodeAttributesMask::Variable;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Variable");
  e = NodeAttributesMask::VariableType;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "VariableType");
  e = NodeAttributesMask::Method;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Method");
  e = NodeAttributesMask::ReferenceType;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "ReferenceType");
  e = NodeAttributesMask::View;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "View");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<NodeAttributesMask>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<NodeAttributesMask>(-9999));
}

TEST_F(GeneratedDataTypeTests, AddNodesItem_Structure)
{
  AddNodesItem val1;
  val1.parent_node_id() = ExpandedNodeId{NodeId{1234}};
  val1.reference_type_id() = NodeId{1234};
  val1.requested_new_node_id() = ExpandedNodeId{NodeId{1234}};
  val1.browse_name() = QualifiedName{"test"};
  val1.node_class() = NodeClass::Unspecified;
  val1.type_definition() = ExpandedNodeId{NodeId{1234}};
  const AddNodesItem& const_val = val1;
  val1.parent_node_id();
  const_val.parent_node_id();
  val1.reference_type_id();
  const_val.reference_type_id();
  val1.requested_new_node_id();
  const_val.requested_new_node_id();
  val1.browse_name();
  const_val.browse_name();
  val1.node_class();
  const_val.node_class();
  val1.node_attributes();
  const_val.node_attributes();
  val1.type_definition();
  const_val.type_definition();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, AddReferencesItem_Structure)
{
  AddReferencesItem val1;
  val1.source_node_id() = NodeId{1234};
  val1.reference_type_id() = NodeId{1234};
  val1.is_forward() = true;
  val1.target_server_uri() = "test";
  val1.target_node_id() = ExpandedNodeId{NodeId{1234}};
  val1.target_node_class() = NodeClass::Unspecified;
  const AddReferencesItem& const_val = val1;
  val1.source_node_id();
  const_val.source_node_id();
  val1.reference_type_id();
  const_val.reference_type_id();
  val1.is_forward();
  const_val.is_forward();
  val1.target_server_uri();
  const_val.target_server_uri();
  val1.target_node_id();
  const_val.target_node_id();
  val1.target_node_class();
  const_val.target_node_class();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, DeleteNodesItem_Structure)
{
  DeleteNodesItem val1;
  val1.node_id() = NodeId{1234};
  val1.delete_target_references() = true;
  const DeleteNodesItem& const_val = val1;
  val1.node_id();
  const_val.node_id();
  val1.delete_target_references();
  const_val.delete_target_references();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, DeleteReferencesItem_Structure)
{
  DeleteReferencesItem val1;
  val1.source_node_id() = NodeId{1234};
  val1.reference_type_id() = NodeId{1234};
  val1.is_forward() = true;
  val1.target_node_id() = ExpandedNodeId{NodeId{1234}};
  val1.delete_bidirectional() = true;
  const DeleteReferencesItem& const_val = val1;
  val1.source_node_id();
  const_val.source_node_id();
  val1.reference_type_id();
  const_val.reference_type_id();
  val1.is_forward();
  const_val.is_forward();
  val1.target_node_id();
  const_val.target_node_id();
  val1.delete_bidirectional();
  const_val.delete_bidirectional();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, AttributeWriteMask_OptionSet)
{
  AttributeWriteMask o;
  auto default_str = to_string(o);
  EXPECT_NE(default_str.find("AttributeWriteMask"), std::string::npos);
  o.set(AttributeWriteMask::Bit::AccessLevel);
  EXPECT_TRUE(o.test(AttributeWriteMask::Bit::AccessLevel));
  EXPECT_NE(to_string(o).find("AccessLevel"), std::string::npos);
  o.set(AttributeWriteMask::Bit::ArrayDimensions);
  EXPECT_TRUE(o.test(AttributeWriteMask::Bit::ArrayDimensions));
  EXPECT_NE(to_string(o).find("ArrayDimensions"), std::string::npos);
  o.set(AttributeWriteMask::Bit::BrowseName);
  EXPECT_TRUE(o.test(AttributeWriteMask::Bit::BrowseName));
  EXPECT_NE(to_string(o).find("BrowseName"), std::string::npos);
  o.set(AttributeWriteMask::Bit::ContainsNoLoops);
  EXPECT_TRUE(o.test(AttributeWriteMask::Bit::ContainsNoLoops));
  EXPECT_NE(to_string(o).find("ContainsNoLoops"), std::string::npos);
  o.set(AttributeWriteMask::Bit::DataType);
  EXPECT_TRUE(o.test(AttributeWriteMask::Bit::DataType));
  EXPECT_NE(to_string(o).find("DataType"), std::string::npos);
  o.set(AttributeWriteMask::Bit::Description);
  EXPECT_TRUE(o.test(AttributeWriteMask::Bit::Description));
  EXPECT_NE(to_string(o).find("Description"), std::string::npos);
  o.set(AttributeWriteMask::Bit::DisplayName);
  EXPECT_TRUE(o.test(AttributeWriteMask::Bit::DisplayName));
  EXPECT_NE(to_string(o).find("DisplayName"), std::string::npos);
  o.set(AttributeWriteMask::Bit::EventNotifier);
  EXPECT_TRUE(o.test(AttributeWriteMask::Bit::EventNotifier));
  EXPECT_NE(to_string(o).find("EventNotifier"), std::string::npos);
  o.set(AttributeWriteMask::Bit::Executable);
  EXPECT_TRUE(o.test(AttributeWriteMask::Bit::Executable));
  EXPECT_NE(to_string(o).find("Executable"), std::string::npos);
  o.set(AttributeWriteMask::Bit::Historizing);
  EXPECT_TRUE(o.test(AttributeWriteMask::Bit::Historizing));
  EXPECT_NE(to_string(o).find("Historizing"), std::string::npos);
  o.set(AttributeWriteMask::Bit::InverseName);
  EXPECT_TRUE(o.test(AttributeWriteMask::Bit::InverseName));
  EXPECT_NE(to_string(o).find("InverseName"), std::string::npos);
  o.set(AttributeWriteMask::Bit::IsAbstract);
  EXPECT_TRUE(o.test(AttributeWriteMask::Bit::IsAbstract));
  EXPECT_NE(to_string(o).find("IsAbstract"), std::string::npos);
  o.set(AttributeWriteMask::Bit::MinimumSamplingInterval);
  EXPECT_TRUE(o.test(AttributeWriteMask::Bit::MinimumSamplingInterval));
  EXPECT_NE(to_string(o).find("MinimumSamplingInterval"), std::string::npos);
  o.set(AttributeWriteMask::Bit::NodeClass);
  EXPECT_TRUE(o.test(AttributeWriteMask::Bit::NodeClass));
  EXPECT_NE(to_string(o).find("NodeClass"), std::string::npos);
  o.set(AttributeWriteMask::Bit::NodeId);
  EXPECT_TRUE(o.test(AttributeWriteMask::Bit::NodeId));
  EXPECT_NE(to_string(o).find("NodeId"), std::string::npos);
  o.set(AttributeWriteMask::Bit::Symmetric);
  EXPECT_TRUE(o.test(AttributeWriteMask::Bit::Symmetric));
  EXPECT_NE(to_string(o).find("Symmetric"), std::string::npos);
  o.set(AttributeWriteMask::Bit::UserAccessLevel);
  EXPECT_TRUE(o.test(AttributeWriteMask::Bit::UserAccessLevel));
  EXPECT_NE(to_string(o).find("UserAccessLevel"), std::string::npos);
  o.set(AttributeWriteMask::Bit::UserExecutable);
  EXPECT_TRUE(o.test(AttributeWriteMask::Bit::UserExecutable));
  EXPECT_NE(to_string(o).find("UserExecutable"), std::string::npos);
  o.set(AttributeWriteMask::Bit::UserWriteMask);
  EXPECT_TRUE(o.test(AttributeWriteMask::Bit::UserWriteMask));
  EXPECT_NE(to_string(o).find("UserWriteMask"), std::string::npos);
  o.set(AttributeWriteMask::Bit::ValueRank);
  EXPECT_TRUE(o.test(AttributeWriteMask::Bit::ValueRank));
  EXPECT_NE(to_string(o).find("ValueRank"), std::string::npos);
  o.set(AttributeWriteMask::Bit::WriteMask);
  EXPECT_TRUE(o.test(AttributeWriteMask::Bit::WriteMask));
  EXPECT_NE(to_string(o).find("WriteMask"), std::string::npos);
  o.set(AttributeWriteMask::Bit::ValueForVariableType);
  EXPECT_TRUE(o.test(AttributeWriteMask::Bit::ValueForVariableType));
  EXPECT_NE(to_string(o).find("ValueForVariableType"), std::string::npos);
  o.set(AttributeWriteMask::Bit::DataTypeDefinition);
  EXPECT_TRUE(o.test(AttributeWriteMask::Bit::DataTypeDefinition));
  EXPECT_NE(to_string(o).find("DataTypeDefinition"), std::string::npos);
  o.set(AttributeWriteMask::Bit::RolePermissions);
  EXPECT_TRUE(o.test(AttributeWriteMask::Bit::RolePermissions));
  EXPECT_NE(to_string(o).find("RolePermissions"), std::string::npos);
  o.set(AttributeWriteMask::Bit::AccessRestrictions);
  EXPECT_TRUE(o.test(AttributeWriteMask::Bit::AccessRestrictions));
  EXPECT_NE(to_string(o).find("AccessRestrictions"), std::string::npos);
  o.set(AttributeWriteMask::Bit::AccessLevelEx);
  EXPECT_TRUE(o.test(AttributeWriteMask::Bit::AccessLevelEx));
  EXPECT_NE(to_string(o).find("AccessLevelEx"), std::string::npos);
  auto all_set_str = to_string(o);
  EXPECT_NE(all_set_str.find("AccessLevel"), std::string::npos);
  EXPECT_NE(all_set_str.find("ArrayDimensions"), std::string::npos);
  EXPECT_NE(all_set_str.find("BrowseName"), std::string::npos);
  EXPECT_NE(all_set_str.find("ContainsNoLoops"), std::string::npos);
  EXPECT_NE(all_set_str.find("DataType"), std::string::npos);
  EXPECT_NE(all_set_str.find("Description"), std::string::npos);
  EXPECT_NE(all_set_str.find("DisplayName"), std::string::npos);
  EXPECT_NE(all_set_str.find("EventNotifier"), std::string::npos);
  EXPECT_NE(all_set_str.find("Executable"), std::string::npos);
  EXPECT_NE(all_set_str.find("Historizing"), std::string::npos);
  EXPECT_NE(all_set_str.find("InverseName"), std::string::npos);
  EXPECT_NE(all_set_str.find("IsAbstract"), std::string::npos);
  EXPECT_NE(all_set_str.find("MinimumSamplingInterval"), std::string::npos);
  EXPECT_NE(all_set_str.find("NodeClass"), std::string::npos);
  EXPECT_NE(all_set_str.find("NodeId"), std::string::npos);
  EXPECT_NE(all_set_str.find("Symmetric"), std::string::npos);
  EXPECT_NE(all_set_str.find("UserAccessLevel"), std::string::npos);
  EXPECT_NE(all_set_str.find("UserExecutable"), std::string::npos);
  EXPECT_NE(all_set_str.find("UserWriteMask"), std::string::npos);
  EXPECT_NE(all_set_str.find("ValueRank"), std::string::npos);
  EXPECT_NE(all_set_str.find("WriteMask"), std::string::npos);
  EXPECT_NE(all_set_str.find("ValueForVariableType"), std::string::npos);
  EXPECT_NE(all_set_str.find("DataTypeDefinition"), std::string::npos);
  EXPECT_NE(all_set_str.find("RolePermissions"), std::string::npos);
  EXPECT_NE(all_set_str.find("AccessRestrictions"), std::string::npos);
  EXPECT_NE(all_set_str.find("AccessLevelEx"), std::string::npos);
  o.reset(AttributeWriteMask::Bit::AccessLevel);
  EXPECT_FALSE(o.test(AttributeWriteMask::Bit::AccessLevel));
  o.reset(AttributeWriteMask::Bit::ArrayDimensions);
  EXPECT_FALSE(o.test(AttributeWriteMask::Bit::ArrayDimensions));
  o.reset(AttributeWriteMask::Bit::BrowseName);
  EXPECT_FALSE(o.test(AttributeWriteMask::Bit::BrowseName));
  o.reset(AttributeWriteMask::Bit::ContainsNoLoops);
  EXPECT_FALSE(o.test(AttributeWriteMask::Bit::ContainsNoLoops));
  o.reset(AttributeWriteMask::Bit::DataType);
  EXPECT_FALSE(o.test(AttributeWriteMask::Bit::DataType));
  o.reset(AttributeWriteMask::Bit::Description);
  EXPECT_FALSE(o.test(AttributeWriteMask::Bit::Description));
  o.reset(AttributeWriteMask::Bit::DisplayName);
  EXPECT_FALSE(o.test(AttributeWriteMask::Bit::DisplayName));
  o.reset(AttributeWriteMask::Bit::EventNotifier);
  EXPECT_FALSE(o.test(AttributeWriteMask::Bit::EventNotifier));
  o.reset(AttributeWriteMask::Bit::Executable);
  EXPECT_FALSE(o.test(AttributeWriteMask::Bit::Executable));
  o.reset(AttributeWriteMask::Bit::Historizing);
  EXPECT_FALSE(o.test(AttributeWriteMask::Bit::Historizing));
  o.reset(AttributeWriteMask::Bit::InverseName);
  EXPECT_FALSE(o.test(AttributeWriteMask::Bit::InverseName));
  o.reset(AttributeWriteMask::Bit::IsAbstract);
  EXPECT_FALSE(o.test(AttributeWriteMask::Bit::IsAbstract));
  o.reset(AttributeWriteMask::Bit::MinimumSamplingInterval);
  EXPECT_FALSE(o.test(AttributeWriteMask::Bit::MinimumSamplingInterval));
  o.reset(AttributeWriteMask::Bit::NodeClass);
  EXPECT_FALSE(o.test(AttributeWriteMask::Bit::NodeClass));
  o.reset(AttributeWriteMask::Bit::NodeId);
  EXPECT_FALSE(o.test(AttributeWriteMask::Bit::NodeId));
  o.reset(AttributeWriteMask::Bit::Symmetric);
  EXPECT_FALSE(o.test(AttributeWriteMask::Bit::Symmetric));
  o.reset(AttributeWriteMask::Bit::UserAccessLevel);
  EXPECT_FALSE(o.test(AttributeWriteMask::Bit::UserAccessLevel));
  o.reset(AttributeWriteMask::Bit::UserExecutable);
  EXPECT_FALSE(o.test(AttributeWriteMask::Bit::UserExecutable));
  o.reset(AttributeWriteMask::Bit::UserWriteMask);
  EXPECT_FALSE(o.test(AttributeWriteMask::Bit::UserWriteMask));
  o.reset(AttributeWriteMask::Bit::ValueRank);
  EXPECT_FALSE(o.test(AttributeWriteMask::Bit::ValueRank));
  o.reset(AttributeWriteMask::Bit::WriteMask);
  EXPECT_FALSE(o.test(AttributeWriteMask::Bit::WriteMask));
  o.reset(AttributeWriteMask::Bit::ValueForVariableType);
  EXPECT_FALSE(o.test(AttributeWriteMask::Bit::ValueForVariableType));
  o.reset(AttributeWriteMask::Bit::DataTypeDefinition);
  EXPECT_FALSE(o.test(AttributeWriteMask::Bit::DataTypeDefinition));
  o.reset(AttributeWriteMask::Bit::RolePermissions);
  EXPECT_FALSE(o.test(AttributeWriteMask::Bit::RolePermissions));
  o.reset(AttributeWriteMask::Bit::AccessRestrictions);
  EXPECT_FALSE(o.test(AttributeWriteMask::Bit::AccessRestrictions));
  o.reset(AttributeWriteMask::Bit::AccessLevelEx);
  EXPECT_FALSE(o.test(AttributeWriteMask::Bit::AccessLevelEx));
  auto u = o.as_underlying_type();
  o.from_underlying_type(u);
  EXPECT_EQ(o.as_underlying_type(), u);
}

TEST_F(GeneratedDataTypeTests, ContinuationPoint_SimpleType)
{
  ContinuationPoint val1{};
  ContinuationPoint val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, RelativePathElement_Structure)
{
  RelativePathElement val1;
  val1.reference_type_id() = NodeId{1234};
  val1.is_inverse() = true;
  val1.include_subtypes() = true;
  val1.target_name() = QualifiedName{"test"};
  const RelativePathElement& const_val = val1;
  val1.reference_type_id();
  const_val.reference_type_id();
  val1.is_inverse();
  const_val.is_inverse();
  val1.include_subtypes();
  const_val.include_subtypes();
  val1.target_name();
  const_val.target_name();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, RelativePath_Structure)
{
  RelativePath val1;
  val1.elements().resize(2);
  val1.elements()[0].reference_type_id() = NodeId{1234};
  val1.elements()[0].is_inverse() = true;
  val1.elements()[0].include_subtypes() = true;
  val1.elements()[0].target_name() = QualifiedName{"test"};
  const RelativePath& const_val = val1;
  val1.elements();
  const_val.elements();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, Counter_SimpleType)
{
  Counter val1{};
  Counter val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, NumericRange_SimpleType)
{
  NumericRange val1{};
  NumericRange val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, EndpointConfiguration_Structure)
{
  EndpointConfiguration val1;
  val1.operation_timeout() = 123456;
  val1.use_binary_encoding() = true;
  val1.max_string_length() = 123456;
  val1.max_byte_string_length() = 123456;
  val1.max_array_length() = 123456;
  val1.max_message_size() = 123456;
  val1.max_buffer_size() = 123456;
  val1.channel_lifetime() = 123456;
  val1.security_token_lifetime() = 123456;
  const EndpointConfiguration& const_val = val1;
  val1.operation_timeout();
  const_val.operation_timeout();
  val1.use_binary_encoding();
  const_val.use_binary_encoding();
  val1.max_string_length();
  const_val.max_string_length();
  val1.max_byte_string_length();
  const_val.max_byte_string_length();
  val1.max_array_length();
  const_val.max_array_length();
  val1.max_message_size();
  const_val.max_message_size();
  val1.max_buffer_size();
  const_val.max_buffer_size();
  val1.channel_lifetime();
  const_val.channel_lifetime();
  val1.security_token_lifetime();
  const_val.security_token_lifetime();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, FilterOperator_Enumeration)
{
  FilterOperator e{};
  e = FilterOperator::Equals;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Equals");
  e = FilterOperator::IsNull;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "IsNull");
  e = FilterOperator::GreaterThan;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "GreaterThan");
  e = FilterOperator::LessThan;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "LessThan");
  e = FilterOperator::GreaterThanOrEqual;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "GreaterThanOrEqual");
  e = FilterOperator::LessThanOrEqual;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "LessThanOrEqual");
  e = FilterOperator::Like;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Like");
  e = FilterOperator::Not;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Not");
  e = FilterOperator::Between;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Between");
  e = FilterOperator::InList;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "InList");
  e = FilterOperator::And;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "And");
  e = FilterOperator::Or;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Or");
  e = FilterOperator::Cast;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Cast");
  e = FilterOperator::InView;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "InView");
  e = FilterOperator::OfType;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "OfType");
  e = FilterOperator::RelatedTo;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "RelatedTo");
  e = FilterOperator::BitwiseAnd;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "BitwiseAnd");
  e = FilterOperator::BitwiseOr;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "BitwiseOr");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<FilterOperator>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<FilterOperator>(-9999));
}

TEST_F(GeneratedDataTypeTests, ContentFilterElement_Structure)
{
  ContentFilterElement val1;
  val1.filter_operator() = FilterOperator::Equals;
  val1.filter_operands().resize(2);
  const ContentFilterElement& const_val = val1;
  val1.filter_operator();
  const_val.filter_operator();
  val1.filter_operands();
  const_val.filter_operands();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ContentFilter_Structure)
{
  ContentFilter val1;
  val1.elements().resize(2);
  val1.elements()[0].filter_operator() = FilterOperator::Equals;
  val1.elements()[0].filter_operands().resize(2);
  const ContentFilter& const_val = val1;
  val1.elements();
  const_val.elements();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, FilterOperand_AbstractStructure)
{
  // Testing only metadata for abstract structures
  // we cannot instantiate them
}

TEST_F(GeneratedDataTypeTests, ElementOperand_Structure)
{
  ElementOperand val1;
  val1.index() = 123456;
  const ElementOperand& const_val = val1;
  val1.index();
  const_val.index();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, LiteralOperand_Structure)
{
  LiteralOperand val1;
  val1.value() = Variant{123};
  const LiteralOperand& const_val = val1;
  val1.value();
  const_val.value();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, AttributeOperand_Structure)
{
  AttributeOperand val1;
  val1.node_id() = NodeId{1234};
  val1.alias() = "test";
  val1.browse_path().elements().resize(2);
  val1.browse_path().elements()[0].reference_type_id() = NodeId{1234};
  val1.browse_path().elements()[0].is_inverse() = true;
  val1.browse_path().elements()[0].include_subtypes() = true;
  val1.browse_path().elements()[0].target_name() = QualifiedName{"test"};
  val1.attribute_id() = 123456;
  val1.index_range() = "test";
  const AttributeOperand& const_val = val1;
  val1.node_id();
  const_val.node_id();
  val1.alias();
  const_val.alias();
  val1.browse_path();
  const_val.browse_path();
  val1.attribute_id();
  const_val.attribute_id();
  val1.index_range();
  const_val.index_range();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, SimpleAttributeOperand_Structure)
{
  SimpleAttributeOperand val1;
  val1.type_definition_id() = NodeId{1234};
  val1.browse_path().resize(2);
  val1.browse_path()[0] = QualifiedName{"test"};
  val1.attribute_id() = 123456;
  val1.index_range() = "test";
  const SimpleAttributeOperand& const_val = val1;
  val1.type_definition_id();
  const_val.type_definition_id();
  val1.browse_path();
  const_val.browse_path();
  val1.attribute_id();
  const_val.attribute_id();
  val1.index_range();
  const_val.index_range();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ModificationInfo_Structure)
{
  ModificationInfo val1;
  val1.modification_time() = DateTime::now();
  val1.update_type() = HistoryUpdateType::Insert;
  val1.user_name() = "test";
  const ModificationInfo& const_val = val1;
  val1.modification_time();
  const_val.modification_time();
  val1.update_type();
  const_val.update_type();
  val1.user_name();
  const_val.user_name();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, HistoryEvent_Structure)
{
  HistoryEvent val1;
  val1.events().resize(2);
  val1.events()[0].event_fields().resize(2);
  const HistoryEvent& const_val = val1;
  val1.events();
  const_val.events();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, HistoryModifiedEvent_Structure)
{
  HistoryModifiedEvent val1;
  val1.modification_infos().resize(2);
  val1.modification_infos()[0].modification_time() = DateTime::now();
  val1.modification_infos()[0].update_type() = HistoryUpdateType::Insert;
  val1.modification_infos()[0].user_name() = "test";
  const HistoryModifiedEvent& const_val = val1;
  val1.modification_infos();
  const_val.modification_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, HistoryUpdateType_Enumeration)
{
  HistoryUpdateType e{};
  e = HistoryUpdateType::Insert;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Insert");
  e = HistoryUpdateType::Replace;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Replace");
  e = HistoryUpdateType::Update;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Update");
  e = HistoryUpdateType::Delete;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Delete");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<HistoryUpdateType>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<HistoryUpdateType>(-9999));
}

TEST_F(GeneratedDataTypeTests, PerformUpdateType_Enumeration)
{
  PerformUpdateType e{};
  e = PerformUpdateType::Insert;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Insert");
  e = PerformUpdateType::Replace;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Replace");
  e = PerformUpdateType::Update;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Update");
  e = PerformUpdateType::Remove;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Remove");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<PerformUpdateType>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<PerformUpdateType>(-9999));
}

TEST_F(GeneratedDataTypeTests, MonitoringFilter_Structure)
{
  MonitoringFilter val1;
  const MonitoringFilter& const_val = val1;
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, EventFilter_Structure)
{
  EventFilter val1;
  val1.select_clauses().resize(2);
  val1.select_clauses()[0].type_definition_id() = NodeId{1234};
  val1.select_clauses()[0].browse_path().resize(2);
  val1.select_clauses()[0].browse_path()[0] = QualifiedName{"test"};
  val1.select_clauses()[0].attribute_id() = 123456;
  val1.select_clauses()[0].index_range() = "test";
  val1.where_clause().elements().resize(2);
  val1.where_clause().elements()[0].filter_operator() = FilterOperator::Equals;
  val1.where_clause().elements()[0].filter_operands().resize(2);
  const EventFilter& const_val = val1;
  val1.select_clauses();
  const_val.select_clauses();
  val1.where_clause();
  const_val.where_clause();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, AggregateConfiguration_Structure)
{
  AggregateConfiguration val1;
  val1.use_server_capabilities_defaults() = true;
  val1.treat_uncertain_as_bad() = true;
  val1.percent_data_bad() = 123;
  val1.percent_data_good() = 123;
  val1.use_sloped_extrapolation() = true;
  const AggregateConfiguration& const_val = val1;
  val1.use_server_capabilities_defaults();
  const_val.use_server_capabilities_defaults();
  val1.treat_uncertain_as_bad();
  const_val.treat_uncertain_as_bad();
  val1.percent_data_bad();
  const_val.percent_data_bad();
  val1.percent_data_good();
  const_val.percent_data_good();
  val1.use_sloped_extrapolation();
  const_val.use_sloped_extrapolation();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, HistoryEventFieldList_Structure)
{
  HistoryEventFieldList val1;
  val1.event_fields().resize(2);
  const HistoryEventFieldList& const_val = val1;
  val1.event_fields();
  const_val.event_fields();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, BuildInfo_Structure)
{
  BuildInfo val1;
  val1.product_uri() = "test";
  val1.manufacturer_name() = "test";
  val1.product_name() = "test";
  val1.software_version() = "test";
  val1.build_number() = "test";
  val1.build_date() = DateTime::now();
  const BuildInfo& const_val = val1;
  val1.product_uri();
  const_val.product_uri();
  val1.manufacturer_name();
  const_val.manufacturer_name();
  val1.product_name();
  const_val.product_name();
  val1.software_version();
  const_val.software_version();
  val1.build_number();
  const_val.build_number();
  val1.build_date();
  const_val.build_date();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, RedundancySupport_Enumeration)
{
  RedundancySupport e{};
  e = RedundancySupport::None;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "None");
  e = RedundancySupport::Cold;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Cold");
  e = RedundancySupport::Warm;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Warm");
  e = RedundancySupport::Hot;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Hot");
  e = RedundancySupport::Transparent;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Transparent");
  e = RedundancySupport::HotAndMirrored;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "HotAndMirrored");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<RedundancySupport>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<RedundancySupport>(-9999));
}

TEST_F(GeneratedDataTypeTests, ServerState_Enumeration)
{
  ServerState e{};
  e = ServerState::Running;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Running");
  e = ServerState::Failed;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Failed");
  e = ServerState::NoConfiguration;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "NoConfiguration");
  e = ServerState::Suspended;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Suspended");
  e = ServerState::Shutdown;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Shutdown");
  e = ServerState::Test;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Test");
  e = ServerState::CommunicationFault;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "CommunicationFault");
  e = ServerState::Unknown;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Unknown");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<ServerState>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<ServerState>(-9999));
}

TEST_F(GeneratedDataTypeTests, RedundantServerDataType_Structure)
{
  RedundantServerDataType val1;
  val1.server_id() = "test";
  val1.service_level() = 123;
  val1.server_state() = ServerState::Running;
  const RedundantServerDataType& const_val = val1;
  val1.server_id();
  const_val.server_id();
  val1.service_level();
  const_val.service_level();
  val1.server_state();
  const_val.server_state();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, EndpointUrlListDataType_Structure)
{
  EndpointUrlListDataType val1;
  val1.endpoint_url_list().resize(2);
  val1.endpoint_url_list()[0] = "test";
  const EndpointUrlListDataType& const_val = val1;
  val1.endpoint_url_list();
  const_val.endpoint_url_list();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, NetworkGroupDataType_Structure)
{
  NetworkGroupDataType val1;
  val1.server_uri() = "test";
  val1.network_paths().resize(2);
  val1.network_paths()[0].endpoint_url_list().resize(2);
  val1.network_paths()[0].endpoint_url_list()[0] = "test";
  const NetworkGroupDataType& const_val = val1;
  val1.server_uri();
  const_val.server_uri();
  val1.network_paths();
  const_val.network_paths();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, SamplingIntervalDiagnosticsDataType_Structure)
{
  SamplingIntervalDiagnosticsDataType val1;
  val1.sampling_interval() = 1.5;
  val1.monitored_item_count() = 123456;
  val1.max_monitored_item_count() = 123456;
  val1.disabled_monitored_item_count() = 123456;
  const SamplingIntervalDiagnosticsDataType& const_val = val1;
  val1.sampling_interval();
  const_val.sampling_interval();
  val1.monitored_item_count();
  const_val.monitored_item_count();
  val1.max_monitored_item_count();
  const_val.max_monitored_item_count();
  val1.disabled_monitored_item_count();
  const_val.disabled_monitored_item_count();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ServerDiagnosticsSummaryDataType_Structure)
{
  ServerDiagnosticsSummaryDataType val1;
  val1.server_view_count() = 123456;
  val1.current_session_count() = 123456;
  val1.cumulated_session_count() = 123456;
  val1.security_rejected_session_count() = 123456;
  val1.rejected_session_count() = 123456;
  val1.session_timeout_count() = 123456;
  val1.session_abort_count() = 123456;
  val1.current_subscription_count() = 123456;
  val1.cumulated_subscription_count() = 123456;
  val1.publishing_interval_count() = 123456;
  val1.security_rejected_requests_count() = 123456;
  val1.rejected_requests_count() = 123456;
  const ServerDiagnosticsSummaryDataType& const_val = val1;
  val1.server_view_count();
  const_val.server_view_count();
  val1.current_session_count();
  const_val.current_session_count();
  val1.cumulated_session_count();
  const_val.cumulated_session_count();
  val1.security_rejected_session_count();
  const_val.security_rejected_session_count();
  val1.rejected_session_count();
  const_val.rejected_session_count();
  val1.session_timeout_count();
  const_val.session_timeout_count();
  val1.session_abort_count();
  const_val.session_abort_count();
  val1.current_subscription_count();
  const_val.current_subscription_count();
  val1.cumulated_subscription_count();
  const_val.cumulated_subscription_count();
  val1.publishing_interval_count();
  const_val.publishing_interval_count();
  val1.security_rejected_requests_count();
  const_val.security_rejected_requests_count();
  val1.rejected_requests_count();
  const_val.rejected_requests_count();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ServerStatusDataType_Structure)
{
  ServerStatusDataType val1;
  val1.start_time() = DateTime::now();
  val1.current_time() = DateTime::now();
  val1.state() = ServerState::Running;
  val1.build_info().product_uri() = "test";
  val1.build_info().manufacturer_name() = "test";
  val1.build_info().product_name() = "test";
  val1.build_info().software_version() = "test";
  val1.build_info().build_number() = "test";
  val1.build_info().build_date() = DateTime::now();
  val1.seconds_till_shutdown() = 123456;
  val1.shutdown_reason() = LocalizedText{"en", "test"};
  const ServerStatusDataType& const_val = val1;
  val1.start_time();
  const_val.start_time();
  val1.current_time();
  const_val.current_time();
  val1.state();
  const_val.state();
  val1.build_info();
  const_val.build_info();
  val1.seconds_till_shutdown();
  const_val.seconds_till_shutdown();
  val1.shutdown_reason();
  const_val.shutdown_reason();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, SessionDiagnosticsDataType_Structure)
{
  SessionDiagnosticsDataType val1;
  val1.session_id() = NodeId{1234};
  val1.session_name() = "test";
  val1.client_description().application_uri() = "test";
  val1.client_description().product_uri() = "test";
  val1.client_description().application_name() = LocalizedText{"en", "test"};
  val1.client_description().application_type() = ApplicationType::Server;
  val1.client_description().gateway_server_uri() = "test";
  val1.client_description().discovery_profile_uri() = "test";
  val1.client_description().discovery_urls().resize(2);
  val1.client_description().discovery_urls()[0] = "test";
  val1.server_uri() = "test";
  val1.endpoint_url() = "test";
  val1.locale_ids().resize(2);
  val1.locale_ids()[0] = "test";
  val1.actual_session_timeout() = 1.5;
  val1.max_response_message_size() = 123456;
  val1.client_connection_time() = DateTime::now();
  val1.client_last_contact_time() = DateTime::now();
  val1.current_subscriptions_count() = 123456;
  val1.current_monitored_items_count() = 123456;
  val1.current_publish_requests_in_queue() = 123456;
  val1.total_request_count().total_count() = 123456;
  val1.total_request_count().error_count() = 123456;
  val1.unauthorized_request_count() = 123456;
  val1.read_count().total_count() = 123456;
  val1.read_count().error_count() = 123456;
  val1.history_read_count().total_count() = 123456;
  val1.history_read_count().error_count() = 123456;
  val1.write_count().total_count() = 123456;
  val1.write_count().error_count() = 123456;
  val1.history_update_count().total_count() = 123456;
  val1.history_update_count().error_count() = 123456;
  val1.call_count().total_count() = 123456;
  val1.call_count().error_count() = 123456;
  val1.create_monitored_items_count().total_count() = 123456;
  val1.create_monitored_items_count().error_count() = 123456;
  val1.modify_monitored_items_count().total_count() = 123456;
  val1.modify_monitored_items_count().error_count() = 123456;
  val1.set_monitoring_mode_count().total_count() = 123456;
  val1.set_monitoring_mode_count().error_count() = 123456;
  val1.set_triggering_count().total_count() = 123456;
  val1.set_triggering_count().error_count() = 123456;
  val1.delete_monitored_items_count().total_count() = 123456;
  val1.delete_monitored_items_count().error_count() = 123456;
  val1.create_subscription_count().total_count() = 123456;
  val1.create_subscription_count().error_count() = 123456;
  val1.modify_subscription_count().total_count() = 123456;
  val1.modify_subscription_count().error_count() = 123456;
  val1.set_publishing_mode_count().total_count() = 123456;
  val1.set_publishing_mode_count().error_count() = 123456;
  val1.publish_count().total_count() = 123456;
  val1.publish_count().error_count() = 123456;
  val1.republish_count().total_count() = 123456;
  val1.republish_count().error_count() = 123456;
  val1.transfer_subscriptions_count().total_count() = 123456;
  val1.transfer_subscriptions_count().error_count() = 123456;
  val1.delete_subscriptions_count().total_count() = 123456;
  val1.delete_subscriptions_count().error_count() = 123456;
  val1.add_nodes_count().total_count() = 123456;
  val1.add_nodes_count().error_count() = 123456;
  val1.add_references_count().total_count() = 123456;
  val1.add_references_count().error_count() = 123456;
  val1.delete_nodes_count().total_count() = 123456;
  val1.delete_nodes_count().error_count() = 123456;
  val1.delete_references_count().total_count() = 123456;
  val1.delete_references_count().error_count() = 123456;
  val1.browse_count().total_count() = 123456;
  val1.browse_count().error_count() = 123456;
  val1.browse_next_count().total_count() = 123456;
  val1.browse_next_count().error_count() = 123456;
  val1.translate_browse_paths_to_node_ids_count().total_count() = 123456;
  val1.translate_browse_paths_to_node_ids_count().error_count() = 123456;
  val1.query_first_count().total_count() = 123456;
  val1.query_first_count().error_count() = 123456;
  val1.query_next_count().total_count() = 123456;
  val1.query_next_count().error_count() = 123456;
  val1.register_nodes_count().total_count() = 123456;
  val1.register_nodes_count().error_count() = 123456;
  val1.unregister_nodes_count().total_count() = 123456;
  val1.unregister_nodes_count().error_count() = 123456;
  const SessionDiagnosticsDataType& const_val = val1;
  val1.session_id();
  const_val.session_id();
  val1.session_name();
  const_val.session_name();
  val1.client_description();
  const_val.client_description();
  val1.server_uri();
  const_val.server_uri();
  val1.endpoint_url();
  const_val.endpoint_url();
  val1.locale_ids();
  const_val.locale_ids();
  val1.actual_session_timeout();
  const_val.actual_session_timeout();
  val1.max_response_message_size();
  const_val.max_response_message_size();
  val1.client_connection_time();
  const_val.client_connection_time();
  val1.client_last_contact_time();
  const_val.client_last_contact_time();
  val1.current_subscriptions_count();
  const_val.current_subscriptions_count();
  val1.current_monitored_items_count();
  const_val.current_monitored_items_count();
  val1.current_publish_requests_in_queue();
  const_val.current_publish_requests_in_queue();
  val1.total_request_count();
  const_val.total_request_count();
  val1.unauthorized_request_count();
  const_val.unauthorized_request_count();
  val1.read_count();
  const_val.read_count();
  val1.history_read_count();
  const_val.history_read_count();
  val1.write_count();
  const_val.write_count();
  val1.history_update_count();
  const_val.history_update_count();
  val1.call_count();
  const_val.call_count();
  val1.create_monitored_items_count();
  const_val.create_monitored_items_count();
  val1.modify_monitored_items_count();
  const_val.modify_monitored_items_count();
  val1.set_monitoring_mode_count();
  const_val.set_monitoring_mode_count();
  val1.set_triggering_count();
  const_val.set_triggering_count();
  val1.delete_monitored_items_count();
  const_val.delete_monitored_items_count();
  val1.create_subscription_count();
  const_val.create_subscription_count();
  val1.modify_subscription_count();
  const_val.modify_subscription_count();
  val1.set_publishing_mode_count();
  const_val.set_publishing_mode_count();
  val1.publish_count();
  const_val.publish_count();
  val1.republish_count();
  const_val.republish_count();
  val1.transfer_subscriptions_count();
  const_val.transfer_subscriptions_count();
  val1.delete_subscriptions_count();
  const_val.delete_subscriptions_count();
  val1.add_nodes_count();
  const_val.add_nodes_count();
  val1.add_references_count();
  const_val.add_references_count();
  val1.delete_nodes_count();
  const_val.delete_nodes_count();
  val1.delete_references_count();
  const_val.delete_references_count();
  val1.browse_count();
  const_val.browse_count();
  val1.browse_next_count();
  const_val.browse_next_count();
  val1.translate_browse_paths_to_node_ids_count();
  const_val.translate_browse_paths_to_node_ids_count();
  val1.query_first_count();
  const_val.query_first_count();
  val1.query_next_count();
  const_val.query_next_count();
  val1.register_nodes_count();
  const_val.register_nodes_count();
  val1.unregister_nodes_count();
  const_val.unregister_nodes_count();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, SessionSecurityDiagnosticsDataType_Structure)
{
  SessionSecurityDiagnosticsDataType val1;
  val1.session_id() = NodeId{1234};
  val1.client_user_id_of_session() = "test";
  val1.client_user_id_history().resize(2);
  val1.client_user_id_history()[0] = "test";
  val1.authentication_mechanism() = "test";
  val1.encoding() = "test";
  val1.transport_protocol() = "test";
  val1.security_mode() = MessageSecurityMode::Invalid;
  val1.security_policy_uri() = "test";
  val1.client_certificate() = ByteString{1, 2, 3};
  const SessionSecurityDiagnosticsDataType& const_val = val1;
  val1.session_id();
  const_val.session_id();
  val1.client_user_id_of_session();
  const_val.client_user_id_of_session();
  val1.client_user_id_history();
  const_val.client_user_id_history();
  val1.authentication_mechanism();
  const_val.authentication_mechanism();
  val1.encoding();
  const_val.encoding();
  val1.transport_protocol();
  const_val.transport_protocol();
  val1.security_mode();
  const_val.security_mode();
  val1.security_policy_uri();
  const_val.security_policy_uri();
  val1.client_certificate();
  const_val.client_certificate();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ServiceCounterDataType_Structure)
{
  ServiceCounterDataType val1;
  val1.total_count() = 123456;
  val1.error_count() = 123456;
  const ServiceCounterDataType& const_val = val1;
  val1.total_count();
  const_val.total_count();
  val1.error_count();
  const_val.error_count();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, StatusResult_Structure)
{
  StatusResult val1;
  val1.status_code() = Status::Good;
  const StatusResult& const_val = val1;
  val1.status_code();
  const_val.status_code();
  val1.diagnostic_info();
  const_val.diagnostic_info();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, SubscriptionDiagnosticsDataType_Structure)
{
  SubscriptionDiagnosticsDataType val1;
  val1.session_id() = NodeId{1234};
  val1.subscription_id() = 123456;
  val1.priority() = 123;
  val1.publishing_interval() = 1.5;
  val1.max_keep_alive_count() = 123456;
  val1.max_lifetime_count() = 123456;
  val1.max_notifications_per_publish() = 123456;
  val1.publishing_enabled() = true;
  val1.modify_count() = 123456;
  val1.enable_count() = 123456;
  val1.disable_count() = 123456;
  val1.republish_request_count() = 123456;
  val1.republish_message_request_count() = 123456;
  val1.republish_message_count() = 123456;
  val1.transfer_request_count() = 123456;
  val1.transferred_to_alt_client_count() = 123456;
  val1.transferred_to_same_client_count() = 123456;
  val1.publish_request_count() = 123456;
  val1.data_change_notifications_count() = 123456;
  val1.event_notifications_count() = 123456;
  val1.notifications_count() = 123456;
  val1.late_publish_request_count() = 123456;
  val1.current_keep_alive_count() = 123456;
  val1.current_lifetime_count() = 123456;
  val1.unacknowledged_message_count() = 123456;
  val1.discarded_message_count() = 123456;
  val1.monitored_item_count() = 123456;
  val1.disabled_monitored_item_count() = 123456;
  val1.monitoring_queue_overflow_count() = 123456;
  val1.next_sequence_number() = 123456;
  val1.event_queue_overflow_count() = 123456;
  const SubscriptionDiagnosticsDataType& const_val = val1;
  val1.session_id();
  const_val.session_id();
  val1.subscription_id();
  const_val.subscription_id();
  val1.priority();
  const_val.priority();
  val1.publishing_interval();
  const_val.publishing_interval();
  val1.max_keep_alive_count();
  const_val.max_keep_alive_count();
  val1.max_lifetime_count();
  const_val.max_lifetime_count();
  val1.max_notifications_per_publish();
  const_val.max_notifications_per_publish();
  val1.publishing_enabled();
  const_val.publishing_enabled();
  val1.modify_count();
  const_val.modify_count();
  val1.enable_count();
  const_val.enable_count();
  val1.disable_count();
  const_val.disable_count();
  val1.republish_request_count();
  const_val.republish_request_count();
  val1.republish_message_request_count();
  const_val.republish_message_request_count();
  val1.republish_message_count();
  const_val.republish_message_count();
  val1.transfer_request_count();
  const_val.transfer_request_count();
  val1.transferred_to_alt_client_count();
  const_val.transferred_to_alt_client_count();
  val1.transferred_to_same_client_count();
  const_val.transferred_to_same_client_count();
  val1.publish_request_count();
  const_val.publish_request_count();
  val1.data_change_notifications_count();
  const_val.data_change_notifications_count();
  val1.event_notifications_count();
  const_val.event_notifications_count();
  val1.notifications_count();
  const_val.notifications_count();
  val1.late_publish_request_count();
  const_val.late_publish_request_count();
  val1.current_keep_alive_count();
  const_val.current_keep_alive_count();
  val1.current_lifetime_count();
  const_val.current_lifetime_count();
  val1.unacknowledged_message_count();
  const_val.unacknowledged_message_count();
  val1.discarded_message_count();
  const_val.discarded_message_count();
  val1.monitored_item_count();
  const_val.monitored_item_count();
  val1.disabled_monitored_item_count();
  const_val.disabled_monitored_item_count();
  val1.monitoring_queue_overflow_count();
  const_val.monitoring_queue_overflow_count();
  val1.next_sequence_number();
  const_val.next_sequence_number();
  val1.event_queue_overflow_count();
  const_val.event_queue_overflow_count();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ModelChangeStructureDataType_Structure)
{
  ModelChangeStructureDataType val1;
  val1.affected() = NodeId{1234};
  val1.affected_type() = NodeId{1234};
  val1.verb() = 123;
  const ModelChangeStructureDataType& const_val = val1;
  val1.affected();
  const_val.affected();
  val1.affected_type();
  const_val.affected_type();
  val1.verb();
  const_val.verb();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, SemanticChangeStructureDataType_Structure)
{
  SemanticChangeStructureDataType val1;
  val1.affected() = NodeId{1234};
  val1.affected_type() = NodeId{1234};
  const SemanticChangeStructureDataType& const_val = val1;
  val1.affected();
  const_val.affected();
  val1.affected_type();
  const_val.affected_type();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, Range_Structure)
{
  Range val1;
  val1.low() = 1.5;
  val1.high() = 1.5;
  const Range& const_val = val1;
  val1.low();
  const_val.low();
  val1.high();
  const_val.high();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, EUInformation_Structure)
{
  EUInformation val1;
  val1.namespace_uri() = "test";
  val1.unit_id() = 123456;
  val1.display_name() = LocalizedText{"en", "test"};
  val1.description() = LocalizedText{"en", "test"};
  const EUInformation& const_val = val1;
  val1.namespace_uri();
  const_val.namespace_uri();
  val1.unit_id();
  const_val.unit_id();
  val1.display_name();
  const_val.display_name();
  val1.description();
  const_val.description();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, AxisScaleEnumeration_Enumeration)
{
  AxisScaleEnumeration e{};
  e = AxisScaleEnumeration::Linear;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Linear");
  e = AxisScaleEnumeration::Log;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Log");
  e = AxisScaleEnumeration::Ln;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Ln");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<AxisScaleEnumeration>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<AxisScaleEnumeration>(-9999));
}

TEST_F(GeneratedDataTypeTests, ComplexNumberType_Structure)
{
  ComplexNumberType val1;
  val1.real() = 1.5f;
  val1.imaginary() = 1.5f;
  const ComplexNumberType& const_val = val1;
  val1.real();
  const_val.real();
  val1.imaginary();
  const_val.imaginary();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, DoubleComplexNumberType_Structure)
{
  DoubleComplexNumberType val1;
  val1.real() = 1.5;
  val1.imaginary() = 1.5;
  const DoubleComplexNumberType& const_val = val1;
  val1.real();
  const_val.real();
  val1.imaginary();
  const_val.imaginary();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, AxisInformation_Structure)
{
  AxisInformation val1;
  val1.engineering_units().namespace_uri() = "test";
  val1.engineering_units().unit_id() = 123456;
  val1.engineering_units().display_name() = LocalizedText{"en", "test"};
  val1.engineering_units().description() = LocalizedText{"en", "test"};
  val1.eu_range().low() = 1.5;
  val1.eu_range().high() = 1.5;
  val1.title() = LocalizedText{"en", "test"};
  val1.axis_scale_type() = AxisScaleEnumeration::Linear;
  val1.axis_steps().resize(2);
  val1.axis_steps()[0] = 1.5;
  const AxisInformation& const_val = val1;
  val1.engineering_units();
  const_val.engineering_units();
  val1.eu_range();
  const_val.eu_range();
  val1.title();
  const_val.title();
  val1.axis_scale_type();
  const_val.axis_scale_type();
  val1.axis_steps();
  const_val.axis_steps();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, XVType_Structure)
{
  XVType val1;
  val1.x() = 1.5;
  val1.value() = 1.5f;
  const XVType& const_val = val1;
  val1.x();
  const_val.x();
  val1.value();
  const_val.value();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ProgramDiagnosticDataType_Structure)
{
  ProgramDiagnosticDataType val1;
  val1.create_session_id() = NodeId{1234};
  val1.create_client_name() = "test";
  val1.invocation_creation_time() = DateTime::now();
  val1.last_transition_time() = DateTime::now();
  val1.last_method_call() = "test";
  val1.last_method_session_id() = NodeId{1234};
  val1.last_method_input_arguments().resize(2);
  val1.last_method_input_arguments()[0].name() = "test";
  val1.last_method_input_arguments()[0].data_type() = NodeId{1234};
  val1.last_method_input_arguments()[0].value_rank() = 123456;
  val1.last_method_input_arguments()[0].array_dimensions().resize(2);
  val1.last_method_input_arguments()[0].array_dimensions()[0] = 123456;
  val1.last_method_input_arguments()[0].description() = LocalizedText{"en", "test"};
  val1.last_method_output_arguments().resize(2);
  val1.last_method_output_arguments()[0].name() = "test";
  val1.last_method_output_arguments()[0].data_type() = NodeId{1234};
  val1.last_method_output_arguments()[0].value_rank() = 123456;
  val1.last_method_output_arguments()[0].array_dimensions().resize(2);
  val1.last_method_output_arguments()[0].array_dimensions()[0] = 123456;
  val1.last_method_output_arguments()[0].description() = LocalizedText{"en", "test"};
  val1.last_method_call_time() = DateTime::now();
  val1.last_method_return_status().status_code() = Status::Good;
  const ProgramDiagnosticDataType& const_val = val1;
  val1.create_session_id();
  const_val.create_session_id();
  val1.create_client_name();
  const_val.create_client_name();
  val1.invocation_creation_time();
  const_val.invocation_creation_time();
  val1.last_transition_time();
  const_val.last_transition_time();
  val1.last_method_call();
  const_val.last_method_call();
  val1.last_method_session_id();
  const_val.last_method_session_id();
  val1.last_method_input_arguments();
  const_val.last_method_input_arguments();
  val1.last_method_output_arguments();
  const_val.last_method_output_arguments();
  val1.last_method_call_time();
  const_val.last_method_call_time();
  val1.last_method_return_status();
  const_val.last_method_return_status();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ProgramDiagnostic2DataType_Structure)
{
  ProgramDiagnostic2DataType val1;
  val1.create_session_id() = NodeId{1234};
  val1.create_client_name() = "test";
  val1.invocation_creation_time() = DateTime::now();
  val1.last_transition_time() = DateTime::now();
  val1.last_method_call() = "test";
  val1.last_method_session_id() = NodeId{1234};
  val1.last_method_input_arguments().resize(2);
  val1.last_method_input_arguments()[0].name() = "test";
  val1.last_method_input_arguments()[0].data_type() = NodeId{1234};
  val1.last_method_input_arguments()[0].value_rank() = 123456;
  val1.last_method_input_arguments()[0].array_dimensions().resize(2);
  val1.last_method_input_arguments()[0].array_dimensions()[0] = 123456;
  val1.last_method_input_arguments()[0].description() = LocalizedText{"en", "test"};
  val1.last_method_output_arguments().resize(2);
  val1.last_method_output_arguments()[0].name() = "test";
  val1.last_method_output_arguments()[0].data_type() = NodeId{1234};
  val1.last_method_output_arguments()[0].value_rank() = 123456;
  val1.last_method_output_arguments()[0].array_dimensions().resize(2);
  val1.last_method_output_arguments()[0].array_dimensions()[0] = 123456;
  val1.last_method_output_arguments()[0].description() = LocalizedText{"en", "test"};
  val1.last_method_input_values().resize(2);
  val1.last_method_output_values().resize(2);
  val1.last_method_call_time() = DateTime::now();
  val1.last_method_return_status() = Status::Good;
  const ProgramDiagnostic2DataType& const_val = val1;
  val1.create_session_id();
  const_val.create_session_id();
  val1.create_client_name();
  const_val.create_client_name();
  val1.invocation_creation_time();
  const_val.invocation_creation_time();
  val1.last_transition_time();
  const_val.last_transition_time();
  val1.last_method_call();
  const_val.last_method_call();
  val1.last_method_session_id();
  const_val.last_method_session_id();
  val1.last_method_input_arguments();
  const_val.last_method_input_arguments();
  val1.last_method_output_arguments();
  const_val.last_method_output_arguments();
  val1.last_method_input_values();
  const_val.last_method_input_values();
  val1.last_method_output_values();
  const_val.last_method_output_values();
  val1.last_method_call_time();
  const_val.last_method_call_time();
  val1.last_method_return_status();
  const_val.last_method_return_status();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, Annotation_Structure)
{
  Annotation val1;
  val1.message() = "test";
  val1.user_name() = "test";
  val1.annotation_time() = DateTime::now();
  const Annotation& const_val = val1;
  val1.message();
  const_val.message();
  val1.user_name();
  const_val.user_name();
  val1.annotation_time();
  const_val.annotation_time();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ExceptionDeviationFormat_Enumeration)
{
  ExceptionDeviationFormat e{};
  e = ExceptionDeviationFormat::AbsoluteValue;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "AbsoluteValue");
  e = ExceptionDeviationFormat::PercentOfValue;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "PercentOfValue");
  e = ExceptionDeviationFormat::PercentOfRange;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "PercentOfRange");
  e = ExceptionDeviationFormat::PercentOfEURange;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "PercentOfEURange");
  e = ExceptionDeviationFormat::Unknown;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Unknown");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<ExceptionDeviationFormat>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<ExceptionDeviationFormat>(-9999));
}

TEST_F(GeneratedDataTypeTests, ReferenceNode_Structure)
{
  ReferenceNode val1;
  val1.reference_type_id() = NodeId{1234};
  val1.is_inverse() = true;
  val1.target_id() = ExpandedNodeId{NodeId{1234}};
  const ReferenceNode& const_val = val1;
  val1.reference_type_id();
  const_val.reference_type_id();
  val1.is_inverse();
  const_val.is_inverse();
  val1.target_id();
  const_val.target_id();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, RequestHeader_Structure)
{
  RequestHeader val1;
  val1.authentication_token() = NodeId{1234};
  val1.timestamp() = DateTime::now();
  val1.request_handle() = 123456;
  val1.return_diagnostics() = 123456;
  val1.audit_entry_id() = "test";
  val1.timeout_hint() = 123456;
  const RequestHeader& const_val = val1;
  val1.authentication_token();
  const_val.authentication_token();
  val1.timestamp();
  const_val.timestamp();
  val1.request_handle();
  const_val.request_handle();
  val1.return_diagnostics();
  const_val.return_diagnostics();
  val1.audit_entry_id();
  const_val.audit_entry_id();
  val1.timeout_hint();
  const_val.timeout_hint();
  val1.additional_header();
  const_val.additional_header();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ResponseHeader_Structure)
{
  ResponseHeader val1;
  val1.timestamp() = DateTime::now();
  val1.request_handle() = 123456;
  val1.service_result() = Status::Good;
  val1.string_table().resize(2);
  val1.string_table()[0] = "test";
  const ResponseHeader& const_val = val1;
  val1.timestamp();
  const_val.timestamp();
  val1.request_handle();
  const_val.request_handle();
  val1.service_result();
  const_val.service_result();
  val1.service_diagnostics();
  const_val.service_diagnostics();
  val1.string_table();
  const_val.string_table();
  val1.additional_header();
  const_val.additional_header();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ServiceFault_Structure)
{
  ServiceFault val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  const ServiceFault& const_val = val1;
  val1.response_header();
  const_val.response_header();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, SessionlessInvokeRequestType_Structure)
{
  SessionlessInvokeRequestType val1;
  val1.uris_version() = 123456;
  val1.namespace_uris().resize(2);
  val1.namespace_uris()[0] = "test";
  val1.server_uris().resize(2);
  val1.server_uris()[0] = "test";
  val1.locale_ids().resize(2);
  val1.locale_ids()[0] = "test";
  val1.service_id() = 123456;
  const SessionlessInvokeRequestType& const_val = val1;
  val1.uris_version();
  const_val.uris_version();
  val1.namespace_uris();
  const_val.namespace_uris();
  val1.server_uris();
  const_val.server_uris();
  val1.locale_ids();
  const_val.locale_ids();
  val1.service_id();
  const_val.service_id();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, SessionlessInvokeResponseType_Structure)
{
  SessionlessInvokeResponseType val1;
  val1.namespace_uris().resize(2);
  val1.namespace_uris()[0] = "test";
  val1.server_uris().resize(2);
  val1.server_uris()[0] = "test";
  val1.service_id() = 123456;
  const SessionlessInvokeResponseType& const_val = val1;
  val1.namespace_uris();
  const_val.namespace_uris();
  val1.server_uris();
  const_val.server_uris();
  val1.service_id();
  const_val.service_id();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, FindServersRequest_Structure)
{
  FindServersRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.endpoint_url() = "test";
  val1.locale_ids().resize(2);
  val1.locale_ids()[0] = "test";
  val1.server_uris().resize(2);
  val1.server_uris()[0] = "test";
  const FindServersRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.endpoint_url();
  const_val.endpoint_url();
  val1.locale_ids();
  const_val.locale_ids();
  val1.server_uris();
  const_val.server_uris();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, FindServersResponse_Structure)
{
  FindServersResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.servers().resize(2);
  val1.servers()[0].application_uri() = "test";
  val1.servers()[0].product_uri() = "test";
  val1.servers()[0].application_name() = LocalizedText{"en", "test"};
  val1.servers()[0].application_type() = ApplicationType::Server;
  val1.servers()[0].gateway_server_uri() = "test";
  val1.servers()[0].discovery_profile_uri() = "test";
  val1.servers()[0].discovery_urls().resize(2);
  val1.servers()[0].discovery_urls()[0] = "test";
  const FindServersResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.servers();
  const_val.servers();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, FindServersOnNetworkRequest_Structure)
{
  FindServersOnNetworkRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.starting_record_id() = 123456;
  val1.max_records_to_return() = 123456;
  val1.server_capability_filter().resize(2);
  val1.server_capability_filter()[0] = "test";
  const FindServersOnNetworkRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.starting_record_id();
  const_val.starting_record_id();
  val1.max_records_to_return();
  const_val.max_records_to_return();
  val1.server_capability_filter();
  const_val.server_capability_filter();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, FindServersOnNetworkResponse_Structure)
{
  FindServersOnNetworkResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.last_counter_reset_time() = DateTime::now();
  val1.servers().resize(2);
  val1.servers()[0].record_id() = 123456;
  val1.servers()[0].server_name() = "test";
  val1.servers()[0].discovery_url() = "test";
  val1.servers()[0].server_capabilities().resize(2);
  val1.servers()[0].server_capabilities()[0] = "test";
  const FindServersOnNetworkResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.last_counter_reset_time();
  const_val.last_counter_reset_time();
  val1.servers();
  const_val.servers();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, GetEndpointsRequest_Structure)
{
  GetEndpointsRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.endpoint_url() = "test";
  val1.locale_ids().resize(2);
  val1.locale_ids()[0] = "test";
  val1.profile_uris().resize(2);
  val1.profile_uris()[0] = "test";
  const GetEndpointsRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.endpoint_url();
  const_val.endpoint_url();
  val1.locale_ids();
  const_val.locale_ids();
  val1.profile_uris();
  const_val.profile_uris();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, GetEndpointsResponse_Structure)
{
  GetEndpointsResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.endpoints().resize(2);
  val1.endpoints()[0].endpoint_url() = "test";
  val1.endpoints()[0].server().application_uri() = "test";
  val1.endpoints()[0].server().product_uri() = "test";
  val1.endpoints()[0].server().application_name() = LocalizedText{"en", "test"};
  val1.endpoints()[0].server().application_type() = ApplicationType::Server;
  val1.endpoints()[0].server().gateway_server_uri() = "test";
  val1.endpoints()[0].server().discovery_profile_uri() = "test";
  val1.endpoints()[0].server().discovery_urls().resize(2);
  val1.endpoints()[0].server().discovery_urls()[0] = "test";
  val1.endpoints()[0].server_certificate() = ByteString{1, 2, 3};
  val1.endpoints()[0].security_mode() = MessageSecurityMode::Invalid;
  val1.endpoints()[0].security_policy_uri() = "test";
  val1.endpoints()[0].user_identity_tokens().resize(2);
  val1.endpoints()[0].user_identity_tokens()[0].policy_id() = "test";
  val1.endpoints()[0].user_identity_tokens()[0].token_type() = UserTokenType::Anonymous;
  val1.endpoints()[0].user_identity_tokens()[0].issued_token_type() = "test";
  val1.endpoints()[0].user_identity_tokens()[0].issuer_endpoint_url() = "test";
  val1.endpoints()[0].user_identity_tokens()[0].security_policy_uri() = "test";
  val1.endpoints()[0].transport_profile_uri() = "test";
  val1.endpoints()[0].security_level() = 123;
  const GetEndpointsResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.endpoints();
  const_val.endpoints();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, RegisterServerRequest_Structure)
{
  RegisterServerRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.server().server_uri() = "test";
  val1.server().product_uri() = "test";
  val1.server().server_names().resize(2);
  val1.server().server_names()[0] = LocalizedText{"en", "test"};
  val1.server().server_type() = ApplicationType::Server;
  val1.server().gateway_server_uri() = "test";
  val1.server().discovery_urls().resize(2);
  val1.server().discovery_urls()[0] = "test";
  val1.server().semaphore_file_path() = "test";
  val1.server().is_online() = true;
  const RegisterServerRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.server();
  const_val.server();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, RegisterServerResponse_Structure)
{
  RegisterServerResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  const RegisterServerResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, RegisterServer2Request_Structure)
{
  RegisterServer2Request val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.server().server_uri() = "test";
  val1.server().product_uri() = "test";
  val1.server().server_names().resize(2);
  val1.server().server_names()[0] = LocalizedText{"en", "test"};
  val1.server().server_type() = ApplicationType::Server;
  val1.server().gateway_server_uri() = "test";
  val1.server().discovery_urls().resize(2);
  val1.server().discovery_urls()[0] = "test";
  val1.server().semaphore_file_path() = "test";
  val1.server().is_online() = true;
  val1.discovery_configuration().resize(2);
  const RegisterServer2Request& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.server();
  const_val.server();
  val1.discovery_configuration();
  const_val.discovery_configuration();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, RegisterServer2Response_Structure)
{
  RegisterServer2Response val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.configuration_results().resize(2);
  val1.configuration_results()[0] = Status::Good;
  val1.diagnostic_infos().resize(2);
  const RegisterServer2Response& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.configuration_results();
  const_val.configuration_results();
  val1.diagnostic_infos();
  const_val.diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ChannelSecurityToken_Structure)
{
  ChannelSecurityToken val1;
  val1.channel_id() = 123456;
  val1.token_id() = 123456;
  val1.created_at() = DateTime::now();
  val1.revised_lifetime() = 123456;
  const ChannelSecurityToken& const_val = val1;
  val1.channel_id();
  const_val.channel_id();
  val1.token_id();
  const_val.token_id();
  val1.created_at();
  const_val.created_at();
  val1.revised_lifetime();
  const_val.revised_lifetime();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, OpenSecureChannelRequest_Structure)
{
  OpenSecureChannelRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.client_protocol_version() = 123456;
  val1.request_type() = SecurityTokenRequestType::Issue;
  val1.security_mode() = MessageSecurityMode::Invalid;
  val1.client_nonce() = ByteString{1, 2, 3};
  val1.requested_lifetime() = 123456;
  const OpenSecureChannelRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.client_protocol_version();
  const_val.client_protocol_version();
  val1.request_type();
  const_val.request_type();
  val1.security_mode();
  const_val.security_mode();
  val1.client_nonce();
  const_val.client_nonce();
  val1.requested_lifetime();
  const_val.requested_lifetime();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, OpenSecureChannelResponse_Structure)
{
  OpenSecureChannelResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.server_protocol_version() = 123456;
  val1.security_token().channel_id() = 123456;
  val1.security_token().token_id() = 123456;
  val1.security_token().created_at() = DateTime::now();
  val1.security_token().revised_lifetime() = 123456;
  val1.server_nonce() = ByteString{1, 2, 3};
  const OpenSecureChannelResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.server_protocol_version();
  const_val.server_protocol_version();
  val1.security_token();
  const_val.security_token();
  val1.server_nonce();
  const_val.server_nonce();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, CloseSecureChannelRequest_Structure)
{
  CloseSecureChannelRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  const CloseSecureChannelRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, CloseSecureChannelResponse_Structure)
{
  CloseSecureChannelResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  const CloseSecureChannelResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, SignatureData_Structure)
{
  SignatureData val1;
  val1.algorithm() = "test";
  val1.signature() = ByteString{1, 2, 3};
  const SignatureData& const_val = val1;
  val1.algorithm();
  const_val.algorithm();
  val1.signature();
  const_val.signature();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, CreateSessionRequest_Structure)
{
  CreateSessionRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.client_description().application_uri() = "test";
  val1.client_description().product_uri() = "test";
  val1.client_description().application_name() = LocalizedText{"en", "test"};
  val1.client_description().application_type() = ApplicationType::Server;
  val1.client_description().gateway_server_uri() = "test";
  val1.client_description().discovery_profile_uri() = "test";
  val1.client_description().discovery_urls().resize(2);
  val1.client_description().discovery_urls()[0] = "test";
  val1.server_uri() = "test";
  val1.endpoint_url() = "test";
  val1.session_name() = "test";
  val1.client_nonce() = ByteString{1, 2, 3};
  val1.client_certificate() = ByteString{1, 2, 3};
  val1.requested_session_timeout() = 1.5;
  val1.max_response_message_size() = 123456;
  const CreateSessionRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.client_description();
  const_val.client_description();
  val1.server_uri();
  const_val.server_uri();
  val1.endpoint_url();
  const_val.endpoint_url();
  val1.session_name();
  const_val.session_name();
  val1.client_nonce();
  const_val.client_nonce();
  val1.client_certificate();
  const_val.client_certificate();
  val1.requested_session_timeout();
  const_val.requested_session_timeout();
  val1.max_response_message_size();
  const_val.max_response_message_size();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, CreateSessionResponse_Structure)
{
  CreateSessionResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.session_id() = NodeId{1234};
  val1.authentication_token() = NodeId{1234};
  val1.revised_session_timeout() = 1.5;
  val1.server_nonce() = ByteString{1, 2, 3};
  val1.server_certificate() = ByteString{1, 2, 3};
  val1.server_endpoints().resize(2);
  val1.server_endpoints()[0].endpoint_url() = "test";
  val1.server_endpoints()[0].server().application_uri() = "test";
  val1.server_endpoints()[0].server().product_uri() = "test";
  val1.server_endpoints()[0].server().application_name() = LocalizedText{"en", "test"};
  val1.server_endpoints()[0].server().application_type() = ApplicationType::Server;
  val1.server_endpoints()[0].server().gateway_server_uri() = "test";
  val1.server_endpoints()[0].server().discovery_profile_uri() = "test";
  val1.server_endpoints()[0].server().discovery_urls().resize(2);
  val1.server_endpoints()[0].server().discovery_urls()[0] = "test";
  val1.server_endpoints()[0].server_certificate() = ByteString{1, 2, 3};
  val1.server_endpoints()[0].security_mode() = MessageSecurityMode::Invalid;
  val1.server_endpoints()[0].security_policy_uri() = "test";
  val1.server_endpoints()[0].user_identity_tokens().resize(2);
  val1.server_endpoints()[0].user_identity_tokens()[0].policy_id() = "test";
  val1.server_endpoints()[0].user_identity_tokens()[0].token_type() = UserTokenType::Anonymous;
  val1.server_endpoints()[0].user_identity_tokens()[0].issued_token_type() = "test";
  val1.server_endpoints()[0].user_identity_tokens()[0].issuer_endpoint_url() = "test";
  val1.server_endpoints()[0].user_identity_tokens()[0].security_policy_uri() = "test";
  val1.server_endpoints()[0].transport_profile_uri() = "test";
  val1.server_endpoints()[0].security_level() = 123;
  val1.server_software_certificates().resize(2);
  val1.server_software_certificates()[0].certificate_data() = ByteString{1, 2, 3};
  val1.server_software_certificates()[0].signature() = ByteString{1, 2, 3};
  val1.server_signature().algorithm() = "test";
  val1.server_signature().signature() = ByteString{1, 2, 3};
  val1.max_request_message_size() = 123456;
  const CreateSessionResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.session_id();
  const_val.session_id();
  val1.authentication_token();
  const_val.authentication_token();
  val1.revised_session_timeout();
  const_val.revised_session_timeout();
  val1.server_nonce();
  const_val.server_nonce();
  val1.server_certificate();
  const_val.server_certificate();
  val1.server_endpoints();
  const_val.server_endpoints();
  val1.server_software_certificates();
  const_val.server_software_certificates();
  val1.server_signature();
  const_val.server_signature();
  val1.max_request_message_size();
  const_val.max_request_message_size();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, RsaEncryptedSecret_SimpleType)
{
  RsaEncryptedSecret val1{};
  RsaEncryptedSecret val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, EccEncryptedSecret_SimpleType)
{
  EccEncryptedSecret val1{};
  EccEncryptedSecret val2 = val1;
  val1 = val2;
  (void)val1;
}

TEST_F(GeneratedDataTypeTests, ActivateSessionRequest_Structure)
{
  ActivateSessionRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.client_signature().algorithm() = "test";
  val1.client_signature().signature() = ByteString{1, 2, 3};
  val1.client_software_certificates().resize(2);
  val1.client_software_certificates()[0].certificate_data() = ByteString{1, 2, 3};
  val1.client_software_certificates()[0].signature() = ByteString{1, 2, 3};
  val1.locale_ids().resize(2);
  val1.locale_ids()[0] = "test";
  val1.user_token_signature().algorithm() = "test";
  val1.user_token_signature().signature() = ByteString{1, 2, 3};
  const ActivateSessionRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.client_signature();
  const_val.client_signature();
  val1.client_software_certificates();
  const_val.client_software_certificates();
  val1.locale_ids();
  const_val.locale_ids();
  val1.user_identity_token();
  const_val.user_identity_token();
  val1.user_token_signature();
  const_val.user_token_signature();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ActivateSessionResponse_Structure)
{
  ActivateSessionResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.server_nonce() = ByteString{1, 2, 3};
  val1.results().resize(2);
  val1.results()[0] = Status::Good;
  val1.diagnostic_infos().resize(2);
  const ActivateSessionResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.server_nonce();
  const_val.server_nonce();
  val1.results();
  const_val.results();
  val1.diagnostic_infos();
  const_val.diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, CloseSessionRequest_Structure)
{
  CloseSessionRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.delete_subscriptions() = true;
  const CloseSessionRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.delete_subscriptions();
  const_val.delete_subscriptions();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, CloseSessionResponse_Structure)
{
  CloseSessionResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  const CloseSessionResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, CancelRequest_Structure)
{
  CancelRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.request_handle() = 123456;
  const CancelRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.request_handle();
  const_val.request_handle();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, CancelResponse_Structure)
{
  CancelResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.cancel_count() = 123456;
  const CancelResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.cancel_count();
  const_val.cancel_count();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, NodeAttributes_Structure)
{
  NodeAttributes val1;
  val1.specified_attributes() = 123456;
  val1.display_name() = LocalizedText{"en", "test"};
  val1.description() = LocalizedText{"en", "test"};
  val1.write_mask() = 123456;
  val1.user_write_mask() = 123456;
  const NodeAttributes& const_val = val1;
  val1.specified_attributes();
  const_val.specified_attributes();
  val1.display_name();
  const_val.display_name();
  val1.description();
  const_val.description();
  val1.write_mask();
  const_val.write_mask();
  val1.user_write_mask();
  const_val.user_write_mask();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ObjectAttributes_Structure)
{
  ObjectAttributes val1;
  val1.event_notifier() = 123;
  const ObjectAttributes& const_val = val1;
  val1.event_notifier();
  const_val.event_notifier();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, VariableAttributes_Structure)
{
  VariableAttributes val1;
  val1.value() = Variant{123};
  val1.data_type() = NodeId{1234};
  val1.value_rank() = 123456;
  val1.array_dimensions().resize(2);
  val1.array_dimensions()[0] = 123456;
  val1.access_level() = 123;
  val1.user_access_level() = 123;
  val1.minimum_sampling_interval() = 1.5;
  val1.historizing() = true;
  const VariableAttributes& const_val = val1;
  val1.value();
  const_val.value();
  val1.data_type();
  const_val.data_type();
  val1.value_rank();
  const_val.value_rank();
  val1.array_dimensions();
  const_val.array_dimensions();
  val1.access_level();
  const_val.access_level();
  val1.user_access_level();
  const_val.user_access_level();
  val1.minimum_sampling_interval();
  const_val.minimum_sampling_interval();
  val1.historizing();
  const_val.historizing();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, MethodAttributes_Structure)
{
  MethodAttributes val1;
  val1.executable() = true;
  val1.user_executable() = true;
  const MethodAttributes& const_val = val1;
  val1.executable();
  const_val.executable();
  val1.user_executable();
  const_val.user_executable();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ObjectTypeAttributes_Structure)
{
  ObjectTypeAttributes val1;
  val1.is_abstract() = true;
  const ObjectTypeAttributes& const_val = val1;
  val1.is_abstract();
  const_val.is_abstract();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, VariableTypeAttributes_Structure)
{
  VariableTypeAttributes val1;
  val1.value() = Variant{123};
  val1.data_type() = NodeId{1234};
  val1.value_rank() = 123456;
  val1.array_dimensions().resize(2);
  val1.array_dimensions()[0] = 123456;
  val1.is_abstract() = true;
  const VariableTypeAttributes& const_val = val1;
  val1.value();
  const_val.value();
  val1.data_type();
  const_val.data_type();
  val1.value_rank();
  const_val.value_rank();
  val1.array_dimensions();
  const_val.array_dimensions();
  val1.is_abstract();
  const_val.is_abstract();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ReferenceTypeAttributes_Structure)
{
  ReferenceTypeAttributes val1;
  val1.is_abstract() = true;
  val1.symmetric() = true;
  val1.inverse_name() = LocalizedText{"en", "test"};
  const ReferenceTypeAttributes& const_val = val1;
  val1.is_abstract();
  const_val.is_abstract();
  val1.symmetric();
  const_val.symmetric();
  val1.inverse_name();
  const_val.inverse_name();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, DataTypeAttributes_Structure)
{
  DataTypeAttributes val1;
  val1.is_abstract() = true;
  const DataTypeAttributes& const_val = val1;
  val1.is_abstract();
  const_val.is_abstract();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ViewAttributes_Structure)
{
  ViewAttributes val1;
  val1.contains_no_loops() = true;
  val1.event_notifier() = 123;
  const ViewAttributes& const_val = val1;
  val1.contains_no_loops();
  const_val.contains_no_loops();
  val1.event_notifier();
  const_val.event_notifier();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, GenericAttributeValue_Structure)
{
  GenericAttributeValue val1;
  val1.attribute_id() = 123456;
  val1.value() = Variant{123};
  const GenericAttributeValue& const_val = val1;
  val1.attribute_id();
  const_val.attribute_id();
  val1.value();
  const_val.value();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, GenericAttributes_Structure)
{
  GenericAttributes val1;
  val1.attribute_values().resize(2);
  val1.attribute_values()[0].attribute_id() = 123456;
  val1.attribute_values()[0].value() = Variant{123};
  const GenericAttributes& const_val = val1;
  val1.attribute_values();
  const_val.attribute_values();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, AddNodesResult_Structure)
{
  AddNodesResult val1;
  val1.status_code() = Status::Good;
  val1.added_node_id() = NodeId{1234};
  const AddNodesResult& const_val = val1;
  val1.status_code();
  const_val.status_code();
  val1.added_node_id();
  const_val.added_node_id();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, AddNodesRequest_Structure)
{
  AddNodesRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.nodes_to_add().resize(2);
  val1.nodes_to_add()[0].parent_node_id() = ExpandedNodeId{NodeId{1234}};
  val1.nodes_to_add()[0].reference_type_id() = NodeId{1234};
  val1.nodes_to_add()[0].requested_new_node_id() = ExpandedNodeId{NodeId{1234}};
  val1.nodes_to_add()[0].browse_name() = QualifiedName{"test"};
  val1.nodes_to_add()[0].node_class() = NodeClass::Unspecified;
  val1.nodes_to_add()[0].type_definition() = ExpandedNodeId{NodeId{1234}};
  const AddNodesRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.nodes_to_add();
  const_val.nodes_to_add();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, AddNodesResponse_Structure)
{
  AddNodesResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.results().resize(2);
  val1.results()[0].status_code() = Status::Good;
  val1.results()[0].added_node_id() = NodeId{1234};
  val1.diagnostic_infos().resize(2);
  const AddNodesResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.results();
  const_val.results();
  val1.diagnostic_infos();
  const_val.diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, AddReferencesRequest_Structure)
{
  AddReferencesRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.references_to_add().resize(2);
  val1.references_to_add()[0].source_node_id() = NodeId{1234};
  val1.references_to_add()[0].reference_type_id() = NodeId{1234};
  val1.references_to_add()[0].is_forward() = true;
  val1.references_to_add()[0].target_server_uri() = "test";
  val1.references_to_add()[0].target_node_id() = ExpandedNodeId{NodeId{1234}};
  val1.references_to_add()[0].target_node_class() = NodeClass::Unspecified;
  const AddReferencesRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.references_to_add();
  const_val.references_to_add();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, AddReferencesResponse_Structure)
{
  AddReferencesResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.results().resize(2);
  val1.results()[0] = Status::Good;
  val1.diagnostic_infos().resize(2);
  const AddReferencesResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.results();
  const_val.results();
  val1.diagnostic_infos();
  const_val.diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, DeleteNodesRequest_Structure)
{
  DeleteNodesRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.nodes_to_delete().resize(2);
  val1.nodes_to_delete()[0].node_id() = NodeId{1234};
  val1.nodes_to_delete()[0].delete_target_references() = true;
  const DeleteNodesRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.nodes_to_delete();
  const_val.nodes_to_delete();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, DeleteNodesResponse_Structure)
{
  DeleteNodesResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.results().resize(2);
  val1.results()[0] = Status::Good;
  val1.diagnostic_infos().resize(2);
  const DeleteNodesResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.results();
  const_val.results();
  val1.diagnostic_infos();
  const_val.diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, DeleteReferencesRequest_Structure)
{
  DeleteReferencesRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.references_to_delete().resize(2);
  val1.references_to_delete()[0].source_node_id() = NodeId{1234};
  val1.references_to_delete()[0].reference_type_id() = NodeId{1234};
  val1.references_to_delete()[0].is_forward() = true;
  val1.references_to_delete()[0].target_node_id() = ExpandedNodeId{NodeId{1234}};
  val1.references_to_delete()[0].delete_bidirectional() = true;
  const DeleteReferencesRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.references_to_delete();
  const_val.references_to_delete();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, DeleteReferencesResponse_Structure)
{
  DeleteReferencesResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.results().resize(2);
  val1.results()[0] = Status::Good;
  val1.diagnostic_infos().resize(2);
  const DeleteReferencesResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.results();
  const_val.results();
  val1.diagnostic_infos();
  const_val.diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, BrowseDirection_Enumeration)
{
  BrowseDirection e{};
  e = BrowseDirection::Forward;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Forward");
  e = BrowseDirection::Inverse;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Inverse");
  e = BrowseDirection::Both;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Both");
  e = BrowseDirection::Invalid;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Invalid");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<BrowseDirection>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<BrowseDirection>(-9999));
}

TEST_F(GeneratedDataTypeTests, ViewDescription_Structure)
{
  ViewDescription val1;
  val1.view_id() = NodeId{1234};
  val1.timestamp() = DateTime::now();
  val1.view_version() = 123456;
  const ViewDescription& const_val = val1;
  val1.view_id();
  const_val.view_id();
  val1.timestamp();
  const_val.timestamp();
  val1.view_version();
  const_val.view_version();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, BrowseDescription_Structure)
{
  BrowseDescription val1;
  val1.node_id() = NodeId{1234};
  val1.browse_direction() = BrowseDirection::Forward;
  val1.reference_type_id() = NodeId{1234};
  val1.include_subtypes() = true;
  val1.node_class_mask() = 123456;
  val1.result_mask() = 123456;
  const BrowseDescription& const_val = val1;
  val1.node_id();
  const_val.node_id();
  val1.browse_direction();
  const_val.browse_direction();
  val1.reference_type_id();
  const_val.reference_type_id();
  val1.include_subtypes();
  const_val.include_subtypes();
  val1.node_class_mask();
  const_val.node_class_mask();
  val1.result_mask();
  const_val.result_mask();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, BrowseResultMask_Enumeration)
{
  BrowseResultMask e{};
  e = BrowseResultMask::None;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "None");
  e = BrowseResultMask::ReferenceTypeId;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "ReferenceTypeId");
  e = BrowseResultMask::IsForward;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "IsForward");
  e = BrowseResultMask::NodeClass;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "NodeClass");
  e = BrowseResultMask::BrowseName;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "BrowseName");
  e = BrowseResultMask::DisplayName;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "DisplayName");
  e = BrowseResultMask::TypeDefinition;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "TypeDefinition");
  e = BrowseResultMask::All;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "All");
  e = BrowseResultMask::ReferenceTypeInfo;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "ReferenceTypeInfo");
  e = BrowseResultMask::TargetInfo;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "TargetInfo");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<BrowseResultMask>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<BrowseResultMask>(-9999));
}

TEST_F(GeneratedDataTypeTests, ReferenceDescription_Structure)
{
  ReferenceDescription val1;
  val1.reference_type_id() = NodeId{1234};
  val1.is_forward() = true;
  val1.node_id() = ExpandedNodeId{NodeId{1234}};
  val1.browse_name() = QualifiedName{"test"};
  val1.display_name() = LocalizedText{"en", "test"};
  val1.node_class() = NodeClass::Unspecified;
  val1.type_definition() = ExpandedNodeId{NodeId{1234}};
  const ReferenceDescription& const_val = val1;
  val1.reference_type_id();
  const_val.reference_type_id();
  val1.is_forward();
  const_val.is_forward();
  val1.node_id();
  const_val.node_id();
  val1.browse_name();
  const_val.browse_name();
  val1.display_name();
  const_val.display_name();
  val1.node_class();
  const_val.node_class();
  val1.type_definition();
  const_val.type_definition();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, BrowseResult_Structure)
{
  BrowseResult val1;
  val1.status_code() = Status::Good;
  val1.continuation_point() = ByteString{1, 2, 3};
  val1.references().resize(2);
  val1.references()[0].reference_type_id() = NodeId{1234};
  val1.references()[0].is_forward() = true;
  val1.references()[0].node_id() = ExpandedNodeId{NodeId{1234}};
  val1.references()[0].browse_name() = QualifiedName{"test"};
  val1.references()[0].display_name() = LocalizedText{"en", "test"};
  val1.references()[0].node_class() = NodeClass::Unspecified;
  val1.references()[0].type_definition() = ExpandedNodeId{NodeId{1234}};
  const BrowseResult& const_val = val1;
  val1.status_code();
  const_val.status_code();
  val1.continuation_point();
  const_val.continuation_point();
  val1.references();
  const_val.references();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, BrowseRequest_Structure)
{
  BrowseRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.view().view_id() = NodeId{1234};
  val1.view().timestamp() = DateTime::now();
  val1.view().view_version() = 123456;
  val1.requested_max_references_per_node() = 123456;
  val1.nodes_to_browse().resize(2);
  val1.nodes_to_browse()[0].node_id() = NodeId{1234};
  val1.nodes_to_browse()[0].browse_direction() = BrowseDirection::Forward;
  val1.nodes_to_browse()[0].reference_type_id() = NodeId{1234};
  val1.nodes_to_browse()[0].include_subtypes() = true;
  val1.nodes_to_browse()[0].node_class_mask() = 123456;
  val1.nodes_to_browse()[0].result_mask() = 123456;
  const BrowseRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.view();
  const_val.view();
  val1.requested_max_references_per_node();
  const_val.requested_max_references_per_node();
  val1.nodes_to_browse();
  const_val.nodes_to_browse();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, BrowseResponse_Structure)
{
  BrowseResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.results().resize(2);
  val1.results()[0].status_code() = Status::Good;
  val1.results()[0].continuation_point() = ByteString{1, 2, 3};
  val1.results()[0].references().resize(2);
  val1.results()[0].references()[0].reference_type_id() = NodeId{1234};
  val1.results()[0].references()[0].is_forward() = true;
  val1.results()[0].references()[0].node_id() = ExpandedNodeId{NodeId{1234}};
  val1.results()[0].references()[0].browse_name() = QualifiedName{"test"};
  val1.results()[0].references()[0].display_name() = LocalizedText{"en", "test"};
  val1.results()[0].references()[0].node_class() = NodeClass::Unspecified;
  val1.results()[0].references()[0].type_definition() = ExpandedNodeId{NodeId{1234}};
  val1.diagnostic_infos().resize(2);
  const BrowseResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.results();
  const_val.results();
  val1.diagnostic_infos();
  const_val.diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, BrowseNextRequest_Structure)
{
  BrowseNextRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.release_continuation_points() = true;
  val1.continuation_points().resize(2);
  val1.continuation_points()[0] = ByteString{1, 2, 3};
  const BrowseNextRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.release_continuation_points();
  const_val.release_continuation_points();
  val1.continuation_points();
  const_val.continuation_points();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, BrowseNextResponse_Structure)
{
  BrowseNextResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.results().resize(2);
  val1.results()[0].status_code() = Status::Good;
  val1.results()[0].continuation_point() = ByteString{1, 2, 3};
  val1.results()[0].references().resize(2);
  val1.results()[0].references()[0].reference_type_id() = NodeId{1234};
  val1.results()[0].references()[0].is_forward() = true;
  val1.results()[0].references()[0].node_id() = ExpandedNodeId{NodeId{1234}};
  val1.results()[0].references()[0].browse_name() = QualifiedName{"test"};
  val1.results()[0].references()[0].display_name() = LocalizedText{"en", "test"};
  val1.results()[0].references()[0].node_class() = NodeClass::Unspecified;
  val1.results()[0].references()[0].type_definition() = ExpandedNodeId{NodeId{1234}};
  val1.diagnostic_infos().resize(2);
  const BrowseNextResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.results();
  const_val.results();
  val1.diagnostic_infos();
  const_val.diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, BrowsePath_Structure)
{
  BrowsePath val1;
  val1.starting_node() = NodeId{1234};
  val1.relative_path().elements().resize(2);
  val1.relative_path().elements()[0].reference_type_id() = NodeId{1234};
  val1.relative_path().elements()[0].is_inverse() = true;
  val1.relative_path().elements()[0].include_subtypes() = true;
  val1.relative_path().elements()[0].target_name() = QualifiedName{"test"};
  const BrowsePath& const_val = val1;
  val1.starting_node();
  const_val.starting_node();
  val1.relative_path();
  const_val.relative_path();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, BrowsePathTarget_Structure)
{
  BrowsePathTarget val1;
  val1.target_id() = ExpandedNodeId{NodeId{1234}};
  val1.remaining_path_index() = 123456;
  const BrowsePathTarget& const_val = val1;
  val1.target_id();
  const_val.target_id();
  val1.remaining_path_index();
  const_val.remaining_path_index();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, BrowsePathResult_Structure)
{
  BrowsePathResult val1;
  val1.status_code() = Status::Good;
  val1.targets().resize(2);
  val1.targets()[0].target_id() = ExpandedNodeId{NodeId{1234}};
  val1.targets()[0].remaining_path_index() = 123456;
  const BrowsePathResult& const_val = val1;
  val1.status_code();
  const_val.status_code();
  val1.targets();
  const_val.targets();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, TranslateBrowsePathsToNodeIdsRequest_Structure)
{
  TranslateBrowsePathsToNodeIdsRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.browse_paths().resize(2);
  val1.browse_paths()[0].starting_node() = NodeId{1234};
  val1.browse_paths()[0].relative_path().elements().resize(2);
  const TranslateBrowsePathsToNodeIdsRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.browse_paths();
  const_val.browse_paths();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, TranslateBrowsePathsToNodeIdsResponse_Structure)
{
  TranslateBrowsePathsToNodeIdsResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.results().resize(2);
  val1.results()[0].status_code() = Status::Good;
  val1.results()[0].targets().resize(2);
  val1.results()[0].targets()[0].target_id() = ExpandedNodeId{NodeId{1234}};
  val1.results()[0].targets()[0].remaining_path_index() = 123456;
  val1.diagnostic_infos().resize(2);
  const TranslateBrowsePathsToNodeIdsResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.results();
  const_val.results();
  val1.diagnostic_infos();
  const_val.diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, RegisterNodesRequest_Structure)
{
  RegisterNodesRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.nodes_to_register().resize(2);
  val1.nodes_to_register()[0] = NodeId{1234};
  const RegisterNodesRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.nodes_to_register();
  const_val.nodes_to_register();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, RegisterNodesResponse_Structure)
{
  RegisterNodesResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.registered_node_ids().resize(2);
  val1.registered_node_ids()[0] = NodeId{1234};
  const RegisterNodesResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.registered_node_ids();
  const_val.registered_node_ids();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, UnregisterNodesRequest_Structure)
{
  UnregisterNodesRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.nodes_to_unregister().resize(2);
  val1.nodes_to_unregister()[0] = NodeId{1234};
  const UnregisterNodesRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.nodes_to_unregister();
  const_val.nodes_to_unregister();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, UnregisterNodesResponse_Structure)
{
  UnregisterNodesResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  const UnregisterNodesResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, QueryDataDescription_Structure)
{
  QueryDataDescription val1;
  val1.relative_path().elements().resize(2);
  val1.relative_path().elements()[0].reference_type_id() = NodeId{1234};
  val1.relative_path().elements()[0].is_inverse() = true;
  val1.relative_path().elements()[0].include_subtypes() = true;
  val1.relative_path().elements()[0].target_name() = QualifiedName{"test"};
  val1.attribute_id() = 123456;
  val1.index_range() = "test";
  const QueryDataDescription& const_val = val1;
  val1.relative_path();
  const_val.relative_path();
  val1.attribute_id();
  const_val.attribute_id();
  val1.index_range();
  const_val.index_range();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, NodeTypeDescription_Structure)
{
  NodeTypeDescription val1;
  val1.type_definition_node() = ExpandedNodeId{NodeId{1234}};
  val1.include_sub_types() = true;
  val1.data_to_return().resize(2);
  val1.data_to_return()[0].relative_path().elements().resize(2);
  val1.data_to_return()[0].attribute_id() = 123456;
  val1.data_to_return()[0].index_range() = "test";
  const NodeTypeDescription& const_val = val1;
  val1.type_definition_node();
  const_val.type_definition_node();
  val1.include_sub_types();
  const_val.include_sub_types();
  val1.data_to_return();
  const_val.data_to_return();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, QueryDataSet_Structure)
{
  QueryDataSet val1;
  val1.node_id() = ExpandedNodeId{NodeId{1234}};
  val1.type_definition_node() = ExpandedNodeId{NodeId{1234}};
  val1.values().resize(2);
  const QueryDataSet& const_val = val1;
  val1.node_id();
  const_val.node_id();
  val1.type_definition_node();
  const_val.type_definition_node();
  val1.values();
  const_val.values();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, NodeReference_Structure)
{
  NodeReference val1;
  val1.node_id() = NodeId{1234};
  val1.reference_type_id() = NodeId{1234};
  val1.is_forward() = true;
  val1.referenced_node_ids().resize(2);
  val1.referenced_node_ids()[0] = NodeId{1234};
  const NodeReference& const_val = val1;
  val1.node_id();
  const_val.node_id();
  val1.reference_type_id();
  const_val.reference_type_id();
  val1.is_forward();
  const_val.is_forward();
  val1.referenced_node_ids();
  const_val.referenced_node_ids();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ContentFilterElementResult_Structure)
{
  ContentFilterElementResult val1;
  val1.status_code() = Status::Good;
  val1.operand_status_codes().resize(2);
  val1.operand_status_codes()[0] = Status::Good;
  val1.operand_diagnostic_infos().resize(2);
  const ContentFilterElementResult& const_val = val1;
  val1.status_code();
  const_val.status_code();
  val1.operand_status_codes();
  const_val.operand_status_codes();
  val1.operand_diagnostic_infos();
  const_val.operand_diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ContentFilterResult_Structure)
{
  ContentFilterResult val1;
  val1.element_results().resize(2);
  val1.element_results()[0].status_code() = Status::Good;
  val1.element_results()[0].operand_status_codes().resize(2);
  val1.element_results()[0].operand_status_codes()[0] = Status::Good;
  val1.element_results()[0].operand_diagnostic_infos().resize(2);
  val1.element_diagnostic_infos().resize(2);
  const ContentFilterResult& const_val = val1;
  val1.element_results();
  const_val.element_results();
  val1.element_diagnostic_infos();
  const_val.element_diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ParsingResult_Structure)
{
  ParsingResult val1;
  val1.status_code() = Status::Good;
  val1.data_status_codes().resize(2);
  val1.data_status_codes()[0] = Status::Good;
  val1.data_diagnostic_infos().resize(2);
  const ParsingResult& const_val = val1;
  val1.status_code();
  const_val.status_code();
  val1.data_status_codes();
  const_val.data_status_codes();
  val1.data_diagnostic_infos();
  const_val.data_diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, QueryFirstRequest_Structure)
{
  QueryFirstRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.view().view_id() = NodeId{1234};
  val1.view().timestamp() = DateTime::now();
  val1.view().view_version() = 123456;
  val1.node_types().resize(2);
  val1.node_types()[0].type_definition_node() = ExpandedNodeId{NodeId{1234}};
  val1.node_types()[0].include_sub_types() = true;
  val1.node_types()[0].data_to_return().resize(2);
  val1.node_types()[0].data_to_return()[0].relative_path().elements().resize(2);
  val1.node_types()[0].data_to_return()[0].attribute_id() = 123456;
  val1.node_types()[0].data_to_return()[0].index_range() = "test";
  val1.filter().elements().resize(2);
  val1.filter().elements()[0].filter_operator() = FilterOperator::Equals;
  val1.filter().elements()[0].filter_operands().resize(2);
  val1.max_data_sets_to_return() = 123456;
  val1.max_references_to_return() = 123456;
  const QueryFirstRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.view();
  const_val.view();
  val1.node_types();
  const_val.node_types();
  val1.filter();
  const_val.filter();
  val1.max_data_sets_to_return();
  const_val.max_data_sets_to_return();
  val1.max_references_to_return();
  const_val.max_references_to_return();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, QueryFirstResponse_Structure)
{
  QueryFirstResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.query_data_sets().resize(2);
  val1.query_data_sets()[0].node_id() = ExpandedNodeId{NodeId{1234}};
  val1.query_data_sets()[0].type_definition_node() = ExpandedNodeId{NodeId{1234}};
  val1.query_data_sets()[0].values().resize(2);
  val1.continuation_point() = ByteString{1, 2, 3};
  val1.parsing_results().resize(2);
  val1.parsing_results()[0].status_code() = Status::Good;
  val1.parsing_results()[0].data_status_codes().resize(2);
  val1.parsing_results()[0].data_status_codes()[0] = Status::Good;
  val1.parsing_results()[0].data_diagnostic_infos().resize(2);
  val1.diagnostic_infos().resize(2);
  val1.filter_result().element_results().resize(2);
  val1.filter_result().element_results()[0].status_code() = Status::Good;
  val1.filter_result().element_results()[0].operand_status_codes().resize(2);
  val1.filter_result().element_results()[0].operand_status_codes()[0] = Status::Good;
  val1.filter_result().element_results()[0].operand_diagnostic_infos().resize(2);
  val1.filter_result().element_diagnostic_infos().resize(2);
  const QueryFirstResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.query_data_sets();
  const_val.query_data_sets();
  val1.continuation_point();
  const_val.continuation_point();
  val1.parsing_results();
  const_val.parsing_results();
  val1.diagnostic_infos();
  const_val.diagnostic_infos();
  val1.filter_result();
  const_val.filter_result();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, QueryNextRequest_Structure)
{
  QueryNextRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.release_continuation_point() = true;
  val1.continuation_point() = ByteString{1, 2, 3};
  const QueryNextRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.release_continuation_point();
  const_val.release_continuation_point();
  val1.continuation_point();
  const_val.continuation_point();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, QueryNextResponse_Structure)
{
  QueryNextResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.query_data_sets().resize(2);
  val1.query_data_sets()[0].node_id() = ExpandedNodeId{NodeId{1234}};
  val1.query_data_sets()[0].type_definition_node() = ExpandedNodeId{NodeId{1234}};
  val1.query_data_sets()[0].values().resize(2);
  val1.revised_continuation_point() = ByteString{1, 2, 3};
  const QueryNextResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.query_data_sets();
  const_val.query_data_sets();
  val1.revised_continuation_point();
  const_val.revised_continuation_point();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, TimestampsToReturn_Enumeration)
{
  TimestampsToReturn e{};
  e = TimestampsToReturn::Source;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Source");
  e = TimestampsToReturn::Server;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Server");
  e = TimestampsToReturn::Both;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Both");
  e = TimestampsToReturn::Neither;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Neither");
  e = TimestampsToReturn::Invalid;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Invalid");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<TimestampsToReturn>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<TimestampsToReturn>(-9999));
}

TEST_F(GeneratedDataTypeTests, ReadValueId_Structure)
{
  ReadValueId val1;
  val1.node_id() = NodeId{1234};
  val1.attribute_id() = 123456;
  val1.index_range() = "test";
  val1.data_encoding() = QualifiedName{"test"};
  const ReadValueId& const_val = val1;
  val1.node_id();
  const_val.node_id();
  val1.attribute_id();
  const_val.attribute_id();
  val1.index_range();
  const_val.index_range();
  val1.data_encoding();
  const_val.data_encoding();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ReadRequest_Structure)
{
  ReadRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.max_age() = 1.5;
  val1.timestamps_to_return() = TimestampsToReturn::Source;
  val1.nodes_to_read().resize(2);
  val1.nodes_to_read()[0].node_id() = NodeId{1234};
  val1.nodes_to_read()[0].attribute_id() = 123456;
  val1.nodes_to_read()[0].index_range() = "test";
  val1.nodes_to_read()[0].data_encoding() = QualifiedName{"test"};
  const ReadRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.max_age();
  const_val.max_age();
  val1.timestamps_to_return();
  const_val.timestamps_to_return();
  val1.nodes_to_read();
  const_val.nodes_to_read();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ReadResponse_Structure)
{
  ReadResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.results().resize(2);
  val1.diagnostic_infos().resize(2);
  const ReadResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.results();
  const_val.results();
  val1.diagnostic_infos();
  const_val.diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, HistoryReadValueId_Structure)
{
  HistoryReadValueId val1;
  val1.node_id() = NodeId{1234};
  val1.index_range() = "test";
  val1.data_encoding() = QualifiedName{"test"};
  val1.continuation_point() = ByteString{1, 2, 3};
  const HistoryReadValueId& const_val = val1;
  val1.node_id();
  const_val.node_id();
  val1.index_range();
  const_val.index_range();
  val1.data_encoding();
  const_val.data_encoding();
  val1.continuation_point();
  const_val.continuation_point();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, HistoryReadResult_Structure)
{
  HistoryReadResult val1;
  val1.status_code() = Status::Good;
  val1.continuation_point() = ByteString{1, 2, 3};
  const HistoryReadResult& const_val = val1;
  val1.status_code();
  const_val.status_code();
  val1.continuation_point();
  const_val.continuation_point();
  val1.history_data();
  const_val.history_data();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, HistoryReadDetails_AbstractStructure)
{
  // Testing only metadata for abstract structures
  // we cannot instantiate them
}

TEST_F(GeneratedDataTypeTests, ReadEventDetails_Structure)
{
  ReadEventDetails val1;
  val1.num_values_per_node() = 123456;
  val1.start_time() = DateTime::now();
  val1.end_time() = DateTime::now();
  val1.filter().select_clauses().resize(2);
  val1.filter().select_clauses()[0].type_definition_id() = NodeId{1234};
  val1.filter().select_clauses()[0].browse_path().resize(2);
  val1.filter().select_clauses()[0].browse_path()[0] = QualifiedName{"test"};
  val1.filter().select_clauses()[0].attribute_id() = 123456;
  val1.filter().select_clauses()[0].index_range() = "test";
  val1.filter().where_clause().elements().resize(2);
  val1.filter().where_clause().elements()[0].filter_operands().resize(2);
  const ReadEventDetails& const_val = val1;
  val1.num_values_per_node();
  const_val.num_values_per_node();
  val1.start_time();
  const_val.start_time();
  val1.end_time();
  const_val.end_time();
  val1.filter();
  const_val.filter();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ReadEventDetails2_Structure)
{
  ReadEventDetails2 val1;
  val1.read_modified() = true;
  const ReadEventDetails2& const_val = val1;
  val1.read_modified();
  const_val.read_modified();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, SortOrderType_Enumeration)
{
  SortOrderType e{};
  e = SortOrderType::Ascending;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Ascending");
  e = SortOrderType::Descending;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Descending");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<SortOrderType>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<SortOrderType>(-9999));
}

TEST_F(GeneratedDataTypeTests, SortRuleElement_Structure)
{
  SortRuleElement val1;
  val1.sort_order() = SortOrderType::Ascending;
  val1.event_field().type_definition_id() = NodeId{1234};
  val1.event_field().browse_path().resize(2);
  val1.event_field().browse_path()[0] = QualifiedName{"test"};
  val1.event_field().attribute_id() = 123456;
  val1.event_field().index_range() = "test";
  const SortRuleElement& const_val = val1;
  val1.sort_order();
  const_val.sort_order();
  val1.event_field();
  const_val.event_field();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ReadEventDetailsSorted_Structure)
{
  ReadEventDetailsSorted val1;
  val1.sort_clause().resize(2);
  val1.sort_clause()[0].sort_order() = SortOrderType::Ascending;
  val1.sort_clause()[0].event_field().type_definition_id() = NodeId{1234};
  val1.sort_clause()[0].event_field().browse_path().resize(2);
  val1.sort_clause()[0].event_field().browse_path()[0] = QualifiedName{"test"};
  val1.sort_clause()[0].event_field().attribute_id() = 123456;
  val1.sort_clause()[0].event_field().index_range() = "test";
  const ReadEventDetailsSorted& const_val = val1;
  val1.sort_clause();
  const_val.sort_clause();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ReadRawModifiedDetails_Structure)
{
  ReadRawModifiedDetails val1;
  val1.is_read_modified() = true;
  val1.start_time() = DateTime::now();
  val1.end_time() = DateTime::now();
  val1.num_values_per_node() = 123456;
  val1.return_bounds() = true;
  const ReadRawModifiedDetails& const_val = val1;
  val1.is_read_modified();
  const_val.is_read_modified();
  val1.start_time();
  const_val.start_time();
  val1.end_time();
  const_val.end_time();
  val1.num_values_per_node();
  const_val.num_values_per_node();
  val1.return_bounds();
  const_val.return_bounds();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ReadProcessedDetails_Structure)
{
  ReadProcessedDetails val1;
  val1.start_time() = DateTime::now();
  val1.end_time() = DateTime::now();
  val1.processing_interval() = 1.5;
  val1.aggregate_type().resize(2);
  val1.aggregate_type()[0] = NodeId{1234};
  val1.aggregate_configuration().use_server_capabilities_defaults() = true;
  val1.aggregate_configuration().treat_uncertain_as_bad() = true;
  val1.aggregate_configuration().percent_data_bad() = 123;
  val1.aggregate_configuration().percent_data_good() = 123;
  val1.aggregate_configuration().use_sloped_extrapolation() = true;
  const ReadProcessedDetails& const_val = val1;
  val1.start_time();
  const_val.start_time();
  val1.end_time();
  const_val.end_time();
  val1.processing_interval();
  const_val.processing_interval();
  val1.aggregate_type();
  const_val.aggregate_type();
  val1.aggregate_configuration();
  const_val.aggregate_configuration();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ReadAtTimeDetails_Structure)
{
  ReadAtTimeDetails val1;
  val1.req_times().resize(2);
  val1.req_times()[0] = DateTime::now();
  val1.use_simple_bounds() = true;
  const ReadAtTimeDetails& const_val = val1;
  val1.req_times();
  const_val.req_times();
  val1.use_simple_bounds();
  const_val.use_simple_bounds();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ReadAnnotationDataDetails_Structure)
{
  ReadAnnotationDataDetails val1;
  val1.req_times().resize(2);
  val1.req_times()[0] = DateTime::now();
  const ReadAnnotationDataDetails& const_val = val1;
  val1.req_times();
  const_val.req_times();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, HistoryData_Structure)
{
  HistoryData val1;
  val1.data_values().resize(2);
  const HistoryData& const_val = val1;
  val1.data_values();
  const_val.data_values();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, HistoryModifiedData_Structure)
{
  HistoryModifiedData val1;
  val1.modification_infos().resize(2);
  val1.modification_infos()[0].modification_time() = DateTime::now();
  val1.modification_infos()[0].update_type() = HistoryUpdateType::Insert;
  val1.modification_infos()[0].user_name() = "test";
  const HistoryModifiedData& const_val = val1;
  val1.modification_infos();
  const_val.modification_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, HistoryReadRequest_Structure)
{
  HistoryReadRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.timestamps_to_return() = TimestampsToReturn::Source;
  val1.release_continuation_points() = true;
  val1.nodes_to_read().resize(2);
  val1.nodes_to_read()[0].node_id() = NodeId{1234};
  val1.nodes_to_read()[0].index_range() = "test";
  val1.nodes_to_read()[0].data_encoding() = QualifiedName{"test"};
  val1.nodes_to_read()[0].continuation_point() = ByteString{1, 2, 3};
  const HistoryReadRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.history_read_details();
  const_val.history_read_details();
  val1.timestamps_to_return();
  const_val.timestamps_to_return();
  val1.release_continuation_points();
  const_val.release_continuation_points();
  val1.nodes_to_read();
  const_val.nodes_to_read();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, HistoryReadResponse_Structure)
{
  HistoryReadResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.results().resize(2);
  val1.results()[0].status_code() = Status::Good;
  val1.results()[0].continuation_point() = ByteString{1, 2, 3};
  val1.diagnostic_infos().resize(2);
  const HistoryReadResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.results();
  const_val.results();
  val1.diagnostic_infos();
  const_val.diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, WriteValue_Structure)
{
  WriteValue val1;
  val1.node_id() = NodeId{1234};
  val1.attribute_id() = 123456;
  val1.index_range() = "test";
  const WriteValue& const_val = val1;
  val1.node_id();
  const_val.node_id();
  val1.attribute_id();
  const_val.attribute_id();
  val1.index_range();
  const_val.index_range();
  val1.value();
  const_val.value();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, WriteRequest_Structure)
{
  WriteRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.nodes_to_write().resize(2);
  val1.nodes_to_write()[0].node_id() = NodeId{1234};
  val1.nodes_to_write()[0].attribute_id() = 123456;
  val1.nodes_to_write()[0].index_range() = "test";
  const WriteRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.nodes_to_write();
  const_val.nodes_to_write();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, WriteResponse_Structure)
{
  WriteResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.results().resize(2);
  val1.results()[0] = Status::Good;
  val1.diagnostic_infos().resize(2);
  const WriteResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.results();
  const_val.results();
  val1.diagnostic_infos();
  const_val.diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, HistoryUpdateDetails_AbstractStructure)
{
  // Testing only metadata for abstract structures
  // we cannot instantiate them
}

TEST_F(GeneratedDataTypeTests, UpdateDataDetails_Structure)
{
  UpdateDataDetails val1;
  val1.node_id() = NodeId{1234};
  val1.perform_insert_replace() = PerformUpdateType::Insert;
  val1.update_values().resize(2);
  const UpdateDataDetails& const_val = val1;
  val1.node_id();
  const_val.node_id();
  val1.perform_insert_replace();
  const_val.perform_insert_replace();
  val1.update_values();
  const_val.update_values();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, UpdateStructureDataDetails_Structure)
{
  UpdateStructureDataDetails val1;
  val1.node_id() = NodeId{1234};
  val1.perform_insert_replace() = PerformUpdateType::Insert;
  val1.update_values().resize(2);
  const UpdateStructureDataDetails& const_val = val1;
  val1.node_id();
  const_val.node_id();
  val1.perform_insert_replace();
  const_val.perform_insert_replace();
  val1.update_values();
  const_val.update_values();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, UpdateEventDetails_Structure)
{
  UpdateEventDetails val1;
  val1.node_id() = NodeId{1234};
  val1.perform_insert_replace() = PerformUpdateType::Insert;
  val1.filter().select_clauses().resize(2);
  val1.filter().select_clauses()[0].type_definition_id() = NodeId{1234};
  val1.filter().select_clauses()[0].browse_path().resize(2);
  val1.filter().select_clauses()[0].browse_path()[0] = QualifiedName{"test"};
  val1.filter().select_clauses()[0].attribute_id() = 123456;
  val1.filter().select_clauses()[0].index_range() = "test";
  val1.filter().where_clause().elements().resize(2);
  val1.filter().where_clause().elements()[0].filter_operands().resize(2);
  val1.event_data().resize(2);
  val1.event_data()[0].event_fields().resize(2);
  const UpdateEventDetails& const_val = val1;
  val1.node_id();
  const_val.node_id();
  val1.perform_insert_replace();
  const_val.perform_insert_replace();
  val1.filter();
  const_val.filter();
  val1.event_data();
  const_val.event_data();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, DeleteRawModifiedDetails_Structure)
{
  DeleteRawModifiedDetails val1;
  val1.node_id() = NodeId{1234};
  val1.is_delete_modified() = true;
  val1.start_time() = DateTime::now();
  val1.end_time() = DateTime::now();
  const DeleteRawModifiedDetails& const_val = val1;
  val1.node_id();
  const_val.node_id();
  val1.is_delete_modified();
  const_val.is_delete_modified();
  val1.start_time();
  const_val.start_time();
  val1.end_time();
  const_val.end_time();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, DeleteAtTimeDetails_Structure)
{
  DeleteAtTimeDetails val1;
  val1.node_id() = NodeId{1234};
  val1.req_times().resize(2);
  val1.req_times()[0] = DateTime::now();
  const DeleteAtTimeDetails& const_val = val1;
  val1.node_id();
  const_val.node_id();
  val1.req_times();
  const_val.req_times();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, DeleteEventDetails_Structure)
{
  DeleteEventDetails val1;
  val1.node_id() = NodeId{1234};
  val1.event_ids().resize(2);
  val1.event_ids()[0] = ByteString{1, 2, 3};
  const DeleteEventDetails& const_val = val1;
  val1.node_id();
  const_val.node_id();
  val1.event_ids();
  const_val.event_ids();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, HistoryUpdateResult_Structure)
{
  HistoryUpdateResult val1;
  val1.status_code() = Status::Good;
  val1.operation_results().resize(2);
  val1.operation_results()[0] = Status::Good;
  val1.diagnostic_infos().resize(2);
  const HistoryUpdateResult& const_val = val1;
  val1.status_code();
  const_val.status_code();
  val1.operation_results();
  const_val.operation_results();
  val1.diagnostic_infos();
  const_val.diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, HistoryUpdateRequest_Structure)
{
  HistoryUpdateRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.history_update_details().resize(2);
  const HistoryUpdateRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.history_update_details();
  const_val.history_update_details();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, HistoryUpdateResponse_Structure)
{
  HistoryUpdateResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.results().resize(2);
  val1.results()[0].status_code() = Status::Good;
  val1.results()[0].operation_results().resize(2);
  val1.results()[0].operation_results()[0] = Status::Good;
  val1.results()[0].diagnostic_infos().resize(2);
  val1.diagnostic_infos().resize(2);
  const HistoryUpdateResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.results();
  const_val.results();
  val1.diagnostic_infos();
  const_val.diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, CallMethodRequest_Structure)
{
  CallMethodRequest val1;
  val1.object_id() = NodeId{1234};
  val1.method_id() = NodeId{1234};
  val1.input_arguments().resize(2);
  const CallMethodRequest& const_val = val1;
  val1.object_id();
  const_val.object_id();
  val1.method_id();
  const_val.method_id();
  val1.input_arguments();
  const_val.input_arguments();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, CallMethodResult_Structure)
{
  CallMethodResult val1;
  val1.status_code() = Status::Good;
  val1.input_argument_results().resize(2);
  val1.input_argument_results()[0] = Status::Good;
  val1.input_argument_diagnostic_infos().resize(2);
  val1.output_arguments().resize(2);
  const CallMethodResult& const_val = val1;
  val1.status_code();
  const_val.status_code();
  val1.input_argument_results();
  const_val.input_argument_results();
  val1.input_argument_diagnostic_infos();
  const_val.input_argument_diagnostic_infos();
  val1.output_arguments();
  const_val.output_arguments();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, CallRequest_Structure)
{
  CallRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.methods_to_call().resize(2);
  val1.methods_to_call()[0].object_id() = NodeId{1234};
  val1.methods_to_call()[0].method_id() = NodeId{1234};
  val1.methods_to_call()[0].input_arguments().resize(2);
  const CallRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.methods_to_call();
  const_val.methods_to_call();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, CallResponse_Structure)
{
  CallResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.results().resize(2);
  val1.results()[0].status_code() = Status::Good;
  val1.results()[0].input_argument_results().resize(2);
  val1.results()[0].input_argument_results()[0] = Status::Good;
  val1.results()[0].input_argument_diagnostic_infos().resize(2);
  val1.results()[0].output_arguments().resize(2);
  val1.diagnostic_infos().resize(2);
  const CallResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.results();
  const_val.results();
  val1.diagnostic_infos();
  const_val.diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, MonitoringMode_Enumeration)
{
  MonitoringMode e{};
  e = MonitoringMode::Disabled;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Disabled");
  e = MonitoringMode::Sampling;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Sampling");
  e = MonitoringMode::Reporting;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Reporting");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<MonitoringMode>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<MonitoringMode>(-9999));
}

TEST_F(GeneratedDataTypeTests, DataChangeTrigger_Enumeration)
{
  DataChangeTrigger e{};
  e = DataChangeTrigger::Status;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Status");
  e = DataChangeTrigger::StatusValue;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "StatusValue");
  e = DataChangeTrigger::StatusValueTimestamp;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "StatusValueTimestamp");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<DataChangeTrigger>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<DataChangeTrigger>(-9999));
}

TEST_F(GeneratedDataTypeTests, DeadbandType_Enumeration)
{
  DeadbandType e{};
  e = DeadbandType::None;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "None");
  e = DeadbandType::Absolute;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Absolute");
  e = DeadbandType::Percent;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "Percent");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<DeadbandType>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<DeadbandType>(-9999));
}

TEST_F(GeneratedDataTypeTests, DataChangeFilter_Structure)
{
  DataChangeFilter val1;
  val1.trigger() = DataChangeTrigger::Status;
  val1.deadband_type() = 123456;
  val1.deadband_value() = 1.5;
  const DataChangeFilter& const_val = val1;
  val1.trigger();
  const_val.trigger();
  val1.deadband_type();
  const_val.deadband_type();
  val1.deadband_value();
  const_val.deadband_value();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, AggregateFilter_Structure)
{
  AggregateFilter val1;
  val1.start_time() = DateTime::now();
  val1.aggregate_type() = NodeId{1234};
  val1.processing_interval() = 1.5;
  val1.aggregate_configuration().use_server_capabilities_defaults() = true;
  val1.aggregate_configuration().treat_uncertain_as_bad() = true;
  val1.aggregate_configuration().percent_data_bad() = 123;
  val1.aggregate_configuration().percent_data_good() = 123;
  val1.aggregate_configuration().use_sloped_extrapolation() = true;
  const AggregateFilter& const_val = val1;
  val1.start_time();
  const_val.start_time();
  val1.aggregate_type();
  const_val.aggregate_type();
  val1.processing_interval();
  const_val.processing_interval();
  val1.aggregate_configuration();
  const_val.aggregate_configuration();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, MonitoringFilterResult_Structure)
{
  MonitoringFilterResult val1;
  const MonitoringFilterResult& const_val = val1;
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, EventFilterResult_Structure)
{
  EventFilterResult val1;
  val1.select_clause_results().resize(2);
  val1.select_clause_results()[0] = Status::Good;
  val1.select_clause_diagnostic_infos().resize(2);
  val1.where_clause_result().element_results().resize(2);
  val1.where_clause_result().element_results()[0].status_code() = Status::Good;
  val1.where_clause_result().element_results()[0].operand_status_codes().resize(2);
  val1.where_clause_result().element_results()[0].operand_status_codes()[0] = Status::Good;
  val1.where_clause_result().element_results()[0].operand_diagnostic_infos().resize(2);
  val1.where_clause_result().element_diagnostic_infos().resize(2);
  const EventFilterResult& const_val = val1;
  val1.select_clause_results();
  const_val.select_clause_results();
  val1.select_clause_diagnostic_infos();
  const_val.select_clause_diagnostic_infos();
  val1.where_clause_result();
  const_val.where_clause_result();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, AggregateFilterResult_Structure)
{
  AggregateFilterResult val1;
  val1.revised_start_time() = DateTime::now();
  val1.revised_processing_interval() = 1.5;
  val1.revised_aggregate_configuration().use_server_capabilities_defaults() = true;
  val1.revised_aggregate_configuration().treat_uncertain_as_bad() = true;
  val1.revised_aggregate_configuration().percent_data_bad() = 123;
  val1.revised_aggregate_configuration().percent_data_good() = 123;
  val1.revised_aggregate_configuration().use_sloped_extrapolation() = true;
  const AggregateFilterResult& const_val = val1;
  val1.revised_start_time();
  const_val.revised_start_time();
  val1.revised_processing_interval();
  const_val.revised_processing_interval();
  val1.revised_aggregate_configuration();
  const_val.revised_aggregate_configuration();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, MonitoringParameters_Structure)
{
  MonitoringParameters val1;
  val1.client_handle() = 123456;
  val1.sampling_interval() = 1.5;
  val1.queue_size() = 123456;
  val1.discard_oldest() = true;
  const MonitoringParameters& const_val = val1;
  val1.client_handle();
  const_val.client_handle();
  val1.sampling_interval();
  const_val.sampling_interval();
  val1.filter();
  const_val.filter();
  val1.queue_size();
  const_val.queue_size();
  val1.discard_oldest();
  const_val.discard_oldest();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, MonitoredItemCreateRequest_Structure)
{
  MonitoredItemCreateRequest val1;
  val1.item_to_monitor().node_id() = NodeId{1234};
  val1.item_to_monitor().attribute_id() = 123456;
  val1.item_to_monitor().index_range() = "test";
  val1.item_to_monitor().data_encoding() = QualifiedName{"test"};
  val1.monitoring_mode() = MonitoringMode::Disabled;
  val1.requested_parameters().client_handle() = 123456;
  val1.requested_parameters().sampling_interval() = 1.5;
  val1.requested_parameters().queue_size() = 123456;
  val1.requested_parameters().discard_oldest() = true;
  const MonitoredItemCreateRequest& const_val = val1;
  val1.item_to_monitor();
  const_val.item_to_monitor();
  val1.monitoring_mode();
  const_val.monitoring_mode();
  val1.requested_parameters();
  const_val.requested_parameters();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, MonitoredItemCreateResult_Structure)
{
  MonitoredItemCreateResult val1;
  val1.status_code() = Status::Good;
  val1.monitored_item_id() = 123456;
  val1.revised_sampling_interval() = 1.5;
  val1.revised_queue_size() = 123456;
  const MonitoredItemCreateResult& const_val = val1;
  val1.status_code();
  const_val.status_code();
  val1.monitored_item_id();
  const_val.monitored_item_id();
  val1.revised_sampling_interval();
  const_val.revised_sampling_interval();
  val1.revised_queue_size();
  const_val.revised_queue_size();
  val1.filter_result();
  const_val.filter_result();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, CreateMonitoredItemsRequest_Structure)
{
  CreateMonitoredItemsRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.subscription_id() = 123456;
  val1.timestamps_to_return() = TimestampsToReturn::Source;
  val1.items_to_create().resize(2);
  val1.items_to_create()[0].item_to_monitor().node_id() = NodeId{1234};
  val1.items_to_create()[0].item_to_monitor().attribute_id() = 123456;
  val1.items_to_create()[0].item_to_monitor().index_range() = "test";
  val1.items_to_create()[0].item_to_monitor().data_encoding() = QualifiedName{"test"};
  val1.items_to_create()[0].monitoring_mode() = MonitoringMode::Disabled;
  val1.items_to_create()[0].requested_parameters().client_handle() = 123456;
  val1.items_to_create()[0].requested_parameters().sampling_interval() = 1.5;
  val1.items_to_create()[0].requested_parameters().queue_size() = 123456;
  val1.items_to_create()[0].requested_parameters().discard_oldest() = true;
  const CreateMonitoredItemsRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.subscription_id();
  const_val.subscription_id();
  val1.timestamps_to_return();
  const_val.timestamps_to_return();
  val1.items_to_create();
  const_val.items_to_create();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, CreateMonitoredItemsResponse_Structure)
{
  CreateMonitoredItemsResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.results().resize(2);
  val1.results()[0].status_code() = Status::Good;
  val1.results()[0].monitored_item_id() = 123456;
  val1.results()[0].revised_sampling_interval() = 1.5;
  val1.results()[0].revised_queue_size() = 123456;
  val1.diagnostic_infos().resize(2);
  const CreateMonitoredItemsResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.results();
  const_val.results();
  val1.diagnostic_infos();
  const_val.diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, MonitoredItemModifyRequest_Structure)
{
  MonitoredItemModifyRequest val1;
  val1.monitored_item_id() = 123456;
  val1.requested_parameters().client_handle() = 123456;
  val1.requested_parameters().sampling_interval() = 1.5;
  val1.requested_parameters().queue_size() = 123456;
  val1.requested_parameters().discard_oldest() = true;
  const MonitoredItemModifyRequest& const_val = val1;
  val1.monitored_item_id();
  const_val.monitored_item_id();
  val1.requested_parameters();
  const_val.requested_parameters();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, MonitoredItemModifyResult_Structure)
{
  MonitoredItemModifyResult val1;
  val1.status_code() = Status::Good;
  val1.revised_sampling_interval() = 1.5;
  val1.revised_queue_size() = 123456;
  const MonitoredItemModifyResult& const_val = val1;
  val1.status_code();
  const_val.status_code();
  val1.revised_sampling_interval();
  const_val.revised_sampling_interval();
  val1.revised_queue_size();
  const_val.revised_queue_size();
  val1.filter_result();
  const_val.filter_result();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ModifyMonitoredItemsRequest_Structure)
{
  ModifyMonitoredItemsRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.subscription_id() = 123456;
  val1.timestamps_to_return() = TimestampsToReturn::Source;
  val1.items_to_modify().resize(2);
  val1.items_to_modify()[0].monitored_item_id() = 123456;
  val1.items_to_modify()[0].requested_parameters().client_handle() = 123456;
  val1.items_to_modify()[0].requested_parameters().sampling_interval() = 1.5;
  val1.items_to_modify()[0].requested_parameters().queue_size() = 123456;
  val1.items_to_modify()[0].requested_parameters().discard_oldest() = true;
  const ModifyMonitoredItemsRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.subscription_id();
  const_val.subscription_id();
  val1.timestamps_to_return();
  const_val.timestamps_to_return();
  val1.items_to_modify();
  const_val.items_to_modify();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ModifyMonitoredItemsResponse_Structure)
{
  ModifyMonitoredItemsResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.results().resize(2);
  val1.results()[0].status_code() = Status::Good;
  val1.results()[0].revised_sampling_interval() = 1.5;
  val1.results()[0].revised_queue_size() = 123456;
  val1.diagnostic_infos().resize(2);
  const ModifyMonitoredItemsResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.results();
  const_val.results();
  val1.diagnostic_infos();
  const_val.diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, SetMonitoringModeRequest_Structure)
{
  SetMonitoringModeRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.subscription_id() = 123456;
  val1.monitoring_mode() = MonitoringMode::Disabled;
  val1.monitored_item_ids().resize(2);
  val1.monitored_item_ids()[0] = 123456;
  const SetMonitoringModeRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.subscription_id();
  const_val.subscription_id();
  val1.monitoring_mode();
  const_val.monitoring_mode();
  val1.monitored_item_ids();
  const_val.monitored_item_ids();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, SetMonitoringModeResponse_Structure)
{
  SetMonitoringModeResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.results().resize(2);
  val1.results()[0] = Status::Good;
  val1.diagnostic_infos().resize(2);
  const SetMonitoringModeResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.results();
  const_val.results();
  val1.diagnostic_infos();
  const_val.diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, SetTriggeringRequest_Structure)
{
  SetTriggeringRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.subscription_id() = 123456;
  val1.triggering_item_id() = 123456;
  val1.links_to_add().resize(2);
  val1.links_to_add()[0] = 123456;
  val1.links_to_remove().resize(2);
  val1.links_to_remove()[0] = 123456;
  const SetTriggeringRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.subscription_id();
  const_val.subscription_id();
  val1.triggering_item_id();
  const_val.triggering_item_id();
  val1.links_to_add();
  const_val.links_to_add();
  val1.links_to_remove();
  const_val.links_to_remove();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, SetTriggeringResponse_Structure)
{
  SetTriggeringResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.add_results().resize(2);
  val1.add_results()[0] = Status::Good;
  val1.add_diagnostic_infos().resize(2);
  val1.remove_results().resize(2);
  val1.remove_results()[0] = Status::Good;
  val1.remove_diagnostic_infos().resize(2);
  const SetTriggeringResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.add_results();
  const_val.add_results();
  val1.add_diagnostic_infos();
  const_val.add_diagnostic_infos();
  val1.remove_results();
  const_val.remove_results();
  val1.remove_diagnostic_infos();
  const_val.remove_diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, DeleteMonitoredItemsRequest_Structure)
{
  DeleteMonitoredItemsRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.subscription_id() = 123456;
  val1.monitored_item_ids().resize(2);
  val1.monitored_item_ids()[0] = 123456;
  const DeleteMonitoredItemsRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.subscription_id();
  const_val.subscription_id();
  val1.monitored_item_ids();
  const_val.monitored_item_ids();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, DeleteMonitoredItemsResponse_Structure)
{
  DeleteMonitoredItemsResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.results().resize(2);
  val1.results()[0] = Status::Good;
  val1.diagnostic_infos().resize(2);
  const DeleteMonitoredItemsResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.results();
  const_val.results();
  val1.diagnostic_infos();
  const_val.diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, CreateSubscriptionRequest_Structure)
{
  CreateSubscriptionRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.requested_publishing_interval() = 1.5;
  val1.requested_lifetime_count() = 123456;
  val1.requested_max_keep_alive_count() = 123456;
  val1.max_notifications_per_publish() = 123456;
  val1.publishing_enabled() = true;
  val1.priority() = 123;
  const CreateSubscriptionRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.requested_publishing_interval();
  const_val.requested_publishing_interval();
  val1.requested_lifetime_count();
  const_val.requested_lifetime_count();
  val1.requested_max_keep_alive_count();
  const_val.requested_max_keep_alive_count();
  val1.max_notifications_per_publish();
  const_val.max_notifications_per_publish();
  val1.publishing_enabled();
  const_val.publishing_enabled();
  val1.priority();
  const_val.priority();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, CreateSubscriptionResponse_Structure)
{
  CreateSubscriptionResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.subscription_id() = 123456;
  val1.revised_publishing_interval() = 1.5;
  val1.revised_lifetime_count() = 123456;
  val1.revised_max_keep_alive_count() = 123456;
  const CreateSubscriptionResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.subscription_id();
  const_val.subscription_id();
  val1.revised_publishing_interval();
  const_val.revised_publishing_interval();
  val1.revised_lifetime_count();
  const_val.revised_lifetime_count();
  val1.revised_max_keep_alive_count();
  const_val.revised_max_keep_alive_count();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ModifySubscriptionRequest_Structure)
{
  ModifySubscriptionRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.subscription_id() = 123456;
  val1.requested_publishing_interval() = 1.5;
  val1.requested_lifetime_count() = 123456;
  val1.requested_max_keep_alive_count() = 123456;
  val1.max_notifications_per_publish() = 123456;
  val1.priority() = 123;
  const ModifySubscriptionRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.subscription_id();
  const_val.subscription_id();
  val1.requested_publishing_interval();
  const_val.requested_publishing_interval();
  val1.requested_lifetime_count();
  const_val.requested_lifetime_count();
  val1.requested_max_keep_alive_count();
  const_val.requested_max_keep_alive_count();
  val1.max_notifications_per_publish();
  const_val.max_notifications_per_publish();
  val1.priority();
  const_val.priority();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ModifySubscriptionResponse_Structure)
{
  ModifySubscriptionResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.revised_publishing_interval() = 1.5;
  val1.revised_lifetime_count() = 123456;
  val1.revised_max_keep_alive_count() = 123456;
  const ModifySubscriptionResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.revised_publishing_interval();
  const_val.revised_publishing_interval();
  val1.revised_lifetime_count();
  const_val.revised_lifetime_count();
  val1.revised_max_keep_alive_count();
  const_val.revised_max_keep_alive_count();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, SetPublishingModeRequest_Structure)
{
  SetPublishingModeRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.publishing_enabled() = true;
  val1.subscription_ids().resize(2);
  val1.subscription_ids()[0] = 123456;
  const SetPublishingModeRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.publishing_enabled();
  const_val.publishing_enabled();
  val1.subscription_ids();
  const_val.subscription_ids();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, SetPublishingModeResponse_Structure)
{
  SetPublishingModeResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.results().resize(2);
  val1.results()[0] = Status::Good;
  val1.diagnostic_infos().resize(2);
  const SetPublishingModeResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.results();
  const_val.results();
  val1.diagnostic_infos();
  const_val.diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, NotificationMessage_Structure)
{
  NotificationMessage val1;
  val1.sequence_number() = 123456;
  val1.publish_time() = DateTime::now();
  val1.notification_data().resize(2);
  const NotificationMessage& const_val = val1;
  val1.sequence_number();
  const_val.sequence_number();
  val1.publish_time();
  const_val.publish_time();
  val1.notification_data();
  const_val.notification_data();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, NotificationData_Structure)
{
  NotificationData val1;
  const NotificationData& const_val = val1;
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, DataChangeNotification_Structure)
{
  DataChangeNotification val1;
  val1.monitored_items().resize(2);
  val1.monitored_items()[0].client_handle() = 123456;
  val1.diagnostic_infos().resize(2);
  const DataChangeNotification& const_val = val1;
  val1.monitored_items();
  const_val.monitored_items();
  val1.diagnostic_infos();
  const_val.diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, MonitoredItemNotification_Structure)
{
  MonitoredItemNotification val1;
  val1.client_handle() = 123456;
  const MonitoredItemNotification& const_val = val1;
  val1.client_handle();
  const_val.client_handle();
  val1.value();
  const_val.value();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, EventNotificationList_Structure)
{
  EventNotificationList val1;
  val1.events().resize(2);
  val1.events()[0].client_handle() = 123456;
  val1.events()[0].event_fields().resize(2);
  const EventNotificationList& const_val = val1;
  val1.events();
  const_val.events();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, EventFieldList_Structure)
{
  EventFieldList val1;
  val1.client_handle() = 123456;
  val1.event_fields().resize(2);
  const EventFieldList& const_val = val1;
  val1.client_handle();
  const_val.client_handle();
  val1.event_fields();
  const_val.event_fields();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, StatusChangeNotification_Structure)
{
  StatusChangeNotification val1;
  val1.status() = Status::Good;
  const StatusChangeNotification& const_val = val1;
  val1.status();
  const_val.status();
  val1.diagnostic_info();
  const_val.diagnostic_info();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, SubscriptionAcknowledgement_Structure)
{
  SubscriptionAcknowledgement val1;
  val1.subscription_id() = 123456;
  val1.sequence_number() = 123456;
  const SubscriptionAcknowledgement& const_val = val1;
  val1.subscription_id();
  const_val.subscription_id();
  val1.sequence_number();
  const_val.sequence_number();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, PublishRequest_Structure)
{
  PublishRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.subscription_acknowledgements().resize(2);
  val1.subscription_acknowledgements()[0].subscription_id() = 123456;
  val1.subscription_acknowledgements()[0].sequence_number() = 123456;
  const PublishRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.subscription_acknowledgements();
  const_val.subscription_acknowledgements();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, PublishResponse_Structure)
{
  PublishResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.subscription_id() = 123456;
  val1.available_sequence_numbers().resize(2);
  val1.available_sequence_numbers()[0] = 123456;
  val1.more_notifications() = true;
  val1.notification_message().sequence_number() = 123456;
  val1.notification_message().publish_time() = DateTime::now();
  val1.notification_message().notification_data().resize(2);
  val1.results().resize(2);
  val1.results()[0] = Status::Good;
  val1.diagnostic_infos().resize(2);
  const PublishResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.subscription_id();
  const_val.subscription_id();
  val1.available_sequence_numbers();
  const_val.available_sequence_numbers();
  val1.more_notifications();
  const_val.more_notifications();
  val1.notification_message();
  const_val.notification_message();
  val1.results();
  const_val.results();
  val1.diagnostic_infos();
  const_val.diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, RepublishRequest_Structure)
{
  RepublishRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.subscription_id() = 123456;
  val1.retransmit_sequence_number() = 123456;
  const RepublishRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.subscription_id();
  const_val.subscription_id();
  val1.retransmit_sequence_number();
  const_val.retransmit_sequence_number();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, RepublishResponse_Structure)
{
  RepublishResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.notification_message().sequence_number() = 123456;
  val1.notification_message().publish_time() = DateTime::now();
  val1.notification_message().notification_data().resize(2);
  const RepublishResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.notification_message();
  const_val.notification_message();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, TransferResult_Structure)
{
  TransferResult val1;
  val1.status_code() = Status::Good;
  val1.available_sequence_numbers().resize(2);
  val1.available_sequence_numbers()[0] = 123456;
  const TransferResult& const_val = val1;
  val1.status_code();
  const_val.status_code();
  val1.available_sequence_numbers();
  const_val.available_sequence_numbers();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, TransferSubscriptionsRequest_Structure)
{
  TransferSubscriptionsRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.subscription_ids().resize(2);
  val1.subscription_ids()[0] = 123456;
  val1.send_initial_values() = true;
  const TransferSubscriptionsRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.subscription_ids();
  const_val.subscription_ids();
  val1.send_initial_values();
  const_val.send_initial_values();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, TransferSubscriptionsResponse_Structure)
{
  TransferSubscriptionsResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.results().resize(2);
  val1.results()[0].status_code() = Status::Good;
  val1.results()[0].available_sequence_numbers().resize(2);
  val1.results()[0].available_sequence_numbers()[0] = 123456;
  val1.diagnostic_infos().resize(2);
  const TransferSubscriptionsResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.results();
  const_val.results();
  val1.diagnostic_infos();
  const_val.diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, DeleteSubscriptionsRequest_Structure)
{
  DeleteSubscriptionsRequest val1;
  val1.request_header().authentication_token() = NodeId{1234};
  val1.request_header().timestamp() = DateTime::now();
  val1.request_header().request_handle() = 123456;
  val1.request_header().return_diagnostics() = 123456;
  val1.request_header().audit_entry_id() = "test";
  val1.request_header().timeout_hint() = 123456;
  val1.subscription_ids().resize(2);
  val1.subscription_ids()[0] = 123456;
  const DeleteSubscriptionsRequest& const_val = val1;
  val1.request_header();
  const_val.request_header();
  val1.subscription_ids();
  const_val.subscription_ids();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, DeleteSubscriptionsResponse_Structure)
{
  DeleteSubscriptionsResponse val1;
  val1.response_header().timestamp() = DateTime::now();
  val1.response_header().request_handle() = 123456;
  val1.response_header().service_result() = Status::Good;
  val1.response_header().string_table().resize(2);
  val1.response_header().string_table()[0] = "test";
  val1.results().resize(2);
  val1.results()[0] = Status::Good;
  val1.diagnostic_infos().resize(2);
  const DeleteSubscriptionsResponse& const_val = val1;
  val1.response_header();
  const_val.response_header();
  val1.results();
  const_val.results();
  val1.diagnostic_infos();
  const_val.diagnostic_infos();
  test_binary_round_trip(val1);
  test_metadata(val1);
  test_clone(val1);
  test_xml_round_trip(val1);
  test_extension_object_round_trip(val1);
  test_to_string(val1);
}

TEST_F(GeneratedDataTypeTests, ModelChangeStructureVerbMask_Enumeration)
{
  ModelChangeStructureVerbMask e{};
  e = ModelChangeStructureVerbMask::NodeAdded;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "NodeAdded");
  e = ModelChangeStructureVerbMask::NodeDeleted;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "NodeDeleted");
  e = ModelChangeStructureVerbMask::ReferenceAdded;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "ReferenceAdded");
  e = ModelChangeStructureVerbMask::ReferenceDeleted;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "ReferenceDeleted");
  e = ModelChangeStructureVerbMask::DataTypeChanged;
  EXPECT_TRUE(is_valid(e));
  EXPECT_EQ(to_string(e), "DataTypeChanged");
  // Test invalid value
  EXPECT_FALSE(is_valid(static_cast<ModelChangeStructureVerbMask>(-9999)));
  // Exercise the to_string() fallthrough for unknown values.
  (void)to_string(static_cast<ModelChangeStructureVerbMask>(-9999));
}
