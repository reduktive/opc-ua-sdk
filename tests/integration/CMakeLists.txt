# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(integration_tests PRIVATE
        helpers/matchers.h
        helpers/requests.h
        helpers/requests.cpp
        helpers/role_based_security_fixture.h
        helpers/rbac_server_certificate_validation_fixture.h
        helpers/certificate_validation_integration_fixture.h
        helpers/subscription.h
        helpers/subscription.cpp
        helpers/heap_watermark.h
        helpers/heap_watermark.cpp
        helpers/environment_variable.h
        helpers/toxiproxy_control.h
        helpers/toxiproxy_control.cpp
        helpers/gds_emulator.h
        helpers/gds_emulator.cpp
        gds_emulator_self_tests.cpp
        gds_pull_provisioning_tests.cpp
        client_renewal_integration_tests.cpp
        enhanced_security_policies_tests.cpp
        chaos/chaos_tests.cpp
        leak_loop_tests.cpp
        helpers_builders_test.cpp
        helpers_subscription_test.cpp
        spec_compliance_integration_tests.cpp
        security_integration_tests.cpp
        certificate_validation_server_matrix_tests.cpp
        certificate_validation_client_matrix_tests.cpp
        certificate_validation_trust_list_live_tests.cpp
        certificate_validation_misbehaving_server_tests.cpp
        compliance_smoke_tests.cpp
        compliance_discovery_tests.cpp
        compliance_secure_channel_tests.cpp
        shutdown_integration_tests.cpp
        compliance_session_tests.cpp
        compliance_attribute_read_tests.cpp
        read_index_range_tests.cpp
        compliance_attribute_write_tests.cpp
        write_variable_type_value_tests.cpp
        variable_type_value_permission_tests.cpp
        monitored_variable_type_value_tests.cpp
        write_index_range_tests.cpp
        decode_recursion_dos_integration_tests.cpp
        compliance_history_tests.cpp
        compliance_view_browse_tests.cpp
        browse_in_view_tests.cpp
        compliance_address_space_invariants_tests.cpp
        dictionary_identifiers_tests.cpp
        live_namespace_registration_tests.cpp
        compliance_view_translate_tests.cpp
        compliance_view_register_tests.cpp
        compliance_method_tests.cpp
        compliance_node_management_tests.cpp
        compliance_monitored_item_tests.cpp
        monitored_item_index_range_tests.cpp
        compliance_monitored_item_characterisation_tests.cpp
        compliance_subscription_tests.cpp
        compliance_event_tests.cpp
        compliance_model_change_tests.cpp
        compliance_semantic_change_tests.cpp
        model_change_event_source_tests.cpp
        compliance_semantics_changed_tests.cpp
        semantic_change_and_configuration_version_tests.cpp
        semantics_helper_namespace_tests.cpp
        monitoring_release_tests.cpp
        session_end_abort_tests.cpp
        default_monitoring_tests.cpp
        register_nodes_ownership_tests.cpp
        call_routing_tests.cpp
        model_change_on_attributes_tests.cpp
        model_change_versions_tests.cpp
        write_non_value_attributes_tests.cpp
        write_interceptor_tests.cpp
        data_access_write_interceptor_tests.cpp
        data_access_write_tests.cpp
        file_directory_tests.cpp
        temporary_file_transfer_tests.cpp
        transfer_subscriptions_integration_tests.cpp
        sampled_caller_integration_tests.cpp
        client_server_integration_tests.cpp
        text_parse_integration_tests.cpp
        client_connect_integration_tests.cpp
        connection_impl_integration_tests.cpp
        connection_impl_reconnect_integration_tests.cpp
        connection_impl_subscription_integration_tests.cpp
        dynamic_type_integration_tests.cpp
        error_detail_integration_tests.cpp
        method_handler_outcomes_integration_tests.cpp
        condition_integration_tests.cpp
        compliance_condition_tests.cpp
        role_based_security_integration_tests.cpp
        role_based_security_management_integration_tests.cpp
        role_based_security_role_permissions_integration_tests.cpp
        access_control_bootstrap_integration_tests.cpp
        role_based_security_default_permissions_integration_tests.cpp
        role_based_security_push_certificate_integration_tests.cpp
        role_based_security_nodeset_import_integration_tests.cpp
        reverse_connect_tests.cpp
        push_certificate_management_tests.cpp
        get_monitored_items_tests.cpp
        set_subscription_durable_tests.cpp
        subscription_diagnostics_nodes_tests.cpp
        diagnostics_server_summary_integration_tests.cpp
        diagnostics_session_service_integration_tests.cpp
        diagnostics_subscription_integration_tests.cpp
        server_object_methods_tests.cpp
        nodeset_export_namespace_tests.cpp
        client_close_teardown_integration_tests.cpp
        client_shutdown_safety_integration_tests.cpp
        discovery/lds/lds_registration_integration_tests.cpp
        misbehaving_server_demo_tests.cpp
        client_read_matrix_tests.cpp
        client_write_matrix_tests.cpp
        client_browse_matrix_tests.cpp
        client_subscription_matrix_tests.cpp
        client_monitored_item_matrix_tests.cpp
        client_monitor_control_matrix_tests.cpp
        client_subscription_fallback_matrix_tests.cpp
        client_monitor_event_matrix_tests.cpp
        client_event_cache_matrix_tests.cpp
        client_method_call_matrix_tests.cpp
        client_cert_lifecycle_matrix_tests.cpp
        client_security_policy_matrix_tests.cpp
        client_cert_validation_matrix_tests.cpp
        client_pull_cert_matrix_tests.cpp
        client_username_password_matrix_tests.cpp
        client_ecc_matrix_tests.cpp
        client_discovery_get_endpoints_matrix_tests.cpp
        client_republish_matrix_tests.cpp
        client_reverse_listener_matrix_tests.cpp
        standard_client_capacity_manifest_integration_tests.cpp
        client_type_resolver_matrix_tests.cpp
        configuration_trust_matrix_tests.cpp
        configuration_observer_matrix_tests.cpp
        configuration_server_limits_tests.cpp
        partial_results_integration_tests.cpp
        browse_flow_integration_tests.cpp
        address_space_redesign_defect_tests.cpp
        address_space_redesign_probe_tests.cpp
        configuration_stack_limits_tests.cpp
        client_transport_matrix_tests.cpp
        client_alarm_tracker_matrix_tests.cpp
        client_alarm_live_server_tests.cpp
        client_condition_refresh_matrix_tests.cpp
        client_limit_alarm_matrix_tests.cpp
        client_alarm_methods_matrix_tests.cpp
        client_data_access_matrix_tests.cpp
        client_session_matrix_tests.cpp
        client_state_machine_matrix_tests.cpp
        client_finite_state_machine_matrix_tests.cpp
        client_subscription_modify_matrix_tests.cpp
        client_discovery_find_servers_matrix_tests.cpp
        client_discovery_gds_matrix_tests.cpp
        client_monitor_by_index_matrix_tests.cpp
        client_read_write_index_matrix_tests.cpp
        client_read_write_complex_matrix_tests.cpp
        client_history_matrix_tests.cpp
        client_register_browsenext_matrix_tests.cpp
        client_register_nodes_alias_cache_tests.cpp
        client_nodeid_namespace_matrix_tests.cpp
        client_translate_matrix_tests.cpp
        client_decode_caps_matrix_tests.cpp
        client_diagnostics_matrix_tests.cpp
        client_multi_connection_matrix_tests.cpp
        client_anonymous_matrix_tests.cpp
)

# Phase 2: SecureChannel compliance tests need access to impl internals and fuzzer tooling.
# Phase 3: Session compliance tests need access to session impl internals.
target_compile_definitions(integration_tests PRIVATE
        TEST_RESOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../resources"
)

# The Historical Access component (compliance_history_tests.cpp exercises it end-to-end).
target_link_libraries(integration_tests PUBLIC uasdk-history-sqlite)

target_include_directories(integration_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/helpers
        ${CMAKE_SOURCE_DIR}/sdk/implementation/client
        ${CMAKE_SOURCE_DIR}/sdk/implementation/client/secure_channel
        ${CMAKE_SOURCE_DIR}/sdk/implementation/client/session
        ${CMAKE_SOURCE_DIR}/sdk/implementation/address_space
        ${CMAKE_SOURCE_DIR}/sdk/implementation/server/conditions
        ${CMAKE_SOURCE_DIR}/sdk/implementation/core/general
        ${CMAKE_SOURCE_DIR}/tooling/fuzzer/include
)

# The GDS emulator reads the subjectAltName of a PKCS #10 request with OpenSSL directly: the Crypto
# interface signs a request but exposes no reader for it. Linked explicitly because the SDK's own OpenSSL
# link reaches consumers only when the SDK is a static library.
find_package(OpenSSL REQUIRED)
target_link_libraries(integration_tests PRIVATE OpenSSL::Crypto)

# Fuzzer interception utilities used by SecureChannel compliance tests.
# The MisbehavingServer fixture (semantic Response& layer) is a fuzzer extension cross-listed here
# only (it is NOT part of the opcua-fuzzer executable); its header is listed per the build convention.
target_sources(integration_tests PRIVATE
        ${CMAKE_SOURCE_DIR}/tooling/fuzzer/src/fuzz_transport_connection.cpp
        ${CMAKE_SOURCE_DIR}/tooling/fuzzer/src/fuzz_security_policy.cpp
        ${CMAKE_SOURCE_DIR}/tooling/fuzzer/include/misbehaving_server.h
        ${CMAKE_SOURCE_DIR}/tooling/fuzzer/src/misbehaving_server.cpp
)

# The certificate-structure vectors carry the fixed test-vector CA's private key, so the public
# snapshot withholds that one file: the specimens it signs are pinned DER and the key cannot be
# generated at run time. Only the two tests that need the key live there, so everything else
# built on the same fixture ships. The guard is on the file rather than on an option, for the
# same reason the private development projects are guarded that way: a published tree must not
# fail for want of a file it was never given, and a development checkout must not need a flag to
# remember to compile one it has.
if (EXISTS "${CMAKE_CURRENT_LIST_DIR}/role_based_certificate_vector_tests.cpp")
    target_sources(integration_tests PRIVATE role_based_certificate_vector_tests.cpp)
endif ()

# The compliance_test_server's own address-space seed, run in-process. The server is a private
# development project, so the same file guard applies: a published tree has no seed to test.
set(_compliance_server_dir "${_uasdk_private_dir}/projects/compliance_test_server")
if (EXISTS "${_compliance_server_dir}/address_space_seed.cpp")
    target_sources(integration_tests PRIVATE
            compliance_seed_access_tests.cpp
            compliance_seed_coverage_tests.cpp
            compliance_user_token_trust_tests.cpp
            compliance_node_management_delegate_tests.cpp
            ${_compliance_server_dir}/address_space_seed.cpp
            ${_compliance_server_dir}/address_space_seed.h
            ${_compliance_server_dir}/authenticators.cpp
            ${_compliance_server_dir}/authenticators.h
            ${_compliance_server_dir}/node_management_delegate.cpp
            ${_compliance_server_dir}/node_management_delegate.h
            ${_compliance_server_dir}/server_setup.cpp
            ${_compliance_server_dir}/server_setup.h)
    target_include_directories(integration_tests PRIVATE ${_compliance_server_dir})
    target_compile_definitions(integration_tests PRIVATE
            COMPLIANCE_SERVER_RUNTIME_DIR="${_compliance_server_dir}/runtime")
endif ()
