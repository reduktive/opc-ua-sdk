# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

# Reuse the existing attribute-scripted Node in the helper's item-local inspection tests.
target_include_directories(tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../address_space)

# Only this test source needs the existing private instantiation entry point.
set_property(SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/namespace_caller_lifetime_tests.cpp
        TARGET_DIRECTORY tests APPEND PROPERTY INCLUDE_DIRECTORIES
        ${PROJECT_SOURCE_DIR}/sdk/implementation/address_space/instantiation)

target_sources(tests PRIVATE
        batch_resolve_tests.cpp
        namespace_caller_lifetime_tests.cpp
        request_withdrawal_tests.cpp
        read_service_default_path_tests.cpp
        read_service_requirement_tests.cpp
        read_flow_tests.cpp
        write_service_tests.cpp
        write_flow_tests.cpp
        role_permissions_updates_tests.cpp
        data_access_projection_tests.cpp
        information_model_pairs_tests.cpp
        data_access_write_interceptor_unit_tests.cpp
        data_access_policy_alias_tests.cpp
        browse_service_tests.cpp
        resolution_round_trip_tests.cpp
        browse_flow_tests.cpp
        browse_partial_results_tests.cpp
        register_nodes_service_tests.cpp
        unregister_nodes_service_tests.cpp
        register_nodes_release_tests.cpp
        register_nodes_ownership_tests.cpp
        session_registered_nodes_tests.cpp
        operation_limits_service_tests.cpp
        service_authorization_tests.cpp
        per_item_access_control_tests.cpp
        node_management_service_tests.cpp
        security_level_tests.cpp
        history_read_service_tests.cpp
        history_update_service_tests.cpp
        history_flow_tests.cpp
        translate_browse_paths_tests.cpp
        translate_flow_tests.cpp
        status_routing_service_tests.cpp
        call_flow_tests.cpp
        method_argument_validation_tests.cpp
        option_set_merge_tests.cpp
        option_set_write_tests.cpp
        aggregate_primitives_tests.cpp
        aggregate_csv_oracle_tests.cpp
)

add_subdirectory(namespace_caller_allocation)
