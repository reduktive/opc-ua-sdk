# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        core_client_impl_tests.cpp
        easy_connect_tests.cpp
        browse_drain_guard_tests.cpp
        session_trust_store_tests.cpp
        client_connect_tests.cpp
        client_observer_sink_tests.cpp
        client_own_cert_validation_tests.cpp
        client_create_executor_precondition_tests.cpp
        client_security_policy_gate_tests.cpp
        server_cert_validator_tests.cpp
        client_test_hooks_tests.cpp
        client_registry_revalidate_tests.cpp
        reverse_connect_listener_tests.cpp
        standard_client_capacity_manifest_tests.cpp
        ua_client_encoding_limits_tests.cpp
)

# client_registry_revalidate_tests.cpp reuses the FakeSessionOps / FakeReopen tier-0 stubs that live in the
# connection/ test directory.
target_include_directories(tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/connection)

add_subdirectory(address_space_cache)
add_subdirectory(browse_cursor)
add_subdirectory(connection)
add_subdirectory(data_access)
add_subdirectory(diagnostics)
add_subdirectory(discovery)
add_subdirectory(events)
add_subdirectory(file)
add_subdirectory(history)
add_subdirectory(namespace_table)
add_subdirectory(observer)
add_subdirectory(pull_cert_management)
add_subdirectory(reconnect)
add_subdirectory(redundancy)
add_subdirectory(secure_channel)
add_subdirectory(semantic_change)
add_subdirectory(server_diagnostics)
add_subdirectory(server_table)
add_subdirectory(subscription)
add_subdirectory(session)
add_subdirectory(state_machine)
add_subdirectory(type_resolver)
