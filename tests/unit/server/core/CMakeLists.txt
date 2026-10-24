# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        history_server_capabilities_tests.cpp
        reverse_connect_listener_tests.cpp
        server_capabilities_tests.cpp
        server_max_connections_tests.cpp
        server_listener_endpoints_tests.cpp
        server_start_single_threaded_executor_tests.cpp
        server_event_handler_tests.cpp
        server_diagnostics_tests.cpp
        server_throttling_tests.cpp
        discovery_throttling_tests.cpp
        create_session_endpoint_url_validation_tests.cpp
        configuration_tests.cpp
        server_configuration_defaults_tests.cpp
        embedded_server_profile_tests.cpp
        advertised_profile_consistency_tests.cpp
        server_shutdown_tests.cpp
        server_application_uri_tests.cpp
        crypto_provider_required_tests.cpp
        server_shutdown_safety_tests.cpp
        server_async_surface_catalogue_tests.cpp
        fire_and_forget_scanner_tests.cpp
)
