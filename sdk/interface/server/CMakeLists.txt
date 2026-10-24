# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-server PUBLIC ua_server.h ua_listen_options.h
        ua_server_observer.h
        ua_server_configuration.h
        ua_reverse_connect_handle.h
        ua_server_config_bundle.h
        ua_server_components.h
        ua_server_endpoint_configuration.h
        ua_server_health.h
        ua_session_security.h)

target_include_directories(uasdk-server PUBLIC .)

add_subdirectory(conditions)
add_subdirectory(helpers)
add_subdirectory(security)
add_subdirectory(services)
