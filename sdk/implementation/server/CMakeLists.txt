# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-server PRIVATE
        ua_server_counters.h
        ua_request_latency_tracker.h
        ua_session_description.h
        ua_server_secure_channel_info.h
        ua_server_session_info.h
        ua_server_reverse_connect_listener.cpp
        ua_server_reverse_connect_listener.h
        ua_server.cpp
        ua_server_encoding_limits.h
        ua_embedded_server_profile.cpp
        ua_server_impl.cpp
        ua_server_endpoint_configuration.cpp
        ua_server_impl.h
        ua_server_model.cpp
        ua_server_model.h
        ua_anonymous_authenticator.cpp
        ua_simple_user_password_authenticator.cpp
        ua_composite_authenticator.cpp
        ua_x509_user_authenticator.cpp
        ua_role_configuration.cpp
        ua_role_permission_utils.cpp
        ua_role_set_population.cpp
        ua_role_set_population.h
        ua_namespace_metadata_publication.cpp
        ua_namespace_metadata_publication.h
        ua_role_method_handlers.cpp
        ua_role_method_handlers.h
        ua_session_security_state.cpp
        ua_subscription_id_allocator.h
)

uasdk_private_include_directory(uasdk-server)
add_subdirectory(core)
add_subdirectory(helpers)
add_subdirectory(secure_channel)
add_subdirectory(session)
add_subdirectory(services)
add_subdirectory(subscription)
add_subdirectory(events)
add_subdirectory(conditions)
add_subdirectory(security)
add_subdirectory(state_machine)
