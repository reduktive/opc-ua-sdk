# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-client PRIVATE
  ua_client_session_impl.h
  ua_client_session_security_info.h
  ua_client_session_impl.cpp
  ua_client_session.cpp
  ua_client_session_test_access.h
  ua_client_token_builder.h
  ua_client_token_builder.cpp
  ua_session_service_helpers.h
  ua_session_attribute_services.cpp
  ua_session_discovery_services.cpp
  ua_session_method_services.cpp
  ua_session_monitored_item_services.cpp
  ua_session_node_management_services.cpp
  ua_session_query_services.cpp
  ua_session_subscription_services.cpp
  ua_session_view_services.cpp
)

uasdk_private_include_directory(uasdk-client)
