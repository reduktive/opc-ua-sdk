# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
  client_session_capture_harness.h
  client_reconnection_tests.cpp
  client_session_impl_tests.cpp
  client_session_token_encryption_tests.cpp
  client_token_builder_tests.cpp
  real_session_ops_tests.cpp
  request_header_timestamp_tests.cpp
  session_attribute_services_tests.cpp
  session_model_access_tests.cpp
  session_discovery_services_tests.cpp
  session_method_services_tests.cpp
  session_monitored_item_services_tests.cpp
  session_node_management_services_tests.cpp
  session_query_services_tests.cpp
  session_service_guard_fixture.h
  session_subscription_services_tests.cpp
  session_view_services_tests.cpp
)
