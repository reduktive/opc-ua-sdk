# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-client PUBLIC
  ua_client.h
  ua_core_client.h
  ua_client_observers.h
  ua_alarm_condition_tracker.h
  ua_address_space_cache_policy.h
  ua_client_diagnostic_policy.h
  ua_translated_node_id.h
  ua_type_resolution_policy.h
  ua_browse_cursor.h
  ua_continuation_limits.h
  ua_client_config_bundle.h
  ua_client_components.h
  ua_client_configuration.h
  ua_client_secure_channel.h
  ua_client_session.h
  ua_connection.h
  ua_connection_config.h
  ua_connection_state.h
  ua_data_access.h
  ua_discovery.h
  ua_easy_connect_policy.h
  ua_event_subscriber.h
  ua_file_transfer_client.h
  ua_history_facade.h
  ua_history_read_cursor.h
  ua_mdns_transport.h
  ua_client_monitored_item.h
  ua_client_subscription.h
  ua_namespace_table.h
  ua_numeric_range_builder.h
  ua_server_table.h
  ua_property_accessor.h
  ua_pull_certificate_manager.h
  ua_server_diagnostics_access.h
  ua_service_set.h
  ua_subscriptions.h
  ua_subscription_fallback_policy.h
  ua_reconnect_policy.h
  ua_reconnect_types.h
  ua_reverse_connect_config.h
  ua_session_attribute_services.h
  ua_session_discovery_services.h
  ua_session_method_services.h
  ua_session_monitored_item_services.h
  ua_session_node_management_services.h
  ua_session_query_services.h
  ua_session_subscription_services.h
  ua_session_view_services.h
  ua_session_model_access.h
  ua_state_machine_access.h
  ua_typed_access.h
  ua_user_identity.h
)

target_include_directories(uasdk-client PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
