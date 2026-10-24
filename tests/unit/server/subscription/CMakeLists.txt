# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        access_recheck_flow_tests.cpp
        create_delete_monitored_items_tests.cpp
        create_flow_tests.cpp
        create_flow_range_tests.cpp
        event_type_flow_tests.cpp
        monitored_item_access_control_tests.cpp
        subscription_router_interval_tests.cpp
        monitored_item_services_tests.cpp
        monitored_item_tests.cpp
        monitored_item_factory_tests.cpp
        namespace_monitoring_tests.cpp
        orphaned_subscription_store_tests.cpp
        percent_deadband_tests.cpp
        variable_type_value_monitoring_tests.cpp
        monitoring_helper_behaviour_tests.cpp
        monitoring_helper_tests.cpp
        monitoring_helper_range_tests.cpp
        monitoring_report_order_tests.cpp
        write_fed_delivery_tests.cpp
        monitoring_release_tests.cpp
        monitoring_release_api_tests.cpp
        monitoring_status_routing_tests.cpp
        monitoring_route_tests.cpp
        node_accessor_route_monitoring_tests.cpp
        sampled_caller_tests.cpp
        sampling_flow_tests.cpp
        sampling_engine_reader_tests.cpp
        publish_flow_tests.cpp
        sampling_engine_tests.cpp
        sampling_engine_stress_tests.cpp
        subscriptions_pipeline_tests.cpp
        subscription_tests.cpp
        structure_changed_sink_tests.cpp
        transfer_subscriptions_tests.cpp
)
