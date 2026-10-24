# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        open_continuation_point_tracker_tests.cpp
        connect_plan_tests.cpp
        real_connection_establisher_tests.cpp
        pending_request_queue_tests.cpp
        connection_dispatch_tests.cpp
        connection_ops_shim_tests.cpp
        keep_alive_tracker_tests.cpp
        connection_impl_tests.cpp
        connection_subscription_factory_tests.cpp
        subscription_tuning_wiring_tests.cpp
        service_set_tests.cpp
        connection_facade_tests.cpp
        namespace_remap_comparison_tests.cpp
        connection_redundancy_wiring_tests.cpp
        connection_cert_revalidate_tests.cpp
        event_router_connection_event_backbone_ops_tests.cpp
        connection_type_resolver_seeding_tests.cpp
        connection_address_space_cache_wiring_tests.cpp
        typed_access_tests.cpp
        connection_status_routing_tests.cpp
        value_shape_validation_tests.cpp
        numeric_range_builder_tests.cpp
        numeric_range_validation_tests.cpp
        typed_access_reify_tests.cpp
        read_write_index_range_forwarding_tests.cpp
        fake_session_ops.h
)
