# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        sequence_tracker_tests.cpp
        publish_pump_tests.cpp
        ack_queue_tests.cpp
        client_subscriptions_pipeline_tests.cpp
        client_handle_allocator_tests.cpp
        client_monitored_item_data_change_monitored_item_owner_tests.cpp
        subscription_tests.cpp
)

# subscription_tests.cpp reuses the FakeSessionOps tier-0 interface from the connection test dir.
target_include_directories(tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../connection)
