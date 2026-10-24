# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        close_pin_test.cpp
        create_monitored_items_pin_test.cpp
        delete_monitored_items_pin_test.cpp
        dispatch_pin_test.cpp
        error_detail_pin_test.cpp
        fulfill_publish_pin_test.cpp
        modify_monitored_items_pin_test.cpp
        subscription_pin_test.cpp
        subscriptions_pipeline_pin_test.cpp
)

target_include_directories(tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
