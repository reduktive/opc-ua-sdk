# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        fake_secure_channel_dependencies.h
        fake_secure_channel_dependencies.cpp
        open_channel_failure_pin_test.cpp
        secure_channel_inflight_teardown_tests.cpp
        secure_channel_inflight_caps_tests.cpp
)

target_include_directories(tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
