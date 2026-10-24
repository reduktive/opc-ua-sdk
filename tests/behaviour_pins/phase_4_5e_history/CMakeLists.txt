# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        fake_history_delegate.h
        fake_history_delegate.cpp
        history_read_pin_test.cpp
        history_update_pin_test.cpp
        strand_dispatch_pin_test.cpp
)

target_include_directories(tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
