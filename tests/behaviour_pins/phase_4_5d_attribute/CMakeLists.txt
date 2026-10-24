# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        attribute_service_pin_fixture.h
        attribute_service_pin_fixture.cpp
        read_service_pin_test.cpp
        write_service_pin_test.cpp
)

target_include_directories(tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
