# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        pin_certificate_store.h
        find_servers_pin_test.cpp
        find_servers_on_network_pin_test.cpp
        get_endpoints_pin_test.cpp
)

target_include_directories(tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
