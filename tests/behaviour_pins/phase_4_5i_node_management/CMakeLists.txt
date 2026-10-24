# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        fake_node_management_delegate.cpp
        fake_node_management_delegate.h
        node_management_pin_fixture.h
        add_nodes_pin_test.cpp
        add_references_pin_test.cpp
        delete_nodes_pin_test.cpp
        delete_references_pin_test.cpp
        strand_dispatch_pin_test.cpp
)

target_include_directories(tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
