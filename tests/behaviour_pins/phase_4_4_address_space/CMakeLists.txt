# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        address_space_surface_pin_test.cpp
        file_helper_pin_test.cpp
        instance_utils_pin_test.cpp
        instantiation_pin_test.cpp
        monitoring_pin_test.cpp
        namespace_virtuals_pin_test.cpp
        nodeset_importer_pin_test.cpp
        strand_dispatch_pin_test.cpp
        typed_accessors_pin_test.cpp
        fake_async_namespace.cpp
        fake_async_namespace.h
        fake_node.cpp
        fake_node.h
)

target_include_directories(tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
