# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

# This replacement of global allocation belongs only to the private executable.
# The location proof requires Linux unwind support, addr2line and SDK debug symbols.
if (NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(WARNING "namespace_caller_allocation_tests skipped: it requires Linux; its criteria are not verified by this build")
    return()
endif ()
if (NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE MATCHES "^(Debug|RelWithDebInfo)$")
    message(WARNING "namespace_caller_allocation_tests skipped: it requires a debug-symbol build; its criteria are not verified by this build")
    return()
endif ()

find_program(UASDK_ALLOCATION_ADDR2LINE NAMES addr2line)
if (NOT UASDK_ALLOCATION_ADDR2LINE)
    message(WARNING "namespace_caller_allocation_tests skipped: addr2line not found; its criteria are not verified by this build")
    return()
endif ()
add_executable(namespace_caller_allocation_tests
        allocation_controller.cpp
        allocation_controller.h
        error_boundary_allocation_tests.cpp
        namespace_caller_allocation_tests.cpp)
set_target_properties(namespace_caller_allocation_tests PROPERTIES
        CXX_STANDARD 20
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
target_link_libraries(namespace_caller_allocation_tests PRIVATE test_infra ${CMAKE_DL_LIBS})
target_link_options(namespace_caller_allocation_tests PRIVATE "-Wl,--wrap=aligned_alloc")
target_include_directories(namespace_caller_allocation_tests PRIVATE
        "${PROJECT_SOURCE_DIR}/tests/unit/address_space"
        "${PROJECT_SOURCE_DIR}/sdk/implementation/client"
        "${PROJECT_SOURCE_DIR}/sdk/implementation/address_space/instantiation")
target_compile_definitions(namespace_caller_allocation_tests PRIVATE
        UASDK_ALLOCATION_ADDR2LINE="${UASDK_ALLOCATION_ADDR2LINE}")
target_compile_options(namespace_caller_allocation_tests PRIVATE -g)

gtest_discover_tests(namespace_caller_allocation_tests
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        DISCOVERY_TIMEOUT 180)
uasdk_add_test_report(namespace_caller_allocation_tests NO_DEFAULT_REPORT)
