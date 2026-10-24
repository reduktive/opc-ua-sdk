# SPDX-License-Identifier: 0BSD
# Copyright (c) 2026 Reduktive Limited.

# Public example programs for the Reduktive OPC UA SDK.
#
# Every example here is also buildable on its own, outside this tree, against an installed SDK
# package.
include("${CMAKE_CURRENT_SOURCE_DIR}/uasdk_example_test.cmake")

# The behaviour tests run each example and compare its whole normalised output to the golden file
# beside it. They register only in the SDK tree, where the harness lives, and only when
# UASDK_BUILD_EXAMPLE_TESTS asks for them.
#
# Python3 is REQUIRED rather than QUIET once the option is on. A missing interpreter has to fail the
# configure: the alternative is a build that registers no tests, runs none, and reports success -
# which is exactly how this gate can be alive and prove nothing.
if (UASDK_BUILD_EXAMPLE_TESTS)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    set(UASDK_EXAMPLE_TEST_RUNNER "${CMAKE_CURRENT_SOURCE_DIR}/../tooling/examples/run_example_test.py")
endif ()

add_subdirectory(support)

add_subdirectory(quickstart/roundtrip)
add_subdirectory(server/minimal)
add_subdirectory(server/address_space)
add_subdirectory(server/nodeset_and_methods)
add_subdirectory(server/events)
add_subdirectory(server/alarms)
add_subdirectory(server/authentication)
add_subdirectory(server/diagnostics)
add_subdirectory(server/file_transfer)
add_subdirectory(server/history)
add_subdirectory(server/reverse_connect)
add_subdirectory(server/custom_types)
add_subdirectory(server/data_access)
add_subdirectory(server/push_certificates)
add_subdirectory(client/minimal)
add_subdirectory(client/browse_and_call)
add_subdirectory(client/subscriptions)
add_subdirectory(client/events)
add_subdirectory(client/alarms)
add_subdirectory(client/reconnect_and_keepalive)
add_subdirectory(client/authentication)
add_subdirectory(client/discovery)
add_subdirectory(client/file_transfer)
add_subdirectory(client/history)
add_subdirectory(client/reverse_connect)
add_subdirectory(client/custom_types)
add_subdirectory(client/data_access)
add_subdirectory(client/push_certificates)

# The reference pair: two production-shaped applications that share one narrow PKI helper.
add_subdirectory(reference_common)
add_subdirectory(reference_server)
add_subdirectory(reference_client)
