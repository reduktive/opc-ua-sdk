# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

# Fuzz campaign GTest wrappers.
# Separate executable so fuzzer source changes don't trigger a full tests rebuild.

add_executable(fuzzer_tests
    fuzz_campaign_tests.cpp
    fuzz_security_policy_tests.cpp

    # Fuzzer sources needed by the tests.
    ${CMAKE_SOURCE_DIR}/tooling/fuzzer/src/fuzz_types.cpp
    ${CMAKE_SOURCE_DIR}/tooling/fuzzer/src/fuzzer_config.cpp
    ${CMAKE_SOURCE_DIR}/tooling/fuzzer/src/reporter.cpp
    ${CMAKE_SOURCE_DIR}/tooling/fuzzer/src/monitor.cpp
    ${CMAKE_SOURCE_DIR}/tooling/fuzzer/src/mutation_engine.cpp
    ${CMAKE_SOURCE_DIR}/tooling/fuzzer/src/input_generators.cpp
    ${CMAKE_SOURCE_DIR}/tooling/fuzzer/src/service_layer_harness.cpp
    ${CMAKE_SOURCE_DIR}/tooling/fuzzer/src/liveness_watchdog.cpp
    ${CMAKE_SOURCE_DIR}/tooling/fuzzer/src/message_layer_harness.cpp
    ${CMAKE_SOURCE_DIR}/tooling/fuzzer/src/fuzz_security_policy.cpp
    ${CMAKE_SOURCE_DIR}/tooling/fuzzer/src/fuzz_transport_connection.cpp
    ${CMAKE_SOURCE_DIR}/tooling/fuzzer/src/transport_layer_harness.cpp
    ${CMAKE_SOURCE_DIR}/tooling/fuzzer/src/channel_layer_harness.cpp
    ${CMAKE_SOURCE_DIR}/tooling/fuzzer/src/raw_tcp_harness.cpp
    ${CMAKE_SOURCE_DIR}/tooling/fuzzer/src/baseline.cpp
    ${CMAKE_SOURCE_DIR}/tooling/fuzzer/src/campaign.cpp
)

set_property(TARGET fuzzer_tests PROPERTY CXX_STANDARD 20)

target_link_libraries(fuzzer_tests PRIVATE test_infra uasdk::uasdk GTest::gtest)

target_include_directories(fuzzer_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/tooling/fuzzer/include
    # Same implementation headers needed by the fuzzer.
    ${CMAKE_SOURCE_DIR}/sdk/implementation/core/general
    ${CMAKE_SOURCE_DIR}/sdk/implementation/core/security
    ${CMAKE_SOURCE_DIR}/sdk/implementation/core/security/openssl
)

find_package(Boost CONFIG REQUIRED COMPONENTS json)
target_link_libraries(fuzzer_tests PRIVATE Boost::json)

add_custom_command(
    TARGET fuzzer_tests POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    ${CMAKE_BINARY_DIR}/_deps/uanodeset-src/Schema/Opc.Ua.NodeSet2.xml
    ${CMAKE_CURRENT_BINARY_DIR}/../NodeSet2.xml)

include(GoogleTest)
# DISCOVERY_TIMEOUT 180: gtest_discover_tests runs the freshly-built exe POST_BUILD
# (--gtest_list_tests) while the rest of the parallel build is still compiling. On the
# CPU-starved Windows runner the large exe can take >5s (the default) just to start and
# list, failing the build with "Process terminated due to timeout". Build-time only; no
# runtime effect.
gtest_discover_tests(fuzzer_tests DISCOVERY_TIMEOUT 180)
uasdk_add_test_report(fuzzer_tests)
