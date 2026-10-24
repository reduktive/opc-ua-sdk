# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

find_package(Boost CONFIG REQUIRED COMPONENTS json)

add_executable(opcua-fuzzer
    src/main.cpp
    src/fuzz_types.cpp
    src/fuzzer_config.cpp
    src/reporter.cpp
    src/monitor.cpp
    src/mutation_engine.cpp
    src/input_generators.cpp
    src/liveness_watchdog.cpp
    src/service_layer_harness.cpp
    src/message_layer_harness.cpp
    src/fuzz_security_policy.cpp
    src/fuzz_transport_connection.cpp
    src/transport_layer_harness.cpp
    src/channel_layer_harness.cpp
    src/raw_tcp_harness.cpp
    src/baseline.cpp
    src/campaign.cpp
    src/perf_tester.cpp
)

set_property(TARGET opcua-fuzzer PROPERTY CXX_STANDARD 20)

target_include_directories(opcua-fuzzer PRIVATE
    include
    # Needed for FuzzSecurityPolicy - ua_security_policy.h transitively includes
    # implementation-private headers. This is a pre-existing SDK issue; the fuzzer
    # is an internal tool so we work around it here.
    ${CMAKE_SOURCE_DIR}/sdk/implementation/core/general
    ${CMAKE_SOURCE_DIR}/sdk/implementation/core/security
    ${CMAKE_SOURCE_DIR}/sdk/implementation/core/security/openssl
    ${CMAKE_SOURCE_DIR}/sdk/implementation/client
)

target_link_libraries(opcua-fuzzer PRIVATE uasdk::uasdk uasdk::internal Boost::boost Boost::json)

# Coverage-guided libFuzzer decode targets (Phase 2). Clang-only; gated by
# ENABLE_LIBFUZZER (see the top-level CMakeLists). BUILD_FUZZER is already ON here.
# Guarded on the directory, not on the option: the coverage-guided drivers and their binary
# corpus are withheld from the public snapshot, and a tree that does not carry them must
# report that plainly rather than fail inside add_subdirectory on a path it never had.
if (ENABLE_LIBFUZZER AND EXISTS "${CMAKE_CURRENT_LIST_DIR}/libfuzzer/CMakeLists.txt")
    add_subdirectory(libfuzzer)
endif ()
