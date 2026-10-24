# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIR})

# Static-analysis gate: ErrorDetail prose must be string literals (facts go to
# context keys). Baseline-ratcheted - passes today against the grandfathered
# set and fails on any NEW violation; the baseline shrinks as sites are swept.
# The guard is on the SCRIPT, not on the interpreter. A tree that does not carry the checker cannot
# run this gate and correctly registers nothing; a tree that carries it and has no Python3 must fail
# the configure, because the alternative is a gate that registers no test, runs nothing and reports
# success - alive, and proving nothing.
set(_uasdk_prose_checker "${UASDK_EVIDENCE_PRIVATE_ROOT}/tooling/static_analysis/check_error_detail_prose.py")
if (EXISTS "${_uasdk_prose_checker}")
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_test(
            NAME error_detail_prose_gate
            COMMAND ${Python3_EXECUTABLE}
                    "${_uasdk_prose_checker}"
                    --root ${PROJECT_SOURCE_DIR}/sdk
                    --baseline "${UASDK_EVIDENCE_PRIVATE_ROOT}/tooling/static_analysis/error_detail_prose_baseline.txt")
endif ()

# Configure-time compiler floor (cmake/UaCompilerFloor.cmake): the refusal is itself tested, by
# driving the check with injected compiler identities in script mode. Pure CMake; no build needed.
add_test(
        NAME compiler_floor_gate
        COMMAND ${CMAKE_COMMAND} -P "${PROJECT_SOURCE_DIR}/cmake/UaCompilerFloorTest.cmake")

# Shared test infrastructure (helpers, utilities) used by all test targets.
add_library(test_infra OBJECT
        test_main.cpp
        test_utilities.cpp
        test_utilities.h
        stubs.h
        helpers/ua_test_server.cpp helpers/ua_test_server.h
        helpers/test_components.cpp helpers/test_components.h
        helpers/fake_async_crypto.cpp helpers/fake_async_crypto.h
        helpers/fake_async_security_policy.cpp helpers/fake_async_security_policy.h
        helpers/fake_certificate_store.h
        helpers/fake_connection_ops.h
        helpers/fake_discovery_dependencies.h
        helpers/fake_pull_cert_manager_host.h
        helpers/fake_redundancy_manager_host.h
        helpers/fake_namespace.cpp helpers/fake_namespace.h
        helpers/stub_x509_certificate.h
        helpers/fake_transport_connection.cpp helpers/fake_transport_connection.h
        helpers/fake_connection_protocol_deps.cpp helpers/fake_connection_protocol_deps.h
        helpers/async_test_runtime.h
        helpers/access_control_test_support.h
        helpers/channel_bound_signature_test_data.h
        helpers/counting_executor.h
        helpers/run_async_sync.h
        helpers/server_test_access.h
        helpers/server_chunk_forge.cpp helpers/server_chunk_forge.h
        helpers/server_async_surface_catalogue.h
        helpers/fire_and_forget_scanner.h
        helpers/mutable_claim_authenticator.h
        helpers/strand_test_access_base.h
        helpers/deferred_namespace.cpp helpers/deferred_namespace.h
        helpers/posting_writes_namespace.cpp helpers/posting_writes_namespace.h
        helpers/scripted_referrer_namespace.cpp helpers/scripted_referrer_namespace.h
        helpers/monitoring_recording_namespace.cpp helpers/monitoring_recording_namespace.h
        helpers/register_nodes_recording_namespace.cpp helpers/register_nodes_recording_namespace.h
        helpers/batch_recording_namespace.cpp helpers/batch_recording_namespace.h
        helpers/every_node_in_view_namespace.cpp helpers/every_node_in_view_namespace.h
        helpers/per_item_join.h
        helpers/offloading_node_management_delegate.h
        helpers/namespace_registration_coordinator_test_access.h
        helpers/node_value_reader.h
        helpers/test_log_sink.cpp helpers/test_log_sink.h
        helpers/test_key_cache.cpp helpers/test_key_cache.h
        helpers/test_certificate_rewrite.cpp helpers/test_certificate_rewrite.h
)

set_property(TARGET test_infra PROPERTY CXX_STANDARD 20)
target_link_libraries(test_infra PUBLIC uasdk::uasdk uasdk::internal GTest::gtest)
# The test helpers and the security tests call OpenSSL in their own right (the key cache, the independent
# wire oracles), so they link it in their own right. Through uasdk it arrives only as a LINK_ONLY dependency,
# which carries no include directory, and the tests would compile against whatever OpenSSL headers the host
# has instead of the version the SDK was built with.
find_package(OpenSSL 1.1.1 REQUIRED)
target_link_libraries(test_infra PUBLIC OpenSSL::Crypto)
# test_main.cpp writes a JUnit report for every whole-suite run so that the traceability corpus can
# tell "a test exists" from "a test ran and passed" (qa_remediation_plan.md R8). The directory is
# fixed at compile time rather than passed at each call site because the callers are CI jobs, the shard runner
# and developers, none of which should have to know about it; UA_TEST_REPORT_DIR overrides it and
# UA_TEST_REPORT=0 turns it off.
#
if (ENABLE_CODE_COVERAGE)
    # Coverage-instrumented handlers are materially slower. This PUBLIC definition intentionally matches
    # the test_infra PCH producer and both consumers, and selects a longer finite teardown watchdog.
    target_compile_definitions(test_infra PUBLIC UASDK_COVERAGE_INSTRUMENTED_TESTS=1)
endif ()

if (ENABLE_TSAN)
    # TSan instrumentation needs the same finite extended teardown watchdog as gcov-instrumented tests.
    target_compile_definitions(test_infra PUBLIC UASDK_TSAN_INSTRUMENTED_TESTS=1)
endif ()

if (ENABLE_ASAN)
    # ASan instrumentation is slower than an ordinary Debug build for the same reason gcov and TSan are,
    # and the sanitizer job fans the integration suite out across more shards than any other job. Without
    # this the ASan run is the ONLY instrumented mode left on the ordinary 5 s watchdog, and legitimate
    # final handlers miss it under load - reported as a teardown leak that does not exist.
    target_compile_definitions(test_infra PUBLIC UASDK_ASAN_INSTRUMENTED_TESTS=1)
endif ()

# PUBLIC, and only one source uses it. `tests` and `integration_tests` REUSE_FROM this target's
# precompiled header, and GCC rejects a PCH whose macro set differs from the consuming TU's
# ("not used because `X' not defined"), silently reverting every test TU to parsing the full header
# set. A PRIVATE define here would therefore cost the whole suite's PCH for one string.
target_compile_definitions(test_infra PUBLIC
        UASDK_TEST_REPORT_DIR="${UASDK_TEST_REPORT_DIR}")
if (MSVC)
    # Match the /bigobj on tests/integration_tests: test_infra is the PCH producer
    # those two REUSE_FROM, and MSVC requires the producer's flags to match.
    target_compile_options(test_infra PRIVATE /bigobj)
endif ()

target_include_directories(test_infra
        PUBLIC
        .
        helpers
        # Implementation directories (PRIVATE to sdk, but needed by tests for internal headers)
        ../sdk/implementation/address_space
        ../sdk/implementation/address_space/implementations/default
        ../sdk/implementation/address_space/nodeset_tools
        ../sdk/implementation/core/codecs
        ../sdk/implementation/core/general
        ../sdk/implementation/core/transport
        ../sdk/implementation/core/security
        ../sdk/implementation/core/security/openssl
        ../sdk/implementation/server
        ../sdk/implementation/server/core
        ../sdk/implementation/server/secure_channel
        ../sdk/implementation/server/services
        ../sdk/implementation/server/services/aggregates
        ../sdk/implementation/server/session
        ../sdk/implementation/server/subscription
        ../sdk/implementation/server/events
        ../sdk/implementation/server/conditions
        ../sdk/implementation/server/security
        ../sdk/implementation/client
        ../sdk/implementation/client/secure_channel
)

# --- Unit tests (fast, isolated, no real I/O) ---
add_executable(tests)
set(_uasdk_unit_test_targets tests)
# The fully instrumented unit executable exceeds GCC startup objects' 32-bit relocation range.
# Keep the existing client subtree in another executable for this configuration. Both executables
# retain the same test infrastructure and instrumentation and are run by the ASan CI job.
if (ENABLE_ASAN AND UASDK_BUILD_SHARED)
    add_executable(client_unit_tests)
    list(APPEND _uasdk_unit_test_targets client_unit_tests)
endif ()
# `configuration_tests.cpp` includes <boost/json.hpp> and calls boost::json::parse directly, so
# this target uses Boost.JSON in its own right and must link it in its own right. The SDK links
# Boost::json through `uasdk-build-private`, which reaches consumers only when uasdk is STATIC:
# CMake carries a static library's private dependencies into its link interface because the final
# link still needs them, and correctly drops them for a shared one. Every job but
# `sanitizer / gcc14-asan` builds static, so the missing link was invisible - and ASan had not
# reached its link step since July, so nothing reported it either.
find_package(Boost CONFIG REQUIRED COMPONENTS json)
foreach (_target IN LISTS _uasdk_unit_test_targets)
    set_property(TARGET ${_target} PROPERTY CXX_STANDARD 20)
    if (MSVC)
        target_compile_options(${_target} PRIVATE /bigobj)
    endif ()
    target_link_libraries(${_target} PUBLIC test_infra uasdk::uasdk GTest::gtest)
    target_link_libraries(${_target} PRIVATE Boost::json)
    target_include_directories(${_target} PUBLIC $<TARGET_PROPERTY:test_infra,INTERFACE_INCLUDE_DIRECTORIES>)
    target_compile_definitions(${_target} PRIVATE UASDK_TEST_RELEASE_VERSION="${UASDK_RELEASE_VERSION}")
endforeach ()
# The absolute tests/ source directory, from which the structure tests walk up to the checkout's root
# marker. __FILE__ cannot anchor that walk: it is relative to the build directory when the build tree sits
# inside the checkout, and the sharded runner starts each shard in a directory of its own. Set on those
# files only, so the rest of the target keeps its compile command (and its ccache entries).
set_source_files_properties(
        unit/server/core/server_async_surface_catalogue_tests.cpp
        unit/server/events/audit_event_emitter_tests.cpp
        unit/server/session/client_signature_verification_tests.cpp
        PROPERTIES COMPILE_DEFINITIONS "UASDK_TEST_SOURCE_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}\"")
if (UASDK_RENDERED_CAPACITY_MANIFEST)
    foreach (_target IN LISTS _uasdk_unit_test_targets)
        add_custom_command(
                TARGET ${_target} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${UASDK_RENDERED_CAPACITY_MANIFEST}"
                "$<TARGET_FILE_DIR:${_target}>/standard_client_2025_capacities.md")
    endforeach ()
endif ()

set(_generated_test_sources
        ../sdk/implementation/core/generated/ua/data_types/generated_data_type_tests.cpp
        ../sdk/implementation/address_space/generated/ua/generated_instance_type_tests.cpp
        ../sdk/implementation/address_space/generated/ua/event_types/generated_event_type_tests.cpp
)
foreach(_src ${_generated_test_sources})
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${_src}")
        target_sources(tests PRIVATE ${_src})
    endif()
endforeach()

add_subdirectory(unit)

# NR-13a's proof: a global allocation counter replaces operator new for every test in its binary, so it has a
# binary of its own.
add_executable(value_source_allocation_tests allocation/value_source_allocation_tests.cpp)
set_property(TARGET value_source_allocation_tests PROPERTY CXX_STANDARD 20)
target_link_libraries(value_source_allocation_tests PRIVATE test_infra uasdk::uasdk GTest::gtest)
add_test(NAME value_source_allocation_tests COMMAND value_source_allocation_tests)

foreach (_target IN LISTS _uasdk_unit_test_targets)
    add_custom_command(
            TARGET ${_target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_BINARY_DIR}/_deps/uanodeset-src/Schema/Opc.Ua.NodeSet2.xml
            ${CMAKE_CURRENT_BINARY_DIR}/NodeSet2.xml)

    add_custom_command(
            TARGET ${_target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_SOURCE_DIR}/resources/MultiNamespaceFixture.NodeSet2.xml
            ${CMAKE_CURRENT_BINARY_DIR}/MultiNamespaceFixture.NodeSet2.xml)

    add_custom_command(
            TARGET ${_target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_SOURCE_DIR}/resources/MultiTranslationFixture.NodeSet2.xml
            ${CMAKE_CURRENT_BINARY_DIR}/MultiTranslationFixture.NodeSet2.xml)

    add_custom_command(
            TARGET ${_target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_SOURCE_DIR}/resources/StructValueTranslationFixture.NodeSet2.xml
            ${CMAKE_CURRENT_BINARY_DIR}/StructValueTranslationFixture.NodeSet2.xml)

    add_custom_command(
            TARGET ${_target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_SOURCE_DIR}/resources/RolePermissionTranslationFixture.NodeSet2.xml
            ${CMAKE_CURRENT_BINARY_DIR}/RolePermissionTranslationFixture.NodeSet2.xml)

    add_custom_command(
            TARGET ${_target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_SOURCE_DIR}/resources/BadNamespaceIndexFixture.NodeSet2.xml
            ${CMAKE_CURRENT_BINARY_DIR}/BadNamespaceIndexFixture.NodeSet2.xml)

    add_custom_command(
            TARGET ${_target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_SOURCE_DIR}/resources/TypeDefinitionReferencesFixture.NodeSet2.xml
            ${CMAKE_CURRENT_BINARY_DIR}/TypeDefinitionReferencesFixture.NodeSet2.xml)

    add_custom_command(
            TARGET ${_target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_SOURCE_DIR}/resources/StateMachineGeneratesEventFixture.NodeSet2.xml
            ${CMAKE_CURRENT_BINARY_DIR}/StateMachineGeneratesEventFixture.NodeSet2.xml)

    add_custom_command(
            TARGET ${_target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_SOURCE_DIR}/resources/DataTypePropertyFixture.NodeSet2.xml
            ${CMAKE_CURRENT_BINARY_DIR}/DataTypePropertyFixture.NodeSet2.xml)

    add_custom_command(
            TARGET ${_target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_SOURCE_DIR}/resources/NamespaceSubsetFixture.NodeSet2.xml
            ${CMAKE_CURRENT_BINARY_DIR}/NamespaceSubsetFixture.NodeSet2.xml)

    add_custom_command(
            TARGET ${_target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_SOURCE_DIR}/resources/AggregateExamples.csv
            ${CMAKE_CURRENT_BINARY_DIR}/AggregateExamples.csv)
endforeach ()

include(GoogleTest)
# A published tree has no internal/, so the tests listed in development_only_tests.txt cannot pass
# there; ctest leaves them out instead of reporting them as failures. TEST_FILTER needs CMake 3.22.
# The project's minimum stays 3.21, because raising it would also change the CMP0128 language-
# standard flags for every consumer; under 3.21 a published tree registers them as before.
set(_uasdk_test_filter "")
if (NOT _uasdk_private_tree AND CMAKE_VERSION VERSION_GREATER_EQUAL 3.22)
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/development_only_tests.txt" _uasdk_development_only_tests
         REGEX "^[^#]")
    list(JOIN _uasdk_development_only_tests ":" _uasdk_development_only_tests)
    set(_uasdk_test_filter TEST_FILTER "-${_uasdk_development_only_tests}")
endif ()

# DISCOVERY_TIMEOUT 180: post-build --gtest_list_tests can exceed the 5s default on the
# CPU-starved Windows runner while the parallel build is still compiling. Build-time only.
foreach (_target IN LISTS _uasdk_unit_test_targets)
    gtest_discover_tests(${_target} DISCOVERY_TIMEOUT 180 ${_uasdk_test_filter})
    uasdk_add_test_report(${_target})
endforeach ()

# --- Integration tests (slower, real TCP/crypto/multi-component) ---
add_executable(integration_tests)
set_property(TARGET integration_tests PROPERTY CXX_STANDARD 20)
if(MSVC)
    target_compile_options(integration_tests PRIVATE /bigobj)
endif()
target_link_libraries(integration_tests PUBLIC test_infra uasdk::uasdk GTest::gtest GTest::gmock)
target_include_directories(integration_tests PUBLIC $<TARGET_PROPERTY:test_infra,INTERFACE_INCLUDE_DIRECTORIES>)
target_compile_definitions(
        integration_tests PRIVATE UASDK_TEST_SOURCE_REVISION="${UASDK_SOURCE_REVISION}")

# Precompiled headers: test_infra compiles the PCH; both test executables REUSE_FROM
# it. All three share C++20 + the Boost/fmt include dirs (via `sdk`), so the heavy
# third-party/std headers in cmake/uasdk_pch.h are parsed once and reused across the
# thousands of test TUs. Applies to all sources added by the unit/integration/
# behaviour-pin subdirectories below (PCH is a target property resolved at generate).
if (UASDK_USE_PCH)
    # test_infra is a static library, so CMAKE_POSITION_INDEPENDENT_CODE (set under hardening in
    # RelWithDebInfo/Release) compiles its PCH with -fPIC, while the executables that REUSE_FROM it get
    # -fPIE per target type (CMP0083). Clang bakes the PIE level into the PCH and rejects the mismatch
    # ("is pie differs in PCH file vs current file"); GCC tolerates it. test_infra is linked only into
    # these PIE test executables, so compiling it -fPIE realigns the PCH without weakening anything. The
    # guard is essential: without hardening there is no PIC/PIE split, so an unconditional -fPIE would
    # itself desync the PCH.
    if (UASDK_ENABLE_HARDENING AND (CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang"))
        target_compile_options(test_infra PRIVATE -fPIE)
    endif ()
    target_precompile_headers(test_infra PRIVATE "${PROJECT_SOURCE_DIR}/cmake/uasdk_pch.h")
    foreach (_target IN LISTS _uasdk_unit_test_targets)
        target_precompile_headers(${_target} REUSE_FROM test_infra)
    endforeach ()
    target_precompile_headers(integration_tests REUSE_FROM test_infra)
endif ()

add_subdirectory(integration)

if (UASDK_RENDERED_CAPACITY_MANIFEST)
    add_custom_command(
            TARGET integration_tests POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${UASDK_RENDERED_CAPACITY_MANIFEST}"
            "$<TARGET_FILE_DIR:integration_tests>/standard_client_2025_capacities.md")
endif ()

add_custom_command(
        TARGET integration_tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_BINARY_DIR}/_deps/uanodeset-src/Schema/Opc.Ua.NodeSet2.xml
        ${CMAKE_CURRENT_BINARY_DIR}/NodeSet2.xml)

# The official GDS NodeSet, imported at runtime by the GDS emulator (tests/integration/helpers/gds_emulator.h).
add_custom_command(
        TARGET integration_tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_BINARY_DIR}/_deps/uanodeset-src/GDS/Opc.Ua.Gds.NodeSet2.xml
        ${CMAKE_CURRENT_BINARY_DIR}/Opc.Ua.Gds.NodeSet2.xml)

add_custom_command(
        TARGET integration_tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/MultiNamespaceFixture.NodeSet2.xml
        ${CMAKE_CURRENT_BINARY_DIR}/MultiNamespaceFixture.NodeSet2.xml)

add_custom_command(
        TARGET integration_tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/RolePermissionTranslationFixture.NodeSet2.xml
        ${CMAKE_CURRENT_BINARY_DIR}/RolePermissionTranslationFixture.NodeSet2.xml)

gtest_discover_tests(integration_tests DISCOVERY_TIMEOUT 180 ${_uasdk_test_filter})
uasdk_add_test_report(integration_tests)

# --- Companion-spec (multi-nodeset) integration tests (Phase 7) ---
# Generates DI + PROFINET type libraries via ua_generate_types() and links
# them alongside sdk. Separate executable so the generated companion trees
# don't bloat the core integration binary.
add_subdirectory(integration/companion_spec)

# --- Codegen matrix (generate + compile EVERY companion spec; opt-in, nightly) ---
# Heavy allow-fail coverage dashboard over the whole UA-Nodeset checkout. Gated by
# UASDK_BUILD_CODEGEN_MATRIX (default OFF); see tests/codegen/. Added after
# companion_spec so a ua_*_types TU is present in compile_commands.json, from which
# the matrix harness lifts the real SDK compile flags.
if (UASDK_BUILD_CODEGEN_MATRIX)
    add_subdirectory(codegen)
endif ()

# --- Behaviour-pin corpus (historical migration spec; folded into `tests`). ---
add_subdirectory(behaviour_pins)

# --- Fuzz campaign tests (bounded fuzz runs as GTest, separate executable) ---
# Gated behind BUILD_FUZZER (default OFF) - heavy link, built/run only by the
# nightly sanitizer jobs. See BUILD_FUZZER in the root CMakeLists.
if (BUILD_FUZZER)
    add_subdirectory(fuzz)
endif ()
