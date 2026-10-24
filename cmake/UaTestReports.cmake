# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

# Execution evidence for the requirements corpus.
#
# A `@relation` marker proves a test *exists*. Only a JUnit report proves it *ran and passed*, and
# that is the distinction the corpus is built on: the traceability tooling reads
# `<repo>/build/test-reports/*.gtest.junit.xml` to make it. Nothing in the tree wrote there, so
# every coverage figure the corpus produced meant only that a marker existed, and the process had
# to carry an interim status to stay followable in the meantime.
#
# Two mechanisms, because they answer different questions:
#
#   * `tests/test_main.cpp` defaults the output path, so an *ordinary* whole-suite run - CI's, or a
#     developer's - leaves evidence behind without anyone remembering a flag. That is what makes the
#     evidence keep up with the tree rather than being a thing someone regenerates occasionally.
#   * `uasdk_add_test_report()` registers a suite with the `test-reports` target, which runs every
#     registered suite once and normalises the result. That is the reproducible way to regenerate
#     the whole evidence set in one command, and it is the only route for a suite that does not use
#     our own `main()` (`example_tests` links `GTest::gtest_main`).
#
# The report directory is a cache variable rather than a literal because three consumers already
# hardcode `build/test-reports`; `UA_TEST_REPORT_DIR` in the environment overrides it for all of
# them, so the location has one definition instead of four.

# Both of the private helpers below are optional, and a tree that lacks them still produces
# reports - it just produces plain ones. Naming that tree through one computed root rather than
# two literal paths is deliberate: a published tree does not carry it, and should not carry its
# layout either.
get_filename_component(_uasdk_evidence_private_root "${CMAKE_CURRENT_LIST_DIR}/../internal" ABSOLUTE)
set(UASDK_EVIDENCE_PRIVATE_ROOT "${_uasdk_evidence_private_root}" CACHE INTERNAL
    "Root of the private tree, when this is a development checkout")

set(UASDK_TEST_REPORT_DIR "${PROJECT_SOURCE_DIR}/build/test-reports" CACHE PATH
    "Directory the GoogleTest suites write their JUnit execution evidence into")

# The suites create it themselves (GoogleTest creates the output file's parents), but the corpus
# gate only passes `build/test-reports` to StrictDoc when the directory exists, so a configured tree
# that has not yet run a suite should still resolve the path.
file(MAKE_DIRECTORY "${UASDK_TEST_REPORT_DIR}")

find_package(Python3 QUIET COMPONENTS Interpreter)

# The aggregate. Its own command is the normalisation pass, which runs after every registered suite
# because `add_dependencies` orders them ahead of it: GoogleTest emits a `DISABLED_` case as
# `status="notrun"` with no `<skipped>` child, and StrictDoc's JUnit reader falls through to PASSED
# on anything without a `<failure>` or `<skipped>` - so an un-normalised report hands a disabled
# test to the corpus as passing execution evidence.
set(_uasdk_report_normaliser
    "${UASDK_EVIDENCE_PRIVATE_ROOT}/tooling/traceability/normalise_gtest_xml.py")
if (NOT EXISTS "${_uasdk_report_normaliser}")
    # No corpus in this tree, so nothing consumes the reports as evidence and there is nothing for
    # normalisation to protect against. The suites still write ordinary JUnit XML, which is what a
    # reader wants from `test-reports` anyway: a result file their own CI can ingest.
    add_custom_target(test-reports
        COMMENT "Test reports: ${UASDK_TEST_REPORT_DIR}"
        VERBATIM)
elseif (Python3_FOUND)
    add_custom_target(test-reports
        COMMAND ${Python3_EXECUTABLE} "${_uasdk_report_normaliser}" "${UASDK_TEST_REPORT_DIR}"
        COMMENT "Execution evidence: normalising ${UASDK_TEST_REPORT_DIR}"
        VERBATIM USES_TERMINAL)
else ()
    add_custom_target(test-reports
        COMMAND ${CMAKE_COMMAND} -E echo
                "test-reports: Python3 not found, reports are NOT normalised - a DISABLED_ test will read as passing"
        VERBATIM)
endif ()

# uasdk_add_test_report(<gtest target> [NO_DEFAULT_REPORT] [ARGS <extra gtest args>...])
#
# Registers <target> with the `test-reports` aggregate. The suite runs from its own output directory
# because every suite resolves its data files (NodeSet2.xml, the fixture NodeSets, the CSV) relative
# to the working directory.
#
# NO_DEFAULT_REPORT marks a suite that does not link tests/test_main.cpp - it has no report default
# of its own, so it must be handed `--gtest_output` and cannot be sharded (the shards would race for
# the one path).
#
# Registered suites run one after another rather than in parallel. They bind real TCP ports on
# ephemeral addresses and several are timing-sensitive under load; two suites racing each other is a
# flake source, and a flaky report is worse than a slow one because it becomes evidence.
function(uasdk_add_test_report target)
    cmake_parse_arguments(ARG "NO_DEFAULT_REPORT" "" "ARGS" ${ARGN})

    # The unit suite is ~25 CPU-minutes run serially and about two wall-clock minutes sharded, and a
    # regeneration command nobody is willing to wait for is not a mechanism. run_sharded_tests.sh
    # resolves its own shard count from the cgroup-clamped CPU budget, and each shard names its own
    # report from tests/test_main.cpp, so the slices compose in the directory the consumers glob.
    set(_shard_runner "${UASDK_EVIDENCE_PRIVATE_ROOT}/tooling/scripts/run_sharded_tests.sh")
    if (UNIX AND EXISTS "${_shard_runner}" AND NOT ARG_NO_DEFAULT_REPORT)
        set(_command "${_shard_runner}" $<TARGET_FILE:${target}> -- ${ARG_ARGS})
    else ()
        set(_command $<TARGET_FILE:${target}>
            --gtest_output=xml:${UASDK_TEST_REPORT_DIR}/${target}.gtest.junit.xml ${ARG_ARGS})
    endif ()

    # Through UaRunTestSuite.cmake so a red suite still yields its report and does not abort the
    # suites queued behind it - see that file for why the exit status is printed rather than
    # propagated.
    add_custom_target(test-report-${target}
        COMMAND ${CMAKE_COMMAND} -P "${PROJECT_SOURCE_DIR}/cmake/UaRunTestSuite.cmake"
                -- ${_command}
        WORKING_DIRECTORY $<TARGET_FILE_DIR:${target}>
        COMMENT "Execution evidence: running ${target}"
        VERBATIM USES_TERMINAL)
    # add_dependencies, not add_custom_target(DEPENDS): the latter takes files and outputs of
    # add_custom_command, so naming a target there builds nothing and the report target would run an
    # executable that may not exist yet.
    add_dependencies(test-report-${target} ${target})

    get_property(_previous GLOBAL PROPERTY UASDK_LAST_TEST_REPORT_TARGET)
    if (_previous)
        add_dependencies(test-report-${target} ${_previous})
    endif ()
    set_property(GLOBAL PROPERTY UASDK_LAST_TEST_REPORT_TARGET test-report-${target})

    add_dependencies(test-reports test-report-${target})
endfunction()
