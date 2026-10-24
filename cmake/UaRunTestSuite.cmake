# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

# Run one GoogleTest suite for its execution evidence, and do not fail on a failing test.
#
#   cmake -P UaRunTestSuite.cmake -- <command> [args...]
#
# Called only by the `test-report-*` targets in UaTestReports.cmake. The distinction it exists to
# keep is between producing evidence and passing judgement on it:
#
#   * The suite's exit status says whether the tests passed. It is printed, not propagated.
#   * The JUnit report says which tests ran and what each of them did. That is this target's
#     product, and it is most valuable precisely when a suite is red.
#
# Propagating the failure would abort the aggregate at the first red suite, so the suites after it
# would produce no evidence at all - a run with one failing test would leave three suites looking
# untested rather than untried. Turning a `<failure>` in a report into a red verdict is the job of
# whatever reads the reports afterwards - in this repository, the corpus evidence gate.

set(_command "")
set(_after_separator FALSE)
math(EXPR _last "${CMAKE_ARGC} - 1")
foreach (_index RANGE 0 ${_last})
    if (_after_separator)
        list(APPEND _command "${CMAKE_ARGV${_index}}")
    elseif ("${CMAKE_ARGV${_index}}" STREQUAL "--")
        set(_after_separator TRUE)
    endif ()
endforeach ()

if (NOT _command)
    message(FATAL_ERROR "UaRunTestSuite.cmake: no command given after --")
endif ()

execute_process(COMMAND ${_command} RESULT_VARIABLE _result)
if (NOT _result EQUAL 0)
    list(GET _command 0 _binary)
    message("execution evidence: ${_binary} exited ${_result} - the report records what failed; "
            "check_execution_evidence.py is what fails on it")
endif ()
