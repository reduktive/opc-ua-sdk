# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

# Codegen matrix - generate + compile EVERY companion spec the UA-Nodeset
# checkout provides, as an allow-fail coverage dashboard.
#
# Opt-in (UASDK_BUILD_CODEGEN_MATRIX, default OFF). Two Python pieces drive it:
#
#   * companion_matrix.py - discovers every spec + its cross-spec dependency DAG
#     and writes an ordered build plan (codegen_plan.json), run here at configure.
#   * matrix_compile.py - for each spec: generate, then compile the emitted TUs in
#     the real SDK compile environment (flags lifted from compile_commands.json).
#     Registered as the ``codegen_matrix`` CTest test.
#
# Completed model failures outside allowlist.txt are dashboard data. Incomplete
# execution, infrastructure failures and allowlist regressions fail the test.

find_package(Python3 QUIET COMPONENTS Interpreter)
if (NOT Python3_FOUND)
    message(FATAL_ERROR "codegen matrix: Python3 is required")
endif ()

set(_RUN_PY "${CMAKE_SOURCE_DIR}/tooling/type_generator/run_type_generator.py")
set(_UANODESET_DIR "${CMAKE_BINARY_DIR}/_deps/uanodeset-src")
set(_PLAN "${CMAKE_CURRENT_BINARY_DIR}/codegen_plan.json")

# Discover the spec set + dependency DAG now, so the plan exists for the test.
# CMAKE_CONFIGURE_DEPENDS re-runs discovery if the checkout's models change.
execute_process(
    COMMAND "${Python3_EXECUTABLE}" "${_RUN_PY}"
        --py-module tooling.type_generator.companion_matrix
        --root "${_UANODESET_DIR}" --out "${_PLAN}" --quiet
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    RESULT_VARIABLE _disc_rv
    OUTPUT_VARIABLE _disc_out
    ERROR_VARIABLE _disc_err
)
if (NOT _disc_rv EQUAL 0)
    message(FATAL_ERROR "codegen matrix: discovery failed (exit ${_disc_rv})\n"
            "stdout:\n${_disc_out}\nstderr:\n${_disc_err}")
endif ()
message(VERBOSE "codegen matrix: discovery plan written to ${_PLAN}")

# Discovery already provisioned the host Python environment. The test must start
# the bounded supervisor directly, without a second network/bootstrap subprocess.
if (CMAKE_HOST_WIN32)
    set(_MATRIX_PY "${CMAKE_SOURCE_DIR}/.venv-typegen/Scripts/python.exe")
else ()
    set(_MATRIX_PY "${CMAKE_SOURCE_DIR}/.venv-typegen/bin/python")
endif ()
if (NOT EXISTS "${_MATRIX_PY}")
    message(FATAL_ERROR "codegen matrix: provisioned Python not found: ${_MATRIX_PY}")
endif ()

add_test(
    NAME codegen_matrix
    COMMAND "${_MATRIX_PY}" -u -m tooling.type_generator.matrix_compile
        --plan "${_PLAN}"
        --root "${_UANODESET_DIR}"
        --compile-commands "${CMAKE_BINARY_DIR}/compile_commands.json"
        --out-dir "${CMAKE_CURRENT_BINARY_DIR}/gen"
        --report "${CMAKE_CURRENT_BINARY_DIR}/codegen_matrix_report"
        --allowlist "${CMAKE_CURRENT_SOURCE_DIR}/allowlist.txt"
        --repo-root "${CMAKE_SOURCE_DIR}"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)
# Heavy: ~124 specs x generate + compile. Generous timeout; its own label so a
# nightly job can select just this (ctest -L codegen_matrix).
set_tests_properties(codegen_matrix PROPERTIES TIMEOUT 3600 LABELS "codegen_matrix")
