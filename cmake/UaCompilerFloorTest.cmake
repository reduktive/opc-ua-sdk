# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.
#
# UaCompilerFloorTest.cmake - tests the refusal in UaCompilerFloor.cmake.
#
#   cmake -P cmake/UaCompilerFloorTest.cmake
#
# A FATAL_ERROR cannot be caught in-process, so every case is a child `cmake -P` of THIS file in
# probe mode (-DUA_FLOOR_PROBE=1), with the compiler identity injected through the same variables
# CMake itself sets after project(): CMAKE_CXX_COMPILER_ID and CMAKE_CXX_COMPILER_VERSION. The
# driver asserts the child's exit status and, on a refusal, that the message names the floor.
# Registered as the `compiler_floor_gate` CTest in tests/CMakeLists.txt.

if (UA_FLOOR_PROBE)
    include("${CMAKE_CURRENT_LIST_DIR}/UaCompilerFloor.cmake")
    ua_check_compiler_floor()
    return()
endif ()

set(_failures 0)

# ua_floor_case(<id> <version> <expect: PASS|FAIL> [OVERRIDE] [EXPECT_IN_OUTPUT <text>])
# <id> NONE leaves both variables undefined, which is what a project() without CXX looks like.
function(ua_floor_case id version expect)
    cmake_parse_arguments(ARG "OVERRIDE" "EXPECT_IN_OUTPUT" "" ${ARGN})
    set(_args -DUA_FLOOR_PROBE=1)
    if (NOT id STREQUAL "NONE")
        list(APPEND _args "-DCMAKE_CXX_COMPILER_ID=${id}" "-DCMAKE_CXX_COMPILER_VERSION=${version}")
    endif ()
    if (ARG_OVERRIDE)
        list(APPEND _args -DUASDK_ALLOW_UNSUPPORTED_COMPILER=ON)
    endif ()
    execute_process(
            COMMAND "${CMAKE_COMMAND}" ${_args} -P "${CMAKE_CURRENT_LIST_FILE}"
            RESULT_VARIABLE _result
            OUTPUT_VARIABLE _out
            ERROR_VARIABLE _err)
    # CMake re-wraps message() text at the terminal width, so a phrase can straddle a line break;
    # match against the output with all whitespace runs collapsed to one space.
    string(REGEX REPLACE "[ \t\r\n]+" " " _text "${_out}${_err}")
    set(_label "${id} ${version}")
    if (ARG_OVERRIDE)
        string(APPEND _label " (override on)")
    endif ()
    if (expect STREQUAL "PASS" AND NOT _result EQUAL 0)
        message(SEND_ERROR "expected ${_label} to configure, got exit ${_result}:\n${_err}")
        math(EXPR _failures "${_failures} + 1")
    elseif (expect STREQUAL "FAIL" AND _result EQUAL 0)
        message(SEND_ERROR "expected ${_label} to be refused, but it configured")
        math(EXPR _failures "${_failures} + 1")
    elseif (ARG_EXPECT_IN_OUTPUT AND NOT _text MATCHES "${ARG_EXPECT_IN_OUTPUT}")
        message(SEND_ERROR "expected the output for ${_label} to contain '${ARG_EXPECT_IN_OUTPUT}':\n${_text}")
        math(EXPR _failures "${_failures} + 1")
    else ()
        message(STATUS "ok: ${_label} -> ${expect}")
    endif ()
    set(_failures "${_failures}" PARENT_SCOPE)
endfunction()

# GCC: 12 is refused by name and floor; 13.1 is the floor; a newer release passes.
ua_floor_case(GNU 12.3.0 FAIL EXPECT_IN_OUTPUT "requires GCC 13.1 or later; this is GCC 12.3.0")
ua_floor_case(GNU 13.1.0 PASS)
ua_floor_case(GNU 14.3.0 PASS)
# Clang: 18 (the last release without llvm.coro.await.suspend) is refused; 19.1.0 is the first release of 19.
ua_floor_case(Clang 18.1.8 FAIL EXPECT_IN_OUTPUT "requires Clang 19.0 or later")
ua_floor_case(Clang 19.1.0 PASS)
# MSVC: the hosted Windows image's 19.44 is refused; 19.50 (Build Tools 14.50) passes.
ua_floor_case(MSVC 19.44.35228.0 FAIL EXPECT_IN_OUTPUT "requires MSVC 19.50 or later")
ua_floor_case(MSVC 19.50.35000.0 PASS)
# Refusals name the escape hatch, and the escape hatch demotes the refusal to a warning.
ua_floor_case(GNU 12.3.0 FAIL EXPECT_IN_OUTPUT "UASDK_ALLOW_UNSUPPORTED_COMPILER=ON")
ua_floor_case(GNU 12.3.0 PASS OVERRIDE EXPECT_IN_OUTPUT "this build is unsupported")
# An unverified compiler family warns and continues; a missing CXX language is refused.
ua_floor_case(AppleClang 17.0.0 PASS EXPECT_IN_OUTPUT "has not been verified with AppleClang 17.0.0")
ua_floor_case(NONE NONE FAIL EXPECT_IN_OUTPUT "needs the CXX language enabled")

if (_failures GREATER 0)
    message(FATAL_ERROR "${_failures} compiler-floor case(s) failed")
endif ()
message(STATUS "compiler floor: all cases passed")
