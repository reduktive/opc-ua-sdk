# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.
#
# UaCompilerFloor.cmake - the SDK's compiler floors, enforced at configure time.
#
# ua_check_compiler_floor() refuses a C++ compiler below the floor with one sentence naming the
# required version, instead of the template errors from inside <coroutine> that an unsupported
# compiler produces on its own - or worse, no error at all. It runs from the top-level
# CMakeLists.txt, which every route that BUILDS the SDK goes through: a developer build, a
# vendored add_subdirectory / FetchContent consumer, the vcpkg port and the Conan recipe.
#
# It deliberately does NOT run from the installed uasdkConfig.cmake. The coroutine machinery
# (sdk/implementation/core/async/) is private: no installed header under sdk/interface/ includes
# <coroutine>, awaits anything, or names Task, so a find_package consumer's compiler never
# compiles a coroutine of the SDK's and needs only what cxx_std_20 already propagates, plus ABI
# compatibility with the compiler that built the archives - the ordinary rule for any static
# library, and not something a version check here could establish. The floor is a property of
# the compiler that builds the archives, and this file is the ONE place the numbers live.
#
# The floors are set by C++20 coroutine CODE GENERATION, not by a library feature. The SDK's
# asynchronous core is coroutine-shaped and relies on symmetric transfer, and each floor is the
# first release that contains a specific fix. Below it the compiler ACCEPTS the code and runs
# it wrongly, which is why there is no warning-only mode by default:
#
#   GCC 13    GCC PR 101367: `co_await f([&]{...})` - an await on an expression holding a
#             temporary lambda - promoted a temporary that is then elided and ran a destructor
#             for something never constructed. Fixed on trunk 2022-12-04 (gcc-mirror/gcc@58a7b1e3,
#             "coroutines: Do not promote temporaries that will be elided") for 13.1; no backport.
#             Every await_callback / await_step site in the SDK is that shape.
#   Clang 19  llvm/llvm-project#56301, #65018, #72006: clang stored into the coroutine frame
#             AFTER await_suspend had handed it to another thread. Fixed by PR #79712 (the
#             llvm.coro.await.suspend intrinsics), merged 2024-03-11 after the 18 branch.
#             clang-cl reports CMAKE_CXX_COMPILER_ID "Clang" with its own version, so the same
#             floor applies to it.
#   MSVC 19.50 (MSVC Build Tools 14.50, Visual Studio 2026 18.0): toolsets 19.34-19.44 keep the
#             handle await_suspend returns ON the coroutine frame during symmetric transfer, so
#             a frame released during the transfer is read after it is freed (cppalliance/capy#427).
#
# The same numbers are published in README.md ("Requirements") and the manual's setup page;
# the coroutine conversion status record ("Compiler baselines") holds the
# evidence. Change them together.
#
# UASDK_ALLOW_UNSUPPORTED_COMPILER=ON turns the refusal into a warning, for reproducing a
# report on a compiler below the floor or for an analysis build whose output is never run. A
# build made that way is not supported and the warning says so on every configure.

set(UASDK_COMPILER_FLOOR_GNU "13.1")
set(UASDK_COMPILER_FLOOR_CLANG "19.0")
set(UASDK_COMPILER_FLOOR_MSVC "19.50")

option(UASDK_ALLOW_UNSUPPORTED_COMPILER
        "Configure on a compiler below the SDK's floor (unsupported; the build may misbehave)" OFF)

function(ua_check_compiler_floor)
    if (NOT CMAKE_CXX_COMPILER_ID)
        message(FATAL_ERROR
                "The reduktive OPC UA SDK is a C++ library and needs the CXX language enabled before "
                "it is configured or found: add CXX to project(LANGUAGES ...) or enable_language(CXX).")
    endif ()

    set(_id "${CMAKE_CXX_COMPILER_ID}")
    set(_version "${CMAKE_CXX_COMPILER_VERSION}")
    if (_id STREQUAL "GNU")
        set(_name "GCC")
        set(_floor "${UASDK_COMPILER_FLOOR_GNU}")
        set(_why "GCC PR 101367, fixed in GCC 13")
    elseif (_id STREQUAL "Clang")
        set(_name "Clang")
        set(_floor "${UASDK_COMPILER_FLOOR_CLANG}")
        set(_why "llvm/llvm-project#72006, fixed in LLVM 19")
    elseif (_id STREQUAL "MSVC")
        set(_name "MSVC")
        set(_floor "${UASDK_COMPILER_FLOOR_MSVC}")
        set(_why "cppalliance/capy#427, fixed in MSVC Build Tools 14.50 / Visual Studio 2026")
    else ()
        # AppleClang, IntelLLVM, NVHPC, ... : the SDK claims Linux and Windows with GCC, Clang and
        # MSVC only. An unknown compiler is not refused - it may well be a Clang derivative above the
        # floor - but nothing here has verified it, and its version numbers do not map onto the
        # floors above (Apple's clang numbering is not LLVM's).
        message(WARNING
                "The reduktive OPC UA SDK has not been verified with ${_id} ${_version}. Its "
                "supported compilers are GCC ${UASDK_COMPILER_FLOOR_GNU}+, Clang "
                "${UASDK_COMPILER_FLOOR_CLANG}+ and MSVC ${UASDK_COMPILER_FLOOR_MSVC}+; the floors "
                "are set by C++20 coroutine code generation, and an older compiler accepts the SDK's "
                "code and runs it wrongly.")
        return()
    endif ()

    if (_version VERSION_LESS _floor)
        # string(CONCAT), not set(): set() with several quoted arguments makes a LIST, and the
        # message then reads "this is Clang ;18.1.3".
        string(CONCAT _sentence
                "The reduktive OPC UA SDK requires ${_name} ${_floor} or later; this is ${_name} "
                "${_version}. The floor is set by C++20 coroutine code generation (${_why}): an "
                "older compiler accepts the SDK's code and produces wrong behaviour at run time, so "
                "the floor is not lowered. See README.md, 'Requirements'.")
        if (UASDK_ALLOW_UNSUPPORTED_COMPILER)
            message(WARNING
                    "${_sentence} UASDK_ALLOW_UNSUPPORTED_COMPILER is ON, so configuring continues; "
                    "this build is unsupported.")
        else ()
            message(FATAL_ERROR
                    "${_sentence} Set UASDK_ALLOW_UNSUPPORTED_COMPILER=ON to proceed with an "
                    "unsupported build.")
        endif ()
    endif ()
endfunction()
