# SPDX-License-Identifier: 0BSD
# Copyright (c) 2026 Reduktive Limited.

cmake_minimum_required(VERSION 3.21)

# Buildable two ways: as part of the SDK source tree, or on its own against an installed SDK
# package. To build it on its own, copy this directory and examples/support/ together, then:
#
#   cmake -S <this directory> -B build -DCMAKE_PREFIX_PATH=<SDK install prefix>
#   cmake --build build
if (NOT TARGET uasdk::uasdk)
    project(example_quickstart_roundtrip CXX)
    find_package(uasdk CONFIG REQUIRED)
endif ()
if (NOT TARGET example_support)
    # In this repository the support library is examples/support; in a copied-out example it sits
    # beside the example directory. Try both, so the same file builds either way.
    foreach (_support_candidate "../support" "../../support")
        if (EXISTS "${CMAKE_CURRENT_LIST_DIR}/${_support_candidate}/example_support.h")
            add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/${_support_candidate}" example_support)
            break ()
        endif ()
    endforeach ()
endif ()

add_executable(example_quickstart_roundtrip)

set_target_properties(example_quickstart_roundtrip PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON)

if (MSVC)
    target_compile_options(example_quickstart_roundtrip PRIVATE /W4 /WX)
else ()
    target_compile_options(example_quickstart_roundtrip PRIVATE -Wall -Wextra -pedantic -Werror)
endif ()

target_link_libraries(example_quickstart_roundtrip PRIVATE example_support uasdk::uasdk)

target_sources(example_quickstart_roundtrip PRIVATE main.cpp)

# Registered only inside this repository, where the harness exists.
if (COMMAND uasdk_add_example_test)
    uasdk_add_example_test(example_quickstart_roundtrip TIMEOUT 60)
endif ()
