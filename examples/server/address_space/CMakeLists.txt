# SPDX-License-Identifier: 0BSD
# Copyright (c) 2026 Reduktive Limited.

cmake_minimum_required(VERSION 3.21)

# Buildable two ways: as part of the SDK source tree, or on its own against an installed SDK
# package. To build it on its own, copy this directory and examples/support/ together, then:
#
#   cmake -S <this directory> -B build -DCMAKE_PREFIX_PATH=<SDK install prefix>
#   cmake --build build
if (NOT TARGET uasdk::uasdk)
    project(example_server_address_space CXX)
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

add_executable(example_server_address_space)

set_target_properties(example_server_address_space PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON)

if (MSVC)
    target_compile_options(example_server_address_space PRIVATE /W4 /WX)
else ()
    target_compile_options(example_server_address_space PRIVATE -Wall -Wextra -pedantic -Werror)
endif ()

target_link_libraries(example_server_address_space PRIVATE example_support uasdk::uasdk)

target_sources(example_server_address_space PRIVATE main.cpp model.h model.cpp)

# Registered only inside this repository, where the harness exists.
if (COMMAND uasdk_add_example_test)
    uasdk_add_example_test(example_server_address_space TIMEOUT 60 INTERRUPT_WHEN "Press Ctrl+C to stop")
endif ()
