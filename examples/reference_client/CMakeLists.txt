# SPDX-License-Identifier: 0BSD
# Copyright (c) 2026 Reduktive Limited.

cmake_minimum_required(VERSION 3.21)

# Buildable two ways: as part of the SDK source tree, or on its own against an installed SDK
# package. To build it on its own, copy this directory together with examples/reference_common/.
if (NOT TARGET uasdk::uasdk)
    project(example_reference_client CXX)
    find_package(uasdk CONFIG REQUIRED)
endif ()
if (NOT TARGET reference_common)
    # In this repository it is examples/reference_common; in a copied-out pair it sits beside this
    # directory. Try both, so the same file builds either way.
    foreach (_common_candidate "../reference_common" "../../reference_common")
        if (EXISTS "${CMAKE_CURRENT_LIST_DIR}/${_common_candidate}/reference_pki.h")
            add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/${_common_candidate}" reference_common)
            break ()
        endif ()
    endforeach ()
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

add_executable(reference_client)

set_property(TARGET reference_client PROPERTY CXX_STANDARD 20)

if (MSVC)
    target_compile_options(reference_client PRIVATE /W4 /WX /MP /bigobj)
elseif (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
    target_compile_options(reference_client PRIVATE -Wall -Wextra -pedantic -Werror)
endif ()

find_package(Boost CONFIG REQUIRED COMPONENTS program_options)

target_link_libraries(reference_client
    PRIVATE
        Boost::boost
        Boost::program_options
        example_support
        reference_common
        uasdk::uasdk)

target_sources(reference_client
    PRIVATE
        demo.h
        demo.cpp
        main.cpp
        options.h
        options.cpp)

# The reference pair is one deliverable in two programs, so its behaviour test drives both: it
# performs the documented provisioning workflow, starts the server, runs the client, and compares
# both programs' whole output to their golden files.
if (UASDK_EXAMPLE_TEST_RUNNER)
    add_test(NAME example.reference_pair
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/../../tooling/examples/run_reference_pair_test.py"
            --server "$<TARGET_FILE:reference_server>"
            --client "$<TARGET_FILE:reference_client>"
            --model "${CMAKE_CURRENT_SOURCE_DIR}/../reference_server/model/Reduktive.ReferenceServer.NodeSet2.xml"
            --server-expected "${CMAKE_CURRENT_SOURCE_DIR}/../reference_server/expected_output.txt"
            --client-expected "${CMAKE_CURRENT_SOURCE_DIR}/expected_output.txt"
            --mask "UptimeSeconds = [0-9]+")
    set_tests_properties(example.reference_pair PROPERTIES
        TIMEOUT 180
        RESOURCE_LOCK uasdk_example_server_port)
endif ()
