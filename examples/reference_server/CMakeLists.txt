# SPDX-License-Identifier: 0BSD
# Copyright (c) 2026 Reduktive Limited.

cmake_minimum_required(VERSION 3.21)

# Buildable two ways: as part of the SDK source tree, or on its own against an installed SDK
# package. To build it on its own, copy this directory together with examples/reference_common/.
if (NOT TARGET uasdk::uasdk)
    project(example_reference_server CXX)
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

add_library(reference_demo_types STATIC)
set_target_properties(reference_demo_types PROPERTIES
    LINKER_LANGUAGE CXX
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON)
target_compile_features(reference_demo_types PUBLIC cxx_std_20)
target_link_libraries(reference_demo_types PUBLIC uasdk::uasdk)
add_subdirectory(model)
add_subdirectory(generated/reference_demo)

add_library(reference_demo_model STATIC)
set_property(TARGET reference_demo_model PROPERTY CXX_STANDARD 20)
target_compile_features(reference_demo_model PUBLIC cxx_std_20)
target_link_libraries(reference_demo_model PUBLIC reference_demo_types uasdk::uasdk)
target_include_directories(reference_demo_model PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_sources(reference_demo_model
    PUBLIC
        demo_model.h
    PRIVATE
        demo_logic.cpp
        demo_model.cpp)

add_executable(reference_server)

if (MSVC)
    target_compile_options(reference_server PRIVATE /W4 /WX /MP /bigobj)
elseif (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
    target_compile_options(reference_server PRIVATE -Wall -Wextra -pedantic -Werror)
endif ()

set_property(TARGET reference_server PROPERTY CXX_STANDARD 20)

find_package(Boost CONFIG REQUIRED COMPONENTS program_options)

target_link_libraries(reference_server
    PRIVATE
        Boost::boost
        Boost::program_options
        example_support
        reference_common
        reference_demo_model
        uasdk::uasdk)

target_sources(reference_server
    PRIVATE
        endpoints.h
        endpoints.cpp
        main.cpp
        options.h
        options.cpp)
