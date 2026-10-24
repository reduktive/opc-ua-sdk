# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

# Standalone downstream project - NOT part of the SDK build. Built by the consume-it gate
# against an installed SDK prefix to prove raw
# find_package(uasdk CONFIG) consumption works end to end. Requests the optional sqlite-store
# component so the gate also covers component selection + find_dependency(SQLite3).
cmake_minimum_required(VERSION 3.21)
project(uasdk_consume_smoke CXX)

find_package(uasdk CONFIG REQUIRED COMPONENTS sqlite-store)

add_executable(uasdk_consume_smoke main.cpp)
target_link_libraries(uasdk_consume_smoke PRIVATE uasdk::uasdk uasdk::history-sqlite)

# Every installed header compiles on its own against include/uasdk (public API review 2026-10, item 1,
# API-1.4). A public header that needs a private one, or that relies on another header being included
# first, fails here and nowhere else: in the SDK's own build every source directory is on the include
# path. One generated translation unit per header, compiled and not linked.
get_target_property(_uasdk_include_dirs uasdk::build-public INTERFACE_INCLUDE_DIRECTORIES)
set(_uasdk_header_dir "")
foreach (_dir IN LISTS _uasdk_include_dirs)
    if (EXISTS "${_dir}/ua_server.h")
        set(_uasdk_header_dir "${_dir}")
    endif ()
endforeach ()
if (NOT _uasdk_header_dir)
    message(FATAL_ERROR "The installed SDK's include/uasdk directory was not found in ${_uasdk_include_dirs}")
endif ()
file(GLOB _uasdk_installed_headers RELATIVE "${_uasdk_header_dir}" "${_uasdk_header_dir}/*.h")
set(_uasdk_header_units "")
foreach (_header IN LISTS _uasdk_installed_headers)
    string(MAKE_C_IDENTIFIER "${_header}" _unit)
    set(_unit_file "${CMAKE_CURRENT_BINARY_DIR}/header_units/${_unit}.cpp")
    file(WRITE "${_unit_file}" "#include \"${_header}\"\n")
    list(APPEND _uasdk_header_units "${_unit_file}")
endforeach ()
list(LENGTH _uasdk_header_units _uasdk_header_count)
message(STATUS "Compiling ${_uasdk_header_count} installed headers on their own")
add_library(uasdk_installed_headers_compile OBJECT ${_uasdk_header_units})
target_link_libraries(uasdk_installed_headers_compile PRIVATE uasdk::uasdk uasdk::history-sqlite)

# Generated object and variable types include only installed headers, so an application that commits its
# generated sources builds them against an installed SDK. The reference server's generated tree, which the
# example builds this way, is compiled here as such an application compiles it. A generated Structure type
# is not: its encoding calls the SDK's codecs, which are not installed, so it builds only in a build of the
# SDK's source tree (ua_generate_types() links it to uasdk::internal).
add_library(reference_demo_types STATIC)
target_compile_features(reference_demo_types PUBLIC cxx_std_20)
target_link_libraries(reference_demo_types PUBLIC uasdk::uasdk)
add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/../../../examples/reference_server/generated/reference_demo"
    reference_demo)
