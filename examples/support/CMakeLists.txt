# SPDX-License-Identifier: 0BSD
# Copyright (c) 2026 Reduktive Limited.

# Console output, failure rendering, signal waiting, and temporary directories shared by the
# example programs. It deliberately contains no OPC UA code: see example_support.h.
add_library(example_support STATIC)

set_target_properties(example_support PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON)

target_include_directories(example_support PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")

target_link_libraries(example_support PUBLIC uasdk::uasdk)

target_sources(example_support
    PUBLIC
        example_support.h
        example_pki.h
        example_queue.h
    PRIVATE
        example_support.cpp
        example_pki.cpp)
