# SPDX-License-Identifier: 0BSD
# Copyright (c) 2026 Reduktive Limited.

# The narrow PKI helper shared by the reference server and the reference client.
#
# The two reference applications are one deliverable in two programs, and they perform the same
# provisioning workflow from opposite sides, so this is the one place in examples/ where two
# examples share code that is not example_support.
add_library(reference_common STATIC)

set_target_properties(reference_common PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON)

target_include_directories(reference_common PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")

target_link_libraries(reference_common PUBLIC uasdk::uasdk)

target_sources(reference_common
    PUBLIC
        reference_pki.h
    PRIVATE
        reference_pki.cpp)
