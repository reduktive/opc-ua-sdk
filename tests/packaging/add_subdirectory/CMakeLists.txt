# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

# Standalone downstream project for the add_subdirectory consume gate.
# Vendors the SDK checkout and pulls
# it in with add_subdirectory(${UASDK_SOURCE_DIR}) - the same path reference_server uses
# internally. The SDK builds as a subproject through the PROJECT_IS_TOP_LEVEL=OFF profile switch:
# libraries only, no tests/examples/type-gen, no UA-Nodeset clone. The gate then asserts that
# switch actually flipped the dev options OFF.
cmake_minimum_required(VERSION 3.21)
project(uasdk_add_subdirectory_consume_smoke CXX)

# Opt into the optional Historical Access component (OFF by default for a consumer via the
# profile switch) so the gate also covers uasdk-history-sqlite + find_package(SQLite3).
set(UASDK_BUILD_HISTORY ON CACHE BOOL "" FORCE)

add_subdirectory("${UASDK_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/uasdk")

add_executable(uasdk_add_subdirectory_consume_smoke main.cpp)
# Link the uasdk:: namespaced targets - the SAME names an installed find_package() consumer uses,
# now available in-tree via add_library(uasdk::... ALIAS ...). (The backwards-compatible `sdk` alias of
# the umbrella also still works here and is exercised by examples/reference_server.)
target_link_libraries(uasdk_add_subdirectory_consume_smoke PRIVATE uasdk::uasdk uasdk::history-sqlite)
