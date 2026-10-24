# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

# Standalone downstream project for the FetchContent consume gate.
# Pulls the SDK into its own build
# via FetchContent from the LOCAL checkout (UASDK_SOURCE_DIR) - a real consumer swaps the
# SOURCE_DIR line for GIT_REPOSITORY/GIT_TAG. The SDK builds as a subproject through the
# PROJECT_IS_TOP_LEVEL=OFF profile switch: libraries only, no tests/examples/type-gen and no
# UA-Nodeset clone. The gate then asserts that switch actually flipped the dev options OFF.
cmake_minimum_required(VERSION 3.21)
project(uasdk_fetchcontent_consume_smoke CXX)

# Opt into the optional Historical Access component (OFF by default for a consumer via the
# profile switch) so the gate also covers uasdk-history-sqlite + find_package(SQLite3).
set(UASDK_BUILD_HISTORY ON CACHE BOOL "" FORCE)

include(FetchContent)
FetchContent_Declare(uasdk SOURCE_DIR "${UASDK_SOURCE_DIR}")  # local source => offline
FetchContent_MakeAvailable(uasdk)

add_executable(uasdk_fetchcontent_consume_smoke main.cpp)
# Link the uasdk:: namespaced targets - the SAME names an installed find_package() consumer uses.
# These now exist in-tree via add_library(uasdk::... ALIAS ...) in sdk/CMakeLists.txt, so a source
# consumer and a package consumer link identically; this gate proves the in-tree aliases resolve.
target_link_libraries(uasdk_fetchcontent_consume_smoke PRIVATE uasdk::uasdk uasdk::history-sqlite)
