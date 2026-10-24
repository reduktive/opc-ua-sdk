# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

# Standalone downstream project for the vcpkg overlay-port consume gate.
# Built with the vcpkg toolchain against the uasdk overlay
# port (ports/uasdk), which builds the SDK from the local checkout (UASDK_SOURCE_DIR). Requests the
# optional sqlite-store feature so the gate also covers component selection + find_dependency(SQLite3).
cmake_minimum_required(VERSION 3.21)
project(uasdk_vcpkg_consume_smoke CXX)

find_package(uasdk CONFIG REQUIRED COMPONENTS sqlite-store)

add_executable(uasdk_vcpkg_consume_smoke main.cpp)
target_link_libraries(uasdk_vcpkg_consume_smoke PRIVATE uasdk::uasdk uasdk::history-sqlite)
