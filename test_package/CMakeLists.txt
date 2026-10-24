# SPDX-License-Identifier: 0BSD
# Copyright (c) 2026 Reduktive Limited.

# Downstream Conan consumer - built by `conan create` (the test_package gate). Consumes the SDK
# through the uasdk-config.cmake that Conan's CMakeDeps generates from package_info().
#
# No COMPONENTS clause here (unlike the find_package / vcpkg consumers): the generated config exposes
# the package_info component names (core/.../history-sqlite), not the shipped config's logical feature
# names (history/sqlite-store). The package is created with with_sqlite_store=True, so the
# uasdk::history-sqlite target is present and linking it directly is sufficient.
cmake_minimum_required(VERSION 3.21)
project(uasdk_test_package CXX)

find_package(uasdk CONFIG REQUIRED)

add_executable(uasdk_test_package src/test_package.cpp)
target_link_libraries(uasdk_test_package PRIVATE uasdk::uasdk uasdk::history-sqlite)
