# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        client_observer_tests.cpp
)

# The observer sink is exercised over a real ConnectionImpl built with the shared FakeSessionOps / FakeReopen
# stubs, which live in the sibling connection/ test directory.
target_include_directories(tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../connection)
