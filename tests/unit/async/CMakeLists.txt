# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        guarded_tests.cpp
        post_borrowing_tests.cpp
        post_borrowing_repeating_tests.cpp
        post_owning_tests.cpp
        registry_tests.cpp
        runtime_tests.cpp
        sync_wait_tests.cpp
        coro_tests.cpp
        timer_tests.cpp
)
