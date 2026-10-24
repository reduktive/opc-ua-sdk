# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-core PRIVATE
        ua_await_callback.h
        ua_coro.h
        ua_on_strand.h
        ua_self_owning_operation.h
        ua_sync_wait.cpp
        ua_timer.cpp
        ua_guarded.cpp
)

uasdk_private_include_directory(uasdk-core)
