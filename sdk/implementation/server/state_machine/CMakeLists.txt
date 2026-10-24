# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-server PRIVATE
        ua_state_machine_method_hook.cpp
        ua_state_machine_method_hook.h
        ua_state_machine_runtime.cpp
        ua_state_machine_runtime.h
)

uasdk_private_include_directory(uasdk-server)
