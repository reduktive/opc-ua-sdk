# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-address-space PUBLIC)

target_sources(uasdk-address-space PRIVATE
        ua_event_types.cpp
)

uasdk_private_include_directory(uasdk-address-space)

