# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-core PUBLIC)

target_sources(uasdk-core PRIVATE
        ua_namespace_zero_tables.cpp
)

uasdk_private_include_directory(uasdk-core)

