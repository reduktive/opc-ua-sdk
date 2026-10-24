# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-core PRIVATE
        ua_null_stream.h
        ua_memory_stream.cpp
        ua_file_stream.cpp
        ua_null_stream.cpp
)

uasdk_private_include_directory(uasdk-core)
