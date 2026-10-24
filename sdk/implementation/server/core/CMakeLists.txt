# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-server PRIVATE
        ua_method_response_correlation.h
        ua_status_routing.h
)

target_include_directories(uasdk-server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
