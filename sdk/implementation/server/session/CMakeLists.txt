# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-server PRIVATE
        ua_server_session.cpp
        ua_server_session.h
        ua_service_kind.h
)

uasdk_private_include_directory(uasdk-server)
