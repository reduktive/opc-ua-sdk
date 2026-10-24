# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-server PRIVATE
        ua_session_diagnostics_helper.h
        ua_session_diagnostics_helper.cpp
        ua_subscription_diagnostics_node_manager.cpp
        ua_subscription_diagnostics_node_manager.h
        ua_sampling_interval_diagnostics_node_manager.cpp
        ua_sampling_interval_diagnostics_node_manager.h)

uasdk_private_include_directory(uasdk-server)
