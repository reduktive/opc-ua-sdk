# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-server PRIVATE
        ua_condition_alarm_metrics.cpp
        ua_condition_state_snapshot.cpp
        ua_condition_instance.cpp
        ua_conditions.cpp)

uasdk_private_include_directory(uasdk-server)
