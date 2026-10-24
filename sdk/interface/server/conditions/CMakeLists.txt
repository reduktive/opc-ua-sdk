# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-server PUBLIC
        ua_condition_alarm_metrics.h
        ua_condition_state_snapshot.h
        ua_condition_instance.h
        ua_conditions.h)

target_include_directories(uasdk-server PUBLIC .)
