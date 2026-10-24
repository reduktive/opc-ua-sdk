# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-address-space PRIVATE
        ua_acknowledgeable_condition_logic.cpp
        ua_alarm_condition_logic.cpp
        ua_certificate_expiration_alarm_logic.cpp
        ua_condition_logic.cpp
        ua_dialog_condition_logic.cpp
        ua_discrepancy_alarm_logic.cpp
        ua_discrete_alarm_logic.cpp
        ua_limit_alarm_logic.cpp
        ua_off_normal_alarm_logic.cpp)

uasdk_private_include_directory(uasdk-address-space)
