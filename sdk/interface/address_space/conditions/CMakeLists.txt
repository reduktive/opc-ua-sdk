# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-address-space PUBLIC
        ua_acknowledgeable_condition_logic.h
        ua_alarm_condition_logic.h
        ua_certificate_expiration_alarm_logic.h
        ua_condition_logic.h
        ua_dialog_condition_logic.h
        ua_discrepancy_alarm_logic.h
        ua_discrete_alarm_logic.h
        ua_limit_alarm_logic.h
        ua_off_normal_alarm_logic.h)

target_include_directories(uasdk-address-space PUBLIC .)
