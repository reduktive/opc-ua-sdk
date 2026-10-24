# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        acknowledgeable_condition_logic_tests.cpp
        alarm_condition_logic_tests.cpp
        certificate_expiration_alarm_logic_tests.cpp
        condition_instance_tests.cpp
        condition_logic_tests.cpp
        condition_source_probe_tests.cpp
        conditions_tests.cpp
        condition_state_snapshot_tests.cpp
        dialog_condition_logic_tests.cpp
        discrepancy_alarm_logic_tests.cpp
        discrete_alarm_logic_tests.cpp
        limit_alarm_logic_tests.cpp
        off_normal_alarm_logic_tests.cpp)
