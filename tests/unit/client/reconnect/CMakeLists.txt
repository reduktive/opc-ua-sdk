# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        reconnect_policy_backoff_tests.cpp
        reconnect_fsm_logic_cause_priority_tests.cpp
        reconnection_fsm_tests.cpp
)
