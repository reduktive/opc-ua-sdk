# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        condition_instance_lifecycle_pin_test.cpp
        condition_instance_state_flow_pin_test.cpp
        conditions_pin_test.cpp
        timed_shelve_pin_test.cpp
        error_detail_propagation_pin_test.cpp
)
