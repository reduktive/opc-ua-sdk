# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        address_space_change_event_emitter_tests.cpp
        audit_event_emitter_tests.cpp
        base_event_tests.cpp
        event_bus_tests.cpp
        event_climb_flow_tests.cpp
        event_filter_tests.cpp
        event_monitoring_tests.cpp
)
