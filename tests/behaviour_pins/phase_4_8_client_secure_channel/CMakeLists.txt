# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        open_channel_pin_test.cpp
        open_channel_failure_pin_test.cpp
        renew_token_pin_test.cpp
        close_flow_pin_test.cpp
        outgoing_drain_pin_test.cpp
        incoming_drain_pin_test.cpp
        strand_dispatch_pin_test.cpp
        error_detail_pin_test.cpp
)
