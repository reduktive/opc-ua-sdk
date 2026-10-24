# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        create_session_pin_test.cpp
        activate_session_pin_test.cpp
        service_request_pin_test.cpp
        execute_service_pin_test.cpp
        cancel_request_pin_test.cpp
        service_call_ownership_pin_test.cpp
        close_session_pin_test.cpp
        session_helper_pin_test.cpp
)
