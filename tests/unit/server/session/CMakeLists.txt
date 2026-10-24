# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        client_signature_verification_tests.cpp
        server_signature_tests.cpp
        session_activate_token_encryption_tests.cpp
        session_shell_wiring_tests.cpp
        session_timeout_clamping_tests.cpp
        session_browse_continuation_point_tests.cpp
        session_user_token_policy_validation_tests.cpp
)
