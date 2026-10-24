# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        general_tests.cpp
        entry_headers_tests.cpp
        error_safety_tests.cpp
        file_log_sink_tests.cpp
        logger_throwing_sink_tests.cpp
        file_stream_tests.cpp
        diagnostic_collector_tests.cpp
        diagnostic_to_error_detail_tests.cpp
        error_chain_tests.cpp
        error_detail_context_tests.cpp
        batch_result_tests.cpp
        byte_format_tests.cpp
        callback_tests.cpp
        completion_or_log_tests.cpp
        trust_list_dir_cleanup_tests.cpp
        test_utilities_tests.cpp
)
