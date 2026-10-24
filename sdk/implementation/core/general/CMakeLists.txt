# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-core PRIVATE
        ua_error_chain.h
        ua_lru_map.h
        ua_random.h
        ua_error_detail.cpp
        ua_utilities.cpp
        ua_logger.cpp
        ua_console_log_sink.cpp
        ua_file_log_sink.cpp
        ua_log_format.cpp
        ua_log_format.h
        ua_resolver.cpp
        ua_exceptions.cpp
        ua_stack_utilities.cpp
        ua_application_configuration.cpp
        ua_application_overrides.cpp
        ua_json_helpers.cpp
        ua_stack_utilities.h
        ua_json_helpers.h
        ua_log_exception.h
        ua_instance_tracker.h
        ua_diagnostic_to_error_detail.cpp
        ua_error_chain.cpp
        ua_error_detail_context_json.cpp
)

uasdk_private_include_directory(uasdk-core)
