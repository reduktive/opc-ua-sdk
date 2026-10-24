# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-core PUBLIC ua_claim_keys.h ua_defines.h ua_error_detail.h ua_error_detail_keys.h ua_exceptions.h ua_includes.h
        ua_utilities.h ua_resolver.h ua_result.h ua_application_configuration.h
        ua_application_overrides.h ua_encoding_limits.h ua_execution_limits.h
        ua_log_level.h ua_log_entry.h ua_log_sink.h ua_logger.h ua_log_sink_implementations.h
        ua_to_result.h ua_callback_safety.h ua_callback.h
        ua_diagnostic_to_error_detail.h )

target_sources(uasdk-core PUBLIC ua_resource_budgets.h ua_service_operation_limits.h)


target_include_directories(uasdk-core PUBLIC .)

