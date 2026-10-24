# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-client PRIVATE
  ua_diagnostic_info_decoder.h
  ua_diagnostic_info_decoder.cpp
  ua_response_diagnostics.h
  ua_response_diagnostics.cpp
)

uasdk_private_include_directory(uasdk-client)
