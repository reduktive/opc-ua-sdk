# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        pull_certificate_manager_impl_tests.cpp
        pull_certificate_manager_client_host_tests.cpp
        pull_cert_trust_list_codec_tests.cpp
        pull_certificate_request_codec_tests.cpp
)
