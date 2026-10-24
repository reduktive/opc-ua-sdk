# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        tcp_endpoint_tests.cpp
        tcp_transport_tests.cpp
        stream_tests.cpp
        reverse_hello_tests.cpp
        url_parser_tests.cpp
)
