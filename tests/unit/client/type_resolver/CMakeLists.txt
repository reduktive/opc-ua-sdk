# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        client_type_registry_tests.cpp
        client_type_defer_gate_tests.cpp
        client_type_resolver_tests.cpp
        client_native_structure_decode_tests.cpp
        client_type_reify_consumer_tests.cpp
)
