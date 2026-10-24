# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        context_keepalive_pin_test.cpp
        decode_asymmetric_pin_test.cpp
        decode_symmetric_pin_test.cpp
        encode_symmetric_pin_test.cpp
        derive_symmetric_keys_pin_test.cpp
        wire_roundtrip_pin_test.cpp
)
