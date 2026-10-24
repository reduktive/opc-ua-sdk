# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        binary_codec_tests.cpp
        opaque_structure_codec_tests.cpp
        structure_reify_tests.cpp
        xml_codec_tests.cpp
        xml_encoder_tests.cpp
        xml_writer_tests.cpp
        xml_parser_tests.cpp
        ua_binary_encoding_limits_tests.cpp
        uasc_encode_limits_tests.cpp
)
