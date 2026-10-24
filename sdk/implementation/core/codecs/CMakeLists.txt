# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-core PRIVATE
        ua_xml_parser.cpp
        ua_codec.cpp
        ua_xml_codec.cpp
        ua_xml_writer.cpp
        ua_binary_codec.cpp
        ua_binary_data_value_codec.cpp
        ua_structure_reify.cpp
        ua_codec.h
        ua_xml_parser.h
        ua_xml_codec.h
        ua_xml_writer.h
        ua_xml_escape.h
        ua_binary_codec.h
)

uasdk_private_include_directory(uasdk-core)
