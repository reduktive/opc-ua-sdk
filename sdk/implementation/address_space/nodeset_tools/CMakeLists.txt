# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-address-space PRIVATE
        ua_nodeset_parser.cpp
        ua_nodeset_import_engine.cpp
        ua_nodeset_import.cpp
        ua_nodeset_export_engine.cpp
        ua_nodeset_export.cpp
        ua_nodeset_writer.cpp
        ua_nodeset_parser.h
        ua_nodeset_import_engine.h
        ua_nodeset_export_engine.h
        ua_nodeset_writer.h
)

uasdk_private_include_directory(uasdk-address-space)
