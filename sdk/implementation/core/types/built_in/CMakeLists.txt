# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-core PRIVATE
        ua_byte_string.cpp
        ua_guid.cpp
        ua_date_time.cpp
        ua_xml_element.cpp
        ua_array_base.cpp
        ua_codec_namespace_context.cpp
        ua_structure.cpp
        ua_union.cpp
        ua_variant.cpp
        ua_expanded_node_id.cpp
        ua_localized_text.cpp
        ua_resolve_in_variant.cpp
        ua_data_value.cpp
        ua_qualified_name.cpp
        ua_string.cpp
        ua_node_id.cpp
        ua_node_id_validation.h
        ua_value_rank.cpp
        ua_decimal.cpp
        ua_status_code.cpp
        ua_diagnostic_info.cpp
        ua_unknown_structure.cpp
        ua_to_string.cpp
        ua_numeric_range_parser.cpp
        ua_index_range_utils.cpp
        ua_option_set_value_merge.cpp
        ua_data_access_utils.cpp
)

uasdk_private_include_directory(uasdk-core)
