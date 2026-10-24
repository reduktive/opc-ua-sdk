# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-core PUBLIC ua_variant.h ua_built_in_types_fwd_decl.h ua_date_time.h
        ua_status_code.h ua_data_value.h ua_decimal.h ua_diagnostic_info.h ua_expanded_node_id.h
        ua_guid.h ua_localized_text.h ua_node_id.h ua_qualified_name.h ua_structure.h ua_unknown_structure.h
        ua_codec_namespace_context.h
        ua_uri_array.h
        ua_union.h
        ua_string.h ua_array.h ua_array_base.h ua_xml_element.h ua_ref_structure.h ua_value_rank.h
        ua_ref_wrapper.h ua_built_in_type_id.h ua_to_string.h ua_fmt.h ua_numeric_range_parser.h ua_option_set_value_merge.h ua_data_access_utils.h
        ua_data_type_trait.h ua_data_type_of.h)

target_include_directories(uasdk-core PUBLIC .)
