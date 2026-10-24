# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        built_in_types_tests.cpp
        text_parse_tests.cpp
        data_type_of_tests.cpp
        hierarchical_path_tests.cpp
        variant_coercion_tests.cpp
        localized_text_tests.cpp
        localized_text_resolve_walk_tests.cpp
        dynamic_structure_tests.cpp
        dynamic_union_tests.cpp
        dynamic_enum_view_tests.cpp
        dynamic_option_set_view_tests.cpp
        dynamic_option_set_tests.cpp
        dynamic_type_registry_tests.cpp
        structure_factory_tests.cpp
        result_tests.cpp
        result_good_subcode_tests.cpp
        result_uncertain_value_tests.cpp
        to_string_tests.cpp
        spec_sentinel_types_tests.cpp
        numeric_range_parser_tests.cpp
        index_range_utils_tests.cpp
        apply_to_value_tests.cpp
        data_access_utils_tests.cpp
        equivalent_tests.cpp
        dynamic_type_nodeset_tests.cpp
        model_access_flow_tests.cpp
        type_loader_tests.cpp
        unknown_structure_tests.cpp
        reference_type_model_tests.cpp
)
