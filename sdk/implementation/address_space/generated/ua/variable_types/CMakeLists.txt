# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-address-space PUBLIC)

target_sources(uasdk-address-space PRIVATE
        ua_alarm_rate_variable.cpp
        ua_alarm_state_variable.cpp
        ua_analog_item.cpp
        ua_analog_unit_range.cpp
        ua_analog_unit.cpp
        ua_audio_variable.cpp
        ua_base_analog.cpp
        ua_base_data_variable.cpp
        ua_build_info_variable.cpp
        ua_condition_variable.cpp
        ua_cube_item.cpp
        ua_data_item.cpp
        ua_else_guard_variable.cpp
        ua_expression_guard_variable.cpp
        ua_finite_state_variable.cpp
        ua_finite_transition_variable.cpp
        ua_guard_variable.cpp
        ua_image_item.cpp
        ua_multi_state_dictionary_entry_discrete_base.cpp
        ua_multi_state_dictionary_entry_discrete.cpp
        ua_multi_state_discrete.cpp
        ua_multi_state_value_discrete.cpp
        ua_n_dimension_array_item.cpp
        ua_program_diagnostic2.cpp
        ua_program_diagnostic.cpp
        ua_property.cpp
        ua_reference_description_variable.cpp
        ua_selection_list.cpp
        ua_server_status.cpp
        ua_state_variable.cpp
        ua_transition_variable.cpp
        ua_two_state_discrete.cpp
        ua_two_state_variable.cpp
        ua_xy_array_item.cpp
        ua_y_array_item.cpp
)

uasdk_private_include_directory(uasdk-address-space)

