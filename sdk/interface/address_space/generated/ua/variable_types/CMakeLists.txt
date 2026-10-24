# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-address-space PUBLIC
        ua_alarm_rate_variable.h
        ua_alarm_state_variable.h
        ua_analog_item.h
        ua_analog_unit_range.h
        ua_analog_unit.h
        ua_audio_variable.h
        ua_base_analog.h
        ua_base_data_variable.h
        ua_build_info_variable.h
        ua_condition_variable.h
        ua_cube_item.h
        ua_data_item.h
        ua_else_guard_variable.h
        ua_expression_guard_variable.h
        ua_finite_state_variable.h
        ua_finite_transition_variable.h
        ua_guard_variable.h
        ua_image_item.h
        ua_multi_state_dictionary_entry_discrete_base.h
        ua_multi_state_dictionary_entry_discrete.h
        ua_multi_state_discrete.h
        ua_multi_state_value_discrete.h
        ua_n_dimension_array_item.h
        ua_program_diagnostic2.h
        ua_program_diagnostic.h
        ua_property.h
        ua_reference_description_variable.h
        ua_selection_list.h
        ua_server_status.h
        ua_state_variable.h
        ua_transition_variable.h
        ua_two_state_discrete.h
        ua_two_state_variable.h
        ua_xy_array_item.h
        ua_y_array_item.h
)

target_include_directories(uasdk-address-space PUBLIC .)

