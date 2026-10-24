# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        application_criteria_gate_tests.cpp
        applications_filter_signed_channel_floor_tests.cpp
        default_namespace_role_delegate_tests.cpp
        push_management_wiring_tests.cpp
        trust_list_tests.cpp
        role_configuration_tests.cpp
        role_method_handlers_tests.cpp
        role_permission_utils_tests.cpp
        role_set_population_tests.cpp
        role_set_browse_name_tests.cpp
        server_part18_wiring_tests.cpp
        thumbprint_criteria_format_tests.cpp
        x509_subject_criteria_format_tests.cpp
        default_role_permissions_property_tests.cpp
        default_user_role_permissions_tests.cpp
        default_user_role_permissions_sampling_tests.cpp
        well_known_role_default_permissions_tests.cpp
        role_property_writable_tests.cpp
        ns0_access_decoration_tests.cpp
        namespace_access_control_defaults_tests.cpp
        access_identity_registry_tests.cpp
        access_control_tests.cpp
        access_control_forms_tests.cpp
)
