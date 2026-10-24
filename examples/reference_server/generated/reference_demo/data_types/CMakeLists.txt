# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(reference_demo_types
        PUBLIC
        ua_reference_demo_namespace_uri.h
        ua_reference_demo_aliases.h
        ua_reference_demo_data_type_registration.h
        PRIVATE
        ua_reference_demo_data_type_registration.cpp
        ua_reference_demo_enum_helpers.cpp
        ua_reference_demo_optionset_helpers.cpp
)

target_include_directories(reference_demo_types PUBLIC .)
