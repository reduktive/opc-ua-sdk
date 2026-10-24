# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(reference_demo_types
        PUBLIC
        ua_reference_demo_method_id.h
        ua_reference_demo_object_id.h
        ua_reference_demo_objecttype_id.h
        ua_reference_demo_variable_id.h
)

target_include_directories(reference_demo_types PUBLIC .)
