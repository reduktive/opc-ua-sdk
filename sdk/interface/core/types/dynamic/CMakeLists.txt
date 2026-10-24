# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-core PUBLIC
        ua_dynamic_type_descriptor.h
        ua_dynamic_enum_type_descriptor.h
        ua_dynamic_structure.h
        ua_dynamic_union.h
        ua_dynamic_views.h
        ua_dynamic_option_set.h
        ua_dynamic_type_registry.h
        ua_type_model_access.h
        ua_type_loader.h
)

target_include_directories(uasdk-core PUBLIC .)
