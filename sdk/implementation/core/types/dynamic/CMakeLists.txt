# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-core PRIVATE
        ua_dynamic_field_codec.h
        ua_dynamic_field_codec.cpp
        ua_dynamic_type_descriptor.cpp
        ua_dynamic_enum_type_descriptor.cpp
        ua_dynamic_structure.cpp
        ua_dynamic_union.cpp
        ua_dynamic_enum_view.cpp
        ua_dynamic_option_set_view.cpp
        ua_dynamic_option_set.cpp
        ua_dynamic_type_registry.cpp
        ua_equivalent.cpp
        ua_type_loader.cpp
)

uasdk_private_include_directory(uasdk-core)
