# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-address-space PRIVATE
        ua_default_base_node.h
        ua_default_data_type_node.h
        ua_default_method_node.h
        ua_default_namespace.h
        ua_default_object_node.h
        ua_default_object_type_node.h
        ua_default_reference.h
        ua_default_reference_type_node.h
        ua_default_value_source.h
        ua_default_variable_node.h
        ua_default_variable_type_node.h
        ua_default_view_node.h
        ua_default_namespace.cpp
        ua_namespace_zero.cpp
        ua_namespace_zero.h
        ua_default_base_node.cpp
        ua_default_object_node.cpp
        ua_default_view_node.cpp
        ua_default_variable_node.cpp
        ua_default_value_source.cpp
        ua_default_data_type_node.cpp
        ua_default_object_type_node.cpp
        ua_default_reference_type_node.cpp
        ua_default_variable_type_node.cpp
        ua_default_method_node.cpp
        ua_sampling_engine.h
        ua_sampling_engine.cpp
)

uasdk_private_include_directory(uasdk-address-space)
