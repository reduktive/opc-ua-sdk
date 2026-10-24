# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_include_directories(uasdk-core PUBLIC .)

add_subdirectory(built_in)
add_subdirectory(dynamic)
add_subdirectory(factories)


target_sources(uasdk-core PUBLIC ua_hierarchical_path.h ua_reference_type_model.h)
