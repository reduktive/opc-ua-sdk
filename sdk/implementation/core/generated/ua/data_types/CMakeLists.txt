# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-core PUBLIC)

target_sources(uasdk-core PRIVATE
        ua_data_types_0.cpp
        ua_data_types_1.cpp
        ua_data_types_2.cpp
        ua_data_types_3.cpp
        ua_data_types_4.cpp
        ua_data_types_5.cpp
        ua_data_types_6.cpp
        ua_data_types_7.cpp
        ua_data_type_registration.cpp
        ua_enum_helpers.cpp
        ua_optionset_helpers.cpp
)

uasdk_private_include_directory(uasdk-core)

