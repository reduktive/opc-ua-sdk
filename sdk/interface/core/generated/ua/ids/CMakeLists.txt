# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-core PUBLIC
        ua_datatype_id.h
        ua_method_id.h
        ua_object_id.h
        ua_objecttype_id.h
        ua_referencetype_id.h
        ua_variable_id.h
        ua_variabletype_id.h
        ua_attribute_id.h
)

target_include_directories(uasdk-core PUBLIC .)

