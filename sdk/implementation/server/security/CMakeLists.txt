# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-server PRIVATE
        ua_access_operation.h
        ua_role_permission_utils.h
        ua_user_token_certificate_validation.h
        ua_user_token_certificate_validation.cpp
        ua_trust_list_manager.h
        ua_trust_list_manager.cpp
        ua_certificate_push_service.h
        ua_certificate_push_service.cpp
        ua_push_management_wiring.h
        ua_push_management_wiring.cpp
        ua_well_known_role_permissions.cpp
        ua_ns0_access_decoration.h
        ua_ns0_access_decoration.cpp
        ua_access_identity_registry.h
        ua_access_identity_registry.cpp
        ua_access_control.h
        ua_access_control.cpp)

uasdk_private_include_directory(uasdk-server)
