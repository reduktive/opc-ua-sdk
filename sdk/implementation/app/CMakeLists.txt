# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-app PRIVATE
        ua_process_configuration_file.cpp
        ua_lds_registrar.cpp
        ua_registration_endpoint_choice.h
        ua_discovery_registration.cpp
        ua_server_with_discovery.cpp)

uasdk_private_include_directory(uasdk-app)
