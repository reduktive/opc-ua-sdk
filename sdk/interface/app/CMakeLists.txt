# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-app PUBLIC
        ua_process_configuration_file.h
        ua_lds_registrar.h
        ua_discovery_registration.h
        ua_server_with_discovery.h)

target_include_directories(uasdk-app PUBLIC .)
