# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(
        uasdk-address-space
        PUBLIC
        ua_instantiation_options.h
        ua_node_subtree.h
        ua_instantiation_service.h)

target_include_directories(uasdk-address-space PUBLIC .)
