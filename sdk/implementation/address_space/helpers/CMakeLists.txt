# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-address-space PRIVATE ua_file_helper.cpp ua_file_directory_helper.cpp ua_temporary_file_transfer_helper.cpp)

uasdk_private_include_directory(uasdk-address-space)
