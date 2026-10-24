# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-client PRIVATE
  ua_client_secure_channel_impl.h
  ua_client_secure_channel_impl.cpp
  ua_client_secure_channel.cpp
  ua_client_secure_channel_test_access.h
)

uasdk_private_include_directory(uasdk-client)
