# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

set(VCPKG_TARGET_ARCHITECTURE x86)
set(VCPKG_CMAKE_SYSTEM_NAME Linux)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)
# Inject -m32 into vcpkg's compiler detection step. Without this, cmake 4.x
# treats x86 on an x86_64 host as a cross-compile and can't find the compiler.
set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE "${CMAKE_CURRENT_LIST_DIR}/../toolchains/linux-x86.cmake")
