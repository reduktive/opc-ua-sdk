# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-core PUBLIC ${CMAKE_CURRENT_LIST_DIR}/doc_groups.h)

add_subdirectory(core)
add_subdirectory(address_space)
add_subdirectory(server)
add_subdirectory(client)
add_subdirectory(app)

# Optional Historical Access tier (uasdk-history[-sqlite]) - the libs are declared in
# sdk/CMakeLists.txt under UASDK_BUILD_HISTORY before this directory is processed.
if (UASDK_BUILD_HISTORY)
    add_subdirectory(history)
endif ()
