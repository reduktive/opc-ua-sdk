# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

add_subdirectory(core)
add_subdirectory(address_space)
add_subdirectory(server)
add_subdirectory(client)
add_subdirectory(app)

# Optional Historical Access tier (uasdk-history[-sqlite]) - see sdk/interface/history and
# sdk/CMakeLists.txt. Guarded so size-sensitive builds omit it (and its SQLite dependency).
if (UASDK_BUILD_HISTORY)
    add_subdirectory(history)
endif ()
