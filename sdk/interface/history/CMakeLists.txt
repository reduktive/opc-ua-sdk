# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

# Public headers for the optional Historical Access component. Wired onto the history libraries
# (declared in sdk/CMakeLists.txt under UASDK_BUILD_HISTORY, before this dir is added). The engine
# headers ride uasdk-history; the SQLite store's public headers ride uasdk-history-sqlite when built.
target_sources(uasdk-history PUBLIC
        ua_history_store.h
        ua_history_engine.h
        ua_history_engine_delegate.h
        ua_history_namespace.h
        ua_history_annotations_property.h)
target_include_directories(uasdk-history PUBLIC .)

if (UASDK_BUILD_HISTORY_SQLITE)
    target_sources(uasdk-history-sqlite PUBLIC
            ua_history_sqlite_store.h
            ua_history_sqlite_connection.h
            ua_history_sqlite_statement.h)
    target_include_directories(uasdk-history-sqlite PUBLIC .)
endif ()
