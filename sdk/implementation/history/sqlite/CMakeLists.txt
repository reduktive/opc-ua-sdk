# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

# The bundled SQLite-backed HistoryStore (uasdk-history-sqlite): the only SQLite consumer in the tree.
# Public headers live in sdk/interface/history; these are the implementation translation units.
target_sources(uasdk-history-sqlite PRIVATE
        ua_history_sqlite_store.cpp
        ua_history_sqlite_connection.cpp
        ua_history_sqlite_statement.cpp)
uasdk_private_include_directory(uasdk-history-sqlite)
