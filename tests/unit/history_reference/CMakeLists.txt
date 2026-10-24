# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

# Unit tests for the Historical Access component (sdk/{interface,implementation}/history, built as uasdk-history /
# uasdk-history-sqlite static libraries). Linking the SQLite store brings the agnostic engine too.
target_link_libraries(tests PUBLIC uasdk-history-sqlite)

target_sources(tests PRIVATE
    annotations_property_tests.cpp
    history_engine_tests.cpp
    history_failure_contract_tests.cpp
    history_namespace_tests.cpp
    sqlite_history_store_tests.cpp
)
