# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

# Sources for the storage-agnostic Historical Access engine (uasdk-history): OPC 10000-11 section 6.4/section 6.8
# semantics, the NamespaceHistoryDelegate wiring, the HistoryNamespace wrapper, and the Annotations
# Property helper. The bundled SQLite store is a separate, independently-optional sub-library.
target_sources(uasdk-history PRIVATE
        ua_history_engine.cpp
        ua_history_engine_delegate.cpp
        ua_history_namespace.cpp
        ua_history_annotations_property.cpp)
uasdk_private_include_directory(uasdk-history)
if (UASDK_BUILD_HISTORY_SQLITE)
    add_subdirectory(sqlite)
endif ()
