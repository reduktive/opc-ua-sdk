// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Downstream consume-it smoke for the add_subdirectory (source) integration path. Exercises the
// core SDK (a flat header + a real symbol) and the optional Historical Access component
// (uasdk-history-sqlite) together, so the CI consume gate fails loudly if the profile-switch
// consumer build, the flat include layout, the in-tree `sdk` alias / history targets, or the
// transitive dependency resolution (Boost/OpenSSL/fmt/SQLite3) ever break.

#include "ua_history_sqlite_store.h"  // optional history component (flat include)
#include "ua_node_id.h"  // core SDK

#include <cstdio>

int main()
{
  // Core: a .cpp-defined NodeId ctor -> a real symbol out of libuasdk-core.a.
  ua::NodeId node{static_cast<uint16_t>(2), static_cast<uint32_t>(5000)};
  // History: constructing the SQLite store opens an in-memory DB and creates the schema, pulling
  // real symbols from libuasdk-history-sqlite.a and transitively SQLite::SQLite3.
  ua::history::SqliteHistoryStore store{":memory:", nullptr};
  (void)node;
  (void)store;
  std::printf("uasdk add_subdirectory consume smoke OK (core + history-sqlite)\n");
  return 0;
}
