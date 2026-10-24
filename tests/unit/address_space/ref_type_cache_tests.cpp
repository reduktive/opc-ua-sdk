// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file Tests for node_utils::RefTypeCache (Stage-3a F1).
///
/// RefTypeCache memoises reference-type subtype checks. It is shared across an async type-hierarchy walk
/// whose completion runs on the address-space pool executor while concurrent operations look it up on
/// another executor - so it must be internally synchronised (a bare std::unordered_map shared this way is
/// UB: a `find` on one thread races an `emplace` on another). These tests pin the synchronised contract:
/// correct memoisation, and no corruption under concurrent store/lookup (a regression to the unsynchronised
/// map would be caught here under TSan and risks crashes/wrong answers otherwise).

#include <gtest/gtest.h>

#include "ua_node_utilities.h"
#include "ua_node_id.h"

#include <atomic>
#include <thread>
#include <vector>

using namespace ua;

namespace
{
std::pair<NodeId, NodeId> key(uint32_t a, uint32_t b)
{
  return {NodeId{0, a}, NodeId{0, b}};
}
}  // namespace

TEST(RefTypeCacheTests, LookupMissReturnsNullopt)
{
  node_utils::RefTypeCache cache;
  EXPECT_FALSE(cache.lookup(key(1, 2)).has_value());
}

TEST(RefTypeCacheTests, StoreThenLookupReturnsValue)
{
  node_utils::RefTypeCache cache;
  cache.store(key(1, 2), true);
  cache.store(key(3, 4), false);

  auto a = cache.lookup(key(1, 2));
  auto b = cache.lookup(key(3, 4));
  ASSERT_TRUE(a.has_value());
  ASSERT_TRUE(b.has_value());
  EXPECT_TRUE(*a);
  EXPECT_FALSE(*b);
  EXPECT_FALSE(cache.lookup(key(9, 9)).has_value());
}

TEST(RefTypeCacheTests, FirstWriterWinsOnDuplicateStore)
{
  node_utils::RefTypeCache cache;
  cache.store(key(1, 2), true);
  cache.store(key(1, 2), false);  // idempotent emplace - first value retained
  auto v = cache.lookup(key(1, 2));
  ASSERT_TRUE(v.has_value());
  EXPECT_TRUE(*v);
}

// Concurrent store + lookup across many threads must not corrupt the map. Distinct keys per thread, plus
// cross-thread lookups, mirror the real "find on the strand races emplace on the pool" hazard. With the
// bare unordered_map this is undefined behaviour (TSan-flagged; possible crash/rehash corruption); with
// the synchronised cache every stored key is consistently retrievable.
TEST(RefTypeCacheTests, ConcurrentStoreAndLookupIsSafe)
{
  node_utils::RefTypeCache cache;
  constexpr uint32_t threads = 8;
  constexpr uint32_t perThread = 2000;

  std::vector<std::thread> writers;
  for (uint32_t t = 0; t < threads; ++t)
  {
    writers.emplace_back(
      [&cache, t]
      {
        for (uint32_t i = 0; i < perThread; ++i)
        {
          const auto k = key(t, i);
          cache.store(k, (i & 1u) != 0u);
          // Interleave lookups (some hit this thread's writes, some another thread's) to exercise
          // concurrent find/emplace on the same container.
          (void)cache.lookup(k);
          (void)cache.lookup(key((t + 1u) % threads, i));
        }
      });
  }
  for (auto& w : writers)
  {
    w.join();
  }

  // Every key written must be present with its stored value - no lost/corrupted entries.
  for (uint32_t t = 0; t < threads; ++t)
  {
    for (uint32_t i = 0; i < perThread; ++i)
    {
      auto v = cache.lookup(key(t, i));
      ASSERT_TRUE(v.has_value()) << "missing key (" << t << "," << i << ")";
      EXPECT_EQ(*v, (i & 1u) != 0u);
    }
  }
}
