// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::async::Registry. Covers the four-operation contract
// (insert / lookup / remove / enumerate), try_emplace-style duplicate
// semantics, ownership behaviour of the returned shared_ptrs, and a small
// concurrent-stress exercise that verifies the shared_mutex-guarded API is
// sound under multi-thread access (best validated under TSan).

#include "ua_registry.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace
{

struct Entry
{
  int value;
};

using IntRegistry = ua::async::Registry<int, Entry>;
using StringRegistry = ua::async::Registry<std::string, Entry>;

}  // namespace

TEST(Registry, LookupOnEmptyRegistryReturnsNull)
{
  IntRegistry registry;
  EXPECT_EQ(registry.lookup(1), nullptr);
}

TEST(Registry, EnumerateOnEmptyRegistryReturnsEmptyVector)
{
  IntRegistry registry;
  EXPECT_TRUE(registry.enumerate().empty());
}

TEST(Registry, InsertReturnsTheInsertedEntryWhenIdIsNew)
{
  IntRegistry registry;
  auto entry = std::make_shared<Entry>(Entry{42});
  auto stored = registry.insert(7, entry);
  EXPECT_EQ(stored, entry);
}

TEST(Registry, LookupReturnsInsertedEntry)
{
  IntRegistry registry;
  auto entry = std::make_shared<Entry>(Entry{42});
  registry.insert(7, entry);

  auto retrieved = registry.lookup(7);
  ASSERT_NE(retrieved, nullptr);
  EXPECT_EQ(retrieved, entry);
  EXPECT_EQ(retrieved->value, 42);
}

TEST(Registry, InsertWithExistingIdRetainsOriginalAndDiscardsNew)
{
  IntRegistry registry;
  auto first = std::make_shared<Entry>(Entry{1});
  auto second = std::make_shared<Entry>(Entry{2});

  auto firstResult = registry.insert(7, first);
  EXPECT_EQ(firstResult, first);

  auto secondResult = registry.insert(7, second);
  // try_emplace semantics: existing entry is retained, new one is discarded.
  EXPECT_EQ(secondResult, first);
  EXPECT_NE(secondResult, second);

  // Lookup confirms the original entry is still in place.
  EXPECT_EQ(registry.lookup(7), first);
}

TEST(Registry, RemoveOfPresentIdMakesLookupReturnNull)
{
  IntRegistry registry;
  registry.insert(7, std::make_shared<Entry>(Entry{42}));
  registry.remove(7);
  EXPECT_EQ(registry.lookup(7), nullptr);
}

TEST(Registry, RemoveOfAbsentIdIsNoOp)
{
  IntRegistry registry;
  registry.remove(7);  // must not throw or assert
  EXPECT_EQ(registry.lookup(7), nullptr);
}

TEST(Registry, RemoveDoesNotAffectOtherIds)
{
  IntRegistry registry;
  auto a = std::make_shared<Entry>(Entry{1});
  auto b = std::make_shared<Entry>(Entry{2});
  registry.insert(1, a);
  registry.insert(2, b);

  registry.remove(1);
  EXPECT_EQ(registry.lookup(1), nullptr);
  EXPECT_EQ(registry.lookup(2), b);
}

TEST(Registry, EnumerateContainsAllInsertedEntries)
{
  IntRegistry registry;
  auto a = std::make_shared<Entry>(Entry{1});
  auto b = std::make_shared<Entry>(Entry{2});
  auto c = std::make_shared<Entry>(Entry{3});
  registry.insert(1, a);
  registry.insert(2, b);
  registry.insert(3, c);

  auto snapshot = registry.enumerate();
  ASSERT_EQ(snapshot.size(), 3u);

  std::unordered_set<Entry*> seen;
  for (const auto& entry : snapshot)
    seen.insert(entry.get());
  EXPECT_EQ(seen.count(a.get()), 1u);
  EXPECT_EQ(seen.count(b.get()), 1u);
  EXPECT_EQ(seen.count(c.get()), 1u);
}

TEST(Registry, EnumerateReflectsRemovals)
{
  IntRegistry registry;
  registry.insert(1, std::make_shared<Entry>(Entry{1}));
  registry.insert(2, std::make_shared<Entry>(Entry{2}));
  registry.insert(3, std::make_shared<Entry>(Entry{3}));
  registry.remove(2);

  auto snapshot = registry.enumerate();
  EXPECT_EQ(snapshot.size(), 2u);
}

TEST(Registry, EnumerateReturnsSnapshotIndependentOfFutureMutations)
{
  IntRegistry registry;
  registry.insert(1, std::make_shared<Entry>(Entry{1}));
  registry.insert(2, std::make_shared<Entry>(Entry{2}));

  auto snapshot = registry.enumerate();
  ASSERT_EQ(snapshot.size(), 2u);

  // Mutating the registry after the snapshot must not affect the snapshot.
  registry.remove(1);
  registry.insert(3, std::make_shared<Entry>(Entry{3}));

  EXPECT_EQ(snapshot.size(), 2u);
}

TEST(Registry, EnumerateSharesOwnershipWithEntriesInRegistry)
{
  IntRegistry registry;
  auto entry = std::make_shared<Entry>(Entry{42});
  registry.insert(7, entry);

  auto snapshot = registry.enumerate();
  ASSERT_EQ(snapshot.size(), 1u);

  // The registry, the original local, and the snapshot all share ownership.
  EXPECT_EQ(entry.use_count(), 3);

  // Removing from the registry drops one reference.
  registry.remove(7);
  EXPECT_EQ(entry.use_count(), 2);

  // Dropping the snapshot drops another.
  snapshot.clear();
  EXPECT_EQ(entry.use_count(), 1);
}

TEST(Registry, WorksWithNonTriviallyCopyableId)
{
  StringRegistry registry;
  auto entry = std::make_shared<Entry>(Entry{99});
  registry.insert("abc", entry);
  EXPECT_EQ(registry.lookup("abc"), entry);
  EXPECT_EQ(registry.lookup("missing"), nullptr);
  registry.remove("abc");
  EXPECT_EQ(registry.lookup("abc"), nullptr);
}

// Concurrent stress: mixed insert/lookup/remove/enumerate from multiple
// threads. The contract verified here is that the API is internally
// synchronised - there must be no data race on mEntries. Best run under TSan
// where a missing lock would surface as a warning. Without TSan, this test is
// still useful for stressing reentrancy and exercising shared_lock contention.
TEST(Registry, ConcurrentMixedAccessIsSafe)
{
  IntRegistry registry;
  constexpr int threadCount = 8;
  constexpr int iterations = 2000;
  constexpr int keyspace = 64;

  std::atomic<bool> start{false};
  std::vector<std::thread> threads;
  threads.reserve(threadCount);

  for (int t = 0; t < threadCount; ++t)
  {
    threads.emplace_back(
      [&registry, &start, t]
      {
        while (!start.load(std::memory_order_acquire))
        {
          std::this_thread::yield();
        }
        for (int i = 0; i < iterations; ++i)
        {
          const int key = (t * 31 + i) % keyspace;
          const int op = i & 0x3;
          switch (op)
          {
          case 0:
            registry.insert(key, std::make_shared<Entry>(Entry{i}));
            break;
          case 1:
            (void)registry.lookup(key);
            break;
          case 2:
            registry.remove(key);
            break;
          case 3:
            (void)registry.enumerate();
            break;
          }
        }
      });
  }

  start.store(true, std::memory_order_release);
  for (auto& th : threads)
    th.join();

  // Final state is unspecified; the test passes if no UB / data race occurred.
  // Exercise the API one last time post-join to confirm the registry is still
  // usable.
  registry.insert(keyspace, std::make_shared<Entry>(Entry{0}));
  EXPECT_NE(registry.lookup(keyspace), nullptr);
}
