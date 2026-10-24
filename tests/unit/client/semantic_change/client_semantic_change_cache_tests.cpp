// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the per-Connection DataAccess Property invalidation cache
// (ua::client::detail::SemanticChangeCache, client design section 8.18.2/section 8.18.3, Slice W2a).
//
// The cache is strand-confined: every mutation (register / invalidate / close) self-marshals onto the
// injected strand (ConnectionImpl's), so these tests drain that strand (an io_context run()) before reading
// the strand-private state through SemanticChangeCacheTestAccess. No real ConnectionImpl is involved - the
// cache is constructed directly over a test strand, exactly as ConnectionImpl injects mStrand.
//
// @verifies CL-DA-010
// @relation(CL-DA-010, scope=file)
// @verifies CL-DA-011 (partial): the cache's single invalidation sink (invalidate_async) - the one path both
// @relation(CL-DA-011, scope=file)
//   real triggers route through - is proven here by driving it directly. The `SemanticChangeEventType` event
//   path that FEEDS invalidate_async is W8-deferred (no trigger wiring exists yet), so it is not exercised.
//   // CL-DA-011 event path W8-deferred

#include "ua_node_id.h"
#include "ua_semantic_change_cache.h"
#include "ua_semantic_change_cache_test_access.h"

#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>

#include <gtest/gtest.h>

#include <memory>
#include <vector>

namespace
{

using ua::client::detail::SemanticChangeCache;
using ua::client::detail::SemanticChangeCacheTestAccess;
using ua::client::detail::TypedPropertiesState;

ua::NodeId node(std::uint32_t id)
{
  return ua::NodeId{std::uint16_t{2}, id};
}

struct Fixture
{
  boost::asio::io_context ctx;
  // The single strand injected into the cache - the fixture holds it so a structural test can assert the
  // cache posts onto THIS strand (ConnectionImpl's) rather than fabricating its own (section 8.18.2).
  boost::asio::strand<boost::asio::any_io_executor> strand = boost::asio::make_strand(ctx.get_executor());

  std::shared_ptr<SemanticChangeCache> make_cache()
  {
    return SemanticChangeCache::create(strand, ua::Logger{});
  }

  void run()
  {
    ctx.run();
    ctx.restart();
  }
};

// The cache lives on the injected strand - it must NOT fabricate its own (section 8.18.2 no-private-strand).
TEST(ClientSemanticChangeCache, UsesInjectedStrandNotAPrivateOne)
{
  Fixture f;
  auto cache = f.make_cache();
  EXPECT_EQ(SemanticChangeCacheTestAccess::post_strand(*cache), f.strand)
    << "the cache must post onto ConnectionImpl's injected strand, not a fabricated one";
}

// The observer hook is installed at construction (the lazy cache self-installs its on_semantic_change
// subscription sentinel; the real subscription lands in W8) - @verifies CL-DA-010.
TEST(ClientSemanticChangeCache, HookInstalledAtConstruction)
{
  Fixture f;
  auto cache = f.make_cache();
  EXPECT_TRUE(SemanticChangeCacheTestAccess::hook_installed(*cache));
}

// register -> invalidate flips the registered handle-state's invalidated flag - @verifies CL-DA-010.
TEST(ClientSemanticChangeCache, RegisterThenInvalidateFlipsInvalidatedFlag)
{
  Fixture f;
  auto cache = f.make_cache();
  auto state = std::make_shared<TypedPropertiesState>();

  auto ticket = cache->register_state(node(1), state);
  f.run();  // drain the marshalled mEntries insertion
  EXPECT_TRUE(ticket.registered());
  EXPECT_EQ(ticket.node_id(), node(1));
  ASSERT_EQ(SemanticChangeCacheTestAccess::entry_count(*cache), 1U);
  EXPECT_TRUE(SemanticChangeCacheTestAccess::entry_is_live(*cache, node(1)));
  EXPECT_FALSE(state->invalidated.load());

  cache->invalidate_async({node(1)});
  f.run();

  EXPECT_TRUE(state->invalidated.load()) << "the SemanticsChanged invalidation must flip the handle's flag";
  // The entry is retained (still live) - it is re-used by the handle's next read.
  EXPECT_EQ(SemanticChangeCacheTestAccess::entry_count(*cache), 1U);
  EXPECT_TRUE(SemanticChangeCacheTestAccess::entry_is_live(*cache, node(1)));
}

// Invalidating an UNregistered NodeId is a clean no-op (no crash, no entry created) - @verifies CL-DA-010.
TEST(ClientSemanticChangeCache, InvalidateUnregisteredNodeIsNoOp)
{
  Fixture f;
  auto cache = f.make_cache();

  cache->invalidate_async({node(42), node(7)});
  f.run();

  EXPECT_EQ(SemanticChangeCacheTestAccess::entry_count(*cache), 0U);
}

// A dropped handle-state (its Ticket lives on the state, so the handle drop drops both) leaves the entry's
// weak ref expired; the next invalidate walk prunes it lazily - @verifies CL-DA-010.
TEST(ClientSemanticChangeCache, InvalidateExpiredEntryPrunesIt)
{
  Fixture f;
  auto cache = f.make_cache();
  auto state = std::make_shared<TypedPropertiesState>();

  auto ticket = cache->register_state(node(5), state);
  f.run();
  ASSERT_EQ(SemanticChangeCacheTestAccess::entry_count(*cache), 1U);

  // Drop the handle-state (what a dropped handle does): the weak entry now dangles.
  state.reset();
  EXPECT_TRUE(SemanticChangeCacheTestAccess::has_entry(*cache, node(5)));
  EXPECT_FALSE(SemanticChangeCacheTestAccess::entry_is_live(*cache, node(5)));

  cache->invalidate_async({node(5)});
  f.run();

  EXPECT_EQ(SemanticChangeCacheTestAccess::entry_count(*cache), 0U) << "the expired weak entry is pruned";
  EXPECT_FALSE(SemanticChangeCacheTestAccess::has_entry(*cache, node(5)));
}

// close() drops the observer hook and clears every entry (Connection close, section 8.18.3).
// @verifies CL-DA-010
TEST(ClientSemanticChangeCache, CloseDropsHookAndClearsEntries)
{
  Fixture f;
  auto cache = f.make_cache();
  auto stateA = std::make_shared<TypedPropertiesState>();
  auto stateB = std::make_shared<TypedPropertiesState>();

  auto ticketA = cache->register_state(node(1), stateA);
  auto ticketB = cache->register_state(node(2), stateB);
  f.run();
  ASSERT_EQ(SemanticChangeCacheTestAccess::entry_count(*cache), 2U);
  ASSERT_TRUE(SemanticChangeCacheTestAccess::hook_installed(*cache));

  cache->close();
  f.run();

  EXPECT_EQ(SemanticChangeCacheTestAccess::entry_count(*cache), 0U);
  EXPECT_FALSE(SemanticChangeCacheTestAccess::hook_installed(*cache))
    << "close must drop the on_semantic_change hook (section 8.18.3)";
}

// The cache outliving a handle: two handles over the SAME NodeId - the later registration supersedes; both
// states observe the flag only if still registered - @verifies CL-DA-011 (single invalidation path).
TEST(ClientSemanticChangeCache, ReregisterSameNodeSupersedesPriorEntry)
{
  Fixture f;
  auto cache = f.make_cache();
  auto first = std::make_shared<TypedPropertiesState>();
  auto second = std::make_shared<TypedPropertiesState>();

  auto ticketFirst = cache->register_state(node(9), first);
  auto ticketSecond = cache->register_state(node(9), second);  // supersedes the first entry
  f.run();
  EXPECT_EQ(SemanticChangeCacheTestAccess::entry_count(*cache), 1U);

  cache->invalidate_async({node(9)});
  f.run();

  EXPECT_FALSE(first->invalidated.load()) << "the superseded state is no longer the registered entry";
  EXPECT_TRUE(second->invalidated.load()) << "the current registration is invalidated";
}

// A cache-gone self-marshalled mutation is a clean no-op (the weak-captured cache no longer exists) - the
// post_borrowing weak guard drops the work. @verifies CL-DA-010.
TEST(ClientSemanticChangeCache, MutationAfterCacheDestroyedIsSafeNoOp)
{
  Fixture f;
  auto state = std::make_shared<TypedPropertiesState>();
  {
    auto cache = f.make_cache();
    cache->invalidate_async({node(1)});  // posted, but the cache is destroyed before the strand drains
  }
  // The cache is gone; draining runs the weak-guarded posted work, which no-ops without touching freed state.
  EXPECT_NO_THROW(f.run());
  EXPECT_FALSE(state->invalidated.load());
}

// M2 - register opportunistically prunes dead weak entries, so mEntries cannot grow unboundedly when handles
// are dropped without their NodeId ever being invalidated. Without the sweep an entry is only removed when
// its own NodeId is later invalidated, so a Connection that churns short-lived handles would leak entries
// forever.
// @verifies CL-DA-010.
// @relation(CL-DA-010, scope=function)
TEST(ClientSemanticChangeCache, RegisterPrunesExpiredEntriesToBoundGrowth)
{
  Fixture f;
  auto cache = f.make_cache();

  // Register many handles over distinct NodeIds and DROP each immediately (no invalidate ever names them): by
  // drain time every one of these weak entries has expired.
  for (std::uint32_t i = 0; i < 100; ++i)
  {
    auto state = std::make_shared<TypedPropertiesState>();
    auto ticket = cache->register_state(node(1000 + i), state);  // ticket + state dropped at loop end
  }
  f.run();

  // Now register a small LIVE batch (states retained); each register sweeps out the dangling entries.
  std::vector<std::shared_ptr<TypedPropertiesState>> live;
  for (std::uint32_t i = 0; i < 5; ++i)
  {
    auto state = std::make_shared<TypedPropertiesState>();
    auto ticket = cache->register_state(node(2000 + i), state);
    live.push_back(std::move(state));
  }
  f.run();

  // Only the 5 live entries remain - the 100 dangling ones were pruned. Without the sweep mEntries would hold
  // all 105.
  EXPECT_EQ(SemanticChangeCacheTestAccess::entry_count(*cache), 5U)
    << "dead weak entries must be pruned opportunistically on register (bounded growth)";
}

}  // namespace
