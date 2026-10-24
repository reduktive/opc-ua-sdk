// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the ua::client::BrowseCursor read-surface Browse cache wiring (client design section 8.7,
// Slice 2a). The BrowseCursor consults the per-Connection AddressSpaceCache's Browse sub-cache on its INITIAL
// browse (first page only): a cache HIT serves the cached references without a wire Browse; a MISS issues the
// wire Browse and installs the single-page result. The consult/install is caller-on-strand, so the cursor
// (which runs on the executor) hops onto the connection strand for the lookup/install and hops back to the
// executor to continue the walk. A DISABLED / unwired cache is a strict pass-through no-op.
//
// Falsifiability: a cursor that never consults the cache fails BrowseServedFromCacheOnSecondIdenticalBrowse
// and CacheHitIteratesAllCachedReferencesInOrder; one that keys the cache without includeSubtypes fails
// IncludeSubtypesDistinguishesCacheKey (wrong-shape hit); one that ignores model-change invalidation fails
// ReferenceDeletedInvalidationForcesFreshBrowse; one that caches multi-page results fails
// MultiPageResultIsNotCached.

#include "ua_browse_cursor.h"

#include "fake_connection_ops.h"

#include "ua_address_space_cache.h"
#include "ua_address_space_cache_policy.h"
#include "ua_address_space_cache_test_access.h"
#include "ua_browse_cursor_test_access.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_reference_description.h"
#include "ua_status.h"

#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace
{

using ua::client::AddressSpaceCachePolicy;
using ua::client::BrowseCursor;
using ua::client::BrowseOptions;
using ua::client::detail::AddressSpaceCache;
using ua::client::detail::AddressSpaceCacheTestAccess;
using ua::client::detail::BrowseCursorTestAccess;
using ua::client::detail::ModelChange;
using ua::client::detail::ModelChangeNotification;
using ua::client::detail::ModelChangeVerb;
using ua::test_helpers::FakeWireOps;

ua::NodeId node(std::uint32_t identifier)
{
  return ua::NodeId{0, identifier};
}

ua::ReferenceDescription make_reference(std::uint32_t targetIdentifier)
{
  ua::ReferenceDescription reference;
  reference.node_id().node_id() = node(targetIdentifier);
  reference.is_forward() = true;
  return reference;
}

struct Fixture
{
  boost::asio::io_context ctx;
  // The single strand injected into BOTH the cache and each cursor: the caller-on-strand cache lookups/
  // installs and the cache's own strand-run invalidation share one serialization domain.
  boost::asio::strand<boost::asio::any_io_executor> strand = boost::asio::make_strand(ctx.get_executor());
  std::shared_ptr<FakeWireOps> wireOps = std::make_shared<FakeWireOps>();
  std::shared_ptr<AddressSpaceCache> cache = make_cache(/*enabled=*/true);

  std::shared_ptr<AddressSpaceCache> make_cache(bool enabled)
  {
    AddressSpaceCachePolicy policy;
    policy.enabled = enabled;
    return AddressSpaceCache::create(strand, wireOps, policy, ua::Logger{});
  }

  BrowseCursor make(
    ua::NodeId start = node(85), BrowseOptions options = {}, std::weak_ptr<AddressSpaceCache> wired = {})
  {
    return BrowseCursorTestAccess::make_with_cache(
      wireOps, ctx.get_executor(), std::move(start), std::move(options), std::move(wired), strand);
  }

  // A cursor wired to the fixture's enabled cache.
  BrowseCursor make_cached(ua::NodeId start = node(85), BrowseOptions options = {})
  {
    return make(std::move(start), std::move(options), cache);
  }

  ua::Result<BrowseCursor::Entry> next(BrowseCursor& cursor)
  {
    std::optional<ua::Result<BrowseCursor::Entry>> captured;
    cursor.next_async([&captured](ua::Result<BrowseCursor::Entry> result) { captured = std::move(result); });
    ctx.run();
    ctx.restart();
    return std::move(captured.value());
  }
};

// (a) The required wiring: two identical browses of the same node with the cache enabled - the SECOND is
// served entirely from cache with NO wire Browse.
TEST(BrowseCursorCache, BrowseServedFromCacheOnSecondIdenticalBrowse)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{make_reference(1), make_reference(2)}, ua::ContinuationPoint{}, {}});

  auto first = f.make_cached(node(85));
  auto r1 = f.next(first);  // MISS: wire Browse + install the single page
  ASSERT_TRUE(r1.is_good());
  EXPECT_EQ(r1.value().targetNodeId, node(1));
  ASSERT_EQ(f.wireOps->browseRequests.size(), 1u) << "the first browse hits the wire";
  ASSERT_EQ(AddressSpaceCacheTestAccess::browse_count(*f.cache), 1u) << "and installs the single-page result";

  auto second = f.make_cached(node(85));
  auto r2 = f.next(second);  // HIT: served from cache, no wire Browse
  ASSERT_TRUE(r2.is_good());
  EXPECT_EQ(r2.value().targetNodeId, node(1)) << "the cached first entry is served";
  EXPECT_EQ(f.wireOps->browseRequests.size(), 1u)
    << "the second identical browse is served from cache - no wire Browse";
}

// (f) A cache HIT preserves page ordering: every cached reference is yielded in order, then the walk is
// exhausted (no continuation point on a cached single page -> close/destructor are clean no-ops).
TEST(BrowseCursorCache, CacheHitIteratesAllCachedReferencesInOrder)
{
  Fixture f;
  f.wireOps->browsePages.push_back(
    {{make_reference(1), make_reference(2), make_reference(3)}, ua::ContinuationPoint{}, {}});

  auto primer = f.make_cached(node(85));
  (void)f.next(primer);  // install the 3-reference page
  ASSERT_EQ(AddressSpaceCacheTestAccess::browse_count(*f.cache), 1u);

  auto cursor = f.make_cached(node(85));
  auto e1 = f.next(cursor);
  ASSERT_TRUE(e1.is_good());
  EXPECT_EQ(e1.value().targetNodeId, node(1));
  auto e2 = f.next(cursor);
  ASSERT_TRUE(e2.is_good());
  EXPECT_EQ(e2.value().targetNodeId, node(2));
  auto e3 = f.next(cursor);
  ASSERT_TRUE(e3.is_good());
  EXPECT_EQ(e3.value().targetNodeId, node(3)) << "cached references are yielded in order";
  auto done = f.next(cursor);
  EXPECT_TRUE(done.is_bad());
  EXPECT_EQ(done.status_code(), ua::StatusCode{ua::Status::BadNoData})
    << "a cached single page then exhausts";
  EXPECT_FALSE(cursor.has_more());
  EXPECT_EQ(f.wireOps->browseRequests.size(), 1u) << "only the primer hit the wire";
}

// (b) section 3.1 pre-empt: two browses of the same node differing ONLY in includeSubtypes must BOTH hit the
// wire - includeSubtypes is part of the cache key (a subtype walk is a strict superset, so a false-page must
// not satisfy a true-walk). Falsifier: a key omitting includeSubtypes serves browse #2 from cache (count 1).
TEST(BrowseCursorCache, IncludeSubtypesDistinguishesCacheKey)
{
  Fixture f;
  f.wireOps->browsePages.push_back(
    {{make_reference(1)}, ua::ContinuationPoint{}, {}});  // includeSubtypes=true
  f.wireOps->browsePages.push_back(
    {{make_reference(2)}, ua::ContinuationPoint{}, {}});  // includeSubtypes=false

  BrowseOptions optsTrue;
  optsTrue.includeSubtypes = true;
  auto c1 = f.make_cached(node(85), optsTrue);
  (void)f.next(c1);
  ASSERT_EQ(f.wireOps->browseRequests.size(), 1u);

  BrowseOptions optsFalse;
  optsFalse.includeSubtypes = false;
  auto c2 = f.make_cached(node(85), optsFalse);
  auto r2 = f.next(c2);
  ASSERT_TRUE(r2.is_good());
  EXPECT_EQ(f.wireOps->browseRequests.size(), 2u)
    << "a browse differing only in includeSubtypes must not hit the cache (wrong-shape guard)";
  EXPECT_EQ(r2.value().targetNodeId, node(2)) << "browse #2 served its own wire page, not the cached one";
}

// @verifies CL-VIEW-008
// @relation(CL-VIEW-008, scope=function)
TEST(BrowseCursorCache, ViewTimestampBypassesDefaultViewCache)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{make_reference(1)}, ua::ContinuationPoint{}, {}});
  f.wireOps->browsePages.push_back({{make_reference(2)}, ua::ContinuationPoint{}, {}});

  auto primer = f.make_cached(node(85));
  ASSERT_TRUE(f.next(primer).is_good());
  ASSERT_EQ(AddressSpaceCacheTestAccess::browse_count(*f.cache), 1u);

  BrowseOptions options;
  options.viewTimestamp = ua::DateTime{2025, 1, 2, 3, 4, 5.0};
  auto selectedView = f.make_cached(node(85), options);
  auto result = f.next(selectedView);

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().targetNodeId, node(2));
  ASSERT_EQ(f.wireOps->browseRequests.size(), 2u);
  EXPECT_EQ(f.wireOps->browseRequests.back().view().timestamp(), *options.viewTimestamp);
  EXPECT_EQ(AddressSpaceCacheTestAccess::browse_count(*f.cache), 1u)
    << "a view-selected response must not replace or extend the default-view cache";
}

// @verifies CL-VIEW-008
// @relation(CL-VIEW-008, scope=function)
TEST(BrowseCursorCache, ViewVersionBypassesDefaultViewCache)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{make_reference(1)}, ua::ContinuationPoint{}, {}});
  f.wireOps->browsePages.push_back({{make_reference(2)}, ua::ContinuationPoint{}, {}});

  auto primer = f.make_cached(node(85));
  ASSERT_TRUE(f.next(primer).is_good());
  ASSERT_EQ(AddressSpaceCacheTestAccess::browse_count(*f.cache), 1u);

  BrowseOptions options;
  options.viewVersion = 7;
  auto selectedView = f.make_cached(node(85), options);
  auto result = f.next(selectedView);

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().targetNodeId, node(2));
  ASSERT_EQ(f.wireOps->browseRequests.size(), 2u);
  EXPECT_EQ(f.wireOps->browseRequests.back().view().view_version(), *options.viewVersion);
  EXPECT_EQ(AddressSpaceCacheTestAccess::browse_count(*f.cache), 1u)
    << "a view-selected response must not replace or extend the default-view cache";
}

// (d) Model-change invalidation: a GeneralModelChange ReferenceDeleted for X drops X's cached browse page, so
// the next Browse(X) re-issues a wire Browse.
TEST(BrowseCursorCache, ReferenceDeletedInvalidationForcesFreshBrowse)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{make_reference(1)}, ua::ContinuationPoint{}, {}});  // browse #1
  f.wireOps->browsePages.push_back(
    {{make_reference(1)}, ua::ContinuationPoint{}, {}});  // browse #2 (post-invalidate)

  auto c1 = f.make_cached(node(85));
  (void)f.next(c1);
  ASSERT_EQ(f.wireOps->browseRequests.size(), 1u);
  ASSERT_EQ(AddressSpaceCacheTestAccess::browse_count(*f.cache), 1u);

  ModelChangeNotification notification;
  notification.kind = ModelChangeNotification::Kind::General;
  notification.changes.push_back(ModelChange{node(85), ModelChangeVerb::ReferenceDeleted});
  f.cache->on_model_change_async(notification, [] {});
  f.ctx.run();
  f.ctx.restart();
  EXPECT_EQ(AddressSpaceCacheTestAccess::browse_count(*f.cache), 0u)
    << "ReferenceDeleted for X drops X's cached browse page";

  auto c2 = f.make_cached(node(85));
  auto r2 = f.next(c2);
  ASSERT_TRUE(r2.is_good());
  EXPECT_EQ(f.wireOps->browseRequests.size(), 2u) << "the invalidated page forces a fresh wire Browse";
}

// (e) Single-page-only (v1): a browse whose first page carries a continuation point (a multi-page walk) is
// NOT installed - only whole single-page results are cached.
TEST(BrowseCursorCache, MultiPageResultIsNotCached)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{make_reference(1)}, ua::ContinuationPoint{0x01}, {}});  // page 1 + CP
  f.wireOps->browsePages.push_back({{make_reference(2)}, ua::ContinuationPoint{}, {}});  // page 2, no CP

  auto cursor = f.make_cached(node(85));
  auto r1 =
    f.next(cursor);  // initial browse returns a page WITH a continuation point -> multi-page -> no install
  ASSERT_TRUE(r1.is_good());
  EXPECT_EQ(AddressSpaceCacheTestAccess::browse_count(*f.cache), 0u)
    << "a continuation-point-bearing (multi-page) result must not be cached (single-page-only v1)";
}

// (e') Server-flagged-incomplete is NOT cached (CL-VIEW-005): a page whose per-node status is Good_MoreData
// with an EMPTY continuation point is non-conformant - the server flagged "more results" it did not deliver.
// Such a page must NOT be installed as a whole single page (a coarse is_good() install gate would poison the
// cache with a truncated page and suppress the advisory on every subsequent cache hit). The install gate
// keys on the EXACT plain-Good status, so a Good_MoreData page is served once but never cached; a second
// identical browse re-hits the wire (and re-emits the advisory).
TEST(BrowseCursorCache, GoodMoreDataWithoutContinuationPointIsNotCached)
{
  Fixture f;
  // Two identical scripted pages: references + empty CP, but the per-node status claims Good_MoreData.
  f.wireOps->browsePages.push_back(
    {{make_reference(1)}, ua::ContinuationPoint{}, ua::StatusCode{ua::Status::GoodMoreData}});
  f.wireOps->browsePages.push_back(
    {{make_reference(1)}, ua::ContinuationPoint{}, ua::StatusCode{ua::Status::GoodMoreData}});

  auto first = f.make_cached(node(85));
  auto r1 = f.next(first);  // MISS: wire Browse; the flagged-incomplete page must NOT be installed
  ASSERT_TRUE(r1.is_good());
  EXPECT_EQ(r1.value().targetNodeId, node(1));
  EXPECT_EQ(AddressSpaceCacheTestAccess::browse_count(*f.cache), 0u)
    << "a Good_MoreData page with an empty continuation point is server-flagged-incomplete and must not be "
       "cached";

  auto second = f.make_cached(node(85));
  auto r2 = f.next(second);  // no cached entry -> re-hits the wire
  ASSERT_TRUE(r2.is_good());
  EXPECT_EQ(f.wireOps->browseRequests.size(), 2u)
    << "the flagged-incomplete page was not cached, so the second identical browse re-hits the wire";
}

// (c) Strict no-op - the production disabled default wires NO cache into the cursor: every browse hits the
// wire and nothing is installed (byte-for-byte the pre-cache behaviour).
TEST(BrowseCursorCache, NoCacheWiredEveryBrowseHitsWire)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{make_reference(1)}, ua::ContinuationPoint{}, {}});
  f.wireOps->browsePages.push_back({{make_reference(1)}, ua::ContinuationPoint{}, {}});

  auto c1 = f.make(node(85), {}, /*wired=*/{});  // no cache weak wired
  (void)f.next(c1);
  auto c2 = f.make(node(85), {}, /*wired=*/{});
  (void)f.next(c2);
  EXPECT_EQ(f.wireOps->browseRequests.size(), 2u) << "with no cache wired every browse hits the wire";
  EXPECT_EQ(AddressSpaceCacheTestAccess::browse_count(*f.cache), 0u) << "and nothing is installed";
}

// (c') Strict no-op - a DISABLED cache wired into the cursor serves nothing and installs nothing (lookup /
// install pass through when !enabled, and the cursor takes no strand hop).
TEST(BrowseCursorCache, DisabledCacheEveryBrowseHitsWireAndInstallsNothing)
{
  Fixture f;
  auto disabled = f.make_cache(/*enabled=*/false);
  f.wireOps->browsePages.push_back({{make_reference(1)}, ua::ContinuationPoint{}, {}});
  f.wireOps->browsePages.push_back({{make_reference(1)}, ua::ContinuationPoint{}, {}});

  auto c1 = f.make(node(85), {}, disabled);
  (void)f.next(c1);
  auto c2 = f.make(node(85), {}, disabled);
  (void)f.next(c2);
  EXPECT_EQ(f.wireOps->browseRequests.size(), 2u)
    << "a disabled cache serves nothing - every browse hits the wire";
  EXPECT_EQ(AddressSpaceCacheTestAccess::browse_count(*disabled), 0u) << "and nothing is installed";
}

}  // namespace
