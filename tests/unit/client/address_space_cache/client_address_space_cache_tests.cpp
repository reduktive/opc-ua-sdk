// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::detail::AddressSpaceCache (client design section 8.7): the optional
// per-Connection client-side cache. Covers alias substitution (CL-VIEW-009), batched UnregisterNodes
// eviction/release (CL-VIEW-010), Session-scoped invalidation with the ratified retention split (CL-VIEW-011
// / section 9.8 override 3), model-change invalidation (CL-EVT-003), the browse-result cache, the disabled
// no-op, and the section 9.8.3 weak-owner UAF guard (an async completion after the owner is gone must not
// dereference it).
//
// Falsifiability: a cache that never substitutes fails AliasSubstitutionHitReturnsRegistered; one that
// never evicts fails AliasEvictionQueuesUnregister; one that clears userAccessLevel-retaining attributes
// fails SessionChangeSameServerRetainsIntrinsic...; one that derefs a gone owner crashes
// UnregisterCompletionAfterCacheGoneDoesNotDeref.

#include "ua_address_space_cache.h"

#include "fake_connection_ops.h"

#include "ua_address_space_cache_test_access.h"
#include "ua_log_entry.h"
#include "ua_log_level.h"
#include "ua_log_sink.h"
#include "ua_logger.h"
#include "ua_node_id.h"

#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace
{

using ua::client::AddressSpaceCachePolicy;
using ua::client::detail::AddressSpaceCache;
using ua::client::detail::AddressSpaceCacheTestAccess;
using ua::client::detail::AttributeEntry;
using ua::client::detail::BrowseEntry;
using ua::client::detail::CachedBrowseKey;
using ua::client::detail::ModelChange;
using ua::client::detail::ModelChangeNotification;
using ua::client::detail::ModelChangeVerb;
using ua::test_helpers::FakeWireOps;

struct RecordingLogSink : public ua::LogSink
{
  std::vector<std::string> messages;

  void log(const ua::LogEntry& entry) override
  {
    messages.push_back(entry.message);
  }

  [[nodiscard]] bool has_message_containing(std::string_view needle) const
  {
    for (const auto& message : messages)
    {
      if (message.find(needle) != std::string::npos)
      {
        return true;
      }
    }
    return false;
  }
};

ua::NodeId node(std::uint32_t identifier)
{
  return ua::NodeId{0, identifier};
}

struct Fixture
{
  boost::asio::io_context ctx;
  // The single strand injected into the cache - the fixture holds it so a structural test can assert the
  // cache posts onto THIS strand (ConnectionImpl's) rather than fabricating its own (section 8.7
  // no-private-strand).
  boost::asio::strand<boost::asio::any_io_executor> strand = boost::asio::make_strand(ctx.get_executor());
  std::shared_ptr<FakeWireOps> wireOps = std::make_shared<FakeWireOps>();
  std::shared_ptr<RecordingLogSink> logSink = std::make_shared<RecordingLogSink>();

  AddressSpaceCachePolicy policy()
  {
    AddressSpaceCachePolicy value;
    value.enabled = true;
    return value;
  }

  std::shared_ptr<AddressSpaceCache> make(AddressSpaceCachePolicy value)
  {
    auto level = std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Trace);
    return AddressSpaceCache::create(
      strand, wireOps, value, ua::Logger{logSink, level, "address_space_cache_test"});
  }
};

// ---- Alias substitution (CL-VIEW-009) ----

// @verifies CL-VIEW-009
// @relation(CL-VIEW-009, scope=function)
TEST(AddressSpaceCache, AliasSubstitutionHitReturnsRegistered)
{
  Fixture f;
  auto cache = f.make(f.policy());
  cache->install_aliases({node(100)}, {node(9100)});
  EXPECT_EQ(cache->lookup_for_request(node(100)), node(9100));
}

// @verifies CL-VIEW-009
// @relation(CL-VIEW-009, scope=function)
TEST(AddressSpaceCache, AliasMissReturnsOriginalVerbatim)
{
  Fixture f;
  auto cache = f.make(f.policy());
  EXPECT_EQ(cache->lookup_for_request(node(200)), node(200));
}

// @verifies CL-VIEW-009
// @relation(CL-VIEW-009, scope=function)
TEST(AddressSpaceCache, StaleGenerationAliasSilentlyDropped)
{
  Fixture f;
  auto cache = f.make(f.policy());
  cache->install_aliases({node(100)}, {node(9100)});
  // Defence-in-depth: a generation bump without an alias clear (a missed on_session_changed) must drop the
  // now-stale entry on lookup and return the original.
  AddressSpaceCacheTestAccess::set_session_generation(*cache, 7);
  EXPECT_EQ(cache->lookup_for_request(node(100)), node(100));
  EXPECT_EQ(AddressSpaceCacheTestAccess::alias_count(*cache), 0u);
}

// ---- Disabled no-op ----

// @verifies CL-MULTI-001
// @relation(CL-MULTI-001, scope=function)
TEST(AddressSpaceCache, DisabledPolicyIsCleanNoOp)
{
  Fixture f;
  AddressSpaceCachePolicy disabled;  // enabled defaults to false
  auto cache = f.make(disabled);
  EXPECT_FALSE(cache->enabled());
  cache->install_aliases({node(100)}, {node(9100)});
  cache->install_attributes(node(100), AttributeEntry{});
  // Nothing cached: lookups pass through / miss, so no substitution and no RegisterNodes semantics.
  EXPECT_EQ(cache->lookup_for_request(node(100)), node(100));
  EXPECT_EQ(AddressSpaceCacheTestAccess::alias_count(*cache), 0u);
  EXPECT_FALSE(cache->lookup_attributes(node(100)).has_value());
}

// ---- Eviction + batched UnregisterNodes (CL-VIEW-010) ----

// @verifies CL-VIEW-010
// @relation(CL-VIEW-010, scope=function)
TEST(AddressSpaceCache, AliasEvictionQueuesUnregisterOfServerHandle)
{
  Fixture f;
  auto policy = f.policy();
  policy.maxRegisteredNodes = 1;
  policy.unregisterBatchSize = 32;  // above the single eviction, so it stays pending (no immediate flush)
  auto cache = f.make(policy);
  cache->install_aliases({node(100)}, {node(9100)});
  cache->install_aliases({node(101)}, {node(9101)});  // evicts node(100) -> queue its server handle 9100
  const auto pending = AddressSpaceCacheTestAccess::pending_unregister(*cache);
  ASSERT_EQ(pending.size(), 1u);
  EXPECT_EQ(pending[0], node(9100));
  EXPECT_TRUE(f.wireOps->unregisterRequests.empty()) << "below the batch threshold: no flush yet";
}

// @verifies CL-VIEW-010
// @relation(CL-VIEW-010, scope=function)
TEST(AddressSpaceCache, EvictionBatchThresholdFiresImmediateUnregister)
{
  Fixture f;
  auto policy = f.policy();
  policy.maxRegisteredNodes = 1;
  policy.unregisterBatchSize = 1;  // one eviction hits the threshold -> flush immediately
  auto cache = f.make(policy);
  cache->install_aliases({node(100)}, {node(9100)});
  cache->install_aliases({node(101)}, {node(9101)});  // evicts 100 -> threshold -> UnregisterNodes([9100])
  ASSERT_EQ(f.wireOps->unregisterRequests.size(), 1u);
  ASSERT_EQ(f.wireOps->unregisterRequests[0].nodes_to_unregister().size(), 1u);
  EXPECT_EQ(f.wireOps->unregisterRequests[0].nodes_to_unregister()[0], node(9100));
  EXPECT_TRUE(AddressSpaceCacheTestAccess::pending_unregister(*cache).empty());
  f.ctx.run();  // drain the completion (advisory path)
}

// @verifies CL-VIEW-010
// @relation(CL-VIEW-010, scope=function)
TEST(AddressSpaceCache, LruEvictionCoalescesEvictionsIntoBatchedUnregister)
{
  Fixture f;
  auto policy = f.policy();
  policy.maxRegisteredNodes = 4;  // the cache holds 4
  policy.unregisterBatchSize = 2;  // coalesce 2 evicted handles per UnregisterNodes call
  auto cache = f.make(policy);

  // Register 8 nodes into a size-4 cache: nodes 1001..1004 (handles 9001..9004) are evicted LRU-first and
  // their SERVER handles queued for UnregisterNodes; with batchSize 2 they must flush as TWO batched
  // UnregisterNodes calls of 2 handles each - NOT four single-node calls (CL-VIEW-010 eviction batching).
  std::vector<ua::NodeId> originals;
  std::vector<ua::NodeId> registered;
  for (std::uint32_t i = 1; i <= 8; ++i)
  {
    originals.push_back(node(1000 + i));
    registered.push_back(node(9000 + i));
  }
  cache->install_aliases(originals, registered);
  f.ctx.run();  // drain the two UnregisterNodes advisory completions (and the aborted coalesce-timer waits)

  ASSERT_EQ(f.wireOps->unregisterRequests.size(), 2u)
    << "two batched UnregisterNodes calls, not four single-node calls";
  EXPECT_EQ(f.wireOps->unregisterRequests[0].nodes_to_unregister().size(), 2u)
    << "the first call coalesces two evicted handles";
  EXPECT_EQ(f.wireOps->unregisterRequests[1].nodes_to_unregister().size(), 2u)
    << "the second call coalesces two evicted handles";

  std::vector<ua::NodeId> unregistered;
  for (const auto& request : f.wireOps->unregisterRequests)
  {
    for (const auto& handle : request.nodes_to_unregister())
    {
      unregistered.push_back(handle);
    }
  }
  for (std::uint32_t handle : {9001u, 9002u, 9003u, 9004u})
  {
    EXPECT_NE(std::find(unregistered.begin(), unregistered.end(), node(handle)), unregistered.end())
      << "evicted handle " << handle << " must be unregistered via the batch";
  }
}

// @verifies CL-VIEW-010
// @relation(CL-VIEW-010, scope=function)
TEST(AddressSpaceCache, ExplicitReleaseUnregistersAndDropsEntry)
{
  Fixture f;
  auto policy = f.policy();
  policy.unregisterBatchSize = 1;  // flush on the single release
  auto cache = f.make(policy);
  cache->install_aliases({node(100)}, {node(9100)});
  bool released = false;
  cache->release_async(node(100), [&released](ua::VoidResult result) { released = result.is_good(); });
  f.ctx.run();
  EXPECT_TRUE(released);
  EXPECT_EQ(AddressSpaceCacheTestAccess::alias_count(*cache), 0u);
  ASSERT_EQ(f.wireOps->unregisterRequests.size(), 1u);
  EXPECT_EQ(f.wireOps->unregisterRequests[0].nodes_to_unregister()[0], node(9100));
}

// @verifies CL-VIEW-010
// @relation(CL-VIEW-010, scope=function)
TEST(AddressSpaceCache, DrainFlushesUnionOfLiveAndPending)
{
  Fixture f;
  auto policy = f.policy();
  policy.maxRegisteredNodes = 2;
  policy.unregisterBatchSize = 32;  // keep both aliases live and un-flushed
  auto cache = f.make(policy);
  cache->install_aliases({node(100), node(101)}, {node(9100), node(9101)});
  cache->drain_async([] {});
  f.ctx.run();
  ASSERT_EQ(f.wireOps->unregisterRequests.size(), 1u) << "drain issues exactly one batched UnregisterNodes";
  EXPECT_EQ(f.wireOps->unregisterRequests[0].nodes_to_unregister().size(), 2u);
  EXPECT_EQ(AddressSpaceCacheTestAccess::alias_count(*cache), 0u);
}

// @verifies CL-VIEW-010
// @relation(CL-VIEW-010, scope=function)
TEST(AddressSpaceCache, UnregisterServiceResultBadIsAdvisoryEntriesStillGone)
{
  Fixture f;
  auto policy = f.policy();
  policy.unregisterBatchSize = 1;
  auto cache = f.make(policy);
  f.wireOps->unregisterServiceStatus = ua::StatusCode{ua::Status::BadNodeIdUnknown};
  cache->install_aliases({node(100)}, {node(9100)});
  cache->release_async(node(100), [](ua::VoidResult) {});
  f.ctx.run();
  EXPECT_TRUE(f.logSink->has_message_containing("UnregisterNodes")) << "a bad service result is advisory";
  EXPECT_EQ(AddressSpaceCacheTestAccess::alias_count(*cache), 0u) << "entry removed locally regardless";
}

// ---- Session-scoped invalidation + retention split (CL-VIEW-011 / section 9.8 override 3) ----

AttributeEntry full_attributes()
{
  AttributeEntry entry;
  entry.accessLevel = std::uint8_t{3};
  entry.accessLevelEx = std::uint32_t{0x20003};
  entry.dataType = node(11);  // ns0 Double
  entry.valueRank = std::int32_t{-1};
  entry.arrayDimensions = std::vector<std::uint32_t>{};
  entry.userAccessLevel = std::uint8_t{1};
  return entry;
}

// @verifies CL-VIEW-011
// @relation(CL-VIEW-011, scope=function)
TEST(AddressSpaceCache, SessionChangeSameServerRetainsIntrinsicFlushesUserAccessLevel)
{
  Fixture f;
  auto cache = f.make(f.policy());
  cache->install_attributes(node(500), full_attributes());
  cache->install_aliases({node(100)}, {node(9100)});

  cache->on_session_changed_async(/*serverIdentityPreserved=*/true, /*namespaceArrayChanged=*/false, [] {});
  f.ctx.run();

  // Alias cache flushed + generation bumped.
  EXPECT_EQ(AddressSpaceCacheTestAccess::alias_count(*cache), 0u);
  EXPECT_EQ(AddressSpaceCacheTestAccess::session_generation(*cache), 1u);
  EXPECT_EQ(cache->lookup_for_request(node(100)), node(100));

  // Attribute cache retained, but the Session-dependent userAccessLevel flushed; the five server-intrinsic
  // attributes survive (section 9.8 override 3).
  auto attributes = cache->lookup_attributes(node(500));
  ASSERT_TRUE(attributes.has_value());
  EXPECT_FALSE(attributes->userAccessLevel.has_value()) << "userAccessLevel is Session-dependent -> flushed";
  EXPECT_TRUE(attributes->accessLevel.has_value());
  EXPECT_TRUE(attributes->accessLevelEx.has_value());
  EXPECT_TRUE(attributes->dataType.has_value());
  EXPECT_TRUE(attributes->valueRank.has_value());
  EXPECT_TRUE(attributes->arrayDimensions.has_value());
}

// @verifies CL-SESS-028
// @relation(CL-SESS-028, scope=function)
TEST(AddressSpaceCache, SessionChangeSameServerNamespaceRenumberFlushesAttributes)
{
  Fixture f;
  auto cache = f.make(f.policy());
  cache->install_attributes(node(500), full_attributes());

  // Same-server reconnect, but the server RENUMBERED its NamespaceArray. The attribute cache is keyed by a
  // namespace-INDEX NodeId, so a retained entry would become a mis-keyed stale hit for a DIFFERENT node
  // (security-adjacent for accessLevel-derived pre-flight gates). It must be flushed, not retained
  // (CL-SESS-028 fallback for the index-keying limitation). Falsifiability: an implementation that retains
  // on same-server regardless of the renumber returns the stale entry and fails here.
  cache->on_session_changed_async(/*serverIdentityPreserved=*/true, /*namespaceArrayChanged=*/true, [] {});
  f.ctx.run();

  EXPECT_FALSE(cache->lookup_attributes(node(500)).has_value())
    << "a namespace renumber flushes the index-keyed attribute cache (no stale mis-keyed hit)";
  EXPECT_EQ(AddressSpaceCacheTestAccess::attribute_count(*cache), 0u);
}

// @verifies CL-VIEW-011
// @relation(CL-VIEW-011, scope=function)
TEST(AddressSpaceCache, SessionChangeDifferentServerClearsAllAttributes)
{
  Fixture f;
  auto cache = f.make(f.policy());
  cache->install_attributes(node(500), full_attributes());
  cache->on_session_changed_async(/*serverIdentityPreserved=*/false, /*namespaceArrayChanged=*/false, [] {});
  f.ctx.run();
  EXPECT_FALSE(cache->lookup_attributes(node(500)).has_value());
  EXPECT_EQ(AddressSpaceCacheTestAccess::attribute_count(*cache), 0u);
}

// @verifies CL-VIEW-011
// @relation(CL-VIEW-011, scope=function)
TEST(AddressSpaceCache, SessionChangeFlushesBrowseCacheOnEveryReconnect)
{
  Fixture f;
  auto cache = f.make(f.policy());
  BrowseEntry entry;
  entry.installedAt = std::chrono::steady_clock::now();
  CachedBrowseKey key;
  key.node = node(500);
  cache->install_browse(key, entry);
  ASSERT_EQ(AddressSpaceCacheTestAccess::browse_count(*cache), 1u);

  // Even a same-server (identity-preserved) reconnect flushes the browse cache (section 9.6.19.3).
  cache->on_session_changed_async(/*serverIdentityPreserved=*/true, /*namespaceArrayChanged=*/false, [] {});
  f.ctx.run();
  EXPECT_EQ(AddressSpaceCacheTestAccess::browse_count(*cache), 0u);
}

// ---- Attribute + browse caches ----

// @verifies CL-ATTR-009
// @relation(CL-ATTR-009, scope=function)
TEST(AddressSpaceCache, AttributeLookupHitAndMiss)
{
  Fixture f;
  auto cache = f.make(f.policy());
  cache->install_attributes(node(500), full_attributes());
  auto hit = cache->lookup_attributes(node(500));
  ASSERT_TRUE(hit.has_value());
  EXPECT_EQ(hit->valueRank, std::int32_t{-1});
  EXPECT_FALSE(cache->lookup_attributes(node(501)).has_value());
}

TEST(AddressSpaceCache, BrowseCacheHitReturnsCachedReferences)
{
  Fixture f;
  auto cache = f.make(f.policy());
  BrowseEntry entry;
  entry.installedAt = std::chrono::steady_clock::now();
  entry.references.emplace_back();
  entry.references.emplace_back();
  CachedBrowseKey key;
  key.node = node(500);
  cache->install_browse(key, entry);
  auto hit = cache->lookup_browse(key);
  ASSERT_TRUE(hit.has_value());
  EXPECT_EQ(hit->references.size(), 2u);
}

TEST(AddressSpaceCache, BrowseCacheTtlExpiryReturnsMissAndDrops)
{
  Fixture f;
  auto cache = f.make(f.policy());  // default browseEntryTtl = 30s
  BrowseEntry entry;
  entry.installedAt = std::chrono::steady_clock::now() - std::chrono::seconds{40};  // past TTL
  entry.references.emplace_back();
  CachedBrowseKey key;
  key.node = node(500);
  cache->install_browse(key, entry);
  EXPECT_FALSE(cache->lookup_browse(key).has_value()) << "TTL-expired entry reads as a miss";
  EXPECT_EQ(AddressSpaceCacheTestAccess::browse_count(*cache), 0u) << "and is dropped";
}

// ---- Model-change invalidation (CL-EVT-003) ----

// @verifies CL-EVT-003
// @relation(CL-EVT-003, scope=function)
TEST(AddressSpaceCache, ModelChangeNodeDeletedInvalidatesWithoutUnregister)
{
  Fixture f;
  auto cache = f.make(f.policy());
  cache->install_aliases({node(500)}, {node(9500)});
  cache->install_attributes(node(500), full_attributes());
  BrowseEntry browseEntry;
  browseEntry.installedAt = std::chrono::steady_clock::now();
  CachedBrowseKey key;
  key.node = node(500);
  cache->install_browse(key, browseEntry);

  ModelChangeNotification notification;
  notification.kind = ModelChangeNotification::Kind::General;
  notification.changes.push_back(ModelChange{node(500), ModelChangeVerb::NodeDeleted});
  cache->on_model_change_async(notification, [] {});
  f.ctx.run();

  EXPECT_EQ(AddressSpaceCacheTestAccess::alias_count(*cache), 0u);
  EXPECT_FALSE(cache->lookup_attributes(node(500)).has_value());
  EXPECT_EQ(AddressSpaceCacheTestAccess::browse_count(*cache), 0u);
  EXPECT_TRUE(AddressSpaceCacheTestAccess::pending_unregister(*cache).empty())
    << "a deleted node is not queued for UnregisterNodes (the server already removed it)";
  EXPECT_TRUE(f.wireOps->unregisterRequests.empty());
}

// @verifies CL-EVT-003
// @relation(CL-EVT-003, scope=function)
TEST(AddressSpaceCache, ModelChangeDataTypeChangedInvalidatesAttributeOnly)
{
  Fixture f;
  auto cache = f.make(f.policy());
  cache->install_attributes(node(500), full_attributes());
  BrowseEntry browseEntry;
  browseEntry.installedAt = std::chrono::steady_clock::now();
  CachedBrowseKey key;
  key.node = node(500);
  cache->install_browse(key, browseEntry);

  ModelChangeNotification notification;
  notification.changes.push_back(ModelChange{node(500), ModelChangeVerb::DataTypeChanged});
  cache->on_model_change_async(notification, [] {});
  f.ctx.run();

  EXPECT_FALSE(cache->lookup_attributes(node(500)).has_value()) << "attribute entry dropped";
  EXPECT_EQ(AddressSpaceCacheTestAccess::browse_count(*cache), 1u) << "browse entry unaffected";
}

// @verifies CL-EVT-003
// @relation(CL-EVT-003, scope=function)
TEST(AddressSpaceCache, ModelChangeReferenceAddedInvalidatesBrowseEndpoint)
{
  Fixture f;
  auto cache = f.make(f.policy());
  cache->install_attributes(node(500), full_attributes());
  BrowseEntry browseEntry;
  browseEntry.installedAt = std::chrono::steady_clock::now();
  CachedBrowseKey key;
  key.node = node(500);
  cache->install_browse(key, browseEntry);

  ModelChangeNotification notification;
  notification.changes.push_back(ModelChange{node(500), ModelChangeVerb::ReferenceAdded});
  cache->on_model_change_async(notification, [] {});
  f.ctx.run();

  EXPECT_EQ(AddressSpaceCacheTestAccess::browse_count(*cache), 0u)
    << "browse entry from the endpoint dropped";
  EXPECT_TRUE(cache->lookup_attributes(node(500)).has_value())
    << "attributes unaffected by a reference change";
}

// @verifies CL-EVT-003
// @relation(CL-EVT-003, scope=function)
TEST(AddressSpaceCache, BaseModelChangeFullFlush)
{
  Fixture f;
  auto cache = f.make(f.policy());
  cache->install_aliases({node(500)}, {node(9500)});
  cache->install_attributes(node(500), full_attributes());
  BrowseEntry browseEntry;
  browseEntry.installedAt = std::chrono::steady_clock::now();
  CachedBrowseKey key;
  key.node = node(500);
  cache->install_browse(key, browseEntry);

  ModelChangeNotification notification;
  notification.kind = ModelChangeNotification::Kind::Base;
  notification.view = node(87);
  cache->on_model_change_async(notification, [] {});
  f.ctx.run();

  EXPECT_EQ(AddressSpaceCacheTestAccess::alias_count(*cache), 0u);
  EXPECT_EQ(AddressSpaceCacheTestAccess::attribute_count(*cache), 0u);
  EXPECT_EQ(AddressSpaceCacheTestAccess::browse_count(*cache), 0u);
}

// ---- Strand identity: no private strand (section 8.7) ----

// @verifies CL-MULTI-001
// @relation(CL-MULTI-001, scope=function)
TEST(AddressSpaceCache, PostsOntoInjectedConnectionStrandNotAPrivateOne)
{
  Fixture f;
  auto cache = f.make(f.policy());
  // Structural section 8.7: the cache must NOT fabricate its own strand (make_strand). It must post all async
  // work onto the injected ConnectionImpl strand, so the sync caller-on-strand methods (which
  // LRU-reorder/erase) and the marshalled async ones (which touch the same LruMaps + the coalesce timer)
  // share ONE serialization domain - otherwise a multi-threaded io_context races the sub-caches.
  // Falsifiability: a cache that did `make_strand(mExecutor)` yields a distinct strand and fails this
  // equality.
  EXPECT_EQ(AddressSpaceCacheTestAccess::post_strand(*cache), f.strand)
    << "the cache fabricated its own strand instead of sharing ConnectionImpl's";
}

// ---- Weak-owner UAF guard (section 9.8.3) ----

// @verifies CL-DIAG-002
// @relation(CL-DIAG-002, scope=function)
TEST(AddressSpaceCache, ReleaseCallbackFiresEvenWhenCacheGoneBeforeStrandTurn)
{
  Fixture f;
  auto policy = f.policy();
  policy.unregisterBatchSize = 1;
  auto cache = f.make(policy);
  cache->install_aliases({node(100)}, {node(9100)});

  // The owed completion must fire exactly once even if the cache is destroyed before its strand turn runs.
  // A plain weak post drops the callback -> the sync wrapper (block_on) would hang / observe a broken
  // promise. Falsifiability: with the plain weak post `observed` stays false and this test fails.
  bool observed = false;
  cache->release_async(node(100), [&observed](ua::VoidResult) { observed = true; });
  cache.reset();  // owner gone BEFORE the strand turn runs
  f.ctx.run();
  EXPECT_TRUE(observed) << "release_async must fire its callback on the cache-gone path (completion-owning)";
}

// @verifies CL-DIAG-002
// @relation(CL-DIAG-002, scope=function)
TEST(AddressSpaceCache, DrainWithWireOpsGoneBailsCleanly)
{
  Fixture f;
  auto policy = f.policy();
  policy.unregisterBatchSize = 32;
  auto cache = f.make(policy);
  cache->install_aliases({node(100)}, {node(9100)});
  f.wireOps.reset();  // the wire interface (and the Connection behind it) is gone

  bool drained = false;
  cache->drain_async([&drained] { drained = true; });
  f.ctx.run();
  EXPECT_TRUE(drained) << "drain still completes (no deref of the gone interface)";
  EXPECT_TRUE(f.logSink->has_message_containing("Connection is gone")) << "advisory logged, no crash";
}

// @verifies CL-DIAG-002
// @relation(CL-DIAG-002, scope=function)
TEST(AddressSpaceCache, UnregisterCompletionAfterCacheGoneDoesNotDeref)
{
  Fixture f;
  auto policy = f.policy();
  policy.maxRegisteredNodes = 1;
  policy.unregisterBatchSize = 1;
  auto cache = f.make(policy);
  f.wireOps->deferUnregister = true;  // capture the completion instead of firing it now

  cache->install_aliases({node(100)}, {node(9100)});
  cache->install_aliases({node(101)}, {node(9101)});  // evicts 100 -> flush -> unregister completion captured
  ASSERT_EQ(f.wireOps->deferredUnregisterCbs.size(), 1u);

  // Self-checking (not ASan-dependent): the log sink is a sentinel that OUTLIVES the cache (a Logger is a
  // value handle sharing the sink). The unregister-response handler, IF it ran, logs an advisory containing
  // "returned" on a Bad status. After the cache is destroyed the weak-captured handler must no-op, so no such
  // advisory appears. A weak_ptr also proves the completion did not strong-capture (which would keep the
  // cache alive and defeat the whole guard).
  std::weak_ptr<AddressSpaceCache> weakCache = cache;
  cache.reset();  // destroy the cache (owner gone) BEFORE the wire completion arrives
  ASSERT_TRUE(weakCache.expired())
    << "the in-flight completion strong-captured the cache (should be weak) - lifetime leak";

  f.wireOps->fire_deferred_unregisters(ua::Status::BadNodeIdUnknown);  // Bad response after the owner is gone
  f.ctx.run();  // the post_borrowing completion re-locks weak_from_this() -> gone -> no-op (no deref)

  EXPECT_FALSE(f.logSink->has_message_containing("returned"))
    << "the response handler ran against the gone cache (it would have logged the Bad advisory) - UAF path";
}

}  // namespace
