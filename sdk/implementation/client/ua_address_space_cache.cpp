// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_address_space_cache.h"

#include "ua_connection_ops.h"
#include "ua_error_detail.h"
#include "ua_on_strand.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_unregister_nodes_request.h"
#include "ua_unregister_nodes_response.h"

#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <utility>

namespace ua::client::detail
{

std::shared_ptr<AddressSpaceCache> AddressSpaceCache::create(
  boost::asio::strand<boost::asio::any_io_executor> strand, std::weak_ptr<WireOps> wireOps,
  AddressSpaceCachePolicy policy, ua::Logger logger)
{
  return std::shared_ptr<AddressSpaceCache>(
    new AddressSpaceCache(std::move(strand), std::move(wireOps), std::move(policy), std::move(logger)));
}

AddressSpaceCache::AddressSpaceCache(boost::asio::strand<boost::asio::any_io_executor> strand,
  std::weak_ptr<WireOps> wireOps, AddressSpaceCachePolicy policy, ua::Logger logger)
  // No private strand (section 8.7): the injected `strand` is ConnectionImpl's, and every async completion
  // posts onto it. mExecutor (its inner executor) is used only to hop a user callback OFF the strand for
  // delivery. The coalesce timer runs on the same strand, so the sync caller-on-strand path and the
  // marshalled async path share one serialization domain  -  no data race on the LruMaps or the timer.
  : mStrand(std::move(strand)), mExecutor(mStrand.get_inner_executor()), mWireOps(std::move(wireOps)),
    mPolicy(std::move(policy)), mLogger(std::move(logger)), mAliasCache(mPolicy.maxRegisteredNodes),
    mAttributeCache(mPolicy.maxCachedAttributes), mBrowseCache(mPolicy.maxCachedBrowses),
    mPendingUnregisterTimer(mStrand)
{}

std::function<void(ua::VoidResult)> AddressSpaceCache::on_executor(
  std::function<void(ua::VoidResult)> cb) const
{
  return [executor = mExecutor, cb = std::move(cb)](ua::VoidResult result) mutable
  {
    boost::asio::post(executor,
      ua::async::guarded(
        ua::Logger{}, [cb = std::move(cb), result = std::move(result)]() mutable { cb(std::move(result)); }));
  };
}

std::function<void(ua::VoidResult)> AddressSpaceCache::on_executor(std::function<void()> cb) const
{
  return [executor = mExecutor, cb = std::move(cb)](ua::VoidResult) mutable
  {
    boost::asio::post(executor, ua::async::guarded(ua::Logger{}, [cb = std::move(cb)]() mutable { cb(); }));
  };
}

// -------- Alias substitution (CL-VIEW-009) --------

ua::NodeId AddressSpaceCache::lookup_for_request(const ua::NodeId& userFacing) const noexcept
{
  if (!mPolicy.enabled || !mPolicy.useRegisterNodes)
  {
    return userFacing;  // disabled: pass through verbatim (no substitution)
  }
  auto* alias = mAliasCache.get(userFacing);
  if (alias == nullptr)
  {
    return userFacing;  // miss: tier-2 sends the unaliased NodeId and lazily registers on next use
  }
  if (alias->sessionGeneration != mSessionGeneration)
  {
    // Stale across a missed on_session_changed (defence-in-depth): drop and return the original.
    mAliasCache.erase(userFacing);
    return userFacing;
  }
  return alias->registered;
}

void AddressSpaceCache::install_aliases(std::vector<ua::NodeId> originals, std::vector<ua::NodeId> registered)
{
  if (!mPolicy.enabled || !mPolicy.useRegisterNodes)
  {
    return;  // disabled: no-op (the cache stores nothing, so lookup_for_request always passes through)
  }
  const std::size_t count = std::min(originals.size(), registered.size());
  for (std::size_t index = 0; index < count; ++index)
  {
    AliasEntry entry{std::move(registered[index]), mSessionGeneration};
    auto evicted = mAliasCache.put(std::move(originals[index]), std::move(entry));
    if (evicted)
    {
      // LRU eviction: the evicted alias's SERVER handle must be unregistered (CL-VIEW-010).
      queue_unregister(evicted->second.registered);
    }
  }
}

// -------- Attribute pre-flight cache --------

void AddressSpaceCache::install_attributes(const ua::NodeId& userFacing, AttributeEntry attributes)
{
  if (!mPolicy.enabled)
  {
    return;
  }
  mAttributeCache.put(userFacing, std::move(attributes));
}

std::optional<AttributeEntry> AddressSpaceCache::lookup_attributes(
  const ua::NodeId& userFacing) const noexcept
{
  if (!mPolicy.enabled)
  {
    return std::nullopt;
  }
  auto* entry = mAttributeCache.get(userFacing);
  if (entry == nullptr)
  {
    return std::nullopt;
  }
  return *entry;
}

// -------- Browse-result cache --------

std::optional<BrowseEntry> AddressSpaceCache::lookup_browse(const CachedBrowseKey& key) const noexcept
{
  if (!mPolicy.enabled)
  {
    return std::nullopt;
  }
  auto* entry = mBrowseCache.get(key);
  if (entry == nullptr)
  {
    return std::nullopt;
  }
  if (std::chrono::steady_clock::now() - entry->installedAt > mPolicy.browseEntryTtl)
  {
    // Idle TTL expired: treat as a miss and drop it (section 8.7 browse-cache TTL).
    mBrowseCache.erase(key);
    return std::nullopt;
  }
  return *entry;
}

void AddressSpaceCache::install_browse(CachedBrowseKey key, BrowseEntry entry)
{
  if (!mPolicy.enabled)
  {
    return;
  }
  mBrowseCache.put(std::move(key), std::move(entry));
}

// -------- Eviction / release / invalidation / shutdown --------

void AddressSpaceCache::release_async(ua::NodeId userFacing, std::function<void(ua::VoidResult)> cb)
{
  // Completion-owning post: the owed `cb` fires exactly once even if the cache is destroyed before the
  // strand turn runs (a plain weak post drops it -> the sync wrapper hangs / broken_promise). On the gone
  // path the caller learns the release could not run; on the alive path the handler delivers Good.
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    on_executor(std::move(cb)),
    ua::VoidResult{ua::Status::BadSessionClosed,
      ua::make_error_detail("AddressSpaceCacheGone",
        "the address-space cache was destroyed before release_async could run",
        std::string{"client.tier1.address_space_cache.release"})},
    [userFacing = std::move(userFacing)](
      AddressSpaceCache& self, std::function<void(ua::VoidResult)> completion) mutable
    {
      if (const auto* alias = self.mAliasCache.peek(userFacing); alias != nullptr)
      {
        const ua::NodeId registered = alias->registered;
        self.mAliasCache.erase(userFacing);
        self.queue_unregister(registered);
      }
      self.mAttributeCache.erase(userFacing);
      self.remove_browse_entries_for_node(userFacing);
      completion(ua::VoidResult{});
    })();
}

void AddressSpaceCache::on_session_changed_async(
  bool serverIdentityPreserved, bool namespaceArrayChanged, std::function<void()> cb)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    on_executor(std::move(cb)),
    ua::VoidResult{},  // gone path: nothing left to invalidate  -  the completion just fires Good
    [serverIdentityPreserved, namespaceArrayChanged](
      AddressSpaceCache& self, std::function<void(ua::VoidResult)> completion) mutable
    {
      // Alias cache is Session-scoped: always cleared, generation bumped (CL-VIEW-011). The server lost
      // the registrations across the new Session, so the pending batch is dropped (nothing to unregister).
      self.mAliasCache.clear();
      self.mSessionGeneration += 1;
      self.mPendingUnregisterBatch.clear();
      self.mPendingUnregisterTimer.cancel();
      // Browse cache flushes on EVERY reconnect (section 9.6.19.3 ratified: a republish-queue overflow can
      // drop a model-change even on a preserved Session, so there is no reliable invalidation path).
      self.mBrowseCache.clear();
      if (serverIdentityPreserved && !namespaceArrayChanged)
      {
        // Retain the server-intrinsic attributes across a same-server reconnect but flush the
        // Session-dependent userAccessLevel (section 9.8 override 3).
        self.mAttributeCache.for_each(
          [](const ua::NodeId&, AttributeEntry& entry) { entry.userAccessLevel.reset(); });
      }
      else
      {
        // Clear every attribute when the server endpoint changed (redundancy switch section 8.11) OR the
        // server renumbered its NamespaceArray. The sub-caches are keyed by a namespace-INDEX NodeId, so a
        // retained entry after a renumber would become a mis-keyed stale hit for a DIFFERENT node
        // (security-adjacent for accessLevel-derived pre-flight gates).
        //
        // NOTE(CL-SESS-028): this namespace-generation FLUSH is the sanctioned fallback for the index-keying
        // limitation. The full fix per section 8.7.1 is a URI-based CachedNodeKey{namespaceUri, NodeIdValue}
        // that is invariant under remap (so the retained entries survive a renumber instead of being
        // flushed). That re-key needs a NamespaceTable interface injected into the cache (not yet wired  -
        // the cache has no ConnectionImpl/NamespaceTable dependency today) and is deferred; the flush closes
        // the correctness hole in the meantime (never a wrong-node hit).
        self.mAttributeCache.clear();
      }
      completion(ua::VoidResult{});
    })();
}

void AddressSpaceCache::on_model_change_async(ModelChangeNotification notification, std::function<void()> cb)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    on_executor(std::move(cb)),
    ua::VoidResult{},  // gone path: nothing left to invalidate  -  the completion just fires Good
    [notification = std::move(notification)](
      AddressSpaceCache& self, std::function<void(ua::VoidResult)> completion) mutable
    {
      if (notification.kind == ModelChangeNotification::Kind::Base)
      {
        // BaseModelChangeEvent for a View: full flush (section 9.6.19.4 ratified) - the cache lacks a
        // reachable-from-View index, so it drops everything and re-warms by use.
        self.mAliasCache.clear();
        self.mAttributeCache.clear();
        self.mBrowseCache.clear();
      }
      else
      {
        for (const auto& change : notification.changes)
        {
          switch (change.verb)
          {
          case ModelChangeVerb::NodeDeleted:
            // The server already deleted the node; drop from every sub-cache WITHOUT an UnregisterNodes.
            self.invalidate_node(change.affected);
            break;
          case ModelChangeVerb::DataTypeChanged:
            // The DataType attribute is part of the cached payload; drop the attribute entry only.
            self.mAttributeCache.erase(change.affected);
            break;
          case ModelChangeVerb::ReferenceAdded:
          case ModelChangeVerb::ReferenceDeleted:
            // A reference changed at this endpoint: any cached Browse from it is now stale.
            self.remove_browse_entries_for_node(change.affected);
            break;
          case ModelChangeVerb::NodeAdded:
            // A new node has no cache entry yet; nothing to invalidate here (parent-browse invalidation
            // needs a linkage index the cache does not maintain - best-effort skip).
            break;
          }
        }
      }
      completion(ua::VoidResult{});
    })();
}

void AddressSpaceCache::drain_async(std::function<void()> cb)
{
  // Completion-owning: close_async waits on this drain, so the owed completion must fire even if the cache
  // is destroyed before the strand turn (the gone path fires Good  -  there is nothing left to unregister).
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    on_executor(std::move(cb)),
    ua::VoidResult{},
    [](AddressSpaceCache& self, std::function<void(ua::VoidResult)> completion) mutable
    {
      // Union of the pending batch + every live alias's server handle, flushed as one best-effort
      // UnregisterNodes (CL-VIEW-010). Local state is cleared regardless of the wire outcome.
      std::vector<ua::NodeId> batch = std::exchange(self.mPendingUnregisterBatch, {});
      self.mAliasCache.for_each(
        [&batch](const ua::NodeId&, AliasEntry& entry) { batch.push_back(entry.registered); });
      self.mAliasCache.clear();
      self.mPendingUnregisterTimer.cancel();
      self.issue_unregister(std::move(batch));
      completion(ua::VoidResult{});
    })();
}

// -------- on-strand helpers --------

void AddressSpaceCache::queue_unregister(const ua::NodeId& node)
{
  mPendingUnregisterBatch.push_back(node);
  if (mPendingUnregisterBatch.size() >= mPolicy.unregisterBatchSize)
  {
    // Size threshold reached: flush immediately (cancel the pending coalesce wait first).
    mPendingUnregisterTimer.cancel();
    flush_unregister_batch();
    return;
  }
  arm_unregister_timer();
}

void AddressSpaceCache::arm_unregister_timer()
{
  // Single-armed-with-rearm: expires_after cancels any pending wait and re-arms with the fresh window, so a
  // steady stream of evictions never flushes before the stream quiets (section 8.7 coalesce-timer rules).
  mPendingUnregisterTimer.expires_after(mPolicy.unregisterCoalesceWindow);
  mPendingUnregisterTimer.async_wait(ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [](AddressSpaceCache& self, const boost::system::error_code& error)
    {
      if (error)
      {
        return;  // operation_aborted on rearm/cancel (expected), or a timer error -> drop this wait
      }
      self.flush_unregister_batch();
    }));
}

void AddressSpaceCache::flush_unregister_batch()
{
  if (mPendingUnregisterBatch.empty())
  {
    return;
  }
  std::vector<ua::NodeId> batch;
  batch.swap(mPendingUnregisterBatch);
  issue_unregister(std::move(batch));
}

void AddressSpaceCache::issue_unregister(std::vector<ua::NodeId> nodes)
{
  if (nodes.empty())
  {
    return;
  }
  auto wireOps = mWireOps.lock();
  if (!wireOps)
  {
    // The wire interface (and the Connection behind it) is gone: there is nothing to free server-side. Bail
    // cleanly rather than dereferencing a gone owner across the async boundary (section 9.8.3 UAF fix).
    mLogger.warning(
      "address_space_cache: skipped UnregisterNodes for {} node(s) - the Connection is gone", nodes.size());
    return;
  }
  ua::UnregisterNodesRequest request;
  for (auto& node : nodes)
  {
    request.nodes_to_unregister().push_back(std::move(node));
  }
  const std::size_t count = request.nodes_to_unregister().size();
  wireOps->unregister_nodes_async(std::move(request),
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [count](AddressSpaceCache& self, ua::Result<ua::UnregisterNodesResponse> response)
      {
        if (response.is_bad())
        {
          // Advisory (CL-VIEW-010): the local entries are already removed; the server may have lost the
          // registrations via Session timeout. Do not retry.
          self.mLogger.warning(
            "address_space_cache: UnregisterNodes for {} node(s) returned {} (advisory; entries already "
            "freed locally)",
            count,
            static_cast<std::uint32_t>(response.status_code().value()));
        }
      }));
}

void AddressSpaceCache::invalidate_node(const ua::NodeId& node)
{
  // Drop the node from every sub-cache. Used by NodeDeleted (server already removed it) so NO UnregisterNodes
  // is queued - the batched-unregister path is only for LRU eviction / explicit release.
  mAliasCache.erase(node);
  mAttributeCache.erase(node);
  remove_browse_entries_for_node(node);
}

void AddressSpaceCache::remove_browse_entries_for_node(const ua::NodeId& node)
{
  // The browse cache is keyed by (node, shape); drop every entry whose start node is this node.
  for (const auto& key : mBrowseCache.keys())
  {
    if (key.node == node)
    {
      mBrowseCache.erase(key);
    }
  }
}

}  // namespace ua::client::detail
