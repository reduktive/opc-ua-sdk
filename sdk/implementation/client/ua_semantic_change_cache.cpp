// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_semantic_change_cache.h"

#include "ua_on_strand.h"

#include <utility>

namespace ua::client::detail
{

std::shared_ptr<SemanticChangeCache> SemanticChangeCache::create(
  boost::asio::strand<boost::asio::any_io_executor> strand, ua::Logger logger)
{
  return std::shared_ptr<SemanticChangeCache>(new SemanticChangeCache(std::move(strand), std::move(logger)));
}

SemanticChangeCache::SemanticChangeCache(
  boost::asio::strand<boost::asio::any_io_executor> strand, ua::Logger logger)
  : mStrand(std::move(strand)), mLogger(std::move(logger)),
    // Install the observer-hook sentinel eagerly (section 8.18.3: the lazy cache subscribes itself on first
    // handle construction). For W2a this is a placeholder; W8 replaces it with the concrete
    // SemanticChangeHook that routes the host `on_semantic_change` fan-out into invalidate_async. close()
    // drops it.
    mObserverHook(std::make_shared<int>(0))
{}

SemanticChangeCache::Ticket SemanticChangeCache::register_state(
  ua::NodeId nodeId, std::shared_ptr<TypedPropertiesState> state)
{
  // Build the Ticket synchronously (the off-strand DataAccess handle-build completion stores it), and
  // marshal the weak-entry insertion onto the strand (mEntries is strand-only). The Ticket holds no strong
  // ref to `state`, so no state and Ticket cycle forms; the caller (the handle) already keeps `state` alive,
  // so the posted weak(state) is valid when the insertion runs.
  Ticket ticket{weak_from_this(), nodeId};
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [nodeId = std::move(nodeId), weak = std::weak_ptr<TypedPropertiesState>{state}](
      SemanticChangeCache& self) mutable { self.register_on_strand(std::move(nodeId), std::move(weak)); })();
  return ticket;
}

void SemanticChangeCache::register_on_strand(ua::NodeId nodeId, std::weak_ptr<TypedPropertiesState> state)
{
  // Opportunistic prune (M2): before inserting, sweep out every dead weak entry. Without this, an entry is
  // only removed when its own NodeId is later invalidated; a DataAccess handle dropped without its NodeId
  // ever being named in a semantic change would leave its entry in mEntries forever, so a long-lived
  // Connection that churns through many short-lived handles would grow mEntries unboundedly. Sweeping on
  // register bounds mEntries to (roughly) the live handle set.
  prune_expired_on_strand();
  // Last-writer-wins on a repeat NodeId (a rebuilt handle over the same Variable re-registers a fresh state);
  // the superseded weak entry simply expires with its old handle-state.
  mEntries[std::move(nodeId)] = std::move(state);
}

void SemanticChangeCache::prune_expired_on_strand()
{
  for (auto entry = mEntries.begin(); entry != mEntries.end();)
  {
    if (entry->second.expired())
    {
      entry = mEntries.erase(entry);
    }
    else
    {
      ++entry;
    }
  }
}

void SemanticChangeCache::invalidate_async(std::vector<ua::NodeId> affected)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [affected = std::move(affected)](SemanticChangeCache& self) mutable
    { self.invalidate_on_strand(affected); })();
}

void SemanticChangeCache::invalidate_on_strand(const std::vector<ua::NodeId>& affected)
{
  for (const auto& nodeId : affected)
  {
    auto entry = mEntries.find(nodeId);
    if (entry == mEntries.end())
    {
      continue;  // no DataAccess handle registered for this NodeId  -  nothing to invalidate
    }
    if (auto state = entry->second.lock())
    {
      // The handle-state is still live: flip its flag so the next typed read re-resolves the Properties
      // before combining them with the freshly-read Value (CL-DA-010/011). release order pairs with the
      // acquire load the read path performs.
      state->invalidated.store(true, std::memory_order_release);
    }
    else
    {
      // The handle (and its state) has been dropped: prune the dead weak ref (lazy prune  -  this walk is the
      // only place entries are removed for expiry).
      mEntries.erase(entry);
    }
  }
}

void SemanticChangeCache::close()
{
  ua::async::post_borrowing(
    this, mStrand, mLogger, [](SemanticChangeCache& self) { self.close_on_strand(); })();
}

void SemanticChangeCache::close_on_strand()
{
  mObserverHook.reset();  // drop the on_semantic_change subscription (a no-op sentinel for W2a)
  mEntries.clear();
}

}  // namespace ua::client::detail
