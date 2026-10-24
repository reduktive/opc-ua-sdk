// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_orphaned_subscription_store.h"

#include "ua_subscription.h"

#include <algorithm>
#include <utility>

namespace ua::server
{

namespace
{
void erase_from_order(std::deque<IntegerId>& order, IntegerId id)
{
  order.erase(std::remove(order.begin(), order.end(), id), order.end());
}
}  // namespace

OrphanedSubscriptionStore::State::State(size_t capacity) : maxEntries(capacity < 1 ? 1 : capacity)
{}

OrphanedSubscriptionStore::State::~State()
{
  clear();
}

void OrphanedSubscriptionStore::State::clear()
{
  // Close every still-parked subscription so its timer is torn down before the shared_ptr drops.
  std::unordered_map<IntegerId, OrphanedSubscription> taken;
  {
    const std::lock_guard lock(mutex);
    // Swap (not move-then-clear) so entries is left definitively empty without reading a
    // moved-from object: taken starts empty, so this leaves entries empty and taken owning
    // the prior contents to be closed below.
    taken.swap(entries);
    parkOrder.clear();
  }
  for (auto& [id, entry] : taken)
  {
    if (entry.subscription)
      entry.subscription->close_async();
  }
}

OrphanedSubscriptionStore::OrphanedSubscriptionStore(size_t maxEntries)
  : mState(std::make_shared<State>(maxEntries))
{}

OrphanedSubscriptionStore::OrphanedSubscriptionStore(std::shared_ptr<State> state) : mState(std::move(state))
{}

OrphanedSubscriptionStore::Weak OrphanedSubscriptionStore::weak() const
{
  return Weak{mState};
}

OrphanedSubscriptionStore::Weak::Weak(std::weak_ptr<State> state) : mState(std::move(state))
{}

std::optional<OrphanedSubscriptionStore> OrphanedSubscriptionStore::Weak::lock() const
{
  if (auto state = mState.lock())
  {
    return OrphanedSubscriptionStore{std::move(state)};
  }
  return std::nullopt;
}

void OrphanedSubscriptionStore::set_max_entries(size_t maxEntries)
{
  const std::lock_guard lock(mState->mutex);
  mState->maxEntries = maxEntries < 1 ? 1 : maxEntries;
}

void OrphanedSubscriptionStore::clear()
{
  mState->clear();
}

void OrphanedSubscriptionStore::park(IntegerId id, OrphanedSubscription entry)
{
  // Drop-oldest eviction must close the victim's subscription, but never while holding the store
  // mutex (the final ~Subscription would run under the lock). Stage it and close after unlocking.
  std::shared_ptr<Subscription> evicted;
  {
    const std::lock_guard lock(mState->mutex);

    auto existing = mState->entries.find(id);
    if (existing != mState->entries.end())
    {
      existing->second = std::move(entry);  // re-park: replace in place, keep order position
      return;
    }

    if (mState->entries.size() >= mState->maxEntries && !mState->parkOrder.empty())
    {
      const IntegerId victim = mState->parkOrder.front();
      mState->parkOrder.pop_front();
      auto victimIt = mState->entries.find(victim);
      if (victimIt != mState->entries.end())
      {
        evicted = std::move(victimIt->second.subscription);
        mState->entries.erase(victimIt);
      }
    }

    mState->entries.emplace(id, std::move(entry));
    mState->parkOrder.push_back(id);
  }
  if (evicted)
    evicted->close_async();
}

void OrphanedSubscriptionStore::remove(IntegerId id)
{
  // Move the entry out under the lock; close + drop the subscription after releasing it so the
  // (possibly final) ~Subscription does not run while holding the store mutex.
  std::shared_ptr<Subscription> dropped;
  {
    const std::lock_guard lock(mState->mutex);
    auto it = mState->entries.find(id);
    if (it == mState->entries.end())
      return;
    dropped = std::move(it->second.subscription);
    mState->entries.erase(it);
    erase_from_order(mState->parkOrder, id);
  }
  if (dropped)
    dropped->close_async();
}

std::optional<OrphanedSubscription> OrphanedSubscriptionStore::take(IntegerId id)
{
  const std::lock_guard lock(mState->mutex);
  auto it = mState->entries.find(id);
  if (it == mState->entries.end())
    return std::nullopt;
  OrphanedSubscription taken = std::move(it->second);
  mState->entries.erase(it);
  erase_from_order(mState->parkOrder, id);
  return taken;
}

bool OrphanedSubscriptionStore::contains(IntegerId id) const
{
  const std::lock_guard lock(mState->mutex);
  return mState->entries.find(id) != mState->entries.end();
}

size_t OrphanedSubscriptionStore::size() const
{
  const std::lock_guard lock(mState->mutex);
  return mState->entries.size();
}

}  // namespace ua::server
