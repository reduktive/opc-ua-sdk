// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_subscription_router.h"

#include <algorithm>
#include <utility>

namespace ua::server
{

SubscriptionRouter::SubscriptionRouter() : mState(std::make_shared<State>())
{}

SubscriptionRouter::SubscriptionRouter(std::shared_ptr<State> state) : mState(std::move(state))
{}

SubscriptionRouter::Weak SubscriptionRouter::weak() const
{
  return Weak{mState};
}

SubscriptionRouter::Weak::Weak(std::weak_ptr<State> state) : mState(std::move(state))
{}

std::optional<SubscriptionRouter> SubscriptionRouter::Weak::lock() const
{
  if (auto state = mState.lock())
  {
    return SubscriptionRouter{std::move(state)};
  }
  return std::nullopt;
}

void SubscriptionRouter::register_subscription(
  IntegerId id, std::weak_ptr<Session> owner, std::weak_ptr<Subscription> subscription)
{
  SubscriptionAddedCallback onAdded;
  {
    const std::unique_lock lock(mState->mutex);
    const bool inserted = mState->entries.find(id) == mState->entries.end();
    mState->entries[id] = Entry{owner, subscription};
    if (inserted)
      onAdded = mState->onAdded;
  }
  // Fire outside the lock so the observer can post address-space work without re-entrancy risk.
  if (onAdded)
    onAdded(id, std::move(subscription), std::move(owner));
}

void SubscriptionRouter::unregister_subscription(IntegerId id)
{
  SubscriptionRemovedCallback onRemoved;
  {
    const std::unique_lock lock(mState->mutex);
    if (mState->entries.erase(id) > 0)
      onRemoved = mState->onRemoved;
  }
  if (onRemoved)
    onRemoved(id);
}

void SubscriptionRouter::set_lifecycle_observers(
  SubscriptionAddedCallback onAdded, SubscriptionRemovedCallback onRemoved)
{
  const std::unique_lock lock(mState->mutex);
  mState->onAdded = std::move(onAdded);
  mState->onRemoved = std::move(onRemoved);
}

void SubscriptionRouter::set_node_readiness_callback(NodeReadinessCallback callback)
{
  const std::unique_lock lock(mState->mutex);
  mState->nodeReadiness = std::move(callback);
}

void SubscriptionRouter::when_subscription_node_ready(IntegerId id, std::function<void()> completion) const
{
  NodeReadinessCallback callback;
  {
    const std::shared_lock lock(mState->mutex);
    callback = mState->nodeReadiness;
  }
  if (callback)
    callback(id, std::move(completion));
  else
    completion();  // No diagnostics-node manager wired - nothing to wait for.
}

bool SubscriptionRouter::has_node_readiness_callback() const
{
  const std::shared_lock lock(mState->mutex);
  return static_cast<bool>(mState->nodeReadiness);
}

void SubscriptionRouter::set_monitoring_reflection_callback(MonitoringReflectionCallback callback)
{
  const std::unique_lock lock(mState->mutex);
  mState->monitoringReflection = std::move(callback);
}

void SubscriptionRouter::when_monitoring_reflected(std::function<void()> completion) const
{
  MonitoringReflectionCallback callback;
  {
    const std::shared_lock lock(mState->mutex);
    callback = mState->monitoringReflection;
  }
  if (callback)
    callback(std::move(completion));
  else
    completion();
}

bool SubscriptionRouter::has_monitoring_reflection_callback() const
{
  const std::shared_lock lock(mState->mutex);
  return static_cast<bool>(mState->monitoringReflection);
}

void SubscriptionRouter::update_sampling_intervals(
  const SamplingIntervalCounts& before, const SamplingIntervalCounts& after)
{
  const std::lock_guard lock(mState->intervalMutex);
  bool setChanged = false;
  for (const auto& [interval, count] : before)
  {
    auto it = mState->intervalCounts.find(interval);
    if (it == mState->intervalCounts.end())
      continue;  // Never counted: nothing to take back.
    it->second -= std::min(it->second, count);
    if (it->second == 0)
    {
      mState->intervalCounts.erase(it);
      setChanged = true;
    }
  }
  for (const auto& [interval, count] : after)
  {
    if (count == 0)
      continue;
    auto [it, inserted] = mState->intervalCounts.try_emplace(interval, 0);
    it->second += count;
    setChanged = setChanged || inserted;
  }
  if (setChanged)
    ++mState->intervalGeneration;
}

SubscriptionRouter::SamplingIntervalsInUse SubscriptionRouter::sampling_intervals_in_use() const
{
  const std::lock_guard lock(mState->intervalMutex);
  SamplingIntervalsInUse inUse;
  inUse.generation = mState->intervalGeneration;
  inUse.intervals.reserve(mState->intervalCounts.size());
  for (const auto& [interval, count] : mState->intervalCounts)
    inUse.intervals.push_back(interval);
  return inUse;
}

std::shared_ptr<Session> SubscriptionRouter::find_owner(IntegerId id) const
{
  const std::shared_lock lock(mState->mutex);
  auto it = mState->entries.find(id);
  if (it == mState->entries.end())
    return nullptr;
  return it->second.owner.lock();
}

std::vector<std::pair<std::shared_ptr<Subscription>, std::shared_ptr<Session>>>
  SubscriptionRouter::live_subscriptions() const
{
  std::vector<std::pair<std::shared_ptr<Subscription>, std::shared_ptr<Session>>> result;
  const std::shared_lock lock(mState->mutex);
  result.reserve(mState->entries.size());
  for (const auto& [id, entry] : mState->entries)
  {
    auto subscription = entry.subscription.lock();
    if (!subscription)
      continue;
    result.emplace_back(std::move(subscription), entry.owner.lock());
  }
  return result;
}

}  // namespace ua::server
