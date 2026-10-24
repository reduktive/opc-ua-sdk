// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SUBSCRIPTION_ID_ALLOCATOR_H
#define UA_SUBSCRIPTION_ID_ALLOCATOR_H

#include "ua_integer_id.h"

#include <atomic>
#include <memory>
#include <random>

namespace ua::server
{

/// Server-wide unique subscription ID allocator.
/// Owned by ServerImpl and injected into sessions via SessionDependencies.
///
/// A handle onto one shared counter: a copy allocates from the same sequence, and the counter lives while any
/// copy does. A session's subscriptions pipeline keeps a copy, so a CreateSubscription that runs after the
/// server is destroyed still allocates from live memory.
///
/// Starts from a random value on each server restart (SVR-SUB-GEN-071) to prevent
/// clients from accidentally reassociating with stale subscriptions.
class SubscriptionIdAllocator
{
public:
  SubscriptionIdAllocator() : mNext{std::make_shared<std::atomic<IntegerId>>(random_start())}
  {}

  IntegerId allocate()
  {
    return mNext->fetch_add(1, std::memory_order_relaxed);
  }

private:
  static IntegerId random_start()
  {
    std::random_device rd;
    // Range [1, 2^31] - leaves ample headroom for sequential allocation.
    std::uniform_int_distribution<IntegerId> dist(1, 0x7FFF'FFFFu);
    return dist(rd);
  }

  std::shared_ptr<std::atomic<IntegerId>> mNext;
};

}  // namespace ua::server

#endif  // !UA_SUBSCRIPTION_ID_ALLOCATOR_H
