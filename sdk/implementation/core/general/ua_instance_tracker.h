// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_INSTANCE_TRACKER_H
#define UA_INSTANCE_TRACKER_H

#include <atomic>
#include <cstddef>

// RAII live-instance counter for leak diagnostics.
//
// A type opts in by holding a `[[no_unique_address]] InstanceTracker<ThatType>`
// member: construction increments and destruction decrements a per-tag atomic,
// so the count always equals the number of live instances on every code path
// (Rule of Zero, exception-safe - no manual inc/dec in the owner's ctor/dtor).
// Read the current count via `InstanceTracker<Tag>::live()`.
//
// Active in debug / sanitizer builds (NDEBUG undefined) or when
// UA_ENABLE_INSTANCE_TRACKING is defined; in release it is an empty type whose
// live() returns 0, so with [[no_unique_address]] it costs nothing.

#if !defined(NDEBUG) || defined(UA_ENABLE_INSTANCE_TRACKING)
#define UA_INSTANCE_TRACKING_ACTIVE 1
#else
#define UA_INSTANCE_TRACKING_ACTIVE 0
#endif

namespace ua::diagnostics
{

// Public tag types for leak-diagnostic instance counters. Forward declarations
// suffice: InstanceTracker<Tag> uses Tag only as a distinct key for its static
// counter, never instantiating it. This lets tests read e.g.
// InstanceTracker<ServerSessionTag>::live() without depending on the internal
// impl class that owns the tracked member.
struct ServerSessionTag;
struct ClientSessionTag;
struct ServerSecureChannelTag;
struct ClientSecureChannelTag;
struct ServerSubscriptionTag;
struct ServerMonitoredItemTag;
struct DefaultBaseNodeTag;

template<class Tag>
class InstanceTracker
{
public:
#if UA_INSTANCE_TRACKING_ACTIVE
  InstanceTracker() noexcept
  {
    counter().fetch_add(1, std::memory_order_relaxed);
  }

  InstanceTracker(const InstanceTracker&) noexcept
  {
    counter().fetch_add(1, std::memory_order_relaxed);
  }

  InstanceTracker(InstanceTracker&&) noexcept
  {
    counter().fetch_add(1, std::memory_order_relaxed);
  }

  InstanceTracker& operator=(const InstanceTracker&) noexcept
  {
    return *this;
  }

  InstanceTracker& operator=(InstanceTracker&&) noexcept
  {
    return *this;
  }

  ~InstanceTracker()
  {
    counter().fetch_sub(1, std::memory_order_relaxed);
  }

  static std::size_t live() noexcept
  {
    return counter().load(std::memory_order_relaxed);
  }

private:
  static std::atomic<std::size_t>& counter() noexcept
  {
    static std::atomic<std::size_t> instances{0};
    return instances;
  }
#else
  static std::size_t live() noexcept
  {
    return 0;
  }
#endif
};

}  // namespace ua::diagnostics

#endif  // UA_INSTANCE_TRACKER_H
