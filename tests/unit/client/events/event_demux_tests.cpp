// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::detail::group_events_by_client_handle - the pure grouping the inbound event
// demux applies before routing an EventNotificationList to the EventSubscriber (one call per backbone
// handle).
//
// Falsifiability: asserts the exact grouping (handle set, first-seen handle order, per-group arrival order)
// of a mixed EventNotificationList, so a grouper that dropped an entry, merged distinct handles, or reordered
// fails a concrete assertion.

#include "ua_event_demux.h"

#include "ua_event_field_list.h"
#include "ua_event_notification_list.h"
#include "ua_variant.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>

namespace
{
using ua::client::detail::group_events_by_client_handle;

// An EventFieldList with a chosen client_handle and a single sentinel field (a UInt32 tag) so grouping order
// is checkable.
ua::EventFieldList field_list(std::uint32_t clientHandle, std::uint32_t tag)
{
  ua::EventFieldList list;
  list.client_handle() = clientHandle;
  list.event_fields().push_back(ua::Variant{tag});
  return list;
}

std::uint32_t tag_of(const ua::EventFieldList& list)
{
  return list.event_fields()[0].to<std::uint32_t>().value();
}

TEST(EventDemux, GroupsByClientHandlePreservingOrderAndBatches)
{
  ua::EventNotificationList notifications;
  // Interleaved handles: 7, 9, 7, 9, 7 - two groups, arrival order preserved within each.
  notifications.events().push_back(field_list(7, 100));
  notifications.events().push_back(field_list(9, 200));
  notifications.events().push_back(field_list(7, 101));
  notifications.events().push_back(field_list(9, 201));
  notifications.events().push_back(field_list(7, 102));

  const auto groups = group_events_by_client_handle(notifications);

  ASSERT_EQ(groups.size(), 2u) << "two distinct client handles => two groups";
  EXPECT_EQ(groups[0].first, 7u) << "first-seen handle comes first";
  EXPECT_EQ(groups[1].first, 9u);

  ASSERT_EQ(groups[0].second.size(), 3u);
  EXPECT_EQ(tag_of(groups[0].second[0]), 100u) << "arrival order preserved within a group";
  EXPECT_EQ(tag_of(groups[0].second[1]), 101u);
  EXPECT_EQ(tag_of(groups[0].second[2]), 102u);

  ASSERT_EQ(groups[1].second.size(), 2u);
  EXPECT_EQ(tag_of(groups[1].second[0]), 200u);
  EXPECT_EQ(tag_of(groups[1].second[1]), 201u);
}

// A misbehaving server can send an EventNotificationList whose events() array (bounded only by
// MaxArrayLength) carries the maximum count of DISTINCT client_handles - the worst case for the grouper. The
// grouping must scale LINEARLY: an O(N^2) linear-scan grouper (find the handle's group by scanning the whole
// accumulated group vector each time) does ~N^2/2 comparisons here (~2e9 for N=65535) on the serial
// connection/pipeline strand, stalling all other work - a remote CPU DoS (section 3.1 security-robustness
// finding). This pins BOTH the O(N) complexity (a generous wall-clock ceiling the quadratic version blows by
// seconds but the linear version clears by ~4 orders of magnitude) AND the correctness of the large
// distinct-handle grouping (N singleton groups in first-seen order).
TEST(EventDemux, GroupsLargeDistinctHandleArrayInLinearTime)
{
  constexpr std::uint32_t count = 65535;
  ua::EventNotificationList notifications;
  notifications.events().reserve(count);
  for (std::uint32_t handle = 0; handle < count; ++handle)
  {
    notifications.events().push_back(field_list(handle, handle));  // all distinct handles
  }

  const auto start = std::chrono::steady_clock::now();
  const auto groups = group_events_by_client_handle(notifications);
  const auto elapsed =
    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);

  // Correctness: one singleton group per distinct handle, first-seen (ascending) order.
  ASSERT_EQ(groups.size(), count);
  EXPECT_EQ(groups.front().first, 0u);
  EXPECT_EQ(groups.back().first, count - 1);
  EXPECT_EQ(groups.front().second.size(), 1u);
  EXPECT_EQ(groups[count / 2].first, count / 2);

  // Complexity: the O(N^2) grouper took ~11 s here; the O(N) grouper ~0.4 s in this debug build (dominated by
  // the 65535 EventFieldList copies, not the now-microsecond lookups). The 3 s ceiling sits clearly below the
  // quadratic cost (RED margin ~3.7x) yet ~8x above the linear cost, so it stays RED for a regression to
  // O(N^2) but robust against CI CPU contention / sharding.
  EXPECT_LT(elapsed.count(), 3000) << "grouping " << count
                                   << " distinct client handles must be linear, not quadratic (took "
                                   << elapsed.count() << " ms)";
}

TEST(EventDemux, EmptyListYieldsNoGroups)
{
  const auto groups = group_events_by_client_handle(ua::EventNotificationList{});
  EXPECT_TRUE(groups.empty());
}

TEST(EventDemux, SingleHandleYieldsOneGroup)
{
  ua::EventNotificationList notifications;
  notifications.events().push_back(field_list(42, 1));
  notifications.events().push_back(field_list(42, 2));

  const auto groups = group_events_by_client_handle(notifications);

  ASSERT_EQ(groups.size(), 1u);
  EXPECT_EQ(groups[0].first, 42u);
  EXPECT_EQ(groups[0].second.size(), 2u);
}
}  // namespace
