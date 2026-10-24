// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_event_demux.h"

#include "ua_event_notification_list.h"

#include <cstddef>
#include <unordered_map>

namespace ua::client::detail
{

std::vector<std::pair<std::uint32_t, std::vector<ua::EventFieldList>>> group_events_by_client_handle(
  const ua::EventNotificationList& list)
{
  std::vector<std::pair<std::uint32_t, std::vector<ua::EventFieldList>>> groups;
  // O(1) handle  to  index-into-`groups` map so grouping is O(N), not O(N^2): the group key is
  // attacker-controlled wire data (EventFieldList.client_handle) and the events() array is bounded only by
  // MaxArrayLength (65535), so a hostile all-distinct-handle array would otherwise cost ~N^2/2 comparisons on
  // the serial connection/ pipeline strand  -  a remote CPU DoS (section 3.1). `groups` stays a vector so
  // first-seen group order and arrival order within a group (the demux relies on both) are preserved.
  std::unordered_map<std::uint32_t, std::size_t> indexByHandle;
  indexByHandle.reserve(list.events().size());
  for (const auto& fieldList : list.events())
  {
    const std::uint32_t handle = fieldList.client_handle();
    const auto [entry, inserted] = indexByHandle.try_emplace(handle, groups.size());
    if (inserted)
    {
      groups.push_back({handle, {fieldList}});
    }
    else
    {
      groups[entry->second].second.push_back(fieldList);
    }
  }
  return groups;
}

}  // namespace ua::client::detail
