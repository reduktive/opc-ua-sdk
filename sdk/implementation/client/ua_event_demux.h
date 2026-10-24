// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_EVENT_DEMUX_H
#define UA_EVENT_DEMUX_H

/// @file
/// @brief Pure grouping of a Publish @ref ua::EventNotificationList by backbone client handle, for the
///        client-side inbound event demux (section 8.13).
/// @ingroup client

#include "ua_event_field_list.h"

#include <cstdint>
#include <utility>
#include <vector>

namespace ua
{
class EventNotificationList;
}  // namespace ua

namespace ua::client::detail
{

/// Groups an @ref ua::EventNotificationList's @ref ua::EventFieldList entries by their `client_handle`  - the
/// CLIENT-assigned backbone handle the server echoes, which is the EventSubscriber's inbound demux key. A
/// single EventNotificationList may carry entries for several backbone MonitoredItems (distinct handles);
/// @ref EventSubscriberImpl::on_publish_events_async takes ONE handle plus that handle's batch, so the demux
/// must group before routing. Handles appear in first-seen order; within each group the field lists keep
/// their arrival order (the per-item order CL-MI-026 preserves downstream). Pure and deterministic.
[[nodiscard]] std::vector<std::pair<std::uint32_t, std::vector<ua::EventFieldList>>>
  group_events_by_client_handle(const ua::EventNotificationList& list);

}  // namespace ua::client::detail

#endif  // UA_EVENT_DEMUX_H
