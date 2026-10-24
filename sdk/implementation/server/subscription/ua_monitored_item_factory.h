// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_MONITORED_ITEM_FACTORY_H
#define UA_MONITORED_ITEM_FACTORY_H

#include "ua_data_change_trigger.h"
#include "ua_deadband_type.h"
#include "ua_duration.h"
#include "ua_event_filter_result.h"
#include "ua_monitored_item.h"
#include "ua_monitored_item_create_request.h"
#include "ua_node_id.h"
#include "ua_status_code.h"
#include "ua_timestamps_to_return.h"

#include <memory>
#include <optional>

namespace ua::server
{

/// Context passed to validate_and_build_monitored_item.
struct MonitoredItemCreateContext
{
  const MonitoredItemCreateRequest& request;
  TimestampsToReturn timestampsToReturn{TimestampsToReturn::Both};
  Duration publishingInterval{1000};
  uint32_t maxQueueSize{100};
  Duration minSamplingInterval{0};
  Duration maxSamplingInterval{60000};
  uint32_t maxEventQueueSize{1000};
  uint32_t defaultEventQueueSize{50};
  /// EventFilter clause caps applied at compile (SVR-EVT-CAP-001/002); 0 = unlimited.
  uint32_t maxSelectClauses{0};
  uint32_t maxWhereClauseElements{0};
  /// Total where-clause string-literal operand byte budget (SVR-EVT-CAP-002c); 0 = unlimited.
  uint32_t maxWhereClauseOperandBytes{0};
};

/// Outcome of validate_and_build_monitored_item.
struct MonitoredItemCreateOutcome
{
  StatusCode statusCode;
  std::unique_ptr<MonitoredItem> item;
  Duration revisedSamplingInterval{0};
  uint32_t revisedQueueSize{0};
  /// Set for event items - contains per-clause validation results for the client.
  std::optional<EventFilterResult> eventFilterResult;
};

/// Pure validation + construction of a MonitoredItem from a CreateMonitoredItems request item.
/// Does not perform any I/O or namespace interaction.
MonitoredItemCreateOutcome validate_and_build_monitored_item(
  const MonitoredItemCreateContext& context, IntegerId assignedId);

/// Revise requested sampling interval per spec rules.
Duration revise_sampling_interval(
  Duration requested, Duration publishingInterval, Duration minServer, Duration maxServer);

/// Revise requested queue size per spec rules.
uint32_t revise_queue_size(uint32_t requested, uint32_t maxConfigured);

/// Parse the monitoring filter from request parameters.
/// Returns the parsed filter fields. On error, statusCode is set.
struct ParsedFilter
{
  StatusCode statusCode;
  DataChangeTrigger trigger{DataChangeTrigger::StatusValue};
  DeadbandType deadbandType{DeadbandType::None};
  double deadbandValue{0.0};
};

ParsedFilter parse_data_change_filter(
  const RefStructure<Structure>& filter, const NodeId& nodeId, AttributeId attributeId);

}  // namespace ua::server

#endif  // !UA_MONITORED_ITEM_FACTORY_H
