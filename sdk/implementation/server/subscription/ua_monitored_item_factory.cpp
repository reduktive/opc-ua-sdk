// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_monitored_item_factory.h"

#include "ua_aggregate_filter.h"
#include "ua_attribute_id.h"
#include "ua_compiled_event_filter.h"
#include "ua_data_change_filter.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_event_filter.h"
#include "ua_monitoring_parameters.h"
#include "ua_numeric_range_parser.h"
#include "ua_to_string.h"
#include "ua_utilities.h"

#include <algorithm>
#include <cmath>

namespace ua::server
{

Duration revise_sampling_interval(
  Duration requested, Duration publishingInterval, Duration minServer, Duration maxServer)
{
  // Negative -> use publishing interval (spec 5.12.1.2)
  if (requested < 0)
    return publishingInterval;

  // Zero -> fastest the server supports
  if (requested == 0)
    return minServer;

  // Clamp to [min, max]
  return std::clamp(requested, minServer, maxServer);
}

uint32_t revise_queue_size(uint32_t requested, uint32_t maxConfigured)
{
  // 0 or 1 -> 1 (spec 5.12.1.2)
  if (requested <= 1)
    return 1;

  // Clamp to max
  if (maxConfigured > 0 && requested > maxConfigured)
    return maxConfigured;

  return requested;
}

ParsedFilter parse_data_change_filter(
  const RefStructure<Structure>& filter, const NodeId& nodeId, AttributeId attributeId)
{
  ParsedFilter result;

  // No filter specified -> use defaults
  if (!filter.inner_unique_ptr())
  {
    result.trigger = DataChangeTrigger::StatusValue;
    result.deadbandType = DeadbandType::None;
    result.deadbandValue = 0.0;
    return result;
  }

  // Must be a DataChangeFilter
  auto* dcFilter = dynamic_cast<const DataChangeFilter*>(filter.inner_unique_ptr().get());
  if (!dcFilter)
  {
    if (dynamic_cast<const AggregateFilter*>(filter.inner_unique_ptr().get()))
    {
      result.statusCode = StatusCode{Status::BadMonitoredItemFilterUnsupported,
        ErrorDetail::build("MonitoredItemFilterUnsupported",
          "AggregateFilter is not supported for data-change monitored items",
          "MonitoredItemFactory")
          .context(ua::ContextKeys::nodeId, to_string(nodeId))
          .context(ua::ContextKeys::nodeAttribute, to_string(attributeId))};
    }
    else
    {
      result.statusCode = StatusCode{Status::BadFilterNotAllowed,
        ErrorDetail::build("FilterNotAllowed",
          "Filter type is not allowed for a data-change monitored item",
          "MonitoredItemFactory")
          .context(ua::ContextKeys::nodeId, to_string(nodeId))
          .context(ua::ContextKeys::nodeAttribute, to_string(attributeId))};
    }
    return result;
  }

  result.trigger = dcFilter->trigger();
  if (result.trigger != DataChangeTrigger::Status && result.trigger != DataChangeTrigger::StatusValue &&
      result.trigger != DataChangeTrigger::StatusValueTimestamp)
  {
    result.statusCode = StatusCode{Status::BadMonitoredItemFilterInvalid,
      ErrorDetail::build("MonitoredItemFilterInvalid",
        "DataChangeTrigger is outside its valid enumeration",
        "MonitoredItemFactory")
        .context(ua::ContextKeys::nodeId, to_string(nodeId))
        .context(ua::ContextKeys::nodeAttribute, to_string(attributeId))
        .context(ua::ContextKeys::value, std::to_string(utils::to_underlying(result.trigger)))};
    return result;
  }

  auto deadbandTypeRaw = dcFilter->deadband_type();
  if (deadbandTypeRaw > numeric_cast<uint32_t>(utils::to_underlying(DeadbandType::Percent)))
  {
    result.statusCode = StatusCode{Status::BadDeadbandFilterInvalid,
      ErrorDetail::build("DeadbandFilterInvalid", "Deadband type is out of range", "MonitoredItemFactory")
        .context(ua::ContextKeys::nodeId, to_string(nodeId))};
    return result;
  }

  result.deadbandType = static_cast<DeadbandType>(deadbandTypeRaw);
  result.deadbandValue = dcFilter->deadband_value();

  // Deadband is only valid on Value attribute (spec 7.22.2)
  if (result.deadbandType != DeadbandType::None && attributeId != AttributeId::Value)
  {
    result.statusCode = StatusCode{Status::BadFilterNotAllowed,
      ErrorDetail::build(
        "FilterNotAllowed", "Deadband filter is only allowed on the Value attribute", "MonitoredItemFactory")
        .context(ua::ContextKeys::nodeId, to_string(nodeId))
        .context(ua::ContextKeys::nodeAttribute, to_string(attributeId))};
    return result;
  }

  // Negative deadband value is invalid
  if (result.deadbandValue < 0.0 || std::isnan(result.deadbandValue))
  {
    result.statusCode = StatusCode{Status::BadDeadbandFilterInvalid,
      ErrorDetail::build(
        "DeadbandFilterInvalid", "Deadband value is negative or not a number", "MonitoredItemFactory")
        .context(ua::ContextKeys::nodeId, to_string(nodeId))};
    return result;
  }

  // OPC 10000-8 section 6.2: PercentDeadband is constrained to [0.0, 100.0].
  if (result.deadbandType == DeadbandType::Percent && result.deadbandValue > 100.0)
  {
    result.statusCode = StatusCode{Status::BadDeadbandFilterInvalid,
      ErrorDetail::build(
        "DeadbandFilterInvalid", "Percent deadband value exceeds 100 percent", "MonitoredItemFactory")
        .context(ua::ContextKeys::nodeId, to_string(nodeId))
        .context(ua::ContextKeys::actual, std::to_string(result.deadbandValue))
        .context(ua::ContextKeys::limit, 100)};
    return result;
  }

  return result;
}

/// Revise event queue size per spec rules (SVR-EVT-MON-004/005).
/// Event queue minimum is 1, clamped to [1, maxConfigured].
static uint32_t revise_event_queue_size(uint32_t requested, uint32_t defaultSize, uint32_t maxConfigured)
{
  if (requested == 0)
  {
    // Server default - distinct from minimum (queueSize=1).
    if (maxConfigured > 0 && defaultSize > maxConfigured)
      defaultSize = maxConfigured;
    return std::max(defaultSize, 1u);
  }

  if (requested == 1)
    return 1;  // Server minimum

  if (maxConfigured > 0 && requested > maxConfigured)
    return maxConfigured;

  return requested;
}

MonitoredItemCreateOutcome validate_and_build_monitored_item(
  const MonitoredItemCreateContext& context, IntegerId assignedId)
{
  MonitoredItemCreateOutcome outcome;

  const auto& request = context.request;
  const auto& params = request.requested_parameters();
  const auto& itemToMonitor = request.item_to_monitor();

  // Validate MonitoringMode
  auto mode = request.monitoring_mode();
  if (mode != MonitoringMode::Disabled && mode != MonitoringMode::Sampling &&
      mode != MonitoringMode::Reporting)
  {
    outcome.statusCode = StatusCode{Status::BadMonitoringModeInvalid,
      ErrorDetail::build(
        "MonitoringModeInvalid", "Requested monitoring mode is not a valid value", "MonitoredItemFactory")
        .context(ua::ContextKeys::nodeId, to_string(itemToMonitor.node_id()))
        .context(ua::ContextKeys::value, std::to_string(utils::to_underlying(mode)))};
    return outcome;
  }

  // Validate AttributeId
  auto attributeIdRaw = itemToMonitor.attribute_id();
  if (attributeIdRaw == 0 || attributeIdRaw > utils::to_underlying(AttributeId::AccessLevelEx))
  {
    outcome.statusCode = StatusCode{Status::BadAttributeIdInvalid,
      ErrorDetail::build("AttributeIdInvalid",
        "Requested attribute id is not valid for the target node",
        "MonitoredItemFactory")
        .context(ua::ContextKeys::nodeId, to_string(itemToMonitor.node_id()))
        .context(
          ua::ContextKeys::nodeAttribute, to_string(utils::from_underlying<AttributeId>(attributeIdRaw)))};
    return outcome;
  }
  auto attributeId = utils::from_underlying<AttributeId>(attributeIdRaw);

  // Validate IndexRange up front: a non-empty but malformed range (inverted,
  // negative, unparseable) can never produce a valid slice, so the item is
  // rejected at create time with Bad_IndexRangeInvalid rather than silently
  // accepted. Mirrors the Read service's range parsing.
  if (!itemToMonitor.index_range().empty())
  {
    auto rangeResult = parse_numeric_range(itemToMonitor.index_range());
    if (rangeResult.is_bad())
    {
      outcome.statusCode = rangeResult.status_code();
      return outcome;
    }
  }

  // --- Event monitoring path ---
  if (attributeId == AttributeId::EventNotifier)
  {
    // Extract and compile EventFilter from monitoring parameters
    const auto& filterRef = params.filter();
    if (!filterRef.inner_unique_ptr())
    {
      // SVR-EVT-MON-003: EventFilter is required for EventNotifier monitoring
      outcome.statusCode = StatusCode{Status::BadMonitoredItemFilterInvalid,
        ErrorDetail::build("MonitoredItemFilterInvalid",
          "EventNotifier monitoring requires an EventFilter",
          "MonitoredItemFactory")
          .context(ua::ContextKeys::nodeId, to_string(itemToMonitor.node_id()))
          .context(ua::ContextKeys::nodeAttribute, to_string(attributeId))};
      return outcome;
    }

    auto* eventFilter = dynamic_cast<const EventFilter*>(filterRef.inner_unique_ptr().get());
    if (!eventFilter)
    {
      // DataChangeFilter on EventNotifier -> Bad_FilterNotAllowed
      outcome.statusCode = StatusCode{Status::BadFilterNotAllowed,
        ErrorDetail::build("FilterNotAllowed",
          "DataChangeFilter is not allowed on an EventNotifier monitored item",
          "MonitoredItemFactory")
          .context(ua::ContextKeys::nodeId, to_string(itemToMonitor.node_id()))
          .context(ua::ContextKeys::nodeAttribute, to_string(attributeId))};
      return outcome;
    }

    // Compile the event filter, enforcing the configured select/where clause caps (SVR-EVT-CAP-001/002).
    auto compiled = CompiledEventFilter::compile(*eventFilter,
      {.maxSelectClauses = context.maxSelectClauses,
        .maxWhereClauseElements = context.maxWhereClauseElements,
        .maxWhereClauseOperandBytes = context.maxWhereClauseOperandBytes});
    if (compiled.overallStatus.is_bad())
    {
      outcome.statusCode = compiled.overallStatus;
      outcome.eventFilterResult = std::move(compiled.filterResult);
      return outcome;
    }

    // Event sampling interval is always 0 (SVR-EVT-MON-002)
    const Duration revisedInterval = 0;
    const uint32_t revisedQueueSize =
      revise_event_queue_size(params.queue_size(), context.defaultEventQueueSize, context.maxEventQueueSize);

    auto item = std::make_unique<MonitoredItem>();
    item->id = assignedId;
    item->clientHandle = params.client_handle();
    item->itemToMonitor = itemToMonitor;
    item->monitoringMode = mode;
    item->timestampsToReturn = context.timestampsToReturn;
    item->samplingInterval = revisedInterval;
    item->queueSize = revisedQueueSize;
    item->discardOldest = params.discard_oldest();
    item->isEventItem = true;
    item->eventFilter = std::move(compiled.filter);
    item->namespaceIndex = itemToMonitor.node_id().namespace_index();

    outcome.statusCode = StatusCode{Status::Good};
    outcome.item = std::move(item);
    outcome.revisedSamplingInterval = revisedInterval;
    outcome.revisedQueueSize = revisedQueueSize;
    outcome.eventFilterResult = std::move(compiled.filterResult);
    return outcome;
  }

  // --- Data-change monitoring path (existing) ---

  // Parse filter
  const bool isNonValueAttribute = (attributeId != AttributeId::Value);
  auto filter = parse_data_change_filter(params.filter(), itemToMonitor.node_id(), attributeId);
  if (filter.statusCode.is_bad())
  {
    outcome.statusCode = filter.statusCode;
    return outcome;
  }

  // Revise parameters
  const Duration revisedInterval = revise_sampling_interval(params.sampling_interval(),
    context.publishingInterval,
    context.minSamplingInterval,
    context.maxSamplingInterval);
  const uint32_t revisedQueueSize = revise_queue_size(params.queue_size(), context.maxQueueSize);

  // Build the MonitoredItem
  auto item = std::make_unique<MonitoredItem>();
  item->id = assignedId;
  item->clientHandle = params.client_handle();
  item->itemToMonitor = itemToMonitor;
  item->monitoringMode = mode;
  item->timestampsToReturn = context.timestampsToReturn;
  item->samplingInterval = revisedInterval;
  item->queueSize = revisedQueueSize;
  item->discardOldest = params.discard_oldest();
  item->trigger = filter.trigger;
  item->deadbandType = filter.deadbandType;
  item->deadbandValue = filter.deadbandValue;
  item->isNonValueAttribute = isNonValueAttribute;
  item->namespaceIndex = itemToMonitor.node_id().namespace_index();

  outcome.statusCode = StatusCode{Status::Good};
  outcome.item = std::move(item);
  outcome.revisedSamplingInterval = revisedInterval;
  outcome.revisedQueueSize = revisedQueueSize;
  return outcome;
}

}  // namespace ua::server
