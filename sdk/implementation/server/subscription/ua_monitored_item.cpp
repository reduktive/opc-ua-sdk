// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_monitored_item.h"

#include "ua_date_time.h"
#include "ua_monitoring_equality.h"

#include "ua_base_event.h"
#include "ua_numeric_range_parser.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_to_result.h"
#include "ua_value_range_check.h"
#include "ua_variant.h"

#include <atomic>
#include <cmath>
#include <vector>
#include <cstring>
#include <limits>
#include <utility>

namespace ua::server
{

namespace
{

bool is_nan_value(double value)
{
  return std::isnan(value);
}

/// Compare two StatusCodes for data change filter purposes.
/// Returns true if they differ. Compares only the quality status (severity + subcode), not the
/// transient delivery InfoBits (Overflow, SemanticsChanged, StructureChanged) - those are
/// per-notification metadata, not a change in the value's status. Without this, a value that gained
/// a transient bit (e.g. SemanticsChanged) and became the deadband baseline would make the next
/// plain value look like a status change and spuriously bypass the deadband.
///
/// A DataValue that omits its StatusCode has status Good (OPC 10000-6 5.2.2.17), so an absent status
/// and a Good one are the same status. Treating them as different made the first plain sample after a
/// synthesised SemanticsChanged notification (which must carry an explicit status for the bit) look like
/// a status change, so the Client received a second, spurious notification.
bool status_changed(const std::optional<StatusCode>& oldStatus, const std::optional<StatusCode>& newStatus)
{
  return !oldStatus.value_or(StatusCode{}).equivalent(newStatus.value_or(StatusCode{}));
}

/// Whether @p value carries the StructureChanged bit (OPC 10000-4 7.39.1 Table 180).
bool carries_structure_change(const DataValue& value)
{
  const auto& valueStatus = value.status();
  return valueStatus && valueStatus.value().structure_changed();
}

/// Sets the StructureChanged bit on @p value, keeping the rest of its status.
void set_structure_changed(DataValue& value)
{
  auto& status = value.status();
  status.emplace(status.value_or(StatusCode{})).structure_changed(true);
}

template<typename T>
std::vector<double> widen(const Array<T>& values)
{
  std::vector<double> out;
  out.reserve(values.size());
  for (const auto& value : values)
    out.push_back(static_cast<double>(value));
  return out;
}

/// The elements of a numeric array Variant as doubles, or nullopt if it is not a numeric array.
std::optional<std::vector<double>> numeric_elements(const Variant& variant)
{
  if (variant.is_array_of_int8())
    return widen(variant.as<Array<int8_t>>());
  if (variant.is_array_of_uint8())
    return widen(variant.as<Array<uint8_t>>());
  if (variant.is_array_of_int16())
    return widen(variant.as<Array<int16_t>>());
  if (variant.is_array_of_uint16())
    return widen(variant.as<Array<uint16_t>>());
  if (variant.is_array_of_int32())
    return widen(variant.as<Array<int32_t>>());
  if (variant.is_array_of_uint32())
    return widen(variant.as<Array<uint32_t>>());
  if (variant.is_array_of_int64())
    return widen(variant.as<Array<int64_t>>());
  if (variant.is_array_of_uint64())
    return widen(variant.as<Array<uint64_t>>());
  if (variant.is_array_of_float())
    return widen(variant.as<Array<float>>());
  if (variant.is_array_of_double())
    return widen(variant.as<Array<double>>());
  return std::nullopt;
}

/// Part 4 7.22.2 applied to arrays: a change of length is always reported, and otherwise the change
/// is reported when any element moves by more than @p threshold. NaN follows the scalar rule per
/// element: entering NaN reports, staying NaN does not.
std::optional<bool> array_exceeds_deadband(const Variant& oldValue, const Variant& newValue, double threshold)
{
  auto oldElements = numeric_elements(oldValue);
  auto newElements = numeric_elements(newValue);
  if (!oldElements || !newElements)
    return std::nullopt;
  if (oldElements->size() != newElements->size())
    return true;
  for (size_t index = 0; index < newElements->size(); ++index)
  {
    const double before = (*oldElements)[index];
    const double after = (*newElements)[index];
    if (std::isnan(before) && std::isnan(after))
      continue;
    if (std::isnan(after) || std::isnan(before))
      return true;
    if (std::abs(after - before) > threshold)
      return true;
  }
  return false;
}

/// Replaces @p value, when its status is not Bad and its Value is larger than @p range in a dimension, by
/// `Bad_InternalError` with the ErrorDetail `NamespaceValueExceedsRange` for @p nodeId, keeping the value's
/// timestamps (NR-10 rule 8). The value is never narrowed: its producer was asked for the range.
void fail_beyond_range(DataValue& value, const ParsedNumericRange& range, const NodeId& nodeId)
{
  const auto& valueStatus = value.status();
  if (valueStatus && valueStatus.value().is_bad())
    return;
  std::optional<StatusCode> failure;
  try
  {
    if (const auto excess = ua::detail::first_dimension_beyond(value.value(), range))
      failure = ua::detail::value_exceeds_range(nodeId, *excess, "MonitoredItem");
  }
  catch (...)
  {
    failure = exception_to_status_code(std::current_exception());
  }
  if (!failure)
    return;
  DataValue failed{std::move(*failure)};
  failed.source_timestamp() = value.source_timestamp();
  failed.source_pico_seconds() = value.source_pico_seconds();
  failed.server_timestamp() = value.server_timestamp();
  failed.server_pico_seconds() = value.server_pico_seconds();
  value = std::move(failed);
}

}  // namespace

std::optional<double> MonitoredItem::to_numeric(const Variant& variant)
{
  if (variant.is_boolean())
    return variant.as<bool>() ? 1.0 : 0.0;
  if (variant.is_int8())
    return static_cast<double>(variant.as<int8_t>());
  if (variant.is_uint8())
    return static_cast<double>(variant.as<uint8_t>());
  if (variant.is_int16())
    return static_cast<double>(variant.as<int16_t>());
  if (variant.is_uint16())
    return static_cast<double>(variant.as<uint16_t>());
  if (variant.is_int32())
    return static_cast<double>(variant.as<int32_t>());
  if (variant.is_uint32())
    return static_cast<double>(variant.as<uint32_t>());
  if (variant.is_int64())
    return static_cast<double>(variant.as<int64_t>());
  if (variant.is_uint64())
    return static_cast<double>(variant.as<uint64_t>());
  if (variant.is_float())
    return static_cast<double>(variant.as<float>());
  if (variant.is_double())
    return variant.as<double>();
  return std::nullopt;
}

bool MonitoredItem::passes_filter(const DataValue& newValue) const
{
  // Non-Value attributes bypass the filter entirely (SVR-MI-GEN-071).
  if (isNonValueAttribute)
    return true;

  // No previous value - always passes.
  if (!lastQueuedValue.has_value())
    return true;

  const auto& oldValue = *lastQueuedValue;

  switch (trigger)
  {
  case DataChangeTrigger::Status:
  {
    return status_changed(oldValue.status(), newValue.status());
  }

  case DataChangeTrigger::StatusValue:
  {
    // Status change always passes (deadband ignored on status change).
    if (status_changed(oldValue.status(), newValue.status()))
      return true;

    // Value comparison with deadband.
    return passes_value_deadband(oldValue, newValue);
  }

  case DataChangeTrigger::StatusValueTimestamp:
  {
    // Status change always passes.
    if (status_changed(oldValue.status(), newValue.status()))
      return true;

    // If deadband is set, it overrides timestamp comparison.
    if (deadbandType != DeadbandType::None)
      return passes_value_deadband(oldValue, newValue);

    // Value change passes (NaN-aware: two NaN samples compare equal).
    if (!values_equal_for_monitoring(oldValue.value(), newValue.value()))
      return true;

    // Timestamp change passes.
    return oldValue.source_timestamp() != newValue.source_timestamp();
  }
  }

  return true;
}

bool MonitoredItem::passes_value_deadband(const DataValue& oldValue, const DataValue& newValue) const
{
  // Any value change if no deadband (NaN-aware equality).
  if (deadbandType == DeadbandType::None)
    return !values_equal_for_monitoring(oldValue.value(), newValue.value());

  if (deadbandType == DeadbandType::Absolute)
  {
    if (auto arrayDecision = array_exceeds_deadband(oldValue.value(), newValue.value(), deadbandValue))
      return *arrayDecision;

    auto oldNumeric = to_numeric(oldValue.value());
    auto newNumeric = to_numeric(newValue.value());

    if (!oldNumeric.has_value() || !newNumeric.has_value())
    {
      // Non-numeric values - fall back to equality comparison.
      return !values_equal_for_monitoring(oldValue.value(), newValue.value());
    }

    // SVR-MI-GEN-052: NaN dedup - if both are NaN, reject (only report once on entering NaN).
    if (is_nan_value(*newNumeric) && is_nan_value(*oldNumeric))
      return false;

    // If new value is NaN but old was not, report the transition into NaN.
    if (is_nan_value(*newNumeric))
      return true;

    return std::abs(*newNumeric - *oldNumeric) > deadbandValue;
  }

  if (deadbandType == DeadbandType::Percent)
  {
    // CreateMonitoredItems and ModifyMonitoredItems refuse a PercentDeadband whose node has no usable
    // EURange with Bad_DeadbandFilterInvalid (OPC 10000-8 Table 29). Reached only when the EURange
    // Property later changes to a value that is not a usable range: the Subscription logs that, and
    // reporting every change is the safe direction.
    if (!hasEuRange || !std::isfinite(euRangeLow) || !std::isfinite(euRangeHigh) ||
        euRangeHigh <= euRangeLow || !std::isfinite(euRangeHigh - euRangeLow))
      return !values_equal_for_monitoring(oldValue.value(), newValue.value());

    if (auto arrayDecision = array_exceeds_deadband(
          oldValue.value(), newValue.value(), deadbandValue / 100.0 * (euRangeHigh - euRangeLow)))
      return *arrayDecision;

    auto oldNumeric = to_numeric(oldValue.value());
    auto newNumeric = to_numeric(newValue.value());

    if (!oldNumeric.has_value() || !newNumeric.has_value())
      return !values_equal_for_monitoring(oldValue.value(), newValue.value());

    // NaN dedup - same logic as absolute deadband.
    if (is_nan_value(*newNumeric) && is_nan_value(*oldNumeric))
      return false;
    if (is_nan_value(*newNumeric))
      return true;

    const double range = euRangeHigh - euRangeLow;
    const double threshold = deadbandValue / 100.0 * range;
    return std::abs(*newNumeric - *oldNumeric) > threshold;
  }

  // Unknown deadband type - report all changes.
  return !values_equal_for_monitoring(oldValue.value(), newValue.value());
}

bool MonitoredItem::evaluate_and_enqueue(DataValue value, std::optional<DataValue> userIndependentValue)
{
  if (monitoringMode == MonitoringMode::Disabled)
    return false;

  apply_index_range(value, userIndependentValue);

  if (pendingSemanticChange)
  {
    // Arm/apply rule (008): while armed, OR the SemanticsChanged bit into the sampled value and
    // bypass the DataChangeFilter outright. A semantics change must reach the client regardless of
    // deadband, and bypassing (rather than relying on the status-change deadband exception) re-flags
    // the surviving value even when a later unchanged sample overwrites a queueSize-1 slot. Stay
    // armed until the bit-carrying value is actually published (cleared in drain).
    StatusCode status = value.status().value_or(StatusCode{});
    status.semantics_changed(true);
    value.status() = status;
    // The retained value keeps its own status, as mark_queued_semantics_changed leaves it: it is the
    // projection's input, and the client's status is not its quality.
    if (userIndependentValue)
    {
      auto& retainedStatus = userIndependentValue->status();
      retainedStatus.emplace(retainedStatus.value_or(StatusCode{})).semantics_changed(true);
    }
    enqueue(std::move(value), std::move(userIndependentValue));
    return true;
  }

  // A value owed the StructureChanged bit is not held back by the filter: the bit must reach the client.
  if (!pendingStructureChange && !passes_filter(value))
    return false;

  enqueue(std::move(value), std::move(userIndependentValue));
  return true;
}

void MonitoredItem::enqueue_initial(DataValue value, std::optional<DataValue> userIndependentValue)
{
  apply_index_range(value, userIndependentValue);
  // SVR-MI-GEN-060: first sample is enqueued without applying filter.
  enqueue(std::move(value), std::move(userIndependentValue));
}

bool MonitoredItem::enqueue_reprojection_if_changed(
  DataValue value, std::optional<DataValue> userIndependentValue)
{
  if (monitoringMode == MonitoringMode::Disabled)
    return false;

  apply_index_range(value, userIndependentValue);
  // The latest user-independent value is refreshed by every sample, changed or not, so it carries a
  // later ServerTimestamp than the last value queued even when nothing the client sees has changed. That
  // alone is not a change, and resending the value for it would break sendInitialValues=false.
  if (lastQueuedValue)
  {
    const auto withoutServerTimestamp = [](DataValue v)
    {
      v.server_timestamp().reset();
      v.server_pico_seconds().reset();
      return v;
    };
    if (withoutServerTimestamp(*lastQueuedValue) == withoutServerTimestamp(value))
      return false;
  }

  enqueue(std::move(value), std::move(userIndependentValue));
  return true;
}

bool MonitoredItem::mark_queued_semantics_changed()
{
  if (monitoringMode == MonitoringMode::Disabled || isEventItem || queue.empty())
    return false;
  const auto setBit = [](DataValue& value)
  {
    auto& status = value.status();
    status.emplace(status.value_or(StatusCode{})).semantics_changed(true);
  };
  setBit(queue.back());
  if (!queuedUserIndependentValues.empty() && queuedUserIndependentValues.back())
    setBit(*queuedUserIndependentValues.back());
  return true;
}

bool MonitoredItem::enqueue_semantic_from_cache()
{
  if (monitoringMode == MonitoringMode::Disabled)
    return false;
  if (!lastSentValue.has_value())
    return false;

  // The cached value was already index-range-sliced before it was sent, so do NOT re-slice it; just
  // OR the SemanticsChanged bit onto the quality the client last saw and enqueue. Overflow and
  // StructureChanged belong to the notification that was sent, not to this synthesized sample, so clear them.
  DataValue synthesized = *lastSentValue;
  StatusCode status = synthesized.status().value_or(StatusCode{});
  status.semantics_changed(true);
  status.overflow(false);
  status.structure_changed(false);
  synthesized.status() = status;
  // The input the cached value was made from, so that a Republish of this notification projects it again
  // rather than refusing a notification with no retained input.
  std::optional<DataValue> retained = lastSentUserIndependentValue;
  if (retained)
  {
    StatusCode& retainedStatus = retained->status().emplace(retained->status().value_or(StatusCode{}));
    retainedStatus.semantics_changed(true);
    retainedStatus.overflow(false);
    retainedStatus.structure_changed(false);
  }
  enqueue(std::move(synthesized), std::move(retained));
  return true;
}

bool MonitoredItem::mark_structure_changed()
{
  if (monitoringMode == MonitoringMode::Disabled || isEventItem)
    return false;
  if (!queue.empty())
  {
    // The next DataChange the Client receives carries the bit, as for SemanticsChanged.
    set_structure_changed(queue.back());
    if (!queuedUserIndependentValues.empty() && queuedUserIndependentValues.back())
      set_structure_changed(*queuedUserIndependentValues.back());
    return false;
  }
  // Taken by the next value enqueued: the one made below, or, with nothing sent yet, the item's first value.
  pendingStructureChange = true;
  if (!lastSentValue.has_value())
    return false;

  // As enqueue_semantic_from_cache: the value the client last saw, without the bits of the notification that
  // sent it; the SemanticsChanged bit only while that change is still owed.
  const auto fresh = [this](DataValue& value)
  {
    StatusCode& engaged = value.status().emplace(value.status().value_or(StatusCode{}));
    engaged.overflow(false);
    engaged.structure_changed(false);
    engaged.semantics_changed(pendingSemanticChange);
  };
  DataValue synthesized = *lastSentValue;
  fresh(synthesized);
  std::optional<DataValue> retained = lastSentUserIndependentValue;
  if (retained)
    fresh(*retained);
  enqueue(std::move(synthesized), std::move(retained));
  return true;
}

void MonitoredItem::apply_index_range(DataValue& value, std::optional<DataValue>& userIndependentValue) const
{
  const auto& range = itemToMonitor.index_range();
  if (range.empty())
    return;
  if (AccessControl::produces_value(utils::from_underlying<AttributeId>(itemToMonitor.attribute_id())))
  {
    // The server produced this value from the Attribute the namespace holds, registered with no range
    // (DL-69 (D3)), so the item narrows it as the Read service would. The user-independent value is the
    // projection's input and stays whole: a Republish projects it again and narrows that.
    index_range_utils::apply_to_value(value, range);
    return;
  }
  // The range syntax was validated at create time; a range that does not parse fails the value as the Read
  // service would fail it.
  const auto parsed = parse_numeric_range(range);
  if (!parsed.is_good())
  {
    index_range_utils::apply_to_value(value, range);
    if (userIndependentValue)
      index_range_utils::apply_to_value(*userIndependentValue, range);
    return;
  }
  fail_beyond_range(value, parsed.value(), itemToMonitor.node_id());
  if (userIndependentValue)
    fail_beyond_range(*userIndependentValue, parsed.value(), itemToMonitor.node_id());
}

void MonitoredItem::enqueue(DataValue value, std::optional<DataValue> userIndependentValue)
{
  // Part 4 7.11: the ServerTimestamp is when the Server received the value. A source that did not stamp
  // one - a read handler answering only its SourceTimestamp - is stamped as its value is taken in, so a
  // client asking for it is not sent a value without one. Stamped after lastQueuedValue is recorded:
  // that is the value as the source gave it, which the duplicate checks compare like with like.
  const auto stamp = [](DataValue& queued)
  {
    if (const auto& serverTimestamp = queued.server_timestamp();
        !serverTimestamp || serverTimestamp->is_null())
      queued.server_timestamp() = DateTime::now();
  };
  // StructureChanged is owed to this value when the item was marked with no value to carry the bit, or when
  // the notification that carries it is discarded below: "the bit must be set on the next data change
  // notification in the queue" (OPC 10000-4 7.39.1 Table 180). Set after lastQueuedValue is recorded, like
  // the ServerTimestamp: the bit belongs to the notification, not to the value the source gave.
  bool takesStructureChange = std::exchange(pendingStructureChange, false);
  const auto takeStructureChange = [&takesStructureChange](
                                     DataValue& queued, std::optional<DataValue>& retained)
  {
    if (!takesStructureChange)
      return;
    set_structure_changed(queued);
    if (retained)
      set_structure_changed(*retained);
  };

  if (queueSize == 1)
  {
    // SVR-MI-GEN-024: queue size 1 - replace the single entry, do NOT set Overflow bit.
    // Discard policy is ignored.
    takesStructureChange =
      takesStructureChange || (!queue.empty() && carries_structure_change(queue.front()));
    queue.clear();
    queuedUserIndependentValues.clear();
    lastQueuedValue = value;
    takeStructureChange(value, userIndependentValue);
    stamp(value);
    queue.push_back(std::move(value));
    queuedUserIndependentValues.push_back(std::move(userIndependentValue));
    return;
  }

  if (queue.size() >= queueSize)
  {
    ++dataQueueOverflowCount;
    if (discardOldest)
    {
      // SVR-MI-GEN-022: discard oldest, set Overflow bit on the new front (next oldest).
      const bool discardedStructureChange = !queue.empty() && carries_structure_change(queue.front());
      queue.pop_front();
      if (!queuedUserIndependentValues.empty())
        queuedUserIndependentValues.pop_front();
      if (!queue.empty())
      {
        auto& frontStatus = queue.front().status();
        StatusCode& engagedStatus = frontStatus.emplace(frontStatus.value_or(StatusCode{}));
        engagedStatus.overflow(true);
        engagedStatus.structure_changed(engagedStatus.structure_changed() || discardedStructureChange);
        if (!queuedUserIndependentValues.empty())
        {
          auto& retainedValue = queuedUserIndependentValues.front();
          if (retainedValue)
          {
            auto& retainedStatus = retainedValue.value().status();
            StatusCode& retainedEngaged = retainedStatus.emplace(retainedStatus.value_or(StatusCode{}));
            retainedEngaged.overflow(true);
            retainedEngaged.structure_changed(
              retainedEngaged.structure_changed() || discardedStructureChange);
          }
        }
      }
      else
      {
        takesStructureChange = takesStructureChange || discardedStructureChange;
      }
    }
    else
    {
      // SVR-MI-GEN-023: discard newest (replace back), set Overflow bit on new value.
      takesStructureChange =
        takesStructureChange || (!queue.empty() && carries_structure_change(queue.back()));
      queue.pop_back();
      if (!queuedUserIndependentValues.empty())
        queuedUserIndependentValues.pop_back();
      auto& valueStatus = value.status();
      StatusCode& engagedStatus = valueStatus.emplace(valueStatus.value_or(StatusCode{}));
      engagedStatus.overflow(true);
      if (userIndependentValue)
      {
        auto& retainedStatus = userIndependentValue->status();
        StatusCode& retainedEngaged = retainedStatus.emplace(retainedStatus.value_or(StatusCode{}));
        retainedEngaged.overflow(true);
      }
    }
  }

  lastQueuedValue = value;
  takeStructureChange(value, userIndependentValue);
  stamp(value);
  queue.push_back(std::move(value));
  queuedUserIndependentValues.push_back(std::move(userIndependentValue));
}

void MonitoredItem::drain(uint32_t maxCount, std::vector<MonitoredItemNotification>& out)
{
  std::vector<RetainedDataProjection> discardedProjections;
  drain(maxCount, out, discardedProjections);
}

void MonitoredItem::drain(uint32_t maxCount, std::vector<MonitoredItemNotification>& out,
  std::vector<RetainedDataProjection>& retainedProjections)
{
  const uint32_t count = (maxCount == 0) ? numeric_cast<uint32_t>(queue.size())
                                         : std::min(maxCount, numeric_cast<uint32_t>(queue.size()));

  for (uint32_t i = 0; i < count; ++i)
  {
    MonitoredItemNotification notification;
    notification.client_handle() = clientHandle;
    notification.value() = std::move(queue.front());
    queue.pop_front();
    std::optional<DataValue> userIndependentValue;
    if (!queuedUserIndependentValues.empty())
    {
      userIndependentValue = std::move(queuedUserIndependentValues.front());
      queuedUserIndependentValues.pop_front();
    }
    const auto attribute = utils::from_underlying<AttributeId>(itemToMonitor.attribute_id());
    // A value the server produces is retained whole and narrowed again after the Republish projects it
    // (COMP-SVR-NAMESPACE-CALLS-15 rule 4); any other is retained as its producer narrowed it.
    retainedProjections.push_back(RetainedDataProjection{id,
      itemToMonitor.node_id(),
      attribute,
      std::move(userIndependentValue),
      AccessControl::produces_value(attribute) ? itemToMonitor.index_range() : NumericRange{}});

    // Clear-on-publish (008): the SemanticsChanged bit is delivered exactly once. The flag stays
    // armed until a value carrying the bit is actually drained here (the single drain point), so it
    // survives queue overwrite/overflow until a flagged value really ships.
    const auto& notificationStatus = notification.value().status();
    if (pendingSemanticChange && notificationStatus.has_value() && notificationStatus->semantics_changed())
    {
      pendingSemanticChange = false;
    }

    lastSentValue = notification.value();

    // Part 4 5.12.2.2: the CreateMonitoredItems timestampsToReturn decides which timestamps each
    // notification carries. Applied here, as the value leaves the queue, so the change detection and the
    // retained values above still see both.
    const bool wantSource =
      timestampsToReturn == TimestampsToReturn::Source || timestampsToReturn == TimestampsToReturn::Both;
    const bool wantServer =
      timestampsToReturn == TimestampsToReturn::Server || timestampsToReturn == TimestampsToReturn::Both;
    if (!wantSource)
    {
      notification.value().source_timestamp().reset();
      notification.value().source_pico_seconds().reset();
    }
    if (!wantServer)
    {
      notification.value().server_timestamp().reset();
      notification.value().server_pico_seconds().reset();
    }
    out.push_back(std::move(notification));
  }
  // Copied once per drain, from the last value drained: only the input of lastSentValue is kept.
  if (count > 0)
  {
    lastSentUserIndependentValue = retainedProjections.back().userIndependentValue;
  }
}

void MonitoredItem::enqueue_event(EventFieldList fields, bool isConditionEvent)
{
  enqueue_event(std::move(fields), isConditionEvent, NodeId{}, NodeId{});
}

void MonitoredItem::enqueue_event(
  EventFieldList fields, bool isConditionEvent, NodeId sourceNode, NodeId eventType)
{
  enqueue_event(std::move(fields),
    isConditionEvent,
    RetainedEventProjection{clientHandle, std::move(sourceNode), std::move(eventType), {}, {}, {}});
}

void MonitoredItem::note_event_queue_overflow()
{
  // A loss counted before the delivered queue is involved (the subscription's hand-off FIFO, SVC-5).
  // The overflow event itself is inserted by enqueue_event, on the next delivery, through the one path
  // that knows the queue's slot rules and whose caller keeps the subscription's reportable bookkeeping.
  ++eventQueueOverflowCount;
  overflowEventPending = true;
}

void MonitoredItem::insert_overflow_event_once()
{
  overflowEventPending = false;
  // Generate EventQueueOverflowEventType on first overflow (SVR-EVT-MON-006).
  // The overflow event is in addition to the queue size (SVR-EVT-MON-007).
  if (!overflowEventInserted && eventFilter)
  {
    static std::atomic<uint64_t> overflowEventIdCounter{1};

    BaseEvent overflowEvent;
    overflowEvent.eventType = NodeId{ObjectTypeId::EventQueueOverflowEventType};
    overflowEvent.sourceNode = NodeId{ObjectId::Server};  // SVR-EVT-TYP-001
    overflowEvent.sourceName = String{"Internal/EventQueueOverflow"};  // SVR-EVT-TYP-002
    overflowEvent.severity = 1;
    overflowEvent.message = LocalizedText{LocaleId{}, String{"Event queue overflow"}};
    overflowEvent.time = DateTime::now();
    overflowEvent.receiveTime = overflowEvent.time;

    // Assign unique EventId (SVR-EVT-BET-003).
    auto ovfId = overflowEventIdCounter++;
    overflowEvent.eventId.resize(sizeof(ovfId));
    std::memcpy(overflowEvent.eventId.data(), &ovfId, sizeof(ovfId));

    // Project through select clauses (bypasses where clause - SVR-EVT-FLT-022).
    auto overflowFields = eventFilter->project(overflowEvent, clientHandle);
    RetainedEventProjection overflowProjection{clientHandle,
      overflowEvent.sourceNode,
      overflowEvent.eventType,
      std::make_shared<const BaseEvent>(overflowEvent),
      {},
      eventFilter->retained_copy()};

    if (discardOldest)
    {
      // SVR-EVT-MON-008: overflow event at front, never discarded.
      eventQueue.push_front(
        QueuedEvent{std::move(overflowFields), false, std::move(overflowProjection), true});
    }
    else
    {
      // SVR-EVT-MON-008: overflow event at end.
      eventQueue.push_back(
        QueuedEvent{std::move(overflowFields), false, std::move(overflowProjection), true});
    }
    overflowEventInserted = true;
    overflowEventQueued = true;
  }
}

void MonitoredItem::enqueue_event(
  EventFieldList fields, bool isConditionEvent, RetainedEventProjection projection)
{
  if (monitoringMode == MonitoringMode::Disabled)
    return;

  // The overflow event is queued in addition to the queue size (SVR-EVT-MON-007), so only the regular
  // events count against it.
  size_t queuedEvents = eventQueue.size();
  if (overflowEventQueued)
    --queuedEvents;
  if (queuedEvents >= queueSize)
  {
    ++eventQueueOverflowCount;
    insert_overflow_event_once();

    if (discardOldest)
    {
      // Discard the oldest regular event: the front, unless the overflow event is there. A Publish may
      // have taken the overflow event and left the rest, and then the front is the oldest event.
      size_t discardIndex = 0;
      if (eventQueue.front().overflowEvent && eventQueue.size() > 1)
        discardIndex = 1;

      // COND-920: Track condition event loss for RefreshRequired emission.
      if (eventQueue[discardIndex].conditionEvent)
        refreshRequired = true;

      eventQueue.erase(eventQueue.begin() + static_cast<ptrdiff_t>(discardIndex));
    }
    else
    {
      // Discard newest - drop the incoming event.
      // COND-920: Track condition event loss for RefreshRequired emission.
      if (isConditionEvent)
        refreshRequired = true;
      return;
    }
  }

  else if (overflowEventPending && discardOldest)
  {
    // Losses accounted before authorization (SVC-5) get their overflow event with this delivery, at the
    // front (SVR-EVT-MON-008). Under discard-newest the marker goes after the last event kept at the
    // loss; the subscription inserts it when that entry has left the hand-off FIFO.
    insert_overflow_event_once();
  }
  projection.clientHandle = clientHandle;
  eventQueue.push_back(QueuedEvent{std::move(fields), isConditionEvent, std::move(projection)});
}

void MonitoredItem::drain_events(uint32_t maxCount, std::vector<EventFieldList>& out)
{
  std::vector<QueuedEvent> drained;
  drain_events(maxCount, drained);
  out.reserve(out.size() + drained.size());
  for (auto& event : drained)
    out.push_back(std::move(event.fields));
}

void MonitoredItem::drain_events(uint32_t maxCount, std::vector<QueuedEvent>& out)
{
  uint32_t count = numeric_cast<uint32_t>(eventQueue.size());
  if (maxCount != 0)
    count = std::min(maxCount, count);

  for (uint32_t i = 0; i < count; ++i)
  {
    if (eventQueue.front().overflowEvent)
      overflowEventQueued = false;
    out.push_back(std::move(eventQueue.front()));
    eventQueue.pop_front();
  }

  // Reset overflow flag when queue is fully drained.
  if (eventQueue.empty())
  {
    overflowEventInserted = false;
  }
}

bool MonitoredItem::has_reportable_notifications() const
{
  const bool hasQueued = isEventItem ? !eventQueue.empty() : !queue.empty();
  if (!hasQueued)
    return false;

  if (monitoringMode == MonitoringMode::Reporting)
    return true;

  // SAMPLING mode items may be reported if triggered.
  if (monitoringMode == MonitoringMode::Sampling && triggeredReportPending)
    return true;

  return false;
}

}  // namespace ua::server
