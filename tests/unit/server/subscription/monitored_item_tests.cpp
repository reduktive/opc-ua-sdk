// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include <cmath>
#include <limits>

#include "ua_array.h"
#include "ua_monitored_item.h"
#include "ua_role_permission_type.h"
#include "ua_status_code.h"
#include "ua_variant.h"

using namespace ua;
using namespace ua::server;

namespace
{

DataValue make_value(double val, StatusCode status = StatusCode{})
{
  DataValue dv;
  dv.value() = Variant{val};
  dv.status() = status;
  return dv;
}

DataValue make_float_value(float val, StatusCode status = StatusCode{})
{
  DataValue dv;
  dv.value() = Variant{val};
  dv.status() = status;
  return dv;
}

DataValue make_value_with_timestamp(double val, DateTime sourceTimestamp)
{
  DataValue dv;
  dv.value() = Variant{val};
  dv.status() = StatusCode{};
  dv.source_timestamp() = sourceTimestamp;
  return dv;
}

DataValue make_status_only(StatusCode status)
{
  DataValue dv;
  dv.status() = status;
  return dv;
}

MonitoredItem create_default_item(uint32_t itemQueueSize = 4)
{
  MonitoredItem item;
  item.id = 1;
  item.clientHandle = 100;
  item.monitoringMode = MonitoringMode::Reporting;
  item.queueSize = itemQueueSize;
  item.discardOldest = true;
  item.trigger = DataChangeTrigger::StatusValue;
  item.deadbandType = DeadbandType::None;
  item.deadbandValue = 0.0;
  return item;
}

/// A RolePermissions value as the service projects it: one RolePermissionType per Role, the n-th naming the
/// Role (1, @p firstRole + n).
DataValue role_permissions_value(uint32_t firstRole, std::size_t count)
{
  Array<RefStructure<Structure>> entries;
  for (std::size_t i = 0; i < count; ++i)
  {
    auto entry = std::make_unique<RolePermissionType>();
    entry->role_id() = NodeId{1, firstRole + static_cast<uint32_t>(i)};
    entry->permissions() = PermissionType{PermissionType::Bit::Browse};
    RefStructure<Structure> reference;
    reference.inner_unique_ptr() = std::move(entry);
    entries.push_back(std::move(reference));
  }
  DataValue value;
  value.value() = Variant{std::move(entries)};
  value.status() = StatusCode{};
  return value;
}

/// The Roles named by the RolePermissions entries @p value holds, in order.
std::vector<NodeId> roles_of(const Variant& value)
{
  std::vector<NodeId> roles;
  for (const auto& entry : value.as<Array<RefStructure<Structure>>>())
  {
    const auto* permission = dynamic_cast<const RolePermissionType*>(entry.get());
    roles.push_back(permission != nullptr ? permission->role_id() : NodeId{});
  }
  return roles;
}

/// An item on RolePermissions, an attribute the service produces, which the item still narrows (DL-69 (D3)).
MonitoredItem create_role_permissions_item(const char* indexRange)
{
  auto item = create_default_item();
  item.itemToMonitor.node_id() = NodeId{2, 1600u};
  item.itemToMonitor.attribute_id() = utils::to_underlying(AttributeId::RolePermissions);
  item.itemToMonitor.index_range() = indexRange;
  item.isNonValueAttribute = true;
  return item;
}

}  // namespace

// ============================================================================
// Basic enqueue and drain
// ============================================================================

// Covers F32 (CTT Monitor Value Change V2 023-030): a MonitoredItem with an IndexRange reports only
// the sliced sub-value, not the full array (Part 4 section 5.12). The item narrows the values of the five
// attributes the service produces, RolePermissions among them, after projecting them (DL-69 (D3)).
TEST(MonitoredItemTests, IndexRangeSlicesReportedValue)
{
  auto item = create_role_permissions_item("1:3");  // entries at index 1..3

  item.enqueue_initial(role_permissions_value(10, 5));

  std::vector<MonitoredItemNotification> notifications;
  item.drain(10, notifications);
  ASSERT_EQ(notifications.size(), 1u);
  EXPECT_EQ(roles_of(notifications[0].value().value()),
    (std::vector<NodeId>{NodeId{1, 11u}, NodeId{1, 12u}, NodeId{1, 13u}}));
}

// An IndexRange beyond the array bounds yields Bad_IndexRangeNoData (per spec), not the full value, for an
// attribute the service produces, which the item narrows (DL-69 (D3)).
TEST(MonitoredItemTests, IndexRangeOutOfBoundsYieldsBadIndexRangeNoData)
{
  auto item = create_role_permissions_item("10:20");

  item.enqueue_initial(role_permissions_value(10, 3));

  std::vector<MonitoredItemNotification> notifications;
  item.drain(10, notifications);
  ASSERT_EQ(notifications.size(), 1u);
  ASSERT_TRUE(notifications[0].value().status().has_value());
  EXPECT_EQ(*notifications[0].value().status(), Status::BadIndexRangeNoData);
}

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-060, scope=function)
TEST(MonitoredItemTests, EnqueueInitialBypasses_filter)
{
  auto item = create_default_item();
  item.deadbandType = DeadbandType::Absolute;
  item.deadbandValue = 100.0;

  // Initial enqueue always succeeds regardless of deadband.
  item.enqueue_initial(make_value(1.0));
  EXPECT_TRUE(item.has_reportable_notifications());
  EXPECT_EQ(item.queue.size(), 1u);
}

TEST(MonitoredItemTests, DrainReturnsNotificationsWithClientHandle)
{
  auto item = create_default_item();
  item.enqueue_initial(make_value(1.0));
  item.enqueue_initial(make_value(2.0));

  std::vector<MonitoredItemNotification> notifications;
  item.drain(10, notifications);
  ASSERT_EQ(notifications.size(), 2u);
  EXPECT_EQ(notifications[0].client_handle(), 100u);
  EXPECT_EQ(notifications[1].client_handle(), 100u);
}

TEST(MonitoredItemTests, DrainRespectsMaxCount)
{
  auto item = create_default_item();
  item.enqueue_initial(make_value(1.0));
  item.enqueue_initial(make_value(2.0));
  item.enqueue_initial(make_value(3.0));

  std::vector<MonitoredItemNotification> notifications;
  item.drain(2, notifications);
  EXPECT_EQ(notifications.size(), 2u);
  EXPECT_EQ(item.queue.size(), 1u);
}

TEST(MonitoredItemTests, DrainMaxCountZeroMeansUnlimited)
{
  auto item = create_default_item();
  item.enqueue_initial(make_value(1.0));
  item.enqueue_initial(make_value(2.0));
  item.enqueue_initial(make_value(3.0));

  std::vector<MonitoredItemNotification> notifications;
  item.drain(0, notifications);
  EXPECT_EQ(notifications.size(), 3u);
  EXPECT_TRUE(item.queue.empty());
}

TEST(MonitoredItemTests, DrainUpdatesLastSentValue)
{
  auto item = create_default_item();
  item.enqueue_initial(make_value(42.0));

  std::vector<MonitoredItemNotification> notifications;
  item.drain(1, notifications);
  ASSERT_TRUE(item.lastSentValue.has_value());
}

// ============================================================================
// Disabled mode
// ============================================================================

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-010, scope=function)
TEST(MonitoredItemTests, DisabledModeRejectsAll)
{
  auto item = create_default_item();
  item.monitoringMode = MonitoringMode::Disabled;

  EXPECT_FALSE(item.evaluate_and_enqueue(make_value(1.0)));
  EXPECT_TRUE(item.queue.empty());
}

// ============================================================================
// Filter: StatusValue trigger, no deadband
// ============================================================================

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-051, scope=function)
TEST(MonitoredItemTests, StatusValueTriggerAcceptsValueChange)
{
  auto item = create_default_item();
  item.enqueue_initial(make_value(1.0));

  EXPECT_TRUE(item.evaluate_and_enqueue(make_value(2.0)));
  EXPECT_EQ(item.queue.size(), 2u);
}

TEST(MonitoredItemTests, StatusValueTriggerRejectsSameValue)
{
  auto item = create_default_item();
  item.enqueue_initial(make_value(1.0));

  EXPECT_FALSE(item.evaluate_and_enqueue(make_value(1.0)));
  EXPECT_EQ(item.queue.size(), 1u);
}

TEST(MonitoredItemTests, StatusValueTriggerAcceptsStatusChange)
{
  auto item = create_default_item();
  item.enqueue_initial(make_value(1.0));

  EXPECT_TRUE(item.evaluate_and_enqueue(make_value(1.0, StatusCode{Status::BadOutOfRange})));
  EXPECT_EQ(item.queue.size(), 2u);
}

// ============================================================================
// Filter: Status trigger only
// ============================================================================

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-050, scope=function)
TEST(MonitoredItemTests, StatusTriggerRejectsValueOnlyChange)
{
  auto item = create_default_item();
  item.trigger = DataChangeTrigger::Status;
  item.enqueue_initial(make_value(1.0));

  EXPECT_FALSE(item.evaluate_and_enqueue(make_value(2.0)));
}

TEST(MonitoredItemTests, StatusTriggerAcceptsStatusChange)
{
  auto item = create_default_item();
  item.trigger = DataChangeTrigger::Status;
  item.enqueue_initial(make_value(1.0));

  EXPECT_TRUE(item.evaluate_and_enqueue(make_value(1.0, StatusCode{Status::BadOutOfRange})));
}

// ============================================================================
// Filter: StatusValueTimestamp trigger
// ============================================================================

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-053, scope=function)
TEST(MonitoredItemTests, StatusValueTimestampAcceptsTimestampChange)
{
  auto item = create_default_item();
  item.trigger = DataChangeTrigger::StatusValueTimestamp;

  item.enqueue_initial(make_value_with_timestamp(1.0, DateTime::now()));

  // Same value, different timestamp.
  EXPECT_TRUE(item.evaluate_and_enqueue(make_value_with_timestamp(1.0, DateTime::now())));
}

// ============================================================================
// Filter: Absolute deadband
// ============================================================================

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-042, scope=function)
TEST(MonitoredItemTests, AbsoluteDeadbandRejectsWithinBand)
{
  auto item = create_default_item();
  item.deadbandType = DeadbandType::Absolute;
  item.deadbandValue = 5.0;
  item.enqueue_initial(make_value(10.0));

  EXPECT_FALSE(item.evaluate_and_enqueue(make_value(13.0)));
  EXPECT_EQ(item.queue.size(), 1u);
}

TEST(MonitoredItemTests, AbsoluteDeadbandAcceptsOutsideBand)
{
  auto item = create_default_item();
  item.deadbandType = DeadbandType::Absolute;
  item.deadbandValue = 5.0;
  item.enqueue_initial(make_value(10.0));

  EXPECT_TRUE(item.evaluate_and_enqueue(make_value(15.1)));
  EXPECT_EQ(item.queue.size(), 2u);
}

// Part 4 7.22.2 applies the deadband to each element of an array. Before, any element change on an array
// fell back to plain inequality and was reported, so an array item under a deadband was never filtered
// (the CTT's Monitored Items Deadband Filter 010/011/013/016/018).
namespace
{
DataValue int32_array(std::initializer_list<int32_t> elements)
{
  Array<int32_t> values;
  for (auto element : elements)
    values.push_back(element);
  return DataValue{Variant{std::move(values)}};
}
}  // namespace

TEST(MonitoredItemTests, AbsoluteDeadbandOnAnArrayRejectsAnElementMovingWithinTheBand)
{
  auto item = create_default_item();
  item.deadbandType = DeadbandType::Absolute;
  item.deadbandValue = 10.0;
  item.enqueue_initial(int32_array({100, 200, 300}));

  EXPECT_FALSE(item.evaluate_and_enqueue(int32_array({105, 200, 300})));
}

TEST(MonitoredItemTests, AbsoluteDeadbandOnAnArrayReportsAnElementMovingBeyondTheBand)
{
  auto item = create_default_item();
  item.deadbandType = DeadbandType::Absolute;
  item.deadbandValue = 10.0;
  item.enqueue_initial(int32_array({100, 200, 300}));

  EXPECT_TRUE(item.evaluate_and_enqueue(int32_array({100, 211, 300})));
}

TEST(MonitoredItemTests, AbsoluteDeadbandOnAnArrayReportsALengthChange)
{
  auto item = create_default_item();
  item.deadbandType = DeadbandType::Absolute;
  item.deadbandValue = 10.0;
  item.enqueue_initial(int32_array({100, 200, 300}));

  EXPECT_TRUE(item.evaluate_and_enqueue(int32_array({100, 200})));
}

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-041, scope=function)
TEST(MonitoredItemTests, AbsoluteDeadbandStatusChangeBypassesDeadband)
{
  auto item = create_default_item();
  item.deadbandType = DeadbandType::Absolute;
  item.deadbandValue = 100.0;
  item.enqueue_initial(make_value(10.0));

  // Value within deadband, but status changed - should pass.
  EXPECT_TRUE(item.evaluate_and_enqueue(make_value(10.5, StatusCode{Status::BadOutOfRange})));
}

// ============================================================================
// NaN dedup (SVR-MI-GEN-052)
// ============================================================================

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-052, scope=function)
TEST(MonitoredItemTests, NanTransitionIsReported)
{
  auto item = create_default_item();
  item.deadbandType = DeadbandType::Absolute;
  item.deadbandValue = 1.0;
  item.enqueue_initial(make_value(10.0));

  // Transition to NaN is reported.
  EXPECT_TRUE(item.evaluate_and_enqueue(make_value(std::numeric_limits<double>::quiet_NaN())));
}

TEST(MonitoredItemTests, NanToNanIsSuppressed)
{
  auto item = create_default_item();
  item.deadbandType = DeadbandType::Absolute;
  item.deadbandValue = 1.0;
  item.enqueue_initial(make_value(std::numeric_limits<double>::quiet_NaN()));

  // NaN -> NaN is suppressed (only one notification for entering NaN state).
  EXPECT_FALSE(item.evaluate_and_enqueue(make_value(std::numeric_limits<double>::quiet_NaN())));
}

// ============================================================================
// Non-Value attribute bypass (SVR-MI-GEN-071)
// ============================================================================

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-071, scope=function)
TEST(MonitoredItemTests, NonValueAttributeBypassesFilter)
{
  auto item = create_default_item();
  item.isNonValueAttribute = true;
  item.deadbandType = DeadbandType::Absolute;
  item.deadbandValue = 1000.0;
  item.enqueue_initial(make_value(1.0));

  // Even with huge deadband, non-Value attributes always pass.
  EXPECT_TRUE(item.evaluate_and_enqueue(make_value(1.001)));
}

// ============================================================================
// Queue overflow: discardOldest=true (SVR-MI-GEN-022)
// ============================================================================

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-020, SVR-MI-GEN-021, SVR-MI-GEN-022, scope=function)
TEST(MonitoredItemTests, DiscardOldestOverflowSetsOverflowBitOnNewFront)
{
  auto item = create_default_item(2);
  item.discardOldest = true;

  item.enqueue_initial(make_value(1.0));
  item.enqueue_initial(make_value(2.0));
  ASSERT_EQ(item.queue.size(), 2u);

  // Overflow: oldest (1.0) is discarded, Overflow bit set on new front (2.0).
  item.enqueue_initial(make_value(3.0));
  ASSERT_EQ(item.queue.size(), 2u);
  EXPECT_TRUE(item.queue.front().status()->overflow());
  // F32 (CTT Monitor Queueing 003/004): the Overflow InfoBit is only valid with InfoType=DataValue,
  // so the on-wire StatusCode is 0x00000480 (InfoType DataValue 0x400 | Overflow 0x80), not 0x80.
  EXPECT_TRUE(item.queue.front().status()->info_type_data_value());
  EXPECT_EQ(item.queue.front().status()->as_uint32() & 0x0000FFFFu, 0x0480u);
}

// ============================================================================
// Queue overflow: discardOldest=false (SVR-MI-GEN-023)
// ============================================================================

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-021, SVR-MI-GEN-023, scope=function)
TEST(MonitoredItemTests, DiscardNewestOverflowSetsOverflowBitOnNewValue)
{
  auto item = create_default_item(2);
  item.discardOldest = false;

  item.enqueue_initial(make_value(1.0));
  item.enqueue_initial(make_value(2.0));
  ASSERT_EQ(item.queue.size(), 2u);

  // Overflow: newest (2.0) is replaced with 3.0, Overflow bit set on it.
  item.enqueue_initial(make_value(3.0));
  ASSERT_EQ(item.queue.size(), 2u);
  EXPECT_TRUE(item.queue.back().status()->overflow());
}

// ============================================================================
// Queue size 1 special case (SVR-MI-GEN-024)
// ============================================================================

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-024, scope=function)
TEST(MonitoredItemTests, QueueSizeOneReplacesWithoutOverflowBit)
{
  auto item = create_default_item(1);

  item.enqueue_initial(make_value(1.0));
  ASSERT_EQ(item.queue.size(), 1u);

  item.enqueue_initial(make_value(2.0));
  ASSERT_EQ(item.queue.size(), 1u);
  // Queue size 1: Overflow bit is NOT set.
  EXPECT_FALSE(item.queue.front().status()->overflow());
}

// @relation(AC-COMP-SVR-REPUBLISH-PROJECTION-01-RAW-ALIGNMENT, scope=function)
TEST(MonitoredItemTests, RetainedProjectionSidecarsTrackIndexRangeAndQueueOverflow)
{
  auto item = create_default_item(2);
  item.id = 17;
  item.itemToMonitor.node_id() = NodeId{2, 1700u};
  item.itemToMonitor.attribute_id() = utils::to_underlying(AttributeId::Value);
  item.itemToMonitor.index_range() = "1:2";

  const auto arrayValue = [](Array<int32_t> values)
  {
    DataValue value;
    value.value() = Variant{std::move(values)};
    return value;
  };

  // The values as a namespace delivers them for the range 1:2, already narrowed (NR-14 rule 1).
  item.enqueue_initial(arrayValue({11, 12}), arrayValue({111, 112}));
  item.enqueue_initial(arrayValue({21, 22}), arrayValue({121, 122}));
  item.enqueue_initial(arrayValue({31, 32}), arrayValue({131, 132}));

  std::vector<MonitoredItemNotification> notifications;
  std::vector<RetainedDataProjection> projections;
  item.drain(0, notifications, projections);

  ASSERT_EQ(notifications.size(), 2u);
  ASSERT_EQ(projections.size(), notifications.size());
  EXPECT_EQ(projections[0].monitoredItemId, 17u);
  EXPECT_EQ(projections[0].subject, NodeId(2, 1700u));
  EXPECT_EQ(projections[0].attribute, AttributeId::Value);
  ASSERT_TRUE(projections[0].userIndependentValue.has_value());
  ASSERT_TRUE(projections[1].userIndependentValue.has_value());

  const auto& firstWire = notifications[0].value().value().as<Array<int32_t>>();
  const auto& secondWire = notifications[1].value().value().as<Array<int32_t>>();
  const auto& firstRaw = projections[0].userIndependentValue->value().as<Array<int32_t>>();
  const auto& secondRaw = projections[1].userIndependentValue->value().as<Array<int32_t>>();
  ASSERT_EQ(firstWire.size(), 2);
  ASSERT_EQ(secondWire.size(), 2);
  ASSERT_EQ(firstRaw.size(), 2);
  ASSERT_EQ(secondRaw.size(), 2);
  EXPECT_EQ(firstWire[0], 21);
  EXPECT_EQ(firstWire[1], 22);
  EXPECT_EQ(secondWire[0], 31);
  EXPECT_EQ(secondWire[1], 32);
  EXPECT_EQ(firstRaw[0], 121);
  EXPECT_EQ(firstRaw[1], 122);
  EXPECT_EQ(secondRaw[0], 131);
  EXPECT_EQ(secondRaw[1], 132);
  ASSERT_TRUE(notifications[0].value().status().has_value());
  ASSERT_TRUE(projections[0].userIndependentValue->status().has_value());
  EXPECT_TRUE(notifications[0].value().status()->overflow());
  EXPECT_TRUE(projections[0].userIndependentValue->status()->overflow());
}

// ============================================================================
// has_reportable_notifications
// ============================================================================

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-012, scope=function)
TEST(MonitoredItemTests, ReportingModeWithQueueIsReportable)
{
  auto item = create_default_item();
  item.monitoringMode = MonitoringMode::Reporting;
  item.enqueue_initial(make_value(1.0));
  EXPECT_TRUE(item.has_reportable_notifications());
}

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-011, scope=function)
TEST(MonitoredItemTests, SamplingModeWithQueueIsNotReportable)
{
  auto item = create_default_item();
  item.monitoringMode = MonitoringMode::Sampling;
  item.enqueue_initial(make_value(1.0));
  EXPECT_FALSE(item.has_reportable_notifications());
}

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-011, SVR-MI-GEN-084, scope=function)
TEST(MonitoredItemTests, SamplingModeWithTriggeredPendingIsReportable)
{
  auto item = create_default_item();
  item.monitoringMode = MonitoringMode::Sampling;
  item.enqueue_initial(make_value(1.0));
  item.triggeredReportPending = true;
  EXPECT_TRUE(item.has_reportable_notifications());
}

TEST(MonitoredItemTests, EmptyQueueIsNotReportable)
{
  auto item = create_default_item();
  item.monitoringMode = MonitoringMode::Reporting;
  EXPECT_FALSE(item.has_reportable_notifications());
}

// ============================================================================
// First value always passes filter (no lastQueuedValue)
// ============================================================================

TEST(MonitoredItemTests, FirstEvaluateAndEnqueueAlwaysPasses)
{
  auto item = create_default_item();
  item.deadbandType = DeadbandType::Absolute;
  item.deadbandValue = 1000.0;

  // No lastQueuedValue - should always pass.
  EXPECT_TRUE(item.evaluate_and_enqueue(make_value(0.001)));
}

// ============================================================================
// Ordering guarantee (SVR-MI-GEN-025)
// ============================================================================

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-025, SVR-SUB-GEN-090, scope=function)
TEST(MonitoredItemTests, DrainPreservesOrder)
{
  auto item = create_default_item();
  item.enqueue_initial(make_value(1.0));
  item.enqueue_initial(make_value(2.0));
  item.enqueue_initial(make_value(3.0));

  std::vector<MonitoredItemNotification> notifications;
  item.drain(0, notifications);
  ASSERT_EQ(notifications.size(), 3u);
  EXPECT_EQ(notifications[0].value().value().as<double>(), 1.0);
  EXPECT_EQ(notifications[1].value().value().as<double>(), 2.0);
  EXPECT_EQ(notifications[2].value().value().as<double>(), 3.0);
}

// ============================================================================
// Percent deadband
// ============================================================================

// Covers SVR-DA-022 (coverage-audit retag).
TEST(MonitoredItemTests, PercentDeadband_WithinRange_DoesNotReport)
{
  MonitoredItem item;
  item.id = 1;
  item.clientHandle = 1;
  item.monitoringMode = MonitoringMode::Reporting;
  item.queueSize = 10;
  item.trigger = DataChangeTrigger::StatusValue;
  item.deadbandType = DeadbandType::Percent;
  item.deadbandValue = 10.0;  // 10% of [0, 100] = threshold of 10
  item.hasEuRange = true;
  item.euRangeLow = 0.0;
  item.euRangeHigh = 100.0;

  item.enqueue_initial(make_value(50.0));
  // Change of 5 is within 10% deadband - should not enqueue.
  EXPECT_FALSE(item.evaluate_and_enqueue(make_value(55.0)));
  EXPECT_EQ(item.queue.size(), 1u);
}

TEST(MonitoredItemTests, PercentDeadband_ExceedsRange_Reports)
{
  MonitoredItem item;
  item.id = 1;
  item.clientHandle = 1;
  item.monitoringMode = MonitoringMode::Reporting;
  item.queueSize = 10;
  item.trigger = DataChangeTrigger::StatusValue;
  item.deadbandType = DeadbandType::Percent;
  item.deadbandValue = 10.0;  // 10% of [0, 100] = threshold of 10
  item.hasEuRange = true;
  item.euRangeLow = 0.0;
  item.euRangeHigh = 100.0;

  item.enqueue_initial(make_value(50.0));
  // Change of 15 exceeds 10% deadband - should enqueue.
  EXPECT_TRUE(item.evaluate_and_enqueue(make_value(65.0)));
  EXPECT_EQ(item.queue.size(), 2u);
}

TEST(MonitoredItemTests, PercentDeadband_MissingEURange_ReportsAllChanges)
{
  MonitoredItem item;
  item.id = 1;
  item.clientHandle = 1;
  item.monitoringMode = MonitoringMode::Reporting;
  item.queueSize = 10;
  item.trigger = DataChangeTrigger::StatusValue;
  item.deadbandType = DeadbandType::Percent;
  item.deadbandValue = 10.0;
  item.hasEuRange = false;  // No EURange available

  item.enqueue_initial(make_value(50.0));
  // Without EURange, any value change passes (fallback).
  EXPECT_TRUE(item.evaluate_and_enqueue(make_value(50.001)));
  EXPECT_EQ(item.queue.size(), 2u);
}

TEST(MonitoredItemTests, PercentDeadband_ExactlyAtThreshold_DoesNotReport)
{
  MonitoredItem item;
  item.id = 1;
  item.clientHandle = 1;
  item.monitoringMode = MonitoringMode::Reporting;
  item.queueSize = 10;
  item.trigger = DataChangeTrigger::StatusValue;
  item.deadbandType = DeadbandType::Percent;
  item.deadbandValue = 10.0;  // threshold = 10
  item.hasEuRange = true;
  item.euRangeLow = 0.0;
  item.euRangeHigh = 100.0;

  item.enqueue_initial(make_value(50.0));
  // Change of exactly 10 is NOT > threshold (spec: exceeds, not equals).
  EXPECT_FALSE(item.evaluate_and_enqueue(make_value(60.0)));
}

// ============================================================================
// Float NaN dedup (mirrors double NaN tests for float type)
// ============================================================================

TEST(MonitoredItemTests, FloatNanTransitionIsReported)
{
  auto item = create_default_item();
  item.deadbandType = DeadbandType::Absolute;
  item.deadbandValue = 1.0;
  item.enqueue_initial(make_float_value(10.0f));

  // Transition from a normal float value to NaN must be reported.
  EXPECT_TRUE(item.evaluate_and_enqueue(make_float_value(std::numeric_limits<float>::quiet_NaN())));
}

TEST(MonitoredItemTests, FloatNanToNanIsSuppressed)
{
  auto item = create_default_item();
  item.deadbandType = DeadbandType::Absolute;
  item.deadbandValue = 1.0;
  item.enqueue_initial(make_float_value(std::numeric_limits<float>::quiet_NaN()));

  // Float NaN -> NaN is suppressed, same as double.
  EXPECT_FALSE(item.evaluate_and_enqueue(make_float_value(std::numeric_limits<float>::quiet_NaN())));
}

// ============================================================================
// NaN transition regression fence (SVR-MI-GEN-052 extended)
// ============================================================================

TEST(MonitoredItemTests, NanTransitionRegressionFenceFullSequence)
{
  // Sequence: 10.0 -> NaN (pass) -> NaN (suppress) -> 20.0 (pass) -> NaN (pass)
  // This ensures the NaN dedup does not over-suppress real transitions.
  auto item = create_default_item();
  item.trigger = DataChangeTrigger::StatusValue;

  // Step 1: initial value 10.0
  item.enqueue_initial(make_value(10.0));
  ASSERT_EQ(item.queue.size(), 1u);

  // Step 2: transition to NaN - must pass (value changed).
  EXPECT_TRUE(item.evaluate_and_enqueue(make_value(std::numeric_limits<double>::quiet_NaN())));
  EXPECT_EQ(item.queue.size(), 2u);

  // Step 3: NaN -> NaN - must be suppressed (both are NaN).
  EXPECT_FALSE(item.evaluate_and_enqueue(make_value(std::numeric_limits<double>::quiet_NaN())));
  EXPECT_EQ(item.queue.size(), 2u);

  // Step 4: NaN -> 20.0 - must pass (transition out of NaN).
  EXPECT_TRUE(item.evaluate_and_enqueue(make_value(20.0)));
  EXPECT_EQ(item.queue.size(), 3u);

  // Step 5: 20.0 -> NaN - must pass again (re-entering NaN state).
  EXPECT_TRUE(item.evaluate_and_enqueue(make_value(std::numeric_limits<double>::quiet_NaN())));
  EXPECT_EQ(item.queue.size(), 4u);
}

// ============================================================================
// Variant NaN equality guard
// ============================================================================

TEST(MonitoredItemTests, VariantNanEqualityGuard)
{
  // Variant wrapping NaN must NOT compare equal to another Variant wrapping NaN.
  // This guards against someone "fixing" NaN equality globally; the NaN
  // relaxation is strictly in the monitoring filter layer.
  Variant a{std::numeric_limits<double>::quiet_NaN()};
  Variant b{std::numeric_limits<double>::quiet_NaN()};
  EXPECT_NE(a, b);
}

// ============================================================================
// SemanticsChanged arm/apply/clear rule (CTT Data Access Analog 008)
//
// Prove-first: hand-arm pendingSemanticChange and verify the rule delivers the
// SemanticsChanged bit through a deadband and survives queue churn, before any
// capability/sink/generator wiring exists.
// ============================================================================

namespace
{

bool drained_has_semantics_changed(const MonitoredItemNotification& notification)
{
  return notification.value().status().has_value() && notification.value().status()->semantics_changed();
}

}  // namespace

// Negative control / baseline: WITHOUT arming, an unchanged value within the deadband is filtered
// out and no SemanticsChanged bit appears. Establishes that the positive tests below would fail if
// the rule were a no-op (falsifiability).
TEST(MonitoredItemTests, SemanticsChangedNotArmedWithinDeadbandIsFiltered)
{
  auto item = create_default_item();
  item.deadbandType = DeadbandType::Absolute;
  item.deadbandValue = 10.0;
  item.enqueue_initial(make_value(50.0));

  std::vector<MonitoredItemNotification> seed;
  item.drain(0, seed);  // Publish #1

  // Within deadband (|51 - 50| = 1 < 10) and not armed -> suppressed.
  EXPECT_FALSE(item.evaluate_and_enqueue(make_value(51.0)));
  EXPECT_TRUE(item.queue.empty());
  EXPECT_FALSE(item.pendingSemanticChange);
}

// Polled case (the CTT 008 path): armed, a real sample arrives within the deadband. The bit is
// folded in and the deadband is bypassed; the flag clears only once a bit-carrying value is drained.
TEST(MonitoredItemTests, SemanticsChangedArmedDeliversThroughDeadbandThenClearsOnPublish)
{
  auto item = create_default_item();
  item.deadbandType = DeadbandType::Absolute;
  item.deadbandValue = 10.0;
  item.enqueue_initial(make_value(50.0));

  std::vector<MonitoredItemNotification> seed;
  item.drain(0, seed);  // Publish #1 - value 50, no bit.
  ASSERT_EQ(seed.size(), 1u);
  EXPECT_FALSE(drained_has_semantics_changed(seed[0]));

  // Semantics changed: arm the item (stands in for the namespace/sink signal).
  item.pendingSemanticChange = true;

  // Next sampling tick delivers an unchanged-within-deadband value. Normally filtered; while armed
  // it must enqueue and carry the bit.
  EXPECT_TRUE(item.evaluate_and_enqueue(make_value(51.0)));
  ASSERT_EQ(item.queue.size(), 1u);
  EXPECT_TRUE(item.pendingSemanticChange);  // still armed until actually published

  std::vector<MonitoredItemNotification> published;
  item.drain(0, published);  // Publish #2
  ASSERT_EQ(published.size(), 1u);
  EXPECT_TRUE(drained_has_semantics_changed(published[0]));
  EXPECT_TRUE(published[0].value().status()->is_good());  // Good | SemanticsChanged
  EXPECT_FALSE(item.pendingSemanticChange);  // cleared on publish
}

// Queue churn: queueSize 1 + discardOldest, sampling faster than publish. While armed, each tick
// overwrites the single slot but re-flags it, so the surviving latest value still carries the bit
// when it is finally published. Proves the "clear-on-publish, re-flag-on-enqueue" rule is queue-safe.
TEST(MonitoredItemTests, SemanticsChangedSurvivesQueueOverwriteUntilPublished)
{
  auto item = create_default_item(/*itemQueueSize=*/1);
  item.discardOldest = true;
  item.deadbandType = DeadbandType::Absolute;
  item.deadbandValue = 10.0;
  item.enqueue_initial(make_value(50.0));

  std::vector<MonitoredItemNotification> seed;
  item.drain(0, seed);  // Publish #1

  item.pendingSemanticChange = true;

  // Several ticks before the next Publish; all within deadband, all while armed.
  EXPECT_TRUE(item.evaluate_and_enqueue(make_value(51.0)));
  EXPECT_TRUE(item.evaluate_and_enqueue(make_value(52.0)));
  EXPECT_TRUE(item.evaluate_and_enqueue(make_value(53.0)));
  ASSERT_EQ(item.queue.size(), 1u);  // single slot, repeatedly overwritten
  EXPECT_TRUE(item.pendingSemanticChange);  // never drained -> still armed

  std::vector<MonitoredItemNotification> published;
  item.drain(0, published);  // Publish #2 - the surviving latest (53) carries the bit.
  ASSERT_EQ(published.size(), 1u);
  EXPECT_TRUE(drained_has_semantics_changed(published[0]));
  EXPECT_EQ(published[0].value().value().as<double>(), 53.0);
  EXPECT_FALSE(item.pendingSemanticChange);
}

// Exception path: an armed item with a cached value synthesizes a bit-carrying sample from that
// cache (no tick required). The cache is delivered unchanged except for the SemanticsChanged bit.
TEST(MonitoredItemTests, SemanticsChangedSynthesizesFromCache)
{
  auto item = create_default_item();
  item.enqueue_initial(make_value(42.0));

  std::vector<MonitoredItemNotification> seed;
  item.drain(0, seed);  // Publish #1 populates lastSentValue (42.0).
  ASSERT_TRUE(item.lastSentValue.has_value());

  item.pendingSemanticChange = true;
  EXPECT_TRUE(item.enqueue_semantic_from_cache());
  ASSERT_EQ(item.queue.size(), 1u);

  std::vector<MonitoredItemNotification> published;
  item.drain(0, published);  // Publish #2
  ASSERT_EQ(published.size(), 1u);
  EXPECT_EQ(published[0].value().value().as<double>(), 42.0);  // the cached value
  ASSERT_TRUE(published[0].value().status().has_value());
  EXPECT_TRUE(published[0].value().status()->semantics_changed());
  EXPECT_FALSE(item.pendingSemanticChange);  // cleared on publish
}

// Exception path with no cache yet: synthesis is a no-op; the item stays armed so the first real
// value carries the bit.
TEST(MonitoredItemTests, SemanticsChangedNoCacheStaysArmed)
{
  auto item = create_default_item();

  item.pendingSemanticChange = true;
  EXPECT_FALSE(item.enqueue_semantic_from_cache());  // nothing cached
  EXPECT_TRUE(item.queue.empty());
  EXPECT_TRUE(item.pendingSemanticChange);  // still armed

  // The first real value (via the normal armed path) carries the bit.
  EXPECT_TRUE(item.evaluate_and_enqueue(make_value(7.0)));
  std::vector<MonitoredItemNotification> published;
  item.drain(0, published);
  ASSERT_EQ(published.size(), 1u);
  EXPECT_TRUE(published[0].value().status()->semantics_changed());
}

// Clear-on-publish is one-shot: once a flagged value is published the flag is gone, so a subsequent
// unchanged-within-deadband sample is filtered again (the bit is transient, not sticky).
TEST(MonitoredItemTests, SemanticsChangedIsTransientAfterPublish)
{
  auto item = create_default_item();
  item.deadbandType = DeadbandType::Absolute;
  item.deadbandValue = 10.0;
  item.enqueue_initial(make_value(50.0));

  std::vector<MonitoredItemNotification> seed;
  item.drain(0, seed);  // Publish #1

  item.pendingSemanticChange = true;
  EXPECT_TRUE(item.evaluate_and_enqueue(make_value(51.0)));

  std::vector<MonitoredItemNotification> published;
  item.drain(0, published);  // Publish #2 - clears the flag.
  ASSERT_EQ(published.size(), 1u);
  EXPECT_TRUE(drained_has_semantics_changed(published[0]));
  ASSERT_FALSE(item.pendingSemanticChange);

  // A further within-deadband sample is now suppressed again (no lingering bit).
  EXPECT_FALSE(item.evaluate_and_enqueue(make_value(52.0)));
  EXPECT_TRUE(item.queue.empty());
}

// ============================================================================
// Queue overflow on a four-deep queue: which value is lost and which is flagged
// ============================================================================

// Part 4 section 5.12.1.5: with discardOldest TRUE the oldest queued value is deleted and the value
// that *becomes* the oldest is marked with the Overflow InfoBit. A plausible implementation gets
// this wrong in two ways that a two-deep queue cannot separate: it marks the incoming value (the
// only other candidate when the queue holds two), or it marks every survivor. Both conjuncts are
// asserted here - the deletion of the oldest (by surviving-value identity and order) and the bit
// landing on exactly the new front.
// @verifies AC-SVR-MI-GEN-022-DISCARDOLDEST-TRUE
TEST(MonitoredItemTests, OverflowWithDiscardOldestDeletesOldestAndFlagsTheValueThatBecomesOldest)
{
  auto item = create_default_item(4);
  item.discardOldest = true;

  item.enqueue_initial(make_value(1.0));
  ASSERT_TRUE(item.evaluate_and_enqueue(make_value(2.0)));
  ASSERT_TRUE(item.evaluate_and_enqueue(make_value(3.0)));
  ASSERT_TRUE(item.evaluate_and_enqueue(make_value(4.0)));
  ASSERT_EQ(item.queue.size(), 4u);

  // Fifth sample overflows the four-deep queue.
  ASSERT_TRUE(item.evaluate_and_enqueue(make_value(5.0)));

  // Conjunct 1: the oldest (1.0) was deleted; the survivors are 2,3,4,5 in order.
  ASSERT_EQ(item.queue.size(), 4u);
  EXPECT_EQ(item.queue[0].value().as<double>(), 2.0);
  EXPECT_EQ(item.queue[1].value().as<double>(), 3.0);
  EXPECT_EQ(item.queue[2].value().as<double>(), 4.0);
  EXPECT_EQ(item.queue[3].value().as<double>(), 5.0);

  // Conjunct 2: the value that became the oldest (2.0) carries the Overflow InfoBit, which is only
  // valid alongside InfoType=DataValue.
  ASSERT_TRUE(item.queue[0].status().has_value());
  EXPECT_TRUE(item.queue[0].status()->overflow());
  EXPECT_TRUE(item.queue[0].status()->info_type_data_value());

  // And nothing else is flagged - in particular not the incoming value.
  for (size_t i = 1; i < item.queue.size(); ++i)
  {
    ASSERT_TRUE(item.queue[i].status().has_value());
    EXPECT_FALSE(item.queue[i].status()->overflow()) << "unexpected Overflow bit at queue index " << i;
  }
}

// Part 4 section 5.12.1.5: with discardOldest FALSE the *last queued* value is replaced by the
// incoming one and the incoming value carries the Overflow InfoBit. A plausible implementation
// instead drops the incoming sample entirely (leaving the queue untouched and nothing flagged), or
// keeps the tail and flags the front as in the discardOldest TRUE branch. Both conjuncts are
// asserted - the tail replacement (by surviving-value identity and order) and the bit on the value
// that replaced it.
// @verifies AC-SVR-MI-GEN-023-DISCARDOLDEST-FALSE
TEST(MonitoredItemTests, OverflowWithDiscardOldestFalseReplacesLastQueuedValueAndFlagsTheNewValue)
{
  auto item = create_default_item(4);
  item.discardOldest = false;

  item.enqueue_initial(make_value(1.0));
  ASSERT_TRUE(item.evaluate_and_enqueue(make_value(2.0)));
  ASSERT_TRUE(item.evaluate_and_enqueue(make_value(3.0)));
  ASSERT_TRUE(item.evaluate_and_enqueue(make_value(4.0)));
  ASSERT_EQ(item.queue.size(), 4u);

  // Fifth sample overflows the four-deep queue.
  ASSERT_TRUE(item.evaluate_and_enqueue(make_value(5.0)));

  // Conjunct 1: the last queued value (4.0) was replaced by 5.0; the older three are untouched.
  ASSERT_EQ(item.queue.size(), 4u);
  EXPECT_EQ(item.queue[0].value().as<double>(), 1.0);
  EXPECT_EQ(item.queue[1].value().as<double>(), 2.0);
  EXPECT_EQ(item.queue[2].value().as<double>(), 3.0);
  EXPECT_EQ(item.queue[3].value().as<double>(), 5.0);

  // Conjunct 2: the replacing value carries the Overflow InfoBit (with InfoType=DataValue).
  ASSERT_TRUE(item.queue[3].status().has_value());
  EXPECT_TRUE(item.queue[3].status()->overflow());
  EXPECT_TRUE(item.queue[3].status()->info_type_data_value());

  // The retained older values are not flagged - the bit belongs to the replacing value, not a
  // survivor.
  for (size_t i = 0; i + 1 < item.queue.size(); ++i)
  {
    ASSERT_TRUE(item.queue[i].status().has_value());
    EXPECT_FALSE(item.queue[i].status()->overflow()) << "unexpected Overflow bit at queue index " << i;
  }
}
