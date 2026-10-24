// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_attribute_id.h"
#include "ua_compiled_event_filter.h"
#include "ua_content_filter_element.h"
#include "ua_data_change_filter.h"
#include "ua_event_field_list.h"
#include "ua_event_filter.h"
#include "ua_event_filter_result.h"
#include "ua_filter_operator.h"
#include "ua_literal_operand.h"
#include "ua_monitored_item.h"
#include "ua_monitored_item_factory.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_simple_attribute_operand.h"

#include "ua_address_space.h"
#include "ua_create_monitored_items_request.h"
#include "ua_default_namespace.h"
#include "ua_event_notifier_type.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_referencetype_id.h"
#include "ua_subscription.h"
#include "ua_subscription_test_access.h"
#include <boost/asio/thread_pool.hpp>

#include <future>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

using namespace ua;
using namespace ua::server;

namespace
{

// --- Helpers ---

SimpleAttributeOperand make_select_clause(std::string_view fieldName)
{
  SimpleAttributeOperand clause;
  clause.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  clause.browse_path().push_back(QualifiedName{0, String{fieldName}});
  clause.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  return clause;
}

EventFilter make_simple_event_filter()
{
  EventFilter filter;
  filter.select_clauses().push_back(make_select_clause("EventId"));
  filter.select_clauses().push_back(make_select_clause("Severity"));
  return filter;
}

void seed_base_event_type_model(AddressSpace& addressSpace, uint16_t namespaceIndex)
{
  auto baseEventType =
    addressSpace.try_create_node_sync(NodeId{ObjectTypeId::BaseEventType}, NodeClass::ObjectType).value();
  baseEventType.set_browse_name(QualifiedName{0, String{"BaseEventType"}});

  auto eventId =
    addressSpace.try_create_node_sync(NodeId{namespaceIndex, 6990u}, NodeClass::Variable).value();
  eventId.set_browse_name(QualifiedName{0, String{"EventId"}});
  baseEventType.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, eventId.get_node_id(), true);

  auto severity =
    addressSpace.try_create_node_sync(NodeId{namespaceIndex, 6991u}, NodeClass::Variable).value();
  severity.set_browse_name(QualifiedName{0, String{"Severity"}});
  baseEventType.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, severity.get_node_id(), true);
}

MonitoredItemCreateRequest make_event_create_request(
  NodeId nodeId, EventFilter filter, uint32_t queueSize = 10)
{
  MonitoredItemCreateRequest request;
  request.item_to_monitor().node_id() = std::move(nodeId);
  request.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::EventNotifier);
  request.monitoring_mode() = MonitoringMode::Reporting;

  auto eventFilterPtr = std::make_unique<EventFilter>(std::move(filter));
  request.requested_parameters().filter().inner_unique_ptr() = std::move(eventFilterPtr);
  request.requested_parameters().queue_size() = queueSize;
  request.requested_parameters().client_handle() = 42;
  request.requested_parameters().sampling_interval() = 0;
  return request;
}

EventFieldList make_event_field_list(uint32_t clientHandle, uint16_t severity)
{
  EventFieldList fields;
  fields.client_handle() = clientHandle;
  fields.event_fields().push_back(Variant{ByteString{uint8_t{0x01}}});
  fields.event_fields().push_back(Variant{severity});
  return fields;
}

}  // namespace

// ============================================================================
// MonitoredItemFactory: event item creation
// ============================================================================

TEST(EventMonitoringTests, CreateEventItemSucceeds)
{
  auto request = make_event_create_request(NodeId{ObjectId::Server}, make_simple_event_filter());
  MonitoredItemCreateContext context{request};

  auto outcome = validate_and_build_monitored_item(context, 1);
  EXPECT_TRUE(outcome.statusCode.is_good());
  ASSERT_TRUE(outcome.item);
  EXPECT_TRUE(outcome.item->isEventItem);
  EXPECT_TRUE(outcome.item->eventFilter);
}

TEST(EventMonitoringTests, EventItemSamplingIntervalRevisedToZero)
{
  // SVR-EVT-MON-002: sampling interval for events is always 0
  auto request = make_event_create_request(NodeId{ObjectId::Server}, make_simple_event_filter());
  request.requested_parameters().sampling_interval() = 5000;
  MonitoredItemCreateContext context{request};

  auto outcome = validate_and_build_monitored_item(context, 1);
  EXPECT_TRUE(outcome.statusCode.is_good());
  EXPECT_EQ(outcome.revisedSamplingInterval, 0);
}

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-031, scope=function)
TEST(EventMonitoringTests, EventItemQueueSizeRevised)
{
  // SVR-EVT-MON-004: queue size 0 -> server default (50)
  auto request = make_event_create_request(NodeId{ObjectId::Server}, make_simple_event_filter(), 0);
  MonitoredItemCreateContext context{request};

  auto outcome = validate_and_build_monitored_item(context, 1);
  EXPECT_TRUE(outcome.statusCode.is_good());
  EXPECT_EQ(outcome.revisedQueueSize, 50u);
}

TEST(EventMonitoringTests, EventItemQueueSizeClamped)
{
  // SVR-EVT-MON-005: clamped to max
  auto request = make_event_create_request(NodeId{ObjectId::Server}, make_simple_event_filter(), 5000);
  MonitoredItemCreateContext context{request};
  context.maxEventQueueSize = 100;

  auto outcome = validate_and_build_monitored_item(context, 1);
  EXPECT_TRUE(outcome.statusCode.is_good());
  EXPECT_EQ(outcome.revisedQueueSize, 100u);
}

// @relation(SVR-MI-GEN-034, scope=function)
TEST(EventMonitoringTests, EventItemWithinRangeReturnedUnchanged)
{
  auto request = make_event_create_request(NodeId{ObjectId::Server}, make_simple_event_filter(), 50);
  MonitoredItemCreateContext context{request};
  context.maxEventQueueSize = 100;

  auto outcome = validate_and_build_monitored_item(context, 1);
  EXPECT_TRUE(outcome.statusCode.is_good());
  EXPECT_EQ(outcome.revisedQueueSize, 50u);
}

// @relation(SVR-EVT-ATTR-002, SVR-MI-EVT-015, SVR-MI-GEN-070, scope=function)
TEST(EventMonitoringTests, NoFilterOnEventNotifierFails)
{
  // SVR-EVT-MON-003: EventFilter required for EventNotifier
  MonitoredItemCreateRequest request;
  request.item_to_monitor().node_id() = NodeId{ObjectId::Server};
  request.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::EventNotifier);
  request.monitoring_mode() = MonitoringMode::Reporting;
  // No filter set

  MonitoredItemCreateContext context{request};
  auto outcome = validate_and_build_monitored_item(context, 1);
  EXPECT_TRUE(outcome.statusCode.is_bad());
  EXPECT_EQ(outcome.statusCode.as_status(), Status::BadMonitoredItemFilterInvalid);
}

TEST(EventMonitoringTests, DataChangeFilterOnEventNotifierFails)
{
  // DataChangeFilter on EventNotifier -> Bad_FilterNotAllowed
  MonitoredItemCreateRequest request;
  request.item_to_monitor().node_id() = NodeId{ObjectId::Server};
  request.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::EventNotifier);
  request.monitoring_mode() = MonitoringMode::Reporting;

  auto dcFilter = std::make_unique<DataChangeFilter>();
  request.requested_parameters().filter().inner_unique_ptr() = std::move(dcFilter);

  MonitoredItemCreateContext context{request};
  auto outcome = validate_and_build_monitored_item(context, 1);
  EXPECT_TRUE(outcome.statusCode.is_bad());
  EXPECT_EQ(outcome.statusCode.as_status(), Status::BadFilterNotAllowed);
}

// @relation(SVR-MI-EVT-008, scope=function)
TEST(EventMonitoringTests, InvalidEventFilterReturnsFilterResult)
{
  // Empty select clauses -> bad filter with result
  EventFilter badFilter;
  auto request = make_event_create_request(NodeId{ObjectId::Server}, std::move(badFilter));
  MonitoredItemCreateContext context{request};

  auto outcome = validate_and_build_monitored_item(context, 1);
  EXPECT_TRUE(outcome.statusCode.is_bad());
  // eventFilterResult should be set
  EXPECT_TRUE(outcome.eventFilterResult.has_value());
}

TEST(EventMonitoringTests, ValidEventFilterReturnsFilterResult)
{
  auto request = make_event_create_request(NodeId{ObjectId::Server}, make_simple_event_filter());
  MonitoredItemCreateContext context{request};

  auto outcome = validate_and_build_monitored_item(context, 1);
  EXPECT_TRUE(outcome.statusCode.is_good());
  EXPECT_TRUE(outcome.eventFilterResult.has_value());

  // Select clause results should have 2 Good entries
  auto& efr = *outcome.eventFilterResult;
  EXPECT_EQ(efr.select_clause_results().size(), 2u);
  EXPECT_TRUE(efr.select_clause_results()[0].is_good());
  EXPECT_TRUE(efr.select_clause_results()[1].is_good());
}

// ============================================================================
// MonitoredItem: event queue operations
// ============================================================================

TEST(EventMonitoringTests, EnqueueAndDrainEvent)
{
  MonitoredItem item;
  item.id = 1;
  item.clientHandle = 42;
  item.monitoringMode = MonitoringMode::Reporting;
  item.isEventItem = true;
  item.queueSize = 10;

  item.enqueue_event(make_event_field_list(42, 500));
  EXPECT_TRUE(item.has_reportable_notifications());
  EXPECT_EQ(item.eventQueue.size(), 1u);

  std::vector<EventFieldList> out;
  item.drain_events(10, out);
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0].client_handle(), 42u);
  EXPECT_FALSE(item.has_reportable_notifications());
}

TEST(EventMonitoringTests, EventQueueOrdering)
{
  // SVR-EVT-MON-010: notifications in order
  MonitoredItem item;
  item.id = 1;
  item.clientHandle = 42;
  item.monitoringMode = MonitoringMode::Reporting;
  item.isEventItem = true;
  item.queueSize = 10;

  item.enqueue_event(make_event_field_list(42, 100));
  item.enqueue_event(make_event_field_list(42, 200));
  item.enqueue_event(make_event_field_list(42, 300));

  std::vector<EventFieldList> out;
  item.drain_events(10, out);
  ASSERT_EQ(out.size(), 3u);
  // Severity is the second field
  EXPECT_EQ(out[0].event_fields()[1].as<uint16_t>(), 100);
  EXPECT_EQ(out[1].event_fields()[1].as<uint16_t>(), 200);
  EXPECT_EQ(out[2].event_fields()[1].as<uint16_t>(), 300);
}

TEST(EventMonitoringTests, EventQueueOverflowDiscardOldest)
{
  MonitoredItem item;
  item.id = 1;
  item.clientHandle = 42;
  item.monitoringMode = MonitoringMode::Reporting;
  item.isEventItem = true;
  item.queueSize = 2;
  item.discardOldest = true;

  item.enqueue_event(make_event_field_list(42, 100));
  item.enqueue_event(make_event_field_list(42, 200));
  item.enqueue_event(make_event_field_list(42, 300));  // Overflows, discards 100

  EXPECT_EQ(item.eventQueue.size(), 2u);

  std::vector<EventFieldList> out;
  item.drain_events(10, out);
  ASSERT_EQ(out.size(), 2u);
  EXPECT_EQ(out[0].event_fields()[1].as<uint16_t>(), 200);
  EXPECT_EQ(out[1].event_fields()[1].as<uint16_t>(), 300);
}

TEST(EventMonitoringTests, EventQueueOverflowDiscardNewest)
{
  MonitoredItem item;
  item.id = 1;
  item.clientHandle = 42;
  item.monitoringMode = MonitoringMode::Reporting;
  item.isEventItem = true;
  item.queueSize = 2;
  item.discardOldest = false;

  item.enqueue_event(make_event_field_list(42, 100));
  item.enqueue_event(make_event_field_list(42, 200));
  item.enqueue_event(make_event_field_list(42, 300));  // Dropped

  EXPECT_EQ(item.eventQueue.size(), 2u);

  std::vector<EventFieldList> out;
  item.drain_events(10, out);
  ASSERT_EQ(out.size(), 2u);
  EXPECT_EQ(out[0].event_fields()[1].as<uint16_t>(), 100);
  EXPECT_EQ(out[1].event_fields()[1].as<uint16_t>(), 200);
}

TEST(EventMonitoringTests, DisabledEventItemDoesNotEnqueue)
{
  // SVR-EVT-MON-012 (negative): Disabled mode does not receive events
  MonitoredItem item;
  item.id = 1;
  item.clientHandle = 42;
  item.monitoringMode = MonitoringMode::Disabled;
  item.isEventItem = true;
  item.queueSize = 10;

  item.enqueue_event(make_event_field_list(42, 500));
  EXPECT_FALSE(item.has_reportable_notifications());
  EXPECT_TRUE(item.eventQueue.empty());
}

TEST(EventMonitoringTests, DrainEventsRespectsMaxCount)
{
  MonitoredItem item;
  item.id = 1;
  item.clientHandle = 42;
  item.monitoringMode = MonitoringMode::Reporting;
  item.isEventItem = true;
  item.queueSize = 10;

  for (uint16_t i = 0; i < 5; ++i)
    item.enqueue_event(make_event_field_list(42, i));

  std::vector<EventFieldList> out;
  item.drain_events(2, out);
  EXPECT_EQ(out.size(), 2u);
  EXPECT_EQ(item.eventQueue.size(), 3u);
}

TEST(EventMonitoringTests, EventItemHasReportableInSamplingModeWhenTriggered)
{
  MonitoredItem item;
  item.id = 1;
  item.clientHandle = 42;
  item.monitoringMode = MonitoringMode::Sampling;
  item.isEventItem = true;
  item.queueSize = 10;

  item.enqueue_event(make_event_field_list(42, 500));
  EXPECT_FALSE(item.has_reportable_notifications());

  item.triggeredReportPending = true;
  EXPECT_TRUE(item.has_reportable_notifications());
}

// ============================================================================
// EventQueueOverflow
// ============================================================================

MonitoredItem create_event_item_with_filter(uint32_t queueSize, bool discardOldest = true)
{
  // Compile a simple filter for the overflow event projection.
  EventFilter filter = make_simple_event_filter();
  auto compiled = CompiledEventFilter::compile(filter);

  MonitoredItem item;
  item.id = 1;
  item.clientHandle = 42;
  item.monitoringMode = MonitoringMode::Reporting;
  item.isEventItem = true;
  item.queueSize = queueSize;
  item.discardOldest = discardOldest;
  item.eventFilter = std::move(compiled.filter);
  return item;
}

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-072, scope=function)
TEST(EventMonitoringTests, OverflowEventGeneratedOnFirstDiscard)
{
  // SVR-EVT-MON-006: overflow event generated when first event is discarded
  auto item = create_event_item_with_filter(2);

  item.enqueue_event(make_event_field_list(42, 100));
  item.enqueue_event(make_event_field_list(42, 200));
  item.enqueue_event(make_event_field_list(42, 300));  // Triggers overflow

  // Queue should hold queueSize + 1 (overflow event in addition - SVR-EVT-MON-007)
  EXPECT_EQ(item.eventQueue.size(), 3u);
  EXPECT_TRUE(item.overflowEventInserted);
}

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-073, SVR-MI-GEN-074, scope=function)
TEST(EventMonitoringTests, OverflowEventAtFrontWhenDiscardOldest)
{
  // SVR-EVT-MON-008: discardOldest=true -> overflow event at front
  auto item = create_event_item_with_filter(2, true);

  item.enqueue_event(make_event_field_list(42, 100));
  item.enqueue_event(make_event_field_list(42, 200));
  item.enqueue_event(make_event_field_list(42, 300));

  // Front should be the overflow event (projected through select clauses)
  std::vector<EventFieldList> out;
  item.drain_events(10, out);
  ASSERT_GE(out.size(), 3u);

  // The overflow event has EventQueueOverflowEventType fields.
  // It's projected through our 2-field filter (EventId, Severity).
  // The first field (EventId) should be non-empty.
  EXPECT_FALSE(out[0].event_fields().empty());

  // Last two should be the remaining regular events (200, 300 - 100 was discarded)
  EXPECT_EQ(out[1].event_fields()[1].as<uint16_t>(), 200);
  EXPECT_EQ(out[2].event_fields()[1].as<uint16_t>(), 300);
}

// @relation(SVR-MI-GEN-074, scope=function)
TEST(EventMonitoringTests, OverflowEventAtEndWhenDiscardNewest)
{
  // SVR-EVT-MON-008: discardOldest=false -> overflow event at end
  auto item = create_event_item_with_filter(2, false);

  item.enqueue_event(make_event_field_list(42, 100));
  item.enqueue_event(make_event_field_list(42, 200));
  item.enqueue_event(make_event_field_list(42, 300));  // Dropped, overflow added to end

  EXPECT_EQ(item.eventQueue.size(), 3u);

  std::vector<EventFieldList> out;
  item.drain_events(10, out);
  ASSERT_EQ(out.size(), 3u);

  // First two are the original events (100, 200)
  EXPECT_EQ(out[0].event_fields()[1].as<uint16_t>(), 100);
  EXPECT_EQ(out[1].event_fields()[1].as<uint16_t>(), 200);
  // Third is the overflow event
  EXPECT_FALSE(out[2].event_fields().empty());
}

// @relation(SVR-MI-GEN-072, scope=function)
TEST(EventMonitoringTests, OnlyOneOverflowEventPerEpisode)
{
  // SVR-EVT-MON-008: second overflow does not add another overflow event
  auto item = create_event_item_with_filter(2, true);

  item.enqueue_event(make_event_field_list(42, 100));
  item.enqueue_event(make_event_field_list(42, 200));
  item.enqueue_event(make_event_field_list(42, 300));  // First overflow
  item.enqueue_event(make_event_field_list(42, 400));  // Second overflow - no new overflow event

  // Should still have 3 items (overflow + 2 newest)
  EXPECT_EQ(item.eventQueue.size(), 3u);
}

// @relation(SVR-MI-GEN-072, scope=function)
TEST(EventMonitoringTests, OverflowFlagResetsAfterDrain)
{
  auto item = create_event_item_with_filter(2, true);

  item.enqueue_event(make_event_field_list(42, 100));
  item.enqueue_event(make_event_field_list(42, 200));
  item.enqueue_event(make_event_field_list(42, 300));
  EXPECT_TRUE(item.overflowEventInserted);

  std::vector<EventFieldList> out;
  item.drain_events(10, out);
  EXPECT_FALSE(item.overflowEventInserted);

  // New overflow episode should generate a new overflow event
  item.enqueue_event(make_event_field_list(42, 400));
  item.enqueue_event(make_event_field_list(42, 500));
  item.enqueue_event(make_event_field_list(42, 600));
  EXPECT_TRUE(item.overflowEventInserted);
}

TEST(EventMonitoringTests, NoOverflowEventWithoutFilter)
{
  // If eventFilter is null, no overflow event is generated (graceful degradation)
  MonitoredItem item;
  item.id = 1;
  item.clientHandle = 42;
  item.monitoringMode = MonitoringMode::Reporting;
  item.isEventItem = true;
  item.queueSize = 2;
  item.discardOldest = true;
  // eventFilter is null

  item.enqueue_event(make_event_field_list(42, 100));
  item.enqueue_event(make_event_field_list(42, 200));
  item.enqueue_event(make_event_field_list(42, 300));

  // Should just discard without overflow event
  EXPECT_EQ(item.eventQueue.size(), 2u);
  EXPECT_FALSE(item.overflowEventInserted);
}

// ============================================================================
// Additional queue size tests
// ============================================================================

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-032, scope=function)
TEST(EventMonitoringTests, EventItemQueueSizeOneReturnsMinimum)
{
  // TEST-MON-004-P2: QueueSize=1 -> server minimum
  auto request = make_event_create_request(NodeId{ObjectId::Server}, make_simple_event_filter(), 1);
  MonitoredItemCreateContext context{request};

  auto outcome = validate_and_build_monitored_item(context, 1);
  EXPECT_TRUE(outcome.statusCode.is_good());
  EXPECT_EQ(outcome.revisedQueueSize, 1u);
}

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-033, scope=function)
TEST(EventMonitoringTests, EventItemQueueSizeMaxUint32ReturnsMax)
{
  // TEST-MON-004-P3: QueueSize=MaxUInt32 -> server maximum
  auto request = make_event_create_request(
    NodeId{ObjectId::Server}, make_simple_event_filter(), std::numeric_limits<uint32_t>::max());
  MonitoredItemCreateContext context{request};
  context.maxEventQueueSize = 500;

  auto outcome = validate_and_build_monitored_item(context, 1);
  EXPECT_TRUE(outcome.statusCode.is_good());
  EXPECT_EQ(outcome.revisedQueueSize, 500u);
}

// ============================================================================
// Overflow event details
// ============================================================================

// @relation(SVR-MI-GEN-073, scope=function)
TEST(EventMonitoringTests, NoOverflowWhenQueueNotFull)
{
  // TEST-MON-006-N1: no overflow event when queue is not full
  auto item = create_event_item_with_filter(5);

  item.enqueue_event(make_event_field_list(42, 100));
  item.enqueue_event(make_event_field_list(42, 200));

  EXPECT_FALSE(item.overflowEventInserted);
  EXPECT_EQ(item.eventQueue.size(), 2u);
}

MonitoredItem create_event_item_with_detail_filter(uint32_t queueSize, bool discardOldest = true)
{
  // Filter that selects EventId, Severity, SourceNode, SourceName for overflow verification.
  EventFilter filter;
  filter.select_clauses().push_back(make_select_clause("EventId"));
  filter.select_clauses().push_back(make_select_clause("Severity"));
  filter.select_clauses().push_back(make_select_clause("SourceNode"));
  filter.select_clauses().push_back(make_select_clause("SourceName"));
  auto compiled = CompiledEventFilter::compile(filter);

  MonitoredItem item;
  item.id = 1;
  item.clientHandle = 42;
  item.monitoringMode = MonitoringMode::Reporting;
  item.isEventItem = true;
  item.queueSize = queueSize;
  item.discardOldest = discardOldest;
  item.eventFilter = std::move(compiled.filter);
  return item;
}

EventFieldList make_detail_event_field_list(uint32_t clientHandle, uint16_t severity)
{
  EventFieldList fields;
  fields.client_handle() = clientHandle;
  fields.event_fields().push_back(Variant{ByteString{uint8_t{0x01}}});  // EventId
  fields.event_fields().push_back(Variant{severity});  // Severity
  fields.event_fields().push_back(Variant{NodeId{0, 9999u}});  // SourceNode
  fields.event_fields().push_back(Variant{String{"TestSource"}});  // SourceName
  return fields;
}

/// Drains up to @p maxCount entries (0: all) and names each: "overflow" for the EventQueueOverflowEvent,
/// otherwise the event's Severity. Needs the detail filter (SourceName is field 3).
std::vector<std::string> drained_shape(MonitoredItem& item, uint32_t maxCount = 0)
{
  std::vector<EventFieldList> out;
  item.drain_events(maxCount, out);
  std::vector<std::string> shape;
  for (const auto& fields : out)
  {
    const auto& values = fields.event_fields();
    if (values.size() > 3 && values[3].is_string() &&
        static_cast<std::string_view>(values[3].as<String>()) == "Internal/EventQueueOverflow")
      shape.emplace_back("overflow");
    else
      shape.push_back(std::to_string(values[1].as<uint16_t>()));
  }
  return shape;
}

// Part 4 section 5.12.1.5: the EventQueueOverflowEvent "is put into the Queue of the MonitoredItem in
// addition to the size of the Queue defined for this MonitoredItem without discarding any other Event". A
// loss counted before the delivered queue (the subscription's pre-authorization FIFO) brings the notice in
// with a later delivery; it must not then occupy one of the queue's slots.
// @relation(AC-SVR-MI-GEN-073-OVERFLOW-EVENT-EXTRA, scope=function)
TEST(EventMonitoringTests, AnOverflowEventCarriedFromBeforeTheQueueTakesNoSlot)
{
  {
    auto item = create_event_item_with_detail_filter(2, true);
    item.note_event_queue_overflow();
    item.enqueue_event(make_detail_event_field_list(42, 100));  // brings the notice, at the front
    item.enqueue_event(make_detail_event_field_list(42, 200));
    EXPECT_EQ(drained_shape(item), (std::vector<std::string>{"overflow", "100", "200"}));
  }
  {
    auto item = create_event_item_with_detail_filter(2, false);
    item.enqueue_event(make_detail_event_field_list(42, 100));
    item.insert_overflow_event_once();  // where the subscription puts it: after the event kept at the loss
    item.enqueue_event(make_detail_event_field_list(42, 200));
    EXPECT_EQ(drained_shape(item), (std::vector<std::string>{"100", "overflow", "200"}));
  }
}

// Part 4 section 7.21: with discardOldest TRUE "the oldest (first) Notification in the queue is discarded".
// Once a Publish has taken the overflow event and left the rest, the front of the queue is a regular event
// again, and it is the one a further overflow discards.
// @relation(AC-SVR-MI-GEN-020-DISCARDOLDEST, scope=function)
TEST(EventMonitoringTests, AfterThePublishedOverflowEventTheOldestRemainingEventIsDiscarded)
{
  auto item = create_event_item_with_detail_filter(2, true);
  item.enqueue_event(make_detail_event_field_list(42, 100));
  item.enqueue_event(make_detail_event_field_list(42, 200));
  item.enqueue_event(make_detail_event_field_list(42, 300));  // [overflow, 200, 300]
  ASSERT_EQ(drained_shape(item, 1), (std::vector<std::string>{"overflow"}));  // a Publish capped at one

  item.enqueue_event(make_detail_event_field_list(42, 400));
  auto shape = drained_shape(item);
  std::erase(shape, std::string{"overflow"});  // whether this loss gets its own notice is not the subject
  EXPECT_EQ(shape, (std::vector<std::string>{"300", "400"}));
}

// @relation(SVR-MI-EVT-012, scope=function)
TEST(EventMonitoringTests, OverflowEventSourceNodeIsServerObject)
{
  // TEST-TYP-001-P1: overflow event SourceNode = Server Object (ns=0, i=2253)
  auto item = create_event_item_with_detail_filter(2);

  item.enqueue_event(make_detail_event_field_list(42, 100));
  item.enqueue_event(make_detail_event_field_list(42, 200));
  item.enqueue_event(make_detail_event_field_list(42, 300));

  std::vector<EventFieldList> out;
  item.drain_events(10, out);
  ASSERT_GE(out.size(), 3u);

  // First event is the overflow - field 2 is SourceNode
  const auto& overflowSourceNode = out[0].event_fields()[2];
  ASSERT_TRUE(overflowSourceNode.is_node_id());
  auto expectedServerObject = NodeId{ObjectId::Server};
  EXPECT_EQ(overflowSourceNode.as<NodeId>(), expectedServerObject);

  // Severity should be 1
  EXPECT_EQ(out[0].event_fields()[1].as<uint16_t>(), 1);
}

TEST(EventMonitoringTests, OverflowEventSourceNameIsInternalEventQueueOverflow)
{
  // TEST-TYP-002-P1: overflow event SourceName = "Internal/EventQueueOverflow"
  auto item = create_event_item_with_detail_filter(2);

  item.enqueue_event(make_detail_event_field_list(42, 100));
  item.enqueue_event(make_detail_event_field_list(42, 200));
  item.enqueue_event(make_detail_event_field_list(42, 300));

  std::vector<EventFieldList> out;
  item.drain_events(10, out);
  ASSERT_GE(out.size(), 3u);

  // First event is the overflow - field 3 is SourceName
  const auto& overflowSourceName = out[0].event_fields()[3];
  ASSERT_TRUE(overflowSourceName.is_string());
  EXPECT_EQ(static_cast<std::string_view>(overflowSourceName.as<String>()), "Internal/EventQueueOverflow");
}

// @relation(AC-SVR-MI-EVT-012-OVERFLOW-BYPASSES-FILTER, SVR-MI-EVT-015, scope=function)
TEST(EventMonitoringTests, OverflowEventBypassesWhereClause)
{
  // TEST-FLT-022-P1: overflow event bypasses where clause
  // Create a filter with a where clause that rejects severity < 100
  EventFilter filter;
  filter.select_clauses().push_back(make_select_clause("EventId"));
  filter.select_clauses().push_back(make_select_clause("Severity"));

  // Add where clause: Severity >= 100
  ContentFilterElement element;
  element.filter_operator() = FilterOperator::GreaterThanOrEqual;

  auto sao = std::make_unique<SimpleAttributeOperand>();
  sao->type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  sao->browse_path().push_back(QualifiedName{0, "Severity"});
  sao->attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  RefStructure<Structure> saoRef;
  saoRef.inner_unique_ptr() = std::move(sao);
  element.filter_operands().push_back(std::move(saoRef));

  auto lit = std::make_unique<LiteralOperand>();
  lit->value() = Variant{uint16_t{100}};
  RefStructure<Structure> litRef;
  litRef.inner_unique_ptr() = std::move(lit);
  element.filter_operands().push_back(std::move(litRef));

  filter.where_clause().elements().push_back(std::move(element));

  auto compiled = CompiledEventFilter::compile(filter);
  ASSERT_TRUE(compiled.filter);

  MonitoredItem item;
  item.id = 1;
  item.clientHandle = 42;
  item.monitoringMode = MonitoringMode::Reporting;
  item.isEventItem = true;
  item.queueSize = 2;
  item.discardOldest = true;
  item.eventFilter = std::move(compiled.filter);

  // The overflow event has severity=1, which would NOT pass the where clause.
  // But it should still be present in the queue (SVR-EVT-FLT-022).
  item.enqueue_event(make_event_field_list(42, 500));
  item.enqueue_event(make_event_field_list(42, 600));
  item.enqueue_event(make_event_field_list(42, 700));

  EXPECT_TRUE(item.overflowEventInserted);
  EXPECT_EQ(item.eventQueue.size(), 3u);  // overflow + 2 regular
}

// ============================================================================
// Data-change items still work (regression)
// ============================================================================

TEST(EventMonitoringTests, DataChangeItemStillWorksAfterEventExtension)
{
  MonitoredItem item;
  item.id = 1;
  item.clientHandle = 100;
  item.monitoringMode = MonitoringMode::Reporting;
  item.queueSize = 4;
  item.trigger = DataChangeTrigger::StatusValue;
  item.deadbandType = DeadbandType::None;

  DataValue dv;
  dv.value() = Variant{42.0};
  item.enqueue_initial(dv);

  EXPECT_TRUE(item.has_reportable_notifications());
  EXPECT_FALSE(item.isEventItem);
  EXPECT_EQ(item.queue.size(), 1u);
  EXPECT_TRUE(item.eventQueue.empty());
}

// ============================================================================
// COND-920 / COND-921: RefreshRequired on condition event queue overflow
// ============================================================================

// @relation(SVR-MI-EVT-012, scope=function)
TEST(EventMonitoringTests, RefreshRequired_SetOnConditionEventOverflow)
{
  // COND-920: When a condition event is discarded due to queue overflow
  // (discardOldest=true), refreshRequired must be set.
  auto item = create_event_item_with_filter(2, true);

  item.enqueue_event(make_event_field_list(42, 100), true);  // condition event
  item.enqueue_event(make_event_field_list(42, 200), true);  // condition event - queue full
  EXPECT_FALSE(item.refreshRequired);

  item.enqueue_event(make_event_field_list(42, 300), true);  // overflow discards oldest condition event
  EXPECT_TRUE(item.refreshRequired);
}

TEST(EventMonitoringTests, RefreshRequired_NotSetOnNonConditionEventOverflow)
{
  // COND-921: When only non-condition events are discarded, refreshRequired
  // must remain false.
  auto item = create_event_item_with_filter(2, true);

  item.enqueue_event(make_event_field_list(42, 100), false);  // non-condition
  item.enqueue_event(make_event_field_list(42, 200), false);  // non-condition - queue full
  EXPECT_FALSE(item.refreshRequired);

  item.enqueue_event(make_event_field_list(42, 300), false);  // overflow discards oldest non-condition
  EXPECT_FALSE(item.refreshRequired);
}

TEST(EventMonitoringTests, RefreshRequired_SetOnConditionEventOverflow_DiscardNewest)
{
  // COND-920: When discardOldest=false, the incoming event is dropped.
  // If the dropped event is a condition event, refreshRequired must be set.
  auto item = create_event_item_with_filter(2, false);

  item.enqueue_event(make_event_field_list(42, 100), true);  // condition event
  item.enqueue_event(make_event_field_list(42, 200), true);  // condition event - queue full
  EXPECT_FALSE(item.refreshRequired);

  item.enqueue_event(make_event_field_list(42, 300), true);  // incoming condition event dropped
  EXPECT_TRUE(item.refreshRequired);
}

TEST(EventMonitoringTests, RefreshRequired_MixedEvents_OnlySetWhenConditionDiscarded)
{
  // COND-920/921: refreshRequired tracks the nature of the *discarded* event,
  // not the nature of the incoming event.
  auto item = create_event_item_with_filter(2, true);

  item.enqueue_event(make_event_field_list(42, 100), false);  // non-condition
  item.enqueue_event(make_event_field_list(42, 200), true);  // condition - queue full
  EXPECT_FALSE(item.refreshRequired);

  // Overflow discards oldest (non-condition event at index 1, after overflow marker).
  item.enqueue_event(make_event_field_list(42, 300), false);
  EXPECT_FALSE(item.refreshRequired);

  // Now queue holds: [overflow, condition(200), non-condition(300)].
  // Next enqueue discards the oldest regular event which is condition(200).
  item.enqueue_event(make_event_field_list(42, 400), false);
  EXPECT_TRUE(item.refreshRequired);
}

// ============================================================================
// Queue size revision: minimum, default and range
// ============================================================================

// Part 4 section 5.12.2 / section 7.21: for an event item queueSize=1 asks for the server's *minimum* event
// queue size, which is a different quantity from the server's default (returned for queueSize=0). An
// implementation that folds 1 into the same branch as 0 - or that treats every "small" request as a
// request for its preferred size - returns the default and silently oversizes every minimal item.
// @verifies AC-SVR-MI-GEN-032-EVENT-QUEUESIZE-ONE
TEST(EventMonitoringTests, EventItemQueueSizeOfOneYieldsServerMinimumNotDefault)
{
  // Establish what this server's default is, under the same configuration (queueSize=0 path).
  auto defaultRequest = make_event_create_request(NodeId{ObjectId::Server}, make_simple_event_filter(), 0);
  MonitoredItemCreateContext defaultContext{defaultRequest};
  defaultContext.defaultEventQueueSize = 200;
  defaultContext.maxEventQueueSize = 500;

  auto defaultOutcome = validate_and_build_monitored_item(defaultContext, 1);
  ASSERT_TRUE(defaultOutcome.statusCode.is_good());
  EXPECT_EQ(defaultOutcome.revisedQueueSize, 200u);

  // queueSize=1 asks for the minimum.
  auto request = make_event_create_request(NodeId{ObjectId::Server}, make_simple_event_filter(), 1);
  MonitoredItemCreateContext context{request};
  context.defaultEventQueueSize = 200;
  context.maxEventQueueSize = 500;

  auto outcome = validate_and_build_monitored_item(context, 2);
  ASSERT_TRUE(outcome.statusCode.is_good());
  ASSERT_TRUE(outcome.item);

  // A minimum is a usable queue, is not the default, and cannot exceed either bound.
  EXPECT_GE(outcome.revisedQueueSize, 1u);
  EXPECT_NE(outcome.revisedQueueSize, defaultOutcome.revisedQueueSize);
  EXPECT_LE(outcome.revisedQueueSize, defaultOutcome.revisedQueueSize);
  EXPECT_LE(outcome.revisedQueueSize, context.maxEventQueueSize);

  // The revised value is what the item actually gets, not just what is reported.
  EXPECT_EQ(outcome.item->queueSize, outcome.revisedQueueSize);
}

// Part 4 section 5.12.2: a queueSize inside the server's range is returned unchanged, and one outside is
// returned as the bounding value. Returning unchanged is the obligation that is easy to lose - a
// server that normalised every request to its own default or preferred size would still satisfy the
// clamp half while silently overriding the client's sizing decision, so both halves are asserted
// with a requested value (37) that is neither the default nor the maximum.
// @verifies AC-SVR-MI-GEN-034-QUEUESIZE-IN-RANGE
TEST(EventMonitoringTests, QueueSizeInRangeReturnedUnchangedAndAboveMaximumClamped)
{
  auto inRangeRequest = make_event_create_request(NodeId{ObjectId::Server}, make_simple_event_filter(), 37);
  MonitoredItemCreateContext inRangeContext{inRangeRequest};
  inRangeContext.defaultEventQueueSize = 50;
  inRangeContext.maxEventQueueSize = 100;

  auto inRange = validate_and_build_monitored_item(inRangeContext, 1);
  ASSERT_TRUE(inRange.statusCode.is_good());
  ASSERT_TRUE(inRange.item);
  EXPECT_EQ(inRange.revisedQueueSize, 37u);
  EXPECT_EQ(inRange.item->queueSize, 37u);

  auto aboveMaxRequest =
    make_event_create_request(NodeId{ObjectId::Server}, make_simple_event_filter(), 5000);
  MonitoredItemCreateContext aboveMaxContext{aboveMaxRequest};
  aboveMaxContext.defaultEventQueueSize = 50;
  aboveMaxContext.maxEventQueueSize = 100;

  auto aboveMax = validate_and_build_monitored_item(aboveMaxContext, 2);
  ASSERT_TRUE(aboveMax.statusCode.is_good());
  ASSERT_TRUE(aboveMax.item);
  EXPECT_EQ(aboveMax.revisedQueueSize, 100u);
  EXPECT_EQ(aboveMax.item->queueSize, 100u);
}

// ============================================================================
// Overflow event placement under the discard policy
// ============================================================================

// Part 4 section 5.12.1.5: with discardOldest TRUE the EventQueueOverflowEventType sits at the front of the
// queue and is never itself discarded; with FALSE it sits at the end. An implementation that places
// the notice at a fixed end gets one policy right and, under the other, lets the very overflow the
// notice reports evict it before the client ever sees it - so the TRUE case is driven through
// several further overflows rather than only the first one.
// @verifies AC-SVR-MI-GEN-074-OVERFLOW-EVENT-POSITION
TEST(EventMonitoringTests, OverflowEventPositionFollowsDiscardPolicyAndSurvivesLaterDiscards)
{
  // --- discardOldest = TRUE: at the front, and never discarded ---
  {
    auto item = create_event_item_with_detail_filter(2, true);

    item.enqueue_event(make_detail_event_field_list(42, 100));
    item.enqueue_event(make_detail_event_field_list(42, 200));
    item.enqueue_event(make_detail_event_field_list(42, 300));  // first overflow
    ASSERT_TRUE(item.overflowEventInserted);

    // Keep overflowing: each further discard takes a real event, never the notice.
    item.enqueue_event(make_detail_event_field_list(42, 400));
    item.enqueue_event(make_detail_event_field_list(42, 500));

    std::vector<EventFieldList> out;
    item.drain_events(10, out);
    ASSERT_EQ(out.size(), 3u);

    // Front is still the overflow event (SourceName field is index 3 of the detail filter).
    ASSERT_EQ(out[0].event_fields().size(), 4u);
    ASSERT_TRUE(out[0].event_fields()[3].is_string());
    EXPECT_EQ(
      static_cast<std::string_view>(out[0].event_fields()[3].as<String>()), "Internal/EventQueueOverflow");
    EXPECT_EQ(out[0].event_fields()[1].as<uint16_t>(), 1);

    // The survivors behind it are the two newest real events.
    EXPECT_EQ(out[1].event_fields()[1].as<uint16_t>(), 400);
    EXPECT_EQ(out[2].event_fields()[1].as<uint16_t>(), 500);
  }

  // --- discardOldest = FALSE: at the end ---
  {
    auto item = create_event_item_with_detail_filter(2, false);

    item.enqueue_event(make_detail_event_field_list(42, 100));
    item.enqueue_event(make_detail_event_field_list(42, 200));
    item.enqueue_event(make_detail_event_field_list(42, 300));  // dropped, overflow appended
    ASSERT_TRUE(item.overflowEventInserted);

    item.enqueue_event(make_detail_event_field_list(42, 400));  // dropped as well

    std::vector<EventFieldList> out;
    item.drain_events(10, out);
    ASSERT_EQ(out.size(), 3u);

    // The two oldest real events are kept, the notice is last.
    EXPECT_EQ(out[0].event_fields()[1].as<uint16_t>(), 100);
    EXPECT_EQ(out[1].event_fields()[1].as<uint16_t>(), 200);

    ASSERT_EQ(out[2].event_fields().size(), 4u);
    ASSERT_TRUE(out[2].event_fields()[3].is_string());
    EXPECT_EQ(
      static_cast<std::string_view>(out[2].event_fields()[3].as<String>()), "Internal/EventQueueOverflow");
    EXPECT_EQ(out[2].event_fields()[1].as<uint16_t>(), 1);
  }
}

// ============================================================================
// EventNotifier.SubscribeToEvents as the gate on event subscription
// ============================================================================

namespace
{

using EventNotifierSTA = ua::server::SubscriptionTestAccess;

/// Address space + subscription harness for the obligations that are decided against a real node's
/// EventNotifier attribute. The factory explicitly performs no namespace interaction, so the bit can
/// only be exercised through the create flow that reads the node.
class EventNotifierGateTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mExecutor = mThreadPool.get_executor();

    mAddressSpace = AddressSpace::create("urn:test", mExecutor);
    auto eventNs = default_ns::Namespace::create("urn:test:events", mExecutor);
    mNsIndex = mAddressSpace->add_namespace_sync(eventNs);
    seed_base_event_type_model(*mAddressSpace, mNsIndex);
  }

  void TearDown() override
  {
    mSubscription.reset();
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  std::shared_ptr<Subscription> create_subscription()
  {
    mSubscription =
      Subscription::create(1, 1000, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
    return mSubscription;
  }

  /// Create an Object node carrying exactly the supplied EventNotifier value.
  NodeId create_object_with_notifier(IntegerId numericId, EventNotifierType notifier)
  {
    NodeId id{mNsIndex, numericId};
    auto result = mAddressSpace->try_create_sync<ObjectAccessor>(id, NodeClass::Object);
    EXPECT_TRUE(result.is_good()) << "failed to create notifier object";
    result.value().set_event_notifier(notifier);
    return id;
  }

  std::vector<MonitoredItemCreateResult> create_items(
    std::shared_ptr<Subscription>& sub, CreateMonitoredItemsRequest request)
  {
    std::promise<std::vector<MonitoredItemCreateResult>> promise;
    auto future = promise.get_future();

    sub->create_monitored_items_async(std::move(request),
      *mAddressSpace,
      mCapabilities,
      mSubscriptionLimits,
      nullptr,
      std::weak_ptr<EventBus>{},
      nullptr,
      [&promise](std::vector<MonitoredItemCreateResult> results) { promise.set_value(std::move(results)); });

    return future.get();
  }

  boost::asio::thread_pool mThreadPool;
  boost::asio::any_io_executor mExecutor;
  optional<AddressSpace> mAddressSpace;
  std::shared_ptr<Subscription> mSubscription;
  uint16_t mNsIndex{0};
  ServerConfig::ServerCapabilities mCapabilities;
  ServerConfig::SubscriptionLimits mSubscriptionLimits;
};

}  // namespace

// Part 4 section 5.12.1: the EventNotifier attribute is how a client discovers which Nodes are event
// sources, so an event monitored item may only be created on a Node that advertises bit 0
// (SubscribeToEvents). An implementation that validates only the filter - which is all the pure
// factory can see - accepts the item on any Node at all: it is Good, it costs a queue and a
// subscription slot, and it can never fire. Both halves are driven in ONE batch against the same
// fixture, so the refusal cannot come from anything but the node's own attribute.
// @verifies AC-SVR-MI-GEN-070-EVENTNOTIFIER-REQUIRED
TEST_F(EventNotifierGateTest, EventItemRefusedOnNodeWithoutSubscribeToEventsAndAcceptedWithIt)
{
  auto sub = create_subscription();

  const NodeId notSubscribable = create_object_with_notifier(7000u, EventNotifierType{});
  const NodeId subscribable =
    create_object_with_notifier(7001u, EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});

  CreateMonitoredItemsRequest request;
  request.subscription_id() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;
  request.items_to_create().push_back(make_event_create_request(notSubscribable, make_simple_event_filter()));
  request.items_to_create().push_back(make_event_create_request(subscribable, make_simple_event_filter()));

  auto results = create_items(sub, std::move(request));
  ASSERT_EQ(results.size(), 2u);

  // The Node without the bit is refused, and no item is handed back for it.
  EXPECT_TRUE(results[0].status_code().is_bad())
    << "an event item was accepted on a Node whose EventNotifier lacks SubscribeToEvents";
  EXPECT_EQ(results[0].monitored_item_id(), 0u);

  // The Node with the bit is accepted - the refusal is the attribute's doing, not a blanket reject.
  EXPECT_TRUE(results[1].status_code().is_good());
  EXPECT_NE(results[1].monitored_item_id(), 0u);

  // Only the accepted item is actually live on the subscription; the refused one costs nothing.
  auto liveItems = EventNotifierSTA::on_strand(*sub, [](auto& g) { return g.monitored_items().size(); });
  EXPECT_EQ(liveItems, 1u);
}

// Part 4 section 7.4.4.5 / section 7.22.3: each BrowsePath element of a SimpleAttributeOperand must resolve
// to an Object or Variable InstanceDeclaration. This drives the public create flow, not only the pure
// compiler interface, and places a valid request after the invalid one under a one-item subscription cap.
// The rejected Method filter must therefore neither become live nor consume the valid request's slot.
// @relation(AC-SVR-MI-EVT-013-BROWSEPATH-NODECLASS, scope=function)
TEST_F(EventNotifierGateTest, MethodInstanceDeclarationIsRejectedWithoutConsumingSubscriptionCapacity)
{
  auto sub = create_subscription();
  mCapabilities.maxMonitoredItemsPerSubscription = 1;

  auto eventType =
    mAddressSpace->try_create_node_sync(NodeId{mNsIndex, 7020u}, NodeClass::ObjectType).value();
  eventType.set_browse_name(QualifiedName{mNsIndex, String{"MethodEventType"}});
  eventType.add_reference_sync(
    NodeId{ReferenceTypeId::HasSubtype}, NodeId{ObjectTypeId::BaseEventType}, false);

  auto method = mAddressSpace->try_create_node_sync(NodeId{mNsIndex, 7021u}, NodeClass::Method).value();
  method.set_browse_name(QualifiedName{mNsIndex, String{"ControlMethod"}});
  eventType.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, method.get_node_id(), true);

  EventFilter invalidFilter;
  SimpleAttributeOperand methodClause;
  methodClause.type_definition_id() = eventType.get_node_id();
  methodClause.browse_path().push_back(QualifiedName{mNsIndex, String{"ControlMethod"}});
  methodClause.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  invalidFilter.select_clauses().push_back(std::move(methodClause));

  const NodeId eventSource =
    create_object_with_notifier(7022u, EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
  CreateMonitoredItemsRequest request;
  request.subscription_id() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;
  request.items_to_create().push_back(make_event_create_request(eventSource, std::move(invalidFilter)));
  request.items_to_create().push_back(make_event_create_request(eventSource, make_simple_event_filter()));

  auto results = create_items(sub, std::move(request));
  ASSERT_EQ(results.size(), 2u);

  EXPECT_EQ(results[0].status_code().as_status(), Status::BadMonitoredItemFilterInvalid);
  EXPECT_EQ(results[0].monitored_item_id(), 0u);
  ASSERT_NE(results[0].status_code().shared_detail(), nullptr);

  const auto* filterResult = dynamic_cast<const EventFilterResult*>(results[0].filter_result().get());
  ASSERT_NE(filterResult, nullptr);
  ASSERT_EQ(filterResult->select_clause_results().size(), 1u);
  EXPECT_EQ(filterResult->select_clause_results()[0].as_status(), Status::BadFilterOperandInvalid);
  EXPECT_NE(filterResult->select_clause_results()[0].shared_detail(), nullptr);

  EXPECT_TRUE(results[1].status_code().is_good());
  EXPECT_NE(results[1].monitored_item_id(), 0u);
  const auto liveItems =
    EventNotifierSTA::on_strand(*sub, [](auto& guarded) { return guarded.monitored_items().size(); });
  EXPECT_EQ(liveItems, 1u);
}

// Part 3 section 7 / section 5.5.1: a HasEventSource reference may only originate from an Object whose
// EventNotifier has bit 0 set, because the notifier hierarchy a client walks is only navigable
// through Nodes it can actually subscribe to. A mutator that treats HasEventSource as just another
// reference type materialises links out of Objects that can never be subscribed to, and every
// traversal that follows them ends at a dead end. The audit is run over the references that were
// actually materialised, and is asserted non-empty first so a mutator that refuses everything cannot
// pass it vacuously.
// @verifies AC-SVR-EVT-ATTR-002-HASEVENTSOURCE-NOTIFIER-BIT
TEST_F(EventNotifierGateTest, HasEventSourceOriginatesOnlyFromObjectsThatCanBeSubscribedTo)
{
  const NodeId subscribable =
    create_object_with_notifier(7100u, EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
  const NodeId notSubscribable = create_object_with_notifier(7101u, EventNotifierType{});
  const NodeId eventSource = create_object_with_notifier(7102u, EventNotifierType{});

  auto subscribableNode = mAddressSpace->try_find_node_sync(subscribable);
  ASSERT_TRUE(subscribableNode.is_good());
  auto notSubscribableNode = mAddressSpace->try_find_node_sync(notSubscribable);
  ASSERT_TRUE(notSubscribableNode.is_good());

  // An Object that can be subscribed to may own an event source.
  EXPECT_TRUE(subscribableNode.value()
                .try_add_reference_sync(NodeId{ReferenceTypeId::HasEventSource}, eventSource)
                .is_good());

  // An Object that cannot be subscribed to must not: the mutator refuses to materialise it.
  // The mutation commits: the event-graph check is no longer on the mutation path. Part 3 7.17 is an
  // obligation on the address space a server presents, so the server implementer discharges it by calling
  // AddressSpace::validate_event_graph_async once a build is finished - which is what this now does. The rule
  // being tested is unchanged, and so is the detail that names it.
  ASSERT_TRUE(notSubscribableNode.value()
                .try_add_reference_sync(NodeId{ReferenceTypeId::HasEventSource}, eventSource)
                .is_good());
  const auto rejected = mAddressSpace->try_validate_event_graph_sync();
  EXPECT_TRUE(rejected.is_bad())
    << "a HasEventSource reference from an Object whose EventNotifier lacks SubscribeToEvents was not "
       "reported by the event-graph check";
  EXPECT_EQ(rejected.status_code(), Status::BadReferenceNotAllowed);
  ASSERT_NE(rejected.status_code().shared_detail(), nullptr);
  EXPECT_EQ(rejected.status_code().shared_detail()->code, "EventReferenceSourceNotSubscribable");
  // Removed again, so the audit below reads a graph the check accepts, and stays an independent statement
  // of the same rule over what the store actually holds.
  notSubscribableNode.value().remove_reference_sync(NodeId{ReferenceTypeId::HasEventSource}, eventSource);
  EXPECT_TRUE(mAddressSpace->try_validate_event_graph_sync().is_good());

  // Audit every HasEventSource reference that now exists and read its source Object's EventNotifier.
  const NodeId candidates[] = {subscribable, notSubscribable, eventSource};
  size_t hasEventSourceReferences = 0;
  for (const auto& candidate : candidates)
  {
    auto nodeResult = mAddressSpace->try_find_node_sync(candidate);
    ASSERT_TRUE(nodeResult.is_good());
    auto object = nodeResult.value().as<ObjectAccessor>();
    ASSERT_TRUE(object);

    auto references = nodeResult.value().get_references_sync();
    for (const auto& reference : references)
    {
      if (!reference.is_forward() || reference.is_remote())
        continue;
      if (reference.type_id() != NodeId{ReferenceTypeId::HasEventSource})
        continue;

      ++hasEventSourceReferences;
      EXPECT_TRUE(object->get_event_notifier().test(EventNotifierType::Bit::SubscribeToEvents))
        << "a HasEventSource reference originates from an Object that cannot be subscribed to";
    }
  }

  ASSERT_GT(hasEventSourceReferences, 0u)
    << "no HasEventSource reference was materialised at all - the bit audit would be vacuous";
}

// Part 3 section 5.5.1 (Table 11) / section 7: a HasEventSource reference may only originate from an Object
// whose EventNotifier has bit 0 (SubscribeToEvents) set; SVR-EVT-ATTR-002 puts the duty on the address-space
// mutator, which "must refuse to materialise the reference". A refusal is two claims, not one, and the second
// is the one a plausible implementation loses: a mutator that grew a reference-type check late - or that
// validates in the service layer above the store - can report a Bad status to the caller while the edge has
// already been appended to the source Node's reference list, so every later browse and every notifier
// traversal still walks a link out of an Object that can never be subscribed to. Status and materialisation
// are therefore asserted separately, against the source Node's own references, and the identical add from an
// Object that DOES carry the bit is driven through the same call in the same fixture so the enumeration is
// proven able to see such an edge and the refusal cannot be a blanket reject of HasEventSource.
// @verifies AC-SVR-EVT-ATTR-002-HASEVENTSOURCE-NOTIFIER-BIT
TEST_F(EventNotifierGateTest, EveryHasEventSourceOriginatesFromAnObjectThatCanBeSubscribedTo)
{
  const NodeId subscribable =
    create_object_with_notifier(7200u, EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
  const NodeId notSubscribable = create_object_with_notifier(7201u, EventNotifierType{});
  const NodeId eventSource = create_object_with_notifier(7202u, EventNotifierType{});

  auto subscribableNode = mAddressSpace->try_find_node_sync(subscribable);
  ASSERT_TRUE(subscribableNode.is_good());
  auto notSubscribableNode = mAddressSpace->try_find_node_sync(notSubscribable);
  ASSERT_TRUE(notSubscribableNode.is_good());

  // Counts the forward HasEventSource edges from one Node to one target that the store actually
  // holds - this is what "materialised" means, independent of what the mutator reported.
  auto countMaterialisedEventSources = [this](const NodeId& source, const NodeId& target)
  {
    size_t materialised = 0;
    auto nodeResult = mAddressSpace->try_find_node_sync(source);
    EXPECT_TRUE(nodeResult.is_good());
    if (!nodeResult.is_good())
      return materialised;

    auto references = nodeResult.value().get_references_sync();
    for (const auto& reference : references)
    {
      if (!reference.is_forward() || reference.is_remote())
        continue;
      if (reference.type_id() != NodeId{ReferenceTypeId::HasEventSource})
        continue;
      if (reference.target_id().node_id() != target)
        continue;
      ++materialised;
    }
    return materialised;
  };

  // Control: an Object that can be subscribed to may own an event source, and the edge is visible.
  EXPECT_TRUE(subscribableNode.value()
                .try_add_reference_sync(NodeId{ReferenceTypeId::HasEventSource}, eventSource)
                .is_good());
  ASSERT_EQ(countMaterialisedEventSources(subscribable, eventSource), 1u)
    << "the permitted HasEventSource edge is not visible, so absence elsewhere proves nothing";

  // The event-graph check is no longer on the mutation path: Part 3 7.17 binds the address space a server
  // presents, and the implementer discharges it by calling AddressSpace::validate_event_graph_async once a build
  // is finished. So the add commits, the check reports it, and the edge is removed again - which is what
  // keeps the audit below an audit of a graph the server would accept.
  ASSERT_TRUE(notSubscribableNode.value()
                .try_add_reference_sync(NodeId{ReferenceTypeId::HasEventSource}, eventSource)
                .is_good());

  // First conjunct: the check reports it, naming the rule it broke.
  const auto verdict = mAddressSpace->try_validate_event_graph_sync();
  EXPECT_EQ(verdict.status_code(), Status::BadReferenceNotAllowed)
    << "a HasEventSource reference sourced from an Object whose EventNotifier lacks SubscribeToEvents "
       "went unreported";
  ASSERT_NE(verdict.status_code().shared_detail(), nullptr);
  EXPECT_EQ(verdict.status_code().shared_detail()->code, "EventReferenceSourceNotSubscribable");

  // Second conjunct: the edge it names really is in the store, so the report is about something real
  // rather than a status invented over an absent reference.
  EXPECT_EQ(countMaterialisedEventSources(notSubscribable, eventSource), 1u)
    << "the check reported an edge the store does not hold";

  notSubscribableNode.value().remove_reference_sync(NodeId{ReferenceTypeId::HasEventSource}, eventSource);
  EXPECT_TRUE(mAddressSpace->try_validate_event_graph_sync().is_good());

  // The criterion's own audit: for every HasEventSource reference that now exists anywhere in this
  // address space, read the source Object's EventNotifier and require the SubscribeToEvents bit.
  const NodeId candidates[] = {subscribable, notSubscribable, eventSource};
  size_t auditedReferences = 0;
  for (const auto& candidate : candidates)
  {
    auto nodeResult = mAddressSpace->try_find_node_sync(candidate);
    ASSERT_TRUE(nodeResult.is_good());
    auto object = nodeResult.value().as<ObjectAccessor>();
    ASSERT_TRUE(object);

    auto references = nodeResult.value().get_references_sync();
    for (const auto& reference : references)
    {
      if (!reference.is_forward() || reference.is_remote())
        continue;
      if (reference.type_id() != NodeId{ReferenceTypeId::HasEventSource})
        continue;

      ++auditedReferences;
      EXPECT_TRUE(object->get_event_notifier().test(EventNotifierType::Bit::SubscribeToEvents))
        << "a HasEventSource reference originates from an Object that cannot be subscribed to";
    }
  }

  ASSERT_GT(auditedReferences, 0u)
    << "no HasEventSource reference exists at all - the bit audit would be vacuous";
}

// Part 3 section 7.17: rejecting one invalid HasEventSource in a batch must not leave earlier edges from
// that batch materialised.
// @verifies AC-SVR-EVT-ATTR-002-HASEVENTSOURCE-NOTIFIER-BIT
TEST_F(EventNotifierGateTest, InvalidEventReferenceCommitsWithItsWholeBatchAndTheDetectorFindsIt)
{
  const NodeId notSubscribable = create_object_with_notifier(7250u, EventNotifierType{});
  const NodeId target = create_object_with_notifier(7251u, EventNotifierType{});

  auto sourceResult = mAddressSpace->try_find_node_sync(notSubscribable);
  ASSERT_TRUE(sourceResult.is_good());

  std::vector<Reference> references;
  references.emplace_back(NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{target}, true);
  references.emplace_back(NodeId{ReferenceTypeId::HasEventSource}, ExpandedNodeId{target}, true);

  // The mutation commits: the event-graph check is no longer on the mutation path. Part 3 7.17 is an
  // obligation on the address space a server presents, so the server implementer discharges it by calling
  // AddressSpace::validate_event_graph_async once a build is finished - which is what this now does. The rule
  // being tested is unchanged, and so is the detail that names it.
  // Atomicity of the batch is still the subject: it commits as one overlay, so BOTH references land,
  // and the check then judges the graph that overlay produced.
  ASSERT_TRUE(sourceResult.value().try_add_references_sync(std::move(references)).is_good());
  EXPECT_EQ(sourceResult.value().get_references_sync().size(), 2u)
    << "a batch must commit whole or not at all; a partial prefix would be the defect";
  const auto rejected = mAddressSpace->try_validate_event_graph_sync();
  EXPECT_EQ(rejected.status_code(), Status::BadReferenceNotAllowed);
  ASSERT_NE(rejected.status_code().shared_detail(), nullptr);
  EXPECT_EQ(rejected.status_code().shared_detail()->code, "EventReferenceSourceNotSubscribable");
}

// Part 3 section 5.5.1 / section 7: the constraint is on the *reference*, not on the call that creates it - a
// HasEventSource reference may only originate from an Object whose EventNotifier has bit 0 set,
// however that reference came to exist. Every reference has two ends, and the store lets either end
// add it: `BaseNode::add_reference_internal`
// (sdk/implementation/address_space/implementations/default/ua_default_base_node.cpp:167) appends
// whatever it is handed and mirrors nothing, so adding an INVERSE HasEventSource on the event source
// node names the other Node as the reference's source without that Node ever being touched. A
// mutator that grew its guard on the forward path - the obvious place, where the caller is the
// source - leaves this back door wide open, and the resulting model defect is identical: the
// notifier hierarchy claims an event source under an Object no client can subscribe to. The audit
// therefore resolves each reference's source from its direction rather than assuming it is the Node
// being enumerated, and the legal inverse add is driven first so the enumeration is proven able to
// see an inverse edge at all.
// @verifies AC-SVR-EVT-ATTR-002-HASEVENTSOURCE-NOTIFIER-BIT
TEST_F(EventNotifierGateTest, HasEventSourceOriginatesFromASubscribableObjectWhicheverEndAddsIt)
{
  const NodeId subscribable =
    create_object_with_notifier(7300u, EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
  const NodeId notSubscribable = create_object_with_notifier(7301u, EventNotifierType{});
  const NodeId eventSource = create_object_with_notifier(7302u, EventNotifierType{});

  auto eventSourceNode = mAddressSpace->try_find_node_sync(eventSource);
  ASSERT_TRUE(eventSourceNode.is_good());

  // Counts the INVERSE HasEventSource edges held by @p holder that name @p namedSource as the
  // reference's source Object - i.e. the edges asserting "namedSource HasEventSource holder".
  auto countMaterialisedInverseEdges = [this](const NodeId& holder, const NodeId& namedSource)
  {
    size_t materialised = 0;
    auto nodeResult = mAddressSpace->try_find_node_sync(holder);
    EXPECT_TRUE(nodeResult.is_good());
    if (!nodeResult.is_good())
      return materialised;

    auto references = nodeResult.value().get_references_sync();
    for (const auto& reference : references)
    {
      if (reference.is_forward() || reference.is_remote())
        continue;
      if (reference.type_id() != NodeId{ReferenceTypeId::HasEventSource})
        continue;
      if (reference.target_id().node_id() != namedSource)
        continue;
      ++materialised;
    }
    return materialised;
  };

  // Control: "subscribable HasEventSource eventSource", added from the eventSource end. The named
  // source carries the bit, so this is a legal model and the edge must be visible from this end.
  EXPECT_TRUE(
    eventSourceNode.value()
      .try_add_reference_sync(NodeId{ReferenceTypeId::HasEventSource}, subscribable, /*isForward=*/false)
      .is_good());
  ASSERT_EQ(countMaterialisedInverseEdges(eventSource, subscribable), 1u)
    << "the permitted inverse HasEventSource edge is not visible from the node that holds it, so its "
       "absence elsewhere would prove nothing";

  // First conjunct: the same add naming an Object without the bit as the reference's source is
  // reported as refused, even though the caller is the target end rather than the source end.
  // The mutation commits: the event-graph check is no longer on the mutation path. Part 3 7.17 is an
  // obligation on the address space a server presents, so the server implementer discharges it by calling
  // AddressSpace::validate_event_graph_async once a build is finished - which is what this now does. The rule
  // being tested is unchanged, and so is the detail that names it.
  // Added from the TARGET end, which is the point: the constraint is on the reference, not on the call
  // that created it, and the check looks at the reference whichever end holds it.
  ASSERT_TRUE(
    eventSourceNode.value()
      .try_add_reference_sync(NodeId{ReferenceTypeId::HasEventSource}, notSubscribable, /*isForward=*/false)
      .is_good());
  const auto rejected = mAddressSpace->try_validate_event_graph_sync();
  EXPECT_TRUE(rejected.is_bad())
    << "a HasEventSource reference whose source Object lacks SubscribeToEvents went unreported when it "
       "was added from the target end";
  EXPECT_EQ(rejected.status_code(), Status::BadReferenceNotAllowed);
  ASSERT_NE(rejected.status_code().shared_detail(), nullptr);
  EXPECT_EQ(rejected.status_code().shared_detail()->code, "EventReferenceSourceNotSubscribable");

  // Second conjunct: the edge it names really is in the store, held at the target end.
  EXPECT_EQ(countMaterialisedInverseEdges(eventSource, notSubscribable), 1u)
    << "the check reported an inverse edge the store does not hold";

  eventSourceNode.value().remove_reference_sync(
    NodeId{ReferenceTypeId::HasEventSource}, notSubscribable, /*isForward=*/false);
  EXPECT_TRUE(mAddressSpace->try_validate_event_graph_sync().is_good());

  // The criterion's own audit, run over every HasEventSource reference now held anywhere in this
  // address space in EITHER direction: resolve the reference's source Object from its direction and
  // require the SubscribeToEvents bit on it.
  const NodeId candidates[] = {subscribable, notSubscribable, eventSource};
  size_t auditedReferences = 0;
  for (const auto& candidate : candidates)
  {
    auto nodeResult = mAddressSpace->try_find_node_sync(candidate);
    ASSERT_TRUE(nodeResult.is_good());

    auto references = nodeResult.value().get_references_sync();
    for (const auto& reference : references)
    {
      if (reference.is_remote())
        continue;
      if (reference.type_id() != NodeId{ReferenceTypeId::HasEventSource})
        continue;

      // A forward reference is sourced by the Node holding it; an inverse one is sourced by the
      // Node it points at.
      const NodeId sourceId = reference.is_forward() ? candidate : reference.target_id().node_id();
      auto sourceResult = mAddressSpace->try_find_node_sync(sourceId);
      ASSERT_TRUE(sourceResult.is_good());
      auto sourceObject = sourceResult.value().as<ObjectAccessor>();
      ASSERT_TRUE(sourceObject);

      ++auditedReferences;
      EXPECT_TRUE(sourceObject->get_event_notifier().test(EventNotifierType::Bit::SubscribeToEvents))
        << "a HasEventSource reference originates from an Object that cannot be subscribed to";
    }
  }

  ASSERT_GT(auditedReferences, 0u)
    << "no HasEventSource reference exists at all - the bit audit would be vacuous";
}
