// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_monitored_item_factory.h"

#include "ua_aggregate_filter.h"
#include "ua_attribute_id.h"
#include "ua_content_filter_element.h"
#include "ua_data_change_filter.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_event_filter.h"
#include "ua_filter_operator.h"
#include "ua_monitoring_parameters.h"
#include "ua_monitored_item_create_request.h"
#include "ua_objecttype_id.h"
#include "ua_qualified_name.h"
#include "ua_simple_attribute_operand.h"
#include "ua_utilities.h"

#include <algorithm>

using namespace ua;
using namespace ua::server;

namespace
{

// Returns true when the StatusCode carries an ErrorDetail with the given context key.
bool has_context_key(const StatusCode& statusCode, const ContextKey& key)
{
  const auto detail = statusCode.shared_detail();
  if (!detail)
  {
    return false;
  }
  return std::any_of(detail->context.begin(),
    detail->context.end(),
    [&](const NamedValue& entry) { return entry.key == key.value(); });
}

MonitoredItemCreateRequest make_request(
  NodeId nodeId, uint32_t attributeId = 13, MonitoringMode mode = MonitoringMode::Reporting)
{
  MonitoredItemCreateRequest req;
  req.item_to_monitor().node_id() = std::move(nodeId);
  req.item_to_monitor().attribute_id() = attributeId;
  req.monitoring_mode() = mode;
  req.requested_parameters().client_handle() = 42;
  req.requested_parameters().sampling_interval() = 1000;
  req.requested_parameters().queue_size() = 5;
  req.requested_parameters().discard_oldest() = true;
  return req;
}

MonitoredItemCreateContext make_context(const MonitoredItemCreateRequest& req)
{
  return {req, TimestampsToReturn::Both, 1000, 100, 0, 60000};
}

MonitoredItemCreateRequest make_deadband_request(DeadbandType deadbandType, double deadbandValue)
{
  auto request = make_request(NodeId{42});
  auto filter = std::make_unique<DataChangeFilter>();
  filter->deadband_type() = numeric_cast<uint32_t>(utils::to_underlying(deadbandType));
  filter->deadband_value() = deadbandValue;
  request.requested_parameters().filter().inner_unique_ptr() = std::move(filter);
  return request;
}

// A valid BaseEventType select clause (Value attribute on the named field).
SimpleAttributeOperand make_select_clause(std::string_view fieldName)
{
  SimpleAttributeOperand clause;
  clause.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  clause.browse_path().push_back(QualifiedName{0, String{fieldName}});
  clause.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  return clause;
}

// An EventNotifier MonitoredItem request carrying an EventFilter with the given select/where counts.
MonitoredItemCreateRequest make_event_request(uint32_t selectClauseCount, uint32_t whereElementCount = 0)
{
  auto req = make_request(NodeId{0, 2253}, static_cast<uint32_t>(AttributeId::EventNotifier));

  auto filter = std::make_unique<EventFilter>();
  for (uint32_t i = 0; i < selectClauseCount; ++i)
  {
    filter->select_clauses().push_back(make_select_clause("Message"));
  }
  for (uint32_t i = 0; i < whereElementCount; ++i)
  {
    ContentFilterElement element;
    element.filter_operator() = FilterOperator::OfType;
    filter->where_clause().elements().push_back(std::move(element));
  }

  req.requested_parameters().filter().inner_unique_ptr() = std::move(filter);
  return req;
}

}  // namespace

// --- revise_sampling_interval ---

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-001, scope=function)
TEST(MonitoredItemFactoryTests, ReviseSamplingIntervalNegativeUsesPublishingInterval)
{
  EXPECT_EQ(revise_sampling_interval(-1, 500, 0, 60000), 500);
}

TEST(MonitoredItemFactoryTests, ReviseSamplingIntervalZeroUsesFastest)
{
  EXPECT_EQ(revise_sampling_interval(0, 1000, 50, 60000), 50);
}

TEST(MonitoredItemFactoryTests, ReviseSamplingIntervalExactMatch)
{
  EXPECT_EQ(revise_sampling_interval(250, 1000, 50, 60000), 250);
}

TEST(MonitoredItemFactoryTests, ReviseSamplingIntervalClampedToMin)
{
  EXPECT_EQ(revise_sampling_interval(10, 1000, 50, 60000), 50);
}

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-004, scope=function)
TEST(MonitoredItemFactoryTests, ReviseSamplingIntervalClampedToMax)
{
  EXPECT_EQ(revise_sampling_interval(100000, 1000, 50, 60000), 60000);
}

// --- revise_queue_size ---

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-030, scope=function)
TEST(MonitoredItemFactoryTests, ReviseQueueSizeZeroToOne)
{
  EXPECT_EQ(revise_queue_size(0, 100), 1u);
}

TEST(MonitoredItemFactoryTests, ReviseQueueSizeOneToOne)
{
  EXPECT_EQ(revise_queue_size(1, 100), 1u);
}

TEST(MonitoredItemFactoryTests, ReviseQueueSizeClampedToMax)
{
  EXPECT_EQ(revise_queue_size(200, 100), 100u);
}

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-034, scope=function)
TEST(MonitoredItemFactoryTests, ReviseQueueSizeWithinRange)
{
  EXPECT_EQ(revise_queue_size(50, 100), 50u);
}

// --- parse_data_change_filter ---

// @relation(SVR-MI-EVT-015, SVR-MI-GEN-040, scope=function)
TEST(MonitoredItemFactoryTests, ParseFilterNoFilterUsesDefaults)
{
  RefStructure<Structure> noFilter;
  auto result = parse_data_change_filter(noFilter, NodeId{42}, AttributeId::Value);
  EXPECT_TRUE(result.statusCode.is_good());
  EXPECT_EQ(result.trigger, DataChangeTrigger::StatusValue);
  EXPECT_EQ(result.deadbandType, DeadbandType::None);
}

TEST(MonitoredItemFactoryTests, ParseFilterValidDataChangeFilter)
{
  RefStructure<Structure> filter;
  auto dcf = std::make_unique<DataChangeFilter>();
  dcf->trigger() = DataChangeTrigger::StatusValueTimestamp;
  dcf->deadband_type() = static_cast<uint32_t>(DeadbandType::Absolute);
  dcf->deadband_value() = 1.5;
  filter.inner_unique_ptr() = std::move(dcf);

  auto result = parse_data_change_filter(filter, NodeId{42}, AttributeId::Value);
  EXPECT_TRUE(result.statusCode.is_good());
  EXPECT_EQ(result.trigger, DataChangeTrigger::StatusValueTimestamp);
  EXPECT_EQ(result.deadbandType, DeadbandType::Absolute);
  EXPECT_EQ(result.deadbandValue, 1.5);
}

TEST(MonitoredItemFactoryTests, ParseFilterRejectsInvalidDataChangeTriggerWithDetail)
{
  RefStructure<Structure> filter;
  auto dataChangeFilter = std::make_unique<DataChangeFilter>();
  dataChangeFilter->trigger() = static_cast<DataChangeTrigger>(99);
  filter.inner_unique_ptr() = std::move(dataChangeFilter);

  auto result = parse_data_change_filter(filter, NodeId{42}, AttributeId::Value);

  EXPECT_EQ(result.statusCode, StatusCode{Status::BadMonitoredItemFilterInvalid});
  ASSERT_NE(result.statusCode.shared_detail(), nullptr);
  EXPECT_TRUE(has_context_key(result.statusCode, ContextKeys::nodeId));
  EXPECT_TRUE(has_context_key(result.statusCode, ContextKeys::nodeAttribute));
  EXPECT_TRUE(has_context_key(result.statusCode, ContextKeys::value));
}

TEST(MonitoredItemFactoryTests, ParseFilterReportsAggregateFilterAsUnsupported)
{
  RefStructure<Structure> filter;
  filter.inner_unique_ptr() = std::make_unique<AggregateFilter>();

  auto result = parse_data_change_filter(filter, NodeId{42}, AttributeId::Value);

  EXPECT_EQ(result.statusCode, StatusCode{Status::BadMonitoredItemFilterUnsupported});
  ASSERT_NE(result.statusCode.shared_detail(), nullptr);
  EXPECT_TRUE(has_context_key(result.statusCode, ContextKeys::nodeId));
  EXPECT_TRUE(has_context_key(result.statusCode, ContextKeys::nodeAttribute));
}

// @relation(SVR-MI-GEN-042, scope=function)
TEST(MonitoredItemFactoryTests, ParseFilterDeadbandOnNonValueAttributeFails)
{
  RefStructure<Structure> filter;
  auto dcf = std::make_unique<DataChangeFilter>();
  dcf->deadband_type() = static_cast<uint32_t>(DeadbandType::Absolute);
  dcf->deadband_value() = 1.0;
  filter.inner_unique_ptr() = std::move(dcf);

  auto result = parse_data_change_filter(filter, NodeId{42}, AttributeId::BrowseName);
  EXPECT_EQ(result.statusCode, StatusCode{Status::BadFilterNotAllowed});
  // Enriched with an ErrorDetail carrying the offending node id + attribute.
  ASSERT_NE(result.statusCode.shared_detail(), nullptr);
  EXPECT_TRUE(has_context_key(result.statusCode, ContextKeys::nodeId));
  EXPECT_TRUE(has_context_key(result.statusCode, ContextKeys::nodeAttribute));
}

TEST(MonitoredItemFactoryTests, ParseFilterNegativeDeadbandFails)
{
  RefStructure<Structure> filter;
  auto dcf = std::make_unique<DataChangeFilter>();
  dcf->deadband_type() = static_cast<uint32_t>(DeadbandType::Absolute);
  dcf->deadband_value() = -1.0;
  filter.inner_unique_ptr() = std::move(dcf);

  auto result = parse_data_change_filter(filter, NodeId{42}, AttributeId::Value);
  EXPECT_EQ(result.statusCode, StatusCode{Status::BadDeadbandFilterInvalid});
  // Enriched with an ErrorDetail carrying the offending node id.
  ASSERT_NE(result.statusCode.shared_detail(), nullptr);
  EXPECT_TRUE(has_context_key(result.statusCode, ContextKeys::nodeId));
}

// @relation(AC-SVR-DA-022-DEADBAND-RANGE, scope=function)
TEST(MonitoredItemFactoryTests, PercentDeadbandOutsideRangeRejectedWithoutCreatingItem)
{
  for (const double deadbandValue : {-1.0, 150.0})
  {
    auto request = make_deadband_request(DeadbandType::Percent, deadbandValue);
    auto context = make_context(request);

    const auto outcome = validate_and_build_monitored_item(context, 7);

    EXPECT_EQ(outcome.statusCode, StatusCode{Status::BadDeadbandFilterInvalid})
      << "deadbandValue=" << deadbandValue;
    EXPECT_EQ(outcome.item, nullptr) << "deadbandValue=" << deadbandValue;
    ASSERT_NE(outcome.statusCode.shared_detail(), nullptr) << "deadbandValue=" << deadbandValue;
    EXPECT_TRUE(has_context_key(outcome.statusCode, ContextKeys::nodeId))
      << "deadbandValue=" << deadbandValue;
    if (deadbandValue > 100.0)
    {
      EXPECT_TRUE(has_context_key(outcome.statusCode, ContextKeys::actual));
      EXPECT_TRUE(has_context_key(outcome.statusCode, ContextKeys::limit));
    }
  }
}

// @relation(AC-SVR-DA-022-DEADBAND-RANGE, scope=function)
TEST(MonitoredItemFactoryTests, PercentDeadbandExactBoundariesAccepted)
{
  for (const double deadbandValue : {0.0, 100.0})
  {
    auto request = make_deadband_request(DeadbandType::Percent, deadbandValue);
    auto context = make_context(request);

    auto outcome = validate_and_build_monitored_item(context, 7);

    EXPECT_TRUE(outcome.statusCode.is_good()) << "deadbandValue=" << deadbandValue;
    ASSERT_NE(outcome.item, nullptr) << "deadbandValue=" << deadbandValue;
    EXPECT_EQ(outcome.item->deadbandType, DeadbandType::Percent);
    EXPECT_DOUBLE_EQ(outcome.item->deadbandValue, deadbandValue);
  }
}

// @relation(AC-SVR-DA-022-DEADBAND-RANGE, scope=function)
TEST(MonitoredItemFactoryTests, AbsoluteDeadbandAboveOneHundredRemainsAccepted)
{
  auto request = make_deadband_request(DeadbandType::Absolute, 150.0);
  auto context = make_context(request);

  auto outcome = validate_and_build_monitored_item(context, 7);

  EXPECT_TRUE(outcome.statusCode.is_good());
  ASSERT_NE(outcome.item, nullptr);
  EXPECT_EQ(outcome.item->deadbandType, DeadbandType::Absolute);
  EXPECT_DOUBLE_EQ(outcome.item->deadbandValue, 150.0);
}

// --- validate_and_build_monitored_item ---

TEST(MonitoredItemFactoryTests, ValidItemBuildsSuccessfully)
{
  auto req = make_request(NodeId{1});
  auto context = make_context(req);

  auto outcome = validate_and_build_monitored_item(context, 7);
  EXPECT_TRUE(outcome.statusCode.is_good());
  ASSERT_NE(outcome.item, nullptr);
  EXPECT_EQ(outcome.item->id, 7u);
  EXPECT_EQ(outcome.item->clientHandle, 42u);
  EXPECT_EQ(outcome.item->monitoringMode, MonitoringMode::Reporting);
  EXPECT_EQ(outcome.item->queueSize, 5u);
  EXPECT_TRUE(outcome.item->discardOldest);
  EXPECT_FALSE(outcome.item->isNonValueAttribute);
}

TEST(MonitoredItemFactoryTests, InvalidMonitoringModeRejected)
{
  auto req = make_request(NodeId{1});
  req.monitoring_mode() = static_cast<MonitoringMode>(99);
  auto context = make_context(req);

  auto outcome = validate_and_build_monitored_item(context, 1);
  EXPECT_EQ(outcome.statusCode, StatusCode{Status::BadMonitoringModeInvalid});
  EXPECT_EQ(outcome.item, nullptr);
  // Enriched with an ErrorDetail carrying the target node id.
  ASSERT_NE(outcome.statusCode.shared_detail(), nullptr);
  EXPECT_TRUE(has_context_key(outcome.statusCode, ContextKeys::nodeId));
}

TEST(MonitoredItemFactoryTests, InvalidAttributeIdRejected)
{
  auto req = make_request(NodeId{1}, 0);
  auto context = make_context(req);

  auto outcome = validate_and_build_monitored_item(context, 1);
  EXPECT_EQ(outcome.statusCode, StatusCode{Status::BadAttributeIdInvalid});
  EXPECT_EQ(outcome.item, nullptr);
  // Enriched with an ErrorDetail carrying the target node id + attribute.
  ASSERT_NE(outcome.statusCode.shared_detail(), nullptr);
  EXPECT_TRUE(has_context_key(outcome.statusCode, ContextKeys::nodeId));
  EXPECT_TRUE(has_context_key(outcome.statusCode, ContextKeys::nodeAttribute));
}

TEST(MonitoredItemFactoryTests, InvalidIndexRangeRejected)
{
  // A malformed IndexRange (inverted bounds) cannot produce a valid slice, so the
  // item is rejected at create time with Bad_IndexRangeInvalid rather than accepted
  // as Good. Mirrors UACTT Monitor Basic (negative/inverted ranges on array items).
  auto req = make_request(NodeId{1});
  req.item_to_monitor().index_range() = NumericRange{"4:2"};  // hi < lo
  auto context = make_context(req);

  auto outcome = validate_and_build_monitored_item(context, 1);
  EXPECT_EQ(outcome.statusCode, StatusCode{Status::BadIndexRangeInvalid});
  EXPECT_EQ(outcome.item, nullptr);
}

TEST(MonitoredItemFactoryTests, ValidIndexRangeAccepted)
{
  auto req = make_request(NodeId{1});
  req.item_to_monitor().index_range() = NumericRange{"0:3"};
  auto context = make_context(req);

  auto outcome = validate_and_build_monitored_item(context, 1);
  EXPECT_TRUE(outcome.statusCode.is_good());
  ASSERT_NE(outcome.item, nullptr);
}

// @relation(SVR-MI-GEN-071, scope=function)
TEST(MonitoredItemFactoryTests, NonValueAttributeFlagSet)
{
  auto req = make_request(NodeId{1}, static_cast<uint32_t>(AttributeId::BrowseName));
  auto context = make_context(req);

  auto outcome = validate_and_build_monitored_item(context, 1);
  EXPECT_TRUE(outcome.statusCode.is_good());
  ASSERT_NE(outcome.item, nullptr);
  EXPECT_TRUE(outcome.item->isNonValueAttribute);
}

TEST(MonitoredItemFactoryTests, SamplingIntervalRevised)
{
  auto req = make_request(NodeId{1});
  req.requested_parameters().sampling_interval() = -1;
  auto context = make_context(req);

  auto outcome = validate_and_build_monitored_item(context, 1);
  EXPECT_TRUE(outcome.statusCode.is_good());
  // Negative -> publishing interval (1000)
  EXPECT_EQ(outcome.revisedSamplingInterval, 1000);
}

TEST(MonitoredItemFactoryTests, QueueSizeRevised)
{
  auto req = make_request(NodeId{1});
  req.requested_parameters().queue_size() = 999;
  auto context = make_context(req);
  // maxQueueSize = 100

  auto outcome = validate_and_build_monitored_item(context, 1);
  EXPECT_TRUE(outcome.statusCode.is_good());
  EXPECT_EQ(outcome.revisedQueueSize, 100u);
}

// --- EventFilter clause limits (SVR-EVT-CAP-001/002) ---
// The compile-time caps are now wired from the context (sourced from ServerCapabilities). Before the
// wiring these all compiled with limits {0,0} and an over-limit filter was accepted.

TEST(MonitoredItemFactoryTests, EventFilterSelectClausesOverLimitRejected)
{
  auto req = make_event_request(/*selectClauseCount=*/3);
  auto context = make_context(req);
  context.maxSelectClauses = 2;

  auto outcome = validate_and_build_monitored_item(context, 1);
  EXPECT_EQ(outcome.statusCode.as_uint32(), static_cast<uint32_t>(Status::BadMonitoredItemFilterInvalid));
}

TEST(MonitoredItemFactoryTests, EventFilterSelectClausesAtLimitAccepted)
{
  auto req = make_event_request(/*selectClauseCount=*/2);
  auto context = make_context(req);
  context.maxSelectClauses = 2;

  auto outcome = validate_and_build_monitored_item(context, 1);
  EXPECT_TRUE(outcome.statusCode.is_good()) << "0x" << std::hex << outcome.statusCode.as_uint32();
  ASSERT_NE(outcome.item, nullptr);
}

TEST(MonitoredItemFactoryTests, EventFilterSelectClausesUnlimitedWhenZero)
{
  auto req = make_event_request(/*selectClauseCount=*/5);
  auto context = make_context(req);
  context.maxSelectClauses = 0;  // 0 = unlimited

  auto outcome = validate_and_build_monitored_item(context, 1);
  EXPECT_TRUE(outcome.statusCode.is_good()) << "0x" << std::hex << outcome.statusCode.as_uint32();
}

TEST(MonitoredItemFactoryTests, EventFilterWhereClausesOverLimitRejected)
{
  auto req = make_event_request(/*selectClauseCount=*/1, /*whereElementCount=*/3);
  auto context = make_context(req);
  context.maxWhereClauseElements = 2;

  auto outcome = validate_and_build_monitored_item(context, 1);
  EXPECT_EQ(outcome.statusCode.as_uint32(), static_cast<uint32_t>(Status::BadMonitoredItemFilterInvalid));
}
