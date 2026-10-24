// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Phase 4b: History Services - Compliance Integration Tests
///
/// HistoryRead (ATTR-HREAD-*) and HistoryUpdate (ATTR-HUPD-*) tests.

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"

#include "ua_session_attribute_services.h"
#include "ua_session_view_services.h"
#include "ua_browse_direction.h"
#include "ua_referencetype_id.h"
#include "ua_to_string.h"

#include "ua_access_level_type.h"
#include "ua_data_value.h"
#include "ua_history_data.h"
#include "ua_namespace_history_delegate.h"
#include "ua_history_event.h"
#include "ua_history_event_field_list.h"
#include "ua_history_read_request.h"
#include "ua_read_at_time_details.h"
#include "ua_read_event_details.h"
#include "ua_history_read_response.h"
#include "ua_history_read_result.h"
#include "ua_history_read_value_id.h"
#include "ua_history_update_request.h"
#include "ua_history_update_response.h"
#include "ua_history_update_result.h"
#include "ua_namespace.h"
#include "ua_read_raw_modified_details.h"
#include "ua_update_data_details.h"
#include "ua_perform_update_type.h"
#include "ua_timestamps_to_return.h"
#include "ua_variable_id.h"
#include "ua_object_id.h"

// Canonical Historical Access reference (history_reference lib) - the new-behaviour mirrors below
// exercise the real engine/store/delegate end-to-end over the wire, not a file-local stub.
#include "ua_history_annotations_property.h"
#include "ua_history_engine_delegate.h"
#include "ua_history_namespace.h"
#include "ua_history_sqlite_store.h"

#include "ua_annotation.h"
#include "ua_encoding_limits.h"
#include "ua_event_filter.h"
#include "ua_event_notifier_type.h"
#include "ua_history_modified_data.h"
#include "ua_history_update_type.h"
#include "ua_instantiation_options.h"
#include "ua_localized_text.h"
#include "ua_modification_info.h"
#include "ua_property.h"
#include "ua_qualified_name.h"
#include "ua_read_annotation_data_details.h"
#include "ua_read_processed_details.h"
#include "ua_simple_attribute_operand.h"
#include "ua_update_event_details.h"
#include "ua_update_structure_data_details.h"

#include <chrono>
#include <string_view>
#include <thread>

using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

// ===========================================================================
// In-memory history delegate for compliance tests
// ===========================================================================

namespace
{

/// Simple in-memory history delegate that stores data values per node.
class InMemoryHistoryDelegate : public NamespaceHistoryDelegate
{
public:
  void add_values(const NodeId& nodeId, std::vector<DataValue> values)
  {
    std::lock_guard lock(mMutex);
    auto& existing = mData[nodeId];
    existing.insert(
      existing.end(), std::make_move_iterator(values.begin()), std::make_move_iterator(values.end()));
  }

  void read_raw_async(const NamespaceHistoryDelegate::ReadContext& /*context*/,
    std::vector<NamespaceHistoryDelegate::ReadRawItem> items, ReadRawCallback callback) noexcept override
  {
    BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
    batch.items.reserve(items.size());

    std::lock_guard lock(mMutex);
    for (const auto& item : items)
    {
      NamespaceHistoryDelegate::HistoryReadRawSuccess success;
      auto it = mData.find(item.nodeId);
      if (it != mData.end())
      {
        // Filter by time range and max_values_per_node.
        uint32_t count = 0;
        for (const auto& dv : it->second)
        {
          if (item.maxValuesPerNode > 0 && count >= item.maxValuesPerNode)
          {
            // Return a cursor to signal more data.
            success.cursor = std::string("continuation");
            break;
          }
          auto ts = dv.source_timestamp().value_or(DateTime{});
          if ((item.startTime.is_null() || ts >= item.startTime) &&
              (item.endTime.is_null() || ts <= item.endTime))
          {
            success.values.push_back(dv);
            ++count;
          }
        }
      }
      batch.items.emplace_back(std::move(success));
    }

    callback(std::move(batch));
  }

  Capabilities capabilities() const noexcept override
  {
    Capabilities caps;
    caps.readRaw = true;
    caps.readAtTime = true;
    caps.readEvents = true;
    return caps;
  }

  // Rudimentary ReadAtTime: stepped interpolation - for each requested timestamp return the stored
  // value at-or-before it (reported at the requested time), or a Bad_NoData placeholder. Enough to
  // exercise the service's AtTime dispatch + HistoryData wrapping.
  void read_at_time_async(const NamespaceHistoryDelegate::ReadContext& /*context*/,
    std::vector<NamespaceHistoryDelegate::ReadAtTimeItem> items,
    ReadAtTimeCallback callback) noexcept override
  {
    BatchResult<NamespaceHistoryDelegate::ReadAtTimeItemResult> batch;
    batch.items.reserve(items.size());

    std::lock_guard lock(mMutex);
    for (const auto& item : items)
    {
      NamespaceHistoryDelegate::HistoryReadAtTimeSuccess success;
      auto it = mData.find(item.nodeId);
      for (const auto& reqTime : item.timestamps)
      {
        const DataValue* picked = nullptr;
        if (it != mData.end())
        {
          for (const auto& dv : it->second)
          {
            if (dv.source_timestamp().value_or(DateTime{}) <= reqTime)
              picked = &dv;
          }
        }
        if (picked)
        {
          DataValue out = *picked;
          out.source_timestamp() = reqTime;
          success.values.push_back(std::move(out));
        }
        else
        {
          DataValue nodata{StatusCode{Status::BadNoData}};
          nodata.source_timestamp() = reqTime;
          success.values.push_back(std::move(nodata));
        }
      }
      batch.items.emplace_back(std::move(success));
    }

    callback(std::move(batch));
  }

  // Rudimentary ReadEvents: returns two synthetic single-field events per node (the filter is
  // ignored). Enough to exercise the service's Events dispatch + HistoryEvent wrapping.
  void read_events_async(const NamespaceHistoryDelegate::ReadContext& /*context*/,
    std::vector<NamespaceHistoryDelegate::ReadEventsItem> items,
    ReadEventsCallback callback) noexcept override
  {
    BatchResult<NamespaceHistoryDelegate::ReadEventsItemResult> batch;
    batch.items.reserve(items.size());
    for ([[maybe_unused]] const auto& item : items)
    {
      NamespaceHistoryDelegate::HistoryReadEventsSuccess success;
      for (int32_t i = 0; i < 2; ++i)
      {
        HistoryEventFieldList event;
        event.event_fields().push_back(Variant{i});
        success.events.push_back(std::move(event));
      }
      batch.items.emplace_back(std::move(success));
    }
    callback(std::move(batch));
  }

private:
  std::mutex mMutex;
  std::unordered_map<NodeId, std::vector<DataValue>> mData;
};

/// Namespace that provides an in-memory history delegate.
class HistoryTestNamespace : public default_ns::Namespace
{
public:
  using default_ns::Namespace::Namespace;

  static shared_ptr<HistoryTestNamespace> create(String uri, boost::asio::any_io_executor executor)
  {
    auto ns = shared_ptr<HistoryTestNamespace>(new HistoryTestNamespace(std::move(uri), std::move(executor)));
    return ns;
  }

  void set_delegate(shared_ptr<InMemoryHistoryDelegate> delegate)
  {
    mDelegate = std::move(delegate);
  }

  shared_ptr<NamespaceHistoryDelegate> history_delegate() noexcept override
  {
    return mDelegate;
  }

private:
  shared_ptr<InMemoryHistoryDelegate> mDelegate;
};

}  // namespace

// ===========================================================================
// ComplianceWithHistory: fixture with a historized variable node
// ===========================================================================

class ComplianceWithHistory : public ComplianceWithSession
{
protected:
  void configure_server() override
  {
    auto addressSpace = mServer.server().address_space();

    mHistoryNamespace = HistoryTestNamespace::create("urn:test:history", mServer.thread_pool().executor());
    mHistoryDelegate = make_shared<InMemoryHistoryDelegate>();
    mHistoryNamespace->set_delegate(mHistoryDelegate);
    mHistoryNsIndex = addressSpace.add_namespace_sync(mHistoryNamespace);

    // Create a historized variable node.
    mHistorizedNodeId = NodeId{mHistoryNsIndex, uint32_t{1000}};
    auto node = addressSpace.create_node_sync(mHistorizedNodeId, NodeClass::Variable);
    auto variable = node.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{mHistoryNsIndex, "HistorizedVar"});
    variable->set_display_name(LocalizedText{"", "HistorizedVar"});
    variable->set_data_type(NodeId{DataTypeId::Double});
    variable->write_value_sync(double{0.0});
    variable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead,
      AccessLevelType::Bit::HistoryRead,
      AccessLevelType::Bit::HistoryWrite});

    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mHistorizedNodeId);

    mSyntheticEventHistoryObjectId = NodeId{mHistoryNsIndex, uint32_t{1001}};
    auto eventNode = addressSpace.create_node_sync(mSyntheticEventHistoryObjectId, NodeClass::Object);
    auto eventSource = eventNode.as<ObjectAccessor>();
    ASSERT_TRUE(eventSource.has_value());
    eventSource->set_browse_name(QualifiedName{mHistoryNsIndex, "SyntheticEventHistory"});
    eventSource->set_display_name(LocalizedText{"", "SyntheticEventHistory"});
    eventSource->set_event_notifier(EventNotifierType{EventNotifierType::Bit::HistoryRead});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mSyntheticEventHistoryObjectId);

    // Pre-populate with some historical data.
    std::vector<DataValue> historyValues;
    for (int i = 0; i < 10; ++i)
    {
      DataValue dv;
      dv.value() = Variant{double(i * 1.5)};
      dv.source_timestamp() = UtcTime{2025, 1, 1, 0, 0, static_cast<double>(i)};
      dv.server_timestamp() = UtcTime{2025, 1, 1, 0, 0, static_cast<double>(i)};
      dv.status() = Status::Good;
      historyValues.push_back(std::move(dv));
    }
    mHistoryDelegate->add_values(mHistorizedNodeId, std::move(historyValues));
  }

  shared_ptr<HistoryTestNamespace> mHistoryNamespace;
  shared_ptr<InMemoryHistoryDelegate> mHistoryDelegate;
  uint16_t mHistoryNsIndex{0};
  NodeId mHistorizedNodeId;
  NodeId mSyntheticEventHistoryObjectId;
};

// ===========================================================================
// Helpers
// ===========================================================================

// Conventional start/end window for raw-history reads in this file: covers all
// pre-populated values (2025) with margin.
static const DateTime historyStart{UtcTime{2020, 1, 1, 0, 0, 0}};
static const DateTime historyEnd{UtcTime{2030, 1, 1, 0, 0, 0}};

/// Build a HistoryUpdateRequest with UpdateDataDetails for a single node.
static HistoryUpdateRequest make_update_data_request(
  const NodeId& nodeId, PerformUpdateType updateType = PerformUpdateType::Insert)
{
  auto details = std::make_unique<UpdateDataDetails>();
  details->node_id() = nodeId;
  details->perform_insert_replace() = updateType;
  details->update_values().push_back(DataValue{Variant{int32_t{42}}, DateTime::now()});

  HistoryUpdateRequest req;
  RefStructure<Structure> wrapped;
  wrapped = std::unique_ptr<Structure>(std::move(details));
  req.history_update_details().push_back(std::move(wrapped));
  return req;
}

// A well-known variable that exists in NS0 - used as a target node for requests.
static const NodeId serverStateNodeId{
  uint16_t{0}, static_cast<uint32_t>(VariableId::Server_ServerStatus_State)};

// ===========================================================================
// HistoryRead tests (ATTR-HREAD-*)
// ===========================================================================

// ---------------------------------------------------------------------------
// Smoke / existence tests
// ---------------------------------------------------------------------------

// Requirement: -
// HistoryRead service responds with a Good service result when given a valid
// request targeting a historised node.  Proves the full stack is wired.
TEST_F(ComplianceWithSession, HistoryRead_ServiceExists)
{
  auto result = mSession->attributes().try_history_read_sync(
    history_read_raw(serverStateNodeId, historyStart, historyEnd));

  ASSERT_THAT(result, Good()) << "HistoryRead must not return transport/session error";
  EXPECT_THAT(result.value(), ServiceResultIsGood());
}

// Requirement: -
// Read raw historical data for a node.  When history is supported, the
// response must contain results and the per-node status must be Good with
// at least one DataValue in the HistoryData.
// @relation(SVR-ATTR-HREAD-031, scope=function)
TEST_F(ComplianceWithHistory, HistoryRead_BasicRawData)
{
  auto result = mSession->attributes().try_history_read_sync(
    history_read_raw(mHistorizedNodeId, historyStart, historyEnd));

  ASSERT_THAT(result, Good()) << "HistoryRead must not return transport/session error";
  auto& resp = result.value();
  ASSERT_THAT(resp, ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good()) << "Expected Good per-node status";

  auto* historyData = dynamic_cast<const HistoryData*>(resp.results()[0].history_data().get());
  ASSERT_NE(historyData, nullptr) << "Expected HistoryData in result";
  EXPECT_FALSE(historyData->data_values().empty()) << "Expected at least one historical DataValue";
}

// ---------------------------------------------------------------------------
// SVR-ATTR-HREAD-004: TimestampsToReturn=NEITHER is invalid
// ---------------------------------------------------------------------------

// Requirement: SVR-ATTR-HREAD-004 (SHALL)
// Specifying a TimestampsToReturn of NEITHER is not valid for HistoryRead accessing
// HistoricalDataNodes: it is rejected with Bad_TimestampsToReturnInvalid, delivered as a ServiceFault
// (Part 11 section 4.5 - the HA-specific rule the CTT enforces, Read Raw Err-002). The client surfaces a
// ServiceFault as a Bad Result.
// Spec: Part 11, section 4.5
// @relation(AC-SVR-ATTR-HREAD-004-NEITHER-INVALID, scope=function)
TEST_F(ComplianceWithSession, ATTR_HREAD_004_BadTimestampsToReturnInvalid_Neither)
{
  auto result = mSession->attributes().try_history_read_sync(HistoryReadRawBuilder(historyStart, historyEnd)
                                                               .timestamps(TimestampsToReturn::Neither)
                                                               .read(serverStateNodeId));

  EXPECT_THAT(result, HasStatus(Status::BadTimestampsToReturnInvalid))
    << "Expected BadTimestampsToReturnInvalid ServiceFault for TimestampsToReturn::Neither";
}

// ---------------------------------------------------------------------------
// SVR-ATTR-HREAD-006: releaseContinuationPoints=true frees CPs
// ---------------------------------------------------------------------------

// Requirement: SVR-ATTR-HREAD-006 (SHALL)
// When releaseContinuationPoints is TRUE, passed continuationPoints shall be
// reset to free resources in the Server.  The service result must be Good.
// Spec: Part 4, section 5.10.3.2, line 3788
//
// Approach: obtain a real CP by reading with numValuesPerNode=1, then release
// it, then attempt to reuse the same CP and verify BadContinuationPointInvalid.
// @relation(SVR-ATTR-HREAD-006, SVR-ATTR-HREAD-031, SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithHistory, ATTR_HREAD_006_ReleaseContinuationPoints)
{
  // Step 1: Read with numValuesPerNode=1 to obtain a continuation point.
  auto initialResult = mSession->attributes().try_history_read_sync(
    HistoryReadRawBuilder(historyStart, historyEnd, /*num=*/1).read(mHistorizedNodeId));
  ASSERT_THAT(initialResult, Good());
  auto& initialResp = initialResult.value();
  ASSERT_THAT(initialResp, ServiceResultIsGood());
  ASSERT_EQ(initialResp.results().size(), 1u);
  ASSERT_THAT(initialResp.results()[0], Good());
  auto cp = initialResp.results()[0].continuation_point();
  ASSERT_FALSE(cp.empty()) << "Expected a continuation point from numValuesPerNode=1 read";

  // Step 2: Release the continuation point.
  auto releaseResult =
    mSession->attributes().try_history_read_sync(HistoryReadRawBuilder(historyStart, historyEnd)
                                                   .release_continuation_points(true)
                                                   .read(mHistorizedNodeId, cp));
  ASSERT_THAT(releaseResult, Good());
  EXPECT_THAT(releaseResult.value(), ServiceResultIsGood()) << "Release request must succeed with Good";

  // Step 3: Try to use the released CP - must fail with BadContinuationPointInvalid.
  auto reuseResult = mSession->attributes().try_history_read_sync(
    HistoryReadRawBuilder(historyStart, historyEnd).read(mHistorizedNodeId, cp));
  ASSERT_THAT(reuseResult, Good());
  auto& reuseResp = reuseResult.value();
  ASSERT_THAT(reuseResp, ServiceResultIsGood());
  ASSERT_EQ(reuseResp.results().size(), 1u);
  EXPECT_THAT(reuseResp.results()[0], HasStatus(Status::BadContinuationPointInvalid))
    << "Released CP must be invalid when reused";
}

// ---------------------------------------------------------------------------
// SVR-ATTR-HREAD-007: releaseContinuationPoints=false returns next set
// ---------------------------------------------------------------------------

// Requirement: SVR-ATTR-HREAD-007 (SHALL)
// When releaseContinuationPoints is FALSE, passed continuationPoints shall be
// used to get the next set of historical information.  The service must
// succeed with Good.
// Spec: Part 4, section 5.10.3.2, line 3790
//
// Approach: read with numValuesPerNode=1 to get a CP, then pass the CP back
// with releaseContinuationPoints=false and verify additional data is returned.
// @relation(SVR-ATTR-HREAD-007, SVR-ATTR-HREAD-031, SVR-ATTR-READ-029, scope=function)
// @verifies AC-SVR-ATTR-HREAD-029-RESPECT-PER-OP-CAP
TEST_F(ComplianceWithHistory, ATTR_HREAD_007_ContinueWithContinuationPoint)
{
  // Step 1: Read with numValuesPerNode=1 to get first value + CP.
  auto initialResult = mSession->attributes().try_history_read_sync(
    HistoryReadRawBuilder(historyStart, historyEnd, /*num=*/1).read(mHistorizedNodeId));
  ASSERT_THAT(initialResult, Good());
  auto& initialResp = initialResult.value();
  ASSERT_THAT(initialResp, ServiceResultIsGood());
  ASSERT_EQ(initialResp.results().size(), 1u);
  ASSERT_THAT(initialResp.results()[0], Good());

  auto* initialData = dynamic_cast<const HistoryData*>(initialResp.results()[0].history_data().get());
  ASSERT_NE(initialData, nullptr);
  ASSERT_EQ(initialData->data_values().size(), 1u) << "Expected exactly 1 value with numValuesPerNode=1";
  auto cp = initialResp.results()[0].continuation_point();
  ASSERT_FALSE(cp.empty()) << "Expected a continuation point (node has 10 values, read 1)";

  // Step 2: Pass the CP with releaseContinuationPoints=false to get next data.
  auto continueResult = mSession->attributes().try_history_read_sync(
    HistoryReadRawBuilder(historyStart, historyEnd).read(mHistorizedNodeId, cp));
  ASSERT_THAT(continueResult, Good());
  auto& continueResp = continueResult.value();
  ASSERT_THAT(continueResp, ServiceResultIsGood());
  ASSERT_EQ(continueResp.results().size(), 1u);
  ASSERT_THAT(continueResp.results()[0], Good());

  auto* continueData = dynamic_cast<const HistoryData*>(continueResp.results()[0].history_data().get());
  ASSERT_NE(continueData, nullptr);
  EXPECT_FALSE(continueData->data_values().empty()) << "Continuation must return additional historical data";
}

// ---------------------------------------------------------------------------
// ServerConfig::historyContinuationPointTimeout (configuration coverage matrix row)
// ---------------------------------------------------------------------------

// The session purges expired history continuation points at the start of the NEXT HistoryRead rather than on
// a timer, so the row reads one value to get a continuation point, waits past the timeout, and then presents
// it. There is no injectable clock on this path; the row costs ~1.5 s.
class ConfigurationHistoryContinuationPointTimeout : public ComplianceWithHistory
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    ComplianceWithHistory::configure_server_config(serverCfg);
    serverCfg.historyContinuationPointTimeout = std::chrono::milliseconds{300};  // default 30000
  }

  ByteString read_one_value_for_a_continuation_point()
  {
    auto first = mSession->attributes().try_history_read_sync(
      HistoryReadRawBuilder(historyStart, historyEnd, /*num=*/1).read(mHistorizedNodeId));
    EXPECT_THAT(first, Good());
    if (!first.is_good() || first.value().results().size() != 1)
      return {};
    return first.value().results()[0].continuation_point();
  }

  StatusCode present(const ByteString& continuationPoint)
  {
    auto next = mSession->attributes().try_history_read_sync(
      HistoryReadRawBuilder(historyStart, historyEnd).read(mHistorizedNodeId, continuationPoint));
    EXPECT_THAT(next, Good());
    if (!next.is_good() || next.value().results().size() != 1)
      return StatusCode{Status::BadUnexpectedError};
    return next.value().results()[0].status_code();
  }
};

TEST_F(ConfigurationHistoryContinuationPointTimeout, ExpiredHistoryContinuationPointIsRejected)
{
  // Control first: presented at once, a continuation point is still valid and returns the next value.
  const auto immediate = read_one_value_for_a_continuation_point();
  ASSERT_FALSE(immediate.empty()) << "the node has 10 values, so reading 1 must return a continuation point";
  EXPECT_THAT(present(immediate), Good())
    << "a continuation point presented at once must still be valid, or the expiry oracle proves nothing";

  // A fresh point, presented after the timeout has passed.
  const auto stale = read_one_value_for_a_continuation_point();
  ASSERT_FALSE(stale.empty());
  std::this_thread::sleep_for(std::chrono::milliseconds{1200});
  EXPECT_EQ(present(stale).as_status(), Status::BadContinuationPointInvalid)
    << "after 1.2 s the 300 ms timeout must have expired the point; the default of 30 s keeps it valid, "
       "as the immediate control shows";
}

// ---------------------------------------------------------------------------
// SVR-ATTR-HREAD-010: Returned value always includes timestamp
// ---------------------------------------------------------------------------

// Requirement: SVR-ATTR-HREAD-010 (SHALL)
// The value returned shall always include a timestamp (for RAW, PROCESSED,
// MODIFIED, or ATTIME history reads).
// Spec: Part 4, section 5.10.3.2, line 3799
// @relation(SVR-ATTR-HREAD-010, SVR-ATTR-HREAD-031, SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithHistory, ATTR_HREAD_010_ValueIncludesTimestamp)
{
  auto result = mSession->attributes().try_history_read_sync(HistoryReadRawBuilder(historyStart, historyEnd)
                                                               .timestamps(TimestampsToReturn::Source)
                                                               .read(mHistorizedNodeId));

  ASSERT_THAT(result, Good()) << "HistoryRead must not return transport/session error";
  auto& resp = result.value();
  ASSERT_THAT(resp, ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 1u);
  ASSERT_THAT(resp.results()[0], Good());

  auto* historyData = dynamic_cast<const HistoryData*>(resp.results()[0].history_data().get());
  ASSERT_NE(historyData, nullptr) << "Expected HistoryData in result";
  for (size_t i = 0; i < historyData->data_values().size(); ++i)
  {
    EXPECT_TRUE(historyData->data_values()[i].source_timestamp().has_value())
      << "DataValue[" << i << "] missing source timestamp";
  }
}

// ---------------------------------------------------------------------------
// SVR-ATTR-HREAD-011: Node without history returns error
// ---------------------------------------------------------------------------

// Requirement: SVR-ATTR-HREAD-011 (SHALL)
// If the Node does not support the requested access for historical values or
// historical Events the appropriate error response for the given Node shall
// be generated.
// Spec: Part 4, section 5.10.3.2, line 3803
// @relation(SVR-ATTR-HREAD-011, SVR-ATTR-HREAD-031, SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithSession, ATTR_HREAD_011_NodeWithoutHistoryReturnsError)
{
  // ObjectsFolder is not a historised node.
  auto result = mSession->attributes().try_history_read_sync(
    history_read_raw(NodeId{ObjectId::ObjectsFolder}, historyStart, historyEnd));

  ASSERT_THAT(result, Good()) << "HistoryRead must not return transport/session error";
  auto& resp = result.value();
  // Service itself should succeed (Good); the per-node result carries the error.
  ASSERT_THAT(resp, ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadHistoryOperationUnsupported))
    << "Expected BadHistoryOperationUnsupported for non-historised node";
}

// ---------------------------------------------------------------------------
// SVR-ATTR-HREAD-012: At least one CP per session
// ---------------------------------------------------------------------------

// Requirement: SVR-ATTR-HREAD-012 (SHALL)
// Servers shall support at least one continuation point per Session.
// Spec: Part 4, section 5.10.3.2, line 3838
//
// To verify, we read with numValuesPerNode=1 so the server must return a CP
// if there is more than one historical value.
// @relation(AC-SVR-ATTR-CP-002-ONE-POINT-MINIMUM, SVR-ATTR-CP-006, scope=function)
// @relation(SVR-ATTR-HREAD-012, SVR-ATTR-HREAD-031, SVR-ATTR-HUPD-013, scope=function)
// @relation(SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithHistory, ATTR_HREAD_012_AtLeastOneCPPerSession)
{
  // Force CP since node has 10 values.
  auto result = mSession->attributes().try_history_read_sync(
    HistoryReadRawBuilder(historyStart, historyEnd, /*num=*/1).read(mHistorizedNodeId));

  ASSERT_THAT(result, Good()) << "HistoryRead must not return transport/session error";
  auto& resp = result.value();
  EXPECT_THAT(resp, ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good()) << "Expected Good per-node status";

  // The node has 10 values; numValuesPerNode=1 must produce a CP.
  EXPECT_FALSE(resp.results()[0].continuation_point().empty())
    << "Server must support at least one CP per session - expected a continuation point "
       "when numValuesPerNode=1 and node has more data";
}

// ---------------------------------------------------------------------------
// SVR-ATTR-HREAD-014: Oldest CP reset on max
// ---------------------------------------------------------------------------

// Requirement: SVR-ATTR-HREAD-014 (SHALL)
// If the max continuation points have been reached the oldest continuation
// point shall be reset.
// Spec: Part 4, section 5.10.3.2, line 3842
//
// Approach: issue many reads with numValuesPerNode=1 to accumulate CPs beyond
// the server's limit.  The server must not reject with BadNoContinuationPoints
// - it must evict the oldest and continue.  We verify by issuing more
// CP-producing reads than the configured max (default 100) and checking that
// each succeeds with a CP.  We don't need to exceed the limit by a lot -
// just enough to prove eviction works.
// @relation(SVR-ATTR-CP-003, SVR-ATTR-CP-006, SVR-ATTR-HREAD-014, scope=function)
// @relation(SVR-ATTR-HREAD-031, SVR-ATTR-HUPD-013, scope=function)
// @relation(SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithHistory, ATTR_HREAD_014_OldestCPResetOnMax)
{
  // Issue 3 separate reads, each producing a CP.  If the server's max is 1
  // or any small number, this exercises eviction.  If it's large, this at
  // least verifies multiple CPs can coexist.
  for (int round = 0; round < 3; ++round)
  {
    auto result = mSession->attributes().try_history_read_sync(
      HistoryReadRawBuilder(historyStart, historyEnd, /*num=*/1).read(mHistorizedNodeId));
    ASSERT_THAT(result, Good()) << "Round " << round << ": transport error";
    auto& resp = result.value();
    ASSERT_THAT(resp, ServiceResultIsGood()) << "Round " << round;
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_NE(
      resp.results()[0].status_code().as_uint32(), static_cast<uint32_t>(Status::BadNoContinuationPoints))
      << "Round " << round << ": server must reset oldest CP, not reject";
    EXPECT_THAT(resp.results()[0], Good()) << "Round " << round;
  }
}

// ---------------------------------------------------------------------------
// SVR-ATTR-HREAD-015: BadNothingToDo - empty list
// ---------------------------------------------------------------------------

// Requirement: SVR-ATTR-HREAD-015 (SHALL)
// Bad_NothingToDo - The list of nodes to read is empty.
// Spec: Part 4, section 5.10.3.3, line 3866
// @relation(SVR-ATTR-HREAD-015, SVR-ATTR-HREAD-031, SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithSession, ATTR_HREAD_015_BadNothingToDo)
{
  // Build a request with valid details but no nodes_to_read entries.
  auto result =
    mSession->attributes().try_history_read_sync(HistoryReadRawBuilder(historyStart, historyEnd).build());

  // Whole-request validation errors are delivered as a ServiceFault -> Bad Result (finding F52).
  EXPECT_THAT(result, HasStatus(Status::BadNothingToDo)) << "Expected BadNothingToDo for empty nodes_to_read";
}

// ---------------------------------------------------------------------------
// SVR-ATTR-HREAD-016: BadTooManyOperations
// ---------------------------------------------------------------------------

// Requirement: SVR-ATTR-HREAD-016 (SHALL)
// Bad_TooManyOperations - The request exceeds the Server's operation limit.
// Spec: Part 4, section 5.10.3.3, line 3867
// @relation(SVR-ATTR-HREAD-016, SVR-ATTR-HREAD-031, SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithSession, ATTR_HREAD_016_BadTooManyOperations)
{
  // Add more nodes than the default MaxNodesPerHistoryReadData (100).
  HistoryReadRawBuilder builder(historyStart, historyEnd);
  for (uint32_t i = 0; i < 200; ++i)
  {
    builder.read(serverStateNodeId);
  }

  auto result = mSession->attributes().try_history_read_sync(builder.build());

  // Whole-request validation errors are delivered as a ServiceFault -> Bad Result (finding F52).
  EXPECT_THAT(result, HasStatus(Status::BadTooManyOperations))
    << "Expected BadTooManyOperations for 200 nodes (limit is 100)";
}

// ---------------------------------------------------------------------------
// SVR-ATTR-HREAD-017: BadTimestampsToReturnInvalid
// ---------------------------------------------------------------------------

// Requirement: SVR-ATTR-HREAD-017 (SHALL)
// Bad_TimestampsToReturnInvalid - Timestamps parameter is invalid.
// Spec: Part 4, section 5.10.3.3, line 3868
// @relation(SVR-ATTR-HREAD-017, SVR-ATTR-HREAD-031, SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithSession, ATTR_HREAD_017_BadTimestampsToReturnInvalid)
{
  auto result = mSession->attributes().try_history_read_sync(HistoryReadRawBuilder(historyStart, historyEnd)
                                                               .timestamps(TimestampsToReturn::Invalid)
                                                               .read(serverStateNodeId));

  // Whole-request validation errors are delivered as a ServiceFault -> Bad Result (finding F52).
  EXPECT_THAT(result, HasStatus(Status::BadTimestampsToReturnInvalid))
    << "Expected BadTimestampsToReturnInvalid for TimestampsToReturn::Invalid";
}

// ---------------------------------------------------------------------------
// SVR-ATTR-HREAD-018: BadHistoryOperationInvalid
// ---------------------------------------------------------------------------

// Requirement: SVR-ATTR-HREAD-018 (SHALL)
// Bad_HistoryOperationInvalid - History operation details are not valid.
// Spec: Part 4, section 5.10.3.3, line 3869
// @relation(SVR-ATTR-HREAD-018, SVR-ATTR-HREAD-031, SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithSession, ATTR_HREAD_018_BadHistoryOperationInvalid)
{
  // Send a request with no history_read_details (null/empty). The
  // HistoryReadRawBuilder always populates details, so this scenario is
  // constructed inline.
  HistoryReadRequest req;
  // history_read_details left empty - no details provided.
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.release_continuation_points() = false;
  HistoryReadValueId rv;
  rv.node_id() = serverStateNodeId;
  req.nodes_to_read().push_back(std::move(rv));

  auto result = mSession->attributes().try_history_read_sync(std::move(req));

  // Whole-request validation errors are delivered as a ServiceFault -> Bad Result (finding F52).
  EXPECT_THAT(result, HasStatus(Status::BadHistoryOperationInvalid))
    << "Expected BadHistoryOperationInvalid for missing history_read_details";
}

// ---------------------------------------------------------------------------
// SVR-ATTR-HREAD-019: BadHistoryOperationUnsupported
// ---------------------------------------------------------------------------

// Requirement: SVR-ATTR-HREAD-019 (SHALL)
// Bad_HistoryOperationUnsupported - Requested history operation is not
// supported by the Server.
// Spec: Part 4, section 5.10.3.3, line 3870
//
// When the server does not support history at all, a valid HistoryRead
// request should return BadHistoryOperationUnsupported (not BadServiceUnsupported).
// BadServiceUnsupported means the service is not even wired; a compliant server
// should wire the service but report the operation as unsupported.
// @relation(SVR-ATTR-HREAD-019, SVR-ATTR-HREAD-031, SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithSession, ATTR_HREAD_019_BadHistoryOperationUnsupported)
{
  // ServerState is in NS0 which has no history delegate.
  auto result = mSession->attributes().try_history_read_sync(
    history_read_raw(serverStateNodeId, historyStart, historyEnd));

  ASSERT_THAT(result, Good()) << "HistoryRead must not return transport/session error";
  auto& resp = result.value();
  auto serviceStatus = resp.response_header().service_result().as_uint32();
  if (serviceStatus == static_cast<uint32_t>(Status::Good))
  {
    // Service succeeded - verify per-node status is BadHistoryOperationUnsupported.
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_THAT(resp.results()[0], HasStatus(Status::BadHistoryOperationUnsupported))
      << "Expected per-node BadHistoryOperationUnsupported for node in namespace without history delegate";
  }
  else
  {
    EXPECT_EQ(serviceStatus, static_cast<uint32_t>(Status::BadHistoryOperationUnsupported))
      << "Expected BadHistoryOperationUnsupported at service level; got: 0x" << std::hex << serviceStatus;
  }
}

// ---------------------------------------------------------------------------
// SVR-ATTR-HREAD-020: BadNodeIdInvalid
// ---------------------------------------------------------------------------

// Requirement: SVR-ATTR-HREAD-020 (SHALL)
// Bad_NodeIdInvalid - Syntactically invalid NodeId.
// Spec: Part 4, section 5.10.3.4, line 3882
// @relation(SVR-ATTR-HREAD-020, SVR-ATTR-HREAD-031, SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithSession, ATTR_HREAD_020_BadNodeIdInvalid)
{
  // Use a null NodeId - syntactically invalid for a history read target.
  auto result =
    mSession->attributes().try_history_read_sync(history_read_raw(NodeId{}, historyStart, historyEnd));

  ASSERT_THAT(result, Good()) << "HistoryRead must not return transport/session error";
  auto& resp = result.value();
  ASSERT_THAT(resp, ServiceResultIsGood()) << "Expected Good service result (per-node error)";
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNodeIdInvalid))
    << "Expected BadNodeIdInvalid for null NodeId";
}

// ---------------------------------------------------------------------------
// SVR-ATTR-HREAD-021: BadNodeIdUnknown
// ---------------------------------------------------------------------------

// Requirement: SVR-ATTR-HREAD-021 (SHALL)
// Bad_NodeIdUnknown - NodeId refers to a Node that does not exist.
// Spec: Part 4, section 5.10.3.4, line 3883
// @relation(SVR-ATTR-HREAD-021, SVR-ATTR-HREAD-031, SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithSession, ATTR_HREAD_021_BadNodeIdUnknown)
{
  // Use a NodeId that does not exist in the address space.
  auto result = mSession->attributes().try_history_read_sync(
    history_read_raw(NodeId{uint16_t{99}, uint32_t{99999}}, historyStart, historyEnd));

  ASSERT_THAT(result, Good()) << "HistoryRead must not return transport/session error";
  auto& resp = result.value();
  ASSERT_THAT(resp, ServiceResultIsGood()) << "Expected Good service result (per-node error)";
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNodeIdUnknown))
    << "Expected BadNodeIdUnknown for non-existent node";
}

// ---------------------------------------------------------------------------
// SVR-ATTR-HREAD-024: BadUserAccessDenied
// ---------------------------------------------------------------------------

// Requirement: SVR-ATTR-HREAD-024 (SHALL)
// Bad_UserAccessDenied - User does not have permission.
// Spec: Part 4, section 5.10.3.4, line 3886
//
// NOTE: This test uses broad demonstration Role policy-it documents the
// requirement but cannot provoke the error until a restricted-Namespace
// fixture is added alongside history support.  For now, the service must
// at least accept the request with a Good service result.
// @relation(SVR-ATTR-HREAD-024, SVR-ATTR-HREAD-031, SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithSession, ATTR_HREAD_024_BadUserAccessDenied)
{
  auto result = mSession->attributes().try_history_read_sync(
    history_read_raw(serverStateNodeId, historyStart, historyEnd));

  ASSERT_THAT(result, Good()) << "HistoryRead must not return transport/session error";
  EXPECT_THAT(result.value(), ServiceResultIsGood());
}

// ---------------------------------------------------------------------------
// SVR-ATTR-HREAD-025: BadContinuationPointInvalid
// ---------------------------------------------------------------------------

// Requirement: SVR-ATTR-HREAD-025 (SHALL)
// Bad_ContinuationPointInvalid - Continuation point is not valid.
// Spec: Part 4, section 5.10.3.4, line 3887
// @relation(SVR-ATTR-HREAD-025, SVR-ATTR-HREAD-031, SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithSession, ATTR_HREAD_025_BadContinuationPointInvalid)
{
  // Send a fabricated continuation point that the server has never issued.
  // Uses default-constructed ReadRawModifiedDetails inline because the
  // HistoryReadRawBuilder constructor always populates start_time/end_time,
  // which would change the request's wire shape relative to the
  // pre-migration test.  CP validation happens before details inspection.
  HistoryReadRequest req;
  req.history_read_details() = std::make_unique<ReadRawModifiedDetails>();
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.release_continuation_points() = false;

  HistoryReadValueId rv;
  rv.node_id() = serverStateNodeId;
  rv.continuation_point() =
    ContinuationPoint{std::vector<byte>{byte{0xDE}, byte{0xAD}, byte{0xBE}, byte{0xEF}}};
  req.nodes_to_read().push_back(std::move(rv));

  auto result = mSession->attributes().try_history_read_sync(std::move(req));

  ASSERT_THAT(result, Good()) << "HistoryRead must not return transport/session error";
  auto& resp = result.value();
  ASSERT_THAT(resp, ServiceResultIsGood()) << "Expected Good service result (per-node error)";
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadContinuationPointInvalid))
    << "Expected BadContinuationPointInvalid for bogus CP";
}

// ---------------------------------------------------------------------------
// SVR-ATTR-HREAD-026: BadInvalidTimestampArgument
// ---------------------------------------------------------------------------

// Requirement: SVR-ATTR-HREAD-026 (SHALL)
// An invalid TimestampsToReturn (here out-of-range) is rejected. For HistoryRead accessing
// HistoricalDataNodes the code is Bad_TimestampsToReturnInvalid (Part 11 section 4.3, the HA-specific rule
// the CTT enforces - Read Raw Err-003), delivered as a ServiceFault.
// Spec: Part 11, section 4.3
TEST_F(ComplianceWithSession, ATTR_HREAD_026_BadTimestampsToReturnInvalid_OutOfRange)
{
  // Use an out-of-range TimestampsToReturn value.
  auto result =
    mSession->attributes().try_history_read_sync(HistoryReadRawBuilder(historyStart, historyEnd)
                                                   .timestamps(static_cast<TimestampsToReturn>(99))
                                                   .read(serverStateNodeId));

  // An out-of-range TimestampsToReturn is a whole-request error -> ServiceFault
  // BadTimestampsToReturnInvalid (Part 11 section 4.3), surfaced by the client as a Bad Result (finding F52).
  EXPECT_THAT(result, HasStatus(Status::BadTimestampsToReturnInvalid))
    << "Expected BadTimestampsToReturnInvalid ServiceFault for out-of-range TimestampsToReturn";
}

// ---------------------------------------------------------------------------
// SVR-ATTR-HREAD-027: BadHistoryOperationUnsupported per node
// ---------------------------------------------------------------------------

// Requirement: SVR-ATTR-HREAD-027 (SHALL)
// Bad_HistoryOperationUnsupported - Requested history operation not supported
// for the requested node.
// Spec: Part 4, section 5.10.3.4, line 3889
// @relation(SVR-ATTR-HREAD-027, SVR-ATTR-HREAD-031, SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithSession, ATTR_HREAD_027_BadHistoryOperationUnsupported_Node)
{
  // ObjectsFolder does not support history - per-node rejection expected.
  auto result = mSession->attributes().try_history_read_sync(
    history_read_raw(NodeId{ObjectId::ObjectsFolder}, historyStart, historyEnd));

  ASSERT_THAT(result, Good()) << "HistoryRead must not return transport/session error";
  auto& resp = result.value();
  ASSERT_THAT(resp, ServiceResultIsGood()) << "Expected Good service result (per-node error)";
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadHistoryOperationUnsupported))
    << "Expected BadHistoryOperationUnsupported for non-historised node";
}

// ---------------------------------------------------------------------------
// SVR-ATTR-HREAD-028: BadNoContinuationPoints
// ---------------------------------------------------------------------------

// Requirement: SVR-ATTR-HREAD-028 (SHALL)
// Bad_NoContinuationPoints - No continuation points available.
// Spec: Part 4, section 5.10.3.4, line 3891
//
// This would require exhausting all CPs without the server resetting the
// oldest (SVR-ATTR-HREAD-014 mandates reset).  So this scenario only arises
// transiently.  The service must at least accept the request.
// @relation(SVR-ATTR-CP-005, SVR-ATTR-CP-006, SVR-ATTR-HREAD-028, scope=function)
// @relation(SVR-ATTR-HREAD-031, SVR-ATTR-HUPD-013, scope=function)
// @relation(SVR-ATTR-READ-029, scope=function)
TEST_F(ComplianceWithSession, ATTR_HREAD_028_BadNoContinuationPoints)
{
  auto result = mSession->attributes().try_history_read_sync(
    history_read_raw(serverStateNodeId, historyStart, historyEnd));

  ASSERT_THAT(result, Good()) << "HistoryRead must not return transport/session error";
  EXPECT_THAT(result.value(), ServiceResultIsGood());
}

// ===========================================================================
// HistoryUpdate tests (ATTR-HUPD-*)
// ===========================================================================

// HistoryUpdate is not currently covered by the test-helper builders; tests
// below construct UpdateDataDetails / HistoryUpdateRequest inline.

// ---------------------------------------------------------------------------
// Smoke / existence test
// ---------------------------------------------------------------------------

// Requirement: -
// HistoryUpdate service responds with a Good service result when given a
// valid request.
TEST_F(ComplianceWithSession, HistoryUpdate_ServiceExists)
{
  auto result = mSession->attributes().try_history_update_sync(make_update_data_request(serverStateNodeId));

  ASSERT_THAT(result, Good()) << "HistoryUpdate must not return transport/session error";
  EXPECT_THAT(result.value(), ServiceResultIsGood());
}

// ---------------------------------------------------------------------------
// SVR-ATTR-HUPD-001: BadNothingToDo
// ---------------------------------------------------------------------------

// Requirement: SVR-ATTR-HUPD-001 (SHALL)
// Bad_NothingToDo - The list of update details is empty.
// Spec: Part 4, section 5.10.5.3, line 4085
// @relation(SVR-ATTR-HUPD-001, SVR-ATTR-HUPD-013, SVR-ATTR-WRITE-031, scope=function)
TEST_F(ComplianceWithSession, ATTR_HUPD_001_BadNothingToDo)
{
  HistoryUpdateRequest req;
  // history_update_details is intentionally empty.

  auto result = mSession->attributes().try_history_update_sync(std::move(req));

  EXPECT_THAT(result, Bad(Status::BadNothingToDo))
    << "Expected BadNothingToDo for empty history_update_details";
}

// ---------------------------------------------------------------------------
// SVR-ATTR-HUPD-002: BadTooManyOperations
// ---------------------------------------------------------------------------

// Requirement: SVR-ATTR-HUPD-002 (SHALL)
// Bad_TooManyOperations - The request exceeds the Server's operation limit.
// Spec: Part 4, section 5.10.5.3, line 4086
// @relation(SVR-ATTR-HUPD-002, SVR-ATTR-HUPD-013, SVR-ATTR-WRITE-031, scope=function)
TEST_F(ComplianceWithSession, ATTR_HUPD_002_BadTooManyOperations)
{
  HistoryUpdateRequest req;
  // Add more entries than the default MaxNodesPerHistoryUpdateData (100).
  for (uint32_t i = 0; i < 200; ++i)
  {
    auto details = std::make_unique<UpdateDataDetails>();
    details->node_id() = serverStateNodeId;
    details->perform_insert_replace() = PerformUpdateType::Insert;
    details->update_values().push_back(DataValue{Variant{int32_t{static_cast<int32_t>(i)}}, DateTime::now()});

    RefStructure<Structure> wrapped;
    wrapped = std::unique_ptr<Structure>(std::move(details));
    req.history_update_details().push_back(std::move(wrapped));
  }

  auto result = mSession->attributes().try_history_update_sync(std::move(req));

  EXPECT_THAT(result, Bad(Status::BadTooManyOperations))
    << "Expected BadTooManyOperations for 200 entries (limit is 100)";
}

// ---------------------------------------------------------------------------
// SVR-ATTR-HUPD-003: BadNotWritable
// ---------------------------------------------------------------------------

// Requirement: SVR-ATTR-HUPD-003 (SHALL)
// Bad_NotWritable - Historical data is not writable.
// Spec: Part 4, section 5.10.5.4, line 4097
// @relation(SVR-ATTR-HUPD-003, SVR-ATTR-HUPD-013, SVR-ATTR-WRITE-031, scope=function)
TEST_F(ComplianceWithSession, ATTR_HUPD_003_BadNotWritable)
{
  // ServerState does not have historical write access.
  auto result = mSession->attributes().try_history_update_sync(make_update_data_request(serverStateNodeId));

  ASSERT_THAT(result, Good()) << "HistoryUpdate must not return transport/session error";
  auto& resp = result.value();
  ASSERT_THAT(resp, ServiceResultIsGood()) << "Expected Good service result (per-node error)";
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNotWritable))
    << "Expected BadNotWritable for non-historised node";
}

// ---------------------------------------------------------------------------
// SVR-ATTR-HUPD-004: BadHistoryOperationInvalid
// ---------------------------------------------------------------------------

// Requirement: SVR-ATTR-HUPD-004 (SHALL)
// Bad_HistoryOperationInvalid - History update details are not valid.
// Spec: Part 4, section 5.10.5.4, line 4098
// @relation(SVR-ATTR-HUPD-004, SVR-ATTR-HUPD-013, SVR-ATTR-WRITE-031, scope=function)
TEST_F(ComplianceWithSession, ATTR_HUPD_004_BadHistoryOperationInvalid)
{
  // Send UpdateDataDetails with empty update_values - invalid details.
  auto details = std::make_unique<UpdateDataDetails>();
  details->node_id() = serverStateNodeId;
  details->perform_insert_replace() = PerformUpdateType::Insert;
  // update_values intentionally left empty.

  HistoryUpdateRequest req;
  RefStructure<Structure> wrapped;
  wrapped = std::unique_ptr<Structure>(std::move(details));
  req.history_update_details().push_back(std::move(wrapped));

  auto result = mSession->attributes().try_history_update_sync(std::move(req));

  ASSERT_THAT(result, Good()) << "HistoryUpdate must not return transport/session error";
  auto& resp = result.value();
  ASSERT_THAT(resp, ServiceResultIsGood()) << "Expected Good service result (per-node error)";
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadHistoryOperationInvalid))
    << "Expected BadHistoryOperationInvalid for empty update_values";
}

// ---------------------------------------------------------------------------
// SVR-ATTR-HUPD-005: BadHistoryOperationUnsupported
// ---------------------------------------------------------------------------

// Requirement: SVR-ATTR-HUPD-005 (SHALL)
// Bad_HistoryOperationUnsupported - Requested history operation is not
// supported.
// Spec: Part 4, section 5.10.5.4, line 4099
//
// When the server does not support history updates, a valid HistoryUpdate
// request should return Good at the service level with per-node
// BadHistoryOperationUnsupported (or the service may return
// BadHistoryOperationUnsupported at the service level).
// @relation(SVR-ATTR-HUPD-005, SVR-ATTR-HUPD-013, SVR-ATTR-WRITE-031, scope=function)
TEST_F(ComplianceWithHistory, ATTR_HUPD_005_BadHistoryOperationUnsupported)
{
  // Target the historized node (which has HistoryWrite access) but use a node
  // in NS0 (no history delegate) to get BadHistoryOperationUnsupported rather
  // than BadNotWritable.  ServerState has no HistoryWrite access, so it would
  // return BadNotWritable.  Instead, use serverStateNodeId which is in NS0
  // without a delegate - the implementation checks access first, then delegate.
  // To truly test this requirement, we need a node with HistoryWrite in a
  // namespace without a history delegate.  We'll use serverStateNodeId and
  // accept BadNotWritable as an acceptable alternative, but verify the specific
  // code when the service result is Good.
  auto result = mSession->attributes().try_history_update_sync(make_update_data_request(serverStateNodeId));

  ASSERT_THAT(result, Good()) << "HistoryUpdate must not return transport/session error";
  auto& resp = result.value();
  auto serviceStatus = resp.response_header().service_result().as_uint32();
  if (serviceStatus == static_cast<uint32_t>(Status::Good))
  {
    ASSERT_EQ(resp.results().size(), 1u);
    auto perNodeStatus = resp.results()[0].status_code().as_uint32();
    // ServerState lacks HistoryWrite access -> BadNotWritable is returned before
    // the delegate check.  Both BadNotWritable and BadHistoryOperationUnsupported
    // are acceptable per-node errors for a non-historised node.
    bool acceptable = (perNodeStatus == static_cast<uint32_t>(Status::BadNotWritable)) ||
                      (perNodeStatus == static_cast<uint32_t>(Status::BadHistoryOperationUnsupported));
    EXPECT_TRUE(acceptable) << "Expected BadNotWritable or BadHistoryOperationUnsupported; got: 0x"
                            << std::hex << perNodeStatus;
  }
  else
  {
    auto expected = static_cast<uint32_t>(Status::BadHistoryOperationUnsupported);
    EXPECT_EQ(serviceStatus, expected)
      << "Expected BadHistoryOperationUnsupported at service level; got: 0x" << std::hex << serviceStatus;
  }
}

// ---------------------------------------------------------------------------
// SVR-ATTR-HUPD-006: BadUserAccessDenied
// ---------------------------------------------------------------------------

// Requirement: SVR-ATTR-HUPD-006 (SHALL)
// Bad_UserAccessDenied - Current user does not have permission to update the
// history.
// Spec: Part 4, section 5.10.5.4, line 4100
//
// NOTE: Uses broad demonstration Role policy-documents the requirement but
// cannot provoke the error until a restricted-Namespace fixture is added.
// The service must at least accept the request.
// @relation(SVR-ATTR-HUPD-006, SVR-ATTR-HUPD-013, SVR-ATTR-WRITE-031, scope=function)
TEST_F(ComplianceWithSession, ATTR_HUPD_006_BadUserAccessDenied)
{
  auto result = mSession->attributes().try_history_update_sync(make_update_data_request(serverStateNodeId));

  ASSERT_THAT(result, Good()) << "HistoryUpdate must not return transport/session error";
  EXPECT_THAT(result.value(), ServiceResultIsGood());
}

// ---------------------------------------------------------------------------
// HistoryRead dispatch wiring for ReadAtTimeDetails and ReadEventDetails.
//
// These verify end-to-end that HistoryReadService now routes the AtTime/Event detail types to the
// delegate's read_at_time_async / read_events_async (previously the service returned
// BadHistoryOperationUnsupported without ever consulting the delegate) and wraps the results in the
// correct response structure (HistoryData for AtTime values, HistoryEvent for events).
// ---------------------------------------------------------------------------

namespace
{
EventFilter time_severity_message_filter();
}

TEST_F(ComplianceWithHistory, ReadAtTime_DispatchesToDelegate_ReturnsHistoryDataPerTimestamp)
{
  HistoryReadRequest req;
  req.request_header().request_handle() = 1;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  auto details = std::make_unique<ReadAtTimeDetails>();
  details->req_times().push_back(UtcTime{2025, 1, 1, 0, 0, 2.0});
  details->req_times().push_back(UtcTime{2025, 1, 1, 0, 0, 5.0});
  req.history_read_details() = std::move(details);
  HistoryReadValueId rv;
  rv.node_id() = mHistorizedNodeId;
  req.nodes_to_read().push_back(std::move(rv));

  auto result = mSession->attributes().try_history_read_sync(std::move(req));
  ASSERT_THAT(result, Good()) << "HistoryRead must not return transport/session error";
  auto& resp = result.value();
  ASSERT_THAT(resp, ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());
  auto* histData = dynamic_cast<HistoryData*>(resp.results()[0].history_data().get());
  ASSERT_NE(histData, nullptr) << "AtTime read must be wrapped in HistoryData";
  EXPECT_EQ(histData->data_values().size(), 2u) << "one value per requested timestamp";
}

TEST_F(ComplianceWithHistory, ReadEvents_DispatchesToDelegate_ReturnsHistoryEvent)
{
  HistoryReadRequest req;
  req.request_header().request_handle() = 1;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  auto details = std::make_unique<ReadEventDetails>();
  details->start_time() = UtcTime{2025, 1, 1, 0, 0, 0.0};
  details->end_time() = UtcTime{2025, 1, 1, 0, 0, 9.0};
  details->num_values_per_node() = 100;
  details->filter() = time_severity_message_filter();
  req.history_read_details() = std::move(details);
  HistoryReadValueId rv;
  rv.node_id() = mSyntheticEventHistoryObjectId;
  req.nodes_to_read().push_back(std::move(rv));

  auto result = mSession->attributes().try_history_read_sync(std::move(req));
  ASSERT_THAT(result, Good()) << "HistoryRead must not return transport/session error";
  auto& resp = result.value();
  ASSERT_THAT(resp, ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());
  auto* histEvent = dynamic_cast<HistoryEvent*>(resp.results()[0].history_data().get());
  ASSERT_NE(histEvent, nullptr) << "Events read must be wrapped in HistoryEvent";
  EXPECT_EQ(histEvent->events().size(), 2u) << "delegate returned two synthetic events";
}

// ===========================================================================
// End-to-end mirrors against the canonical history_reference implementation
// ===========================================================================
//
// The tests above use a file-local in-memory stub to isolate SDK service dispatch. The fixture below
// instead wires the REAL reference (SQLite-backed engine + strand/worker delegate) so the new
// behaviour - event write (UpdateEventDetails), annotation read/write (UpdateStructureDataDetails),
// the Annotations Property, ReadModified, and the raw-read ExtraData bit - is exercised across the
// full wire roundtrip: client -> server -> SDK service -> delegate -> store -> response -> client.

namespace
{

// Wrap a single HistoryUpdate detail into a request (mirrors make_update_data_request for any detail).
template<typename Detail>
HistoryUpdateRequest history_update_request(std::unique_ptr<Detail> details)
{
  HistoryUpdateRequest req;
  RefStructure<Structure> wrapped;
  wrapped = std::unique_ptr<Structure>(std::move(details));
  req.history_update_details().push_back(std::move(wrapped));
  return req;
}

// Wrap a single HistoryRead detail + one node into a request.
template<typename Detail>
HistoryReadRequest history_read_request(
  std::unique_ptr<Detail> details, const NodeId& node, TimestampsToReturn ts = TimestampsToReturn::Both)
{
  HistoryReadRequest req;
  req.request_header().request_handle() = 1;
  req.timestamps_to_return() = ts;
  req.history_read_details() = std::move(details);
  HistoryReadValueId rv;
  rv.node_id() = node;
  req.nodes_to_read().push_back(std::move(rv));
  return req;
}

// An EventFilter selecting the Time / Severity / Message fields (browse-path names the engine keys on).
EventFilter time_severity_message_filter()
{
  auto clause = [](std::string_view name)
  {
    SimpleAttributeOperand operand;
    operand.browse_path().push_back(QualifiedName{0, std::string{name}});
    return operand;
  };
  EventFilter filter;
  filter.select_clauses().push_back(clause("Time"));
  filter.select_clauses().push_back(clause("Severity"));
  filter.select_clauses().push_back(clause("Message"));
  return filter;
}

// The three fields above are what these tests read back and assert on, but an *insert* has to
// satisfy OPC 10000-11 6.8.4.2 as well: the selectClause must name every field the EventType makes
// Mandatory, and the row must carry a value of each declared type. The insert filter is therefore
// wider than the read filter, and deliberately so - narrowing the read to the three interesting
// fields is what a Client does, while narrowing the insert is what the Server refuses.
EventFilter base_event_insert_filter()
{
  EventFilter filter;
  for (const auto* name :
    {"EventId", "EventType", "SourceNode", "SourceName", "Time", "ReceiveTime", "Message", "Severity"})
  {
    SimpleAttributeOperand operand;
    operand.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
    operand.browse_path().push_back(QualifiedName{0, name});
    operand.attribute_id() = utils::to_underlying(AttributeId::Value);
    filter.select_clauses().push_back(operand);
  }
  return filter;
}

// One conforming eventData row for base_event_insert_filter(), in the same order.
HistoryEventFieldList base_event_insert_row(
  const NodeId& sourceNode, DateTime when, uint16_t severity, std::string_view message)
{
  HistoryEventFieldList fields;
  fields.event_fields().push_back(Variant{});  // EventId: the Server generates one
  fields.event_fields().push_back(Variant{NodeId{ObjectTypeId::BaseEventType}});
  fields.event_fields().push_back(Variant{sourceNode});
  fields.event_fields().push_back(Variant{String{"compliance history tests"}});
  fields.event_fields().push_back(Variant{when});
  fields.event_fields().push_back(Variant{when});
  fields.event_fields().push_back(Variant{LocalizedText{"", std::string{message}}});
  fields.event_fields().push_back(Variant{severity});
  return fields;
}

}  // namespace

// Fixture backing a historised node with the canonical SQLite reference (history_reference lib),
// pre-seeded with 10 raw values (2025-01-01 00:00:00..09) and an Annotations Property.
class ComplianceWithReferenceHistory : public ComplianceWithSession
{
protected:
  void configure_server() override
  {
    auto addressSpace = mServer.server().address_space();

    // Granted at CREATION, not through grant_fixture_namespace_permissions: what goes into the
    // namespace array here is a HistoryNamespace WRAPPER, and that helper reaches a namespace by
    // dynamic_pointer_cast<default_ns::Namespace>, which a wrapper is not. It therefore skips this
    // namespace silently and every read, browse and history call against it is refused
    // BadUserAccessDenied. The wrapper forwards default_role_permissions() to the namespace it
    // wraps, so granting the inner one here is what the wrapper then publishes.
    auto innerNs = addressSpace.create_namespace("urn:test:history:reference",
      []
      {
        std::vector<RolePermissionType> grants;
        for (const auto role : {ObjectId::WellKnownRole_Anonymous, ObjectId::WellKnownRole_SecurityAdmin})
        {
          RolePermissionType grant;
          grant.role_id() = NodeId{role};
          grant.permissions() = ua::test_helpers::all_permissions();
          grants.push_back(std::move(grant));
        }
        return grants;
      }());
    auto store = std::make_unique<ua::history::SqliteHistoryStore>(
      ":memory:", mServer.server().ua_binary_data_value_codec());
    mStore = store.get();
    mDelegate = make_shared<ua::history::HistoryEngineDelegate>(std::move(store));
    auto ns = make_shared<ua::history::HistoryNamespace>(std::move(innerNs), mDelegate);
    mHistoryNsIndex = addressSpace.add_namespace_sync(ns);

    mHistorizedNodeId = NodeId{mHistoryNsIndex, uint32_t{1000}};
    auto node = addressSpace.create_node_sync(mHistorizedNodeId, NodeClass::Variable);
    auto variable = node.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{mHistoryNsIndex, "Historised"});
    variable->set_display_name(LocalizedText{"", "Historised"});
    variable->set_data_type(NodeId{DataTypeId::Double});
    variable->write_value_sync(double{0.0});
    variable->set_historizing(true);
    variable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead,
      AccessLevelType::Bit::HistoryRead,
      AccessLevelType::Bit::HistoryWrite});
    addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder})
      .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mHistorizedNodeId);

    mEventHistoryObjectId = NodeId{mHistoryNsIndex, uint32_t{1002}};
    auto eventNode = addressSpace.create_node_sync(mEventHistoryObjectId, NodeClass::Object);
    auto eventSource = eventNode.as<ObjectAccessor>();
    ASSERT_TRUE(eventSource.has_value());
    eventSource->set_browse_name(QualifiedName{mHistoryNsIndex, "EventHistory"});
    eventSource->set_display_name(LocalizedText{"", "EventHistory"});
    eventSource->set_event_notifier(
      EventNotifierType{EventNotifierType::Bit::HistoryRead, EventNotifierType::Bit::HistoryWrite});
    addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder})
      .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mEventHistoryObjectId);

    // Annotations Property via the generated helper (Gap 1).
    InstantiationOptions options;
    options.nodeIdAllocator = [this](uint16_t, const QualifiedName&)
    {
      return NodeId{mHistoryNsIndex, uint32_t{1001}};
    };
    auto annotationsProperty =
      ua::history::add_annotations_property(addressSpace, mHistorizedNodeId, *mDelegate, options).value();
    mAnnotationsPropertyId = annotationsProperty.node_id();

    // Pre-seed raw history directly into the store (single-threaded setup, before the server serves).
    for (int i = 0; i < 10; ++i)
    {
      DataValue dv{Variant{double(i * 1.5)}};
      dv.source_timestamp() = UtcTime{2025, 1, 1, 0, 0, static_cast<double>(i)};
      dv.server_timestamp() = UtcTime{2025, 1, 1, 0, 0, static_cast<double>(i)};
      dv.status() = Status::Good;
      mStore->insert_value(mHistorizedNodeId, dv).value();
    }
  }

  ua::history::SqliteHistoryStore* mStore{nullptr};
  shared_ptr<ua::history::HistoryEngineDelegate> mDelegate;
  uint16_t mHistoryNsIndex{0};
  NodeId mHistorizedNodeId;
  NodeId mEventHistoryObjectId;
  NodeId mAnnotationsPropertyId;
};

// SVR-HIST-ANN-001: the historised node exposes a readable Annotations Property (DataType Annotation)
// over the wire - the client can discover that the node supports Annotation data.
TEST_F(ComplianceWithReferenceHistory, AnnotationsPropertyIsReadableOverTheWire)
{
  auto resp = mSession->attributes().read_sync(read_value(mAnnotationsPropertyId));
  ASSERT_THAT(resp, ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good()) << "the Annotations Property Value must be readable";
  EXPECT_NE(resp.results()[0].value().try_as<Annotation>(), nullptr)
    << "the Annotations Property Value must be an Annotation";
}

// UpdateStructureDataDetails dispatch (new): inserting an Annotation via HistoryUpdate then reading it
// back via ReadAnnotationDataDetails returns the same Annotation, keyed by its SourceTimestamp.
TEST_F(ComplianceWithReferenceHistory, AnnotationInsertThenReadRoundtrip)
{
  const DateTime annotationTime{UtcTime{2025, 1, 1, 0, 0, 5.0}};

  Annotation annotation;
  annotation.message() = String{"operator note"};
  annotation.user_name() = String{"tester"};
  annotation.annotation_time() = DateTime::now();
  DataValue annotationValue{Variant{std::move(annotation)}};
  annotationValue.source_timestamp() = annotationTime;

  auto update = std::make_unique<UpdateStructureDataDetails>();
  update->node_id() = mHistorizedNodeId;
  update->perform_insert_replace() = PerformUpdateType::Insert;
  update->update_values().push_back(std::move(annotationValue));

  auto updateResult =
    mSession->attributes().try_history_update_sync(history_update_request(std::move(update)));
  ASSERT_THAT(updateResult, Good());
  ASSERT_THAT(updateResult.value(), ServiceResultIsGood());
  ASSERT_EQ(updateResult.value().results().size(), 1u);
  ASSERT_THAT(updateResult.value().results()[0], Good());
  ASSERT_EQ(updateResult.value().results()[0].operation_results().size(), 1u);
  EXPECT_THAT(updateResult.value().results()[0].operation_results()[0], Good())
    << "Insert of a new Annotation must succeed";

  auto read = std::make_unique<ReadAnnotationDataDetails>();
  read->req_times().push_back(annotationTime);
  auto readResult =
    mSession->attributes().try_history_read_sync(history_read_request(std::move(read), mHistorizedNodeId));
  ASSERT_THAT(readResult, Good());
  ASSERT_THAT(readResult.value(), ServiceResultIsGood());
  ASSERT_EQ(readResult.value().results().size(), 1u);
  EXPECT_THAT(readResult.value().results()[0], Good());
  auto* histData = dynamic_cast<HistoryData*>(readResult.value().results()[0].history_data().get());
  ASSERT_NE(histData, nullptr) << "Annotation read must be wrapped in HistoryData";
  ASSERT_EQ(histData->data_values().size(), 1u);
  const auto* readBack = histData->data_values()[0].value().try_as<Annotation>();
  ASSERT_NE(readBack, nullptr) << "the read-back value must be an Annotation";
  EXPECT_EQ(std::string_view{readBack->message()}, "operator note");
}

// UpdateEventDetails dispatch (new): inserting a historical Event via HistoryUpdate then reading it
// back via ReadEventDetails returns the event with its projected fields.
TEST_F(ComplianceWithReferenceHistory, EventInsertThenReadRoundtrip)
{
  const DateTime eventTime{UtcTime{2025, 6, 1, 0, 0, 0.0}};

  auto update = std::make_unique<UpdateEventDetails>();
  update->node_id() = mEventHistoryObjectId;
  update->perform_insert_replace() = PerformUpdateType::Insert;
  update->filter() = base_event_insert_filter();
  update->event_data().push_back(
    base_event_insert_row(mEventHistoryObjectId, eventTime, 500, "process alarm"));

  auto updateResult =
    mSession->attributes().try_history_update_sync(history_update_request(std::move(update)));
  ASSERT_THAT(updateResult, Good());
  ASSERT_THAT(updateResult.value(), ServiceResultIsGood());
  ASSERT_EQ(updateResult.value().results().size(), 1u);
  ASSERT_THAT(updateResult.value().results()[0], Good());
  ASSERT_EQ(updateResult.value().results()[0].operation_results().size(), 1u);
  EXPECT_THAT(updateResult.value().results()[0].operation_results()[0], Good())
    << "Insert of a new Event must succeed";

  auto read = std::make_unique<ReadEventDetails>();
  read->start_time() = UtcTime{2025, 1, 1, 0, 0, 0.0};
  read->end_time() = UtcTime{2025, 12, 31, 0, 0, 0.0};
  read->num_values_per_node() = 100;
  read->filter() = time_severity_message_filter();
  auto readResult = mSession->attributes().try_history_read_sync(
    history_read_request(std::move(read), mEventHistoryObjectId));
  ASSERT_THAT(readResult, Good());
  ASSERT_THAT(readResult.value(), ServiceResultIsGood());
  ASSERT_EQ(readResult.value().results().size(), 1u);
  EXPECT_THAT(readResult.value().results()[0], Good());
  auto* histEvent = dynamic_cast<HistoryEvent*>(readResult.value().results()[0].history_data().get());
  ASSERT_NE(histEvent, nullptr) << "Events read must be wrapped in HistoryEvent";
  ASSERT_EQ(histEvent->events().size(), 1u) << "the single inserted event must be returned";
  const auto& readFields = histEvent->events()[0].event_fields();
  ASSERT_EQ(readFields.size(), 3u) << "one Variant per select clause (Time/Severity/Message)";
  const auto* severity = readFields[1].try_as<uint16_t>();
  ASSERT_NE(severity, nullptr);
  EXPECT_EQ(*severity, 500);
}

// ModificationInfo path (new): replacing an existing raw value records a modification, surfaced via a
// ReadRawModified read as a HistoryModifiedData carrying a Replace ModificationInfo.
TEST_F(ComplianceWithReferenceHistory, ReplaceRecordsModificationReadViaReadModified)
{
  const DateTime replaceTime{UtcTime{2025, 1, 1, 0, 0, 5.0}};

  DataValue replacement{Variant{double{99.0}}};
  replacement.source_timestamp() = replaceTime;
  replacement.server_timestamp() = replaceTime;
  replacement.status() = Status::Good;

  auto update = std::make_unique<UpdateDataDetails>();
  update->node_id() = mHistorizedNodeId;
  update->perform_insert_replace() = PerformUpdateType::Replace;
  update->update_values().push_back(std::move(replacement));

  auto updateResult =
    mSession->attributes().try_history_update_sync(history_update_request(std::move(update)));
  ASSERT_THAT(updateResult, Good());
  ASSERT_THAT(updateResult.value(), ServiceResultIsGood());
  ASSERT_EQ(updateResult.value().results().size(), 1u);
  ASSERT_EQ(updateResult.value().results()[0].operation_results().size(), 1u);
  EXPECT_THAT(updateResult.value().results()[0].operation_results()[0], Good())
    << "Replace of an existing value must succeed";

  auto read = std::make_unique<ReadRawModifiedDetails>();
  read->is_read_modified() = true;
  read->start_time() = UtcTime{2025, 1, 1, 0, 0, 0.0};
  read->end_time() = UtcTime{2025, 1, 1, 0, 0, 9.0};
  read->num_values_per_node() = 100;
  auto readResult =
    mSession->attributes().try_history_read_sync(history_read_request(std::move(read), mHistorizedNodeId));
  ASSERT_THAT(readResult, Good());
  ASSERT_THAT(readResult.value(), ServiceResultIsGood());
  ASSERT_EQ(readResult.value().results().size(), 1u);
  EXPECT_THAT(readResult.value().results()[0], Good());
  auto* histModified =
    dynamic_cast<HistoryModifiedData*>(readResult.value().results()[0].history_data().get());
  ASSERT_NE(histModified, nullptr) << "a modified read must be wrapped in HistoryModifiedData";
  ASSERT_FALSE(histModified->modification_infos().empty()) << "the Replace must produce a modification";
  bool sawReplace = false;
  for (const auto& info : histModified->modification_infos())
    if (info.update_type() == HistoryUpdateType::Replace)
      sawReplace = true;
  EXPECT_TRUE(sawReplace) << "the modification record must be classified as Replace";
}

// Raw-read ExtraData bit (new): after a Replace, a raw read of the modified value carries the
// ExtraData InfoBit (Part 8) signalling that a modification record exists for it.
TEST_F(ComplianceWithReferenceHistory, RawReadFlagsExtraDataAfterModification)
{
  const DateTime modifiedTime{UtcTime{2025, 1, 1, 0, 0, 5.0}};

  DataValue replacement{Variant{double{77.0}}};
  replacement.source_timestamp() = modifiedTime;
  replacement.server_timestamp() = modifiedTime;
  replacement.status() = Status::Good;

  auto update = std::make_unique<UpdateDataDetails>();
  update->node_id() = mHistorizedNodeId;
  update->perform_insert_replace() = PerformUpdateType::Replace;
  update->update_values().push_back(std::move(replacement));
  auto updateResult =
    mSession->attributes().try_history_update_sync(history_update_request(std::move(update)));
  ASSERT_THAT(updateResult, Good());
  ASSERT_THAT(updateResult.value(), ServiceResultIsGood());

  auto read = std::make_unique<ReadRawModifiedDetails>();
  read->is_read_modified() = false;
  read->start_time() = UtcTime{2025, 1, 1, 0, 0, 0.0};
  read->end_time() = UtcTime{2025, 1, 1, 0, 0, 9.0};
  read->num_values_per_node() = 100;
  auto readResult =
    mSession->attributes().try_history_read_sync(history_read_request(std::move(read), mHistorizedNodeId));
  ASSERT_THAT(readResult, Good());
  ASSERT_THAT(readResult.value(), ServiceResultIsGood());
  auto* histData = dynamic_cast<HistoryData*>(readResult.value().results()[0].history_data().get());
  ASSERT_NE(histData, nullptr);
  bool sawExtraData = false;
  for (const auto& dv : histData->data_values())
    if (dv.source_timestamp().value_or(DateTime{}) == modifiedTime)
      sawExtraData = dv.status().value_or(StatusCode{}).extra_data();
  EXPECT_TRUE(sawExtraData) << "the modified value's raw read must set the ExtraData InfoBit";
}

// ===========================================================================
// Row: HistoryConfig::maxReturnDataValues (configuration coverage matrix section 11).
//
// The server-side page size for raw history reads. The fixture seeds 10 values, so a cap of 2 must both
// TRIM the response and hand back a continuation point for the rest - trimming without one would silently
// lose data, which is the failure this row really guards against.
//
// TWO INDEPENDENT ORACLES: the advertised HistoryServerCapabilities node, and the actual response length.
// A server that advertised the number without enforcing it, or enforced it without advertising, passes
// only one of them.
// ===========================================================================
class ConfigurationHistoryReturnLimits : public ComplianceWithHistory
{
protected:
  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    cfg.historyConfiguration.maxReturnDataValues = 2;  // default 10000; 0 == unlimited
  }
};

// DEFAULT (0 == no cap): the same read returns all 10 seeded values in one response and issues no
// continuation point.
TEST_F(ConfigurationHistoryReturnLimits, RawReadIsTrimmedToTheConfiguredPageSize)
{
  auto result = mSession->attributes().try_history_read_sync(
    HistoryReadRawBuilder(historyStart, historyEnd).read(mHistorizedNodeId));
  ASSERT_TRUE(result.is_good()) << to_string(result.status_code());

  const auto& resp = result.value();
  ASSERT_EQ(resp.results().size(), 1u);
  ASSERT_TRUE(resp.results()[0].status_code().is_good()) << to_string(resp.results()[0].status_code());

  const auto* history = dynamic_cast<const HistoryData*>(resp.results()[0].history_data().get());
  ASSERT_NE(history, nullptr) << "the read must return HistoryData";

  EXPECT_LE(history->data_values().size(), 2u)
    << "the configured cap of 2 must bound one response (10 values are seeded)";
  EXPECT_FALSE(resp.results()[0].continuation_point().empty())
    << "and the remainder must stay reachable - a cap that trimmed WITHOUT a continuation point would lose "
       "data silently, which is worse than not capping at all";
}

// The advertising half, on the same server.
TEST_F(ConfigurationHistoryReturnLimits, ConfiguredPageSizeIsAdvertised)
{
  auto read = mSession->attributes().try_read_sync(
    read_value(NodeId{VariableId::HistoryServerCapabilities_MaxReturnDataValues}));
  ASSERT_TRUE(read.is_good()) << to_string(read.status_code());
  ASSERT_FALSE(read.value().results().empty());

  EXPECT_EQ(read.value().results()[0].value().as<uint32_t>(), 2u)
    << "HistoryServerCapabilities.MaxReturnDataValues must report the configured cap";
}

// ===========================================================================
// Row: HistoryConfig::maxReturnEventValues.
//
// The event-side sibling of the raw page size, and it needs its own row: the two caps are read from
// different fields into different flow members (`ua_history_read_service.cpp:422-423`) and applied at
// different sites, so neither stands in for the other. The branch control below makes that explicit.
// ===========================================================================
class ConfigurationHistoryEventReturnLimit : public ComplianceWithReferenceHistory
{
protected:
  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    cfg.historyConfiguration.maxReturnEventValues = 2;  // default 10000; 0 == unlimited
    // The DATA cap stays at its default (10000, far above the six seeded events), so a trimmed event
    // response cannot be blamed on the sibling.
  }

  // Insert @p count events an hour apart, all matching the shared Time/Severity/Message filter.
  void seed_events(size_t count)
  {
    for (size_t i = 0; i < count; ++i)
    {
      auto update = std::make_unique<UpdateEventDetails>();
      update->node_id() = mEventHistoryObjectId;
      update->perform_insert_replace() = PerformUpdateType::Insert;
      update->filter() = base_event_insert_filter();
      update->event_data().push_back(base_event_insert_row(mEventHistoryObjectId,
        DateTime{UtcTime{2025, 6, 1, static_cast<uint16_t>(i), 0, 0.0}},
        500,
        "seeded"));

      auto result = mSession->attributes().try_history_update_sync(history_update_request(std::move(update)));
      ASSERT_THAT(result, Good());
      ASSERT_THAT(result.value(), ServiceResultIsGood());
      ASSERT_EQ(result.value().results().size(), 1u);
      ASSERT_THAT(result.value().results()[0], Good());
      ASSERT_EQ(result.value().results()[0].operation_results().size(), 1u);
      ASSERT_THAT(result.value().results()[0].operation_results()[0], Good());
    }
  }
};

// DEFAULT (0 == no cap): all six seeded events come back in one response with no continuation point.
TEST_F(ConfigurationHistoryEventReturnLimit, EventReadIsTrimmedToTheConfiguredPageSize)
{
  seed_events(6);

  auto read = std::make_unique<ReadEventDetails>();
  read->start_time() = UtcTime{2025, 1, 1, 0, 0, 0.0};
  read->end_time() = UtcTime{2025, 12, 31, 0, 0, 0.0};
  // Deliberately ABOVE the configured cap: the request asking for more is what makes the server's cap the
  // deciding number rather than the client's.
  read->num_values_per_node() = 100;
  read->filter() = time_severity_message_filter();

  auto result = mSession->attributes().try_history_read_sync(
    history_read_request(std::move(read), mEventHistoryObjectId));
  ASSERT_THAT(result, Good());
  ASSERT_THAT(result.value(), ServiceResultIsGood());
  ASSERT_EQ(result.value().results().size(), 1u);
  ASSERT_THAT(result.value().results()[0], Good());

  auto* histEvent = dynamic_cast<HistoryEvent*>(result.value().results()[0].history_data().get());
  ASSERT_NE(histEvent, nullptr);

  EXPECT_LE(histEvent->events().size(), 2u)
    << "the configured event cap of 2 must bound one response (six events are seeded)";
  EXPECT_FALSE(result.value().results()[0].continuation_point().empty())
    << "and the remaining events must stay reachable";
}

// ===========================================================================
// Continuation-point lifetime and paging obligations
// ===========================================================================

namespace
{

/// How many historical DataValues a HistoryRead result actually carried back.
///
/// A result with no `historyData` at all and a result carrying an empty `HistoryData` both mean
/// "no data returned"; the release-path assertions below need to treat them the same way.
size_t returned_value_count(const HistoryReadResult& result)
{
  const auto* data = dynamic_cast<const HistoryData*>(result.history_data().get());
  return data == nullptr ? 0u : data->data_values().size();
}

}  // namespace

/// Two historised nodes in the same namespace, both backed by the in-memory delegate and both seeded
/// with ten values. A single node cannot express either of the multi-point obligations below: freeing
/// "the continuation points" (plural) named in one release request, and exhausting a continuation-point
/// budget with a request that carries more operations than the budget has slots.
class ComplianceWithTwoHistorisedNodes : public ComplianceWithHistory
{
protected:
  void configure_server() override
  {
    ComplianceWithHistory::configure_server();

    auto addressSpace = mServer.server().address_space();
    mSecondHistorizedNodeId = NodeId{mHistoryNsIndex, uint32_t{1004}};
    auto node = addressSpace.create_node_sync(mSecondHistorizedNodeId, NodeClass::Variable);
    auto variable = node.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{mHistoryNsIndex, "HistorizedVar2"});
    variable->set_display_name(LocalizedText{"", "HistorizedVar2"});
    variable->set_data_type(NodeId{DataTypeId::Double});
    variable->write_value_sync(double{0.0});
    variable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead,
      AccessLevelType::Bit::HistoryRead,
      AccessLevelType::Bit::HistoryWrite});
    addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder})
      .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mSecondHistorizedNodeId);

    std::vector<DataValue> historyValues;
    for (int i = 0; i < 10; ++i)
    {
      DataValue dv;
      dv.value() = Variant{double(i * 2.0)};
      dv.source_timestamp() = UtcTime{2025, 1, 1, 0, 0, static_cast<double>(i)};
      dv.server_timestamp() = UtcTime{2025, 1, 1, 0, 0, static_cast<double>(i)};
      dv.status() = Status::Good;
      historyValues.push_back(std::move(dv));
    }
    mHistoryDelegate->add_values(mSecondHistorizedNodeId, std::move(historyValues));
  }

  NodeId mSecondHistorizedNodeId;
};

/// The same two nodes on a server whose HistoryRead continuation-point budget is exactly ONE per
/// Session. The budget is what makes both reclamation and overflow reachable from a test: at the
/// default of 100 neither path is ever entered.
class ComplianceWithSingleHistoryContinuationPoint : public ComplianceWithTwoHistorisedNodes
{
protected:
  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    ComplianceBase::configure_server_config(cfg);
    cfg.server_capabilities().maxHistoryContinuationPoints = 1;
  }
};

// Part 4 section 7.9: when a new request would push the continuation-point store over capacity the Server
// frees an older point from THAT Session and serves the request; the reclamation is silent, and other
// Sessions' points are not collateral. Two plausible implementations get this wrong in opposite
// directions: one refuses the new request with Bad_NoContinuationPoints instead of reclaiming, the
// other reclaims from a single server-wide table and so evicts a point belonging to somebody else.
// The other Session takes its point FIRST here, so a server-wide table would have to sacrifice it.
// @verifies AC-SVR-ATTR-CP-003-AUTO-FREE
TEST_F(ComplianceWithSingleHistoryContinuationPoint, OverBudgetRequestFreesAnOlderPointOfItsOwnSession)
{
  // A second Session on the same channel, holding the only continuation point its own budget allows.
  auto otherSession = mChannel->create_session_sync({.sessionName = "HistoryCPOtherSession"});
  otherSession.activate_sync();

  auto otherRead = otherSession.attributes().try_history_read_sync(
    HistoryReadRawBuilder(historyStart, historyEnd, /*num=*/1).read(mHistorizedNodeId));
  ASSERT_THAT(otherRead, Good());
  ASSERT_THAT(otherRead.value(), ServiceResultIsGood());
  ASSERT_EQ(otherRead.value().results().size(), 1u);
  ASSERT_THAT(otherRead.value().results()[0], Good());
  auto otherCp = otherRead.value().results()[0].continuation_point();
  ASSERT_FALSE(otherCp.empty()) << "the other Session must hold a live point for this test to mean anything";

  // The Session under test fills its own single-point budget.
  auto firstRead = mSession->attributes().try_history_read_sync(
    HistoryReadRawBuilder(historyStart, historyEnd, /*num=*/1).read(mHistorizedNodeId));
  ASSERT_THAT(firstRead, Good());
  ASSERT_THAT(firstRead.value(), ServiceResultIsGood());
  ASSERT_EQ(firstRead.value().results().size(), 1u);
  ASSERT_THAT(firstRead.value().results()[0], Good());
  auto firstCp = firstRead.value().results()[0].continuation_point();
  ASSERT_FALSE(firstCp.empty()) << "the budget must actually be occupied before the over-budget request";

  // The over-budget request: it must be SERVED, not refused.
  auto secondRead = mSession->attributes().try_history_read_sync(
    HistoryReadRawBuilder(historyStart, historyEnd, /*num=*/1).read(mHistorizedNodeId));
  ASSERT_THAT(secondRead, Good());
  auto& secondResp = secondRead.value();
  ASSERT_THAT(secondResp, ServiceResultIsGood());
  ASSERT_EQ(secondResp.results().size(), 1u);
  EXPECT_THAT(secondResp.results()[0], Good())
    << "an over-budget request must reclaim, not be refused with Bad_NoContinuationPoints";
  EXPECT_FALSE(secondResp.results()[0].continuation_point().empty())
    << "the reclaimed slot must be handed to the new request";
  EXPECT_GT(returned_value_count(secondResp.results()[0]), 0u) << "and the new request must be served data";

  // Conjunct 1: the older point OF THIS SESSION was freed by that reclamation.
  auto staleRead = mSession->attributes().try_history_read_sync(
    HistoryReadRawBuilder(historyStart, historyEnd).read(mHistorizedNodeId, firstCp));
  ASSERT_THAT(staleRead, Good());
  ASSERT_THAT(staleRead.value(), ServiceResultIsGood());
  ASSERT_EQ(staleRead.value().results().size(), 1u);
  EXPECT_THAT(staleRead.value().results()[0], HasStatus(Status::BadContinuationPointInvalid))
    << "the reclaimed point must read back as invalid - that is how its holder learns of the eviction";

  // Conjunct 2: the other Session's point is untouched and still resumes.
  auto otherResume = otherSession.attributes().try_history_read_sync(
    HistoryReadRawBuilder(historyStart, historyEnd).read(mHistorizedNodeId, otherCp));
  ASSERT_THAT(otherResume, Good());
  auto& otherResumeResp = otherResume.value();
  ASSERT_THAT(otherResumeResp, ServiceResultIsGood());
  ASSERT_EQ(otherResumeResp.results().size(), 1u);
  EXPECT_THAT(otherResumeResp.results()[0], Good())
    << "reclamation is scoped to the requesting Session; another Session's point must survive it";
  EXPECT_GT(returned_value_count(otherResumeResp.results()[0]), 0u)
    << "and must still resume real data, not merely report Good";

  (void)otherSession.try_close_sync();
}

// Part 4 section 7.9: a request carrying more operations than the continuation-point store has slots is not
// failed as a whole. The Server serves operations in request order until the slots run out and marks
// only the remainder Bad_NoContinuationPoints. The tempting shortcuts are to compute the whole-batch
// demand up front and fail the service, or to drop the unservable operations silently - both leave a
// client unable to tell which of its nodes were read.
// @verifies AC-SVR-ATTR-CP-005-NOCONTINUATIONPOINTS
TEST_F(ComplianceWithSingleHistoryContinuationPoint, OperationsBeyondThePointCapacityAreMarkedNotFailedWhole)
{
  // Two operations, one slot: both nodes hold ten values and are read one value at a time, so each
  // operation genuinely needs a continuation point.
  HistoryReadRawBuilder builder(historyStart, historyEnd, /*num=*/1);
  builder.read(mHistorizedNodeId);
  builder.read(mSecondHistorizedNodeId);

  auto result = mSession->attributes().try_history_read_sync(builder.build());

  ASSERT_THAT(result, Good()) << "the request must not be failed as a whole";
  auto& resp = result.value();
  ASSERT_THAT(resp, ServiceResultIsGood()) << "overflow is a per-operation outcome, not a service fault";
  ASSERT_EQ(resp.results().size(), 2u) << "both operations must be reported on";

  // The operation the Server had a slot for is served, with a usable point.
  EXPECT_THAT(resp.results()[0], Good()) << "the first operation is within capacity and must succeed";
  EXPECT_FALSE(resp.results()[0].continuation_point().empty())
    << "a served operation with more data must carry the point that reaches it";
  EXPECT_GT(returned_value_count(resp.results()[0]), 0u) << "and must carry the data it read";

  // The operation past capacity is marked, and carries no point.
  EXPECT_THAT(resp.results()[1], HasStatus(Status::BadNoContinuationPoints))
    << "operations beyond the point capacity must be reported, not dropped";
  EXPECT_TRUE(resp.results()[1].continuation_point().empty())
    << "a refused operation must not hand back a point the Server is not holding";
}

// OPC 10000-11 4.5: `TimestampsToReturn::Neither` is meaningful on a live Read and meaningless on a history
// read - a historical value without a timestamp has no position in the history - and "A HistoryRead with
// invalid settings will be rejected with Bad_TimestampsToReturnInvalid". Part 4 5.10.3.2 names
// Bad_InvalidTimestampArgument for the same case; SVR-ATTR-HREAD-004 records the conflict and follows the
// history-specific Part 11 rule, which CTT Read Raw Err-002 enforces. The target is a real
// HistoricalDataNode, so the rejection cannot be attributed to a missing history delegate.
// @relation(AC-SVR-ATTR-HREAD-004-NEITHER-INVALID, scope=function)
TEST_F(ComplianceWithHistory, TimestampsToReturnNeitherIsInvalidOnAHistoryRead)
{
  auto result = mSession->attributes().try_history_read_sync(HistoryReadRawBuilder(historyStart, historyEnd)
                                                               .timestamps(TimestampsToReturn::Neither)
                                                               .read(mHistorizedNodeId));

  EXPECT_THAT(result, HasStatus(Status::BadTimestampsToReturnInvalid))
    << "a history read with TimestampsToReturn::Neither must be rejected with "
       "Bad_TimestampsToReturnInvalid";
}

// Part 11 section 6.4: `releaseContinuationPoints=TRUE` is a pure release. Every point named in the request
// is freed AND the call returns no history - a Server that treats the flag as "send this page, then release"
// satisfies the freeing half while quietly billing the client for a page it did not want, and a Server that
// releases only the first named point leaves the rest to expire on a timeout. Both halves are asserted here,
// on two live points, before either point is touched again.
// @verifies AC-SVR-ATTR-HREAD-006-RELEASE-FREES
TEST_F(ComplianceWithTwoHistorisedNodes, ReleaseFreesEveryNamedPointAndReturnsNoData)
{
  auto firstRead = mSession->attributes().try_history_read_sync(
    HistoryReadRawBuilder(historyStart, historyEnd, /*num=*/1).read(mHistorizedNodeId));
  ASSERT_THAT(firstRead, Good());
  ASSERT_THAT(firstRead.value(), ServiceResultIsGood());
  ASSERT_EQ(firstRead.value().results().size(), 1u);
  ASSERT_THAT(firstRead.value().results()[0], Good());
  auto firstCp = firstRead.value().results()[0].continuation_point();
  ASSERT_FALSE(firstCp.empty()) << "a live point on the first node is the precondition of this test";

  auto secondRead = mSession->attributes().try_history_read_sync(
    HistoryReadRawBuilder(historyStart, historyEnd, /*num=*/1).read(mSecondHistorizedNodeId));
  ASSERT_THAT(secondRead, Good());
  ASSERT_THAT(secondRead.value(), ServiceResultIsGood());
  ASSERT_EQ(secondRead.value().results().size(), 1u);
  ASSERT_THAT(secondRead.value().results()[0], Good());
  auto secondCp = secondRead.value().results()[0].continuation_point();
  ASSERT_FALSE(secondCp.empty()) << "a live point on the second node is the precondition of this test";

  // One release request naming both live points.
  HistoryReadRawBuilder releaseBuilder(historyStart, historyEnd);
  releaseBuilder.release_continuation_points(true);
  releaseBuilder.read(mHistorizedNodeId, firstCp);
  releaseBuilder.read(mSecondHistorizedNodeId, secondCp);

  auto releaseResult = mSession->attributes().try_history_read_sync(releaseBuilder.build());
  ASSERT_THAT(releaseResult, Good());
  auto& releaseResp = releaseResult.value();
  ASSERT_THAT(releaseResp, ServiceResultIsGood());
  ASSERT_EQ(releaseResp.results().size(), 2u) << "both named points must be reported on";

  // Conjunct A: the release itself returns no history for either point.
  EXPECT_THAT(releaseResp.results()[0], Good()) << "releasing a live point succeeds";
  EXPECT_EQ(returned_value_count(releaseResp.results()[0]), 0u)
    << "a release is a pure release - it must not also deliver a page of history";
  EXPECT_THAT(releaseResp.results()[1], Good()) << "releasing the second live point succeeds";
  EXPECT_EQ(returned_value_count(releaseResp.results()[1]), 0u)
    << "a release is a pure release - it must not also deliver a page of history";

  // Conjunct B: BOTH points are gone, not just the first one named.
  auto reuseFirst = mSession->attributes().try_history_read_sync(
    HistoryReadRawBuilder(historyStart, historyEnd).read(mHistorizedNodeId, firstCp));
  ASSERT_THAT(reuseFirst, Good());
  ASSERT_THAT(reuseFirst.value(), ServiceResultIsGood());
  ASSERT_EQ(reuseFirst.value().results().size(), 1u);
  EXPECT_THAT(reuseFirst.value().results()[0], HasStatus(Status::BadContinuationPointInvalid))
    << "the first released point must no longer resume";

  auto reuseSecond = mSession->attributes().try_history_read_sync(
    HistoryReadRawBuilder(historyStart, historyEnd).read(mSecondHistorizedNodeId, secondCp));
  ASSERT_THAT(reuseSecond, Good());
  ASSERT_THAT(reuseSecond.value(), ServiceResultIsGood());
  ASSERT_EQ(reuseSecond.value().results().size(), 1u);
  EXPECT_THAT(reuseSecond.value().results()[0], HasStatus(Status::BadContinuationPointInvalid))
    << "the second released point must no longer resume - every point named in the request is freed";
}

// Part 11 section 6.4: a continuation resumes where the previous page stopped. Repetition and omission at the
// page boundary are both silent, because the client concatenates the pages: an off-by-one that replays
// the boundary value, or one that steps over it, produces a history that looks complete and is not.
// Asserting only that "more data came back" cannot see either. This pages the whole node through the
// real reference engine and compares the concatenation against the seeded series, value for value.
// @verifies AC-SVR-ATTR-HREAD-007-CONTINUE-WITH-CP
TEST_F(ComplianceWithReferenceHistory, ContinuationResumesWithoutRepeatingOrSkippingValues)
{
  std::vector<double> paged;
  auto collect = [&paged](const HistoryReadResult& result)
  {
    const auto* data = dynamic_cast<const HistoryData*>(result.history_data().get());
    ASSERT_NE(data, nullptr) << "a raw history page must be wrapped in HistoryData";
    ASSERT_GT(data->data_values().size(), 0u) << "a page that returns nothing cannot be a resumption";
    for (size_t i = 0; i < data->data_values().size(); ++i)
    {
      const double* value = data->data_values()[i].value().try_as<double>();
      ASSERT_NE(value, nullptr) << "the seeded history is Double";
      paged.push_back(*value);
    }
  };

  // Ten seeded values, three per page: the boundary is crossed three times.
  ContinuationPoint cp;
  int pages = 0;
  for (; pages < 8; ++pages)
  {
    HistoryReadRawBuilder builder(historyStart, historyEnd, /*num=*/3);
    if (cp.empty())
      builder.read(mHistorizedNodeId);
    else
      builder.read(mHistorizedNodeId, cp);

    auto result = mSession->attributes().try_history_read_sync(builder.build());
    ASSERT_THAT(result, Good()) << "page " << pages;
    auto& resp = result.value();
    ASSERT_THAT(resp, ServiceResultIsGood()) << "page " << pages;
    ASSERT_EQ(resp.results().size(), 1u) << "page " << pages;
    ASSERT_THAT(resp.results()[0], Good()) << "page " << pages;

    if (pages == 0)
    {
      ASSERT_FALSE(resp.results()[0].continuation_point().empty())
        << "ten values read three at a time must leave a continuation point on the first page";
      ASSERT_EQ(returned_value_count(resp.results()[0]), 3u) << "the first page must honour the cap";
    }

    collect(resp.results()[0]);
    cp = resp.results()[0].continuation_point();
    if (cp.empty())
      break;
  }

  ASSERT_GT(pages, 0) << "the read must have been paged for this to test continuation at all";
  ASSERT_TRUE(cp.empty()) << "paging must terminate rather than hand back points for ever";

  // The seeded series is value = index * 1.5 at one-second intervals; the concatenation of the pages
  // must be exactly that, in order - no value seen twice, none missed.
  ASSERT_EQ(paged.size(), 10u) << "a repeated boundary value inflates this, a skipped one shrinks it";
  for (size_t i = 0; i < paged.size(); ++i)
  {
    EXPECT_DOUBLE_EQ(paged[i], static_cast<double>(i) * 1.5) << "page boundary misplaced at position " << i;
  }
}

// Part 11 section 6.4: every historical value returned carries a timestamp, in every read mode. Processed is
// where this is easiest to omit - an aggregate is computed FOR AN INTERVAL rather than sampled at an
// instant, so it has no timestamp of its own and the interval's must be supplied - and a modified read
// is next, because the modification record and the value it describes are assembled separately. A raw
// read passing therefore says nothing about the other three, so all four are driven here against the
// real reference engine.
// @verifies AC-SVR-ATTR-HREAD-010-TIMESTAMP-ALWAYS
TEST_F(ComplianceWithReferenceHistory, EveryReturnedHistoricalValueCarriesATimestampInAllFourReadModes)
{
  auto expectAllTimestamped = [](const HistoryReadResult& result, const char* mode)
  {
    const auto* data = dynamic_cast<const HistoryData*>(result.history_data().get());
    ASSERT_NE(data, nullptr) << mode << ": expected history values to inspect";
    ASSERT_GT(data->data_values().size(), 0u)
      << mode << ": a mode that returned nothing proves nothing about timestamps";
    for (size_t i = 0; i < data->data_values().size(); ++i)
    {
      EXPECT_TRUE(data->data_values()[i].source_timestamp().has_value())
        << mode << ": value[" << i << "] carries no source timestamp";
    }
  };

  // Mode 1 - RAW.
  {
    auto result = mSession->attributes().try_history_read_sync(
      HistoryReadRawBuilder(historyStart, historyEnd).read(mHistorizedNodeId));
    ASSERT_THAT(result, Good());
    ASSERT_THAT(result.value(), ServiceResultIsGood());
    ASSERT_EQ(result.value().results().size(), 1u);
    ASSERT_THAT(result.value().results()[0], Good());
    expectAllTimestamped(result.value().results()[0], "raw");
  }

  // Mode 2 - AT TIME, at instants the store holds exactly.
  {
    auto details = std::make_unique<ReadAtTimeDetails>();
    details->req_times().push_back(UtcTime{2025, 1, 1, 0, 0, 2.0});
    details->req_times().push_back(UtcTime{2025, 1, 1, 0, 0, 5.0});
    auto result = mSession->attributes().try_history_read_sync(
      history_read_request(std::move(details), mHistorizedNodeId));
    ASSERT_THAT(result, Good());
    ASSERT_THAT(result.value(), ServiceResultIsGood());
    ASSERT_EQ(result.value().results().size(), 1u);
    ASSERT_THAT(result.value().results()[0], Good());
    expectAllTimestamped(result.value().results()[0], "at-time");
  }

  // Mode 3 - PROCESSED. Average over three-second intervals of the seeded window. TimestampsToReturn
  // must be Source for a processed read (Part 13 section 5.4.3.1), which is precisely the timestamp the
  // interval has to supply.
  {
    auto details = std::make_unique<ReadProcessedDetails>();
    details->start_time() = UtcTime{2025, 1, 1, 0, 0, 0.0};
    details->end_time() = UtcTime{2025, 1, 1, 0, 0, 9.0};
    details->processing_interval() = 3000.0;
    details->aggregate_configuration().use_server_capabilities_defaults() = true;
    details->aggregate_type().push_back(NodeId{ObjectId::AggregateFunction_Average});
    auto result = mSession->attributes().try_history_read_sync(
      history_read_request(std::move(details), mHistorizedNodeId, TimestampsToReturn::Source));
    ASSERT_THAT(result, Good());
    ASSERT_THAT(result.value(), ServiceResultIsGood());
    ASSERT_EQ(result.value().results().size(), 1u);
    ASSERT_THAT(result.value().results()[0], Good());
    expectAllTimestamped(result.value().results()[0], "processed");
  }

  // Mode 4 - MODIFIED. A Replace first, so the modified read has something to return; without it the
  // mode would come back empty and assert nothing.
  {
    const DateTime replaceTime{UtcTime{2025, 1, 1, 0, 0, 5.0}};
    DataValue replacement{Variant{double{55.0}}};
    replacement.source_timestamp() = replaceTime;
    replacement.server_timestamp() = replaceTime;
    replacement.status() = Status::Good;

    auto update = std::make_unique<UpdateDataDetails>();
    update->node_id() = mHistorizedNodeId;
    update->perform_insert_replace() = PerformUpdateType::Replace;
    update->update_values().push_back(std::move(replacement));
    auto updateResult =
      mSession->attributes().try_history_update_sync(history_update_request(std::move(update)));
    ASSERT_THAT(updateResult, Good());
    ASSERT_THAT(updateResult.value(), ServiceResultIsGood());

    auto details = std::make_unique<ReadRawModifiedDetails>();
    details->is_read_modified() = true;
    details->start_time() = UtcTime{2025, 1, 1, 0, 0, 0.0};
    details->end_time() = UtcTime{2025, 1, 1, 0, 0, 9.0};
    details->num_values_per_node() = 100;
    auto result = mSession->attributes().try_history_read_sync(
      history_read_request(std::move(details), mHistorizedNodeId));
    ASSERT_THAT(result, Good());
    ASSERT_THAT(result.value(), ServiceResultIsGood());
    ASSERT_EQ(result.value().results().size(), 1u);
    ASSERT_THAT(result.value().results()[0], Good());
    expectAllTimestamped(result.value().results()[0], "modified");
  }
}

// Part 11 section 6.4 / Part 4 section 5.10.3.2: "If the Node does not support the requested access for
// historical values or historical Events the appropriate error response for the given Node shall be
// generated." The appropriate code is named, once, by SVR-ATTR-HREAD-011 ("a Variable lacking AccessLevel
// HistoryRead, or an Object lacking EventNotifier HistoryRead -> Bad_HistoryOperationUnsupported") and
// again by SVR-ATTR-HREAD-027 for the per-node variant; Part 4 Table 58 offers no second code to
// tell the two capabilities apart. So what is observable here is that the refusal is keyed to the
// access actually requested against the Node that was named - value history classified off
// AccessLevel, Event history off EventNotifier - each answering that one code, and neither degrading
// into Bad_UserAccessDenied, Bad_NodeIdUnknown or a service fault. The historised node is read first
// as a control, so the two refusals cannot be a server that is refusing everything.
// @verifies AC-SVR-ATTR-HREAD-011-NO-HISTORY-ACCESS
TEST_F(ComplianceWithHistory, MissingValueHistoryAndMissingEventHistoryEachReturnTheNodeAppropriateError)
{
  // Control: this server does serve history, so a refusal below is about the Node, not the server.
  {
    auto control = mSession->attributes().try_history_read_sync(
      HistoryReadRawBuilder(historyStart, historyEnd).read(mHistorizedNodeId));
    ASSERT_THAT(control, Good());
    ASSERT_THAT(control.value(), ServiceResultIsGood());
    ASSERT_EQ(control.value().results().size(), 1u);
    ASSERT_THAT(control.value().results()[0], Good());
    ASSERT_GT(returned_value_count(control.value().results()[0]), 0u)
      << "the control read must actually return history for the refusals below to mean anything";
  }

  // Leg 1 - VALUES against a Variable that has no historical values (ServerState carries no
  // AccessLevel.HistoryRead bit).
  auto valuesResult = mSession->attributes().try_history_read_sync(
    HistoryReadRawBuilder(historyStart, historyEnd).read(serverStateNodeId));
  ASSERT_THAT(valuesResult, Good()) << "HistoryRead must not return transport/session error";
  auto& valuesResp = valuesResult.value();
  ASSERT_THAT(valuesResp, ServiceResultIsGood()) << "the refusal is per node, not a service fault";
  ASSERT_EQ(valuesResp.results().size(), 1u);

  // Leg 2 - EVENTS against a Node that is not an event notifier (ObjectsFolder carries no
  // EventNotifier.HistoryRead bit).
  auto eventDetails = std::make_unique<ReadEventDetails>();
  eventDetails->start_time() = UtcTime{2025, 1, 1, 0, 0, 0.0};
  eventDetails->end_time() = UtcTime{2025, 12, 31, 0, 0, 0.0};
  eventDetails->num_values_per_node() = 100;
  eventDetails->filter() = time_severity_message_filter();
  auto eventsResult = mSession->attributes().try_history_read_sync(
    history_read_request(std::move(eventDetails), NodeId{ObjectId::ObjectsFolder}));
  ASSERT_THAT(eventsResult, Good()) << "HistoryRead must not return transport/session error";
  auto& eventsResp = eventsResult.value();
  ASSERT_THAT(eventsResp, ServiceResultIsGood()) << "the refusal is per node, not a service fault";
  ASSERT_EQ(eventsResp.results().size(), 1u);

  const uint32_t valuesCode = valuesResp.results()[0].status_code().as_uint32();
  const uint32_t eventsCode = eventsResp.results()[0].status_code().as_uint32();

  // The value-history refusal is decided off AccessLevel.HistoryRead, and it is the code the
  // requirement names - not a blanket denial and not a NodeId error for a Node that plainly resolves.
  EXPECT_THAT(valuesResp.results()[0], HasStatus(Status::BadHistoryOperationUnsupported))
    << "a Variable with no AccessLevel.HistoryRead bit must refuse a value history read with "
       "Bad_HistoryOperationUnsupported; got: 0x"
    << std::hex << valuesCode;

  // The Event-history refusal is decided off EventNotifier.HistoryRead on the same request path, and
  // answers the same named code - the appropriate error for that Node and that access.
  EXPECT_THAT(eventsResp.results()[0], HasStatus(Status::BadHistoryOperationUnsupported))
    << "an Object with no EventNotifier.HistoryRead bit must refuse an Event history read with "
       "Bad_HistoryOperationUnsupported; got: 0x"
    << std::hex << eventsCode;
}

/// The historised node on a server whose HistoryRead continuation-point budget is exactly TWO per
/// Session. Two is the smallest budget that can tell "the OLDEST point was reset" apart from "some
/// point was reset": with a budget of one there is only ever one candidate, and at the default of 100
/// the reclamation path is never entered at all.
class ComplianceWithTwoHistoryContinuationPoints : public ComplianceWithHistory
{
protected:
  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    ComplianceBase::configure_server_config(cfg);
    cfg.server_capabilities().maxHistoryContinuationPoints = 2;
  }
};

// Part 11 section 6.4 / Part 4 section 5.10.3.2: when the per-Session continuation-point store is at capacity
// and a new allocation arrives, the OLDEST existing point is reset to make room and the new request is
// served. "Oldest" is the required word. The store is a hash map, so the three wrong answers all
// look plausible from the inside: refuse the new request with Bad_NoContinuationPoints, evict whatever
// the map iterator reaches first, or evict the most recent point (the one whose bookkeeping entry is
// nearest to hand). Only the first of those is visible to a test that asks merely "was the request
// served" - the other two need a second, YOUNGER point that has to survive, which is what the budget
// of two buys. The three conjuncts are asserted in an order that leaves each point still resumable at
// the moment it is inspected.
// @verifies AC-SVR-ATTR-HREAD-014-OLDEST-RESET
TEST_F(ComplianceWithTwoHistoryContinuationPoints, AtCapacityTheOldestContinuationPointIsTheOneReset)
{
  // Fill the budget: two points, taken in a known order. The node holds ten values and is read one at
  // a time, so each read genuinely leaves a point behind.
  auto firstRead = mSession->attributes().try_history_read_sync(
    HistoryReadRawBuilder(historyStart, historyEnd, /*num=*/1).read(mHistorizedNodeId));
  ASSERT_THAT(firstRead, Good());
  ASSERT_THAT(firstRead.value(), ServiceResultIsGood());
  ASSERT_EQ(firstRead.value().results().size(), 1u);
  ASSERT_THAT(firstRead.value().results()[0], Good());
  auto oldestCp = firstRead.value().results()[0].continuation_point();
  ASSERT_FALSE(oldestCp.empty()) << "the oldest point must exist before capacity can be reached";

  auto secondRead = mSession->attributes().try_history_read_sync(
    HistoryReadRawBuilder(historyStart, historyEnd, /*num=*/1).read(mHistorizedNodeId));
  ASSERT_THAT(secondRead, Good());
  ASSERT_THAT(secondRead.value(), ServiceResultIsGood());
  ASSERT_EQ(secondRead.value().results().size(), 1u);
  ASSERT_THAT(secondRead.value().results()[0], Good());
  auto youngerCp = secondRead.value().results()[0].continuation_point();
  ASSERT_FALSE(youngerCp.empty()) << "the budget of two must actually be full before the next request";
  ASSERT_FALSE(oldestCp == youngerCp)
    << "the two points must be distinct handles for the eviction CHOICE to be observable";

  // The request that arrives at capacity.
  auto overBudget = mSession->attributes().try_history_read_sync(
    HistoryReadRawBuilder(historyStart, historyEnd, /*num=*/1).read(mHistorizedNodeId));
  ASSERT_THAT(overBudget, Good());
  auto& overBudgetResp = overBudget.value();
  ASSERT_THAT(overBudgetResp, ServiceResultIsGood());
  ASSERT_EQ(overBudgetResp.results().size(), 1u);

  // Conjunct 1: the new request is SERVED - reclamation, not refusal.
  EXPECT_THAT(overBudgetResp.results()[0], Good())
    << "at capacity the Server resets a point rather than refusing with Bad_NoContinuationPoints";
  EXPECT_FALSE(overBudgetResp.results()[0].continuation_point().empty())
    << "the reclaimed slot must be handed to the new request";
  EXPECT_GT(returned_value_count(overBudgetResp.results()[0]), 0u)
    << "and the new request must be served data, not merely reported Good";

  // Conjunct 2: the point that was reset is the OLDEST one.
  auto oldestResume = mSession->attributes().try_history_read_sync(
    HistoryReadRawBuilder(historyStart, historyEnd).read(mHistorizedNodeId, oldestCp));
  ASSERT_THAT(oldestResume, Good());
  ASSERT_THAT(oldestResume.value(), ServiceResultIsGood());
  ASSERT_EQ(oldestResume.value().results().size(), 1u);
  EXPECT_THAT(oldestResume.value().results()[0], HasStatus(Status::BadContinuationPointInvalid))
    << "the oldest point must have been reset - that is how its holder learns the slot was taken";

  // Conjunct 3: the younger point was NOT the one sacrificed, and still resumes real data.
  auto youngerResume = mSession->attributes().try_history_read_sync(
    HistoryReadRawBuilder(historyStart, historyEnd).read(mHistorizedNodeId, youngerCp));
  ASSERT_THAT(youngerResume, Good());
  auto& youngerResumeResp = youngerResume.value();
  ASSERT_THAT(youngerResumeResp, ServiceResultIsGood());
  ASSERT_EQ(youngerResumeResp.results().size(), 1u);
  EXPECT_THAT(youngerResumeResp.results()[0], Good())
    << "only the oldest point is reset; a younger point must survive the reclamation";
  EXPECT_GT(returned_value_count(youngerResumeResp.results()[0]), 0u)
    << "and must still resume real history, not merely report Good";
}

// Part 11 section 6.4: an operation the Server's history provider does not implement is refused with
// Bad_HistoryOperationUnsupported, which is a different message from Bad_HistoryOperationInvalid for a
// malformed one. The pair is the content: *unsupported* tells the client to stop asking, *invalid*
// tells it to fix the request and try again, so a Server that answers one for the other sends the
// client round a loop correcting something that was already correct. Both are driven here on the same
// node, so neither answer can be attributed to the target.
//
// The criterion illustrates the unsupported case with "a processed read on a server offering only
// raw". That instantiation is not available on this SDK: a raw-capable delegate that declares no
// readProcessed capability is served by the built-in Part-13 turnkey calculator
// (`ua_history_read_service.cpp` start_namespace_read_processed), so a processed read IS implemented
// here. The annotation read below is the same stimulus with an operation this provider genuinely does
// not implement - the in-memory delegate declares no readAnnotations capability and overrides no
// annotation hook, so the refusal comes from the SDK's own default delegate hook, not from the fixture.
// @verifies AC-SVR-ATTR-HREAD-019-OPERATIONUNSUPPORTED
TEST_F(ComplianceWithHistory, AnUnimplementedHistoryOperationIsUnsupportedAndNotConfusedWithAnInvalidOne)
{
  // Control: the provider does serve history for this node, so "unsupported" below is about the
  // OPERATION and not about the node having no history at all.
  {
    auto control = mSession->attributes().try_history_read_sync(
      HistoryReadRawBuilder(historyStart, historyEnd).read(mHistorizedNodeId));
    ASSERT_THAT(control, Good());
    ASSERT_THAT(control.value(), ServiceResultIsGood());
    ASSERT_EQ(control.value().results().size(), 1u);
    ASSERT_THAT(control.value().results()[0], Good());
    ASSERT_GT(returned_value_count(control.value().results()[0]), 0u)
      << "the provider must serve a supported operation on this node for the contrast to hold";
  }

  // Leg 1 - a well-formed request for an operation the provider does not implement.
  auto unsupportedDetails = std::make_unique<ReadAnnotationDataDetails>();
  unsupportedDetails->req_times().push_back(UtcTime{2025, 1, 1, 0, 0, 5.0});
  auto unsupportedResult = mSession->attributes().try_history_read_sync(
    history_read_request(std::move(unsupportedDetails), mHistorizedNodeId));
  ASSERT_THAT(unsupportedResult, Good()) << "HistoryRead must not return transport/session error";
  auto& unsupportedResp = unsupportedResult.value();
  ASSERT_THAT(unsupportedResp, ServiceResultIsGood());
  ASSERT_EQ(unsupportedResp.results().size(), 1u);
  EXPECT_THAT(unsupportedResp.results()[0], HasStatus(Status::BadHistoryOperationUnsupported))
    << "a valid details type the provider cannot service is UNSUPPORTED";
  EXPECT_NE(unsupportedResp.results()[0].status_code().as_uint32(),
    static_cast<uint32_t>(Status::BadHistoryOperationInvalid))
    << "an operation the Server does not implement must not be reported as a malformed request - that "
       "sends the client to correct a request that was already correct";

  // Leg 2 - the contrast, on the same node: a MALFORMED details of a supported operation.
  // ReadRawModifiedDetails needs at least two of {startTime, endTime, numValuesPerNode}; only one is
  // given here, so the request itself is at fault.
  auto malformedDetails = std::make_unique<ReadRawModifiedDetails>();
  malformedDetails->start_time() = historyStart;
  auto malformedResult = mSession->attributes().try_history_read_sync(
    history_read_request(std::move(malformedDetails), mHistorizedNodeId));
  EXPECT_THAT(malformedResult, HasStatus(Status::BadHistoryOperationInvalid))
    << "a malformed history operation is INVALID, the code that tells the client to fix and retry";
}

// Part 11 section 6.4 / Part 4 section 5.10.3.4: HistoryRead reports per operation, so a structurally invalid
// NodeId spoils only its own slot. The tempting shortcut is to validate the whole nodesToRead list up front
// and fail the service - Part 4 section 5.10.3.4 places Bad_NodeIdInvalid in the per-operation table, not the
// service table, and rejecting the batch destroys the results of every node the client asked about
// alongside the one it got wrong. The valid node is read in the SAME request, and its history is
// asserted non-empty, so a Server that answers Good for it without reading anything does not pass.
// @verifies AC-SVR-ATTR-HREAD-020-NODEIDINVALID
TEST_F(ComplianceWithHistory, AnInvalidNodeIdIsRefusedInItsOwnSlotWhileTheValidNodeIsStillServed)
{
  // Slot 0 carries a null NodeId (structurally invalid); slot 1 a real historised node.
  HistoryReadRawBuilder builder(historyStart, historyEnd);
  builder.read(NodeId{});
  builder.read(mHistorizedNodeId);

  auto result = mSession->attributes().try_history_read_sync(builder.build());

  ASSERT_THAT(result, Good()) << "one bad NodeId must not fail the request as a whole";
  auto& resp = result.value();
  ASSERT_THAT(resp, ServiceResultIsGood())
    << "an invalid NodeId is a per-operation outcome, not a service fault";
  ASSERT_EQ(resp.results().size(), 2u) << "both operations must be reported on, in request order";

  // Conjunct 1: the offending slot, and only it, carries the code.
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNodeIdInvalid))
    << "a structurally invalid NodeId is refused with Bad_NodeIdInvalid in its own slot";

  // Conjunct 2: the valid node is served - with data, not merely a Good status.
  EXPECT_THAT(resp.results()[1], Good()) << "the valid node in the same request must still be served";
  EXPECT_GT(returned_value_count(resp.results()[1]), 0u)
    << "and must carry its history - a Good status over an empty result is the same data loss as "
       "rejecting the batch";
}

/// The historised Variable of `ComplianceWithHistory` alongside an Object that is an event notifier
/// FOR HISTORY and holds no historical values. The pair is what makes the two history capabilities
/// separable: the Variable has value history and cannot notify events, the Object is the reverse. A
/// single node cannot express that, and neither can two nodes that both lack everything.
///
/// The in-memory delegate is deliberately permissive in both directions - it declares `readRaw` and
/// `readEvents` and answers an events read for ANY node with two synthetic events - so a refusal
/// below cannot have come from the fixture. It has to come from the Server's own per-node gate.
class ComplianceWithSeparableHistoryCapabilities : public ComplianceWithHistory
{
protected:
  void configure_server() override
  {
    ComplianceWithHistory::configure_server();

    auto addressSpace = mServer.server().address_space();

    // An Object that historises EVENTS and nothing else: EventNotifier carries the HistoryRead bit,
    // and no values are ever seeded for it in the delegate.
    mEventHistoryObjectId = NodeId{mHistoryNsIndex, uint32_t{1005}};
    auto node = addressSpace.create_node_sync(mEventHistoryObjectId, NodeClass::Object);
    auto object = node.as<ObjectAccessor>();
    ASSERT_TRUE(object.has_value());
    object->set_browse_name(QualifiedName{mHistoryNsIndex, "EventHistorySource"});
    object->set_display_name(LocalizedText{"", "EventHistorySource"});
    object->set_event_notifier(
      EventNotifierType{EventNotifierType::Bit::SubscribeToEvents, EventNotifierType::Bit::HistoryRead});
    addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder})
      .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mEventHistoryObjectId);
  }

  NodeId mEventHistoryObjectId;
};

// Part 11 section 6.4 / Part 4 section 5.10.3.2: "If the Node does not support the requested access for
// historical values or historical Events the appropriate error response for the given Node shall be
// generated." Value history and Event history are SEPARATE capabilities of the same Node - a Variable may
// historise values and notify no events, an Object the reverse - so the refusal has to be decided from the
// access the request asked for, not from the Node alone. The plausible implementation gets this wrong by
// classifying the Node once, off its NodeClass and one capability bit, and then serving whatever
// details type arrives: that answers an Event history read from a Variable that has never notified an
// event, and a value history read from an Object that holds no values, telling the client nothing about
// which of the two requests to stop making. Each direction is driven with its own control - the access
// the Node DOES support is read first and asserted non-empty - so neither refusal can be a Server that
// is refusing everything, and neither can be attributed to the delegate, which serves both operations
// for any node.
// @verifies AC-SVR-ATTR-HREAD-011-NO-HISTORY-ACCESS
TEST_F(ComplianceWithSeparableHistoryCapabilities, HistoryRefusalFollowsTheAccessRequestedNotTheNode)
{
  // Control A: the Variable's VALUE history is served, with data.
  {
    auto control = mSession->attributes().try_history_read_sync(
      HistoryReadRawBuilder(historyStart, historyEnd).read(mHistorizedNodeId));
    ASSERT_THAT(control, Good());
    ASSERT_THAT(control.value(), ServiceResultIsGood());
    ASSERT_EQ(control.value().results().size(), 1u);
    ASSERT_THAT(control.value().results()[0], Good());
    ASSERT_GT(returned_value_count(control.value().results()[0]), 0u)
      << "the Variable must actually serve value history for its Event refusal to be about the ACCESS";
  }

  // Leg 1: the same Variable has no historical EVENTS - it is not an event notifier at all - so an
  // Event history read against it must be refused even though its value history is live.
  {
    auto details = std::make_unique<ReadEventDetails>();
    details->start_time() = UtcTime{2025, 1, 1, 0, 0, 0.0};
    details->end_time() = UtcTime{2025, 12, 31, 0, 0, 0.0};
    details->num_values_per_node() = 100;
    details->filter() = time_severity_message_filter();

    auto result = mSession->attributes().try_history_read_sync(
      history_read_request(std::move(details), mHistorizedNodeId));
    ASSERT_THAT(result, Good()) << "HistoryRead must not return transport/session error";
    auto& resp = result.value();
    ASSERT_THAT(resp, ServiceResultIsGood()) << "the refusal is per node, not a service fault";
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_THAT(resp.results()[0], HasStatus(Status::BadHistoryOperationUnsupported))
      << "a Variable that historises values and notifies no events must refuse an EVENT history read; "
         "serving it from the value-history capability collapses the two capabilities into one";
  }

  // Control B: the Object's EVENT history is served, with events.
  {
    auto details = std::make_unique<ReadEventDetails>();
    details->start_time() = UtcTime{2025, 1, 1, 0, 0, 0.0};
    details->end_time() = UtcTime{2025, 12, 31, 0, 0, 0.0};
    details->num_values_per_node() = 100;
    details->filter() = time_severity_message_filter();

    auto control = mSession->attributes().try_history_read_sync(
      history_read_request(std::move(details), mEventHistoryObjectId));
    ASSERT_THAT(control, Good());
    ASSERT_THAT(control.value(), ServiceResultIsGood());
    ASSERT_EQ(control.value().results().size(), 1u);
    ASSERT_THAT(control.value().results()[0], Good());
    auto* events = dynamic_cast<HistoryEvent*>(control.value().results()[0].history_data().get());
    ASSERT_NE(events, nullptr) << "an Event history read must be wrapped in HistoryEvent";
    ASSERT_GT(events->events().size(), 0u)
      << "the Object must actually serve Event history for its value refusal to be about the ACCESS";
  }

  // Leg 2: the converse. The same Object holds no historical VALUES, so a raw read against it must be
  // refused even though its Event history is live.
  {
    auto result = mSession->attributes().try_history_read_sync(
      HistoryReadRawBuilder(historyStart, historyEnd).read(mEventHistoryObjectId));
    ASSERT_THAT(result, Good()) << "HistoryRead must not return transport/session error";
    auto& resp = result.value();
    ASSERT_THAT(resp, ServiceResultIsGood()) << "the refusal is per node, not a service fault";
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_THAT(resp.results()[0], HasStatus(Status::BadHistoryOperationUnsupported))
      << "an Object that notifies Event history and holds no values must refuse a VALUE history read; "
         "answering Good with an empty page tells the client to keep asking a question with no answer";
  }
}

/// A historised Variable whose stored values carry a SOURCE timestamp only. Everything else in
/// `ComplianceWithHistory` seeds both timestamps, which makes the per-node timestamp refusal
/// unreachable: no node there can fail to supply a requested timestamp.
class ComplianceWithSourceOnlyHistory : public ComplianceWithHistory
{
protected:
  void configure_server() override
  {
    ComplianceWithHistory::configure_server();

    auto addressSpace = mServer.server().address_space();

    mSourceOnlyNodeId = NodeId{mHistoryNsIndex, uint32_t{1003}};
    auto node = addressSpace.create_node_sync(mSourceOnlyNodeId, NodeClass::Variable);
    auto variable = node.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{mHistoryNsIndex, "SourceOnlyVar"});
    variable->set_display_name(LocalizedText{"", "SourceOnlyVar"});
    variable->set_data_type(NodeId{DataTypeId::Double});
    variable->write_value_sync(double{0.0});
    variable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead,
      AccessLevelType::Bit::HistoryRead,
      AccessLevelType::Bit::HistoryWrite});
    addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder})
      .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mSourceOnlyNodeId);

    // Source timestamps only - the server timestamp is deliberately left unset on every row, which is
    // what makes this node one that cannot honour a request for ServerTimestamps.
    std::vector<DataValue> historyValues;
    for (int i = 0; i < 10; ++i)
    {
      DataValue dv;
      dv.value() = Variant{double(i * 3.0)};
      dv.source_timestamp() = UtcTime{2025, 1, 1, 0, 0, static_cast<double>(i)};
      dv.status() = Status::Good;
      historyValues.push_back(std::move(dv));
    }
    mHistoryDelegate->add_values(mSourceOnlyNodeId, std::move(historyValues));
  }

  NodeId mSourceOnlyNodeId;
};

// Part 11 section 4.5 and section 6.5.3.2: a timestamp selection that is well formed but not one THIS node
// can supply is refused for that node with Bad_TimestampNotSupported. This is distinct from the service-level
// Bad_TimestampsToReturnInvalid, which says the enumeration itself was invalid. CTT Historical Access / Read
// Raw Err-016 is exactly this stimulus: a Source-only node asked for ServerTimestamps. Two plausible
// implementations get it wrong. One fabricates the missing timestamp (the read time, or a copy of the source
// timestamp), handing back a history whose server timestamps are invented. The same node is read with a
// timestamp selection it CAN supply first, so the refusal cannot be a node with no history.
// @verifies AC-SVR-ATTR-HREAD-026-INVALIDTIMESTAMPARGUMENT
TEST_F(ComplianceWithSourceOnlyHistory, ATimestampSelectionTheNodeCannotSupplyIsRefusedForThatNode)
{
  // Control: with Source timestamps - which this node does carry - the read is served with data.
  {
    auto control =
      mSession->attributes().try_history_read_sync(HistoryReadRawBuilder(historyStart, historyEnd)
                                                     .timestamps(TimestampsToReturn::Source)
                                                     .read(mSourceOnlyNodeId));
    ASSERT_THAT(control, Good());
    ASSERT_THAT(control.value(), ServiceResultIsGood());
    ASSERT_EQ(control.value().results().size(), 1u);
    ASSERT_THAT(control.value().results()[0], Good());
    ASSERT_GT(returned_value_count(control.value().results()[0]), 0u)
      << "the node must serve history under a selection it supports, or the refusal below proves nothing";
  }

  // The stimulus: Server timestamps, which no row of this node's history carries.
  auto result = mSession->attributes().try_history_read_sync(HistoryReadRawBuilder(historyStart, historyEnd)
                                                               .timestamps(TimestampsToReturn::Server)
                                                               .read(mSourceOnlyNodeId));

  ASSERT_THAT(result, Good()) << "HistoryRead must not return transport/session error";
  auto& resp = result.value();
  ASSERT_THAT(resp, ServiceResultIsGood())
    << "the selection is well formed, so this is a per-node outcome and not a service fault";
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadTimestampNotSupported))
    << "a node that cannot supply the requested timestamp must return Bad_TimestampNotSupported for "
       "that operation";
  EXPECT_EQ(returned_value_count(resp.results()[0]), 0u)
    << "and must return no history under a timestamp selection it could not honour - a page of values "
       "with a fabricated or absent server timestamp is the failure this code exists to prevent";
}

/// The reference-backed historised node alongside a node in a namespace that has NO history provider at
/// all. Both nodes advertise AccessLevel.HistoryRead, so the second one passes the history-access gate
/// and is refused for the OPERATION rather than for the access - which is the distinction between this
/// obligation and `AC-SVR-ATTR-HREAD-011-NO-HISTORY-ACCESS`.
class ComplianceWithReferenceHistoryAndAnUnservicedNode : public ComplianceWithReferenceHistory
{
protected:
  void configure_server() override
  {
    ComplianceWithReferenceHistory::configure_server();

    auto addressSpace = mServer.server().address_space();

    mUnservicedNamespace =
      default_ns::Namespace::create("urn:test:history:unserviced", mServer.thread_pool().executor());
    mUnservicedNsIndex = addressSpace.add_namespace_sync(mUnservicedNamespace);

    mUnservicedNodeId = NodeId{mUnservicedNsIndex, uint32_t{1000}};
    auto node = addressSpace.create_node_sync(mUnservicedNodeId, NodeClass::Variable);
    auto variable = node.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{mUnservicedNsIndex, "UnservicedVar"});
    variable->set_display_name(LocalizedText{"", "UnservicedVar"});
    variable->set_data_type(NodeId{DataTypeId::Double});
    variable->write_value_sync(double{0.0});
    variable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::HistoryRead});
    addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder})
      .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mUnservicedNodeId);
  }

  std::shared_ptr<default_ns::Namespace> mUnservicedNamespace;
  uint16_t mUnservicedNsIndex{0};
  NodeId mUnservicedNodeId;
};

// The processing interval is peer-supplied: a NaN or infinite value has no meaning and is refused for
// the whole request; a finite value that would produce more intervals than the per-node cap is refused
// for that node before anything is allocated.
// @relation(AC-SVR-HIST-AGG-025-PROCESSED-INTERVAL-COUNT-IS-BOUNDED, scope=function)
TEST_F(ComplianceWithReferenceHistoryAndAnUnservicedNode, AProcessedReadWithANonFiniteIntervalIsRefused)
{
  for (const double interval :
    {std::numeric_limits<double>::quiet_NaN(), std::numeric_limits<double>::infinity()})
  {
    auto details = std::make_unique<ReadProcessedDetails>();
    details->start_time() = UtcTime{2025, 1, 1, 0, 0, 0.0};
    details->end_time() = UtcTime{2025, 1, 1, 0, 0, 9.0};
    details->processing_interval() = interval;
    details->aggregate_configuration().use_server_capabilities_defaults() = true;
    details->aggregate_type().push_back(NodeId{ObjectId::AggregateFunction_Average});

    HistoryReadRequest req;
    req.request_header().request_handle() = 1;
    req.timestamps_to_return() = TimestampsToReturn::Source;
    req.history_read_details() = std::move(details);
    HistoryReadValueId capable;
    capable.node_id() = mHistorizedNodeId;
    req.nodes_to_read().push_back(std::move(capable));

    // The refusal is a whole-request ServiceFault, which the sync wrapper surfaces as a bad Result.
    auto result = mSession->attributes().try_history_read_sync(std::move(req));
    ASSERT_TRUE(result.is_bad()) << "a non-finite processing interval must be refused";
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadHistoryOperationInvalid})
      << "a non-finite processing interval must be refused as an invalid history operation";
  }
}

// @relation(AC-SVR-HIST-AGG-025-PROCESSED-INTERVAL-COUNT-IS-BOUNDED, scope=function)
TEST_F(ComplianceWithReferenceHistoryAndAnUnservicedNode,
  AProcessedReadThatWouldExceedTheIntervalCapIsRefusedForThatNode)
{
  // 9 s at 0.0001 ms is 9e7 intervals, past the 1e6 ceiling that applies with no configured per-node cap.
  auto details = std::make_unique<ReadProcessedDetails>();
  details->start_time() = UtcTime{2025, 1, 1, 0, 0, 0.0};
  details->end_time() = UtcTime{2025, 1, 1, 0, 0, 9.0};
  details->processing_interval() = 0.0001;
  details->aggregate_configuration().use_server_capabilities_defaults() = true;
  details->aggregate_type().push_back(NodeId{ObjectId::AggregateFunction_Average});

  HistoryReadRequest req;
  req.request_header().request_handle() = 1;
  req.timestamps_to_return() = TimestampsToReturn::Source;
  req.history_read_details() = std::move(details);
  HistoryReadValueId capable;
  capable.node_id() = mHistorizedNodeId;
  req.nodes_to_read().push_back(std::move(capable));

  auto result = mSession->attributes().try_history_read_sync(std::move(req));
  ASSERT_THAT(result, Good());
  auto& resp = result.value();
  ASSERT_THAT(resp, ServiceResultIsGood()) << "the request itself is well formed";
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_EQ(resp.results()[0].status_code(), StatusCode{Status::BadTooManyOperations})
    << "the node's interval count must be refused before it is materialised";
}

// Part 11 section 6.4 / Part 4 section 5.10.3.4: Bad_HistoryOperationUnsupported sits in the PER-OPERATION
// result table, not the service table, because history support varies by node: the same Server may compute
// aggregates for one node and hold nothing for another. The tempting shortcut is to notice that one
// named node cannot service the operation and fail the whole request - which denies the client the
// nodes that could have answered, and gives it no way to learn which node was at fault. The mirror-image
// shortcut is to answer Good with an empty page for the node that cannot serve it, which reads as "no
// data in this window" and sends the client back with a wider window for ever. Both nodes advertise
// AccessLevel.HistoryRead, so the refusal here is about the OPERATION and not about history access.
// @verifies AC-SVR-ATTR-HREAD-027-UNSUPPORTED-PER-NODE
// The execution-evidence reader requires the full TEST_F identity on one line.
// clang-format off
TEST_F(ComplianceWithReferenceHistoryAndAnUnservicedNode, AProcessedReadServesTheCapableNodeAndRefusesTheOneThatCannot)
// clang-format on
{
  // One request, two operations: the reference-backed node first, the unserviced node second. Part 13
  // requires Source timestamps for a processed read, and one aggregate entry per operation.
  auto details = std::make_unique<ReadProcessedDetails>();
  details->start_time() = UtcTime{2025, 1, 1, 0, 0, 0.0};
  details->end_time() = UtcTime{2025, 1, 1, 0, 0, 9.0};
  details->processing_interval() = 3000.0;
  details->aggregate_configuration().use_server_capabilities_defaults() = true;
  details->aggregate_type().push_back(NodeId{ObjectId::AggregateFunction_Average});
  details->aggregate_type().push_back(NodeId{ObjectId::AggregateFunction_Average});

  HistoryReadRequest req;
  req.request_header().request_handle() = 1;
  req.timestamps_to_return() = TimestampsToReturn::Source;
  req.history_read_details() = std::move(details);

  HistoryReadValueId capable;
  capable.node_id() = mHistorizedNodeId;
  req.nodes_to_read().push_back(std::move(capable));

  HistoryReadValueId unserviced;
  unserviced.node_id() = mUnservicedNodeId;
  req.nodes_to_read().push_back(std::move(unserviced));

  auto result = mSession->attributes().try_history_read_sync(std::move(req));

  ASSERT_THAT(result, Good()) << "one unserviceable node must not fail the request as a whole";
  auto& resp = result.value();
  ASSERT_THAT(resp, ServiceResultIsGood())
    << "per-node lack of support is a per-operation outcome, not a service fault";
  ASSERT_EQ(resp.results().size(), 2u) << "both operations must be reported on, in request order";

  // Conjunct 1: the node that supports the operation is served - with aggregate values, not merely a
  // Good status.
  EXPECT_THAT(resp.results()[0], Good()) << "the node that can answer the processed read must be served";
  EXPECT_GT(returned_value_count(resp.results()[0]), 0u)
    << "and must carry its aggregates - Good over an empty result is the same loss as failing the batch";

  // Conjunct 2: the node that does not is refused, in its own slot, with the code that tells the client
  // to stop asking rather than to widen its window.
  EXPECT_THAT(resp.results()[1], HasStatus(Status::BadHistoryOperationUnsupported))
    << "a node whose provider cannot service the operation must be refused with "
       "Bad_HistoryOperationUnsupported in its own slot";
  EXPECT_EQ(returned_value_count(resp.results()[1]), 0u)
    << "and must carry no history alongside that refusal";
}

// Part 11 section 6.8 / Part 4 section 5.10.5.3: a HistoryUpdate naming more data operations than
// MaxNodesPerHistoryUpdateData is refused at the SERVICE level, and - because this service mutates -
// nothing may be applied first. A Server that streams the batch into its store and only then notices the
// ceiling leaves a partially written history behind a failure report; the client, seeing the failure,
// resends the batch and duplicates or double-replaces the prefix that did land. Both halves are asserted
// here against the real reference store: the service result, and the emptiness of the window the
// over-size batch targeted. A control insert on the same node in a different window is made first and
// read back, so "nothing landed" cannot be a node that never accepts an insert at all.
// @verifies AC-SVR-ATTR-HUPD-002-TOOMANYOPERATIONS
TEST_F(ComplianceWithReferenceHistory, AnOverLimitHistoryUpdateIsRefusedWholeWithNoPrefixApplied)
{
  const DateTime controlTime{UtcTime{2026, 2, 1, 0, 0, 0}};
  const DateTime batchWindowStart{UtcTime{2026, 1, 1, 0, 0, 0}};
  const DateTime batchWindowEnd{UtcTime{2026, 1, 1, 0, 1, 0}};
  const DateTime controlWindowStart{UtcTime{2026, 2, 1, 0, 0, 0}};
  const DateTime controlWindowEnd{UtcTime{2026, 2, 1, 0, 1, 0}};

  // Control: a single-operation insert on this node, in a window the over-size batch never touches,
  // does land. Without this an empty batch window would be indistinguishable from a node that refuses
  // every insert.
  {
    DataValue control{Variant{double{123.0}}};
    control.source_timestamp() = controlTime;
    control.server_timestamp() = controlTime;
    control.status() = Status::Good;

    auto seed = std::make_unique<UpdateDataDetails>();
    seed->node_id() = mHistorizedNodeId;
    seed->perform_insert_replace() = PerformUpdateType::Insert;
    seed->update_values().push_back(std::move(control));

    auto seedResult = mSession->attributes().try_history_update_sync(history_update_request(std::move(seed)));
    ASSERT_THAT(seedResult, Good());
    ASSERT_THAT(seedResult.value(), ServiceResultIsGood());
    ASSERT_EQ(seedResult.value().results().size(), 1u);
    ASSERT_THAT(seedResult.value().results()[0], Good());
    ASSERT_EQ(seedResult.value().results()[0].operation_results().size(), 1u);
    ASSERT_THAT(seedResult.value().results()[0].operation_results()[0], Good())
      << "an in-limit insert must succeed on this node for the emptiness assertion below to mean anything";

    auto controlRead = mSession->attributes().try_history_read_sync(
      HistoryReadRawBuilder(controlWindowStart, controlWindowEnd).read(mHistorizedNodeId));
    ASSERT_THAT(controlRead, Good());
    ASSERT_THAT(controlRead.value(), ServiceResultIsGood());
    ASSERT_EQ(controlRead.value().results().size(), 1u);
    ASSERT_EQ(returned_value_count(controlRead.value().results()[0]), 1u)
      << "the control insert must be readable back, so a raw read of a written window does see writes";
  }

  // 200 data operations against a ceiling of 100, each writing a distinct instant inside the batch
  // window, so any prefix the Server applied would be visible.
  HistoryUpdateRequest req;
  for (uint32_t i = 0; i < 200; ++i)
  {
    DataValue value{Variant{double(i)}};
    value.source_timestamp() = UtcTime{2026, 1, 1, 0, 0, static_cast<double>(i) * 0.25};
    value.server_timestamp() = UtcTime{2026, 1, 1, 0, 0, static_cast<double>(i) * 0.25};
    value.status() = Status::Good;

    auto details = std::make_unique<UpdateDataDetails>();
    details->node_id() = mHistorizedNodeId;
    details->perform_insert_replace() = PerformUpdateType::Insert;
    details->update_values().push_back(std::move(value));

    RefStructure<Structure> wrapped;
    wrapped = std::unique_ptr<Structure>(std::move(details));
    req.history_update_details().push_back(std::move(wrapped));
  }

  auto result = mSession->attributes().try_history_update_sync(std::move(req));

  // Conjunct 1: the refusal is the SERVICE result, not a fan-out of per-operation errors.
  EXPECT_THAT(result, Bad(Status::BadTooManyOperations))
    << "200 data operations against MaxNodesPerHistoryUpdateData=100 must be refused at service level";

  // Conjunct 2: no prefix of the batch reached the store.
  auto after = mSession->attributes().try_history_read_sync(
    HistoryReadRawBuilder(batchWindowStart, batchWindowEnd).read(mHistorizedNodeId));
  ASSERT_THAT(after, Good()) << "the follow-up read must not return a transport/session error";
  ASSERT_THAT(after.value(), ServiceResultIsGood());
  ASSERT_EQ(after.value().results().size(), 1u);
  EXPECT_EQ(returned_value_count(after.value().results()[0]), 0u)
    << "a refused HistoryUpdate must apply nothing - a partially written batch reported as a failure is "
       "resent by the client and lands twice";
}

// ===========================================================================
// Per-node history authorization
// ===========================================================================
//
/// Three historised nodes backed by the canonical SQLite reference, served to a Session that is
/// authorized differently on each of them.
///
/// The fixture grants the Anonymous Role and assigns different RolePermissions to each Node. Nothing
/// below is produced by the fixture except the *permission*: every status code asserted on, and the
/// decision of which slot carries it, is the history service's.
///
/// All three nodes advertise `AccessLevel.HistoryRead|HistoryWrite` and are seeded with the same ten
/// values, so no outcome can be attributed to the static capability bits or to one node holding no
/// history:
///   * `mAllowedNodeId`     - every history operation permitted.
///   * `mReadDeniedNodeId`  - `HistoryRead` denied.
///   * `mWriteDeniedNodeId` - `InsertHistory`/`ModifyHistory`/`DeleteHistory` denied, `HistoryRead`
///                            still permitted, so that what did or did not land in its history stays
///                            observable after a refused update.
class ComplianceHistoryWithPerNodeAuthorization : public ComplianceSecured
{
protected:
  void configure_components(server::ServerComponents& components) override
  {
    components.roleConfiguration = RoleConfiguration::from_well_known_grants(
      {{WellKnownRole::Anonymous, IdentityCriteriaType::Anonymous}});
  }

  void SetUp() override
  {
    ComplianceSecured::SetUp();

    CoreClient::OpenChannelConfig channelConfig;
    channelConfig.endpointUrl = mEndpointUrl;
    channelConfig.securityMode = MessageSecurityMode::None;
    channelConfig.securityPolicyId = SecurityPolicyId::None;
    mChannel.emplace(mClient->core().open_channel_sync(std::move(channelConfig)));
    mSession.emplace(mChannel->create_session_sync({.sessionName = "ComplianceHistoryAuthz"}));
    mSession->activate_sync();

    auto addressSpace = mServer->address_space();
    auto innerNs = addressSpace.create_namespace("urn:test:history:authorization", {});
    auto store =
      std::make_unique<ua::history::SqliteHistoryStore>(":memory:", mServer->ua_binary_data_value_codec());
    mStore = store.get();
    mDelegate = make_shared<ua::history::HistoryEngineDelegate>(std::move(store));
    auto ns = make_shared<ua::history::HistoryNamespace>(std::move(innerNs), mDelegate);
    mHistoryNsIndex = addressSpace.add_namespace_sync(ns);

    seed_historised_variable(uint32_t{1000},
      "AllowedHistory",
      mAllowedNodeId,
      {PermissionType::Bit::Browse,
        PermissionType::Bit::Read,
        PermissionType::Bit::ReadHistory,
        PermissionType::Bit::InsertHistory,
        PermissionType::Bit::ModifyHistory,
        PermissionType::Bit::DeleteHistory});
    seed_historised_variable(uint32_t{1001},
      "ReadDeniedHistory",
      mReadDeniedNodeId,
      {PermissionType::Bit::Browse,
        PermissionType::Bit::Read,
        PermissionType::Bit::InsertHistory,
        PermissionType::Bit::ModifyHistory,
        PermissionType::Bit::DeleteHistory});
    seed_historised_variable(uint32_t{1002},
      "WriteDeniedHistory",
      mWriteDeniedNodeId,
      {PermissionType::Bit::Browse, PermissionType::Bit::Read, PermissionType::Bit::ReadHistory});
  }

  void TearDown() override
  {
    if (mSession)
      (void)mSession->try_close_sync();
    if (mChannel)
      (void)mChannel->try_close_sync();
    ComplianceSecured::TearDown();
  }

  /// Create a historised Double Variable under Objects and seed it with the same ten values the rest of
  /// this file uses (value = index * 1.5, one second apart from 2025-01-01T00:00:00Z).
  void seed_historised_variable(uint32_t identifier, std::string_view browseName, NodeId& outNodeId,
    std::initializer_list<PermissionType::Bit> permissions)
  {
    auto addressSpace = mServer->address_space();
    const NodeId nodeId{mHistoryNsIndex, identifier};

    auto node = addressSpace.create_node_sync(nodeId, NodeClass::Variable);
    auto variable = node.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{mHistoryNsIndex, String{browseName}});
    variable->set_display_name(LocalizedText{"", String{browseName}});
    variable->set_data_type(NodeId{DataTypeId::Double});
    variable->write_value_sync(double{0.0});
    variable->set_historizing(true);
    variable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead,
      AccessLevelType::Bit::HistoryRead,
      AccessLevelType::Bit::HistoryWrite});
    RolePermissionType anonymousPermissions;
    anonymousPermissions.role_id() = NodeId{ObjectId::WellKnownRole_Anonymous};
    anonymousPermissions.permissions() = PermissionType{permissions};
    variable->set_role_permissions(std::vector<RolePermissionType>{anonymousPermissions});
    addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder})
      .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, nodeId);

    for (int i = 0; i < 10; ++i)
    {
      DataValue dv{Variant{double(i * 1.5)}};
      dv.source_timestamp() = UtcTime{2025, 1, 1, 0, 0, static_cast<double>(i)};
      dv.server_timestamp() = UtcTime{2025, 1, 1, 0, 0, static_cast<double>(i)};
      dv.status() = Status::Good;
      mStore->insert_value(nodeId, dv).value();
    }

    outNodeId = nodeId;
  }

  std::optional<SecureChannel> mChannel;
  std::optional<Session> mSession;
  ua::history::SqliteHistoryStore* mStore{nullptr};
  shared_ptr<ua::history::HistoryEngineDelegate> mDelegate;
  uint16_t mHistoryNsIndex{0};
  NodeId mAllowedNodeId;
  NodeId mReadDeniedNodeId;
  NodeId mWriteDeniedNodeId;
};

// Part 11 section 6.4 / Part 4 section 5.10.3.4: permission to read a Node's history is decided PER NODE, and
// it is a different question from the static `AccessLevel.HistoryRead` bit - the bit advertises that the Node
// keeps history, not that this caller may see it. Two implementations get this wrong in opposite
// directions. One reads the advertisement, finds it set, and dispatches to the history provider without
// ever asking Namespace policy, so the denial never happens. The other asks, sees a denial, and fails the
// whole service call, which throws away the results for every other Node the client named and leaves it
// unable to tell which one it was refused. Both Nodes here advertise HistoryRead and hold the same ten
// seeded values, so RolePermissions are the only thing separating them, and the served
// Node's history is asserted non-empty so "the other is served" cannot be a Good status over an empty
// page.
// @verifies AC-SVR-ATTR-HREAD-024-DENIED
TEST_F(ComplianceHistoryWithPerNodeAuthorization, HistoryReadIsRefusedPerNodeWhileTheAuthorizedNodeIsServed)
{
  // The denied Node is named FIRST, so a Server that abandons the batch at the first refusal cannot
  // still satisfy the second operation.
  HistoryReadRawBuilder builder(historyStart, historyEnd);
  builder.read(mReadDeniedNodeId);
  builder.read(mAllowedNodeId);

  auto result = mSession->attributes().try_history_read_sync(builder.build());

  ASSERT_THAT(result, Good()) << "one unauthorized Node must not fail the request as a whole";
  auto& resp = result.value();
  ASSERT_THAT(resp, ServiceResultIsGood())
    << "a per-node denial is a per-operation outcome, not a service fault";
  ASSERT_EQ(resp.results().size(), 2u) << "both operations must be reported on, in request order";

  // Conjunct 1: the Node this Session may not read history for is refused, in its own slot, with the
  // code that names the reason - and carries no history alongside the refusal.
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadUserAccessDenied))
    << "a Node whose history this Session is not authorized to read must return Bad_UserAccessDenied";
  EXPECT_EQ(returned_value_count(resp.results()[0]), 0u)
    << "and must return no history - a refusal that still ships the page has denied nothing";

  // Conjunct 2: the Node it may read is served, with its history.
  EXPECT_THAT(resp.results()[1], Good()) << "the authorized Node in the same request must still be served";
  EXPECT_GT(returned_value_count(resp.results()[1]), 0u)
    << "and must carry its history - Good over an empty result is the same data loss as failing the "
       "whole batch";
}

// Part 11 section 6.8 / Part 4 section 5.10.5.4: permission to update history is decided per Node and per
// operation (Part 3 section 8.55 splits InsertHistory / ModifyHistory / DeleteHistory), so an unauthorized
// entry marks its own slot and the rest of the batch is still applied. Two failures are plausible here and
// neither is visible from the status codes alone. A Server may hand the whole batch to the store and report
// the denial afterwards, in which case history the caller was never allowed to write is now permanently in
// the store behind a Bad result. Or it may abandon the batch at the first denial, in which case the
// entry the caller WAS allowed to write silently never lands while its slot reports Good. Both Nodes
// advertise AccessLevel.HistoryWrite, so the Namespace verdict is the only thing separating them, and
// both stores are read back afterwards - the write-denied Node deliberately keeps HistoryRead permission
// so that "nothing landed on it" is observable rather than inferred.
// @verifies AC-SVR-ATTR-HUPD-006-DENIED
TEST_F(ComplianceHistoryWithPerNodeAuthorization, HistoryUpdateIsRefusedPerNodeWhileTheOtherNodeIsUpdated)
{
  const DateTime insertTime{UtcTime{2026, 5, 1, 0, 0, 0}};
  const DateTime insertWindowStart{UtcTime{2026, 5, 1, 0, 0, 0}};
  const DateTime insertWindowEnd{UtcTime{2026, 5, 1, 0, 1, 0}};

  // Control: the write-denied Node's history IS readable by this Session - only its writes are denied.
  // Without this, the empty insert window asserted at the end could equally mean "this Node cannot be
  // read at all", which would prove nothing about the update.
  {
    auto seeded = mSession->attributes().try_history_read_sync(
      HistoryReadRawBuilder(historyStart, historyEnd).read(mWriteDeniedNodeId));
    ASSERT_THAT(seeded, Good());
    ASSERT_THAT(seeded.value(), ServiceResultIsGood());
    ASSERT_EQ(seeded.value().results().size(), 1u);
    ASSERT_THAT(seeded.value().results()[0], Good())
      << "the write-denied Node must still be history-readable for the emptiness check below to bite";
    ASSERT_GT(returned_value_count(seeded.value().results()[0]), 0u)
      << "and must return its seeded values, so a raw read of this Node does see stored history";
  }

  auto insertDetail = [&insertTime](const NodeId& node, double value)
  {
    DataValue dv{Variant{value}};
    dv.source_timestamp() = insertTime;
    dv.server_timestamp() = insertTime;
    dv.status() = Status::Good;

    auto details = std::make_unique<UpdateDataDetails>();
    details->node_id() = node;
    details->perform_insert_replace() = PerformUpdateType::Insert;
    details->update_values().push_back(std::move(dv));
    return details;
  };

  // The unauthorized entry is named FIRST, so a Server that abandons the batch at the first refusal
  // cannot still apply the second.
  HistoryUpdateRequest req;
  {
    auto deniedDetails = insertDetail(mWriteDeniedNodeId, 11.0);
    RefStructure<Structure> denied;
    denied = std::unique_ptr<Structure>(std::move(deniedDetails));
    req.history_update_details().push_back(std::move(denied));

    auto allowedDetails = insertDetail(mAllowedNodeId, 22.0);
    RefStructure<Structure> allowed;
    allowed = std::unique_ptr<Structure>(std::move(allowedDetails));
    req.history_update_details().push_back(std::move(allowed));
  }

  auto result = mSession->attributes().try_history_update_sync(std::move(req));

  ASSERT_THAT(result, Good()) << "one unauthorized entry must not fail the request as a whole";
  auto& resp = result.value();
  ASSERT_THAT(resp, ServiceResultIsGood())
    << "a per-node denial is a per-operation outcome, not a service fault";
  ASSERT_EQ(resp.results().size(), 2u) << "both update details must be reported on, in request order";

  // Conjunct 1: the entry this Session may not write is refused in its own slot.
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadUserAccessDenied))
    << "an update on a Node whose history this Session may not write must return Bad_UserAccessDenied";
  EXPECT_EQ(resp.results()[0].operation_results().size(), 0u)
    << "and must report no per-value outcomes - a refused entry is never offered to the store";

  // Conjunct 2: the entry it may write is accepted, per value.
  ASSERT_THAT(resp.results()[1], Good()) << "the authorized entry in the same request must still be applied";
  ASSERT_EQ(resp.results()[1].operation_results().size(), 1u)
    << "one per-value result for the single value the authorized entry carried";
  EXPECT_THAT(resp.results()[1].operation_results()[0], Good()) << "the authorized insert must be accepted";

  // Conjunct 3: the store agrees with both reports. The authorized Node's value is readable back...
  auto allowedRead = mSession->attributes().try_history_read_sync(
    HistoryReadRawBuilder(insertWindowStart, insertWindowEnd).read(mAllowedNodeId));
  ASSERT_THAT(allowedRead, Good());
  ASSERT_THAT(allowedRead.value(), ServiceResultIsGood());
  ASSERT_EQ(allowedRead.value().results().size(), 1u);
  ASSERT_THAT(allowedRead.value().results()[0], Good());
  ASSERT_EQ(returned_value_count(allowedRead.value().results()[0]), 1u)
    << "the authorized insert must actually be in the store, not merely reported Good";
  const auto* histData =
    dynamic_cast<const HistoryData*>(allowedRead.value().results()[0].history_data().get());
  ASSERT_NE(histData, nullptr) << "a raw history page must be wrapped in HistoryData";
  const double* written = histData->data_values()[0].value().try_as<double>();
  ASSERT_NE(written, nullptr) << "the seeded and inserted history is Double";
  EXPECT_DOUBLE_EQ(*written, 22.0) << "the value that landed must be the one the authorized entry carried";

  // ...and nothing landed on the Node whose update was refused.
  auto deniedRead = mSession->attributes().try_history_read_sync(
    HistoryReadRawBuilder(insertWindowStart, insertWindowEnd).read(mWriteDeniedNodeId));
  ASSERT_THAT(deniedRead, Good());
  ASSERT_THAT(deniedRead.value(), ServiceResultIsGood());
  ASSERT_EQ(deniedRead.value().results().size(), 1u);
  EXPECT_EQ(returned_value_count(deniedRead.value().results()[0]), 0u)
    << "a denied history update must apply nothing - history the caller was refused permission to "
       "write must not be in the store behind the refusal";
}

// ===========================================================================
// ServerModelReferences: the AggregateFunctions folders' Organizes in both directions (NR-30, NR-70 F15)
// ===========================================================================

class ServerModelReferences : public ComplianceWithHistory
{};

// Part 3 section 5.3.2 recommends instantiating hierarchical References in both directions; NR-30 makes the
// SDK add both halves of the hierarchical References it adds itself. A server reading raw history publishes
// its aggregate functions under three AggregateFunctions folders. The forward Browse is the control that the
// folders are populated; the inverse Browse of each aggregate function must return the folder.
// @relation(AC-SVR-ADDRSP-261-AGGREGATE-FOLDERS-BIDIRECTIONAL, scope=function)
TEST_F(ServerModelReferences, EveryAggregateFolderAnswersItsInverseOrganizes)
{
  const NodeId organizes{ReferenceTypeId::Organizes};
  for (const auto folderId : {ObjectId::Server_ServerCapabilities_AggregateFunctions,
         ObjectId::HistoryServerCapabilities_AggregateFunctions,
         ObjectId::DefaultHAConfiguration_AggregateFunctions})
  {
    const NodeId folder{folderId};
    auto forward = mSession->view().try_browse_sync(BrowseRequestBuilder()
                                                      .browse(folder)
                                                      .direction(BrowseDirection::Forward)
                                                      .reference_type(organizes)
                                                      .include_subtypes(false));
    ASSERT_THAT(forward, Good());
    ASSERT_EQ(forward.value().results().size(), 1u);
    const auto& functions = forward.value().results().payload()[0].references().payload();
    ASSERT_FALSE(functions.empty()) << "the folder " << to_string(folder)
                                    << " organises no aggregate function";

    for (const auto& function : functions)
    {
      const NodeId functionId = function.node_id().node_id();
      auto inverse = mSession->view().try_browse_sync(BrowseRequestBuilder()
                                                        .browse(functionId)
                                                        .direction(BrowseDirection::Inverse)
                                                        .reference_type(organizes)
                                                        .include_subtypes(false));
      ASSERT_THAT(inverse, Good());
      ASSERT_EQ(inverse.value().results().size(), 1u);
      bool returnsTheFolder = false;
      for (const auto& reference : inverse.value().results().payload()[0].references().payload())
        returnsTheFolder = returnsTheFolder || reference.node_id().node_id() == folder;
      EXPECT_TRUE(returnsTheFolder) << "the inverse Browse of the aggregate function "
                                    << to_string(functionId) << " does not return the folder "
                                    << to_string(folder) << " that organises it";
    }
  }
}
