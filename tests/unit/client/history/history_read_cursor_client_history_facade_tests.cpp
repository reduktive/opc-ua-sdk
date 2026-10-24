// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::HistoryFacade + ua::client::HistoryReadCursor (client design section 8.9, D2
// flatten): the flattened one-hop Historical Access facade and its paged read cursor. Covers the per-CU
// detail composition (raw / modified / at-time / processed / annotations), the caller-side pre-flight
// rejections (CL-HIST-003 / -004 / -010 / -022), the two-layer status mapping (CL-HIST-011 / -012 / -021 /
// -023), the per-flavour update-detail composition (CL-HIST-017..019), and the cursor's continuation-point
// paging + close/destructor release (CL-HIST-008 / -009 / -013) + WireOps-gone bail.
//
// Falsifiability: a facade that mis-composes the details fails Compose*; one that skips the pre-flight fails
// Rejects*Inline (a wire read would be recorded); one that flattens a per-node/entry Bad into a service
// failure fails PerNode*/PerEntry*; a cursor that never pages fails MultiPage; one that leaks the CP fails
// Close/DestructorReleasesContinuationPoint; one that derefs a gone interface fails WireOpsGone*.

#include "ua_history_facade.h"

#include "ua_aggregate_configuration.h"
#include "ua_access_level_type.h"
#include "ua_attribute_id.h"
#include "ua_browse_direction.h"
#include "ua_browse_result_mask.h"

#include "fake_connection_ops.h"

#include "test_utilities.h"

#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_delete_at_time_details.h"
#include "ua_delete_raw_modified_details.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_history_facade_test_access.h"
#include "ua_history_read_cursor.h"
#include "ua_log_entry.h"
#include "ua_log_level.h"
#include "ua_log_sink.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_perform_update_type.h"
#include "ua_read_annotation_data_details.h"
#include "ua_read_at_time_details.h"
#include "ua_read_processed_details.h"
#include "ua_read_raw_modified_details.h"
#include "ua_referencetype_id.h"
#include "ua_ref_structure.h"
#include "ua_status.h"
#include "ua_to_string.h"
#include "ua_structure.h"
#include "ua_update_data_details.h"
#include "ua_variant.h"
#include "ua_variable_id.h"

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

namespace
{

using ua::client::HistoryFacade;
using ua::client::HistoryReadCursor;
using ua::client::HistoryReadOptions;
using ua::client::HistoryUpdateResult;
using ua::client::TimeRange;
using ua::client::detail::HistoryFacadeTestAccess;
using ua::test_helpers::FakeWireOps;

ua::NodeId node(std::uint32_t identifier)
{
  return ua::NodeId{0, identifier};
}

ua::DataValue dv(std::int32_t value)
{
  return ua::DataValue{ua::Variant{value}};
}

ua::DateTime instant(double seconds)
{
  return ua::DateTime{2025, 1, 1, 0, 0, seconds};
}

/// A LogSink that records each entry's level + message so a test can assert the cursor logged the best-effort
/// continuation-point release outcome at the wire boundary (CL-HIST-009 / section 8.9.6).
struct RecordingLogSink : public ua::LogSink
{
  struct Entry
  {
    ua::LogLevel level;
    std::string message;
  };

  std::vector<Entry> entries;

  void log(const ua::LogEntry& entry) override
  {
    entries.push_back(Entry{entry.level, entry.message});
  }

  [[nodiscard]] bool has_warning_containing(std::string_view needle) const
  {
    for (const auto& entry : entries)
    {
      if (entry.level == ua::LogLevel::Warning && entry.message.find(needle) != std::string::npos)
      {
        return true;
      }
    }
    return false;
  }
};

/// Builds a Trace-level Logger over @p sink (so Warning/Info both pass the filter).
ua::Logger make_logger(std::shared_ptr<ua::LogSink> sink)
{
  auto level = std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Trace);
  return ua::Logger{std::move(sink), std::move(level), "history_test"};
}

/// A raw-details snapshot for the directly-constructed cursor tests (mirrors what read_raw_async caches).
ua::RefStructure<ua::Structure> raw_details_snapshot()
{
  ua::RefStructure<ua::Structure> details;
  details = std::unique_ptr<ua::Structure>(std::make_unique<ua::ReadRawModifiedDetails>());
  return details;
}

struct Fixture
{
  boost::asio::io_context ctx;
  std::shared_ptr<FakeWireOps> wireOps = std::make_shared<FakeWireOps>();

  HistoryFacade facade()
  {
    return HistoryFacadeTestAccess::make_facade(wireOps, ctx.get_executor());
  }

  // Drives one read to completion and returns the delivered cursor Result.
  ua::Result<HistoryReadCursor> drain_read(
    const std::function<void(HistoryFacade&, std::function<void(ua::Result<HistoryReadCursor>)>)>& invoke)
  {
    std::optional<ua::Result<HistoryReadCursor>> captured;
    auto f = facade();
    invoke(f, [&captured](ua::Result<HistoryReadCursor> result) { captured = std::move(result); });
    ctx.run();
    ctx.restart();
    return std::move(captured.value());
  }

  // Drives one update to completion and returns the delivered Result.
  ua::Result<HistoryUpdateResult> drain_update(
    const std::function<void(HistoryFacade&, std::function<void(ua::Result<HistoryUpdateResult>)>)>& invoke,
    bool seedSuccessfulPreflight = true)
  {
    if (seedSuccessfulPreflight && wireOps->scriptedReadResponses.empty())
    {
      ua::ReadResponse accessLevel;
      accessLevel.results().push_back(ua::DataValue{
        ua::Variant{ua::AccessLevelType{ua::AccessLevelType::Bit::HistoryWrite}.as_underlying_type()}});
      wireOps->scriptedReadResponses.push_back(std::move(accessLevel));
      ua::ReadResponse capabilities;
      for (std::size_t index = 0; index < 5; ++index)
        capabilities.results().push_back(ua::DataValue{ua::Variant{true}});
      wireOps->scriptedReadResponses.push_back(std::move(capabilities));
    }
    std::optional<ua::Result<HistoryUpdateResult>> captured;
    auto f = facade();
    invoke(f, [&captured](ua::Result<HistoryUpdateResult> result) { captured = std::move(result); });
    ctx.run();
    ctx.restart();
    return std::move(captured.value());
  }

  ua::Result<bool> probe(HistoryFacade& facade, ua::NodeId target)
  {
    std::optional<ua::Result<bool>> captured;
    facade.is_history_capable_async(
      std::move(target), [&captured](ua::Result<bool> result) { captured = std::move(result); });
    ctx.run();
    ctx.restart();
    return std::move(captured.value());
  }

  ua::Result<std::vector<ua::NodeId>> configurations(HistoryFacade& facade, ua::NodeId target)
  {
    std::optional<ua::Result<std::vector<ua::NodeId>>> captured;
    facade.historical_configurations_async(std::move(target),
      [&captured](ua::Result<std::vector<ua::NodeId>> result) { captured = std::move(result); });
    ctx.run();
    ctx.restart();
    return std::move(captured.value());
  }

  // Drives one cursor advance to completion and returns the delivered page Result.
  ua::Result<std::vector<ua::DataValue>> next(HistoryReadCursor& cursor)
  {
    std::optional<ua::Result<std::vector<ua::DataValue>>> captured;
    cursor.next_async(
      [&captured](ua::Result<std::vector<ua::DataValue>> result) { captured = std::move(result); });
    ctx.run();
    ctx.restart();
    return std::move(captured.value());
  }
};

TimeRange full_range()
{
  TimeRange range;
  range.startTime = instant(0.0);
  range.endTime = instant(9.0);
  range.numValuesPerNode = 100;
  return range;
}

ua::ReadResponse access_level_response(std::uint8_t accessLevel)
{
  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{ua::Variant{accessLevel}});
  return response;
}

ua::ReadResponse history_capabilities_response(const std::array<bool, 5>& flags)
{
  ua::ReadResponse response;
  for (const bool flag : flags)
    response.results().push_back(ua::DataValue{ua::Variant{flag}});
  return response;
}

ua::ReferenceDescription configuration_reference(std::uint32_t identifier, std::string_view name)
{
  ua::ReferenceDescription reference;
  reference.node_id() = ua::ExpandedNodeId{node(identifier)};
  reference.browse_name() = ua::QualifiedName{1, name};
  reference.node_class() = ua::NodeClass::Object;
  return reference;
}

// ===========================================================================
// Capability discovery (CL-HIST-001)
// ===========================================================================

// @verifies CL-HIST-001
// @relation(CL-HIST-001, scope=function)
TEST(HistoryFacadeCapabilityProbe, ExtractsHistoryReadBitAcrossMixedVariables)
{
  Fixture f;
  f.wireOps->scriptedReadResponses.push_back(
    access_level_response(ua::AccessLevelType{ua::AccessLevelType::Bit::CurrentRead}.as_underlying_type()));
  f.wireOps->scriptedReadResponses.push_back(
    access_level_response(ua::AccessLevelType{ua::AccessLevelType::Bit::HistoryRead}.as_underlying_type()));
  f.wireOps->scriptedReadResponses.push_back(
    access_level_response(ua::AccessLevelType{ua::AccessLevelType::Bit::HistoryWrite}.as_underlying_type()));
  auto facade = f.facade();

  auto plain = f.probe(facade, node(100));
  auto readable = f.probe(facade, node(101));
  auto writeOnly = f.probe(facade, node(102));

  ASSERT_TRUE(plain.is_good());
  ASSERT_TRUE(readable.is_good());
  ASSERT_TRUE(writeOnly.is_good());
  EXPECT_FALSE(plain.value());
  EXPECT_TRUE(readable.value());
  EXPECT_FALSE(writeOnly.value());
  ASSERT_EQ(f.wireOps->readRequests.size(), 3u);
  for (const auto& request : f.wireOps->readRequests)
  {
    ASSERT_EQ(request.nodes_to_read().size(), 1u);
    EXPECT_EQ(
      request.nodes_to_read()[0].attribute_id(), static_cast<ua::IntegerId>(ua::AttributeId::AccessLevel));
  }
}

// @verifies CL-HIST-001
// @relation(CL-HIST-001, scope=function)
TEST(HistoryFacadeCapabilityProbe, ReusesCacheAcrossCopiedFacadeHandles)
{
  Fixture f;
  f.wireOps->scriptedReadResponses.push_back(
    access_level_response(ua::AccessLevelType{ua::AccessLevelType::Bit::HistoryRead}.as_underlying_type()));
  auto first = f.facade();
  auto copy = first;

  ASSERT_TRUE(f.probe(first, node(110)).value());
  ASSERT_TRUE(f.probe(copy, node(110)).value());
  EXPECT_EQ(f.wireOps->readCalls, 1u);
}

// @verifies CL-HIST-001
// @relation(CL-HIST-001, scope=function)
TEST(HistoryFacadeCapabilityProbe, BadAttributeStatusCarriesErrorDetail)
{
  Fixture f;
  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{ua::Status::BadNotReadable});
  f.wireOps->scriptedReadResponses.push_back(std::move(response));
  auto facade = f.facade();

  auto result = f.probe(facade, node(120));

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadNotReadable);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "HistoryCapabilityAccessLevelBad");
}

// @verifies CL-HIST-001
// @relation(CL-HIST-001, scope=function)
TEST(HistoryFacadeCapabilityProbe, WrongAttributeTypeIsRejectedWithDetail)
{
  Fixture f;
  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{ua::Variant{std::int32_t{4}}});
  f.wireOps->scriptedReadResponses.push_back(std::move(response));
  auto facade = f.facade();

  auto result = f.probe(facade, node(121));

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadTypeMismatch);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "HistoryCapabilityAccessLevelType");
}

// @verifies CL-HIST-001
// @relation(CL-HIST-001, scope=function)
TEST(HistoryFacadeCapabilityProbe, ForcedReadWithoutAdvertisedBitPreservesServerRejectionDetail)
{
  Fixture f;
  f.wireOps->historyReadPages.push_back(
    {{}, ua::ContinuationPoint{}, ua::Status::BadHistoryOperationUnsupported});

  auto result = f.drain_read([](HistoryFacade& facade, auto callback)
    { facade.read_raw_async(node(130), full_range(), {}, std::move(callback)); });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadHistoryOperationUnsupported);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "HistoryReadNodeBad");
}

// @verifies CL-HIST-002
// @relation(CL-HIST-002, scope=function)
TEST(HistoryFacadeConfigurationBrowse, ReturnsAllConfigurationsAcrossPages)
{
  Fixture f;
  f.wireOps->browsePages.push_back(
    {{configuration_reference(201, "HA Configuration")}, ua::ContinuationPoint{1}, {}});
  f.wireOps->browsePages.push_back(
    {{configuration_reference(202, "Long Term Configuration")}, ua::ContinuationPoint{}, {}});
  auto facade = f.facade();

  auto result = f.configurations(facade, node(200));

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value(), (std::vector<ua::NodeId>{node(201), node(202)}));
  ASSERT_EQ(f.wireOps->browseRequests.size(), 1u);
  const auto& browse = f.wireOps->browseRequests[0].nodes_to_browse()[0];
  EXPECT_EQ(browse.reference_type_id(), ua::NodeId{ua::ReferenceTypeId::HasHistoricalConfiguration});
  EXPECT_EQ(browse.browse_direction(), ua::BrowseDirection::Forward);
  EXPECT_TRUE(browse.include_subtypes());
  EXPECT_EQ(browse.node_class_mask(), static_cast<std::uint32_t>(ua::NodeClass::Object));
  EXPECT_EQ(browse.result_mask(), static_cast<std::uint32_t>(ua::BrowseResultMask::TargetInfo));
  EXPECT_EQ(f.wireOps->browseNextRequests.size(), 1u);
}

// @verifies AC-CL-VIEW-005-THE-DRAIN-IS-BOUNDED
TEST(HistoryFacadeConfigurationBrowse, ConfigurationDrainEndsAfterTooManyEmptyPagesInARow)
{
  Fixture f;
  f.wireOps->browsePages.push_back(
    {{configuration_reference(201, "HA Configuration")}, ua::ContinuationPoint{1}, {}});
  for (int page = 0; page < 11; ++page)
  {
    f.wireOps->browsePages.push_back({{}, ua::ContinuationPoint{1}, {}});  // the same point, nothing else
  }
  auto facade = f.facade();

  auto result = f.configurations(facade, node(200));

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadTimeout);
  EXPECT_EQ(f.wireOps->browseNextRequests.size(), 12U)
    << "eleven reads, then one release of the point the server still holds";
}

// @verifies CL-HIST-002
// @relation(CL-HIST-002, scope=function)
TEST(HistoryFacadeConfigurationBrowse, MissingConfigurationReturnsGoodEmpty)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{}, ua::ContinuationPoint{}, {}});
  auto facade = f.facade();

  auto result = f.configurations(facade, node(210));

  ASSERT_TRUE(result.is_good());
  EXPECT_TRUE(result.value().empty());
}

// @verifies CL-HIST-002
// @relation(CL-HIST-002, scope=function)
TEST(HistoryFacadeConfigurationBrowse, BadBrowseCarriesErrorDetail)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{}, ua::ContinuationPoint{}, ua::Status::BadNodeIdUnknown});
  auto facade = f.facade();

  auto result = f.configurations(facade, node(220));

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadNodeIdUnknown);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "HistoricalConfigurationBrowseFailed");
}

// ===========================================================================
// Reads - detail composition (CL-HIST-005 / -007 / -015 / -016 / -018)
// ===========================================================================

// @verifies CL-HIST-007
// @relation(CL-HIST-007, scope=function)
TEST(HistoryFacade, ReadRawComposesReadRawModifiedDetails)
{
  Fixture f;
  f.wireOps->historyReadPages.push_back({{dv(1), dv(2)}, ua::ContinuationPoint{}, {}});

  auto result = f.drain_read(
    [](HistoryFacade& facade, auto cb) { facade.read_raw_async(node(11), full_range(), {}, std::move(cb)); });
  ASSERT_TRUE(result.is_good());

  ASSERT_EQ(f.wireOps->historyReadRequests.size(), 1u);
  const auto* details = dynamic_cast<const ua::ReadRawModifiedDetails*>(
    f.wireOps->historyReadRequests[0].history_read_details().get());
  ASSERT_NE(details, nullptr) << "read_raw must compose a ReadRawModifiedDetails";
  EXPECT_FALSE(details->is_read_modified()) << "a raw read has isReadModified=false";
  EXPECT_EQ(f.wireOps->historyReadRequests[0].nodes_to_read().size(), 1u);
}

// @verifies CL-HIST-007
// @relation(CL-HIST-007, scope=function)
TEST(HistoryFacade, ReadModifiedPinsIsReadModifiedAndReturnBoundsFalse)
{
  Fixture f;
  f.wireOps->historyReadPages.push_back({{dv(1)}, ua::ContinuationPoint{}, {}});
  HistoryReadOptions options;
  options.returnBounds = true;  // must be IGNORED for a modified read (hard-coded false)

  auto result = f.drain_read([options](HistoryFacade& facade, auto cb)
    { facade.read_modified_async(node(11), full_range(), options, std::move(cb)); });
  ASSERT_TRUE(result.is_good());

  const auto* details = dynamic_cast<const ua::ReadRawModifiedDetails*>(
    f.wireOps->historyReadRequests[0].history_read_details().get());
  ASSERT_NE(details, nullptr);
  EXPECT_TRUE(details->is_read_modified());
  EXPECT_FALSE(details->return_bounds()) << "CL-HIST-007: modified hard-codes returnBounds=false";
}

// @verifies CL-HIST-016
// @relation(CL-HIST-016, scope=function)
TEST(HistoryFacade, ReadAtTimeComposesReadAtTimeDetailsPreservingOrder)
{
  Fixture f;
  f.wireOps->historyReadPages.push_back({{dv(3)}, ua::ContinuationPoint{}, {}});
  std::vector<ua::DateTime> times{instant(3.0), instant(1.0), instant(2.0)};

  auto result = f.drain_read([times](HistoryFacade& facade, auto cb)
    { facade.read_at_time_async(node(11), times, {}, std::move(cb)); });
  ASSERT_TRUE(result.is_good());

  const auto* details = dynamic_cast<const ua::ReadAtTimeDetails*>(
    f.wireOps->historyReadRequests[0].history_read_details().get());
  ASSERT_NE(details, nullptr) << "read_at_time must compose a ReadAtTimeDetails";
  ASSERT_EQ(details->req_times().size(), 3u);
  EXPECT_EQ(details->req_times()[0], instant(3.0)) << "CL-HIST-016: request timestamp order preserved";
  EXPECT_EQ(details->req_times()[1], instant(1.0));
  EXPECT_EQ(details->req_times()[2], instant(2.0));
}

// @verifies CL-HIST-005
// @relation(CL-HIST-005, scope=function)
TEST(HistoryFacade, ReadProcessedComposesSingleAggregateReadProcessedDetails)
{
  Fixture f;
  f.wireOps->historyReadPages.push_back({{dv(4)}, ua::ContinuationPoint{}, {}});

  auto result = f.drain_read([](HistoryFacade& facade, auto cb)
    { facade.read_processed_async(node(11), full_range(), node(2342), 1000.0, {}, std::move(cb)); });
  ASSERT_TRUE(result.is_good());

  const auto* details = dynamic_cast<const ua::ReadProcessedDetails*>(
    f.wireOps->historyReadRequests[0].history_read_details().get());
  ASSERT_NE(details, nullptr) << "read_processed must compose a ReadProcessedDetails";
  ASSERT_EQ(details->aggregate_type().size(), 1u) << "CL-HIST-005: a single aggregate per call";
  EXPECT_EQ(details->aggregate_type()[0], node(2342));
  EXPECT_DOUBLE_EQ(details->processing_interval(), 1000.0);
}

// The AggregateFunction may be vendor-defined and browsed from the server's AggregateFunctions folder; the
// client must pass the caller's NodeId through unchanged rather than constrain it to NS0 constants.
// @verifies CL-HIST-006
// @relation(CL-HIST-006, scope=function)
TEST(HistoryFacade, ReadProcessedPreservesVendorAggregateNodeId)
{
  Fixture f;
  f.wireOps->historyReadPages.push_back({{dv(4)}, ua::ContinuationPoint{}, {}});
  const ua::NodeId vendorAggregate{2, 9001};

  auto result = f.drain_read([&vendorAggregate](HistoryFacade& facade, auto cb)
    { facade.read_processed_async(node(11), full_range(), vendorAggregate, 1000.0, {}, std::move(cb)); });
  ASSERT_TRUE(result.is_good());

  const auto* details = dynamic_cast<const ua::ReadProcessedDetails*>(
    f.wireOps->historyReadRequests[0].history_read_details().get());
  ASSERT_NE(details, nullptr);
  ASSERT_EQ(details->aggregate_type().size(), 1U);
  EXPECT_EQ(details->aggregate_type()[0], vendorAggregate);
}

// CL-HIST-014: a processed read with default options sends useServerCapabilitiesDefaults=true, so the server
// applies its own configured aggregate defaults and the per-call fields stay inert. @verifies CL-HIST-014
TEST(HistoryFacade, ReadProcessedDefaultAggregateConfigUsesServerCapabilitiesDefaults)
{
  Fixture f;
  f.wireOps->historyReadPages.push_back({{dv(4)}, ua::ContinuationPoint{}, {}});

  auto result = f.drain_read([](HistoryFacade& facade, auto cb)
    { facade.read_processed_async(node(11), full_range(), node(2342), 1000.0, {}, std::move(cb)); });
  ASSERT_TRUE(result.is_good());

  const auto* details = dynamic_cast<const ua::ReadProcessedDetails*>(
    f.wireOps->historyReadRequests[0].history_read_details().get());
  ASSERT_NE(details, nullptr);
  EXPECT_TRUE(details->aggregate_configuration().use_server_capabilities_defaults())
    << "an unset override must defer to the server's aggregate defaults (override inert)";
}

// CL-HIST-014: a per-call AggregateConfiguration override is plumbed to the wire ReadProcessedDetails
// verbatim.
// @verifies CL-HIST-014
// @relation(CL-HIST-014, scope=function)
TEST(HistoryFacade, ReadProcessedAggregateConfigOverridePlumbedToWire)
{
  Fixture f;
  f.wireOps->historyReadPages.push_back({{dv(4)}, ua::ContinuationPoint{}, {}});

  HistoryReadOptions options;
  ua::AggregateConfiguration config;
  config.use_server_capabilities_defaults() = false;
  config.treat_uncertain_as_bad() = false;
  config.percent_data_bad() = 50;
  options.aggregateConfiguration = config;

  auto result = f.drain_read([options](HistoryFacade& facade, auto cb)
    { facade.read_processed_async(node(11), full_range(), node(2342), 1000.0, options, std::move(cb)); });
  ASSERT_TRUE(result.is_good());

  const auto* details = dynamic_cast<const ua::ReadProcessedDetails*>(
    f.wireOps->historyReadRequests[0].history_read_details().get());
  ASSERT_NE(details, nullptr);
  const auto& wire = details->aggregate_configuration();
  EXPECT_FALSE(wire.use_server_capabilities_defaults())
    << "the override must reach the wire, not the default";
  EXPECT_FALSE(wire.treat_uncertain_as_bad());
  EXPECT_EQ(wire.percent_data_bad(), 50);
}

// CL-HIST-014: a server that rejects the per-call override returns Bad_AggregateConfigurationRejected, which
// the reader surfaces with a dedicated source and a remediation hint (retry with
// useServerCapabilitiesDefaults=true). @verifies CL-HIST-014
TEST(HistoryFacade, ReadProcessedAggregateConfigRejectedSurfacesHint)
{
  Fixture f;
  // Inject the rejection WITH an info bit set (SemanticsChanged): Part 4 section 7.34 permits info bits on
  // any StatusCode, so the special-case must match on the BASE status (as_status, info bits masked), not the
  // raw 32-bit value - otherwise the aggregate-specific remediation hint is silently lost.
  ua::StatusCode rejected{ua::Status::BadAggregateConfigurationRejected};
  rejected.semantics_changed(true);
  f.wireOps->historyReadPages.push_back({{}, ua::ContinuationPoint{}, rejected});

  HistoryReadOptions options;
  ua::AggregateConfiguration config;
  config.use_server_capabilities_defaults() = false;
  config.percent_data_bad() = 50;
  options.aggregateConfiguration = config;

  auto result = f.drain_read([options](HistoryFacade& facade, auto cb)
    { facade.read_processed_async(node(11), full_range(), node(2342), 1000.0, options, std::move(cb)); });
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadAggregateConfigurationRejected);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier2.history_reader.aggregate_config_rejected");
  EXPECT_NE(result.shared_detail()->summary.find("useServerCapabilitiesDefaults"), std::string::npos)
    << "the rejection must carry the fallback remediation hint";
}

// @verifies CL-HIST-015
// @relation(CL-HIST-015, scope=function)
TEST(HistoryFacade, ReadAnnotationsComposesReadAnnotationDataDetails)
{
  Fixture f;
  f.wireOps->historyReadPages.push_back({{dv(5)}, ua::ContinuationPoint{}, {}});
  std::vector<ua::DateTime> times{instant(1.0)};

  auto result = f.drain_read([times](HistoryFacade& facade, auto cb)
    { facade.read_annotations_async(node(11), times, {}, std::move(cb)); });
  ASSERT_TRUE(result.is_good());

  const auto* details = dynamic_cast<const ua::ReadAnnotationDataDetails*>(
    f.wireOps->historyReadRequests[0].history_read_details().get());
  ASSERT_NE(details, nullptr) << "CL-HIST-015: read_annotations composes ReadAnnotationDataDetails";
  ASSERT_EQ(details->req_times().size(), 1u);
}

// ===========================================================================
// Reads - caller-side pre-flight rejection (CL-HIST-003 / -004 / -010)
// ===========================================================================

// @verifies CL-HIST-003
// @relation(CL-HIST-003, scope=function)
TEST(HistoryFacade, ReadRawRejectsFewerThanTwoRangeParamsInline)
{
  Fixture f;
  TimeRange onlyStart;
  onlyStart.startTime = instant(0.0);  // one of three specified => reject

  auto result = f.drain_read([onlyStart](HistoryFacade& facade, auto cb)
    { facade.read_raw_async(node(11), onlyStart, {}, std::move(cb)); });
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadInvalidArgument});
  EXPECT_TRUE(f.wireOps->historyReadRequests.empty()) << "CL-HIST-003: rejected before any wire round-trip";
}

// @verifies CL-HIST-004
// @relation(CL-HIST-004, scope=function)
TEST(HistoryFacade, ReadProcessedRejectsUnspecifiedEndInline)
{
  Fixture f;
  TimeRange onlyStart;
  onlyStart.startTime = instant(0.0);  // endTime unspecified => reject

  auto result = f.drain_read([onlyStart](HistoryFacade& facade, auto cb)
    { facade.read_processed_async(node(11), onlyStart, node(2342), 1000.0, {}, std::move(cb)); });
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadInvalidArgument});
  EXPECT_TRUE(f.wireOps->historyReadRequests.empty());
}

// @verifies CL-HIST-004
// @relation(CL-HIST-004, scope=function)
TEST(HistoryFacade, ReadProcessedRejectsEqualStartEndInline)
{
  Fixture f;
  TimeRange equal;
  equal.startTime = instant(5.0);
  equal.endTime = instant(5.0);  // start == end => reject

  auto result = f.drain_read([equal](HistoryFacade& facade, auto cb)
    { facade.read_processed_async(node(11), equal, node(2342), 1000.0, {}, std::move(cb)); });
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadInvalidArgument});
  EXPECT_TRUE(f.wireOps->historyReadRequests.empty());
}

// @verifies CL-HIST-010
// @relation(CL-HIST-010, scope=function)
TEST(HistoryFacade, ReadRejectsNeitherTimestampsInline)
{
  Fixture f;
  HistoryReadOptions options;
  options.timestampsToReturn = ua::TimestampsToReturn::Neither;

  auto result = f.drain_read([options](HistoryFacade& facade, auto cb)
    { facade.read_raw_async(node(11), full_range(), options, std::move(cb)); });
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadInvalidTimestampArgument});
  EXPECT_TRUE(f.wireOps->historyReadRequests.empty());
}

// ===========================================================================
// Reads - two-layer status mapping (CL-HIST-011 / -012)
// ===========================================================================

// @verifies CL-HIST-011
// @relation(CL-HIST-011, scope=function)
TEST(HistoryFacade, PerNodeGoodNoDataYieldsEmptyGoodCursor)
{
  Fixture f;
  f.wireOps->historyReadPages.push_back(
    {{}, ua::ContinuationPoint{}, ua::StatusCode{ua::Status::GoodNoData}});

  auto result = f.drain_read(
    [](HistoryFacade& facade, auto cb) { facade.read_raw_async(node(11), full_range(), {}, std::move(cb)); });
  ASSERT_TRUE(result.is_good()) << "CL-HIST-011: Good_NoData is a good (empty) cursor, not a bad Result";
  HistoryReadCursor cursor = std::move(result.value());
  EXPECT_TRUE(cursor.has_more()) << "the buffered (empty) first page has not yet been delivered";

  auto page = f.next(cursor);
  ASSERT_TRUE(page.is_good());
  EXPECT_TRUE(page.value().empty()) << "the first next yields Good + empty vector";
  EXPECT_FALSE(cursor.has_more());
}

// @verifies CL-HIST-011
// @relation(CL-HIST-011, scope=function)
TEST(HistoryFacade, PerNodeBadYieldsBadCursorResult)
{
  Fixture f;
  f.wireOps->historyReadPages.push_back({{}, ua::ContinuationPoint{}, ua::StatusCode{ua::Status::BadNoData}});

  auto result = f.drain_read(
    [](HistoryFacade& facade, auto cb) { facade.read_raw_async(node(11), full_range(), {}, std::move(cb)); });
  EXPECT_TRUE(result.is_bad()) << "CL-HIST-011: a whole-node Bad surfaces as a bad Result<HistoryReadCursor>";
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadNoData});
}

// @verifies CL-HIST-011
// @relation(CL-HIST-011, scope=function)
TEST(HistoryFacade, ReadTransportFailurePropagates)
{
  Fixture f;
  f.wireOps->historyReadServiceStatus = ua::StatusCode{ua::Status::BadServerNotConnected};

  auto result = f.drain_read(
    [](HistoryFacade& facade, auto cb) { facade.read_raw_async(node(11), full_range(), {}, std::move(cb)); });
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadServerNotConnected})
    << "a transport-level failure surfaces to the caller";
}

// @verifies CL-HIST-012
// @relation(CL-HIST-012, scope=function)
TEST(HistoryFacade, PerValueStatusPreservedVerbatimInPage)
{
  Fixture f;
  // A per-value Bad_BoundNotFound tuple must ride through as value-quality inside a GOOD cursor page - NOT be
  // promoted to a Result failure (CL-HIST-012 / section 8.9.4).
  ua::DataValue boundTuple;
  boundTuple.status() = ua::StatusCode{ua::Status::BadBoundNotFound};
  f.wireOps->historyReadPages.push_back({{dv(7), boundTuple}, ua::ContinuationPoint{}, {}});

  auto result = f.drain_read(
    [](HistoryFacade& facade, auto cb) { facade.read_raw_async(node(11), full_range(), {}, std::move(cb)); });
  ASSERT_TRUE(result.is_good());
  HistoryReadCursor cursor = std::move(result.value());

  auto page = f.next(cursor);
  ASSERT_TRUE(page.is_good());
  ASSERT_EQ(page.value().size(), 2u);
  ASSERT_TRUE(page.value()[1].status().has_value());
  EXPECT_EQ(page.value()[1].status().value(), ua::StatusCode{ua::Status::BadBoundNotFound})
    << "the per-value StatusCode is preserved verbatim (two-layer model)";
}

// ===========================================================================
// HistoryReadCursor - paging, has_more, close/destructor release, gone bail
// ===========================================================================

// Builds a cursor directly over the fake interface so the paging path can be exercised precisely.
HistoryReadCursor make_cursor(Fixture& f, std::vector<ua::DataValue> firstPage, bool firstPagePending,
  ua::ContinuationPoint continuationPoint)
{
  return HistoryFacadeTestAccess::make_cursor(f.wireOps,
    f.ctx.get_executor(),
    node(11),
    raw_details_snapshot(),
    ua::TimestampsToReturn::Source,
    std::move(firstPage),
    firstPagePending,
    std::move(continuationPoint));
}

// @verifies CL-HIST-008
// @relation(CL-HIST-008, scope=function)
TEST(HistoryReadCursor, MultiPageDrivesContinuationRead)
{
  Fixture f;
  const ua::ContinuationPoint cp1{0x01};
  f.wireOps->historyReadPages.push_back({{dv(2)}, ua::ContinuationPoint{}, {}});  // the continuation page

  auto cursor = make_cursor(f, {dv(1)}, /*firstPagePending=*/true, cp1);
  EXPECT_TRUE(cursor.has_more());

  auto first = f.next(cursor);
  ASSERT_TRUE(first.is_good());
  ASSERT_EQ(first.value().size(), 1u);
  EXPECT_EQ(first.value()[0].value(), ua::Variant{std::int32_t{1}});
  EXPECT_TRUE(cursor.has_more()) << "a continuation point is held after the first page";

  auto second = f.next(cursor);
  ASSERT_TRUE(second.is_good());
  ASSERT_EQ(second.value().size(), 1u);
  EXPECT_EQ(second.value()[0].value(), ua::Variant{std::int32_t{2}}) << "page 2 fetched via continuation";

  ASSERT_EQ(f.wireOps->historyReadRequests.size(), 1u);
  EXPECT_FALSE(f.wireOps->historyReadRequests[0].release_continuation_points())
    << "a data read (CL-HIST-008)";
  ASSERT_EQ(f.wireOps->historyReadRequests[0].nodes_to_read().size(), 1u);
  EXPECT_EQ(f.wireOps->historyReadRequests[0].nodes_to_read()[0].continuation_point(), cp1)
    << "the cached continuation point is re-sent";
  EXPECT_FALSE(cursor.has_more()) << "drained after the final page";
}

// Public API review D1 (API-D1.1): Part 11 section 6.3 lets a server return no values with a continuation
// point (for example when the calculation is approaching the timeout). The cursor asks again itself, so the
// caller never sees an empty page while more data is coming: an empty page it delivers means the history is
// exhausted.
// @verifies CL-HIST-008
// @relation(CL-HIST-008, scope=function)
TEST(HistoryReadCursor, AnEmptyPageWithAContinuationPointIsAskedAgainNotDelivered)
{
  Fixture f;
  const ua::ContinuationPoint cp1{0x01};
  f.wireOps->historyReadPages.push_back({{}, cp1, {}});  // the continuation answers with nothing yet
  f.wireOps->historyReadPages.push_back({{dv(2)}, ua::ContinuationPoint{}, {}});

  auto cursor = make_cursor(f, {}, /*firstPagePending=*/true, cp1);  // the initial read was empty too
  auto first = f.next(cursor);
  ASSERT_TRUE(first.is_good());
  ASSERT_EQ(first.value().size(), 1u) << "the empty pages are not delivered";
  EXPECT_EQ(first.value()[0].value(), ua::Variant{std::int32_t{2}});
  EXPECT_EQ(f.wireOps->historyReadRequests.size(), 2u);
  EXPECT_FALSE(cursor.has_more());
}

// API-D1.2: ten empty pages in a row are asked again; the eleventh fails next with Bad_Timeout and the count,
// and the continuation point is released.
TEST(HistoryReadCursor, OneMoreEmptyPageThanTheLimitFailsWithTimeoutAndReleasesThePoint)
{
  Fixture f;
  const ua::ContinuationPoint cp1{0x01};
  for (int page = 0; page < 11; ++page)
  {
    f.wireOps->historyReadPages.push_back({{}, cp1, {}});
  }
  auto cursor = make_cursor(f, {dv(1)}, /*firstPagePending=*/true, cp1);
  ASSERT_TRUE(f.next(cursor).is_good());

  auto stalled = f.next(cursor);
  ASSERT_TRUE(stalled.is_bad());
  EXPECT_EQ(stalled.status_code().as_status(), ua::Status::BadTimeout);
  ASSERT_NE(stalled.status_code().shared_detail(), nullptr);
  EXPECT_EQ(stalled.status_code().shared_detail()->code, "HistoryCursorEmptyPageLimitExceeded");
  ASSERT_EQ(f.wireOps->historyReadRequests.size(), 12u) << "eleven reads, then one release";
  EXPECT_TRUE(f.wireOps->historyReadRequests.back().release_continuation_points());
  EXPECT_FALSE(cursor.has_more());
}

TEST(HistoryReadCursor, TenEmptyPagesThenValuesAreDelivered)
{
  Fixture f;
  const ua::ContinuationPoint cp1{0x01};
  for (int page = 0; page < 10; ++page)
  {
    f.wireOps->historyReadPages.push_back({{}, cp1, {}});
  }
  f.wireOps->historyReadPages.push_back({{dv(5)}, ua::ContinuationPoint{}, {}});
  auto cursor = make_cursor(f, {dv(1)}, /*firstPagePending=*/true, cp1);
  ASSERT_TRUE(f.next(cursor).is_good());

  auto second = f.next(cursor);
  ASSERT_TRUE(second.is_good()) << ua::to_string(second.status_code());
  ASSERT_EQ(second.value().size(), 1u);
  EXPECT_EQ(second.value()[0].value(), ua::Variant{std::int32_t{5}});
}

TEST(HistoryReadCursor, TheLimitComesFromTheHistoryReadOptions)
{
  Fixture f;
  const ua::ContinuationPoint cp1{0x01};
  for (int page = 0; page < 3; ++page)
  {
    f.wireOps->historyReadPages.push_back({{}, cp1, {}});  // the initial read and two continuations
  }
  f.wireOps->historyReadPages.push_back({{dv(5)}, ua::ContinuationPoint{}, {}});
  HistoryReadOptions options;
  options.continuationLimits.maxConsecutiveEmptyPages = 1;

  auto cursor = f.drain_read([&options](HistoryFacade& facade, auto callback)
    { facade.read_raw_async(node(11), full_range(), options, std::move(callback)); });
  ASSERT_TRUE(cursor.is_good());
  auto first = f.next(cursor.value());
  ASSERT_TRUE(first.is_bad()) << "two empty pages in a row exceed a limit of one";
  EXPECT_EQ(first.status_code().as_status(), ua::Status::BadTimeout);
}

// @verifies CL-HIST-013
// @relation(CL-HIST-013, scope=function)
TEST(HistoryReadCursor, ContinuationResendsDetailsVerbatim)
{
  Fixture f;
  const ua::ContinuationPoint cp1{0x01};
  f.wireOps->historyReadPages.push_back({{dv(2)}, ua::ContinuationPoint{}, {}});

  auto cursor = make_cursor(f, {dv(1)}, /*firstPagePending=*/true, cp1);
  (void)f.next(cursor);  // deliver the buffered first page
  (void)f.next(cursor);  // drives the continuation read

  ASSERT_EQ(f.wireOps->historyReadRequests.size(), 1u);
  const auto* details = dynamic_cast<const ua::ReadRawModifiedDetails*>(
    f.wireOps->historyReadRequests[0].history_read_details().get());
  EXPECT_NE(details, nullptr) << "CL-HIST-013: the original details are re-sent verbatim on continuation";
}

// @verifies CL-HIST-011
// @relation(CL-HIST-011, scope=function)
TEST(HistoryReadCursor, DrainedCursorNextReturnsGoodEmpty)
{
  Fixture f;
  auto cursor = make_cursor(f, {dv(1)}, /*firstPagePending=*/true, ua::ContinuationPoint{});
  auto first = f.next(cursor);
  ASSERT_TRUE(first.is_good());
  EXPECT_FALSE(cursor.has_more());

  auto second = f.next(cursor);
  ASSERT_TRUE(second.is_good()) << "a drained cursor's next yields Good + empty (not Bad)";
  EXPECT_TRUE(second.value().empty());
  EXPECT_TRUE(f.wireOps->historyReadRequests.empty()) << "no wire read once drained";
}

// @verifies CL-HIST-008
// @relation(CL-HIST-008, scope=function)
TEST(HistoryReadCursor, ContinuationInvalidClearsContinuationPoint)
{
  Fixture f;
  const ua::ContinuationPoint cp1{0x01};
  f.wireOps->historyReadPages.push_back(
    {{}, ua::ContinuationPoint{}, ua::StatusCode{ua::Status::BadContinuationPointInvalid}});

  auto cursor = make_cursor(f, {dv(1)}, /*firstPagePending=*/true, cp1);
  (void)f.next(cursor);  // deliver first page (CP still held)
  auto second = f.next(cursor);
  EXPECT_TRUE(second.is_bad());
  EXPECT_EQ(second.status_code(), ua::StatusCode{ua::Status::BadContinuationPointInvalid});
  EXPECT_FALSE(cursor.has_more()) << "CL-HIST-008: a bad continuation clears the CP (no auto-retry)";
}

// @verifies CL-HIST-009
// @relation(CL-HIST-009, scope=function)
TEST(HistoryReadCursor, CloseReleasesContinuationPoint)
{
  Fixture f;
  const ua::ContinuationPoint cp1{0x0A, 0x0B};
  auto cursor = make_cursor(f, {dv(1)}, /*firstPagePending=*/false, cp1);

  bool closed = false;
  cursor.close_async([&closed](ua::VoidResult result) { closed = result.is_good(); });
  f.ctx.run();
  EXPECT_TRUE(closed);
  ASSERT_EQ(f.wireOps->historyReadRequests.size(), 1u);
  EXPECT_TRUE(f.wireOps->historyReadRequests[0].release_continuation_points())
    << "CL-HIST-009: close issues a release-only HistoryRead";
  ASSERT_EQ(f.wireOps->historyReadRequests[0].nodes_to_read().size(), 1u);
  EXPECT_EQ(f.wireOps->historyReadRequests[0].nodes_to_read()[0].continuation_point(), cp1);
}

// @verifies CL-HIST-009
// @relation(CL-HIST-009, scope=function)
TEST(HistoryReadCursor, DestructorReleasesContinuationPoint)
{
  Fixture f;
  const ua::ContinuationPoint cp1{0x0A};
  {
    auto cursor = make_cursor(f, {dv(1)}, /*firstPagePending=*/false, cp1);
  }  // ~HistoryReadCursor posts a release-only HistoryRead (fire-and-forget, synchronous in the fake)
  ASSERT_EQ(f.wireOps->historyReadRequests.size(), 1u);
  EXPECT_TRUE(f.wireOps->historyReadRequests[0].release_continuation_points());
}

// @verifies CL-HIST-009
// @relation(CL-HIST-009, scope=function)
TEST(HistoryReadCursor, DestructorWithoutContinuationPointIssuesNoRelease)
{
  Fixture f;
  {
    auto cursor = make_cursor(f, {dv(1)}, /*firstPagePending=*/false, ua::ContinuationPoint{});
  }
  EXPECT_TRUE(f.wireOps->historyReadRequests.empty()) << "nothing to release => no HistoryRead (idempotent)";
}

// Robustness (no requirement): the wire-interface-gone bail is a lifetime guard (section 8.9 gone path).
TEST(HistoryReadCursor, WireOpsGoneNextBailsCleanly)
{
  Fixture f;
  auto cursor = make_cursor(f, {}, /*firstPagePending=*/false, ua::ContinuationPoint{0x01});
  f.wireOps.reset();  // the Connection (and its wire interface) is gone

  auto result = f.next(cursor);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadConnectionClosed})
    << "a dropped Connection completes the advance with a boundary failure, not a deref";
}

// @verifies CL-HIST-009
// @relation(CL-HIST-009, scope=function)
TEST(HistoryReadCursor, WireOpsGoneCloseBailsCleanly)
{
  Fixture f;
  auto cursor = make_cursor(f, {dv(1)}, /*firstPagePending=*/false, ua::ContinuationPoint{0x0A});
  f.wireOps.reset();  // interface gone before close

  bool closed = false;
  cursor.close_async([&closed](ua::VoidResult result) { closed = result.is_good(); });
  f.ctx.run();
  EXPECT_TRUE(closed) << "close is best-effort: Good when there is nothing to free server-side";
}

// @verifies CL-HIST-009
// W1: a Bad best-effort continuation-point release must be LOGGED at the wire boundary (Warning, source-
// tagged), never silently discarded. Falsifiability: the pre-fix empty completion lambda logs nothing, so
// has_warning_containing() would be false.
// @relation(CL-HIST-009, scope=function)
TEST(HistoryReadCursor, ReleaseFailureLoggedAsWarning)
{
  Fixture f;
  auto sink = std::make_shared<RecordingLogSink>();
  f.wireOps->historyReadServiceStatus = ua::StatusCode{ua::Status::BadServerNotConnected};  // release -> Bad

  {
    // A cursor holding a continuation point, carrying a logger over the recording sink.
    auto cursor = ua::client::detail::HistoryFacadeTestAccess::make_cursor(f.wireOps,
      f.ctx.get_executor(),
      node(11),
      raw_details_snapshot(),
      ua::TimestampsToReturn::Source,
      {dv(1)},
      /*firstPagePending=*/false,
      ua::ContinuationPoint{0x0A},
      make_logger(sink));
  }  // ~HistoryReadCursor issues a release-only HistoryRead which the fake completes Bad (inline)

  ASSERT_EQ(f.wireOps->historyReadRequests.size(), 1u);
  EXPECT_TRUE(f.wireOps->historyReadRequests[0].release_continuation_points());
  EXPECT_TRUE(sink->has_warning_containing("client.tier2.history_reader.release_continuation_point"))
    << "CL-HIST-009/section 8.9.6: a Bad best-effort release is logged at Warning with the source tag";
}

// @verifies CL-HIST-009
// W2: a continuation advance that completes AFTER close_async marked the cursor closed must release the FRESH
// continuation point it returned (so it is not leaked into a closed cursor) and complete the advance as
// BadInvalidState. Falsifiability: a branch that stored the fresh CP into the closed cursor would issue no
// fresh release; one that reported Good would fail the status assert.
// @relation(CL-HIST-009, scope=function)
TEST(HistoryReadCursor, CloseRacesInFlightAdvanceReleasesFreshContinuationPoint)
{
  Fixture f;
  f.wireOps->deferHistoryRead = true;  // capture the advance completion so close can race it
  const ua::ContinuationPoint cp1{0x01};
  const ua::ContinuationPoint freshCp{0x02, 0x03};
  f.wireOps->historyReadPages.push_back({{dv(5)}, freshCp, {}});  // the deferred advance returns a FRESH CP

  auto cursor = make_cursor(f, {}, /*firstPagePending=*/false, cp1);

  std::optional<ua::Result<std::vector<ua::DataValue>>> advanceResult;
  cursor.next_async([&advanceResult](ua::Result<std::vector<ua::DataValue>> result)
    { advanceResult = std::move(result); });  // deferred: still in flight

  bool closed = false;
  cursor.close_async([&closed](ua::VoidResult result)
    { closed = result.is_good(); });  // marks closed; release of cp1 also deferred

  f.wireOps->fire_deferred_history_reads();  // the advance completes AFTER close -> closed-race branch
  f.ctx.run();

  ASSERT_TRUE(advanceResult.has_value());
  EXPECT_TRUE(advanceResult->is_bad());
  EXPECT_EQ(advanceResult->status_code(), ua::StatusCode{ua::Status::BadInvalidState})
    << "an advance that completes after close reports BadInvalidState";

  bool freshReleaseIssued = false;
  for (const auto& request : f.wireOps->historyReadRequests)
  {
    if (request.release_continuation_points() && !request.nodes_to_read().empty() &&
        request.nodes_to_read()[0].continuation_point() == freshCp)
    {
      freshReleaseIssued = true;
    }
  }
  EXPECT_TRUE(freshReleaseIssued)
    << "the fresh continuation point handed back by the raced advance is released, not leaked into a closed "
       "cursor";
  EXPECT_TRUE(closed);
}

// The section 7.0 sync triple over next_async (exercises try_next_sync on a background-run executor).
TEST(HistoryReadCursor, TryNextSyncReturnsPage)
{
  Fixture f;
  auto cursor = make_cursor(f, {dv(9)}, /*firstPagePending=*/true, ua::ContinuationPoint{});

  auto work = boost::asio::make_work_guard(f.ctx);
  std::thread runner([&f] { f.ctx.run(); });

  auto result = cursor.try_next_sync();
  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().size(), 1u);
  EXPECT_EQ(result.value()[0].value(), ua::Variant{std::int32_t{9}});

  work.reset();
  runner.join();
}

// Handle hygiene (no requirement): a moved-from cursor fails fast rather than dereferencing null.
TEST(HistoryReadCursor, MovedFromCursorNextReturnsBad)
{
  Fixture f;
  auto cursor = make_cursor(f, {dv(1)}, /*firstPagePending=*/true, ua::ContinuationPoint{});
  HistoryReadCursor moved = std::move(cursor);

  std::optional<ua::Result<std::vector<ua::DataValue>>> captured;
  cursor.next_async(  // NOLINT(bugprone-use-after-move) - deliberately exercising the moved-from guard
    [&captured](ua::Result<std::vector<ua::DataValue>> result) { captured = std::move(result); });
  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code(), ua::StatusCode{ua::Status::BadInvalidState});
}

// ===========================================================================
// Updates - detail composition + two-layer status (CL-HIST-017..019 / -021 / -023)
// ===========================================================================

// @verifies CL-HIST-020
// @relation(CL-HIST-020, scope=function)
TEST(HistoryFacadeUpdatePreflight, HistoryWriteClearRejectsWithoutHistoryUpdate)
{
  Fixture f;
  f.wireOps->scriptedReadResponses.push_back(
    access_level_response(ua::AccessLevelType{ua::AccessLevelType::Bit::CurrentRead}.as_underlying_type()));

  auto result = f.drain_update([](HistoryFacade& facade, auto callback)
    { facade.insert_data_async(node(11), {dv(1)}, std::move(callback)); },
    false);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadHistoryOperationUnsupported);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "HistoryWriteNotAdvertised");
  EXPECT_TRUE(f.wireOps->historyUpdateRequests.empty());
  EXPECT_EQ(f.wireOps->readRequests.size(), 1u);
}

// @verifies CL-HIST-020
// @relation(CL-HIST-020, scope=function)
TEST(HistoryFacadeUpdatePreflight, EveryUpdateFlavourChecksItsMatchingCapability)
{
  using Invoke = std::function<void(HistoryFacade&, std::function<void(ua::Result<HistoryUpdateResult>)>)>;

  struct Case
  {
    std::size_t falseFlag;
    std::string_view capabilityName;
    Invoke invoke;
  };

  const std::vector<Case> cases{{0,
                                  "InsertDataCapability",
                                  [](HistoryFacade& facade, auto callback)
                                  {
                                    facade.insert_data_async(node(11), {dv(1)}, std::move(callback));
                                  }},
    {1,
      "ReplaceDataCapability",
      [](HistoryFacade& facade, auto callback)
      {
        facade.replace_data_async(node(11), {dv(1)}, std::move(callback));
      }},
    {2,
      "UpdateDataCapability",
      [](HistoryFacade& facade, auto callback)
      {
        facade.update_data_async(node(11), {dv(1)}, ua::PerformUpdateType::Update, std::move(callback));
      }},
    {3,
      "DeleteRawCapability",
      [](HistoryFacade& facade, auto callback)
      {
        facade.delete_raw_modified_async(node(11), full_range(), false, std::move(callback));
      }},
    {4,
      "DeleteAtTimeCapability",
      [](HistoryFacade& facade, auto callback)
      {
        facade.delete_at_time_async(node(11), {instant(1.0)}, std::move(callback));
      }}};

  for (const auto& testCase : cases)
  {
    Fixture f;
    f.wireOps->scriptedReadResponses.push_back(access_level_response(
      ua::AccessLevelType{ua::AccessLevelType::Bit::HistoryWrite}.as_underlying_type()));
    std::array flags{true, true, true, true, true};
    flags[testCase.falseFlag] = false;
    f.wireOps->scriptedReadResponses.push_back(history_capabilities_response(flags));

    auto result = f.drain_update(testCase.invoke, false);

    ASSERT_TRUE(result.is_bad()) << testCase.capabilityName;
    EXPECT_EQ(result.status_code().as_status(), ua::Status::BadHistoryOperationUnsupported);
    ASSERT_NE(result.shared_detail(), nullptr);
    EXPECT_EQ(result.shared_detail()->code, "HistoryUpdateCapabilityMissing");
    EXPECT_EQ(
      ::ua::test_utils::error_context(result.shared_detail().get(), ua::ContextKeys::fieldName.value()),
      testCase.capabilityName);
    EXPECT_EQ(
      ::ua::test_utils::error_context(result.shared_detail().get(), ua::ContextKeys::actual.value()), "0");
    EXPECT_TRUE(f.wireOps->historyUpdateRequests.empty());
  }
}

// @verifies CL-HIST-020
// @relation(CL-HIST-020, scope=function)
TEST(HistoryFacadeUpdatePreflight, AttributeAndCapabilitiesAreCachedAcrossFiveUpdates)
{
  Fixture f;
  f.wireOps->scriptedReadResponses.push_back(
    access_level_response(ua::AccessLevelType{ua::AccessLevelType::Bit::HistoryWrite}.as_underlying_type()));
  f.wireOps->scriptedReadResponses.push_back(history_capabilities_response({true, true, true, true, true}));
  auto facade = f.facade();

  const auto run = [&](const auto& invoke)
  {
    std::optional<ua::Result<HistoryUpdateResult>> captured;
    invoke(facade, [&captured](ua::Result<HistoryUpdateResult> result) { captured = std::move(result); });
    f.ctx.run();
    f.ctx.restart();
    ASSERT_TRUE(captured.has_value());
    ASSERT_TRUE(captured->is_good());
  };
  run([](HistoryFacade& history, auto callback)
    { history.insert_data_async(node(11), {dv(1)}, std::move(callback)); });
  run([](HistoryFacade& history, auto callback)
    { history.replace_data_async(node(11), {dv(1)}, std::move(callback)); });
  run([](HistoryFacade& history, auto callback)
    { history.update_data_async(node(11), {dv(1)}, ua::PerformUpdateType::Update, std::move(callback)); });
  run([](HistoryFacade& history, auto callback)
    { history.delete_raw_modified_async(node(11), full_range(), false, std::move(callback)); });
  run([](HistoryFacade& history, auto callback)
    { history.delete_at_time_async(node(11), {instant(1.0)}, std::move(callback)); });

  EXPECT_EQ(f.wireOps->readRequests.size(), 2u)
    << "one AccessLevel Read plus one five-flag HistoryServerCapabilities Read";
  EXPECT_EQ(f.wireOps->historyUpdateRequests.size(), 5u);
  ASSERT_EQ(f.wireOps->readRequests[1].nodes_to_read().size(), 5u);
  EXPECT_EQ(f.wireOps->readRequests[1].nodes_to_read()[0].node_id(),
    ua::NodeId{ua::VariableId::HistoryServerCapabilities_InsertDataCapability});
  EXPECT_EQ(f.wireOps->readRequests[1].nodes_to_read()[4].node_id(),
    ua::NodeId{ua::VariableId::HistoryServerCapabilities_DeleteAtTimeCapability});
}

// @verifies CL-HIST-020
// @relation(CL-HIST-020, scope=function)
TEST(HistoryFacadeUpdatePreflight, ConcurrentColdCallsShareOneCapabilityLoad)
{
  Fixture f;
  f.wireOps->scriptedReadResponses.push_back(
    access_level_response(ua::AccessLevelType{ua::AccessLevelType::Bit::HistoryWrite}.as_underlying_type()));
  auto facade = f.facade();
  std::optional<ua::Result<bool>> primed;
  facade.is_history_writable_async(
    node(11), [&primed](ua::Result<bool> result) { primed = std::move(result); });
  f.ctx.run();
  f.ctx.restart();
  ASSERT_TRUE(primed.has_value());
  ASSERT_TRUE(primed->is_good());

  f.wireOps->scriptedReadResponses.push_back(history_capabilities_response({true, true, true, true, true}));
  f.wireOps->deferReads = true;
  std::size_t completions = 0;
  facade.insert_data_async(node(11),
    {dv(1)},
    [&completions](ua::Result<HistoryUpdateResult> result)
    {
      EXPECT_TRUE(result.is_good());
      ++completions;
    });
  facade.insert_data_async(node(11),
    {dv(2)},
    [&completions](ua::Result<HistoryUpdateResult> result)
    {
      EXPECT_TRUE(result.is_good());
      ++completions;
    });
  f.ctx.run();
  f.ctx.restart();

  ASSERT_EQ(f.wireOps->deferredReadInvocations.size(), 1u);
  EXPECT_EQ(f.wireOps->readRequests.size(), 2u)
    << "one priming AccessLevel Read and one shared capability Read";
  EXPECT_EQ(completions, 0u);

  f.wireOps->deferReads = false;
  f.wireOps->fire_deferred_reads();
  f.ctx.run();
  EXPECT_EQ(completions, 2u);
  EXPECT_EQ(f.wireOps->historyUpdateRequests.size(), 2u);
}

// @verifies CL-HIST-020
// @relation(CL-HIST-020, scope=function)
TEST(HistoryFacadeUpdatePreflight, HistoryWriteProbeFailurePreservesPrimaryErrorDetail)
{
  Fixture f;
  auto detail = ua::make_error_detail(
    "PrimaryAccessLevelFailure", "scripted AccessLevel failure", "test.history.primary");
  const auto* detailAddress = detail.get();
  f.wireOps->scriptedReadResponses.push_back(
    ua::Result<ua::ReadResponse>{ua::Status::BadTimeout, std::move(detail)});

  auto result = f.drain_update([](HistoryFacade& facade, auto callback)
    { facade.insert_data_async(node(11), {dv(1)}, std::move(callback)); },
    false);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadTimeout);
  EXPECT_EQ(result.shared_detail().get(), detailAddress);
  EXPECT_TRUE(f.wireOps->historyUpdateRequests.empty());
}

// @verifies CL-HIST-020
// @relation(CL-HIST-020, scope=function)
TEST(HistoryFacadeUpdatePreflight, MalformedCapabilityValueIsRejectedWithDetail)
{
  Fixture f;
  f.wireOps->scriptedReadResponses.push_back(
    access_level_response(ua::AccessLevelType{ua::AccessLevelType::Bit::HistoryWrite}.as_underlying_type()));
  auto capabilities = history_capabilities_response({true, true, true, true, true});
  capabilities.results()[2].value() = ua::Variant{std::int32_t{1}};
  f.wireOps->scriptedReadResponses.push_back(std::move(capabilities));

  auto result = f.drain_update([](HistoryFacade& facade, auto callback)
    { facade.update_data_async(node(11), {dv(1)}, ua::PerformUpdateType::Update, std::move(callback)); },
    false);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadTypeMismatch);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "HistoryCapabilityValueInvalid");
  EXPECT_TRUE(f.wireOps->historyUpdateRequests.empty());
}

// @verifies CL-HIST-020
// @relation(CL-HIST-020, scope=function)
TEST(HistoryFacadeUpdatePreflight, InvalidCapabilityResultCountIsRejectedWithDetail)
{
  Fixture f;
  f.wireOps->scriptedReadResponses.push_back(
    access_level_response(ua::AccessLevelType{ua::AccessLevelType::Bit::HistoryWrite}.as_underlying_type()));
  ua::ReadResponse shortCapabilities;
  for (std::size_t index = 0; index < 4; ++index)
    shortCapabilities.results().push_back(ua::DataValue{ua::Variant{true}});
  f.wireOps->scriptedReadResponses.push_back(std::move(shortCapabilities));

  auto result = f.drain_update([](HistoryFacade& facade, auto callback)
    { facade.insert_data_async(node(11), {dv(1)}, std::move(callback)); },
    false);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadUnexpectedError);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "HistoryCapabilitiesReadFailed");
  EXPECT_TRUE(f.wireOps->historyUpdateRequests.empty());
}

// @verifies CL-HIST-018
// @verifies CL-HIST-024
// @relation(CL-HIST-018, CL-HIST-024, scope=function)
TEST(HistoryFacade, UpdateDataComposesUpdateDataDetailsWithPerformType)
{
  Fixture f;
  auto result = f.drain_update([](HistoryFacade& facade, auto cb)
    { facade.update_data_async(node(11), {dv(1), dv(2)}, ua::PerformUpdateType::Update, std::move(cb)); });
  ASSERT_TRUE(result.is_good());

  ASSERT_EQ(f.wireOps->historyUpdateRequests.size(), 1u);
  ASSERT_EQ(f.wireOps->historyUpdateRequests[0].history_update_details().size(), 1u);
  const auto* details = dynamic_cast<const ua::UpdateDataDetails*>(
    f.wireOps->historyUpdateRequests[0].history_update_details()[0].get());
  ASSERT_NE(details, nullptr) << "CL-HIST-018: update_data composes an UpdateDataDetails";
  EXPECT_EQ(details->perform_insert_replace(), ua::PerformUpdateType::Update);
  EXPECT_EQ(details->update_values().size(), 2u);
}

// @verifies CL-HIST-019
// @verifies CL-HIST-024
// @relation(CL-HIST-019, CL-HIST-024, scope=function)
TEST(HistoryFacade, InsertDataPinsInsert)
{
  Fixture f;
  auto result = f.drain_update(
    [](HistoryFacade& facade, auto cb) { facade.insert_data_async(node(11), {dv(1)}, std::move(cb)); });
  ASSERT_TRUE(result.is_good());
  const auto* details = dynamic_cast<const ua::UpdateDataDetails*>(
    f.wireOps->historyUpdateRequests[0].history_update_details()[0].get());
  ASSERT_NE(details, nullptr);
  EXPECT_EQ(details->perform_insert_replace(), ua::PerformUpdateType::Insert);
}

// @verifies CL-HIST-019
// @relation(CL-HIST-019, scope=function)
TEST(HistoryFacade, ReplaceDataPinsReplace)
{
  Fixture f;
  auto result = f.drain_update(
    [](HistoryFacade& facade, auto cb) { facade.replace_data_async(node(11), {dv(1)}, std::move(cb)); });
  ASSERT_TRUE(result.is_good());
  const auto* details = dynamic_cast<const ua::UpdateDataDetails*>(
    f.wireOps->historyUpdateRequests[0].history_update_details()[0].get());
  ASSERT_NE(details, nullptr);
  EXPECT_EQ(details->perform_insert_replace(), ua::PerformUpdateType::Replace);
}

// @verifies CL-HIST-018
// @verifies CL-HIST-024
// @relation(CL-HIST-018, CL-HIST-024, scope=function)
TEST(HistoryFacade, DeleteRawModifiedComposesDeleteRawModifiedDetails)
{
  Fixture f;
  auto result = f.drain_update([](HistoryFacade& facade, auto cb)
    { facade.delete_raw_modified_async(node(11), full_range(), /*isDeleteModified=*/true, std::move(cb)); });
  ASSERT_TRUE(result.is_good());
  const auto* details = dynamic_cast<const ua::DeleteRawModifiedDetails*>(
    f.wireOps->historyUpdateRequests[0].history_update_details()[0].get());
  ASSERT_NE(details, nullptr) << "CL-HIST-018: delete_raw_modified composes a DeleteRawModifiedDetails";
  EXPECT_TRUE(details->is_delete_modified());
  EXPECT_EQ(details->start_time(), instant(0.0));
  EXPECT_EQ(details->end_time(), instant(9.0));
}

// @verifies CL-HIST-022
// @relation(CL-HIST-022, scope=function)
TEST(HistoryFacade, DeleteRawModifiedRejectsReverseRangeInline)
{
  Fixture f;
  TimeRange reversed;
  reversed.startTime = instant(9.0);
  reversed.endTime = instant(0.0);  // end < start => reject (deletes have no order axis)

  auto result = f.drain_update([reversed](HistoryFacade& facade, auto cb)
    { facade.delete_raw_modified_async(node(11), reversed, false, std::move(cb)); });
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadInvalidArgument});
  EXPECT_TRUE(f.wireOps->historyUpdateRequests.empty()) << "CL-HIST-022: rejected before any wire round-trip";
}

// @verifies CL-HIST-018
// @verifies CL-HIST-024
// @relation(CL-HIST-018, CL-HIST-024, scope=function)
TEST(HistoryFacade, DeleteAtTimeComposesDeleteAtTimeDetails)
{
  Fixture f;
  std::vector<ua::DateTime> times{instant(1.0), instant(2.0)};
  auto result = f.drain_update(
    [times](HistoryFacade& facade, auto cb) { facade.delete_at_time_async(node(11), times, std::move(cb)); });
  ASSERT_TRUE(result.is_good());
  const auto* details = dynamic_cast<const ua::DeleteAtTimeDetails*>(
    f.wireOps->historyUpdateRequests[0].history_update_details()[0].get());
  ASSERT_NE(details, nullptr) << "CL-HIST-018: delete_at_time composes a DeleteAtTimeDetails";
  EXPECT_EQ(details->req_times().size(), 2u);
}

// @verifies CL-HIST-021
// @relation(CL-HIST-021, scope=function)
TEST(HistoryFacade, PerNodeUpdateBadIsValueQualityNotServiceFailure)
{
  Fixture f;
  FakeWireOps::HistoryUpdateOutcome outcome;
  outcome.statusCode = ua::StatusCode{ua::Status::BadUserAccessDenied};
  f.wireOps->historyUpdateOutcomes.push_back(outcome);

  auto result = f.drain_update(
    [](HistoryFacade& facade, auto cb) { facade.insert_data_async(node(11), {dv(1)}, std::move(cb)); });
  ASSERT_TRUE(result.is_good()) << "CL-HIST-021: a per-node Bad is value-quality - the outer Result is Good";
  EXPECT_EQ(result.value().statusCode, ua::StatusCode{ua::Status::BadUserAccessDenied});
}

// @verifies CL-HIST-023
// @relation(CL-HIST-023, scope=function)
TEST(HistoryFacade, PerEntryOperationResultsPreservedVerbatim)
{
  Fixture f;
  FakeWireOps::HistoryUpdateOutcome outcome;
  outcome.operationResults = {
    ua::StatusCode{ua::Status::GoodEntryInserted}, ua::StatusCode{ua::Status::BadEntryExists}};
  f.wireOps->historyUpdateOutcomes.push_back(outcome);

  auto result = f.drain_update([](HistoryFacade& facade, auto cb)
    { facade.insert_data_async(node(11), {dv(1), dv(2)}, std::move(cb)); });
  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().operationResults.size(), 2u);
  EXPECT_EQ(result.value().operationResults[0], ua::StatusCode{ua::Status::GoodEntryInserted})
    << "CL-HIST-023: Good_EntryInserted is not collapsed to plain Good";
  EXPECT_EQ(result.value().operationResults[1], ua::StatusCode{ua::Status::BadEntryExists});
}

// @verifies CL-HIST-021
// N4: for an UpdateData* call the server must return one operationResult per updateValue. A Good per-node
// status with a mismatched operationResults length is a protocol defect that surfaces a bad
// Result<HistoryUpdateResult> source-tagged client.tier2.history_updater.result_length_mismatch - NOT a Good
// result. Falsifiability: the pre-fix code copied operationResults verbatim, yielding a Good Result.
// @relation(CL-HIST-021, scope=function)
TEST(HistoryFacade, UpdateDataResultLengthMismatchSurfacesBadResult)
{
  Fixture f;
  FakeWireOps::HistoryUpdateOutcome outcome;
  outcome.statusCode = ua::StatusCode{ua::Status::Good};  // per-node Good => the length invariant applies
  outcome.operationResults = {
    ua::StatusCode{ua::Status::Good}, ua::StatusCode{ua::Status::Good}};  // TWO results...
  f.wireOps->historyUpdateOutcomes.push_back(outcome);

  // ...but only ONE value is sent: operationResults.size()(2) != updateValues.size()(1).
  auto result = f.drain_update(
    [](HistoryFacade& facade, auto cb) { facade.insert_data_async(node(11), {dv(1)}, std::move(cb)); });

  ASSERT_TRUE(result.is_bad())
    << "CL-HIST-021: operationResults.size() != updateValues.size() surfaces a bad Result";
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadUnexpectedError});
  ASSERT_NE(result.shared_detail(), nullptr) << "the length-mismatch carries an ErrorDetail";
  EXPECT_EQ(result.shared_detail()->source, "client.tier2.history_updater.result_length_mismatch");
}

// @verifies CL-HIST-021
// N4 companion: a per-node BAD status is value-quality (CL-HIST-021) - a short/empty operationResults is NOT
// promoted to a length-mismatch service failure. Guards the gate that skips the check on a bad per-node code.
// @relation(CL-HIST-021, scope=function)
TEST(HistoryFacade, UpdateDataPerNodeBadSkipsLengthMismatchCheck)
{
  Fixture f;
  FakeWireOps::HistoryUpdateOutcome outcome;
  outcome.statusCode = ua::StatusCode{ua::Status::BadUserAccessDenied};  // node action rejected wholesale
  // no operationResults (empty) - legitimate when the node action did not run
  f.wireOps->historyUpdateOutcomes.push_back(outcome);

  auto result = f.drain_update([](HistoryFacade& facade, auto cb)
    { facade.insert_data_async(node(11), {dv(1), dv(2)}, std::move(cb)); });

  ASSERT_TRUE(result.is_good()) << "a per-node Bad rides through as value quality, not a length mismatch";
  EXPECT_EQ(result.value().statusCode, ua::StatusCode{ua::Status::BadUserAccessDenied});
  EXPECT_TRUE(result.value().operationResults.empty());
}

// @verifies CL-HIST-017
// @relation(CL-HIST-017, scope=function)
TEST(HistoryFacade, UpdateTransportFailurePropagates)
{
  Fixture f;
  f.wireOps->historyUpdateServiceStatus = ua::StatusCode{ua::Status::BadServerNotConnected};

  auto result = f.drain_update(
    [](HistoryFacade& facade, auto cb) { facade.insert_data_async(node(11), {dv(1)}, std::move(cb)); });
  EXPECT_TRUE(result.is_bad()) << "a transport-level failure is a bad Result<HistoryUpdateResult>";
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadServerNotConnected});
}

// Wire-interface-gone bail on the update path (section 8.9 gone path).
TEST(HistoryFacade, UpdateWireOpsGoneBailsCleanly)
{
  Fixture f;
  auto facade = f.facade();
  f.wireOps.reset();  // the Connection is gone before the update is issued

  std::optional<ua::Result<HistoryUpdateResult>> captured;
  facade.insert_data_async(
    node(11), {dv(1)}, [&captured](ua::Result<HistoryUpdateResult> result) { captured = std::move(result); });
  f.ctx.run();
  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code(), ua::StatusCode{ua::Status::BadConnectionClosed});
}

// ===========================================================================
// ServiceFault flatten (error_handling.md, D2): the tier-0 History funnels return the response VERBATIM, so a
// bad ResponseHeader.serviceResult must surface that EXACT service status - never masked as
// Bad_UnexpectedError (empty results[]) nor silently collapsed to a Good cursor / page / VoidResult
// (non-empty results[]).
// ===========================================================================

// @verifies CL-HIST-011
// @relation(CL-HIST-011, scope=function)
TEST(HistoryFacadeServiceFault, ReadSurfacesBadHistoryReadServiceResultNotMaskedAsSuccess)
{
  Fixture f;
  // A Good-transport HistoryReadResponse whose SERVICE-level serviceResult is bad. No page is scripted, so
  // the default per-node result is Good - without the flatten the fault would collapse to a Good cursor.
  f.wireOps->historyReadHeaderServiceResult = ua::StatusCode{ua::Status::BadUserAccessDenied};

  auto result = f.drain_read(
    [](HistoryFacade& facade, auto cb) { facade.read_raw_async(node(11), full_range(), {}, std::move(cb)); });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadUserAccessDenied);  // the real fault, verbatim
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "HistoryReadServiceFault");
  EXPECT_EQ(result.shared_detail()->source, "client.tier2.history_reader.read");
}

// @verifies CL-HIST-017
// @relation(CL-HIST-017, scope=function)
TEST(HistoryFacadeServiceFault, UpdateSurfacesBadHistoryUpdateServiceResultNotMaskedAsSuccess)
{
  Fixture f;
  // A Good-transport HistoryUpdateResponse whose SERVICE-level serviceResult is bad. The default per-node
  // result is Good - without the flatten the fault would collapse to a Good Result<HistoryUpdateResult>.
  f.wireOps->historyUpdateHeaderServiceResult = ua::StatusCode{ua::Status::BadUserAccessDenied};

  auto result = f.drain_update(
    [](HistoryFacade& facade, auto cb) { facade.insert_data_async(node(11), {dv(1)}, std::move(cb)); });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadUserAccessDenied);  // the real fault, verbatim
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "HistoryUpdateServiceFault");
  EXPECT_EQ(result.shared_detail()->source, "client.tier2.history_updater.update");
}

// @verifies CL-HIST-008
// @relation(CL-HIST-008, scope=function)
TEST(HistoryReadCursorServiceFault, ContinuationReadSurfacesBadServiceResultNotMaskedAsSuccess)
{
  Fixture f;
  const ua::ContinuationPoint cp1{0x01};
  // The continuation read returns a Good-transport response whose SERVICE-level serviceResult is bad (the
  // default per-node result is Good). Without the flatten the second page would collapse to a Good page.
  f.wireOps->historyReadHeaderServiceResult = ua::StatusCode{ua::Status::BadTooManyOperations};

  auto cursor = make_cursor(f, {dv(1)}, /*firstPagePending=*/true, cp1);
  auto first = f.next(cursor);  // buffered first page - delivered locally, no wire read
  ASSERT_TRUE(first.is_good());

  auto second = f.next(cursor);  // drives the continuation wire read carrying the bad serviceResult
  ASSERT_TRUE(second.is_bad());
  EXPECT_EQ(second.status_code().as_status(), ua::Status::BadTooManyOperations);  // verbatim, not a Good page
  ASSERT_NE(second.shared_detail(), nullptr);
  EXPECT_EQ(second.shared_detail()->code, "HistoryContinuationServiceFault");
  EXPECT_EQ(second.shared_detail()->source, "client.tier2.history_reader.next");
}

// @verifies CL-HIST-009
// The release-only HistoryRead surfaces a CALLER-VISIBLE VoidResult (unlike FileHandle's fire-and-forget
// Close): a bad serviceResult on the release must not be reported as a Good close (matches close_async's own
// comment about not silently swallowing a release failure).
// @relation(CL-HIST-009, scope=function)
TEST(HistoryReadCursorServiceFault, CloseSurfacesBadReleaseServiceResultNotMaskedAsGood)
{
  Fixture f;
  const ua::ContinuationPoint cp1{0x0A, 0x0B};
  f.wireOps->historyReadHeaderServiceResult = ua::StatusCode{ua::Status::BadSessionIdInvalid};

  auto cursor = make_cursor(f, {dv(1)}, /*firstPagePending=*/false, cp1);
  std::optional<ua::VoidResult> captured;
  cursor.close_async([&captured](ua::VoidResult result) { captured = std::move(result); });
  f.ctx.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadSessionIdInvalid);  // not masked as Good
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->code, "HistoryReleaseServiceFault");
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.history_reader.release_continuation_point");
}

// ===========================================================================
// A Good subcode or an Uncertain code the server answers reaches the application
// ===========================================================================

// A per-node Good_NoData is the status of the cursor's Result and of the first page, not plain Good.
// @relation(AC-CL-STATUS-ROUTING-01-A-HISTORY-READ-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(HistoryFacadeStatusRouting, GoodNoDataReachesTheCursorResultAndItsFirstPage)
{
  Fixture f;
  f.wireOps->historyReadPages.push_back(
    {{}, ua::ContinuationPoint{}, ua::StatusCode{ua::Status::GoodNoData}});

  auto result = f.drain_read(
    [](HistoryFacade& facade, auto cb) { facade.read_raw_async(node(11), full_range(), {}, std::move(cb)); });
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::GoodNoData});
  ASSERT_TRUE(result.is_good());
  HistoryReadCursor cursor = std::move(result.value());

  auto page = f.next(cursor);
  EXPECT_EQ(page.status_code(), ua::StatusCode{ua::Status::GoodNoData});
  ASSERT_TRUE(page.is_good());
  EXPECT_TRUE(page.value().empty());
}

// A continuation page answered Uncertain with values is delivered with its values and the Uncertain code.
// @relation(AC-CL-STATUS-ROUTING-01-A-HISTORY-READ-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(HistoryFacadeStatusRouting, AnUncertainContinuationPageKeepsItsValuesAndCode)
{
  Fixture f;
  f.wireOps->historyReadPages.push_back({{dv(1)}, ua::ContinuationPoint{0x01}, {}});
  f.wireOps->historyReadPages.push_back(
    {{dv(2)}, ua::ContinuationPoint{}, ua::StatusCode{ua::Status::UncertainDataSubNormal}});

  auto result = f.drain_read(
    [](HistoryFacade& facade, auto cb) { facade.read_raw_async(node(11), full_range(), {}, std::move(cb)); });
  ASSERT_TRUE(result.is_good());
  HistoryReadCursor cursor = std::move(result.value());
  auto first = f.next(cursor);
  EXPECT_EQ(first.status_code(), ua::StatusCode{ua::Status::Good});

  auto second = f.next(cursor);
  EXPECT_TRUE(second.is_uncertain());
  EXPECT_EQ(second.status_code(), ua::StatusCode{ua::Status::UncertainDataSubNormal});
  const auto values = second.value_or({});
  ASSERT_EQ(values.size(), 1u);
  EXPECT_EQ(values[0].value(), ua::Variant{std::int32_t{2}});
}

// An Uncertain per-node code without values: the cursor's Result is Uncertain and the page is the code with
// no values, so value() throws rather than yielding an empty Good page.
// @relation(AC-CL-STATUS-ROUTING-01-A-HISTORY-READ-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(HistoryFacadeStatusRouting, AnUncertainAnswerWithoutValuesIsAPageWithoutValues)
{
  Fixture f;
  f.wireOps->historyReadPages.push_back(
    {{}, ua::ContinuationPoint{}, ua::StatusCode{ua::Status::UncertainNoCommunicationLastUsableValue}});

  auto result = f.drain_read(
    [](HistoryFacade& facade, auto cb) { facade.read_raw_async(node(11), full_range(), {}, std::move(cb)); });
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::UncertainNoCommunicationLastUsableValue});
  ASSERT_FALSE(result.is_bad());
  HistoryReadCursor cursor = std::move(result.value());

  auto page = f.next(cursor);
  EXPECT_EQ(page.status_code(), ua::StatusCode{ua::Status::UncertainNoCommunicationLastUsableValue});
  EXPECT_THROW((void)page.value(), ua::UaException);
}

// A Good subcode on the HistoryRead's ServiceResult is the status of the cursor's Result and its first page.
// @relation(AC-CL-STATUS-ROUTING-01-A-SERVICE-RESULT-GOOD-SUBCODE-REACHES-THE-APPLICATION, scope=function)
TEST(HistoryFacadeStatusRouting, AServiceResultGoodSubcodeReachesTheCursorResult)
{
  for (const ua::Status serviceStatus :
    {ua::Status::GoodResultsMayBeIncomplete, ua::Status::GoodLocalOverride})
  {
    SCOPED_TRACE(ua::StatusCode{serviceStatus}.value());
    Fixture f;
    f.wireOps->historyReadHeaderServiceResult = ua::StatusCode{serviceStatus};
    f.wireOps->historyReadPages.push_back({{dv(5)}, ua::ContinuationPoint{}, {}});

    auto result = f.drain_read([](HistoryFacade& facade, auto cb)
      { facade.read_raw_async(node(11), full_range(), {}, std::move(cb)); });
    EXPECT_EQ(result.status_code(), ua::StatusCode{serviceStatus});
    ASSERT_TRUE(result.is_good());
    HistoryReadCursor cursor = std::move(result.value());
    auto page = f.next(cursor);
    EXPECT_EQ(page.status_code(), ua::StatusCode{serviceStatus});
    ASSERT_TRUE(page.is_good());
    ASSERT_EQ(page.value().size(), 1u);
    EXPECT_EQ(page.value()[0].value(), ua::Variant{std::int32_t{5}});
  }
}

// A Good subcode on the HistoryUpdate's ServiceResult is the status of the update's Result; the per-node
// statusCode is unchanged beside it.
// @relation(AC-CL-STATUS-ROUTING-01-A-SERVICE-RESULT-GOOD-SUBCODE-REACHES-THE-APPLICATION, scope=function)
TEST(HistoryFacadeStatusRouting, AnUpdateServiceResultGoodSubcodeReachesTheResult)
{
  for (const ua::Status serviceStatus :
    {ua::Status::GoodResultsMayBeIncomplete, ua::Status::GoodLocalOverride})
  {
    SCOPED_TRACE(ua::StatusCode{serviceStatus}.value());
    Fixture f;
    f.wireOps->historyUpdateHeaderServiceResult = ua::StatusCode{serviceStatus};
    FakeWireOps::HistoryUpdateOutcome outcome;
    outcome.statusCode = ua::StatusCode{ua::Status::Good};
    outcome.operationResults = {ua::StatusCode{ua::Status::GoodEntryInserted}};
    f.wireOps->historyUpdateOutcomes.push_back(outcome);

    auto result = f.drain_update(
      [](HistoryFacade& facade, auto cb) { facade.insert_data_async(node(11), {dv(1)}, std::move(cb)); });
    EXPECT_EQ(result.status_code(), ua::StatusCode{serviceStatus});
    ASSERT_TRUE(result.is_good());
    EXPECT_EQ(result.value().statusCode, ua::StatusCode{ua::Status::Good});
    ASSERT_EQ(result.value().operationResults.size(), 1u);
    EXPECT_EQ(result.value().operationResults[0], ua::StatusCode{ua::Status::GoodEntryInserted});
  }
}

// The capability probe decodes AccessLevel from an Uncertain DataValue: the flag is held with the Uncertain
// code; without a value the code is answered with no flag. Neither is cached as a plain Good answer.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(HistoryFacadeStatusRouting, TheCapabilityProbeKeepsAnUncertainAccessLevelsCode)
{
  Fixture f;
  ua::ReadResponse withValue;
  ua::DataValue accessLevel{
    ua::Variant{ua::AccessLevelType{ua::AccessLevelType::Bit::HistoryRead}.as_underlying_type()}};
  accessLevel.status() = ua::StatusCode{ua::Status::UncertainLastUsableValue};
  withValue.results().push_back(accessLevel);
  f.wireOps->scriptedReadResponses.push_back(std::move(withValue));
  ua::ReadResponse withoutValue;
  withoutValue.results().push_back(ua::DataValue{ua::Status::UncertainNoCommunicationLastUsableValue});
  f.wireOps->scriptedReadResponses.push_back(std::move(withoutValue));
  auto facade = f.facade();

  auto uncertain = f.probe(facade, node(130));
  EXPECT_TRUE(uncertain.is_uncertain());
  EXPECT_EQ(uncertain.status_code(), ua::StatusCode{ua::Status::UncertainLastUsableValue});
  EXPECT_TRUE(uncertain.value_or(false));

  auto empty = f.probe(facade, node(130));
  EXPECT_EQ(f.wireOps->readCalls, 2u) << "an Uncertain answer is not cached";
  EXPECT_EQ(empty.status_code(), ua::StatusCode{ua::Status::UncertainNoCommunicationLastUsableValue});
  EXPECT_THROW((void)empty.value(), ua::UaException);
}

// The update preflight acts on AccessLevel itself, so an Uncertain AccessLevel is refused with
// Bad_InternalError (ReadAnswerUncertain) and no HistoryUpdate is sent.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(HistoryFacadeStatusRouting, TheUpdatePreflightRefusesAnUncertainAccessLevel)
{
  Fixture f;
  ua::ReadResponse accessLevelResponse;
  ua::DataValue accessLevel{
    ua::Variant{ua::AccessLevelType{ua::AccessLevelType::Bit::HistoryWrite}.as_underlying_type()}};
  accessLevel.status() = ua::StatusCode{ua::Status::UncertainLastUsableValue};
  accessLevelResponse.results().push_back(accessLevel);
  f.wireOps->scriptedReadResponses.push_back(std::move(accessLevelResponse));
  f.wireOps->scriptedReadResponses.push_back(history_capabilities_response({true, true, true, true, true}));

  auto result = f.drain_update([](HistoryFacade& facade, auto cb)
    { facade.insert_data_async(node(11), {dv(1)}, std::move(cb)); },
    /*seedSuccessfulPreflight=*/false);
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadInternalError);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "ReadAnswerUncertain");
  EXPECT_TRUE(f.wireOps->historyUpdateRequests.empty()) << "no update is sent on an uncertain preflight";
}

// The update preflight refuses an Uncertain HistoryServerCapabilities flag the same way.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(HistoryFacadeStatusRouting, TheUpdatePreflightRefusesAnUncertainCapabilityFlag)
{
  Fixture f;
  f.wireOps->scriptedReadResponses.push_back(
    access_level_response(ua::AccessLevelType{ua::AccessLevelType::Bit::HistoryWrite}.as_underlying_type()));
  auto capabilities = history_capabilities_response({true, true, true, true, true});
  capabilities.results()[0].status() = ua::StatusCode{ua::Status::UncertainSubstituteValue};
  f.wireOps->scriptedReadResponses.push_back(std::move(capabilities));

  auto result = f.drain_update([](HistoryFacade& facade, auto cb)
    { facade.insert_data_async(node(11), {dv(1)}, std::move(cb)); },
    /*seedSuccessfulPreflight=*/false);
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadInternalError);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "ReadAnswerUncertain");
  EXPECT_TRUE(f.wireOps->historyUpdateRequests.empty());
}

// The HasHistoricalConfiguration list carries a Good subcode the Browse page answered.
// @relation(AC-CL-STATUS-ROUTING-01-A-BROWSE-OR-TRANSLATE-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(HistoryFacadeStatusRouting, TheConfigurationListKeepsTheBrowsePagesCode)
{
  Fixture f;
  f.wireOps->browsePages.push_back({{configuration_reference(300, "HA Configuration")},
    ua::ContinuationPoint{},
    ua::StatusCode{ua::Status::GoodResultsMayBeIncomplete}});
  auto facade = f.facade();

  auto result = f.configurations(facade, node(30));
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::GoodResultsMayBeIncomplete});
  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().size(), 1u);
  EXPECT_EQ(result.value()[0], node(300));
}

}  // namespace
