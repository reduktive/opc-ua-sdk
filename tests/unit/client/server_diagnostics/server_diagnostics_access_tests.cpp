// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the tier-2 ServerDiagnostics typed-read accessor (client design section 8.18.1.c,
// CL-BASEDIAG-002/003). Covers the one-shot ServerDiagnosticsSummary read (CL-BASEDIAG-002), the four
// diagnostic-array reads with the cached EnabledFlag + disabled-advisory (CL-BASEDIAG-003), and the
// EnabledFlag mutator (verbatim server reject + cache refresh on success).
//
// The tests drive the real code through the fake upward interface roles (FakeWireOps / FakeSupportOps) with
// no real ConnectionImpl: reads are scripted via scriptedReadResponses, writes via writeOutcomes. The
// accessor is built through ServerDiagnosticsClientTestAccess over a shared cache whose now-provider is
// injected so the 60 s TTL is deterministic. The disabled-advisory (no observer fan-out yet) is asserted via
// a recording LogSink.
//
// Falsifiability: a summary read that ignores the DataValue Bad quality fails
// SummarySurfacesBadStatusViaResult; an array read that batches the flag on every call (no cache) fails
// EnabledFlagCachedFor60s; one that never re-reads a stale flag fails StaleFlagReReadAfter60s; one that
// blocks the array when disabled fails EnabledFlagFalseSurfacesAdvisoryButDeliversData; a set that writes the
// wrong node fails SetEnabledFlagWritesRightNode; one that swallows the server reject fails
// SetEnabledFlagServerRejectSurfacesVerbatim.

#include "ua_server_diagnostics_access.h"

#include "fake_connection_ops.h"

#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_client_monitored_item.h"
#include "ua_data_change_filter.h"
#include "ua_data_change_trigger.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_eu_information.h"
#include "ua_exceptions.h"
#include "ua_log_sink.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_read_response.h"
#include "ua_ref_structure.h"
#include "ua_sampling_interval_diagnostics_data_type.h"
#include "ua_server_diagnostics_access_state.h"
#include "ua_server_diagnostics_access_test_access.h"
#include "ua_server_diagnostics_summary_data_type.h"
#include "ua_session_diagnostics_data_type.h"
#include "ua_session_security_diagnostics_data_type.h"
#include "ua_status.h"
#include "ua_string.h"
#include "ua_structure.h"
#include "ua_subscription_diagnostics_data_type.h"
#include "ua_variant.h"

#include <boost/asio/io_context.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace
{

using ua::client::MonitoredItem;
using ua::client::MonitoredItemKind;
using ua::client::MonitoredItemResult;
using ua::client::SamplingIntervalDiagnosticsArrayResult;
using ua::client::ServerDiagnosticsAccessor;
using ua::client::ServerDiagnosticsSummaryResult;
using ua::client::SessionDiagnosticsArrayResult;
using ua::client::SessionsArrayCallback;
using ua::client::SessionSecurityDiagnosticsArrayResult;
using ua::client::SubscriptionDiagnosticsArrayResult;
using ua::client::SubscriptionsArrayCallback;
using ua::client::detail::ServerDiagnosticsCacheState;
using ua::client::detail::ServerDiagnosticsClientTestAccess;
using ua::test_helpers::FakeSubscriptionFactory;
using ua::test_helpers::FakeSupportOps;
using ua::test_helpers::FakeWireOps;

ua::NodeId node(std::uint32_t identifier)
{
  return ua::NodeId{std::uint16_t{0}, identifier};
}

constexpr std::uint32_t valueAttribute = static_cast<std::uint32_t>(ua::AttributeId::Value);

// The well-known ns0 node ids the accessor targets (client design section 8.18.1.c).
constexpr std::uint32_t summaryNode = 2275;
constexpr std::uint32_t samplingNode = 2289;
constexpr std::uint32_t subscriptionsNode = 2290;
constexpr std::uint32_t enabledFlagNode = 2294;
constexpr std::uint32_t sessionsNode = 3707;
constexpr std::uint32_t sessionsSecurityNode = 3708;

// ---- value builders ----

ua::DataValue dv_summary(std::uint32_t currentSessionCount)
{
  ua::ServerDiagnosticsSummaryDataType summary;
  summary.current_session_count() = currentSessionCount;
  return ua::DataValue{ua::Variant{summary}};
}

ua::DataValue dv_summary_bad_quality(ua::Status status)
{
  ua::ServerDiagnosticsSummaryDataType summary;  // value still present; the quality is what is Bad
  return ua::DataValue{ua::Variant{summary}, ua::StatusCode{status}};
}

ua::DataValue dv_bool(bool value)
{
  return ua::DataValue{ua::Variant{value}};
}

ua::SessionDiagnosticsDataType session(std::uint32_t sessionIdentifier)
{
  ua::SessionDiagnosticsDataType entry;
  entry.session_id() = node(sessionIdentifier);
  return entry;
}

ua::SessionSecurityDiagnosticsDataType session_security(std::uint32_t sessionIdentifier)
{
  ua::SessionSecurityDiagnosticsDataType entry;
  entry.session_id() = node(sessionIdentifier);
  return entry;
}

ua::SubscriptionDiagnosticsDataType subscription(std::uint32_t subscriptionIdentifier)
{
  ua::SubscriptionDiagnosticsDataType entry;
  entry.subscription_id() = subscriptionIdentifier;
  return entry;
}

ua::SamplingIntervalDiagnosticsDataType sampling(std::uint32_t monitoredItemCount)
{
  ua::SamplingIntervalDiagnosticsDataType entry;
  entry.monitored_item_count() = monitoredItemCount;
  return entry;
}

template<typename T>
ua::DataValue dv_struct_array(std::vector<T> items)
{
  ua::Array<ua::RefStructure<ua::Structure>> array;
  for (auto& item : items)
  {
    array.push_back(ua::RefStructure<ua::Structure>{std::make_unique<T>(std::move(item))});
  }
  return ua::DataValue{ua::Variant{std::move(array)}};
}

// An array whose single element is the WRONG structure type (an EUInformation) so a
// SessionDiagnosticsDataType decode must fail.
ua::DataValue dv_wrong_type_array()
{
  ua::Array<ua::RefStructure<ua::Structure>> array;
  array.push_back(ua::RefStructure<ua::Structure>{std::make_unique<ua::EUInformation>()});
  return ua::DataValue{ua::Variant{std::move(array)}};
}

ua::ReadResponse read_response(std::vector<ua::DataValue> values)
{
  ua::ReadResponse response;
  for (auto& value : values)
  {
    response.results().push_back(std::move(value));
  }
  return response;
}

// Captures the messages the accessor logs so the disabled-advisory (which has no observer fan-out wired yet)
// can be asserted.
struct RecordingLogSink : public ua::LogSink
{
  std::vector<std::string> messages;

  void log(const ua::LogEntry& entry) override
  {
    messages.push_back(entry.message);
  }

  [[nodiscard]] bool has_message_containing(std::string_view needle) const
  {
    for (const auto& message : messages)
    {
      if (message.find(needle) != std::string::npos)
      {
        return true;
      }
    }
    return false;
  }

  [[nodiscard]] int count_messages_containing(std::string_view needle) const
  {
    int count = 0;
    for (const auto& message : messages)
    {
      if (message.find(needle) != std::string::npos)
      {
        ++count;
      }
    }
    return count;
  }
};

struct Fixture
{
  boost::asio::io_context ctx;
  std::shared_ptr<FakeWireOps> wireOps = std::make_shared<FakeWireOps>();
  std::shared_ptr<FakeSupportOps> supportOps = std::make_shared<FakeSupportOps>();
  std::shared_ptr<RecordingLogSink> logSink = std::make_shared<RecordingLogSink>();
  std::shared_ptr<ServerDiagnosticsCacheState> cache = std::make_shared<ServerDiagnosticsCacheState>();
  std::shared_ptr<std::vector<std::shared_ptr<const ua::ErrorDetail>>> advisories =
    std::make_shared<std::vector<std::shared_ptr<const ua::ErrorDetail>>>();
  std::function<void(std::shared_ptr<const ua::ErrorDetail>)> emitAdvisory;
  ua::DateTime nowValue{2026, 7, 18, 12, 0, 0.0};  // the injected, controllable clock

  Fixture()
  {
    emitAdvisory = [captured = advisories](std::shared_ptr<const ua::ErrorDetail> detail)
    {
      captured->push_back(std::move(detail));
    };
    cache->now = [this]
    {
      return nowValue;
    };
  }

  ua::Logger logger()
  {
    auto level = std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Trace);
    return ua::Logger{logSink, level, "server_diagnostics_test"};
  }

  ServerDiagnosticsAccessor accessor()
  {
    return ServerDiagnosticsClientTestAccess::make_accessor(
      wireOps, supportOps, ctx.get_executor(), cache, logger(), emitAdvisory);
  }

  void run()
  {
    ctx.run();
    ctx.restart();
  }

  void push_read(std::vector<ua::DataValue> values)
  {
    wireOps->scriptedReadResponses.push_back(ua::Result<ua::ReadResponse>{read_response(std::move(values))});
  }

  // Scripts a transport-Good Read whose ResponseHeader.serviceResult is Bad and whose results[] is EMPTY (a
  // legal service-fault shape). The facade must surface @p status, not the masked Bad_UnexpectedError the
  // empty/count-mismatch branches would otherwise fabricate.
  void push_read_service_fault(ua::Status status)
  {
    ua::ReadResponse response;
    response.response_header().service_result() = ua::StatusCode{status};
    wireOps->scriptedReadResponses.push_back(ua::Result<ua::ReadResponse>{std::move(response)});
  }

  void advance_seconds(int seconds)
  {
    nowValue.value() +=
      std::chrono::duration_cast<ua::datetime::OneHundredNanoSeconds>(std::chrono::seconds{seconds});
  }

  int count_flag_reads() const
  {
    int count = 0;
    for (const auto& request : wireOps->readRequests)
    {
      for (const auto& readValue : request.nodes_to_read())
      {
        if (readValue.node_id() == node(enabledFlagNode))
        {
          ++count;
        }
      }
    }
    return count;
  }
};

// ===========================================================================
// summary_async (CL-BASEDIAG-002)
// ===========================================================================

// @verifies CL-BASEDIAG-002
// @relation(CL-BASEDIAG-002, scope=function)
TEST(ClientServerDiagnosticsSummary, SummaryDecodedFromWire)
{
  Fixture f;
  f.push_read({dv_summary(7)});

  std::optional<ServerDiagnosticsSummaryResult> captured;
  f.accessor().summary_async([&captured](ServerDiagnosticsSummaryResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_EQ(captured->value().current_session_count(), 7U);
  // The Read targets Server.ServerDiagnostics.ServerDiagnosticsSummary Value.
  ASSERT_EQ(f.wireOps->readRequests.size(), 1U);
  ASSERT_EQ(f.wireOps->readRequests[0].nodes_to_read().size(), 1U);
  EXPECT_EQ(f.wireOps->readRequests[0].nodes_to_read()[0].node_id(), node(summaryNode));
  EXPECT_EQ(f.wireOps->readRequests[0].nodes_to_read()[0].attribute_id(), valueAttribute);
}

// @verifies CL-BASEDIAG-002
// @relation(CL-BASEDIAG-002, scope=function)
TEST(ClientServerDiagnosticsSummary, SummarySurfacesBadStatusViaResult)
{
  Fixture f;
  // A Bad DataValue quality on the summary surfaces via the Result (single structured value: a Bad quality
  // means the value is not to be trusted).
  f.push_read({dv_summary_bad_quality(ua::Status::BadOutOfService)});

  std::optional<ServerDiagnosticsSummaryResult> captured;
  f.accessor().summary_async([&captured](ServerDiagnosticsSummaryResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadOutOfService);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.server_diagnostics.summary");
}

// @verifies CL-BASEDIAG-002
// @relation(CL-BASEDIAG-002, scope=function)
TEST(ClientServerDiagnosticsSummary, SummaryServiceFailureSurfacesWithSummarySource)
{
  Fixture f;
  f.wireOps->readStatus = ua::StatusCode{ua::Status::BadTimeout};  // the Read service itself fails

  std::optional<ServerDiagnosticsSummaryResult> captured;
  f.accessor().summary_async([&captured](ServerDiagnosticsSummaryResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadTimeout);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.server_diagnostics.summary");
}

// @verifies CL-BASEDIAG-002
// @relation(CL-BASEDIAG-002, scope=function)
TEST(ClientServerDiagnosticsSummary, SummaryNonStructureValueIsDecodeBad)
{
  Fixture f;
  // The summary Value holds a non-structure type (an Int32) -> undecodable, tagged with the summary source.
  f.push_read({ua::DataValue{ua::Variant{std::int32_t{5}}}});

  std::optional<ServerDiagnosticsSummaryResult> captured;
  f.accessor().summary_async([&captured](ServerDiagnosticsSummaryResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadDecodingError);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.server_diagnostics.summary");
}

// @verifies CL-BASEDIAG-002
// @relation(CL-BASEDIAG-002, scope=function)
TEST(ClientServerDiagnosticsSummary, SummaryEmptyResultsIsBad)
{
  Fixture f;
  f.push_read({});  // a Good service response carrying no result for the summary ReadValueId

  std::optional<ServerDiagnosticsSummaryResult> captured;
  f.accessor().summary_async([&captured](ServerDiagnosticsSummaryResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadUnexpectedError);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.server_diagnostics.summary");
}

// A transport-Good summary Read whose ResponseHeader.serviceResult is Bad with an empty results[] MUST
// surface the true serviceResult, not the masked Bad_UnexpectedError the count-mismatch branch would
// otherwise fabricate (summary_async serviceResult FLATTEN).
// @verifies CL-BASEDIAG-002
// @relation(CL-BASEDIAG-002, scope=function)
TEST(ClientServerDiagnosticsSummary, SummaryServiceFaultSurfacesServiceResultNotMasked)
{
  Fixture f;
  f.push_read_service_fault(ua::Status::BadSessionIdInvalid);

  std::optional<ServerDiagnosticsSummaryResult> captured;
  f.accessor().summary_async([&captured](ServerDiagnosticsSummaryResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadSessionIdInvalid);
  EXPECT_NE(captured->status_code().as_status(), ua::Status::BadUnexpectedError);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.server_diagnostics.summary");
}

// @verifies CL-BASEDIAG-002
// @relation(CL-BASEDIAG-002, scope=function)
TEST(ClientServerDiagnosticsSummary, SummaryOverReturnIsBad)
{
  Fixture f;
  // The server over-returns: two DataValues for the single summary ReadValueId. The response cannot be
  // positionally trusted, so it is rejected BadUnexpectedError with the summary source (W1 uniformity with
  // the array read's count guard) rather than blindly decoding results[0].
  f.wireOps->resultsPerReadDelta = 1;
  f.push_read({dv_summary(3)});

  std::optional<ServerDiagnosticsSummaryResult> captured;
  f.accessor().summary_async([&captured](ServerDiagnosticsSummaryResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadUnexpectedError);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.server_diagnostics.summary");
}

// @verifies CL-BASEDIAG-002
// @relation(CL-BASEDIAG-002, scope=function)
TEST(ClientServerDiagnosticsSummary, SummaryOnGoneConnectionReturnsConnectionClosed)
{
  Fixture f;
  f.wireOps.reset();  // the wire interface weak-ref expires

  std::optional<ServerDiagnosticsSummaryResult> captured;
  f.accessor().summary_async([&captured](ServerDiagnosticsSummaryResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadConnectionClosed);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.server_diagnostics.connection_closed");
}

// ===========================================================================
// array reads - decode (CL-BASEDIAG-003)
// ===========================================================================

// @verifies CL-BASEDIAG-003
// @relation(CL-BASEDIAG-003, scope=function)
TEST(ClientServerDiagnosticsArrays, SessionsArrayDecodedAndBatchesEnabledFlag)
{
  Fixture f;
  // Cache is absent -> the EnabledFlag is batched alongside the array Read (one ReadRequest, two nodes).
  f.push_read({dv_struct_array<ua::SessionDiagnosticsDataType>({session(11), session(12)}), dv_bool(true)});

  std::optional<SessionDiagnosticsArrayResult> captured;
  f.accessor().sessions_async([&captured](SessionDiagnosticsArrayResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  ASSERT_EQ(captured->value().size(), 2U);
  EXPECT_EQ(captured->value()[0].session_id(), node(11));
  EXPECT_EQ(captured->value()[1].session_id(), node(12));
  // The batched Read targets [SessionDiagnosticsArray.Value, EnabledFlag.Value] in that fixed order.
  ASSERT_EQ(f.wireOps->readRequests.size(), 1U);
  const auto& nodesToRead = f.wireOps->readRequests[0].nodes_to_read();
  ASSERT_EQ(nodesToRead.size(), 2U);
  EXPECT_EQ(nodesToRead[0].node_id(), node(sessionsNode));
  EXPECT_EQ(nodesToRead[1].node_id(), node(enabledFlagNode));
  // EnabledFlag == true -> no disabled-advisory logged.
  EXPECT_FALSE(f.logSink->has_message_containing("client.tier2.server_diagnostics.diagnostics_disabled"));
}

// @verifies CL-BASEDIAG-003
// @relation(CL-BASEDIAG-003, scope=function)
TEST(ClientServerDiagnosticsArrays, SessionsSecurityArrayDecoded)
{
  Fixture f;
  f.push_read(
    {dv_struct_array<ua::SessionSecurityDiagnosticsDataType>({session_security(21)}), dv_bool(true)});

  std::optional<SessionSecurityDiagnosticsArrayResult> captured;
  f.accessor().sessions_security_async(
    [&captured](SessionSecurityDiagnosticsArrayResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  ASSERT_EQ(captured->value().size(), 1U);
  EXPECT_EQ(captured->value()[0].session_id(), node(21));
  EXPECT_EQ(f.wireOps->readRequests[0].nodes_to_read()[0].node_id(), node(sessionsSecurityNode));
}

// @verifies CL-BASEDIAG-003
// @relation(CL-BASEDIAG-003, scope=function)
TEST(ClientServerDiagnosticsArrays, SubscriptionsArrayDecoded)
{
  Fixture f;
  f.push_read({dv_struct_array<ua::SubscriptionDiagnosticsDataType>({subscription(101), subscription(102)}),
    dv_bool(true)});

  std::optional<SubscriptionDiagnosticsArrayResult> captured;
  f.accessor().subscriptions_async(
    [&captured](SubscriptionDiagnosticsArrayResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  ASSERT_EQ(captured->value().size(), 2U);
  EXPECT_EQ(captured->value()[0].subscription_id(), 101U);
  EXPECT_EQ(captured->value()[1].subscription_id(), 102U);
  EXPECT_EQ(f.wireOps->readRequests[0].nodes_to_read()[0].node_id(), node(subscriptionsNode));
}

// @verifies CL-BASEDIAG-003
// @relation(CL-BASEDIAG-003, scope=function)
TEST(ClientServerDiagnosticsArrays, SamplingIntervalsArrayDecoded)
{
  Fixture f;
  f.push_read(
    {dv_struct_array<ua::SamplingIntervalDiagnosticsDataType>({sampling(3), sampling(4)}), dv_bool(true)});

  std::optional<SamplingIntervalDiagnosticsArrayResult> captured;
  f.accessor().sampling_intervals_async(
    [&captured](SamplingIntervalDiagnosticsArrayResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  ASSERT_EQ(captured->value().size(), 2U);
  EXPECT_EQ(captured->value()[0].monitored_item_count(), 3U);
  EXPECT_EQ(f.wireOps->readRequests[0].nodes_to_read()[0].node_id(), node(samplingNode));
}

// @verifies CL-BASEDIAG-003
// @relation(CL-BASEDIAG-003, scope=function)
TEST(ClientServerDiagnosticsArrays, ArrayBadPerNodeStatusSurfacesAsOuterBad)
{
  Fixture f;
  // The per-node DataValue for the array carries a Bad quality (e.g. Bad_UserAccessDenied). The array read
  // MUST surface that as an outer Bad Result (the Bad status + a sessions-source ErrorDetail), NOT silently
  // decode a null value to a Good/empty vector and swallow the Bad status. The flag DataValue is present so
  // the W1 count check passes first.
  f.push_read({ua::DataValue{ua::Variant{}, ua::StatusCode{ua::Status::BadUserAccessDenied}}, dv_bool(true)});

  std::optional<SessionDiagnosticsArrayResult> captured;
  f.accessor().sessions_async([&captured](SessionDiagnosticsArrayResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadUserAccessDenied);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.server_diagnostics.sessions");
}

// A transport-Good diagnostic-array Read whose ResponseHeader.serviceResult is Bad with an empty results[]
// MUST surface the true serviceResult, not the masked Bad_UnexpectedError the count-mismatch branch would
// otherwise fabricate. run_array_read is the single shared helper behind sessions / sessions_security /
// subscriptions / sampling_intervals, so this one test heals all four facades (run_array_read FLATTEN).
// @verifies CL-BASEDIAG-003
// @relation(CL-BASEDIAG-003, scope=function)
TEST(ClientServerDiagnosticsArrays, ArrayServiceFaultSurfacesServiceResultNotMasked)
{
  Fixture f;
  f.push_read_service_fault(ua::Status::BadTooManyOperations);

  std::optional<SessionDiagnosticsArrayResult> captured;
  f.accessor().sessions_async([&captured](SessionDiagnosticsArrayResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadTooManyOperations);
  EXPECT_NE(captured->status_code().as_status(), ua::Status::BadUnexpectedError);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.server_diagnostics.sessions");
}

// @verifies CL-BASEDIAG-003
// @relation(CL-BASEDIAG-003, scope=function)
TEST(ClientServerDiagnosticsArrays, EmptyArrayDecodesToEmptyVectorGood)
{
  Fixture f;
  f.push_read({dv_struct_array<ua::SessionDiagnosticsDataType>({}), dv_bool(true)});

  std::optional<SessionDiagnosticsArrayResult> captured;
  f.accessor().sessions_async([&captured](SessionDiagnosticsArrayResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_TRUE(captured->value().empty());
}

// ===========================================================================
// array reads - EnabledFlag advisory + TTL cache (CL-BASEDIAG-003)
// ===========================================================================

// @verifies CL-BASEDIAG-003
// @relation(CL-BASEDIAG-003, scope=function)
TEST(ClientServerDiagnosticsEnabledFlag, EnabledFlagFalseSurfacesAdvisoryButDeliversData)
{
  Fixture f;
  // EnabledFlag == false: the array data is still delivered (data + advisory, not a blocked call), and the
  // disabled-advisory is logged at the wire boundary carrying the diagnostics-disabled source.
  f.push_read({dv_struct_array<ua::SessionDiagnosticsDataType>({session(31)}), dv_bool(false)});

  std::optional<SessionDiagnosticsArrayResult> captured;
  f.accessor().sessions_async([&captured](SessionDiagnosticsArrayResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());  // data delivered regardless of the flag
  ASSERT_EQ(captured->value().size(), 1U);
  EXPECT_EQ(captured->value()[0].session_id(), node(31));
  EXPECT_TRUE(f.logSink->has_message_containing("client.tier2.server_diagnostics.diagnostics_disabled"));
  ASSERT_EQ(f.advisories->size(), 1U);
  ASSERT_NE((*f.advisories)[0], nullptr);
  EXPECT_EQ((*f.advisories)[0]->code, "ServerDiagnosticsDisabled");
  EXPECT_EQ((*f.advisories)[0]->source, "client.tier2.server_diagnostics.diagnostics_disabled");
}

// @verifies CL-BASEDIAG-003
// @relation(CL-BASEDIAG-003, scope=function)
TEST(ClientServerDiagnosticsEnabledFlag, ThrowingAdvisoryEmitterCannotLoseArrayCompletion)
{
  Fixture f;
  int advisoryCalls = 0;
  f.emitAdvisory = [&advisoryCalls](std::shared_ptr<const ua::ErrorDetail>)
  {
    ++advisoryCalls;
    throw ua::UaException{ua::Status::BadUnexpectedError,
      ua::make_error_detail("InjectedAdvisoryFailure",
        "the deterministic advisory emitter failed",
        "test.server_diagnostics.advisory")};
  };
  f.push_read({dv_struct_array<ua::SessionDiagnosticsDataType>({session(32)}), dv_bool(false)});

  std::optional<SessionDiagnosticsArrayResult> captured;
  f.accessor().sessions_async(
    [&captured](SessionDiagnosticsArrayResult result) { captured = std::move(result); });
  f.run();

  EXPECT_EQ(advisoryCalls, 1);
  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  ASSERT_EQ(captured->value().size(), 1U);
  EXPECT_EQ(captured->value()[0].session_id(), node(32));
}

// @verifies CL-BASEDIAG-003
// @relation(CL-BASEDIAG-003, scope=function)
TEST(ClientServerDiagnosticsEnabledFlag, DisabledAdvisoryFiresOnlyOnFreshFlagReadNotCachedFalse)
{
  Fixture f;
  // First read at T0: cache absent -> the flag is freshly read as false -> the advisory fires (once).
  f.push_read({dv_struct_array<ua::SessionDiagnosticsDataType>({}), dv_bool(false)});
  std::optional<SessionDiagnosticsArrayResult> first;
  f.accessor().sessions_async([&first](SessionDiagnosticsArrayResult r) { first = std::move(r); });
  f.run();
  ASSERT_TRUE(first && first->is_good());

  // Second read at T0+30s: the cached false is still fresh (<=60 s) -> the flag is NOT re-read. The advisory
  // MUST NOT re-fire off a cached false (W2 - no log spam within the TTL). Only a FRESH flag read advises.
  f.advance_seconds(30);
  f.push_read({dv_struct_array<ua::SessionDiagnosticsDataType>({})});  // array only (flag served from cache)
  std::optional<SessionDiagnosticsArrayResult> second;
  f.accessor().sessions_async([&second](SessionDiagnosticsArrayResult r) { second = std::move(r); });
  f.run();
  ASSERT_TRUE(second && second->is_good());

  EXPECT_EQ(f.count_flag_reads(), 1);  // only the first read batched the flag
  // The advisory fired exactly once (on the fresh read), not again off the cached false.
  EXPECT_EQ(f.logSink->count_messages_containing("client.tier2.server_diagnostics.diagnostics_disabled"), 1);
}

// @verifies CL-BASEDIAG-003
// @relation(CL-BASEDIAG-003, scope=function)
TEST(ClientServerDiagnosticsEnabledFlag, UndecodableFlagSuppressesAdvisoryAndDoesNotPoisonCache)
{
  Fixture f;
  // The flag DataValue is not a bool (an Int32) -> to<bool>() fails: the array is still delivered, but no
  // advisory fires and the cache is NOT poisoned (an undecodable flag must not be stored as a false value).
  f.push_read({dv_struct_array<ua::SessionDiagnosticsDataType>({session(51)}),
    ua::DataValue{ua::Variant{std::int32_t{7}}}});
  std::optional<SessionDiagnosticsArrayResult> first;
  f.accessor().sessions_async([&first](SessionDiagnosticsArrayResult r) { first = std::move(r); });
  f.run();
  ASSERT_TRUE(first && first->is_good());  // array delivered regardless of the undecodable flag
  ASSERT_EQ(first->value().size(), 1U);
  EXPECT_FALSE(f.logSink->has_message_containing("client.tier2.server_diagnostics.diagnostics_disabled"));

  // Cache NOT poisoned: a second read within the TTL still batches the flag (the cache was never warmed).
  f.advance_seconds(5);
  f.push_read({dv_struct_array<ua::SessionDiagnosticsDataType>({}), dv_bool(true)});
  std::optional<SessionDiagnosticsArrayResult> second;
  f.accessor().sessions_async([&second](SessionDiagnosticsArrayResult r) { second = std::move(r); });
  f.run();
  ASSERT_TRUE(second && second->is_good());
  EXPECT_EQ(f.count_flag_reads(), 2);  // both reads batched the flag: an undecodable flag never warms cache
}

// @verifies CL-BASEDIAG-003
// @relation(CL-BASEDIAG-003, scope=function)
TEST(ClientServerDiagnosticsEnabledFlag, EnabledFlagCachedFor60s)
{
  Fixture f;
  // First read at T0: cache absent -> the flag is batched (two nodes).
  f.push_read({dv_struct_array<ua::SessionDiagnosticsDataType>({}), dv_bool(true)});
  std::optional<SessionDiagnosticsArrayResult> first;
  f.accessor().sessions_async([&first](SessionDiagnosticsArrayResult r) { first = std::move(r); });
  f.run();
  ASSERT_TRUE(first && first->is_good());
  ASSERT_EQ(f.wireOps->readRequests[0].nodes_to_read().size(), 2U);

  // Second read at T0+30s: cache is fresh (<=60 s) -> the flag is NOT re-read (one node only).
  f.advance_seconds(30);
  f.push_read({dv_struct_array<ua::SessionDiagnosticsDataType>({})});  // array only (no flag value scripted)
  std::optional<SessionDiagnosticsArrayResult> second;
  f.accessor().sessions_async([&second](SessionDiagnosticsArrayResult r) { second = std::move(r); });
  f.run();
  ASSERT_TRUE(second && second->is_good());
  ASSERT_EQ(f.wireOps->readRequests.size(), 2U);
  ASSERT_EQ(f.wireOps->readRequests[1].nodes_to_read().size(), 1U);
  EXPECT_EQ(f.wireOps->readRequests[1].nodes_to_read()[0].node_id(), node(sessionsNode));
  // Exactly ONE EnabledFlag Read across both array reads (the second reused the cache).
  EXPECT_EQ(f.count_flag_reads(), 1);
}

// @verifies CL-BASEDIAG-003
// @relation(CL-BASEDIAG-003, scope=function)
TEST(ClientServerDiagnosticsEnabledFlag, StaleFlagReReadAfter60s)
{
  Fixture f;
  // First read at T0: flag batched.
  f.push_read({dv_struct_array<ua::SessionDiagnosticsDataType>({}), dv_bool(true)});
  std::optional<SessionDiagnosticsArrayResult> first;
  f.accessor().sessions_async([&first](SessionDiagnosticsArrayResult r) { first = std::move(r); });
  f.run();
  ASSERT_TRUE(first && first->is_good());

  // Second read at T0+61s: the cached flag is stale (>60 s) -> the flag is re-read (two nodes again).
  f.advance_seconds(61);
  f.push_read({dv_struct_array<ua::SessionDiagnosticsDataType>({}), dv_bool(true)});
  std::optional<SessionDiagnosticsArrayResult> second;
  f.accessor().sessions_async([&second](SessionDiagnosticsArrayResult r) { second = std::move(r); });
  f.run();
  ASSERT_TRUE(second && second->is_good());
  ASSERT_EQ(f.wireOps->readRequests.size(), 2U);
  EXPECT_EQ(f.wireOps->readRequests[1].nodes_to_read().size(), 2U);
  // Two EnabledFlag Reads total (the stale cache forced a re-read).
  EXPECT_EQ(f.count_flag_reads(), 2);
}

// @verifies CL-BASEDIAG-003
// @relation(CL-BASEDIAG-003, scope=function)
TEST(ClientServerDiagnosticsArrays, ArrayReadCountMismatchIsBad)
{
  Fixture f;
  // The server under-returns: one DataValue for the two-ReadValueId (array + flag) batch -> the W1 guard
  // rejects it BadUnexpectedError with the sessions source.
  f.wireOps->resultsPerReadDelta = -1;
  f.push_read({dv_struct_array<ua::SessionDiagnosticsDataType>({session(41)}), dv_bool(true)});

  std::optional<SessionDiagnosticsArrayResult> captured;
  f.accessor().sessions_async([&captured](SessionDiagnosticsArrayResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadUnexpectedError);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.server_diagnostics.sessions");
}

// @verifies CL-BASEDIAG-003
// @relation(CL-BASEDIAG-003, scope=function)
TEST(ClientServerDiagnosticsArrays, ArrayElementDecodeFailureIsBad)
{
  Fixture f;
  // The array element is the wrong structure type -> the decode fails BadDecodingError with the sessions
  // source; the flag DataValue is still present so the count check passes first.
  f.push_read({dv_wrong_type_array(), dv_bool(true)});

  std::optional<SessionDiagnosticsArrayResult> captured;
  f.accessor().sessions_async([&captured](SessionDiagnosticsArrayResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadDecodingError);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.server_diagnostics.sessions");
}

// @verifies CL-BASEDIAG-003
// @relation(CL-BASEDIAG-003, scope=function)
TEST(ClientServerDiagnosticsArrays, ArrayReadOnGoneConnectionReturnsConnectionClosed)
{
  Fixture f;
  f.wireOps.reset();

  std::optional<SessionDiagnosticsArrayResult> captured;
  f.accessor().sessions_async([&captured](SessionDiagnosticsArrayResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadConnectionClosed);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.server_diagnostics.connection_closed");
}

// ===========================================================================
// set_enabled_flag_async (CL-BASEDIAG-003)
// ===========================================================================

// @verifies CL-BASEDIAG-003
// @relation(CL-BASEDIAG-003, scope=function)
TEST(ClientServerDiagnosticsSetEnabledFlag, WritesRightNodeAndValue)
{
  Fixture f;

  std::optional<ua::VoidResult> captured;
  f.accessor().set_enabled_flag_async(true, [&captured](ua::VoidResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  ASSERT_EQ(f.wireOps->writeRequests.size(), 1U);
  const auto& writeValue = f.wireOps->writeRequests[0].nodes_to_write()[0];
  EXPECT_EQ(writeValue.node_id(), node(enabledFlagNode));
  EXPECT_EQ(writeValue.attribute_id(), valueAttribute);
  ASSERT_TRUE(writeValue.value().value().to<bool>().is_good());
  EXPECT_TRUE(writeValue.value().value().to<bool>().value());
}

// @verifies CL-BASEDIAG-003
// @relation(CL-BASEDIAG-003, scope=function)
TEST(ClientServerDiagnosticsSetEnabledFlag, ServerRejectSurfacesVerbatim)
{
  Fixture f;
  f.wireOps->writeOutcomes.push_back(ua::StatusCode{ua::Status::BadUserAccessDenied});

  std::optional<ua::VoidResult> captured;
  f.accessor().set_enabled_flag_async(true, [&captured](ua::VoidResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadUserAccessDenied);  // verbatim
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.server_diagnostics.set_enabled_flag");
}

// A transport-Good EnabledFlag Write whose ResponseHeader.serviceResult is Bad with an empty results[] MUST
// surface the true serviceResult, not the masked Bad_UnexpectedError the empty-results branch would
// otherwise fabricate (set_enabled_flag_async serviceResult FLATTEN).
// @verifies CL-BASEDIAG-003
// @relation(CL-BASEDIAG-003, scope=function)
TEST(ClientServerDiagnosticsSetEnabledFlag, ServiceFaultSurfacesServiceResultNotMasked)
{
  Fixture f;
  f.wireOps->writeHeaderServiceResult = ua::StatusCode{ua::Status::BadSessionClosed};
  f.wireOps->writeResultsDelta = -1;  // drop the per-write result -> empty results[]: the service-fault shape

  std::optional<ua::VoidResult> captured;
  f.accessor().set_enabled_flag_async(true, [&captured](ua::VoidResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadSessionClosed);
  EXPECT_NE(captured->status_code().as_status(), ua::Status::BadUnexpectedError);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.server_diagnostics.set_enabled_flag");
}

// @verifies CL-BASEDIAG-003
// @relation(CL-BASEDIAG-003, scope=function)
TEST(ClientServerDiagnosticsSetEnabledFlag, SuccessRefreshesCacheSoNextArrayReadSkipsFlag)
{
  Fixture f;
  // A successful set stamps the cache; the next array read within the TTL must NOT re-read the flag.
  std::optional<ua::VoidResult> set;
  f.accessor().set_enabled_flag_async(true, [&set](ua::VoidResult r) { set = std::move(r); });
  f.run();
  ASSERT_TRUE(set && set->is_good());

  f.push_read({dv_struct_array<ua::SessionDiagnosticsDataType>({})});  // array only
  std::optional<SessionDiagnosticsArrayResult> array;
  f.accessor().sessions_async([&array](SessionDiagnosticsArrayResult r) { array = std::move(r); });
  f.run();

  ASSERT_TRUE(array && array->is_good());
  ASSERT_EQ(f.wireOps->readRequests.size(), 1U);
  ASSERT_EQ(f.wireOps->readRequests[0].nodes_to_read().size(), 1U);  // no flag re-read (cache warmed by set)
  EXPECT_EQ(f.count_flag_reads(), 0);
}

// @verifies CL-BASEDIAG-003
// @relation(CL-BASEDIAG-003, scope=function)
TEST(ClientServerDiagnosticsSetEnabledFlag, RejectDoesNotRefreshCache)
{
  Fixture f;
  // A rejected set must NOT warm the cache; the next array read still batches the flag.
  f.wireOps->writeOutcomes.push_back(ua::StatusCode{ua::Status::BadUserAccessDenied});
  std::optional<ua::VoidResult> set;
  f.accessor().set_enabled_flag_async(true, [&set](ua::VoidResult r) { set = std::move(r); });
  f.run();
  ASSERT_TRUE(set && set->is_bad());

  f.push_read({dv_struct_array<ua::SessionDiagnosticsDataType>({}), dv_bool(true)});
  std::optional<SessionDiagnosticsArrayResult> array;
  f.accessor().sessions_async([&array](SessionDiagnosticsArrayResult r) { array = std::move(r); });
  f.run();

  ASSERT_TRUE(array && array->is_good());
  EXPECT_EQ(f.count_flag_reads(), 1);  // the flag was re-read (a rejected set left the cache cold)
}

// @verifies CL-BASEDIAG-003
// @relation(CL-BASEDIAG-003, scope=function)
TEST(ClientServerDiagnosticsSetEnabledFlag, EmptyResultsIsBad)
{
  Fixture f;
  // The server returns a Good Write response carrying no per-write result -> reject BadUnexpectedError with
  // the set-enabled-flag source (the write cannot be confirmed).
  f.wireOps->writeResultsDelta = -1;

  std::optional<ua::VoidResult> captured;
  f.accessor().set_enabled_flag_async(true, [&captured](ua::VoidResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadUnexpectedError);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.server_diagnostics.set_enabled_flag");
}

// @verifies CL-BASEDIAG-003
// @relation(CL-BASEDIAG-003, scope=function)
TEST(ClientServerDiagnosticsSetEnabledFlag, OnGoneConnectionReturnsConnectionClosed)
{
  Fixture f;
  f.wireOps.reset();

  std::optional<ua::VoidResult> captured;
  f.accessor().set_enabled_flag_async(true, [&captured](ua::VoidResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().as_status(), ua::Status::BadConnectionClosed);
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(captured->shared_detail()->source, "client.tier2.server_diagnostics.connection_closed");
}

// ===========================================================================
// subscribe_sessions_async / subscribe_subscriptions_async (CL-BASEDIAG-004)
// ===========================================================================

// The StatusValueTimestamp DataChangeFilter the subscribe-over-poll wrappers must attach.
const ua::DataChangeFilter* data_change_filter(const ua::client::MonitorRequest& request)
{
  return std::get_if<ua::DataChangeFilter>(&request.filter);
}

// @verifies CL-BASEDIAG-004
// @relation(CL-BASEDIAG-004, scope=function)
TEST(ClientServerDiagnosticsSubscribe, SubscribeSessionsBuildsMonitorRequestAndDecodesArrayDelivery)
{
  Fixture f;
  auto factory = std::make_shared<FakeSubscriptionFactory>();
  f.supportOps->subscriptionFactory = factory;

  std::optional<MonitoredItemResult> item;
  std::vector<ua::SessionDiagnosticsDataType> delivered;
  f.accessor().subscribe_sessions_async([&delivered](std::vector<ua::SessionDiagnosticsDataType> sessions)
    { delivered = std::move(sessions); },
    [&item](MonitoredItemResult r) { item = std::move(r); });
  f.run();

  // A managed Subscription was created (server-chosen interval, publishing enabled).
  ASSERT_EQ(factory->creates.size(), 1u);
  EXPECT_DOUBLE_EQ(factory->creates[0].publishingInterval, 0.0);
  EXPECT_TRUE(factory->creates[0].publishingEnabled);

  // The MonitorRequest targets the SessionDiagnosticsArray Variable's Value with server-chosen sampling and a
  // StatusValueTimestamp DataChangeFilter.
  ASSERT_EQ(factory->monitorRequests.size(), 1u);
  const ua::client::MonitorRequest& request = factory->monitorRequests[0];
  EXPECT_EQ(request.nodeId, node(sessionsNode));
  EXPECT_EQ(request.attribute, ua::AttributeId::Value);
  EXPECT_DOUBLE_EQ(request.samplingIntervalMs, 0.0);
  const ua::DataChangeFilter* filter = data_change_filter(request);
  ASSERT_NE(filter, nullptr);
  EXPECT_EQ(filter->trigger(), ua::DataChangeTrigger::StatusValueTimestamp);
  EXPECT_EQ(factory->lastMonitorSubscriptionId, factory->nextSubscriptionId);

  // The returned handle is the unified DataChange MonitoredItem on the array Variable.
  ASSERT_TRUE(item.has_value());
  ASSERT_TRUE(item->is_good());
  EXPECT_EQ(item->value().kind(), MonitoredItemKind::DataChange);
  EXPECT_EQ(item->value().node_id(), node(sessionsNode));

  // A data-change notification carrying the array decodes into the SessionsArrayCallback.
  factory->deliver_data_change(dv_struct_array<ua::SessionDiagnosticsDataType>({session(11), session(22)}));
  ASSERT_EQ(delivered.size(), 2u);
  EXPECT_EQ(delivered[0].session_id(), node(11));
  EXPECT_EQ(delivered[1].session_id(), node(22));
}

// @verifies CL-BASEDIAG-004
// @relation(CL-BASEDIAG-004, scope=function)
TEST(ClientServerDiagnosticsSubscribe, SubscribeSubscriptionsBuildsMonitorRequestAndDecodesArrayDelivery)
{
  Fixture f;
  auto factory = std::make_shared<FakeSubscriptionFactory>();
  f.supportOps->subscriptionFactory = factory;

  std::optional<MonitoredItemResult> item;
  std::vector<ua::SubscriptionDiagnosticsDataType> delivered;
  f.accessor().subscribe_subscriptions_async(
    [&delivered](std::vector<ua::SubscriptionDiagnosticsDataType> subscriptions)
    { delivered = std::move(subscriptions); },
    [&item](MonitoredItemResult r) { item = std::move(r); });
  f.run();

  ASSERT_EQ(factory->monitorRequests.size(), 1u);
  const ua::client::MonitorRequest& request = factory->monitorRequests[0];
  EXPECT_EQ(request.nodeId, node(subscriptionsNode));
  EXPECT_EQ(request.attribute, ua::AttributeId::Value);
  const ua::DataChangeFilter* filter = data_change_filter(request);
  ASSERT_NE(filter, nullptr);
  EXPECT_EQ(filter->trigger(), ua::DataChangeTrigger::StatusValueTimestamp);

  ASSERT_TRUE(item.has_value());
  ASSERT_TRUE(item->is_good());
  EXPECT_EQ(item->value().kind(), MonitoredItemKind::DataChange);
  EXPECT_EQ(item->value().node_id(), node(subscriptionsNode));

  factory->deliver_data_change(
    dv_struct_array<ua::SubscriptionDiagnosticsDataType>({subscription(101), subscription(202)}));
  ASSERT_EQ(delivered.size(), 2u);
  EXPECT_EQ(delivered[0].subscription_id(), 101u);
  EXPECT_EQ(delivered[1].subscription_id(), 202u);
}

// @verifies CL-BASEDIAG-004
// D-DIAG-1: the returned MonitoredItem is persist-on-drop - dropping the handle issues NO delete; only an
// explicit delete_async does.
// @relation(CL-BASEDIAG-004, scope=function)
TEST(ClientServerDiagnosticsSubscribe, SubscribeSessionsReturnsPersistOnDropMonitoredItem)
{
  Fixture f;
  auto factory = std::make_shared<FakeSubscriptionFactory>();
  f.supportOps->subscriptionFactory = factory;

  std::optional<MonitoredItemResult> item;
  f.accessor().subscribe_sessions_async([](std::vector<ua::SessionDiagnosticsDataType>) {},
    [&item](MonitoredItemResult r) { item = std::move(r); });
  f.run();
  ASSERT_TRUE(item.has_value() && item->is_good());

  // Dropping a COPY of the handle is a no-op (persist-on-drop) - no DeleteMonitoredItems is issued.
  {
    MonitoredItem dropMe = item->value();
    (void)dropMe;
  }
  EXPECT_EQ(factory->deleteCalls, 0u);

  // An EXPLICIT delete_async is the only way to stop the stream.
  std::optional<ua::VoidResult> deleteResult;
  item->value().delete_async([&deleteResult](ua::VoidResult r) { deleteResult = r; });
  f.run();
  ASSERT_TRUE(deleteResult.has_value());
  EXPECT_TRUE(deleteResult->is_good());
  EXPECT_EQ(factory->deleteCalls, 1u);
}

// @verifies CL-BASEDIAG-004
// @relation(CL-BASEDIAG-004, scope=function)
TEST(ClientServerDiagnosticsSubscribe, SubscribeSessionsGoneFactoryReturnsConnectionClosed)
{
  Fixture f;
  f.supportOps->subscriptionFactory = nullptr;  // no factory available == a gone interface

  std::optional<MonitoredItemResult> item;
  f.accessor().subscribe_sessions_async([](std::vector<ua::SessionDiagnosticsDataType>) {},
    [&item](MonitoredItemResult r) { item = std::move(r); });
  f.run();

  ASSERT_TRUE(item.has_value());
  ASSERT_TRUE(item->is_bad());
  EXPECT_EQ(item->status_code().as_status(), ua::Status::BadConnectionClosed);
  ASSERT_NE(item->shared_detail(), nullptr);
  EXPECT_EQ(item->shared_detail()->source, "client.tier2.server_diagnostics.subscribe_sessions");
}

// @verifies CL-BASEDIAG-004
// Falsifiability: a wrapper that swallowed a bad CreateSubscription (and still returned a Good handle) would
// fail this - the create failure must surface as the item Result.
// @relation(CL-BASEDIAG-004, scope=function)
TEST(ClientServerDiagnosticsSubscribe, SubscribeSessionsCreateFailureSurfacesAsBadResult)
{
  Fixture f;
  auto factory = std::make_shared<FakeSubscriptionFactory>();
  factory->createStatus = ua::StatusCode{ua::Status::BadTooManyOperations};
  f.supportOps->subscriptionFactory = factory;

  std::optional<MonitoredItemResult> item;
  f.accessor().subscribe_sessions_async([](std::vector<ua::SessionDiagnosticsDataType>) {},
    [&item](MonitoredItemResult r) { item = std::move(r); });
  f.run();

  ASSERT_TRUE(item.has_value());
  ASSERT_TRUE(item->is_bad());
  EXPECT_EQ(item->status_code().as_status(), ua::Status::BadTooManyOperations);
  EXPECT_EQ(factory->monitorRequests.size(), 0u);  // no monitor after a failed create
}

// ===========================================================================
// Status routing: the server's code reaches the application
// ===========================================================================

// The EnabledFlag write's Good subcode is the write's result.
// @relation(AC-CL-STATUS-ROUTING-01-A-WRITES-GOOD-SUBCODE-REACHES-THE-APPLICATION, scope=function)
TEST(ClientServerDiagnosticsStatusRouting, ASetEnabledFlagGoodSubcodeReachesTheApplication)
{
  for (const ua::Status itemStatus : {ua::Status::GoodCompletesAsynchronously, ua::Status::GoodClamped})
  {
    SCOPED_TRACE(ua::StatusCode{itemStatus}.value());
    Fixture f;
    f.wireOps->writeOutcomes.push_back(ua::StatusCode{itemStatus});

    std::optional<ua::VoidResult> captured;
    f.accessor().set_enabled_flag_async(true, [&captured](ua::VoidResult r) { captured = std::move(r); });
    f.run();

    ASSERT_TRUE(captured.has_value());
    EXPECT_TRUE(captured->is_good());
    EXPECT_EQ(captured->status_code(), ua::StatusCode{itemStatus});
  }
}

// An Uncertain EnabledFlag write is the write's result, and the cache is not refreshed from it: the next
// array read still reads the flag.
// @relation(AC-CL-STATUS-ROUTING-01-A-WRITES-GOOD-SUBCODE-REACHES-THE-APPLICATION, scope=function)
TEST(ClientServerDiagnosticsStatusRouting, AnUncertainSetEnabledFlagReachesTheApplicationAndLeavesTheCache)
{
  Fixture f;
  f.wireOps->writeOutcomes.push_back(ua::StatusCode{ua::Status::UncertainNotAllNodesAvailable});

  std::optional<ua::VoidResult> captured;
  f.accessor().set_enabled_flag_async(true, [&captured](ua::VoidResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_uncertain());
  EXPECT_EQ(captured->status_code(), ua::StatusCode{ua::Status::UncertainNotAllNodesAvailable});

  f.push_read({dv_struct_array<ua::SessionDiagnosticsDataType>({session(1)}), dv_bool(true)});
  std::optional<SessionDiagnosticsArrayResult> array;
  f.accessor().sessions_async([&array](SessionDiagnosticsArrayResult r) { array = std::move(r); });
  f.run();
  ASSERT_TRUE(array.has_value());
  EXPECT_EQ(f.count_flag_reads(), 1);
}

// A summary answered Uncertain with its value gives the value with the Uncertain code.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(ClientServerDiagnosticsStatusRouting, AnUncertainSummaryKeepsItsValueAndCode)
{
  Fixture f;
  ua::DataValue summary = dv_summary(7);
  summary.status() = ua::StatusCode{ua::Status::UncertainLastUsableValue};
  f.push_read({std::move(summary)});

  std::optional<ServerDiagnosticsSummaryResult> captured;
  f.accessor().summary_async([&captured](ServerDiagnosticsSummaryResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_uncertain());
  EXPECT_EQ(captured->status_code(), ua::StatusCode{ua::Status::UncertainLastUsableValue});
  EXPECT_EQ(captured->value_or(ua::ServerDiagnosticsSummaryDataType{}).current_session_count(), 7U);
}

// A summary answered Uncertain without a value gives the code and no value (not a decode failure).
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(ClientServerDiagnosticsStatusRouting, AnUncertainSummaryWithoutAValueGivesTheCodeAlone)
{
  Fixture f;
  f.push_read(
    {ua::DataValue{ua::Variant{}, ua::StatusCode{ua::Status::UncertainNoCommunicationLastUsableValue}}});

  std::optional<ServerDiagnosticsSummaryResult> captured;
  f.accessor().summary_async([&captured](ServerDiagnosticsSummaryResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_uncertain());
  EXPECT_EQ(captured->status_code(), ua::StatusCode{ua::Status::UncertainNoCommunicationLastUsableValue});
  EXPECT_THROW(static_cast<void>(captured->value()), ua::UaException);
}

// A Good subcode on the array's DataValue reaches the caller with the array.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(ClientServerDiagnosticsStatusRouting, AnArraysGoodSubcodeReachesTheApplication)
{
  Fixture f;
  ua::DataValue array = dv_struct_array<ua::SessionDiagnosticsDataType>({session(41)});
  array.status() = ua::StatusCode{ua::Status::GoodLocalOverride};
  f.push_read({std::move(array), dv_bool(true)});

  std::optional<SessionDiagnosticsArrayResult> captured;
  f.accessor().sessions_async([&captured](SessionDiagnosticsArrayResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_EQ(captured->status_code(), ua::StatusCode{ua::Status::GoodLocalOverride});
  ASSERT_EQ(captured->value().size(), 1U);
  EXPECT_EQ(captured->value()[0].session_id(), node(41));
}

// The SDK decides on the EnabledFlag itself, so a flag answered Uncertain is not used: no disabled-advisory
// fires and nothing is cached (the next array read reads the flag again).
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(ClientServerDiagnosticsStatusRouting, AnUncertainEnabledFlagIsNotUsed)
{
  Fixture f;
  f.push_read({dv_struct_array<ua::SessionDiagnosticsDataType>({session(51)}),
    ua::DataValue{ua::Variant{false}, ua::StatusCode{ua::Status::UncertainLastUsableValue}}});

  std::optional<SessionDiagnosticsArrayResult> captured;
  f.accessor().sessions_async([&captured](SessionDiagnosticsArrayResult r) { captured = std::move(r); });
  f.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_TRUE(f.advisories->empty());
  EXPECT_FALSE(f.logSink->has_message_containing("client.tier2.server_diagnostics.diagnostics_disabled"));

  f.push_read({dv_struct_array<ua::SessionDiagnosticsDataType>({session(52)}), dv_bool(true)});
  std::optional<SessionDiagnosticsArrayResult> second;
  f.accessor().sessions_async([&second](SessionDiagnosticsArrayResult r) { second = std::move(r); });
  f.run();
  ASSERT_TRUE(second.has_value());
  EXPECT_EQ(f.count_flag_reads(), 2);
}

// The array callback has no place for a status, so a Bad notification is not delivered (rather than as an
// empty array).
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(ClientServerDiagnosticsStatusRouting, ABadNotificationIsNotDeliveredToTheArrayCallback)
{
  Fixture f;
  auto factory = std::make_shared<FakeSubscriptionFactory>();
  f.supportOps->subscriptionFactory = factory;

  std::optional<MonitoredItemResult> item;
  int deliveries = 0;
  f.accessor().subscribe_sessions_async([&deliveries](std::vector<ua::SessionDiagnosticsDataType>)
    { ++deliveries; },
    [&item](MonitoredItemResult r) { item = std::move(r); });
  f.run();
  ASSERT_TRUE(item.has_value() && item->is_good());

  factory->deliver_data_change(ua::DataValue{ua::Variant{}, ua::StatusCode{ua::Status::BadUserAccessDenied}});
  EXPECT_EQ(deliveries, 0);

  factory->deliver_data_change(dv_struct_array<ua::SessionDiagnosticsDataType>({session(61)}));
  EXPECT_EQ(deliveries, 1);
}

}  // namespace
