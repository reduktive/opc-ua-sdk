// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Client-side Historical Access matrix (tier-2 HistoryFacade over a real client/Server pair). Currently pins
// the CL-HIST-014 AggregateConfiguration override reaching the wire: a real client drives
// Connection::history().read_processed with a per-call AggregateConfiguration, and the MisbehavingServer's
// request observer captures the outgoing ReadProcessedDetails to prove the override was plumbed onto the wire
// (not the useServerCapabilitiesDefaults=true sentinel). The full round-trip / rejected-hint rows are
// unit-covered in history_read_cursor_client_history_facade_tests.cpp.

#include "compliance_helpers.h"
#include "test_utilities.h"

#include "misbehaving_server.h"

#include "ua_connection.h"
#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_history_facade.h"
#include "ua_session_attribute_services.h"

#include "ua_aggregate_configuration.h"
#include "ua_access_level_type.h"
#include "ua_attribute_id.h"
#include "ua_client.h"
#include "ua_client_secure_channel.h"
#include "ua_client_session.h"
#include "ua_date_time.h"
#include "ua_delete_at_time_details.h"
#include "ua_delete_raw_modified_details.h"
#include "ua_error_detail_keys.h"
#include "ua_history_data.h"
#include "ua_namespace_history_delegate.h"
#include "ua_history_update_request.h"
#include "ua_history_read_request.h"
#include "ua_history_read_response.h"
#include "ua_history_read_result.h"
#include "ua_history_read_value_id.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_read_processed_details.h"
#include "ua_read_response.h"
#include "ua_status.h"
#include "ua_structure.h"
#include "ua_timestamps_to_return.h"
#include "ua_update_data_details.h"

#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <any>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <gtest/gtest.h>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

using ua::test_helpers::MisbehavingServer;

namespace
{

// Wraps a ConnectionImpl (built over an activated Session) into the public tier-2 Connection handle, runs the
// bootstrap, and closes on destruction. Mirror of the ClientRead/ClientWrite/ClientIndex slices.
class StartedConnection
{
public:
  StartedConnection(boost::asio::any_io_executor executor, Session session)
  {
    auto impl = ua::client::detail::ConnectionImpl::create(
      std::move(executor), std::move(session), ua::client::detail::ConnectionConfig{}, Logger{});

    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    impl->start_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
    mStartStatus = future.get();

    mConnection.emplace(ua::client::detail::ConnectionHandleFactory::make_connection(std::move(impl)));
  }

  ~StartedConnection()
  {
    if (mConnection)
      (void)mConnection->try_close_sync();
  }

  StartedConnection(const StartedConnection&) = delete;
  StartedConnection& operator=(const StartedConnection&) = delete;

  const VoidResult& start_status() const
  {
    return mStartStatus;
  }

  Connection& operator*()
  {
    return *mConnection;
  }

  Connection* operator->()
  {
    return &*mConnection;
  }

private:
  VoidResult mStartStatus{};
  std::optional<Connection> mConnection;
};

// A real client bound to a MisbehavingServer's crypto + trusted cert store, on its own thread pool, with an
// activated Session wrapped into a started tier-2 Connection. The bootstrap completes against the un-mutated
// server; the test arms the request observer AFTER construction.
class MisbehavingHistoryFixture
{
public:
  explicit MisbehavingHistoryFixture(MisbehavingServer& server)
  {
    auto appConfig = ua::test_utils::create_test_config();
    appConfig.application_description_part().applicationUri = "urn:test:misbehaving:client";
    ua::client::CreateConfig clientConfig{
      .identity = ApplicationIdentity::load_default(), .application = std::move(appConfig)};
    mClient.emplace(Client::create(mThreadPool.executor(),
      std::move(clientConfig),
      ua::client::ClientComponents{.crypto = server.crypto(),
        .applicationGroupCertificateStore = server.client_certificate_store(),
        .logLevel = LogLevel::Warning}));

    CoreClient::OpenChannelConfig openConfig;
    openConfig.endpointUrl = server.endpoint_url_none();
    openConfig.timeout = 5000ms;
    auto channel = mClient->core().open_channel_sync(openConfig);
    auto session = channel.create_session_sync({.sessionName = "ClientHistoryMatrix"});
    session.activate_sync();
    mConnection.emplace(mThreadPool.executor(), std::move(session));
  }

  ~MisbehavingHistoryFixture()
  {
    mConnection.reset();
    mClient.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  MisbehavingHistoryFixture(const MisbehavingHistoryFixture&) = delete;
  MisbehavingHistoryFixture& operator=(const MisbehavingHistoryFixture&) = delete;

  Connection& conn()
  {
    return **mConnection;
  }

  const VoidResult& start_status() const
  {
    return mConnection->start_status();
  }

private:
  boost::asio::thread_pool mThreadPool;
  std::optional<Client> mClient;
  std::optional<StartedConnection> mConnection;
};

}  // namespace

class ClientHistory : public ::testing::Test
{};

class HistoryCapabilityIntegration : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();
    mHistorizingNode = ua::NodeId{mTestNamespaceIndex, 1900};
    auto variable = mServer.server()
                      .address_space()
                      .create_node_sync(mHistorizingNode, ua::NodeClass::Variable)
                      .as<ua::VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_browse_name(ua::QualifiedName{mTestNamespaceIndex, "HistorizingVariable"});
    variable->set_display_name(ua::LocalizedText{"", "HistorizingVariable"});
    variable->set_data_type(ua::NodeId{ua::DataTypeId::Double});
    variable->set_access_level(ua::AccessLevelType{ua::AccessLevelType::Bit::CurrentRead,
      ua::AccessLevelType::Bit::HistoryRead,
      ua::AccessLevelType::Bit::HistoryWrite});

    mConfigurationNode = ua::NodeId{mTestNamespaceIndex, 1901};
    auto configuration = mServer.server()
                           .address_space()
                           .create_node_sync(mConfigurationNode, ua::NodeClass::Object)
                           .as<ua::ObjectAccessor>();
    ASSERT_TRUE(configuration.has_value());
    configuration->set_browse_name(ua::QualifiedName{0, "HA Configuration"});
    configuration->set_display_name(ua::LocalizedText{"", "HA Configuration"});
    mServer.server()
      .address_space()
      .find_node_sync(mHistorizingNode)
      .add_reference_sync(ua::NodeId{ua::ReferenceTypeId::HasHistoricalConfiguration}, mConfigurationNode);
  }

  ua::client::Session open_activated_session()
  {
    auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
    auto session = channel.create_session_sync({.sessionName = "HistoryCapabilityIntegration"});
    session.activate_sync();
    return session;
  }

  ua::NodeId mHistorizingNode;
  ua::NodeId mConfigurationNode;
};

// @verifies CL-HIST-001 [integration]
// @relation(CL-HIST-001, scope=function)
TEST_F(HistoryCapabilityIntegration, PublicFacadeReadsAccessLevelAndCachesResult)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session()};
  ASSERT_TRUE(connection.start_status().is_good());
  auto history = connection->history();

  auto historizing = history.try_is_history_capable_sync(mHistorizingNode);
  auto plain = history.try_is_history_capable_sync(mWritableVariableId);
  ASSERT_TRUE(historizing.is_good());
  ASSERT_TRUE(plain.is_good());
  EXPECT_TRUE(historizing.value());
  EXPECT_FALSE(plain.value());

  auto variable =
    mServer.server().address_space().find_node_sync(mHistorizingNode).as<ua::VariableAccessor>();
  ASSERT_TRUE(variable.has_value());
  variable->set_access_level(ua::AccessLevelType{ua::AccessLevelType::Bit::CurrentRead});
  auto cached = history.try_is_history_capable_sync(mHistorizingNode);

  ASSERT_TRUE(cached.is_good());
  EXPECT_TRUE(cached.value())
    << "the second probe must retain the session-lifetime result instead of re-reading changed server state";
}

// @verifies CL-HIST-002 [integration]
// @relation(CL-HIST-002, scope=function)
TEST_F(HistoryCapabilityIntegration, PublicFacadeDiscoversHistoricalConfiguration)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session()};
  ASSERT_TRUE(connection.start_status().is_good());

  auto result = connection->history().try_historical_configurations_sync(mHistorizingNode);

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value(), (std::vector<ua::NodeId>{mConfigurationNode}));
}

// @verifies CL-HIST-020 [integration]
// @relation(CL-HIST-020, scope=function)
TEST_F(HistoryCapabilityIntegration, PublicUpdaterRejectsFalseInsertDataCapability)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session()};
  ASSERT_TRUE(connection.start_status().is_good());

  ua::DataValue value{ua::Variant{1.0}};
  value.source_timestamp() = ua::DateTime{2025, 1, 1, 0, 0, 1.0};
  auto result = connection->history().try_insert_data_sync(mHistorizingNode, {value});

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadHistoryOperationUnsupported);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "HistoryUpdateCapabilityMissing");
  EXPECT_EQ(::ua::test_utils::error_context(result.shared_detail().get(), ua::ContextKeys::fieldName.value()),
    "InsertDataCapability");
}

// =============================================================================================
// Row - ReadProcessedAggregateConfigOverridePlumbedToWire  (MisbehavingServer, request capture; CL-HIST-014)
// A per-call AggregateConfiguration{useServerCapabilitiesDefaults=false, treatUncertainAsBad=false,
// percentDataBad=50} must be plumbed onto the wire ReadProcessedDetails verbatim. The server has no
// historizing node, so the read itself fails - but the request observer captures the outgoing details,
// proving the override reached the wire and not the server-defaults sentinel. Falsified if the wire shows
// defaults.
// =============================================================================================
// @verifies CL-HIST-006
// @verifies CL-HIST-014
// @relation(CL-HIST-006, CL-HIST-014, scope=function)
TEST_F(ClientHistory, ReadProcessedAggregateConfigOverridePlumbedToWire)
{
  MisbehavingServer server;
  MisbehavingHistoryFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  struct CapturedProcessedDetails
  {
    std::optional<ua::AggregateConfiguration> config;
    std::optional<ua::NodeId> aggregateType;
  };

  auto captured = std::make_shared<CapturedProcessedDetails>();
  server.set_request_observer(
    [captured](const ua::Structure& request)
    {
      const auto* historyRead = dynamic_cast<const ua::HistoryReadRequest*>(&request);
      if (historyRead == nullptr)
        return;
      const auto* details =
        dynamic_cast<const ua::ReadProcessedDetails*>(historyRead->history_read_details().get());
      if (details != nullptr)
      {
        captured->config = details->aggregate_configuration();
        if (!details->aggregate_type().empty())
          captured->aggregateType = details->aggregate_type()[0];
      }
    });

  HistoryReadOptions options;
  ua::AggregateConfiguration config;
  config.use_server_capabilities_defaults() = false;
  config.treat_uncertain_as_bad() = false;
  config.percent_data_bad() = 50;
  options.aggregateConfiguration = config;

  TimeRange range;
  range.startTime = ua::DateTime{2025, 1, 1, 0, 0, 0.0};
  range.endTime = ua::DateTime{2025, 1, 1, 0, 0, 9.0};
  range.numValuesPerNode = 100;

  // Drive a processed read. The read's Result is unimportant (no historizing node) - the observer captures
  // the wire ReadProcessedDetails synchronously before the sync call returns.
  const ua::NodeId vendorAggregate{2, 9001};
  (void)fixture.conn().history().try_read_processed_sync(
    ua::NodeId{0, 2258}, range, vendorAggregate, 1000.0, options);

  ASSERT_TRUE(captured->config.has_value())
    << "the client must send a ReadProcessedDetails for a processed read";
  ASSERT_TRUE(captured->aggregateType.has_value());
  EXPECT_EQ(*captured->aggregateType, vendorAggregate)
    << "the public history facade must preserve a vendor AggregateFunction NodeId verbatim";
  EXPECT_FALSE(captured->config->use_server_capabilities_defaults())
    << "the per-call override must reach the wire, not the useServerCapabilitiesDefaults=true sentinel";
  EXPECT_FALSE(captured->config->treat_uncertain_as_bad());
  EXPECT_EQ(captured->config->percent_data_bad(), 50);
}

// Public updater methods intentionally issue one operation flavour per HistoryUpdate call. Part 11
// section 6.8 recommends separate calls because mixed DataValue/Event/Annotation requests may bypass
// operation limits or be rejected Bad_TooManyOperations.
// @verifies CL-HIST-024
// @relation(CL-HIST-024, scope=function)
TEST_F(ClientHistory, PublicUpdaterEmitsSingleFlavourCalls)
{
  MisbehavingServer server;
  MisbehavingHistoryFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  server.set_response_mutator(
    [](ua::Response& response)
    {
      auto* read = dynamic_cast<ua::ReadResponse*>(response.second.get());
      if (read == nullptr)
        return;
      if (read->results().size() == 1)
      {
        read->results()[0] = ua::DataValue{
          ua::Variant{ua::AccessLevelType{ua::AccessLevelType::Bit::HistoryWrite}.as_underlying_type()}};
      }
      else if (read->results().size() == 5)
      {
        for (auto& value : read->results())
          value = ua::DataValue{ua::Variant{true}};
      }
    });

  enum class DetailKind
  {
    UpdateData,
    DeleteAtTime,
    Other
  };
  auto captured = std::make_shared<std::vector<std::pair<std::size_t, DetailKind>>>();
  auto captureMutex = std::make_shared<std::mutex>();
  server.set_request_observer(
    [captured, captureMutex](const ua::Structure& request)
    {
      const auto* update = dynamic_cast<const ua::HistoryUpdateRequest*>(&request);
      if (update == nullptr)
        return;
      DetailKind kind = DetailKind::Other;
      if (update->history_update_details().size() == 1U)
      {
        const auto* detail = update->history_update_details()[0].get();
        if (dynamic_cast<const ua::UpdateDataDetails*>(detail) != nullptr)
          kind = DetailKind::UpdateData;
        else if (dynamic_cast<const ua::DeleteAtTimeDetails*>(detail) != nullptr)
          kind = DetailKind::DeleteAtTime;
      }
      std::lock_guard lock(*captureMutex);
      captured->emplace_back(update->history_update_details().size(), kind);
    });

  ua::DataValue value;
  value.value() = ua::Variant{std::int32_t{42}};
  (void)fixture.conn().history().try_update_data_sync(
    ua::NodeId{0, 2258}, {value}, ua::PerformUpdateType::Update);
  (void)fixture.conn().history().try_delete_at_time_sync(
    ua::NodeId{0, 2258}, {ua::DateTime{2025, 1, 1, 0, 0, 0.0}});

  std::lock_guard lock(*captureMutex);
  ASSERT_EQ(captured->size(), 2U);
  EXPECT_EQ((*captured)[0], (std::pair<std::size_t, DetailKind>{1U, DetailKind::UpdateData}));
  EXPECT_EQ((*captured)[1], (std::pair<std::size_t, DetailKind>{1U, DetailKind::DeleteAtTime}));
}

// Part 11 section 5.2.4 makes `AccessLevel.HistoryWrite` the per-Node gate and section 5.4.2 makes the
// `HistoryServerCapabilities` flags the per-server gate. The two are independent - a Node advertising
// HistoryWrite on a server that cannot insert is a conforming configuration - so a plausible client that
// consults only one of them emits a HistoryUpdate the server rejects with a code naming neither. Both
// refusals belong on the client side of the wire, and each must say which gate failed.
// @verifies AC-CL-HIST-020-CAPABILITY-BEFORE-UPDATE
TEST_F(ClientHistory, HistoryUpdateIsWithheldUnlessAccessLevelAndCapabilityBothAllowIt)
{
  // Gate 1 - the target Node's AccessLevel lacks HistoryWrite while the server advertises every update
  // capability as true. A client that consulted only HistoryServerCapabilities would put this on the wire.
  {
    MisbehavingServer server;
    MisbehavingHistoryFixture fixture{server};
    ASSERT_TRUE(fixture.start_status().is_good());

    server.set_response_mutator(
      [](ua::Response& response)
      {
        auto* read = dynamic_cast<ua::ReadResponse*>(response.second.get());
        if (read == nullptr)
          return;
        if (read->results().size() == 1)
        {
          read->results()[0] = ua::DataValue{
            ua::Variant{ua::AccessLevelType{ua::AccessLevelType::Bit::CurrentRead}.as_underlying_type()}};
        }
        else if (read->results().size() == 5)
        {
          for (auto& value : read->results())
            value = ua::DataValue{ua::Variant{true}};
        }
      });

    auto updatesOnWire = std::make_shared<std::atomic<int>>(0);
    server.set_request_observer(
      [updatesOnWire](const ua::Structure& request)
      {
        if (dynamic_cast<const ua::HistoryUpdateRequest*>(&request) != nullptr)
          updatesOnWire->fetch_add(1);
      });

    ua::DataValue value{ua::Variant{1.0}};
    value.source_timestamp() = ua::DateTime{2025, 1, 1, 0, 0, 1.0};
    auto result = fixture.conn().history().try_insert_data_sync(ua::NodeId{0, 2258}, {value});

    ASSERT_TRUE(result.is_bad()) << "an insert against a Node without HistoryWrite must be refused";
    EXPECT_EQ(result.status_code().as_status(), ua::Status::BadHistoryOperationUnsupported);
    ASSERT_NE(result.shared_detail(), nullptr);
    EXPECT_EQ(result.shared_detail()->code, "HistoryWriteNotAdvertised")
      << "the refusal must name the AccessLevel gate, not the server-capability gate";
    EXPECT_NE(result.shared_detail()->summary.find("HistoryWrite"), std::string::npos);
    EXPECT_EQ(updatesOnWire->load(), 0)
      << "a HistoryUpdate refused on AccessLevel must never be sent to the server";
  }

  // Gate 2 - the Node advertises HistoryWrite but the server's InsertDataCapability is false. A client that
  // consulted only AccessLevel would put this on the wire.
  {
    MisbehavingServer server;
    MisbehavingHistoryFixture fixture{server};
    ASSERT_TRUE(fixture.start_status().is_good());

    server.set_response_mutator(
      [](ua::Response& response)
      {
        auto* read = dynamic_cast<ua::ReadResponse*>(response.second.get());
        if (read == nullptr)
          return;
        if (read->results().size() == 1)
        {
          read->results()[0] = ua::DataValue{
            ua::Variant{ua::AccessLevelType{ua::AccessLevelType::Bit::HistoryWrite}.as_underlying_type()}};
        }
        else if (read->results().size() == 5)
        {
          for (auto& value : read->results())
            value = ua::DataValue{ua::Variant{false}};
        }
      });

    auto updatesOnWire = std::make_shared<std::atomic<int>>(0);
    server.set_request_observer(
      [updatesOnWire](const ua::Structure& request)
      {
        if (dynamic_cast<const ua::HistoryUpdateRequest*>(&request) != nullptr)
          updatesOnWire->fetch_add(1);
      });

    ua::DataValue value{ua::Variant{1.0}};
    value.source_timestamp() = ua::DateTime{2025, 1, 1, 0, 0, 1.0};
    auto result = fixture.conn().history().try_insert_data_sync(ua::NodeId{0, 2258}, {value});

    ASSERT_TRUE(result.is_bad()) << "an insert against a server without InsertDataCapability must be refused";
    EXPECT_EQ(result.status_code().as_status(), ua::Status::BadHistoryOperationUnsupported);
    ASSERT_NE(result.shared_detail(), nullptr);
    EXPECT_EQ(result.shared_detail()->code, "HistoryUpdateCapabilityMissing")
      << "the refusal must name the server-capability gate, not the AccessLevel gate";
    const auto capabilityFact = std::ranges::find(
      result.shared_detail()->context, std::string{ua::ContextKeys::fieldName.value()}, &ua::NamedValue::key);
    ASSERT_NE(capabilityFact, result.shared_detail()->context.end());
    EXPECT_EQ(capabilityFact->value, "InsertDataCapability");
    EXPECT_EQ(updatesOnWire->load(), 0)
      << "a HistoryUpdate refused on HistoryServerCapabilities must never be sent to the server";
  }
}

// Part 11 section 6.8: a HistoryUpdate carrying two or more of DataValues, Events and Annotations lets the
// server ignore MaxNodesPerHistoryUpdateData / -Events and licenses it to fail the whole request with
// Bad_TooManyOperations, so the caller gets a result it cannot interpret. A plausible client coalesces
// whatever the caller queued into one request to save a round trip; the SDK must instead emit one request
// per flavour, each carrying exactly one `historyUpdateDetails` entry - including when a single call batches
// several values of the same flavour.
// @verifies AC-CL-HIST-024-SINGLE-FLAVOUR-UPDATE
TEST_F(ClientHistory, HistoryUpdateNeverCarriesMoreThanOneUpdateFlavour)
{
  MisbehavingServer server;
  MisbehavingHistoryFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  // Let every pre-flight through (AccessLevel.HistoryWrite set, every capability true) so each updater
  // method actually reaches the wire and the emitted requests can be inspected.
  server.set_response_mutator(
    [](ua::Response& response)
    {
      auto* read = dynamic_cast<ua::ReadResponse*>(response.second.get());
      if (read == nullptr)
        return;
      if (read->results().size() == 1)
      {
        read->results()[0] = ua::DataValue{
          ua::Variant{ua::AccessLevelType{ua::AccessLevelType::Bit::HistoryWrite}.as_underlying_type()}};
      }
      else if (read->results().size() == 5)
      {
        for (auto& value : read->results())
          value = ua::DataValue{ua::Variant{true}};
      }
    });

  enum class FlavourKind
  {
    UpdateData,
    DeleteRawModified,
    DeleteAtTime,
    Mixed,
    Other
  };
  auto captured = std::make_shared<std::vector<std::pair<std::size_t, FlavourKind>>>();
  auto captureMutex = std::make_shared<std::mutex>();
  server.set_request_observer(
    [captured, captureMutex](const ua::Structure& request)
    {
      const auto* update = dynamic_cast<const ua::HistoryUpdateRequest*>(&request);
      if (update == nullptr)
        return;

      // Classify the whole details array: a request mixing flavours is reported as Mixed, so a coalescing
      // client is distinguishable from one that merely batches.
      std::optional<FlavourKind> seen;
      FlavourKind kind = FlavourKind::Other;
      for (const auto& entry : update->history_update_details())
      {
        const auto* detail = entry.get();
        FlavourKind entryKind = FlavourKind::Other;
        if (dynamic_cast<const ua::UpdateDataDetails*>(detail) != nullptr)
          entryKind = FlavourKind::UpdateData;
        else if (dynamic_cast<const ua::DeleteRawModifiedDetails*>(detail) != nullptr)
          entryKind = FlavourKind::DeleteRawModified;
        else if (dynamic_cast<const ua::DeleteAtTimeDetails*>(detail) != nullptr)
          entryKind = FlavourKind::DeleteAtTime;

        if (!seen.has_value())
        {
          seen = entryKind;
          kind = entryKind;
        }
        else if (*seen != entryKind)
        {
          kind = FlavourKind::Mixed;
        }
      }

      std::lock_guard lock(*captureMutex);
      captured->emplace_back(update->history_update_details().size(), kind);
    });

  const ua::NodeId node{0, 2258};

  // A same-flavour batch of two values: still one detail entry, still one flavour.
  ua::DataValue first{ua::Variant{1.0}};
  first.source_timestamp() = ua::DateTime{2025, 1, 1, 0, 0, 1.0};
  ua::DataValue second{ua::Variant{2.0}};
  second.source_timestamp() = ua::DateTime{2025, 1, 1, 0, 0, 2.0};
  (void)fixture.conn().history().try_insert_data_sync(node, {first, second});
  (void)fixture.conn().history().try_replace_data_sync(node, {first});
  (void)fixture.conn().history().try_update_data_sync(node, {first}, ua::PerformUpdateType::Update);

  TimeRange range;
  range.startTime = ua::DateTime{2025, 1, 1, 0, 0, 0.0};
  range.endTime = ua::DateTime{2025, 1, 1, 0, 0, 9.0};
  (void)fixture.conn().history().try_delete_raw_modified_sync(node, range, /*isDeleteModified=*/false);
  (void)fixture.conn().history().try_delete_at_time_sync(node, {ua::DateTime{2025, 1, 1, 0, 0, 1.0}});

  std::lock_guard lock(*captureMutex);
  ASSERT_FALSE(captured->empty()) << "no HistoryUpdate reached the wire: nothing was exercised";
  ASSERT_EQ(captured->size(), 5U)
    << "the five update flavours must be split into five separate HistoryUpdate calls";
  for (std::size_t index = 0; index < captured->size(); ++index)
  {
    EXPECT_EQ((*captured)[index].first, 1U)
      << "HistoryUpdate " << index << " must carry exactly one historyUpdateDetails entry";
    EXPECT_NE((*captured)[index].second, FlavourKind::Mixed)
      << "HistoryUpdate " << index << " mixed update flavours in a single request";
    EXPECT_NE((*captured)[index].second, FlavourKind::Other)
      << "HistoryUpdate " << index << " carried an unrecognised update detail";
  }
  EXPECT_EQ((*captured)[0].second, FlavourKind::UpdateData);
  EXPECT_EQ((*captured)[1].second, FlavourKind::UpdateData);
  EXPECT_EQ((*captured)[2].second, FlavourKind::UpdateData);
  EXPECT_EQ((*captured)[3].second, FlavourKind::DeleteRawModified);
  EXPECT_EQ((*captured)[4].second, FlavourKind::DeleteAtTime);
}

namespace
{

// The historized node carries this many values; the read below caps each page below it so the client is
// forced through the continuation-point dance.
constexpr std::size_t pagedHistoryValueCount = 10;

// A history delegate that serves stored values strictly page-by-page: the cursor it hands back is the offset
// of the next unread value, so a client that drops, re-sends or ignores the continuation point produces a
// concatenation that repeats or omits values. The delegate itself never repeats a value, which is what makes
// the client the only candidate explanation for a malformed concatenation.
class PagingHistoryDelegate : public ua::NamespaceHistoryDelegate
{
public:
  void add_values(const ua::NodeId& nodeId, std::vector<ua::DataValue> values)
  {
    std::lock_guard lock(mMutex);
    auto& existing = mData[nodeId];
    existing.insert(
      existing.end(), std::make_move_iterator(values.begin()), std::make_move_iterator(values.end()));
  }

  void read_raw_async(const ua::NamespaceHistoryDelegate::ReadContext& /*context*/,
    std::vector<ua::NamespaceHistoryDelegate::ReadRawItem> items, ReadRawCallback callback) noexcept override
  {
    ua::BatchResult<ua::NamespaceHistoryDelegate::ReadRawItemResult> batch;
    batch.items.reserve(items.size());

    std::lock_guard lock(mMutex);
    for (const auto& item : items)
    {
      std::vector<ua::DataValue> window;
      const auto stored = mData.find(item.nodeId);
      if (stored != mData.end())
      {
        for (const auto& dataValue : stored->second)
        {
          const auto timestamp = dataValue.source_timestamp().value_or(ua::DateTime{});
          if ((item.startTime.is_null() || timestamp >= item.startTime) &&
              (item.endTime.is_null() || timestamp <= item.endTime))
          {
            window.push_back(dataValue);
          }
        }
      }

      std::size_t offset = 0;
      if (item.cursor.has_value())
      {
        if (const auto* resume = std::any_cast<std::size_t>(&*item.cursor))
          offset = *resume;
      }
      if (offset > window.size())
        offset = window.size();

      std::size_t limit = window.size();
      if (item.maxValuesPerNode != 0)
      {
        limit =
          std::min<std::size_t>(window.size(), offset + static_cast<std::size_t>(item.maxValuesPerNode));
      }

      ua::NamespaceHistoryDelegate::HistoryReadRawSuccess success;
      for (std::size_t index = offset; index < limit; ++index)
        success.values.push_back(window[index]);
      if (limit < window.size())
        success.cursor = ua::NamespaceHistoryDelegate::Cursor{limit};

      batch.items.emplace_back(std::move(success));
    }

    callback(std::move(batch));
  }

  Capabilities capabilities() const noexcept override
  {
    Capabilities caps;
    caps.readRaw = true;
    return caps;
  }

private:
  std::mutex mMutex;
  std::unordered_map<ua::NodeId, std::vector<ua::DataValue>> mData;
};

/// Namespace that exposes the paging delegate for the nodes it owns.
class PagingHistoryNamespace : public default_ns::Namespace
{
public:
  using default_ns::Namespace::Namespace;

  static std::shared_ptr<PagingHistoryNamespace> create(
    std::string_view uri, boost::asio::any_io_executor executor)
  {
    return std::shared_ptr<PagingHistoryNamespace>(new PagingHistoryNamespace(uri, std::move(executor)));
  }

  void set_delegate(std::shared_ptr<PagingHistoryDelegate> delegate)
  {
    mDelegate = std::move(delegate);
  }

  std::shared_ptr<ua::NamespaceHistoryDelegate> history_delegate() noexcept override
  {
    return mDelegate;
  }

private:
  std::shared_ptr<PagingHistoryDelegate> mDelegate;
};

}  // namespace

// A real server whose historized Variable holds pagedHistoryValueCount values behind a delegate that pages
// them off a continuation cursor - the data the public cursor's continuation loop has to traverse.
class HistoryPaginationIntegration : public ComplianceWithSession
{
protected:
  void configure_server() override
  {
    auto addressSpace = mServer.server().address_space();

    mHistoryNamespace =
      PagingHistoryNamespace::create("urn:test:history:paging", mServer.thread_pool().executor());
    mHistoryDelegate = std::make_shared<PagingHistoryDelegate>();
    mHistoryNamespace->set_delegate(mHistoryDelegate);
    mHistoryNsIndex = addressSpace.add_namespace_sync(mHistoryNamespace);

    mPagedNodeId = ua::NodeId{mHistoryNsIndex, uint32_t{1000}};
    auto node = addressSpace.create_node_sync(mPagedNodeId, ua::NodeClass::Variable);
    node.add_reference_sync(ua::NodeId{ua::ReferenceTypeId::HasTypeDefinition},
      ua::NodeId{ua::VariableTypeId::BaseDataVariableType});
    auto variable = node.as<ua::VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_browse_name(ua::QualifiedName{mHistoryNsIndex, "PagedHistoryVariable"});
    variable->set_display_name(ua::LocalizedText{"", "PagedHistoryVariable"});
    variable->set_data_type(ua::NodeId{ua::DataTypeId::Double});
    variable->write_value_sync(double{0.0});
    variable->set_access_level(
      ua::AccessLevelType{ua::AccessLevelType::Bit::CurrentRead, ua::AccessLevelType::Bit::HistoryRead});

    auto objectsFolder = addressSpace.find_node_sync(ua::NodeId{ua::ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(ua::NodeId{ua::ReferenceTypeId::Organizes}, mPagedNodeId);

    std::vector<ua::DataValue> values;
    for (std::size_t index = 0; index < pagedHistoryValueCount; ++index)
    {
      ua::DataValue dataValue{ua::Variant{static_cast<double>(index)}};
      dataValue.source_timestamp() = ua::DateTime{2025, 1, 1, 0, 0, static_cast<double>(index)};
      values.push_back(std::move(dataValue));
    }
    mHistoryDelegate->add_values(mPagedNodeId, std::move(values));
  }

  ua::client::Session open_activated_session()
  {
    auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
    auto session = channel.create_session_sync({.sessionName = "HistoryPaginationIntegration"});
    session.activate_sync();
    return session;
  }

  std::shared_ptr<PagingHistoryNamespace> mHistoryNamespace;
  std::shared_ptr<PagingHistoryDelegate> mHistoryDelegate;
  uint16_t mHistoryNsIndex{0};
  ua::NodeId mPagedNodeId;
};

// Part 11 section 6.4.3.2: when a HistoryRead response carries a continuationPoint the client must re-issue
// the same details with that point (and releaseContinuationPoints=false) to obtain the next page. The failure
// is silent - the client concatenates, so a page boundary that re-sends a stale point (a repeat) or drops the
// point (an omission) still yields a history that looks complete. Only the concatenation asserted against the
// exact stored series can tell the three apart.
// @verifies AC-CL-HIST-008-PAGINATE-WITH-CP
TEST_F(HistoryPaginationIntegration, PaginatedHistoryReadYieldsEveryStoredValueExactlyOnce)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session()};
  ASSERT_TRUE(connection.start_status().is_good());

  TimeRange range;
  range.startTime = ua::DateTime{2024, 1, 1, 0, 0, 0.0};
  range.endTime = ua::DateTime{2026, 1, 1, 0, 0, 0.0};
  range.numValuesPerNode = 3;  // strictly below the stored count, so the server must cap and continue

  auto cursorResult = connection->history().try_read_raw_sync(mPagedNodeId, range);
  ASSERT_TRUE(cursorResult.is_good()) << "the capped raw read must succeed and hand back a cursor";
  ua::client::HistoryReadCursor cursor = std::move(cursorResult.value());

  std::vector<std::size_t> pageSizes;
  std::vector<ua::DataValue> concatenated;
  int advances = 0;
  while (cursor.has_more() && advances < 20)
  {
    ++advances;
    auto page = cursor.try_next_sync();
    ASSERT_TRUE(page.is_good()) << "continuation " << advances << " failed";
    if (page.value().empty())
      break;
    pageSizes.push_back(page.value().size());
    for (const auto& dataValue : page.value())
      concatenated.push_back(dataValue);
  }

  ASSERT_FALSE(pageSizes.empty()) << "the paged read yielded no page at all";
  ASSERT_GE(pageSizes.size(), 2U) << "numValuesPerNode=3 over " << pagedHistoryValueCount
                                  << " values must produce a continuation, not a single page";
  for (std::size_t index = 0; index < pageSizes.size(); ++index)
  {
    EXPECT_LE(pageSizes[index], std::size_t{3}) << "page " << index << " exceeded numValuesPerNode";
  }

  ASSERT_EQ(concatenated.size(), pagedHistoryValueCount)
    << "the concatenated pages must hold each stored value exactly once";
  for (std::size_t index = 0; index < pagedHistoryValueCount; ++index)
  {
    EXPECT_EQ(concatenated[index].value(), ua::Variant{static_cast<double>(index)})
      << "value " << index << " of the concatenation is not the " << index << "th stored value";
  }
  EXPECT_FALSE(cursor.has_more()) << "the cursor must be drained once the last page has been delivered";
}

namespace
{

// Three historized nodes, two aggregates on each: six `nodesToRead` entries paired index-by-index with six
// `aggregateType` entries.
constexpr std::size_t alignmentOperationCount = 6;

// A history delegate that computes no aggregate. For each processed-read item it records the
// (nodeId, aggregateType) pair the server handed it, keyed by the item's position in the originating
// service request, and returns a single value encoding that pair. The pairing the server derived from the
// two request arrays is therefore observable twice: at the far end of the wire, and in the value that comes
// back against each result position.
class AggregateAlignmentDelegate : public ua::NamespaceHistoryDelegate
{
public:
  struct SeenItem
  {
    ua::NodeId nodeId;
    ua::NodeId aggregateType;
    bool present{false};
  };

  void set_node_code(ua::NodeId nodeId, double code)
  {
    std::lock_guard lock(mMutex);
    mNodeCodes[std::move(nodeId)] = code;
  }

  void set_aggregate_code(ua::NodeId aggregateType, double code)
  {
    std::lock_guard lock(mMutex);
    mAggregateCodes[std::move(aggregateType)] = code;
  }

  void read_processed_async(const ua::NamespaceHistoryDelegate::ReadContext& /*context*/,
    std::vector<ua::NamespaceHistoryDelegate::ReadProcessedItem> items,
    ReadProcessedCallback callback) noexcept override
  {
    ua::BatchResult<ua::NamespaceHistoryDelegate::ReadProcessedItemResult> batch;
    batch.items.reserve(items.size());

    std::lock_guard lock(mMutex);
    for (const auto& item : items)
    {
      if (mSeen.size() <= item.index)
        mSeen.resize(item.index + 1);
      mSeen[item.index] = SeenItem{item.nodeId, item.aggregateType, true};

      // An unrecognised node or aggregate yields 0.0, which matches no expected pair.
      double code = 0.0;
      const auto node = mNodeCodes.find(item.nodeId);
      const auto aggregate = mAggregateCodes.find(item.aggregateType);
      if (node != mNodeCodes.end() && aggregate != mAggregateCodes.end())
        code = (node->second * 10.0) + aggregate->second;

      ua::NamespaceHistoryDelegate::HistoryReadProcessedSuccess success;
      ua::DataValue value{ua::Variant{code}};
      value.source_timestamp() = ua::DateTime{2025, 1, 1, 0, 0, 0.0};
      success.values.push_back(std::move(value));
      batch.items.emplace_back(std::move(success));
    }

    callback(std::move(batch));
  }

  Capabilities capabilities() const noexcept override
  {
    Capabilities caps;
    caps.readProcessed = true;
    return caps;
  }

  std::vector<SeenItem> seen()
  {
    std::lock_guard lock(mMutex);
    return mSeen;
  }

private:
  std::mutex mMutex;
  std::unordered_map<ua::NodeId, double> mNodeCodes;
  std::unordered_map<ua::NodeId, double> mAggregateCodes;
  std::vector<SeenItem> mSeen;
};

/// Namespace that exposes the alignment delegate for the nodes it owns.
class AggregateAlignmentNamespace : public default_ns::Namespace
{
public:
  using default_ns::Namespace::Namespace;

  static std::shared_ptr<AggregateAlignmentNamespace> create(
    std::string_view uri, boost::asio::any_io_executor executor)
  {
    return std::shared_ptr<AggregateAlignmentNamespace>(
      new AggregateAlignmentNamespace(uri, std::move(executor)));
  }

  void set_delegate(std::shared_ptr<AggregateAlignmentDelegate> delegate)
  {
    mDelegate = std::move(delegate);
  }

  std::shared_ptr<ua::NamespaceHistoryDelegate> history_delegate() noexcept override
  {
    return mDelegate;
  }

private:
  std::shared_ptr<AggregateAlignmentDelegate> mDelegate;
};

}  // namespace

// A real server with three historized Variables behind a delegate that natively serves processed reads, so
// the aggregate applied to each requested node is decided by the server from the request's two arrays and
// reported back per operation.
class HistoryAggregateAlignmentIntegration : public ComplianceWithSession
{
protected:
  void configure_server() override
  {
    auto addressSpace = mServer.server().address_space();

    mAlignmentNamespace = AggregateAlignmentNamespace::create(
      "urn:test:history:aggregate-alignment", mServer.thread_pool().executor());
    mAlignmentDelegate = std::make_shared<AggregateAlignmentDelegate>();
    mAlignmentNamespace->set_delegate(mAlignmentDelegate);
    mAlignmentNsIndex = addressSpace.add_namespace_sync(mAlignmentNamespace);

    const char* const names[] = {"AlignmentVariableA", "AlignmentVariableB", "AlignmentVariableC"};
    auto objectsFolder = addressSpace.find_node_sync(ua::NodeId{ua::ObjectId::ObjectsFolder});
    for (std::size_t index = 0; index < 3; ++index)
    {
      ua::NodeId nodeId{mAlignmentNsIndex, static_cast<uint32_t>(2000 + index)};
      auto node = addressSpace.create_node_sync(nodeId, ua::NodeClass::Variable);
      node.add_reference_sync(ua::NodeId{ua::ReferenceTypeId::HasTypeDefinition},
        ua::NodeId{ua::VariableTypeId::BaseDataVariableType});
      auto variable = node.as<ua::VariableAccessor>();
      ASSERT_TRUE(variable.has_value());
      variable->set_browse_name(ua::QualifiedName{mAlignmentNsIndex, names[index]});
      variable->set_display_name(ua::LocalizedText{"", names[index]});
      variable->set_data_type(ua::NodeId{ua::DataTypeId::Double});
      variable->write_value_sync(double{0.0});
      variable->set_access_level(
        ua::AccessLevelType{ua::AccessLevelType::Bit::CurrentRead, ua::AccessLevelType::Bit::HistoryRead});
      objectsFolder.add_reference_sync(ua::NodeId{ua::ReferenceTypeId::Organizes}, nodeId);

      mAlignmentDelegate->set_node_code(nodeId, static_cast<double>(index + 1));
      mAlignmentNodes.push_back(std::move(nodeId));
    }

    mAlignmentDelegate->set_aggregate_code(ua::NodeId{ua::ObjectId::AggregateFunction_Average}, 1.0);
    mAlignmentDelegate->set_aggregate_code(ua::NodeId{ua::ObjectId::AggregateFunction_Minimum}, 2.0);
  }

  std::shared_ptr<AggregateAlignmentNamespace> mAlignmentNamespace;
  std::shared_ptr<AggregateAlignmentDelegate> mAlignmentDelegate;
  uint16_t mAlignmentNsIndex{0};
  std::vector<ua::NodeId> mAlignmentNodes;
};

// Part 11 section 6.4.4.2/section 6.4.5: `aggregateType[]` requests one aggregate calculation per
// `nodesToRead[]` entry, so asking for two aggregates on each of three nodes means each node appears twice
// and the pairing is purely positional - the arrays are not a set of nodes plus a set of aggregates. A
// plausible implementation groups by NodeId, or takes `aggregateType[0]` for every entry, and still returns
// six results of the right length and the right per-node identity, with the aggregates swapped between
// positions. Only a matrix in which no two positions share a (node, aggregate) pair separates that from a
// correct pairing, and the results must be read back against the same correspondence.
// @verifies AC-CL-HIST-005-AGGREGATE-ARRAY-ALIGNMENT
TEST_F(HistoryAggregateAlignmentIntegration, ProcessedReadPairsAggregateTypeWithNodeToReadByPosition)
{
  ASSERT_EQ(mAlignmentNodes.size(), std::size_t{3}) << "the alignment fixture built no nodes";

  const ua::NodeId average{ua::ObjectId::AggregateFunction_Average};
  const ua::NodeId minimum{ua::ObjectId::AggregateFunction_Minimum};

  // Interleaved so that every position carries a distinct (node, aggregate) pair: A/Avg, B/Min, C/Avg,
  // A/Min, B/Avg, C/Min. Each node is asked for two aggregates; no positional shift reproduces this.
  const std::vector<ua::NodeId> expectedNodes{mAlignmentNodes[0],
    mAlignmentNodes[1],
    mAlignmentNodes[2],
    mAlignmentNodes[0],
    mAlignmentNodes[1],
    mAlignmentNodes[2]};
  const std::vector<ua::NodeId> expectedAggregates{average, minimum, average, minimum, average, minimum};
  const std::vector<double> expectedCodes{11.0, 22.0, 31.0, 12.0, 21.0, 32.0};
  ASSERT_EQ(expectedNodes.size(), alignmentOperationCount);
  ASSERT_EQ(expectedAggregates.size(), alignmentOperationCount);

  ua::HistoryReadRequest request;
  request.timestamps_to_return() = ua::TimestampsToReturn::Source;
  request.release_continuation_points() = false;
  auto details = std::make_unique<ua::ReadProcessedDetails>();
  details->start_time() = ua::DateTime{2025, 1, 1, 0, 0, 0.0};
  details->end_time() = ua::DateTime{2025, 1, 1, 0, 0, 10.0};
  details->processing_interval() = 10000.0;
  details->aggregate_configuration().use_server_capabilities_defaults() = true;
  for (const auto& aggregate : expectedAggregates)
    details->aggregate_type().push_back(aggregate);
  request.history_read_details() = std::move(details);
  for (const auto& node : expectedNodes)
  {
    ua::HistoryReadValueId valueId;
    valueId.node_id() = node;
    request.nodes_to_read().push_back(std::move(valueId));
  }

  auto result = mSession->attributes().try_history_read_sync(std::move(request));
  ASSERT_TRUE(result.is_good()) << "the HistoryRead must not fail at the transport/session level";
  auto& response = result.value();
  ASSERT_TRUE(response.response_header().service_result().is_good())
    << "six aggregateType entries against six nodesToRead entries is a conforming processed read and must "
       "not be rejected Bad_AggregateListMismatch";
  ASSERT_EQ(response.results().size(), alignmentOperationCount)
    << "one result is owed per nodesToRead entry, not one per distinct node";

  // Conjunct 1 - the arrays as sent: each dispatched operation must carry the aggregate that sat at its own
  // position, not the aggregate of another position that happens to name the same node.
  auto seen = mAlignmentDelegate->seen();
  ASSERT_EQ(seen.size(), alignmentOperationCount) << "the server dispatched no operation per request entry";
  for (std::size_t index = 0; index < alignmentOperationCount; ++index)
  {
    ASSERT_TRUE(seen[index].present) << "no operation was dispatched for request position " << index;
    EXPECT_EQ(seen[index].nodeId, expectedNodes[index])
      << "request position " << index << " was read against the wrong node";
    EXPECT_EQ(seen[index].aggregateType, expectedAggregates[index])
      << "request position " << index << " applied the aggregate belonging to another position";
  }

  // Conjunct 2 - the results as received: each result must hold the value computed for its own position's
  // pair, so the response is read back against the same correspondence the request expressed.
  for (std::size_t index = 0; index < alignmentOperationCount; ++index)
  {
    EXPECT_TRUE(response.results()[index].status_code().is_good())
      << "operation " << index << " was not answered";
    auto* historyData = dynamic_cast<ua::HistoryData*>(response.results()[index].history_data().get());
    ASSERT_NE(historyData, nullptr) << "operation " << index << " returned no HistoryData";
    ASSERT_EQ(historyData->data_values().size(), std::size_t{1})
      << "operation " << index << " returned no aggregated value";
    EXPECT_EQ(historyData->data_values()[0].value(), ua::Variant{expectedCodes[index]})
      << "result " << index << " carries the value computed for a different (node, aggregate) pair";
  }
}
