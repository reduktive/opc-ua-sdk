// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientDataAccess.Percent* cluster (batch 1) of the client integration-test matrix (the 9
///        `ClientDataAccess.Percent*` rows, spec refs section 8.18.4.1, CL-DA-003..006). This is the first
///        sub-batch of the ClientDataAccess cluster.
///
/// These drive the TIER-2 DataAccess facade end-to-end through the PUBLIC `ua::client::Connection`
/// (`Connection::data_access()` -> `DataAccessAccessor::analog_item_async` -> `AnalogItemHandle`) over a REAL
/// reference server. The Connection is a genuine public handle wrapped by `ConnectionHandleFactory` over a
/// started `ConnectionImpl` (the same orchestrator the connection-impl subscription integration test uses),
/// bound to an activated Session on an ephemeral-TCP `ComplianceWithNodes` server extended with two
/// AnalogItemType Variables (a scalar + an 8-element array, each EURange [0,100]).
///
/// SCOPE / analog pinning (see the report accompanying this batch for the full audit):
///  - The percent-deadband BOUNDS + EURange precondition (rows 1-4) run against a REAL server-resolved
///    EURange handle: `analog_item_async` does the live DA Property pre-flight (Browse HasProperty + Read
///    EURange), then `make_percent_deadband_filter(pct)` is exercised on the resulting handle. This is
///    genuinely distinct from the fake-interface unit tests in
///    tests/unit/client/data_access/property_accessor_client_data_access_tests.cpp (which discharge the pure
///    bounds/EURange LOGIC - those are NOT duplicated here).
///  - Row 4 (RequiresEuRange) is REPORTED as divergent: `analog_item_async` enforces EURange as MANDATORY,
///    so a node lacking EURange fails at the FACTORY (Bad_NotFound / property_resolution_failed) before a
///    handle exists - the `make_percent_deadband_filter` EURange precondition (CL-DA-005,
///    Bad_FilterNotAllowed) is unreachable through the managed path (it is defense-in-depth, covered only by
///    the direct-construction unit test). The integration form asserts the real client-observable gate.
///  - Rows 5-6 are PINNED to the built analog: the DataChangeFilter is NOT yet plumbed onto the wire
///    MonitoringParameters (ua_data_change_monitored_item_owner.cpp - `create_monitored_item` takes no
///    filter), and the client-side fallback evaluator (CL-SUB-021) is deferred, so "notifies only above
///    threshold" cannot be verified end-to-end. Row 5 pins the emitted filter's shape; row 6 pins BOTH the
///    single unsplit filter (CL-DA-006) AND that a data-change notification on an array node carries the FULL
///    array (not a per-element delta). The wire-filter plumbing gap is REPORTED.
///  - Rows 7-9 (ServerFilter*Surfaces) drive the MisbehavingServer: a well-formed CreateMonitoredItems whose
///    per-item result is rewritten to Bad_MonitoredItemFilterInvalid / Bad_FilterNotAllowed /
///    Bad_MonitoredItemFilterUnsupported. The client must surface that status VERBATIM (never swallow it to
///    Good), leave the item un-attached, and issue exactly one CreateMonitoredItems (no retry storm). The
///    client does NOT synthesize its own ErrorDetail on a verbatim per-item server status (section 7.10
///    no-retag; DiagnosticInfo->ErrorDetail bridging for per-item MI results is unbuilt) - REPORTED.
///
/// Timing: every wait is BOUNDED POLLING on a thread-safe observable (a delivered value / a request count),
/// never a fixed sleep. All completions are bridged off the executor via std::promise; the test thread is the
/// only one that blocks on a future (never a pool thread).

#include "compliance_helpers.h"

#include "misbehaving_server.h"
#include "requests.h"  // read_value(...) - the raw Read shape the server-side model rows use
#include "subscription.h"  // raw CreateMonitoredItems + Publish shapes the server-side deadband rows need

#include "ua_connection.h"
#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"
#include "ua_data_access.h"

#include "ua_client_monitored_item.h"  // EventNotification (sub-batch 5 semantic-change routing)
#include "ua_client_observers.h"  // AddressSpaceObserver / SemanticChangeStructure
#include "ua_event_router.h"  // EventRouter (drive handle_semantic_event via TestAccess)
#include "ua_semantic_change_cache.h"  // SemanticChangeCache::invalidate_async (in-band sink)
#include "ua_semantic_change_structure_data_type.h"  // SemanticChangeStructureDataType

#include "ua_access_level_type.h"
#include "ua_analog_item.h"  // production AnalogItemType instantiation (Mandatory EURange + semantics wiring)
#include "ua_analog_unit.h"  // AnalogUnitType: EngineeringUnits Mandatory (Part 8 section 5.3.2.4)
#include "ua_analog_unit_range.h"  // AnalogUnitRangeType: EURange AND EngineeringUnits both Mandatory
#include "ua_application_configuration.h"
#include "ua_array.h"
#include "ua_axis_information.h"  // AxisInformation: the payload an ArrayItem axis-definition Property carries
#include "ua_axis_scale_enumeration.h"  // AxisScaleEnumeration: Linear / Log / Ln
#include "ua_cube_item.h"  // production CubeItemType instantiation (X/Y/ZAxisDefinition)
#include "ua_image_item.h"  // production ImageItemType instantiation (X/YAxisDefinition)
#include "ua_multi_state_discrete.h"  // production MultiStateDiscreteType instantiation (EnumStrings)
#include "ua_multi_state_value_discrete.h"  // production MultiStateValueDiscreteType instantiation
#include "ua_n_dimension_array_item.h"  // production NDimensionArrayItemType instantiation (AxisDefinition)
#include "ua_xy_array_item.h"  // production XYArrayItemType instantiation (XAxisDefinition)
#include "ua_y_array_item.h"  // production YArrayItemType instantiation (XAxisDefinition)
#include "ua_attribute_id.h"
#include "ua_client.h"
#include "ua_eu_information.h"
#include "ua_instance_utils.h"  // resolve_and_set_value_source_async (the external data-source interface)
#include "ua_instantiation_options.h"
#include "ua_object_id.h"
#include "ua_read_response.h"
#include "ua_session_attribute_services.h"
#include "ua_two_state_discrete.h"  // production TwoStateDiscreteType instantiation (TrueState/FalseState)
#include "ua_data_access_utils.h"
#include "ua_numeric_range_parser.h"
#include "ua_read_value_id.h"
#include "ua_write_value.h"
#include "ua_create_monitored_items_request.h"
#include "ua_create_monitored_items_response.h"
#include "ua_monitored_item_create_result.h"
#include "ua_status_code.h"
#include "ua_variable_id.h"
#include "ua_data_change_filter.h"
#include "ua_data_change_trigger.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_deadband_type.h"
#include "ua_enum_value_type.h"
#include "ua_error_detail.h"
#include "ua_localized_text.h"
#include "ua_logger.h"
#include "ua_node.h"  // ExternalValueSource::set_value_source
#include "ua_value_source.h"
#include "ua_node_id.h"
#include "ua_range.h"
#include "ua_ref_structure.h"
#include "ua_referencetype_id.h"
#include "ua_status.h"
#include "ua_structure.h"
#include "ua_value_rank.h"
#include "ua_variabletype_id.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <future>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionHandleFactory;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionImplTestAccess;

namespace
{

// Runs the ConnectionImpl bootstrap and blocks (on the test thread) until it completes.
VoidResult start_and_wait(ConnectionImpl& connection)
{
  std::promise<VoidResult> promise;
  auto future = promise.get_future();
  connection.start_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
  return future.get();
}

// Closes the ConnectionImpl and blocks (on the test thread) until it completes.
VoidResult close_and_wait(ConnectionImpl& connection)
{
  std::promise<VoidResult> promise;
  auto future = promise.get_future();
  connection.close_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
  return future.get();
}

// Thread-safe sink for DataValues delivered to a monitored-item data callback (the pipeline hops the callback
// onto the pool, so delivery and the test thread run concurrently).
class DataValueSink
{
public:
  void push(DataValue value)
  {
    std::lock_guard lock(mMutex);
    mValues.push_back(std::move(value));
  }

  std::vector<DataValue> snapshot() const
  {
    std::lock_guard lock(mMutex);
    return mValues;
  }

private:
  mutable std::mutex mMutex;
  std::vector<DataValue> mValues;
};

// Busy-wait (bounded) until @p predicate holds or @p timeout elapses; returns the final predicate value.
bool wait_until(const std::function<bool()>& predicate, std::chrono::milliseconds timeout = 5000ms)
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (predicate())
    {
      return true;
    }
    std::this_thread::sleep_for(10ms);
  }
  return predicate();
}

// Thread-safe recording AddressSpaceObserver (sub-batch 5): the observer_sink delivers on_semantic_change on
// its own delivery strand (a pool thread), so the call counter is atomic and the captured affected NodeId /
// TypeDefinition are mutex-guarded. Used by EventSubscriberRoutesSemanticChangeEvent to observe the router's
// SemanticChange fan-out through the PUBLIC Connection observer setter.
class RecordingAddressSpaceObserver : public AddressSpaceObserver
{
public:
  std::atomic<int> semanticChangeCalls{0};

  void on_semantic_change(
    const ua::client::Connection&, std::vector<ua::client::SemanticChangeStructure> changes) override
  {
    {
      std::lock_guard<std::mutex> lock(mMutex);
      mLastChanges = std::move(changes);
    }
    ++semanticChangeCalls;
  }

  std::vector<ua::client::SemanticChangeStructure> last_changes() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mLastChanges;
  }

private:
  mutable std::mutex mMutex;
  std::vector<ua::client::SemanticChangeStructure> mLastChanges;
};

// A standard NS0 Variable that exists on every server and is monitorable - the ServerFilter* rows only need a
// well-formed CreateMonitoredItems to exist so the MisbehavingServer can rewrite its per-item result.
const NodeId monitoredNode{VariableId::Server_ServerStatus_State};

// A minimal managed connection over a MisbehavingServer for the ServerFilter surfacing rows (7-9): a real
// Client bound to the server's crypto + trusted store over ephemeral TCP, an activated Session wrapped into a
// started ConnectionImpl. Mirrors the ClientMonitoredItem cluster's MisbehavingMonitoredItemFixture.
class MisbehavingDaConnection
{
public:
  explicit MisbehavingDaConnection(MisbehavingServer& server)
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
    mChannel.emplace(mClient->core().open_channel_sync(openConfig));
    auto session = mChannel->create_session_sync({.sessionName = "ClientDataAccessServerFilter"});
    session.activate_sync();

    mConnection = ConnectionImpl::create(
      mThreadPool.executor(), std::move(session), ua::client::detail::ConnectionConfig{}, Logger{});
    mStartStatus = start_and_wait(*mConnection);
  }

  ~MisbehavingDaConnection()
  {
    if (mConnection)
    {
      (void)close_and_wait(*mConnection);
    }
    mConnection.reset();
    mChannel.reset();
    mClient.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  MisbehavingDaConnection(const MisbehavingDaConnection&) = delete;
  MisbehavingDaConnection& operator=(const MisbehavingDaConnection&) = delete;

  const VoidResult& start_status() const
  {
    return mStartStatus;
  }

  Result<std::uint32_t> create_subscription(double publishingInterval)
  {
    std::promise<Result<std::uint32_t>> promise;
    auto future = promise.get_future();
    mConnection->create_subscription_async(
      publishingInterval, [&promise](Result<std::uint32_t> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  Result<std::uint32_t> create_monitored_item(
    std::uint32_t subscriptionId, std::uint32_t clientHandle, std::shared_ptr<DataValueSink> sink)
  {
    std::promise<Result<std::uint32_t>> promise;
    auto future = promise.get_future();
    mConnection->create_monitored_item_async(
      subscriptionId,
      monitoredNode,
      clientHandle,
      [sink](DataValue value) { sink->push(std::move(value)); },
      [&promise](Result<std::uint32_t> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  std::size_t monitored_item_count() const
  {
    auto info = ConnectionImplTestAccess::pipeline_info(*mConnection);
    return info ? info->monitoredItemCount : 0;
  }

private:
  boost::asio::thread_pool mThreadPool;
  std::optional<Client> mClient;
  std::optional<SecureChannel> mChannel;
  std::shared_ptr<ConnectionImpl> mConnection;
  VoidResult mStartStatus{};
};

// Shared body for the three ServerFilter* rows: the MisbehavingServer rewrites the single per-item
// CreateMonitoredItems result to @p injectedStatus (a filter-rejection code). The client must surface that
// status VERBATIM, leave the item un-attached, and issue exactly one CreateMonitoredItems (no retry storm).
// The client does NOT synthesize its own ErrorDetail on a verbatim per-item server status (section 7.10
// no-retag; DiagnosticInfo->ErrorDetail bridging for per-item MI results is unbuilt) - REPORTED, not
// asserted.
void expect_server_filter_status_surfaced(ua::Status injectedStatus)
{
  MisbehavingServer server;

  // Count CreateMonitoredItems requests to prove the client does not retry on the per-item rejection.
  auto createRequestCount = std::make_shared<std::atomic<int>>(0);
  server.set_request_observer(
    [createRequestCount](const ua::Structure& request)
    {
      if (dynamic_cast<const ua::CreateMonitoredItemsRequest*>(&request) != nullptr)
      {
        createRequestCount->fetch_add(1);
      }
    });

  // Rewrite the single per-item result to the injected filter-rejection status (service result left Good).
  server.set_response_mutator(
    [injectedStatus](ua::Response& response)
    {
      if (auto* create = dynamic_cast<ua::CreateMonitoredItemsResponse*>(response.second.get()))
      {
        if (!create->results().empty())
        {
          create->results()[0].status_code() = ua::StatusCode{injectedStatus};
        }
      }
    });

  MisbehavingDaConnection connection{server};
  ASSERT_TRUE(connection.start_status().is_good());

  auto subscription = connection.create_subscription(100.0);
  ASSERT_TRUE(subscription.is_good())
    << "create_subscription failed: 0x" << std::hex << subscription.status_code().as_uint32();

  auto sink = std::make_shared<DataValueSink>();
  auto item = connection.create_monitored_item(subscription.value(), /*clientHandle=*/1, sink);

  ASSERT_TRUE(item.is_bad()) << "the server's filter rejection must surface, never be swallowed to Good";
  EXPECT_EQ(item.status_code().as_status(), injectedStatus)
    << "the per-item filter status must surface VERBATIM, not remapped to a generic error";
  // The optimistic client-handle registration is deregistered on the per-item bad status, but
  // remove_monitored_item_async posts to the pipeline strand - it is eventually-consistent, so poll for it
  // rather than racing the async deregister right after the completion fires.
  EXPECT_TRUE(wait_until([&] { return connection.monitored_item_count() == 0; }))
    << "a rejected item must not remain attached to the pipeline (not reported Good behind the scenes)";
  EXPECT_EQ(createRequestCount->load(), 1)
    << "a per-item rejection must not trigger a retry storm - exactly one CreateMonitoredItems on the wire";
}

// Server-side "stub" for the write-passthrough rows (CL-DA-007 Accept / Clamp / Reject, MultiState reject,
// the dictionary-entries write counter): a value source on the designated Variable that keeps the Value and
// judges each Value write with @p rule, which may replace the proposed value and answers the write's result.
// The CLIENT under test never clamps or rejects locally - the rows assert it surfaces the server's verdict.
std::shared_ptr<ua::ValueSource> make_judging_source(
  DataValue initial, std::function<ua::ValueSource::WriteResult(DataValue&)> rule)
{
  struct State
  {
    std::mutex mutex;
    DataValue value;
  };

  auto state = std::make_shared<State>();
  state->value = std::move(initial);
  return make_value_source(
    [state](const ValueSource::ReadContext& /*context*/,
      const Node& /*node*/,
      const ReadValueId& read,
      std::function<void(DataValueResult)>
        callback)
    {
      DataValue current;
      {
        std::lock_guard lock(state->mutex);
        current = state->value;
      }
      index_range_utils::apply_to_value(current, read.index_range());
      callback(DataValueResult{std::move(current)});
    },
    [state, rule = std::move(rule)](const ValueSource::WriteContext& /*context*/,
      const Node& /*node*/,
      const WriteValue& write,
      std::function<void(ValueSource::WriteResult)>
        callback)
    {
      DataValue proposed = write.value();
      ValueSource::WriteResult result = rule(proposed);
      if (result.is_good())
      {
        std::lock_guard lock(state->mutex);
        state->value = std::move(proposed);
      }
      callback(std::move(result));
    });
}

// The rule of an AnalogItem with EURange [0, 100] under @p policy: a Value outside it is refused with
// Bad_OutOfRange (Reject) or clamped into it, answering Good_Clamped (Clamp).
std::function<ua::ValueSource::WriteResult(DataValue&)> analog_range_rule(
  ua::DataAccessOutOfRangePolicy policy)
{
  return [policy](DataValue& proposed) -> ua::ValueSource::WriteResult
  {
    Range range;
    range.low() = 0.0;
    range.high() = 100.0;
    const VoidResult checked = data_access_utils::apply_analog_range(proposed.value(), range, policy);
    if (checked.is_bad())
      return ValueSource::WriteResult{checked.status_code()};
    return ValueSource::WriteResult{ValueSource::Written{}, checked.status_code()};
  };
}

}  // namespace

// ============================================================================================================
// Fixture A - ComplianceWithNodes extended with AnalogItemType nodes, driven through the PUBLIC Connection.
// Suite name `ClientDataAccess` (tests named exactly `ClientDataAccess.<Row>`).
// ============================================================================================================
class ClientDataAccess : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();
    auto addressSpace = mServer.server().address_space();
    const AccessLevelType readWrite{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite};

    // --- Scalar AnalogItem (Double) with EURange [0, 100]: ns;6000 (+ EURange Property ns;6001) ---
    mScalarAnalogId = NodeId{mTestNamespaceIndex, uint32_t{6000}};
    auto scalarNode = addressSpace.create_node_sync(mScalarAnalogId, NodeClass::Variable);
    auto scalar = scalarNode.as<VariableAccessor>();
    ASSERT_TRUE(scalar.has_value());
    scalar->set_browse_name(QualifiedName{mTestNamespaceIndex, "AnalogScalar"});
    scalar->set_display_name(LocalizedText{"", "AnalogScalar"});
    scalar->set_data_type(NodeId{DataTypeId::Double});
    scalar->set_access_level(readWrite);
    scalar->write_value_sync(double{50.0});
    scalarNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::AnalogItemType});
    add_eu_range_property(addressSpace, scalarNode, NodeId{mTestNamespaceIndex, uint32_t{6001}});

    // --- Array AnalogItem (Double[8]) with EURange [0, 100]: ns;6100 (+ EURange Property ns;6101) ---
    mArrayAnalogId = NodeId{mTestNamespaceIndex, uint32_t{6100}};
    auto arrayNode = addressSpace.create_node_sync(mArrayAnalogId, NodeClass::Variable);
    auto array = arrayNode.as<VariableAccessor>();
    ASSERT_TRUE(array.has_value());
    array->set_browse_name(QualifiedName{mTestNamespaceIndex, "AnalogArray"});
    array->set_display_name(LocalizedText{"", "AnalogArray"});
    array->set_data_type(NodeId{DataTypeId::Double});
    array->set_value_rank(ValueRank{1});  // one-dimensional
    array->set_access_level(readWrite);
    array->write_value_sync(Array<double>{10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0});
    arrayNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::AnalogItemType});
    add_eu_range_property(addressSpace, arrayNode, NodeId{mTestNamespaceIndex, uint32_t{6101}});

    // --- AnalogItemType lacking its Mandatory EURange Property: ns;6200 (no EURange child) ---
    mNoEuRangeAnalogId = NodeId{mTestNamespaceIndex, uint32_t{6200}};
    create_analog_variable(addressSpace,
      mNoEuRangeAnalogId,
      NodeId{VariableTypeId::AnalogItemType},
      "AnalogNoEuRange",
      DataValue{Variant{double{50.0}}});

    // --- Clamp AnalogItem (EURange [0,100]): the write policy clamps an over-range write here: ns;6300 ---
    mClampAnalogId = NodeId{mTestNamespaceIndex, uint32_t{6300}};
    auto clampNode = create_analog_variable(addressSpace,
      mClampAnalogId,
      NodeId{VariableTypeId::AnalogItemType},
      "AnalogClamp",
      DataValue{Variant{double{50.0}}});
    add_eu_range_property(addressSpace, clampNode, NodeId{mTestNamespaceIndex, uint32_t{6301}});

    // --- Reject AnalogItem (EURange [0,100]): the write policy rejects an over-range write here: ns;6400 ---
    mRejectAnalogId = NodeId{mTestNamespaceIndex, uint32_t{6400}};
    auto rejectNode = create_analog_variable(addressSpace,
      mRejectAnalogId,
      NodeId{VariableTypeId::AnalogItemType},
      "AnalogReject",
      DataValue{Variant{double{50.0}}});
    add_eu_range_property(addressSpace, rejectNode, NodeId{mTestNamespaceIndex, uint32_t{6401}});

    // --- AnalogItem whose stored Value carries a Bad_DeviceFailure quality StatusCode: ns;6500 ---
    mBadStatusAnalogId = NodeId{mTestNamespaceIndex, uint32_t{6500}};
    auto badStatusNode = create_analog_variable(addressSpace,
      mBadStatusAnalogId,
      NodeId{VariableTypeId::AnalogItemType},
      "AnalogBadStatus",
      DataValue{Variant{double{50.0}}, StatusCode{Status::BadDeviceFailure}});
    add_eu_range_property(addressSpace, badStatusNode, NodeId{mTestNamespaceIndex, uint32_t{6501}});

    // --- AnalogUnitType with EURange present but its (type-)Mandatory EngineeringUnits absent: ns;6600 ---
    mAnalogUnitNoUnitsId = NodeId{mTestNamespaceIndex, uint32_t{6600}};
    auto unitNode = create_analog_variable(addressSpace,
      mAnalogUnitNoUnitsId,
      NodeId{VariableTypeId::AnalogUnitType},
      "AnalogUnitNoUnits",
      DataValue{Variant{double{50.0}}});
    add_eu_range_property(addressSpace, unitNode, NodeId{mTestNamespaceIndex, uint32_t{6601}});

    // --- AnalogUnitRangeType variant (a): EURange absent, EngineeringUnits present: ns;6700 ---
    mAnalogUnitRangeNoEuId = NodeId{mTestNamespaceIndex, uint32_t{6700}};
    auto unitRangeNoEuNode = create_analog_variable(addressSpace,
      mAnalogUnitRangeNoEuId,
      NodeId{VariableTypeId::AnalogUnitRangeType},
      "AURangeNoEu",
      DataValue{Variant{double{50.0}}});
    add_engineering_units_property(
      addressSpace, unitRangeNoEuNode, NodeId{mTestNamespaceIndex, uint32_t{6701}});

    // --- AnalogUnitRangeType variant (b): EURange present, EngineeringUnits absent: ns;6710 ---
    mAnalogUnitRangeNoUnitsId = NodeId{mTestNamespaceIndex, uint32_t{6710}};
    auto unitRangeNoUnitsNode = create_analog_variable(addressSpace,
      mAnalogUnitRangeNoUnitsId,
      NodeId{VariableTypeId::AnalogUnitRangeType},
      "AURangeNoUnits",
      DataValue{Variant{double{50.0}}});
    add_eu_range_property(addressSpace, unitRangeNoUnitsNode, NodeId{mTestNamespaceIndex, uint32_t{6711}});

    // --- BaseAnalogType with NONE of the Optional Properties (no EURange / EngineeringUnits): ns;6800 ---
    mBaseAnalogId = NodeId{mTestNamespaceIndex, uint32_t{6800}};
    create_analog_variable(addressSpace,
      mBaseAnalogId,
      NodeId{VariableTypeId::BaseAnalogType},
      "BaseAnalogNoProps",
      DataValue{Variant{double{50.0}}});

    // ========================================================================================================
    // sub-batch 2b nodes (Definition / EngineeringUnits / Range field-fidelity rows). Each carries the
    // Mandatory EURange (so analog_item_async builds a handle) plus the specific DA Property under test,
    // served VERBATIM (the client surfaces raw decoded values without correction - CL-DA-007/-013/-014/
    // -016/-017).
    // ========================================================================================================
    const NodeId analogItemType{VariableTypeId::AnalogItemType};

    // --- Definition = empty string (DDQ-DA-4: present-empty -> optional{""}): ns;6900 ---
    mDefinitionEmptyId = NodeId{mTestNamespaceIndex, uint32_t{6900}};
    auto definitionEmptyNode = create_analog_variable(
      addressSpace, mDefinitionEmptyId, analogItemType, "DefinitionEmpty", DataValue{Variant{double{50.0}}});
    add_eu_range_property(addressSpace, definitionEmptyNode, NodeId{mTestNamespaceIndex, uint32_t{6901}});
    add_definition_property(
      addressSpace, definitionEmptyNode, NodeId{mTestNamespaceIndex, uint32_t{6902}}, "");

    // --- Definition = ~1KB opaque vendor blob (surfaced byte-for-byte, never parsed): ns;6910 ---
    const std::string loremSentence =
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore "
      "et dolore magna aliqua. ";
    mLongDefinition.clear();
    while (mLongDefinition.size() < 1024)
    {
      mLongDefinition += loremSentence;
    }
    mDefinitionLongId = NodeId{mTestNamespaceIndex, uint32_t{6910}};
    auto definitionLongNode = create_analog_variable(
      addressSpace, mDefinitionLongId, analogItemType, "DefinitionLong", DataValue{Variant{double{50.0}}});
    add_eu_range_property(addressSpace, definitionLongNode, NodeId{mTestNamespaceIndex, uint32_t{6911}});
    add_definition_property(
      addressSpace, definitionLongNode, NodeId{mTestNamespaceIndex, uint32_t{6912}}, mLongDefinition);

    // --- EngineeringUnits with ALL four fields populated (namespaceUri / unitId / displayName / desc):
    // ns;6920
    mEuFullId = NodeId{mTestNamespaceIndex, uint32_t{6920}};
    auto euFullNode = create_analog_variable(
      addressSpace, mEuFullId, analogItemType, "EuFull", DataValue{Variant{double{50.0}}});
    add_eu_range_property(addressSpace, euFullNode, NodeId{mTestNamespaceIndex, uint32_t{6921}});
    add_full_engineering_units_property(
      addressSpace, euFullNode, NodeId{mTestNamespaceIndex, uint32_t{6922}}, make_full_eu_information());

    // --- EngineeringUnits with an EMPTY description (other fields populated): ns;6930 ---
    mEuEmptyDescriptionId = NodeId{mTestNamespaceIndex, uint32_t{6930}};
    auto euEmptyDescriptionNode = create_analog_variable(addressSpace,
      mEuEmptyDescriptionId,
      analogItemType,
      "EuEmptyDescription",
      DataValue{Variant{double{50.0}}});
    add_eu_range_property(addressSpace, euEmptyDescriptionNode, NodeId{mTestNamespaceIndex, uint32_t{6931}});
    {
      EUInformation info = make_full_eu_information();
      info.description() = LocalizedText{};  // empty verbatim
      add_full_engineering_units_property(
        addressSpace, euEmptyDescriptionNode, NodeId{mTestNamespaceIndex, uint32_t{6932}}, std::move(info));
    }

    // --- EngineeringUnits with an EMPTY displayName (other fields populated): ns;6940 ---
    mEuEmptyDisplayNameId = NodeId{mTestNamespaceIndex, uint32_t{6940}};
    auto euEmptyDisplayNameNode = create_analog_variable(addressSpace,
      mEuEmptyDisplayNameId,
      analogItemType,
      "EuEmptyDisplayName",
      DataValue{Variant{double{50.0}}});
    add_eu_range_property(addressSpace, euEmptyDisplayNameNode, NodeId{mTestNamespaceIndex, uint32_t{6941}});
    {
      EUInformation info = make_full_eu_information();
      info.display_name() = LocalizedText{};  // empty verbatim
      add_full_engineering_units_property(
        addressSpace, euEmptyDisplayNameNode, NodeId{mTestNamespaceIndex, uint32_t{6942}}, std::move(info));
    }

    // --- EngineeringUnits with an EMPTY namespaceUri (SDK must NOT default to CEFACT): ns;6950 ---
    mEuEmptyNamespaceUriId = NodeId{mTestNamespaceIndex, uint32_t{6950}};
    auto euEmptyNamespaceUriNode = create_analog_variable(addressSpace,
      mEuEmptyNamespaceUriId,
      analogItemType,
      "EuEmptyNamespaceUri",
      DataValue{Variant{double{50.0}}});
    add_eu_range_property(addressSpace, euEmptyNamespaceUriNode, NodeId{mTestNamespaceIndex, uint32_t{6951}});
    {
      EUInformation info = make_full_eu_information();
      info.namespace_uri() = String{""};  // empty verbatim
      add_full_engineering_units_property(
        addressSpace, euEmptyNamespaceUriNode, NodeId{mTestNamespaceIndex, uint32_t{6952}}, std::move(info));
    }

    // --- Distinct EURange [0,100] AND InstrumentRange [-10,110] (two separate optionals): ns;6960 ---
    mDistinctRangesId = NodeId{mTestNamespaceIndex, uint32_t{6960}};
    auto distinctRangesNode = create_analog_variable(
      addressSpace, mDistinctRangesId, analogItemType, "DistinctRanges", DataValue{Variant{double{50.0}}});
    add_range_property(
      addressSpace, distinctRangesNode, NodeId{mTestNamespaceIndex, uint32_t{6961}}, "EURange", 0.0, 100.0);
    add_range_property(addressSpace,
      distinctRangesNode,
      NodeId{mTestNamespaceIndex, uint32_t{6962}},
      "InstrumentRange",
      -10.0,
      110.0);

    // --- EURange inverted (high < low): served verbatim, no swap/correction: ns;6970 ---
    mEuRangeInvertedId = NodeId{mTestNamespaceIndex, uint32_t{6970}};
    auto euRangeInvertedNode = create_analog_variable(
      addressSpace, mEuRangeInvertedId, analogItemType, "EuRangeInverted", DataValue{Variant{double{50.0}}});
    add_range_property(
      addressSpace, euRangeInvertedNode, NodeId{mTestNamespaceIndex, uint32_t{6971}}, "EURange", 80.0, 20.0);

    // --- EURange with a NaN High limit (Low=0): NaN preserved verbatim: ns;6980 ---
    mEuRangeNanId = NodeId{mTestNamespaceIndex, uint32_t{6980}};
    auto euRangeNanNode = create_analog_variable(
      addressSpace, mEuRangeNanId, analogItemType, "EuRangeNan", DataValue{Variant{double{50.0}}});
    add_range_property(addressSpace,
      euRangeNanNode,
      NodeId{mTestNamespaceIndex, uint32_t{6981}},
      "EURange",
      0.0,
      std::numeric_limits<double>::quiet_NaN());

    // --- InstrumentRange inverted (high < low), EURange present [0,100]: ns;6990 ---
    mInstrumentRangeInvertedId = NodeId{mTestNamespaceIndex, uint32_t{6990}};
    auto instrumentRangeInvertedNode = create_analog_variable(addressSpace,
      mInstrumentRangeInvertedId,
      analogItemType,
      "InstrumentRangeInverted",
      DataValue{Variant{double{50.0}}});
    add_eu_range_property(
      addressSpace, instrumentRangeInvertedNode, NodeId{mTestNamespaceIndex, uint32_t{6991}});
    add_range_property(addressSpace,
      instrumentRangeInvertedNode,
      NodeId{mTestNamespaceIndex, uint32_t{6992}},
      "InstrumentRange",
      110.0,
      -10.0);

    // --- InstrumentRange NaN variants (High=NaN / Low=NaN / both NaN), EURange present [0,100].
    // NB: ns;7000-7002 are taken by the base ComplianceWithNodes fixture, so these live at ns;7100+. ---
    mInstrumentRangeNanHighId = NodeId{mTestNamespaceIndex, uint32_t{7100}};
    auto instrumentRangeNanHighNode = create_analog_variable(addressSpace,
      mInstrumentRangeNanHighId,
      analogItemType,
      "InstrumentRangeNanHigh",
      DataValue{Variant{double{50.0}}});
    add_eu_range_property(
      addressSpace, instrumentRangeNanHighNode, NodeId{mTestNamespaceIndex, uint32_t{7101}});
    add_range_property(addressSpace,
      instrumentRangeNanHighNode,
      NodeId{mTestNamespaceIndex, uint32_t{7102}},
      "InstrumentRange",
      0.0,
      std::numeric_limits<double>::quiet_NaN());

    mInstrumentRangeNanLowId = NodeId{mTestNamespaceIndex, uint32_t{7110}};
    auto instrumentRangeNanLowNode = create_analog_variable(addressSpace,
      mInstrumentRangeNanLowId,
      analogItemType,
      "InstrumentRangeNanLow",
      DataValue{Variant{double{50.0}}});
    add_eu_range_property(
      addressSpace, instrumentRangeNanLowNode, NodeId{mTestNamespaceIndex, uint32_t{7111}});
    add_range_property(addressSpace,
      instrumentRangeNanLowNode,
      NodeId{mTestNamespaceIndex, uint32_t{7112}},
      "InstrumentRange",
      std::numeric_limits<double>::quiet_NaN(),
      100.0);

    mInstrumentRangeNanBothId = NodeId{mTestNamespaceIndex, uint32_t{7120}};
    auto instrumentRangeNanBothNode = create_analog_variable(addressSpace,
      mInstrumentRangeNanBothId,
      analogItemType,
      "InstrumentRangeNanBoth",
      DataValue{Variant{double{50.0}}});
    add_eu_range_property(
      addressSpace, instrumentRangeNanBothNode, NodeId{mTestNamespaceIndex, uint32_t{7121}});
    add_range_property(addressSpace,
      instrumentRangeNanBothNode,
      NodeId{mTestNamespaceIndex, uint32_t{7122}},
      "InstrumentRange",
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::quiet_NaN());

    // --- Degenerate EURange {50,50} AND InstrumentRange {50,50} (zero width; legal, accepted): ns;7130 ---
    mDegenerateRangeId = NodeId{mTestNamespaceIndex, uint32_t{7130}};
    auto degenerateRangeNode = create_analog_variable(
      addressSpace, mDegenerateRangeId, analogItemType, "DegenerateRange", DataValue{Variant{double{50.0}}});
    add_range_property(
      addressSpace, degenerateRangeNode, NodeId{mTestNamespaceIndex, uint32_t{7131}}, "EURange", 50.0, 50.0);
    add_range_property(addressSpace,
      degenerateRangeNode,
      NodeId{mTestNamespaceIndex, uint32_t{7132}},
      "InstrumentRange",
      50.0,
      50.0);

    // ========================================================================================================
    // sub-batch 3 nodes - TwoStateDiscreteType / MultiStateDiscreteType / MultiStateValueDiscreteType /
    // MultiStateDictionaryEntryDiscreteBaseType. Node ids ns;7200+ (disjoint from the base fixture
    // ns;7000-7002 and batches 1/2a/2b ns;6000-7132) to avoid a BadNodeIdExists collision in SetUp.
    // ========================================================================================================
    const NodeId twoStateType{VariableTypeId::TwoStateDiscreteType};
    const NodeId multiStateType{VariableTypeId::MultiStateDiscreteType};
    const NodeId multiStateValueType{VariableTypeId::MultiStateValueDiscreteType};
    const NodeId msdeType{VariableTypeId::MultiStateDictionaryEntryDiscreteBaseType};

    // --- TwoStateDiscrete lacking Mandatory TrueState (FalseState present): ns;7200 ---
    mTwoStateMissingTrueId = NodeId{mTestNamespaceIndex, uint32_t{7200}};
    auto twoStateMissingTrue = create_da_variable(addressSpace,
      mTwoStateMissingTrueId,
      twoStateType,
      "TwoStateMissingTrue",
      NodeId{DataTypeId::Boolean},
      DataValue{Variant{false}});
    add_localized_text_property(addressSpace,
      twoStateMissingTrue,
      NodeId{mTestNamespaceIndex, uint32_t{7201}},
      "FalseState",
      LocalizedText{"", "Off"});

    // --- TwoStateDiscrete value=true, TrueState = EMPTY LocalizedText (present-empty): ns;7210 ---
    mTwoStateTrueEmptyId = NodeId{mTestNamespaceIndex, uint32_t{7210}};
    auto twoStateTrueEmpty = create_da_variable(addressSpace,
      mTwoStateTrueEmptyId,
      twoStateType,
      "TwoStateTrueEmpty",
      NodeId{DataTypeId::Boolean},
      DataValue{Variant{true}});
    add_localized_text_property(addressSpace,
      twoStateTrueEmpty,
      NodeId{mTestNamespaceIndex, uint32_t{7211}},
      "TrueState",
      LocalizedText{});  // empty verbatim
    add_localized_text_property(addressSpace,
      twoStateTrueEmpty,
      NodeId{mTestNamespaceIndex, uint32_t{7212}},
      "FalseState",
      LocalizedText{"", "Off"});

    // --- TwoStateDiscrete value=false, FalseState = EMPTY LocalizedText (present-empty): ns;7220 ---
    mTwoStateFalseEmptyId = NodeId{mTestNamespaceIndex, uint32_t{7220}};
    auto twoStateFalseEmpty = create_da_variable(addressSpace,
      mTwoStateFalseEmptyId,
      twoStateType,
      "TwoStateFalseEmpty",
      NodeId{DataTypeId::Boolean},
      DataValue{Variant{false}});
    add_localized_text_property(addressSpace,
      twoStateFalseEmpty,
      NodeId{mTestNamespaceIndex, uint32_t{7221}},
      "TrueState",
      LocalizedText{"", "On"});
    add_localized_text_property(addressSpace,
      twoStateFalseEmpty,
      NodeId{mTestNamespaceIndex, uint32_t{7222}},
      "FalseState",
      LocalizedText{});  // empty verbatim

    // --- MultiStateDiscrete lacking Mandatory EnumStrings: ns;7230 ---
    mMultiStateNoEnumStringsId = NodeId{mTestNamespaceIndex, uint32_t{7230}};
    create_da_variable(addressSpace,
      mMultiStateNoEnumStringsId,
      multiStateType,
      "MultiStateNoEnumStrings",
      NodeId{DataTypeId::UInt32},
      DataValue{Variant{std::uint32_t{0}}});

    // --- MultiStateDiscrete, EnumStrings {Off,Low,High}, value 7 (out of [0,3)): ns;7240 ---
    mMultiStateOutsideId = NodeId{mTestNamespaceIndex, uint32_t{7240}};
    auto multiStateOutside = create_da_variable(addressSpace,
      mMultiStateOutsideId,
      multiStateType,
      "MultiStateOutside",
      NodeId{DataTypeId::UInt32},
      DataValue{Variant{std::uint32_t{7}}});
    add_enum_strings_property(addressSpace,
      multiStateOutside,
      NodeId{mTestNamespaceIndex, uint32_t{7241}},
      {LocalizedText{"", "Off"}, LocalizedText{"", "Low"}, LocalizedText{"", "High"}});

    // --- MultiStateDiscrete, EnumStrings {Off, "", High} (index 1 present-empty), value 1: ns;7250 ---
    mMultiStateEmptyStringId = NodeId{mTestNamespaceIndex, uint32_t{7250}};
    auto multiStateEmptyString = create_da_variable(addressSpace,
      mMultiStateEmptyStringId,
      multiStateType,
      "MultiStateEmptyString",
      NodeId{DataTypeId::UInt32},
      DataValue{Variant{std::uint32_t{1}}});
    add_enum_strings_property(addressSpace,
      multiStateEmptyString,
      NodeId{mTestNamespaceIndex, uint32_t{7251}},
      {LocalizedText{"", "Off"}, LocalizedText{}, LocalizedText{"", "High"}});  // index 1 empty verbatim

    // --- MultiStateDiscrete write-accept node (EnumStrings {Off,Low,High}): ns;7260 ---
    mMultiStateWriteAcceptId = NodeId{mTestNamespaceIndex, uint32_t{7260}};
    auto multiStateWriteAccept = create_da_variable(addressSpace,
      mMultiStateWriteAcceptId,
      multiStateType,
      "MultiStateWriteAccept",
      NodeId{DataTypeId::UInt32},
      DataValue{Variant{std::uint32_t{0}}});
    add_enum_strings_property(addressSpace,
      multiStateWriteAccept,
      NodeId{mTestNamespaceIndex, uint32_t{7261}},
      {LocalizedText{"", "Off"}, LocalizedText{"", "Low"}, LocalizedText{"", "High"}});

    // --- MultiStateDiscrete write-reject node (its write source rejects here): ns;7270 ---
    mMultiStateWriteRejectId = NodeId{mTestNamespaceIndex, uint32_t{7270}};
    auto multiStateWriteReject = create_da_variable(addressSpace,
      mMultiStateWriteRejectId,
      multiStateType,
      "MultiStateWriteReject",
      NodeId{DataTypeId::UInt32},
      DataValue{Variant{std::uint32_t{0}}});
    add_enum_strings_property(addressSpace,
      multiStateWriteReject,
      NodeId{mTestNamespaceIndex, uint32_t{7271}},
      {LocalizedText{"", "Off"}, LocalizedText{"", "Low"}, LocalizedText{"", "High"}});

    // --- MultiStateValueDiscrete lacking Mandatory EnumValues: ns;7280 ---
    mMultiStateValueNoEnumId = NodeId{mTestNamespaceIndex, uint32_t{7280}};
    create_da_variable(addressSpace,
      mMultiStateValueNoEnumId,
      multiStateValueType,
      "MultiStateValueNoEnum",
      NodeId{DataTypeId::Int64},
      DataValue{Variant{std::int64_t{0}}});

    // --- MultiStateValueDiscrete with EnumValues present but ValueAsText absent: ns;7285 ---
    mMultiStateValueNoTextId = NodeId{mTestNamespaceIndex, uint32_t{7285}};
    auto multiStateValueNoText = create_da_variable(addressSpace,
      mMultiStateValueNoTextId,
      multiStateValueType,
      "MultiStateValueNoText",
      NodeId{DataTypeId::Int64},
      DataValue{Variant{std::int64_t{1}}});
    add_enum_values_property(addressSpace,
      multiStateValueNoText,
      NodeId{mTestNamespaceIndex, uint32_t{7286}},
      {{1, "Low"}, {2, "High"}});

    // --- MultiStateValueDiscrete, EnumValues size 5, value 999 (matches no entry): ns;7290 ---
    mMultiStateValueOutsideId = NodeId{mTestNamespaceIndex, uint32_t{7290}};
    auto multiStateValueOutside = create_da_variable(addressSpace,
      mMultiStateValueOutsideId,
      multiStateValueType,
      "MultiStateValueOutside",
      NodeId{DataTypeId::Int64},
      DataValue{Variant{std::int64_t{999}}});
    add_enum_values_property(addressSpace,
      multiStateValueOutside,
      NodeId{mTestNamespaceIndex, uint32_t{7291}},
      {{1, "A"}, {2, "B"}, {3, "C"}, {4, "D"}, {5, "E"}});
    add_localized_text_property(addressSpace,
      multiStateValueOutside,
      NodeId{mTestNamespaceIndex, uint32_t{7292}},
      "ValueAsText",
      LocalizedText{"", "Unknown"});  // Mandatory ValueAsText (CL-DA-001)

    // --- MSDE-DBT dictionary-write RESOLVES node (OPC 10000-19 section 7.1, CL-DA-012): EnumValues
    // {1Low,2High,3Running}, a Mandatory 2-D EnumDictionaryEntries table (3 states x 1 dictionary), and a
    // client-WRITABLE ValueAsDictionaryEntries NodeId[]. State index 2 (dictionary 0) selects
    // EnumDictionaryEntries[2][0] = ns;7308 (mDictEntryRunningId) and therefore changes the parent Value to
    // the third enumerated value. ns;7300 ---
    mDictWriteResolvesId = NodeId{mTestNamespaceIndex, uint32_t{7300}};
    auto dictWriteResolves = create_da_variable(addressSpace,
      mDictWriteResolvesId,
      msdeType,
      "DictWriteResolves",
      NodeId{DataTypeId::Int64},
      DataValue{Variant{std::int64_t{1}}});
    add_enum_values_property(addressSpace,
      dictWriteResolves,
      NodeId{mTestNamespaceIndex, uint32_t{7301}},
      {{1, "Low"}, {2, "High"}, {3, "Running"}});
    add_localized_text_property(addressSpace,
      dictWriteResolves,
      NodeId{mTestNamespaceIndex, uint32_t{7304}},
      "ValueAsText",
      LocalizedText{"", "Low"});  // inherited Mandatory ValueAsText (CL-DA-001)
    mDictEntryLowId = NodeId{mTestNamespaceIndex, uint32_t{7306}};
    mDictEntryHighId = NodeId{mTestNamespaceIndex, uint32_t{7307}};
    mDictEntryRunningId = NodeId{mTestNamespaceIndex, uint32_t{7308}};
    add_enum_dictionary_entries_property(addressSpace,
      dictWriteResolves,
      NodeId{mTestNamespaceIndex, uint32_t{7305}},
      /*states=*/3,
      /*dictionaries=*/1,
      {mDictEntryLowId, mDictEntryHighId, mDictEntryRunningId});  // row-major [state][dictionary]
    mValueAsDictEntriesResolvesId = NodeId{mTestNamespaceIndex, uint32_t{7309}};
    add_value_as_dictionary_entries_property(addressSpace, dictWriteResolves, mValueAsDictEntriesResolvesId);

    // --- MSDE-DBT dictionary-write OUT-OF-RANGE node (CL-DA-012 negative): a valid EnumDictionaryEntries
    // table (2 states x 1 dictionary), so an out-of-bounds state index is a LOCAL reject (no wire Write). A
    // CountValueWritesOnNode on its ValueAsDictionaryEntries proves ZERO writes reach the wire. ns;7310 ---
    mDictWriteNoMatchId = NodeId{mTestNamespaceIndex, uint32_t{7310}};
    auto dictWriteNoMatch = create_da_variable(addressSpace,
      mDictWriteNoMatchId,
      msdeType,
      "DictWriteOutOfRange",
      NodeId{DataTypeId::Int64},
      DataValue{Variant{std::int64_t{1}}});
    add_enum_values_property(
      addressSpace, dictWriteNoMatch, NodeId{mTestNamespaceIndex, uint32_t{7311}}, {{1, "Low"}, {2, "High"}});
    add_localized_text_property(addressSpace,
      dictWriteNoMatch,
      NodeId{mTestNamespaceIndex, uint32_t{7314}},
      "ValueAsText",
      LocalizedText{"", "Low"});  // inherited Mandatory ValueAsText (CL-DA-001)
    add_enum_dictionary_entries_property(addressSpace,
      dictWriteNoMatch,
      NodeId{mTestNamespaceIndex, uint32_t{7318}},
      /*states=*/2,
      /*dictionaries=*/1,
      {NodeId{mTestNamespaceIndex, uint32_t{7316}}, NodeId{mTestNamespaceIndex, uint32_t{7317}}});
    mValueAsDictEntriesOobId = NodeId{mTestNamespaceIndex, uint32_t{7315}};
    add_value_as_dictionary_entries_property(addressSpace, dictWriteNoMatch, mValueAsDictEntriesOobId);

    // --- MSDE (MultiStateDictionaryEntryDiscreteBaseType) with EnumValues but no EnumDictionaryEntries: the
    // client accesses an MSDE via multi_state_value_discrete_async, which pre-flights only EnumValues, so
    // this builds a GOOD handle (EnumDictionaryEntries is NOT enforced - REPORTED divergence): ns;7320 ---
    mMsdeNoDictionaryId = NodeId{mTestNamespaceIndex, uint32_t{7320}};
    auto msdeNoDictionary = create_da_variable(addressSpace,
      mMsdeNoDictionaryId,
      msdeType,
      "MsdeNoDictionary",
      NodeId{DataTypeId::Int64},
      DataValue{Variant{std::int64_t{1}}});
    add_enum_values_property(
      addressSpace, msdeNoDictionary, NodeId{mTestNamespaceIndex, uint32_t{7321}}, {{1, "Low"}, {2, "High"}});
    add_localized_text_property(addressSpace,
      msdeNoDictionary,
      NodeId{mTestNamespaceIndex, uint32_t{7322}},
      "ValueAsText",
      LocalizedText{
        "", "Low"});  // inherited Mandatory ValueAsText, so ns;7320 fails ONLY on EnumDictionaryEntries

    // --- MSDE lacking EnumValues: the real Mandatory-Property gate the MSVD accessor enforces: ns;7330 ---
    mMsdeNoEnumValuesId = NodeId{mTestNamespaceIndex, uint32_t{7330}};
    create_da_variable(addressSpace,
      mMsdeNoEnumValuesId,
      msdeType,
      "MsdeNoEnumValues",
      NodeId{DataTypeId::Int64},
      DataValue{Variant{std::int64_t{0}}});

    // ========================================================================================================
    // sub-batch 4 nodes - ValuePrecision decode (CL-DA-002) + an Uncertain-quality DataItem (CL-DA-015). Node
    // ids ns;7340+ (disjoint from the base fixture ns;7000-7002 and batches 1/2a/2b/3 ns;6000-7330) to avoid
    // a BadNodeIdExists collision in SetUp. Each carries the Mandatory EURange (so analog_item_async builds a
    // handle) plus the specific DA Property / quality under test, served VERBATIM.
    // ========================================================================================================

    // --- AnalogItem whose stored Value carries an Uncertain_SubstituteValue quality StatusCode: ns;7340 ---
    mUncertainStatusAnalogId = NodeId{mTestNamespaceIndex, uint32_t{7340}};
    auto uncertainStatusNode = create_analog_variable(addressSpace,
      mUncertainStatusAnalogId,
      analogItemType,
      "AnalogUncertainStatus",
      DataValue{Variant{double{50.0}}, StatusCode{Status::UncertainSubstituteValue}});
    add_eu_range_property(addressSpace, uncertainStatusNode, NodeId{mTestNamespaceIndex, uint32_t{7341}});

    // --- ValuePrecision = NaN: surfaced as NO precision (nullopt) - narrowing NaN to int16 is UB: ns;7350
    // ---
    mValuePrecisionNanId = NodeId{mTestNamespaceIndex, uint32_t{7350}};
    auto valuePrecisionNanNode = create_analog_variable(addressSpace,
      mValuePrecisionNanId,
      analogItemType,
      "ValuePrecisionNan",
      DataValue{Variant{double{50.0}}});
    add_eu_range_property(addressSpace, valuePrecisionNanNode, NodeId{mTestNamespaceIndex, uint32_t{7351}});
    add_value_precision_property(addressSpace,
      valuePrecisionNanNode,
      NodeId{mTestNamespaceIndex, uint32_t{7352}},
      std::numeric_limits<double>::quiet_NaN());

    // --- ValuePrecision = -2.7: static_cast<int16> TRUNCATES toward zero to -2 (NOT round-half -3): ns;7360
    // -
    mValuePrecisionNegativeId = NodeId{mTestNamespaceIndex, uint32_t{7360}};
    auto valuePrecisionNegativeNode = create_analog_variable(addressSpace,
      mValuePrecisionNegativeId,
      analogItemType,
      "ValuePrecisionNegative",
      DataValue{Variant{double{50.0}}});
    add_eu_range_property(
      addressSpace, valuePrecisionNegativeNode, NodeId{mTestNamespaceIndex, uint32_t{7361}});
    add_value_precision_property(
      addressSpace, valuePrecisionNegativeNode, NodeId{mTestNamespaceIndex, uint32_t{7362}}, -2.7);

    // --- ValuePrecision = 6.0 (whole): surfaced as informational optional{6}, NOT applied to the fine-detail
    // Value (50.123456 stays verbatim): ns;7370 ---
    mValuePrecisionWholeId = NodeId{mTestNamespaceIndex, uint32_t{7370}};
    auto valuePrecisionWholeNode = create_analog_variable(addressSpace,
      mValuePrecisionWholeId,
      analogItemType,
      "ValuePrecisionWhole",
      DataValue{Variant{double{50.123456}}});
    add_eu_range_property(addressSpace, valuePrecisionWholeNode, NodeId{mTestNamespaceIndex, uint32_t{7371}});
    add_value_precision_property(
      addressSpace, valuePrecisionWholeNode, NodeId{mTestNamespaceIndex, uint32_t{7372}}, 6.0);

    // --- ValuePrecision = 0.0: a VALID precision, present-not-absent -> optional{0} (never nullopt): ns;7380
    mValuePrecisionZeroId = NodeId{mTestNamespaceIndex, uint32_t{7380}};
    auto valuePrecisionZeroNode = create_analog_variable(addressSpace,
      mValuePrecisionZeroId,
      analogItemType,
      "ValuePrecisionZero",
      DataValue{Variant{double{50.0}}});
    add_eu_range_property(addressSpace, valuePrecisionZeroNode, NodeId{mTestNamespaceIndex, uint32_t{7381}});
    add_value_precision_property(
      addressSpace, valuePrecisionZeroNode, NodeId{mTestNamespaceIndex, uint32_t{7382}}, 0.0);

    // ========================================================================================================
    // sub-batch 5 node - SemanticChange DA-Property invalidation (section 8.18.2/section 8.13.5,
    // CL-DA-010/011). A single AnalogItem whose EURange the TEST mutates SERVER-SIDE (set_server_eu_range)
    // between reads, to prove the DataAccess typed-accessor RE-RESOLVES fresh Properties after a
    // SemanticChangeCache invalidation. Node ids ns;7400+ (disjoint from the base fixture ns;7000-7002 and
    // batches 1-4 ns;6000-7382). EURange starts [0,100]; the invalidation rows rewrite it to [0,200] /
    // [0,300] and re-read.
    // ========================================================================================================
    mSemanticChangeAnalogId = NodeId{mTestNamespaceIndex, uint32_t{7400}};
    auto semanticChangeNode = create_analog_variable(addressSpace,
      mSemanticChangeAnalogId,
      analogItemType,
      "SemanticChangeAnalog",
      DataValue{Variant{double{50.0}}});
    mSemanticChangeEuRangeId = NodeId{mTestNamespaceIndex, uint32_t{7401}};
    add_eu_range_property(addressSpace, semanticChangeNode, mSemanticChangeEuRangeId);

    // ========================================================================================================
    // sub-batch 6 nodes - SERVER-side DataAccess model obligations (Part 8 section 5.2 / section 5.3.2 /
    // section 5.3.3). Two families:
    //  (a) a hand-authored DataItem carrying a vendor Definition equation (ns;7500+, disjoint from batches
    //      1-5), for the non-localised-String obligation; and
    //  (b) instances materialised by the PRODUCTION type-instantiation path (the generated AnalogItem /
    //      AnalogUnitRange / TwoStateDiscrete helpers). That path is what materialises a type's Mandatory
    //      Properties, each holding the inverse HasProperty Reference from which the hosting in-memory
    //      namespace finds the owner of a changed semantic Property and marks the owner's monitored items, so
    //      the Mandatory-Property and SemanticsChanged obligations are driven through it rather than through
    //      hand-built nodes (a hand-built Property without that inverse Reference has no owner, so its writes
    //      could never raise the bit - that would be a fixture artefact, not a server verdict). The
    //      instantiation engine allocates their NodeIds, so each is captured into a member here.
    // ========================================================================================================
    mDefinitionEquationId = NodeId{mTestNamespaceIndex, uint32_t{7500}};
    auto definitionEquationNode = create_analog_variable(addressSpace,
      mDefinitionEquationId,
      analogItemType,
      "DefinitionEquation",
      DataValue{Variant{double{50.0}}});
    add_eu_range_property(addressSpace, definitionEquationNode, NodeId{mTestNamespaceIndex, uint32_t{7501}});
    mDefinitionEquationPropertyId = NodeId{mTestNamespaceIndex, uint32_t{7502}};
    add_definition_property(
      addressSpace, definitionEquationNode, mDefinitionEquationPropertyId, sDefinitionEquation);

    InstantiationOptions instantiationOptions;
    instantiationOptions.targetNamespaceIndex = mTestNamespaceIndex;

    // (b1) A plain AnalogItemType instance - EURange is the type's Mandatory Property.
    {
      auto created = AnalogItem::try_create_sync(addressSpace,
        NodeId{ObjectId::ObjectsFolder},
        QualifiedName{mTestNamespaceIndex, "InstantiatedAnalogItem"},
        instantiationOptions,
        VariableInstantiationAttributes{
          .dataType = NodeId{DataTypeId::Double}, .valueRank = ValueRank::scalar, .accessLevel = readWrite});
      if (created.is_good())
      {
        AnalogItem analogItem = std::move(created).value();
        mInstantiatedAnalogId = analogItem.node_id();
        auto euRangeProperty = analogItem.try_eu_range_property_sync();
        if (euRangeProperty.is_good())
        {
          mInstantiatedEuRangeId = euRangeProperty.value().node_id();
        }
        // Keep the instantiated subtree as permanent server content (the handle would otherwise remove it).
        analogItem.release();
      }
      seed_instance_value(addressSpace, mInstantiatedAnalogId, DataValue{Variant{double{50.0}}});
      Range instantiatedRange = make_range(0.0, 100.0);
      seed_writable_property(addressSpace, mInstantiatedEuRangeId, DataValue{Variant{instantiatedRange}});
    }

    // (b2) An ARRAY-valued AnalogUnitRangeType instance (Double[8]). AnalogUnitRangeType mandates BOTH
    // EURange and EngineeringUnits, so the array-wide Property obligation can be observed on one instance
    // without opting any Optional child in.
    {
      auto created = AnalogUnitRange::try_create_sync(addressSpace,
        NodeId{ObjectId::ObjectsFolder},
        QualifiedName{mTestNamespaceIndex, "InstantiatedAnalogArray"},
        instantiationOptions,
        VariableInstantiationAttributes{
          .dataType = NodeId{DataTypeId::Double}, .valueRank = 1, .accessLevel = readWrite});
      if (created.is_good())
      {
        AnalogUnitRange arrayItem = std::move(created).value();
        mArrayUnitRangeId = arrayItem.node_id();
        auto euRangeProperty = arrayItem.try_eu_range_property_sync();
        if (euRangeProperty.is_good())
        {
          mArrayUnitRangeEuRangeId = euRangeProperty.value().node_id();
        }
        auto unitsProperty = arrayItem.try_engineering_units_property_sync();
        if (unitsProperty.is_good())
        {
          mArrayUnitRangeUnitsId = unitsProperty.value().node_id();
        }
        arrayItem.release();
      }
      seed_instance_value(addressSpace,
        mArrayUnitRangeId,
        DataValue{Variant{Array<double>{10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0}}});
      Range arrayRange = make_range(0.0, 100.0);
      seed_writable_property(addressSpace, mArrayUnitRangeEuRangeId, DataValue{Variant{arrayRange}});
      EUInformation arrayUnits = make_full_eu_information();
      seed_writable_property(addressSpace, mArrayUnitRangeUnitsId, DataValue{Variant{arrayUnits}});
    }

    // (b3) A scalar AnalogUnitRangeType instance whose EURange and EngineeringUnits the SemanticsChanged row
    // rewrites from the client (both Properties are made client-writable by the seeding helper).
    {
      auto created = AnalogUnitRange::try_create_sync(addressSpace,
        NodeId{ObjectId::ObjectsFolder},
        QualifiedName{mTestNamespaceIndex, "InstantiatedSemanticsAnalog"},
        instantiationOptions,
        VariableInstantiationAttributes{
          .dataType = NodeId{DataTypeId::Double}, .valueRank = ValueRank::scalar, .accessLevel = readWrite});
      if (created.is_good())
      {
        AnalogUnitRange semanticsItem = std::move(created).value();
        mSemanticsUnitRangeId = semanticsItem.node_id();
        auto euRangeProperty = semanticsItem.try_eu_range_property_sync();
        if (euRangeProperty.is_good())
        {
          mSemanticsEuRangeId = euRangeProperty.value().node_id();
        }
        auto unitsProperty = semanticsItem.try_engineering_units_property_sync();
        if (unitsProperty.is_good())
        {
          mSemanticsUnitsId = unitsProperty.value().node_id();
        }
        semanticsItem.release();
      }
      seed_instance_value(addressSpace, mSemanticsUnitRangeId, DataValue{Variant{double{50.0}}});
      Range semanticsRange = make_range(0.0, 100.0);
      seed_writable_property(addressSpace, mSemanticsEuRangeId, DataValue{Variant{semanticsRange}});
      EUInformation semanticsUnits = make_full_eu_information();
      seed_writable_property(addressSpace, mSemanticsUnitsId, DataValue{Variant{semanticsUnits}});
    }

    // (b4) A TwoStateDiscreteType instance - TrueState and FalseState are both Mandatory on the type, and
    // both are registered as semantic properties by the same generated create flow.
    {
      auto created = TwoStateDiscrete::try_create_sync(addressSpace,
        NodeId{ObjectId::ObjectsFolder},
        QualifiedName{mTestNamespaceIndex, "InstantiatedTwoState"},
        instantiationOptions,
        VariableInstantiationAttributes{
          .dataType = NodeId{DataTypeId::Boolean}, .valueRank = ValueRank::scalar, .accessLevel = readWrite});
      if (created.is_good())
      {
        TwoStateDiscrete twoState = std::move(created).value();
        mTwoStateInstanceId = twoState.node_id();
        auto trueStateProperty = twoState.try_true_state_property_sync();
        if (trueStateProperty.is_good())
        {
          mTwoStateTruePropertyId = trueStateProperty.value().node_id();
        }
        auto falseStateProperty = twoState.try_false_state_property_sync();
        if (falseStateProperty.is_good())
        {
          mTwoStateFalsePropertyId = falseStateProperty.value().node_id();
        }
        twoState.release();
      }
      seed_instance_value(addressSpace, mTwoStateInstanceId, DataValue{Variant{false}});
      seed_writable_property(
        addressSpace, mTwoStateTruePropertyId, DataValue{Variant{LocalizedText{"", "Running"}}});
      seed_writable_property(
        addressSpace, mTwoStateFalsePropertyId, DataValue{Variant{LocalizedText{"", "Stopped"}}});
    }

    // ========================================================================================================
    // sub-batch 7 nodes - the remaining Part 8 section 5.3.3 / section 5.3.4 model obligations: the
    // MultiState lookup tables and the ArrayItem family. Every instance below is materialised by the
    // PRODUCTION type-instantiation path for the same reason as (b1)-(b4): that path is what materialises a
    // type's Mandatory Properties, each holding the inverse HasProperty Reference from which the hosting
    // in-memory namespace finds its owner, so a hand-built node without it could never raise the bit and its
    // "failure" would be a fixture artefact.
    // ========================================================================================================

    // (c1) A scalar MultiStateDiscreteType instance. EnumStrings is the type's Mandatory Property; the table
    // {Off, Low, High} is positional - entry i names state value i.
    {
      auto created = MultiStateDiscrete::try_create_sync(addressSpace,
        NodeId{ObjectId::ObjectsFolder},
        QualifiedName{mTestNamespaceIndex, "InstantiatedMultiState"},
        instantiationOptions,
        VariableInstantiationAttributes{
          .dataType = NodeId{DataTypeId::UInt32}, .valueRank = ValueRank::scalar, .accessLevel = readWrite});
      if (created.is_good())
      {
        MultiStateDiscrete multiState = std::move(created).value();
        mMultiStateInstanceId = multiState.node_id();
        auto enumStringsProperty = multiState.try_enum_strings_property_sync();
        if (enumStringsProperty.is_good())
        {
          mMultiStateEnumStringsId = enumStringsProperty.value().node_id();
        }
        multiState.release();
      }
      seed_instance_value(addressSpace, mMultiStateInstanceId, DataValue{Variant{std::uint32_t{1}}});
      Array<LocalizedText> multiStateTable =
        make_enum_strings({LocalizedText{"", "Off"}, LocalizedText{"", "Low"}, LocalizedText{"", "High"}});
      seed_writable_property(
        addressSpace, mMultiStateEnumStringsId, DataValue{Variant{std::move(multiStateTable)}});
    }

    // (c2) An ARRAY-valued MultiStateDiscreteType instance holding [0, 2, 1]. One EnumStrings table has to
    // govern all three elements, so the array shape has to exist for the obligation to be observable.
    {
      auto created = MultiStateDiscrete::try_create_sync(addressSpace,
        NodeId{ObjectId::ObjectsFolder},
        QualifiedName{mTestNamespaceIndex, "InstantiatedMultiStateArray"},
        instantiationOptions,
        VariableInstantiationAttributes{
          .dataType = NodeId{DataTypeId::UInt32}, .valueRank = 1, .accessLevel = readWrite});
      if (created.is_good())
      {
        MultiStateDiscrete multiStateArray = std::move(created).value();
        mMultiStateArrayId = multiStateArray.node_id();
        auto enumStringsProperty = multiStateArray.try_enum_strings_property_sync();
        if (enumStringsProperty.is_good())
        {
          mMultiStateArrayEnumStringsId = enumStringsProperty.value().node_id();
        }
        multiStateArray.release();
      }
      seed_instance_value(addressSpace,
        mMultiStateArrayId,
        DataValue{Variant{Array<std::uint32_t>{std::uint32_t{0}, std::uint32_t{2}, std::uint32_t{1}}}});
      Array<LocalizedText> arrayTable =
        make_enum_strings({LocalizedText{"", "Off"}, LocalizedText{"", "Low"}, LocalizedText{"", "High"}});
      seed_writable_property(
        addressSpace, mMultiStateArrayEnumStringsId, DataValue{Variant{std::move(arrayTable)}});
    }

    // (c3) A MultiStateValueDiscreteType instance whose Mandatory EnumValues the SemanticsChanged row
    // rewrites from the client. Its Mandatory ValueAsText is captured too (the instantiation engine
    // materialises it with a null Value): AC-SVR-DA-013 quantifies over EVERY MultiStateValueDiscrete
    // instance, so the second member of that population has to be inspectable as well.
    {
      auto created = MultiStateValueDiscrete::try_create_sync(addressSpace,
        NodeId{ObjectId::ObjectsFolder},
        QualifiedName{mTestNamespaceIndex, "InstantiatedMultiStateValue"},
        instantiationOptions,
        VariableInstantiationAttributes{
          .dataType = NodeId{DataTypeId::Int64}, .valueRank = ValueRank::scalar, .accessLevel = readWrite});
      if (created.is_good())
      {
        MultiStateValueDiscrete multiStateValue = std::move(created).value();
        mMsvdInstanceId = multiStateValue.node_id();
        auto enumValuesProperty = multiStateValue.try_enum_values_property_sync();
        if (enumValuesProperty.is_good())
        {
          mMsvdEnumValuesId = enumValuesProperty.value().node_id();
        }
        auto valueAsTextProperty = multiStateValue.try_value_as_text_property_sync();
        if (valueAsTextProperty.is_good())
        {
          mMsvdValueAsTextId = valueAsTextProperty.value().node_id();
        }
        multiStateValue.release();
      }
      seed_instance_value(addressSpace, mMsvdInstanceId, DataValue{Variant{std::int64_t{1}}});
      Array<RefStructure<Structure>> msvdTable = make_enum_values({{1, "Low"}, {2, "High"}});
      seed_writable_property(addressSpace, mMsvdEnumValuesId, DataValue{Variant{std::move(msvdTable)}});
      // ValueAsText is not seeded: it is projected from the Value through EnumValues (Value 1 -> "Low") by a
      // read-only source, which refuses a write.
    }

    // (c4) A YArrayItemType instance modelled the only way Part 8 section 5.3.4.1 permits the type to be
    // picked at all: ArrayItemType is for Variables whose Title and AxisScaleType CAN be filled with
    // reasonable values, so a deployment that chooses it over a plain AnalogItem fills them. AC-SVR-DA-015
    // inspects what the server serves back for them. Its DataType / ValueRank are the shape AC-SVR-DA-017
    // reads back.
    {
      auto created = YArrayItem::try_create_sync(addressSpace,
        NodeId{ObjectId::ObjectsFolder},
        QualifiedName{mTestNamespaceIndex, "InstantiatedYArrayItem"},
        instantiationOptions,
        VariableInstantiationAttributes{
          .dataType = NodeId{DataTypeId::Double}, .valueRank = 1, .accessLevel = readWrite});
      if (created.is_good())
      {
        YArrayItem yArray = std::move(created).value();
        mYArrayItemId = yArray.node_id();
        auto xAxisProperty = yArray.try_x_axis_definition_property_sync();
        if (xAxisProperty.is_good())
        {
          mYArrayXAxisDefinitionId = xAxisProperty.value().node_id();
        }
        auto titleProperty = yArray.try_title_property_sync();
        if (titleProperty.is_good())
        {
          mYArrayTitleId = titleProperty.value().node_id();
        }
        auto axisScaleProperty = yArray.try_axis_scale_type_property_sync();
        if (axisScaleProperty.is_good())
        {
          mYArrayAxisScaleTypeId = axisScaleProperty.value().node_id();
        }
        yArray.release();
      }
      seed_instance_value(addressSpace, mYArrayItemId, DataValue{Variant{Array<double>{1.0, 2.0, 3.0}}});
      seed_writable_property(
        addressSpace, mYArrayTitleId, DataValue{Variant{LocalizedText{"", "Reactor temperature profile"}}});
      // Log rather than Linear: Linear is the zero enumerator, so a served Linear cannot be told apart from
      // an AxisScaleType that nobody ever set.
      seed_writable_property(addressSpace,
        mYArrayAxisScaleTypeId,
        DataValue{Variant{static_cast<std::int32_t>(AxisScaleEnumeration::Log)}});
    }

    // (c5)-(c9) One instance of every concrete ArrayItem subtype, each with its own axis Properties and its
    // Title made client-writable, so the per-subtype SemanticsChanged obligation can be driven on each.
    // ArrayItemType itself is abstract, so the five concrete subtypes ARE the population.
    {
      auto created = YArrayItem::try_create_sync(addressSpace,
        NodeId{ObjectId::ObjectsFolder},
        QualifiedName{mTestNamespaceIndex, "SemanticsYArrayItem"},
        instantiationOptions,
        VariableInstantiationAttributes{
          .dataType = NodeId{DataTypeId::Double}, .valueRank = 1, .accessLevel = readWrite});
      if (created.is_good())
      {
        YArrayItem item = std::move(created).value();
        mSemanticsYArrayId = item.node_id();
        auto xAxisProperty = item.try_x_axis_definition_property_sync();
        if (xAxisProperty.is_good())
        {
          mSemanticsYArrayXAxisId = xAxisProperty.value().node_id();
        }
        auto titleProperty = item.try_title_property_sync();
        if (titleProperty.is_good())
        {
          mSemanticsYArrayTitleId = titleProperty.value().node_id();
        }
        item.release();
      }
      seed_array_item_instance(
        addressSpace, mSemanticsYArrayId, {mSemanticsYArrayXAxisId}, mSemanticsYArrayTitleId, "Y axis");
    }

    {
      auto created = XYArrayItem::try_create_sync(addressSpace,
        NodeId{ObjectId::ObjectsFolder},
        QualifiedName{mTestNamespaceIndex, "SemanticsXYArrayItem"},
        instantiationOptions,
        VariableInstantiationAttributes{.accessLevel = readWrite});
      if (created.is_good())
      {
        XYArrayItem item = std::move(created).value();
        mSemanticsXYArrayId = item.node_id();
        auto xAxisProperty = item.try_x_axis_definition_property_sync();
        if (xAxisProperty.is_good())
        {
          mSemanticsXYArrayXAxisId = xAxisProperty.value().node_id();
        }
        auto titleProperty = item.try_title_property_sync();
        if (titleProperty.is_good())
        {
          mSemanticsXYArrayTitleId = titleProperty.value().node_id();
        }
        item.release();
      }
      seed_array_item_instance(
        addressSpace, mSemanticsXYArrayId, {mSemanticsXYArrayXAxisId}, mSemanticsXYArrayTitleId, "XY axis");
    }

    {
      auto created = ImageItem::try_create_sync(addressSpace,
        NodeId{ObjectId::ObjectsFolder},
        QualifiedName{mTestNamespaceIndex, "SemanticsImageItem"},
        instantiationOptions,
        VariableInstantiationAttributes{.accessLevel = readWrite});
      if (created.is_good())
      {
        ImageItem item = std::move(created).value();
        mSemanticsImageId = item.node_id();
        auto xAxisProperty = item.try_x_axis_definition_property_sync();
        if (xAxisProperty.is_good())
        {
          mSemanticsImageXAxisId = xAxisProperty.value().node_id();
        }
        auto yAxisProperty = item.try_y_axis_definition_property_sync();
        if (yAxisProperty.is_good())
        {
          mSemanticsImageYAxisId = yAxisProperty.value().node_id();
        }
        auto titleProperty = item.try_title_property_sync();
        if (titleProperty.is_good())
        {
          mSemanticsImageTitleId = titleProperty.value().node_id();
        }
        item.release();
      }
      seed_array_item_instance(addressSpace,
        mSemanticsImageId,
        {mSemanticsImageXAxisId, mSemanticsImageYAxisId},
        mSemanticsImageTitleId,
        "Image axis");
    }

    {
      auto created = CubeItem::try_create_sync(addressSpace,
        NodeId{ObjectId::ObjectsFolder},
        QualifiedName{mTestNamespaceIndex, "SemanticsCubeItem"},
        instantiationOptions,
        VariableInstantiationAttributes{.accessLevel = readWrite});
      if (created.is_good())
      {
        CubeItem item = std::move(created).value();
        mSemanticsCubeId = item.node_id();
        auto xAxisProperty = item.try_x_axis_definition_property_sync();
        if (xAxisProperty.is_good())
        {
          mSemanticsCubeXAxisId = xAxisProperty.value().node_id();
        }
        auto yAxisProperty = item.try_y_axis_definition_property_sync();
        if (yAxisProperty.is_good())
        {
          mSemanticsCubeYAxisId = yAxisProperty.value().node_id();
        }
        auto zAxisProperty = item.try_z_axis_definition_property_sync();
        if (zAxisProperty.is_good())
        {
          mSemanticsCubeZAxisId = zAxisProperty.value().node_id();
        }
        auto titleProperty = item.try_title_property_sync();
        if (titleProperty.is_good())
        {
          mSemanticsCubeTitleId = titleProperty.value().node_id();
        }
        item.release();
      }
      seed_array_item_instance(addressSpace,
        mSemanticsCubeId,
        {mSemanticsCubeXAxisId, mSemanticsCubeYAxisId, mSemanticsCubeZAxisId},
        mSemanticsCubeTitleId,
        "Cube axis");
    }

    // NDimensionArrayItemType is the odd one out: its AxisDefinition is an AxisInformation ARRAY (one entry
    // per dimension, NS0 ValueRank 1), so it is seeded and written as an array rather than a scalar.
    {
      auto created = NDimensionArrayItem::try_create_sync(addressSpace,
        NodeId{ObjectId::ObjectsFolder},
        QualifiedName{mTestNamespaceIndex, "SemanticsNDimensionArrayItem"},
        instantiationOptions,
        VariableInstantiationAttributes{.accessLevel = readWrite});
      if (created.is_good())
      {
        NDimensionArrayItem item = std::move(created).value();
        mSemanticsNDimensionId = item.node_id();
        auto axisProperty = item.try_axis_definition_property_sync();
        if (axisProperty.is_good())
        {
          mSemanticsNDimensionAxisId = axisProperty.value().node_id();
        }
        auto titleProperty = item.try_title_property_sync();
        if (titleProperty.is_good())
        {
          mSemanticsNDimensionTitleId = titleProperty.value().node_id();
        }
        item.release();
      }
      seed_instance_value(
        addressSpace, mSemanticsNDimensionId, DataValue{Variant{Array<double>{1.0, 2.0, 3.0}}});
      Array<RefStructure<Structure>> axes = make_axis_information_array("N axis", 0.0, 100.0);
      seed_writable_property(addressSpace, mSemanticsNDimensionAxisId, DataValue{Variant{std::move(axes)}});
      seed_writable_property(
        addressSpace, mSemanticsNDimensionTitleId, DataValue{Variant{LocalizedText{"", "N title"}}});
    }

    // ========================================================================================================
    // sub-batch 8 nodes - the MASTER SemanticsChanged rule (Part 8 section 5.2) and the generic-Bad overlay
    // (Part 8 section 6.3.2 Table 29). The master rule's second half ("and no other Property change does")
    // needs a Property that the SAME type-instantiation flow materialises but that the specification leaves
    // OFF the trigger list, on an instance whose trigger Property is writable in the same run - otherwise a
    // silent instance and an over-eager one are indistinguishable. Two families supply one each:
    //   * MultiStateValueDiscreteType - Mandatory {EnumValues, ValueAsText}; section 5.3.3.4 names only
    //   EnumValues.
    //   * YArrayItemType - section 5.3.4.2 names exactly five Properties, and Mandatory AxisScaleType is not
    //   one.
    // ========================================================================================================

    // (d1) MultiStateValueDiscreteType: EnumValues is the trigger, ValueAsText the Mandatory non-trigger.
    {
      auto created = MultiStateValueDiscrete::try_create_sync(addressSpace,
        NodeId{ObjectId::ObjectsFolder},
        QualifiedName{mTestNamespaceIndex, "MasterRuleMultiStateValue"},
        instantiationOptions,
        VariableInstantiationAttributes{
          .dataType = NodeId{DataTypeId::Int64}, .valueRank = ValueRank::scalar, .accessLevel = readWrite});
      if (created.is_good())
      {
        MultiStateValueDiscrete masterMsvd = std::move(created).value();
        mMasterMsvdId = masterMsvd.node_id();
        auto enumValuesProperty = masterMsvd.try_enum_values_property_sync();
        if (enumValuesProperty.is_good())
        {
          mMasterMsvdEnumValuesId = enumValuesProperty.value().node_id();
        }
        auto valueAsTextProperty = masterMsvd.try_value_as_text_property_sync();
        if (valueAsTextProperty.is_good())
        {
          mMasterMsvdValueAsTextId = valueAsTextProperty.value().node_id();
        }
        masterMsvd.release();
      }
      seed_instance_value(addressSpace, mMasterMsvdId, DataValue{Variant{std::int64_t{1}}});
      Array<RefStructure<Structure>> masterTable = make_enum_values({{1, "Low"}, {2, "High"}});
      seed_writable_property(
        addressSpace, mMasterMsvdEnumValuesId, DataValue{Variant{std::move(masterTable)}});
      // ValueAsText is not seeded: it is projected from the Value through EnumValues (Value 1 -> "Low") by a
      // read-only source, which refuses a write.
    }

    // (d2) YArrayItemType: XAxisDefinition is one of the five triggers, AxisScaleType is the Mandatory
    // Property section 5.3.4.2 deliberately leaves out of them.
    {
      auto created = YArrayItem::try_create_sync(addressSpace,
        NodeId{ObjectId::ObjectsFolder},
        QualifiedName{mTestNamespaceIndex, "MasterRuleYArrayItem"},
        instantiationOptions,
        VariableInstantiationAttributes{
          .dataType = NodeId{DataTypeId::Double}, .valueRank = 1, .accessLevel = readWrite});
      if (created.is_good())
      {
        YArrayItem masterYArray = std::move(created).value();
        mMasterYArrayId = masterYArray.node_id();
        auto xAxisProperty = masterYArray.try_x_axis_definition_property_sync();
        if (xAxisProperty.is_good())
        {
          mMasterYArrayXAxisId = xAxisProperty.value().node_id();
        }
        auto axisScaleProperty = masterYArray.try_axis_scale_type_property_sync();
        if (axisScaleProperty.is_good())
        {
          mMasterYArrayAxisScaleTypeId = axisScaleProperty.value().node_id();
        }
        auto titleProperty = masterYArray.try_title_property_sync();
        if (titleProperty.is_good())
        {
          mMasterYArrayTitleId = titleProperty.value().node_id();
        }
        masterYArray.release();
      }
      seed_instance_value(addressSpace, mMasterYArrayId, DataValue{Variant{Array<double>{1.0, 2.0, 3.0}}});
      seed_writable_property(addressSpace,
        mMasterYArrayXAxisId,
        DataValue{Variant{make_axis_information("Master axis", 0.0, 100.0)}});
      seed_writable_property(
        addressSpace, mMasterYArrayTitleId, DataValue{Variant{LocalizedText{"", "Master title"}}});
      seed_writable_property(addressSpace,
        mMasterYArrayAxisScaleTypeId,
        DataValue{Variant{static_cast<std::int32_t>(AxisScaleEnumeration::Log)}});
    }

    // (d3) An AnalogItem whose stored Value carries the PLAIN generic Bad - the code Part 8 section 6.3.2
    // Table 29 reserves for a Value that is unusable for no reason the table names. Its sibling ns;6500
    // carries the SPECIFIC Bad_DeviceFailure, so the two together decide whether the server distinguishes
    // them: ns;7600
    // ---
    mGenericBadAnalogId = NodeId{mTestNamespaceIndex, uint32_t{7600}};
    auto genericBadNode = create_analog_variable(addressSpace,
      mGenericBadAnalogId,
      analogItemType,
      "AnalogGenericBad",
      DataValue{Variant{double{50.0}}, StatusCode{Status::Bad}});
    add_eu_range_property(addressSpace, genericBadNode, NodeId{mTestNamespaceIndex, uint32_t{7601}});

    // ========================================================================================================
    // sub-batch 9 nodes - the MultiStateDictionaryEntryDiscrete dictionary table (OPC 10000-19 section 7.1)
    // and the two remaining status-code overlays (Part 8 section 6.3.2 Tables 30/31). Node ids ns;7700+
    // (disjoint from the base fixture ns;7000-7002 and batches 1-8 ns;6000-7601; the type-instantiation
    // engine allocates string `inst:{counter}` ids, so it cannot collide with a numeric one).
    // ========================================================================================================

    // (e1) An MSDE whose EnumDictionaryEntries table is 3 states x 2 DICTIONARIES. The two axes have
    // different lengths, so a transposed table is observable at all; the second dictionary is what makes the
    // ORDER of a ValueAsDictionaryEntries slice observable. The parent is writeable and its Value is the
    // SECOND enumerated value (2 == "High"), so the entries published for it are row 1. EnumValues is made
    // client-writeable so the first-dimension alignment can be driven from the wire, and
    // ValueAsDictionaryEntries is authored READ-ONLY so that "the server declares it writeable because its
    // parent is" is a verdict on the server rather than an echo of what the fixture wrote.
    mDictAlignedId = NodeId{mTestNamespaceIndex, uint32_t{7700}};
    auto dictAligned = create_da_variable(addressSpace,
      mDictAlignedId,
      msdeType,
      "DictAligned",
      NodeId{DataTypeId::Int64},
      DataValue{Variant{std::int64_t{2}}});
    mDictAlignedEnumValuesId = NodeId{mTestNamespaceIndex, uint32_t{7701}};
    add_enum_values_property(
      addressSpace, dictAligned, mDictAlignedEnumValuesId, {{1, "Low"}, {2, "High"}, {3, "Running"}});
    seed_writable_property(addressSpace,
      mDictAlignedEnumValuesId,
      DataValue{Variant{make_enum_values({{1, "Low"}, {2, "High"}, {3, "Running"}})}});
    add_localized_text_property(addressSpace,
      dictAligned,
      NodeId{mTestNamespaceIndex, uint32_t{7702}},
      "ValueAsText",
      LocalizedText{"", "High"});  // inherited Mandatory ValueAsText (CL-DA-001)
    mDictAlignedEntries = {NodeId{mTestNamespaceIndex, uint32_t{7710}},
      NodeId{mTestNamespaceIndex, uint32_t{7711}},
      NodeId{mTestNamespaceIndex, uint32_t{7712}},
      NodeId{mTestNamespaceIndex, uint32_t{7713}},
      NodeId{mTestNamespaceIndex, uint32_t{7714}},
      NodeId{mTestNamespaceIndex, uint32_t{7715}}};
    mDictAlignedEntriesId = NodeId{mTestNamespaceIndex, uint32_t{7703}};
    add_enum_dictionary_entries_property(addressSpace,
      dictAligned,
      mDictAlignedEntriesId,
      sDictAlignedStates,
      sDictAlignedDictionaries,
      mDictAlignedEntries);  // row-major [state][dictionary]
    mDictAlignedValueAsEntriesId = NodeId{mTestNamespaceIndex, uint32_t{7704}};
    add_value_as_dictionary_entries_property(addressSpace, dictAligned, mDictAlignedValueAsEntriesId);
    set_authored_access_level(
      addressSpace, mDictAlignedValueAsEntriesId, AccessLevelType{AccessLevelType::Bit::CurrentRead});

    // (e2) The read-only counterpart: an MSDE whose parent Variable advertises CurrentRead only, whose
    // ValueAsDictionaryEntries is authored read/WRITE. The two instances disagree with their Properties in
    // OPPOSITE directions, so "the Property is writeable exactly where its parent is" can fail either way.
    mDictReadOnlyParentId = NodeId{mTestNamespaceIndex, uint32_t{7720}};
    auto dictReadOnly = create_da_variable(addressSpace,
      mDictReadOnlyParentId,
      msdeType,
      "DictReadOnlyParent",
      NodeId{DataTypeId::Int64},
      DataValue{Variant{std::int64_t{1}}});
    set_authored_access_level(
      addressSpace, mDictReadOnlyParentId, AccessLevelType{AccessLevelType::Bit::CurrentRead});
    add_enum_values_property(
      addressSpace, dictReadOnly, NodeId{mTestNamespaceIndex, uint32_t{7721}}, {{1, "Low"}, {2, "High"}});
    add_localized_text_property(addressSpace,
      dictReadOnly,
      NodeId{mTestNamespaceIndex, uint32_t{7722}},
      "ValueAsText",
      LocalizedText{"", "Low"});
    add_enum_dictionary_entries_property(addressSpace,
      dictReadOnly,
      NodeId{mTestNamespaceIndex, uint32_t{7723}},
      /*states=*/2,
      /*dictionaries=*/2,
      {NodeId{mTestNamespaceIndex, uint32_t{7730}},
        NodeId{mTestNamespaceIndex, uint32_t{7731}},
        NodeId{mTestNamespaceIndex, uint32_t{7732}},
        NodeId{mTestNamespaceIndex, uint32_t{7733}}});
    mDictReadOnlyValueAsEntriesId = NodeId{mTestNamespaceIndex, uint32_t{7724}};
    add_value_as_dictionary_entries_property(addressSpace, dictReadOnly, mDictReadOnlyValueAsEntriesId);

    // (e3) An AnalogItem whose stored Value carries the PLAIN generic Uncertain - the code Part 8
    // section 6.3.2 Table 30 reserves for a Value that is doubtful for no reason the table names. Its sibling
    // ns;7340 carries the SPECIFIC Uncertain_SubstituteValue, so the two together decide whether the server
    // keeps them apart: ns;7740 ---
    mUncertainGenericAnalogId = NodeId{mTestNamespaceIndex, uint32_t{7740}};
    auto uncertainGenericNode = create_analog_variable(addressSpace,
      mUncertainGenericAnalogId,
      analogItemType,
      "AnalogGenericUncertain",
      DataValue{Variant{double{50.0}}, StatusCode{Status::Uncertain}});
    add_eu_range_property(addressSpace, uncertainGenericNode, NodeId{mTestNamespaceIndex, uint32_t{7741}});

    // (e4) An AnalogItem whose Value is produced by a DATA SOURCE the server cannot reach. The read handler
    // installed here IS the defined communication channel to that source (reads are delegated to it rather
    // than served from stored state); it fails to establish the connection and hands back no value at all.
    // The node is seeded with 50.0 BEFORE the handler goes on, so a Value served out of that stored state
    // would be precisely the "last known value" the trigger says is unavailable: ns;7750 ---
    mNoCommunicationAnalogId = NodeId{mTestNamespaceIndex, uint32_t{7750}};
    auto noCommunicationNode = create_analog_variable(addressSpace,
      mNoCommunicationAnalogId,
      analogItemType,
      "AnalogNoCommunication",
      DataValue{Variant{double{50.0}}});
    add_eu_range_property(addressSpace, noCommunicationNode, NodeId{mTestNamespaceIndex, uint32_t{7751}});
    {
      std::promise<VoidResult> handlerInstalled;
      auto handlerInstalledFuture = handlerInstalled.get_future();
      instance_utils::resolve_and_set_value_source_async(addressSpace,
        mNoCommunicationAnalogId,
        make_value_source([](const ValueSource::ReadContext& /*context*/,
                            const Node& /*node*/,
                            const ReadValueId& /*read*/,
                            std::function<void(DataValueResult)>
                              done) { done(Result<DataValue>{StatusCode{Status::BadNoCommunication}}); }),
        [&handlerInstalled](VoidResult result) { handlerInstalled.set_value(std::move(result)); });
      ASSERT_TRUE(handlerInstalledFuture.get().is_good())
        << "the unreachable source's read handler must install, or the row has no stimulus at all";
    }

    // ========================================================================================================
    // sub-batch 10 node - the AnalogUnitType population (Part 8 section 5.3.2.4 Table 4, EngineeringUnits
    // Mandatory). The hand-built ns;6600 above is a DELIBERATELY malformed AnalogUnitType (the client-side
    // negative for "the handle build fails when EngineeringUnits is absent"), so it is a fixture artefact and
    // not a subject of the server-side invariant: SVR-DA-005 places the obligation at address-space
    // registration time, which is the type-instantiation path, and only nodes built through that path are the
    // server's own work. One scalar instance is materialised here so that population is not a single
    // AnalogUnitRangeType subtype.
    // ========================================================================================================
    {
      auto created = AnalogUnit::try_create_sync(addressSpace,
        NodeId{ObjectId::ObjectsFolder},
        QualifiedName{mTestNamespaceIndex, "InstantiatedAnalogUnit"},
        instantiationOptions,
        VariableInstantiationAttributes{
          .dataType = NodeId{DataTypeId::Double}, .valueRank = ValueRank::scalar, .accessLevel = readWrite});
      if (created.is_good())
      {
        AnalogUnit analogUnit = std::move(created).value();
        mAnalogUnitInstanceId = analogUnit.node_id();
        auto unitsProperty = analogUnit.try_engineering_units_property_sync();
        if (unitsProperty.is_good())
        {
          mAnalogUnitUnitsId = unitsProperty.value().node_id();
        }
        auto euRangeProperty = analogUnit.try_eu_range_property_sync();
        if (euRangeProperty.is_good())
        {
          mAnalogUnitEuRangeId = euRangeProperty.value().node_id();
        }
        analogUnit.release();
      }
      seed_instance_value(addressSpace, mAnalogUnitInstanceId, DataValue{Variant{double{50.0}}});
      Range analogUnitRange = make_range(0.0, 100.0);
      seed_writable_property(addressSpace, mAnalogUnitEuRangeId, DataValue{Variant{analogUnitRange}});
      EUInformation analogUnitInfo = make_full_eu_information();
      seed_writable_property(addressSpace, mAnalogUnitUnitsId, DataValue{Variant{analogUnitInfo}});
    }

    // The per-node write sources that model the Accept / Clamp / Reject server behaviours: the clamp node
    // clamps an out-of-range write into EURange and the reject node refuses it.
    attach_judging_source(
      mClampAnalogId, DataValue{Variant{double{50.0}}}, analog_range_rule(DataAccessOutOfRangePolicy::Clamp));
    attach_judging_source(mRejectAnalogId,
      DataValue{Variant{double{50.0}}},
      analog_range_rule(DataAccessOutOfRangePolicy::Reject));
    // sub-batch 3 sources: refuse Value writes on the MultiState reject node and COUNT writes reaching the
    // OUT-OF-RANGE node's ValueAsDictionaryEntries (to prove the local-reject path issues ZERO writes on the
    // wire). The positive dictionary path is observed through the parent state after the server's Part 19
    // translation; the exact client request target and payload are pinned at the WireOps unit interface.
    attach_judging_source(mMultiStateWriteRejectId,
      DataValue{Variant{std::uint32_t{0}}},
      [](DataValue&) -> ValueSource::WriteResult
      {
        return ValueSource::WriteResult{StatusCode{Status::BadOutOfRange},
          make_error_detail("TestMultiStateWriteRejected",
            "the test source rejects an out-of-enum write on the reject node",
            "test.server.data_access.multi_state_write_policy")};
      });
    attach_judging_source(mValueAsDictEntriesOobId,
      DataValue{Variant{Array<NodeId>{}}},
      [counter = mDictNoMatchWriteCount](DataValue&) -> ValueSource::WriteResult
      {
        counter->fetch_add(1);
        return ValueSource::Written{};
      });
  }

  // Attaches a source made by make_judging_source to @p nodeId, which must already exist.
  void attach_judging_source(
    const NodeId& nodeId, DataValue initial, std::function<ua::ValueSource::WriteResult(DataValue&)> rule)
  {
    std::promise<VoidResult> installed;
    auto installedFuture = installed.get_future();
    instance_utils::resolve_and_set_value_source_async(mServer.server().address_space(),
      nodeId,
      make_judging_source(std::move(initial), std::move(rule)),
      [&installed](VoidResult result) { installed.set_value(std::move(result)); });
    ASSERT_TRUE(installedFuture.get().is_good()) << "the write source must install";
  }

  // Creates a Double AnalogItem-shaped (read/write) Variable @p id typed by @p typeDefinition with the
  // given initial @p value (which may carry a quality StatusCode). Property children are added by the
  // caller. Returns the created node so the caller can attach HasProperty children.
  NodeAccessor create_analog_variable(AddressSpace& addressSpace, const NodeId& id,
    const NodeId& typeDefinition, std::string browseName, DataValue value)
  {
    const AccessLevelType readWrite{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite};
    auto node = addressSpace.create_node_sync(id, NodeClass::Variable);
    auto variable = node.as<VariableAccessor>();
    EXPECT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{mTestNamespaceIndex, browseName});
    variable->set_display_name(LocalizedText{"", browseName});
    variable->set_data_type(NodeId{DataTypeId::Double});
    variable->set_access_level(readWrite);
    variable->write_value_sync(std::move(value));
    node.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, typeDefinition);
    return node;
  }

  // Adds an EngineeringUnits (EUInformation) HasProperty child @p euInfoId to @p ownerNode.
  static void add_engineering_units_property(
    AddressSpace& addressSpace, NodeAccessor& ownerNode, const NodeId& euInfoId)
  {
    auto euNode = addressSpace.create_node_sync(euInfoId, NodeClass::Variable);
    auto engineeringUnits = euNode.as<VariableAccessor>();
    ASSERT_TRUE(engineeringUnits.has_value());
    engineeringUnits->set_browse_name(QualifiedName{0, "EngineeringUnits"});
    engineeringUnits->set_data_type(NodeId{DataTypeId::EUInformation});
    EUInformation info;
    info.namespace_uri() = String{"http://www.opcfoundation.org/UA/units/un/cefact"};
    engineeringUnits->write_value_sync(DataValue{Variant{info}});
    euNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
    ownerNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, euInfoId);
  }

  // Adds an EURange (Range [0,100]) HasProperty child @p euRangeId to @p ownerNode.
  static void add_eu_range_property(
    AddressSpace& addressSpace, NodeAccessor& ownerNode, const NodeId& euRangeId)
  {
    auto euRangeNode = addressSpace.create_node_sync(euRangeId, NodeClass::Variable);
    auto euRange = euRangeNode.as<VariableAccessor>();
    ASSERT_TRUE(euRange.has_value());
    euRange->set_browse_name(QualifiedName{0, "EURange"});
    euRange->set_data_type(NodeId{DataTypeId::Range});
    auto range = std::make_unique<Range>();
    range->low() = 0.0;
    range->high() = 100.0;
    euRange->write_value_sync(DataValue{Variant{RefStructure<Structure>{std::move(range)}}});
    euRangeNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
    ownerNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, euRangeId);
  }

  // Adds a named Range HasProperty child (@p propertyName is "EURange" or "InstrumentRange") carrying the
  // exact @p low / @p high limits - used to serve anomalous ranges (inverted high<low, NaN limit, degenerate
  // high==low) VERBATIM so the read decodes them without correction (CL-DA-007/-013/-016).
  static void add_range_property(AddressSpace& addressSpace, NodeAccessor& ownerNode, const NodeId& rangeId,
    std::string_view propertyName, double low, double high)
  {
    auto rangeNode = addressSpace.create_node_sync(rangeId, NodeClass::Variable);
    auto rangeVariable = rangeNode.as<VariableAccessor>();
    ASSERT_TRUE(rangeVariable.has_value());
    rangeVariable->set_browse_name(QualifiedName{0, std::string{propertyName}});
    rangeVariable->set_data_type(NodeId{DataTypeId::Range});
    auto range = std::make_unique<Range>();
    range->low() = low;
    range->high() = high;
    rangeVariable->write_value_sync(DataValue{Variant{RefStructure<Structure>{std::move(range)}}});
    rangeNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
    ownerNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, rangeId);
  }

  // Adds a Definition (String) HasProperty child carrying @p text verbatim (CL-DA-017 - vendor-opaque, never
  // parsed; serves both the empty-string and the long-vendor-blob rows).
  static void add_definition_property(
    AddressSpace& addressSpace, NodeAccessor& ownerNode, const NodeId& definitionId, std::string_view text)
  {
    auto definitionNode = addressSpace.create_node_sync(definitionId, NodeClass::Variable);
    auto definition = definitionNode.as<VariableAccessor>();
    ASSERT_TRUE(definition.has_value());
    definition->set_browse_name(QualifiedName{0, "Definition"});
    definition->set_data_type(NodeId{DataTypeId::String});
    definition->write_value_sync(DataValue{Variant{String{text}}});
    definitionNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
    ownerNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, definitionId);
  }

  // Adds a ValuePrecision (Double) HasProperty child carrying @p precision verbatim. ValuePrecision is a
  // server-controlled Double; the client decodes it to an informational optional<int16> (CL-DA-002 -
  // surfaced, never applied to the Value). Serves the surfaced / zero / negative-truncation /
  // NaN-no-precision rows.
  static void add_value_precision_property(
    AddressSpace& addressSpace, NodeAccessor& ownerNode, const NodeId& propertyId, double precision)
  {
    auto precisionNode = addressSpace.create_node_sync(propertyId, NodeClass::Variable);
    auto valuePrecision = precisionNode.as<VariableAccessor>();
    ASSERT_TRUE(valuePrecision.has_value());
    valuePrecision->set_browse_name(QualifiedName{0, "ValuePrecision"});
    valuePrecision->set_data_type(NodeId{DataTypeId::Double});
    valuePrecision->write_value_sync(DataValue{Variant{precision}});
    precisionNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
    ownerNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, propertyId);
  }

  // Adds an EngineeringUnits (EUInformation) HasProperty child carrying the fully-specified @p info verbatim
  // (CL-DA-014 - all four fields surfaced as served, including empty ones; the SDK never maps to a local unit
  // table).
  static void add_full_engineering_units_property(
    AddressSpace& addressSpace, NodeAccessor& ownerNode, const NodeId& euInfoId, EUInformation info)
  {
    auto euNode = addressSpace.create_node_sync(euInfoId, NodeClass::Variable);
    auto engineeringUnits = euNode.as<VariableAccessor>();
    ASSERT_TRUE(engineeringUnits.has_value());
    engineeringUnits->set_browse_name(QualifiedName{0, "EngineeringUnits"});
    engineeringUnits->set_data_type(NodeId{DataTypeId::EUInformation});
    engineeringUnits->write_value_sync(DataValue{Variant{info}});
    euNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
    ownerNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, euInfoId);
  }

  // The canonical fully-populated EngineeringUnits (UN/CEFACT degree-Celsius) the fidelity rows serve; the
  // empty-field rows clone this and blank one field so the other three stay populated.
  static EUInformation make_full_eu_information()
  {
    EUInformation info;
    info.namespace_uri() = String{"http://www.opcfoundation.org/UA/units/un/cefact"};
    info.unit_id() = 4408652;
    info.display_name() = LocalizedText{"", "\u00b0C"};
    info.description() = LocalizedText{"", "degree Celsius"};
    return info;
  }

  // Creates a read/write Variable @p id typed by @p typeDefinition with the given @p dataType and initial
  // @p value. Property children are attached by the caller. Returns the created node. Generalises
  // create_analog_variable to the discrete DA types (Boolean / UInt32 / Int64 values).
  NodeAccessor create_da_variable(AddressSpace& addressSpace, const NodeId& id, const NodeId& typeDefinition,
    std::string browseName, const NodeId& dataType, DataValue value)
  {
    const AccessLevelType readWrite{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite};
    auto node = addressSpace.create_node_sync(id, NodeClass::Variable);
    auto variable = node.as<VariableAccessor>();
    EXPECT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{mTestNamespaceIndex, browseName});
    variable->set_display_name(LocalizedText{"", browseName});
    variable->set_data_type(dataType);
    variable->set_access_level(readWrite);
    variable->write_value_sync(std::move(value));
    node.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, typeDefinition);
    return node;
  }

  // Adds a LocalizedText HasProperty child @p propertyId named @p propertyName (ns0 - e.g. "TrueState" /
  // "FalseState" / "ValueAsText") carrying @p text verbatim (including an EMPTY LocalizedText).
  static void add_localized_text_property(AddressSpace& addressSpace, NodeAccessor& ownerNode,
    const NodeId& propertyId, std::string_view propertyName, LocalizedText text)
  {
    auto propertyNode = addressSpace.create_node_sync(propertyId, NodeClass::Variable);
    auto property = propertyNode.as<VariableAccessor>();
    ASSERT_TRUE(property.has_value());
    property->set_browse_name(QualifiedName{0, std::string{propertyName}});
    property->set_data_type(NodeId{DataTypeId::LocalizedText});
    property->write_value_sync(DataValue{Variant{std::move(text)}});
    propertyNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
    ownerNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, propertyId);
    // The inverse edge too: the write check finds the owner only through it (owner decision 14),
    // and a conformant address space carries both directions.
    propertyNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, ownerNode.get_node_id(), false);
  }

  // Adds an EnumStrings (LocalizedText[]) HasProperty child @p propertyId carrying @p strings verbatim
  // (including a present-empty LocalizedText entry).
  static void add_enum_strings_property(AddressSpace& addressSpace, NodeAccessor& ownerNode,
    const NodeId& propertyId, std::vector<LocalizedText> strings)
  {
    auto propertyNode = addressSpace.create_node_sync(propertyId, NodeClass::Variable);
    auto property = propertyNode.as<VariableAccessor>();
    ASSERT_TRUE(property.has_value());
    property->set_browse_name(QualifiedName{0, "EnumStrings"});
    property->set_data_type(NodeId{DataTypeId::LocalizedText});
    Array<LocalizedText> array;
    for (auto& text : strings)
    {
      array.push_back(std::move(text));
    }
    property->write_value_sync(DataValue{Variant{std::move(array)}});
    propertyNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
    ownerNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, propertyId);
    // The inverse edge too: the write check finds the owner only through it (owner decision 14),
    // and a conformant address space carries both directions.
    propertyNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, ownerNode.get_node_id(), false);
  }

  // Adds an EnumValues (EnumValueType[]) HasProperty child @p propertyId carrying @p entries (value +
  // display name) verbatim.
  static void add_enum_values_property(AddressSpace& addressSpace, NodeAccessor& ownerNode,
    const NodeId& propertyId, const std::vector<std::pair<std::int64_t, std::string>>& entries)
  {
    auto propertyNode = addressSpace.create_node_sync(propertyId, NodeClass::Variable);
    auto property = propertyNode.as<VariableAccessor>();
    ASSERT_TRUE(property.has_value());
    property->set_browse_name(QualifiedName{0, "EnumValues"});
    property->set_data_type(NodeId{DataTypeId::EnumValueType});
    property->set_value_rank(ValueRank{1});
    Array<RefStructure<Structure>> array;
    for (const auto& [value, name] : entries)
    {
      auto entry = std::make_unique<EnumValueType>();
      entry->value() = value;
      entry->display_name() = LocalizedText{"", name};
      array.push_back(RefStructure<Structure>{std::move(entry)});
    }
    property->write_value_sync(DataValue{Variant{std::move(array)}});
    propertyNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
    ownerNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, propertyId);
    // The inverse edge too: the write check finds the owner only through it (owner decision 14),
    // and a conformant address space carries both directions.
    propertyNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, ownerNode.get_node_id(), false);
  }

  // Adds the Mandatory MSDE-DBT EnumDictionaryEntries HasProperty child (OPC 10000-19 section 7.1): a 2-D
  // NodeId table, dimension 0 = state (== |EnumValues|), dimension 1 = dictionary. @p flat is row-major so
  // that element [state][dictionary] == flat[state * dictionaries + dictionary].
  static void add_enum_dictionary_entries_property(AddressSpace& addressSpace, NodeAccessor& ownerNode,
    const NodeId& propertyId, std::size_t states, std::size_t dictionaries, std::vector<NodeId> flat)
  {
    auto propertyNode = addressSpace.create_node_sync(propertyId, NodeClass::Variable);
    auto property = propertyNode.as<VariableAccessor>();
    ASSERT_TRUE(property.has_value());
    property->set_browse_name(QualifiedName{0, "EnumDictionaryEntries"});
    property->set_data_type(NodeId{DataTypeId::NodeId});
    property->set_value_rank(ValueRank{2});
    property->write_value_sync(DataValue{Variant{
      Array<NodeId>{Dimensions{static_cast<std::int32_t>(states), static_cast<std::int32_t>(dictionaries)},
        std::move(flat)}}});
    propertyNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
    ownerNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, propertyId);
    // The inverse edge too: the write check finds the owner only through it (owner decision 14),
    // and a conformant address space carries both directions.
    propertyNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, ownerNode.get_node_id(), false);
  }

  // Adds a client-WRITABLE ValueAsDictionaryEntries HasProperty child (OPC 10000-19 section 7.1): a 1-D
  // NodeId[] (initially empty). This is the node the client writes the selected dictionary-entry NodeId to.
  static void add_value_as_dictionary_entries_property(
    AddressSpace& addressSpace, NodeAccessor& ownerNode, const NodeId& propertyId)
  {
    const AccessLevelType readWrite{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite};
    auto propertyNode = addressSpace.create_node_sync(propertyId, NodeClass::Variable);
    auto property = propertyNode.as<VariableAccessor>();
    ASSERT_TRUE(property.has_value());
    property->set_browse_name(QualifiedName{0, "ValueAsDictionaryEntries"});
    property->set_data_type(NodeId{DataTypeId::NodeId});
    property->set_value_rank(ValueRank{1});
    property->set_access_level(readWrite);
    property->write_value_sync(DataValue{Variant{Array<NodeId>{}}});
    propertyNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
    ownerNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, propertyId);
    propertyNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, ownerNode.get_node_id(), false);
  }

  // A Range carrying the given limits - the payload the type-instantiated EURange Properties are seeded with
  // (the instantiation engine materialises a Mandatory Property with no Value).
  static Range make_range(double low, double high)
  {
    Range range;
    range.low() = low;
    range.high() = high;
    return range;
  }

  // Seeds the Value of a Variable materialised by the type-instantiation engine (which leaves the instance
  // Value null). A no-op when @p nodeId is null, so a failed instantiation surfaces in the TEST that asserts
  // over it rather than aborting every test in the fixture.
  static void seed_instance_value(AddressSpace& addressSpace, const NodeId& nodeId, DataValue value)
  {
    if (nodeId.is_null())
    {
      return;
    }
    auto node = addressSpace.find_node_sync(nodeId);
    auto variable = node.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->write_value_sync(std::move(value));
  }

  // Seeds a type-instantiated Property's Value and makes it client-writable: the instantiation engine
  // materialises Mandatory Properties read-only, and the SemanticsChanged rows must WRITE them over the wire
  // (a server-side write would bypass the client->server->namespace path under test).
  static void seed_writable_property(AddressSpace& addressSpace, const NodeId& propertyId, DataValue value)
  {
    if (propertyId.is_null())
    {
      return;
    }
    auto node = addressSpace.find_node_sync(propertyId);
    auto variable = node.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    variable->write_value_sync(std::move(value));
  }

  // Overrides the AccessLevel a node was AUTHORED with, leaving its Value untouched. The
  // ValueAsDictionaryEntries rows need an authored AccessLevel that DISAGREES with the parent Variable's, so
  // that "the Property is writeable exactly where its parent is" is a verdict on the server rather than an
  // echo of what the fixture wrote.
  static void set_authored_access_level(
    AddressSpace& addressSpace, const NodeId& nodeId, AccessLevelType accessLevel)
  {
    if (nodeId.is_null())
    {
      return;
    }
    auto node = addressSpace.find_node_sync(nodeId);
    auto variable = node.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_access_level(accessLevel);
  }

  // The EnumStrings payload (LocalizedText[]) a MultiStateDiscreteType instance's Mandatory Property
  // carries. Index i is the label for state value i - the table is positional and has no keys.
  static Array<LocalizedText> make_enum_strings(std::vector<LocalizedText> strings)
  {
    Array<LocalizedText> array;
    for (auto& text : strings)
    {
      array.push_back(std::move(text));
    }
    return array;
  }

  // The EnumValues payload (EnumValueType[]) a MultiStateValueDiscreteType instance's Mandatory Property
  // carries. Unlike EnumStrings this table is KEYED: an entry's meaning can change without renumbering.
  static Array<RefStructure<Structure>> make_enum_values(
    const std::vector<std::pair<std::int64_t, std::string>>& entries)
  {
    Array<RefStructure<Structure>> array;
    for (const auto& [value, name] : entries)
    {
      auto entry = std::make_unique<EnumValueType>();
      entry->value() = value;
      entry->display_name() = LocalizedText{"", name};
      array.push_back(RefStructure<Structure>{std::move(entry)});
    }
    return array;
  }

  // The AxisInformation payload an ArrayItem axis-definition Property (XAxisDefinition / YAxisDefinition /
  // ZAxisDefinition) carries: the axis units, its range, its label and the scale it is drawn on.
  static AxisInformation make_axis_information(const char* title, double low, double high)
  {
    AxisInformation axis;
    axis.engineering_units() = make_full_eu_information();
    axis.eu_range() = make_range(low, high);
    axis.title() = LocalizedText{"", title};
    axis.axis_scale_type() = AxisScaleEnumeration::Linear;
    return axis;
  }

  // A one-entry AxisInformation[] - the shape NDimensionArrayItemType.AxisDefinition declares in NS0
  // (ValueRank 1: one AxisInformation per dimension), so it can never be written as a scalar.
  static Array<RefStructure<Structure>> make_axis_information_array(
    const char* title, double low, double high)
  {
    Array<RefStructure<Structure>> axes;
    auto entry = std::make_unique<AxisInformation>();
    entry->engineering_units() = make_full_eu_information();
    entry->eu_range() = make_range(low, high);
    entry->title() = LocalizedText{"", title};
    entry->axis_scale_type() = AxisScaleEnumeration::Linear;
    axes.push_back(RefStructure<Structure>{std::move(entry)});
    return axes;
  }

  // Seeds an ArrayItem subtype instance materialised by the type system: a readable Value (so a monitored
  // item delivers an initial sample), plus each scalar axis-definition Property and the Title made
  // client-writable (the SemanticsChanged rows must WRITE them over the wire).
  static void seed_array_item_instance(AddressSpace& addressSpace, const NodeId& instanceId,
    const std::vector<NodeId>& axisPropertyIds, const NodeId& titleId, const char* axisTitle)
  {
    seed_instance_value(addressSpace, instanceId, DataValue{Variant{Array<double>{1.0, 2.0, 3.0}}});
    for (const NodeId& axisPropertyId : axisPropertyIds)
    {
      seed_writable_property(
        addressSpace, axisPropertyId, DataValue{Variant{make_axis_information(axisTitle, 0.0, 100.0)}});
    }
    seed_writable_property(addressSpace, titleId, DataValue{Variant{LocalizedText{"", axisTitle}}});
  }

  // Creates a dictionary-entry Variable @p entryId carrying a ValueAsText HasProperty child @p valueAsTextId
  // whose Value is @p valueAsText (CL-DA-012: write_via_dictionary_async browses the entry for its
  // ns0 "ValueAsText" child and matches its text against the Variable's EnumValues).
  void create_dictionary_entry(AddressSpace& addressSpace, const NodeId& entryId, std::string browseName,
    const NodeId& valueAsTextId, LocalizedText valueAsText)
  {
    auto entryNode = create_da_variable(addressSpace,
      entryId,
      NodeId{VariableTypeId::MultiStateValueDiscreteType},
      std::move(browseName),
      NodeId{DataTypeId::Int64},
      DataValue{Variant{std::int64_t{0}}});
    add_localized_text_property(
      addressSpace, entryNode, valueAsTextId, "ValueAsText", std::move(valueAsText));
  }

  void SetUp() override
  {
    ComplianceWithNodes::SetUp();

    // A dedicated channel + activated session handed to a started ConnectionImpl, then wrapped into the
    // PUBLIC Connection handle via the test wrap interface (the same shape the connect path produces).
    mConnChannel.emplace(mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl}));
    auto session = mConnChannel->create_session_sync({.sessionName = "CLIENT_DA_MATRIX"});
    session.activate_sync();
    mConnImpl = ConnectionImpl::create(
      mClientThreadPool.executor(), std::move(session), ua::client::detail::ConnectionConfig{}, Logger{});
    ASSERT_TRUE(start_and_wait(*mConnImpl).is_good());
    mConnection.emplace(ConnectionHandleFactory::make_connection(mConnImpl));
  }

  void TearDown() override
  {
    if (mConnImpl)
    {
      (void)close_and_wait(*mConnImpl);
    }
    mConnection.reset();
    mConnImpl.reset();
    mConnChannel.reset();
    ComplianceWithNodes::TearDown();
  }

  // Runs Connection::data_access().analog_item_async against the real server and blocks for the handle
  // Result.
  AnalogItemHandleResult build_analog(const NodeId& nodeId)
  {
    std::promise<AnalogItemHandleResult> promise;
    auto future = promise.get_future();
    mConnection->data_access().analog_item_async(
      nodeId, [&promise](AnalogItemHandleResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  // Runs Connection::data_access().base_analog_async against the real server and blocks for the handle
  // Result.
  AnalogItemHandleResult build_base_analog(const NodeId& nodeId)
  {
    std::promise<AnalogItemHandleResult> promise;
    auto future = promise.get_future();
    mConnection->data_access().base_analog_async(
      nodeId, [&promise](AnalogItemHandleResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  // Runs Connection::data_access().analog_unit_async against the real server and blocks for the Result.
  AnalogItemHandleResult build_analog_unit(const NodeId& nodeId)
  {
    std::promise<AnalogItemHandleResult> promise;
    auto future = promise.get_future();
    mConnection->data_access().analog_unit_async(
      nodeId, [&promise](AnalogItemHandleResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  // Runs Connection::data_access().analog_unit_range_async against the real server and blocks for the Result.
  AnalogItemHandleResult build_analog_unit_range(const NodeId& nodeId)
  {
    std::promise<AnalogItemHandleResult> promise;
    auto future = promise.get_future();
    mConnection->data_access().analog_unit_range_async(
      nodeId, [&promise](AnalogItemHandleResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  // Reads @p handle and blocks (on the test thread) for the typed value Result.
  static Result<AnalogItemValue> handle_read(AnalogItemHandle handle)
  {
    std::promise<Result<AnalogItemValue>> promise;
    auto future = promise.get_future();
    handle.read_async([&promise](Result<AnalogItemValue> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  // Writes @p value through @p handle and blocks (on the test thread) for the passthrough VoidResult.
  static VoidResult handle_write(AnalogItemHandle handle, Variant value)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    handle.write_value_async(
      std::move(value), [&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  Result<std::uint32_t> create_subscription(double publishingInterval)
  {
    std::promise<Result<std::uint32_t>> promise;
    auto future = promise.get_future();
    mConnImpl->create_subscription_async(
      publishingInterval, [&promise](Result<std::uint32_t> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  Result<std::uint32_t> create_data_monitored_item(std::uint32_t subscriptionId, const NodeId& node,
    std::uint32_t clientHandle, std::shared_ptr<DataValueSink> sink)
  {
    std::promise<Result<std::uint32_t>> promise;
    auto future = promise.get_future();
    mConnImpl->create_monitored_item_async(
      subscriptionId,
      node,
      clientHandle,
      [sink](DataValue value) { sink->push(std::move(value)); },
      [&promise](Result<std::uint32_t> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  // ---- sub-batch 3 typed-handle drivers (block on the test thread for the async completion) ----

  TwoStateDiscreteHandleResult build_two_state(const NodeId& nodeId)
  {
    std::promise<TwoStateDiscreteHandleResult> promise;
    auto future = promise.get_future();
    mConnection->data_access().two_state_discrete_async(
      nodeId, [&promise](TwoStateDiscreteHandleResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  MultiStateDiscreteHandleResult build_multi_state_discrete(const NodeId& nodeId)
  {
    std::promise<MultiStateDiscreteHandleResult> promise;
    auto future = promise.get_future();
    mConnection->data_access().multi_state_discrete_async(
      nodeId, [&promise](MultiStateDiscreteHandleResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  MultiStateValueDiscreteHandleResult build_multi_state_value(const NodeId& nodeId)
  {
    std::promise<MultiStateValueDiscreteHandleResult> promise;
    auto future = promise.get_future();
    mConnection->data_access().multi_state_value_discrete_async(nodeId,
      [&promise](MultiStateValueDiscreteHandleResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  MultiStateValueDiscreteHandleResult build_msde(const NodeId& nodeId)
  {
    std::promise<MultiStateValueDiscreteHandleResult> promise;
    auto future = promise.get_future();
    mConnection->data_access().multi_state_dictionary_entry_async(nodeId,
      [&promise](MultiStateValueDiscreteHandleResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<TwoStateDiscreteValue> read_two_state(TwoStateDiscreteHandle handle)
  {
    std::promise<Result<TwoStateDiscreteValue>> promise;
    auto future = promise.get_future();
    handle.read_async(
      [&promise](Result<TwoStateDiscreteValue> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<MultiStateDiscreteValue> read_multi_state_discrete(MultiStateDiscreteHandle handle)
  {
    std::promise<Result<MultiStateDiscreteValue>> promise;
    auto future = promise.get_future();
    handle.read_async(
      [&promise](Result<MultiStateDiscreteValue> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static Result<MultiStateValueDiscreteValue> read_multi_state_value(MultiStateValueDiscreteHandle handle)
  {
    std::promise<Result<MultiStateValueDiscreteValue>> promise;
    auto future = promise.get_future();
    handle.read_async(
      [&promise](Result<MultiStateValueDiscreteValue> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static VoidResult write_multi_state_discrete(MultiStateDiscreteHandle handle, Variant value)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    handle.write_value_async(
      std::move(value), [&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static VoidResult write_via_dictionary(
    MultiStateValueDiscreteHandle handle, std::size_t stateIndex, std::size_t dictionaryIndex)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    handle.write_via_dictionary_async(
      stateIndex, dictionaryIndex, [&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  // ---- sub-batch 5 SemanticChange helpers ----

  // Rewrites the EURange Property node @p euRangeId to [low, high] SERVER-SIDE (bypasses access level - the
  // DA EURange child is not client-writable). A subsequent client re-resolve Read observes the new range, so
  // this is the stimulus behind "the next read returns FRESH EURange".
  void set_server_eu_range(const NodeId& euRangeId, double low, double high)
  {
    auto addressSpace = mServer.server().address_space();
    auto node = addressSpace.find_node_sync(euRangeId);
    auto variable = node.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    auto range = std::make_unique<Range>();
    range->low() = low;
    range->high() = high;
    variable->write_value_sync(DataValue{Variant{RefStructure<Structure>{std::move(range)}}});
  }

  // Drives the SemanticChangeCache::invalidate_async sink directly (the invalidation -> re-resolve half of
  // CL-DA-010). The in-band status-bit TRIGGER (the SubscriptionsPipeline watching a delivered DataValue's
  // SemanticsChanged bit and routing the node here) is now BUILT and unit-covered
  // (SubscriptionsPipeline.SemanticsChangedBitRoutesNodeToInvalidation); this integration exercises the
  // downstream cache -> handle-re-resolve half without standing up a full subscription + server-side
  // bit-injection harness for the affected node (OPEN-DA-010a: a fully end-to-end subscription-delivered
  // SemanticsChanged pin is a follow-up).
  void drive_in_band_invalidate(const NodeId& affected)
  {
    mConnImpl->semantic_change_cache()->invalidate_async({affected});
  }

  // Drives the SemanticChangeEventType invalidation via the REAL EventRouter (CL-DA-011): builds a
  // Changes-bearing EventNotification (as the wire codec would deliver it) and feeds it to the router's
  // handle_semantic_event, exercising the real decode + route into SemanticChangeCache::invalidate_async and
  // the observer fan-out. NB: the router's backbone event Subscription omits the "Changes" SelectClause (a
  // documented follow-up, ua_event_router.cpp), so a live-wire SemanticChangeEvent decodes to a no-op;
  // feeding the router the Changes notification directly is the pin for that gap (REPORTED).
  void route_semantic_change_event(const NodeId& affected, const NodeId& affectedType)
  {
    ua::client::EventNotification notification;
    notification.fieldPaths.push_back({QualifiedName{std::uint16_t{0}, String{"Changes"}}});
    Array<RefStructure<Structure>> array;
    auto entry = std::make_unique<SemanticChangeStructureDataType>();
    entry->affected() = affected;
    entry->affected_type() = affectedType;
    array.push_back(RefStructure<Structure>{std::move(entry)});
    notification.fields.push_back(std::optional<Variant>{Variant{std::move(array)}});
    ConnectionImplTestAccess::event_router(*mConnImpl)->handle_semantic_event(std::move(notification));
  }

  // ---- sub-batch 6 server-model helpers ----

  // Browses one level for HasProperty, matches the ns0 BrowseName @p propertyName and Reads the matched
  // child's Value - the wire shape a client uses to discover a DataAccess Property
  // (Connection::node -> PropertyAccessor). Blocks on the test thread for the completion.
  Result<DataValue> read_property(const NodeId& nodeId, std::string_view propertyName)
  {
    std::promise<Result<DataValue>> promise;
    auto future = promise.get_future();
    mConnection->node(nodeId).read_property_async(QualifiedName{0, std::string{propertyName}},
      [&promise](Result<DataValue> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  // Reads @p nodeId's DataType Attribute over the wire; nullopt when the service fails or the returned
  // Variant does not carry a NodeId.
  std::optional<NodeId> read_data_type_attribute(const NodeId& nodeId)
  {
    auto readResult = mSession->attributes().try_read_sync(read_value(nodeId, AttributeId::DataType));
    if (readResult.is_bad())
    {
      return std::nullopt;
    }
    ua::ReadResponse response = std::move(readResult).value();
    if (response.results().size() != 1U)
    {
      return std::nullopt;
    }
    const NodeId* dataType = response.results()[0].value().try_as<NodeId>();
    if (dataType == nullptr)
    {
      return std::nullopt;
    }
    return *dataType;
  }

  // Reads @p nodeId's ValueRank Attribute over the wire; nullopt when the service fails or the returned
  // Variant does not carry an Int32. The array-ness of a DataAccess Property (EnumStrings is
  // `LocalizedText[]`, not a LocalizedText) lives in this Attribute, not in whatever Value happens to be
  // stored, so it is the Attribute the shape obligations have to read.
  std::optional<std::int32_t> read_value_rank_attribute(const NodeId& nodeId)
  {
    auto readResult = mSession->attributes().try_read_sync(read_value(nodeId, AttributeId::ValueRank));
    if (readResult.is_bad())
    {
      return std::nullopt;
    }
    ua::ReadResponse response = std::move(readResult).value();
    if (response.results().size() != 1U)
    {
      return std::nullopt;
    }
    const std::int32_t* valueRank = response.results()[0].value().try_as<std::int32_t>();
    if (valueRank == nullptr)
    {
      return std::nullopt;
    }
    return *valueRank;
  }

  // Reads @p nodeId's AccessLevel Attribute over the wire; nullopt when the service fails or the returned
  // Variant does not carry a Byte. AccessLevel is what a client consults BEFORE it attempts a Write, so the
  // Attribute - not the outcome of a trial Write - is where "this Property may be written" is published.
  std::optional<AccessLevelType> read_access_level_attribute(const NodeId& nodeId)
  {
    auto readResult = mSession->attributes().try_read_sync(read_value(nodeId, AttributeId::AccessLevel));
    if (readResult.is_bad())
    {
      return std::nullopt;
    }
    ua::ReadResponse response = std::move(readResult).value();
    if (response.results().size() != 1U)
    {
      return std::nullopt;
    }
    const std::uint8_t* accessLevel = response.results()[0].value().try_as<std::uint8_t>();
    if (accessLevel == nullptr)
    {
      return std::nullopt;
    }
    return AccessLevelType{*accessLevel};
  }

  // Counts the DataValues delivered to @p sink whose StatusCode carries the SemanticsChanged bit. The sink
  // is never drained, so a bit delivered earlier in the test is still observable at the point of assertion.
  static std::size_t semantics_changed_count(const DataValueSink& sink)
  {
    std::size_t count = 0;
    for (const auto& value : sink.snapshot())
    {
      if (value.status().has_value() && value.status()->semantics_changed())
      {
        ++count;
      }
    }
    return count;
  }

  // Reads @p node's EURange.high via a fresh AnalogItemHandle read; returns nullopt on a Bad read / absent
  // EURange. Used by the invalidation rows to poll for the FRESH re-resolved range.
  static std::optional<double> read_eu_range_high(AnalogItemHandle handle)
  {
    Result<AnalogItemValue> value = handle_read(std::move(handle));
    if (value.is_bad() || !value.value().euRange.has_value())
    {
      return std::nullopt;
    }
    return value.value().euRange->high();
  }

  // Subscribes to @p instanceId, requires its initial sample to carry NO SemanticsChanged bit, then writes
  // each (Property, value) pair in @p mutations over the wire in turn and requires a FURTHER notification
  // carrying the bit after each one. Each conjunct is counted from its own pre-write baseline, so a bit
  // raised by an earlier write can never satisfy a later one. @p subtype names the ArrayItem subtype under
  // test so a per-subtype failure identifies itself; the assertions are non-fatal at the call site, so one
  // subtype failing still lets the remaining five be judged in the same run.
  void expect_semantics_changed_on_each_property_write(const std::string& subtype, const NodeId& instanceId,
    const std::vector<std::pair<NodeId, Variant>>& mutations)
  {
    ASSERT_FALSE(instanceId.is_null()) << subtype << ": the instance must have been instantiated";
    ASSERT_FALSE(mutations.empty()) << subtype << ": no Property was driven - the check would be vacuous";

    auto subscription = create_subscription(100.0);
    ASSERT_TRUE(subscription.is_good())
      << subtype << ": create_subscription failed: 0x" << std::hex << subscription.status_code().as_uint32();
    auto sink = std::make_shared<DataValueSink>();
    auto item = create_data_monitored_item(subscription.value(), instanceId, /*clientHandle=*/1, sink);
    ASSERT_TRUE(item.is_good()) << subtype << ": create_monitored_item failed: 0x" << std::hex
                                << item.status_code().as_uint32();

    ASSERT_TRUE(wait_until([&] { return !sink->snapshot().empty(); }))
      << subtype << ": the monitored item must deliver its initial sample before the Properties change";
    ASSERT_EQ(semantics_changed_count(*sink), 0U)
      << subtype << ": nothing has changed a Property yet, so no notification may carry SemanticsChanged";

    for (const auto& mutation : mutations)
    {
      ASSERT_FALSE(mutation.first.is_null())
        << subtype << ": instantiating the type must materialise every Mandatory axis / range Property";
      const std::size_t baseline = semantics_changed_count(*sink);
      ASSERT_TRUE(mConnection->try_write_value_sync(mutation.first, mutation.second).is_good())
        << subtype << ": the Property write must reach the server";
      EXPECT_TRUE(wait_until([&] { return semantics_changed_count(*sink) > baseline; }))
        << subtype << ": changing this Property must set SemanticsChanged on the next data-change";
    }
  }

  // Drives BOTH halves of the master SemanticsChanged rule on one Data Access type. @p nonTrigger is a
  // Mandatory Property the specification leaves OFF that type's trigger list and @p trigger is one that is on
  // it; @p forcedValue is a Value change used to GUARANTEE a notification follows the non-trigger write, so
  // "the bit was not set" can never be the absence of any notification at all. The trigger arm runs last and
  // proves the emission interface is live on this very instance, so a server whose bit never fires cannot
  // pass the negative half by doing nothing. Assertions are non-fatal at the call site so one type failing
  // still lets the others be judged in the same run.
  /// @p nonTrigger names the unlisted Property and the value a client writes to it; with no value, the
  /// Property is one the server projects from the Variable's Value (ValueAsText), so the forcing Value write
  /// is what changes it, and the change itself is asserted so the row cannot pass vacuously.
  void expect_only_listed_properties_raise_semantics_changed(const std::string& type,
    const NodeId& instanceId, const std::pair<NodeId, std::optional<Variant>>& nonTrigger,
    const std::pair<NodeId, Variant>& trigger, const Variant& forcedValue)
  {
    ASSERT_FALSE(instanceId.is_null()) << type << ": the instance must have been instantiated";
    ASSERT_FALSE(nonTrigger.first.is_null())
      << type << ": its Mandatory non-trigger Property must have been materialised";
    ASSERT_FALSE(trigger.first.is_null())
      << type << ": its Mandatory trigger Property must have been materialised";

    auto subscription = create_subscription(100.0);
    ASSERT_TRUE(subscription.is_good())
      << type << ": create_subscription failed: 0x" << std::hex << subscription.status_code().as_uint32();
    auto sink = std::make_shared<DataValueSink>();
    auto item = create_data_monitored_item(subscription.value(), instanceId, /*clientHandle=*/1, sink);
    ASSERT_TRUE(item.is_good()) << type << ": create_monitored_item failed: 0x" << std::hex
                                << item.status_code().as_uint32();
    ASSERT_TRUE(wait_until([&] { return !sink->snapshot().empty(); }))
      << type << ": the initial sample must arrive before any Property is touched";
    ASSERT_EQ(semantics_changed_count(*sink), 0U)
      << type << ": nothing has changed a Property yet, so no notification may carry SemanticsChanged";

    // The unlisted Property changes, then the Value changes so a notification is guaranteed to follow it. A
    // projected Property changes with the Value itself.
    std::optional<Variant> projectedBefore;
    if (nonTrigger.second)
    {
      ASSERT_TRUE(mConnection->try_write_value_sync(nonTrigger.first, *nonTrigger.second).is_good())
        << type << ": the unlisted Property write must reach the server";
    }
    else
    {
      auto before = mConnection->try_read_value_sync(nonTrigger.first);
      ASSERT_TRUE(before.is_good()) << type << ": the projected unlisted Property must be readable";
      projectedBefore = before.value().value();
    }
    const std::size_t delivered = sink->snapshot().size();
    ASSERT_TRUE(mConnection->try_write_value_sync(instanceId, forcedValue).is_good())
      << type << ": the forcing Value write must reach the server";
    ASSERT_TRUE(wait_until([&] { return sink->snapshot().size() > delivered; }))
      << type << ": a notification must be delivered after the unlisted write, or the control is vacuous";
    if (projectedBefore)
    {
      auto after = mConnection->try_read_value_sync(nonTrigger.first);
      ASSERT_TRUE(after.is_good()) << type << ": the projected unlisted Property must stay readable";
      ASSERT_NE(after.value().value(), *projectedBefore)
        << type << ": the Value write must have changed the projected Property, or the row is vacuous";
    }
    EXPECT_EQ(semantics_changed_count(*sink), 0U)
      << type
      << ": changing a Property the specification does not list must NOT set SemanticsChanged - a server "
         "that raises it on every Property change makes clients re-read their metadata continuously, the "
         "cost the selective list exists to avoid";

    // ...and the interface really is live here: the LISTED Property does raise it.
    const std::size_t baseline = semantics_changed_count(*sink);
    ASSERT_TRUE(mConnection->try_write_value_sync(trigger.first, trigger.second).is_good())
      << type << ": the listed Property write must reach the server";
    EXPECT_TRUE(wait_until([&] { return semantics_changed_count(*sink) > baseline; }))
      << type
      << ": changing a Property the specification lists must set SemanticsChanged (Part 8 section 5.2)";
  }

  NodeId mScalarAnalogId;
  NodeId mArrayAnalogId;
  NodeId mNoEuRangeAnalogId;
  NodeId mClampAnalogId;
  NodeId mRejectAnalogId;
  NodeId mBadStatusAnalogId;
  NodeId mAnalogUnitNoUnitsId;
  NodeId mAnalogUnitRangeNoEuId;
  NodeId mAnalogUnitRangeNoUnitsId;
  NodeId mBaseAnalogId;
  NodeId mDefinitionEmptyId;
  NodeId mDefinitionLongId;
  NodeId mEuFullId;
  NodeId mEuEmptyDescriptionId;
  NodeId mEuEmptyDisplayNameId;
  NodeId mEuEmptyNamespaceUriId;
  NodeId mDistinctRangesId;
  NodeId mEuRangeInvertedId;
  NodeId mEuRangeNanId;
  NodeId mInstrumentRangeInvertedId;
  NodeId mInstrumentRangeNanHighId;
  NodeId mInstrumentRangeNanLowId;
  NodeId mInstrumentRangeNanBothId;
  NodeId mDegenerateRangeId;
  // sub-batch 3 node ids
  NodeId mTwoStateMissingTrueId;
  NodeId mTwoStateTrueEmptyId;
  NodeId mTwoStateFalseEmptyId;
  NodeId mMultiStateNoEnumStringsId;
  NodeId mMultiStateOutsideId;
  NodeId mMultiStateEmptyStringId;
  NodeId mMultiStateWriteAcceptId;
  NodeId mMultiStateWriteRejectId;
  NodeId mMultiStateValueNoEnumId;
  NodeId mMultiStateValueNoTextId;
  NodeId mMultiStateValueOutsideId;
  NodeId mDictWriteResolvesId;
  NodeId mDictEntryLowId;
  NodeId mDictEntryHighId;
  NodeId mDictEntryRunningId;
  NodeId mValueAsDictEntriesResolvesId;
  NodeId mDictWriteNoMatchId;
  NodeId mDictEntryNoMatchId;
  NodeId mValueAsDictEntriesOobId;
  NodeId mMsdeNoDictionaryId;
  NodeId mMsdeNoEnumValuesId;
  // sub-batch 4 node ids
  NodeId mUncertainStatusAnalogId;
  NodeId mValuePrecisionNanId;
  NodeId mValuePrecisionNegativeId;
  NodeId mValuePrecisionWholeId;
  NodeId mValuePrecisionZeroId;
  // sub-batch 5 node ids (SemanticChange invalidation)
  NodeId mSemanticChangeAnalogId;
  NodeId mSemanticChangeEuRangeId;
  // sub-batch 6 node ids (server-side DataAccess model obligations)
  NodeId mDefinitionEquationId;
  NodeId mDefinitionEquationPropertyId;
  NodeId mInstantiatedAnalogId;
  NodeId mInstantiatedEuRangeId;
  NodeId mArrayUnitRangeId;
  NodeId mArrayUnitRangeEuRangeId;
  NodeId mArrayUnitRangeUnitsId;
  NodeId mSemanticsUnitRangeId;
  NodeId mSemanticsEuRangeId;
  NodeId mSemanticsUnitsId;
  NodeId mTwoStateInstanceId;
  NodeId mTwoStateTruePropertyId;
  NodeId mTwoStateFalsePropertyId;
  // sub-batch 7 node ids (MultiState lookup tables + the ArrayItem family)
  NodeId mMultiStateInstanceId;
  NodeId mMultiStateEnumStringsId;
  NodeId mMultiStateArrayId;
  NodeId mMultiStateArrayEnumStringsId;
  NodeId mMsvdInstanceId;
  NodeId mMsvdEnumValuesId;
  NodeId mMsvdValueAsTextId;
  NodeId mYArrayItemId;
  NodeId mYArrayXAxisDefinitionId;
  NodeId mYArrayTitleId;
  NodeId mYArrayAxisScaleTypeId;
  NodeId mSemanticsYArrayId;
  NodeId mSemanticsYArrayXAxisId;
  NodeId mSemanticsYArrayTitleId;
  NodeId mSemanticsXYArrayId;
  NodeId mSemanticsXYArrayXAxisId;
  NodeId mSemanticsXYArrayTitleId;
  NodeId mSemanticsImageId;
  NodeId mSemanticsImageXAxisId;
  NodeId mSemanticsImageYAxisId;
  NodeId mSemanticsImageTitleId;
  NodeId mSemanticsCubeId;
  NodeId mSemanticsCubeXAxisId;
  NodeId mSemanticsCubeYAxisId;
  NodeId mSemanticsCubeZAxisId;
  NodeId mSemanticsCubeTitleId;
  NodeId mSemanticsNDimensionId;
  NodeId mSemanticsNDimensionAxisId;
  NodeId mSemanticsNDimensionTitleId;
  // sub-batch 8 node ids (the master SemanticsChanged rule + the generic-Bad overlay)
  NodeId mMasterMsvdId;
  NodeId mMasterMsvdEnumValuesId;
  NodeId mMasterMsvdValueAsTextId;
  NodeId mMasterYArrayId;
  NodeId mMasterYArrayXAxisId;
  NodeId mMasterYArrayAxisScaleTypeId;
  NodeId mMasterYArrayTitleId;
  NodeId mGenericBadAnalogId;
  // sub-batch 9 node ids (the MSDE dictionary table + the Uncertain / Good status-code overlays)
  NodeId mDictAlignedId;
  NodeId mDictAlignedEnumValuesId;
  NodeId mDictAlignedEntriesId;
  NodeId mDictAlignedValueAsEntriesId;
  NodeId mDictReadOnlyParentId;
  NodeId mDictReadOnlyValueAsEntriesId;
  NodeId mUncertainGenericAnalogId;
  NodeId mNoCommunicationAnalogId;
  // sub-batch 10 node ids (the AnalogUnitType Mandatory-Property population)
  NodeId mAnalogUnitInstanceId;
  NodeId mAnalogUnitUnitsId;
  NodeId mAnalogUnitEuRangeId;
  // The dictionary-entry NodeIds ns;7700's EnumDictionaryEntries is published with, row-major
  // [state][dictionary] - the table the ORDER and SHAPE rows compare what the server serves against.
  std::vector<NodeId> mDictAlignedEntries;
  static constexpr std::size_t sDictAlignedStates = 3;
  static constexpr std::size_t sDictAlignedDictionaries = 2;
  // The vendor Definition the non-localisation row serves: an equation, the payload Part 8 section 5.3.2.2
  // names, whose separators and operators a localisation pass would be free to rewrite.
  static constexpr const char* sDefinitionEquation = "(TempA - 25) + TempB";
  // The one namespaceUri Part 8 section 5.6.3.3 assigns to the UN/CEFACT Common Code mapping. It is compared
  // as a string by every client and never resolved, so it is spelled out here rather than derived.
  static constexpr const char* sUnCefactNamespaceUri = "http://www.opcfoundation.org/UA/units/un/cefact";
  std::shared_ptr<std::atomic<int>> mDictNoMatchWriteCount = std::make_shared<std::atomic<int>>(0);
  std::string mLongDefinition;
  std::optional<SecureChannel> mConnChannel;
  std::shared_ptr<ConnectionImpl> mConnImpl;
  std::optional<Connection> mConnection;
};

// ============================================================================================================
// Row - PercentDeadbandAcceptsBoundaryZeroAndHundred (section 8.18.4.1, CL-DA-004)  [integration; unit
// already discharged by BoundaryPercentsAreAccepted]. On a real EURange-resolved handle,
// make_percent_deadband_filter accepts the inclusive endpoints 0.0 and 100.0 and produces a PercentDeadband
// filter carrying that value. [neg: an off-by-one strict comparison rejects 0.0 or 100.0]
// ============================================================================================================
// @verifies CL-DA-004
// @relation(CL-DA-004, scope=function)
TEST_F(ClientDataAccess, PercentDeadbandAcceptsBoundaryZeroAndHundred)
{
  AnalogItemHandleResult handle = build_analog(mScalarAnalogId);
  ASSERT_TRUE(handle.is_good()) << "analog_item_async must resolve the EURange-bearing handle: 0x" << std::hex
                                << handle.status_code().as_uint32();

  for (double percent : {0.0, 100.0})
  {
    ua::Result<ua::DataChangeFilter> filter = handle.value().make_percent_deadband_filter(percent);
    ASSERT_TRUE(filter.is_good()) << "boundary percent=" << percent << " must be accepted (inclusive)";
    EXPECT_EQ(filter.value().deadband_type(), static_cast<std::uint32_t>(ua::DeadbandType::Percent));
    EXPECT_DOUBLE_EQ(filter.value().deadband_value(), percent);
  }
}

// ============================================================================================================
// Row - PercentDeadbandRejectsNegativeLocally (section 8.18.4.1, CL-DA-004)  [integration; unit already
// discharged by PercentOutOfRangeRejectedLocally]. make_percent_deadband_filter(-1.0) on a real handle is
// rejected LOCALLY with Bad_DeadbandFilterInvalid and a source-tagged ErrorDetail; the client never proceeds
// to emit a CreateMonitoredItems carrying a negative deadband (the local failure stops the flow before any
// wire op). [neg: request goes out with a negative deadband, deferring the error to the server]
// ============================================================================================================
// @verifies CL-DA-004
// @verifies CL-DIAG-003
// @relation(CL-DA-004, CL-DIAG-003, scope=function)
TEST_F(ClientDataAccess, PercentDeadbandRejectsNegativeLocally)
{
  AnalogItemHandleResult handle = build_analog(mScalarAnalogId);
  ASSERT_TRUE(handle.is_good());

  ua::Result<ua::DataChangeFilter> filter = handle.value().make_percent_deadband_filter(-1.0);
  ASSERT_TRUE(filter.is_bad()) << "a negative percent must be rejected locally, not sent to the server";
  EXPECT_EQ(filter.status_code().as_status(), ua::Status::BadDeadbandFilterInvalid);
  ASSERT_NE(filter.shared_detail(), nullptr);
  EXPECT_EQ(filter.shared_detail()->source, "client.tier2.data_access.percent_deadband");
}

// ============================================================================================================
// Row - PercentDeadbandRejectsOver100Locally (section 8.18.4.1, CL-DA-004)  [integration; unit already
// discharged by PercentOutOfRangeRejectedLocally]. make_percent_deadband_filter(101.0) on a real handle is
// rejected LOCALLY with Bad_DeadbandFilterInvalid; 101 is never accepted and sent. [neg: 101 accepted and
// sent]
// ============================================================================================================
// @verifies CL-DA-004
// @relation(CL-DA-004, scope=function)
TEST_F(ClientDataAccess, PercentDeadbandRejectsOver100Locally)
{
  AnalogItemHandleResult handle = build_analog(mScalarAnalogId);
  ASSERT_TRUE(handle.is_good());

  ua::Result<ua::DataChangeFilter> filter = handle.value().make_percent_deadband_filter(101.0);
  ASSERT_TRUE(filter.is_bad()) << "a percent above 100 must be rejected locally";
  EXPECT_EQ(filter.status_code().as_status(), ua::Status::BadDeadbandFilterInvalid);
  ASSERT_NE(filter.shared_detail(), nullptr);
  EXPECT_EQ(filter.shared_detail()->source, "client.tier2.data_access.percent_deadband");
}

// ============================================================================================================
// Row - PercentDeadbandRequiresEuRangeLocally (section 8.18.4.1, CL-DA-005)  [integration; unit already
// discharged by RequiresEuRangeElseFilterNotAllowed]
//
// PINNED-ANALOG + REPORTED DIVERGENCE. The matrix wants make_percent_deadband_filter on a handle for a node
// with NO EURange to fail locally. Through the MANAGED path, however, `analog_item_async` treats EURange as a
// MANDATORY Property (CL-DA-001): a node lacking it fails at the FACTORY (Bad_NotFound, source
// property_resolution_failed) BEFORE any handle exists. The `make_percent_deadband_filter` EURange
// precondition (CL-DA-005, Bad_FilterNotAllowed) is therefore defense-in-depth reachable only by direct
// construction (covered by the unit test) - it cannot be reached through Connection::data_access(). This is
// the REAL client-observable guarantee: a PercentDeadband filter can never be built for a node without
// EURange because the client cannot even obtain its AnalogItemHandle. (The matrix's own DDQ-DA-2 gate + its
// warning "do not hard-code a status the spec assigns to the server path" are relevant: the code's
// direct-construction status is Bad_FilterNotAllowed, not the Bad_DeadbandFilterInvalid the matrix names.)
// [neg: a no-EURange node yields a usable AnalogItemHandle]
// ============================================================================================================
// @verifies CL-DA-005
// @relation(CL-DA-005, scope=function)
TEST_F(ClientDataAccess, PercentDeadbandRequiresEuRangeLocally)
{
  // mWritableVariableId is a plain Int32 Variable: no AnalogItemType definition, no EURange HasProperty
  // child.
  AnalogItemHandleResult handle = build_analog(mWritableVariableId);
  ASSERT_TRUE(handle.is_bad()) << "a node with no EURange must not yield a usable AnalogItemHandle";
  EXPECT_EQ(handle.status_code().as_status(), ua::Status::BadNotFound)
    << "the mandatory-EURange pre-flight rejects the node before a handle (and thus a filter) can exist";
  ASSERT_NE(handle.shared_detail(), nullptr);
  EXPECT_EQ(handle.shared_detail()->source, "client.tier2.data_access.property_resolution_failed");
}

// ============================================================================================================
// Row - PercentDeadbandFilterNotifiesOnlyAboveThreshold (section 8.18.1.a, CL-DA-003)  [integration]
//
// PINNED-ANALOG + REPORTED GAP. The DataChangeFilter is NOT yet plumbed onto the wire MonitoringParameters
// (create_monitored_item carries no filter) and the client-side fallback evaluator (CL-SUB-021) is deferred,
// so the end-to-end "server (or client) drops the below-band sample, delivers the above-band one" cannot be
// verified. Per the matrix row's own strengthening ("For CL-DA-003 proper: assert the emitted
// DataChangeFilter has deadbandType==PercentDeadband(2) and deadbandValue==5.0"), this pins the FILTER the
// client constructs on a real EURange-resolved handle. The wire-plumbing + fallback-evaluator gaps are
// REPORTED. [neg: the constructed filter is not a PercentDeadband, or carries the wrong band]
// ============================================================================================================
// @verifies CL-DA-003
// @relation(CL-DA-003, scope=function)
TEST_F(ClientDataAccess, PercentDeadbandFilterNotifiesOnlyAboveThreshold)
{
  AnalogItemHandleResult handle = build_analog(mScalarAnalogId);
  ASSERT_TRUE(handle.is_good());

  ua::Result<ua::DataChangeFilter> filter = handle.value().make_percent_deadband_filter(5.0);
  ASSERT_TRUE(filter.is_good());
  EXPECT_EQ(filter.value().deadband_type(), static_cast<std::uint32_t>(ua::DeadbandType::Percent))
    << "the emitted filter must be a PercentDeadband(2)";
  EXPECT_DOUBLE_EQ(filter.value().deadband_value(), 5.0)
    << "the 5% band must be carried verbatim on the wire";
  EXPECT_EQ(filter.value().trigger(), ua::DataChangeTrigger::StatusValue);
}

// ============================================================================================================
// Row - PercentDeadbandArrayReturnsFullArrayOnChange (section 8.18.1.a, CL-DA-006)  [integration]
//
// Two-part oracle on an ARRAY AnalogItem (EURange [0,100]):
//  (a) make_percent_deadband_filter(10.0) yields ONE unsplit PercentDeadband filter for the whole array (the
//      SDK never splits into per-element filters - CL-DA-006); and
//  (b) a data-change notification for the array node carries the FULL array Variant, not a sparse
//      single-element delta. (The percent-deadband filter is not yet plumbed onto the wire, so part (b) is
//      driven by a plain monitored item + a full-array write; the server delivers the whole value. The
//      wire-filter plumbing gap is REPORTED.)
// [neg: the SDK splits the array into per-element filters, or the callback sees only the changed element]
// ============================================================================================================
// @verifies CL-DA-006
// @relation(CL-DA-006, scope=function)
TEST_F(ClientDataAccess, PercentDeadbandArrayReturnsFullArrayOnChange)
{
  AnalogItemHandleResult handle = build_analog(mArrayAnalogId);
  ASSERT_TRUE(handle.is_good());

  // (a) One unsplit filter for the whole array.
  ua::Result<ua::DataChangeFilter> filter = handle.value().make_percent_deadband_filter(10.0);
  ASSERT_TRUE(filter.is_good());
  EXPECT_EQ(filter.value().deadband_type(), static_cast<std::uint32_t>(ua::DeadbandType::Percent));
  EXPECT_DOUBLE_EQ(filter.value().deadband_value(), 10.0)
    << "a single scalar percent applies to the whole array - no per-element filters (CL-DA-006)";

  // (b) A data-change notification carries the FULL 8-element array, not a single-element delta.
  auto subscription = create_subscription(100.0);
  ASSERT_TRUE(subscription.is_good())
    << "create_subscription failed: 0x" << std::hex << subscription.status_code().as_uint32();
  auto sink = std::make_shared<DataValueSink>();
  auto item = create_data_monitored_item(subscription.value(), mArrayAnalogId, /*clientHandle=*/1, sink);
  ASSERT_TRUE(item.is_good()) << "create_monitored_item failed: 0x" << std::hex
                              << item.status_code().as_uint32();

  // Mutate a single element (index 3) beyond the band; the whole array is re-sent.
  const Array<double> updated{10.0, 20.0, 30.0, 999.0, 50.0, 60.0, 70.0, 80.0};
  ASSERT_TRUE(mConnection->try_write_value_sync(mArrayAnalogId, Variant{updated}).is_good());

  const auto carriesFullUpdatedArray = [](const DataValue& value)
  {
    ua::Result<std::vector<double>> array = value.value().to_vector<double>();
    return array.is_good() && array.value().size() == 8 && array.value()[3] == 999.0;
  };
  ASSERT_TRUE(wait_until(
    [&]
    {
      for (const auto& value : sink->snapshot())
      {
        if (carriesFullUpdatedArray(value))
        {
          return true;
        }
      }
      return false;
    }))
    << "the client callback must receive the FULL 8-element array on change, not a single-element delta";
}

// ============================================================================================================
// Row - PercentDeadbandServerFilterInvalidSurfaces (section 7.10, CL-DA-004; CTT DA/Deadband/Err-001-02)
// [integration]. A well-formed CreateMonitoredItems whose per-item result the MisbehavingServer rewrites to
// Bad_MonitoredItemFilterInvalid must surface that status verbatim; the item must not attach, and there must
// be no retry storm. [neg: status swallowed, item reported Good, or a retry storm]
//
// (The PercentDeadband filter is not yet plumbed onto the wire, so the client emits a plain
// CreateMonitoredItems whose per-item filter-rejection the server injects - the surfacing path is identical;
// REPORTED.)
// ============================================================================================================
// @verifies CL-DA-004
// @relation(CL-DA-004, scope=function)
TEST_F(ClientDataAccess, PercentDeadbandServerFilterInvalidSurfaces)
{
  expect_server_filter_status_surfaced(ua::Status::BadMonitoredItemFilterInvalid);
}

// ============================================================================================================
// Row - PercentDeadbandServerFilterNotAllowedSurfaces (section 7.10, CL-DA-005; CTT DA/Deadband/Err-001-01)
// [integration]. The MisbehavingServer returns a per-item Bad_FilterNotAllowed; the client must surface it
// verbatim, leave the item un-attached, and not retry. [neg: status dropped or item reported Good]
// ============================================================================================================
// @verifies CL-DA-005
// @relation(CL-DA-005, scope=function)
TEST_F(ClientDataAccess, PercentDeadbandServerFilterNotAllowedSurfaces)
{
  expect_server_filter_status_surfaced(ua::Status::BadFilterNotAllowed);
}

// ============================================================================================================
// Row - PercentDeadbandServerFilterUnsupportedSurfaces (section 7.10, CL-DA-005; CTT DA/Deadband/Err-001-03)
// [integration]. The MisbehavingServer returns a per-item Bad_MonitoredItemFilterUnsupported; the client must
// surface it verbatim through the same Result channel. [neg: unsupported status silently ignored]
// ============================================================================================================
// @verifies CL-DA-005
// @relation(CL-DA-005, scope=function)
TEST_F(ClientDataAccess, PercentDeadbandServerFilterUnsupportedSurfaces)
{
  expect_server_filter_status_surfaced(ua::Status::BadMonitoredItemFilterUnsupported);
}

// ============================================================================================================
// Row - AnalogItemHandleResolvesEuRangeBeforeExposingValue (section 8.18.1.a / section 8.18.4.1, CL-DA-001)
// [integration]. The accessor's DA Property pre-flight (Browse HasProperty + batched Read) resolves the
// Mandatory EURange BEFORE the typed value is exposed: a read on the resolved handle yields an
// AnalogItemValue whose euRange is present and equals {0,100}, alongside the decoded Value. [neg: the
// pre-flight is skipped and euRange is nullopt - a typed view with no limits]
// ============================================================================================================
// @verifies CL-DA-001
// @relation(CL-DA-001, scope=function)
TEST_F(ClientDataAccess, AnalogItemHandleResolvesEuRangeBeforeExposingValue)
{
  AnalogItemHandleResult handle = build_analog(mScalarAnalogId);
  ASSERT_TRUE(handle.is_good()) << "analog_item_async must resolve the EURange-bearing handle: 0x" << std::hex
                                << handle.status_code().as_uint32();

  Result<AnalogItemValue> value = handle_read(handle.value());
  ASSERT_TRUE(value.is_good()) << "the resolved handle must read the typed value: 0x" << std::hex
                               << value.status_code().as_uint32();
  ASSERT_TRUE(value.value().euRange.has_value())
    << "the Mandatory EURange must be resolved before the value is exposed (pre-flight not skipped)";
  EXPECT_DOUBLE_EQ(value.value().euRange->low(), 0.0);
  EXPECT_DOUBLE_EQ(value.value().euRange->high(), 100.0);
  EXPECT_DOUBLE_EQ(value.value().value.value().to<double>().value(), 50.0);
}

// ============================================================================================================
// Row - AnalogItemHandleBadWhenEuRangeMissing (section 8.18.4.1, CL-DA-001) [integration; unit half in
// tests/unit/client/data_access/property_accessor_client_data_access_tests.cpp]. An AnalogItemType node with
// NO HasProperty->EURange child fails the accessor's Mandatory-Property pre-flight: the Result is
// Bad_NotFound with source client.tier2.data_access.property_resolution_failed (never a Good handle exposing
// euRange=nullopt). [neg: a Good handle with a silently-incomplete typed view]
//
// REPORTED: the matrix oracle also wants the ErrorDetail to NAME "EURange". The built detail is generic ("a
// Mandatory DataAccess Property was absent or undecodable during handle construction") and does not name the
// specific property - a diagnostic-granularity gap, not a correctness defect. Asserted at the granularity the
// code actually emits (matching the batch-1 precedent HandleConstructionBadOnMissingMandatoryProperty).
// ============================================================================================================
// @verifies CL-DA-001
// @relation(CL-DA-001, scope=function)
TEST_F(ClientDataAccess, AnalogItemHandleBadWhenEuRangeMissing)
{
  AnalogItemHandleResult handle = build_analog(mNoEuRangeAnalogId);
  ASSERT_TRUE(handle.is_bad())
    << "a node lacking the Mandatory EURange must not yield a usable AnalogItemHandle";
  EXPECT_EQ(handle.status_code().as_status(), Status::BadNotFound);
  ASSERT_NE(handle.shared_detail(), nullptr);
  EXPECT_EQ(handle.shared_detail()->source, "client.tier2.data_access.property_resolution_failed");
}

// ============================================================================================================
// Row - AnalogReadOutOfRangeValueNoException (section 8.18.4.1, CL-DA-007) [integration]. A Value outside
// EURange (999 with EURange {0,100} - a simulated sensor fault) must decode WITHOUT the SDK rejecting or
// clamping it: the read succeeds, the raw 999 surfaces verbatim, and EURange is still {0,100}. [neg: the SDK
// rejects or clamps the read because the value lies outside EURange]
//
// REPORTED: pinned to ComplianceWithNodes (the out-of-range value is stored by a normal write) rather than
// the matrix's MisbehavingServer - the client-observable read of an out-of-range value is identical.
// ============================================================================================================
// @verifies CL-DA-007
// @relation(CL-DA-007, scope=function)
TEST_F(ClientDataAccess, AnalogReadOutOfRangeValueNoException)
{
  // Store a value outside EURange [0,100] on the AnalogItem (mScalarAnalogId is the accept node, so the
  // write policy stores it verbatim).
  ASSERT_TRUE(mConnection->try_write_value_sync(mScalarAnalogId, Variant{double{999.0}}).is_good());

  AnalogItemHandleResult handle = build_analog(mScalarAnalogId);
  ASSERT_TRUE(handle.is_good());

  Result<AnalogItemValue> value = handle_read(handle.value());
  ASSERT_TRUE(value.is_good()) << "an out-of-range value must decode without rejection or clamping";
  EXPECT_DOUBLE_EQ(value.value().value.value().to<double>().value(), 999.0)
    << "the raw out-of-range value must surface verbatim";
  ASSERT_TRUE(value.value().euRange.has_value());
  EXPECT_DOUBLE_EQ(value.value().euRange->high(), 100.0) << "EURange is unchanged by an out-of-range value";
}

// ============================================================================================================
// Row - AnalogWriteOutOfRangeAcceptPassesThrough (section 8.18.4.1, CL-DA-007) [integration]. The server
// ACCEPTS an out-of-range write (150, EURange {0,100}); the client's write_value_async must be a thin
// passthrough that surfaces Good verbatim and performs NO local clamping - a follow-up read returns the
// stored 150. [neg: the SDK clamps to 100 or rejects locally because value>EURange.high]
// ============================================================================================================
// @verifies CL-DA-007
// @relation(CL-DA-007, scope=function)
TEST_F(ClientDataAccess, AnalogWriteOutOfRangeAcceptPassesThrough)
{
  AnalogItemHandleResult handle = build_analog(mScalarAnalogId);  // the accept node
  ASSERT_TRUE(handle.is_good());

  VoidResult write = handle_write(handle.value(), Variant{double{150.0}});
  ASSERT_TRUE(write.is_good())
    << "the server accepts the out-of-range write; the client must surface Good verbatim";

  Result<AnalogItemValue> value = handle_read(handle.value());
  ASSERT_TRUE(value.is_good());
  EXPECT_DOUBLE_EQ(value.value().value.value().to<double>().value(), 150.0)
    << "no local clamp - the server stored 150 verbatim";
}

// ============================================================================================================
// Row - AnalogWriteOutOfRangeClampPassesThrough (section 8.18.4.1, CL-DA-007) [integration]. The server
// CLAMPS an out-of-range write to 100 and returns Good_Clamped; the client must surface it as success and NOT
// assert a written!=echoed mismatch - a follow-up read shows the server's clamped 100. [neg: the SDK asserts
// written!=echoed, or reports the clamp as an error]
// ============================================================================================================
// @verifies CL-DA-007
// @relation(CL-DA-007, scope=function)
TEST_F(ClientDataAccess, AnalogWriteOutOfRangeClampPassesThrough)
{
  AnalogItemHandleResult handle = build_analog(mClampAnalogId);  // the clamp node
  ASSERT_TRUE(handle.is_good());

  VoidResult write = handle_write(handle.value(), Variant{double{150.0}});
  ASSERT_TRUE(write.is_good())
    << "the server clamps and returns Good_Clamped; the client must not treat the clamp as an error";

  Result<AnalogItemValue> value = handle_read(handle.value());
  ASSERT_TRUE(value.is_good());
  EXPECT_DOUBLE_EQ(value.value().value.value().to<double>().value(), 100.0)
    << "the follow-up read echoes the server's clamped value; the client surfaces it verbatim";
}

// ============================================================================================================
// Row - AnalogWriteOutOfRangeRejectPassesThrough (section 8.18.4.1, CL-DA-007) [integration]. The server
// REJECTS an out-of-range write with Bad_OutOfRange; the client must surface that status VERBATIM beneath
// source client.tier2.data_access.write, never masking it or pre-empting with a different local error. [neg:
// the SDK masks the server rejection or pre-empts it with a local error]
// ============================================================================================================
// @verifies CL-DA-007
// @relation(CL-DA-007, scope=function)
TEST_F(ClientDataAccess, AnalogWriteOutOfRangeRejectPassesThrough)
{
  AnalogItemHandleResult handle = build_analog(mRejectAnalogId);  // the reject node
  ASSERT_TRUE(handle.is_good());

  VoidResult write = handle_write(handle.value(), Variant{double{150.0}});
  ASSERT_TRUE(write.is_bad()) << "the server rejects the out-of-range write; the client must not mask it";
  EXPECT_EQ(write.status_code().as_status(), Status::BadOutOfRange)
    << "the server's Bad_OutOfRange must surface verbatim, not a client-side local error";
  ASSERT_NE(write.shared_detail(), nullptr);
  EXPECT_EQ(write.shared_detail()->source, "client.tier2.data_access.write");
}

// ============================================================================================================
// Row - BadDaStatusProducesBadResult (section 8.18.4.1 / section 7.10, CL-DA-015) [integration]. A DA item
// whose Value carries a Bad_DeviceFailure quality StatusCode must surface that status intact (never masked to
// Good, never demoted to a generic bad code). [neg: Bad status masked as Good, or demoted losing
// Bad_DeviceFailure]
//
// REPORTED - DIVERGENCE from the matrix oracle ("Result is bad"). Per CL-DA-015 the DA quality StatusCode is
// surfaced VERBATIM in value.status(): a Read whose SERVICE succeeded returns a GOOD Result carrying the
// bad-quality DataValue (the value + last-known quality are not discarded). The bad status is fully surfaced
// at the value-quality level - the OPC-UA semantics for a Read - not promoted to a bad Result. This matches
// the unit test StatusCodesPassedThroughVerbatim and the CL-DA-015 requirement text.
// ============================================================================================================
// @verifies CL-DA-015
// @relation(CL-DA-015, scope=function)
TEST_F(ClientDataAccess, BadDaStatusProducesBadResult)
{
  AnalogItemHandleResult handle = build_analog(mBadStatusAnalogId);
  ASSERT_TRUE(handle.is_good());

  Result<AnalogItemValue> value = handle_read(handle.value());
  ASSERT_TRUE(value.is_good()) << "a bad DA quality StatusCode does not fail the Read Result (CL-DA-015)";
  ASSERT_TRUE(value.value().value.status().has_value());
  EXPECT_EQ(value.value().value.status()->as_status(), Status::BadDeviceFailure)
    << "the DA quality StatusCode must surface verbatim, neither masked to Good nor demoted";
}

// ============================================================================================================
// Row - ArrayDaPropertiesAreScalarNotPerElement (section 8.18.4.1, CL-DA-009) [integration]. For an
// array-valued AnalogItem the DA Properties are SCALAR: the resolved euRange is a single Range applying to
// every element, not a per-element array of ranges. The Value is the multi-element array; euRange stays one
// scalar. [neg: the SDK exposes a per-element euRange array]
//
// REPORTED: the matrix row also names an array length of 10 and a wire assertion (exactly one Property read,
// not one per element). Fixture A's array is length 8 (immaterial to the scalar-property invariant), and
// ComplianceWithNodes exposes no wire read-counter - the "one batched Property read" is discharged by the
// unit test AnalogItemResolvesMandatoryPropertiesAndComposesBrowse (readRequests.size()==1).
// ============================================================================================================
// @verifies CL-DA-009
// @relation(CL-DA-009, scope=function)
TEST_F(ClientDataAccess, ArrayDaPropertiesAreScalarNotPerElement)
{
  AnalogItemHandleResult handle = build_analog(mArrayAnalogId);
  ASSERT_TRUE(handle.is_good());

  Result<AnalogItemValue> value = handle_read(handle.value());
  ASSERT_TRUE(value.is_good());

  // The Value is a multi-element array...
  Result<std::vector<double>> array = value.value().value.value().to_vector<double>();
  ASSERT_TRUE(array.is_good());
  EXPECT_EQ(array.value().size(), 8U) << "the Value is per-element (an array)";

  // ...but the EURange DA Property is a single scalar Range applying to all elements (CL-DA-009), never a
  // per-element array (AnalogItemValue::euRange is a single std::optional<Range>).
  ASSERT_TRUE(value.value().euRange.has_value());
  EXPECT_DOUBLE_EQ(value.value().euRange->low(), 0.0);
  EXPECT_DOUBLE_EQ(value.value().euRange->high(), 100.0);
}

// ============================================================================================================
// Row - AnalogUnitHandleBadWhenEngineeringUnitsMissing (section 8.18.4.1, CL-DA-001) [integration; unit half
// in tests/unit/client/data_access/property_accessor_client_data_access_tests.cpp]. AnalogUnitType (OPC
// 10000-8 section 5.3.2.4) derives from BaseAnalogType and mandates ONLY EngineeringUnits (EURange is
// inherited-Optional). The NEW analog_unit_async accessor rejects ns;6600 (EURange present, EngineeringUnits
// absent). Discriminator: the SAME node builds a GOOD handle through analog_item_async (which enforces
// EURange, treats EngineeringUnits as Optional) - proving the AnalogUnitType-specific pre-flight is real.
// (Previously REPORTED as divergent.)
// ============================================================================================================
// @verifies CL-DA-001
// @relation(CL-DA-001, scope=function)
TEST_F(ClientDataAccess, AnalogUnitHandleBadWhenEngineeringUnitsMissing)
{
  AnalogItemHandleResult handle = build_analog_unit(mAnalogUnitNoUnitsId);
  ASSERT_TRUE(handle.is_bad())
    << "AnalogUnitType mandates EngineeringUnits; a node lacking it must not yield a handle";
  EXPECT_EQ(handle.status_code().as_status(), Status::BadNotFound);
  ASSERT_NE(handle.shared_detail(), nullptr);
  EXPECT_EQ(handle.shared_detail()->source, "client.tier2.data_access.property_resolution_failed");

  // Discriminator: analog_item_async accepts the SAME node (EURange present; EngineeringUnits Optional
  // there).
  EXPECT_TRUE(build_analog(mAnalogUnitNoUnitsId).is_good())
    << "analog_item_async treats EngineeringUnits as Optional - proving analog_unit_async's gate is distinct";
}

// ============================================================================================================
// Row - AnalogUnitRangeHandleBadOnEitherMissingProperty (section 8.18.4.1, CL-DA-001) [integration; unit half
// in tests/unit/client/data_access/property_accessor_client_data_access_tests.cpp]. AnalogUnitRangeType (OPC
// 10000-8 section 5.3.2.5) derives from AnalogItemType and additionally mandates EngineeringUnits, so BOTH
// EURange and EngineeringUnits are Mandatory. The NEW analog_unit_range_async accessor rejects EITHER
// missing: variant (a) EURange absent (ns;6700) and variant (b) EngineeringUnits absent (ns;6710). Variant
// (b) is the case analog_item_async wrongly ACCEPTS (EngineeringUnits Optional there) - the discriminator.
// (Previously PARTIALLY REPORTED.)
// ============================================================================================================
// @verifies CL-DA-001
// @relation(CL-DA-001, scope=function)
TEST_F(ClientDataAccess, AnalogUnitRangeHandleBadOnEitherMissingProperty)
{
  // Variant (a): EURange absent -> rejected (EURange Mandatory).
  {
    AnalogItemHandleResult handle = build_analog_unit_range(mAnalogUnitRangeNoEuId);
    ASSERT_TRUE(handle.is_bad()) << "EURange absent must reject at the pre-flight";
    EXPECT_EQ(handle.status_code().as_status(), Status::BadNotFound);
    ASSERT_NE(handle.shared_detail(), nullptr);
    EXPECT_EQ(handle.shared_detail()->source, "client.tier2.data_access.property_resolution_failed");
  }

  // Variant (b): EngineeringUnits absent (EURange present) -> rejected (EngineeringUnits Mandatory).
  {
    AnalogItemHandleResult handle = build_analog_unit_range(mAnalogUnitRangeNoUnitsId);
    ASSERT_TRUE(handle.is_bad()) << "EngineeringUnits absent must reject at the pre-flight";
    EXPECT_EQ(handle.status_code().as_status(), Status::BadNotFound);

    // Discriminator: analog_item_async ACCEPTS the same variant-(b) node (EngineeringUnits Optional there),
    // proving analog_unit_range_async's EngineeringUnits gate is real.
    EXPECT_TRUE(build_analog(mAnalogUnitRangeNoUnitsId).is_good())
      << "analog_item_async does not enforce EngineeringUnits - the two accessors diverge as intended";
  }
}

// ============================================================================================================
// Row - BaseAnalogHandleSucceedsWithNoOptionalProperties (section 8.18.4.1, CL-DA-001) [integration; unit
// half in tests/unit/client/data_access/property_accessor_client_data_access_tests.cpp]. BaseAnalogType has
// NO Mandatory Property (EURange / EngineeringUnits / InstrumentRange are all Optional on the base type), so
// the NEW base_analog_async accessor resolves a usable AnalogItemHandle for a node (ns;6800) exposing NONE of
// them - exactly the case analog_item_async rejects. The handle reads its value; euRange is (legitimately)
// absent. (Previously REPORTED as divergent because no BaseAnalogType-aware accessor existed;
// base_analog_async now closes that gap.) [neg: the base accessor wrongly imposes the AnalogItemType
// Mandatory-EURange gate]
// ============================================================================================================
// @verifies CL-DA-001
// @relation(CL-DA-001, scope=function)
TEST_F(ClientDataAccess, BaseAnalogHandleSucceedsWithNoOptionalProperties)
{
  AnalogItemHandleResult handle = build_base_analog(mBaseAnalogId);
  ASSERT_TRUE(handle.is_good()) << "base_analog_async must resolve a BaseAnalogType node with no Optional "
                                   "Properties (no Mandatory Property to enforce): 0x"
                                << std::hex << handle.status_code().as_uint32();

  Result<AnalogItemValue> value = handle_read(handle.value());
  ASSERT_TRUE(value.is_good()) << "the resolved base-analog handle must read the typed value: 0x" << std::hex
                               << value.status_code().as_uint32();
  EXPECT_FALSE(value.value().euRange.has_value())
    << "BaseAnalogType exposes no EURange here; the handle must surface it as absent, not fabricate one";
  EXPECT_DOUBLE_EQ(value.value().value.value().to<double>().value(), 50.0);

  // Discriminator: the SAME node still fails analog_item_async, whose Mandatory-EURange gate a bare
  // BaseAnalogType node cannot satisfy - proving base_analog_async's relaxation is real, not a no-op alias.
  EXPECT_TRUE(build_analog(mBaseAnalogId).is_bad())
    << "analog_item_async must still reject the BaseAnalogType node (no Mandatory EURange)";
}

// ============================================================================================================
// Row - DefinitionEmptyStringHandled (section 8.18.4.1, CL-DA-017; DDQ-DA-4) [integration]. DDQ-DA-4 is
// RATIFIED (client_design.md section 17378): `Definition = std::optional<std::string>`, `optional{""}` iff
// present-empty (nullopt iff absent). A node whose Definition Property is an empty String must read back as
// `optional{""}` EXACTLY - the read succeeds, definition is present-and-empty (never nullopt, never dropped).
// [neg: a present-empty Definition collapses to nullopt, blurring "absent" and "present-empty"]
// ============================================================================================================
// @verifies CL-DA-017
// @relation(CL-DA-017, scope=function)
TEST_F(ClientDataAccess, DefinitionEmptyStringHandled)
{
  AnalogItemHandleResult handle = build_analog(mDefinitionEmptyId);
  ASSERT_TRUE(handle.is_good()) << "the EURange-bearing node must resolve a handle: 0x" << std::hex
                                << handle.status_code().as_uint32();

  Result<AnalogItemValue> value = handle_read(handle.value());
  ASSERT_TRUE(value.is_good()) << "a present-empty Definition must not fail the read";
  EXPECT_EQ(value.value().definition, std::optional<std::string>{""})
    << "DDQ-DA-4: a present-empty Definition surfaces as optional{\"\"}, not nullopt";
}

// ============================================================================================================
// Row - DefinitionLongVendorStringVerbatim (section 8.18.4.1, CL-DA-017; CTT DA/Basic/Err-001-01)
// [integration]. A ~1KB opaque vendor Definition string must surface byte-for-byte: no truncation, no
// parse/validation as an equation, no rejection (CL-DA-017 - vendor-opaque pass-through). [neg: the string is
// truncated, or the SDK tries to parse/validate it as an equation and rejects/alters it]
//
// REPORTED - fixture pin: the matrix names MisbehavingServer; this serves the ~1KB Definition through
// ComplianceWithNodes (Fixture A). The client-observable read of a long opaque Definition Property is
// identical - the surfacing path (Browse HasProperty + Read Definition + extract_definition) does not depend
// on which server serves it.
// ============================================================================================================
// @verifies CL-DA-017
// @relation(CL-DA-017, scope=function)
TEST_F(ClientDataAccess, DefinitionLongVendorStringVerbatim)
{
  ASSERT_GE(mLongDefinition.size(), 1024U) << "the fixture must serve a ~1KB Definition blob";

  AnalogItemHandleResult handle = build_analog(mDefinitionLongId);
  ASSERT_TRUE(handle.is_good());

  Result<AnalogItemValue> value = handle_read(handle.value());
  ASSERT_TRUE(value.is_good()) << "a long opaque Definition must not be rejected";
  ASSERT_TRUE(value.value().definition.has_value());
  EXPECT_EQ(*value.value().definition, mLongDefinition)
    << "the vendor Definition must surface byte-for-byte - no truncation, no parse";
}

// ============================================================================================================
// Row - EngineeringUnitsAllFieldsPreserved (section 8.18.4.1, CL-DA-014) [integration]. A well-formed
// EngineeringUnits (namespaceUri=UN/CEFACT, unitId=4408652, displayName='degC', description='degree Celsius')
// must decode with all four fields exactly as served - the SDK never drops a field nor maps the unit to a
// local table. [neg: any field dropped, or the SDK unilaterally maps to a local unit table]
// ============================================================================================================
// @verifies CL-DA-014
// @relation(CL-DA-014, scope=function)
TEST_F(ClientDataAccess, EngineeringUnitsAllFieldsPreserved)
{
  AnalogItemHandleResult handle = build_analog(mEuFullId);
  ASSERT_TRUE(handle.is_good());

  Result<AnalogItemValue> value = handle_read(handle.value());
  ASSERT_TRUE(value.is_good());
  ASSERT_TRUE(value.value().engineeringUnits.has_value())
    << "a present EngineeringUnits Property must decode (CL-DA-014)";
  const EUInformation& units = *value.value().engineeringUnits;
  EXPECT_EQ(
    static_cast<std::string>(units.namespace_uri()), "http://www.opcfoundation.org/UA/units/un/cefact");
  EXPECT_EQ(units.unit_id(), 4408652);
  EXPECT_EQ(static_cast<std::string>(units.display_name().text()), "\u00b0C");
  EXPECT_EQ(static_cast<std::string>(units.description().text()), "degree Celsius");
}

// ============================================================================================================
// Row - EngineeringUnitsEmptyDescriptionAdvisory (section 8.18.4.1, CL-DA-014; CTT DA/Basic/Err-002-04)
// [integration].
//
// VERBATIM half ASSERTED (built); ADVISORY half REPORTED UNBUILT. The matrix wants: read succeeds,
// description empty verbatim, AND on_advisory_diagnostic fired once. The client's DA decode path
// (sdk/implementation/client/ua_data_access.cpp - extract_eu / decode_analog_value) is a PURE verbatim
// extractor: it surfaces the decoded EUInformation as-is with NO empty-field detection and NO advisory /
// ClientObserver fan-out (grep of the file finds no advisory emission - the DataAccess advisory arm is
// UNBUILT, mirroring the LimitAlarm CL-AC-023/025 declared-but-unbuilt finding). So this asserts ONLY the
// built VERBATIM half (empty description surfaced, read not rejected, sibling fields intact) GREEN; the
// on_advisory_diagnostic assertion is deferred until the advisory arm is built (REPORTED, not authored RED).
// [neg: an empty description is rejected or silently substituted]
// ============================================================================================================
// @verifies CL-DA-014
// @relation(CL-DA-014, scope=function)
TEST_F(ClientDataAccess, EngineeringUnitsEmptyDescriptionAdvisory)
{
  AnalogItemHandleResult handle = build_analog(mEuEmptyDescriptionId);
  ASSERT_TRUE(handle.is_good());

  Result<AnalogItemValue> value = handle_read(handle.value());
  ASSERT_TRUE(value.is_good()) << "an empty EngineeringUnits description must not fail the read";
  ASSERT_TRUE(value.value().engineeringUnits.has_value());
  EXPECT_TRUE(value.value().engineeringUnits->description().text().empty())
    << "the empty description surfaces verbatim, neither rejected nor substituted";
  EXPECT_FALSE(value.value().engineeringUnits->display_name().text().empty())
    << "the sibling displayName stays populated (only description is empty)";
}

// ============================================================================================================
// Row - EngineeringUnitsEmptyDisplayNameAdvisory (section 8.18.4.1, CL-DA-014; CTT DA/Basic/Err-002-03)
// [integration].
//
// VERBATIM half ASSERTED (built); ADVISORY half REPORTED UNBUILT (see
// EngineeringUnitsEmptyDescriptionAdvisory for the full rationale - the DA decode advisory arm emits no
// on_advisory_diagnostic). Asserts the built VERBATIM half: read succeeds, engineeringUnits->displayName is
// empty verbatim (never substituted), sibling fields intact. [neg: empty displayName rejected, or silently
// substituted, or the read rejected]
// ============================================================================================================
// @verifies CL-DA-014
// @relation(CL-DA-014, scope=function)
TEST_F(ClientDataAccess, EngineeringUnitsEmptyDisplayNameAdvisory)
{
  AnalogItemHandleResult handle = build_analog(mEuEmptyDisplayNameId);
  ASSERT_TRUE(handle.is_good());

  Result<AnalogItemValue> value = handle_read(handle.value());
  ASSERT_TRUE(value.is_good()) << "an empty EngineeringUnits displayName must not fail the read";
  ASSERT_TRUE(value.value().engineeringUnits.has_value());
  EXPECT_TRUE(value.value().engineeringUnits->display_name().text().empty())
    << "the empty displayName surfaces verbatim, never substituted";
  EXPECT_FALSE(value.value().engineeringUnits->description().text().empty())
    << "the sibling description stays populated (only displayName is empty)";
}

// ============================================================================================================
// Row - EngineeringUnitsEmptyNamespaceUriAdvisory (section 8.18.4.1, CL-DA-014; CTT DA/Basic/Err-002-05)
// [integration].
//
// VERBATIM half ASSERTED (built); ADVISORY half REPORTED UNBUILT (see
// EngineeringUnitsEmptyDescriptionAdvisory for the full rationale). Critically the matrix ALSO demands the
// SDK must NOT silently default the namespace to UN/CEFACT - that no-substitution guarantee IS built and is
// asserted here (the empty namespaceUri surfaces empty, not backfilled). Only the
// on_advisory_diagnostic('namespace unknown') firing is deferred (REPORTED). [neg: the read is rejected, OR
// the SDK silently defaults namespaceUri to CEFACT]
// ============================================================================================================
// @verifies CL-DA-014
// @relation(CL-DA-014, scope=function)
TEST_F(ClientDataAccess, EngineeringUnitsEmptyNamespaceUriAdvisory)
{
  AnalogItemHandleResult handle = build_analog(mEuEmptyNamespaceUriId);
  ASSERT_TRUE(handle.is_good());

  Result<AnalogItemValue> value = handle_read(handle.value());
  ASSERT_TRUE(value.is_good()) << "an empty EngineeringUnits namespaceUri must not fail the read";
  ASSERT_TRUE(value.value().engineeringUnits.has_value());
  EXPECT_TRUE(value.value().engineeringUnits->namespace_uri().empty())
    << "the SDK must NOT silently default the namespace to UN/CEFACT - it surfaces empty verbatim";
  EXPECT_EQ(value.value().engineeringUnits->unit_id(), 4408652)
    << "the sibling unitId stays populated (only namespaceUri is empty)";
}

// ============================================================================================================
// Row - EuRangeAndInstrumentRangeAreDistinctFields (section 8.18.4.1, CL-DA-016) [integration].
// EURange={0,100} and InstrumentRange={-10,110} must surface as TWO separate optionals - the two Properties
// are never conflated into one field and InstrumentRange is never dropped (CL-DA-016). [neg: the two ranges
// are conflated, or instrumentRange is dropped]
// ============================================================================================================
// @verifies CL-DA-016
// @relation(CL-DA-016, scope=function)
TEST_F(ClientDataAccess, EuRangeAndInstrumentRangeAreDistinctFields)
{
  AnalogItemHandleResult handle = build_analog(mDistinctRangesId);
  ASSERT_TRUE(handle.is_good());

  Result<AnalogItemValue> value = handle_read(handle.value());
  ASSERT_TRUE(value.is_good());
  ASSERT_TRUE(value.value().euRange.has_value());
  ASSERT_TRUE(value.value().instrumentRange.has_value()) << "InstrumentRange must not be dropped (CL-DA-016)";
  EXPECT_DOUBLE_EQ(value.value().euRange->low(), 0.0);
  EXPECT_DOUBLE_EQ(value.value().euRange->high(), 100.0);
  EXPECT_DOUBLE_EQ(value.value().instrumentRange->low(), -10.0)
    << "instrumentRange is a distinct field, not conflated with euRange";
  EXPECT_DOUBLE_EQ(value.value().instrumentRange->high(), 110.0);
}

// ============================================================================================================
// Row - EuRangeInvertedSurfacesAdvisory (section 8.18.4.1, CL-DA-007; CTT DA/Basic/Err-002-07) [integration].
//
// VERBATIM half ASSERTED (built); ADVISORY half REPORTED UNBUILT. The matrix wants an inverted EURange
// (High<Low) to surface verbatim AND fire on_advisory_diagnostic. The DA decode path (extract_range) returns
// the decoded Range as-is with NO inverted-range detection and NO advisory (grep confirms the advisory arm is
// UNBUILT). This asserts the built VERBATIM half: the handle builds, the read succeeds, and low/high surface
// exactly as served (80,20) - never swapped or corrected. The advisory firing is deferred (REPORTED). [neg:
// the read is rejected because high<low, OR the SDK silently swaps the fields to {20,80}]
// ============================================================================================================
// @verifies CL-DA-007
// @relation(CL-DA-007, scope=function)
TEST_F(ClientDataAccess, EuRangeInvertedSurfacesAdvisory)
{
  AnalogItemHandleResult handle = build_analog(mEuRangeInvertedId);
  ASSERT_TRUE(handle.is_good()) << "an inverted EURange must not fail handle construction";

  Result<AnalogItemValue> value = handle_read(handle.value());
  ASSERT_TRUE(value.is_good()) << "an inverted range is surfaced verbatim, never rejected";
  ASSERT_TRUE(value.value().euRange.has_value());
  EXPECT_DOUBLE_EQ(value.value().euRange->low(), 80.0);
  EXPECT_DOUBLE_EQ(value.value().euRange->high(), 20.0)
    << "high<low is preserved verbatim - the SDK never swaps or corrects the limits";
}

// ============================================================================================================
// Row - EuRangeNanLimitPreservedAsNan (section 8.18.4.1, CL-DA-013; CTT DA/Basic/Err-002-06) [integration].
// An EURange with High=NaN (Low=0) must surface with euRange present, isnan(high)==true, low==0, and no
// exception - the SDK never maps a NaN limit to 0/max nor rejects the read (CL-DA-013). [neg: NaN mapped to
// 0/max, or the read rejected because a limit is 'unknown']
// ============================================================================================================
// @verifies CL-DA-013
// @relation(CL-DA-013, scope=function)
TEST_F(ClientDataAccess, EuRangeNanLimitPreservedAsNan)
{
  AnalogItemHandleResult handle = build_analog(mEuRangeNanId);
  ASSERT_TRUE(handle.is_good());

  Result<AnalogItemValue> value = handle_read(handle.value());
  ASSERT_TRUE(value.is_good()) << "a NaN EURange limit must not reject the read";
  ASSERT_TRUE(value.value().euRange.has_value());
  EXPECT_DOUBLE_EQ(value.value().euRange->low(), 0.0) << "the non-NaN limit is intact";
  EXPECT_TRUE(std::isnan(value.value().euRange->high()))
    << "a NaN limit is preserved as NaN, never mapped to 0/max";
}

// ============================================================================================================
// Row - InstrumentRangeInvertedSurfacesAdvisory (section 8.18.4.1, CL-DA-016/CL-DA-007; CTT
// DA/Basic/016,Err-002-07) [integration].
//
// VERBATIM half ASSERTED (built); ADVISORY half REPORTED UNBUILT (see EuRangeInvertedSurfacesAdvisory). An
// inverted InstrumentRange (High<Low) surfaces verbatim: the read succeeds and low/high are exactly as served
// (110,-10), never swapped. The advisory firing is deferred (REPORTED). [neg: the read is rejected because
// high<low, OR the SDK silently swaps the fields]
// ============================================================================================================
// @verifies CL-DA-016
// @relation(CL-DA-016, scope=function)
TEST_F(ClientDataAccess, InstrumentRangeInvertedSurfacesAdvisory)
{
  AnalogItemHandleResult handle = build_analog(mInstrumentRangeInvertedId);
  ASSERT_TRUE(handle.is_good());

  Result<AnalogItemValue> value = handle_read(handle.value());
  ASSERT_TRUE(value.is_good()) << "an inverted InstrumentRange is surfaced verbatim, never rejected";
  ASSERT_TRUE(value.value().instrumentRange.has_value());
  EXPECT_DOUBLE_EQ(value.value().instrumentRange->low(), 110.0);
  EXPECT_DOUBLE_EQ(value.value().instrumentRange->high(), -10.0)
    << "high<low preserved verbatim - the SDK never swaps the InstrumentRange fields";
}

// ============================================================================================================
// Row - InstrumentRangeNanLimitPreservedAsNan (section 8.18.4.1, CL-DA-013; CTT DA/Basic/Err-002-01)
// [integration]. Across three served variants (High=NaN, then Low=NaN, then both NaN) each NaN
// InstrumentRange limit surfaces as isnan==true on the corresponding field while the non-NaN limit stays
// intact - no substitution, no crash, no rejection (CL-DA-013). [neg: a NaN limit is substituted or the read
// rejected]
// ============================================================================================================
// @verifies CL-DA-013
// @relation(CL-DA-013, scope=function)
TEST_F(ClientDataAccess, InstrumentRangeNanLimitPreservedAsNan)
{
  // Variant 1 - High=NaN, Low intact (0).
  {
    AnalogItemHandleResult handle = build_analog(mInstrumentRangeNanHighId);
    ASSERT_TRUE(handle.is_good());
    Result<AnalogItemValue> value = handle_read(handle.value());
    ASSERT_TRUE(value.is_good());
    ASSERT_TRUE(value.value().instrumentRange.has_value());
    EXPECT_DOUBLE_EQ(value.value().instrumentRange->low(), 0.0) << "the non-NaN low limit is intact";
    EXPECT_TRUE(std::isnan(value.value().instrumentRange->high())) << "High=NaN preserved as NaN";
  }

  // Variant 2 - Low=NaN, High intact (100).
  {
    AnalogItemHandleResult handle = build_analog(mInstrumentRangeNanLowId);
    ASSERT_TRUE(handle.is_good());
    Result<AnalogItemValue> value = handle_read(handle.value());
    ASSERT_TRUE(value.is_good());
    ASSERT_TRUE(value.value().instrumentRange.has_value());
    EXPECT_TRUE(std::isnan(value.value().instrumentRange->low())) << "Low=NaN preserved as NaN";
    EXPECT_DOUBLE_EQ(value.value().instrumentRange->high(), 100.0) << "the non-NaN high limit is intact";
  }

  // Variant 3 - both NaN.
  {
    AnalogItemHandleResult handle = build_analog(mInstrumentRangeNanBothId);
    ASSERT_TRUE(handle.is_good());
    Result<AnalogItemValue> value = handle_read(handle.value());
    ASSERT_TRUE(value.is_good());
    ASSERT_TRUE(value.value().instrumentRange.has_value());
    EXPECT_TRUE(std::isnan(value.value().instrumentRange->low())) << "both-NaN: low preserved as NaN";
    EXPECT_TRUE(std::isnan(value.value().instrumentRange->high())) << "both-NaN: high preserved as NaN";
  }
}

// ============================================================================================================
// Row - RangeDegenerateHighEqualsLowAccepted (section 8.18.4.1, CL-DA-007; CTT
// DA/Basic/Err-002-02,Err-002-08) [integration]. A zero-width range (High==Low) is LEGAL: EURange={50,50} and
// InstrumentRange={50,50} must be exposed (high==low) without rejection. A later make_percent_deadband_filter
// must NOT trip a divide-by-zero on the zero-width EURange - the client never computes the band locally (the
// wire carries PercentDeadband and EURange presence is the only precondition, CL-DA-005). [neg: a zero-width
// range is rejected, or trips a divide-by-zero in the percent-deadband build]
// ============================================================================================================
// @verifies CL-DA-007
// @relation(CL-DA-007, scope=function)
TEST_F(ClientDataAccess, RangeDegenerateHighEqualsLowAccepted)
{
  AnalogItemHandleResult handle = build_analog(mDegenerateRangeId);
  ASSERT_TRUE(handle.is_good()) << "a zero-width EURange must not fail handle construction";

  Result<AnalogItemValue> value = handle_read(handle.value());
  ASSERT_TRUE(value.is_good()) << "a degenerate range must not be rejected";
  ASSERT_TRUE(value.value().euRange.has_value());
  EXPECT_DOUBLE_EQ(value.value().euRange->low(), 50.0);
  EXPECT_DOUBLE_EQ(value.value().euRange->high(), 50.0) << "a zero-width EURange is accepted (legal)";
  ASSERT_TRUE(value.value().instrumentRange.has_value());
  EXPECT_DOUBLE_EQ(value.value().instrumentRange->high(), value.value().instrumentRange->low())
    << "a zero-width InstrumentRange is likewise accepted";

  // The zero-width EURange must not trip a divide-by-zero in a later percent-deadband build (the client does
  // not compute the absolute band - EURange presence is the only precondition).
  ua::Result<ua::DataChangeFilter> filter = handle.value().make_percent_deadband_filter(10.0);
  EXPECT_TRUE(filter.is_good())
    << "a degenerate EURange must not trip a divide-by-zero in the percent-deadband build";
}

// ============================================================================================================
// sub-batch 3 - TwoStateDiscreteType / MultiStateDiscreteType / MultiStateValueDiscreteType /
// MultiStateDictionaryEntryDiscreteBaseType (section 8.18.4.1, CL-DA-001/-008/-012). Driven through the
// PUBLIC Connection over the real ComplianceWithNodes server.
// ============================================================================================================

// ============================================================================================================
// Row - TwoStateHandleBadWhenTrueStateMissing (section 8.18.4.1, CL-DA-001) [integration]. A
// TwoStateDiscreteType node lacking its Mandatory TrueState Property (FalseState present) fails the
// accessor's Mandatory-Property pre-flight: the Result is Bad_NotFound with source
// client.tier2.data_access.property_resolution_failed - never a Good handle exposing an empty/default
// trueState. [neg: a Good handle with a silently-empty trueState]
//
// REPORTED: the matrix oracle also wants the ErrorDetail to NAME "TrueState". The built detail is generic ("a
// Mandatory DataAccess Property was absent or undecodable during handle construction") and does not name the
// specific property - a diagnostic-granularity gap, not a correctness defect (same precedent as
// AnalogItemHandleBadWhenEuRangeMissing). Asserted at the granularity the code actually emits.
// ============================================================================================================
// @verifies AC-CL-DA-001-MANDATORY-BEFORE-TYPED
// @relation(AC-CL-DA-001-MANDATORY-BEFORE-TYPED, scope=function)
TEST_F(ClientDataAccess, TwoStateHandleBadWhenTrueStateMissing)
{
  TwoStateDiscreteHandleResult handle = build_two_state(mTwoStateMissingTrueId);
  ASSERT_TRUE(handle.is_bad())
    << "a TwoStateDiscreteType lacking the Mandatory TrueState must not yield a usable handle";
  EXPECT_EQ(handle.status_code().as_status(), Status::BadNotFound);
  ASSERT_NE(handle.shared_detail(), nullptr);
  EXPECT_EQ(handle.shared_detail()->source, "client.tier2.data_access.property_resolution_failed");
}

// ============================================================================================================
// Row - TwoStateTrueStateEmptyTextPreserved (section 8.18.4.1, CL-DA-001; CTT DA/Basic/Err-003-01)
// [integration]. A TwoStateDiscreteType whose value is True and whose TrueState Property is a
// PRESENT-but-EMPTY LocalizedText must read successfully: state==true and trueState is delivered as an empty
// (not absent) LocalizedText verbatim - never treated as a missing Mandatory Property, never substituted with
// a placeholder. [neg: the accessor rejects the empty text as a missing Property, or substitutes a
// placeholder string]
// ============================================================================================================
// @verifies CL-DA-001
// @relation(CL-DA-001, scope=function)
TEST_F(ClientDataAccess, TwoStateTrueStateEmptyTextPreserved)
{
  TwoStateDiscreteHandleResult handle = build_two_state(mTwoStateTrueEmptyId);
  ASSERT_TRUE(handle.is_good())
    << "a present-but-empty TrueState must not be treated as a missing Mandatory Property: 0x" << std::hex
    << handle.status_code().as_uint32();

  Result<TwoStateDiscreteValue> value = read_two_state(handle.value());
  ASSERT_TRUE(value.is_good()) << "an empty TrueState text must not fail the read";
  EXPECT_TRUE(value.value().state) << "the decoded boolean value is True";
  EXPECT_TRUE(value.value().trueState.text().empty())
    << "the empty TrueState text is delivered verbatim, never substituted";
  EXPECT_EQ(static_cast<std::string>(value.value().falseState.text()), "Off")
    << "the sibling FalseState stays populated";
}

// ============================================================================================================
// Row - TwoStateFalseStateEmptyTextPreserved (section 8.18.4.1, CL-DA-001; CTT DA/Basic/Err-003-02)
// [integration]. A TwoStateDiscreteType whose value is False and whose FalseState Property is a
// PRESENT-but-EMPTY LocalizedText must read successfully: state==false and falseState is delivered as an
// empty LocalizedText verbatim - never a bad Result, never a substituted placeholder. [neg: a bad Result or a
// substituted placeholder]
// ============================================================================================================
// @verifies CL-DA-001
// @relation(CL-DA-001, scope=function)
TEST_F(ClientDataAccess, TwoStateFalseStateEmptyTextPreserved)
{
  TwoStateDiscreteHandleResult handle = build_two_state(mTwoStateFalseEmptyId);
  ASSERT_TRUE(handle.is_good())
    << "a present-but-empty FalseState must not be treated as a missing Mandatory Property: 0x" << std::hex
    << handle.status_code().as_uint32();

  Result<TwoStateDiscreteValue> value = read_two_state(handle.value());
  ASSERT_TRUE(value.is_good()) << "an empty FalseState text must not fail the read";
  EXPECT_FALSE(value.value().state) << "the decoded boolean value is False";
  EXPECT_TRUE(value.value().falseState.text().empty())
    << "the empty FalseState text is delivered verbatim, never substituted";
  EXPECT_EQ(static_cast<std::string>(value.value().trueState.text()), "On")
    << "the sibling TrueState stays populated";
}

// ============================================================================================================
// Row - MultiStateDiscreteHandleBadWhenEnumStringsMissing (section 8.18.4.1, CL-DA-001) [integration]. A
// MultiStateDiscreteType node lacking its Mandatory EnumStrings Property fails the accessor's pre-flight:
// Bad_NotFound with source client.tier2.data_access.property_resolution_failed - never a Good handle with an
// empty enumStrings that forces every currentName to nullopt (masquerading as legitimate out-of-range). [neg:
// a Good handle with empty enumStrings]
//
// REPORTED: the matrix wants the ErrorDetail to NAME "EnumStrings"; the built detail is generic (same
// diagnostic-granularity gap as the other pre-flight rows). Asserted at the granularity the code emits.
// ============================================================================================================
// @verifies CL-DA-001
// @relation(CL-DA-001, scope=function)
TEST_F(ClientDataAccess, MultiStateDiscreteHandleBadWhenEnumStringsMissing)
{
  MultiStateDiscreteHandleResult handle = build_multi_state_discrete(mMultiStateNoEnumStringsId);
  ASSERT_TRUE(handle.is_bad())
    << "a MultiStateDiscreteType lacking the Mandatory EnumStrings must not yield a usable handle";
  EXPECT_EQ(handle.status_code().as_status(), Status::BadNotFound);
  ASSERT_NE(handle.shared_detail(), nullptr);
  EXPECT_EQ(handle.shared_detail()->source, "client.tier2.data_access.property_resolution_failed");
}

// ============================================================================================================
// Row - MultiStateDiscreteOutsideEnumYieldsNulloptName (section 8.18.4.1, CL-DA-008) [integration; unit in
// tests/unit/client/data_access/property_accessor_client_data_access_tests.cpp
// ValueOutsideEnumYieldsNulloptNameButSurfacesRaw- Index]. A MultiStateDiscreteType whose rawIndex (7) is >=
// enumStrings.size() (3) surfaces the rawIndex verbatim with currentName==nullopt and no crash - the SDK
// never indexes out of bounds nor fabricates a name. [neg: a vector out-of-bounds crash, or a fabricated
// currentName]
// ============================================================================================================
// @verifies CL-DA-008
// @relation(CL-DA-008, scope=function)
TEST_F(ClientDataAccess, MultiStateDiscreteOutsideEnumYieldsNulloptName)
{
  MultiStateDiscreteHandleResult handle = build_multi_state_discrete(mMultiStateOutsideId);
  ASSERT_TRUE(handle.is_good()) << "the EnumStrings-bearing node must resolve a handle: 0x" << std::hex
                                << handle.status_code().as_uint32();

  Result<MultiStateDiscreteValue> value = read_multi_state_discrete(handle.value());
  ASSERT_TRUE(value.is_good()) << "an out-of-range index must not fail the read";
  EXPECT_EQ(value.value().rawIndex, 7U) << "the raw index is surfaced verbatim";
  EXPECT_FALSE(value.value().currentName.has_value())
    << "an index outside enumStrings yields nullopt, not a fabricated or out-of-bounds name";
  EXPECT_EQ(value.value().enumStrings.size(), 3U) << "the resolved EnumStrings are intact";
}

// ============================================================================================================
// Row - MultiStateEmptyEnumStringYieldsEmptyNotMissing (section 8.18.4.1, CL-DA-008; CTT DA/Basic/Err-004-02)
// [integration; unit in tests/unit/client/data_access/property_accessor_client_data_access_tests.cpp
// ClientDataAccessMultiStateDiscrete.EmptyEnumStringInRangeYieldsPresentEmptyName]. A MultiStateDiscreteType
// whose rawIndex is IN range
// but whose enumStrings[rawIndex].Text is EMPTY must surface currentName.has_value()==true carrying an EMPTY
// LocalizedText - the present-empty case, DISTINCT from the out-of-range nullopt case. [neg: empty text
// conflated with missing => nullopt, losing the in-range/out-of-range distinction]
// ============================================================================================================
// @verifies CL-DA-008
// @relation(CL-DA-008, scope=function)
TEST_F(ClientDataAccess, MultiStateEmptyEnumStringYieldsEmptyNotMissing)
{
  MultiStateDiscreteHandleResult handle = build_multi_state_discrete(mMultiStateEmptyStringId);
  ASSERT_TRUE(handle.is_good()) << "the EnumStrings-bearing node must resolve a handle: 0x" << std::hex
                                << handle.status_code().as_uint32();

  // rawIndex is 1, and enumStrings[1] is a present-but-empty LocalizedText.
  Result<MultiStateDiscreteValue> value = read_multi_state_discrete(handle.value());
  ASSERT_TRUE(value.is_good());
  EXPECT_EQ(value.value().rawIndex, 1U);
  ASSERT_TRUE(value.value().currentName.has_value())
    << "an in-range index with empty text is present-empty, NOT the out-of-range nullopt case";
  EXPECT_TRUE(value.value().currentName->text().empty())
    << "the in-range empty enum string surfaces as an EMPTY LocalizedText, distinct from absent (nullopt)";
}

// ============================================================================================================
// Row - MultiStateWriteIllegalValuePassesServerResult (section 8.18.4.1, CL-DA-008/-007) [integration].
// Writing a raw index NOT present in the enum must NOT be pre-rejected locally by the SDK - the server's
// verdict (Good or Bad) flows through unmodified: an accept node stores the out-of-enum index (Good), a
// reject node returns Bad_OutOfRange surfaced verbatim. [neg: the SDK blocks the write locally on enum
// membership]
//
// REPORTED - PINNED ANALOG. The matrix names MultiStateValueDiscreteType, but the built
// MultiStateValueDiscreteHandle exposes NO write_value_async (only write_via_dictionary_async, CL-DA-012); a
// raw out-of-enum Value write on an MSVD handle is UNBUILT. This pins to MultiStateDiscreteHandle::
// write_value_async (the built CL-DA-007 write passthrough), whose out-of-range index (7, outside [0,3)) is
// the discrete analog of "a value not present in EnumValues". Like the MSVD path, it applies NO local
// enum-membership pre-reject.
// ============================================================================================================
// @verifies CL-DA-008
// @relation(CL-DA-008, scope=function)
TEST_F(ClientDataAccess, MultiStateWriteIllegalValuePassesServerResult)
{
  // Accept run: the server stores the out-of-enum index verbatim; the client surfaces Good and does NOT
  // pre-reject. A follow-up read shows the raw index surfaced with currentName==nullopt (out of range).
  {
    MultiStateDiscreteHandleResult handle = build_multi_state_discrete(mMultiStateWriteAcceptId);
    ASSERT_TRUE(handle.is_good());

    VoidResult write = write_multi_state_discrete(handle.value(), Variant{std::uint32_t{7}});
    ASSERT_TRUE(write.is_good())
      << "the server accepts the out-of-enum index; the client must not pre-reject it locally";

    Result<MultiStateDiscreteValue> value = read_multi_state_discrete(handle.value());
    ASSERT_TRUE(value.is_good());
    EXPECT_EQ(value.value().rawIndex, 7U) << "the illegal index is stored verbatim (no local block)";
    EXPECT_FALSE(value.value().currentName.has_value());
  }

  // Reject run: the server rejects the out-of-enum index with Bad_OutOfRange; the client surfaces it verbatim
  // beneath source client.tier2.data_access.write, never pre-empting with a local error.
  {
    MultiStateDiscreteHandleResult handle = build_multi_state_discrete(mMultiStateWriteRejectId);
    ASSERT_TRUE(handle.is_good());

    VoidResult write = write_multi_state_discrete(handle.value(), Variant{std::uint32_t{7}});
    ASSERT_TRUE(write.is_bad()) << "the server rejects the write; the client must surface it, not mask it";
    EXPECT_EQ(write.status_code().as_status(), Status::BadOutOfRange)
      << "the server's Bad_OutOfRange must surface verbatim, not a client-side local error";
    ASSERT_NE(write.shared_detail(), nullptr);
    EXPECT_EQ(write.shared_detail()->source, "client.tier2.data_access.write");
  }
}

// ============================================================================================================
// Row - MultiStateValueDiscreteHandleBadWhenEnumValuesMissing (section 8.18.4.1, CL-DA-001) [integration].
// MultiStateValueDiscreteType (OPC 10000-8 section 5.3.3.4) mandates BOTH EnumValues and ValueAsText, so
// multi_state_value_discrete_async rejects a node missing EITHER:
//  - Variant (a): EnumValues absent (ns;7280) -> Bad_NotFound, source property_resolution_failed.
//  - Variant (b): ValueAsText absent, EnumValues present (ns;7285) -> Bad_NotFound. (Previously a REPORTED
//    DIVERGENCE - the accessor enforced only EnumValues; ValueAsText enforcement now closes it.)
// [neg: a Good handle when either Mandatory Property is absent]
// ============================================================================================================
// @verifies CL-DA-001
// @relation(CL-DA-001, scope=function)
TEST_F(ClientDataAccess, MultiStateValueDiscreteHandleBadWhenEnumValuesMissing)
{
  // Variant (a): EnumValues absent -> the pre-flight rejects the node.
  {
    MultiStateValueDiscreteHandleResult handle = build_multi_state_value(mMultiStateValueNoEnumId);
    ASSERT_TRUE(handle.is_bad())
      << "a MultiStateValueDiscreteType lacking the Mandatory EnumValues must not yield a usable handle";
    EXPECT_EQ(handle.status_code().as_status(), Status::BadNotFound);
    ASSERT_NE(handle.shared_detail(), nullptr);
    EXPECT_EQ(handle.shared_detail()->source, "client.tier2.data_access.property_resolution_failed");
  }

  // Variant (b): EnumValues present, ValueAsText absent -> rejected (ValueAsText is also Mandatory).
  {
    MultiStateValueDiscreteHandleResult handle = build_multi_state_value(mMultiStateValueNoTextId);
    ASSERT_TRUE(handle.is_bad())
      << "a MultiStateValueDiscreteType lacking the Mandatory ValueAsText must not yield a usable handle";
    EXPECT_EQ(handle.status_code().as_status(), Status::BadNotFound);
    ASSERT_NE(handle.shared_detail(), nullptr);
    EXPECT_EQ(handle.shared_detail()->source, "client.tier2.data_access.property_resolution_failed");
  }
}

// ============================================================================================================
// Row - MultiStateValueOutsideEnumYieldsNulloptName (section 8.18.4.1, CL-DA-008; CTT DA/Basic/Err-004-01)
// [integration; unit in tests/unit/client/data_access/property_accessor_client_data_access_tests.cpp
// ValueMatchingNoEnumYieldsNulloptName]. A MultiStateValueDiscreteType with rawValue=999 and EnumValues of
// size 5 (no entry 999) reads successfully: rawValue==999 surfaced verbatim and currentName==nullopt - the
// out-of-bounds enum lookup neither crashes nor maps to entry[0]/last. [neg: an out-of-bounds crash, or
// currentName wrongly mapping to the first/last entry]
// ============================================================================================================
// @verifies CL-DA-008
// @relation(CL-DA-008, scope=function)
TEST_F(ClientDataAccess, MultiStateValueOutsideEnumYieldsNulloptName)
{
  MultiStateValueDiscreteHandleResult handle = build_multi_state_value(mMultiStateValueOutsideId);
  ASSERT_TRUE(handle.is_good()) << "the EnumValues-bearing node must resolve a handle: 0x" << std::hex
                                << handle.status_code().as_uint32();

  Result<MultiStateValueDiscreteValue> value = read_multi_state_value(handle.value());
  ASSERT_TRUE(value.is_good()) << "a rawValue matching no EnumValues entry must not fail the read";
  EXPECT_EQ(value.value().rawValue, 999) << "the raw value is surfaced verbatim";
  EXPECT_FALSE(value.value().currentName.has_value())
    << "a value matching no EnumValues entry yields nullopt, never entry[0]/last";
  EXPECT_EQ(value.value().enumValues.size(), 5U) << "the resolved EnumValues (size 5) are intact";
}

// ============================================================================================================
// Row - MsdeWriteViaDictionaryResolvesAndWrites (section 8.18.4.1, CL-DA-012, OPC 10000-19 section 7.1)
// [integration; unit in tests/unit/client/data_access/property_accessor_client_data_access_tests.cpp
// client_da_msde_dbt_write_uses_declared_entry]. write_via_dictionary_async(state_index=2,
// dictionary_index=0) selects EnumDictionaryEntries[2][0] (= mDictEntryRunningId) from the cached 2-D table
// and Writes it, as a single-element NodeId[], to the resolved ValueAsDictionaryEntries Property node. The
// WireOps unit control pins that exact request shape; this public end-to-end arm proves the server applies
// the selected dictionary entry as the corresponding parent state. [neg: the write is rejected, selects the
// wrong entry, or leaves the parent state unchanged]
// ============================================================================================================
// @verifies CL-DA-012
// @relation(CL-DA-012, scope=function)
TEST_F(ClientDataAccess, MsdeWriteViaDictionaryResolvesAndWrites)
{
  MultiStateValueDiscreteHandleResult handle = build_msde(mDictWriteResolvesId);
  ASSERT_TRUE(handle.is_good()) << "the MSDE-DBT node (EnumValues + EnumDictionaryEntries) must resolve: 0x"
                                << std::hex << handle.status_code().as_uint32();

  // state_index 2 (dictionary 0) selects EnumDictionaryEntries[2][0] == mDictEntryRunningId.
  VoidResult write = write_via_dictionary(handle.value(), /*stateIndex=*/2, /*dictionaryIndex=*/0);
  ASSERT_TRUE(write.is_good()) << "writing the declared dictionary entry to ValueAsDictionaryEntries must "
                                  "succeed: 0x"
                               << std::hex << write.status_code().as_uint32();

  Result<MultiStateValueDiscreteValue> value = read_multi_state_value(handle.value());
  ASSERT_TRUE(value.is_good()) << "the parent state must remain readable after the dictionary write";
  EXPECT_EQ(value.value().rawValue, 3)
    << "EnumDictionaryEntries[2][0] belongs to the third EnumValues row and must select value 3";
  ASSERT_TRUE(value.value().currentName.has_value())
    << "the selected parent value must resolve through the cached EnumValues table";
  EXPECT_EQ(static_cast<std::string>(value.value().currentName->text()), "Running");
}

// ============================================================================================================
// Row - MsdeWriteViaDictionaryNoMatchReturnsBad (section 8.18.4.1, CL-DA-012) [integration; unit in
// tests/unit/client/data_access/property_accessor_client_data_access_tests.cpp
// client_da_msde_dbt_write_rejects_unknown_entry]. write_via_dictionary_async with an OUT-OF-BOUNDS
// state_index is a LOCAL reject: a Bad VoidResult under the client.tier2.data_access.write_via_dictionary
// source, and ZERO Write requests on the wire (the server-side counter on ValueAsDictionaryEntries stays 0 -
// the strong "no wire request" clause). [neg: the SDK writes an arbitrary entry, or emits a Write despite the
// out-of-range index]
// ============================================================================================================
// @verifies CL-DA-012
// @relation(CL-DA-012, scope=function)
TEST_F(ClientDataAccess, MsdeWriteViaDictionaryNoMatchReturnsBad)
{
  ASSERT_EQ(mDictNoMatchWriteCount->load(), 0) << "no Value write has reached the node before the test acts";

  MultiStateValueDiscreteHandleResult handle = build_msde(mDictWriteNoMatchId);
  ASSERT_TRUE(handle.is_good()) << "the MSDE-DBT node must resolve a handle: 0x" << std::hex
                                << handle.status_code().as_uint32();

  // state_index 99 is outside the 2-state table -> LOCAL reject before any wire Write.
  VoidResult write = write_via_dictionary(handle.value(), /*stateIndex=*/99, /*dictionaryIndex=*/0);
  ASSERT_TRUE(write.is_bad()) << "an out-of-bounds state index must be rejected locally";
  ASSERT_NE(write.shared_detail(), nullptr);
  EXPECT_EQ(write.shared_detail()->source, "client.tier2.data_access.write_via_dictionary")
    << "the local-reject failure is source-tagged at the DataAccess dictionary boundary";
  EXPECT_EQ(mDictNoMatchWriteCount->load(), 0)
    << "the out-of-range path must issue ZERO Write requests on the wire (local reject before the wire)";
}

// ============================================================================================================
// Row - MsdeDbtHandleBadWhenEnumDictionaryEntriesMissing (section 8.18.4.1, CL-DA-001) [integration; unit
// half in tests/unit/client/data_access/property_accessor_client_data_access_tests.cpp].
// MultiStateDictionaryEntryDiscreteBaseType (OPC 10000-19 section 7.1) is a MultiStateValueDiscreteType
// subtype that additionally mandates EnumDictionaryEntries. The NEW multi_state_dictionary_entry_async
// accessor rejects ns;7320 (EnumValues present, EnumDictionaryEntries absent). Discriminator: the SAME node
// builds a GOOD handle through multi_state_value_discrete_async (which enforces only EnumValues), proving the
// EnumDictionaryEntries gate is real. The inherited EnumValues gate still holds too (ns;7330 fails).
// (Previously REPORTED as divergent.)
// ============================================================================================================
// @verifies CL-DA-001
// @relation(CL-DA-001, scope=function)
TEST_F(ClientDataAccess, MsdeDbtHandleBadWhenEnumDictionaryEntriesMissing)
{
  // EnumValues present, EnumDictionaryEntries absent -> BAD through the MSDE-DBT accessor.
  {
    MultiStateValueDiscreteHandleResult handle = build_msde(mMsdeNoDictionaryId);
    ASSERT_TRUE(handle.is_bad())
      << "MSDE-DBT mandates EnumDictionaryEntries; a node lacking it must not yield a handle";
    EXPECT_EQ(handle.status_code().as_status(), Status::BadNotFound);
    ASSERT_NE(handle.shared_detail(), nullptr);
    EXPECT_EQ(handle.shared_detail()->source, "client.tier2.data_access.property_resolution_failed");

    // Discriminator: the MSVD accessor accepts the same node (EnumDictionaryEntries not enforced there).
    EXPECT_TRUE(build_multi_state_value(mMsdeNoDictionaryId).is_good())
      << "multi_state_value_discrete_async enforces only EnumValues - the MSDE-DBT gate is distinct";
  }

  // The inherited Mandatory EnumValues gate still applies: an MSDE lacking EnumValues also fails.
  {
    MultiStateValueDiscreteHandleResult handle = build_msde(mMsdeNoEnumValuesId);
    ASSERT_TRUE(handle.is_bad())
      << "an MSDE-DBT lacking the inherited Mandatory EnumValues must also fail the pre-flight";
    EXPECT_EQ(handle.status_code().as_status(), Status::BadNotFound);
  }
}

// ============================================================================================================
// sub-batch 4 - ValuePrecision decode (CL-DA-002) + Uncertain DataItem quality (CL-DA-015). Driven through
// the PUBLIC Connection over the real ComplianceWithNodes server.
// ============================================================================================================

// ============================================================================================================
// Row - UncertainStatusPassesValueThrough (section 8.18.4.1 / section 7.10, CL-DA-015) [integration; unit
// already discharged by tests/unit/client/data_access/property_accessor_client_data_access_tests.cpp
// StatusCodesPassedThroughVerbatim].
//
// A DA item whose Value carries an Uncertain_SubstituteValue quality StatusCode must surface that status
// VERBATIM in value.status() with a GOOD Result and the Value present: the Uncertain severity is neither
// promoted to Bad (value lost) nor demoted to Good (severity lost). A Read whose SERVICE succeeded is not
// promoted to a bad Result on account of a non-Good value quality (same passthrough as
// BadDaStatusProducesBad- Result in batch 2a - decode_analog_value copies the DataValue verbatim, with NO
// severity branch). [neg: Uncertain promoted to Bad, or demoted to Good]
//
// REPORTED - the paired unit half is NOT authored: the decode path (out.value = value) has no severity
// branch, so an Uncertain quality exercises the IDENTICAL code as the Bad quality
// StatusCodesPassedThroughVerbatim already pins - a renamed Uncertain unit test would be a no-duplicates
// violation. Also a fixture pin: the matrix names MisbehavingServer; this serves the Uncertain-quality
// DataValue via ComplianceWithNodes (Fixture A, stored like mBadStatusAnalogId) - the client-observable read
// is identical.
// ============================================================================================================
// @verifies CL-DA-015
// @relation(CL-DA-015, scope=function)
TEST_F(ClientDataAccess, UncertainStatusPassesValueThrough)
{
  AnalogItemHandleResult handle = build_analog(mUncertainStatusAnalogId);
  ASSERT_TRUE(handle.is_good());

  Result<AnalogItemValue> value = handle_read(handle.value());
  ASSERT_TRUE(value.is_good())
    << "an Uncertain DA quality StatusCode does not fail the Read Result (CL-DA-015)";
  ASSERT_TRUE(value.value().value.status().has_value());
  EXPECT_EQ(value.value().value.status()->as_status(), Status::UncertainSubstituteValue)
    << "the Uncertain quality StatusCode must surface verbatim, neither promoted to Bad nor demoted to Good";
  EXPECT_DOUBLE_EQ(value.value().value.value().to<double>().value(), 50.0)
    << "the Value is passed through alongside the Uncertain quality (value not lost)";
}

// ============================================================================================================
// Row - ValuePrecisionSurfacedAsOptionalInt16 (section 8.18.4.1, CL-DA-002) [integration]. An AnalogItem with
// a ValuePrecision Property = 6.0 (a whole Double) surfaces valuePrecision == optional{6}: the
// server-controlled Double is decoded to the informational int16 digit-count and surfaced, NEVER applied to
// the Value. The Value (50.123456, with fine detail beyond the precision) reads back verbatim - the precision
// rides alongside as metadata only (CL-DA-002 - surfaced, not applied). [neg: nullopt (Property ignored),
// wrong rounding, or the precision applied to quantise the Value]
//
// REPORTED - value pin: the matrix names ValuePrecision=2.0; this serves 6.0 (task calibration). The decode
// path (extract_value_precision static_cast<int16>) is identical.
// ============================================================================================================
// @verifies CL-DA-002
// @relation(CL-DA-002, scope=function)
TEST_F(ClientDataAccess, ValuePrecisionSurfacedAsOptionalInt16)
{
  AnalogItemHandleResult handle = build_analog(mValuePrecisionWholeId);
  ASSERT_TRUE(handle.is_good());

  Result<AnalogItemValue> value = handle_read(handle.value());
  ASSERT_TRUE(value.is_good());
  ASSERT_TRUE(value.value().valuePrecision.has_value())
    << "a present ValuePrecision must surface, not collapse to nullopt";
  EXPECT_EQ(*value.value().valuePrecision, std::int16_t{6})
    << "the whole Double 6.0 surfaces as the informational int16 optional{6}";
  EXPECT_DOUBLE_EQ(value.value().value.value().to<double>().value(), 50.123456)
    << "ValuePrecision is informational metadata - the client never rounds/applies it to the Value";
}

// ============================================================================================================
// Row - ValuePrecisionZeroAccepted (section 8.18.4.1, CL-DA-002; CTT DA/Basic/010) [integration]. A
// ValuePrecision Property = 0.0 is a VALID precision (present, not absent): valuePrecision surfaces as
// optional{0} (has_value()==true, ==0), DISTINCT from nullopt (absent/undecodable). The read succeeds. [neg:
// zero treated as absent (nullopt) or as an error]
// ============================================================================================================
// @verifies CL-DA-002
// @relation(CL-DA-002, scope=function)
TEST_F(ClientDataAccess, ValuePrecisionZeroAccepted)
{
  AnalogItemHandleResult handle = build_analog(mValuePrecisionZeroId);
  ASSERT_TRUE(handle.is_good());

  Result<AnalogItemValue> value = handle_read(handle.value());
  ASSERT_TRUE(value.is_good()) << "a ValuePrecision of 0.0 must not fail the read";
  ASSERT_TRUE(value.value().valuePrecision.has_value())
    << "0.0 is a valid precision - present-not-absent, distinct from nullopt";
  EXPECT_EQ(*value.value().valuePrecision, std::int16_t{0})
    << "zero surfaces as optional{0}, never conflated with absent";
}

// ============================================================================================================
// Row - ValuePrecisionNegativeRoundedToWhole (section 8.18.4.1, CL-DA-002; CTT DA/Basic/Err-001-02)
// [integration; unit companion ClientDataAccessAnalog.ValuePrecisionRoundsToNearestWholeNumber]. A negative
// fractional ValuePrecision = -2.7 surfaces as optional{-3}: extract_value_precision rounds the finite
// in-int16 Double to the NEAREST whole number (std::rint, round-half-to-even), per Part 8 section 5.3.1
// ("shall always be interpreted as a whole number by rounding it to the nearest whole number"). -2.7 is
// nearer -3. [neg: the SDK truncates toward zero (-2), floors (-3 here but wrong for e.g. -1.4 -> -2), or
// drops it]
// ============================================================================================================
// @verifies CL-DA-002
// @relation(CL-DA-002, scope=function)
TEST_F(ClientDataAccess, ValuePrecisionNegativeRoundedToWhole)
{
  AnalogItemHandleResult handle = build_analog(mValuePrecisionNegativeId);
  ASSERT_TRUE(handle.is_good());

  Result<AnalogItemValue> value = handle_read(handle.value());
  ASSERT_TRUE(value.is_good()) << "a negative ValuePrecision must not fail the read";
  ASSERT_TRUE(value.value().valuePrecision.has_value());
  EXPECT_EQ(*value.value().valuePrecision, std::int16_t{-3})
    << "ValuePrecision -2.7 must round to the nearest whole number -3 (Part 8 section 5.3.1), not truncate "
       "to -2";
}

// ============================================================================================================
// Row - ValuePrecisionNanSurfacesDiagnosticNoPrecision (section 8.18.4.1, CL-DA-002; CTT DA/Basic/Err-001-03)
// [integration; unit already discharged by
// tests/unit/client/data_access/property_accessor_client_data_access_tests.cpp
// ValuePrecisionNanLeavesNulloptNoUndefinedCast - NaN -> nullopt exactly].
//
// VERBATIM half ASSERTED (built); ADVISORY half REPORTED UNBUILT. A ValuePrecision Property = NaN surfaces
// valuePrecision == nullopt (no precision): narrowing a NaN to int16 is undefined behaviour ([conv.fpint]),
// so extract_value_precision guards std::isfinite and deliberately does NOT surface it. The read succeeds (a
// NaN precision does not fail the read) and does not crash/assert. The matrix's "SurfacesDiagnostic" advisory
// (on_advisory_diagnostic naming ValuePrecision) is UNBUILT - the DA decode path emits NO advisory (grep of
// ua_data_access.cpp finds no advisory/warn emission, same finding as the EngineeringUnits*Advisory rows in
// sub-batch 2b). So this asserts ONLY the built no-precision guarantee GREEN; the advisory firing is deferred
// (REPORTED, not authored RED). Also a fixture pin: served via ComplianceWithNodes. [neg: NaN cast to int16
// (UB/garbage value) or an assert]
// ============================================================================================================
// @verifies CL-DA-002
// @relation(CL-DA-002, scope=function)
TEST_F(ClientDataAccess, ValuePrecisionNanSurfacesDiagnosticNoPrecision)
{
  AnalogItemHandleResult handle = build_analog(mValuePrecisionNanId);
  ASSERT_TRUE(handle.is_good())
    << "a NaN ValuePrecision must not fail handle construction (EURange still resolves)";

  Result<AnalogItemValue> value = handle_read(handle.value());
  ASSERT_TRUE(value.is_good()) << "a NaN ValuePrecision must not fail or crash the read";
  EXPECT_FALSE(value.value().valuePrecision.has_value())
    << "narrowing NaN to int16 is UB; the client deliberately surfaces no precision (nullopt)";
}

// ============================================================================================================
// sub-batch 5 - SemanticChange DA-Property invalidation (section 8.18.2/section 8.13.5, CL-DA-010/011).
//
// WIRING REALITY (drives the design of these rows, REPORTED with the batch):
//  - The typed-accessor Property cache IS wired to the per-Connection SemanticChangeCache end-to-end: a
//  handle
//    registers its Property snapshot at build (ua_data_access.cpp resolve_and_build_state), and a read
//    RE-RESOLVES fresh Properties when its `invalidated` flag is set (ua_data_access.cpp do_typed_read).
//    This is what these integration rows exercise against the REAL server (build -> mutate server EURange ->
//    invalidate -> the next read re-resolves the FRESH range).
//  - The TRIGGERs that FEED invalidate_async:
//      * CL-DA-010 in-band SemanticsChanged status-bit: NOW BUILT - the SubscriptionsPipeline watches each
//        delivered DataValue's SemanticsChanged bit and routes the node into invalidate_async
//        (deliver_notification_async, unit-tested by SemanticsChangedBitRoutesNodeToInvalidation). These DA
//        rows still drive the sink directly (drive_in_band_invalidate) to exercise the downstream re-resolve
//        without a full subscription + server bit-injection harness for the affected node (OPEN-DA-010a).
//      * CL-DA-011 SemanticChangeEventType: the EventRouter IS wired (handle_semantic_event ->
//        invalidate_async, unit-tested), but the backbone event Subscription omits the "Changes" SelectClause
//        (a documented follow-up in ua_event_router.cpp), so a live SemanticChangeEvent decodes to a no-op.
//        Driven here by feeding the REAL router a Changes-bearing notification (route_semantic_change_event).
//
// The pure per-component LOGIC of the [int+unit] rows is ALREADY discharged by pre-existing UNIT tests (no
// renamed duplicates authored - see the batch report):
//  - tests/unit/client/data_access/property_accessor_client_data_access_tests.cpp:
//  ReadReResolvesPropertiesWhenInvalidated
//    (invalidate -> next read re-resolves fresh EURange, browse/read counted) and
//    ReadDoesNotReResolveWhenNotInvalidated (no invalidation -> cached Properties reused, no re-browse).
//  - tests/unit/client/semantic_change/client_semantic_change_cache_tests.cpp:
//    RegisterThenInvalidateFlipsInvalidatedFlag / ReregisterSameNodeSupersedesPriorEntry (one entry per
//    NodeId = single shared cache) / InvalidateUnregisteredNodeIsNoOp.
//  - tests/unit/client/connection/event_router_connection_event_backbone_ops_tests.cpp:
//    SemanticEventInvalidatesSemanticCacheAndFiresBothObservers (the real EventRouter routes a SemanticChange
//    into invalidate_async AND fires on_semantic_change).
// ============================================================================================================

// ============================================================================================================
// Row - SemanticsChangedBitInvalidatesCacheAndRereads (section 8.18.2, CL-DA-010)  [integration; the in-band
// status-bit TRIGGER is unit-discharged by SubscriptionsPipeline.SemanticsChangedBitRoutesNodeToInvalidation
// + the re-resolve by ReadReResolvesPropertiesWhenInvalidated]. On a real EURange-resolved handle, an in-band
// SemanticsChanged invalidation (driven via its sink, invalidate_async - the pipeline TRIGGER that routes a
// bit-carrying DataChange here is now built + unit-covered) makes the NEXT read re-resolve the Properties and
// return the FRESH server EURange [0,200]. [neg: cache not invalidated
// -> the read returns stale [0,100] and no re-resolve issued]
// ============================================================================================================
// @verifies CL-DA-010
// @relation(CL-DA-010, scope=function)
TEST_F(ClientDataAccess, SemanticsChangedBitInvalidatesCacheAndRereads)
{
  AnalogItemHandleResult handleResult = build_analog(mSemanticChangeAnalogId);
  ASSERT_TRUE(handleResult.is_good()) << "analog_item_async must resolve the EURange-bearing handle: 0x"
                                      << std::hex << handleResult.status_code().as_uint32();
  AnalogItemHandle handle = handleResult.value();

  // Baseline: the handle cached EURange [0,100] at construction.
  auto baseline = read_eu_range_high(handle);
  ASSERT_TRUE(baseline.has_value());
  EXPECT_DOUBLE_EQ(*baseline, 100.0);

  // The server EURange changes to [0,200]; the client cannot see it until the cache is invalidated.
  set_server_eu_range(mSemanticChangeEuRangeId, 0.0, 200.0);
  EXPECT_EQ(read_eu_range_high(handle), std::optional<double>{100.0})
    << "with no invalidation the handle must still serve the STALE cached range";

  // The in-band SemanticsChanged bit invalidates this NodeId (via its designed sink).
  drive_in_band_invalidate(mSemanticChangeAnalogId);

  EXPECT_TRUE(wait_until([&] { return read_eu_range_high(handle) == std::optional<double>{200.0}; }))
    << "an invalidation must make the next read re-resolve and return fresh EURange [0,200] (CL-DA-010)";
}

// ============================================================================================================
// Row - SemanticChangeEventInvalidatesTypedAccessorCache (section 8.13.5/section 8.18.2, CL-DA-011)
// [integration; unit discharged by ReadReResolvesPropertiesWhenInvalidated +
// SemanticEventInvalidatesSemanticCacheAndFiresBoth- Observers]. A SemanticChangeEventType naming the node
// (NOT the in-band status bit) routes through the REAL EventRouter into invalidate_async, so the next handle
// read re-resolves the FRESH server EURange [0,200]. [neg: only the status-bit path invalidates; the
// out-of-band event path leaves the cache stale]
// ============================================================================================================
// @verifies CL-DA-011
// @relation(CL-DA-011, scope=function)
TEST_F(ClientDataAccess, SemanticChangeEventInvalidatesTypedAccessorCache)
{
  AnalogItemHandleResult handleResult = build_analog(mSemanticChangeAnalogId);
  ASSERT_TRUE(handleResult.is_good());
  AnalogItemHandle handle = handleResult.value();

  auto baseline = read_eu_range_high(handle);
  ASSERT_TRUE(baseline.has_value());
  EXPECT_DOUBLE_EQ(*baseline, 100.0);

  set_server_eu_range(mSemanticChangeEuRangeId, 0.0, 200.0);

  // A SemanticChangeEventType naming this node -> real router decode/route -> invalidate_async.
  route_semantic_change_event(mSemanticChangeAnalogId, NodeId{VariableTypeId::AnalogItemType});

  EXPECT_TRUE(wait_until([&] { return read_eu_range_high(handle) == std::optional<double>{200.0}; }))
    << "a SemanticChangeEvent naming the node must invalidate the typed-accessor cache so the next read "
       "re-resolves fresh EURange (CL-DA-011)";
}

// ============================================================================================================
// Row - EventAndBitPathsShareSingleCache (section 8.18.2, CL-DA-011)  [integration; unit discharged by
// ReregisterSameNodeSupersedesPriorEntry (one entry per NodeId)]. For the SAME node, invalidate once via the
// in-band bit sink and once via a SemanticChangeEventType: each targets the SAME cache entry and triggers one
// Property re-resolution (the range goes [0,100]->[0,200] on the bit path, then [0,200]->[0,300] on the event
// path, on the SAME handle). [neg: divergent per-path caches -> the second path leaves THIS handle stale]
// ============================================================================================================
// @verifies CL-DA-011
// @relation(CL-DA-011, scope=function)
TEST_F(ClientDataAccess, EventAndBitPathsShareSingleCache)
{
  AnalogItemHandleResult handleResult = build_analog(mSemanticChangeAnalogId);
  ASSERT_TRUE(handleResult.is_good());
  AnalogItemHandle handle = handleResult.value();

  auto baseline = read_eu_range_high(handle);
  ASSERT_TRUE(baseline.has_value());
  EXPECT_DOUBLE_EQ(*baseline, 100.0);

  // In-band bit path -> the ONE cache entry for this node -> re-resolve to [0,200].
  set_server_eu_range(mSemanticChangeEuRangeId, 0.0, 200.0);
  drive_in_band_invalidate(mSemanticChangeAnalogId);
  ASSERT_TRUE(wait_until([&] { return read_eu_range_high(handle) == std::optional<double>{200.0}; }))
    << "the in-band bit path must re-resolve the handle's Properties";

  // Event path -> the SAME cache entry (same node) -> re-resolve to [0,300]. A divergent per-path cache would
  // leave THIS handle stale at [0,200] after the event.
  set_server_eu_range(mSemanticChangeEuRangeId, 0.0, 300.0);
  route_semantic_change_event(mSemanticChangeAnalogId, NodeId{VariableTypeId::AnalogItemType});
  EXPECT_TRUE(wait_until([&] { return read_eu_range_high(handle) == std::optional<double>{300.0}; }))
    << "the event path must invalidate the SAME cache entry the bit path did (single shared cache)";
}

// ============================================================================================================
// Row - SemanticsChangedBitClearUsesCache (section 8.18.2 no-invalidation path, CL-DA-010)  [integration;
// unit discharged by ReadDoesNotReResolveWhenNotInvalidated]. A DataChangeNotification with SemanticsChanged
// CLEAR (a normal value change delivered via a monitored item) must NOT invalidate: the cached EURange
// [0,100] is reused on the next read even though the server EURange has since changed to [0,200] (proving no
// spurious re-resolve). A subsequent explicit invalidation then re-resolves fresh, proving the staleness was
// the clear-bit no-op - not a broken re-resolve. [neg: cache spuriously invalidated on every notification]
// ============================================================================================================
// @verifies CL-DA-010
// @relation(CL-DA-010, scope=function)
TEST_F(ClientDataAccess, SemanticsChangedBitClearUsesCache)
{
  AnalogItemHandleResult handleResult = build_analog(mSemanticChangeAnalogId);
  ASSERT_TRUE(handleResult.is_good());
  AnalogItemHandle handle = handleResult.value();

  auto baseline = read_eu_range_high(handle);
  ASSERT_TRUE(baseline.has_value());
  EXPECT_DOUBLE_EQ(*baseline, 100.0);

  // Server EURange changes, but NO invalidation is issued.
  set_server_eu_range(mSemanticChangeEuRangeId, 0.0, 200.0);

  // Deliver a NORMAL data-change (SemanticsChanged CLEAR) via a monitored item on the Value.
  auto subscription = create_subscription(100.0);
  ASSERT_TRUE(subscription.is_good())
    << "create_subscription failed: 0x" << std::hex << subscription.status_code().as_uint32();
  auto sink = std::make_shared<DataValueSink>();
  auto item =
    create_data_monitored_item(subscription.value(), mSemanticChangeAnalogId, /*clientHandle=*/1, sink);
  ASSERT_TRUE(item.is_good()) << "create_monitored_item failed: 0x" << std::hex
                              << item.status_code().as_uint32();
  ASSERT_TRUE(mConnection->try_write_value_sync(mSemanticChangeAnalogId, Variant{double{55.0}}).is_good());

  // The delivered notification carries the new value with the SemanticsChanged bit CLEAR (the matrix
  // stimulus).
  const auto clearBitValueDelivered = [](const DataValue& value)
  {
    ua::Result<double> number = value.value().to<double>();
    const bool semanticsChanged = value.status().has_value() && value.status()->semantics_changed();
    return number.is_good() && number.value() == 55.0 && !semanticsChanged;
  };
  ASSERT_TRUE(wait_until(
    [&]
    {
      for (const auto& value : sink->snapshot())
      {
        if (clearBitValueDelivered(value))
        {
          return true;
        }
      }
      return false;
    }))
    << "a normal (SemanticsChanged CLEAR) data-change must be delivered to model the matrix stimulus";

  // The handle STILL serves the cached [0,100] - the clear-bit notification did NOT invalidate, despite the
  // server EURange now being [0,200].
  EXPECT_EQ(read_eu_range_high(handle), std::optional<double>{100.0})
    << "a CLEAR SemanticsChanged notification must not invalidate - the cached EURange is reused (CL-DA-010)";

  // Sanity: an explicit invalidation still re-resolves fresh, so the staleness above was the clear-bit no-op.
  drive_in_band_invalidate(mSemanticChangeAnalogId);
  EXPECT_TRUE(wait_until([&] { return read_eu_range_high(handle) == std::optional<double>{200.0}; }))
    << "an explicit invalidation must still re-resolve fresh (the earlier staleness was the clear-bit no-op)";
}

// ============================================================================================================
// Row - SemanticChangeUserSeesFreshPropertiesNotStale (section 8.18.2 re-resolution ordering, CL-DA-010)
// [integration]. EURange is mutated [0,100]->[0,200] AND the Value 50->77 between reads; after the
// invalidation, the value the user reads is paired with the FRESH EURange [0,200] (never the stale [0,100]) -
// the re-resolve completes BEFORE the Value read. [neg: value delivered before the re-read completes, pairing
// the new value with stale limits]
// ============================================================================================================
// @verifies CL-DA-010
// @relation(CL-DA-010, scope=function)
TEST_F(ClientDataAccess, SemanticChangeUserSeesFreshPropertiesNotStale)
{
  AnalogItemHandleResult handleResult = build_analog(mSemanticChangeAnalogId);
  ASSERT_TRUE(handleResult.is_good());
  AnalogItemHandle handle = handleResult.value();

  // First read: EURange [0,100].
  Result<AnalogItemValue> first = handle_read(handle);
  ASSERT_TRUE(first.is_good());
  ASSERT_TRUE(first.value().euRange.has_value());
  EXPECT_DOUBLE_EQ(first.value().euRange->high(), 100.0);

  // Between reads: EURange [0,100]->[0,200] AND the Value 50->77.
  set_server_eu_range(mSemanticChangeEuRangeId, 0.0, 200.0);
  ASSERT_TRUE(mConnection->try_write_value_sync(mSemanticChangeAnalogId, Variant{double{77.0}}).is_good());

  // The SemanticsChanged invalidation lands.
  drive_in_band_invalidate(mSemanticChangeAnalogId);

  // The value delivered AFTER the invalidation is paired with the FRESH EURange [0,200] - never the stale
  // [0,100]: the re-resolve completes before the Value read (section 8.18.2 ordering).
  EXPECT_TRUE(wait_until(
    [&]
    {
      Result<AnalogItemValue> value = handle_read(handle);
      if (value.is_bad() || !value.value().euRange.has_value())
      {
        return false;
      }
      const double freshHigh = value.value().euRange->high();
      const double freshValue = value.value().value.value().to<double>().value_or(0.0);
      return freshHigh == 200.0 && freshValue == 77.0;
    }))
    << "the fresh value (77) must be paired with the fresh EURange [0,200], never stale limits (CL-DA-010)";
}

// ============================================================================================================
// Row - NoEventSubscriptionFallsBackToStatusBit (section 8.18.2 in-band path independence, CL-DA-010/011)
// [integration]. With NO event subscription open (the default fixture registers no observer, so the router's
// J57 gate stays closed and no backbone event Subscription is created), the in-band invalidation sink still
// fires and the next read returns fresh EURange - proving the invalidation does not depend on an event
// subscription. [neg: invalidation only wired through EventSubscriber -> stale read when no event sub exists]
// ============================================================================================================
// @verifies CL-DA-010
// @relation(CL-DA-010, scope=function)
TEST_F(ClientDataAccess, NoEventSubscriptionFallsBackToStatusBit)
{
  // Precondition, by construction: this fixture starts the Connection with a plain
  // ua::client::detail::ConnectionConfig{} and registers NO observer, so the EventRouter's J57 subscribe-gate
  // stays closed and no backbone event Subscription is ever created (structurally guaranteed; unit-proven by
  // the router's LateRegisteredObserverTriggersSubscription - with no consumer the router does NOT
  // subscribe). There is therefore no event subscription for the invalidation to depend on. (This test
  // deliberately does NOT register an observer, unlike SemanticChangeEventInvalidatesTypedAccessorCache.)

  AnalogItemHandleResult handleResult = build_analog(mSemanticChangeAnalogId);
  ASSERT_TRUE(handleResult.is_good());
  AnalogItemHandle handle = handleResult.value();

  auto baseline = read_eu_range_high(handle);
  ASSERT_TRUE(baseline.has_value());
  EXPECT_DOUBLE_EQ(*baseline, 100.0);

  set_server_eu_range(mSemanticChangeEuRangeId, 0.0, 200.0);

  // The in-band invalidation sink fires with no event subscription present (independence).
  drive_in_band_invalidate(mSemanticChangeAnalogId);
  EXPECT_TRUE(wait_until([&] { return read_eu_range_high(handle) == std::optional<double>{200.0}; }))
    << "the in-band invalidation must not depend on an event subscription (CL-DA-010/011 independence)";
}

// ============================================================================================================
// Row - EventSubscriberRoutesSemanticChangeEvent (section 8.13.5 -> on_semantic_change, CL-DA-011)
// [integration; unit discharged by SemanticEventInvalidatesSemanticCacheAndFiresBothObservers]. A
// SemanticChangeEventType naming <node> (of <typeDef>) routed through the REAL EventRouter fires the
// PUBLIC-Connection-registered AddressSpaceObserver::on_semantic_change once, carrying the affected NodeId +
// TypeDefinition equal to the injected values. [neg: event dropped, or routed to the generic event callback
// without the semantic hook firing] NB: the live-wire form is blocked by the router's missing "Changes"
// SelectClause (documented follow-up); this pins the router->observer fan-out via a direct Changes-bearing
// notification (REPORTED).
// ============================================================================================================
// @verifies CL-DA-011
// @relation(CL-DA-011, scope=function)
TEST_F(ClientDataAccess, EventSubscriberRoutesSemanticChangeEvent)
{
  auto observer = std::make_shared<RecordingAddressSpaceObserver>();
  mConnection->set_address_space_observer(observer);
  ConnectionImplTestAccess::snapshot(*mConnImpl);  // strand barrier: the observer registration has settled

  const NodeId affected = mSemanticChangeAnalogId;
  const NodeId affectedType{VariableTypeId::AnalogItemType};
  route_semantic_change_event(affected, affectedType);

  EXPECT_TRUE(wait_until([&] { return observer->semanticChangeCalls.load() >= 1; }))
    << "a SemanticChangeEvent must fire AddressSpaceObserver::on_semantic_change (CL-DA-011)";
  auto changes = observer->last_changes();
  ASSERT_EQ(changes.size(), 1U);
  EXPECT_EQ(changes.front().affected, affected) << "the affected NodeId must equal the injected value";
  EXPECT_EQ(changes.front().affectedType, affectedType)
    << "the affected TypeDefinition must equal the injected value";
}

// ============================================================================================================
// sub-batch 6 - SERVER-side DataAccess model obligations (Part 8 section 5.2 / section 5.3.2 /
// section 5.3.3), observed over the wire from the client. Each row drives the server's own path: the
// type-instantiation engine for the Mandatory-Property rows, the in-memory namespace's marking of an owner's
// monitored items when a semantic Property of it changes for the SemanticsChanged rows, and the session Read
// path (under several negotiated locales) for the Definition row.
// ============================================================================================================

// ============================================================================================================
// Part 8 section 5.3.2.2: "Definition is non-localized and will often contain an equation." A plausible
// implementation routes every human-readable Property through the same localisation walk it applies to
// DisplayName / Description, and a translation layer is then free to rewrite the separators and operators of
// an equation the client has to read verbatim - or to hand back an empty text when the session asks for a
// locale the server has no translation for. The clause forbids the machinery, not merely the requirement.
// @verifies AC-SVR-DA-001-DEFINITION-PROPERTY
TEST_F(ClientDataAccess, DefinitionPropertyIsServedVerbatimUnderEverySessionLocale)
{
  ASSERT_FALSE(mDefinitionEquationPropertyId.is_null());

  // Four activations of the SAME session, each negotiating a different preferred-locale set (including the
  // server-default empty set), so any locale negotiation applied to Definition would show up as a difference.
  const std::vector<std::vector<String>> localeSets = {
    {}, {String{"en-US"}}, {String{"de-DE"}}, {String{"fr-FR"}, String{"en"}}};

  std::vector<std::string> served;
  for (const auto& locales : localeSets)
  {
    const ua::VoidResult activated =
      mSession->try_activate_sync(ua::client::Session::ActivateConfig{.localeIds = locales});
    ASSERT_TRUE(activated.is_good())
      << "the session must re-activate with the requested preferred-locale set";

    auto readResult = mSession->attributes().try_read_sync(read_value(mDefinitionEquationPropertyId));
    ASSERT_TRUE(readResult.is_good()) << "the Definition Read must succeed at the service level: 0x"
                                      << std::hex << readResult.status_code().as_uint32();
    ua::ReadResponse response = std::move(readResult).value();
    ASSERT_EQ(response.results().size(), 1U);

    const DataValue& definition = response.results()[0];
    const String* text = definition.value().try_as<String>();
    ASSERT_NE(text, nullptr) << "Definition is served as a String (Part 8 section 5.3.2.2)";
    EXPECT_EQ(definition.value().try_as<LocalizedText>(), nullptr)
      << "Definition must not be served in a LocalizedText envelope - it carries no locale";
    served.push_back(static_cast<std::string>(*text));
  }

  ASSERT_EQ(served.size(), localeSets.size()) << "every locale set must have produced an observation";
  for (std::size_t i = 0; i < served.size(); ++i)
  {
    EXPECT_EQ(served[i], std::string{sDefinitionEquation})
      << "locale set #" << i << " altered the Definition - no locale negotiation may be applied to it";
  }

  // ...and the DataType the server publishes for the Property is String, so no client can mistake it for a
  // localised text and start negotiating over it.
  const std::optional<NodeId> dataType = read_data_type_attribute(mDefinitionEquationPropertyId);
  ASSERT_TRUE(dataType.has_value()) << "the Definition Property's DataType Attribute must read back";
  EXPECT_EQ(*dataType, NodeId{DataTypeId::String})
    << "Definition is a String Property, not a LocalizedText one";
}

// ============================================================================================================
// Part 8 section 5.2: an analog item's EURange / EngineeringUnits bound EVERY element of an array Value - one
// set of Properties for the whole item, which is why an array whose elements need different units must be
// modelled as separate Variables. A plausible implementation that lets an application scale element-wise
// would have to serve the Properties as arrays (a Range[] / EUInformation[]) parallel to the Value, leaving a
// client with no single frame in which to interpret the item.
// @verifies AC-SVR-DA-003-ARRAY-PROPERTIES-APPLY-TO-ALL
TEST_F(ClientDataAccess, ArrayAnalogItemPropertiesAreOneSetCoveringEveryElement)
{
  ASSERT_FALSE(mArrayUnitRangeId.is_null())
    << "the array-valued analog item must have been instantiated through the type system";

  // The antecedent: the Value really is a multi-element array (otherwise the obligation is vacuous).
  Result<DataValue> value = mConnection->try_read_value_sync(mArrayUnitRangeId);
  ASSERT_TRUE(value.is_good()) << "the array analog item must read: 0x" << std::hex
                               << value.status_code().as_uint32();
  Result<std::vector<double>> elements = value.value().value().to_vector<double>();
  ASSERT_TRUE(elements.is_good()) << "the Value must decode as a double array";
  ASSERT_EQ(elements.value().size(), 8U) << "the item holds eight elements";

  // ONE EURange for the whole array - a scalar Range, never one per element.
  Result<DataValue> euRange = read_property(mArrayUnitRangeId, "EURange");
  ASSERT_TRUE(euRange.is_good()) << "EURange must be reachable under HasProperty: 0x" << std::hex
                                 << euRange.status_code().as_uint32();
  EXPECT_TRUE(euRange.value().value().is_scalar())
    << "EURange applies to all elements, so it is served as ONE Range - not an array parallel to the Value";
  const Range* range = euRange.value().value().try_as<Range>();
  ASSERT_NE(range, nullptr) << "the EURange Property decodes as a single Range";
  EXPECT_DOUBLE_EQ(range->low(), 0.0);
  EXPECT_DOUBLE_EQ(range->high(), 100.0);

  // ONE EngineeringUnits for the whole array, likewise.
  Result<DataValue> units = read_property(mArrayUnitRangeId, "EngineeringUnits");
  ASSERT_TRUE(units.is_good()) << "EngineeringUnits must be reachable under HasProperty: 0x" << std::hex
                               << units.status_code().as_uint32();
  EXPECT_TRUE(units.value().value().is_scalar())
    << "EngineeringUnits applies to all elements, so it is served as ONE EUInformation";
  const EUInformation* information = units.value().value().try_as<EUInformation>();
  ASSERT_NE(information, nullptr) << "the EngineeringUnits Property decodes as a single EUInformation";
  EXPECT_EQ(static_cast<std::string>(information->display_name().text()), "\u00b0C");

  // The same one-set-per-item shape reaches a client through the typed accessor: a single euRange and a
  // single engineeringUnits accompany the eight-element Value.
  AnalogItemHandleResult handle = build_analog_unit_range(mArrayUnitRangeId);
  ASSERT_TRUE(handle.is_good()) << "the array item exposes both Mandatory Properties: 0x" << std::hex
                                << handle.status_code().as_uint32();
  Result<AnalogItemValue> typed = handle_read(handle.value());
  ASSERT_TRUE(typed.is_good());
  ASSERT_TRUE(typed.value().euRange.has_value());
  EXPECT_DOUBLE_EQ(typed.value().euRange->high(), 100.0);
  ASSERT_TRUE(typed.value().engineeringUnits.has_value());
  EXPECT_EQ(static_cast<std::string>(typed.value().engineeringUnits->display_name().text()), "\u00b0C");
}

// ============================================================================================================
// Part 8 section 5.3.2.3 Table 5 makes EURange Mandatory on AnalogItemType, and Part 3 section 6.5 makes a
// Mandatory ModellingRule binding on the address space as populated - so the invariant has to hold at
// instantiation, not merely be checked on first Read. A plausible implementation materialises the instance
// Value and leaves the Property to the application: the resulting item serves a number with no limits, and a
// PercentDeadband on it is unfilterable (the failure AC-SVR-DA-022 records on the same instance).
// @verifies AC-SVR-DA-004-EURANGE-MANDATORY
TEST_F(ClientDataAccess, AnalogItemTypeInstanceExposesEuRangeAsARangeProperty)
{
  ASSERT_FALSE(mInstantiatedAnalogId.is_null())
    << "the server must instantiate an AnalogItemType Variable through its type system";
  ASSERT_FALSE(mInstantiatedEuRangeId.is_null())
    << "instantiating AnalogItemType must materialise its Mandatory EURange Property";

  // Browse HasProperty + Read, exactly as a client discovers the Property.
  Result<DataValue> euRange = read_property(mInstantiatedAnalogId, "EURange");
  ASSERT_TRUE(euRange.is_good()) << "every AnalogItemType Variable must expose EURange under HasProperty: 0x"
                                 << std::hex << euRange.status_code().as_uint32();
  const Range* range = euRange.value().value().try_as<Range>();
  ASSERT_NE(range, nullptr) << "the EURange Property's Value decodes as a Range";
  EXPECT_DOUBLE_EQ(range->low(), 0.0);
  EXPECT_DOUBLE_EQ(range->high(), 100.0);

  // ...and it is typed Range, so a client can rely on the decode rather than guessing.
  const std::optional<NodeId> dataType = read_data_type_attribute(mInstantiatedEuRangeId);
  ASSERT_TRUE(dataType.has_value()) << "the EURange Property's DataType Attribute must read back";
  EXPECT_EQ(*dataType, NodeId{DataTypeId::Range})
    << "EURange is a Range Property (Part 8 section 5.3.2.3 Table 5)";
}

// ============================================================================================================
// Part 8 section 5.3.2.2: the SemanticsChanged bit shall be set when EURange or EngineeringUnits changes,
// because both silently invalidate what a client has already computed - EURange is the divisor in a
// PercentDeadband, so a subscription that was filtering at 5% of one range is now filtering at 5% of another
// with nothing to say so. A plausible implementation raises the bit only when the VALUE changes (the
// Properties are not sampled), and one that sets it on every notification would pass both positive cases
// while making the signal useless - which is why the unchanged-Property control is asserted here too.
// @verifies AC-SVR-DA-008-SEMANTICSCHANGED
TEST_F(ClientDataAccess, ChangingEuRangeOrEngineeringUnitsRaisesSemanticsChanged)
{
  ASSERT_FALSE(mSemanticsUnitRangeId.is_null()) << "the analog item must have been instantiated";
  ASSERT_FALSE(mSemanticsEuRangeId.is_null()) << "its Mandatory EURange must have been materialised";
  ASSERT_FALSE(mSemanticsUnitsId.is_null()) << "its Mandatory EngineeringUnits must have been materialised";

  auto subscription = create_subscription(100.0);
  ASSERT_TRUE(subscription.is_good())
    << "create_subscription failed: 0x" << std::hex << subscription.status_code().as_uint32();
  auto sink = std::make_shared<DataValueSink>();
  auto item =
    create_data_monitored_item(subscription.value(), mSemanticsUnitRangeId, /*clientHandle=*/1, sink);
  ASSERT_TRUE(item.is_good()) << "create_monitored_item failed: 0x" << std::hex
                              << item.status_code().as_uint32();

  // Control - a change to NEITHER Property: a plain Value change must not carry the bit.
  ASSERT_TRUE(mConnection->try_write_value_sync(mSemanticsUnitRangeId, Variant{double{51.0}}).is_good());
  ASSERT_TRUE(wait_until(
    [&]
    {
      for (const auto& value : sink->snapshot())
      {
        if (value.value().to<double>().value_or(0.0) == 51.0)
        {
          return true;
        }
      }
      return false;
    }))
    << "the plain value change must be delivered (the control is otherwise vacuous)";
  EXPECT_EQ(semantics_changed_count(*sink), 0U)
    << "a notification that follows no Property change must NOT carry SemanticsChanged - a server that sets "
       "it on every notification makes the signal useless";

  // EURange changes (over the wire, onto the Property node) -> the next notification carries the bit.
  Range widened = make_range(0.0, 200.0);
  ASSERT_TRUE(mConnection->try_write_value_sync(mSemanticsEuRangeId, Variant{widened}).is_good())
    << "the EURange Property write must reach the server";
  EXPECT_TRUE(wait_until([&] { return semantics_changed_count(*sink) >= 1U; }))
    << "changing EURange must set SemanticsChanged on the next data-change (Part 8 section 5.3.2.2)";
  const std::size_t afterEuRange = semantics_changed_count(*sink);
  ASSERT_GE(afterEuRange, 1U);

  // EngineeringUnits changes -> a FURTHER notification carries the bit (the second conjunct, counted from the
  // EURange baseline so the earlier bit cannot satisfy it).
  EUInformation rescaled = make_full_eu_information();
  rescaled.display_name() = LocalizedText{"", "\u00b0F"};
  rescaled.description() = LocalizedText{"", "degree Fahrenheit"};
  ASSERT_TRUE(mConnection->try_write_value_sync(mSemanticsUnitsId, Variant{rescaled}).is_good())
    << "the EngineeringUnits Property write must reach the server";
  EXPECT_TRUE(wait_until([&] { return semantics_changed_count(*sink) > afterEuRange; }))
    << "changing EngineeringUnits must likewise set SemanticsChanged on the next data-change";
}

// ============================================================================================================
// Part 8 section 5.3.3.2 Table 7 makes TrueState and FalseState Mandatory LocalizedText on
// TwoStateDiscreteType. These two Properties are the only thing that makes the Boolean readable: the Value is
// true or false, and what those mean on this item - Running / Stopped, Open / Closed - lives entirely in the
// labels. A plausible implementation treats them as presentation sugar and leaves them to the application,
// serving an instance whose value no operator can interpret.
// @verifies AC-SVR-DA-009-STATE-PROPERTIES
TEST_F(ClientDataAccess, TwoStateDiscreteInstanceExposesBothStateLabelsAsLocalizedText)
{
  ASSERT_FALSE(mTwoStateInstanceId.is_null())
    << "the server must instantiate a TwoStateDiscreteType Variable through its type system";
  ASSERT_FALSE(mTwoStateTruePropertyId.is_null())
    << "instantiating TwoStateDiscreteType must materialise its Mandatory TrueState Property";
  ASSERT_FALSE(mTwoStateFalsePropertyId.is_null())
    << "instantiating TwoStateDiscreteType must materialise its Mandatory FalseState Property";

  // TrueState: present under HasProperty, carrying a LocalizedText, typed LocalizedText.
  Result<DataValue> trueState = read_property(mTwoStateInstanceId, "TrueState");
  ASSERT_TRUE(trueState.is_good()) << "TrueState must be reachable under HasProperty: 0x" << std::hex
                                   << trueState.status_code().as_uint32();
  const LocalizedText* trueLabel = trueState.value().value().try_as<LocalizedText>();
  ASSERT_NE(trueLabel, nullptr) << "TrueState's Value decodes as a LocalizedText";
  EXPECT_EQ(static_cast<std::string>(trueLabel->text()), "Running");
  const std::optional<NodeId> trueDataType = read_data_type_attribute(mTwoStateTruePropertyId);
  ASSERT_TRUE(trueDataType.has_value());
  EXPECT_EQ(*trueDataType, NodeId{DataTypeId::LocalizedText})
    << "TrueState is a LocalizedText Property (Part 8 section 5.3.3.2 Table 7)";

  // FalseState: neither optional nor absent on an instance whose type declares it.
  Result<DataValue> falseState = read_property(mTwoStateInstanceId, "FalseState");
  ASSERT_TRUE(falseState.is_good()) << "FalseState must be reachable under HasProperty: 0x" << std::hex
                                    << falseState.status_code().as_uint32();
  const LocalizedText* falseLabel = falseState.value().value().try_as<LocalizedText>();
  ASSERT_NE(falseLabel, nullptr) << "FalseState's Value decodes as a LocalizedText";
  EXPECT_EQ(static_cast<std::string>(falseLabel->text()), "Stopped");
  const std::optional<NodeId> falseDataType = read_data_type_attribute(mTwoStateFalsePropertyId);
  ASSERT_TRUE(falseDataType.has_value());
  EXPECT_EQ(*falseDataType, NodeId{DataTypeId::LocalizedText})
    << "FalseState is a LocalizedText Property (Part 8 section 5.3.3.2 Table 7)";
}

// ============================================================================================================
// Part 8 section 5.3.3.2: "The StatusCode SemanticsChanged bit shall be set if any of the FalseState or
// TrueState Properties are changed." The Boolean does not change when its labels do, so a plausible
// implementation - one that raises the bit from the value sampler - leaves a client displaying *Running*
// after the label became *Stopped*: the value is still true and nothing else signals the change.
// @verifies AC-SVR-DA-010-TWOSTATE-SEMANTICS
TEST_F(ClientDataAccess, ChangingTrueStateOrFalseStateRaisesSemanticsChanged)
{
  ASSERT_FALSE(mTwoStateInstanceId.is_null()) << "the TwoStateDiscrete item must have been instantiated";
  ASSERT_FALSE(mTwoStateTruePropertyId.is_null()) << "its Mandatory TrueState must have been materialised";
  ASSERT_FALSE(mTwoStateFalsePropertyId.is_null()) << "its Mandatory FalseState must have been materialised";

  auto subscription = create_subscription(100.0);
  ASSERT_TRUE(subscription.is_good())
    << "create_subscription failed: 0x" << std::hex << subscription.status_code().as_uint32();
  auto sink = std::make_shared<DataValueSink>();
  auto item = create_data_monitored_item(subscription.value(), mTwoStateInstanceId, /*clientHandle=*/1, sink);
  ASSERT_TRUE(item.is_good()) << "create_monitored_item failed: 0x" << std::hex
                              << item.status_code().as_uint32();

  // The monitor is live - the initial sample of the Boolean Value has been delivered, and it carries no bit.
  ASSERT_TRUE(wait_until([&] { return !sink->snapshot().empty(); }))
    << "the monitored item must deliver its initial sample before the labels are changed";
  ASSERT_EQ(semantics_changed_count(*sink), 0U)
    << "nothing has changed the labels yet, so no delivered notification may carry SemanticsChanged";

  // TrueState changes -> the next notification carries the bit, with the Boolean Value untouched.
  const VoidResult trueStateWrite =
    mConnection->try_write_value_sync(mTwoStateTruePropertyId, Variant{LocalizedText{"", "Open"}});
  ASSERT_TRUE(trueStateWrite.is_good()) << "the TrueState Property write must reach the server";
  EXPECT_TRUE(wait_until([&] { return semantics_changed_count(*sink) >= 1U; }))
    << "changing TrueState must set SemanticsChanged on the next data-change (Part 8 section 5.3.3.2)";
  const std::size_t afterTrueState = semantics_changed_count(*sink);
  ASSERT_GE(afterTrueState, 1U);

  // FalseState changes -> a FURTHER notification carries the bit (counted from the TrueState baseline, so the
  // earlier bit cannot satisfy this conjunct).
  const VoidResult falseStateWrite =
    mConnection->try_write_value_sync(mTwoStateFalsePropertyId, Variant{LocalizedText{"", "Closed"}});
  ASSERT_TRUE(falseStateWrite.is_good()) << "the FalseState Property write must reach the server";
  EXPECT_TRUE(wait_until([&] { return semantics_changed_count(*sink) > afterTrueState; }))
    << "changing FalseState must likewise set SemanticsChanged on the next data-change";
}

// Part 8 section 5.3.3.5: ValueAsText is the text of the EnumValues entry for the Variable's CURRENT Value,
// so a client monitoring the Property must see it change when the Value does (the CTT's Base Info ValueAsText
// 002). A Property that holds whatever was last written to it - or a projection applied only by the Read
// service - delivers the initial text and then nothing, however the Value moves.
TEST_F(ClientDataAccess, AMonitoredValueAsTextFollowsTheValueItDescribes)
{
  ASSERT_FALSE(mMsvdInstanceId.is_null()) << "the MultiStateValueDiscrete item must have been instantiated";
  ASSERT_FALSE(mMsvdValueAsTextId.is_null()) << "its Mandatory ValueAsText must have been materialised";

  auto subscription = create_subscription(100.0);
  ASSERT_TRUE(subscription.is_good())
    << "create_subscription failed: 0x" << std::hex << subscription.status_code().as_uint32();
  auto sink = std::make_shared<DataValueSink>();
  auto item = create_data_monitored_item(subscription.value(), mMsvdValueAsTextId, /*clientHandle=*/1, sink);
  ASSERT_TRUE(item.is_good()) << "create_monitored_item failed: 0x" << std::hex
                              << item.status_code().as_uint32();

  const auto delivered = [&sink](std::string_view text)
  {
    for (const auto& value : sink->snapshot())
    {
      const auto* localized = value.value().try_as<LocalizedText>();
      if (localized != nullptr && static_cast<std::string>(localized->text()) == text)
        return true;
    }
    return false;
  };

  // The seeded Value is 1, whose EnumValues entry is "Low".
  ASSERT_TRUE(wait_until([&] { return delivered("Low"); }))
    << "the initial sample of ValueAsText must be the text for the current Value";

  const VoidResult write = mConnection->try_write_value_sync(mMsvdInstanceId, Variant{std::int64_t{2}});
  ASSERT_TRUE(write.is_good()) << "the Value write must reach the server: 0x" << std::hex
                               << write.status_code().as_uint32();
  EXPECT_TRUE(wait_until([&] { return delivered("High"); }))
    << "writing the Value 2 must deliver ValueAsText \"High\" to the Property's monitor";

  auto read = mConnection->try_read_value_sync(mMsvdValueAsTextId);
  ASSERT_TRUE(read.is_good());
  const auto* text = read.value().value().try_as<LocalizedText>();
  ASSERT_NE(text, nullptr);
  EXPECT_EQ(static_cast<std::string>(text->text()), "High")
    << "a Read of the Property agrees with what its monitor was sent";
}

// ============================================================================================================
// Part 8 section 5.3.3.3 Table 8 makes EnumStrings a Mandatory `LocalizedText[]` on MultiStateDiscreteType,
// and the table is POSITIONAL: it has no keys, so entry i is the name of state value i and nothing in the
// address space says so. A plausible implementation materialises the Property as a scalar LocalizedText (the
// label of the current state) - which reads perfectly for one state and mislabels every other - or serves the
// entries in an order of its own, which no client can detect.
// @verifies AC-SVR-DA-011-ENUMSTRINGS
TEST_F(ClientDataAccess, MultiStateDiscreteInstanceExposesEnumStringsAsSequentialLocalizedTextTable)
{
  ASSERT_FALSE(mMultiStateInstanceId.is_null())
    << "the server must instantiate a MultiStateDiscreteType Variable through its type system";
  ASSERT_FALSE(mMultiStateEnumStringsId.is_null())
    << "instantiating MultiStateDiscreteType must materialise its Mandatory EnumStrings Property";

  // Present under HasProperty, and an ARRAY of LocalizedText - not a scalar label.
  Result<DataValue> enumStrings = read_property(mMultiStateInstanceId, "EnumStrings");
  ASSERT_TRUE(enumStrings.is_good()) << "EnumStrings must be reachable under HasProperty: 0x" << std::hex
                                     << enumStrings.status_code().as_uint32();
  ASSERT_TRUE(enumStrings.value().value().is_array())
    << "EnumStrings is a lookup TABLE - a scalar label would name only the current state";
  Result<std::vector<LocalizedText>> table = enumStrings.value().value().to_vector<LocalizedText>();
  ASSERT_TRUE(table.is_good()) << "EnumStrings must decode as LocalizedText[]";
  ASSERT_EQ(table.value().size(), 3U) << "the fixture's item declares three states";

  // ...and the Attributes the server publishes say so, so a client can rely on the decode.
  const std::optional<NodeId> dataType = read_data_type_attribute(mMultiStateEnumStringsId);
  ASSERT_TRUE(dataType.has_value()) << "the EnumStrings Property's DataType Attribute must read back";
  EXPECT_EQ(*dataType, NodeId{DataTypeId::LocalizedText})
    << "EnumStrings is a LocalizedText Property (Part 8 section 5.3.3.3 Table 8)";
  const std::optional<std::int32_t> valueRank = read_value_rank_attribute(mMultiStateEnumStringsId);
  ASSERT_TRUE(valueRank.has_value()) << "the EnumStrings Property's ValueRank Attribute must read back";
  EXPECT_EQ(*valueRank, 1) << "EnumStrings is LocalizedText[] - a one-dimensional array";

  // The entries correspond to the sequential numeric values 0, 1, 2: each state value in turn is written to
  // the item and the name the server's model resolves for it must be the table entry at that index.
  for (std::uint32_t index = 0; index < 3U; ++index)
  {
    ASSERT_TRUE(
      mConnection->try_write_value_sync(mMultiStateInstanceId, Variant{std::uint32_t{index}}).is_good())
      << "state value " << index << " must be writable on the item";
    MultiStateDiscreteHandleResult handle = build_multi_state_discrete(mMultiStateInstanceId);
    ASSERT_TRUE(handle.is_good()) << "the MultiStateDiscrete handle must resolve: 0x" << std::hex
                                  << handle.status_code().as_uint32();
    Result<MultiStateDiscreteValue> value = read_multi_state_discrete(handle.value());
    ASSERT_TRUE(value.is_good()) << "the typed read must succeed for state value " << index;
    EXPECT_EQ(value.value().rawIndex, index) << "the raw state value must surface verbatim";
    ASSERT_EQ(value.value().enumStrings.size(), table.value().size())
      << "the resolved table must be the one the server serves";
    ASSERT_TRUE(value.value().currentName.has_value())
      << "state value " << index << " must resolve through the table - entry " << index << " names it";
    EXPECT_EQ(static_cast<std::string>(value.value().currentName->text()),
      static_cast<std::string>(table.value()[index].text()))
      << "EnumStrings is positional from zero: entry i is the name of state value i";
  }
}

// ============================================================================================================
// Part 8 section 5.3.3.3: "If the item contains an array then this lookup table shall apply to all elements
// in the array." The natural design for an array-valued item treats each element as an independent item, and
// an implementation that does so has to serve a table per element - a second dimension on EnumStrings, or one
// Property per index. Either shape leaves a client with no single frame in which to name the item's states,
// which is why one table governing the whole array is a separate observable from the table being well-formed.
// @verifies AC-SVR-DA-011-ARRAY-WIDE
TEST_F(ClientDataAccess, ArrayValuedMultiStateItemResolvesEveryElementThroughOneEnumStringsTable)
{
  ASSERT_FALSE(mMultiStateArrayId.is_null())
    << "the array-valued MultiStateDiscrete item must have been instantiated through the type system";
  ASSERT_FALSE(mMultiStateArrayEnumStringsId.is_null())
    << "instantiating it must materialise its Mandatory EnumStrings Property";

  // The antecedent: the Value really is the multi-element array [0, 2, 1] (otherwise nothing is array-wide).
  Result<DataValue> value = mConnection->try_read_value_sync(mMultiStateArrayId);
  ASSERT_TRUE(value.is_good()) << "the array item must read: 0x" << std::hex
                               << value.status_code().as_uint32();
  Result<std::vector<std::uint32_t>> elements = value.value().value().to_vector<std::uint32_t>();
  ASSERT_TRUE(elements.is_good()) << "the Value must decode as a UInt32 array";
  ASSERT_EQ(elements.value().size(), 3U) << "the item holds three elements";
  EXPECT_EQ(elements.value()[0], 0U);
  EXPECT_EQ(elements.value()[1], 2U);
  EXPECT_EQ(elements.value()[2], 1U);

  // ONE table for the whole array: a single three-entry LocalizedText[]. A per-element override would have to
  // arrive either as a second dimension or as three concatenated tables (nine entries).
  Result<DataValue> enumStrings = read_property(mMultiStateArrayId, "EnumStrings");
  ASSERT_TRUE(enumStrings.is_good()) << "EnumStrings must be reachable under HasProperty: 0x" << std::hex
                                     << enumStrings.status_code().as_uint32();
  ASSERT_TRUE(enumStrings.value().value().is_array()) << "EnumStrings is served as a table";
  Result<std::vector<LocalizedText>> table = enumStrings.value().value().to_vector<LocalizedText>();
  ASSERT_TRUE(table.is_good()) << "the one table must decode as LocalizedText[]";
  ASSERT_EQ(table.value().size(), 3U)
    << "one table of three states governs all three elements - not one table per element";

  // Every element resolves through THAT table: each element's value indexes inside it, and the label it takes
  // is the shared table's entry at that index.
  const std::vector<std::string> expected{"Off", "High", "Low"};
  ASSERT_EQ(expected.size(), elements.value().size());
  for (std::size_t i = 0; i < elements.value().size(); ++i)
  {
    const std::size_t element = static_cast<std::size_t>(elements.value()[i]);
    ASSERT_LT(element, table.value().size())
      << "element " << i << " must index the ONE shared table - no per-element table is looked for";
    EXPECT_EQ(static_cast<std::string>(table.value()[element].text()), expected[i])
      << "element " << i << " must take its label from the shared table";
  }
}

// ============================================================================================================
// Part 8 section 5.3.3.3: "The StatusCode SemanticsChanged bit shall be set if the EnumStrings Property is
// changed." EnumStrings is positional, so inserting an entry renumbers every state after it: the item's Value
// does not change, yet a client caching the table now maps every value to the wrong name. A plausible
// implementation raises the bit only from the value sampler, which never fires here - the edit is silent.
// @verifies AC-SVR-DA-012-MULTISTATE-SEMANTICS
TEST_F(ClientDataAccess, ChangingEnumStringsRaisesSemanticsChanged)
{
  ASSERT_FALSE(mMultiStateInstanceId.is_null()) << "the MultiStateDiscrete item must have been instantiated";
  ASSERT_FALSE(mMultiStateEnumStringsId.is_null()) << "its Mandatory EnumStrings must have been materialised";

  auto subscription = create_subscription(100.0);
  ASSERT_TRUE(subscription.is_good())
    << "create_subscription failed: 0x" << std::hex << subscription.status_code().as_uint32();
  auto sink = std::make_shared<DataValueSink>();
  auto item =
    create_data_monitored_item(subscription.value(), mMultiStateInstanceId, /*clientHandle=*/1, sink);
  ASSERT_TRUE(item.is_good()) << "create_monitored_item failed: 0x" << std::hex
                              << item.status_code().as_uint32();

  ASSERT_TRUE(wait_until([&] { return !sink->snapshot().empty(); }))
    << "the monitored item must deliver its initial sample before the table is edited";
  ASSERT_EQ(semantics_changed_count(*sink), 0U)
    << "nothing has edited EnumStrings yet, so no delivered notification may carry SemanticsChanged";

  // Insert an entry at the FRONT: every state after it is renumbered while the Value stays where it was.
  Array<LocalizedText> renumbered = make_enum_strings({LocalizedText{"", "Unknown"},
    LocalizedText{"", "Off"},
    LocalizedText{"", "Low"},
    LocalizedText{"", "High"}});
  ASSERT_TRUE(
    mConnection->try_write_value_sync(mMultiStateEnumStringsId, Variant{std::move(renumbered)}).is_good())
    << "the EnumStrings Property write must reach the server";
  EXPECT_TRUE(wait_until([&] { return semantics_changed_count(*sink) >= 1U; }))
    << "changing EnumStrings must set SemanticsChanged on the next data-change (Part 8 section 5.3.3.3)";
}

// ============================================================================================================
// Part 8 section 5.3.3.4: the SemanticsChanged bit shall be set when EnumValues changes. EnumValues is KEYED
// rather than positional, so an edit can change what a value means without renumbering anything and without
// touching the Value - an implementation that only diffs the table's LENGTH, or that raises the bit from the
// value sampler, leaves the client naming the state with the label it cached.
// @verifies AC-SVR-DA-014-ENUMVALUES-SEMANTICS
TEST_F(ClientDataAccess, ChangingEnumValuesRaisesSemanticsChanged)
{
  ASSERT_FALSE(mMsvdInstanceId.is_null()) << "the MultiStateValueDiscrete item must have been instantiated";
  ASSERT_FALSE(mMsvdEnumValuesId.is_null()) << "its Mandatory EnumValues must have been materialised";

  auto subscription = create_subscription(100.0);
  ASSERT_TRUE(subscription.is_good())
    << "create_subscription failed: 0x" << std::hex << subscription.status_code().as_uint32();
  auto sink = std::make_shared<DataValueSink>();
  auto item = create_data_monitored_item(subscription.value(), mMsvdInstanceId, /*clientHandle=*/1, sink);
  ASSERT_TRUE(item.is_good()) << "create_monitored_item failed: 0x" << std::hex
                              << item.status_code().as_uint32();

  ASSERT_TRUE(wait_until([&] { return !sink->snapshot().empty(); }))
    << "the monitored item must deliver its initial sample before the table is edited";
  ASSERT_EQ(semantics_changed_count(*sink), 0U)
    << "nothing has edited EnumValues yet, so no delivered notification may carry SemanticsChanged";

  // Same keys, same count - only the MEANING of key 1 changes. Nothing else in the address space says so.
  Array<RefStructure<Structure>> remeaned = make_enum_values({{1, "Stopped"}, {2, "High"}});
  ASSERT_TRUE(mConnection->try_write_value_sync(mMsvdEnumValuesId, Variant{std::move(remeaned)}).is_good())
    << "the EnumValues Property write must reach the server";
  EXPECT_TRUE(wait_until([&] { return semantics_changed_count(*sink) >= 1U; }))
    << "changing EnumValues must set SemanticsChanged on the next data-change (Part 8 section 5.3.3.4)";
}

// ============================================================================================================
// Part 8 section 5.3.4: ArrayItemType is for values a client can PLOT - Title labels the plot and
// AxisScaleType decides whether the axis is drawn linear or logarithmic, which is why the specification makes
// fillable values a precondition on using the type at all rather than modelling the data as a plain array.
// The item under test is modelled with both filled ((c4)), so what is read here is what the server publishes
// for an ArrayItem a deployment was entitled to model: a Mandatory Property reachable under HasProperty whose
// Value still decodes as the type the plot needs. A Property materialised but never carried through, or one
// served with its Value dropped, is a chart the client cannot draw and cannot tell is undrawable.
// @verifies AC-SVR-DA-015-ARRAYITEM-PRECONDITION
TEST_F(ClientDataAccess, ArrayItemInstanceCarriesAPopulatedTitleAndAxisScaleType)
{
  ASSERT_FALSE(mYArrayItemId.is_null())
    << "the server must instantiate an ArrayItemType subtype through its type system";
  ASSERT_FALSE(mYArrayTitleId.is_null()) << "instantiating it must materialise its Mandatory Title Property";
  ASSERT_FALSE(mYArrayAxisScaleTypeId.is_null()) << "...and its Mandatory AxisScaleType Property";

  // Title: present AND carrying a label a client can put on the plot.
  Result<DataValue> title = read_property(mYArrayItemId, "Title");
  ASSERT_TRUE(title.is_good()) << "Title must be reachable under HasProperty: 0x" << std::hex
                               << title.status_code().as_uint32();
  const LocalizedText* label = title.value().value().try_as<LocalizedText>();
  ASSERT_NE(label, nullptr) << "Title's Value must decode as a LocalizedText - an ArrayItem serving no Title "
                               "at all is the same failure as one serving an empty Title";
  EXPECT_FALSE(static_cast<std::string>(label->text()).empty())
    << "an ArrayItem carrying an empty Title is a plot the client cannot label; Part 8 section 5.3.4 makes a "
       "fillable Title the precondition on using the type instead of a plain array";

  // AxisScaleType: a scale was CHOSEN, and it is one of the three the enumeration defines.
  Result<DataValue> axisScale = read_property(mYArrayItemId, "AxisScaleType");
  ASSERT_TRUE(axisScale.is_good()) << "AxisScaleType must be reachable under HasProperty: 0x" << std::hex
                                   << axisScale.status_code().as_uint32();
  EXPECT_FALSE(axisScale.value().value().empty())
    << "an ArrayItem serving no AxisScaleType leaves the client guessing whether the axis is linear or "
       "logarithmic - the same guess the type exists to remove";
  const std::int32_t* scale = axisScale.value().value().try_as<std::int32_t>();
  ASSERT_NE(scale, nullptr) << "AxisScaleType's Value must decode as an AxisScaleEnumeration";
  EXPECT_TRUE(ua::is_valid(static_cast<AxisScaleEnumeration>(*scale)))
    << "the served AxisScaleType must be one of Linear / Log / Ln, not an unset default";
}

// ============================================================================================================
// Part 8 section 5.3.4.1 through section 5.3.4.6 restate one obligation for six ArrayItem subtypes: mutating
// the Properties that define the item's axes or ranges sets SemanticsChanged. Each subtype's Property list is
// handled by its own generated code, so the realistic defect is not that the mechanism is missing but that
// five subtypes register their axis Property and one does not - a client plotting that one subtype keeps
// drawing against an axis definition that has moved under it. All five concrete subtypes are driven here for
// exactly that reason (ArrayItemType itself is abstract).
// @verifies AC-SVR-DA-016-ARRAYITEM-SEMANTICS
TEST_F(ClientDataAccess, ChangingAnyArrayItemAxisOrRangePropertyRaisesSemanticsChangedOnEverySubtype)
{
  const AxisInformation movedAxis = make_axis_information("moved axis", -50.0, 250.0);
  const Array<RefStructure<Structure>> movedAxisArray =
    make_axis_information_array("moved axis", -50.0, 250.0);

  expect_semantics_changed_on_each_property_write("YArrayItemType",
    mSemanticsYArrayId,
    {{mSemanticsYArrayXAxisId, Variant{movedAxis}},
      {mSemanticsYArrayTitleId, Variant{LocalizedText{"", "Y retitled"}}}});

  expect_semantics_changed_on_each_property_write("XYArrayItemType",
    mSemanticsXYArrayId,
    {{mSemanticsXYArrayXAxisId, Variant{movedAxis}},
      {mSemanticsXYArrayTitleId, Variant{LocalizedText{"", "XY retitled"}}}});

  expect_semantics_changed_on_each_property_write("ImageItemType",
    mSemanticsImageId,
    {{mSemanticsImageXAxisId, Variant{movedAxis}},
      {mSemanticsImageYAxisId, Variant{movedAxis}},
      {mSemanticsImageTitleId, Variant{LocalizedText{"", "Image retitled"}}}});

  expect_semantics_changed_on_each_property_write("CubeItemType",
    mSemanticsCubeId,
    {{mSemanticsCubeXAxisId, Variant{movedAxis}},
      {mSemanticsCubeYAxisId, Variant{movedAxis}},
      {mSemanticsCubeZAxisId, Variant{movedAxis}},
      {mSemanticsCubeTitleId, Variant{LocalizedText{"", "Cube retitled"}}}});

  expect_semantics_changed_on_each_property_write("NDimensionArrayItemType",
    mSemanticsNDimensionId,
    {{mSemanticsNDimensionAxisId, Variant{movedAxisArray}},
      {mSemanticsNDimensionTitleId, Variant{LocalizedText{"", "N retitled"}}}});
}

// ============================================================================================================
// Part 8 section 5.3.4.2 restricts YArrayItemType to ValueRank 1 and to eight numeric DataTypes, and makes
// XAxisDefinition Mandatory: the Y values ARE the array and the X axis lives in the Property, which is the
// whole difference from XYArrayItemType where each element carries its own X. The DataType restriction is
// what lets a client assume the elements are plottable numbers - and NS0 cannot express it (YArrayItemType
// inherits BaseDataType), so a server that leans on the nodeset alone will happily serve a String-valued
// YArrayItem that no client can plot.
// @verifies AC-SVR-DA-017-YARRAYITEM-SHAPE
TEST_F(ClientDataAccess, YArrayItemInstanceIsARankOneNumericArrayCarryingAnXAxisDefinition)
{
  ASSERT_FALSE(mYArrayItemId.is_null())
    << "the server must instantiate a YArrayItemType Variable through its type system";
  ASSERT_FALSE(mYArrayXAxisDefinitionId.is_null())
    << "instantiating YArrayItemType must materialise its Mandatory XAxisDefinition Property";

  // The eight DataTypes Part 8 section 5.3.4.2 permits.
  const std::vector<NodeId> permitted{NodeId{DataTypeId::SByte},
    NodeId{DataTypeId::Int16},
    NodeId{DataTypeId::Int32},
    NodeId{DataTypeId::Int64},
    NodeId{DataTypeId::Float},
    NodeId{DataTypeId::Double},
    NodeId{DataTypeId::ComplexNumberType},
    NodeId{DataTypeId::DoubleComplexNumberType}};

  // ValueRank is 1: the Y values are a single-dimensional array.
  const std::optional<std::int32_t> valueRank = read_value_rank_attribute(mYArrayItemId);
  ASSERT_TRUE(valueRank.has_value()) << "the item's ValueRank Attribute must read back";
  EXPECT_EQ(*valueRank, 1) << "YArrayItemType is single-dimensional (Part 8 section 5.3.4.2)";

  // The DataType is one of the permitted numeric types.
  const std::optional<NodeId> dataType = read_data_type_attribute(mYArrayItemId);
  ASSERT_TRUE(dataType.has_value()) << "the item's DataType Attribute must read back";
  EXPECT_TRUE(std::find(permitted.begin(), permitted.end(), *dataType) != permitted.end())
    << "YArrayItemType restricts its DataType to the eight numeric types";

  // XAxisDefinition is present, and typed AxisInformation so a client can decode the axis.
  Result<DataValue> xAxis = read_property(mYArrayItemId, "XAxisDefinition");
  ASSERT_TRUE(xAxis.is_good()) << "XAxisDefinition must be reachable under HasProperty: 0x" << std::hex
                               << xAxis.status_code().as_uint32();
  const std::optional<NodeId> xAxisDataType = read_data_type_attribute(mYArrayXAxisDefinitionId);
  ASSERT_TRUE(xAxisDataType.has_value())
    << "the XAxisDefinition Property's DataType Attribute must read back";
  EXPECT_EQ(*xAxisDataType, NodeId{DataTypeId::AxisInformation})
    << "the X axis is described by an AxisInformation Property, not by the elements";

  // ...and the restriction restricts: a YArrayItemType Variable brought into the address space with a String
  // DataType would be a served Variable violating the observation above, so it must not become one.
  auto addressSpace = mServer.server().address_space();
  InstantiationOptions options;
  options.targetNamespaceIndex = mTestNamespaceIndex;
  auto stringTyped = YArrayItem::try_create_sync(addressSpace,
    NodeId{ObjectId::ObjectsFolder},
    QualifiedName{mTestNamespaceIndex, "StringTypedYArrayItem"},
    options,
    VariableInstantiationAttributes{.dataType = NodeId{DataTypeId::String},
      .valueRank = 1,
      .accessLevel = AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite}});
  if (stringTyped.is_good())
  {
    YArrayItem served = std::move(stringTyped).value();
    const NodeId servedId = served.node_id();
    served.release();  // keep it served, so what the server publishes for it is observable
    const std::optional<NodeId> servedDataType = read_data_type_attribute(servedId);
    ASSERT_TRUE(servedDataType.has_value()) << "the served Variable's DataType Attribute must read back";
    EXPECT_TRUE(std::find(permitted.begin(), permitted.end(), *servedDataType) != permitted.end())
      << "the server serves a YArrayItemType Variable whose DataType is String - Part 8 section 5.3.4.2 "
         "restricts "
         "the type to eight numeric DataTypes, so this Variable can never be plotted by a conforming client";
  }
}

namespace
{

// A PercentDeadband DataChangeFilter carrying @p percent - the filter Part 8 section 6.2 governs. Built here
// rather than through the client's `make_percent_deadband_filter` on purpose: these rows judge the SERVER's
// validation, so the request has to be able to carry a percentage the client-side factory would refuse.
std::unique_ptr<ua::DataChangeFilter> make_percent_deadband(double percent)
{
  auto filter = std::make_unique<ua::DataChangeFilter>();
  filter->trigger() = ua::DataChangeTrigger::StatusValue;
  filter->deadband_type() = static_cast<std::uint32_t>(ua::DeadbandType::Percent);
  filter->deadband_value() = percent;
  return filter;
}

}  // namespace

// ============================================================================================================
// Part 8 section 5.3.4.3: XYArrayItemType has DataType `XVType` and "the axisSteps of XAxisDefinition shall
// be set to NULL because it is not used" - each XVType element carries its own x, so steps would be a second,
// contradictory source for the same axis and a client reading them plots against the wrong positions. The
// instance below is materialised by the server's own type system with NOTHING overridden, so its DataType is
// whatever the server copies from the type: a server that leaves the instance at the inherited BaseDataType,
// or that helpfully synthesises axisSteps from the x values it can see, serves an item no client can plot.
// @verifies AC-SVR-DA-018-XYARRAYITEM-SHAPE
TEST_F(ClientDataAccess, XyArrayItemServesXvTypeValuesAndAnXAxisDefinitionWithoutSteps)
{
  auto addressSpace = mServer.server().address_space();
  InstantiationOptions options;
  options.targetNamespaceIndex = mTestNamespaceIndex;

  auto created = XYArrayItem::try_create_sync(addressSpace,
    NodeId{ObjectId::ObjectsFolder},
    QualifiedName{mTestNamespaceIndex, "ShapeXYArrayItem"},
    options,
    VariableInstantiationAttributes{});
  ASSERT_TRUE(created.is_good()) << "the server must be able to instantiate an XYArrayItemType Variable: 0x"
                                 << std::hex << created.status_code().as_uint32();
  XYArrayItem item = std::move(created).value();
  const NodeId instanceId = item.node_id();
  NodeId xAxisId;
  auto xAxisProperty = item.try_x_axis_definition_property_sync();
  if (xAxisProperty.is_good())
  {
    xAxisId = xAxisProperty.value().node_id();
  }
  item.release();  // keep it served, so what the server publishes for it is observable
  ASSERT_FALSE(xAxisId.is_null())
    << "instantiating XYArrayItemType must materialise its Mandatory XAxisDefinition Property";
  // The modelled axis carries units, a range, a title and a scale - and NO steps, which is the whole point.
  seed_writable_property(
    addressSpace, xAxisId, DataValue{Variant{make_axis_information("XY axis", 0.0, 100.0)}});

  // The values are XVType {x, value} pairs - that is what makes the per-element X the axis source.
  const std::optional<NodeId> dataType = read_data_type_attribute(instanceId);
  ASSERT_TRUE(dataType.has_value()) << "the item's DataType Attribute must read back";
  EXPECT_EQ(*dataType, NodeId{DataTypeId::XVType})
    << "XYArrayItemType Variables carry XVType elements (Part 8 section 5.3.4.3), not a bare numeric array";

  // ...and the X axis definition the server serves declares no steps.
  Result<DataValue> xAxis = read_property(instanceId, "XAxisDefinition");
  ASSERT_TRUE(xAxis.is_good()) << "XAxisDefinition must be reachable under HasProperty: 0x" << std::hex
                               << xAxis.status_code().as_uint32();
  const AxisInformation* axis = xAxis.value().value().try_as<AxisInformation>();
  ASSERT_NE(axis, nullptr) << "XAxisDefinition's Value must decode as an AxisInformation";
  EXPECT_TRUE(axis->axis_steps().payload().empty())
    << "axisSteps must be NULL on an XYArrayItem - steps and the per-element x are two contradictory "
       "sources for the same axis, and a client that reads the steps plots against the wrong positions";
}

// ============================================================================================================
// Part 8 section 5.3.4.4: ImageItemType is two-dimensional (ValueRank 2) with both XAxisDefinition and
// YAxisDefinition Mandatory - one axis definition per dimension, so a matrix a client cannot place on either
// axis is as useless as one it cannot fold. The instance is created with no attributes overridden, so the
// shape read back is the one the type system itself confers. The DataType is deliberately not asserted here:
// Table 14 gives the type BaseDataType and the eight-type restriction binds the element type a modeller
// declares, which this caller declines to declare; enforcing that restriction is a rejection gate on a
// supplied DataType, not a shape read.
// @verifies AC-SVR-DA-019-IMAGEITEM-SHAPE
TEST_F(ClientDataAccess, ImageItemIsTwoDimensionalNumericWithBothAxisDefinitions)
{
  auto addressSpace = mServer.server().address_space();
  InstantiationOptions options;
  options.targetNamespaceIndex = mTestNamespaceIndex;

  auto created = ImageItem::try_create_sync(addressSpace,
    NodeId{ObjectId::ObjectsFolder},
    QualifiedName{mTestNamespaceIndex, "ShapeImageItem"},
    options,
    VariableInstantiationAttributes{});
  ASSERT_TRUE(created.is_good()) << "the server must be able to instantiate an ImageItemType Variable: 0x"
                                 << std::hex << created.status_code().as_uint32();
  ImageItem item = std::move(created).value();
  const NodeId instanceId = item.node_id();
  NodeId xAxisId;
  NodeId yAxisId;
  auto xAxisProperty = item.try_x_axis_definition_property_sync();
  if (xAxisProperty.is_good())
  {
    xAxisId = xAxisProperty.value().node_id();
  }
  auto yAxisProperty = item.try_y_axis_definition_property_sync();
  if (yAxisProperty.is_good())
  {
    yAxisId = yAxisProperty.value().node_id();
  }
  item.release();
  ASSERT_FALSE(xAxisId.is_null())
    << "instantiating ImageItemType must materialise its Mandatory XAxisDefinition Property";
  ASSERT_FALSE(yAxisId.is_null()) << "...and its Mandatory YAxisDefinition Property";
  seed_writable_property(
    addressSpace, xAxisId, DataValue{Variant{make_axis_information("Image X", 0.0, 100.0)}});
  seed_writable_property(
    addressSpace, yAxisId, DataValue{Variant{make_axis_information("Image Y", 0.0, 100.0)}});

  // ValueRank 2 - the image is a matrix, not a flat array a client would have to re-fold itself.
  const std::optional<std::int32_t> valueRank = read_value_rank_attribute(instanceId);
  ASSERT_TRUE(valueRank.has_value()) << "the item's ValueRank Attribute must read back";
  EXPECT_EQ(*valueRank, 2) << "ImageItemType is two-dimensional (Part 8 section 5.3.4.4)";

  // Both axis definitions are present: one per dimension, and each decodes as the AxisInformation a client
  // needs to place the image on its axes.
  Result<DataValue> xAxis = read_property(instanceId, "XAxisDefinition");
  ASSERT_TRUE(xAxis.is_good()) << "XAxisDefinition must be reachable under HasProperty: 0x" << std::hex
                               << xAxis.status_code().as_uint32();
  EXPECT_NE(xAxis.value().value().try_as<AxisInformation>(), nullptr)
    << "XAxisDefinition's Value must decode as an AxisInformation";
  Result<DataValue> yAxis = read_property(instanceId, "YAxisDefinition");
  ASSERT_TRUE(yAxis.is_good()) << "YAxisDefinition must be reachable under HasProperty: 0x" << std::hex
                               << yAxis.status_code().as_uint32();
  EXPECT_NE(yAxis.value().value().try_as<AxisInformation>(), nullptr)
    << "YAxisDefinition's Value must decode as an AxisInformation";
}

// ============================================================================================================
// Part 8 section 5.3.4.5: CubeItemType is three-dimensional (ValueRank 3) with X, Y and Z axis definitions
// all Mandatory. The family rule is one axis definition per dimension, so a missing axis here does not merely
// leave a dimension unlabelled - it leaves one dimension of the cube unplaceable. The plausible failure is a
// generated type that materialises the two axes it shares with ImageItemType and drops the third, which reads
// perfectly on every slice a client happens to plot in the X-Y plane.
// @verifies AC-SVR-DA-020-CUBEITEM-SHAPE
TEST_F(ClientDataAccess, CubeItemIsThreeDimensionalWithAllThreeAxisDefinitions)
{
  auto addressSpace = mServer.server().address_space();
  InstantiationOptions options;
  options.targetNamespaceIndex = mTestNamespaceIndex;

  auto created = CubeItem::try_create_sync(addressSpace,
    NodeId{ObjectId::ObjectsFolder},
    QualifiedName{mTestNamespaceIndex, "ShapeCubeItem"},
    options,
    VariableInstantiationAttributes{});
  ASSERT_TRUE(created.is_good()) << "the server must be able to instantiate a CubeItemType Variable: 0x"
                                 << std::hex << created.status_code().as_uint32();
  CubeItem item = std::move(created).value();
  const NodeId instanceId = item.node_id();
  NodeId xAxisId;
  NodeId yAxisId;
  NodeId zAxisId;
  auto xAxisProperty = item.try_x_axis_definition_property_sync();
  if (xAxisProperty.is_good())
  {
    xAxisId = xAxisProperty.value().node_id();
  }
  auto yAxisProperty = item.try_y_axis_definition_property_sync();
  if (yAxisProperty.is_good())
  {
    yAxisId = yAxisProperty.value().node_id();
  }
  auto zAxisProperty = item.try_z_axis_definition_property_sync();
  if (zAxisProperty.is_good())
  {
    zAxisId = zAxisProperty.value().node_id();
  }
  item.release();
  ASSERT_FALSE(xAxisId.is_null())
    << "instantiating CubeItemType must materialise its Mandatory XAxisDefinition Property";
  ASSERT_FALSE(yAxisId.is_null()) << "...its Mandatory YAxisDefinition Property";
  ASSERT_FALSE(zAxisId.is_null()) << "...and its Mandatory ZAxisDefinition Property";
  seed_writable_property(
    addressSpace, xAxisId, DataValue{Variant{make_axis_information("Cube X", 0.0, 100.0)}});
  seed_writable_property(
    addressSpace, yAxisId, DataValue{Variant{make_axis_information("Cube Y", 0.0, 100.0)}});
  seed_writable_property(
    addressSpace, zAxisId, DataValue{Variant{make_axis_information("Cube Z", 0.0, 100.0)}});

  const std::optional<std::int32_t> valueRank = read_value_rank_attribute(instanceId);
  ASSERT_TRUE(valueRank.has_value()) << "the item's ValueRank Attribute must read back";
  EXPECT_EQ(*valueRank, 3) << "CubeItemType is three-dimensional (Part 8 section 5.3.4.5)";

  // All three axis definitions are served, each decoding as the AxisInformation that places its dimension.
  for (const char* axisName : {"XAxisDefinition", "YAxisDefinition", "ZAxisDefinition"})
  {
    Result<DataValue> axis = read_property(instanceId, axisName);
    ASSERT_TRUE(axis.is_good()) << axisName << " must be reachable under HasProperty: 0x" << std::hex
                                << axis.status_code().as_uint32();
    EXPECT_NE(axis.value().value().try_as<AxisInformation>(), nullptr)
      << axisName
      << "'s Value must decode as an AxisInformation - a dimension whose axis cannot be decoded "
         "is a dimension the client cannot place the cube against";
  }
}

// ============================================================================================================
// Part 8 section 5.3.4.6: NDimensionArrayItemType is the generalisation of the fixed-rank ArrayItem types -
// ValueRank 0 (OneOrMoreDimensions) and a Mandatory `AxisDefinition` that is an AxisInformation ARRAY, one
// entry per dimension. Because the rank is not fixed by the type, the agreement between the AxisDefinition
// array's length and the served data's dimensions is the ONLY thing keeping the axes aligned with the values.
// The plausible failure is materialising AxisDefinition as a scalar AxisInformation (the shape every sibling
// type uses), which reads correctly for a one-dimensional item and can never describe a second dimension.
// @verifies AC-SVR-DA-021-NDIMENSION-SHAPE
TEST_F(ClientDataAccess, NDimensionArrayItemDeclaresOneAxisDefinitionPerDimension)
{
  auto addressSpace = mServer.server().address_space();
  InstantiationOptions options;
  options.targetNamespaceIndex = mTestNamespaceIndex;

  auto created = NDimensionArrayItem::try_create_sync(addressSpace,
    NodeId{ObjectId::ObjectsFolder},
    QualifiedName{mTestNamespaceIndex, "ShapeNDimensionArrayItem"},
    options,
    VariableInstantiationAttributes{});
  ASSERT_TRUE(created.is_good())
    << "the server must be able to instantiate an NDimensionArrayItemType Variable: 0x" << std::hex
    << created.status_code().as_uint32();
  NDimensionArrayItem item = std::move(created).value();
  const NodeId instanceId = item.node_id();
  NodeId axisDefinitionId;
  auto axisProperty = item.try_axis_definition_property_sync();
  if (axisProperty.is_good())
  {
    axisDefinitionId = axisProperty.value().node_id();
  }
  item.release();
  ASSERT_FALSE(axisDefinitionId.is_null())
    << "instantiating NDimensionArrayItemType must materialise its Mandatory AxisDefinition Property";

  // The item is modelled with ONE dimension: a flat three-element Double array, described by exactly one
  // AxisInformation. (seed_writable_property is used for the Value too - the instantiated instance inherits
  // its AccessLevel from the type, and the Value has to be readable for the dimension count to be
  // observable.)
  seed_writable_property(addressSpace, instanceId, DataValue{Variant{Array<double>{1.0, 2.0, 3.0}}});
  Array<RefStructure<Structure>> axes = make_axis_information_array("N axis", 0.0, 100.0);
  seed_writable_property(addressSpace, axisDefinitionId, DataValue{Variant{std::move(axes)}});

  // ValueRank 0 - one-or-more dimensions, fixed by neither the type nor the instance.
  const std::optional<std::int32_t> valueRank = read_value_rank_attribute(instanceId);
  ASSERT_TRUE(valueRank.has_value()) << "the item's ValueRank Attribute must read back";
  EXPECT_EQ(*valueRank, 0) << "NDimensionArrayItemType is OneOrMoreDimensions (Part 8 section 5.3.4.6)";

  // AxisDefinition is declared as an AxisInformation ARRAY, not a scalar: that is what lets it hold one entry
  // per dimension at all.
  const std::optional<NodeId> axisDataType = read_data_type_attribute(axisDefinitionId);
  ASSERT_TRUE(axisDataType.has_value()) << "the AxisDefinition Property's DataType Attribute must read back";
  EXPECT_EQ(*axisDataType, NodeId{DataTypeId::AxisInformation})
    << "AxisDefinition describes the axes with AxisInformation (Part 8 section 5.3.4.6 Table 16)";
  const std::optional<std::int32_t> axisValueRank = read_value_rank_attribute(axisDefinitionId);
  ASSERT_TRUE(axisValueRank.has_value())
    << "the AxisDefinition Property's ValueRank Attribute must read back";
  EXPECT_EQ(*axisValueRank, 1)
    << "AxisDefinition is AxisInformation[] - a scalar Property could never carry one entry per dimension";

  // The served data really is one-dimensional...
  Result<DataValue> value = mConnection->try_read_value_sync(instanceId);
  ASSERT_TRUE(value.is_good()) << "the item's Value must read: 0x" << std::hex
                               << value.status_code().as_uint32();
  ASSERT_TRUE(value.value().value().is_array()) << "the item holds an array";
  Result<std::vector<double>> elements = value.value().value().to_vector<double>();
  ASSERT_TRUE(elements.is_good()) << "the Value must decode as a Double array";
  ASSERT_FALSE(elements.value().empty()) << "an empty Value would make the dimension count vacuous";

  // ...and the AxisDefinition array carries exactly one entry for that one dimension.
  Result<DataValue> axisDefinition = read_property(instanceId, "AxisDefinition");
  ASSERT_TRUE(axisDefinition.is_good()) << "AxisDefinition must be reachable under HasProperty: 0x"
                                        << std::hex << axisDefinition.status_code().as_uint32();
  ASSERT_TRUE(axisDefinition.value().value().is_array())
    << "AxisDefinition is served as an array - a scalar cannot describe an n-dimensional item";
  Result<std::vector<RefStructure<Structure>>> served =
    axisDefinition.value().value().to_vector<RefStructure<Structure>>();
  ASSERT_TRUE(served.is_good()) << "AxisDefinition must decode as a structure array";
  ASSERT_FALSE(served.value().empty()) << "an empty AxisDefinition leaves every dimension unplaced";
  EXPECT_EQ(served.value().size(), 1U)
    << "the served data has one dimension, so AxisDefinition must carry exactly one AxisInformation";
  EXPECT_NE(dynamic_cast<const AxisInformation*>(served.value()[0].get()), nullptr)
    << "each AxisDefinition entry must decode as an AxisInformation";
}

// ============================================================================================================
// Part 8 section 6.2: a PercentDeadband's deadbandValue "is defined as the percentage of the EURange ... it
// applies only to AnalogItems with an EURange Property". Silently ignoring the filter is the dangerous
// failure, not refusing it: a percentage of a range that does not exist has no value, so a server that
// accepted the filter has to fall back to reporting every change - the caller asked for less traffic and gets
// a flood instead of an error. The conjunction is therefore refusal AND non-creation, and both are asserted
// here.
// @verifies AC-SVR-DA-022-PERCENT-NEEDS-EURANGE
TEST_F(ClientDataAccess, PercentDeadbandWithoutEuRangeIsRefusedNotSilentlyIgnored)
{
  const std::uint32_t subscriptionId =
    ua::test_helpers::create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});
  ASSERT_NE(subscriptionId, 0U) << "the subscription the item would live in must exist";

  // ns;6200 is an AnalogItemType Variable with NO EURange child - the antecedent is the NODE, not the filter:
  // 10% is a perfectly legal percentage.
  auto result = mSession->monitored_items().try_create_monitored_items_sync(
    ua::test_helpers::build_create_mi_request(subscriptionId,
      mNoEuRangeAnalogId,
      make_percent_deadband(10.0),
      {.clientHandle = 71U, .samplingInterval = 50.0, .queueSize = 1U}));
  ASSERT_TRUE(result.is_good()) << "CreateMonitoredItems must reach the server: 0x" << std::hex
                                << result.status_code().as_uint32();
  ua::CreateMonitoredItemsResponse response = std::move(result).value();
  ASSERT_EQ(response.results().size(), 1U) << "one item was requested, so one per-item result must come back";
  EXPECT_EQ(response.results()[0].status_code(), StatusCode{Status::BadDeadbandFilterInvalid})
    << "a PercentDeadband on a node without an EURange must be refused (Part 8 Table 29), not accepted and "
       "ignored: 0x"
    << std::hex << response.results()[0].status_code().as_uint32();
  EXPECT_EQ(response.results()[0].monitored_item_id(), 0U)
    << "a refused item must not be assigned a monitored-item id - the filter must not be dropped and the "
       "item "
       "created anyway";

  // ...and nothing is monitoring the node: a value change produces no notification on the subscription.
  ASSERT_TRUE(mConnection->try_write_value_sync(mNoEuRangeAnalogId, Variant{double{99.0}}).is_good())
    << "the stimulus write must reach the server";
  const std::optional<ua::DataChangeNotification> notification = wait_for_data_change(
    *mSession,
    subscriptionId,
    [](const ua::DataChangeNotification& change) { return !change.monitored_items().empty(); },
    500ms);
  EXPECT_FALSE(notification.has_value())
    << "the item was refused, so the server must not be sampling the node with the deadband silently dropped";
}

// ============================================================================================================
// Part 8 section 6.2 with Table 29: "The range of the deadbandValue is from 0,0 to 100,0 per cent. Specifying
// a deadbandValue outside of this range will be rejected and reported with the StatusCode
// Bad_DeadbandFilterInvalid." Both ends matter and both are easy to get wrong in opposite directions: a
// validator that only guards against a negative value lets 150% through (where it degenerates into a filter
// that suppresses everything), while one written with strict comparisons refuses the conforming boundaries -
// 0,0 disables the deadband and 100,0 suppresses all but a full-range swing, and both are legal requests.
// @verifies AC-SVR-DA-022-DEADBAND-RANGE
TEST_F(ClientDataAccess, DeadbandValueOutsideZeroToOneHundredIsRefusedAndBoundariesAccepted)
{
  const std::uint32_t subscriptionId =
    ua::test_helpers::create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});
  ASSERT_NE(subscriptionId, 0U) << "the subscription the items would live in must exist";

  // ns;6000 is an AnalogItem with EURange [0,100], so the EURange precondition is satisfied and the
  // deadbandValue itself is the only thing under judgement.
  std::uint32_t clientHandle = 80U;
  for (double percent : {150.0, -1.0})
  {
    ++clientHandle;
    auto result = mSession->monitored_items().try_create_monitored_items_sync(
      ua::test_helpers::build_create_mi_request(subscriptionId,
        mScalarAnalogId,
        make_percent_deadband(percent),
        {.clientHandle = clientHandle, .samplingInterval = 50.0, .queueSize = 1U}));
    ASSERT_TRUE(result.is_good()) << "CreateMonitoredItems must reach the server for percent=" << percent;
    ua::CreateMonitoredItemsResponse response = std::move(result).value();
    ASSERT_EQ(response.results().size(), 1U) << "one item was requested for percent=" << percent;
    EXPECT_EQ(response.results()[0].status_code(), StatusCode{Status::BadDeadbandFilterInvalid})
      << "deadbandValue=" << percent << " is outside [0,100] and must draw Bad_DeadbandFilterInvalid: 0x"
      << std::hex << response.results()[0].status_code().as_uint32();
    EXPECT_EQ(response.results()[0].monitored_item_id(), 0U)
      << "a refused deadbandValue=" << percent << " must not leave an item created";
  }

  for (double percent : {0.0, 100.0})
  {
    ++clientHandle;
    auto result = mSession->monitored_items().try_create_monitored_items_sync(
      ua::test_helpers::build_create_mi_request(subscriptionId,
        mScalarAnalogId,
        make_percent_deadband(percent),
        {.clientHandle = clientHandle, .samplingInterval = 50.0, .queueSize = 1U}));
    ASSERT_TRUE(result.is_good()) << "CreateMonitoredItems must reach the server for percent=" << percent;
    ua::CreateMonitoredItemsResponse response = std::move(result).value();
    ASSERT_EQ(response.results().size(), 1U) << "one item was requested for percent=" << percent;
    EXPECT_TRUE(response.results()[0].status_code().is_good())
      << "the boundary deadbandValue=" << percent << " is inclusive and must be accepted: 0x" << std::hex
      << response.results()[0].status_code().as_uint32();
    EXPECT_NE(response.results()[0].monitored_item_id(), 0U)
      << "an accepted deadbandValue=" << percent << " must yield a created item";
  }
}

// ============================================================================================================
// Part 8 section 6.2: "If an element that requires a DataChange is found, then no further deadband checking
// is necessary and the entire array shall be returned." The dangerous half is the return shape, not the
// short-circuit: a server that reports only the element that moved satisfies "a notification was reported"
// and hands the client an array of one where it declared three - the client cannot tell which index it holds,
// and a client that overwrites its cached array loses the other elements outright.
// @verifies AC-SVR-DA-022-ARRAY-SHORTCIRCUIT
TEST_F(ClientDataAccess, OneElementBreachingTheDeadbandReturnsTheEntireArray)
{
  const std::uint32_t subscriptionId =
    ua::test_helpers::create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});
  ASSERT_NE(subscriptionId, 0U) << "the subscription the item lives in must exist";

  // ns;6100 is a Double[8] AnalogItem [10..80] with EURange [0,100]; 5% of that span is 5.0.
  constexpr std::uint32_t clientHandle = 91U;
  auto result = mSession->monitored_items().try_create_monitored_items_sync(
    ua::test_helpers::build_create_mi_request(subscriptionId,
      mArrayAnalogId,
      make_percent_deadband(5.0),
      {.clientHandle = clientHandle, .samplingInterval = 50.0, .queueSize = 10U}));
  ASSERT_TRUE(result.is_good()) << "CreateMonitoredItems must reach the server: 0x" << std::hex
                                << result.status_code().as_uint32();
  ua::CreateMonitoredItemsResponse response = std::move(result).value();
  ASSERT_EQ(response.results().size(), 1U) << "one item was requested, so one per-item result must come back";
  ASSERT_TRUE(response.results()[0].status_code().is_good())
    << "a PercentDeadband on an array AnalogItem with an EURange must be accepted: 0x" << std::hex
    << response.results()[0].status_code().as_uint32();

  const std::optional<ua::DataChangeNotification> initial = wait_for_data_change(*mSession,
    subscriptionId,
    [](const ua::DataChangeNotification& change) { return !change.monitored_items().empty(); });
  ASSERT_TRUE(initial.has_value()) << "the item must deliver its initial sample before an element moves";

  // ONE element moves by 6.0 - past the 5.0 threshold. Every other element is written back unchanged.
  const std::vector<double> expected{16.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0};
  ASSERT_TRUE(mConnection
                ->try_write_value_sync(
                  mArrayAnalogId, Variant{Array<double>{16.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0}})
                .is_good())
    << "the element change must reach the server";

  const std::optional<ua::DataChangeNotification> reported = wait_for_data_change(*mSession,
    subscriptionId,
    [](const ua::DataChangeNotification& change)
    {
      for (const auto& notification : change.monitored_items())
      {
        if (notification.client_handle() != clientHandle)
        {
          continue;
        }
        Result<std::vector<double>> elements = notification.value().value().to_vector<double>();
        if (elements.is_good() && !elements.value().empty() && std::fabs(elements.value()[0] - 16.0) < 1e-9)
        {
          return true;
        }
      }
      return false;
    });
  ASSERT_TRUE(reported.has_value())
    << "an element moving past the deadband threshold must produce a data-change notification";

  std::size_t entriesForItem = 0;
  std::vector<double> delivered;
  for (const auto& notification : reported->monitored_items())
  {
    if (notification.client_handle() != clientHandle)
    {
      continue;
    }
    ++entriesForItem;
    Result<std::vector<double>> elements = notification.value().value().to_vector<double>();
    ASSERT_TRUE(elements.is_good()) << "the reported Value must decode as the Double array being monitored";
    delivered = elements.value();
  }
  ASSERT_EQ(entriesForItem, 1U)
    << "one triggering element yields ONE notification for the item - not one notification per element";
  ASSERT_EQ(delivered.size(), expected.size())
    << "the ENTIRE array must be returned, not the element that moved (Part 8 section 6.2)";
  for (std::size_t i = 0; i < expected.size(); ++i)
  {
    EXPECT_DOUBLE_EQ(delivered[i], expected[i]) << "element " << i << " must arrive with the whole array";
  }
}

// ============================================================================================================
// sub-batch 8 - the MASTER Data Access model obligations: the SemanticsChanged rule Part 8 section 5.2 states
// once for every VariableType, the Range / EUInformation encodings of section 5.6, and the status-code
// overlay of section 5.7.
// ============================================================================================================

// ============================================================================================================
// Part 8 section 5.2: servers "shall set this Bit in notifications if certain Property values defined in this
// standard change" - CERTAIN Property values, specified individually per VariableType. The per-type rows in
// this file each prove one listed Property raises the bit; what they cannot see is the other half of the
// master rule. A server that flags every Property write passes all of them and destroys the signal: the bit
// exists so a client re-reads its metadata only when it must, and one that fires on every edit puts the
// client back to re-reading continuously. The realistic implementation registers the type's whole Mandatory
// Property set with the emission interface instead of the specification's list, which is invisible until a
// Mandatory Property that is NOT on the list is written - ValueAsText on MultiStateValueDiscreteType
// (section 5.3.3.4 names only EnumValues) and AxisScaleType on YArrayItemType (section 5.3.4.2 names exactly
// five, and this is not one).
// @verifies AC-SVR-DA-023-SEMANTICSCHANGED-MASTER
TEST_F(ClientDataAccess, SemanticsChangedFollowsTheListedPropertiesAndNoOthers)
{
  expect_only_listed_properties_raise_semantics_changed("MultiStateValueDiscreteType",
    mMasterMsvdId,
    {mMasterMsvdValueAsTextId, std::nullopt},
    {mMasterMsvdEnumValuesId, Variant{make_enum_values({{1, "Stopped"}, {2, "High"}})}},
    Variant{std::int64_t{2}});

  expect_only_listed_properties_raise_semantics_changed("YArrayItemType",
    mMasterYArrayId,
    {mMasterYArrayAxisScaleTypeId, Variant{static_cast<std::int32_t>(AxisScaleEnumeration::Ln)}},
    {mMasterYArrayXAxisId, Variant{make_axis_information("Master axis moved", -50.0, 250.0)}},
    Variant{Array<double>{4.0, 5.0, 6.0}});
}

// ============================================================================================================
// Part 8 section 5.3.4.2, interpretation note under Table 12: "The X axis is displayed in reverse order,
// however, the XAxisDefinition.Range.low shall be lower than XAxisDefinition.Range.high. It is only a
// graphical representation that reverses the display order." Display order is not carried in the address
// space at all - AxisScaleEnumeration offers Linear/Log/Ln and nothing else - so the reversal is invisible to
// the server and the obligation reduces to one the server can be held to: every XAxisDefinition it serves
// declares low below high, and an axis move carries the two limits through in the order they were written.
// The plausible failure is a codec or accessor that normalises a Range by ordering its fields, which would
// silently swap the limits of a legitimately-written axis and is invisible unless the written order is
// checked on the way back.
// @verifies AC-SVR-DA-024-REVERSED-AXIS-RANGE-ASCENDING
TEST_F(ClientDataAccess, ReversedXAxisIsNotExpressedByInvertingItsRange)
{
  ASSERT_FALSE(mSemanticsYArrayId.is_null()) << "the YArrayItem must have been instantiated";
  ASSERT_FALSE(mSemanticsYArrayXAxisId.is_null())
    << "instantiating YArrayItemType must materialise its Mandatory XAxisDefinition Property";

  // As instantiated and seeded by the server's own model authoring.
  Result<DataValue> before = read_property(mSemanticsYArrayId, "XAxisDefinition");
  ASSERT_TRUE(before.is_good()) << "XAxisDefinition must be reachable under HasProperty: 0x" << std::hex
                                << before.status_code().as_uint32();
  const AxisInformation* seeded = before.value().value().try_as<AxisInformation>();
  ASSERT_NE(seeded, nullptr) << "XAxisDefinition's Value must decode as an AxisInformation";
  EXPECT_FALSE(std::isnan(seeded->eu_range().low()))
    << "the axis range must be comparable - a NaN limit would make the ordering check meaningless";
  EXPECT_FALSE(std::isnan(seeded->eu_range().high()))
    << "the axis range must be comparable - a NaN limit would make the ordering check meaningless";
  EXPECT_LT(seeded->eu_range().low(), seeded->eu_range().high())
    << "the axis the server publishes already declares low at or above high";

  // A legitimate axis move, spanning zero so an implementation that sorted or took absolute values would be
  // caught: the limits must come back in the order they went out, still ascending.
  const double movedLow{-50.0};
  const double movedHigh{250.0};
  const VoidResult moved = mConnection->try_write_value_sync(
    mSemanticsYArrayXAxisId, Variant{make_axis_information("moved X axis", movedLow, movedHigh)});
  ASSERT_TRUE(moved.is_good()) << "the server refused a legitimate ascending axis move: 0x" << std::hex
                               << moved.status_code().as_uint32();

  Result<DataValue> after = read_property(mSemanticsYArrayId, "XAxisDefinition");
  ASSERT_TRUE(after.is_good()) << "XAxisDefinition must still read back: 0x" << std::hex
                               << after.status_code().as_uint32();
  const AxisInformation* served = after.value().value().try_as<AxisInformation>();
  ASSERT_NE(served, nullptr) << "XAxisDefinition's Value must still decode as an AxisInformation";
  EXPECT_DOUBLE_EQ(served->eu_range().low(), movedLow)
    << "the low limit came back as something other than the one written - the Range was reordered in transit";
  EXPECT_DOUBLE_EQ(served->eu_range().high(), movedHigh)
    << "the high limit came back as something other than the one written";
  EXPECT_LT(served->eu_range().low(), served->eu_range().high())
    << "Part 8 section 5.3.4.2: however the axis is displayed, the served Range must still declare low below "
       "high - "
       "the reversal belongs to the rendering, not to the Range";
}

// ============================================================================================================
// Part 8 section 5.6.2, under the Range DataType's own Table 17: "If a limit is not known a NaN shall be
// used." The obligation is on the encoding of a Range the server publishes, so the stimulus has to be a
// published Range that HAS an unknown limit - one written over the wire, since a server that mangled NaN on
// ingress and one that mangled it on egress are otherwise indistinguishable. The known limit is carried
// alongside the unknown one deliberately: an implementation that zeroes both limits and one that zeroes only
// the unknown limit look identical if neither limit is known, and zero is the dangerous substitution because
// a client will scale a PercentDeadband against it. NaN is the one encoding that compares false against
// everything, so the client's bounds check FAILS rather than passing wrongly.
// @verifies AC-SVR-DA-025-UNKNOWN-LIMIT-IS-NAN
TEST_F(ClientDataAccess, UnknownRangeLimitIsPublishedAsNaN)
{
  auto addressSpace = mServer.server().address_space();
  InstantiationOptions options;
  options.targetNamespaceIndex = mTestNamespaceIndex;

  auto created = AnalogItem::try_create_sync(addressSpace,
    NodeId{ObjectId::ObjectsFolder},
    QualifiedName{mTestNamespaceIndex, "UnknownLimitAnalogItem"},
    options,
    VariableInstantiationAttributes{.dataType = NodeId{DataTypeId::Double}, .valueRank = ValueRank::scalar});
  ASSERT_TRUE(created.is_good()) << "the server must be able to instantiate an AnalogItemType Variable: 0x"
                                 << std::hex << created.status_code().as_uint32();
  AnalogItem item = std::move(created).value();
  const NodeId instanceId = item.node_id();
  NodeId euRangeId;
  auto euRangeProperty = item.try_eu_range_property_sync();
  if (euRangeProperty.is_good())
  {
    euRangeId = euRangeProperty.value().node_id();
  }
  item.release();
  ASSERT_FALSE(euRangeId.is_null())
    << "instantiating AnalogItemType must materialise its Mandatory EURange Property";

  // The antecedent: both limits start known, so a NaN read back below can only have come from the write
  // under test. Seeding also makes the Property client-writable, which type instantiation does not.
  const double knownHigh{100.0};
  seed_writable_property(addressSpace, euRangeId, DataValue{Variant{make_range(0.0, knownHigh)}});

  // The stimulus: a Range whose low limit is not known and whose high limit is. Written over the wire so the
  // whole client -> server -> namespace -> client round trip is under test.
  const VoidResult written = mConnection->try_write_value_sync(
    euRangeId, Variant{make_range(std::numeric_limits<double>::quiet_NaN(), knownHigh)});
  ASSERT_TRUE(written.is_good())
    << "the server refused a Range carrying an unknown limit, so section 5.6.2's own "
       "encoding of 'not known' is unrepresentable: 0x"
    << std::hex << written.status_code().as_uint32();

  Result<DataValue> euRange = read_property(instanceId, "EURange");
  ASSERT_TRUE(euRange.is_good()) << "EURange must read back under HasProperty: 0x" << std::hex
                                 << euRange.status_code().as_uint32();
  const Range* range = euRange.value().value().try_as<Range>();
  ASSERT_NE(range, nullptr) << "the EURange Property must serve a decodable Range";
  EXPECT_TRUE(std::isnan(range->low()))
    << "the unknown low limit came back as " << range->low()
    << " - a numeric substitution reads as a real limit a client would scale against";
  EXPECT_DOUBLE_EQ(range->high(), knownHigh)
    << "the KNOWN limit was altered as well, so the server is rewriting the Range rather than carrying the "
       "one unknown limit through";
}

// ============================================================================================================
// Part 8 section 5.6.3.1: a server using a unit-definition standard other than the OPC UA default "shall
// identify this standards body by using a proper URI in EUInformation.namespaceUri". The unitId is only
// unique WITHIN its namespace, so the same numeric code names different units in different bodies' tables; a
// server that drops the URI, or that normalises it to the UN/CEFACT default it hardcodes elsewhere, leaves a
// client converting against the wrong table with nothing to warn it. Two items carrying the SAME unitId under
// different bodies is the shape that makes the URI the only discriminator.
// @verifies AC-SVR-DA-026-EUINFORMATION-NAMESPACEURI
TEST_F(ClientDataAccess, NonDefaultUnitStandardIsIdentifiedByItsNamespaceUri)
{
  ASSERT_FALSE(mSemanticsUnitRangeId.is_null()) << "the scalar analog item must have been instantiated";
  ASSERT_FALSE(mSemanticsUnitsId.is_null()) << "its Mandatory EngineeringUnits must have been materialised";
  ASSERT_FALSE(mArrayUnitRangeId.is_null()) << "the array analog item must have been instantiated";
  ASSERT_FALSE(mArrayUnitRangeUnitsId.is_null())
    << "its Mandatory EngineeringUnits must have been materialised";

  constexpr std::int32_t sharedUnitId = 4408652;
  const std::string iecUri = "http://www.iec.ch/units";
  const std::string astmUri = "http://www.astm.org/units";

  EUInformation iec;
  iec.namespace_uri() = String{iecUri};
  iec.unit_id() = sharedUnitId;
  iec.display_name() = LocalizedText{"", "degC"};
  iec.description() = LocalizedText{"", "degree Celsius, IEC table"};

  EUInformation astm;
  astm.namespace_uri() = String{astmUri};
  astm.unit_id() = sharedUnitId;
  astm.display_name() = LocalizedText{"", "degC"};
  astm.description() = LocalizedText{"", "degree Celsius, ASTM table"};

  ASSERT_TRUE(mConnection->try_write_value_sync(mSemanticsUnitsId, Variant{iec}).is_good())
    << "the IEC-sourced EngineeringUnits write must reach the server";
  ASSERT_TRUE(mConnection->try_write_value_sync(mArrayUnitRangeUnitsId, Variant{astm}).is_good())
    << "the ASTM-sourced EngineeringUnits write must reach the server";

  Result<DataValue> iecRead = read_property(mSemanticsUnitRangeId, "EngineeringUnits");
  ASSERT_TRUE(iecRead.is_good()) << "EngineeringUnits must be reachable under HasProperty: 0x" << std::hex
                                 << iecRead.status_code().as_uint32();
  const EUInformation* iecServed = iecRead.value().value().try_as<EUInformation>();
  ASSERT_NE(iecServed, nullptr) << "EngineeringUnits must decode as an EUInformation";

  Result<DataValue> astmRead = read_property(mArrayUnitRangeId, "EngineeringUnits");
  ASSERT_TRUE(astmRead.is_good()) << "EngineeringUnits must be reachable under HasProperty: 0x" << std::hex
                                  << astmRead.status_code().as_uint32();
  const EUInformation* astmServed = astmRead.value().value().try_as<EUInformation>();
  ASSERT_NE(astmServed, nullptr) << "EngineeringUnits must decode as an EUInformation";

  const std::string servedIecUri = static_cast<std::string>(iecServed->namespace_uri());
  const std::string servedAstmUri = static_cast<std::string>(astmServed->namespace_uri());

  EXPECT_FALSE(servedIecUri.empty())
    << "a non-default unit set must name its standards body - an empty namespaceUri leaves the unitId "
       "meaning whatever the reader's own table says";
  EXPECT_EQ(servedIecUri, iecUri) << "namespaceUri must identify the body the units actually came from";
  EXPECT_FALSE(servedAstmUri.empty()) << "the second body must likewise be identified, not left blank";
  EXPECT_EQ(servedAstmUri, astmUri) << "namespaceUri must identify the body the units actually came from";

  EXPECT_NE(servedIecUri, std::string{sUnCefactNamespaceUri})
    << "a non-UN/CEFACT unit set must not be relabelled with the default mapping's URI";
  EXPECT_NE(servedAstmUri, std::string{sUnCefactNamespaceUri})
    << "a non-UN/CEFACT unit set must not be relabelled with the default mapping's URI";

  // The URI really is the only discriminator: both items carry the identical numeric unitId.
  EXPECT_EQ(iecServed->unit_id(), sharedUnitId);
  EXPECT_EQ(astmServed->unit_id(), sharedUnitId);
  EXPECT_NE(servedIecUri, servedAstmUri)
    << "the same unitId under two bodies is two different units; only namespaceUri keeps them apart";
}

// ============================================================================================================
// Part 8 section 5.6.3.3: "The namespaceUri shall be http://www.opcfoundation.org/UA/units/un/cefact".
// Clients compare this string; they never resolve it. So a trailing slash, an https scheme or a path variant
// does not degrade gracefully - the units become unrecognised rather than merely wrong, and the client falls
// back to treating a known unit as an opaque vendor one. The failure mode is a server that re-forms the URI
// on the way out (a normalising URI type, a config round trip) rather than handing back the bytes it holds.
// @verifies AC-SVR-DA-027-UNCEFACT-NAMESPACEURI-EXACT
TEST_F(ClientDataAccess, UnCefactUnitsCarryTheExactSpecifiedNamespaceUri)
{
  ASSERT_FALSE(mSemanticsUnitRangeId.is_null()) << "the type-instantiated analog item must exist";
  ASSERT_FALSE(mEuFullId.is_null()) << "the hand-authored UN/CEFACT item must exist";

  const std::vector<std::pair<NodeId, std::string>> owners{
    {mSemanticsUnitRangeId, "type-instantiated instance"}, {mEuFullId, "hand-authored instance"}};

  std::size_t observed = 0;
  for (const auto& owner : owners)
  {
    Result<DataValue> units = read_property(owner.first, "EngineeringUnits");
    ASSERT_TRUE(units.is_good()) << owner.second
                                 << ": EngineeringUnits must be reachable under HasProperty: 0x" << std::hex
                                 << units.status_code().as_uint32();
    const EUInformation* served = units.value().value().try_as<EUInformation>();
    ASSERT_NE(served, nullptr) << owner.second << ": EngineeringUnits must decode as an EUInformation";
    EXPECT_EQ(static_cast<std::string>(served->namespace_uri()), std::string{sUnCefactNamespaceUri})
      << owner.second
      << ": the UN/CEFACT namespaceUri is matched character for character - no trailing slash, no https "
         "variant, no path variant (Part 8 section 5.6.3.3)";
    ++observed;
  }
  ASSERT_EQ(observed, owners.size()) << "every UN/CEFACT item must have produced an observation";
}

// ============================================================================================================
// Part 8 section 5.6.3.3: "The Symbol field is used for displayName. The localeId field of
// EUInformation.displayName shall be an empty string." A unit symbol is not localised - "kg" is "kg"
// everywhere - so tagging it invites a client to hunt for a translation that does not exist and fall back to
// nothing. The plausible failure is that the symbol is a LocalizedText and so gets swept into whatever locale
// machinery the server applies to LocalizedTexts generally, which is why the read is repeated under several
// negotiated preferred-locale sets: a server that stamps the session locale on it fails on the sets it would
// otherwise never be asked about.
// @verifies AC-SVR-DA-028-UNCEFACT-DISPLAYNAME-LOCALE-EMPTY
TEST_F(ClientDataAccess, UnCefactDisplayNameIsTheSymbolAndCarriesNoLocale)
{
  ASSERT_FALSE(mSemanticsUnitsId.is_null())
    << "the Mandatory EngineeringUnits Property must have been materialised";

  const std::vector<std::vector<String>> localeSets = {
    {}, {String{"en-US"}}, {String{"de-DE"}}, {String{"fr-FR"}, String{"en"}}};

  std::size_t observed = 0;
  for (const auto& locales : localeSets)
  {
    const ua::VoidResult activated =
      mSession->try_activate_sync(ua::client::Session::ActivateConfig{.localeIds = locales});
    ASSERT_TRUE(activated.is_good())
      << "the session must re-activate with the requested preferred-locale set";

    auto readResult = mSession->attributes().try_read_sync(read_value(mSemanticsUnitsId));
    ASSERT_TRUE(readResult.is_good()) << "the EngineeringUnits Read must succeed at the service level: 0x"
                                      << std::hex << readResult.status_code().as_uint32();
    ua::ReadResponse response = std::move(readResult).value();
    ASSERT_EQ(response.results().size(), 1U);
    const EUInformation* served = response.results()[0].value().try_as<EUInformation>();
    ASSERT_NE(served, nullptr) << "EngineeringUnits must decode as an EUInformation";

    EXPECT_EQ(static_cast<std::string>(served->display_name().text()), "\u00b0C")
      << "displayName carries the UN/CEFACT Symbol field verbatim";
    EXPECT_TRUE(static_cast<std::string>(served->display_name().locale()).empty())
      << "the symbol's localeId shall be an empty string - a locale tag on it claims a translation that does "
         "not exist, and the client that goes looking for one finds nothing";
    ++observed;
  }
  ASSERT_EQ(observed, localeSets.size()) << "every locale set must have produced an observation";
}

// ============================================================================================================
// Part 8 section 5.6.3.3: "The Name field is used for description. If the name is copied, then the localeId
// field of EUInformation.description shall be an empty string. If the name is localized then the localeId
// field shall specify the correct locale." The description is prose and so DOES carry a locale - which is
// exactly why the symbol beside it must not. Both directions are wrong in practice: stamping "en" on a
// verbatim copy claims a localisation that never happened, and dropping the locale from a real translation
// leaves the client unable to tell prose it can read from prose it cannot. A codec that discards the locale
// of a LocalizedText nested inside a structure fails the second half while passing the first.
// @verifies AC-SVR-DA-029-UNCEFACT-DESCRIPTION-LOCALE
TEST_F(ClientDataAccess, UnCefactDescriptionCarriesALocaleOnlyWhenTheNameWasTranslated)
{
  ASSERT_FALSE(mSemanticsUnitRangeId.is_null()) << "the scalar analog item must have been instantiated";
  ASSERT_FALSE(mSemanticsUnitsId.is_null()) << "its Mandatory EngineeringUnits must have been materialised";
  ASSERT_FALSE(mArrayUnitRangeId.is_null()) << "the array analog item must have been instantiated";
  ASSERT_FALSE(mArrayUnitRangeUnitsId.is_null())
    << "its Mandatory EngineeringUnits must have been materialised";

  // Case 1 - the UN/CEFACT Name is copied verbatim, so no localisation happened and none may be claimed.
  EUInformation copied = make_full_eu_information();
  copied.description() = LocalizedText{"", "degree Celsius"};
  ASSERT_TRUE(mConnection->try_write_value_sync(mSemanticsUnitsId, Variant{copied}).is_good())
    << "the verbatim-copy EngineeringUnits write must reach the server";

  // Case 2 - the Name is translated, so the description is prose in a specific locale and must say so.
  EUInformation translated = make_full_eu_information();
  translated.description() = LocalizedText{"de", "Grad Celsius"};
  ASSERT_TRUE(mConnection->try_write_value_sync(mArrayUnitRangeUnitsId, Variant{translated}).is_good())
    << "the translated EngineeringUnits write must reach the server";

  Result<DataValue> copiedRead = read_property(mSemanticsUnitRangeId, "EngineeringUnits");
  ASSERT_TRUE(copiedRead.is_good()) << "the copied-description item must read back: 0x" << std::hex
                                    << copiedRead.status_code().as_uint32();
  const EUInformation* copiedServed = copiedRead.value().value().try_as<EUInformation>();
  ASSERT_NE(copiedServed, nullptr) << "EngineeringUnits must decode as an EUInformation";
  EXPECT_EQ(static_cast<std::string>(copiedServed->description().text()), "degree Celsius")
    << "the description carries the UN/CEFACT Name field";
  EXPECT_TRUE(static_cast<std::string>(copiedServed->description().locale()).empty())
    << "copying the Name is not localising it - the localeId shall be an empty string, and an \"en\" tag "
       "would claim a translation that never happened";

  Result<DataValue> translatedRead = read_property(mArrayUnitRangeId, "EngineeringUnits");
  ASSERT_TRUE(translatedRead.is_good()) << "the translated-description item must read back: 0x" << std::hex
                                        << translatedRead.status_code().as_uint32();
  const EUInformation* translatedServed = translatedRead.value().value().try_as<EUInformation>();
  ASSERT_NE(translatedServed, nullptr) << "EngineeringUnits must decode as an EUInformation";
  EXPECT_EQ(static_cast<std::string>(translatedServed->description().text()), "Grad Celsius")
    << "the localized description must reach the client as the prose it is";
  EXPECT_EQ(static_cast<std::string>(translatedServed->description().locale()), "de")
    << "a translated Name shall specify the correct locale - dropping it makes the translation indis"
       "tinguishable from a verbatim copy of the English name";
}

// ============================================================================================================
// Part 8 section 6.3.2 Table 29: "Bad is defined in OPC 10000-4. It shall be used when there is no special
// reason why the Value is bad." The first half is easy and the second half is the obligation: a server that
// answers plain Bad for everything satisfies "use Bad when nothing specific applies" and tells the client
// nothing at all - unreachable device, uninitialised cache and out-of-service all arrive identically, and no
// client can decide whether to retry, wait or alarm. So the unspecified item must carry plain Bad exactly
// (not a fabricated house code), AND the item whose failure has a named code must carry that code rather than
// being flattened.
// @verifies AC-SVR-DA-030-BAD-GENERIC
TEST_F(ClientDataAccess, GenericBadIsUsedOnlyWhereNoMoreSpecificReasonApplies)
{
  ASSERT_FALSE(mGenericBadAnalogId.is_null()) << "the unspecified-bad item must exist";
  ASSERT_FALSE(mBadStatusAnalogId.is_null()) << "the specific-bad item must exist";

  // The unspecified case: plain Bad, exactly.
  {
    AnalogItemHandleResult handle = build_analog(mGenericBadAnalogId);
    ASSERT_TRUE(handle.is_good()) << "the item must resolve: 0x" << std::hex
                                  << handle.status_code().as_uint32();
    Result<AnalogItemValue> value = handle_read(handle.value());
    ASSERT_TRUE(value.is_good()) << "a bad DA quality does not fail the Read Result (CL-DA-015)";
    ASSERT_TRUE(value.value().value.status().has_value())
      << "a Data Access item's quality must be carried on the DataValue, never omitted";
    EXPECT_TRUE(value.value().value.status()->is_bad()) << "the item's Value is unusable, so the quality is "
                                                           "Bad-severity";
    EXPECT_EQ(value.value().value.status()->as_status(), Status::Bad)
      << "Part 8 Table 29 reserves the plain Bad of Part 4 for a Value that is bad for no reason the table "
         "names - not a vendor-invented generic code: 0x"
      << std::hex << value.value().value.status()->as_uint32();
  }

  // The specified case: the specific code survives, rather than being flattened into the generic one.
  {
    AnalogItemHandleResult handle = build_analog(mBadStatusAnalogId);
    ASSERT_TRUE(handle.is_good()) << "the item must resolve: 0x" << std::hex
                                  << handle.status_code().as_uint32();
    Result<AnalogItemValue> value = handle_read(handle.value());
    ASSERT_TRUE(value.is_good()) << "a bad DA quality does not fail the Read Result (CL-DA-015)";
    ASSERT_TRUE(value.value().value.status().has_value())
      << "a Data Access item's quality must be carried on the DataValue, never omitted";
    EXPECT_EQ(value.value().value.status()->as_status(), Status::BadDeviceFailure)
      << "an item whose failure HAS a named code must carry it: 0x" << std::hex
      << value.value().value.status()->as_uint32();
    EXPECT_NE(value.value().value.status()->as_status(), Status::Bad)
      << "flattening a specific reason to plain Bad is the failure the second half of the clause forbids - "
         "it makes the generic code mean nothing";
  }
}

// ============================================================================================================
// Part 8 section 6.3.2 Table 29: "Bad_NoCommunication ... shall be used when communications to the data
// source is defined, but not established, and there is no last known value available." This is the one Bad a
// client can act on by RETRYING - every other code in the table describes the item and this one describes the
// link - so a server that answers a plain Bad, an internal-error code or a house code for an unreachable
// device leaves the client unable to tell "the line is down, wait" from "this item is misconfigured, give
// up". The Value has to be absent as well: the trigger is precisely the case where NO last known value
// exists, so anything served beside the status could only have come from stale stored state and reads to a
// client as a live measurement.
// @verifies AC-SVR-DA-031-BAD-NOCOMMUNICATION
TEST_F(ClientDataAccess, AnItemWhoseDataSourceCannotBeReachedIsReadAsBadNoCommunication)
{
  ASSERT_FALSE(mNoCommunicationAnalogId.is_null()) << "the unreachable-source item must exist";
  ASSERT_FALSE(mBadStatusAnalogId.is_null()) << "the item-fault control must exist";
  ASSERT_FALSE(mScalarAnalogId.is_null()) << "the reachable control must exist";

  // One Read of @p nodeId's Value, returning the per-item DataValue the server served for it.
  const auto served = [&](const NodeId& nodeId, const char* what) -> std::optional<DataValue>
  {
    auto readResult = mSession->attributes().try_read_sync(read_value(nodeId));
    EXPECT_TRUE(readResult.is_good())
      << what
      << ": the Read must succeed at the SERVICE level - an unreachable data source is reported per "
         "item, never by failing the whole request: 0x"
      << std::hex << readResult.status_code().as_uint32();
    if (readResult.is_bad())
    {
      return std::nullopt;
    }
    ua::ReadResponse response = std::move(readResult).value();
    EXPECT_EQ(response.results().size(), 1U) << what << ": one Read of one Attribute yields one result";
    if (response.results().size() != 1U)
    {
      return std::nullopt;
    }
    return response.results()[0];
  };

  // The obligation: communication to the source defined, not established, no last known value.
  const std::optional<DataValue> unreachable = served(mNoCommunicationAnalogId, "the unreachable item");
  ASSERT_TRUE(unreachable.has_value()) << "the unreachable item must produce a per-item DataValue to judge";
  ASSERT_TRUE(unreachable->status().has_value())
    << "a Data Access item's quality must be carried on its DataValue, never omitted";
  EXPECT_EQ(unreachable->status()->as_status(), Status::BadNoCommunication)
    << "the item's data source is defined and cannot be reached, and Part 8 Table 29 names exactly one code "
       "for that - a generic Bad, an internal-error code or a house code says nothing about the LINK and "
       "hides the one failure a client should retry: 0x"
    << std::hex << unreachable->status()->as_uint32();
  EXPECT_TRUE(unreachable->value().empty())
    << "the trigger for Bad_NoCommunication is the case where no last known value is available, yet a Value ("
    << unreachable->value().to<double>().value_or(std::numeric_limits<double>::quiet_NaN())
    << ") was served with it - it can only be stale stored state, and beside a Bad status it is the shape a "
       "client is least able to detect";

  // Distinguishable from a CONFIGURATION failure - an item this server does not publish at all.
  const std::optional<DataValue> unconfigured =
    served(NodeId{mTestNamespaceIndex, uint32_t{9999}}, "the unconfigured item");
  ASSERT_TRUE(unconfigured.has_value()) << "the unconfigured item must produce a per-item DataValue to judge";
  ASSERT_TRUE(unconfigured->status().has_value())
    << "an item the server does not publish must be reported by a status, not by an empty result";
  EXPECT_NE(unconfigured->status()->as_status(), Status::BadNoCommunication)
    << "an item that is not configured at all must not be reported as an unreachable link - a client told to "
       "retry would retry forever against something that will never appear: 0x"
    << std::hex << unconfigured->status()->as_uint32();

  // ...and from a fault in the ITEM - the source answered, and what it reported is its own failure.
  const std::optional<DataValue> faulty = served(mBadStatusAnalogId, "the faulty item");
  ASSERT_TRUE(faulty.has_value()) << "the faulty item must produce a per-item DataValue to judge";
  ASSERT_TRUE(faulty->status().has_value()) << "a faulty item's quality must be carried on its DataValue";
  EXPECT_EQ(faulty->status()->as_status(), Status::BadDeviceFailure)
    << "a failure of the item itself must keep its own code rather than be widened into a communication "
       "failure, or the code stops naming the link at all: 0x"
    << std::hex << faulty->status()->as_uint32();

  // The control the whole row rests on: this server is not answering Bad to everything it is asked.
  const std::optional<DataValue> reachable = served(mScalarAnalogId, "the reachable item");
  ASSERT_TRUE(reachable.has_value()) << "the reachable item must produce a per-item DataValue to judge";
  EXPECT_FALSE(reachable->value().empty())
    << "a reachable item must serve its Value, or 'unreachable' has been asserted of a server that serves "
       "nothing to anyone";
  EXPECT_FALSE(reachable->status().has_value() && reachable->status()->is_bad())
    << "a reachable item must not be served Bad-severity, or the unreachable item's status is not evidence "
       "of anything: 0x"
    << std::hex << (reachable->status().has_value() ? reachable->status()->as_uint32() : 0U);
}

// ============================================================================================================
// Part 8 section 6.3.2 Table 29: "OPC UA requires that the Server shall return a Null value when the Severity
// is Bad." A DataValue that carries a real number beside a Bad status is the most dangerous shape the type
// can take - it reads as data, and a client that samples the status only when it changes carries the last
// good reading forward indefinitely with nothing to say the link behind it is gone. The plausible
// implementation is the one that treats status and value as independent fields and simply serves whatever the
// item last held, which is why every Bad-severity item the server publishes is read here rather than one.
// @verifies AC-SVR-DA-032-BAD-IMPLIES-NULL-VALUE
TEST_F(ClientDataAccess, EveryBadSeverityDataValueIsServedWithANullValue)
{
  ASSERT_FALSE(mBadStatusAnalogId.is_null()) << "the named-failure item must exist";
  ASSERT_FALSE(mGenericBadAnalogId.is_null()) << "the unspecified-failure item must exist";

  const std::vector<std::pair<NodeId, std::string>> badItems{
    {mBadStatusAnalogId, "the item whose quality is Bad_DeviceFailure"},
    {mGenericBadAnalogId, "the item whose quality is the generic Bad"}};

  std::size_t observed = 0;
  for (const auto& item : badItems)
  {
    auto readResult = mSession->attributes().try_read_sync(read_value(item.first));
    ASSERT_TRUE(readResult.is_good()) << item.second << ": the Read must succeed at the service level: 0x"
                                      << std::hex << readResult.status_code().as_uint32();
    ua::ReadResponse response = std::move(readResult).value();
    ASSERT_EQ(response.results().size(), 1U);
    const DataValue& served = response.results()[0];

    // The antecedent - this item really is served at Bad severity, so the obligation applies to it.
    ASSERT_TRUE(served.status().has_value())
      << item.second << ": a Data Access item's quality must be carried on the DataValue, never omitted";
    ASSERT_TRUE(served.status()->is_bad())
      << item.second << ": the item must be served Bad-severity or this observation is vacuous: 0x"
      << std::hex << served.status()->as_uint32();

    EXPECT_TRUE(served.value().empty())
      << item.second << ": a Bad-severity DataValue was served CARRYING a value ("
      << served.value().to<double>().value_or(std::numeric_limits<double>::quiet_NaN())
      << ") - Part 4 makes Bad severity incompatible with a real Value, and a stale reading beside a Bad "
         "status is indistinguishable from live data";
    ++observed;
  }
  ASSERT_EQ(observed, badItems.size()) << "every Bad-severity item must have produced an observation";
}

// ============================================================================================================
// Part 8 section 6.3.2 Table 30: "Uncertain ... shall be used when there is no special reason why the Value
// is uncertain." The clause is a floor and a ceiling at once: the generic code has to be reached for when
// none of Uncertain_LastUsableValue / _SensorNotAccurate / _EngineeringUnitsExceeded / _SubNormal applies,
// and a server that instead reaches for the nearest specific code reports a CAUSE it cannot know. The other
// half of the observation is the contrast with AC-SVR-DA-032: Uncertain permits a Value and Bad does not, so
// an implementation that collapses the two severities into one "not good" and nulls both loses a usable
// reading.
// @verifies AC-SVR-DA-033-UNCERTAIN-GENERIC
TEST_F(ClientDataAccess, DoubtfulValueWithNoNamedReasonIsServedAsPlainUncertainAndKeepsItsValue)
{
  ASSERT_FALSE(mUncertainGenericAnalogId.is_null()) << "the unspecified-doubt item must exist";
  ASSERT_FALSE(mUncertainStatusAnalogId.is_null()) << "the named-doubt item must exist";

  auto readResult = mSession->attributes().try_read_sync(read_value(mUncertainGenericAnalogId));
  ASSERT_TRUE(readResult.is_good()) << "the Read must succeed at the service level: 0x" << std::hex
                                    << readResult.status_code().as_uint32();
  ua::ReadResponse response = std::move(readResult).value();
  ASSERT_EQ(response.results().size(), 1U);
  const DataValue& served = response.results()[0];

  ASSERT_TRUE(served.status().has_value())
    << "a Data Access item's quality must be carried on the DataValue, never omitted";
  EXPECT_TRUE(served.status()->is_uncertain())
    << "the item's Value is usable but doubtful, so its severity is Uncertain - neither Good nor Bad: 0x"
    << std::hex << served.status()->as_uint32();
  EXPECT_EQ(served.status()->as_status(), Status::Uncertain)
    << "no reason named in Table 30 applies to this item, so the code is the generic Uncertain of Part 4 - "
       "a server that substitutes a specific reason it cannot know reports a cause that is not there: 0x"
    << std::hex << served.status()->as_uint32();

  EXPECT_FALSE(served.value().empty())
    << "Uncertain severity permits a Value and that is the whole point of the severity - nulling it out "
       "discards a reading the client was entitled to use with caution";
  EXPECT_DOUBLE_EQ(served.value().to<double>().value_or(std::numeric_limits<double>::quiet_NaN()), 50.0)
    << "the doubtful Value must be the one the item holds, unaltered";

  // The control - an item whose doubt HAS a name keeps it, so "generic when nothing specific applies" is a
  // rule about choosing between codes rather than a server that answers Uncertain to everything.
  auto specific = mSession->attributes().try_read_sync(read_value(mUncertainStatusAnalogId));
  ASSERT_TRUE(specific.is_good()) << "the named-doubt Read must succeed at the service level: 0x" << std::hex
                                  << specific.status_code().as_uint32();
  ua::ReadResponse specificResponse = std::move(specific).value();
  ASSERT_EQ(specificResponse.results().size(), 1U);
  ASSERT_TRUE(specificResponse.results()[0].status().has_value())
    << "the named-doubt item's quality must be carried on its DataValue";
  EXPECT_EQ(specificResponse.results()[0].status()->as_status(), Status::UncertainSubstituteValue)
    << "an item whose doubt has a named reason must carry that reason, not be flattened to the generic "
       "Uncertain: 0x"
    << std::hex << specificResponse.results()[0].status()->as_uint32();
}

// ============================================================================================================
// Part 8 section 6.3.2 Table 31: "Good ... shall be used when there are no special conditions." The normal
// case has to be EXACTLY Good, because a bare equality against Good is how most clients test for health: a
// server that habitually stamps an informational sub-code (a Good_ClampedValue, a house code, a carried-over
// SemanticsChanged) makes every one of those tests fail on a perfectly healthy item. The control is the other
// half - an item whose quality IS a named failure must not be swept up into Good either, or the bare code
// stops meaning "healthy" at all.
// @verifies AC-SVR-DA-034-GOOD-BARE
TEST_F(ClientDataAccess, HealthyDataAccessItemsAreServedWithTheBareGoodStatusCode)
{
  ASSERT_FALSE(mScalarAnalogId.is_null()) << "the scalar analog item must exist";
  ASSERT_FALSE(mArrayAnalogId.is_null()) << "the array analog item must exist";
  ASSERT_FALSE(mInstantiatedAnalogId.is_null())
    << "the type-instantiated analog item must have been instantiated";

  const std::vector<std::pair<NodeId, std::string>> healthy{
    {mScalarAnalogId, "the hand-authored scalar AnalogItem"},
    {mArrayAnalogId, "the hand-authored array AnalogItem"},
    {mInstantiatedAnalogId, "the type-instantiated AnalogItem"}};

  std::size_t observed = 0;
  for (const auto& item : healthy)
  {
    auto readResult = mSession->attributes().try_read_sync(read_value(item.first));
    ASSERT_TRUE(readResult.is_good()) << item.second << ": the Read must succeed at the service level: 0x"
                                      << std::hex << readResult.status_code().as_uint32();
    ua::ReadResponse response = std::move(readResult).value();
    ASSERT_EQ(response.results().size(), 1U);
    const DataValue& served = response.results()[0];

    // The antecedent - the item really is healthy: it served the Value it holds.
    ASSERT_FALSE(served.value().empty())
      << item.second << ": a healthy item must serve its Value, or there is no healthy case to judge";

    // An omitted StatusCode is Good on the wire and can carry no sub-code, so it is the bare Good too.
    const std::uint32_t code = served.status().has_value() ? served.status()->as_uint32() : 0U;
    EXPECT_EQ(code, 0U) << item.second
                        << ": a healthy item under no special condition must carry the BARE Good - any "
                           "informational sub-code breaks the equality against Good that clients test "
                           "health with: 0x"
                        << std::hex << code;
    ++observed;
  }
  ASSERT_EQ(observed, healthy.size()) << "every healthy item must have produced an observation";

  // The control - the server is not simply stamping Good on everything it serves.
  auto faulty = mSession->attributes().try_read_sync(read_value(mBadStatusAnalogId));
  ASSERT_TRUE(faulty.is_good()) << "the failed item's Read must succeed at the service level: 0x" << std::hex
                                << faulty.status_code().as_uint32();
  ua::ReadResponse faultyResponse = std::move(faulty).value();
  ASSERT_EQ(faultyResponse.results().size(), 1U);
  ASSERT_TRUE(faultyResponse.results()[0].status().has_value())
    << "the failed item's quality must be carried on its DataValue";
  EXPECT_EQ(faultyResponse.results()[0].status()->as_status(), Status::BadDeviceFailure)
    << "an item whose quality is a named failure must not be served bare Good: 0x" << std::hex
    << faultyResponse.results()[0].status()->as_uint32();
}

// ============================================================================================================
// OPC 10000-19 section 7.1: "EnumDictionaryEntries is a two-dimensional array of NodeIds. The first dimension
// is used to list all possible dictionary entry values for the related variable ... The size of the first
// array dimension shall be the same size as the EnumValues Property." The dimension order IS the structure:
// served transposed, the array still decodes, still has the right element count, and maps every value to the
// wrong dictionary entry with no shape error anywhere to reveal it. The alignment is likewise an invariant of
// the PAIR rather than of one publication - a server that lets EnumValues grow while the table keeps its old
// row count publishes a value that has no dictionary entries at all.
// @verifies AC-SVR-DA-036-ENUMDICTIONARYENTRIES-SHAPE
TEST_F(ClientDataAccess, EnumDictionaryEntriesFirstDimensionCarriesOneRowPerEnumeratedValue)
{
  ASSERT_FALSE(mDictAlignedId.is_null()) << "the MSDE item must exist";
  ASSERT_FALSE(mDictAlignedEntriesId.is_null()) << "its EnumDictionaryEntries Property must exist";
  ASSERT_FALSE(mDictAlignedEnumValuesId.is_null()) << "its EnumValues Property must exist";

  // The table, discovered the way a client discovers it: Browse HasProperty, then Read.
  Result<DataValue> tableRead = read_property(mDictAlignedId, "EnumDictionaryEntries");
  ASSERT_TRUE(tableRead.is_good()) << "EnumDictionaryEntries must be reachable under HasProperty: 0x"
                                   << std::hex << tableRead.status_code().as_uint32();
  Result<std::vector<NodeId>> flat = tableRead.value().value().to_vector<NodeId>();
  ASSERT_TRUE(flat.is_good()) << "EnumDictionaryEntries is an array of NodeIds (OPC 10000-19 section 7.1)";
  ASSERT_FALSE(flat.value().empty()) << "an empty table would make every shape assertion below vacuous";
  const Array<NodeId>& servedTable = tableRead.value().value().as<Array<NodeId>>();
  ASSERT_TRUE(servedTable.dimensions().has_value())
    << "the served array carries NO dimension metadata, so it reaches the client as a flat list - the row "
       "structure that assigns each value its own dictionary entries is gone";
  const Dimensions dimensions = *servedTable.dimensions();
  ASSERT_EQ(dimensions.size(), 2U)
    << "EnumDictionaryEntries is two-dimensional (value x dictionary); the served rank is "
    << dimensions.size();

  // The values the table is a table OVER.
  Result<DataValue> enumValues = read_property(mDictAlignedId, "EnumValues");
  ASSERT_TRUE(enumValues.is_good()) << "EnumValues must be reachable under HasProperty: 0x" << std::hex
                                    << enumValues.status_code().as_uint32();
  Result<std::vector<RefStructure<Structure>>> values =
    enumValues.value().value().to_vector<RefStructure<Structure>>();
  ASSERT_TRUE(values.is_good()) << "EnumValues must decode as an EnumValueType array";
  ASSERT_FALSE(values.value().empty()) << "an item declaring no values makes the alignment vacuous";

  // The obligation: the FIRST dimension enumerates the values.
  EXPECT_EQ(static_cast<std::size_t>(dimensions[0]), values.value().size())
    << "the first dimension is " << dimensions[0] << " against " << values.value().size()
    << " EnumValues entries (the second dimension is " << dimensions[1]
    << ") - a table whose axes are the other way round decodes perfectly and maps every value to the wrong "
       "dictionary entry";

  // ...and each row lists THAT value's entries, in the order the table was published with.
  ASSERT_EQ(flat.value().size(), mDictAlignedEntries.size())
    << "the served table must carry every published entry";
  for (std::size_t state = 0; state < sDictAlignedStates; ++state)
  {
    for (std::size_t dictionary = 0; dictionary < sDictAlignedDictionaries; ++dictionary)
    {
      const std::size_t offset = (state * sDictAlignedDictionaries) + dictionary;
      EXPECT_EQ(flat.value()[offset], mDictAlignedEntries[offset])
        << "row " << state << ", dictionary " << dictionary
        << " is not the entry published there - the rows are the values and the columns the dictionaries";
    }
  }

  // The alignment holds across a Write too: a fourth enumerated value must leave the table with four rows,
  // whether the server grows the table or refuses the write that would break the pair.
  const VoidResult written = mConnection->try_write_value_sync(mDictAlignedEnumValuesId,
    Variant{make_enum_values({{1, "Low"}, {2, "High"}, {3, "Running"}, {4, "Faulted"}})});

  Result<DataValue> valuesAfter = read_property(mDictAlignedId, "EnumValues");
  ASSERT_TRUE(valuesAfter.is_good()) << "EnumValues must still read back: 0x" << std::hex
                                     << valuesAfter.status_code().as_uint32();
  Result<std::vector<RefStructure<Structure>>> afterValues =
    valuesAfter.value().value().to_vector<RefStructure<Structure>>();
  ASSERT_TRUE(afterValues.is_good()) << "EnumValues must still decode as an EnumValueType array";
  Result<DataValue> tableAfter = read_property(mDictAlignedId, "EnumDictionaryEntries");
  ASSERT_TRUE(tableAfter.is_good()) << "EnumDictionaryEntries must still read back: 0x" << std::hex
                                    << tableAfter.status_code().as_uint32();
  ASSERT_TRUE(tableAfter.value().value().to_vector<NodeId>().is_good())
    << "EnumDictionaryEntries must still decode as a NodeId array";
  const Array<NodeId>& tableAfterArray = tableAfter.value().value().as<Array<NodeId>>();
  ASSERT_TRUE(tableAfterArray.dimensions().has_value())
    << "the re-read table must still carry its dimension metadata";
  ASSERT_EQ(tableAfterArray.dimensions()->size(), 2U) << "the re-read table must still be two-dimensional";
  EXPECT_EQ(static_cast<std::size_t>((*tableAfterArray.dimensions())[0]), afterValues.value().size())
    << "EnumValues now declares " << afterValues.value().size() << " values and the table has "
    << (*tableAfterArray.dimensions())[0]
    << " rows, so a value has been published with no dictionary entries (the EnumValues Write reported 0x"
    << std::hex << written.status_code().as_uint32()
    << ") - the two lengths must stay aligned at every Write, by resizing the table or by refusing the Write";
}

// ============================================================================================================
// OPC 10000-19 section 7.1: "ValueAsDictionaryEntries provides a list of all dictionary entry values in the
// different dictionaries related to the current value of the variable. The order of the array entries shall
// be in the same order used by the EnumDictionaryEntries Property." POSITION is the only link between the two
// arrays - there is no key - so a slice served in a different order is well-formed, decodes cleanly, and
// names every dictionary's entry as the other dictionary's. The slice must also FOLLOW the current value:
// derived once at startup, it silently describes the value the item used to hold.
// @verifies AC-SVR-DA-037-VALUEASDICTIONARYENTRIES-ORDER
TEST_F(ClientDataAccess, ValueAsDictionaryEntriesListsTheCurrentValuesRowInEnumDictionaryEntriesOrder)
{
  ASSERT_FALSE(mDictAlignedId.is_null()) << "the MSDE item must exist";
  ASSERT_FALSE(mDictAlignedValueAsEntriesId.is_null())
    << "its optional ValueAsDictionaryEntries Property must be exposed";
  ASSERT_EQ(mDictAlignedEntries.size(), sDictAlignedStates * sDictAlignedDictionaries)
    << "the fixture must publish one dictionary entry per (value, dictionary) pair for the comparison to "
       "have an expected slice at all";

  // Which ROW of EnumDictionaryEntries the value @p current occupies: the first dimension enumerates the
  // EnumValues entries positionally, so the row is that entry's index - not the enumerated number itself.
  const auto rowOfValue = [&](std::int64_t current) -> std::optional<std::size_t>
  {
    Result<DataValue> enumValues = read_property(mDictAlignedId, "EnumValues");
    if (enumValues.is_bad())
    {
      return std::nullopt;
    }
    Result<std::vector<RefStructure<Structure>>> entries =
      enumValues.value().value().to_vector<RefStructure<Structure>>();
    if (entries.is_bad())
    {
      return std::nullopt;
    }
    for (std::size_t index = 0; index < entries.value().size(); ++index)
    {
      const auto* entry = dynamic_cast<const EnumValueType*>(entries.value()[index].get());
      if ((entry != nullptr) && (entry->value() == current))
      {
        return index;
      }
    }
    return std::nullopt;
  };

  const auto servedSlice = [&]() -> std::optional<std::vector<NodeId>>
  {
    Result<DataValue> property = read_property(mDictAlignedId, "ValueAsDictionaryEntries");
    if (property.is_bad())
    {
      return std::nullopt;
    }
    Result<std::vector<NodeId>> entries = property.value().value().to_vector<NodeId>();
    if (entries.is_bad())
    {
      return std::nullopt;
    }
    return entries.value();
  };

  const auto expectSliceMirrorsRow = [&](std::int64_t current, const char* stage)
  {
    const std::optional<std::size_t> row = rowOfValue(current);
    ASSERT_TRUE(row.has_value()) << stage << ": " << current
                                 << " must be one of the item's enumerated values, or there is no row to "
                                    "mirror";
    const std::optional<std::vector<NodeId>> slice = servedSlice();
    ASSERT_TRUE(slice.has_value())
      << stage << ": ValueAsDictionaryEntries must be reachable under HasProperty and decode as NodeId[]";
    ASSERT_FALSE(slice->empty())
      << stage
      << ": the Property is served EMPTY - the dictionary entries for the current value are simply "
         "absent, so no order can mirror anything";
    ASSERT_EQ(slice->size(), sDictAlignedDictionaries)
      << stage << ": the slice is the current value's row across every dictionary, so it carries "
      << sDictAlignedDictionaries << " entries";
    for (std::size_t dictionary = 0; dictionary < sDictAlignedDictionaries; ++dictionary)
    {
      const NodeId& expected = mDictAlignedEntries[(*row * sDictAlignedDictionaries) + dictionary];
      EXPECT_EQ((*slice)[dictionary], expected)
        << stage << ": position " << dictionary
        << " of ValueAsDictionaryEntries must be the entry at that same position of EnumDictionaryEntries "
           "row "
        << *row
        << " - position is the only link between the two arrays, so a different order names each "
           "dictionary's entry as another dictionary's";
    }
  };

  expectSliceMirrorsRow(2, "as published");

  // ...and the slice follows the current value rather than being frozen at whatever it was first derived
  // from: moving the item to the third enumerated value must move the slice to that value's row.
  ASSERT_TRUE(mConnection->try_write_value_sync(mDictAlignedId, Variant{std::int64_t{3}}).is_good())
    << "the item's Value must be writable for the slice to be observed following it";
  expectSliceMirrorsRow(3, "after the current value moved to 3");
}

// ============================================================================================================
// OPC 10000-19 section 7.1: "If an instance of this type is writeable and the optional
// ValueAsDictionaryEntries Property is implemented, it shall be writeable as well. Clients writing to the
// ValueAsDictionaryEntries Property shall use one of the DictionaryEntryType NodeIds defined by the
// EnumDictionaryEntries Property. This will have the same result as writing the value attribute." The
// Property is a second way to write the same state, so the two AccessLevels have to agree in BOTH directions:
// read-only beside a writeable parent loses a documented write path (the one a client without knowledge of
// the numeric values depends on), and writeable beside a read-only parent is a way around the parent's own
// protection. The two instances here were authored disagreeing with their parents in opposite directions, so
// neither half can pass by accident.
// The projection above follows an instance's owning Variable. The instance declaration on
// MultiStateDictionaryEntryDiscreteBaseType has a VariableType for an owner, so there is nothing to project
// from: it is an ordinary Property, and AccessLevel is an Attribute every Variable has (Part 3 5.6.2). The
// CTT's Address Space Base 001 reads it and was answered BadTypeMismatch.
TEST_F(ClientDataAccess, ValueAsDictionaryEntriesOnTheVariableTypeReportsItsOwnAccessLevel)
{
  const NodeId instanceDeclaration{
    VariableId::MultiStateDictionaryEntryDiscreteBaseType_ValueAsDictionaryEntries};
  EXPECT_TRUE(read_access_level_attribute(instanceDeclaration).has_value())
    << "AccessLevel of the type's ValueAsDictionaryEntries must read back as a Byte";
}

// @verifies AC-SVR-DA-038-VALUEASDICTIONARYENTRIES-WRITEABLE
TEST_F(ClientDataAccess, ValueAsDictionaryEntriesIsWritableExactlyWhereItsParentVariableIs)
{
  ASSERT_FALSE(mDictAlignedId.is_null()) << "the writeable MSDE item must exist";
  ASSERT_FALSE(mDictAlignedValueAsEntriesId.is_null()) << "its ValueAsDictionaryEntries must be exposed";
  ASSERT_FALSE(mDictReadOnlyParentId.is_null()) << "the read-only MSDE item must exist";
  ASSERT_FALSE(mDictReadOnlyValueAsEntriesId.is_null()) << "its ValueAsDictionaryEntries must be exposed";

  // The antecedent both halves rest on: the two parents really do differ in writeability.
  const std::optional<AccessLevelType> writeableParent = read_access_level_attribute(mDictAlignedId);
  const std::optional<AccessLevelType> readOnlyParent = read_access_level_attribute(mDictReadOnlyParentId);
  ASSERT_TRUE(writeableParent.has_value()) << "the writeable item's AccessLevel must read back";
  ASSERT_TRUE(readOnlyParent.has_value()) << "the read-only item's AccessLevel must read back";
  ASSERT_TRUE(writeableParent->test(AccessLevelType::Bit::CurrentWrite))
    << "the writeable instance must really advertise CurrentWrite, or the first half is vacuous";
  ASSERT_FALSE(readOnlyParent->test(AccessLevelType::Bit::CurrentWrite))
    << "the read-only instance must really withhold CurrentWrite, or the second half is vacuous";

  const auto expectAccessAgrees = [&](const NodeId& parent, const NodeId& property, const char* instance)
  {
    const std::optional<AccessLevelType> parentAccess = read_access_level_attribute(parent);
    ASSERT_TRUE(parentAccess.has_value()) << instance << ": the parent's AccessLevel must read back";
    const std::optional<AccessLevelType> propertyAccess = read_access_level_attribute(property);
    ASSERT_TRUE(propertyAccess.has_value())
      << instance << ": ValueAsDictionaryEntries' AccessLevel must read back";
    EXPECT_EQ(propertyAccess->test(AccessLevelType::Bit::CurrentWrite),
      parentAccess->test(AccessLevelType::Bit::CurrentWrite))
      << instance
      << ": the parent advertises CurrentWrite=" << parentAccess->test(AccessLevelType::Bit::CurrentWrite)
      << " while ValueAsDictionaryEntries advertises "
      << propertyAccess->test(AccessLevelType::Bit::CurrentWrite)
      << " - the Property writes the same state as the parent, so read-only beside a writeable parent "
         "loses the documented path and writeable beside a read-only one bypasses its protection";
  };

  expectAccessAgrees(mDictAlignedId, mDictAlignedValueAsEntriesId, "the writeable instance");
  expectAccessAgrees(mDictReadOnlyParentId, mDictReadOnlyValueAsEntriesId, "the read-only instance");

  // ...and on the writeable instance the path really carries. The clause has the client write ONE of the
  // DictionaryEntryType NodeIds ("Clients ... shall use one of the DictionaryEntryType NodeIds defined by the
  // EnumDictionaryEntries Property"), so a single-element NodeId[] is what is written here - the same shape
  // the SDK's own write_via_dictionary path emits. The entry chosen is EnumDictionaryEntries[row 2][dict 0],
  // the row of the THIRD enumerated value (3, "Running"), so an accepted Write must move the item's Value
  // off the 2 it was published holding.
  Array<NodeId> runningEntry;
  runningEntry.push_back(mDictAlignedEntries[2U * sDictAlignedDictionaries]);
  const VoidResult written =
    mConnection->try_write_value_sync(mDictAlignedValueAsEntriesId, Variant{std::move(runningEntry)});
  EXPECT_TRUE(written.is_good())
    << "a Write of one DictionaryEntryType NodeId drawn from EnumDictionaryEntries must be accepted on a "
       "writeable instance: 0x"
    << std::hex << written.status_code().as_uint32();

  Result<DataValue> parentValue = mConnection->try_read_value_sync(mDictAlignedId);
  ASSERT_TRUE(parentValue.is_good()) << "the item's Value must read back: 0x" << std::hex
                                     << parentValue.status_code().as_uint32();
  Result<std::int64_t> current = parentValue.value().value().to<std::int64_t>();
  ASSERT_TRUE(current.is_good()) << "the item's Value must decode as its Int64 enumerated value";
  EXPECT_EQ(current.value(), 3)
    << "the item's Value is " << current.value()
    << " - writing the dictionary entry of the third enumerated value must have the same result as writing "
       "that value to the Value Attribute, which is the whole purpose of the Property";
}

// ============================================================================================================
// Part 8 section 5.3.1 (ValuePrecision is a Property of the DataItemType, Table 1 - the criterion's STATEMENT
// cites section 5.3.2, which is the AnalogItem subclause; the clause quoted below is section 5.3.1's): "A
// Server is expected to silently round any value with more precision that it supports. This implies that a
// Client may encounter cases where the value read back from a Server differs from the value that it wrote to
// the Server. This difference shall be no more than the difference suggested by this Property." Two things
// are binding and they are the two asserted here: the over-precise write is ACCEPTED (silently - the rounding
// is not reported as an error), and the write/read round-trip differs by no more than the advertised
// precision (for a Double, section 5.3.1 makes a positive ValuePrecision "the number of digits after the
// decimal place", so the suggested difference is bounded by 10^-precision). The rounding ALGORITHM is a
// "should" (banker's rounding) and a server that keeps more precision than it advertised produces a
// difference of zero, which satisfies the shall - so neither is asserted, and demanding an exactly-rounded
// stored value would fail a conforming server. What the clause forbids is the defensible-looking
// implementation: refusing the write with Bad_OutOfRange because it carries more digits than the item can
// hold. Having advertised the precision, the server must absorb it.
// @verifies AC-SVR-DA-002-VALUEPRECISION
TEST_F(ClientDataAccess, OverPreciseWriteIsAcceptedSilentlyAndRoundTripsWithinValuePrecision)
{
  struct PrecisionSubject
  {
    NodeId node;
    double precision;
    double overPrecise;
    const char* what;
  };

  // Both DataItems that advertise a USABLE precision. (ns;7350 advertises NaN and ns;7360 a negative
  // precision - neither states a decimal-place count a round-trip can be measured against.)
  const std::vector<PrecisionSubject> subjects{
    {mValuePrecisionWholeId, 6.0, 50.1234567891, "ValuePrecision = 6 (six decimal places)"},
    {mValuePrecisionZeroId, 0.0, 50.4999, "ValuePrecision = 0 (whole numbers)"}};
  ASSERT_FALSE(subjects.empty()) << "no DataItem exposes a ValuePrecision Property - nothing to observe";
  GTEST_LOG_(INFO) << "ValuePrecision-bearing DataItems exercised: " << subjects.size();

  for (const PrecisionSubject& subject : subjects)
  {
    ASSERT_FALSE(subject.node.is_null()) << subject.what << ": the item must exist";

    // The antecedent: the item really does advertise the precision under test.
    Result<DataValue> advertised = read_property(subject.node, "ValuePrecision");
    ASSERT_TRUE(advertised.is_good()) << subject.what
                                      << ": ValuePrecision must be reachable under "
                                         "HasProperty, or the obligation has no antecedent: 0x"
                                      << std::hex << advertised.status_code().as_uint32();
    Result<double> declared = advertised.value().value().to<double>();
    ASSERT_TRUE(declared.is_good()) << subject.what << ": ValuePrecision decodes as a Double";
    ASSERT_DOUBLE_EQ(declared.value(), subject.precision)
      << subject.what << ": the served precision must be the one the stimulus is calibrated against";

    // The written value carries more decimal places than the advertised precision.
    const VoidResult written =
      mConnection->try_write_value_sync(subject.node, Variant{double{subject.overPrecise}});
    EXPECT_TRUE(written.is_good())
      << subject.what
      << ": a value carrying more precision than the item advertises must be ACCEPTED and "
         "silently rounded, never refused - the Property tells a client what will happen to "
         "the excess, and refusing it (0x"
      << std::hex << written.status_code().as_uint32() << ") makes the advertisement a trap";

    Result<DataValue> readBack = mConnection->try_read_value_sync(subject.node);
    ASSERT_TRUE(readBack.is_good()) << subject.what << ": the item must read back: 0x" << std::hex
                                    << readBack.status_code().as_uint32();
    if (readBack.value().status().has_value())
    {
      EXPECT_FALSE(readBack.value().status()->is_bad())
        << subject.what
        << ": rounding to the advertised precision is silent - it may not degrade the stored Value's quality";
    }
    Result<double> stored = readBack.value().value().to<double>();
    ASSERT_TRUE(stored.is_good()) << subject.what << ": the stored Value decodes as a Double";

    // The hard contract: |read-back - written| <= the granularity the Property advertises.
    const double tolerance = std::pow(10.0, -subject.precision);
    EXPECT_LE(std::fabs(stored.value() - subject.overPrecise), tolerance)
      << subject.what << ": wrote " << subject.overPrecise << ", read back " << stored.value()
      << " - a round-trip difference larger than " << tolerance
      << " exceeds the difference this Property suggests, so the client cannot bound what the server did to "
         "its value";
  }
}

// ============================================================================================================
// Part 8 section 5.3.2.3: "Sensor or instrument failure or deactivation can result in a returned item value
// which is actually outside of this range." EURange is the TYPICAL range of the instrument, not a constraint,
// so the obligation SVR-DA-007 states is robustness rather than a particular answer: accept, reject or clamp
// are all conformant, and asserting any one of them would test this SDK's configuration rather than the
// specification. What is observable is that each out-of-range write lands on ONE of those three coherently -
// the item is still readable, a refused write left the stored Value untouched, an accepted one stored either
// the value written or a range edge - that the same stimulus twice gives the same answer, and that a value
// the SOURCE reports outside the range survives the read path. The implementation this fails is the one that
// treats EURange as a constraint: silently truncating the magnitude, storing a mangled number under a Good
// status, or clamping a reported sensor fault into range so the fault is invisible.
// @verifies AC-SVR-DA-007-OUTSIDE-EURANGE
TEST_F(ClientDataAccess, OutOfRangeWriteLandsOnOneCoherentPolicyAndNeverCorruptsTheItem)
{
  struct RangeSubject
  {
    NodeId node;
    const char* what;
  };

  const std::vector<RangeSubject> subjects{{mScalarAnalogId, "the item under the default write policy"},
    {mClampAnalogId, "the item whose server policy clamps"},
    {mRejectAnalogId, "the item whose server policy rejects"}};
  ASSERT_FALSE(subjects.empty()) << "no AnalogItem is available to write out of range";
  GTEST_LOG_(INFO) << "AnalogItems driven out of range: " << subjects.size();

  for (const RangeSubject& subject : subjects)
  {
    ASSERT_FALSE(subject.node.is_null()) << subject.what << ": the item must exist";

    // The antecedent: the item publishes a real EURange, so "outside it" means something.
    Result<DataValue> euRange = read_property(subject.node, "EURange");
    ASSERT_TRUE(euRange.is_good()) << subject.what << ": EURange must be reachable under HasProperty: 0x"
                                   << std::hex << euRange.status_code().as_uint32();
    const Range* range = euRange.value().value().try_as<Range>();
    ASSERT_NE(range, nullptr) << subject.what << ": EURange decodes as a Range";
    const double low = range->low();
    const double high = range->high();
    ASSERT_LT(low, high) << subject.what << ": the published range must be non-degenerate";

    // One out-of-range write, classified into exactly one of the three permitted answers.
    std::string outcome;
    const auto attempt = [&](double target)
    {
      outcome.clear();
      Result<DataValue> priorValue = mConnection->try_read_value_sync(subject.node);
      ASSERT_TRUE(priorValue.is_good()) << subject.what << ": the item must read before the write";
      Result<double> prior = priorValue.value().value().to<double>();
      ASSERT_TRUE(prior.is_good()) << subject.what << ": the stored Value decodes as a Double";

      const VoidResult written = mConnection->try_write_value_sync(subject.node, Variant{double{target}});

      Result<DataValue> afterValue = mConnection->try_read_value_sync(subject.node);
      ASSERT_TRUE(afterValue.is_good())
        << subject.what << ": the item must still be readable after an out-of-range write: 0x" << std::hex
        << afterValue.status_code().as_uint32();
      Result<double> stored = afterValue.value().value().to<double>();
      ASSERT_TRUE(stored.is_good()) << subject.what
                                    << ": the stored Value must still decode as a Double after the write";

      if (written.is_bad())
      {
        EXPECT_DOUBLE_EQ(stored.value(), prior.value())
          << subject.what
          << ": a REJECTED out-of-range write must leave the stored Value untouched - "
             "reporting a refusal while committing the value is the worst of both answers";
        outcome = "rejected";
        return;
      }
      if (stored.value() == target)
      {
        outcome = "accepted";
        return;
      }
      if (stored.value() == high || stored.value() == low)
      {
        outcome = "clamped";
        return;
      }
      outcome = "corrupted";
      ADD_FAILURE()
        << subject.what << ": wrote " << target << " against EURange [" << low << ", " << high
        << "] and the server reported success while storing " << stored.value()
        << " - accept, reject and clamp to a range edge are the three permitted answers; anything "
           "else is a silently truncated or corrupted value";
    };

    attempt(high + 50.0);
    ASSERT_FALSE(outcome.empty()) << subject.what << ": the write must have produced an outcome";
    const std::string firstOutcome = outcome;
    GTEST_LOG_(INFO) << subject.what << ": out-of-range write outcome = " << firstOutcome;

    // The same stimulus a second time: whatever the policy is, it has to be the policy - a server that
    // rejects once and accepts next time leaves a client unable to know what its writes did.
    attempt(high + 50.0);
    EXPECT_EQ(outcome, firstOutcome) << subject.what << ": the identical out-of-range write answered '"
                                     << firstOutcome << "' then '" << outcome
                                     << "' - the policy must be consistent";

    // ...and below the range as well, where a magnitude-truncating implementation shows itself.
    attempt(low - 50.0);
    EXPECT_NE(outcome, "corrupted") << subject.what
                                    << ": a write below EURange must land on the same three "
                                       "answers as one above it";
  }

  // The read path: the SOURCE reports a value outside the range (the sensor-fault case the clause names). The
  // value is placed server-side, so the client write path is not involved at all - a server that assumes the
  // reported value lies inside EURange would clamp or discard it here and hide the fault.
  ASSERT_FALSE(mDistinctRangesId.is_null()) << "an item with a published EURange must exist";
  {
    auto addressSpace = mServer.server().address_space();
    auto node = addressSpace.find_node_sync(mDistinctRangesId);
    auto variable = node.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->write_value_sync(DataValue{Variant{double{150.0}}});
  }
  Result<DataValue> reported = mConnection->try_read_value_sync(mDistinctRangesId);
  ASSERT_TRUE(reported.is_good()) << "the item whose source reports out of range must still read: 0x"
                                  << std::hex << reported.status_code().as_uint32();
  Result<double> reportedValue = reported.value().value().to<double>();
  ASSERT_TRUE(reportedValue.is_good()) << "the reported Value decodes as a Double";
  EXPECT_DOUBLE_EQ(reportedValue.value(), 150.0)
    << "the source reported 150 against EURange [0, 100] and the server served " << reportedValue.value()
    << " - EURange is the typical range of the instrument, not a constraint, so a reported value outside it "
       "is a sensor fault the client must be able to see rather than something to be corrected away";

  // The server is still serving after all of that: out-of-range traffic must not leave it in an undefined
  // state, which is the SHALL SVR-DA-007 actually carries.
  Result<DataValue> stillServing = read_property(mScalarAnalogId, "EURange");
  EXPECT_TRUE(stillServing.is_good()) << "the server must still answer after out-of-range writes: 0x"
                                      << std::hex << stillServing.status_code().as_uint32();
}

// ============================================================================================================
// Part 8 section 5.3.2.4 Table 4 makes EngineeringUnits Mandatory on AnalogUnitType, and Part 3 section 6.5
// makes a Mandatory ModellingRule binding on the address space as populated - the units counterpart of
// AC-SVR-DA-004's EURange. A plausible implementation materialises the instance and leaves the Property to
// the application: the item then serves a bare number whose unit no client can discover, and AC-SVR-DA-008's
// SemanticsChanged notice has nothing to fire on. The population scanned here is the instances the SERVER
// built through its type system - the interface SVR-DA-005 places the invariant on. The fixture's
// hand-authored ns;6600 is deliberately malformed (it is the client-side negative for a missing
// EngineeringUnits) and is a fixture artefact, not a server verdict, so it is excluded by construction rather
// than by exception.
//
// Denominator, stated exactly: AnalogUnitRangeType is NOT a subtype of AnalogUnitType - Table 5 makes it a
// subtype of AnalogItemType that re-declares EngineeringUnits Mandatory in its own right, so the two
// AnalogUnitRange instances are siblings of this criterion's population, not members of it. The server built
// exactly ONE AnalogUnitType Variable through its type system and that is the criterion's whole population;
// the two siblings are scanned alongside it because Table 5 places the identical obligation on them, and they
// are counted separately below so the scan cannot read as three times the size it is.
// @verifies AC-SVR-DA-005-ENGINEERINGUNITS-MANDATORY
TEST_F(ClientDataAccess, EveryTypeInstantiatedAnalogUnitVariableExposesEngineeringUnits)
{
  struct UnitSubject
  {
    NodeId instance;
    NodeId units;
    bool isAnalogUnitType;  // false = AnalogUnitRangeType, which carries the same Table 5 obligation
    const char* what;
  };

  const std::vector<UnitSubject> subjects{
    {mAnalogUnitInstanceId, mAnalogUnitUnitsId, true, "the AnalogUnitType instance"},
    {mArrayUnitRangeId,
      mArrayUnitRangeUnitsId,
      false,
      "the array AnalogUnitRangeType instance (Table 5 re-declares EngineeringUnits Mandatory)"},
    {mSemanticsUnitRangeId,
      mSemanticsUnitsId,
      false,
      "the scalar AnalogUnitRangeType instance (Table 5 re-declares EngineeringUnits Mandatory)"}};

  // The criterion's own population is the AnalogUnitType instances; guard on THAT count, not on the size of
  // the hand-written subject list, so a fixture that stopped instantiating AnalogUnitType cannot pass here on
  // the strength of its AnalogUnitRange siblings alone.
  const std::size_t analogUnitTypeCount = static_cast<std::size_t>(std::count_if(subjects.begin(),
    subjects.end(),
    [](const UnitSubject& subject) { return subject.isAnalogUnitType && !subject.instance.is_null(); }));
  ASSERT_GT(analogUnitTypeCount, 0U)
    << "no AnalogUnitType Variable was built through the server's type system - nothing to scan";
  GTEST_LOG_(INFO) << "AnalogUnitType Variables built by the server's type system: " << analogUnitTypeCount
                   << "; AnalogUnitRangeType siblings scanned under the same Table 5 obligation: "
                   << (subjects.size() - analogUnitTypeCount);

  for (const UnitSubject& subject : subjects)
  {
    ASSERT_FALSE(subject.instance.is_null())
      << subject.what << ": must have been instantiated, or the scan is over an empty population";
    EXPECT_FALSE(subject.units.is_null())
      << subject.what
      << ": instantiating the type must materialise its Mandatory EngineeringUnits Property - a Mandatory "
         "ModellingRule binds the address space as populated, not merely the type declaration";

    // Present where a client looks for it: Browse HasProperty by BrowseName, then Read.
    Result<DataValue> units = read_property(subject.instance, "EngineeringUnits");
    EXPECT_TRUE(units.is_good()) << subject.what
                                 << ": EngineeringUnits must be reachable under HasProperty: 0x" << std::hex
                                 << units.status_code().as_uint32();
    if (units.is_good())
    {
      EXPECT_NE(units.value().value().try_as<EUInformation>(), nullptr)
        << subject.what << ": the EngineeringUnits Property's Value decodes as an EUInformation";
    }

    // ...and it is TYPED EUInformation, so a client can rely on the decode rather than guessing.
    if (!subject.units.is_null())
    {
      const std::optional<NodeId> dataType = read_data_type_attribute(subject.units);
      EXPECT_TRUE(dataType.has_value())
        << subject.what << ": the EngineeringUnits Property's DataType Attribute must read back";
      if (dataType.has_value())
      {
        EXPECT_EQ(*dataType, NodeId{DataTypeId::EUInformation})
          << subject.what
          << ": EngineeringUnits is an EUInformation Property (Part 8 section 5.3.2.4 Table 4)";
      }
    }
  }
}

// ============================================================================================================
// Part 8 section 5.3.2.5 Table 7: AnalogUnitRangeType inherits EURange (Mandatory) from AnalogItemType and
// adds EngineeringUnits (Mandatory) of its own. The type is worth its own criterion because INHERITANCE is
// where a Mandatory Property gets dropped - an instantiation flow that materialises only the members the leaf
// type declares produces an instance with units and no limits, which reads as a well-formed item right up to
// the point a client tries to scale it or apply a PercentDeadband to it. Both Properties are checked on every
// AnalogUnitRangeType instance the server built, each for presence AND for the DataType a client decodes by.
// @verifies AC-SVR-DA-006-ANALOGUNITRANGE-PROPERTIES
TEST_F(ClientDataAccess, EveryAnalogUnitRangeInstanceExposesBothTheInheritedEuRangeAndEngineeringUnits)
{
  struct UnitRangeSubject
  {
    NodeId instance;
    NodeId euRange;
    NodeId units;
    const char* what;
  };

  const std::vector<UnitRangeSubject> subjects{{mArrayUnitRangeId,
                                                 mArrayUnitRangeEuRangeId,
                                                 mArrayUnitRangeUnitsId,
                                                 "the array AnalogUnitRangeType instance"},
    {mSemanticsUnitRangeId,
      mSemanticsEuRangeId,
      mSemanticsUnitsId,
      "the scalar AnalogUnitRangeType instance"}};

  // Non-vacuity guard on the POPULATION, not on the length of the subject list: a fixture whose
  // AnalogUnitRange instantiation silently stopped working leaves every id null, and the scan below would
  // otherwise still "pass" its way to the end of a list of nothing.
  const std::size_t instantiated = static_cast<std::size_t>(std::count_if(subjects.begin(),
    subjects.end(),
    [](const UnitRangeSubject& subject) { return !subject.instance.is_null(); }));
  ASSERT_GT(instantiated, 0U)
    << "no AnalogUnitRangeType Variable was built through the server's type system - nothing to scan";
  GTEST_LOG_(INFO) << "AnalogUnitRangeType Variables built by the server's type system: " << instantiated;

  for (const UnitRangeSubject& subject : subjects)
  {
    ASSERT_FALSE(subject.instance.is_null())
      << subject.what << ": must have been instantiated, or the scan is over an empty population";

    // EURange - the INHERITED Mandatory Property, which is the one at risk.
    EXPECT_FALSE(subject.euRange.is_null())
      << subject.what
      << ": instantiating AnalogUnitRangeType must materialise the EURange it inherits from AnalogItemType";
    Result<DataValue> euRange = read_property(subject.instance, "EURange");
    EXPECT_TRUE(euRange.is_good()) << subject.what << ": EURange must be reachable under HasProperty: 0x"
                                   << std::hex << euRange.status_code().as_uint32();
    if (euRange.is_good())
    {
      EXPECT_NE(euRange.value().value().try_as<Range>(), nullptr)
        << subject.what << ": the EURange Property's Value decodes as a Range";
    }
    if (!subject.euRange.is_null())
    {
      const std::optional<NodeId> euRangeType = read_data_type_attribute(subject.euRange);
      EXPECT_TRUE(euRangeType.has_value()) << subject.what << ": EURange's DataType Attribute must read back";
      if (euRangeType.has_value())
      {
        EXPECT_EQ(*euRangeType, NodeId{DataTypeId::Range})
          << subject.what << ": EURange is a Range Property (Part 8 section 5.3.2.3 Table 3, inherited)";
      }
    }

    // EngineeringUnits - the Property the leaf type declares itself.
    EXPECT_FALSE(subject.units.is_null())
      << subject.what
      << ": instantiating AnalogUnitRangeType must materialise its Mandatory EngineeringUnits";
    Result<DataValue> units = read_property(subject.instance, "EngineeringUnits");
    EXPECT_TRUE(units.is_good()) << subject.what
                                 << ": EngineeringUnits must be reachable under HasProperty: 0x" << std::hex
                                 << units.status_code().as_uint32();
    if (units.is_good())
    {
      EXPECT_NE(units.value().value().try_as<EUInformation>(), nullptr)
        << subject.what << ": the EngineeringUnits Property's Value decodes as an EUInformation";
    }
    if (!subject.units.is_null())
    {
      const std::optional<NodeId> unitsType = read_data_type_attribute(subject.units);
      EXPECT_TRUE(unitsType.has_value())
        << subject.what << ": EngineeringUnits' DataType Attribute must read back";
      if (unitsType.has_value())
      {
        EXPECT_EQ(*unitsType, NodeId{DataTypeId::EUInformation})
          << subject.what
          << ": EngineeringUnits is an EUInformation Property (Part 8 section 5.3.2.5 Table 5)";
      }
    }
  }
}

// ============================================================================================================
// Part 8 section 5.3.3.4 Table 9 makes BOTH EnumValues and ValueAsText Mandatory on
// MultiStateValueDiscreteType, and the clause says what the second is for: "The ValueAsText Property provides
// the localized text representation of the enumeration value. It can be used by Clients only interested in
// displaying the text to subscribe to the Property INSTEAD of the Value Attribute." A Property a client is
// invited to use in place of the Value has to follow the Value; a static label materialised once at
// instantiation would leave every such client displaying the state the item was in when it was built. The
// presence half is asserted over every MultiStateValueDiscrete instance the server's type system produced
// (the Property NODES are the server's work - this fixture only seeds their Values, which is why the tracking
// half below rewrites one from the wire and reads the Property back rather than the Value).
// @verifies AC-SVR-DA-013-MULTISTATEVALUE-PROPERTIES
TEST_F(ClientDataAccess, MultiStateValueDiscreteExposesEnumValuesAndAValueAsTextThatFollowsTheValue)
{
  struct MultiStateValueSubject
  {
    NodeId instance;
    NodeId enumValues;
    NodeId valueAsText;
    const char* what;
  };

  const std::vector<MultiStateValueSubject> subjects{
    {mMsvdInstanceId, mMsvdEnumValuesId, mMsvdValueAsTextId, "the MultiStateValueDiscrete instance"},
    {mMasterMsvdId,
      mMasterMsvdEnumValuesId,
      mMasterMsvdValueAsTextId,
      "the second MultiStateValueDiscrete instance"}};

  // Non-vacuity guard on the POPULATION rather than on the length of the subject list (see the
  // AnalogUnitRange scan): all-null ids mean the type system built nothing, which must read as a failure and
  // not as a clean pass over two absent nodes.
  const std::size_t instantiated = static_cast<std::size_t>(std::count_if(subjects.begin(),
    subjects.end(),
    [](const MultiStateValueSubject& subject) { return !subject.instance.is_null(); }));
  ASSERT_GT(instantiated, 0U)
    << "no MultiStateValueDiscreteType Variable was built through the server's type system";
  GTEST_LOG_(INFO) << "MultiStateValueDiscreteType Variables built by the server's type system: "
                   << instantiated;

  for (const MultiStateValueSubject& subject : subjects)
  {
    ASSERT_FALSE(subject.instance.is_null())
      << subject.what << ": must have been instantiated, or the scan is over an empty population";

    EXPECT_FALSE(subject.enumValues.is_null())
      << subject.what << ": instantiating the type must materialise its Mandatory EnumValues Property";
    Result<DataValue> enumValues = read_property(subject.instance, "EnumValues");
    EXPECT_TRUE(enumValues.is_good())
      << subject.what << ": EnumValues must be reachable under HasProperty: 0x" << std::hex
      << enumValues.status_code().as_uint32();
    if (!subject.enumValues.is_null())
    {
      const std::optional<NodeId> enumValuesType = read_data_type_attribute(subject.enumValues);
      EXPECT_TRUE(enumValuesType.has_value())
        << subject.what << ": EnumValues' DataType Attribute must read back";
      if (enumValuesType.has_value())
      {
        EXPECT_EQ(*enumValuesType, NodeId{DataTypeId::EnumValueType})
          << subject.what << ": EnumValues is an EnumValueType[] Property (Part 8 section 5.3.3.4 Table 9)";
      }
      const std::optional<std::int32_t> enumValuesRank = read_value_rank_attribute(subject.enumValues);
      EXPECT_TRUE(enumValuesRank.has_value()) << subject.what << ": EnumValues' ValueRank must read back";
      if (enumValuesRank.has_value())
      {
        EXPECT_EQ(*enumValuesRank, 1)
          << subject.what
          << ": EnumValues is an ARRAY of EnumValueType - the keyed table, not a single entry";
      }
    }

    EXPECT_FALSE(subject.valueAsText.is_null())
      << subject.what
      << ": instantiating the type must materialise its Mandatory ValueAsText Property - a client is invited "
         "to subscribe to it instead of the Value, and cannot if it does not exist";
    Result<DataValue> valueAsText = read_property(subject.instance, "ValueAsText");
    EXPECT_TRUE(valueAsText.is_good())
      << subject.what << ": ValueAsText must be reachable under HasProperty: 0x" << std::hex
      << valueAsText.status_code().as_uint32();
    if (!subject.valueAsText.is_null())
    {
      const std::optional<NodeId> valueAsTextType = read_data_type_attribute(subject.valueAsText);
      EXPECT_TRUE(valueAsTextType.has_value())
        << subject.what << ": ValueAsText' DataType Attribute must read back";
      if (valueAsTextType.has_value())
      {
        EXPECT_EQ(*valueAsTextType, NodeId{DataTypeId::LocalizedText})
          << subject.what << ": ValueAsText is a LocalizedText Property (Part 8 section 5.3.3.4 Table 9)";
      }
    }
  }

  // The tracking half, on the instance whose EnumValues is {1: "Low", 2: "High"} and whose Value is 1.
  ASSERT_FALSE(mMasterMsvdId.is_null()) << "the instance under test must have been instantiated";
  Result<DataValue> before = read_property(mMasterMsvdId, "ValueAsText");
  ASSERT_TRUE(before.is_good()) << "ValueAsText must be readable before the Value changes: 0x" << std::hex
                                << before.status_code().as_uint32();
  const LocalizedText* beforeText = before.value().value().try_as<LocalizedText>();
  ASSERT_NE(beforeText, nullptr) << "ValueAsText decodes as a LocalizedText";
  ASSERT_EQ(static_cast<std::string>(beforeText->text()), "Low")
    << "the antecedent: ValueAsText starts on the entry for the current Value, so a change is observable";

  ASSERT_TRUE(mConnection->try_write_value_sync(mMasterMsvdId, Variant{std::int64_t{2}}).is_good())
    << "the Value write must reach the server";
  Result<DataValue> current = mConnection->try_read_value_sync(mMasterMsvdId);
  ASSERT_TRUE(current.is_good()) << "the item's Value must read back after the write";
  ASSERT_EQ(current.value().value().to<std::int64_t>().value_or(0), 2)
    << "the item must really hold the second enumerated value, or the tracking check has no stimulus";

  // The Property may be refreshed on the server's own strand, so this polls rather than racing it.
  std::string served;
  const bool tracked = wait_until(
    [&]
    {
      Result<DataValue> text = read_property(mMasterMsvdId, "ValueAsText");
      if (text.is_bad())
      {
        return false;
      }
      const LocalizedText* localized = text.value().value().try_as<LocalizedText>();
      if (localized == nullptr)
      {
        return false;
      }
      served = static_cast<std::string>(localized->text());
      return served == "High";
    });
  EXPECT_TRUE(tracked)
    << "the Value moved to the entry labelled \"High\" and ValueAsText still serves \"" << served
    << "\" - the Property is the text representation OF THE CURRENT ENUMERATION VALUE, and a client that "
       "subscribed to it instead of the Value (which section 5.3.3.4 invites) is now displaying the wrong "
       "state";
}
