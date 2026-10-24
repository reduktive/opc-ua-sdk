// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientMonitorModify / ClientMonitorFilter / ClientMonitorTrigger / ClientMonitorQueue clusters of
/// the
///        client integration-test matrix (13 rows that MODIFY / FILTER / SET-TRIGGERING / OBSERVE-THE-QUEUE
///        of DATA-CHANGE monitored items).
///
/// These are END-TO-END integration tests of the TIER-1/TIER-2 managed monitored-item control surface (client
/// design section 7.4 / section 8.4) reached through the internal `ua::client::detail::ConnectionImpl`
/// orchestrator and the public self-acting `ua::client::MonitoredItem` handle it hands back. The harness is
/// the SAME `MisbehavingServer`-backed fixture the committed ClientMonitoredItem cluster uses (a real
/// `Client` bound to a `MisbehavingServer`'s crypto + trusted store over ephemeral TCP, an activated Session
/// wrapped into a started `ConnectionImpl`, the always-on Publish pump). Control is driven through:
///   - the tier-2 `MonitoredItem` SELF-ACTIONS (`modify_async` / `set_mode_async` / `delete_async`) that
///   route
///     through the data-change `MonitoredItemOwner` interface and flatten to a `VoidResult`;
///   - the tier-1 `ConnectionImpl` pass-throughs (`set_monitoring_mode_async`,
///   `modify_monitored_items_async`,
///     `set_triggering_async`, `set_triggering_by_handles_async`);
///   - the DATA SINK (the per-item callback) - what actually reaches the user; and
///   - the WIRE OBSERVER (`MisbehavingServer::set_request_observer`) - the DECODED outgoing requests, so a
///   row
///     can assert what the client put on (or kept off) the wire: a DataChangeFilter ExtensionObject, a
///     modify's revised queue size, a SetTriggering's link order, or the ABSENCE of a local pre-flight Read.
/// The server is bent with `set_response_mutator` to inject service-level / per-item / per-link errors,
/// overflow InfoBits, and reordered notifications.
///
/// Falsifiability: every test encodes its matrix row's `[neg: ...]` falsifier and asserts the EXACT
/// observable. Timing is ALWAYS bounded polling on an observable, never a fixed sleep.
///
/// =====================================================================================================
/// CALIBRATION - where a matrix oracle assumes a client-side feature that is NOT built (assert REAL behavior;
/// see the authoring report for the batched write-up). These are the required findings this file pins:
/// =====================================================================================================
///   1. DATA-CHANGE FILTER IS PLUMBED ONTO THE CREATE WIRE (CL-MI-011 BUILT). `monitor_data_change_async` ->
///      `build_monitored_item_create_request` now sets `MonitoringParameters.filter` from the caller's
///      `MonitorRequest.filter` (a DataChangeFilter/AggregateFilter -> ExtensionObject; monostate -> null).
///      (`mi_modify_async` filter modify + retention across a session-CHANGED recreate remain follow-ups,
///      OPEN-MI-011.)
///        - AbsoluteDeadbandEncodedOnWire PINS the encoding: the wire CreateMonitoredItems carries the
///          DataChangeFilter with deadbandType=Absolute(1), deadbandValue=2.5 (matches the matrix oracle).
///        - NoFilterOmitsExtensionObject matches the oracle (no filter -> null on wire) trivially, precisely
///          because the client never synthesizes one.
///   2. LOCAL PercentDeadband RANGE VALIDATION ON THE MONITOR PATH (CL-MI-024 BUILT). An out-of-[0,100] (or
///      non-finite) PercentDeadband is rejected locally with Bad_DeadbandFilterInvalid and NO wire request; a
///      valid PercentDeadband is monitored and its filter reaches the wire (CL-MI-011).
///      PercentDeadbandRangeValidatedLocally pins this.
///   3. LOCAL SAME-SUBSCRIPTION PRE-FLIGHT ON SetTriggering (CL-MI-027 BUILT).
///   `set_triggering_by_handles_async`
///      now checks `subscription_of(handle) == subscriptionId` for the trigger + every add/remove handle
///      before building the request, so a cross-subscription link is rejected LOCALLY with
///      Bad_InvalidArgument and nothing reaches the wire (Part 4 section 5.12.5.1).
///      CrossSubscriptionRejectedLocally asserts the local reject.
///   4. THE MonitoredItem HANDLE IS A CONSTRUCTION-TIME IMMUTABLE SNAPSHOT. `modify_async` returns a bare
///      `VoidResult`; the ModifyMonitoredItems response's revisedSamplingInterval/revisedQueueSize are
///      DISCARDED and there is no queue-size field on the handle at all. So a successful modify updates NO
///      client-side snapshot. UpdatesLocalSnapshotOnSuccess asserts the REAL behavior (the create-time
///      revised interval is unchanged after modify) and reports CL-MI-019's "local snapshot" as unbuilt.
///   5. DISABLED MODE DOES NOT LOCALLY GATE DISPATCH. SetMonitoringMode is a pure pass-through wire op that
///   never
///      touches pipeline dispatch registration; the client relies on the SERVER to stop reporting a Disabled
///      item (correct pass-through - the handle's mode snapshot is construction-time and would be stale). If
///      a (mis)behaving server injects a post-disable notification, the client DISPATCHES it.
///      SetModeDisabledStopsDispatch asserts the REAL behavior (dispatch continues) and reports the
///      divergence.
///   6. FLATTEN PATHS ATTACH NO CLIENT SOURCE-TAG FOR SERVICE/OP-LEVEL BADS. modify/set-mode/delete surface
///   the
///      exact server StatusCode but synthesize no ErrorDetail for a service-level or per-item bad (only the
///      transport-error, routing lookup-miss, and connection-gone paths carry a source-tagged detail).
///      ServiceAndOpLevelErrorsSurfaceWithErrorDetail asserts the exact codes AND the real source-tagged
///      detail on the lookup-miss path.

#include "compliance_helpers.h"

#include "misbehaving_server.h"

#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"
#include "ua_connection_handle_factory.h"
#include "ua_data_change_monitored_item_owner.h"

#include "ua_application_configuration.h"
#include "ua_array.h"
#include "ua_client.h"
#include "ua_client_monitored_item.h"
#include "ua_client_subscription.h"
#include "ua_create_monitored_items_request.h"
#include "ua_create_monitored_items_response.h"
#include "ua_create_subscription_request.h"
#include "ua_data_change_filter.h"
#include "ua_data_change_notification.h"
#include "ua_data_change_trigger.h"
#include "ua_data_value.h"
#include "ua_deadband_type.h"
#include "ua_delete_monitored_items_response.h"
#include "ua_error_detail.h"
#include "ua_logger.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_modify_monitored_items_response.h"
#include "ua_monitored_item_create_request.h"
#include "ua_monitored_item_modify_request.h"
#include "ua_monitored_item_notification.h"
#include "ua_monitoring_mode.h"
#include "ua_monitoring_parameters.h"
#include "ua_access_level_type.h"
#include "ua_datatype_id.h"
#include "ua_node_accessor.h"
#include "ua_node_id.h"
#include "ua_range.h"
#include "ua_referencetype_id.h"
#include "ua_variabletype_id.h"
#include "ua_notification_message.h"
#include "ua_publish_response.h"
#include "ua_read_request.h"
#include "ua_ref_structure.h"
#include "ua_set_monitoring_mode_request.h"
#include "ua_set_monitoring_mode_response.h"
#include "ua_set_triggering_request.h"
#include "ua_set_triggering_response.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_structure.h"
#include "ua_to_string.h"
#include "ua_variable_id.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionImplTestAccess;
using ua::client::detail::ConnectionState;
using ua::test_helpers::MisbehavingServer;

namespace
{

// A standard NS0 Variable that exists on every server and carries a value, so a MonitoredItem can be created.
// Injected value changes / statuses ride the response mutator (the MisbehavingServer has no user-writable
// node), so the tests never depend on the server updating it - see the ClientMonitoredItem cluster's GOTCHA.
const NodeId monitoredNode{VariableId::Server_ServerStatus_State};

/// Creates an AnalogItemType Variable carrying an EURange of [0, 100] and returns its NodeId.
///
/// A PercentDeadband expresses a percentage OF THAT RANGE, so it is only defined for a node that has
/// one: OPC 10000-8 6.2 says the filter "applies only to AnalogItems with an EURange Property", and
/// Table 29 names the failure - Bad_DeadbandFilterInvalid when "a PercentDeadband is not supported,
/// since an EURange is not configured". monitoredNode (Server_ServerStatus_State) has no EURange and
/// is not even an analog value, so a row exercising the VALID case needs a node like this one.
NodeId create_analog_item_with_eu_range(ua::test_helpers::MisbehavingServer& server)
{
  auto addressSpace = server.server().address_space();
  const std::uint16_t namespaceIndex =
    addressSpace.add_namespace_sync(addressSpace.create_namespace("urn:test:monitor:analog", {}));

  const NodeId analogId{namespaceIndex, std::uint32_t{6000}};
  auto analogNode = addressSpace.create_node_sync(analogId, ua::NodeClass::Variable);
  auto analog = analogNode.as<ua::VariableAccessor>();
  analog->set_browse_name(ua::QualifiedName{namespaceIndex, "AnalogWithRange"});
  analog->set_display_name(ua::LocalizedText{"", "AnalogWithRange"});
  analog->set_data_type(NodeId{ua::DataTypeId::Double});
  analog->set_access_level(ua::AccessLevelType{ua::AccessLevelType::Bit::CurrentRead});
  analog->write_value_sync(double{50.0});
  analogNode.add_reference_sync(
    NodeId{ua::ReferenceTypeId::HasTypeDefinition}, NodeId{ua::VariableTypeId::AnalogItemType});

  const NodeId euRangeId{namespaceIndex, std::uint32_t{6001}};
  auto euRangeNode = addressSpace.create_node_sync(euRangeId, ua::NodeClass::Variable);
  auto euRange = euRangeNode.as<ua::VariableAccessor>();
  euRange->set_browse_name(ua::QualifiedName{0, "EURange"});
  euRange->set_data_type(NodeId{ua::DataTypeId::Range});
  auto range = std::make_unique<ua::Range>();
  range->low() = 0.0;
  range->high() = 100.0;
  euRange->write_value_sync(ua::DataValue{ua::Variant{ua::RefStructure<ua::Structure>{std::move(range)}}});
  euRangeNode.add_reference_sync(
    NodeId{ua::ReferenceTypeId::HasTypeDefinition}, NodeId{ua::VariableTypeId::PropertyType});
  analogNode.add_reference_sync(NodeId{ua::ReferenceTypeId::HasProperty}, euRangeId);

  addressSpace.find_node_sync(NodeId{ua::ObjectId::ObjectsFolder})
    .add_reference_sync(NodeId{ua::ReferenceTypeId::Organizes}, analogId);
  return analogId;
}

// ---------------------------------------------------------------------------------------------
// Thread-safe sink for the DataValues delivered to a monitored item's data callback.
// ---------------------------------------------------------------------------------------------
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

  std::size_t size() const
  {
    std::lock_guard lock(mMutex);
    return mValues.size();
  }

  // True iff some delivered DataValue carries an int32 == @p sentinel.
  bool has_int32(std::int32_t sentinel) const
  {
    std::lock_guard lock(mMutex);
    for (const auto& value : mValues)
    {
      if (value.value().is_int32() && value.value().as<std::int32_t>() == sentinel)
      {
        return true;
      }
    }
    return false;
  }

  // The index (in delivery order) of the first delivered DataValue carrying @p sentinel, or -1 if absent.
  int index_of_int32(std::int32_t sentinel) const
  {
    std::lock_guard lock(mMutex);
    for (std::size_t i = 0; i < mValues.size(); ++i)
    {
      if (mValues[i].value().is_int32() && mValues[i].value().as<std::int32_t>() == sentinel)
      {
        return static_cast<int>(i);
      }
    }
    return -1;
  }

  // How many delivered DataValues carry an int32 == @p sentinel (to prove no collapse / no duplication).
  std::size_t count_int32(std::int32_t sentinel) const
  {
    std::lock_guard lock(mMutex);
    std::size_t count = 0;
    for (const auto& value : mValues)
    {
      if (value.value().is_int32() && value.value().as<std::int32_t>() == sentinel)
      {
        ++count;
      }
    }
    return count;
  }

  // True iff some delivered DataValue carries the exact @p status (InfoBits included - so the Overflow bit is
  // part of the comparison).
  bool has_status(ua::StatusCode status) const
  {
    std::lock_guard lock(mMutex);
    for (const auto& value : mValues)
    {
      if (value.status().has_value() && *value.status() == status)
      {
        return true;
      }
    }
    return false;
  }

  // True iff some delivered DataValue's status has the Overflow DataValue InfoBit set.
  bool has_overflow_bit() const
  {
    std::lock_guard lock(mMutex);
    for (const auto& value : mValues)
    {
      if (value.status().has_value() && value.status()->overflow())
      {
        return true;
      }
    }
    return false;
  }

private:
  mutable std::mutex mMutex;
  std::vector<DataValue> mValues;
};

// ---------------------------------------------------------------------------------------------
// WireCapture: a read-only snapshot of the DECODED requests the client put on the wire, populated on a server
// strand by the request observer. Guarded by a mutex (the observer and the test thread run concurrently).
// ---------------------------------------------------------------------------------------------
struct WireCapture
{
  mutable std::mutex mutex;

  std::size_t readCount = 0;
  std::size_t createMonitoredItemsCount = 0;
  std::size_t modifyCount = 0;
  std::size_t setTriggeringCount = 0;

  // Last CreateMonitoredItems: whether the single item carried a filter ExtensionObject, and if so its
  // decoded DataChangeFilter fields.
  bool lastCreateHadFilter = false;
  std::uint32_t lastCreateDeadbandType = 0;
  double lastCreateDeadbandValue = 0.0;

  // Last ModifyMonitoredItems: the single item's requested queue size.
  std::uint32_t lastModifyQueueSize = 0;

  // Last SetTriggering: the trigger id and the ordered add / remove link id lists.
  std::uint32_t lastTriggeringItemId = 0;
  std::vector<std::uint32_t> lastLinksToAdd;
  std::vector<std::uint32_t> lastLinksToRemove;

  void observe(const ua::Structure& request)
  {
    std::lock_guard lock(mutex);
    if (dynamic_cast<const ua::ReadRequest*>(&request))
    {
      ++readCount;
    }
    else if (const auto* create = dynamic_cast<const ua::CreateMonitoredItemsRequest*>(&request))
    {
      ++createMonitoredItemsCount;
      lastCreateHadFilter = false;
      if (create->items_to_create().size() >= 1)
      {
        const auto& params = create->items_to_create()[0].requested_parameters();
        if (params.filter())
        {
          if (const auto* filter = dynamic_cast<const ua::DataChangeFilter*>(params.filter().get()))
          {
            lastCreateHadFilter = true;
            lastCreateDeadbandType = filter->deadband_type();
            lastCreateDeadbandValue = filter->deadband_value();
          }
          else
          {
            // A non-DataChange filter still counts as a present ExtensionObject.
            lastCreateHadFilter = true;
          }
        }
      }
    }
    else if (const auto* modify = dynamic_cast<const ua::ModifyMonitoredItemsRequest*>(&request))
    {
      ++modifyCount;
      if (modify->items_to_modify().size() >= 1)
      {
        lastModifyQueueSize = modify->items_to_modify()[0].requested_parameters().queue_size();
      }
    }
    else if (const auto* trigger = dynamic_cast<const ua::SetTriggeringRequest*>(&request))
    {
      ++setTriggeringCount;
      lastTriggeringItemId = trigger->triggering_item_id();
      lastLinksToAdd.assign(trigger->links_to_add().begin(), trigger->links_to_add().end());
      lastLinksToRemove.assign(trigger->links_to_remove().begin(), trigger->links_to_remove().end());
    }
  }

  std::size_t read_count() const
  {
    std::lock_guard lock(mutex);
    return readCount;
  }

  std::size_t create_count() const
  {
    std::lock_guard lock(mutex);
    return createMonitoredItemsCount;
  }

  std::size_t modify_count() const
  {
    std::lock_guard lock(mutex);
    return modifyCount;
  }

  std::size_t set_triggering_count() const
  {
    std::lock_guard lock(mutex);
    return setTriggeringCount;
  }

  bool last_create_had_filter() const
  {
    std::lock_guard lock(mutex);
    return lastCreateHadFilter;
  }

  std::uint32_t last_create_deadband_type() const
  {
    std::lock_guard lock(mutex);
    return lastCreateDeadbandType;
  }

  double last_create_deadband_value() const
  {
    std::lock_guard lock(mutex);
    return lastCreateDeadbandValue;
  }

  std::uint32_t last_modify_queue_size() const
  {
    std::lock_guard lock(mutex);
    return lastModifyQueueSize;
  }

  std::vector<std::uint32_t> last_links_to_add() const
  {
    std::lock_guard lock(mutex);
    return lastLinksToAdd;
  }

  std::vector<std::uint32_t> last_links_to_remove() const
  {
    std::lock_guard lock(mutex);
    return lastLinksToRemove;
  }
};

// Busy-wait until @p predicate holds or @p timeout elapses. Returns the final predicate value.
bool wait_until(const std::function<bool()>& predicate, std::chrono::milliseconds timeout = 8000ms)
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

// ----- Response-mutator building blocks (each edits a response in place, before signing) -----

void set_publish_sequence(ua::PublishResponse& publish, std::uint32_t sequenceNumber)
{
  publish.notification_message().sequence_number() = sequenceNumber;
}

// One {clientHandle, value[, status]} entry to inject into a Publish's DataChangeNotification, IN ORDER.
struct HandleValue
{
  std::uint32_t clientHandle = 0;
  ua::Variant value;
  std::optional<ua::StatusCode> status;
};

void set_data_change(ua::PublishResponse& publish, std::vector<HandleValue> items)
{
  publish.notification_message().notification_data().clear();
  auto notification = std::make_unique<ua::DataChangeNotification>();
  for (auto& entry : items)
  {
    ua::MonitoredItemNotification item;
    item.client_handle() = entry.clientHandle;
    ua::DataValue dataValue;
    dataValue.value() = std::move(entry.value);
    if (entry.status)
    {
      dataValue.status() = *entry.status;
    }
    item.value() = std::move(dataValue);
    notification->monitored_items().push_back(std::move(item));
  }
  ua::RefStructure<ua::Structure> ref;
  ref.inner_unique_ptr() = std::move(notification);
  publish.notification_message().notification_data().push_back(std::move(ref));
}

// ----- Response casts (null for any other response type) -----

ua::CreateMonitoredItemsResponse* as_create_items(ua::Response& response)
{
  return dynamic_cast<ua::CreateMonitoredItemsResponse*>(response.second.get());
}

ua::PublishResponse* as_publish(ua::Response& response)
{
  return dynamic_cast<ua::PublishResponse*>(response.second.get());
}

ua::ModifyMonitoredItemsResponse* as_modify(ua::Response& response)
{
  return dynamic_cast<ua::ModifyMonitoredItemsResponse*>(response.second.get());
}

ua::SetMonitoringModeResponse* as_set_mode(ua::Response& response)
{
  return dynamic_cast<ua::SetMonitoringModeResponse*>(response.second.get());
}

ua::DeleteMonitoredItemsResponse* as_delete(ua::Response& response)
{
  return dynamic_cast<ua::DeleteMonitoredItemsResponse*>(response.second.get());
}

ua::SetTriggeringResponse* as_set_triggering(ua::Response& response)
{
  return dynamic_cast<ua::SetTriggeringResponse*>(response.second.get());
}

// A StatusCode carrying the Overflow DataValue InfoBit (implies InfoType == DataValue; e.g. 0x00000480).
ua::StatusCode with_overflow()
{
  ua::StatusCode status{ua::Status::Good};
  status.overflow(true);
  return status;
}

// ---------------------------------------------------------------------------------------------
// MisbehavingMonitorControlFixture: the ClientMonitoredItem harness plus the control accessors this file
// drives (raw modify/set-triggering wire ops, triggering-by-handles, and blocking wrappers over the tier-2
// MonitoredItem self-actions).
// ---------------------------------------------------------------------------------------------
class MisbehavingMonitorControlFixture
{
public:
  explicit MisbehavingMonitorControlFixture(MisbehavingServer& server)
  {
    auto appConfig = ua::test_utils::create_test_config();
    const auto clientStore = server.client_certificate_store();
    const auto ownCertificates = clientStore->try_get_application_certificates_sync();
    if (ownCertificates.is_good() && !ownCertificates.value().empty() &&
        ownCertificates.value().front().certificate)
    {
      const auto sanUris = ownCertificates.value().front().certificate->san_uris();
      if (!sanUris.empty())
        appConfig.application_description_part().applicationUri = sanUris.front();
    }
    ua::client::CreateConfig clientConfig{
      .identity = ApplicationIdentity::load_default(), .application = std::move(appConfig)};
    mClient.emplace(Client::create(mThreadPool.executor(),
      std::move(clientConfig),
      ua::client::ClientComponents{.crypto = server.crypto(),
        .applicationGroupCertificateStore = clientStore,
        .logLevel = LogLevel::Warning}));

    CoreClient::OpenChannelConfig openConfig;
    openConfig.endpointUrl = server.endpoint_url_none();
    openConfig.timeout = 5000ms;
    auto channel = mClient->core().open_channel_sync(openConfig);
    auto session = channel.create_session_sync({.sessionName = "ClientMonitorControlMatrix"});
    session.activate_sync();

    mConnection = ConnectionImpl::create(
      mThreadPool.executor(), std::move(session), ua::client::detail::ConnectionConfig{}, Logger{});
    mStartStatus = start_and_wait(*mConnection);
  }

  ~MisbehavingMonitorControlFixture()
  {
    if (mConnection)
    {
      (void)close_and_wait(*mConnection);
    }
    mConnection.reset();
    mClient.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  MisbehavingMonitorControlFixture(const MisbehavingMonitorControlFixture&) = delete;
  MisbehavingMonitorControlFixture& operator=(const MisbehavingMonitorControlFixture&) = delete;

  ConnectionImpl& conn()
  {
    return *mConnection;
  }

  Connection public_connection()
  {
    return ua::client::detail::ConnectionHandleFactory::make_connection(mConnection);
  }

  const VoidResult& start_status() const
  {
    return mStartStatus;
  }

  ConnectionState state() const
  {
    auto info = mConnection->info();
    return info ? info->state : ConnectionState::Closed;
  }

  std::size_t monitored_item_count() const
  {
    auto info = ConnectionImplTestAccess::pipeline_info(*mConnection);
    return info ? info->monitoredItemCount : 0;
  }

  std::size_t unknown_handle_drops() const
  {
    auto info = ConnectionImplTestAccess::pipeline_info(*mConnection);
    return info ? info->unknownHandleDrops : 0;
  }

  // ---- Blocking helpers over the async orchestrator surface ----

  static VoidResult start_and_wait(ConnectionImpl& connection)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    connection.start_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static VoidResult close_and_wait(ConnectionImpl& connection)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    connection.close_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  Result<std::uint32_t> create_subscription(double publishingInterval)
  {
    std::promise<Result<std::uint32_t>> promise;
    auto future = promise.get_future();
    mConnection->create_subscription_async(
      publishingInterval, [&promise](Result<std::uint32_t> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  // Attaches a data-change monitor via the OWNER path (monitor_data_change_async), returning the public
  // self-acting MonitoredItem handle. The item is registered with the data-change owner, so its self-actions
  // (modify/set-mode/delete) and triggering-by-handle resolution work.
  MonitoredItemResult monitor(std::uint32_t subscriptionId, ua::client::MonitorRequest request,
    const std::shared_ptr<DataValueSink>& sink)
  {
    std::promise<MonitoredItemResult> promise;
    auto future = promise.get_future();
    mConnection->monitor_data_change_async(
      subscriptionId,
      std::move(request),
      [sink](DataChangeEvent event) { sink->push(std::move(event.value)); },
      [&promise](MonitoredItemResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  // A default data-change monitor on monitoredNode with the given requested sampling interval.
  MonitoredItemResult monitor_value(
    std::uint32_t subscriptionId, double samplingIntervalMs, const std::shared_ptr<DataValueSink>& sink)
  {
    ua::client::MonitorRequest request;
    request.nodeId = monitoredNode;
    request.attribute = ua::AttributeId::Value;
    request.samplingIntervalMs = samplingIntervalMs;
    return monitor(subscriptionId, std::move(request), sink);
  }

  // ---- Tier-2 MonitoredItem self-actions (flatten to VoidResult through the owner interface) ----

  static VoidResult modify_item(MonitoredItem& item, ua::client::MonitorRequest request)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    item.modify_async(
      std::move(request), [&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static VoidResult set_item_mode(MonitoredItem& item, ua::MonitoringMode mode)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    item.set_mode_async(mode, [&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  static VoidResult delete_item(MonitoredItem& item)
  {
    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    item.delete_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  // ---- Tier-1 pass-through wire ops ----

  Result<ua::SetTriggeringResponse> set_triggering_raw(ua::SetTriggeringRequest request)
  {
    std::promise<Result<ua::SetTriggeringResponse>> promise;
    auto future = promise.get_future();
    mConnection->set_triggering_async(std::move(request),
      [&promise](Result<ua::SetTriggeringResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  Result<SetTriggeringResult> set_triggering_by_handles(std::uint32_t subscriptionId,
    std::uint32_t triggerHandle, std::vector<std::uint32_t> addHandles,
    std::vector<std::uint32_t> removeHandles)
  {
    std::promise<Result<SetTriggeringResult>> promise;
    auto future = promise.get_future();
    mConnection->set_triggering_by_handles_async(subscriptionId,
      triggerHandle,
      std::move(addHandles),
      std::move(removeHandles),
      [&promise](Result<SetTriggeringResult> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

private:
  boost::asio::thread_pool mThreadPool;
  std::optional<Client> mClient;
  std::shared_ptr<ConnectionImpl> mConnection;
  VoidResult mStartStatus{};
};

std::shared_ptr<WireCapture> arm_wire_capture(MisbehavingServer& server)
{
  auto capture = std::make_shared<WireCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });
  return capture;
}

// Builds a DataChangeFilter MonitorRequest on monitoredNode (used by the filter cluster).
ua::client::MonitorRequest deadband_request_on(
  const NodeId& node, ua::DeadbandType deadbandType, double deadbandValue)
{
  ua::client::MonitorRequest request;
  request.nodeId = node;
  request.attribute = ua::AttributeId::Value;
  request.samplingIntervalMs = 0.0;
  ua::DataChangeFilter filter;
  filter.trigger() = ua::DataChangeTrigger::StatusValue;
  filter.deadband_type() = static_cast<std::uint32_t>(deadbandType);
  filter.deadband_value() = deadbandValue;
  request.filter = filter;
  return request;
}

ua::client::MonitorRequest deadband_request(ua::DeadbandType deadbandType, double deadbandValue)
{
  ua::client::MonitorRequest request;
  request.nodeId = monitoredNode;
  request.attribute = ua::AttributeId::Value;
  request.samplingIntervalMs = 0.0;
  ua::DataChangeFilter filter;
  filter.trigger() = ua::DataChangeTrigger::StatusValue;
  filter.deadband_type() = static_cast<std::uint32_t>(deadbandType);
  filter.deadband_value() = deadbandValue;
  request.filter = filter;
  return request;
}

}  // namespace

// =============================================================================================
// ClientMonitorModify
// =============================================================================================
class ClientMonitorModify : public ::testing::Test
{};

// Row - UpdatesLocalSnapshotOnSuccess  (MisbehavingServer for the revision)
// BUILT (CL-MI-019): a successful modify updates the client-side handle snapshot to the SERVER's revised
// values - mi_modify_async reads the ModifyMonitoredItems response's revisedSamplingInterval /
// revisedQueueSize and stores them in the shared MonitoredItemState the handle reads. Pins the end-to-end
// refresh: the modify's revised interval (distinct from the create-time revised value) reaches the handle.
// [neg: immediate snapshot freshness]
// @verifies CL-MI-019
// @relation(CL-MI-019, scope=function)
TEST_F(ClientMonitorModify, UpdatesLocalSnapshotOnSuccess)
{
  MisbehavingServer server;
  MisbehavingMonitorControlFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  // The create revises 100 -> 250; a later modify's response would revise to 750 (but that is discarded).
  const double createRevised = 250.0;
  const double modifyRevised = 750.0;
  auto phase = std::make_shared<std::atomic<int>>(0);  // 0 = create phase, 1 = modify phase
  server.set_response_mutator(
    [phase, createRevised, modifyRevised](Response& response)
    {
      if (auto* create = as_create_items(response); create && !create->results().empty())
      {
        create->results()[0].revised_sampling_interval() = createRevised;
      }
      else if (auto* modify = as_modify(response); modify && !modify->results().empty())
      {
        // The server DOES revise on modify - but the client has nowhere to store it.
        modify->results()[0].revised_sampling_interval() = modifyRevised;
        modify->results()[0].revised_queue_size() = 10;
      }
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  auto sink = std::make_shared<DataValueSink>();
  auto created = fixture.monitor_value(subscription.value(), /*samplingIntervalMs=*/100.0, sink);
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
  MonitoredItem item = created.value();
  ASSERT_EQ(item.revised_sampling_interval(), createRevised)
    << "the create-time handle snapshots the server's revised sampling interval (CL-MI-002)";

  // Modify the item (request queueSize=10, a new sampling interval). The modify succeeds.
  phase->store(1);
  ua::client::MonitorRequest modifyRequest;
  modifyRequest.nodeId = monitoredNode;
  modifyRequest.attribute = ua::AttributeId::Value;
  modifyRequest.samplingIntervalMs = 500.0;
  modifyRequest.queueSize = 10;
  const auto modifyResult = MisbehavingMonitorControlFixture::modify_item(item, modifyRequest);
  ASSERT_TRUE(modifyResult.is_good()) << to_string(modifyResult.status_code());

  // BUILT (CL-MI-019): a successful modify refreshes the handle to the server's modify-time revised values.
  EXPECT_EQ(item.revised_sampling_interval(), modifyRevised)
    << "a successful modify updates the handle to the server's modify-time revised sampling interval";
  EXPECT_EQ(item.revised_queue_size(), 10u)
    << "the modify's revised queue size reaches the handle (CL-MI-019)";
  EXPECT_NE(item.revised_sampling_interval(), createRevised)
    << "the create-time revised interval has been superseded by the modify";
}

// Row - SetModeDisabledStopsDispatch  (MisbehavingServer)
// CL-MI-021 has two halves. BUILT: a successful SetMonitoringMode updates the handle's mode() to the applied
// mode (the shared MonitoredItemState). NOT gated locally: the client does NOT suppress DISPATCH on mode - it
// relies on a compliant SERVER to stop reporting a disabled item (correct pass-through). So a (mis)behaving
// server's post-disable notification IS still dispatched. This asserts BOTH: the handle mode() reflects
// Disabled, AND the client does not locally gate dispatch. [neg: disabled item silent -> the client is a
// pass-through, not a local gate]
// @verifies CL-MI-021
// @relation(CL-MI-021, scope=function)
TEST_F(ClientMonitorModify, SetModeDisabledStopsDispatch)
{
  MisbehavingServer server;
  MisbehavingMonitorControlFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const std::int32_t postDisableValue = 90901;
  auto deliver = std::make_shared<std::atomic<bool>>(false);
  auto handle = std::make_shared<std::atomic<std::uint32_t>>(0);
  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);
  server.set_response_mutator(
    [deliver, handle, sequenceNumber, postDisableValue](Response& response)
    {
      auto* publish = as_publish(response);
      if (!publish || !deliver->load())
      {
        return;
      }
      set_publish_sequence(*publish, ++(*sequenceNumber));
      set_data_change(*publish, {HandleValue{handle->load(), ua::Variant{postDisableValue}}});
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  auto sink = std::make_shared<DataValueSink>();
  auto created = fixture.monitor_value(subscription.value(), /*samplingIntervalMs=*/0.0, sink);
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
  MonitoredItem item = created.value();
  handle->store(item.client_handle());
  ASSERT_TRUE(wait_until([&] { return fixture.monitored_item_count() == 1; }));

  // Disable the item; the per-item result is surfaced Good.
  const auto disabled = MisbehavingMonitorControlFixture::set_item_mode(item, ua::MonitoringMode::Disabled);
  ASSERT_TRUE(disabled.is_good()) << to_string(disabled.status_code());
  EXPECT_EQ(item.mode(), ua::MonitoringMode::Disabled)
    << "BUILT (CL-MI-021): a successful set-mode updates the handle's mode() to the applied mode";
  EXPECT_EQ(fixture.monitored_item_count(), 1u) << "Disable does not deregister the item's dispatch routing";

  // Now inject a post-disable notification for the item's handle.
  deliver->store(true);
  EXPECT_TRUE(wait_until([&] { return sink->has_int32(postDisableValue); }))
    << "REPORTED (CL-MI-021 divergence): the client does NOT locally gate dispatch on monitoring mode, so a "
       "server-injected post-disable notification IS dispatched to the callback. In normal operation a "
       "compliant server stops reporting a disabled item, so this is correct pass-through, not a "
       "dropped-item "
       "bug - but it is not the local-suppression the matrix oracle assumed.";
  EXPECT_EQ(fixture.unknown_handle_drops(), 0u) << "the handle is still registered (not an advisory drop)";
}

// Row - SmallerQueueObservesOverflowBit  (MisbehavingServer)
// Shrinking the queue (modify queueSize 10 -> 2) must be carried onto the wire, and a subsequent notification
// carrying the Overflow InfoBit must pass through to the delivered DataValue unaltered. The queue-shrink is
// REAL (queueSize IS plumbed onto the modify wire); the overflow InfoBit is INJECTED (the MisbehavingServer
// has no user-writable node to organically overflow), which is exactly the section 8.4 dispatcher passthrough
// this row pins. [neg: queue shrink -> overflow bit visible]
// @verifies CL-MI-020
// @relation(CL-MI-020, scope=function)
TEST_F(ClientMonitorModify, SmallerQueueObservesOverflowBit)
{
  MisbehavingServer server;
  MisbehavingMonitorControlFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto capture = arm_wire_capture(server);

  const std::int32_t overflowValue = 20201;
  auto handle = std::make_shared<std::atomic<std::uint32_t>>(0);
  auto deliver = std::make_shared<std::atomic<bool>>(false);
  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);
  server.set_response_mutator(
    [handle, deliver, sequenceNumber, overflowValue](Response& response)
    {
      auto* publish = as_publish(response);
      if (!publish || !deliver->load())
      {
        return;
      }
      set_publish_sequence(*publish, ++(*sequenceNumber));
      set_data_change(*publish, {HandleValue{handle->load(), ua::Variant{overflowValue}, with_overflow()}});
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());

  // Create with queueSize=10.
  ua::client::MonitorRequest createRequest;
  createRequest.nodeId = monitoredNode;
  createRequest.attribute = ua::AttributeId::Value;
  createRequest.queueSize = 10;
  createRequest.discardOldest = false;  // CL-MI-020: the overflow policy the handle must surface
  auto sink = std::make_shared<DataValueSink>();
  auto created = fixture.monitor(subscription.value(), createRequest, sink);
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
  MonitoredItem item = created.value();
  handle->store(item.client_handle());
  EXPECT_FALSE(item.discard_oldest())
    << "CL-MI-020: the requested discardOldest=false is surfaced on the handle (was hardcoded true)";

  // Modify down to queueSize=2 - assert the smaller queue size reached the wire (queueSize IS plumbed on
  // modify).
  ua::client::MonitorRequest modifyRequest;
  modifyRequest.nodeId = monitoredNode;
  modifyRequest.attribute = ua::AttributeId::Value;
  modifyRequest.queueSize = 2;
  const auto modifyResult = MisbehavingMonitorControlFixture::modify_item(item, modifyRequest);
  ASSERT_TRUE(modifyResult.is_good()) << to_string(modifyResult.status_code());
  ASSERT_TRUE(wait_until([&] { return capture->modify_count() >= 1; }));
  EXPECT_EQ(capture->last_modify_queue_size(), 2u)
    << "the modify must carry the shrunken queue size (queueSize=2) onto the wire";

  // A subsequent notification with the Overflow InfoBit must reach the callback with the bit intact.
  deliver->store(true);
  EXPECT_TRUE(wait_until([&] { return sink->has_int32(overflowValue); }))
    << "the post-shrink notification must be delivered";
  EXPECT_TRUE(sink->has_overflow_bit())
    << "the Overflow DataValue InfoBit must survive to the delivered DataValue (never masked)";
  EXPECT_TRUE(sink->has_status(with_overflow()))
    << "the exact StatusCode (Good | Overflow) must pass through unaltered";
}

// Row - ServiceAndOpLevelErrorsSurfaceWithErrorDetail  (MisbehavingServer)
// Across the three self-action services (Modify / SetMonitoringMode / Delete), an injected service-level bad
// becomes a bad VoidResult with the EXACT server code, and an injected op-level (per-item) bad becomes a bad
// VoidResult with the EXACT per-item code. A routing lookup-miss (a self-action on an already-deleted item)
// yields Bad_SubscriptionIdInvalid carrying the REAL source-tagged ErrorDetail. [neg: service vs op-level
// across three services; ErrorDetail preserved where the code provides one] CALIBRATION: the flatten paths
// surface the exact StatusCode but attach NO client-synthesized ErrorDetail for a service-level or op-level
// bad (only the transport-error, lookup-miss, and connection-gone paths carry a source-tagged detail). This
// asserts the codes precisely AND the lookup-miss source tag.
// @verifies CL-MI-022
// @relation(CL-MI-022, scope=function)
TEST_F(ClientMonitorModify, ServiceAndOpLevelErrorsSurfaceWithErrorDetail)
{
  MisbehavingServer server;
  MisbehavingMonitorControlFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  // 0 = leave untouched; else stamp the given code at service level (serviceLevel=true) or op level.
  auto injectedCode = std::make_shared<std::atomic<std::uint32_t>>(0);
  auto serviceLevel = std::make_shared<std::atomic<bool>>(false);
  server.set_response_mutator(
    [injectedCode, serviceLevel](Response& response)
    {
      const std::uint32_t code = injectedCode->load();
      if (code == 0)
      {
        return;
      }
      const ua::StatusCode status{static_cast<ua::Status>(code)};
      if (auto* modify = as_modify(response))
      {
        if (serviceLevel->load())
        {
          modify->response_header().service_result() = status;
        }
        else if (!modify->results().empty())
        {
          modify->results()[0].status_code() = status;
        }
      }
      else if (auto* setMode = as_set_mode(response))
      {
        if (serviceLevel->load())
        {
          setMode->response_header().service_result() = status;
        }
        else if (!setMode->results().empty())
        {
          setMode->results()[0] = status;
        }
      }
      else if (auto* del = as_delete(response))
      {
        if (serviceLevel->load())
        {
          del->response_header().service_result() = status;
        }
        else if (!del->results().empty())
        {
          del->results()[0] = status;
        }
      }
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();

  // Helper: create a fresh item and run a self-action under an injected code + level, asserting the surfaced
  // VoidResult status equals the injected code. (Modify / SetMonitoringMode keep the item registered on
  // failure; Delete keeps it too - a bad delete does not unregister.)
  enum class Service
  {
    Modify,
    SetMode,
    Delete
  };
  auto run = [&](Service service, ua::Status code, bool atServiceLevel)
  {
    auto sink = std::make_shared<DataValueSink>();
    auto created = fixture.monitor_value(subscriptionId, 0.0, sink);
    ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
    MonitoredItem item = created.value();

    injectedCode->store(static_cast<std::uint32_t>(code));
    serviceLevel->store(atServiceLevel);
    VoidResult result;
    switch (service)
    {
    case Service::Modify:
    {
      ua::client::MonitorRequest request;
      request.nodeId = monitoredNode;
      request.attribute = ua::AttributeId::Value;
      result = MisbehavingMonitorControlFixture::modify_item(item, request);
      break;
    }
    case Service::SetMode:
      result = MisbehavingMonitorControlFixture::set_item_mode(item, ua::MonitoringMode::Sampling);
      break;
    case Service::Delete:
      result = MisbehavingMonitorControlFixture::delete_item(item);
      break;
    }
    injectedCode->store(0);
    EXPECT_TRUE(result.is_bad()) << "an injected bad must surface as a bad Result";
    EXPECT_EQ(result.status_code(), ua::StatusCode{code})
      << "the EXACT " << (atServiceLevel ? "service" : "op") << "-level code must reach the caller";
  };

  // Service-level bads across the three services.
  run(Service::Modify, ua::Status::BadSubscriptionIdInvalid, /*atServiceLevel=*/true);
  run(Service::SetMode, ua::Status::BadMonitoringModeInvalid, /*atServiceLevel=*/true);
  run(Service::Delete, ua::Status::BadTooManyOperations, /*atServiceLevel=*/true);

  // Op-level (per-item) bads across the three services.
  run(Service::Modify, ua::Status::BadMonitoredItemFilterInvalid, /*atServiceLevel=*/false);
  run(Service::SetMode, ua::Status::BadMonitoredItemIdInvalid, /*atServiceLevel=*/false);
  run(Service::Delete, ua::Status::BadMonitoredItemIdInvalid, /*atServiceLevel=*/false);

  // A routing lookup-miss carries a REAL source-tagged ErrorDetail: successfully delete an item (mutator
  // off), then a further self-action on the stale handle -> Bad_SubscriptionIdInvalid + the owner's
  // lookup-miss tag.
  injectedCode->store(0);
  auto sink = std::make_shared<DataValueSink>();
  auto created = fixture.monitor_value(subscriptionId, 0.0, sink);
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
  MonitoredItem item = created.value();
  const auto deleteResult = MisbehavingMonitorControlFixture::delete_item(item);
  ASSERT_TRUE(deleteResult.is_good()) << to_string(deleteResult.status_code());

  const auto staleResult =
    MisbehavingMonitorControlFixture::set_item_mode(item, ua::MonitoringMode::Reporting);
  EXPECT_TRUE(staleResult.is_bad());
  EXPECT_EQ(staleResult.status_code(), ua::StatusCode{ua::Status::BadSubscriptionIdInvalid})
    << "a self-action after the item is gone from the owner routing is a lookup-miss";
  ASSERT_TRUE(staleResult.shared_detail()) << "the lookup-miss must carry a source-tagged ErrorDetail";
  EXPECT_EQ(staleResult.shared_detail()->source, "client.tier1.data_change_owner.lookup_miss");
}

// =============================================================================================
// ClientMonitorFilter
// =============================================================================================
class ClientMonitorFilter : public ::testing::Test
{};

// Row - AbsoluteDeadbandEncodedOnWire  (MisbehavingServer)  [integration+unit]
// CL-MI-011: a caller's AbsoluteDeadband DataChangeFilter is encoded as a MonitoringParameters.filter
// ExtensionObject on the outgoing CreateMonitoredItems - deadbandType=Absolute(1), deadbandValue=2.5.
// [neg: the DataChangeFilter struct->ExtensionObject encoding]
// @verifies CL-MI-011
// @relation(CL-MI-011, scope=function)
TEST_F(ClientMonitorFilter, AbsoluteDeadbandEncodedOnWire)
{
  MisbehavingServer server;
  MisbehavingMonitorControlFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto capture = arm_wire_capture(server);

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());

  auto sink = std::make_shared<DataValueSink>();
  // A numeric Variable: the server refuses an AbsoluteDeadband outside the Number subtree
  // (Part 4 7.22.2), and ServerStatus.State is an Enumeration.
  auto created = fixture.monitor(subscription.value(),
    deadband_request_on(NodeId{VariableId::Server_ServiceLevel}, ua::DeadbandType::Absolute, 2.5),
    sink);
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
  ASSERT_TRUE(wait_until([&] { return capture->create_count() >= 1; }));

  EXPECT_TRUE(capture->last_create_had_filter())
    << "the caller's AbsoluteDeadband DataChangeFilter must be encoded onto the wire";
  EXPECT_EQ(capture->last_create_deadband_type(), static_cast<std::uint32_t>(ua::DeadbandType::Absolute))
    << "the wire filter must carry deadbandType=Absolute(1)";
  EXPECT_DOUBLE_EQ(capture->last_create_deadband_value(), 2.5)
    << "the wire filter must carry deadbandValue=2.5";
}

// Row - AbsoluteDeadbandOnNonNumericReturnsBadFilterNotAllowed  (MisbehavingServer)
// The client issues NO local pre-flight Read (it defers filter validity to the server, per Phase-A design),
// and surfaces a server per-item Bad_FilterNotAllowed as a bad Result. Driven by injecting the per-item bad
// on the CreateMonitoredItems result. [neg: server-side filter rejection surfaced] CALIBRATION: because the
// filter is not plumbed onto the wire (see AbsoluteDeadbandEncodedOnWire), the server never actually SEES the
// filter - the rejection is INJECTED here to exercise the client's per-item error surfacing (which IS built)
// and the no-pre-flight-Read guarantee.
// @verifies CL-MI-012
// @relation(AC-CL-MI-012-NO-LOCAL-DATATYPE-PRE-FLIGHT, scope=function)
TEST_F(ClientMonitorFilter, AbsoluteDeadbandOnNonNumericReturnsBadFilterNotAllowed)
{
  MisbehavingServer server;
  MisbehavingMonitorControlFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto capture = arm_wire_capture(server);

  server.set_response_mutator(
    [](Response& response)
    {
      if (auto* create = as_create_items(response); create && !create->results().empty())
      {
        create->results()[0].status_code() = ua::StatusCode{ua::Status::BadFilterNotAllowed};
      }
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());

  // Snapshot the Read count so we can prove the create issued NO local pre-flight Read.
  const std::size_t readsBefore = capture->read_count();
  auto sink = std::make_shared<DataValueSink>();
  auto created =
    fixture.monitor(subscription.value(), deadband_request(ua::DeadbandType::Absolute, 2.5), sink);

  EXPECT_TRUE(created.is_bad()) << "the server's per-item Bad_FilterNotAllowed must surface as a bad Result";
  EXPECT_EQ(created.status_code(), ua::StatusCode{ua::Status::BadFilterNotAllowed})
    << "the EXACT per-item status must reach the caller";
  EXPECT_EQ(capture->read_count(), readsBefore)
    << "the client must NOT issue a local pre-flight Read to check the node's DataType (defer to the server)";
  EXPECT_EQ(fixture.monitored_item_count(), 0u) << "a rejected create must leave no attach state";
}

// Row - NoFilterOmitsExtensionObject  (MisbehavingServer)
// A monitor with no filter must leave the outgoing CreateMonitoredItems' MonitoringParameters.filter NULL -
// the client must not synthesize a phantom deadband=0 filter. [neg: absent filter -> null on wire]
// @verifies CL-MI-011
// @relation(CL-MI-011, scope=function)
TEST_F(ClientMonitorFilter, NoFilterOmitsExtensionObject)
{
  MisbehavingServer server;
  MisbehavingMonitorControlFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto capture = arm_wire_capture(server);

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());

  ua::client::MonitorRequest request;  // filter left as monostate (no filter)
  request.nodeId = monitoredNode;
  request.attribute = ua::AttributeId::Value;
  auto sink = std::make_shared<DataValueSink>();
  auto created = fixture.monitor(subscription.value(), request, sink);
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
  ASSERT_TRUE(wait_until([&] { return capture->create_count() >= 1; }));

  EXPECT_FALSE(capture->last_create_had_filter())
    << "a no-filter monitor must carry a NULL MonitoringParameters.filter (no synthesized deadband=0 filter)";
}

// Row - PercentDeadbandRangeValidatedLocally  (MisbehavingServer)  [integration+unit]
// CL-MI-024: the monitor path validates a PercentDeadband's [0,100] range LOCALLY. A valid 5.0 monitors
// normally and its filter reaches the wire (CL-MI-011); an out-of-range -1.0 / 100.5 (or non-finite) returns
// Bad_DeadbandFilterInvalid with NO wire request (a percentage out of [0,100] is a structural error
// independent of the node's DataType, so no round-trip is wasted). [neg: boundary [0,100]]
// @verifies CL-MI-024
// @relation(CL-MI-024, scope=function)
TEST_F(ClientMonitorFilter, PercentDeadbandRangeValidatedLocally)
{
  MisbehavingServer server;
  // A PercentDeadband is a percentage OF AN EURange, so the valid case needs a node that has one
  // (OPC 10000-8 6.2). monitoredNode does not, and a server that accepted a PercentDeadband there
  // would be reporting every change instead of the requested filter - the opposite of what was asked.
  const NodeId analogNode = create_analog_item_with_eu_range(server);
  MisbehavingMonitorControlFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto capture = arm_wire_capture(server);

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();

  // In-range 5.0 on a node WITH an EURange: monitors normally and emits a CreateMonitoredItems
  // carrying the PercentDeadband filter.
  {
    const std::size_t createsBefore = capture->create_count();
    auto sink = std::make_shared<DataValueSink>();
    auto created =
      fixture.monitor(subscriptionId, deadband_request_on(analogNode, ua::DeadbandType::Percent, 5.0), sink);
    EXPECT_TRUE(created.is_good()) << "an in-range PercentDeadband must monitor normally: "
                                   << to_string(created.status_code());
    EXPECT_TRUE(wait_until([&] { return capture->create_count() == createsBefore + 1; }))
      << "a valid PercentDeadband must emit a CreateMonitoredItems";
    EXPECT_TRUE(capture->last_create_had_filter())
      << "the valid PercentDeadband filter must reach the wire (CL-MI-011)";
  }

  // Out-of-range -1.0 / 100.5: rejected LOCALLY with Bad_DeadbandFilterInvalid and NO wire request.
  for (const double outOfRange : {-1.0, 100.5})
  {
    const std::size_t createsBefore = capture->create_count();
    auto sink = std::make_shared<DataValueSink>();
    auto created = fixture.monitor(
      subscriptionId, deadband_request_on(analogNode, ua::DeadbandType::Percent, outOfRange), sink);
    EXPECT_TRUE(created.is_bad()) << "PercentDeadband " << outOfRange << " must be rejected locally";
    EXPECT_EQ(created.status_code(), ua::StatusCode{ua::Status::BadDeadbandFilterInvalid})
      << "an out-of-range PercentDeadband must surface Bad_DeadbandFilterInvalid";
    EXPECT_EQ(capture->create_count(), createsBefore)
      << "an out-of-range PercentDeadband must NOT reach the wire (local short-circuit)";
  }

  // An in-range PercentDeadband on a node with NO EURange: Table 29 names this case explicitly - "a
  // PercentDeadband is not supported, since an EURange is not configured" - and it is the arm that used
  // to pass silently, creating the item Good and then reporting EVERY change.
  {
    auto sink = std::make_shared<DataValueSink>();
    auto created = fixture.monitor(subscriptionId, deadband_request(ua::DeadbandType::Percent, 5.0), sink);
    EXPECT_TRUE(created.is_bad()) << "a PercentDeadband on a node without an EURange must be refused";
    EXPECT_EQ(created.status_code(), ua::StatusCode{ua::Status::BadDeadbandFilterInvalid})
      << "and must say why: " << to_string(created.status_code());
  }
}

// =============================================================================================
// ClientMonitorTrigger
// =============================================================================================
class ClientMonitorTrigger : public ::testing::Test
{};

// Row - PerLinkResultsSurfacedWithoutAbort  (MisbehavingServer)
// The raw SetTriggering surface returns the FULL response with per-link addResults / removeResults
// positionally, and the call completes without aborting on the first per-link bad (first-only / all /
// alternating patterns), with empty diagnosticInfo arrays accepted; a service-level bad is surfaced
// separately. [neg: per-link first/all/alternating add & remove results]
// @verifies CL-MI-029
// @relation(CL-MI-029, scope=function)
TEST_F(ClientMonitorTrigger, PerLinkResultsSurfacedWithoutAbort)
{
  MisbehavingServer server;
  MisbehavingMonitorControlFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  // The mutator rewrites the SetTriggering response: add_results / remove_results to the injected pattern, an
  // optional service-level code, and CLEARS diagnostic_infos (empty arrays must be accepted).
  auto addPattern = std::make_shared<std::vector<std::uint32_t>>();
  auto removePattern = std::make_shared<std::vector<std::uint32_t>>();
  auto serviceCode = std::make_shared<std::atomic<std::uint32_t>>(0);
  auto patternMutex = std::make_shared<std::mutex>();
  server.set_response_mutator(
    [addPattern, removePattern, serviceCode, patternMutex](Response& response)
    {
      auto* trigger = as_set_triggering(response);
      if (!trigger)
      {
        return;
      }
      std::lock_guard lock(*patternMutex);
      const std::uint32_t code = serviceCode->load();
      if (code != 0)
      {
        trigger->response_header().service_result() = ua::StatusCode{static_cast<ua::Status>(code)};
      }
      ua::Array<ua::StatusCode> addResults;
      for (const auto raw : *addPattern)
      {
        addResults.push_back(ua::StatusCode{static_cast<ua::Status>(raw)});
      }
      ua::Array<ua::StatusCode> removeResults;
      for (const auto raw : *removePattern)
      {
        removeResults.push_back(ua::StatusCode{static_cast<ua::Status>(raw)});
      }
      trigger->add_results() = std::move(addResults);
      trigger->remove_results() = std::move(removeResults);
      trigger->add_diagnostic_infos().clear();  // empty diag arrays must be accepted
      trigger->remove_diagnostic_infos().clear();
    });

  const std::uint32_t good = static_cast<std::uint32_t>(ua::Status::Good);
  const std::uint32_t bad = static_cast<std::uint32_t>(ua::Status::BadMonitoredItemIdInvalid);

  // Create a REAL subscription + a trigger item + three link items so the server processes SetTriggering into
  // a real SetTriggeringResponse (a bogus subscription/trigger id would draw a ServiceFault the mutator
  // cannot rewrite). The per-link result contents are then fully injected by the mutator; only the ids'
  // validity matters here.
  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();
  auto sinkT = std::make_shared<DataValueSink>();
  auto sinkA = std::make_shared<DataValueSink>();
  auto sinkB = std::make_shared<DataValueSink>();
  auto sinkC = std::make_shared<DataValueSink>();
  auto itemT = fixture.monitor_value(subscriptionId, 0.0, sinkT);
  auto itemA = fixture.monitor_value(subscriptionId, 0.0, sinkA);
  auto itemB = fixture.monitor_value(subscriptionId, 0.0, sinkB);
  auto itemC = fixture.monitor_value(subscriptionId, 0.0, sinkC);
  ASSERT_TRUE(itemT.is_good() && itemA.is_good() && itemB.is_good() && itemC.is_good());
  auto owner = std::dynamic_pointer_cast<ua::client::detail::DataChangeMonitoredItemOwner>(
    fixture.conn().monitored_item_owner());
  ASSERT_TRUE(owner);
  const auto idT = owner->server_item_id(itemT.value().client_handle());
  const std::vector<std::optional<std::uint32_t>> linkIds{
    owner->server_item_id(itemA.value().client_handle()),
    owner->server_item_id(itemB.value().client_handle()),
    owner->server_item_id(itemC.value().client_handle())};
  ASSERT_TRUE(idT && linkIds[0] && linkIds[1] && linkIds[2]);

  // Issue a raw SetTriggering with real ids; the per-link result contents come from the injected pattern.
  auto issue =
    [&](std::vector<std::uint32_t> addResults, std::vector<std::uint32_t> removeResults, ua::Status service)
  {
    {
      std::lock_guard lock(*patternMutex);
      *addPattern = addResults;
      *removePattern = removeResults;
    }
    serviceCode->store(static_cast<std::uint32_t>(service));
    ua::SetTriggeringRequest request;
    request.subscription_id() = subscriptionId;
    request.triggering_item_id() = *idT;
    for (std::size_t i = 0; i < addResults.size(); ++i)
    {
      request.links_to_add().push_back(static_cast<ua::IntegerId>(*linkIds[i % linkIds.size()]));
    }
    for (std::size_t i = 0; i < removeResults.size(); ++i)
    {
      request.links_to_remove().push_back(static_cast<ua::IntegerId>(*linkIds[i % linkIds.size()]));
    }
    return fixture.set_triggering_raw(std::move(request));
  };

  // First-only bad add: [Bad, Good, Good] - surfaced positionally, no abort.
  {
    const auto result = issue({bad, good, good}, {good}, ua::Status::Good);
    ASSERT_TRUE(result.is_good()) << "the call completes (transport) even with a per-link bad";
    ASSERT_EQ(result.value().add_results().size(), 3u) << "no abort - all add results present";
    EXPECT_TRUE(result.value().add_results()[0].is_bad()) << "first add link bad, positionally";
    EXPECT_TRUE(result.value().add_results()[1].is_good());
    EXPECT_TRUE(result.value().add_results()[2].is_good());
    EXPECT_EQ(result.value().add_results()[0], ua::StatusCode{ua::Status::BadMonitoredItemIdInvalid});
    ASSERT_EQ(result.value().remove_results().size(), 1u);
    EXPECT_TRUE(result.value().remove_results()[0].is_good());
    EXPECT_TRUE(result.value().response_header().service_result().is_good());
  }

  // All-bad add: [Bad, Bad, Bad].
  {
    const auto result = issue({bad, bad, bad}, {}, ua::Status::Good);
    ASSERT_TRUE(result.is_good());
    ASSERT_EQ(result.value().add_results().size(), 3u);
    for (const auto& status : result.value().add_results())
    {
      EXPECT_TRUE(status.is_bad()) << "every add link surfaced bad (no abort collapsing the list)";
    }
  }

  // Alternating add [Bad, Good, Bad] + alternating remove [Good, Bad].
  {
    const auto result = issue({bad, good, bad}, {good, bad}, ua::Status::Good);
    ASSERT_TRUE(result.is_good());
    ASSERT_EQ(result.value().add_results().size(), 3u);
    EXPECT_TRUE(result.value().add_results()[0].is_bad());
    EXPECT_TRUE(result.value().add_results()[1].is_good());
    EXPECT_TRUE(result.value().add_results()[2].is_bad());
    ASSERT_EQ(result.value().remove_results().size(), 2u);
    EXPECT_TRUE(result.value().remove_results()[0].is_good());
    EXPECT_TRUE(result.value().remove_results()[1].is_bad());
  }

  // A service-level bad is surfaced separately from the per-link results. The raw wire op keeps the transport
  // Result good and the service-level code in the response header (or flattens it into the Result status);
  // the effective surfaced status must carry the injected code either way.
  {
    const auto result = issue({good}, {}, ua::Status::BadTooManyOperations);
    const ua::StatusCode effective =
      result.is_bad() ? result.status_code() : result.value().response_header().service_result();
    EXPECT_EQ(effective, ua::StatusCode{ua::Status::BadTooManyOperations})
      << "a service-level bad must be surfaced (not swallowed by the per-link parsing)";
  }
}

// Row - RemoveThenAddOrderPreserved  (MisbehavingServer)  [integration+unit]
// set_triggering(t, add={A,B}, remove={A}) must put linksToRemove=[A] and linksToAdd=[A,B] on the wire (the
// server applies removes before adds), even with A in both lists. The client controls this wire order; the
// post-call link set lives server-side (the client keeps no local link set). [neg: remove-before-add
// semantics with A in both lists; unit pins list encoding order]
// @verifies CL-MI-028
// @relation(CL-MI-028, scope=function)
TEST_F(ClientMonitorTrigger, RemoveThenAddOrderPreserved)
{
  MisbehavingServer server;
  MisbehavingMonitorControlFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto capture = arm_wire_capture(server);

  auto connection = fixture.public_connection();
  auto subscription =
    connection.subscriptions().try_create_sync(ua::client::SubscriptionConfig{.publishingIntervalMs = 50.0});
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  auto subscriptionHandle = std::move(subscription).value();

  // Create the trigger item T plus items A and B; capture their server ids (needed to check the wire order).
  auto sinkT = std::make_shared<DataValueSink>();
  auto sinkA = std::make_shared<DataValueSink>();
  auto sinkB = std::make_shared<DataValueSink>();
  ua::client::MonitorRequest monitorRequest;
  monitorRequest.nodeId = monitoredNode;
  monitorRequest.attribute = ua::AttributeId::Value;
  monitorRequest.samplingIntervalMs = 0.0;
  auto itemT = subscriptionHandle.try_monitor_sync(
    monitorRequest, [sinkT](DataChangeEvent event) { sinkT->push(std::move(event.value)); });
  auto itemA = subscriptionHandle.try_monitor_sync(
    monitorRequest, [sinkA](DataChangeEvent event) { sinkA->push(std::move(event.value)); });
  auto itemB = subscriptionHandle.try_monitor_sync(
    monitorRequest, [sinkB](DataChangeEvent event) { sinkB->push(std::move(event.value)); });
  ASSERT_TRUE(itemT.is_good() && itemA.is_good() && itemB.is_good());
  const std::uint32_t handleT = itemT.value().client_handle();
  const std::uint32_t handleA = itemA.value().client_handle();
  const std::uint32_t handleB = itemB.value().client_handle();
  ASSERT_TRUE(wait_until([&] { return fixture.monitored_item_count() == 3; }));

  // Resolve the server ids the owner will encode, so we can assert the wire order deterministically. The
  // public accessor returns the abstract owner interface; downcast to the concrete data-change owner for its
  // id lookup.
  auto owner = std::dynamic_pointer_cast<ua::client::detail::DataChangeMonitoredItemOwner>(
    fixture.conn().monitored_item_owner());
  ASSERT_TRUE(owner);
  const auto idA = owner->server_item_id(handleA);
  const auto idB = owner->server_item_id(handleB);
  ASSERT_TRUE(idA && idB);

  const auto triggeringResult = subscriptionHandle.try_set_triggering_sync(
    itemT.value(), {itemA.value(), itemB.value()}, {itemA.value()});
  // The result depends on the real server's acceptance of A-in-both; the wire ORDER is what this row pins.
  (void)triggeringResult;
  ASSERT_TRUE(wait_until([&] { return capture->set_triggering_count() >= 1; }));

  EXPECT_EQ(capture->last_links_to_remove(), (std::vector<std::uint32_t>{*idA}))
    << "linksToRemove must carry [A] (server applies removes first)";
  EXPECT_EQ(capture->last_links_to_add(), (std::vector<std::uint32_t>{*idA, *idB}))
    << "linksToAdd must carry [A, B] in order, even with A duplicated in the remove list";
}

// Row - CrossSubscriptionRejectedLocally  (MisbehavingServer)
// BUILT (CL-MI-027): a trigger on Sub1 linking to an item on Sub2 is rejected LOCALLY with
// Bad_InvalidArgument and NO wire request - set_triggering_by_handles_async now runs a same-Subscription
// membership pre-flight (subscription_of(handle) == subscriptionId) for the trigger + every add/remove handle
// before building the request (OPC UA Part 4 section 5.12.5.1). [neg: mixed-subscription link -> local
// reject, nothing on the wire]
// @verifies CL-MI-027
// @relation(CL-MI-027, scope=function)
TEST_F(ClientMonitorTrigger, CrossSubscriptionRejectedLocally)
{
  MisbehavingServer server;
  MisbehavingMonitorControlFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto capture = arm_wire_capture(server);

  auto sub1 = fixture.create_subscription(50.0);
  auto sub2 = fixture.create_subscription(50.0);
  ASSERT_TRUE(sub1.is_good() && sub2.is_good());

  auto sinkTrigger = std::make_shared<DataValueSink>();
  auto sinkCross = std::make_shared<DataValueSink>();
  auto triggerItem = fixture.monitor_value(sub1.value(), 0.0, sinkTrigger);  // trigger on Sub1
  auto crossItem = fixture.monitor_value(sub2.value(), 0.0, sinkCross);  // link on Sub2
  ASSERT_TRUE(triggerItem.is_good() && crossItem.is_good());
  ASSERT_TRUE(wait_until([&] { return fixture.monitored_item_count() == 2; }));

  const std::size_t triggeringBefore = capture->set_triggering_count();
  const auto result = fixture.set_triggering_by_handles(
    sub1.value(), triggerItem.value().client_handle(), {crossItem.value().client_handle()}, {});

  // BUILT: the cross-subscription link is rejected LOCALLY - NO SetTriggering request reaches the wire.
  EXPECT_EQ(capture->set_triggering_count(), triggeringBefore)
    << "a cross-subscription link must be rejected locally with no wire request (CL-MI-027 pre-flight)";
  EXPECT_TRUE(result.is_bad()) << "the cross-subscription link is rejected";
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadInvalidArgument})
    << "a cross-subscription reference is a local Bad_InvalidArgument (Part 4 section 5.12.5.1), not a wire "
       "fault";
}

// =============================================================================================
// ClientMonitorQueue
// =============================================================================================
class ClientMonitorQueue : public ::testing::Test
{};

// Row - OverflowInfoBitPassesThrough  (MisbehavingServer)
// A Publish DataValue carrying the Overflow InfoBit (queueSize>1) must reach the user callback with the same
// StatusCode, InfoBits intact - the client must not mask the InfoBits. [neg: info-bit preserved unaltered]
// @verifies CL-MI-025
// @relation(CL-MI-025, scope=function)
TEST_F(ClientMonitorQueue, OverflowInfoBitPassesThrough)
{
  MisbehavingServer server;
  MisbehavingMonitorControlFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const std::int32_t value = 25255;
  auto handle = std::make_shared<std::atomic<std::uint32_t>>(0);
  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);
  server.set_response_mutator(
    [handle, sequenceNumber, value](Response& response)
    {
      auto* publish = as_publish(response);
      if (!publish || handle->load() == 0)
      {
        return;
      }
      set_publish_sequence(*publish, ++(*sequenceNumber));
      set_data_change(*publish, {HandleValue{handle->load(), ua::Variant{value}, with_overflow()}});
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());

  ua::client::MonitorRequest request;
  request.nodeId = monitoredNode;
  request.attribute = ua::AttributeId::Value;
  request.queueSize = 10;  // queueSize > 1, where the Overflow bit is meaningful
  auto sink = std::make_shared<DataValueSink>();
  auto created = fixture.monitor(subscription.value(), request, sink);
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
  handle->store(created.value().client_handle());

  EXPECT_TRUE(wait_until([&] { return sink->has_int32(value); })) << "the overflow-tagged value is delivered";
  EXPECT_TRUE(sink->has_overflow_bit()) << "the Overflow DataValue InfoBit must survive to the callback";
  EXPECT_TRUE(sink->has_status(with_overflow()))
    << "the exact StatusCode (Good | Overflow) must pass through unaltered (InfoBits never masked)";
}

// Row - PerItemDispatchPreservesQueueOrder  (MisbehavingServer)
// One Publish carrying THREE notifications for the same item (monotonically increasing values) must dispatch
// ALL three - never collapsing them (as a handle-keyed map would, last-wins) and never dropping any. The
// demux iterates the notification vector in wire order and hops each onto the pipeline strand IN ORDER. [neg:
// in-order within one item]
//
// STABLE ASSERTION (deterministic): the real CL-MI-026 falsifier - each of the three distinct same-handle
// values is delivered EXACTLY ONCE, with no advisory drop. A map-keyed dispatcher would collapse the three to
// one (or drop some); this pins that they are all delivered, once each.
//
// ORDERING (now asserted - the delivery-strand fix landed): CL-MI-026 GUARANTEES "dispatches notifications in
// arrival order for the same clientHandle". This originally FAILED (~35% reorder over 15 repeats here): the
// final per-notification callback hop bare-posted each callback to the RAW multi-threaded connection executor
// (deliver_notification_async), and the reference client uses a two-thread Runtime, so
// "the executor preserves enqueue order" was false. The fix routes the hop through a dedicated delivery
// strand (SubscriptionsPipeline::mDeliveryStrand, make_strand(executor)): the processing strand posts in
// arrival order, the strand is FIFO + non-concurrent, so delivery is in-order and serial for ANY executor
// thread count. The order assertion below is now deterministic. (Unit-pinned by
// SubscriptionsPipeline.PerItemDeliverySerializedAndOrderedUnderMultiThreadedExecutor.)
// @verifies CL-MI-026
// @relation(CL-MI-026, scope=function)
TEST_F(ClientMonitorQueue, PerItemDispatchPreservesQueueOrder)
{
  MisbehavingServer server;
  MisbehavingMonitorControlFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const std::int32_t v1 = 26261, v2 = 26262, v3 = 26263;
  auto handle = std::make_shared<std::atomic<std::uint32_t>>(0);
  auto deliver = std::make_shared<std::atomic<bool>>(false);
  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);
  server.set_response_mutator(
    [handle, deliver, sequenceNumber, v1, v2, v3](Response& response)
    {
      auto* publish = as_publish(response);
      if (!publish)
      {
        return;
      }
      if (!deliver->load())
      {
        // The item's initial value can reach the client before the injection is armed, and its sequence
        // number is then spent: the injected message must follow it, or the client drops it as a duplicate.
        if (!publish->notification_message().notification_data().empty())
        {
          sequenceNumber->store(publish->notification_message().sequence_number());
        }
        return;
      }
      // Deliver v1, v2, v3 for the SAME handle in ONE DataChangeNotification, in this order, on ONE Publish.
      set_publish_sequence(*publish, ++(*sequenceNumber));
      set_data_change(*publish,
        {HandleValue{handle->load(), ua::Variant{v1}},
          HandleValue{handle->load(), ua::Variant{v2}},
          HandleValue{handle->load(), ua::Variant{v3}}});
      deliver->store(false);  // inject the triple exactly once, so order is not muddied by re-injection
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  auto sink = std::make_shared<DataValueSink>();
  auto created = fixture.monitor_value(subscription.value(), 0.0, sink);
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
  handle->store(created.value().client_handle());
  ASSERT_TRUE(wait_until([&] { return fixture.monitored_item_count() == 1; }));

  deliver->store(true);
  // STABLE: all three distinct values must arrive - a handle-keyed map would COLLAPSE the three to one (last
  // wins). Wait until all three are present, then assert each was delivered EXACTLY ONCE (no collapse, no
  // drop, no duplication).
  ASSERT_TRUE(wait_until([&] { return sink->has_int32(v1) && sink->has_int32(v2) && sink->has_int32(v3); }))
    << "all three same-item notifications must be delivered (never collapsed)";
  EXPECT_EQ(sink->count_int32(v1), 1u) << "v1 delivered exactly once";
  EXPECT_EQ(sink->count_int32(v2), 1u) << "v2 delivered exactly once";
  EXPECT_EQ(sink->count_int32(v3), 1u) << "v3 delivered exactly once";
  EXPECT_EQ(fixture.unknown_handle_drops(), 0u) << "no notification is dropped as an unknown handle";

  // ORDER (CL-MI-026): the three same-handle values must be delivered to the user callback in ARRIVAL order.
  // The dedicated delivery strand (SubscriptionsPipeline::mDeliveryStrand) serializes the final callback hop,
  // so this holds deterministically even under the fixture's multi-threaded client pool - before that fix a
  // bare post to the multi-threaded executor reordered them (~35% of runs). A reorder now falsifies the
  // in-order guarantee, not just the no-drop one.
  const int i1 = sink->index_of_int32(v1);
  const int i2 = sink->index_of_int32(v2);
  const int i3 = sink->index_of_int32(v3);
  RecordProperty(
    "observed_delivery_order", std::to_string(i1) + "," + std::to_string(i2) + "," + std::to_string(i3));
  EXPECT_LT(i1, i2) << "v1 must be delivered before v2 (arrival order, CL-MI-026)";
  EXPECT_LT(i2, i3) << "v2 must be delivered before v3 (arrival order, CL-MI-026)";
}
