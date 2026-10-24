// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientMonitoredItem cluster of the client integration-test matrix (the 13 `ClientMonitoredItem.*`
///        rows).
///
/// These are END-TO-END integration tests of the TIER-1 managed monitored-item surface (client design
/// section 7.4 / section 8.4) reached through the internal `ua::client::detail::ConnectionImpl` orchestrator
/// - the SAME harness the committed ClientSubscription slice (3f7851e8) uses
/// (`MisbehavingSubscriptionFixture`: a real `Client` bound to a `MisbehavingServer`'s crypto + trusted store
/// over ephemeral TCP, an activated Session wrapped into a started `ConnectionImpl`, the always-on Publish
/// pump auto-running on the pool). Monitored-item behaviour is driven by create/delete/set-mode through the
/// orchestrator accessors and observed through:
///   - the DATA SINK - the per-item data callback (`DataValue`s actually delivered), dispatched by
///     `clientHandle`;
///   - the pipeline INFO snapshot (`ConnectionImplTestAccess::pipeline_info`) - monitoredItemCount /
///     unknownHandleDrops (the strand-private demux state that has no public getter);
///   - the REQUEST OBSERVER (`MisbehavingServer::set_request_observer`) - the DECODED outgoing requests (a
///     row asserts the ABSENCE of a Republish / a recreate CreateSubscription); and
///   - the returned `MonitoredItem` HANDLE - its immutable revised-sampling-interval snapshot (CL-MI-002).
/// The server is bent with `set_response_mutator` (rewrites each `CreateMonitoredItemsResponse` /
/// `PublishResponse` before signing): per-item result mixes, a result-length mismatch, a service-level error,
/// per-item bad statuses, revised-sampling-interval pathologies, and injected notifications for known / stale
/// client handles.
///
/// Falsifiability: every test encodes the matrix row's `[neg: ...]` falsifier and asserts the EXACT
/// observable - the per-item slot attribution, the dropped late notification after delete, the stored revised
/// interval, the mode-change no-replay. Timing is ALWAYS bounded polling on an observable (a delivered value
/// / an item count / a drop count), never a fixed sleep.
///
/// PRODUCT CHANGES this slice landed (see the connection-impl unit suite for the fake-driven coverage):
///   - the single-item `CreateMonitoredItems` facade now validates `results.size() == 1` (rejecting an
///     empty/short/long array with a source-tagged `Bad_UnexpectedError`, mirroring the Read facade) - drives
///     `CreateResultsLengthMismatchRejected`; and
///   - the returned `MonitoredItem` handle snapshots the server's revised sampling interval verbatim
///     (CL-MI-002) - drives `StoresRevisedSamplingInterval` +
///     `RevisedSamplingIntervalPathologiesStoredWithAdvisory`.
///
/// BLOCKED / REPORTED rows (an interface is not yet built - pin the built, spec-consistent observable and
/// record the unbuilt part, per the ClientBrowse / ClientSubscription precedent):
///   - RevisedSamplingIntervalPathologiesStoredWithAdvisory / InterArrivalGapNotFlaggedWhenHonored - the
///     monitored-item ADVISORY-diagnostic interface is UNBUILT: nothing on the monitored-item create /
///     dispatch path calls `ObserverSink::fire_advisory_diagnostic` (it fires only from the redundancy
///     manager), and there is no inter-arrival gap detector. Pin: the raw revised interval is stored verbatim
///     (no crash, no mutation) and NO advisory is ever emitted (a
///     `ConnectionObserver::on_advisory_diagnostic` counter stays zero); report the advisory + the gap
///     detector unbuilt.
///   - FirstSampleDispatchedUnconditionally - the client never applies a DataChangeFilter client-side (it is
///   a
///     pass-through), so the real server's mandatory first sample is always delivered to the callback. (The
///     `MonitorRequest` DataChangeFilter IS now plumbed onto the CREATE wire - CL-MI-011,
///     `DataChangeFilterEncodedOnCreateMonitoredItemsWire`; only its retention across a session-CHANGED
///     recreate remains a follow-up, OPEN-MI-011.)

#include "compliance_helpers.h"

#include "misbehaving_server.h"

#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"
#include "ua_connection_handle_factory.h"
#include "ua_type_resolver.h"

#include "ua_aggregate_filter.h"
#include "ua_application_configuration.h"
#include "ua_argument.h"
#include "ua_array.h"
#include "ua_binary_codec.h"
#include "ua_client.h"
#include "ua_client_monitored_item.h"
#include "ua_client_observers.h"
#include "ua_client_subscription.h"
#include "ua_codec_namespace_context.h"
#include "ua_create_monitored_items_request.h"
#include "ua_create_monitored_items_response.h"
#include "ua_data_change_filter.h"
#include "ua_data_change_notification.h"
#include "ua_data_change_trigger.h"
#include "ua_data_value.h"
#include "ua_delete_monitored_items_response.h"
#include "ua_error_detail.h"
#include "ua_event_filter.h"
#include "ua_logger.h"
#include "ua_memory_stream.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_modify_monitored_items_response.h"
#include "ua_monitored_item_create_result.h"
#include "ua_monitored_item_modify_request.h"
#include "ua_monitored_item_modify_result.h"
#include "ua_monitored_item_notification.h"
#include "ua_monitoring_mode.h"
#include "ua_monitoring_parameters.h"
#include "ua_node_id.h"
#include "ua_notification_message.h"
#include "ua_publish_request.h"
#include "ua_publish_response.h"
#include "ua_ref_structure.h"
#include "ua_republish_request.h"
#include "ua_set_monitoring_mode_request.h"
#include "ua_set_monitoring_mode_response.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_structure.h"
#include "ua_timestamps_to_return.h"
#include "ua_unknown_structure.h"
#include "ua_create_subscription_request.h"
#include "ua_to_string.h"
#include "ua_variable_id.h"
#include "ua_variant.h"

// Headers the criterion-targeted rows below need: the SERVER address space (a writable Variable is the only
// way to drive a real sampler), the tier-2 event surface (the only path that puts an event MonitoredItem on
// the wire) and the EventFilter operand type.
#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_connection.h"
#include "ua_datatype_id.h"
#include "ua_default_namespace.h"
#include "ua_event_subscriber.h"
#include "ua_generic_event.h"
#include "ua_localized_text.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"
#include "ua_simple_attribute_operand.h"
#include "ua_variabletype_id.h"

// Headers the criterion-targeted rows at the END of this file need: the SetTriggering / ModifySubscription /
// Read wire types (no fixture accessor exists for them), including the one fixture that assigns a Node
// RolePermissions without Read to an anonymous Session.

#include "ua_date_time.h"
#include "ua_modify_subscription_response.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_set_triggering_request.h"
#include "ua_set_triggering_response.h"

#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
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
// Injected value changes ride the response mutator (the MisbehavingServer has no user-writable node), so the
// tests never depend on the server updating it.
const NodeId monitoredNode{VariableId::Server_ServerStatus_State};

// ---------------------------------------------------------------------------------------------
// Thread-safe sink for the DataValues delivered to a monitored item's data callback (the pipeline hops the
// callback onto the pool, so the test thread and the delivery run concurrently).
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

  // True iff some delivered DataValue carries the exact @p status.
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

  bool has_argument_named(const ua::String& name) const
  {
    std::lock_guard lock(mMutex);
    for (const auto& value : mValues)
    {
      if (!value.value().is_structure())
        continue;
      const auto* argument = value.value().try_as<ua::Argument>();
      if (argument != nullptr && argument->name() == name)
        return true;
    }
    return false;
  }

  bool has_unknown(const ua::NodeId& encodingId, const ua::ByteString& body) const
  {
    std::lock_guard lock(mMutex);
    for (const auto& value : mValues)
    {
      if (!value.value().is_structure())
        continue;
      const auto* unknown = value.value().try_as<ua::UnknownStructure>();
      if (unknown != nullptr && unknown->encoding_id() == encodingId && unknown->encoded_data() == body)
        return true;
    }
    return false;
  }

private:
  mutable std::mutex mMutex;
  std::vector<DataValue> mValues;
};

// ---------------------------------------------------------------------------------------------
// A read-only capture of the request TYPES the client put on the wire that a row asserts the ABSENCE of (a
// Republish, a recreate CreateSubscription). Populated on a server strand by the request observer.
// ---------------------------------------------------------------------------------------------
struct RequestCapture
{
  mutable std::mutex mutex;
  std::size_t publishCount = 0;
  std::size_t republishCount = 0;
  std::size_t createSubscriptionCount = 0;

  void observe(const ua::Structure& request)
  {
    std::lock_guard lock(mutex);
    if (dynamic_cast<const ua::PublishRequest*>(&request))
    {
      ++publishCount;
    }
    else if (dynamic_cast<const ua::RepublishRequest*>(&request))
    {
      ++republishCount;
    }
    else if (dynamic_cast<const ua::CreateSubscriptionRequest*>(&request))
    {
      ++createSubscriptionCount;
    }
  }

  std::size_t publish_count() const
  {
    std::lock_guard lock(mutex);
    return publishCount;
  }

  std::size_t republish_count() const
  {
    std::lock_guard lock(mutex);
    return republishCount;
  }

  std::size_t create_subscription_count() const
  {
    std::lock_guard lock(mutex);
    return createSubscriptionCount;
  }
};

// A ConnectionObserver that counts advisory-diagnostic fan-outs (section 7.10, CL-DIAG-012). Used to PIN that
// the monitored-item path emits NO advisory today (the interface is unbuilt) - a falsifiable zero, not a "did
// nothing".
class AdvisoryCountingObserver : public ua::client::ConnectionObserver
{
public:
  void on_advisory_diagnostic(const ua::client::Connection&, std::shared_ptr<const ua::ErrorDetail>) override
  {
    mCount.fetch_add(1);
  }

  std::size_t count() const
  {
    return mCount.load();
  }

private:
  std::atomic<std::size_t> mCount{0};
};

class AdvisoryCaptureObserver : public ua::client::ConnectionObserver
{
public:
  void on_advisory_diagnostic(
    const ua::client::Connection&, std::shared_ptr<const ua::ErrorDetail> detail) override
  {
    {
      std::lock_guard lock(mMutex);
      mLastDetail = std::move(detail);
    }
    mCount.fetch_add(1);
  }

  std::size_t count() const
  {
    return mCount.load();
  }

  std::shared_ptr<const ua::ErrorDetail> last_detail() const
  {
    std::lock_guard lock(mMutex);
    return mLastDetail;
  }

private:
  std::atomic<std::size_t> mCount{0};
  mutable std::mutex mMutex;
  std::shared_ptr<const ua::ErrorDetail> mLastDetail;
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

// Forces the PublishResponse's NotificationMessage sequence number (the client expects 1, 2, 3, ... from a
// fresh Subscription), so classification is deterministic.
void set_publish_sequence(ua::PublishResponse& publish, std::uint32_t sequenceNumber)
{
  publish.notification_message().sequence_number() = sequenceNumber;
}

// Replaces the PublishResponse's notification data with a single DataChangeNotification carrying one
// MonitoredItemNotification per {clientHandle, value[, status]} entry, IN THE GIVEN ORDER (so a test can
// deliberately reorder items relative to their creation order).
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

ua::unique_ptr<ua::Structure> make_opaque_argument()
{
  ua::Argument argument;
  argument.name() = "Speed";
  argument.data_type() = ua::NodeId{0, 11U};
  argument.value_rank() = -1;

  ua::memory_stream_device::Dynamic device;
  ua::MemoryStream stream{device};
  const auto limits = ua::make_encoding_limits(ua::ApplicationConfig::load_default());
  ua::UaBinaryEncoder encoder{ua::CodecNamespaceContext{}, stream};
  encoder.encode(limits.stack_depth(), &argument);
  stream.seek_from_start(0);
  ua::UaBinaryDecoder decoder{ua::StructureResolver{}, stream, limits};
  ua::unique_ptr<ua::Structure> opaque;
  decoder.decode(limits.stack_depth(), opaque);
  return opaque;
}

// Casts a mutated response to a CreateMonitoredItemsResponse (or null for any other response).
ua::CreateMonitoredItemsResponse* as_create_items(ua::Response& response)
{
  return dynamic_cast<ua::CreateMonitoredItemsResponse*>(response.second.get());
}

ua::PublishResponse* as_publish(ua::Response& response)
{
  return dynamic_cast<ua::PublishResponse*>(response.second.get());
}

// ---------------------------------------------------------------------------------------------
// MisbehavingMonitoredItemFixture: the ClientSubscription harness (verbatim shape) plus the monitored-item
// self-action accessors this cluster drives (monitor -> MonitoredItem handle, delete, set-mode) and the
// monitoredItemCount snapshot.
// ---------------------------------------------------------------------------------------------
class MisbehavingMonitoredItemFixture
{
public:
  explicit MisbehavingMonitoredItemFixture(MisbehavingServer& server)
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
    auto session = channel.create_session_sync({.sessionName = "ClientMonitoredItemMatrix"});
    session.activate_sync();

    mConnection = ConnectionImpl::create(
      mThreadPool.executor(), std::move(session), ua::client::detail::ConnectionConfig{}, Logger{});
    mStartStatus = start_and_wait(*mConnection);
  }

  ~MisbehavingMonitoredItemFixture()
  {
    if (mConnection)
    {
      (void)close_and_wait(*mConnection);
    }
    mConnection.reset();
    mClient.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  MisbehavingMonitoredItemFixture(const MisbehavingMonitoredItemFixture&) = delete;
  MisbehavingMonitoredItemFixture& operator=(const MisbehavingMonitoredItemFixture&) = delete;

  ConnectionImpl& conn()
  {
    return *mConnection;
  }

  ua::client::Connection connection()
  {
    return ua::client::detail::ConnectionHandleFactory::make_connection(mConnection);
  }

  VoidResult register_argument_type()
  {
    ua::client::detail::UserTypeRegistration registration;
    registration.namespaceUri = "http://opcfoundation.org/UA/";
    registration.dataTypeIdentifier = ua::NodeId{0, 296U};
    registration.binaryEncodingIdentifier = ua::NodeId{ua::Argument::defaultBinaryEncodingId};
    registration.decoder = std::make_shared<ua::Argument>();

    std::promise<Result<std::vector<ua::client::detail::RegistrationOutcome>>> promise;
    auto future = promise.get_future();
    mConnection->type_resolver()->register_types_async(
      {std::move(registration)}, [&promise](auto result) { promise.set_value(std::move(result)); });
    const auto result = future.get();
    if (result.is_bad())
      return VoidResult{result.status_code(), result.shared_detail()};
    if (result.value().size() != 1U)
      return VoidResult{Status::BadUnexpectedError};
    if (result.value().front().status.is_bad())
      return VoidResult{result.value().front().status};
    return {};
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

  void set_connection_observer(std::shared_ptr<ConnectionObserver> observer)
  {
    mConnection->set_connection_observer_async(std::move(observer));
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

  // Creates a data-change item under @p clientHandle whose notifications push into @p sink; returns the
  // server-assigned monitored-item id (the id-only accessor, used where the handle snapshot is not needed).
  Result<std::uint32_t> create_monitored_item(
    std::uint32_t subscriptionId, std::uint32_t clientHandle, const std::shared_ptr<DataValueSink>& sink)
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

  // Drives the OWNER path (monitor_data_change_async) that builds the public MonitoredItem HANDLE (whose
  // revised-sampling-interval snapshot CL-MI-002 asserts). @p samplingIntervalMs is the value the CALLER
  // requests (recorded on the request; the wire-plumbing of the filter/interval is a separate concern).
  MonitoredItemResult monitor(std::uint32_t subscriptionId, double samplingIntervalMs,
    const std::shared_ptr<DataValueSink>& sink, bool withSuppressingFilter = false)
  {
    MonitorRequest request;
    request.nodeId = monitoredNode;
    request.attribute = ua::AttributeId::Value;
    request.samplingIntervalMs = samplingIntervalMs;
    if (withSuppressingFilter)
    {
      // A DataChangeFilter that (server-side) would suppress an unchanged value: StatusValue trigger with a
      // large deadband. (Not yet plumbed onto the wire - see the file header; the first sample is delivered
      // regardless, which is what this arm asserts.)
      ua::DataChangeFilter filter;
      filter.trigger() = ua::DataChangeTrigger::StatusValue;
      request.filter = filter;
    }
    std::promise<MonitoredItemResult> promise;
    auto future = promise.get_future();
    mConnection->monitor_data_change_async(
      subscriptionId,
      std::move(request),
      [sink](DataChangeEvent event) { sink->push(std::move(event.value)); },
      [&promise](MonitoredItemResult result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  Result<ua::DeleteMonitoredItemsResponse> delete_monitored_item(
    std::uint32_t subscriptionId, std::uint32_t monitoredItemId, std::uint32_t clientHandle)
  {
    std::promise<Result<ua::DeleteMonitoredItemsResponse>> promise;
    auto future = promise.get_future();
    mConnection->delete_monitored_item_async(subscriptionId,
      monitoredItemId,
      clientHandle,
      [&promise](Result<ua::DeleteMonitoredItemsResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

  Result<ua::SetMonitoringModeResponse> set_monitoring_mode(
    std::uint32_t subscriptionId, ua::MonitoringMode mode, std::uint32_t monitoredItemId)
  {
    ua::SetMonitoringModeRequest request;
    request.subscription_id() = subscriptionId;
    request.monitoring_mode() = mode;
    request.monitored_item_ids().push_back(monitoredItemId);
    std::promise<Result<ua::SetMonitoringModeResponse>> promise;
    auto future = promise.get_future();
    mConnection->set_monitoring_mode_async(std::move(request),
      [&promise](Result<ua::SetMonitoringModeResponse> result) { promise.set_value(std::move(result)); });
    return future.get();
  }

private:
  boost::asio::thread_pool mThreadPool;
  std::optional<Client> mClient;
  std::shared_ptr<ConnectionImpl> mConnection;
  VoidResult mStartStatus{};
};

std::shared_ptr<RequestCapture> arm_request_capture(MisbehavingServer& server)
{
  auto capture = std::make_shared<RequestCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });
  return capture;
}

}  // namespace

class ClientMonitoredItem : public ::testing::Test
{};

using ClientMonitorComplexValue = ClientMonitoredItem;

// =============================================================================================
// CL-MI-030 - structured monitored values traverse the Connection TypeResolver before the public
// Subscription callback. A registered encoding becomes its concrete Structure; an unresolved encoding
// remains losslessly opaque and emits one bounded first-seen advisory.
// =============================================================================================
// @verifies CL-MI-030
// @relation(CL-MI-030, scope=function)
TEST_F(ClientMonitorComplexValue, DecodedViaTypeResolver)
{
  MisbehavingServer server;
  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  ASSERT_TRUE(fixture.register_argument_type().is_good());

  const auto opaque = make_opaque_argument();
  const auto* unknown = dynamic_cast<const ua::UnknownStructure*>(opaque.get());
  ASSERT_NE(unknown, nullptr);
  const auto encodingId = unknown->encoding_id();
  const auto body = unknown->encoded_data();

  auto clientHandle = std::make_shared<std::atomic<std::uint32_t>>(0);
  auto sequence = std::make_shared<std::atomic<std::uint32_t>>(0);
  server.set_response_mutator(
    [clientHandle, sequence, encodingId, body](ua::Response& response)
    {
      auto* publish = as_publish(response);
      const auto handle = clientHandle->load();
      if (publish == nullptr || handle == 0U)
        return;
      set_publish_sequence(*publish, ++(*sequence));
      set_data_change(*publish,
        {HandleValue{handle,
          ua::Variant{ua::UnknownStructure{
            encodingId, ua::UnknownStructure::BodyEncoding::Binary, ua::ByteString{body}}}}});
    });

  auto connection = fixture.connection();
  auto subscription = connection.subscriptions().try_create_sync({.publishingIntervalMs = 50.0});
  ASSERT_TRUE(subscription.is_good()) << ua::to_string(subscription.status_code());
  auto sink = std::make_shared<DataValueSink>();
  ua::client::MonitorRequest request;
  request.nodeId = monitoredNode;
  auto monitored = subscription.value().try_monitor_sync(
    request, [sink](ua::client::DataChangeEvent event) { sink->push(std::move(event.value)); });
  ASSERT_TRUE(monitored.is_good()) << ua::to_string(monitored.status_code());
  clientHandle->store(monitored.value().client_handle());

  ASSERT_TRUE(wait_until([&] { return sink->has_argument_named("Speed"); }))
    << "the public Subscription callback must receive the registered concrete Argument";
}

// @verifies CL-MI-030
// @relation(CL-MI-030, scope=function)
TEST_F(ClientMonitorComplexValue, UnknownTypeFallsBackToExtensionObject)
{
  MisbehavingServer server;
  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto connection = fixture.connection();
  auto observer = std::make_shared<AdvisoryCaptureObserver>();
  connection.set_connection_observer(observer);

  const ua::NodeId encodingId{9, 9001U};
  const ua::ByteString body{0xCA, 0xFE};
  auto clientHandle = std::make_shared<std::atomic<std::uint32_t>>(0);
  auto sequence = std::make_shared<std::atomic<std::uint32_t>>(0);
  server.set_response_mutator(
    [clientHandle, sequence, encodingId, body](ua::Response& response)
    {
      auto* publish = as_publish(response);
      const auto handle = clientHandle->load();
      if (publish == nullptr || handle == 0U)
        return;
      set_publish_sequence(*publish, ++(*sequence));
      set_data_change(*publish,
        {HandleValue{handle,
          ua::Variant{ua::UnknownStructure{
            encodingId, ua::UnknownStructure::BodyEncoding::Binary, ua::ByteString{body}}}}});
    });

  auto subscription = connection.subscriptions().try_create_sync({.publishingIntervalMs = 50.0});
  ASSERT_TRUE(subscription.is_good()) << ua::to_string(subscription.status_code());
  auto sink = std::make_shared<DataValueSink>();
  ua::client::MonitorRequest request;
  request.nodeId = monitoredNode;
  auto monitored = subscription.value().try_monitor_sync(
    request, [sink](ua::client::DataChangeEvent event) { sink->push(std::move(event.value)); });
  ASSERT_TRUE(monitored.is_good()) << ua::to_string(monitored.status_code());
  clientHandle->store(monitored.value().client_handle());

  ASSERT_TRUE(wait_until([&] { return sink->size() >= 2U && sink->has_unknown(encodingId, body); }))
    << "unknown structured notifications must remain losslessly opaque";
  ASSERT_TRUE(wait_until([&] { return observer->count() >= 1U; }));
  EXPECT_EQ(observer->count(), 1U) << "the resolver gate must coalesce repeat advisories for one encoding";
  const auto detail = observer->last_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "MonitoredItemStructuredValueUnresolved");
  EXPECT_EQ(detail->source, "client.tier1.monitor.structured_value_unresolved");
}

// =============================================================================================
// Row - CreateMixedPerItemResultsSurfacedPositionally  (MisbehavingServer)
// A run of single-item creates whose per-item result alternates Good / Bad_NodeIdUnknown: each create's
// result must be attributed to the RIGHT item (the Good ones attach + later deliver; the Bad one does not),
// and an all-bad tail must NOT tear down the already-attached siblings. [neg: alternating and all-bad
// per-item vectors]
// =============================================================================================
// @verifies AC-CL-MI-005-CREATE-ALIGNMENT
// @verifies CL-MI-006
// @relation(AC-CL-MI-005-CREATE-ALIGNMENT, CL-MI-006, scope=function)
TEST_F(ClientMonitoredItem, CreateMixedPerItemResultsSurfacedPositionally)
{
  MisbehavingServer server;
  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  // atomic drives per-create stamping: 0 = leave the (Good) server result untouched, else stamp results[0]'s
  // status to this code. A separate flag switches on the controlled delivery phase.
  auto createStatus = std::make_shared<std::atomic<std::uint32_t>>(0);
  auto deliver = std::make_shared<std::atomic<bool>>(false);
  const std::int32_t v1 = 11111, v2 = 22222, v3 = 33333;
  const std::uint32_t h1 = 1, h2 = 2, h3 = 3;
  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);
  server.set_response_mutator(
    [createStatus, deliver, sequenceNumber, v1, v2, v3, h1, h2, h3](Response& response)
    {
      if (auto* create = as_create_items(response))
      {
        const std::uint32_t code = createStatus->load();
        if (code != 0 && create->results().size() >= 1)
        {
          create->results()[0].status_code() = ua::StatusCode{static_cast<ua::Status>(code)};
        }
        return;
      }
      if (auto* publish = as_publish(response); publish && deliver->load())
      {
        set_publish_sequence(*publish, ++(*sequenceNumber));
        set_data_change(*publish,
          {HandleValue{h1, ua::Variant{v1}},
            HandleValue{h2, ua::Variant{v2}},
            HandleValue{h3, ua::Variant{v3}}});
      }
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();
  auto sink1 = std::make_shared<DataValueSink>();
  auto sink2 = std::make_shared<DataValueSink>();
  auto sink3 = std::make_shared<DataValueSink>();

  createStatus->store(0);  // item 1: Good
  const auto r1 = fixture.create_monitored_item(subscriptionId, h1, sink1);
  createStatus->store(static_cast<std::uint32_t>(ua::Status::BadNodeIdUnknown));  // item 2: Bad
  const auto r2 = fixture.create_monitored_item(subscriptionId, h2, sink2);
  createStatus->store(0);  // item 3: Good
  const auto r3 = fixture.create_monitored_item(subscriptionId, h3, sink3);

  EXPECT_TRUE(r1.is_good()) << "the first (Good) create must succeed";
  EXPECT_TRUE(r2.is_bad()) << "the second (Bad_NodeIdUnknown) create must fail";
  EXPECT_EQ(r2.status_code(), ua::StatusCode{ua::Status::BadNodeIdUnknown})
    << "the Bad result must be attributed to item 2 with its exact per-item status";
  EXPECT_TRUE(r3.is_good())
    << "the third (Good) create must succeed - the middle failure must not bleed onto "
       "its neighbour";
  ASSERT_TRUE(wait_until([&] { return fixture.monitored_item_count() == 2; }))
    << "exactly the two Good items attach (the Bad one is deregistered)";

  // Controlled delivery: the two attached handles (1, 3) receive their own values; the unattached handle (2)
  // is an unknown-handle advisory drop (proving item 2 truly did not attach).
  deliver->store(true);
  EXPECT_TRUE(wait_until([&] { return sink1->has_int32(v1) && sink3->has_int32(v3); }))
    << "each attached item receives its OWN value (positional per-item attribution)";
  EXPECT_TRUE(wait_until([&] { return fixture.unknown_handle_drops() >= 1; }))
    << "the failed item's handle is unregistered - its notification is an advisory drop";
  EXPECT_EQ(sink2->size(), 0u) << "the failed item's callback must never fire";

  // All-bad tail: two further all-bad creates must NOT tear down the attached siblings.
  createStatus->store(static_cast<std::uint32_t>(ua::Status::BadNodeIdUnknown));
  EXPECT_TRUE(fixture.create_monitored_item(subscriptionId, 4, std::make_shared<DataValueSink>()).is_bad());
  EXPECT_TRUE(fixture.create_monitored_item(subscriptionId, 5, std::make_shared<DataValueSink>()).is_bad());
  EXPECT_TRUE(wait_until([&] { return fixture.monitored_item_count() == 2; }))
    << "an all-bad create batch must deregister its failed items without evicting the good siblings";
  EXPECT_EQ(fixture.state(), ConnectionState::Active) << "per-item failures must not fault the Connection";
}

// =============================================================================================
// Row - CreateResultsLengthMismatchRejected  (MisbehavingServer)  [integration+unit]
// A single-item CreateMonitoredItems whose results array is empty / short / long (not exactly one) must be
// rejected with a slot-alignment error carrying a chained ErrorDetail, leaving NO partial attach state.
// [neg: empty/short/long results array; unit pins results.size()==itemsToCreate.size()]
// =============================================================================================
// @verifies AC-CL-MI-005-CREATE-ALIGNMENT
// @relation(AC-CL-MI-005-CREATE-ALIGNMENT, scope=function)
TEST_F(ClientMonitoredItem, CreateResultsLengthMismatchRejected)
{
  MisbehavingServer server;
  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto targetCount = std::make_shared<std::atomic<int>>(-1);  // -1 = leave untouched
  server.set_response_mutator(
    [targetCount](Response& response)
    {
      auto* create = as_create_items(response);
      if (!create)
      {
        return;
      }
      const int count = targetCount->load();
      if (count < 0)
      {
        return;
      }
      ua::Array<ua::MonitoredItemCreateResult> replacement;
      for (int i = 0; i < count; ++i)
      {
        ua::MonitoredItemCreateResult item;
        item.status_code() = ua::StatusCode{ua::Status::Good};
        item.monitored_item_id() = static_cast<ua::IntegerId>(i + 1);
        replacement.push_back(std::move(item));
      }
      create->results() = std::move(replacement);
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();

  for (const int badCount : {0, 2, 3})
  {
    targetCount->store(badCount);
    auto sink = std::make_shared<DataValueSink>();
    const auto result = fixture.create_monitored_item(subscriptionId, /*clientHandle=*/10, sink);
    EXPECT_TRUE(result.is_bad()) << "a result-count of " << badCount
                                 << " for a single-item create must be rejected, not read positionally";
    EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadUnexpectedError})
      << "a slot-alignment mismatch must be Bad_UnexpectedError";
    ASSERT_TRUE(result.shared_detail()) << "the mismatch rejection must carry a chained ErrorDetail";
    EXPECT_EQ(
      result.shared_detail()->source, "client.tier1.connection.create_monitored_item.result_count_mismatch");
    EXPECT_TRUE(wait_until([&] { return fixture.monitored_item_count() == 0; }))
      << "a rejected create must leave no partial attach state";
  }
}

// =============================================================================================
// Row - CreateServiceLevelErrorsSurfacedNoAttach  (MisbehavingServer)
// A CreateMonitoredItems whose ResponseHeader.serviceResult is bad must surface that exact code and attach NO
// item; a Create-side Bad_SubscriptionIdInvalid must NOT drive a recreate cascade (no extra
// CreateSubscription). [neg: Create Bad_SubscriptionIdInvalid must not drive recreate-FSM]
// =============================================================================================
// @verifies CL-MI-007
// @relation(CL-MI-007, scope=function)
TEST_F(ClientMonitoredItem, CreateServiceLevelErrorsSurfacedNoAttach)
{
  MisbehavingServer server;
  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  auto serviceCode = std::make_shared<std::atomic<std::uint32_t>>(0);  // 0 = leave untouched
  server.set_response_mutator(
    [serviceCode](Response& response)
    {
      auto* create = as_create_items(response);
      if (!create)
      {
        return;
      }
      const std::uint32_t code = serviceCode->load();
      if (code != 0)
      {
        create->response_header().service_result() = ua::StatusCode{static_cast<ua::Status>(code)};
      }
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();
  ASSERT_EQ(capture->create_subscription_count(), 1u);

  for (const ua::Status code : {ua::Status::BadTooManyOperations,
         ua::Status::BadNothingToDo,
         ua::Status::BadTimestampsToReturnInvalid,
         ua::Status::BadSubscriptionIdInvalid})
  {
    serviceCode->store(static_cast<std::uint32_t>(code));
    auto sink = std::make_shared<DataValueSink>();
    const auto result = fixture.create_monitored_item(subscriptionId, /*clientHandle=*/11, sink);
    EXPECT_TRUE(result.is_bad());
    EXPECT_EQ(result.status_code(), ua::StatusCode{code}) << "the exact service-level code must reach the "
                                                             "caller";
    EXPECT_TRUE(wait_until([&] { return fixture.monitored_item_count() == 0; }))
      << "a service-level error must attach no item";
  }

  // A Create-side Bad_SubscriptionIdInvalid must NOT drive a recreate: no extra CreateSubscription is sent,
  // and the Connection stays Active (only the Publish path drives recreate).
  EXPECT_EQ(capture->create_subscription_count(), 1u)
    << "a Create-only failure must not trigger a recreate CreateSubscription cascade";
  EXPECT_EQ(fixture.state(), ConnectionState::Active);
}

// =============================================================================================
// Row - DeleteDoesNotDisturbSiblings  (MisbehavingServer)
// Two items in one Subscription; deleting one must not tear down the shared dispatch state - the surviving
// sibling keeps delivering. [neg: sibling isolation on delete]
// =============================================================================================
// @verifies CL-MI-008
// @relation(CL-MI-008, scope=function)
TEST_F(ClientMonitoredItem, DeleteDoesNotDisturbSiblings)
{
  MisbehavingServer server;
  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const std::uint32_t h1 = 1, h2 = 2;
  const std::int32_t siblingValue = 44444;
  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);
  server.set_response_mutator(
    [sequenceNumber, h2, siblingValue](Response& response)
    {
      auto* publish = as_publish(response);
      if (!publish)
      {
        return;
      }
      set_publish_sequence(*publish, ++(*sequenceNumber));
      set_data_change(*publish, {HandleValue{h2, ua::Variant{siblingValue}}});
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();
  auto sink1 = std::make_shared<DataValueSink>();
  auto sink2 = std::make_shared<DataValueSink>();
  const auto item1 = fixture.create_monitored_item(subscriptionId, h1, sink1);
  ASSERT_TRUE(item1.is_good());
  ASSERT_TRUE(fixture.create_monitored_item(subscriptionId, h2, sink2).is_good());
  ASSERT_TRUE(wait_until([&] { return fixture.monitored_item_count() == 2; }));

  // The sibling (handle 2) is delivering before the delete.
  ASSERT_TRUE(wait_until([&] { return sink2->has_int32(siblingValue); }))
    << "the sibling must be delivering before the delete (non-vacuous)";

  auto deleteResult = fixture.delete_monitored_item(subscriptionId, item1.value(), h1);
  ASSERT_TRUE(deleteResult.is_good()) << to_string(deleteResult.status_code());
  ASSERT_TRUE(wait_until([&] { return fixture.monitored_item_count() == 1; }))
    << "the deleted item is deregistered; the sibling remains";

  // The sibling KEEPS delivering after the delete: record its post-delete count and prove it grows.
  const std::size_t baseline = sink2->size();
  EXPECT_TRUE(wait_until([&] { return sink2->size() > baseline; }))
    << "deleting one item must not stop the sibling's dispatch";
}

// =============================================================================================
// Row - DeleteStopsDispatchOfLateNotifications  (MisbehavingServer)  [integration+unit]
// After a positive DeleteMonitoredItems, a late Publish bearing the now-stale clientHandle must NOT dispatch:
// the dispatch-map entry is erased, so the notification is an advisory drop with no callback fired.
// [neg: late notification after positive Delete; unit pins dispatch-map erase on Delete success]
// =============================================================================================
// @verifies CL-MI-008
// @relation(CL-MI-008, scope=function)
TEST_F(ClientMonitoredItem, DeleteStopsDispatchOfLateNotifications)
{
  MisbehavingServer server;
  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const std::uint32_t handle = 1;
  const std::int32_t staleValue = 55555;
  auto deliverStale = std::make_shared<std::atomic<bool>>(false);
  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);
  server.set_response_mutator(
    [deliverStale, sequenceNumber, handle, staleValue](Response& response)
    {
      auto* publish = as_publish(response);
      if (!publish || !deliverStale->load())
      {
        return;
      }
      set_publish_sequence(*publish, ++(*sequenceNumber));
      set_data_change(*publish, {HandleValue{handle, ua::Variant{staleValue}}});
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();
  auto sink = std::make_shared<DataValueSink>();
  const auto item = fixture.create_monitored_item(subscriptionId, handle, sink);
  ASSERT_TRUE(item.is_good());
  ASSERT_TRUE(wait_until([&] { return fixture.monitored_item_count() == 1; }));

  auto deleteResult = fixture.delete_monitored_item(subscriptionId, item.value(), handle);
  ASSERT_TRUE(deleteResult.is_good()) << to_string(deleteResult.status_code());
  ASSERT_TRUE(wait_until([&] { return fixture.monitored_item_count() == 0; }))
    << "the dispatch-map entry is erased on a positive Delete";

  // NOW inject the stale-handle notification. It must be an advisory drop, never a callback.
  const std::size_t sinkBaseline = sink->size();
  const std::size_t dropBaseline = fixture.unknown_handle_drops();
  deliverStale->store(true);
  EXPECT_TRUE(wait_until([&] { return fixture.unknown_handle_drops() > dropBaseline; }))
    << "a late notification for the deleted handle must be counted as an advisory drop";
  EXPECT_EQ(sink->size(), sinkBaseline) << "a deleted item's callback must NOT fire for a late notification";
  EXPECT_FALSE(sink->has_int32(staleValue)) << "the stale value must never reach the user callback";
}

// =============================================================================================
// Row - DispatchByClientHandle  (MisbehavingServer)  [integration+unit]
// Three items with distinct callbacks; one Publish carrying notifications for all three (REORDERED relative
// to creation) must route each value to its OWN callback by clientHandle. [neg: handle routing]
// =============================================================================================
// @verifies CL-MI-003
// @relation(CL-MI-003, scope=function)
TEST_F(ClientMonitoredItem, DispatchByClientHandle)
{
  MisbehavingServer server;
  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const std::uint32_t h1 = 1, h2 = 2, h3 = 3;
  const std::int32_t v1 = 101, v2 = 202, v3 = 303;
  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);
  // Deliver all three in ONE DataChangeNotification, REORDERED (3, 1, 2): index-based routing would misroute.
  server.set_response_mutator(
    [sequenceNumber, h1, h2, h3, v1, v2, v3](Response& response)
    {
      auto* publish = as_publish(response);
      if (!publish)
      {
        return;
      }
      set_publish_sequence(*publish, ++(*sequenceNumber));
      set_data_change(*publish,
        {HandleValue{h3, ua::Variant{v3}},
          HandleValue{h1, ua::Variant{v1}},
          HandleValue{h2, ua::Variant{v2}}});
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();
  auto sink1 = std::make_shared<DataValueSink>();
  auto sink2 = std::make_shared<DataValueSink>();
  auto sink3 = std::make_shared<DataValueSink>();
  ASSERT_TRUE(fixture.create_monitored_item(subscriptionId, h1, sink1).is_good());
  ASSERT_TRUE(fixture.create_monitored_item(subscriptionId, h2, sink2).is_good());
  ASSERT_TRUE(fixture.create_monitored_item(subscriptionId, h3, sink3).is_good());

  EXPECT_TRUE(wait_until([&] { return sink1->has_int32(v1); }))
    << "handle 1's callback must receive handle 1's value";
  EXPECT_TRUE(wait_until([&] { return sink2->has_int32(v2); }))
    << "handle 2's callback must receive handle 2's value";
  EXPECT_TRUE(wait_until([&] { return sink3->has_int32(v3); }))
    << "handle 3's callback must receive handle 3's value";
  // Cross-contamination check: no callback ever saw another item's value.
  EXPECT_FALSE(sink1->has_int32(v2) || sink1->has_int32(v3)) << "handle 1 must see only its own value";
  EXPECT_FALSE(sink2->has_int32(v1) || sink2->has_int32(v3)) << "handle 2 must see only its own value";
  EXPECT_FALSE(sink3->has_int32(v1) || sink3->has_int32(v2)) << "handle 3 must see only its own value";
}

// =============================================================================================
// Row - FirstSampleDispatchedUnconditionally  (MisbehavingServer)
// The mandatory first sample the server delivers on create must reach the callback - the client never
// swallows the initial value. [neg: first sample bypasses filter]
//
// REPORTED (wire-filter unbuilt): the MonitorRequest DataChangeFilter is not plumbed onto the wire and the
// client applies no filter client-side, so the "despite the filter" clause is vacuous at the client; the
// built, spec-consistent guarantee this pins is that the real server's first sample is delivered.
// =============================================================================================
// @verifies CL-MI-004
// @relation(CL-MI-004, scope=function)
TEST_F(ClientMonitoredItem, FirstSampleDispatchedUnconditionally)
{
  MisbehavingServer server;
  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  // No response mutator: the un-mutated real server delivers the monitored node's initial value.
  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  auto sink = std::make_shared<DataValueSink>();
  const auto item = fixture.monitor(subscription.value(),
    /*samplingIntervalMs=*/0.0,
    sink,
    /*withSuppressingFilter=*/true);
  ASSERT_TRUE(item.is_good()) << to_string(item.status_code());

  EXPECT_TRUE(wait_until([&] { return sink->size() >= 1; }))
    << "the server's mandatory first sample must be delivered to the callback (never swallowed)";
}

// =============================================================================================
// Row - InterArrivalGapNotFlaggedWhenHonored  (MisbehavingServer)
// The honored-cadence arm must not raise an advisory. [neg: honored cadence must not warn]
//
// BLOCKED (inter-arrival gap detector + advisory interface unbuilt): there is no inter-arrival gap detector
// on the monitored-item path and nothing on that path emits an advisory diagnostic. The strengthened matrix
// pairs a below-bound arm that SHOULD fire - but with no detector, neither arm can fire. Pin the built
// observable: notifications flow and NO advisory is ever emitted (a falsifiable zero); report the detector +
// advisory unbuilt.
// =============================================================================================
// @verifies CL-MI-001
// @relation(CL-MI-001, scope=function)
TEST_F(ClientMonitoredItem, InterArrivalGapNotFlaggedWhenHonored)
{
  MisbehavingServer server;
  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto advisory = std::make_shared<AdvisoryCountingObserver>();
  fixture.set_connection_observer(advisory);

  const std::uint32_t handle = 1;
  const std::int32_t value = 61616;
  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);
  // Deliver a fresh value on EVERY publish (an aggressive, below-any-plausible-bound cadence): a real
  // inter-arrival detector would fire here; the unbuilt one does not, and the honored arm certainly must not.
  server.set_response_mutator(
    [sequenceNumber, handle, value](Response& response)
    {
      auto* publish = as_publish(response);
      if (!publish)
      {
        return;
      }
      set_publish_sequence(*publish, ++(*sequenceNumber));
      set_data_change(*publish, {HandleValue{handle, ua::Variant{value}}});
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  auto sink = std::make_shared<DataValueSink>();
  ASSERT_TRUE(fixture.create_monitored_item(subscription.value(), handle, sink).is_good());

  ASSERT_TRUE(wait_until([&] { return sink->size() >= 3; }))
    << "several notifications must flow so the no-advisory assertion is not vacuous";
  std::this_thread::sleep_for(200ms);  // let any (mis)fired advisory be posted before the check
  EXPECT_EQ(advisory->count(), 0u)
    << "REPORTED: the inter-arrival gap detector + advisory interface are unbuilt, so NO advisory fires (the "
       "honored-cadence arm must not warn; the below-bound arm cannot fire either)";
  EXPECT_EQ(fixture.state(), ConnectionState::Active);
}

// =============================================================================================
// Row - NodeIdUnknownThenGoodAfterReAdd  (MisbehavingServer)
// A per-item DataValue Bad_NodeIdUnknown then Good on the same handle: the item must stay ATTACHED across the
// bad status and deliver the later Good value (a node removed then re-added recovers). [neg: transient node
// removal]
// =============================================================================================
// @verifies CL-MI-006
// @relation(CL-MI-006, scope=function)
TEST_F(ClientMonitoredItem, NodeIdUnknownThenGoodAfterReAdd)
{
  MisbehavingServer server;
  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const std::uint32_t handle = 1;
  const std::int32_t goodValue = 71717;
  auto goodPhase = std::make_shared<std::atomic<bool>>(false);
  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);
  server.set_response_mutator(
    [goodPhase, sequenceNumber, handle, goodValue](Response& response)
    {
      auto* publish = as_publish(response);
      if (!publish)
      {
        return;
      }
      set_publish_sequence(*publish, ++(*sequenceNumber));
      if (goodPhase->load())
      {
        set_data_change(*publish, {HandleValue{handle, ua::Variant{goodValue}}});
      }
      else
      {
        // A Bad_NodeIdUnknown per-item status carrying no value (the node is transiently gone server-side).
        set_data_change(
          *publish, {HandleValue{handle, ua::Variant{}, ua::StatusCode{ua::Status::BadNodeIdUnknown}}});
      }
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  auto sink = std::make_shared<DataValueSink>();
  ASSERT_TRUE(fixture.create_monitored_item(subscription.value(), handle, sink).is_good());

  // The bad-status notifications flow; the item must NOT be removed on a per-item bad status.
  ASSERT_TRUE(wait_until([&] { return sink->has_status(ua::StatusCode{ua::Status::BadNodeIdUnknown}); }))
    << "the Bad_NodeIdUnknown per-item notification is delivered (non-vacuous)";
  EXPECT_EQ(fixture.monitored_item_count(), 1u)
    << "a per-item Bad_NodeIdUnknown must NOT remove the item (recovery would be impossible)";

  // The node is re-added: the later Good value must still be delivered on the same handle.
  goodPhase->store(true);
  EXPECT_TRUE(wait_until([&] { return sink->has_int32(goodValue); }))
    << "the later Good value must be delivered - the item stayed attached across the bad status";
}

// =============================================================================================
// Row - PublishBadPerItemStatusPreservesItem  (MisbehavingServer)
// A Bad_UserAccessDenied then Good DataValue on the same handle: BOTH reach the callback and the dispatch
// entry survives between them (a bad per-item status is non-fatal). [neg: bad status is non-fatal; item stays
// registered]
// =============================================================================================
// @verifies AC-CL-MI-006-PERITEM-BAD-NONFATAL
// @relation(AC-CL-MI-006-PERITEM-BAD-NONFATAL, scope=function)
TEST_F(ClientMonitoredItem, PublishBadPerItemStatusPreservesItem)
{
  MisbehavingServer server;
  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const std::uint32_t handle = 1;
  const std::int32_t goodValue = 81818;
  auto goodPhase = std::make_shared<std::atomic<bool>>(false);
  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);
  server.set_response_mutator(
    [goodPhase, sequenceNumber, handle, goodValue](Response& response)
    {
      auto* publish = as_publish(response);
      if (!publish)
      {
        return;
      }
      set_publish_sequence(*publish, ++(*sequenceNumber));
      if (goodPhase->load())
      {
        set_data_change(*publish, {HandleValue{handle, ua::Variant{goodValue}}});
      }
      else
      {
        set_data_change(
          *publish, {HandleValue{handle, ua::Variant{}, ua::StatusCode{ua::Status::BadUserAccessDenied}}});
      }
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  auto sink = std::make_shared<DataValueSink>();
  ASSERT_TRUE(fixture.create_monitored_item(subscription.value(), handle, sink).is_good());

  ASSERT_TRUE(wait_until([&] { return sink->has_status(ua::StatusCode{ua::Status::BadUserAccessDenied}); }))
    << "the bad per-item status notification must reach the callback";
  EXPECT_EQ(fixture.monitored_item_count(), 1u) << "a bad per-item status must not remove the item";

  goodPhase->store(true);
  EXPECT_TRUE(wait_until([&] { return sink->has_int32(goodValue); }))
    << "the subsequent Good notification must also reach the callback (the dispatch entry survived)";
}

// =============================================================================================
// Row - RevisedSamplingIntervalPathologiesStoredWithAdvisory  (MisbehavingServer)
// The server returns pathological revisedSamplingInterval values {10x, requested/10, negative, NaN,
// Double.MaxValue}. Each must be stored VERBATIM on the handle without crashing the decode; a spec-violating
// value would (when the advisory interface lands) additionally raise an advisory. [neg:
// negative/NaN/DoubleMax robustness + <requested advisory]
//
// BLOCKED (advisory interface unbuilt): the monitored-item advisory-diagnostic interface is not built
// (nothing on the create path calls fire_advisory_diagnostic). Pin the BUILT part - the raw revised value
// survives on the handle verbatim, no crash - and report the advisory blocked (a ConnectionObserver counter
// stays zero).
// =============================================================================================
// @verifies AC-CL-MI-002-REVISED-SAMPLING
// @relation(AC-CL-MI-002-REVISED-SAMPLING, scope=function)
TEST_F(ClientMonitoredItem, RevisedSamplingIntervalPathologiesStoredWithAdvisory)
{
  MisbehavingServer server;
  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto advisory = std::make_shared<AdvisoryCountingObserver>();
  fixture.set_connection_observer(advisory);

  auto revised = std::make_shared<std::atomic<double>>(0.0);
  auto active = std::make_shared<std::atomic<bool>>(false);
  server.set_response_mutator(
    [revised, active](Response& response)
    {
      auto* create = as_create_items(response);
      if (!create || !active->load() || create->results().empty())
      {
        return;
      }
      create->results()[0].revised_sampling_interval() = revised->load();
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();
  const double requested = 100.0;
  active->store(true);

  const double nan = std::numeric_limits<double>::quiet_NaN();
  const double dmax = std::numeric_limits<double>::max();
  for (const double pathology : {1000.0, 10.0, -5.0, nan, dmax})
  {
    revised->store(pathology);
    auto sink = std::make_shared<DataValueSink>();
    const auto item = fixture.monitor(subscriptionId, requested, sink);
    ASSERT_TRUE(item.is_good()) << "a pathological revised interval must not crash the create";
    const double stored = item.value().revised_sampling_interval();
    if (std::isnan(pathology))
    {
      EXPECT_TRUE(std::isnan(stored)) << "NaN must be stored verbatim, not normalized";
    }
    else
    {
      EXPECT_EQ(stored, pathology) << "the raw revised interval must be stored verbatim";
    }
  }

  std::this_thread::sleep_for(200ms);
  EXPECT_EQ(advisory->count(), 0u)
    << "REPORTED: the monitored-item advisory-diagnostic interface is unbuilt, so no advisory fires for a "
       "spec-violating revised interval (the verbatim storage IS built and asserted above)";
  EXPECT_EQ(fixture.state(), ConnectionState::Active);
}

// =============================================================================================
// Row - SetMonitoringModeDisabledThenEnabledNoReplay  (MisbehavingServer)
// SetMonitoringMode Disable then Enable: the per-item results are surfaced, the item stays registered across
// the cycle, and the client issues NO Republish/backlog-recovery on re-enable (it must not treat the
// post-enable value as a sequence gap). [neg: queue dropped on Disable]
// =============================================================================================
// @verifies AC-CL-MI-007-DISABLE-DROPS-QUEUE
// @verifies CL-MI-021
// @relation(AC-CL-MI-007-DISABLE-DROPS-QUEUE, CL-MI-021, scope=function)
TEST_F(ClientMonitoredItem, SetMonitoringModeDisabledThenEnabledNoReplay)
{
  MisbehavingServer server;
  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_request_capture(server);
  const std::uint32_t handle = 1;
  const std::int32_t postEnableValue = 91919;
  auto deliver = std::make_shared<std::atomic<bool>>(false);
  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);
  server.set_response_mutator(
    [deliver, sequenceNumber, handle, postEnableValue](Response& response)
    {
      auto* publish = as_publish(response);
      if (!publish || !deliver->load())
      {
        return;
      }
      set_publish_sequence(*publish, ++(*sequenceNumber));
      set_data_change(*publish, {HandleValue{handle, ua::Variant{postEnableValue}}});
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();
  auto sink = std::make_shared<DataValueSink>();
  const auto item = fixture.create_monitored_item(subscriptionId, handle, sink);
  ASSERT_TRUE(item.is_good());

  // Disable, then re-enable - each per-item result must be surfaced Good.
  const auto disabled =
    fixture.set_monitoring_mode(subscriptionId, ua::MonitoringMode::Disabled, item.value());
  ASSERT_TRUE(disabled.is_good()) << to_string(disabled.status_code());
  ASSERT_GE(disabled.value().results().size(), 1u);
  EXPECT_TRUE(disabled.value().results()[0].is_good()) << "the Disable per-item result must be surfaced Good";

  const auto enabled =
    fixture.set_monitoring_mode(subscriptionId, ua::MonitoringMode::Reporting, item.value());
  ASSERT_TRUE(enabled.is_good()) << to_string(enabled.status_code());
  ASSERT_GE(enabled.value().results().size(), 1u);
  EXPECT_TRUE(enabled.value().results()[0].is_good()) << "the Enable per-item result must be surfaced Good";

  EXPECT_EQ(fixture.monitored_item_count(), 1u) << "the item stays registered across Disable -> Enable";

  // A post-enable value must be delivered WITHOUT the client issuing a Republish/backlog recovery.
  deliver->store(true);
  EXPECT_TRUE(wait_until([&] { return sink->has_int32(postEnableValue); }))
    << "the post-enable value must be delivered";
  EXPECT_EQ(capture->republish_count(), 0u)
    << "re-enable must not be treated as a sequence gap (no Republish / backlog recovery)";
}

// =============================================================================================
// Row - StoresRevisedSamplingInterval  (MisbehavingServer for a controlled revision)
// The server revises the requested sampling interval (request 100 ms, server revises to 250 ms); the handle
// must expose the server's revised value AND it must differ from the requested value. [neg: revised>requested
// stored]
// =============================================================================================
// @verifies AC-CL-MI-002-REVISED-SAMPLING
// @relation(AC-CL-MI-002-REVISED-SAMPLING, scope=function)
TEST_F(ClientMonitoredItem, StoresRevisedSamplingInterval)
{
  MisbehavingServer server;
  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const double requested = 100.0;
  const double serverRevised = 250.0;
  server.set_response_mutator(
    [serverRevised](Response& response)
    {
      auto* create = as_create_items(response);
      if (!create || create->results().empty())
      {
        return;
      }
      create->results()[0].revised_sampling_interval() = serverRevised;
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  auto sink = std::make_shared<DataValueSink>();
  const auto item = fixture.monitor(subscription.value(), requested, sink);
  ASSERT_TRUE(item.is_good()) << to_string(item.status_code());

  EXPECT_EQ(item.value().revised_sampling_interval(), serverRevised)
    << "the handle must expose the server's revised sampling interval";
  EXPECT_NE(item.value().revised_sampling_interval(), requested)
    << "the revised interval must differ from the requested value";
}

// =============================================================================================
// Row - DataChangeFilterEncodedOnCreateMonitoredItemsWire  (MisbehavingServer request capture; CL-MI-011)
// A DataChangeFilter supplied on the MonitorRequest must be encoded into the outgoing CreateMonitoredItems'
// MonitoringParameters.filter as a DataChangeFilter ExtensionObject carrying trigger + deadbandType +
// deadbandValue. The request observer captures the DECODED CreateMonitoredItems and inspects the filter.
// Falsified if the filter is dropped (null on the wire).
// =============================================================================================
// @verifies CL-MI-011
// @relation(CL-MI-011, scope=function)
TEST_F(ClientMonitoredItem, DataChangeFilterEncodedOnCreateMonitoredItemsWire)
{
  MisbehavingServer server;
  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto captured = std::make_shared<std::optional<ua::DataChangeFilter>>();
  server.set_request_observer(
    [captured](const ua::Structure& request)
    {
      const auto* create = dynamic_cast<const ua::CreateMonitoredItemsRequest*>(&request);
      if (create == nullptr || create->items_to_create().empty())
        return;
      const auto* wireFilter = dynamic_cast<const ua::DataChangeFilter*>(
        create->items_to_create()[0].requested_parameters().filter().get());
      if (wireFilter != nullptr)
      {
        *captured = *wireFilter;
      }
    });

  const auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());

  MonitorRequest request;
  // A numeric Variable: the server refuses an AbsoluteDeadband outside the Number subtree
  // (Part 4 7.22.2), and monitoredNode (ServerStatus.State) is an Enumeration.
  request.nodeId = NodeId{VariableId::Server_ServiceLevel};
  ua::DataChangeFilter filter;
  filter.trigger() = ua::DataChangeTrigger::StatusValue;
  filter.deadband_type() = 1;  // Absolute
  filter.deadband_value() = 2.5;
  request.filter = filter;

  auto sink = std::make_shared<DataValueSink>();
  std::promise<MonitoredItemResult> promise;
  auto future = promise.get_future();
  fixture.conn().monitor_data_change_async(
    subscription.value(),
    std::move(request),
    [sink](DataChangeEvent event) { sink->push(std::move(event.value)); },
    [&promise](MonitoredItemResult result) { promise.set_value(std::move(result)); });
  ASSERT_TRUE(future.get().is_good());

  ASSERT_TRUE(captured->has_value())
    << "the CreateMonitoredItems wire request must carry the DataChangeFilter (not drop it)";
  EXPECT_EQ((*captured)->trigger(), ua::DataChangeTrigger::StatusValue);
  EXPECT_EQ((*captured)->deadband_type(), 1u);
  EXPECT_DOUBLE_EQ((*captured)->deadband_value(), 2.5);
}

namespace
{

// The SERVICE-level verdict of a tier-1 call, whichever shape the client used to carry it: a ServiceFault
// surfaces as a bad `Result`, while a normal typed response carries its verdict in
// `ResponseHeader.serviceResult`. Accepting both keeps the assertion about the SERVER's service-level code
// instead of about the client's transport of it.
template<typename ResponseT>
ua::StatusCode effective_service_status(const Result<ResponseT>& result)
{
  if (result.is_bad())
  {
    return result.status_code();
  }
  return result.value().response_header().service_result();
}

Result<ua::ModifyMonitoredItemsResponse> send_modify_monitored_items(
  MisbehavingMonitoredItemFixture& fixture, ua::ModifyMonitoredItemsRequest request)
{
  std::promise<Result<ua::ModifyMonitoredItemsResponse>> promise;
  auto future = promise.get_future();
  fixture.conn().modify_monitored_items_async(std::move(request),
    [&promise](Result<ua::ModifyMonitoredItemsResponse> result) { promise.set_value(std::move(result)); });
  return future.get();
}

Result<ua::SetMonitoringModeResponse> send_set_monitoring_mode(
  MisbehavingMonitoredItemFixture& fixture, ua::SetMonitoringModeRequest request)
{
  std::promise<Result<ua::SetMonitoringModeResponse>> promise;
  auto future = promise.get_future();
  fixture.conn().set_monitoring_mode_async(std::move(request),
    [&promise](Result<ua::SetMonitoringModeResponse> result) { promise.set_value(std::move(result)); });
  return future.get();
}

// One ModifyMonitoredItems slot: the monitored-item id it names, the client handle it keeps and (optionally)
// the MonitoringFilter it carries. The sampling/queue parameters are the values the item was created with,
// so the ONLY thing that varies between the slots of a request is the fault under test.
ua::MonitoredItemModifyRequest make_modify_item(
  std::uint32_t monitoredItemId, std::uint32_t clientHandle, ua::unique_ptr<ua::Structure> filter = nullptr)
{
  ua::MonitoredItemModifyRequest item;
  item.monitored_item_id() = monitoredItemId;
  item.requested_parameters().client_handle() = clientHandle;
  item.requested_parameters().sampling_interval() = 100.0;
  item.requested_parameters().queue_size() = 1U;
  item.requested_parameters().discard_oldest() = true;
  if (filter)
  {
    item.requested_parameters().filter().inner_unique_ptr() = std::move(filter);
  }
  return item;
}

}  // namespace

// =============================================================================================
// Part 4 section 5.12.3.3 - ModifyMonitoredItems has its OWN service-level result set: Bad_NothingToDo (empty
// itemsToModify), Bad_TooManyOperations (over MaxMonitoredItemsPerCall), Bad_TimestampsToReturnInvalid (a
// timestampsToReturn outside the enumeration) and Bad_SubscriptionIdInvalid (a subscriptionId the Session
// does not own). A plausible implementation gets this wrong by treating Modify as a thin variant of Create
// and only porting SOME of Create's pre-dispatch checks across - the operation-limit clamp is the one that
// is easiest to leave behind, because Modify does not grow the item population and so "feels" unbounded.
// Each arm is driven separately so a missing check is attributed to its own condition.
// @verifies AC-SVR-MI-GEN-100-MODIFY-SERVICE-CODES
TEST_F(ClientMonitoredItem, ModifyMonitoredItemsReportsEachServiceLevelCondition)
{
  MisbehavingServer server;
  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();
  auto sink = std::make_shared<DataValueSink>();
  const auto item = fixture.create_monitored_item(subscriptionId, /*clientHandle=*/1, sink);
  ASSERT_TRUE(item.is_good()) << to_string(item.status_code());

  // Empty itemsToModify -> Bad_NothingToDo.
  {
    ua::ModifyMonitoredItemsRequest request;
    request.subscription_id() = subscriptionId;
    request.timestamps_to_return() = ua::TimestampsToReturn::Both;
    const auto modify = send_modify_monitored_items(fixture, std::move(request));
    EXPECT_EQ(effective_service_status(modify), ua::StatusCode{ua::Status::BadNothingToDo})
      << "an empty itemsToModify list must be refused at the service level";
  }

  // More items than the server's published MaxMonitoredItemsPerCall -> Bad_TooManyOperations. The limit is
  // taken from the server's own OperationLimits (read at bootstrap), so the arm cannot go vacuous if the
  // configured cap changes.
  {
    const auto info = fixture.conn().info();
    ASSERT_NE(info, nullptr);
    const std::uint32_t limit = info->operationLimits.maxMonitoredItemsPerCall;
    ASSERT_GT(limit, 0u) << "the server must publish MaxMonitoredItemsPerCall for the arm to bite";
    ASSERT_LT(limit, 100000u) << "the published limit must be small enough to exceed in one request";

    ua::ModifyMonitoredItemsRequest request;
    request.subscription_id() = subscriptionId;
    request.timestamps_to_return() = ua::TimestampsToReturn::Both;
    for (std::uint32_t i = 0; i <= limit; ++i)
    {
      request.items_to_modify().push_back(make_modify_item(item.value() + 100000U + i, /*clientHandle=*/1));
    }
    ASSERT_EQ(request.items_to_modify().size(), static_cast<std::size_t>(limit) + 1U);
    const auto modify = send_modify_monitored_items(fixture, std::move(request));
    EXPECT_EQ(effective_service_status(modify), ua::StatusCode{ua::Status::BadTooManyOperations})
      << "a Modify over MaxMonitoredItemsPerCall must be refused whole, at the service level - the "
         "operation limit is not Create-only";
  }

  // timestampsToReturn outside the enumeration -> Bad_TimestampsToReturnInvalid.
  {
    ua::ModifyMonitoredItemsRequest request;
    request.subscription_id() = subscriptionId;
    request.timestamps_to_return() = ua::TimestampsToReturn::Invalid;
    request.items_to_modify().push_back(make_modify_item(item.value(), /*clientHandle=*/1));
    const auto modify = send_modify_monitored_items(fixture, std::move(request));
    EXPECT_EQ(effective_service_status(modify), ua::StatusCode{ua::Status::BadTimestampsToReturnInvalid})
      << "an out-of-enumeration timestampsToReturn must be refused at the service level";
  }

  // A subscriptionId the Session does not own -> Bad_SubscriptionIdInvalid.
  {
    ua::ModifyMonitoredItemsRequest request;
    request.subscription_id() = subscriptionId + 9999U;
    request.timestamps_to_return() = ua::TimestampsToReturn::Both;
    request.items_to_modify().push_back(make_modify_item(item.value(), /*clientHandle=*/1));
    const auto modify = send_modify_monitored_items(fixture, std::move(request));
    EXPECT_EQ(effective_service_status(modify), ua::StatusCode{ua::Status::BadSubscriptionIdInvalid})
      << "an unknown subscriptionId must be refused at the service level";
  }

  EXPECT_EQ(fixture.state(), ConnectionState::Active)
    << "service-level Modify refusals must not fault the Connection";
}

// =============================================================================================
// Part 4 section 5.12.3.4 - ModifyMonitoredItems reports per-item faults POSITIONALLY, each in its own slot:
// Bad_MonitoredItemIdInvalid (no such item in this Subscription), Bad_MonitoredItemFilterInvalid (the filter
// parameter does not parse - here a DataChangeTrigger outside its enumeration), Bad_MonitoredItemFilterUn-
// supported (a filter type that is legal on this attribute but that the server does not implement - an
// AggregateFilter on a Value attribute), and Bad_FilterNotAllowed (a filter type the ATTRIBUTE forbids - an
// EventFilter on a Value attribute). A plausible implementation gets this wrong by validating a filter in
// isolation: it then collapses "unsupported" and "not allowed" onto a single code, and it accepts an
// undefined enumerator because the decoder widened it into the enum without checking.
// @verifies AC-SVR-MI-GEN-101-MODIFY-OPERATION-CODES
TEST_F(ClientMonitoredItem, ModifyMonitoredItemsReportsPerItemFaultsInTheirOwnSlots)
{
  MisbehavingServer server;
  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();

  auto sink1 = std::make_shared<DataValueSink>();
  auto sink2 = std::make_shared<DataValueSink>();
  auto sink3 = std::make_shared<DataValueSink>();
  const auto itemA = fixture.create_monitored_item(subscriptionId, /*clientHandle=*/1, sink1);
  const auto itemB = fixture.create_monitored_item(subscriptionId, /*clientHandle=*/2, sink2);
  const auto itemC = fixture.create_monitored_item(subscriptionId, /*clientHandle=*/3, sink3);
  ASSERT_TRUE(itemA.is_good()) << to_string(itemA.status_code());
  ASSERT_TRUE(itemB.is_good()) << to_string(itemB.status_code());
  ASSERT_TRUE(itemC.is_good()) << to_string(itemC.status_code());
  ASSERT_TRUE(wait_until([&] { return fixture.monitored_item_count() == 3; }))
    << "the three real items must be attached before the per-item faults are exercised";

  // Slot 1: a DataChangeFilter whose trigger is outside the DataChangeTrigger enumeration.
  auto invalidFilter = std::make_unique<ua::DataChangeFilter>();
  invalidFilter->trigger() = static_cast<ua::DataChangeTrigger>(99);

  // Slot 2: an AggregateFilter - a legal MonitoringFilter for a Value attribute that this server does not
  // implement.
  auto unsupportedFilter = std::make_unique<ua::AggregateFilter>();
  unsupportedFilter->processing_interval() = 1000.0;

  // Slot 3: an EventFilter - only ever allowed on an EventNotifier attribute.
  auto notAllowedFilter = std::make_unique<ua::EventFilter>();

  ua::ModifyMonitoredItemsRequest request;
  request.subscription_id() = subscriptionId;
  request.timestamps_to_return() = ua::TimestampsToReturn::Both;
  request.items_to_modify().push_back(make_modify_item(itemA.value() + 100000U, /*clientHandle=*/1));
  request.items_to_modify().push_back(make_modify_item(itemA.value(), 1, std::move(invalidFilter)));
  request.items_to_modify().push_back(make_modify_item(itemB.value(), 2, std::move(unsupportedFilter)));
  request.items_to_modify().push_back(make_modify_item(itemC.value(), 3, std::move(notAllowedFilter)));

  const auto modify = send_modify_monitored_items(fixture, std::move(request));
  ASSERT_TRUE(modify.is_good()) << "per-item faults must not be escalated to a service-level refusal: "
                                << to_string(modify.status_code());
  ASSERT_EQ(modify.value().response_header().service_result(), ua::StatusCode{ua::Status::Good});
  ASSERT_EQ(modify.value().results().size(), 4u)
    << "one result slot per requested item, positionally aligned";

  EXPECT_EQ(modify.value().results()[0].status_code(), ua::StatusCode{ua::Status::BadMonitoredItemIdInvalid})
    << "an item id the Subscription does not own must fail in its own slot";
  EXPECT_EQ(
    modify.value().results()[1].status_code(), ua::StatusCode{ua::Status::BadMonitoredItemFilterInvalid})
    << "a DataChangeTrigger outside its enumeration makes the filter parameter invalid";
  EXPECT_EQ(
    modify.value().results()[2].status_code(), ua::StatusCode{ua::Status::BadMonitoredItemFilterUnsupported})
    << "an AggregateFilter is ALLOWED on a Value attribute - an implementation that does not provide it must "
       "say unsupported, not not-allowed";
  EXPECT_EQ(modify.value().results()[3].status_code(), ua::StatusCode{ua::Status::BadFilterNotAllowed})
    << "an EventFilter is forbidden by the Value attribute itself";

  EXPECT_EQ(fixture.state(), ConnectionState::Active) << "per-item Modify faults must not fault the "
                                                         "Connection";
}

// =============================================================================================
// Part 4 section 5.12.4.3 - SetMonitoringMode has its own service-level result set: Bad_NothingToDo (empty
// monitoredItemIds), Bad_TooManyOperations (over MaxMonitoredItemsPerCall), Bad_SubscriptionIdInvalid (a
// subscriptionId the Session does not own) and Bad_MonitoringModeInvalid (a mode outside the enumeration).
// A plausible implementation gets this wrong by reusing Create's pre-dispatch checks wholesale: the mode is
// the one parameter Create validates per ITEM and SetMonitoringMode validates per REQUEST, and the operation
// limit is easy to omit for a service that only flips a flag.
// @verifies AC-SVR-MI-GEN-102-SETMODE-SERVICE-CODES
TEST_F(ClientMonitoredItem, SetMonitoringModeReportsEachServiceLevelCondition)
{
  MisbehavingServer server;
  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();
  auto sink = std::make_shared<DataValueSink>();
  const auto item = fixture.create_monitored_item(subscriptionId, /*clientHandle=*/1, sink);
  ASSERT_TRUE(item.is_good()) << to_string(item.status_code());

  // Empty monitoredItemIds -> Bad_NothingToDo.
  {
    ua::SetMonitoringModeRequest request;
    request.subscription_id() = subscriptionId;
    request.monitoring_mode() = ua::MonitoringMode::Reporting;
    const auto response = send_set_monitoring_mode(fixture, std::move(request));
    EXPECT_EQ(effective_service_status(response), ua::StatusCode{ua::Status::BadNothingToDo})
      << "an empty monitoredItemIds list must be refused at the service level";
  }

  // More ids than the server's published MaxMonitoredItemsPerCall -> Bad_TooManyOperations.
  {
    const auto info = fixture.conn().info();
    ASSERT_NE(info, nullptr);
    const std::uint32_t limit = info->operationLimits.maxMonitoredItemsPerCall;
    ASSERT_GT(limit, 0u) << "the server must publish MaxMonitoredItemsPerCall for the arm to bite";
    ASSERT_LT(limit, 100000u) << "the published limit must be small enough to exceed in one request";

    ua::SetMonitoringModeRequest request;
    request.subscription_id() = subscriptionId;
    request.monitoring_mode() = ua::MonitoringMode::Reporting;
    for (std::uint32_t i = 0; i <= limit; ++i)
    {
      request.monitored_item_ids().push_back(item.value() + 100000U + i);
    }
    ASSERT_EQ(request.monitored_item_ids().size(), static_cast<std::size_t>(limit) + 1U);
    const auto response = send_set_monitoring_mode(fixture, std::move(request));
    EXPECT_EQ(effective_service_status(response), ua::StatusCode{ua::Status::BadTooManyOperations})
      << "a SetMonitoringMode over MaxMonitoredItemsPerCall must be refused whole, at the service level";
  }

  // A subscriptionId the Session does not own -> Bad_SubscriptionIdInvalid.
  {
    ua::SetMonitoringModeRequest request;
    request.subscription_id() = subscriptionId + 9999U;
    request.monitoring_mode() = ua::MonitoringMode::Reporting;
    request.monitored_item_ids().push_back(item.value());
    const auto response = send_set_monitoring_mode(fixture, std::move(request));
    EXPECT_EQ(effective_service_status(response), ua::StatusCode{ua::Status::BadSubscriptionIdInvalid})
      << "an unknown subscriptionId must be refused at the service level";
  }

  // A monitoringMode outside the enumeration -> Bad_MonitoringModeInvalid.
  {
    ua::SetMonitoringModeRequest request;
    request.subscription_id() = subscriptionId;
    request.monitoring_mode() = static_cast<ua::MonitoringMode>(99);
    request.monitored_item_ids().push_back(item.value());
    const auto response = send_set_monitoring_mode(fixture, std::move(request));
    EXPECT_EQ(effective_service_status(response), ua::StatusCode{ua::Status::BadMonitoringModeInvalid})
      << "an out-of-enumeration monitoringMode has its own code - it must not fall through as a generic "
         "argument error";
  }

  EXPECT_EQ(fixture.state(), ConnectionState::Active)
    << "service-level SetMonitoringMode refusals must not fault the Connection";
}

// =============================================================================================
// Part 4 section 5.12.4.4 - SetMonitoringMode has exactly one per-operation code: an item the Subscription no
// longer owns takes Bad_MonitoredItemIdInvalid in its own slot, and the surviving item still TAKES the
// requested mode. A plausible implementation gets this wrong by aborting the whole call on the first unknown
// id (or by refusing it at the service level), which silently leaves the live item on its previous mode. The
// live item's mode change is observed through the effect the spec attaches to it: a Disabled item's queue is
// dropped, so the LATER Disabled->Reporting transition must re-report the current value. Had the mixed call
// left the item Reporting, that re-enable would be a no-op and no further value would arrive.
// @verifies AC-SVR-MI-GEN-103-SETMODE-OPERATION-CODE
TEST_F(ClientMonitoredItem, SetMonitoringModeReportsUnknownItemPerOperation)
{
  MisbehavingServer server;
  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  // No response mutator: the real server samples, queues and reports, so the mode really drives delivery.
  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();

  auto liveSink = std::make_shared<DataValueSink>();
  auto doomedSink = std::make_shared<DataValueSink>();
  const auto liveItem = fixture.create_monitored_item(subscriptionId, /*clientHandle=*/1, liveSink);
  const auto doomedItem = fixture.create_monitored_item(subscriptionId, /*clientHandle=*/2, doomedSink);
  ASSERT_TRUE(liveItem.is_good()) << to_string(liveItem.status_code());
  ASSERT_TRUE(doomedItem.is_good()) << to_string(doomedItem.status_code());
  ASSERT_TRUE(wait_until([&] { return liveSink->size() >= 1; }))
    << "the live item must have reported at least once before its mode is flipped (the re-enable "
       "observation is about the value the client last saw)";

  // The second item genuinely stops existing, so its id is stale on the server, not merely unused.
  const auto deleted = fixture.delete_monitored_item(subscriptionId, doomedItem.value(), /*clientHandle=*/2);
  ASSERT_TRUE(deleted.is_good()) << to_string(deleted.status_code());
  ASSERT_EQ(deleted.value().results().size(), 1u);
  ASSERT_TRUE(deleted.value().results()[0].is_good()) << "the item must really be gone from the Subscription";

  // Mixed call: the live item and the deleted one, in that order.
  ua::SetMonitoringModeRequest disable;
  disable.subscription_id() = subscriptionId;
  disable.monitoring_mode() = ua::MonitoringMode::Disabled;
  disable.monitored_item_ids().push_back(liveItem.value());
  disable.monitored_item_ids().push_back(doomedItem.value());
  const auto response = send_set_monitoring_mode(fixture, std::move(disable));
  ASSERT_TRUE(response.is_good()) << "one unknown item must not turn the call into a service-level refusal: "
                                  << to_string(response.status_code());
  ASSERT_EQ(response.value().response_header().service_result(), ua::StatusCode{ua::Status::Good});
  ASSERT_EQ(response.value().results().size(), 2u) << "one result slot per requested id, positionally "
                                                      "aligned";
  EXPECT_TRUE(response.value().results()[0].is_good())
    << "the live item must accept the mode despite its neighbour's failure";
  EXPECT_EQ(response.value().results()[1], ua::StatusCode{ua::Status::BadMonitoredItemIdInvalid})
    << "the deleted item must fail in its OWN slot";

  // The live item really took Disabled: re-enabling it must re-report the value the client last saw. This is
  // only true of an item that WAS Disabled - a still-Reporting item re-enables to itself and reports nothing.
  std::this_thread::sleep_for(200ms);  // let any Publish already in flight land before the baseline is taken
  const std::size_t baseline = liveSink->size();
  ua::SetMonitoringModeRequest reenable;
  reenable.subscription_id() = subscriptionId;
  reenable.monitoring_mode() = ua::MonitoringMode::Reporting;
  reenable.monitored_item_ids().push_back(liveItem.value());
  const auto reenabled = send_set_monitoring_mode(fixture, std::move(reenable));
  ASSERT_TRUE(reenabled.is_good()) << to_string(reenabled.status_code());
  ASSERT_EQ(reenabled.value().results().size(), 1u);
  ASSERT_TRUE(reenabled.value().results()[0].is_good());

  EXPECT_TRUE(wait_until([&] { return liveSink->size() > baseline; }))
    << "the live item's Disabled->Reporting transition must re-report - proving the mixed call really did "
       "apply Disabled to it";
}

// =============================================================================================
// Part 4 section 5.12.3.3 / section 5.12.4.3 - a service-level Bad on Modify, SetMonitoringMode or
// DeleteMonitoredItems fails the WHOLE operation and reaches the caller as a bad operation result carrying an
// ErrorDetail, while an operation-level code fails only its own item and leaves the Subscription's other
// items attached. The op-level code that matters most here is Bad_MonitoredItemFilterUnsupported: an
// application answers it by re-modifying with a simpler filter, which it can only do if the code arrives in
// ONE result slot rather than as a failed call. A plausible implementation gets this wrong by handing the
// caller a GOOD Result whose response header happens to be bad - the caller then has neither a failed call to
// branch on nor any diagnostic context, and the natural `if (result.is_good())` reads a response that never
// happened. Delete's per-item arm is already covered by DeleteDoesNotDisturbSiblings and
// PublishBadPerItemStatusPreservesItem; the Modify and SetMonitoringMode error surface, and the ErrorDetail
// on all three, had no test at all.
// @verifies AC-CL-MI-022-MODIFY-DELETE-ERRORS
TEST_F(ClientMonitoredItem, ModifySetModeAndDeleteErrorsReachTheCallerWithErrorDetail)
{
  MisbehavingServer server;
  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();

  auto sinkA = std::make_shared<DataValueSink>();
  auto sinkB = std::make_shared<DataValueSink>();
  const auto itemA = fixture.create_monitored_item(subscriptionId, /*clientHandle=*/1, sinkA);
  const auto itemB = fixture.create_monitored_item(subscriptionId, /*clientHandle=*/2, sinkB);
  ASSERT_TRUE(itemA.is_good()) << to_string(itemA.status_code());
  ASSERT_TRUE(itemB.is_good()) << to_string(itemB.status_code());
  ASSERT_TRUE(wait_until([&] { return sinkA->size() >= 1 && sinkB->size() >= 1; }))
    << "both items must be reporting before the error paths are driven - otherwise the survival assertions "
       "below would prove nothing";

  // ---- Operation-level: an unsupported filter fails ONE slot and destroys nothing --------------------
  // Slot 0 asks for an AggregateFilter on a Value attribute: a filter the client is ENTITLED to ask for,
  // which this server does not implement. Slot 1 restates a perfectly valid parameter set for the sibling.
  {
    auto unsupportedFilter = std::make_unique<ua::AggregateFilter>();
    unsupportedFilter->processing_interval() = 1000.0;

    ua::ModifyMonitoredItemsRequest request;
    request.subscription_id() = subscriptionId;
    request.timestamps_to_return() = ua::TimestampsToReturn::Both;
    request.items_to_modify().push_back(make_modify_item(itemA.value(), 1, std::move(unsupportedFilter)));
    request.items_to_modify().push_back(make_modify_item(itemB.value(), 2));

    const auto modify = send_modify_monitored_items(fixture, std::move(request));
    ASSERT_TRUE(modify.is_good())
      << "an unsupported filter on ONE item must not fail the whole call - an application cannot fall back "
         "to a simpler filter for that item if the code arrives as a failed operation: "
      << to_string(modify.status_code());
    ASSERT_EQ(modify.value().response_header().service_result(), ua::StatusCode{ua::Status::Good});
    ASSERT_EQ(modify.value().results().size(), 2u) << "one result slot per requested item";
    const auto expectedUnsupported = ua::StatusCode{ua::Status::BadMonitoredItemFilterUnsupported};
    EXPECT_EQ(modify.value().results()[0].status_code(), expectedUnsupported)
      << "the unsupported filter must be reported in ITS OWN slot; slot 0 carried "
      << to_string(modify.value().results()[0].status_code());
    EXPECT_TRUE(modify.value().results()[1].status_code().is_good())
      << "the sibling's slot must stay Good - its neighbour's refusal is not its business; slot 1 carried "
      << to_string(modify.value().results()[1].status_code());
  }

  // Both items must still be OWNED by the Subscription after that refusal: a second Modify naming them with
  // valid parameters answers Bad_MonitoredItemIdInvalid for any item the refusal tore down.
  {
    ua::ModifyMonitoredItemsRequest probe;
    probe.subscription_id() = subscriptionId;
    probe.timestamps_to_return() = ua::TimestampsToReturn::Both;
    probe.items_to_modify().push_back(make_modify_item(itemA.value(), 1));
    probe.items_to_modify().push_back(make_modify_item(itemB.value(), 2));
    const auto reprobe = send_modify_monitored_items(fixture, std::move(probe));
    ASSERT_TRUE(reprobe.is_good()) << to_string(reprobe.status_code());
    ASSERT_EQ(reprobe.value().results().size(), 2u);
    EXPECT_TRUE(reprobe.value().results()[0].status_code().is_good())
      << "the item whose filter was refused must survive the refusal, not be destroyed by it; it answered "
      << to_string(reprobe.value().results()[0].status_code());
    EXPECT_TRUE(reprobe.value().results()[1].status_code().is_good())
      << "the untouched sibling must still be attached; it answered "
      << to_string(reprobe.value().results()[1].status_code());
  }

  // ---- Service level: the whole operation fails, with an ErrorDetail --------------------------------
  const auto expectServiceFailure = [](const auto& result, ua::Status expected, const char* service)
  {
    EXPECT_TRUE(result.is_bad())
      << service << ": a service-level " << to_string(ua::StatusCode{expected})
      << " must fail the whole operation - the caller was handed a good operation result carrying "
      << to_string(result.status_code());
    EXPECT_EQ(result.status_code(), ua::StatusCode{expected})
      << service << ": the exact service-level code must reach the caller";
    const auto detail = result.shared_detail();
    EXPECT_NE(detail, nullptr)
      << service
      << ": every surfaced service-level StatusCode must carry an ErrorDetail - a bare code "
         "leaves the caller nothing to log or branch on";
    if (detail != nullptr)
    {
      EXPECT_FALSE(detail->source.empty())
        << service << ": the ErrorDetail must name the component that produced the failure";
    }
  };

  {
    ua::ModifyMonitoredItemsRequest request;
    request.subscription_id() = subscriptionId + 9999U;
    request.timestamps_to_return() = ua::TimestampsToReturn::Both;
    request.items_to_modify().push_back(make_modify_item(itemA.value(), 1));
    expectServiceFailure(send_modify_monitored_items(fixture, std::move(request)),
      ua::Status::BadSubscriptionIdInvalid,
      "ModifyMonitoredItems");
  }

  {
    ua::SetMonitoringModeRequest request;
    request.subscription_id() = subscriptionId;
    request.monitoring_mode() = static_cast<ua::MonitoringMode>(99);
    request.monitored_item_ids().push_back(itemA.value());
    expectServiceFailure(send_set_monitoring_mode(fixture, std::move(request)),
      ua::Status::BadMonitoringModeInvalid,
      "SetMonitoringMode");
  }

  // itemA's REAL clientHandle is named here deliberately: a client that deregisters the handle without first
  // reading the outcome would tear down a LIVE item on this refusal, and the count below would catch it. An
  // unregistered handle would make that count true by construction and prove nothing.
  expectServiceFailure(
    fixture.delete_monitored_item(subscriptionId + 9999U, itemA.value(), /*clientHandle=*/1U),
    ua::Status::BadSubscriptionIdInvalid,
    "DeleteMonitoredItems");

  EXPECT_EQ(fixture.monitored_item_count(), 2u)
    << "neither a per-item refusal nor a service-level refusal may deregister a live item";
  EXPECT_EQ(fixture.state(), ConnectionState::Active)
    << "surfacing these errors must not fault the Connection";
}

namespace
{

// One EventFilter select clause: @p path under @p typeDefinition, selecting the Value attribute - the shape
// every EventFilter in the SDK's own suites uses.
ua::SimpleAttributeOperand make_select_clause(const ua::NodeId& typeDefinition, std::vector<std::string> path)
{
  ua::SimpleAttributeOperand clause;
  clause.type_definition_id() = typeDefinition;
  for (const auto& segment : path)
  {
    clause.browse_path().push_back(ua::QualifiedName{0, ua::String{segment}});
  }
  clause.attribute_id() = static_cast<std::uint32_t>(ua::AttributeId::Value);
  return clause;
}

// Blocking wrapper over the event-backbone create - the ONLY client path that puts an event MonitoredItem on
// the wire (the tier-1 `Subscription::monitor_event_async` is deferred and completes Bad_NotSupported without
// a request). It forces attributeId = EventNotifier and samplingInterval = 0 at the wire boundary.
ua::Result<ua::client::detail::EventBackboneCreated> create_event_item(
  MisbehavingMonitoredItemFixture& fixture, std::uint32_t subscriptionId, const ua::NodeId& notifier,
  std::uint32_t clientHandle, ua::EventFilter filter, std::uint32_t queueSize)
{
  std::promise<ua::Result<ua::client::detail::EventBackboneCreated>> promise;
  auto future = promise.get_future();
  fixture.conn().create_event_monitored_item_async(subscriptionId,
    notifier,
    clientHandle,
    std::move(filter),
    queueSize,
    [&promise](ua::Result<ua::client::detail::EventBackboneCreated> result)
    { promise.set_value(std::move(result)); });
  return future.get();
}

// Blocking wrapper over `monitor_data_change_async` for a CALLER-CHOSEN node and parameter set (the fixture's
// own `monitor()` is pinned to monitoredNode and exposes neither the queue size nor the discard policy).
MonitoredItemResult monitor_node(MisbehavingMonitoredItemFixture& fixture, std::uint32_t subscriptionId,
  ua::client::MonitorRequest request, const std::shared_ptr<DataValueSink>& sink)
{
  std::promise<MonitoredItemResult> promise;
  auto future = promise.get_future();
  fixture.conn().monitor_data_change_async(
    subscriptionId,
    std::move(request),
    [sink](DataChangeEvent event) { sink->push(std::move(event.value)); },
    [&promise](MonitoredItemResult result) { promise.set_value(std::move(result)); });
  return future.get();
}

// One ModifyMonitoredItems slot that restates the item's identity and re-states ONLY the queue parameters
// under test (Modify replaces the WHOLE parameter set, so the sampling interval has to be repeated).
ua::MonitoredItemModifyRequest make_queue_modify_item(std::uint32_t monitoredItemId,
  std::uint32_t clientHandle, double samplingIntervalMs, std::uint32_t queueSize, bool discardOldest)
{
  ua::MonitoredItemModifyRequest item;
  item.monitored_item_id() = monitoredItemId;
  item.requested_parameters().client_handle() = clientHandle;
  item.requested_parameters().sampling_interval() = samplingIntervalMs;
  item.requested_parameters().queue_size() = queueSize;
  item.requested_parameters().discard_oldest() = discardOldest;
  return item;
}

// The Int32 values delivered to @p sink, in delivery order (a monitored item's queue is delivered in order,
// so this vector IS the surviving queue).
std::vector<std::int32_t> delivered_int32s(const DataValueSink& sink)
{
  std::vector<std::int32_t> values;
  for (const auto& value : sink.snapshot())
  {
    if (value.value().is_int32())
    {
      values.push_back(value.value().as<std::int32_t>());
    }
  }
  return values;
}

// True iff some delivered DataValue carries exactly @p sentinel as a Double.
bool has_double(const DataValueSink& sink, double sentinel)
{
  for (const auto& value : sink.snapshot())
  {
    if (value.value().is_double() && value.value().as<double>() == sentinel)
    {
      return true;
    }
  }
  return false;
}

// Creates a writable Variable of @p dataType under the Objects folder of the server under test and returns
// its accessor, which the caller keeps to drive SERVER-side value changes (the MisbehavingServer's stock
// address space has no user-writable node, so a row about sampling has to build one).
std::optional<ua::VariableAccessor> add_writable_variable(ua::AddressSpace& addressSpace,
  const ua::NodeId& nodeId, std::uint16_t namespaceIndex, const char* name, const ua::NodeId& dataType)
{
  auto node = addressSpace.create_node_sync(nodeId, ua::NodeClass::Variable);
  // Part 3 section 5.5: every Variable sources exactly one HasTypeDefinition - keep the test model
  // conforming.
  node.add_reference_sync(
    ua::NodeId{ua::ReferenceTypeId::HasTypeDefinition}, ua::NodeId{ua::VariableTypeId::BaseDataVariableType});
  auto variable = node.as<ua::VariableAccessor>();
  if (!variable.has_value())
  {
    return std::nullopt;
  }
  variable->set_browse_name(ua::QualifiedName{namespaceIndex, name});
  variable->set_display_name(ua::LocalizedText{"", name});
  variable->set_data_type(dataType);
  variable->set_access_level(
    ua::AccessLevelType{ua::AccessLevelType::Bit::CurrentRead, ua::AccessLevelType::Bit::CurrentWrite});
  addressSpace.find_node_sync(ua::NodeId{ua::ObjectId::ObjectsFolder})
    .add_reference_sync(ua::NodeId{ua::ReferenceTypeId::Organizes}, nodeId);
  return variable;
}

// Thread-safe sink for the tier-2 event consumer (the EventSubscriber fires on its own delivery strand).
class EventNotificationSink
{
public:
  void push(ua::client::EventNotification notification)
  {
    std::lock_guard lock(mMutex);
    mNotifications.push_back(std::move(notification));
  }

  // The first delivered notification carrying @p severity (severity is the per-event tag these rows use to
  // tell one emitted event from another).
  std::optional<ua::client::EventNotification> with_severity(std::uint16_t severity) const
  {
    std::lock_guard lock(mMutex);
    for (const auto& notification : mNotifications)
    {
      if (notification.severity == severity)
      {
        return notification;
      }
    }
    return std::nullopt;
  }

private:
  mutable std::mutex mMutex;
  std::vector<ua::client::EventNotification> mNotifications;
};

}  // namespace

// =============================================================================================
// Part 4 section 5.12.1.2 - "A Client shall define a sampling interval of 0 if it subscribes for Events."
// Events are not sampled, they arrive: a non-zero interval asks the server to poll something that does not
// poll, and the revised value it hands back is meaningless. A plausible implementation gets this wrong by
// building the event CreateMonitoredItems from the same MonitoringParameters helper as a data-change item -
// the caller's interval (or the -1 "default" sentinel) then rides onto the wire because nothing on the event
// path overrides it. The data-change item in this row is the control: it proves the request observer reads
// the caller's stated interval verbatim, so a non-zero interval on the event item would have been visible
// here.
// @verifies AC-CL-MI-013-EVENT-SAMPLING-ZERO
TEST_F(ClientMonitoredItem, EventMonitoredItemsRequestZeroSamplingIntervalOnTheWire)
{
  MisbehavingServer server;
  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  struct WireItem
  {
    std::uint32_t attributeId = 0;
    double samplingInterval = 0.0;
  };

  auto wireItems = std::make_shared<std::vector<WireItem>>();
  auto wireMutex = std::make_shared<std::mutex>();
  server.set_request_observer(
    [wireItems, wireMutex](const ua::Structure& request)
    {
      const auto* create = dynamic_cast<const ua::CreateMonitoredItemsRequest*>(&request);
      if (create == nullptr)
        return;
      std::lock_guard lock(*wireMutex);
      for (std::size_t i = 0; i < create->items_to_create().size(); ++i)
      {
        const auto& item = create->items_to_create()[i];
        wireItems->push_back(WireItem{static_cast<std::uint32_t>(item.item_to_monitor().attribute_id()),
          item.requested_parameters().sampling_interval()});
      }
    });

  const auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());

  // Control: a DATA-CHANGE monitor's caller-stated interval reaches the wire verbatim.
  auto sink = std::make_shared<DataValueSink>();
  const auto dataItem = fixture.monitor(subscription.value(), /*samplingIntervalMs=*/250.0, sink);
  ASSERT_TRUE(dataItem.is_good()) << to_string(dataItem.status_code());

  ua::EventFilter filter;
  filter.select_clauses().push_back(
    make_select_clause(ua::NodeId{ua::ObjectTypeId::BaseEventType}, {"Message"}));
  filter.select_clauses().push_back(
    make_select_clause(ua::NodeId{ua::ObjectTypeId::BaseEventType}, {"Severity"}));
  const auto eventItem = create_event_item(
    fixture, subscription.value(), ua::NodeId{ua::ObjectId::Server}, /*clientHandle=*/9000U, filter, 10U);
  EXPECT_TRUE(eventItem.is_good()) << "the event MonitoredItem must be accepted on the Server Object: "
                                   << to_string(eventItem.status_code());

  std::vector<WireItem> observed;
  {
    std::lock_guard lock(*wireMutex);
    observed = *wireItems;
  }
  ASSERT_FALSE(observed.empty()) << "no CreateMonitoredItems was observed on the wire at all";

  std::size_t eventItemsSeen = 0;
  bool sawRequestedDataInterval = false;
  for (const auto& item : observed)
  {
    if (item.attributeId == static_cast<std::uint32_t>(ua::AttributeId::EventNotifier))
    {
      ++eventItemsSeen;
      EXPECT_EQ(item.samplingInterval, 0.0) << "Part 4 section 5.12.1.2 - an event MonitoredItem's requested "
                                               "samplingInterval on the wire must be 0, "
                                               "whatever the caller asked for";
    }
    else if (item.attributeId == static_cast<std::uint32_t>(ua::AttributeId::Value) &&
             item.samplingInterval == 250.0)
    {
      sawRequestedDataInterval = true;
    }
  }
  ASSERT_GE(eventItemsSeen, 1U)
    << "an event CreateMonitoredItems (attributeId = EventNotifier) must have reached the wire - otherwise "
       "the interval assertion above is vacuous";
  EXPECT_TRUE(sawRequestedDataInterval)
    << "the control data-change item must carry its caller-stated 250 ms on the wire, proving a non-zero "
       "interval on the event item would have been observable";
}

// =============================================================================================
// Part 4 section 7.22.3 / section 7.4.4.5 - every InstanceDeclaration a SimpleAttributeOperand's browsePath
// walks shall be an Object or a Variable, and the check belongs to filter COMPILE time. A plausible
// implementation validates the operand in isolation (browse name non-empty, attributeId in range) and never
// resolves the path's NodeClass; a path through a Method is then accepted, and because a Method has no value
// to select the client learns of the mistake only as a per-Event StatusCode, once per Event, instead of once
// when it built the filter. The first arm is the control: paths through Variables must still be accepted, so
// a blanket rejection cannot masquerade as conformance.
// @verifies AC-SVR-MI-EVT-013-BROWSEPATH-NODECLASS
TEST_F(ClientMonitoredItem, SimpleAttributeOperandBrowsePathTraversesOnlyObjectsAndVariables)
{
  MisbehavingServer server;
  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());

  // Control: BaseEventType/Message is a Variable, and ConditionType/EnabledState/Id walks a Variable to a
  // Variable - both are legal InstanceDeclaration paths.
  ua::EventFilter accepted;
  accepted.select_clauses().push_back(
    make_select_clause(ua::NodeId{ua::ObjectTypeId::BaseEventType}, {"Message"}));
  accepted.select_clauses().push_back(
    make_select_clause(ua::NodeId{ua::ObjectTypeId::ConditionType}, {"EnabledState", "Id"}));
  const auto acceptedItem = create_event_item(
    fixture, subscription.value(), ua::NodeId{ua::ObjectId::Server}, /*clientHandle=*/9100U, accepted, 10U);
  ASSERT_TRUE(acceptedItem.is_good()) << "a browsePath through Objects and Variables must be accepted: "
                                      << to_string(acceptedItem.status_code());
  EXPECT_TRUE(acceptedItem.value().filterDiagnostics.empty())
    << "a legal InstanceDeclaration path must produce no bad selectClauseResult";

  // The obligation: ConditionType's Enable is a METHOD InstanceDeclaration - a path element with no value to
  // select - so the filter must be refused when it is compiled.
  ua::EventFilter refusedFilter;
  refusedFilter.select_clauses().push_back(
    make_select_clause(ua::NodeId{ua::ObjectTypeId::ConditionType}, {"Enable"}));
  const auto refusedItem = create_event_item(fixture,
    subscription.value(),
    ua::NodeId{ua::ObjectId::Server},
    /*clientHandle=*/9101U,
    refusedFilter,
    10U);
  const bool refused = refusedItem.is_bad() || !refusedItem.value().filterDiagnostics.empty();
  EXPECT_TRUE(refused)
    << "Part 4 section 7.22.3 - a SimpleAttributeOperand browsePath through a Method InstanceDeclaration "
       "must be "
       "refused at filter-compile time (either as a bad operation status or as a bad selectClauseResult), "
       "not accepted and then answered per Event with a StatusCode";
}

// =============================================================================================
// Part 4 section 7.22.2 - an AbsoluteDeadband reports only when |last cached value - current value| is
// GREATER than the deadband, the last cached value being the last one pushed to the queue. Each change below
// is measured against the still-cached 0.0, not against its predecessor, so a run of suppressed changes never
// advances the reference point: an implementation that compares against the last SAMPLED value instead
// would let the 4.9 -> 5.0 step through, and one that compares with >= would let the exact-band change
// through.
// @verifies AC-SVR-MI-GEN-042-ABSOLUTEDEADBAND
TEST_F(ClientMonitoredItem, AbsoluteDeadbandSuppressesChangesWithinTheBand)
{
  MisbehavingServer server;
  auto addressSpace = server.server().address_space();
  auto testNamespace =
    ua::default_ns::Namespace::create("urn:test:mi-matrix:deadband", addressSpace.executor());
  const std::uint16_t namespaceIndex = addressSpace.add_namespace_sync(testNamespace);

  // MisbehavingServer engages the Role model (SecurityAdmin to Anonymous), so a namespace that
  // declares no permissions publishes an ENGAGED, EMPTY default and refuses every node it owns. The
  // MonitoredItem is still created - the service-level result is Good - but the sampled read is
  // refused, so what reaches the sink is a bad status where the test is waiting for a value. That
  // reads as "the subscription never delivered" and sends you looking at the delivery path.
  //
  // Granted here rather than in a shared helper because this file also tests DENIALS: the
  // Bad_UserAccessDenied arms below need their namespace left ungranted, and a blanket grant would
  // quietly remove the subject from those.
  grant_namespace_to_test_client(addressSpace, namespaceIndex);

  const ua::NodeId numericId{namespaceIndex, std::uint32_t{5200}};
  auto numeric = add_writable_variable(
    addressSpace, numericId, namespaceIndex, "DeadbandDouble", ua::NodeId{ua::DataTypeId::Double});
  ASSERT_TRUE(numeric.has_value());
  ASSERT_TRUE(numeric->try_write_value_sync(double{0.0}).is_good());

  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  const auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();

  ua::DataChangeFilter deadband;
  deadband.trigger() = ua::DataChangeTrigger::StatusValue;
  deadband.deadband_type() = 1;  // Absolute
  deadband.deadband_value() = 5.0;

  // A queue deep enough to hold every reported sample: with a queue of one a wrongly-reported in-band value
  // could be overwritten before the publish and the suppression assertions would go vacuous.
  auto sink = std::make_shared<DataValueSink>();
  ua::client::MonitorRequest numericRequest;
  numericRequest.nodeId = numericId;
  numericRequest.attribute = ua::AttributeId::Value;
  numericRequest.samplingIntervalMs = 50.0;
  numericRequest.queueSize = 16U;
  numericRequest.filter = deadband;
  const auto numericItem = monitor_node(fixture, subscriptionId, numericRequest, sink);
  ASSERT_TRUE(numericItem.is_good()) << "an AbsoluteDeadband on a Double Variable must be accepted: "
                                     << to_string(numericItem.status_code());
  ASSERT_TRUE(wait_until([&] { return has_double(*sink, 0.0); }))
    << "the mandatory first sample must arrive - it is the cached value the deadband is measured from";

  // 4.9 is inside the band; 5.0 is measured against the STILL-cached 0.0 and is not GREATER than the band;
  // 9.9 is 9.9 from that same cached 0.0 and must report.
  ASSERT_TRUE(numeric->try_write_value_sync(double{4.9}).is_good());
  std::this_thread::sleep_for(300ms);
  ASSERT_TRUE(numeric->try_write_value_sync(double{5.0}).is_good());
  std::this_thread::sleep_for(300ms);
  ASSERT_TRUE(numeric->try_write_value_sync(double{9.9}).is_good());

  ASSERT_TRUE(wait_until([&] { return has_double(*sink, 9.9); }))
    << "a change beyond the deadband must report - without it the suppression assertions below prove nothing";
  EXPECT_FALSE(has_double(*sink, 4.9)) << "a change of 4.9 against a deadband of 5.0 must be suppressed";
  EXPECT_FALSE(has_double(*sink, 5.0)) << "a change of exactly the deadbandValue is not GREATER than the "
                                          "band (Part 4 section 7.22.2 formula) and must "
                                          "be suppressed";
}

// =============================================================================================
// Part 4 section 5.12.3 - when ModifyMonitoredItems shrinks the queueSize, the over-cap notifications are
// dropped under the SAME discardOldest policy that governs runtime overflow: with TRUE the oldest go, with
// FALSE the just-replaced tail goes and the newest sample is kept. A plausible implementation trims the
// excess from whichever end is cheapest for its container - popping the back for discardOldest=FALSE - which
// throws away the LATEST value and leaves a client that chose FALSE to keep its earliest history holding a
// queue whose newest entry is stale. The two items here run the identical stimulus under the two policies, so
// a shrink that ignores the policy shows up as two identical queues.
// @verifies AC-SVR-MI-GEN-099-QUEUE-SHRINK
TEST_F(ClientMonitoredItem, ShrinkingAQueueDiscardsTheExcessUnderTheConfiguredDiscardPolicy)
{
  MisbehavingServer server;
  auto addressSpace = server.server().address_space();
  auto testNamespace =
    ua::default_ns::Namespace::create("urn:test:mi-matrix:queueshrink", addressSpace.executor());
  const std::uint16_t namespaceIndex = addressSpace.add_namespace_sync(testNamespace);
  // See the note on the deadband test: MisbehavingServer engages the Role model, so a namespace that
  // declares nothing refuses every node it owns and the sampled read comes back denied where this test
  // waits for a value. Granted per test, never file-wide - ClientMonitoredItemDeniedRead below needs
  // its namespace left exactly as it is.
  grant_namespace_to_test_client(addressSpace, namespaceIndex);
  const ua::NodeId queueVariableId{namespaceIndex, std::uint32_t{5300}};
  auto variable = add_writable_variable(
    addressSpace, queueVariableId, namespaceIndex, "QueueShrinkInt32", ua::NodeId{ua::DataTypeId::Int32});
  ASSERT_TRUE(variable.has_value());
  ASSERT_TRUE(variable->try_write_value_sync(std::int32_t{0}).is_good());

  // The MonitoredItem handle carries only the clientHandle, and ModifyMonitoredItems addresses an item by its
  // SERVER id - read it off the create responses (observation only; nothing is rewritten).
  auto createdIds = std::make_shared<std::vector<std::uint32_t>>();
  auto createdMutex = std::make_shared<std::mutex>();
  server.set_response_mutator(
    [createdIds, createdMutex](Response& response)
    {
      auto* create = as_create_items(response);
      if (create == nullptr || create->results().empty())
      {
        return;
      }
      std::lock_guard lock(*createdMutex);
      createdIds->push_back(static_cast<std::uint32_t>(create->results()[0].monitored_item_id()));
    });

  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  // A publishing interval long enough that the queues are still UNDRAINED when the shrink lands: the shrink,
  // not a publish, must be what removes the excess.
  const auto subscription = fixture.create_subscription(3000.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();

  auto oldestSink = std::make_shared<DataValueSink>();
  auto newestSink = std::make_shared<DataValueSink>();
  ua::client::MonitorRequest oldestRequest;
  oldestRequest.nodeId = queueVariableId;
  oldestRequest.attribute = ua::AttributeId::Value;
  oldestRequest.samplingIntervalMs = 50.0;
  oldestRequest.queueSize = 8U;
  oldestRequest.discardOldest = true;
  const auto oldestItem = monitor_node(fixture, subscriptionId, oldestRequest, oldestSink);
  ASSERT_TRUE(oldestItem.is_good()) << to_string(oldestItem.status_code());

  ua::client::MonitorRequest newestRequest;
  newestRequest.nodeId = queueVariableId;
  newestRequest.attribute = ua::AttributeId::Value;
  newestRequest.samplingIntervalMs = 50.0;
  newestRequest.queueSize = 8U;
  newestRequest.discardOldest = false;
  const auto newestItem = monitor_node(fixture, subscriptionId, newestRequest, newestSink);
  ASSERT_TRUE(newestItem.is_good()) << to_string(newestItem.status_code());

  std::vector<std::uint32_t> ids;
  {
    std::lock_guard lock(*createdMutex);
    ids = *createdIds;
  }
  ASSERT_EQ(ids.size(), 2U) << "both creates must have reported a server monitored-item id";

  // Fill both queues to exactly eight: the create-time sample (0) plus seven writes, so nothing has
  // overflowed yet and the shrink is the ONLY discard under test.
  for (std::int32_t value = 1; value <= 7; ++value)
  {
    std::this_thread::sleep_for(150ms);
    ASSERT_TRUE(variable->try_write_value_sync(value).is_good());
  }
  std::this_thread::sleep_for(150ms);

  ua::ModifyMonitoredItemsRequest modify;
  modify.subscription_id() = subscriptionId;
  modify.timestamps_to_return() = ua::TimestampsToReturn::Both;
  modify.items_to_modify().push_back(make_queue_modify_item(
    ids[0], oldestItem.value().client_handle(), 50.0, /*queueSize=*/3U, /*discardOldest=*/true));
  modify.items_to_modify().push_back(make_queue_modify_item(
    ids[1], newestItem.value().client_handle(), 50.0, /*queueSize=*/3U, /*discardOldest=*/false));
  const auto modified = send_modify_monitored_items(fixture, std::move(modify));
  ASSERT_TRUE(modified.is_good()) << to_string(modified.status_code());
  ASSERT_EQ(modified.value().results().size(), 2U);
  ASSERT_TRUE(modified.value().results()[0].status_code().is_good())
    << "the discardOldest=TRUE shrink must be accepted";
  ASSERT_TRUE(modified.value().results()[1].status_code().is_good())
    << "the discardOldest=FALSE shrink must be accepted";

  ASSERT_TRUE(wait_until([&] { return oldestSink->size() >= 3 && newestSink->size() >= 3; }, 30000ms))
    << "the Subscription's publish must deliver both trimmed queues";
  std::this_thread::sleep_for(500ms);  // let any further queued notification land before the queues are read

  const auto oldestValues = delivered_int32s(*oldestSink);
  const auto newestValues = delivered_int32s(*newestSink);
  ASSERT_FALSE(oldestValues.empty()) << "the discardOldest=TRUE item delivered no values at all";
  ASSERT_FALSE(newestValues.empty()) << "the discardOldest=FALSE item delivered no values at all";
  EXPECT_EQ(oldestSink->size(), 3U) << "a queue shrunk to three must deliver exactly three notifications";
  EXPECT_EQ(newestSink->size(), 3U) << "a queue shrunk to three must deliver exactly three notifications";
  EXPECT_EQ(oldestValues, (std::vector<std::int32_t>{5, 6, 7}))
    << "with discardOldest=TRUE the shrink drops the OLDEST excess, leaving the newest three";
  EXPECT_EQ(newestValues, (std::vector<std::int32_t>{0, 1, 7}))
    << "with discardOldest=FALSE the shrink drops the just-replaced TAIL, leaving the oldest two plus the "
       "latest value - trimming from the newest end instead throws the latest sample away";
}

// =============================================================================================
// Part 4 section 7.22 - when a single selected field's encoded size would push the Publish response past the
// session's maxResponseMessageSize, that field is replaced with Bad_EncodingLimitsExceeded and the rest of
// the Event is still delivered. A plausible implementation budgets nothing at projection time and simply
// encodes what it selected; the whole response then exceeds the limit and the Event is dropped or the channel
// aborts, so one oversized value silences a subscription that was carrying every other field just fine. The
// small-payload event emitted first is the control: it proves the selected field round-trips, so a
// failure on the oversized event is about the size budget and not about the filter.
// @verifies AC-SVR-MI-EVT-007-ENCODINGLIMITS
TEST_F(ClientMonitoredItem, AnOversizedEventFieldIsReplacedByEncodingLimitsExceeded)
{
  MisbehavingServer server;
  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto connection = fixture.connection();

  ua::EventFilter filter;
  filter.select_clauses().push_back(
    make_select_clause(ua::NodeId{ua::ObjectTypeId::BaseEventType}, {"Message"}));
  filter.select_clauses().push_back(
    make_select_clause(ua::NodeId{ua::ObjectTypeId::BaseEventType}, {"Severity"}));

  auto recorder = std::make_shared<EventNotificationSink>();
  ua::client::EventSubscription eventSubscription;
  eventSubscription.notifier = ua::NodeId{ua::ObjectId::Server};
  eventSubscription.filter = filter;
  eventSubscription.requestDedicatedBackbone = true;  // this consumer's filter is the one on the wire
  auto events = connection.events();
  const auto consumer = events.try_subscribe_sync(eventSubscription,
    [recorder](ua::client::EventNotification notification) { recorder->push(std::move(notification)); });
  ASSERT_TRUE(consumer.is_good()) << to_string(consumer.status_code());

  // Control: a small payload on the same select clause is delivered as its value.
  ua::GenericEvent small{ua::NodeId{ua::ObjectTypeId::BaseEventType}};
  small.sourceNode = ua::NodeId{ua::ObjectId::Server};
  small.sourceName = "ClientMonitoredItemMatrix";
  small.message = ua::LocalizedText{"", "in-budget field"};
  small.severity = 100;
  server.server().emit_event(small);

  ASSERT_TRUE(wait_until([&] { return recorder->with_severity(100).has_value(); }))
    << "the control event must be delivered - otherwise the oversized arm below proves nothing";
  const auto controlNotification = recorder->with_severity(100);
  ASSERT_TRUE(controlNotification.has_value());
  const auto controlField = controlNotification->field("Message");
  ASSERT_TRUE(controlField.has_value()) << "the selected field must be delivered on the control event";
  EXPECT_TRUE(controlField->is_localized_text())
    << "an in-budget field is delivered as its VALUE, so the substitution below is a real substitution";

  // The obligation: a field whose value alone exceeds the negotiated 16 MiB message size.
  ua::GenericEvent oversized{ua::NodeId{ua::ObjectTypeId::BaseEventType}};
  oversized.sourceNode = ua::NodeId{ua::ObjectId::Server};
  oversized.sourceName = "ClientMonitoredItemMatrix";
  oversized.message = ua::LocalizedText{"", std::string(17U * 1024U * 1024U, 'Z')};
  oversized.severity = 200;
  server.server().emit_event(oversized);

  ASSERT_TRUE(wait_until([&] { return recorder->with_severity(200).has_value(); }, 30000ms))
    << "Part 4 section 7.22 - the Event must still be delivered; dropping it loses more than the oversized "
       "field "
       "does";
  const auto notification = recorder->with_severity(200);
  ASSERT_TRUE(notification.has_value());
  const auto severityField = notification->field("Severity");
  ASSERT_TRUE(severityField.has_value()) << "the Event's other selected fields must still be delivered";
  EXPECT_TRUE(severityField->is_uint16())
    << "the in-budget fields keep their VALUES - only the oversized one is substituted";
  const auto messageField = notification->field("Message");
  ASSERT_TRUE(messageField.has_value())
    << "the oversized field's slot must still be present in the field list";
  ASSERT_TRUE(messageField->is_status_code())
    << "an oversized field carries a StatusCode in place of its value, not the value itself";
  EXPECT_EQ(messageField->as<ua::StatusCode>(), ua::StatusCode{ua::Status::BadEncodingLimitsExceeded})
    << "Part 4 section 7.22 - a field exceeding maxResponseMessageSize is replaced by "
       "Bad_EncodingLimitsExceeded";
}

namespace
{

// A SimpleAttributeOperand whose browsePath segments are named in @p namespaceIndex. The file's own
// `make_select_clause` is pinned to namespace 0 and so cannot name an InstanceDeclaration that a test builds
// in its own namespace.
ua::SimpleAttributeOperand make_ns_select_clause(
  const ua::NodeId& typeDefinition, std::uint16_t namespaceIndex, std::vector<std::string> path)
{
  ua::SimpleAttributeOperand clause;
  clause.type_definition_id() = typeDefinition;
  for (const auto& segment : path)
  {
    clause.browse_path().push_back(ua::QualifiedName{namespaceIndex, ua::String{segment}});
  }
  clause.attribute_id() = static_cast<std::uint32_t>(ua::AttributeId::Value);
  return clause;
}

// Creates @p nodeId with @p nodeClass, names it in @p namespaceIndex and hangs it off @p parent under
// @p referenceType - the minimum shape that makes a node READ as an InstanceDeclaration of @p parent, so a
// filter compiler that resolves a browsePath against the address space finds it and sees its NodeClass.
void add_instance_declaration(ua::AddressSpace& addressSpace, const ua::NodeId& parent,
  const ua::NodeId& referenceType, const ua::NodeId& nodeId, ua::NodeClass nodeClass,
  std::uint16_t namespaceIndex, std::string_view name, const ua::NodeId& typeDefinition = ua::NodeId{})
{
  auto node = addressSpace.create_node_sync(nodeId, nodeClass);
  node.set_browse_name(ua::QualifiedName{namespaceIndex, name});
  node.set_display_name(ua::LocalizedText{"", name});
  if (!typeDefinition.is_null())
  {
    node.add_reference_sync(ua::NodeId{ua::ReferenceTypeId::HasTypeDefinition}, typeDefinition);
  }
  addressSpace.find_node_sync(parent).add_reference_sync(referenceType, nodeId);
  if (referenceType == ua::NodeId{ua::ReferenceTypeId::HasSubtype})
  {
    node.add_reference_sync(referenceType, parent, false);
  }
}

}  // namespace

// =============================================================================================
// Part 4 section 7.4.4.5 / section 7.22.3 - a SimpleAttributeOperand's browsePath walks the type's
// InstanceDeclarations, and EVERY element it walks shall be an Object or a Variable: an ObjectType, a
// VariableType or a Method InstanceDeclaration is an invalid path element and the filter must be refused when
// it is COMPILED. A plausible implementation validates the operand syntactically - browse names non-empty,
// attributeId in range - and never resolves the path against the address space at all; every NodeClass then
// passes, including the type nodes this row drives, and the client learns of the mistake (if ever) as a
// per-Event StatusCode instead of at the moment it built the filter. The already-checked-in Method row covers
// the TERMINAL Method element; this row covers the type-node elements the obligation also names, plus a
// Method walked as an INTERMEDIATE element. The first arm is the control: a Variable InstanceDeclaration of
// the very same custom type, named in the very same namespace, must still be accepted - so a compiler that
// simply cannot resolve the custom type cannot masquerade as one that enforces the NodeClass rule.
// @relation(AC-SVR-MI-EVT-013-BROWSEPATH-NODECLASS, scope=function)
TEST_F(ClientMonitoredItem, SimpleAttributeOperandBrowsePathIsRefusedThroughANonInstanceNodeClass)
{
  MisbehavingServer server;
  auto addressSpace = server.server().address_space();
  auto testNamespace =
    ua::default_ns::Namespace::create("urn:test:mi-matrix:evt-path-nodeclass", addressSpace.executor());
  const std::uint16_t namespaceIndex = addressSpace.add_namespace_sync(testNamespace);

  const ua::NodeId eventTypeId{namespaceIndex, std::uint32_t{5400}};
  const ua::NodeId legalFieldId{namespaceIndex, std::uint32_t{5401}};
  const ua::NodeId nestedObjectTypeId{namespaceIndex, std::uint32_t{5402}};
  const ua::NodeId nestedVariableTypeId{namespaceIndex, std::uint32_t{5403}};
  const ua::NodeId nestedMethodId{namespaceIndex, std::uint32_t{5404}};
  const ua::NodeId beyondMethodId{namespaceIndex, std::uint32_t{5405}};

  // A real subtype of BaseEventType, so a compiler that DOES resolve typeDefinitionId finds the type and can
  // walk its InstanceDeclarations.
  add_instance_declaration(addressSpace,
    ua::NodeId{ua::ObjectTypeId::BaseEventType},
    ua::NodeId{ua::ReferenceTypeId::HasSubtype},
    eventTypeId,
    ua::NodeClass::ObjectType,
    namespaceIndex,
    "PathNodeClassEventType");

  // The control's InstanceDeclaration: a Variable, which the rule explicitly allows.
  add_instance_declaration(addressSpace,
    eventTypeId,
    ua::NodeId{ua::ReferenceTypeId::HasProperty},
    legalFieldId,
    ua::NodeClass::Variable,
    namespaceIndex,
    "LegalField",
    ua::NodeId{ua::VariableTypeId::PropertyType});

  // The invalid InstanceDeclarations, one per NodeClass the obligation names.
  add_instance_declaration(addressSpace,
    eventTypeId,
    ua::NodeId{ua::ReferenceTypeId::HasComponent},
    nestedObjectTypeId,
    ua::NodeClass::ObjectType,
    namespaceIndex,
    "NestedObjectType");
  add_instance_declaration(addressSpace,
    eventTypeId,
    ua::NodeId{ua::ReferenceTypeId::HasComponent},
    nestedVariableTypeId,
    ua::NodeClass::VariableType,
    namespaceIndex,
    "NestedVariableType");
  add_instance_declaration(addressSpace,
    eventTypeId,
    ua::NodeId{ua::ReferenceTypeId::HasComponent},
    nestedMethodId,
    ua::NodeClass::Method,
    namespaceIndex,
    "Act");
  // A Variable BEYOND the Method, so {"Act", "Beyond"} walks the Method as an INTERMEDIATE element and ends
  // on a perfectly legal terminal - the offence is the element in the middle, nothing else.
  add_instance_declaration(addressSpace,
    nestedMethodId,
    ua::NodeId{ua::ReferenceTypeId::HasProperty},
    beyondMethodId,
    ua::NodeClass::Variable,
    namespaceIndex,
    "Beyond",
    ua::NodeId{ua::VariableTypeId::PropertyType});

  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  const auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());

  // Control: the Variable InstanceDeclaration of the same custom type, in the same namespace, is accepted.
  ua::EventFilter accepted;
  accepted.select_clauses().push_back(make_ns_select_clause(eventTypeId, namespaceIndex, {"LegalField"}));
  const auto acceptedItem = create_event_item(
    fixture, subscription.value(), ua::NodeId{ua::ObjectId::Server}, /*clientHandle=*/9200U, accepted, 10U);
  ASSERT_TRUE(acceptedItem.is_good())
    << "a browsePath through a Variable InstanceDeclaration of a custom event type must be accepted: "
    << to_string(acceptedItem.status_code());
  ASSERT_TRUE(acceptedItem.value().filterDiagnostics.empty())
    << "the control clause must compile clean - otherwise the refusals below could be an unresolvable custom "
       "type rather than the NodeClass rule";

  struct NodeClassArm
  {
    const char* what;
    std::vector<std::string> path;
  };

  const std::vector<NodeClassArm> arms{
    NodeClassArm{"an ObjectType InstanceDeclaration", {"NestedObjectType"}},
    NodeClassArm{"a VariableType InstanceDeclaration", {"NestedVariableType"}},
    NodeClassArm{"a Method InstanceDeclaration walked as an intermediate element", {"Act", "Beyond"}}};
  ASSERT_FALSE(arms.empty());

  std::uint32_t clientHandle = 9201U;
  for (const auto& arm : arms)
  {
    ua::EventFilter refusedFilter;
    refusedFilter.select_clauses().push_back(make_ns_select_clause(eventTypeId, namespaceIndex, arm.path));
    const auto refusedItem = create_event_item(
      fixture, subscription.value(), ua::NodeId{ua::ObjectId::Server}, clientHandle++, refusedFilter, 10U);
    const bool refused = refusedItem.is_bad() || !refusedItem.value().filterDiagnostics.empty();
    EXPECT_TRUE(refused)
      << "Part 4 section 7.4.4.5 - a SimpleAttributeOperand browsePath through " << arm.what
      << " must be refused at filter-compile time (either as a bad operation status or as a bad "
         "selectClauseResult), not accepted and answered per Event with a StatusCode";
  }

  EXPECT_EQ(fixture.state(), ConnectionState::Active)
    << "a refused select clause must not fault the Connection";
}

namespace
{

// Blocking SetTriggering over the tier-1 orchestrator. The fixture exposes no accessor for it, and the
// managed `set_triggering_by_handles_async` facade cannot express the malformed requests these arms need
// (an unknown subscriptionId, an unknown triggering item, an over-limit link list).
Result<ua::SetTriggeringResponse> send_set_triggering(
  MisbehavingMonitoredItemFixture& fixture, ua::SetTriggeringRequest request)
{
  std::promise<Result<ua::SetTriggeringResponse>> promise;
  auto future = promise.get_future();
  fixture.conn().set_triggering_async(std::move(request),
    [&promise](Result<ua::SetTriggeringResponse> result) { promise.set_value(std::move(result)); });
  return future.get();
}

// Blocking ModifySubscription (publishing interval only).
Result<ua::ModifySubscriptionResponse> send_modify_subscription(
  MisbehavingMonitoredItemFixture& fixture, std::uint32_t subscriptionId, double publishingIntervalMs)
{
  std::promise<Result<ua::ModifySubscriptionResponse>> promise;
  auto future = promise.get_future();
  fixture.conn().modify_subscription_async(subscriptionId,
    publishingIntervalMs,
    [&promise](Result<ua::ModifySubscriptionResponse> result) { promise.set_value(std::move(result)); });
  return future.get();
}

// How many DISTINCT Int32 values at or above @p floorValue reached @p sink. The burst rows below tag their
// post-stimulus writes with a value floor so a delivery count is attributable to the burst alone.
std::size_t distinct_int32s_at_or_above(const DataValueSink& sink, std::int32_t floorValue)
{
  std::vector<std::int32_t> seen;
  for (const auto& value : sink.snapshot())
  {
    if (!value.value().is_int32())
      continue;
    const auto raw = value.value().as<std::int32_t>();
    if (raw < floorValue)
      continue;
    if (std::find(seen.begin(), seen.end(), raw) == seen.end())
      seen.push_back(raw);
  }
  return seen.size();
}

// ---- Orchestrator-level helpers for the fixture below, which owns a bare ConnectionImpl -------------
// (the helpers earlier in this file are bound to MisbehavingMonitoredItemFixture).

Result<std::uint32_t> create_subscription_on(ConnectionImpl& connection, double publishingIntervalMs)
{
  std::promise<Result<std::uint32_t>> promise;
  auto future = promise.get_future();
  connection.create_subscription_async(
    publishingIntervalMs, [&promise](Result<std::uint32_t> result) { promise.set_value(std::move(result)); });
  return future.get();
}

MonitoredItemResult monitor_node_on(ConnectionImpl& connection, std::uint32_t subscriptionId,
  ua::client::MonitorRequest request, const std::shared_ptr<DataValueSink>& sink)
{
  std::promise<MonitoredItemResult> promise;
  auto future = promise.get_future();
  connection.monitor_data_change_async(
    subscriptionId,
    std::move(request),
    [sink](DataChangeEvent event) { sink->push(std::move(event.value)); },
    [&promise](MonitoredItemResult result) { promise.set_value(std::move(result)); });
  return future.get();
}

// A one-item Read of @p nodeId's Value attribute. Used ONLY as the non-vacuity guard on Namespace policy
// fixture: it proves the denial is actually armed on the Node before a row asserts anything about it.
Result<ua::ReadResponse> read_value_over_the_wire(ConnectionImpl& connection, const ua::NodeId& nodeId)
{
  ua::ReadRequest request;
  request.max_age() = 0.0;
  request.timestamps_to_return() = ua::TimestampsToReturn::Both;
  ua::ReadValueId item;
  item.node_id() = nodeId;
  item.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::Value);
  request.nodes_to_read().push_back(std::move(item));

  std::promise<Result<ua::ReadResponse>> promise;
  auto future = promise.get_future();
  connection.read_async(std::move(request),
    [&promise](Result<ua::ReadResponse> result) { promise.set_value(std::move(result)); });
  return future.get();
}

}  // namespace

// =============================================================================================
// Part 4 section 5.12.1 / section 5.12.2.1 - "Illegal request values for parameters that can be revised do
// not generate errors. Instead the Server will choose default values and indicate them in the corresponding
// revised parameter." Both revisable parameters are driven at once, each with a value the server cannot
// honour: a samplingInterval of -1000 ms and a queueSize of 2^32-1.
//
// Read to the specification, not to the criterion's title: Part 4 section 5.12.1.2 makes a NEGATIVE
// samplingInterval a legal REQUEST ("A negative number indicates that the default sampling interval defined
// by the publishing interval of the Subscription is requested"), so the obligation asserted here is that the
// negative value is never echoed back and never refused - it is replaced by a usable (non-negative) rate and
// reported. The queueSize is the unambiguously out-of-range half: it must come back clamped below what was
// asked for.
//
// A plausible implementation gets this wrong by validating the requested parameters the way it validates the
// non-revisable ones - returning Bad_InvalidArgument / Bad_OutOfRange for the negative interval - which
// rejects a request the specification says to accept and correct, and leaves the Client with no way to
// discover the acceptable value. The other failure is subtler: echoing the request back into the revised
// field, so the Client believes it got what it asked for.
//
// The request observer is the non-vacuity guard: it proves the illegal values really reached the server's
// CreateMonitoredItems, so the revised values below are the SERVER's correction and not a client-side clamp.
// @verifies AC-SVR-MI-GEN-094-REVISABLE-NO-ERROR
TEST_F(ClientMonitoredItem, IllegalRevisableParametersAreRevisedRatherThanRejected)
{
  constexpr double illegalSamplingIntervalMs = -1000.0;
  constexpr std::uint32_t absurdQueueSize = 4294967295U;

  MisbehavingServer server;
  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  struct WireParameters
  {
    double samplingInterval = 0.0;
    std::uint32_t queueSize = 0;
  };

  auto wireParameters = std::make_shared<std::vector<WireParameters>>();
  auto wireMutex = std::make_shared<std::mutex>();
  server.set_request_observer(
    [wireParameters, wireMutex](const ua::Structure& request)
    {
      const auto* create = dynamic_cast<const ua::CreateMonitoredItemsRequest*>(&request);
      if (create == nullptr)
        return;
      std::lock_guard lock(*wireMutex);
      for (std::size_t i = 0; i < create->items_to_create().size(); ++i)
      {
        const auto& parameters = create->items_to_create()[i].requested_parameters();
        wireParameters->push_back(WireParameters{parameters.sampling_interval(), parameters.queue_size()});
      }
    });

  const auto subscription = fixture.create_subscription(200.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());

  auto sink = std::make_shared<DataValueSink>();
  ua::client::MonitorRequest request;
  request.nodeId = monitoredNode;
  request.attribute = ua::AttributeId::Value;
  request.samplingIntervalMs = illegalSamplingIntervalMs;
  request.queueSize = absurdQueueSize;
  const auto item = monitor_node(fixture, subscription.value(), request, sink);

  // Non-vacuity: the illegal values must have reached the SERVER, or nothing below is about the server.
  std::vector<WireParameters> observed;
  {
    std::lock_guard lock(*wireMutex);
    observed = *wireParameters;
  }
  GTEST_LOG_(INFO) << "CreateMonitoredItems items observed on the wire: " << observed.size();
  ASSERT_EQ(observed.size(), 1U) << "exactly one CreateMonitoredItems item must have reached the server";
  ASSERT_DOUBLE_EQ(observed.front().samplingInterval, illegalSamplingIntervalMs)
    << "the negative samplingInterval must have travelled verbatim - a client-side clamp would make the "
       "revision assertions below vacuous";
  ASSERT_EQ(observed.front().queueSize, absurdQueueSize)
    << "the absurd queueSize must have travelled verbatim";

  ASSERT_TRUE(item.is_good()) << "Part 4 section 5.12.1 - an illegal value for a REVISABLE parameter must "
                                 "not generate an error; the create "
                                 "answered "
                              << to_string(item.status_code());

  const double revisedInterval = item.value().revised_sampling_interval();
  const std::uint32_t revisedQueueSize = item.value().revised_queue_size();
  GTEST_LOG_(INFO) << "revisedSamplingInterval=" << revisedInterval
                   << " revisedQueueSize=" << revisedQueueSize;

  EXPECT_FALSE(std::isnan(revisedInterval)) << "the revised sampling interval must be a real rate";
  EXPECT_GE(revisedInterval, 0.0)
    << "Part 4 section 5.12.1.2 - a negative requested interval asks for the Subscription's publishing "
       "interval; "
       "the server must report the rate it CHOSE, not echo the illegal request back";
  EXPECT_GE(revisedQueueSize, 1U) << "a revised queue size below one is not a usable queue";
  EXPECT_LT(revisedQueueSize, absurdQueueSize)
    << "an out-of-range queueSize must be replaced by the server's supported maximum and reported in the "
       "revised field - echoing 2^32-1 back tells the Client it got a queue the server cannot hold";

  // The item is genuinely live: the mandatory first sample arrives. Without this a server could satisfy
  // every assertion above by returning a Good result for an item it never actually created.
  EXPECT_TRUE(wait_until([&] { return sink->size() >= 1; }))
    << "the revised item must really have been created - its first Notification must arrive";
}

// =============================================================================================
// Part 4 section 5.12.5.3 (Table 79) - SetTriggering carries four service-level result codes, each on its own
// condition: Bad_NothingToDo (neither linksToAdd nor linksToRemove has anything in it), Bad_TooManyOperations
// (the SUM of linksToAdd and linksToRemove exceeds MaxMonitoredItemsPerCall - Part 5 section 6.3.28 names
// SetTriggering explicitly in that Property's definition), Bad_SubscriptionIdInvalid (a subscriptionId the
// Session does not own) and Bad_MonitoredItemIdInvalid (a triggeringItemId the Subscription does not own).
// The last of those sits at SERVICE level because the triggering item is a parameter of the request rather
// than one of its operations; the same code at OPERATION level belongs to the items being LINKED.
//
// A plausible implementation gets this wrong by treating SetTriggering as a bookkeeping call that cannot
// cost anything: it validates the subscription and the triggering item (both are needed to do the work at
// all) and never bounds the link arrays, because linking does not create items and so "feels" free - yet a
// single call can then ask the server to walk an unbounded id list. Each arm is driven separately so a
// missing check is attributed to its own condition.
// @verifies AC-SVR-MI-GEN-105-SETTRIGGERING-SERVICE-CODES
TEST_F(ClientMonitoredItem, SetTriggeringReportsEachServiceLevelConditionOnItsOwnCondition)
{
  MisbehavingServer server;
  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();

  auto triggerSink = std::make_shared<DataValueSink>();
  auto linkedSink = std::make_shared<DataValueSink>();
  const auto triggerItem = fixture.create_monitored_item(subscriptionId, /*clientHandle=*/1, triggerSink);
  const auto linkedItem = fixture.create_monitored_item(subscriptionId, /*clientHandle=*/2, linkedSink);
  ASSERT_TRUE(triggerItem.is_good()) << to_string(triggerItem.status_code());
  ASSERT_TRUE(linkedItem.is_good()) << to_string(linkedItem.status_code());
  ASSERT_TRUE(wait_until([&] { return fixture.monitored_item_count() == 2; }))
    << "both real items must be attached before the malformed SetTriggering calls are driven - otherwise a "
       "Bad_MonitoredItemIdInvalid could be about the wrong item";

  // Neither list carries anything -> Bad_NothingToDo. The subscription and the triggering item are BOTH
  // valid here, so nothing else can produce the refusal.
  {
    ua::SetTriggeringRequest request;
    request.subscription_id() = subscriptionId;
    request.triggering_item_id() = triggerItem.value();
    const auto response = send_set_triggering(fixture, std::move(request));
    EXPECT_EQ(effective_service_status(response), ua::StatusCode{ua::Status::BadNothingToDo})
      << "a SetTriggering with nothing to link and nothing to unlink must be refused at the service level";
  }

  // More links than the server's published MaxMonitoredItemsPerCall -> Bad_TooManyOperations. The limit is
  // read from the server's own OperationLimits, so the arm cannot go vacuous if the configured cap changes.
  {
    const auto info = fixture.conn().info();
    ASSERT_NE(info, nullptr);
    const std::uint32_t limit = info->operationLimits.maxMonitoredItemsPerCall;
    GTEST_LOG_(INFO) << "MaxMonitoredItemsPerCall published by the server: " << limit;
    ASSERT_GT(limit, 0u) << "the server must publish MaxMonitoredItemsPerCall for the arm to bite";
    ASSERT_LT(limit, 100000u) << "the published limit must be small enough to exceed in one request";

    ua::SetTriggeringRequest request;
    request.subscription_id() = subscriptionId;
    request.triggering_item_id() = triggerItem.value();
    // The links name the REAL sibling item, repeatedly: the only thing wrong with this request is its size,
    // so a refusal cannot be attributed to an unknown link target.
    for (std::uint32_t i = 0; i <= limit; ++i)
    {
      request.links_to_add().push_back(linkedItem.value());
    }
    ASSERT_EQ(request.links_to_add().size(), static_cast<std::size_t>(limit) + 1U);
    const auto response = send_set_triggering(fixture, std::move(request));
    EXPECT_EQ(effective_service_status(response), ua::StatusCode{ua::Status::BadTooManyOperations})
      << "Part 5 section 6.3.11 - MaxMonitoredItemsPerCall bounds the SUM of linksToAdd and linksToRemove; a "
         "SetTriggering over that limit must be refused whole, at the service level. The operation limit is "
         "not Create-only.";
  }

  // A subscriptionId the Session does not own -> Bad_SubscriptionIdInvalid.
  {
    ua::SetTriggeringRequest request;
    request.subscription_id() = subscriptionId + 9999U;
    request.triggering_item_id() = triggerItem.value();
    request.links_to_add().push_back(linkedItem.value());
    const auto response = send_set_triggering(fixture, std::move(request));
    EXPECT_EQ(effective_service_status(response), ua::StatusCode{ua::Status::BadSubscriptionIdInvalid})
      << "an unknown subscriptionId must be refused at the service level";
  }

  // A triggeringItemId the Subscription does not own -> Bad_MonitoredItemIdInvalid, at SERVICE level.
  {
    ua::SetTriggeringRequest request;
    request.subscription_id() = subscriptionId;
    request.triggering_item_id() = triggerItem.value() + 100000U;
    request.links_to_add().push_back(linkedItem.value());
    const auto response = send_set_triggering(fixture, std::move(request));
    EXPECT_EQ(effective_service_status(response), ua::StatusCode{ua::Status::BadMonitoredItemIdInvalid})
      << "Part 4 Table 79 - an unknown TRIGGERING item is a service-level refusal (it is a request "
         "parameter, not an operation); collapsing it into a per-link result loses the distinction between "
         "an unknown trigger and an unknown target";
  }

  EXPECT_EQ(fixture.monitored_item_count(), 2u)
    << "a refused SetTriggering must not disturb the Subscription's items";
  EXPECT_EQ(fixture.state(), ConnectionState::Active)
    << "service-level SetTriggering refusals must not fault the Connection";
}

// =============================================================================================
// Part 4 section 5.12.1.2 - a MonitoredItem's sampling interval is "either inherited from the publishing
// interval of the Subscription or ... defined specifically to override that rate", and the assignment is made
// when the item is created: the server returns the assigned interval in revisedSamplingInterval and nothing
// in ModifySubscription touches it. An item created with an EXPLICIT rate therefore keeps that rate when the
// Subscription's publishing interval later changes.
//
// A plausible implementation gets this wrong by storing the requested interval and re-deriving the effective
// one from the Subscription on every publish-interval change - a natural way to keep the "inherit" case
// correct - which silently re-rates every explicitly-configured item on the Subscription. Nothing in the
// protocol tells the Client this happened: the revisedSamplingInterval it was given at create is never
// revised again.
//
// The observable is the item's actual sampling CADENCE, because that is the only thing the protocol exposes
// after the fact. The Subscription's publishing interval is moved from 200 ms to 3000 ms and the monitored
// Variable is then written sixty times at ~50 ms spacing inside a three-second window. An item still sampling
// at its own ~50 ms captures most of those sixty writes; an item re-derived to 3000 ms can capture at most
// one or two of them. The threshold below sits an order of magnitude away from both.
//
// The criterion's second sentence ("Only items that inherited the publishing interval follow it") is a
// permission, not an obligation: section 5.12.1.2 assigns the inherited rate at creation and does not require
// a server to re-derive it later, so asserting that an inheriting item DOES follow would fail a conforming
// server. It is deliberately not asserted here.
// @verifies AC-SVR-MI-GEN-006-INTERVAL-SURVIVES-MODIFY
TEST_F(ClientMonitoredItem, AnExplicitSamplingIntervalSurvivesAChangeToThePublishingInterval)
{
  MisbehavingServer server;
  auto addressSpace = server.server().address_space();
  auto testNamespace =
    ua::default_ns::Namespace::create("urn:test:mi-matrix:intervalsurvives", addressSpace.executor());
  const std::uint16_t namespaceIndex = addressSpace.add_namespace_sync(testNamespace);
  // See the note on the deadband test: MisbehavingServer engages the Role model, so a namespace that
  // declares nothing refuses every node it owns and the sampled read comes back denied where this test
  // waits for a value. Granted per test, never file-wide - ClientMonitoredItemDeniedRead below needs
  // its namespace left exactly as it is.
  grant_namespace_to_test_client(addressSpace, namespaceIndex);

  const ua::NodeId variableId{namespaceIndex, std::uint32_t{5500}};
  auto variable = add_writable_variable(
    addressSpace, variableId, namespaceIndex, "IntervalSurvivesInt32", ua::NodeId{ua::DataTypeId::Int32});
  ASSERT_TRUE(variable.has_value());
  ASSERT_TRUE(variable->try_write_value_sync(std::int32_t{0}).is_good());

  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const auto subscription = fixture.create_subscription(200.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();

  auto sink = std::make_shared<DataValueSink>();
  ua::client::MonitorRequest request;
  request.nodeId = variableId;
  request.attribute = ua::AttributeId::Value;
  request.samplingIntervalMs = 50.0;  // EXPLICIT - this rate is the item's own, not the Subscription's
  request.queueSize = 200U;  // deep enough that a 3 s publish cycle drains the whole burst
  request.discardOldest = true;
  const auto item = monitor_node(fixture, subscriptionId, request, sink);
  ASSERT_TRUE(item.is_good()) << to_string(item.status_code());

  const double revisedAtCreate = item.value().revised_sampling_interval();
  GTEST_LOG_(INFO) << "revisedSamplingInterval assigned at create: " << revisedAtCreate << " ms";
  ASSERT_GT(revisedAtCreate, 0.0)
    << "the server must have assigned a sampling rate at create for the cadence observation to mean anything";
  ASSERT_LE(revisedAtCreate, 200.0)
    << "the item must have been assigned a rate FASTER than the post-modify publishing interval, otherwise "
       "the burst below cannot distinguish a kept rate from a re-derived one";
  ASSERT_TRUE(wait_until([&] { return sink->size() >= 1; }))
    << "the item must be reporting before the publishing interval is changed";

  const auto modified = send_modify_subscription(fixture, subscriptionId, 3000.0);
  ASSERT_TRUE(modified.is_good()) << "the ModifySubscription must succeed: "
                                  << to_string(modified.status_code());
  ASSERT_EQ(modified.value().response_header().service_result(), ua::StatusCode{ua::Status::Good});
  const double revisedPublishingInterval = modified.value().revised_publishing_interval();
  GTEST_LOG_(INFO) << "revisedPublishingInterval after the modify: " << revisedPublishingInterval << " ms";
  ASSERT_GE(revisedPublishingInterval, 2000.0)
    << "the publishing interval must really have moved far above the item's sampling interval; the server "
       "revised it to "
    << revisedPublishingInterval << " ms";

  // The burst: sixty distinct values, tagged at or above 1000 so they are attributable to this window alone.
  constexpr std::int32_t burstFloor = 1000;
  constexpr int burstWrites = 60;
  for (int i = 0; i < burstWrites; ++i)
  {
    ASSERT_TRUE(variable->try_write_value_sync(std::int32_t{burstFloor + i}).is_good());
    std::this_thread::sleep_for(50ms);
  }

  // Two publish cycles at the new interval, plus slack, so the queue is certainly drained.
  ASSERT_TRUE(wait_until([&] { return distinct_int32s_at_or_above(*sink, burstFloor) >= 12U; }, 30000ms))
    << "Part 4 section 5.12.1.2 - an item created with an explicit samplingInterval must keep sampling at "
       "that rate "
       "after ModifySubscription; only "
    << distinct_int32s_at_or_above(*sink, burstFloor) << " of the " << burstWrites
    << " burst values were captured, which is the cadence of an item re-derived to the new "
    << revisedPublishingInterval << " ms publishing interval";

  GTEST_LOG_(INFO) << "distinct burst values delivered: " << distinct_int32s_at_or_above(*sink, burstFloor)
                   << " of " << burstWrites;
  EXPECT_EQ(fixture.state(), ConnectionState::Active);
}

// =============================================================================================
// Part 4 section 5.12.2.1 - "If a NodeId is known to be valid by a Server but the corresponding Node
// Attributes are currently not available, the Server may allow the creation of a MonitoredItem and return an
// appropriate Bad StatusCode in the Publish response." The first Notification is the item's report of its own
// condition; it is not withheld until a usable value turns up.
//
// A plausible implementation gets this wrong by gating the mandatory first Notification on a GOOD read -
// enqueueing the initial sample only when a value came back - because a bad status "isn't data". The item
// then looks identical to a healthy one that simply has not changed yet: the Client waits indefinitely for a
// first Notification that never arrives, with no signal that the source is unreachable, and no service to
// ask.
//
// The subject is a Variable whose stored DataValue carries Bad_NoCommunication: the Node exists and its
// NodeId resolves (so this is not the Bad_NodeIdUnknown path), but its value is unavailable. The recovery arm
// below is the control - once a good value is written the item delivers it, proving the item was live all
// along and that the first delivery was a report rather than an artefact of a broken item.
// @verifies AC-SVR-MI-GEN-061-UNAVAILABLE-FIRST-VALUE
TEST_F(ClientMonitoredItem, AnUnavailableInitialValueIsReportedWithItsStatusRatherThanWithheld)
{
  MisbehavingServer server;
  auto addressSpace = server.server().address_space();
  auto testNamespace =
    ua::default_ns::Namespace::create("urn:test:mi-matrix:unavailable", addressSpace.executor());
  const std::uint16_t namespaceIndex = addressSpace.add_namespace_sync(testNamespace);
  // See the note on the deadband test: MisbehavingServer engages the Role model, so a namespace that
  // declares nothing refuses every node it owns and the sampled read comes back denied where this test
  // waits for a value. Granted per test, never file-wide - ClientMonitoredItemDeniedRead below needs
  // its namespace left exactly as it is.
  grant_namespace_to_test_client(addressSpace, namespaceIndex);

  const ua::NodeId variableId{namespaceIndex, std::uint32_t{5600}};
  auto variable = add_writable_variable(
    addressSpace, variableId, namespaceIndex, "UnavailableInt32", ua::NodeId{ua::DataTypeId::Int32});
  ASSERT_TRUE(variable.has_value());

  // The Node is valid; its VALUE is not available.
  ua::DataValue unavailable;
  unavailable.status() = ua::StatusCode{ua::Status::BadNoCommunication};
  unavailable.source_timestamp() = ua::DateTime::now();
  ASSERT_TRUE(variable->try_write_value_sync(unavailable).is_good())
    << "the test model must be able to hold an unavailable value - without it there is no subject";

  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const auto subscription = fixture.create_subscription(100.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();

  auto sink = std::make_shared<DataValueSink>();
  ua::client::MonitorRequest request;
  request.nodeId = variableId;
  request.attribute = ua::AttributeId::Value;
  request.samplingIntervalMs = 50.0;
  request.queueSize = 16U;
  const auto item = monitor_node(fixture, subscriptionId, request, sink);
  ASSERT_TRUE(item.is_good())
    << "a Node whose value is merely unavailable must still accept a MonitoredItem: "
    << to_string(item.status_code());

  ASSERT_TRUE(wait_until([&] { return sink->size() >= 1; }))
    << "Part 4 section 5.12.2.1 - the first Notification must arrive carrying the status that explains the "
       "unavailability; withholding it makes a broken item indistinguishable from a quiet one";

  const auto first = sink->snapshot().front();
  ASSERT_TRUE(first.status().has_value())
    << "the first Notification must carry a StatusCode - a value-less Notification with no status explains "
       "nothing";
  GTEST_LOG_(INFO) << "first Notification status: " << to_string(*first.status());
  EXPECT_EQ(*first.status(), ua::StatusCode{ua::Status::BadNoCommunication})
    << "the status delivered must be the one explaining WHY the value is unavailable, not a generic bad code";

  // Control: the item is genuinely live. Once a value becomes available it is delivered, which proves the
  // delivery above was a report of the condition rather than the only thing a stuck item could produce.
  ASSERT_TRUE(variable->try_write_value_sync(std::int32_t{7777}).is_good());
  EXPECT_TRUE(wait_until([&] { return sink->has_int32(7777); }))
    << "the item must resume reporting once the value becomes available";
}

// =============================================================================================
// Part 4 section 7.22.3 - "In some cases the same SimpleAttributeOperand.browsePath will apply to multiple
// EventTypes. If the Client specifies the BaseEventType in the SimpleAttributeOperand.typeDefinitionId then
// the Server shall evaluate the SimpleAttributeOperand.browsePath without considering the
// SimpleAttributeOperand.typeDefinitionId."
//
// A plausible implementation gets this wrong by treating typeDefinitionId uniformly - "apply this clause only
// to Events whose type matches" - which is right for every other type and catastrophic for BaseEventType,
// because servers raise CONCRETE subtypes and never BaseEventType itself. Every field selected under the
// base type then projects as null and the Client sees an Event with nothing in it. This is the same trap
// AC-CL-AC-015-OFTYPE-SUBCLASSES records for the OfType operator.
//
// The event raised here is an instance of a custom subtype of BaseEventType, so exact-type matching and
// subtype matching give different answers. Four clauses are selected:
//   BaseEventType + "Message"              - a base field, under the base type: must carry its value;
//   BaseEventType + the SUBTYPE's own field - the discriminating arm: the browsePath does not exist under
//       BaseEventType at all, so it can only resolve if the typeDefinitionId was ignored;
//   the subtype itself + the same field    - the control: it proves the field, the namespace and the select
//       machinery all work for this Event, so a null on the arm above is about the typeDefinitionId alone.
//   an UNRELATED sibling subtype + the same field - the anti-control: Part 4 section 7.7.4.5 Table 133 keeps
//   the
//       type restriction for a typeDefinitionId that is NOT BaseEventType ("this parameter restricts the
//       operand to instances of the TypeDefinitionNode or one of its subtypes"), so this one must project
//       null. Without it a server that ignored typeDefinitionId WHOLESALE would pass the arm above for the
//       wrong reason.
//
// The three custom clauses share one browsePath and differ ONLY in typeDefinitionId, which is exactly what
// makes them a control / obligation / anti-control triple - and also why they cannot be told apart by
// `EventNotification::field(name)` (it matches on the BrowsePath alone). They are located by SLOT instead,
// but NOT by the index they hold in this filter: `EventSubscriberImpl` prepends the eight mandatory
// BaseEventType SelectClauses to every backbone filter and tail-appends each consumer's clauses in order,
// de-duplicating exact repeats (so the "Message" clause here collapses onto the mandatory one). The slots are
// therefore found by scanning `fieldPaths` for the custom BrowseName; the three that match are in the order
// this filter listed them, which the tail-append discipline guarantees.
// @relation(AC-SVR-MI-EVT-002-BASEEVENTTYPE-IGNORED, scope=function)
TEST_F(ClientMonitoredItem, ABaseEventTypeTypeDefinitionIdIsIgnoredWhenSelectingAField)
{
  MisbehavingServer server;
  auto addressSpace = server.server().address_space();
  auto testNamespace =
    ua::default_ns::Namespace::create("urn:test:mi-matrix:basetypeignored", addressSpace.executor());
  const std::uint16_t namespaceIndex = addressSpace.add_namespace_sync(testNamespace);
  // See the note on the deadband test: MisbehavingServer engages the Role model, so a namespace that
  // declares nothing refuses every node it owns and the sampled read comes back denied where this test
  // waits for a value. Granted per test, never file-wide - ClientMonitoredItemDeniedRead below needs
  // its namespace left exactly as it is.
  grant_namespace_to_test_client(addressSpace, namespaceIndex);

  const ua::NodeId raisedTypeId{namespaceIndex, std::uint32_t{5700}};
  const ua::NodeId siblingTypeId{namespaceIndex, std::uint32_t{5701}};
  const ua::NodeId subtypeFieldId{namespaceIndex, std::uint32_t{5702}};

  // Two SIBLING subtypes of BaseEventType. Only the first is ever raised.
  add_instance_declaration(addressSpace,
    ua::NodeId{ua::ObjectTypeId::BaseEventType},
    ua::NodeId{ua::ReferenceTypeId::HasSubtype},
    raisedTypeId,
    ua::NodeClass::ObjectType,
    namespaceIndex,
    "BaseTypeIgnoredEventType");
  add_instance_declaration(addressSpace,
    ua::NodeId{ua::ObjectTypeId::BaseEventType},
    ua::NodeId{ua::ReferenceTypeId::HasSubtype},
    siblingTypeId,
    ua::NodeClass::ObjectType,
    namespaceIndex,
    "UnrelatedSiblingEventType");
  // The field the raised type declares and the base type does not.
  add_instance_declaration(addressSpace,
    raisedTypeId,
    ua::NodeId{ua::ReferenceTypeId::HasProperty},
    subtypeFieldId,
    ua::NodeClass::Variable,
    namespaceIndex,
    "SubtypeOnlyField",
    ua::NodeId{ua::VariableTypeId::PropertyType});

  MisbehavingMonitoredItemFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto connection = fixture.connection();

  ua::EventFilter filter;
  filter.select_clauses().push_back(
    make_select_clause(ua::NodeId{ua::ObjectTypeId::BaseEventType}, {"Message"}));
  filter.select_clauses().push_back(
    make_ns_select_clause(ua::NodeId{ua::ObjectTypeId::BaseEventType}, namespaceIndex, {"SubtypeOnlyField"}));
  filter.select_clauses().push_back(
    make_ns_select_clause(raisedTypeId, namespaceIndex, {"SubtypeOnlyField"}));
  filter.select_clauses().push_back(
    make_ns_select_clause(siblingTypeId, namespaceIndex, {"SubtypeOnlyField"}));

  auto recorder = std::make_shared<EventNotificationSink>();
  ua::client::EventSubscription eventSubscription;
  eventSubscription.notifier = ua::NodeId{ua::ObjectId::Server};
  eventSubscription.filter = filter;
  eventSubscription.requestDedicatedBackbone = true;  // this consumer's filter is the one on the wire
  auto events = connection.events();
  const auto consumer = events.try_subscribe_sync(eventSubscription,
    [recorder](ua::client::EventNotification notification) { recorder->push(std::move(notification)); });
  ASSERT_TRUE(consumer.is_good()) << to_string(consumer.status_code());

  constexpr std::int32_t fieldValue = 4242;
  ua::GenericEvent raised{raisedTypeId};
  raised.sourceNode = ua::NodeId{ua::ObjectId::Server};
  raised.sourceName = "ClientMonitoredItemMatrix";
  raised.message = ua::LocalizedText{"", "base-type-ignored"};
  raised.severity = 610;
  raised.set_field({ua::QualifiedName{namespaceIndex, "SubtypeOnlyField"}}, ua::Variant{fieldValue});
  server.server().emit_event(raised);

  ASSERT_TRUE(wait_until([&] { return recorder->with_severity(610).has_value(); }))
    << "the Event must be delivered at all - otherwise every field assertion below is vacuous";
  const auto notification = recorder->with_severity(610);
  ASSERT_TRUE(notification.has_value());
  ASSERT_EQ(notification->eventTypeId, raisedTypeId)
    << "the delivered Event must be the custom SUBTYPE instance - exact-type matching on BaseEventType is "
       "only distinguishable from subtype matching when the raised type is not BaseEventType itself";
  ASSERT_EQ(notification->fields.size(), notification->fieldPaths.size())
    << "every delivered field slot must carry its BrowsePath metadata, or the slots cannot be identified";

  // Locate the three custom-BrowseName slots. The mandatory prefix means their INDEX is not their position
  // in this test's filter; their relative ORDER is (tail-append discipline, CL-EVT-002).
  std::vector<std::size_t> customSlots;
  for (std::size_t i = 0; i < notification->fieldPaths.size(); ++i)
  {
    const auto& path = notification->fieldPaths[i];
    if (path.size() == 1U && path.front().namespace_index() == namespaceIndex &&
        static_cast<std::string_view>(path.front().name()) == std::string_view{"SubtypeOnlyField"})
    {
      customSlots.push_back(i);
    }
  }
  GTEST_LOG_(INFO) << "delivered field slots: " << notification->fields.size()
                   << ", of which custom-BrowseName slots: " << customSlots.size();
  ASSERT_EQ(customSlots.size(), 3U)
    << "the three clauses that differ ONLY in typeDefinitionId must each have their own field slot - without "
       "all three the control / obligation / anti-control triple is not observable";
  const std::size_t baseTypeSlot = customSlots[0];  // typeDefinitionId = BaseEventType (the obligation)
  const std::size_t subtypeSlot = customSlots[1];  // typeDefinitionId = the raised subtype (the control)
  const std::size_t siblingSlot = customSlots[2];  // typeDefinitionId = an unrelated sibling (anti-control)

  // The control first: if this is null the type, the namespace or the field never resolved, and the
  // obligation arm below could not have been observed either way.
  ASSERT_TRUE(notification->fields[subtypeSlot].has_value())
    << "the control clause (the SUBTYPE's own typeDefinitionId) must select the field";
  ASSERT_TRUE(notification->fields[subtypeSlot]->is_int32())
    << "the control clause must deliver the field's VALUE";
  ASSERT_EQ(notification->fields[subtypeSlot]->as<std::int32_t>(), fieldValue);

  EXPECT_TRUE(notification->field("Message").has_value())
    << "a base field selected under BaseEventType must be delivered for a SUBTYPE instance";

  // The obligation.
  ASSERT_TRUE(notification->fields[baseTypeSlot].has_value())
    << "Part 4 section 7.22.3 - a typeDefinitionId of BaseEventType must be IGNORED, so this browsePath must "
       "be "
       "evaluated against the Event that actually occurred; exact-type matching on BaseEventType selects "
       "nothing, because Servers raise concrete subtypes";
  EXPECT_TRUE(notification->fields[baseTypeSlot]->is_int32())
    << "the field selected under BaseEventType must carry its VALUE, not a substituted status";
  if (notification->fields[baseTypeSlot]->is_int32())
  {
    EXPECT_EQ(notification->fields[baseTypeSlot]->as<std::int32_t>(), fieldValue);
  }

  // The anti-control: the type restriction still applies when the typeDefinitionId is NOT BaseEventType.
  EXPECT_FALSE(notification->fields[siblingSlot].has_value() && notification->fields[siblingSlot]->is_int32())
    << "Part 4 section 7.7.4.5 Table 133 - an operand whose typeDefinitionId is an UNRELATED type must not "
       "apply to "
       "this Event; a server that ignores typeDefinitionId wholesale would satisfy the arm above for the "
       "wrong reason";
}

// =============================================================================================
// Fixture: ClientMonitoredItemDeniedRead - a server whose RolePermissions deny Read on exactly one Node,
// with a bare ConnectionImpl over an anonymous Session on its None
// endpoint. `ComplianceSecured` exposes the security hooks needed to map the anonymous identity to its Role.
//
// The model holds three Variables: the denied scalar, an allowed scalar (the control that proves the harness
// delivers values at all) and an allowed THREE-element array (the subject for an IndexRange that currently
// selects nothing but could later).
// =============================================================================================
class ClientMonitoredItemDeniedRead : public ComplianceSecured
{
protected:
  void configure_components(ua::server::ServerComponents& components) override
  {
    components.roleConfiguration = RoleConfiguration::from_well_known_grants(
      {{WellKnownRole::Anonymous, IdentityCriteriaType::Anonymous}});
  }

  void SetUp() override
  {
    ComplianceSecured::SetUp();

    auto addressSpace = mServer->address_space();
    mTestNamespace =
      ua::default_ns::Namespace::create("urn:test:mi-matrix:deniedread", addressSpace.executor());
    mNamespaceIndex = addressSpace.add_namespace_sync(mTestNamespace);

    const ua::NodeId deniedId{mNamespaceIndex, std::uint32_t{5800}};
    auto deniedVariable = add_writable_variable(
      addressSpace, deniedId, mNamespaceIndex, "DeniedInt32", ua::NodeId{ua::DataTypeId::Int32});
    ASSERT_TRUE(deniedVariable.has_value());
    ASSERT_TRUE(deniedVariable->try_write_value_sync(std::int32_t{111}).is_good());
    RolePermissionType deniedPermissions;
    deniedPermissions.role_id() = NodeId{ObjectId::WellKnownRole_Anonymous};
    deniedPermissions.permissions() = PermissionType{{PermissionType::Bit::Browse}};
    deniedVariable->set_role_permissions(std::vector<RolePermissionType>{deniedPermissions});
    *mDeniedNodeId = deniedId;

    mAllowedNodeId = ua::NodeId{mNamespaceIndex, std::uint32_t{5801}};
    auto allowedVariable = add_writable_variable(
      addressSpace, mAllowedNodeId, mNamespaceIndex, "AllowedInt32", ua::NodeId{ua::DataTypeId::Int32});
    ASSERT_TRUE(allowedVariable.has_value());
    ASSERT_TRUE(allowedVariable->try_write_value_sync(std::int32_t{222}).is_good());
    RolePermissionType readablePermissions;
    readablePermissions.role_id() = NodeId{ObjectId::WellKnownRole_Anonymous};
    readablePermissions.permissions() =
      PermissionType{{PermissionType::Bit::Browse, PermissionType::Bit::Read}};
    allowedVariable->set_role_permissions(std::vector<RolePermissionType>{readablePermissions});

    mArrayNodeId = ua::NodeId{mNamespaceIndex, std::uint32_t{5802}};
    auto arrayVariable = add_writable_variable(
      addressSpace, mArrayNodeId, mNamespaceIndex, "ShortInt32Array", ua::NodeId{ua::DataTypeId::Int32});
    ASSERT_TRUE(arrayVariable.has_value());
    ASSERT_TRUE(
      arrayVariable->try_write_value_sync(ua::DataValue{ua::Variant{ua::Array<std::int32_t>{1, 2, 3}}})
        .is_good());
    arrayVariable->set_role_permissions(std::vector<RolePermissionType>{readablePermissions});

    CoreClient::OpenChannelConfig channelConfig;
    channelConfig.endpointUrl = mEndpointUrl;
    channelConfig.securityMode = MessageSecurityMode::None;
    channelConfig.securityPolicyId = SecurityPolicyId::None;
    channelConfig.timeout = 5000ms;
    auto channel = mClient->core().open_channel_sync(std::move(channelConfig));
    auto session = channel.create_session_sync({.sessionName = "ClientMonitoredItemDeniedRead"});
    session.activate_sync();

    mConnection = ConnectionImpl::create(
      mClientThreadPool.executor(), std::move(session), ua::client::detail::ConnectionConfig{}, Logger{});
    mStartStatus = MisbehavingMonitoredItemFixture::start_and_wait(*mConnection);
  }

  void TearDown() override
  {
    if (mConnection)
    {
      (void)MisbehavingMonitoredItemFixture::close_and_wait(*mConnection);
    }
    mConnection.reset();
    // The namespace owns a SamplingEngine with periodic bucket timers, and closing the Subscription
    // drops its monitored items without unregistering them from the namespace - so a bucket timer is
    // still armed after the DeleteSubscriptions above, and the pool-drain watchdog in
    // ComplianceSecured::TearDown times out on it. Dropping the fixture's reference here lets the
    // last one die with the address space, whose destructor cancels the timer.
    mTestNamespace.reset();
    ComplianceSecured::TearDown();
  }

  ConnectionImpl& conn()
  {
    return *mConnection;
  }

  ua::client::Connection connection()
  {
    return ua::client::detail::ConnectionHandleFactory::make_connection(mConnection);
  }

  std::shared_ptr<ua::NodeId> mDeniedNodeId{std::make_shared<ua::NodeId>()};
  std::shared_ptr<ua::default_ns::Namespace> mTestNamespace;
  std::uint16_t mNamespaceIndex = 0;
  ua::NodeId mAllowedNodeId;
  ua::NodeId mArrayNodeId;
  std::shared_ptr<ConnectionImpl> mConnection;
  VoidResult mStartStatus{};
};

// =============================================================================================
// Part 4 section 5.12.2.1 - "When a user adds a monitored item that the user is denied read access to, the
// add operation for the item SHALL SUCCEED and the bad status Bad_NotReadable or Bad_UserAccessDenied shall
// be returned in the Publish response. ... The same procedure shall be applied for an IndexRange that does
// not deliver data for the current value but could deliver data in the future."
//
// Written to the specification rather than to the criterion's title. The criterion is titled "A monitored
// item on a Node the user cannot read fails at create"; the clause above says the opposite in as many words,
// and the normative sentence governs. Failing the create would be the defect, not the conformance: the
// specification requires the item to exist so that it starts delivering the moment the access rights change,
// which is exactly the case the following sentence ("If the access rights change to read rights, the Server
// shall start sending data") depends on.
//
// A plausible implementation gets this wrong in the intuitive direction - refusing the create with
// Bad_UserAccessDenied, because refusing early is what every other service does with a denied Node - and the
// Client then has no item to be handed data through when its rights change. The second failure mode is the
// mirror image: treating the transient IndexRange case like the permanent one and refusing THAT create too.
//
// The Read below is the non-vacuity guard: it proves the denial is genuinely armed on the Node, so a Good
// first Notification would be a real finding rather than an unconfigured Namespace policy.
// @verifies AC-SVR-MI-GEN-091-CREATE-PERMISSION-AND-PENDING
TEST_F(ClientMonitoredItemDeniedRead, ADeniedNodeAndAPendingIndexRangeBothCreateAndReportPerNotification)
{
  ASSERT_TRUE(mStartStatus.is_good()) << to_string(mStartStatus.status_code());

  // Guard: RolePermissions deny Read on the denied Node and permit it on the allowed one.
  {
    const auto deniedRead = read_value_over_the_wire(conn(), *mDeniedNodeId);
    ASSERT_TRUE(deniedRead.is_good()) << to_string(deniedRead.status_code());
    ASSERT_EQ(deniedRead.value().results().size(), 1U);
    const auto deniedStatus = deniedRead.value().results()[0].status();
    ASSERT_TRUE(deniedStatus.has_value());
    ASSERT_EQ(*deniedStatus, ua::StatusCode{ua::Status::BadUserAccessDenied})
      << "the read denial must be in force before this row asserts anything about it";

    const auto allowedRead = read_value_over_the_wire(conn(), mAllowedNodeId);
    ASSERT_TRUE(allowedRead.is_good()) << to_string(allowedRead.status_code());
    ASSERT_EQ(allowedRead.value().results().size(), 1U);
    const auto allowedStatus = allowedRead.value().results()[0].status();
    ASSERT_TRUE(!allowedStatus.has_value() || allowedStatus->is_good())
      << "the denial must be scoped to ONE Node - a blanket denial would make every arm below trivially true";
  }

  const auto subscription = create_subscription_on(conn(), 100.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value();

  // Control: an allowed Node delivers a VALUE, so the harness really does carry notifications through.
  auto controlSink = std::make_shared<DataValueSink>();
  {
    ua::client::MonitorRequest request;
    request.nodeId = mAllowedNodeId;
    request.attribute = ua::AttributeId::Value;
    request.samplingIntervalMs = 50.0;
    request.queueSize = 8U;
    const auto controlItem = monitor_node_on(conn(), subscriptionId, request, controlSink);
    ASSERT_TRUE(controlItem.is_good()) << to_string(controlItem.status_code());
    ASSERT_TRUE(wait_until([&] { return controlSink->has_int32(222); }))
      << "the control item must deliver its value - otherwise a missing Notification below proves nothing";
  }

  // The permission half.
  auto deniedSink = std::make_shared<DataValueSink>();
  {
    ua::client::MonitorRequest request;
    request.nodeId = *mDeniedNodeId;
    request.attribute = ua::AttributeId::Value;
    request.samplingIntervalMs = 50.0;
    request.queueSize = 8U;
    const auto deniedItem = monitor_node_on(conn(), subscriptionId, request, deniedSink);
    EXPECT_TRUE(deniedItem.is_good()) << "Part 4 section 5.12.2.1 - the add operation for an item the user "
                                         "is denied read access to SHALL SUCCEED; "
                                         "the create answered "
                                      << to_string(deniedItem.status_code());
    if (deniedItem.is_good())
    {
      ASSERT_TRUE(wait_until([&] { return deniedSink->size() >= 1; }))
        << "the denied item must report its condition in the Publish response, not stay silent";
      const auto first = deniedSink->snapshot().front();
      ASSERT_TRUE(first.status().has_value()) << "the denied item's Notification must carry a StatusCode";
      GTEST_LOG_(INFO) << "denied item's first Notification status: " << to_string(*first.status());
      EXPECT_TRUE(*first.status() == ua::StatusCode{ua::Status::BadUserAccessDenied} ||
                  *first.status() == ua::StatusCode{ua::Status::BadNotReadable})
        << "Part 4 section 5.12.2.1 names exactly two acceptable codes here (Bad_NotReadable / "
           "Bad_UserAccessDenied); the item reported "
        << to_string(*first.status());
      EXPECT_FALSE(first.value().is_int32()) << "a denied item must not deliver the value it is denied";
    }
  }

  // The pending half: an IndexRange outside the CURRENT array that a later, longer array could satisfy.
  {
    auto pendingSink = std::make_shared<DataValueSink>();
    ua::client::MonitorRequest request;
    request.nodeId = mArrayNodeId;
    request.attribute = ua::AttributeId::Value;
    request.samplingIntervalMs = 50.0;
    request.queueSize = 8U;
    request.indexRange = std::string{"5:9"};
    const auto pendingItem = monitor_node_on(conn(), subscriptionId, request, pendingSink);
    EXPECT_TRUE(pendingItem.is_good())
      << "Part 4 section 5.12.2.1 - an IndexRange that does not deliver data for the current value but could "
         "in the "
         "future follows the SAME procedure: the create succeeds; it answered "
      << to_string(pendingItem.status_code());
    if (pendingItem.is_good())
    {
      ASSERT_TRUE(wait_until([&] { return pendingSink->size() >= 1; }))
        << "the pending item must report its condition per Notification";
      const auto first = pendingSink->snapshot().front();
      ASSERT_TRUE(first.status().has_value()) << "the pending item's Notification must carry a StatusCode";
      GTEST_LOG_(INFO) << "pending index-range item's first Notification status: "
                       << to_string(*first.status());
      EXPECT_EQ(*first.status(), ua::StatusCode{ua::Status::BadIndexRangeNoData})
        << "Part 4 Table 71 names Bad_IndexRangeNoData for a range with no data in the Publish response";
      EXPECT_NE(*first.status(), ua::StatusCode{ua::Status::BadUserAccessDenied})
        << "pending data is transient and permission is permanent - reporting the two with one code erases "
           "the distinction the specification draws between them";
    }
  }
}
