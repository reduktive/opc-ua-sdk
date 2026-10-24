// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientMonitorByIndex cluster of the client integration-test matrix (the 6 `ClientMonitorByIndex.*`
///        rows, section 7.4).
///
/// These are END-TO-END integration tests of the TIER-1 managed monitored-item surface (client design
/// section 7.4 / section 8.4) reached through the internal `ua::client::detail::ConnectionImpl` orchestrator
/// - the SAME harness the committed ClientMonitoredItem slice uses (a real `Client` bound to a
/// `MisbehavingServer`'s crypto + trusted store over ephemeral TCP, an activated Session wrapped into a
/// started `ConnectionImpl`, the always-on Publish pump auto-running on the pool). The cluster splits into
/// two concerns:
///
///   1. WIRE PLUMBING of `MonitorRequest.indexRange` (EmitsIndexRangeOnWire) - observed through the REQUEST
///      OBSERVER (`MisbehavingServer::set_request_observer`), the decoded outgoing `CreateMonitoredItems`;
///      and
///   2. DELIVERY / PRESERVATION of whatever DataValue the server sends for an indexed item (the five other
///      rows) - driven by injecting notifications via `set_response_mutator` (rewrites each `PublishResponse`
///      before signing) and observed through the per-item DATA SINK (the `DataValue`s actually delivered)
///      plus the pipeline INFO snapshot (`ConnectionImplTestAccess::pipeline_info` - monitoredItemCount, the
///      strand-private demux state that has no public getter).
///
/// Falsifiability: every test encodes the matrix row's `[neg: ...]` falsifier and asserts the EXACT
/// observable - the wire index-range string, the byte-exact subrange value, the un-reshaped array length, the
/// bad-status pass-through with the item still registered. Timing is ALWAYS bounded polling on an observable,
/// never a fixed sleep.
///
/// ============================================================================================================
/// WIRE PLUMBING (see EmitsIndexRangeOnWire) - the create path threads MonitorRequest's five NON-FILTER
/// tuning fields onto the wire, mirroring the modify path (`DataChangeMonitoredItemOwner::mi_modify_async`).
/// Both callers (`monitor_data_change_async`, `create_monitored_item_async`) route through
/// `begin_create_monitored_item` -> `build_create_monitored_items_request`
/// (sdk/implementation/client/ua_connection_impl.cpp), which now carries:
///   - `attribute`          - onto itemToMonitor.attributeId (default AttributeId::Value when the id-only
///                            caller passes none);
///   - `indexRange`         - onto itemToMonitor.indexRange (this row's subject; empty when nullopt);
///   - `samplingIntervalMs` - onto MonitoringParameters.samplingInterval (default 0.0);
///   - `queueSize`          - onto MonitoringParameters.queueSize (default 1);
///   - `monitoringMode`     - onto itemToCreate.monitoringMode (default Reporting).
/// The `filter` (DataChangeFilter / AggregateFilter) is a SEPARATE, still-batched piece (the
/// deadband-filter-wiring + CL-SUB-021 fallback) and is NOT plumbed here - the SAME gap the sibling
/// ClientMonitoredItem cluster flagged for FirstSampleDispatchedUnconditionally. EmitsIndexRangeOnWire
/// asserts the wire index-range equals the requested "0:5" and that the sibling non-filter fields reached the
/// wire verbatim.
///
/// The DELIVERY / PRESERVATION rows are INDEPENDENT of whether the client sent an indexRange: they assert the
/// client correctly DISPATCHES whatever array / subrange / bad-status DataValue the server sends, verbatim,
/// to the callback - and (for the bad-status rows) that a per-sample bad index-range status is a data-quality
/// signal, not an item failure (the item stays registered). Those guarantees hold today and are asserted
/// GREEN.
/// ============================================================================================================

#include "compliance_helpers.h"

#include "misbehaving_server.h"

#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"

#include "ua_application_configuration.h"
#include "ua_array.h"
#include "ua_byte_string.h"
#include "ua_client.h"
#include "ua_client_monitored_item.h"
#include "ua_create_monitored_items_request.h"
#include "ua_data_change_notification.h"
#include "ua_data_value.h"
#include "ua_logger.h"
#include "ua_monitored_item_create_request.h"
#include "ua_monitored_item_notification.h"
#include "ua_monitoring_mode.h"
#include "ua_monitoring_parameters.h"
#include "ua_node_id.h"
#include "ua_notification_message.h"
#include "ua_publish_response.h"
#include "ua_read_value_id.h"
#include "ua_ref_structure.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_string.h"
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

// A standard NS0 Variable that exists on every server, so a MonitoredItem can be created against it. The
// value the client actually observes for the delivery rows rides the response mutator (not the real node),
// so these tests never depend on the server updating this node.
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

  // True iff some delivered DataValue's value is a scalar ByteString equal to @p expected (byte-exact).
  bool has_byte_string(const ua::ByteString& expected) const
  {
    std::lock_guard lock(mMutex);
    for (const auto& value : mValues)
    {
      if (value.value().is_byte_string() && value.value().as<ua::ByteString>() == expected)
      {
        return true;
      }
    }
    return false;
  }

  // True iff some delivered DataValue's value is a scalar String equal to @p expected (byte-exact).
  bool has_string(std::string_view expected) const
  {
    std::lock_guard lock(mMutex);
    for (const auto& value : mValues)
    {
      if (value.value().is_string() &&
          static_cast<std::string_view>(value.value().as<ua::String>()) == expected)
      {
        return true;
      }
    }
    return false;
  }

  // True iff some delivered DataValue carries an Int32 ARRAY whose element count == @p length AND, if
  // non-empty, whose first element == @p firstElement (so a re-shaped/padded array of a different length,
  // or a re-indexed one, fails the match).
  bool has_int32_array(std::size_t length, std::int32_t firstElement) const
  {
    std::lock_guard lock(mMutex);
    for (const auto& value : mValues)
    {
      if (!value.value().is_array_of_int32())
      {
        continue;
      }
      const auto& array = value.value().as<ua::Array<std::int32_t>>();
      if (array.size() != length)
      {
        continue;
      }
      if (length == 0 || array[0] == firstElement)
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

private:
  mutable std::mutex mMutex;
  std::vector<DataValue> mValues;
};

// ---------------------------------------------------------------------------------------------
// Captures the DECODED outgoing CreateMonitoredItems request's first item so EmitsIndexRangeOnWire can assert
// exactly what the client put on the wire (the index-range string + the sibling monitoring parameters the
// systemic finding drops). Populated on a server strand by the request observer; read by the test thread.
// ---------------------------------------------------------------------------------------------
struct CreateItemsCapture
{
  mutable std::mutex mutex;
  bool captured = false;
  std::string indexRange;
  double samplingInterval = -1.0;
  std::uint32_t queueSize = 0;
  ua::MonitoringMode monitoringMode = ua::MonitoringMode::Reporting;
  bool hasFilter = false;
  std::uint32_t attributeId = 0;

  void observe(const ua::Structure& request)
  {
    const auto* create = dynamic_cast<const ua::CreateMonitoredItemsRequest*>(&request);
    if (!create || create->items_to_create().size() == 0)
    {
      return;
    }
    const auto& item = create->items_to_create()[0];
    const auto& params = item.requested_parameters();
    std::lock_guard lock(mutex);
    indexRange = std::string{static_cast<std::string_view>(item.item_to_monitor().index_range())};
    attributeId = item.item_to_monitor().attribute_id();
    monitoringMode = item.monitoring_mode();
    samplingInterval = params.sampling_interval();
    queueSize = params.queue_size();
    hasFilter = static_cast<bool>(params.filter());
    captured = true;
  }

  bool is_captured() const
  {
    std::lock_guard lock(mutex);
    return captured;
  }
};

std::shared_ptr<CreateItemsCapture> arm_create_items_capture(MisbehavingServer& server)
{
  auto capture = std::make_shared<CreateItemsCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });
  return capture;
}

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

// ----- Response-mutator building blocks (each edits a PublishResponse in place, before signing) -----

// Forces the PublishResponse's NotificationMessage sequence number (the client expects 1, 2, 3, ... from a
// fresh Subscription), so the pipeline classifies InOrder and dispatches deterministically.
void set_publish_sequence(ua::PublishResponse& publish, std::uint32_t sequenceNumber)
{
  publish.notification_message().sequence_number() = sequenceNumber;
}

// One {clientHandle, value[, status]} entry to place in an injected DataChangeNotification.
struct HandleValue
{
  std::uint32_t clientHandle = 0;
  ua::Variant value;
  std::optional<ua::StatusCode> status;
};

// Replaces the PublishResponse's notification data with a single DataChangeNotification carrying one
// MonitoredItemNotification per entry, IN THE GIVEN ORDER.
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

ua::PublishResponse* as_publish(ua::Response& response)
{
  return dynamic_cast<ua::PublishResponse*>(response.second.get());
}

// Builds an Int32-array Variant of @p length whose elements are firstElement, firstElement+1, ...
ua::Variant make_int32_array(std::size_t length, std::int32_t firstElement)
{
  ua::Array<std::int32_t> array;
  array.reserve(length);
  for (std::size_t i = 0; i < length; ++i)
  {
    array.push_back(firstElement + static_cast<std::int32_t>(i));
  }
  return ua::Variant{std::move(array)};
}

// ---------------------------------------------------------------------------------------------
// MisbehavingMonitorByIndexFixture: the ClientMonitoredItem harness (verbatim shape) plus a `monitor`
// accessor that takes a full MonitorRequest (so a test can set indexRange / sampling / mode / filter) and
// pushes each delivered DataValue into a sink.
// ---------------------------------------------------------------------------------------------
class MisbehavingMonitorByIndexFixture
{
public:
  explicit MisbehavingMonitorByIndexFixture(MisbehavingServer& server)
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
    auto session = channel.create_session_sync({.sessionName = "ClientMonitorByIndexMatrix"});
    session.activate_sync();

    mConnection = ConnectionImpl::create(
      mThreadPool.executor(), std::move(session), ua::client::detail::ConnectionConfig{}, Logger{});
    mStartStatus = start_and_wait(*mConnection);
  }

  ~MisbehavingMonitorByIndexFixture()
  {
    if (mConnection)
    {
      (void)close_and_wait(*mConnection);
    }
    mConnection.reset();
    mClient.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  MisbehavingMonitorByIndexFixture(const MisbehavingMonitorByIndexFixture&) = delete;
  MisbehavingMonitorByIndexFixture& operator=(const MisbehavingMonitorByIndexFixture&) = delete;

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

  // Attaches a data-change monitor described by @p request; each delivered DataValue is pushed into @p sink.
  // Returns the public MonitoredItem handle (whose client_handle() the delivery mutators target).
  MonitoredItemResult monitor(
    std::uint32_t subscriptionId, MonitorRequest request, const std::shared_ptr<DataValueSink>& sink)
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

private:
  boost::asio::thread_pool mThreadPool;
  std::optional<Client> mClient;
  std::shared_ptr<ConnectionImpl> mConnection;
  VoidResult mStartStatus{};
};

// Builds a data-change MonitorRequest on monitoredNode's Value attribute with @p indexRange (if any).
MonitorRequest index_request(std::optional<std::string> indexRange)
{
  MonitorRequest request;
  request.nodeId = monitoredNode;
  request.attribute = ua::AttributeId::Value;
  request.indexRange = std::move(indexRange);
  return request;
}

}  // namespace

class ClientMonitorByIndex : public ::testing::Test
{};

// =============================================================================================
// Row - EmitsIndexRangeOnWire  (MisbehavingServer)
// Send a MonitorRequest with indexRange="0:5" plus a non-default attribute / sampling / queueSize / mode;
// capture the outgoing CreateMonitoredItems and assert every one of those NON-FILTER fields reached the wire
// verbatim. [neg: NumericRange plumbed verbatim]
//
// The create path threads MonitorRequest's five non-filter tuning fields (attribute, indexRange,
// samplingIntervalMs, queueSize, monitoringMode) through begin_create_monitored_item ->
// build_create_monitored_items_request onto the itemToMonitor / MonitoringParameters, mirroring the modify
// path (mi_modify_async). The DataChangeFilter is a separate, still-batched piece (the deadband-filter-wiring
// + CL-SUB-021 fallback) and is deliberately NOT asserted here.
// =============================================================================================
// @verifies AC-CL-MI-009-INDEXRANGE-VERBATIM
// @relation(AC-CL-MI-009-INDEXRANGE-VERBATIM, scope=function)
TEST_F(ClientMonitorByIndex, EmitsIndexRangeOnWire)
{
  MisbehavingServer server;
  MisbehavingMonitorByIndexFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = arm_create_items_capture(server);

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());

  // A fully-populated, all-non-default MonitorRequest: every non-filter field below must appear on the wire.
  MonitorRequest request = index_request(std::string{"0:5"});
  request.attribute = ua::AttributeId::Value;
  request.samplingIntervalMs = 123.0;
  request.queueSize = 42;
  request.monitoringMode = ua::MonitoringMode::Sampling;

  auto sink = std::make_shared<DataValueSink>();
  const auto item = fixture.monitor(subscription.value(), std::move(request), sink);
  ASSERT_TRUE(item.is_good()) << to_string(item.status_code());

  ASSERT_TRUE(wait_until([&] { return capture->is_captured(); }))
    << "the outgoing CreateMonitoredItems must have been observed on the wire (non-vacuous capture)";

  std::lock_guard lock(capture->mutex);
  // PRIMARY (this row's subject): the requested indexRange="0:5" is plumbed verbatim onto the wire.
  EXPECT_EQ(capture->indexRange, "0:5")
    << "MonitorRequest.indexRange must reach itemToMonitor.indexRange verbatim; got: \""
    << capture->indexRange << "\"";

  // The sibling non-filter tuning fields must ALSO reach the wire verbatim (mirroring the modify path).
  EXPECT_EQ(capture->attributeId, static_cast<std::uint32_t>(ua::AttributeId::Value))
    << "MonitorRequest.attribute must reach itemToMonitor.attributeId";
  EXPECT_EQ(capture->samplingInterval, 123.0)
    << "MonitorRequest.samplingIntervalMs must reach MonitoringParameters.samplingInterval";
  EXPECT_EQ(capture->queueSize, 42u) << "MonitorRequest.queueSize must reach MonitoringParameters.queueSize";
  EXPECT_EQ(capture->monitoringMode, ua::MonitoringMode::Sampling)
    << "MonitorRequest.monitoringMode must reach itemToCreate.monitoringMode";
}

// =============================================================================================
// Row - ByteStringSubrangeAndEmptySliceDelivered  (MisbehavingServer)
// Subscribe to a ByteString with indexRange="0:7"; the server injects an 8-byte slice, then an empty
// ByteString. Both must reach the callback verbatim - the 8-byte value byte-exact and the empty ByteString as
// an empty value with no decode error. [neg: ByteString subrange + empty slice]
// =============================================================================================
// @verifies CL-MI-009
// @relation(CL-MI-009, scope=function)
TEST_F(ClientMonitorByIndex, ByteStringSubrangeAndEmptySliceDelivered)
{
  MisbehavingServer server;
  MisbehavingMonitorByIndexFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  auto sink = std::make_shared<DataValueSink>();
  const auto item = fixture.monitor(subscription.value(), index_request(std::string{"0:7"}), sink);
  ASSERT_TRUE(item.is_good()) << to_string(item.status_code());
  const std::uint32_t handle = item.value().client_handle();

  // Phase 0 = deliver the 8-byte slice; phase 1 = deliver the empty ByteString.
  const ua::ByteString eightBytes{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
  const ua::ByteString emptySlice{};  // present but zero-length (null and empty coincide in this model)
  auto phase = std::make_shared<std::atomic<int>>(0);
  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);
  server.set_response_mutator(
    [phase, sequenceNumber, handle, eightBytes, emptySlice](Response& response)
    {
      auto* publish = as_publish(response);
      if (!publish)
      {
        return;
      }
      set_publish_sequence(*publish, ++(*sequenceNumber));
      const ua::ByteString& slice = phase->load() == 0 ? eightBytes : emptySlice;
      set_data_change(*publish, {HandleValue{handle, ua::Variant{slice}}});
    });

  EXPECT_TRUE(wait_until([&] { return sink->has_byte_string(eightBytes); }))
    << "the 8-byte ByteString slice must be delivered to the callback byte-exact";

  // Switch to the empty slice: it must arrive as an empty ByteString value with no decode error.
  phase->store(1);
  EXPECT_TRUE(wait_until(
    [&]
    {
      for (const auto& value : sink->snapshot())
      {
        if (value.value().is_byte_string() && value.value().as<ua::ByteString>().size() == 0)
        {
          return true;
        }
      }
      return false;
    }))
    << "the empty ByteString slice must be delivered as an empty (zero-length) ByteString value, not dropped";
}

// =============================================================================================
// Row - StringSubrangeAndMultibyteUnicodeDelivered  (MisbehavingServer)
// Subscribe to a String with indexRange="0:4"; the server injects a 5-character slice, then a multi-byte
// UTF-8 string (an em-dash inside the slice). The multi-byte value must round-trip through the codec
// byte-exact - if the codec mis-counted bytes vs characters, it would be corrupted. [neg: String subrange +
// multibyte UTF-8]
// =============================================================================================
// @verifies CL-MI-009
// @relation(CL-MI-009, scope=function)
TEST_F(ClientMonitorByIndex, StringSubrangeAndMultibyteUnicodeDelivered)
{
  MisbehavingServer server;
  MisbehavingMonitorByIndexFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  auto sink = std::make_shared<DataValueSink>();
  const auto item = fixture.monitor(subscription.value(), index_request(std::string{"0:4"}), sink);
  ASSERT_TRUE(item.is_good()) << to_string(item.status_code());
  const std::uint32_t handle = item.value().client_handle();

  const std::string asciiSlice = "Hello";  // 5 ASCII characters == 5 bytes
  const std::string multibyte =
    "A\xE2\x80\x94Z";  // "A", U+2014 EM DASH (3 bytes), "Z" - 5 bytes, 3 characters
  auto phase = std::make_shared<std::atomic<int>>(0);
  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);
  server.set_response_mutator(
    [phase, sequenceNumber, handle, asciiSlice, multibyte](Response& response)
    {
      auto* publish = as_publish(response);
      if (!publish)
      {
        return;
      }
      set_publish_sequence(*publish, ++(*sequenceNumber));
      const std::string& text = phase->load() == 0 ? asciiSlice : multibyte;
      set_data_change(*publish, {HandleValue{handle, ua::Variant{ua::String{text}}}});
    });

  EXPECT_TRUE(wait_until([&] { return sink->has_string(asciiSlice); }))
    << "the 5-character String slice must be delivered to the callback exactly";

  phase->store(1);
  EXPECT_TRUE(wait_until([&] { return sink->has_string(multibyte); }))
    << "the multi-byte UTF-8 String must round-trip through the codec byte-exact (no byte/char miscount)";
}

// =============================================================================================
// Row - EmptyAndReshapedArraysDispatchedAsSent  (MisbehavingServer)
// The server injects, in turn, an empty array, a smaller-than-requested array, and a larger-than-requested
// array for the indexed item. Each must reach the callback exactly as sent (empty stays empty; smaller/larger
// not re-indexed or padded). If the dispatcher re-shaped arrays to match the requested range, the delivered
// length would differ from the wire. [neg: empty/smaller/larger array pass-through]
// =============================================================================================
// @verifies CL-MI-009
// @relation(CL-MI-009, scope=function)
TEST_F(ClientMonitorByIndex, EmptyAndReshapedArraysDispatchedAsSent)
{
  MisbehavingServer server;
  MisbehavingMonitorByIndexFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  auto sink = std::make_shared<DataValueSink>();
  // Requested range "0:9" would be a 10-element slice; the server deliberately sends other lengths.
  const auto item = fixture.monitor(subscription.value(), index_request(std::string{"0:9"}), sink);
  ASSERT_TRUE(item.is_good()) << to_string(item.status_code());
  const std::uint32_t handle = item.value().client_handle();

  // phase 0 = empty array; phase 1 = smaller (3 elements); phase 2 = larger (15 elements).
  const std::int32_t smallerFirst = 1000;
  const std::int32_t largerFirst = 5000;
  auto phase = std::make_shared<std::atomic<int>>(0);
  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);
  server.set_response_mutator(
    [phase, sequenceNumber, handle, smallerFirst, largerFirst](Response& response)
    {
      auto* publish = as_publish(response);
      if (!publish)
      {
        return;
      }
      set_publish_sequence(*publish, ++(*sequenceNumber));
      ua::Variant value;
      switch (phase->load())
      {
      case 0:
        value = make_int32_array(0, 0);
        break;
      case 1:
        value = make_int32_array(3, smallerFirst);
        break;
      default:
        value = make_int32_array(15, largerFirst);
        break;
      }
      set_data_change(*publish, {HandleValue{handle, std::move(value)}});
    });

  EXPECT_TRUE(wait_until([&] { return sink->has_int32_array(0, 0); }))
    << "the empty array must be delivered as a zero-length Int32 array (not padded to the requested range)";

  phase->store(1);
  EXPECT_TRUE(wait_until([&] { return sink->has_int32_array(3, smallerFirst); }))
    << "the smaller-than-requested array must be delivered with its OWN 3-element length (not padded)";

  phase->store(2);
  EXPECT_TRUE(wait_until([&] { return sink->has_int32_array(15, largerFirst); }))
    << "the larger-than-requested array must be delivered with its OWN 15-element length (not truncated)";
}

// =============================================================================================
// Row - PublishBadIndexRangeInvalidPreservesItem  (MisbehavingServer)
// The server injects Publish results[0]=Bad_IndexRangeInvalid. The callback must fire with the bad StatusCode
// and the item must stay registered. If treated as fatal, the item is removed and cannot recover.
// [neg: bad index-range status non-fatal]
// =============================================================================================
// @verifies AC-CL-MI-009-INDEXRANGE-VERBATIM
// @verifies CL-MI-006
// @relation(CL-MI-006, CL-MI-009, scope=function)
TEST_F(ClientMonitorByIndex, PublishBadIndexRangeInvalidPreservesItem)
{
  MisbehavingServer server;
  MisbehavingMonitorByIndexFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  auto sink = std::make_shared<DataValueSink>();
  const auto item = fixture.monitor(subscription.value(), index_request(std::string{"0:5"}), sink);
  ASSERT_TRUE(item.is_good()) << to_string(item.status_code());
  const std::uint32_t handle = item.value().client_handle();
  ASSERT_TRUE(wait_until([&] { return fixture.monitored_item_count() == 1; }));

  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);
  server.set_response_mutator(
    [sequenceNumber, handle](Response& response)
    {
      auto* publish = as_publish(response);
      if (!publish)
      {
        return;
      }
      set_publish_sequence(*publish, ++(*sequenceNumber));
      set_data_change(
        *publish, {HandleValue{handle, ua::Variant{}, ua::StatusCode{ua::Status::BadIndexRangeInvalid}}});
    });

  EXPECT_TRUE(wait_until([&] { return sink->has_status(ua::StatusCode{ua::Status::BadIndexRangeInvalid}); }))
    << "the Bad_IndexRangeInvalid per-sample status must be delivered to the callback (a data-quality "
       "signal)";
  EXPECT_EQ(fixture.monitored_item_count(), 1u)
    << "a Bad_IndexRangeInvalid per-sample status must NOT remove the item (it is non-fatal)";
  EXPECT_EQ(fixture.state(), ConnectionState::Active)
    << "a per-sample bad status must not fault the Connection";
}

// =============================================================================================
// Row - PublishBadIndexRangeNoDataPreservesItem  (MisbehavingServer)
// The server injects Bad_IndexRangeNoData then a Good DataValue on the same handle (a dynamic array whose
// range was initially uncovered, then grows to cover it). Both notifications must reach the callback and the
// item must stay registered; the later Good value must be delivered. If Bad_IndexRangeNoData were treated as
// a Create-time fatal, the item would be dropped and never recover. [neg: deferred no-data on dynamic array]
// =============================================================================================
// @verifies CL-MI-010
// @relation(CL-MI-010, scope=function)
TEST_F(ClientMonitorByIndex, PublishBadIndexRangeNoDataPreservesItem)
{
  MisbehavingServer server;
  MisbehavingMonitorByIndexFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  auto sink = std::make_shared<DataValueSink>();
  const auto item = fixture.monitor(subscription.value(), index_request(std::string{"5:9"}), sink);
  ASSERT_TRUE(item.is_good()) << to_string(item.status_code());
  const std::uint32_t handle = item.value().client_handle();
  ASSERT_TRUE(wait_until([&] { return fixture.monitored_item_count() == 1; }));

  const std::int32_t goodFirst = 7000;
  auto goodPhase = std::make_shared<std::atomic<bool>>(false);
  auto sequenceNumber = std::make_shared<std::atomic<std::uint32_t>>(0);
  server.set_response_mutator(
    [goodPhase, sequenceNumber, handle, goodFirst](Response& response)
    {
      auto* publish = as_publish(response);
      if (!publish)
      {
        return;
      }
      set_publish_sequence(*publish, ++(*sequenceNumber));
      if (goodPhase->load())
      {
        set_data_change(*publish, {HandleValue{handle, make_int32_array(5, goodFirst)}});
      }
      else
      {
        set_data_change(
          *publish, {HandleValue{handle, ua::Variant{}, ua::StatusCode{ua::Status::BadIndexRangeNoData}}});
      }
    });

  // The Bad_IndexRangeNoData notifications flow; the item must NOT be dropped on this deferred no-data
  // status.
  ASSERT_TRUE(wait_until([&] { return sink->has_status(ua::StatusCode{ua::Status::BadIndexRangeNoData}); }))
    << "the Bad_IndexRangeNoData per-sample status must be delivered (non-vacuous)";
  EXPECT_EQ(fixture.monitored_item_count(), 1u)
    << "a Bad_IndexRangeNoData per-sample status must NOT remove the item (recovery must remain possible)";

  // The dynamic array grows to cover the range: the later Good value must still be delivered on the same
  // item.
  goodPhase->store(true);
  EXPECT_TRUE(wait_until([&] { return sink->has_int32_array(5, goodFirst); }))
    << "the later Good value must be delivered - the item stayed attached across the no-data status";
}
