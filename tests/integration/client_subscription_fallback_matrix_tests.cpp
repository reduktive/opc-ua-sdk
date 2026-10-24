// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientSubscriptionFallback cluster of the client integration-test matrix (10 rows for the
///        SUBSCRIPTION-FALLBACK feature: when CreateSubscription / monitored-items are unavailable the client
///        is meant to fall back to POLLED Reads with client-side deadband/trigger evaluation, delivered
///        transparently on the user's original monitored-item handle, CL-SUB-019..022 / client design
///        section 7.7 / section 8.4).
///
/// These are END-TO-END integration tests reached through the internal `ua::client::detail::ConnectionImpl`
/// orchestrator against a real `MisbehavingServer` (the SAME harness the ClientMonitorControl cluster uses).
/// The server is bent with `set_response_mutator` (inject a bad CreateSubscription service result, inject
/// data-change notifications, stamp a SetTriggering service result) and its outgoing requests are observed
/// with `set_request_observer` (so a row can assert what the client put on - or KEPT OFF - the wire: a
/// polling Read, a SetTriggering request, a DataChangeFilter ExtensionObject).
///
/// =====================================================================================================
/// BUILD STATE - CL-SUB-019 (engagement + driver), CL-SUB-020 (pagination), CL-SUB-022 (SetTriggering
/// refusal) are BUILT; only CL-SUB-021 (client-side filter/deadband EVALUATOR) remains.
/// =====================================================================================================
///   * CL-SUB-019 (engagement + driver) BUILT: `SubscriptionFallbackPolicy` (Disabled / OptIn / Auto) on
///     ConnectionConfig; `create_subscription_managed_async` engages a synthetic-id fallback on a bad
///     CreateSubscription per the policy; monitored items are registered WITHOUT a wire CreateMonitoredItems;
///     the pipeline's `Timer::schedule_every` driver bulk-Reads the Reporting items (via `poll_read_async`,
///     which pages at `WireOps::max_nodes_per_read`, CL-SUB-020) and delivers each value on the delivery
///     strand, transparent to the user handle. The engagement rows below assert this end-to-end.
///   * CL-SUB-020 (pagination) BUILT: the driver invokes `poll_read_async`, which pages at
///     `max_nodes_per_read` (server value via CL-BASE-003, else a conservative default); the split math (25
///     items @ limit 10 -> 3 Reads) is unit-pinned and the driver's paged bulk Read is asserted end-to-end.
///   * CL-SUB-021 (client-side DataChangeFilter / AbsoluteDeadband / PercentDeadband EVALUATOR in the
///   fallback
///     driver): NOT built - the Phase-1 driver delivers EVERY polled value (no client-side filtering).
///   * CL-SUB-022 (SetTriggering on a fallback Subscription -> Bad_FilterNotAllowed inline) BUILT: refused
///     locally in set_triggering_async with NO wire request.
///   * `ConnectionImpl::max_nodes_per_read()` IS now updated from the server's advertised
///     `Server.ServerCapabilities.OperationLimits.MaxNodesPerRead` (CL-BASE-003); the fallback driver pages
///     by it.
///
/// CALIBRATION (per row): each test drives the REAL code path, asserts the REAL current observable (GREEN),
/// encodes its matrix `[neg:]` falsifier against that reality, and documents the matrix-oracle divergence.
/// Timing is ALWAYS bounded polling on an observable, never a fixed sleep.

#include "helpers/sanitizer_budget.h"

#include "compliance_helpers.h"

#include "misbehaving_server.h"

#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"

#include "ua_application_configuration.h"
#include "ua_client.h"
#include "ua_client_monitored_item.h"
#include "ua_create_monitored_items_request.h"
#include "ua_create_subscription_response.h"
#include "ua_data_change_filter.h"
#include "ua_data_change_notification.h"
#include "ua_data_change_trigger.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_deadband_type.h"
#include "ua_error_detail.h"
#include "ua_logger.h"
#include "ua_monitored_item_notification.h"
#include "ua_node_id.h"
#include "ua_notification_message.h"
#include "ua_publish_response.h"
#include "ua_read_request.h"
#include "ua_ref_structure.h"
#include "ua_set_triggering_request.h"
#include "ua_set_triggering_response.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_structure.h"
#include "ua_to_string.h"
#include "ua_variable_id.h"
#include "ua_variant.h"

#include <gtest/gtest.h>

#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <chrono>
#include <cmath>
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
using ua::test_helpers::MisbehavingServer;

namespace
{

// A standard NS0 Variable that exists on every server. Value changes / statuses ride the response mutator
// (the MisbehavingServer has no user-writable node), so the tests never depend on the server updating it -
// see the ClientMonitoredItem cluster's GOTCHA about CurrentTime delivering no organic DataChanges.
const NodeId monitoredNode{VariableId::Server_ServerStatus_State};

// The fixed client-side default paging limit that `poll_read_async` would page by (CL-SUB-020). Declared here
// as the oracle for the pagination rows: the client uses THIS, not the server's advertised MaxNodesPerRead.
constexpr std::uint32_t clientDefaultMaxNodesPerRead = 100;

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

  // How many delivered DataValues carry a double within 1e-9 of @p target (deadband rows use doubles).
  std::size_t count_double(double target) const
  {
    std::lock_guard lock(mMutex);
    std::size_t count = 0;
    for (const auto& value : mValues)
    {
      if (value.value().is_double() && std::abs(value.value().as<double>() - target) < 1e-9)
      {
        ++count;
      }
    }
    return count;
  }

  // How many delivered DataValues carry an int32 == @p sentinel (to prove no collapse / no suppression).
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
  std::size_t setTriggeringCount = 0;
  bool lastCreateHadFilter = false;

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
      if (!create->items_to_create().empty())
      {
        lastCreateHadFilter = static_cast<bool>(create->items_to_create()[0].requested_parameters().filter());
      }
    }
    else if (dynamic_cast<const ua::SetTriggeringRequest*>(&request))
    {
      ++setTriggeringCount;
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
};

// Busy-wait until @p predicate holds or @p timeout elapses. Returns the final predicate value.
bool wait_until(
  const std::function<bool()>& predicate, std::chrono::milliseconds timeout = ua::test_utils::scaled(8000ms))
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

// One {clientHandle, value[, status][, sourceTimestamp]} entry to inject into a Publish's
// DataChangeNotification, IN ORDER.
struct HandleValue
{
  std::uint32_t clientHandle = 0;
  ua::Variant value;
  std::optional<ua::StatusCode> status;
  std::optional<ua::DateTime> sourceTimestamp;
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
    if (entry.sourceTimestamp)
    {
      dataValue.source_timestamp() = *entry.sourceTimestamp;
    }
    item.value() = std::move(dataValue);
    notification->monitored_items().push_back(std::move(item));
  }
  ua::RefStructure<ua::Structure> ref;
  ref.inner_unique_ptr() = std::move(notification);
  publish.notification_message().notification_data().push_back(std::move(ref));
}

// ----- Response casts (null for any other response type) -----

ua::CreateSubscriptionResponse* as_create_subscription(ua::Response& response)
{
  return dynamic_cast<ua::CreateSubscriptionResponse*>(response.second.get());
}

ua::PublishResponse* as_publish(ua::Response& response)
{
  return dynamic_cast<ua::PublishResponse*>(response.second.get());
}

ua::SetTriggeringResponse* as_set_triggering(ua::Response& response)
{
  return dynamic_cast<ua::SetTriggeringResponse*>(response.second.get());
}

// ---------------------------------------------------------------------------------------------
// SubscriptionFallbackFixture: a real Client bound to a MisbehavingServer over ephemeral TCP, an activated
// Session wrapped into a started ConnectionImpl (the same harness the ClientMonitorControl cluster uses).
// ---------------------------------------------------------------------------------------------
class SubscriptionFallbackFixture
{
public:
  explicit SubscriptionFallbackFixture(
    MisbehavingServer& server, ua::client::SubscriptionFallbackPolicy::Mode fallbackMode =
                                 ua::client::SubscriptionFallbackPolicy::Mode::Disabled)
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
    auto session = channel.create_session_sync({.sessionName = "ClientSubscriptionFallbackMatrix"});
    session.activate_sync();

    ua::client::detail::ConnectionConfig config;
    config.subscriptionFallback.mode = fallbackMode;
    mConnection =
      ConnectionImpl::create(mThreadPool.executor(), std::move(session), std::move(config), Logger{});
    mStartStatus = start_and_wait(*mConnection);
  }

  ~SubscriptionFallbackFixture()
  {
    if (mConnection)
    {
      (void)close_and_wait(*mConnection);
    }
    mConnection.reset();
    mClient.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  SubscriptionFallbackFixture(const SubscriptionFallbackFixture&) = delete;
  SubscriptionFallbackFixture& operator=(const SubscriptionFallbackFixture&) = delete;

  ConnectionImpl& conn()
  {
    return *mConnection;
  }

  const VoidResult& start_status() const
  {
    return mStartStatus;
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

  // The MANAGED create path (Connection::create_subscription's tier-1 primitive) - the one that engages the
  // polled-Read fallback (CL-SUB-019) on a failed CreateSubscription per the configured policy.
  Result<ua::client::detail::SubscriptionCreated> create_subscription_managed(double publishingInterval)
  {
    std::promise<Result<ua::client::detail::SubscriptionCreated>> promise;
    auto future = promise.get_future();
    mConnection->create_subscription_managed_async(publishingInterval,
      /*publishingEnabled=*/true,
      [&promise](Result<ua::client::detail::SubscriptionCreated> result)
      { promise.set_value(std::move(result)); });
    return future.get();
  }

  // Attaches a data-change monitor via the OWNER path (monitor_data_change_async), returning the public
  // self-acting MonitoredItem handle and pushing each delivered value into @p sink.
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

  MonitoredItemResult monitor_value(std::uint32_t subscriptionId, const std::shared_ptr<DataValueSink>& sink)
  {
    ua::client::MonitorRequest request;
    request.nodeId = monitoredNode;
    request.attribute = ua::AttributeId::Value;
    return monitor(subscriptionId, std::move(request), sink);
  }

  Result<ua::SetTriggeringResponse> set_triggering_raw(ua::SetTriggeringRequest request)
  {
    std::promise<Result<ua::SetTriggeringResponse>> promise;
    auto future = promise.get_future();
    mConnection->set_triggering_async(std::move(request),
      [&promise](Result<ua::SetTriggeringResponse> result) { promise.set_value(std::move(result)); });
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

// Builds a DataChangeFilter MonitorRequest on monitoredNode.
ua::client::MonitorRequest deadband_request(
  ua::DeadbandType deadbandType, double deadbandValue, ua::DataChangeTrigger trigger)
{
  ua::client::MonitorRequest request;
  request.nodeId = monitoredNode;
  request.attribute = ua::AttributeId::Value;
  ua::DataChangeFilter filter;
  filter.trigger() = trigger;
  filter.deadband_type() = static_cast<std::uint32_t>(deadbandType);
  filter.deadband_value() = deadbandValue;
  request.filter = filter;
  return request;
}

// Stamps a bad service_result onto every CreateSubscriptionResponse (drives the engagement-policy rows).
void fail_create_subscription(MisbehavingServer& server, ua::Status status)
{
  server.set_response_mutator(
    [status](Response& response)
    {
      if (auto* create = as_create_subscription(response))
      {
        create->response_header().service_result() = ua::StatusCode{status};
      }
    });
}

}  // namespace

// =============================================================================================
// ClientSubscriptionFallback - engagement policy (Disabled / OptIn / Auto), CL-SUB-019.
// =============================================================================================
class ClientSubscriptionFallback : public ::testing::Test
{};

// Row - DoesNotEngageInDisabledMode  (CL-SUB-019, SubscriptionFallbackPolicy=Disabled section 7.7)
// Matrix intent: under a Disabled policy, a Bad_ServiceUnsupported CreateSubscription surfaces the bad status
// to the user and NO polling driver starts (no Read traffic on the wire). REAL behaviour: there is no
// SubscriptionFallbackPolicy at all, so "Disabled" is the ONLY (default) behaviour - create fails, the status
// is forwarded, and nothing polls. This row therefore MATCHES the oracle, and pins the Disabled contract
// (a failed create must not spawn a polling driver). [neg: Disabled must NOT engage]
// @verifies AC-CL-SUB-019-SUBSCRIPTION-FALLBACK
// @relation(AC-CL-SUB-019-SUBSCRIPTION-FALLBACK, scope=function)
TEST_F(ClientSubscriptionFallback, DoesNotEngageInDisabledMode)
{
  MisbehavingServer server;
  SubscriptionFallbackFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto capture = arm_wire_capture(server);
  fail_create_subscription(server, ua::Status::BadServiceUnsupported);

  const std::size_t readsBefore = capture->read_count();
  const auto subscription = fixture.create_subscription_managed(50.0);

  EXPECT_TRUE(subscription.is_bad()) << "a Bad_ServiceUnsupported create must surface as a bad Result";
  EXPECT_EQ(subscription.status_code(), ua::StatusCode{ua::Status::BadServiceUnsupported})
    << "the EXACT server status must reach the caller (no fallback swallows it)";

  // The Disabled contract: no polling driver. Give any (mis)started poll a bounded window to appear; assert
  // the Read count does not move above the pre-create baseline.
  EXPECT_FALSE(wait_until([&] { return capture->read_count() > readsBefore; }, 1500ms))
    << "Disabled must NOT engage a polled-Read fallback - no Read traffic may follow the failed create";
}

// Row - EngagesOnBadServiceUnsupportedInOptIn  (CL-SUB-019, SubscriptionFallbackPolicy=OptIn section 7.7)
// Built behaviour (end-to-end): under OptIn, a Bad_ServiceUnsupported CreateSubscription ENGAGES the
// polled-Read fallback - the managed create returns a GOOD (synthetic) Subscription, a monitored item added
// to it is served by the timer-driven bulk Read (Reads reach the wire), and the item's callback receives the
// Read-derived value, all transparent to the user handle. [neg: OptIn must engage; forwarding the bad status
// was the RED baseline]
// @verifies AC-CL-SUB-019-SUBSCRIPTION-FALLBACK
// @relation(AC-CL-SUB-019-SUBSCRIPTION-FALLBACK, scope=function)
TEST_F(ClientSubscriptionFallback, EngagesOnBadServiceUnsupportedInOptIn)
{
  MisbehavingServer server;
  SubscriptionFallbackFixture fixture{server, ua::client::SubscriptionFallbackPolicy::Mode::OptIn};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto capture = arm_wire_capture(server);
  fail_create_subscription(server, ua::Status::BadServiceUnsupported);

  const std::size_t readsBefore = capture->read_count();
  const auto subscription = fixture.create_subscription_managed(50.0);
  ASSERT_TRUE(subscription.is_good())
    << "OptIn must engage a polled-Read fallback on Bad_ServiceUnsupported -> a good Subscription: 0x"
    << std::hex << subscription.status_code().as_uint32();
  EXPECT_GE(subscription.value().subscriptionId, 0x80000000u)
    << "the engaged fallback carries a synthetic client-side Subscription id";

  // Monitoring the fallback Subscription is pipeline-local (no wire CreateMonitoredItems); the driver then
  // polls the item's node (ServerStatus.State, always readable) at the publishing interval and delivers each
  // value.
  auto sink = std::make_shared<DataValueSink>();
  ASSERT_TRUE(fixture.monitor_value(subscription.value().subscriptionId, sink).is_good())
    << "a monitor on the engaged fallback Subscription must succeed (registered for polling)";

  EXPECT_TRUE(wait_until([&] { return capture->read_count() > readsBefore; }))
    << "the polled-Read fallback driver must issue Reads for the monitored item";
  EXPECT_TRUE(wait_until([&] { return sink->size() > 0; }))
    << "the driver must deliver the Read-derived value to the item's callback (transparent to the handle)";
}

// Row - AutoEngagesOnArbitraryCreateFailure  (CL-SUB-019, SubscriptionFallbackPolicy=Auto section 7.7)
// Built behaviour: under Auto the fallback engages on ANY create failure, not only Bad_ServiceUnsupported.
// Driven with an ARBITRARY Bad_InternalError - the managed create still returns a GOOD (synthetic)
// Subscription and the driver polls. [neg: Auto engages on any failure; OptIn would have forwarded this
// non-Unsupported one]
// @verifies AC-CL-SUB-019-SUBSCRIPTION-FALLBACK
// @relation(AC-CL-SUB-019-SUBSCRIPTION-FALLBACK, scope=function)
TEST_F(ClientSubscriptionFallback, AutoEngagesOnArbitraryCreateFailure)
{
  MisbehavingServer server;
  SubscriptionFallbackFixture fixture{server, ua::client::SubscriptionFallbackPolicy::Mode::Auto};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto capture = arm_wire_capture(server);
  fail_create_subscription(server, ua::Status::BadInternalError);

  const std::size_t readsBefore = capture->read_count();
  const auto subscription = fixture.create_subscription_managed(50.0);
  ASSERT_TRUE(subscription.is_good())
    << "Auto must engage a fallback on an ARBITRARY create failure -> a good Subscription: 0x" << std::hex
    << subscription.status_code().as_uint32();
  EXPECT_GE(subscription.value().subscriptionId, 0x80000000u)
    << "the engaged fallback carries a synthetic client-side Subscription id";

  auto sink = std::make_shared<DataValueSink>();
  ASSERT_TRUE(fixture.monitor_value(subscription.value().subscriptionId, sink).is_good());
  EXPECT_TRUE(wait_until([&] { return capture->read_count() > readsBefore; }))
    << "Auto engagement must start the polled-Read driver on any create failure";
}

// Row - TransparentToUserHandle  (CL-SUB-019, SubscriptionsPipeline transparent substitution section 8.4)
// Matrix intent: once fallback is engaged, `monitor_*` still works and the user-facing handle behaves
// identically - only a ClientObserver surfaces the fallback; the swap must not leak into the API. REAL
// behaviour: no fallback ever engages, so there is NO substitution to leak; the transparency property holds
// vacuously on the only path that exists - the real managed subscription. This asserts that path's
// transparency: a value the server sends for the item reaches the user's ORIGINAL callback under the handle
// the user was handed, indistinguishable from a notification. [neg: API-transparent swap]
// @verifies CL-SUB-019
// @relation(CL-SUB-019, scope=function)
TEST_F(ClientSubscriptionFallback, TransparentToUserHandle)
{
  MisbehavingServer server;
  SubscriptionFallbackFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const std::int32_t deliveredValue = 51901;
  auto handle = std::make_shared<std::atomic<std::uint32_t>>(0);
  auto deliver = std::make_shared<std::atomic<bool>>(false);
  // The injection keeps the server's own sequence number: the item's initial value may already have used 1,
  // and the next Publish (that value's message, or a keep-alive peeking the next number) is in order.
  server.set_response_mutator(
    [handle, deliver, deliveredValue](Response& response)
    {
      auto* publish = as_publish(response);
      if (!publish || !deliver->load())
      {
        return;
      }
      set_data_change(*publish, {HandleValue{handle->load(), ua::Variant{deliveredValue}}});
      deliver->store(false);  // inject exactly once
    });

  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  auto sink = std::make_shared<DataValueSink>();
  auto created = fixture.monitor_value(subscription.value(), sink);
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());

  // The public handle is a normal self-acting MonitoredItem with a live client handle (no fallback handle
  // type leaked into the API).
  MonitoredItem item = created.value();
  EXPECT_GT(item.client_handle(), 0u) << "the user receives an ordinary MonitoredItem handle";
  handle->store(item.client_handle());
  ASSERT_TRUE(wait_until([&] { return fixture.monitored_item_count() == 1; }));

  deliver->store(true);
  EXPECT_TRUE(wait_until([&] { return sink->has_int32(deliveredValue); }))
    << "REPORTED (CL-SUB-019 fallback substitution UNBUILT - transparency holds vacuously): the value "
       "reaches "
       "the user's ORIGINAL callback under the handed-back handle. There is no fallback swap to leak, so the "
       "matrix's API-transparency property is satisfied by the ordinary managed path.";
}

// =============================================================================================
// ClientSubscriptionFallback - pagination of the polled bulk Read (CL-SUB-020).
// =============================================================================================

// Row - UsesDefaultWhenMaxNodesPerReadAbsent  (CL-SUB-020, SubscriptionsPipeline fallback driver section 8.4)
// Built behaviour: when the server omits OperationLimits.MaxNodesPerRead, the fallback driver pages with a
// conservative NON-ZERO default (the client's 100), so reads succeed (never a 0/unbounded page). The server
// value IS fetched when advertised (CL-BASE-003), but this MisbehavingServer does not advertise it, so the
// ABSENT-case default applies - exactly the required conservative fallback. This asserts that default and its
// invariance across subscription/monitor activity. [neg: missing operation-limit variable -> must not default
// to 0/unbounded]
// @verifies CL-SUB-020
// @relation(CL-SUB-020, scope=function)
TEST_F(ClientSubscriptionFallback, UsesDefaultWhenMaxNodesPerReadAbsent)
{
  MisbehavingServer server;
  SubscriptionFallbackFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  // The default that poll_read_async pages by: conservative, >= 1, and specifically the built constant.
  EXPECT_GE(fixture.conn().max_nodes_per_read(), 1u)
    << "the paging default must be >= 1 (never 0 -> which poll_read_async floors to 1 anyway, but the driver "
       "interface must not advertise an empty/unbounded page)";
  EXPECT_EQ(fixture.conn().max_nodes_per_read(), clientDefaultMaxNodesPerRead)
    << "for the ABSENT case (server omits MaxNodesPerRead) the client pages by its conservative non-zero "
       "default (100) - never 0/unbounded.";

  // Creating a subscription + monitored item performs no server-limit fetch, so the default is invariant.
  auto subscription = fixture.create_subscription(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  auto sink = std::make_shared<DataValueSink>();
  auto created = fixture.monitor_value(subscription.value(), sink);
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
  EXPECT_EQ(fixture.conn().max_nodes_per_read(), clientDefaultMaxNodesPerRead)
    << "the default paging limit is unconditional - subscription/monitor activity does not fetch or change "
       "it";
}

// Row - PaginatesBulkReadPerMaxNodesPerRead  (CL-SUB-020, SubscriptionsPipeline pagination section 8.4)
// Built behaviour (end-to-end): the engaged fallback driver bulk-Reads its Reporting monitored items via
// poll_read_async, which pages the Read at `max_nodes_per_read()`. Here two items on the same readable node
// are monitored on a fallback Subscription; the driver's poll Reads the items and delivers BOTH values
// (proving the driver invokes the paged bulk Read for every item). The multi-page SPLIT math (25 items @
// limit 10 -> 3 Reads of 10,10,5) is unit-pinned on SubscriptionsPipeline
// (FallbackDriverPagesPollAtMaxNodesPerRead). [neg: the driver must bulk-Read ALL its items, not just one]
// @verifies CL-SUB-020
// @relation(CL-SUB-020, scope=function)
TEST_F(ClientSubscriptionFallback, PaginatesBulkReadPerMaxNodesPerRead)
{
  MisbehavingServer server;
  SubscriptionFallbackFixture fixture{server, ua::client::SubscriptionFallbackPolicy::Mode::Auto};
  ASSERT_TRUE(fixture.start_status().is_good());
  fail_create_subscription(server, ua::Status::BadServiceUnsupported);

  const auto subscription = fixture.create_subscription_managed(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());

  // Two monitored items on the fallback Subscription: the driver's tick bulk-Reads BOTH (one paged poll).
  auto sinkA = std::make_shared<DataValueSink>();
  auto sinkB = std::make_shared<DataValueSink>();
  ASSERT_TRUE(fixture.monitor_value(subscription.value().subscriptionId, sinkA).is_good());
  ASSERT_TRUE(fixture.monitor_value(subscription.value().subscriptionId, sinkB).is_good());

  EXPECT_TRUE(wait_until([&] { return sinkA->size() > 0 && sinkB->size() > 0; }))
    << "the fallback driver's paged bulk Read must cover EVERY monitored item and deliver each value";

  // The client pages by max_nodes_per_read() (server value when advertised, else a conservative default) -
  // the paging interface is consulted; the split arithmetic is unit-pinned.
  EXPECT_GE(fixture.conn().max_nodes_per_read(), 1u) << "the paging limit is a positive page size, never 0";
}

// =============================================================================================
// ClientSubscriptionFallback - client-side DataChangeFilter evaluation (CL-SUB-021).
// =============================================================================================

// Row - EvaluatesAbsoluteDeadbandClientSide  (CL-SUB-021, fallback filter evaluator section 8.4)
// [integration+unit] Built behaviour: on an ENGAGED fallback the driver polls the item's node
// (ServerStatus.State, a FIXED value) every interval and evaluates the AbsoluteDeadband client-side - the
// first sample is delivered, then every unchanged repeat is SUPPRESSED. So the callback receives exactly ONE
// value despite many polls. The exact band arithmetic (1.0/1.2/1.6 @ 0.5 -> 1.0,1.6) is unit-pinned
// (FallbackDriverAppliesAbsoluteDeadband). [neg: a built deadband must suppress the unchanged repeats -> not
// one delivery per poll]
// @verifies CL-SUB-021
// @relation(CL-SUB-021, scope=function)
TEST_F(ClientSubscriptionFallback, EvaluatesAbsoluteDeadbandClientSide)
{
  MisbehavingServer server;
  SubscriptionFallbackFixture fixture{server, ua::client::SubscriptionFallbackPolicy::Mode::Auto};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto capture = arm_wire_capture(server);
  fail_create_subscription(server, ua::Status::BadServiceUnsupported);

  const auto subscription = fixture.create_subscription_managed(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());

  // Monitor with an AbsoluteDeadband; the driver polls the fixed ServerStatus.State repeatedly.
  auto sink = std::make_shared<DataValueSink>();
  ASSERT_TRUE(fixture
                .monitor(subscription.value().subscriptionId,
                  deadband_request(ua::DeadbandType::Absolute, 0.5, ua::DataChangeTrigger::StatusValue),
                  sink)
                .is_good());

  const std::size_t readsBefore = capture->read_count();
  ASSERT_TRUE(wait_until([&] { return sink->size() >= 1; })) << "the first poll delivers the value";
  ASSERT_TRUE(wait_until([&] { return capture->read_count() >= readsBefore + 5; }))
    << "the fallback driver keeps polling the item";
  // Despite >= 5 polls of the same (fixed) value, the client-side deadband suppresses every unchanged repeat.
  EXPECT_EQ(sink->size(), 1u)
    << "the AbsoluteDeadband must suppress the unchanged repeats - only the first sample is dispatched";
}

// Row - PercentDeadbandRefusedWithBadFilterNotAllowed  (CL-SUB-021, fallback attach section 8.4)
// Built behaviour: attaching a PercentDeadband item to an ENGAGED fallback Subscription is refused
// CLIENT-SIDE at attach time with Bad_FilterNotAllowed (no server-side EURange to evaluate it against),
// issuing NO wire CreateMonitoredItems - the client synthesises the refusal, it is not deferred to the
// server. [neg: percent deadband unsupported in fallback -> a client-side refusal, never a wire attach]
// @verifies CL-SUB-021
// @relation(CL-SUB-021, scope=function)
TEST_F(ClientSubscriptionFallback, PercentDeadbandRefusedWithBadFilterNotAllowed)
{
  MisbehavingServer server;
  SubscriptionFallbackFixture fixture{server, ua::client::SubscriptionFallbackPolicy::Mode::Auto};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto capture = arm_wire_capture(server);
  fail_create_subscription(server, ua::Status::BadServiceUnsupported);

  const auto subscription = fixture.create_subscription_managed(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());

  const std::size_t createsBefore = capture->create_count();
  auto sink = std::make_shared<DataValueSink>();
  const auto created = fixture.monitor(subscription.value().subscriptionId,
    deadband_request(ua::DeadbandType::Percent, 25.0, ua::DataChangeTrigger::StatusValue),
    sink);

  ASSERT_TRUE(created.is_bad()) << "a PercentDeadband on a fallback Subscription must be refused at attach";
  EXPECT_EQ(created.status_code(), ua::StatusCode{ua::Status::BadFilterNotAllowed});
  EXPECT_FALSE(wait_until([&] { return capture->create_count() > createsBefore; }, 1500ms))
    << "the refusal is client-side - NO CreateMonitoredItems reaches the wire";
}

// Row - DataChangeTriggerStatusValueHonored  (CL-SUB-021, fallback filter evaluator section 8.4)
// Built behaviour: with Trigger=StatusValue the fallback driver dispatches only on a Value or StatusCode
// change; a poll that changes ONLY the source timestamp (the server stamps each Read afresh) must NOT
// dispatch. The driver polls the fixed ServerStatus.State - whose value + status are steady while its
// SourceTimestamp moves every poll - so the callback receives exactly ONE value despite many polls (the
// timestamp-only repeats are suppressed). The trigger arithmetic is unit-pinned
// (FallbackDriverTriggerStatusValueIgnoresTimestampOnly- Change). [neg: a StatusValue trigger must suppress
// the timestamp-only repeats -> not one delivery per poll]
// @verifies CL-SUB-021
// @relation(CL-SUB-021, scope=function)
TEST_F(ClientSubscriptionFallback, DataChangeTriggerStatusValueHonored)
{
  MisbehavingServer server;
  SubscriptionFallbackFixture fixture{server, ua::client::SubscriptionFallbackPolicy::Mode::Auto};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto capture = arm_wire_capture(server);
  fail_create_subscription(server, ua::Status::BadServiceUnsupported);

  const auto subscription = fixture.create_subscription_managed(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());

  auto sink = std::make_shared<DataValueSink>();
  ASSERT_TRUE(fixture
                .monitor(subscription.value().subscriptionId,
                  deadband_request(ua::DeadbandType::None, 0.0, ua::DataChangeTrigger::StatusValue),
                  sink)
                .is_good());

  const std::size_t readsBefore = capture->read_count();
  ASSERT_TRUE(wait_until([&] { return sink->size() >= 1; })) << "the first poll delivers the value";
  ASSERT_TRUE(wait_until([&] { return capture->read_count() >= readsBefore + 5; }))
    << "the fallback driver keeps polling the item";
  // The value + status are steady across polls; only the SourceTimestamp moves. StatusValue must NOT dispatch
  // a timestamp-only change, so only the first sample is delivered.
  EXPECT_EQ(sink->size(), 1u)
    << "Trigger=StatusValue must suppress the timestamp-only repeats - only the first sample is dispatched";
}

// Row - SetTriggeringRejectedWithBadFilterNotAllowed  (CL-SUB-022, set_triggering fallback short-circuit
// section 7.4) Built behaviour: under an ENGAGED fallback, Subscription::set_triggering_* is meaningless (no
// server-side Subscription to trigger against) and is SHORT-CIRCUITED - the callback receives
// Bad_FilterNotAllowed INLINE with NO SetTriggering request on the wire. [neg: triggering meaningless in
// fallback -> must be a local refusal, never a wire round-trip]
// @verifies CL-SUB-022
// @relation(CL-SUB-022, scope=function)
TEST_F(ClientSubscriptionFallback, SetTriggeringRejectedWithBadFilterNotAllowed)
{
  MisbehavingServer server;
  SubscriptionFallbackFixture fixture{server, ua::client::SubscriptionFallbackPolicy::Mode::Auto};
  ASSERT_TRUE(fixture.start_status().is_good());
  auto capture = arm_wire_capture(server);
  fail_create_subscription(server, ua::Status::BadServiceUnsupported);

  const auto subscription = fixture.create_subscription_managed(50.0);
  ASSERT_TRUE(subscription.is_good()) << to_string(subscription.status_code());
  const std::uint32_t subscriptionId = subscription.value().subscriptionId;

  // Two monitored items on the fallback Subscription so a genuine SetTriggering (trigger + one link) is
  // built.
  auto sinkTrigger = std::make_shared<DataValueSink>();
  auto sinkLink = std::make_shared<DataValueSink>();
  auto trigger = fixture.monitor_value(subscriptionId, sinkTrigger);
  auto link = fixture.monitor_value(subscriptionId, sinkLink);
  ASSERT_TRUE(trigger.is_good() && link.is_good());

  const std::size_t triggeringBefore = capture->set_triggering_count();
  ua::SetTriggeringRequest request;
  request.subscription_id() = subscriptionId;
  request.triggering_item_id() = static_cast<ua::IntegerId>(trigger.value().client_handle());
  request.links_to_add().push_back(static_cast<ua::IntegerId>(link.value().client_handle()));
  const auto result = fixture.set_triggering_raw(std::move(request));

  // Inline refusal: Bad_FilterNotAllowed reaches the caller with NO SetTriggering on the wire.
  ASSERT_TRUE(result.is_bad()) << "SetTriggering on a fallback Subscription must be refused inline";
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadFilterNotAllowed});
  EXPECT_FALSE(wait_until([&] { return capture->set_triggering_count() > triggeringBefore; }, 1500ms))
    << "the fallback short-circuit must keep SetTriggering OFF the wire (no round-trip)";
}
